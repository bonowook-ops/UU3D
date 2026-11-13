// D3D12Component::on_frame_flat3d — flat-3D-monitor replacement for the VR
// submit (see D3D11Component_Flat3D.cpp for the D3D11 counterpart). Own TU
// to keep the upstream D3D12Component.cpp diff to a single branch line.

#include <cmath>
#include <filesystem>
#include <thread>

#include <utility/Logging.hpp>
#include <utility/String.hpp>

#include "Framework.hpp"
#include "../../VR.hpp"
#include "../GameDepthCapture.hpp"

#include "../D3D12Component.hpp"
#include "SndDiag.hpp"

#include <d3dcompiler.h>
#pragma comment(lib, "d3dcompiler") // runtime shader compilation (D3DCompile)

namespace vrmod {
// AFW (Asynchronous Frame Warp) for Flat3D. Mirrors the OpenXR warp block in
// D3D12Component::on_frame, but sized to the Flat3D display eye extent and feeding
// the Flat3D compositor instead of the VR compositor. Depth + motion vectors are
// harvested globally (DLSS NGX hook / NeverDLSS raw barriers) into
// vr->depthDesc/motionVectorsDesc regardless of runtime. The PDAFWPlugin and the
// Flat3D compositor both run on the game's main command queue, so the warp (below)
// is serialized before the compositor's read of the warped eye — no extra fence.
namespace {
// UE velocity decode -> per-object pixel motion vectors for the AFW plugin.
// UE EncodeVelocityToTexture(): xy = V * (0.499 * 0.5) + 32767/65535, where V is
// the NDC delta (this - prev, y up) of a moving pixel; untouched (static) pixels
// stay 0, so x > 0 means "velocity written". Jitter is already removed by UE.
// Output convention: previous minus current, y-down pixels (DLSS / plugin).
// AddCameraMotion: a moving pixel also gets the camera-induced motion between
// the current eye camera and the "previous" camera the plugin will use for
// this vector type (same eye's last frame for Normal, the other eye's last
// render for FromOtherEye), from this frame's reverse-Z depth; static pixels
// stay zero either way.
const char* const g_afw_velocity_decode_hlsl = R"(
Texture2D<float4> VelocityTex : register(t0);
Texture2D<float> DepthTex : register(t1);
RWTexture2D<float2> MotionOut : register(u0);
cbuffer Constants : register(b0) {
    float4x4 ClipToView;
    float4x4 ViewToWorld;
    float4x4 PrevWorldToView;
    float4x4 PrevViewToClip;
    uint Width; uint Height; float ScaleX; float ScaleY;
    uint AddCameraMotion; uint Pad0; uint Pad1; uint Pad2;
};
[numthreads(8, 8, 1)]
void cs_main(uint3 id : SV_DispatchThreadID) {
    if (id.x >= Width || id.y >= Height) { return; }
    const float4 enc = VelocityTex.Load(int3(id.xy, 0));
    float2 mv = float2(0.0, 0.0);
    if (enc.x > 0.0) {
        const float inv = 1.0 / (0.499 * 0.5);
        const float2 v = enc.xy * inv - (32767.0 / 65535.0) * inv; // NDC delta this - prev, y up
        mv = float2(-v.x * 0.5 * (float)Width, v.y * 0.5 * (float)Height); // prev - this, y down
        if (AddCameraMotion != 0) {
            const float d = DepthTex.Load(int3(id.xy, 0)).r;
            if (d > 0.0) {
                const float2 pix = float2(id.xy) + 0.5;
                const float2 ndc = float2(pix.x / (float)Width * 2.0 - 1.0, 1.0 - pix.y / (float)Height * 2.0);
                float4 view = mul(ClipToView, float4(ndc, d, 1.0));
                view /= view.w;
                const float4 world = mul(ViewToWorld, view);
                const float4 pclip = mul(PrevViewToClip, mul(PrevWorldToView, world));
                if (pclip.w > 0.0) {
                    const float2 pndc = pclip.xy / pclip.w;
                    const float2 ppix = float2((pndc.x + 1.0) * 0.5 * (float)Width, (1.0 - pndc.y) * 0.5 * (float)Height);
                    mv += ppix - pix;
                }
            }
        }
        mv *= float2(ScaleX, ScaleY);
    }
    MotionOut[id.xy] = mv;
}
)";

struct AfwVelocityDecodeConstants {
    glm::mat4 clip_to_view;
    glm::mat4 view_to_world;
    glm::mat4 prev_world_to_view;
    glm::mat4 prev_view_to_clip;
    uint32_t width, height;
    float scale_x, scale_y;
    uint32_t add_camera_motion, pad0, pad1, pad2;
};
} // namespace

bool D3D12Component::ensure_afw_velocity_decode(ID3D12Device* device) {
    auto& d = m_afw_velocity_decode;
    if (d.ready) {
        return true;
    }
    if (d.attempted || device == nullptr) {
        return false;
    }
    d.attempted = true;

    D3D12_DESCRIPTOR_RANGE vel_range{};
    vel_range.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    vel_range.NumDescriptors = 1;
    vel_range.BaseShaderRegister = 0;
    D3D12_DESCRIPTOR_RANGE depth_range{};
    depth_range.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    depth_range.NumDescriptors = 1;
    depth_range.BaseShaderRegister = 1;
    D3D12_DESCRIPTOR_RANGE uav_range{};
    uav_range.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_UAV;
    uav_range.NumDescriptors = 1;
    uav_range.BaseShaderRegister = 0;

    D3D12_ROOT_PARAMETER params[4]{};
    params[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    params[0].Descriptor.ShaderRegister = 0;
    params[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    params[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    params[1].DescriptorTable.NumDescriptorRanges = 1;
    params[1].DescriptorTable.pDescriptorRanges = &vel_range;
    params[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    params[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    params[2].DescriptorTable.NumDescriptorRanges = 1;
    params[2].DescriptorTable.pDescriptorRanges = &depth_range;
    params[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    params[3].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    params[3].DescriptorTable.NumDescriptorRanges = 1;
    params[3].DescriptorTable.pDescriptorRanges = &uav_range;
    params[3].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    D3D12_ROOT_SIGNATURE_DESC rs_desc{};
    rs_desc.NumParameters = 4;
    rs_desc.pParameters = params;

    ComPtr<ID3DBlob> rs_blob{}, rs_err{};
    if (FAILED(D3D12SerializeRootSignature(&rs_desc, D3D_ROOT_SIGNATURE_VERSION_1, &rs_blob, &rs_err))) {
        spdlog::error("[Flat3D][AFW] velocity decode: root signature serialize failed: {}",
            rs_err != nullptr ? (const char*)rs_err->GetBufferPointer() : "?");
        return false;
    }
    if (FAILED(device->CreateRootSignature(0, rs_blob->GetBufferPointer(), rs_blob->GetBufferSize(), IID_PPV_ARGS(&d.root_sig)))) {
        spdlog::error("[Flat3D][AFW] velocity decode: CreateRootSignature failed");
        return false;
    }

    ComPtr<ID3DBlob> cs{}, err{};
    if (FAILED(D3DCompile(g_afw_velocity_decode_hlsl, strlen(g_afw_velocity_decode_hlsl), "afw_velocity_decode",
            nullptr, nullptr, "cs_main", "cs_5_0", 0, 0, &cs, &err))) {
        spdlog::error("[Flat3D][AFW] velocity decode: shader compile failed: {}",
            err != nullptr ? (const char*)err->GetBufferPointer() : "?");
        return false;
    }

    D3D12_COMPUTE_PIPELINE_STATE_DESC pso{};
    pso.pRootSignature = d.root_sig.Get();
    pso.CS = { cs->GetBufferPointer(), cs->GetBufferSize() };
    if (FAILED(device->CreateComputePipelineState(&pso, IID_PPV_ARGS(&d.pso)))) {
        spdlog::error("[Flat3D][AFW] velocity decode: CreateComputePipelineState failed");
        return false;
    }

    for (uint32_t i = 0; i < AfwVelocityDecode::kRing; ++i) {
        if (!d.cmds[i].setup(L"Flat3D AFW velocity decode")) {
            spdlog::error("[Flat3D][AFW] velocity decode: command context {} setup failed", i);
            return false;
        }
        D3D12_HEAP_PROPERTIES heap{};
        heap.Type = D3D12_HEAP_TYPE_UPLOAD;
        D3D12_RESOURCE_DESC rd{};
        rd.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
        rd.Width = 512; // sizeof(AfwVelocityDecodeConstants) rounded up to the 256-byte CBV granularity
        rd.Height = 1;
        rd.DepthOrArraySize = 1;
        rd.MipLevels = 1;
        rd.SampleDesc.Count = 1;
        rd.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
        if (FAILED(device->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &rd, D3D12_RESOURCE_STATE_GENERIC_READ,
                nullptr, IID_PPV_ARGS(&d.cb[i])))) {
            spdlog::error("[Flat3D][AFW] velocity decode: constant buffer {} creation failed", i);
            return false;
        }
        const D3D12_RANGE no_read{0, 0};
        if (FAILED(d.cb[i]->Map(0, &no_read, &d.cb_mapped[i])) || d.cb_mapped[i] == nullptr) {
            spdlog::error("[Flat3D][AFW] velocity decode: constant buffer {} map failed", i);
            return false;
        }
    }

    d.ready = true;
    SPDLOG_INFO("[Flat3D][AFW] velocity decode pass ready (UE velocity -> per-object pixel motion vectors)");
    return true;
}

bool D3D12Component::run_afw_velocity_decode(VR* vr, const AfwVelocityDecodeParams& p) {
    auto* device = g_framework->get_d3d12_hook()->get_device();
    if (!ensure_afw_velocity_decode(device)) {
        return false;
    }
    if (p.velocity == nullptr || p.out_mv == nullptr || p.depth == nullptr ||
        p.velocity->pTexture == nullptr || p.out_mv->pTexture == nullptr ||
        p.velocity->shaderResourceViewHandle.ptr == 0 || p.out_mv->unorderedAccessViewHandle.ptr == 0) {
        return false;
    }
    // Camera motion needs this frame's depth through the plugin's SRV. Without one
    // (or without a depth copy source when the plugin depth is only filled later on
    // the plugin's own list) fall back to object-only vectors.
    const bool depth_usable = p.depth->pTexture != nullptr && p.depth->shaderResourceViewHandle.ptr != 0;
    const bool add_camera = p.add_camera_motion && depth_usable;
    auto* heap = vr->d3d12Renderer->GetViewHeap();
    if (heap == nullptr) {
        return false;
    }

    auto& d = m_afw_velocity_decode;
    const uint32_t slot = d.frame++ % AfwVelocityDecode::kRing;
    auto& ctx = d.cmds[slot];
    if (!ctx.wait(INFINITE) || !ctx.ready()) {
        return false;
    }
    auto* cmd = ctx.cmd_list.Get();

    const auto od = p.out_mv->pTexture->GetDesc();
    AfwVelocityDecodeConstants constants{};
    constants.clip_to_view = p.clip_to_view;
    constants.view_to_world = p.view_to_world;
    constants.prev_world_to_view = p.prev_world_to_view;
    constants.prev_view_to_clip = p.prev_view_to_clip;
    constants.width = (uint32_t)od.Width;
    constants.height = od.Height;
    constants.scale_x = p.scale_x;
    constants.scale_y = p.scale_y;
    constants.add_camera_motion = add_camera ? 1u : 0u;
    memcpy(d.cb_mapped[slot], &constants, sizeof(constants));

    // Flat3D depth-source fallback: the plugin's per-eye depth is normally filled
    // on the plugin's list, which executes after us. Copy this frame's depth in
    // here first so the camera reprojection and the warp both see it.
    if (add_camera && p.depth_copy_src != nullptr && p.depth_copy_src != p.depth->pTexture) {
        D3D12_RESOURCE_BARRIER pre[2]{};
        pre[0].Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        pre[0].Transition.pResource = p.depth_copy_src;
        pre[0].Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        pre[0].Transition.StateBefore = p.depth_copy_src_state;
        pre[0].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_SOURCE;
        pre[1] = pre[0];
        pre[1].Transition.pResource = p.depth->pTexture;
        pre[1].Transition.StateBefore = D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE;
        pre[1].Transition.StateAfter = D3D12_RESOURCE_STATE_COPY_DEST;
        cmd->ResourceBarrier(2, pre);
        cmd->CopyResource(p.depth->pTexture, p.depth_copy_src);
        D3D12_RESOURCE_BARRIER post[2]{pre[0], pre[1]};
        std::swap(post[0].Transition.StateBefore, post[0].Transition.StateAfter);
        std::swap(post[1].Transition.StateBefore, post[1].Transition.StateAfter);
        cmd->ResourceBarrier(2, post);
    }

    // The plugin keeps its MV buffer in ALL_SHADER_RESOURCE at rest (its own
    // CreateTexture initial state); the velocity and depth copies rest there too,
    // which includes the NON_PIXEL_SHADER_RESOURCE bit a compute SRV read needs.
    D3D12_RESOURCE_BARRIER to_uav{};
    to_uav.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    to_uav.Transition.pResource = p.out_mv->pTexture;
    to_uav.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    to_uav.Transition.StateBefore = D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE;
    to_uav.Transition.StateAfter = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
    cmd->ResourceBarrier(1, &to_uav);

    ID3D12DescriptorHeap* heaps[] = { heap };
    cmd->SetDescriptorHeaps(1, heaps);
    cmd->SetComputeRootSignature(d.root_sig.Get());
    cmd->SetPipelineState(d.pso.Get());
    cmd->SetComputeRootConstantBufferView(0, d.cb[slot]->GetGPUVirtualAddress());
    cmd->SetComputeRootDescriptorTable(1, p.velocity->shaderResourceViewHandle);
    // The depth table must be bound even when unused; the velocity SRV is a valid stand-in.
    cmd->SetComputeRootDescriptorTable(2, depth_usable ? p.depth->shaderResourceViewHandle : p.velocity->shaderResourceViewHandle);
    cmd->SetComputeRootDescriptorTable(3, p.out_mv->unorderedAccessViewHandle);
    cmd->Dispatch((constants.width + 7) / 8, (constants.height + 7) / 8, 1);

    D3D12_RESOURCE_BARRIER back = to_uav;
    back.Transition.StateBefore = D3D12_RESOURCE_STATE_UNORDERED_ACCESS;
    back.Transition.StateAfter = D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE;
    cmd->ResourceBarrier(1, &back);

    ctx.has_commands = true;
    ctx.execute();
    return !ctx.last_close_failed && !ctx.poisoned;
}

ID3D12Resource* D3D12Component::run_flat3d_framewarp(
    VR* vr,
    ID3D12Resource* double_wide,
    uint32_t eye_w, uint32_t eye_h,
    DXGI_FORMAT eye_format,
    DXGI_FORMAT backbuffer_format,
    bool extreme,
    uint32_t backbuffer_index,
    ID3D12Resource* fallback_depth,
    D3D12_RESOURCE_STATES fallback_depth_state)
{
    // State trace: log only on transitions so the log shows when the warp
    // actually engages vs falls back to plain AFR (and why).
    static int s_afw_state = -1;
    const auto trace = [](int state, const char* what) {
        if (s_afw_state != state) {
            s_afw_state = state;
            spdlog::info("[Flat3D][AFW] {}", what);
        }
    };

    // Only once AFW has engaged (post-warmup, DX12) and the real plugin device is
    // live. The dummy PDAFWPlugin returns a null renderer from InitDevice, so this
    // stays a no-op and the caller falls back to plain AFR (stale-eye reuse).
    if (!vr->is_using_afw() || double_wide == nullptr) {
        trace(1, "warp idle (warmup / resolution-change window)");
        return nullptr;
    }
    if (vr->d3d12Renderer == nullptr) {
        trace(2, "warp unavailable: real PDAFWPlugin.dll not loaded - plain AFR fallback");
        return nullptr;
    }

    const EyeIndex nEye = (vr->m_render_frame_count % 2 == vr->m_left_eye_interval) ? EyeLeft : EyeRight;
    const EyeIndex nEyeOther = (nEye == EyeLeft) ? EyeRight : EyeLeft;

    // The plugin creates its eye buffers AND their SRV/UAV/RTV views directly
    // from the format we hand it. UE's double-wide is often a *_TYPELESS
    // format (Hogwarts: B8G8R8A8_TYPELESS) — views created off a typeless
    // format are invalid/undefined, which corrupts the warp output. Hand the
    // plugin the typed equivalent; Crop's CopyTextureRegion stays legal (same
    // format family). PureDark's own path always passes a concrete swapchain
    // format here.
    const auto typed_eye_format = [](DXGI_FORMAT f) {
        switch (f) {
        case DXGI_FORMAT_R8G8B8A8_TYPELESS:     return DXGI_FORMAT_R8G8B8A8_UNORM;
        case DXGI_FORMAT_B8G8R8A8_TYPELESS:     return DXGI_FORMAT_B8G8R8A8_UNORM;
        case DXGI_FORMAT_B8G8R8X8_TYPELESS:     return DXGI_FORMAT_B8G8R8X8_UNORM;
        case DXGI_FORMAT_R10G10B10A2_TYPELESS:  return DXGI_FORMAT_R10G10B10A2_UNORM;
        case DXGI_FORMAT_R16G16B16A16_TYPELESS: return DXGI_FORMAT_R16G16B16A16_FLOAT;
        default:                                return f;
        }
    }(eye_format);

    // (Re)allocate the plugin-owned per-eye framebuffers at the Flat3D eye extent
    // (NOT hmd dims — see the OpenXR setup()'s InitFrameWarp block, which uses
    // get_hmd_width/height). Only re-init on a size/format change.
    static uint32_t s_last_w = 0, s_last_h = 0;
    static DXGI_FORMAT s_last_eye_fmt = DXGI_FORMAT_UNKNOWN;
    static DXGI_FORMAT s_last_bb_fmt = DXGI_FORMAT_UNKNOWN;
    if (s_last_w != eye_w || s_last_h != eye_h || s_last_eye_fmt != typed_eye_format || s_last_bb_fmt != backbuffer_format) {
        FrameWarpInitParams ip{ (int)eye_w, (int)eye_h, typed_eye_format, backbuffer_format };
        m_eyeFrameBuffers = InitFrameWarp(ip);
        s_last_w = eye_w; s_last_h = eye_h; s_last_eye_fmt = typed_eye_format; s_last_bb_fmt = backbuffer_format;
        SPDLOG_INFO("[Flat3D][AFW] InitFrameWarp {}x{} eyeFmt={} (raw {}) bbFmt={}",
            eye_w, eye_h, (uint32_t)typed_eye_format, (uint32_t)eye_format, (uint32_t)backbuffer_format);
    }

    auto& eyeFB = m_eyeFrameBuffers.eyeFrameBuffers[nEye];
    auto& otherFB = m_eyeFrameBuffers.eyeFrameBuffers[nEyeOther];
    if (eyeFB.color.pTexture == nullptr || otherFB.color.pTexture == nullptr) {
        trace(3, "warp unavailable: plugin eye framebuffers not allocated - plain AFR fallback");
        return nullptr; // plugin didn't allocate (dummy / init failed)
    }

    // Seed the depth SIZE from the engine pool if the harvest hasn't set rawDepthTex
    // yet (mirrors on_frame). The harvest hooks fill the CONTENT; this only sizes the
    // depthDesc/motionVectorsDesc copies the plugin samples.
    if (!vr->rawDepthTex) {
        if (auto& rt_pool = vr->get_render_target_pool_hook(); rt_pool != nullptr) {
            if (auto seed = rt_pool->get_texture<ID3D12Resource>(L"SceneDepthZ"); seed) {
                vr->rawDepthTex = seed.Get();
            }
        }
    }

    // Allocate depthDesc / motionVectorsDesc (mirror on_frame). depth sized to
    // rawDepthTex; MV to rawMotionVectorsTex, else an R16G16_FLOAT placeholder.
    if (vr->rawDepthTex) {
        const auto d = vr->rawDepthTex->GetDesc();
        for (int i = 0; i < 2; ++i) {
            if (vr->depthDesc[i].pTexture == nullptr ||
                vr->depthDesc[i].pTexture->GetDesc().Width != d.Width ||
                vr->depthDesc[i].pTexture->GetDesc().Height != d.Height) {
                vr->d3d12Renderer->CreateTexture((int)d.Width, (int)d.Height, d.Format,
                    D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE, vr->depthDesc[i], true);
            }
        }
        if (!vr->rawMotionVectorsTex) {
            for (int i = 0; i < 2; ++i) {
                if (vr->motionVectorsDesc[i].pTexture == nullptr ||
                    vr->motionVectorsDesc[i].pTexture->GetDesc().Width != d.Width ||
                    vr->motionVectorsDesc[i].pTexture->GetDesc().Height != d.Height) {
                    vr->d3d12Renderer->CreateTexture((int)d.Width, (int)d.Height, DXGI_FORMAT_R16G16_FLOAT,
                        D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE, vr->motionVectorsDesc[i], true);
                }
            }
        }
    }
    if (vr->rawMotionVectorsTex) {
        const auto d = vr->rawMotionVectorsTex->GetDesc();
        for (int i = 0; i < 2; ++i) {
            if (vr->motionVectorsDesc[i].pTexture == nullptr ||
                vr->motionVectorsDesc[i].pTexture->GetDesc().Width != d.Width ||
                vr->motionVectorsDesc[i].pTexture->GetDesc().Height != d.Height) {
                vr->d3d12Renderer->CreateTexture((int)d.Width, (int)d.Height, DXGI_FORMAT_R16G16_FLOAT,
                    D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE, vr->motionVectorsDesc[i], true);
            }
        }
    }

    // AFW without DLSS. Neither harvest path (NGX hook, NeverDLSS stencil-clear
    // heuristic) copied depth for this eye this frame, but the compositor resolved
    // this frame's scene depth from the Flat3D depth source (DSV Observer / Engine
    // Pool / Per-Draw). That is the same reverse-Z scene depth DLSS would be fed,
    // so size the plugin's per-eye depth buffer to it and copy it in below, on the
    // plugin's command list. The zeroed motion-vector placeholder stays: Alternate
    // Eye Warping reprojects the same frame's other eye from depth alone.
    const bool depth_fed_this_frame = vr->afw_depth_fed_frame[nEye] == (uint32_t)vr->m_render_frame_count;
    bool use_fallback_depth = false;
    if (!depth_fed_this_frame && fallback_depth != nullptr) {
        const auto fd = fallback_depth->GetDesc();
        if (fd.Width > 0 && fd.Height > 0) {
            if (vr->depthDesc[nEye].pTexture == nullptr ||
                vr->depthDesc[nEye].pTexture->GetDesc().Width != fd.Width ||
                vr->depthDesc[nEye].pTexture->GetDesc().Height != fd.Height ||
                vr->depthDesc[nEye].pTexture->GetDesc().Format != fd.Format) {
                vr->d3d12Renderer->CreateTexture((int)fd.Width, (int)fd.Height, fd.Format,
                    D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE, vr->depthDesc[nEye], true);
                SPDLOG_INFO("[Flat3D][AFW] depth buffer for eye {} sized to the Flat3D depth source: {}x{} fmt={}",
                    (int)nEye, (uint32_t)fd.Width, fd.Height, (uint32_t)fd.Format);
            }
            if (!vr->rawMotionVectorsTex) {
                if (vr->motionVectorsDesc[nEye].pTexture == nullptr ||
                    vr->motionVectorsDesc[nEye].pTexture->GetDesc().Width != fd.Width ||
                    vr->motionVectorsDesc[nEye].pTexture->GetDesc().Height != fd.Height) {
                    vr->d3d12Renderer->CreateTexture((int)fd.Width, (int)fd.Height, DXGI_FORMAT_R16G16_FLOAT,
                        D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE, vr->motionVectorsDesc[nEye], true);
                }
            }
            if (vr->renderSize[0] != fd.Width || vr->renderSize[1] != fd.Height) {
                vr->renderSize[0] = (UINT)fd.Width;
                vr->renderSize[1] = fd.Height;
            }
            use_fallback_depth = vr->depthDesc[nEye].pTexture != nullptr;
        }
    }

    // Don't warp against garbage: require depth for this eye. Until a harvest
    // path or the Flat3D depth source produces it, fall back to plain AFR.
    if (vr->depthDesc[nEye].pTexture == nullptr || (!depth_fed_this_frame && !use_fallback_depth)) {
        trace(4, "warp waiting for depth: no DLSS/raw harvest this frame and no Flat3D depth-source snapshot - plain AFR fallback");
        return nullptr;
    }

    // Camera matrices src(current eye)->dest(other eye). Rate-limited internally.
    vr->update_camera_data(vr->m_render_frame_count);

    // Wrap the engine double-wide as a plugin TextureDesc. The compositor keeps it
    // in RENDER_TARGET (kEngineSrcColor), or PRESENT under extreme-compat; Crop
    // transitions to COPY_SOURCE and restores it before the compositor reads it.
    static TextureDesc s_dwDesc[8];
    const uint32_t di = backbuffer_index % 8;
    if (s_dwDesc[di].pTexture != double_wide) {
        s_dwDesc[di] = TextureDesc{};
        s_dwDesc[di].pTexture = double_wide;
        s_dwDesc[di].initialState = extreme ? D3D12_RESOURCE_STATE_PRESENT : D3D12_RESOURCE_STATE_RENDER_TARGET;
        vr->d3d12Renderer->SetupTextureDesc(s_dwDesc[di]);
    }

    auto* cmdList = vr->d3d12Renderer->BeginCommandList((int)backbuffer_index);

    // Per-object vectors with camera motion need this frame's depth BEFORE the
    // plugin's list runs, so in that case the decode pass copies the fallback depth
    // itself (same copy, earlier on the queue) and the plugin copy below is skipped.
    bool depth_copied_by_decode = false;

    // AFW without DLSS, motion vectors. Neither the NGX hook nor the raw R16G16F
    // harvest copied motion vectors for this eye this frame. If the per-object feed
    // is on and the ResourceBarrier hook harvested UE's velocity buffer for this eye,
    // decode it into pixel motion for moving objects (static pixels zero) straight
    // into motionVectorsDesc[nEye] with our own compute pass, executed on the game
    // queue ahead of the plugin's list, and tell the plugin the vectors are
    // ObjectOnly (it supplies the camera motion itself from depth + camera data).
    // Otherwise the zeroed placeholder stays and the warp is depth-only.
    {
        const uint32_t frame = (uint32_t)vr->m_render_frame_count;
        const bool mv_fed_this_frame = vr->afw_mv_fed_frame[nEye] == frame;
        auto& mvDesc = vr->motionVectorsDesc[nEye];
        if (!mv_fed_this_frame && mvDesc.pTexture != nullptr) {
            const bool velocity_this_frame = vr->afw_velocity_fed_frame[nEye] == frame && vr->rawVelocityDesc[nEye].pTexture != nullptr;
            static bool s_pool_census_done = false;
            if (vr->is_afw_velocity_feed_enabled() && velocity_this_frame) {
                static bool s_logged[2]{false, false};
                // Vector type the plugin will be told (mirrors the selection below):
                // ObjectOnly only when the user picks it; otherwise Normal (same eye's
                // last frame) while the ghosting fix is active, else FromOtherEye
                // (the other eye's last render), with camera motion baked in.
                const int type_override = vr->m_afw_mv_type->value();
                const bool object_only = type_override == 3;
                const bool normal_type = type_override == 1 || (type_override == 0 && vr->is_ghosting_fix_active());
                AfwVelocityDecodeParams dp{};
                dp.velocity = &vr->rawVelocityDesc[nEye];
                dp.out_mv = &mvDesc;
                dp.depth = &vr->depthDesc[nEye];
                if (use_fallback_depth) {
                    dp.depth_copy_src = fallback_depth;
                    dp.depth_copy_src_state = fallback_depth_state;
                }
                dp.clip_to_view = vr->cameraData[nEye].srcClipToViewMatrix;
                dp.view_to_world = vr->cameraData[nEye].srcViewToWorldMatrix;
                if (normal_type) {
                    dp.prev_world_to_view = vr->cameraDataForMV[nEye].srcWorldToViewMatrixPrev;
                    dp.prev_view_to_clip = vr->cameraDataForMV[nEye].srcViewToClipMatrixPrev;
                } else {
                    dp.prev_world_to_view = vr->cameraDataForMV[nEye].destWorldToViewMatrix;
                    dp.prev_view_to_clip = vr->cameraDataForMV[nEye].destViewToClipMatrix;
                }
                dp.add_camera_motion = !object_only;
                dp.scale_x = vr->m_afw_velocity_mv_scale_x->value();
                dp.scale_y = vr->m_afw_velocity_mv_scale_y->value();
                if (run_afw_velocity_decode(vr, dp)) {
                    vr->mvScale[0] = 1.0f; // the decode writes pixels at the MV buffer's resolution
                    vr->mvScale[1] = 1.0f;
                    vr->afw_mv_fed_frame[nEye] = frame;
                    vr->afw_mv_feed.store(VR::AFW_MV_FEED_UE_VELOCITY, std::memory_order_relaxed);
                    if (dp.add_camera_motion && use_fallback_depth) {
                        depth_copied_by_decode = true;
                        vr->afw_depth_fed_frame[nEye] = frame;
                        vr->afw_depth_feed.store(VR::AFW_DEPTH_FEED_FLAT3D, std::memory_order_relaxed);
                    }
                    if (!s_logged[nEye]) {
                        s_logged[nEye] = true;
                        const auto vd = vr->rawVelocityDesc[nEye].pTexture->GetDesc();
                        const auto md = mvDesc.pTexture->GetDesc();
                        SPDLOG_INFO("[Flat3D][AFW] per-object motion vectors for eye {}: UE velocity {}x{} fmt={} decoded into {}x{} fmt={} ({})",
                            (int)nEye, (uint32_t)vd.Width, vd.Height, (uint32_t)vd.Format, (uint32_t)md.Width, md.Height, (uint32_t)md.Format,
                            object_only ? "ObjectOnly" : normal_type ? "Normal + camera motion" : "FromOtherEye + camera motion");
                    }
                }
            } else {
                // Nothing fed within the last pair of frames: report the zero placeholder.
                if (frame - vr->afw_mv_fed_frame[nEyeOther] > 2) {
                    vr->afw_mv_feed.store(VR::AFW_MV_FEED_NONE, std::memory_order_relaxed);
                }
                // One-time census of the engine's pooled render-target names that look
                // like velocity / motion buffers, to pick a by-name source if the barrier
                // heuristic never finds UE's velocity buffer in this title.
                if (!s_pool_census_done && frame > 300 && vr->is_afw_velocity_feed_enabled() && !velocity_this_frame) {
                    s_pool_census_done = true;
                    if (auto& rt_pool = vr->get_render_target_pool_hook(); rt_pool != nullptr) {
                        std::string hits{};
                        for (const auto& n : rt_pool->snapshot_render_target_names()) {
                            std::wstring lower = n;
                            for (auto& c : lower) c = (wchar_t)towlower(c);
                            if (lower.find(L"velocity") != std::wstring::npos || lower.find(L"motion") != std::wstring::npos) {
                                hits += utility::narrow(n) + ", ";
                            }
                        }
                        SPDLOG_INFO("[Flat3D][AFW] no UE velocity harvested yet; pooled render targets named like velocity/motion: {}",
                            hits.empty() ? std::string{"(none)"} : hits);
                    }
                }
            }
        }
    }

    if (use_fallback_depth && !depth_copied_by_decode) {
        // The source rests in fallback_depth_state (observer snapshot: PSR|NPSR;
        // engine pool: DEPTH_READ|PSR|NPSR); the plugin's Copy transitions it to
        // COPY_SOURCE and back around the copy, exactly as the NGX path does for
        // the DLSS input depth.
        TextureDesc src{};
        src.pTexture = fallback_depth;
        src.initialState = fallback_depth_state;
        vr->d3d12Renderer->Copy(cmdList, vr->depthDesc[nEye], src);
        vr->afw_depth_fed_frame[nEye] = (uint32_t)vr->m_render_frame_count;
        vr->afw_depth_feed.store(VR::AFW_DEPTH_FEED_FLAT3D, std::memory_order_relaxed);
    }

    // Crop the freshly-rendered eye (left half of the double-wide) into the plugin's
    // current-eye color buffer.
    D3D12_BOX src_box{ 0, 0, 0, eye_w, eye_h, 1 };
    vr->d3d12Renderer->Crop(cmdList, eyeFB.color, s_dwDesc[di], src_box);

    static FrameBufferDesc s_in{};
    s_in.color = eyeFB.color;
    s_in.depth = vr->depthDesc[nEye];
    s_in.motionVectors = vr->motionVectorsDesc[nEye];

    FrameWarpEvaluateParams p{};
    p.InCmdList = cmdList;
    p.InEyeFrameBuffer = &s_in;
    p.InUIColorAlpha = nullptr;
    p.IsHudlessColor = true;
    // Normal only when each eye really owns a scene history (ghosting fix ACTIVE);
    // in remap-only mode the previous frame still belongs to the other eye. The
    // per-object decode bakes the matching camera motion into its vectors, so the
    // same selection applies whether or not vectors were fed this frame.
    MVType mv_type = vr->is_ghosting_fix_active() ? Normal : FromOtherEye;
    switch (vr->m_afw_mv_type->value()) {
    case 1: mv_type = Normal; break;
    case 2: mv_type = FromOtherEye; break;
    case 3: mv_type = ObjectOnly; break;
    default: break;
    }
    p.MotionVectorsType = mv_type;
    p.InMotionScale[0] = vr->mvScale[0];
    p.InMotionScale[1] = vr->mvScale[1];
    p.Mode = (FrameWarpMode)vr->m_framewarp_mode->value();
    p.EyeIndex = nEye;
    p.ClearBeforeWarping = vr->m_clear_before_framewarp->value();
    p.CameraData = &vr->cameraData[nEye];
    p.IgnoreMotionThreshold = vr->m_ignore_motion_threshold->value();
    p.Debug = vr->m_framewarp_debug->value();
    if (vr->is_fix_object_motion_vector() && vr->is_fix_moving_object_brightness_flickering() &&
        (vr->is_ghosting_fix_enabled() || vr->afw_velocity_fed_frame[nEye] == (uint32_t)vr->m_render_frame_count) &&
        vr->rawVelocityDesc[nEye].pTexture != nullptr) {
        p.InUEVelocityBuffer = &vr->rawVelocityDesc[nEye];
    }
    p.UseUINT64 = vr->is_use_uint64();
    EvaluateFrameWarp(p);

    vr->d3d12Renderer->EndCommandList((int)backbuffer_index);

    trace(0, "warp ENGAGED - reprojecting the second eye from depth + motion vectors");

    // The plugin reprojected into the OTHER eye's buffer, left in ALL_SHADER_RESOURCE.
    return otherFB.color.pTexture;
}

// SND diag5 (logging only): which GPU commands put the double-wide scene into
// the redirected Slate UI target. Shared ID3D12 vtable slots are pointer-hooked
// (originals saved first, chained like GameDepthCapture). Idle cost is one
// atomic load per call; every ~20 s, for 3 presents, the commands that touch
// the UI target or the scene render target are recorded in order per command
// list and then logged. Installed only for StupidNeverDies.exe.
namespace snd_trace {
using PFN_CreateRTV = void(STDMETHODCALLTYPE*)(ID3D12Device*, ID3D12Resource*, const D3D12_RENDER_TARGET_VIEW_DESC*, D3D12_CPU_DESCRIPTOR_HANDLE);
using PFN_OMSetRTs = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, const D3D12_CPU_DESCRIPTOR_HANDLE*, BOOL, const D3D12_CPU_DESCRIPTOR_HANDLE*);
using PFN_BeginRP = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, const D3D12_RENDER_PASS_RENDER_TARGET_DESC*, const D3D12_RENDER_PASS_DEPTH_STENCIL_DESC*, D3D12_RENDER_PASS_FLAGS);
using PFN_Barrier = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, const D3D12_RESOURCE_BARRIER*);
using PFN_SetPSO = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, ID3D12PipelineState*);
using PFN_SetVP = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, const D3D12_VIEWPORT*);
using PFN_Draw = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, UINT, UINT, UINT);
using PFN_DrawIdx = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, UINT, UINT, UINT, INT, UINT);
using PFN_ClearRTV = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, D3D12_CPU_DESCRIPTOR_HANDLE, const FLOAT[4], UINT, const D3D12_RECT*);
using PFN_CopyRegion = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, const D3D12_TEXTURE_COPY_LOCATION*, UINT, UINT, UINT, const D3D12_TEXTURE_COPY_LOCATION*, const D3D12_BOX*);
using PFN_CopyRes = void(STDMETHODCALLTYPE*)(ID3D12GraphicsCommandList*, ID3D12Resource*, ID3D12Resource*);

// Graphics command list vtable slots (base interfaces; same as GameDepthCapture).
constexpr size_t kDraw = 12, kDrawIdx = 13, kCopyRegion = 16, kCopyRes = 17, kSetVP = 21, kSetPSO = 25,
                 kBarrier = 26, kOMSetRTs = 46, kClearRTV = 48, kBeginRP = 68;
constexpr size_t kDevCreateRTV = 20;

std::atomic<void*> o_create_rtv{}, o_om{}, o_rp{}, o_barrier{}, o_pso{}, o_vp{}, o_draw{}, o_draw_idx{},
    o_clear{}, o_copy_region{}, o_copy_res{};
std::vector<std::unique_ptr<PointerHook>> g_hooks{};
bool g_install_attempted{};

std::atomic_bool g_active{};
std::atomic<ID3D12Resource*> g_ui{}, g_dw{};

struct ListState {
    ID3D12Resource* rt0{};
    void* pso{};
    float vp_w{}, vp_h{};
    std::vector<std::string> events{};
};
std::mutex g_mx{};
std::unordered_map<uint64_t, ID3D12Resource*> g_rtv{}; // RTV CPU handle -> resource (always kept)
std::unordered_map<void*, ListState> g_lists{};        // only while tracing
bool g_dw_readable{};                                  // last seen dw transition targets a shader-read state
uint32_t g_trace_index{};
uint32_t g_events_total{};
constexpr uint32_t kMaxEventsPerTrace = 600;

const char* kind(ID3D12Resource* r) {
    if (r == nullptr) { return "null"; }
    if (r == g_ui.load(std::memory_order_relaxed)) { return "UI"; }
    if (r == g_dw.load(std::memory_order_relaxed)) { return "SCENE"; }
    return "other";
}

std::string describe(ID3D12Resource* r) {
    if (r == nullptr) { return "null"; }
    const auto d = r->GetDesc();
    return fmt::format("{}({}x{} fmt={})", kind(r), d.Width, d.Height, (uint32_t)d.Format);
}

// Caller holds g_mx.
void add_event(void* list, std::string text) {
    if (g_events_total >= kMaxEventsPerTrace) { return; }
    ++g_events_total;
    g_lists[list].events.push_back(std::move(text));
}

void STDMETHODCALLTYPE create_rtv(ID3D12Device* self, ID3D12Resource* r, const D3D12_RENDER_TARGET_VIEW_DESC* d, D3D12_CPU_DESCRIPTOR_HANDLE h) {
    reinterpret_cast<PFN_CreateRTV>(o_create_rtv.load(std::memory_order_relaxed))(self, r, d, h);
    std::scoped_lock _{g_mx};
    if (g_rtv.size() > 200000) { g_rtv.clear(); }
    g_rtv[h.ptr] = r;
}

ID3D12Resource* rtv_resource(uint64_t ptr) {
    const auto it = g_rtv.find(ptr);
    return it != g_rtv.end() ? it->second : nullptr;
}

void bind_rt(ID3D12GraphicsCommandList* list, ID3D12Resource* rt, const char* via) {
    auto& st = g_lists[list];
    const bool interesting = rt != nullptr && (rt == g_ui.load() || rt == g_dw.load());
    const bool was_interesting = st.rt0 != nullptr && (st.rt0 == g_ui.load() || st.rt0 == g_dw.load());
    st.rt0 = rt;
    if (interesting || was_interesting) {
        add_event(list, fmt::format("{} RT0={}", via, describe(rt)));
    }
}

void STDMETHODCALLTYPE om_set(ID3D12GraphicsCommandList* self, UINT n, const D3D12_CPU_DESCRIPTOR_HANDLE* rts, BOOL single, const D3D12_CPU_DESCRIPTOR_HANDLE* ds) {
    if (g_active.load(std::memory_order_relaxed)) {
        std::scoped_lock _{g_mx};
        bind_rt(self, n > 0 && rts != nullptr ? rtv_resource(rts[0].ptr) : nullptr, "OMSetRenderTargets");
    }
    reinterpret_cast<PFN_OMSetRTs>(o_om.load(std::memory_order_relaxed))(self, n, rts, single, ds);
}

void STDMETHODCALLTYPE begin_rp(ID3D12GraphicsCommandList* self, UINT n, const D3D12_RENDER_PASS_RENDER_TARGET_DESC* rts,
                                const D3D12_RENDER_PASS_DEPTH_STENCIL_DESC* ds, D3D12_RENDER_PASS_FLAGS f) {
    if (g_active.load(std::memory_order_relaxed)) {
        std::scoped_lock _{g_mx};
        bind_rt(self, n > 0 && rts != nullptr ? rtv_resource(rts[0].cpuDescriptor.ptr) : nullptr, "BeginRenderPass");
    }
    reinterpret_cast<PFN_BeginRP>(o_rp.load(std::memory_order_relaxed))(self, n, rts, ds, f);
}

void STDMETHODCALLTYPE barrier(ID3D12GraphicsCommandList* self, UINT n, const D3D12_RESOURCE_BARRIER* b) {
    if (g_active.load(std::memory_order_relaxed) && b != nullptr) {
        std::scoped_lock _{g_mx};
        for (UINT i = 0; i < n; ++i) {
            if (b[i].Type != D3D12_RESOURCE_BARRIER_TYPE_TRANSITION) { continue; }
            auto* r = b[i].Transition.pResource;
            if (r == nullptr || (r != g_ui.load() && r != g_dw.load())) { continue; }
            if (r == g_dw.load()) {
                g_dw_readable = (b[i].Transition.StateAfter &
                    (D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE | D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE)) != 0;
            }
            add_event(self, fmt::format("Barrier {} 0x{:x} -> 0x{:x} sub={}", kind(r),
                (uint32_t)b[i].Transition.StateBefore, (uint32_t)b[i].Transition.StateAfter, b[i].Transition.Subresource));
        }
    }
    reinterpret_cast<PFN_Barrier>(o_barrier.load(std::memory_order_relaxed))(self, n, b);
}

void STDMETHODCALLTYPE set_pso(ID3D12GraphicsCommandList* self, ID3D12PipelineState* p) {
    if (g_active.load(std::memory_order_relaxed)) {
        std::scoped_lock _{g_mx};
        g_lists[self].pso = p;
    }
    reinterpret_cast<PFN_SetPSO>(o_pso.load(std::memory_order_relaxed))(self, p);
}

void STDMETHODCALLTYPE set_vp(ID3D12GraphicsCommandList* self, UINT n, const D3D12_VIEWPORT* v) {
    if (g_active.load(std::memory_order_relaxed) && n > 0 && v != nullptr) {
        std::scoped_lock _{g_mx};
        auto& st = g_lists[self];
        st.vp_w = v[0].Width;
        st.vp_h = v[0].Height;
    }
    reinterpret_cast<PFN_SetVP>(o_vp.load(std::memory_order_relaxed))(self, n, v);
}

void note_draw(ID3D12GraphicsCommandList* self, const char* what, UINT count, UINT instances) {
    std::scoped_lock _{g_mx};
    auto& st = g_lists[self];
    if (st.rt0 == nullptr || st.rt0 != g_ui.load()) { return; }
    add_event(self, fmt::format("{} count={} inst={} pso={:x} viewport={:.0f}x{:.0f} scene_readable={}", what, count, instances,
        reinterpret_cast<uintptr_t>(st.pso), st.vp_w, st.vp_h, g_dw_readable));
}

void STDMETHODCALLTYPE draw(ID3D12GraphicsCommandList* self, UINT v, UINT i, UINT sv, UINT si) {
    if (g_active.load(std::memory_order_relaxed)) { note_draw(self, "DrawInstanced", v, i); }
    reinterpret_cast<PFN_Draw>(o_draw.load(std::memory_order_relaxed))(self, v, i, sv, si);
}

void STDMETHODCALLTYPE draw_idx(ID3D12GraphicsCommandList* self, UINT c, UINT i, UINT si, INT bv, UINT sin) {
    if (g_active.load(std::memory_order_relaxed)) { note_draw(self, "DrawIndexedInstanced", c, i); }
    reinterpret_cast<PFN_DrawIdx>(o_draw_idx.load(std::memory_order_relaxed))(self, c, i, si, bv, sin);
}

void STDMETHODCALLTYPE clear_rtv(ID3D12GraphicsCommandList* self, D3D12_CPU_DESCRIPTOR_HANDLE h, const FLOAT c[4], UINT n, const D3D12_RECT* r) {
    if (g_active.load(std::memory_order_relaxed)) {
        std::scoped_lock _{g_mx};
        auto* res = rtv_resource(h.ptr);
        if (res != nullptr && (res == g_ui.load() || res == g_dw.load())) {
            add_event(self, fmt::format("ClearRenderTargetView {} color=({:.2f},{:.2f},{:.2f},{:.2f}) rects={}", kind(res),
                c != nullptr ? c[0] : 0.f, c != nullptr ? c[1] : 0.f, c != nullptr ? c[2] : 0.f, c != nullptr ? c[3] : 0.f, n));
        }
    }
    reinterpret_cast<PFN_ClearRTV>(o_clear.load(std::memory_order_relaxed))(self, h, c, n, r);
}

void STDMETHODCALLTYPE copy_region(ID3D12GraphicsCommandList* self, const D3D12_TEXTURE_COPY_LOCATION* dst, UINT x, UINT y, UINT z,
                                   const D3D12_TEXTURE_COPY_LOCATION* src, const D3D12_BOX* box) {
    if (g_active.load(std::memory_order_relaxed) && dst != nullptr && src != nullptr &&
        (dst->pResource == g_ui.load() || dst->pResource == g_dw.load())) {
        std::scoped_lock _{g_mx};
        add_event(self, fmt::format("CopyTextureRegion dst={} src={} at={},{}", kind(dst->pResource), describe(src->pResource), x, y));
    }
    reinterpret_cast<PFN_CopyRegion>(o_copy_region.load(std::memory_order_relaxed))(self, dst, x, y, z, src, box);
}

void STDMETHODCALLTYPE copy_res(ID3D12GraphicsCommandList* self, ID3D12Resource* dst, ID3D12Resource* src) {
    if (g_active.load(std::memory_order_relaxed) && (dst == g_ui.load() || dst == g_dw.load())) {
        std::scoped_lock _{g_mx};
        add_event(self, fmt::format("CopyResource dst={} src={}", kind(dst), describe(src)));
    }
    reinterpret_cast<PFN_CopyRes>(o_copy_res.load(std::memory_order_relaxed))(self, dst, src);
}

void install(ID3D12Device* device) {
    if (g_install_attempted || device == nullptr) { return; }
    g_install_attempted = true;
    Microsoft::WRL::ComPtr<ID3D12CommandAllocator> alloc{};
    Microsoft::WRL::ComPtr<ID3D12GraphicsCommandList> list{};
    if (FAILED(device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&alloc))) ||
        FAILED(device->CreateCommandList(0, D3D12_COMMAND_LIST_TYPE_DIRECT, alloc.Get(), nullptr, IID_PPV_ARGS(&list)))) {
        spdlog::error("[SND diag5] could not create a probe command list; draw trace not installed");
        return;
    }
    list->Close();
    void** lv = *reinterpret_cast<void***>(list.Get());
    void** dv = *reinterpret_cast<void***>(device);
    const auto hook = [](void** slot, std::atomic<void*>& orig, void* dest) {
        orig.store(*slot, std::memory_order_relaxed);
        g_hooks.push_back(std::make_unique<PointerHook>(slot, dest));
    };
    hook(&dv[kDevCreateRTV], o_create_rtv, reinterpret_cast<void*>(&create_rtv));
    hook(&lv[kOMSetRTs], o_om, reinterpret_cast<void*>(&om_set));
    hook(&lv[kBarrier], o_barrier, reinterpret_cast<void*>(&barrier));
    hook(&lv[kSetPSO], o_pso, reinterpret_cast<void*>(&set_pso));
    hook(&lv[kSetVP], o_vp, reinterpret_cast<void*>(&set_vp));
    hook(&lv[kDraw], o_draw, reinterpret_cast<void*>(&draw));
    hook(&lv[kDrawIdx], o_draw_idx, reinterpret_cast<void*>(&draw_idx));
    hook(&lv[kClearRTV], o_clear, reinterpret_cast<void*>(&clear_rtv));
    hook(&lv[kCopyRegion], o_copy_region, reinterpret_cast<void*>(&copy_region));
    hook(&lv[kCopyRes], o_copy_res, reinterpret_cast<void*>(&copy_res));
    Microsoft::WRL::ComPtr<ID3D12GraphicsCommandList4> list4{};
    if (SUCCEEDED(list.As(&list4)) && list4 != nullptr) {
        hook(&lv[kBeginRP], o_rp, reinterpret_cast<void*>(&begin_rp));
    }
    spdlog::info("[SND diag5] draw trace hooks installed ({} slots); RTVs created before this point are unknown "
                 "until the engine recreates them", g_hooks.size());
}

// Called once per Flat3D present.
void on_present(ID3D12Device* device, ID3D12Resource* scene, ID3D12Resource* ui) {
    install(device);
    if (g_hooks.empty()) { return; }
    static uint64_t s_presents = 0;
    static int s_remaining = 0;
    ++s_presents;
    if (g_active.load()) {
        if (--s_remaining > 0) { return; }
        g_active.store(false);
        std::scoped_lock _{g_mx};
        spdlog::info("[SND diag5][trace#{}] end: {} command lists touched UI/SCENE, {} events{} (RTVs known: {})",
            g_trace_index, g_lists.size(), g_events_total, g_events_total >= kMaxEventsPerTrace ? " (capped)" : "", g_rtv.size());
        for (const auto& [l, st] : g_lists) {
            if (st.events.empty()) { continue; }
            spdlog::info("[SND diag5][trace#{}] list={:x}", g_trace_index, reinterpret_cast<uintptr_t>(l));
            for (size_t i = 0; i < st.events.size(); ++i) {
                spdlog::info("[SND diag5][trace#{}]   {:3} {}", g_trace_index, i, st.events[i]);
            }
        }
        g_lists.clear();
        return;
    }
    // First trace ~10 s in, then every ~20 s, at most 12 traces.
    if (scene == nullptr || ui == nullptr || g_trace_index >= 12 || s_presents < 600 || (s_presents % 1200) != 600) { return; }
    std::scoped_lock _{g_mx};
    g_ui.store(ui);
    g_dw.store(scene);
    g_lists.clear();
    g_events_total = 0;
    g_dw_readable = false;
    ++g_trace_index;
    const auto sd = scene->GetDesc();
    const auto ud = ui->GetDesc();
    spdlog::info("[SND diag5][trace#{}] begin at present {}: SCENE={:x} ({}x{}) UI={:x} ({}x{}), 3 presents",
        g_trace_index, s_presents, reinterpret_cast<uintptr_t>(scene), sd.Width, sd.Height,
        reinterpret_cast<uintptr_t>(ui), ud.Width, ud.Height);
    s_remaining = 3;
    g_active.store(true);
}
} // namespace snd_trace

vr::EVRCompositorError D3D12Component::on_frame_flat3d(VR* vr) {
    auto& hook = g_framework->get_d3d12_hook();

    // Leave the game's vsync alone (interlaced modes need tear-free scanout).

    auto device = hook->get_device();
    auto swapchain = hook->get_swap_chain();

    // SND diag5: install the draw-trace hooks at the first Flat3D present, before
    // the engine creates its UI/scene targets, so their RTVs are seen.
    if (flat3d::snd_diag::enabled()) {
        snd_trace::install(device);
    }

    // DSV-observer depth: snapshot the live scene depth at the API level (no
    // engine hook, sees depth allocated at any time). Only the flat3d on_frame
    // path registers this observer, so there is no contention over the slot.
    // AFW without DLSS feeds the warp from the same source, so keep the observer
    // armed whenever AFW is the rendering method and the source is the observer.
    const bool wants_dsv_depth = vr->flat3d_wants_dsv_depth();
    m_flat3d_depth_observer.set_ue5_rdg_depth_capture_enabled(wants_dsv_depth);
    hook->set_depth_stencil_observer(wants_dsv_depth ? &m_flat3d_depth_observer : nullptr);

    ComPtr<ID3D12Resource> real_backbuffer{};
    if (FAILED(swapchain->GetBuffer(swapchain->GetCurrentBackBufferIndex(), IID_PPV_ARGS(&real_backbuffer))) ||
        real_backbuffer == nullptr) {
        SPDLOG_ERROR_EVERY_N_SEC(1, "[Flat3D] Failed to get real backbuffer");
        return vr::VRCompositorError_None;
    }

    // Extreme compatibility mode suppresses the double-wide: the game renders
    // ONE full-width eye per frame straight into the real backbuffer (AFR is
    // forced) — read the backbuffer itself as the eye source. The eye-cache
    // copy is recorded before the repack write in the same command list.
    const bool extreme = vr->is_extreme_compatibility_mode_enabled();

    ComPtr<ID3D12Resource> double_wide{};

    if (extreme) {
        double_wide = real_backbuffer;
    } else {
        const auto ue4_texture = vr->m_fake_stereo_hook->get_render_target_manager()->get_render_target();

        if (ue4_texture != nullptr) {
            double_wide = (ID3D12Resource*)ue4_texture->get_native_resource();
        }
    }

    if (double_wide == nullptr) {
        SPDLOG_ERROR_EVERY_N_SEC(1, "[Flat3D] No engine render target yet");
        return vr::VRCompositorError_None;
    }

    const auto dw_desc = double_wide->GetDesc();
    const auto bb_desc = real_backbuffer->GetDesc();

    // Single-width source: the whole texture is ONE eye (extreme compat, or the
    // single-view target above). Decided from the texture itself rather than the
    // setting, so the frames right after a mode toggle — where the old
    // double-wide is still live — keep slicing correctly.
    const bool single_width_src =
        extreme || dw_desc.Width <= (uint64_t)vr->get_hmd_width() + 8;
    const auto eye_w = (uint32_t)(single_width_src ? dw_desc.Width : dw_desc.Width / 2);
    const auto eye_h = (uint32_t)dw_desc.Height;

    // The observer selects a DSV/RDG candidate by matching the scene source
    // extent.
    if (wants_dsv_depth) {
        m_flat3d_depth_observer.set_depth_trace_expected_extent((uint32_t)dw_desc.Width, dw_desc.Height);
    }

    if (!m_flat3d_compositor.setup(device, eye_w, eye_h, dw_desc.Format, bb_desc.Format, hook->is_swapchain_pq())) {
        SPDLOG_ERROR_EVERY_N_SEC(1, "[Flat3D] Compositor setup failed");
        return vr::VRCompositorError_None;
    }

    m_last_rendered_frame = vr->m_render_frame_count;

    auto params = vr->build_flat3d_frame_params(eye_w, eye_h);
    params.extreme_backbuffer_src = extreme;

    // VSync Override: force the present interval (consumed one-shot by the
    // present hook, so re-assert every frame). 0 = respect the game.
    if (params.vsync_override == 1) {
        hook->set_next_present_interval(1);
    } else if (params.vsync_override == 3) {
        // Force 1/2: stereo pair rate at half the display refresh, locked to
        // the display. Native stereo presents both eyes per frame (interval
        // 2); the AFR family presents one eye per frame (interval 1, so a pair
        // spans two refreshes). The guard enforces the interval on vblank when
        // DXGI does not block (game window covered by a Katanga consumer).
        const uint32_t interval = vr->is_using_afr() ? 1u : 2u;
        hook->set_next_present_interval(interval);
        hook->set_next_present_vblank_guard(interval, params.refresh_period_ms);
    } else if (params.vsync_override >= 2) {
        // No-Tear Fast: interval 0 with ALLOW_TEARING stripped — flip-model
        // scanout stays tear-free while presents run unthrottled, so both
        // AFR/Synced-Sequential eye frames land every refresh.
        hook->set_next_present_interval(0);
        hook->set_next_present_no_tearing();
    }

    // Native-stereo-fix titles render the RIGHT eye into a dedicated
    // scene-capture target (the double-wide's right half is never written).
    ComPtr<ID3D12Resource> right_eye_src{};
    if (params.native_stereo_layout) {
        const auto scene_capture = vr->m_fake_stereo_hook->get_render_target_manager()->get_scene_capture_render_target();
        if (scene_capture != nullptr) {
            right_eye_src = (ID3D12Resource*)scene_capture->get_native_resource();
        }

        // A stale capture (pre-resolution-change, mid-recreation) renders
        // into a corner of the eye — treat it as missing (stable mono) until
        // its size matches again.
        if (right_eye_src != nullptr) {
            const auto sc_desc = right_eye_src->GetDesc();
            if (sc_desc.Width != eye_w || sc_desc.Height != eye_h) {
                SPDLOG_INFO_EVERY_N_SEC(1, "[Flat3D] Scene capture {}x{} != eye {}x{} — waiting for recreation",
                                        sc_desc.Width, sc_desc.Height, eye_w, eye_h);
                right_eye_src.Reset();
            }
        }
    }

    // Redirected game UI layer (may be null).
    ID3D12Resource* ui_tex = nullptr;
    const auto ui_target = vr->m_fake_stereo_hook->get_render_target_manager()->get_ui_target();

    if (ui_target != nullptr) {
        ui_tex = (ID3D12Resource*)ui_target->get_native_resource();
    }

    // The UI target must match the size the ENGINE draws Slate at — its own
    // requested resolution (the swapchain itself is held at native by the
    // 3D Display output override). After an in-game resolution change the
    // target goes stale and Slate draws cropped; ask the hook to recreate it
    // (once per size — same trigger the HMD paths fire via their
    // UI-swapchain size checks).
    if (ui_tex != nullptr) {
        uint64_t expect_w = bb_desc.Width;
        uint32_t expect_h = bb_desc.Height;

        if (const auto& d3d12_hook = g_framework->get_d3d12_hook(); d3d12_hook != nullptr) {
            if (d3d12_hook->get_engine_believed_width() != 0 && d3d12_hook->get_engine_believed_height() != 0) {
                expect_w = d3d12_hook->get_engine_believed_width();
                expect_h = d3d12_hook->get_engine_believed_height();
            }
        }

        const auto ui_desc = ui_tex->GetDesc();
        if (ui_desc.Width != expect_w || ui_desc.Height != expect_h) {
            static uint64_t last_requested_w = 0;
            static uint32_t last_requested_h = 0;
            if (last_requested_w != expect_w || last_requested_h != expect_h) {
                last_requested_w = expect_w;
                last_requested_h = expect_h;
                spdlog::info("[Flat3D][D3D12] UI target {}x{} != engine viewport {}x{} — requesting recreate",
                             ui_desc.Width, ui_desc.Height, expect_w, expect_h);
                vr->m_fake_stereo_hook->set_should_recreate_textures(true);
            }
            ui_tex = nullptr; // skip the stale layer this frame
        }
    }

    // --- UI aspect / top-left crop -----------------------------------------
    // Each output mode gives each EYE a slice of the backbuffer. The UI overlay
    // is reconciled to that eye so it isn't squished, and under Native Render +
    // Upscale it's sampled from the top-left perceived region (see below).
    {
        const auto m = (flat3d::Flat3DOutputMode)params.mode;
        const bool sbs_like = m == flat3d::Flat3DOutputMode::SBS ||
                              m == flat3d::Flat3DOutputMode::LEIA_SR ||
                              m == flat3d::Flat3DOutputMode::DUAL_DISPLAY ||
                              m == flat3d::Flat3DOutputMode::DUAL_DISPLAY_FLIP;
        const bool tab_like = m == flat3d::Flat3DOutputMode::TAB ||
                              m == flat3d::Flat3DOutputMode::FRAMEPACKED_720P60 ||
                              m == flat3d::Flat3DOutputMode::FRAMEPACKED_1080P24 ||
                              m == flat3d::Flat3DOutputMode::FRAMEPACKED_1080P60;
        const float eye_slice_w = sbs_like ? (float)bb_desc.Width * 0.5f : (float)bb_desc.Width;
        const float eye_slice_h = tab_like ? (float)bb_desc.Height * 0.5f : (float)bb_desc.Height;

        const float scene_aspect = eye_h > 0 ? (float)eye_w / (float)eye_h : 0.0f;

        uint64_t ui_w = 0; uint32_t ui_h = 0; float ui_aspect = 0.0f;
        if (auto* ui_native = (ID3D12Resource*)(vr->m_fake_stereo_hook->get_render_target_manager()->get_ui_target()
                                    ? vr->m_fake_stereo_hook->get_render_target_manager()->get_ui_target()->get_native_resource()
                                    : nullptr)) {
            const auto d = ui_native->GetDesc();
            ui_w = d.Width; ui_h = d.Height;
            ui_aspect = ui_h > 0 ? (float)ui_w / (float)ui_h : 0.0f;
        }

        // Reconcile the UI-target aspect to the EYE-TEXTURE aspect (scene_aspect =
        // eye_w/eye_h) — NOT the output slice. The overlay is drawn into the eye
        // texture (the same surface the scene fills), so the eye aspect is the
        // right reference. Using the slice would wrongly crop packed modes
        // (half-SbS/half-TaB) where the slice is squished and the display
        // stretches it back. crop<1 = cover (central crop), crop>1 = contain
        // (letterbox); when ui_aspect==eye_aspect all modes are a no-op.
        if (params.ui_topleft_crop && ui_w > 0 && ui_h > 0) {
            // Native Render + Upscale: the game/menu draw their UI at the
            // PERCEIVED client size (the client-rect spoof's half-panel width x
            // full height = eye_slice_w x eye_slice_h) into the TOP-LEFT of a
            // full-width target — sample exactly that region from the origin
            // (draw_layer anchors it at 0). NOTE: use the perceived size, NOT the
            // eye RENDER size — a game that renders its scene below native
            // (DLSS/dynamic-res, e.g. Jedi Survivor at 960x540) still draws its
            // UI at the full perceived 1920x1080, so eye_w would crop it too tight.
            const float cx = eye_slice_w / (float)ui_w;
            const float cy = eye_slice_h / (float)ui_h;
            params.ui_crop_x = cx < 1.0f ? cx : 1.0f;
            params.ui_crop_y = cy < 1.0f ? cy : 1.0f;
        } else {
            // Non-full-SbS: ui_aspect ~= eye aspect, so this is a no-op central
            // crop (full-SbS goes through the top-left branch above).
            vrmod::flat3d::compute_ui_aspect_crop(
                0, ui_aspect, scene_aspect, params.ui_crop_x, params.ui_crop_y);
        }
    }

    // SceneDepthZ for the adaptive crosshair / auto-convergence and/or the
    // depth-adaptive HUD mode.
    ComPtr<ID3D12Resource> scene_depth{};

    // State the depth resource sits in outside our copies: UE keeps pooled
    // SceneDepthZ in a depth-read state, while the DSV-observer snapshot is an
    // owned plain copy (no DEPTH_READ capability) parked in PSR|NPSR.
    constexpr auto kPoolDepthState = D3D12_RESOURCE_STATE_DEPTH_READ |
        D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE | D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
    constexpr auto kShaderReadState = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE |
        D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE;
    auto scene_depth_state = kPoolDepthState;

    // AFW without DLSS: the warp needs this frame's scene depth too, so resolve
    // the Flat3D depth source on warp frames even when no depth feature wants it.
    if (params.want_depth || params.hud_depth_mode == 1 || params.warp_frame) {
        switch (vr->flat3d_depth_source()) {
        case VR::FLAT3D_DEPTH_DLSS: {
            // Our own plugin-free snapshot of the DLSS input depth (captured in the
            // NGX EvaluateFeature hook into vr->m_dlss_depth[]). The exact render-res
            // scene depth the game feeds DLSS. Works in any rendering method; stays
            // null until DLSS is active, in which case the depth features hold their
            // last values (same graceful behavior as the other sources).
            const int n_eye = (vr->m_render_frame_count % 2 == vr->m_left_eye_interval) ? 0 : 1;
            auto dlss_depth = vr->get_dlss_depth_copy(n_eye);
            if (dlss_depth == nullptr) {
                dlss_depth = vr->get_dlss_depth_copy(1 - n_eye); // eye-index conventions differ; either is fine
            }
            if (dlss_depth != nullptr) {
                scene_depth = dlss_depth;             // owned copy, reverse-Z device depth
                scene_depth_state = kShaderReadState; // == ALL_SHADER_RESOURCE bits
            }
            break;
        }

        case VR::FLAT3D_DEPTH_DSV_OBSERVER:
            if (wants_dsv_depth) {
                // Owned snapshot from the D3D12Hook DSV/barrier observer. No
                // engine hook (safe where the pool's FindFreeElement hook
                // crashes) and visible even when the game allocated depth once
                // at load. The observer captures one verified window per frame;
                // re-arm after consuming this frame's snapshot.
                scene_depth = m_flat3d_depth_observer.captured_depth_snapshot();
                scene_depth_state = kShaderReadState;
                m_flat3d_depth_observer.request_ue5_rdg_depth_capture();
            }
            break;

        case VR::FLAT3D_DEPTH_ENGINE_POOL:
            // Engine pool: read the game's live SceneDepthZ by name. Because it
            // reads UE's own render-target pool it finds a depth buffer allocated
            // once at load — which the API-level path never observes being created
            // (e.g. SMT5V). The pool's inline FindFreeElement hook installs on the
            // engine tick after activate(), so the first frames may be null.
            if (auto& rt_pool = vr->get_render_target_pool_hook(); rt_pool != nullptr) {
                rt_pool->activate();
                scene_depth = rt_pool->get_texture<ID3D12Resource>(L"SceneDepthZ");
            }
            break;

        default: {
            // API-level per-draw capture: watches the game's own D3D12 rendering
            // and identifies scene depth by per-draw counting, independent of RDG
            // resource names (which shipping titles strip/rename). No engine hook,
            // so it is safe on every title but blind to depth created before our
            // D3D hook installed.
            auto& gdc = GameDepthCapture::get();
            if (auto* dev = g_framework->get_d3d12_hook()->get_device()) {
                gdc.ensure_installed_d3d12(dev);
                uint32_t rw = 0, rh = 0;
                if (double_wide != nullptr) {
                    const auto dwd = double_wide->GetDesc();
                    rw = (uint32_t)dwd.Width;
                    rh = (uint32_t)dwd.Height;
                }
                gdc.end_frame_d3d12(rw, rh);
            }
            scene_depth = gdc.get_native<ID3D12Resource>();
            // Only trust the published depth for the CPU readback if it was
            // selected by real draw attribution. On a loading screen the scene
            // stops rendering and GameDepthCapture falls back to a size-matched
            // registry resource whose live GPU state we cannot know; issuing our
            // COPY_SOURCE barrier against it with the wrong StateBefore fails the
            // command-list Close and used to leave the compositor flickering for
            // the rest of the session. Skip it — auto-convergence / adaptive
            // crosshair simply hold their last values until real depth returns.
            if (scene_depth != nullptr && !gdc.last_publish_via_draws()) {
                scene_depth = nullptr;
            }
            break;
        }
        }
    }

    float center_uu = -1.0f;
    float nearest_uu = -1.0f;
    float ui_coverage = 0.0f;

    // AFW: reproject the freshly-rendered eye into the other eye (DLSS / raw depth +
    // motion vectors). When it runs, the warped eye is handed to the compositor as
    // the discrete second per-eye source (via the right_eye_src argument — free here
    // because AFW and native-stereo-fix are mutually exclusive). On any miss (plugin
    // absent, depth not live yet), warp_frame is cleared and the compositor falls
    // back to plain AFR (stale-eye reuse).
    ID3D12Resource* warped_eye = nullptr; // plugin-owned; borrowed for this frame
    if (params.warp_frame) {
        warped_eye = run_flat3d_framewarp(vr, double_wide.Get(), eye_w, eye_h,
            dw_desc.Format, bb_desc.Format, extreme, swapchain->GetCurrentBackBufferIndex(),
            scene_depth.Get(), scene_depth_state);
        if (warped_eye == nullptr) {
            // Warp unavailable this frame (plugin absent / depth not live yet). The
            // engine still rendered only ONE eye (AFW rides AFR), so fall back to
            // plain AFR: fresh eye from the left half, other eye from the stale
            // cache — NOT both double-wide halves (the right half is garbage here).
            params.warp_frame = false;
            params.afr_frame = true;
        }
    }
    ID3D12Resource* second_eye_src = params.warp_frame ? warped_eye : right_eye_src.Get();

    // UEVR's own ImGui menu: composite it into the eyes at menu depth
    // (Framework skips its flat backbuffer draw when we consumed it).
    ID3D12Resource* menu_tex = g_framework->get_rendertarget_d3d12().Get();

    // 3D screenshot: begin a capture (composite hides the UEVR menu while it
    // runs) the present the hotkey / menu button fired.
    if (vr->get_flat3d_runtime()->screenshot_requested.exchange(false)) {
        m_flat3d_compositor.begin_screenshot();
    }

    // SND diag1 (logging only): the composite's inputs, logged when they change.
    if (flat3d::snd_diag::enabled()) {
        static std::string s_last{};
        static uint32_t s_lines = 0;
        const auto second_desc = second_eye_src != nullptr ? second_eye_src->GetDesc() : D3D12_RESOURCE_DESC{};
        const auto ui_desc = ui_tex != nullptr ? ui_tex->GetDesc() : D3D12_RESOURCE_DESC{};
        const auto& d3d12_hook = g_framework->get_d3d12_hook();
        const auto key = fmt::format(
            "dw={}x{} fmt={} bb={}x{} fmt={} eye={}x{} single_width_src={} hmd={}x{} mode={} afr_frame={} synced_pair={} "
            "native_stereo_layout={} warp_frame={} second={}x{} ui={}x{} engine_believed={}x{} scene_scale={:.3f}",
            dw_desc.Width, dw_desc.Height, (uint32_t)dw_desc.Format, bb_desc.Width, bb_desc.Height, (uint32_t)bb_desc.Format,
            eye_w, eye_h, single_width_src, vr->get_hmd_width(), vr->get_hmd_height(), params.mode, params.afr_frame,
            params.afr_synced_pair, params.native_stereo_layout, params.warp_frame, second_desc.Width, second_desc.Height,
            ui_desc.Width, ui_desc.Height,
            d3d12_hook != nullptr ? d3d12_hook->get_engine_believed_width() : 0,
            d3d12_hook != nullptr ? d3d12_hook->get_engine_believed_height() : 0, params.scene_scale);
        if (key != s_last && s_lines < 500) {
            ++s_lines;
            spdlog::info("[SND diag1][Composite] frame={} {}", vr->m_render_frame_count, key);
        }
        s_last = key;

        snd_trace::on_present(device, double_wide.Get(), ui_tex);
    }

    const bool composited = m_flat3d_compositor.composite(double_wide.Get(), second_eye_src, ui_tex, menu_tex,
                                       real_backbuffer.Get(), (uint32_t)bb_desc.Width, bb_desc.Height, params,
                                       scene_depth.Get(), vr->get_flat3d_runtime()->game_nearz.load(),
                                       &center_uu, &nearest_uu, &ui_coverage, g_framework->get_window(),
                                       scene_depth_state);

    vr->get_flat3d_runtime()->leiasr_crosstalk_controls.store(m_flat3d_compositor.leiasr_crosstalk_controls());

    if (!composited) {
        return vr::VRCompositorError_None;
    }

    vr->get_flat3d_runtime()->ui_coverage.store(ui_coverage);

    if (menu_tex != nullptr) {
        g_framework->set_flat3d_menu_composited(true);
    }

    if (params.want_depth) {
        auto* flat3d = vr->get_flat3d_runtime();
        flat3d->center_depth_uu.store(center_uu);
        if (nearest_uu > 0.0f) {
            flat3d->nearest_depth_uu.store(nearest_uu);
        }
    }

    // Katanga handoff via the D3D11On12 bridge. Uses the composited per-eye
    // D3D12 textures; the local window shows a left-eye preview.
    if (params.mode == (int32_t)flat3d::Flat3DOutputMode::KATANGA) {
        if (m_flat3d_katanga12.ensure(device, hook->get_command_queue(),
                                      m_flat3d_compositor.eye_width(), m_flat3d_compositor.eye_height(),
                                      m_flat3d_compositor.eye_format())) {
            const int l = params.eye_swap ? 1 : 0;
            m_flat3d_katanga12.present(m_flat3d_compositor.eye_texture(l),
                                       m_flat3d_compositor.eye_texture(1 - l));
        }
    }

    // 3D screenshot: once both eyes have been refreshed with the UEVR menu
    // hidden (AFR-correct), save the composited pair — game HUD, crosshair,
    // cursor and convergence, but no UEVR menu — as a parallel-view PNG plus a
    // cross-view companion.
    if (m_flat3d_compositor.screenshot_capture_complete()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const auto dir = fs::path(Framework::get_persistent_dir()) / "flat3d_screenshots";
        fs::create_directories(dir, ec);

        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t stamp[32];
        swprintf_s(stamp, L"%04u%02u%02u_%02u%02u%02u_%03u",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        const auto parallel_path = (dir / (std::wstring(L"sbs_") + stamp + L".png")).wstring();
        const auto crossview_path = (dir / (std::wstring(L"sbs_") + stamp + L"_crossview.png")).wstring();

        if (m_flat3d_compositor.save_screenshot(hook->get_command_queue(), params, parallel_path, crossview_path)) {
            spdlog::info("[Flat3D] Saved 3D screenshot: {}", utility::narrow(parallel_path));
            // Success chime (mirrors VRto3D's BeepSuccess). Detached: Beep()
            // blocks for its full duration and this runs on the present thread.
            std::thread([] { Beep(400, 400); }).detach();
        } else {
            SPDLOG_ERROR_EVERY_N_SEC(1, "[Flat3D] Screenshot save failed");
        }
        m_flat3d_compositor.end_screenshot();
    }

    // Drives the one-time window activation / mouse centering; overlay
    // component post-submit paths early-out for non-OpenVR runtimes.
    vr->m_submitted = true;

    return vr::VRCompositorError_None;
}
} // namespace vrmod
