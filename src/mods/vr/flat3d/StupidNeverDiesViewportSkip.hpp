#pragma once

// Stupid Never Dies (UE5.4 with a backported RDG Slate renderer), Flat3D only.
//
// In stereo this game's Slate draws the window into the scene render target.
// UU3D routes that Slate output into a dedicated UI target instead, and then
// the game-viewport widget's full-window quad -- the first Slate draw, with a
// pipeline state no other UI element uses -- paints the whole double-wide
// scene, squeezed and opaque, into the UI target. The compositor then lays
// that over each eye, so each eye shows the squeezed double-wide scene.
//
// While the UI target is the bound render target, skip that one draw: the
// first DrawIndexedInstanced(6, 1) of a pass whose pipeline state has never
// been seen on any other draw into the UI target. If an element ever reuses
// that pipeline state it is learned as UI and never skipped again.

#include <d3d12.h>

namespace vrmod::flat3d::snd_viewport_skip {
// True only for StupidNeverDies.exe.
bool enabled();

// Install the D3D12 hooks (once). Call from the Flat3D present path before the
// engine creates its render targets, so their RTVs are seen.
void install(ID3D12Device* device);

// Publish the current UI target (nullptr disables skipping) and emit the
// periodic status line. Call once per Flat3D present.
void on_present(ID3D12Resource* ui_target);
} // namespace vrmod::flat3d::snd_viewport_skip
