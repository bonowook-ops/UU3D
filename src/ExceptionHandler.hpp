#pragma once

#include <windows.h>
#include <string_view>

namespace framework {
LONG WINAPI global_exception_handler(struct _EXCEPTION_POINTERS* ei);
void setup_exception_handler();

// DllMain calls this on DLL_PROCESS_DETACH, before the C runtime destroys this
// module's static objects. From then on the handlers that stay registered for
// the life of the process (the unhandled exception filter and the vectored
// handlers) pass every exception on untouched: the objects they use may be gone.
void on_module_detach();
bool is_module_detaching();

// Hang diagnostics: suspends every other thread in turn, and logs where each
// one is (RIP as module+offset, plus the module-resident values still on its
// stack). Called from the no-present watchdog in Framework; rate-limited and
// capped internally, so it is safe to call from a polling loop.
void dump_all_thread_stacks(const char* reason);

// --- SW Zero Company diagnostic build (diag1/diag2) --------------------------------
// Observation only, enabled only when the host executable is SWZeroCompany.exe;
// every function below returns immediately for any other game. Writes a raw
// side log (swzc_diag2.txt in the persistent dir) without spdlog, so it keeps
// working if the spdlog lock or the loader lock is what is stuck.
void swzc_diag_init();
bool swzc_diag_enabled();
void swzc_diag_exec_begin(const void* engine, std::wstring_view command, const char* site);
void swzc_diag_exec_end(const char* site);
void swzc_diag_note_unhandled(struct _EXCEPTION_POINTERS* ei);

// diag2: what the SWZC CopyTextureRegionChecked mid-hook saw for one copy and
// which branch it took. Purely a record; the hook's decisions are unchanged.
// Zero means "not known at this branch".
struct SwzcCopyNote {
    const char* verdict;
    unsigned long long box_left, box_top, box_right, box_bottom, box_front, box_back;
    unsigned long long packed_w, packed_h;
    unsigned long long trusted_w, trusted_h;
    unsigned long long src_w, src_h, dst_w, dst_h;
    unsigned long long src_fmt, dst_fmt, src_flags, dst_flags;
    unsigned long long src_depth, dst_depth, src_mips, dst_mips, src_layout, dst_layout, src_samples, dst_samples, src_quality, dst_quality;
    unsigned long long src_res, dst_res;
    int hmd_active;
};
void swzc_diag_note_copy(const SwzcCopyNote& note);

// diag3: D3D12 copy and resource observation for the Flat3D compositor.
// `dst`/`src` are ID3D12Resource*; `box` is a D3D12_BOX* or nullptr (whole
// resource / CopyResource). Logged once per distinct combination, flagged when
// formats differ or the box does not fit. Observation only.
void swzc_diag_note_d3d12_copy(const char* site, void* dst, unsigned dst_x, unsigned dst_y, void* src,
                               const void* box);
void swzc_diag_note_d3d12_resource(const char* site, void* resource);

// Wraps engine->exec(command) with diag markers. Identical behavior: the
// command runs exactly once and nothing is caught here (a try/catch would
// change how an SEH exception unwinds under /EHa); a missing EXEC-END line
// plus the head VEH's record is how an exception through exec shows up.
template <typename Engine>
inline void swzc_diag_exec(Engine* engine, std::wstring_view command, const char* site) {
    swzc_diag_exec_begin(engine, command, site);
    engine->exec(command);
    swzc_diag_exec_end(site);
}
}
