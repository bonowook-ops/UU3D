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

// --- SW Zero Company diagnostic build (diag1) --------------------------------
// Observation only, enabled only when the host executable is SWZeroCompany.exe;
// every function below returns immediately for any other game. Writes a raw
// side log (swzc_diag1.txt in the persistent dir) without spdlog, so it keeps
// working if the spdlog lock or the loader lock is what is stuck.
void swzc_diag_init();
bool swzc_diag_enabled();
void swzc_diag_exec_begin(const void* engine, std::wstring_view command, const char* site);
void swzc_diag_exec_end(const char* site);
void swzc_diag_note_unhandled(struct _EXCEPTION_POINTERS* ei);

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
