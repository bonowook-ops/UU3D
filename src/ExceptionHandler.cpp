#include <windows.h>
#include <DbgHelp.h>
#include <ShlObj.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <atomic>
#include <cwctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <mutex>
#include <string>
#include <unordered_map>
#include <SafetyHook.hpp>
#include <spdlog/spdlog.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/Patch.hpp>
#include <utility/String.hpp>

#include "Framework.hpp"

#include "ExceptionHandler.hpp"

namespace {
// Constant-initialized and trivially destructible, so it stays valid while the
// C runtime destroys the module's other static objects.
std::atomic_bool g_module_detaching{false};
}

void framework::on_module_detach() {
    g_module_detaching.store(true, std::memory_order_release);
}

bool framework::is_module_detaching() {
    return g_module_detaching.load(std::memory_order_acquire);
}

LONG WINAPI framework::global_exception_handler(struct _EXCEPTION_POINTERS* ei) {
    if (is_module_detaching()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // diag1 (SWZeroCompany only): raw line first, in case spdlog is what is stuck.
    framework::swzc_diag_note_unhandled(ei);

    spdlog::flush_on(spdlog::level::err);

    spdlog::error("Exception occurred: {:x}", ei->ExceptionRecord->ExceptionCode);
    spdlog::error("RIP: {:x}", ei->ContextRecord->Rip);
    spdlog::error("RSP: {:x}", ei->ContextRecord->Rsp);
    spdlog::error("RCX: {:x}", ei->ContextRecord->Rcx);
    spdlog::error("RDX: {:x}", ei->ContextRecord->Rdx);
    spdlog::error("R8: {:x}", ei->ContextRecord->R8);
    spdlog::error("R9: {:x}", ei->ContextRecord->R9);
    spdlog::error("R10: {:x}", ei->ContextRecord->R10);
    spdlog::error("R11: {:x}", ei->ContextRecord->R11);
    spdlog::error("R12: {:x}", ei->ContextRecord->R12);
    spdlog::error("R13: {:x}", ei->ContextRecord->R13);
    spdlog::error("R14: {:x}", ei->ContextRecord->R14);
    spdlog::error("R15: {:x}", ei->ContextRecord->R15);
    spdlog::error("RAX: {:x}", ei->ContextRecord->Rax);
    spdlog::error("RBX: {:x}", ei->ContextRecord->Rbx);
    spdlog::error("RBP: {:x}", ei->ContextRecord->Rbp);
    spdlog::error("RSI: {:x}", ei->ContextRecord->Rsi);
    spdlog::error("RDI: {:x}", ei->ContextRecord->Rdi);
    spdlog::error("EFLAGS: {:x}", ei->ContextRecord->EFlags);
    spdlog::error("CS: {:x}", ei->ContextRecord->SegCs);
    spdlog::error("DS: {:x}", ei->ContextRecord->SegDs);
    spdlog::error("ES: {:x}", ei->ContextRecord->SegEs);
    spdlog::error("FS: {:x}", ei->ContextRecord->SegFs);
    spdlog::error("GS: {:x}", ei->ContextRecord->SegGs);
    spdlog::error("SS: {:x}", ei->ContextRecord->SegSs);

    const auto module_within = utility::get_module_within(ei->ContextRecord->Rip);

    if (module_within) {
        const auto module_path = utility::get_module_path(*module_within);

        if (module_path) {
            spdlog::error("Module: {:x} {}", (uintptr_t)*module_within, *module_path);
        } else {
            spdlog::error("Module: Unknown");
        }
    } else {
        spdlog::error("Module: Unknown");
    }

    auto dbghelp = LoadLibrary("dbghelp.dll");

    if (dbghelp) {
        const auto final_path = Framework::get_persistent_dir("crash.dmp").string();

        spdlog::error("Attempting to write dump to {}", final_path);

        auto f = CreateFile(final_path.c_str(), 
            GENERIC_WRITE, 
            FILE_SHARE_WRITE, 
            nullptr, 
            CREATE_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL, 
            nullptr
        );

        if (!f || f == INVALID_HANDLE_VALUE) {  
            spdlog::error("Exception occurred, but could not create dump file");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        MINIDUMP_EXCEPTION_INFORMATION ei_info{
            GetCurrentThreadId(),
            ei,
            FALSE
        };

        auto minidump_write_dump = (decltype(MiniDumpWriteDump)*)GetProcAddress(dbghelp, "MiniDumpWriteDump");

        minidump_write_dump(GetCurrentProcess(), 
            GetCurrentProcessId(),
            f,
            MINIDUMP_TYPE::MiniDumpNormal, 
            &ei_info, 
            nullptr, 
            nullptr
        );

        CloseHandle(f);
    } else {
        spdlog::error("Exception occurred, but could not load dbghelp.dll");
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

// First-chance exception logger. A game's own fatal-error handler can terminate
// the process without our SetUnhandledExceptionFilter ever running, so we log
// every genuine error-class exception (and breakpoints — UE check()/fatal
// reaches here as EXCEPTION_BREAKPOINT via __debugbreak) with the faulting RIP
// (module+offset), registers, and a shallow stack scan, flushed to disk.
// CONTINUE_SEARCH always: this is a pure reporter, zero behavior change.
// Deduped by (RIP,code) so IsBadReadPtr-style probe storms can't flood the log;
// the LAST [FirstChance] entry before the log dies is the fatal one.
static LONG WINAPI first_chance_exception_logger(struct _EXCEPTION_POINTERS* ei) {
    // While the module unloads, the statics below and the logger may already be
    // destroyed; touching them would fault inside this handler, and that fault
    // would come straight back here.
    if (framework::is_module_detaching()) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto code = ei->ExceptionRecord->ExceptionCode;

    switch (code) {
    case 0x406D1388:  // MS-VC SetThreadName
    case 0x40010006:  // DBG_PRINTEXCEPTION_C
    case 0x4001000A:  // DBG_PRINTEXCEPTION_WIDE_C
        return EXCEPTION_CONTINUE_SEARCH;
    default:
        break;
    }

    // error-severity (0xCxxxxxxx), UE fatal RaiseException(1), or breakpoints.
    const bool interesting = (code & 0xF0000000u) == 0xC0000000u || code == 1 || code == EXCEPTION_BREAKPOINT;
    if (!interesting) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static std::mutex log_mtx{};
    static std::unordered_map<uint64_t, uint64_t> seen_counts{};

    std::scoped_lock _{log_mtx};

    const auto rip = ei->ContextRecord->Rip;
    const auto key = (uint64_t)rip ^ ((uint64_t)code << 32);
    const auto count = ++seen_counts[key];

    if (count > 1) {
        if (count <= 4 || (count % 1000) == 0) {
            spdlog::error("[FirstChance] (repeat x{}) code {:x} thread {} RIP {:x}", count, code, GetCurrentThreadId(), rip);
            if (const auto logger = spdlog::default_logger()) { logger->flush(); }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    spdlog::error("[FirstChance] code {:x} thread {} RIP {:x} RSP {:x}", code, GetCurrentThreadId(), rip, ei->ContextRecord->Rsp);

    if (code == EXCEPTION_ACCESS_VIOLATION && ei->ExceptionRecord->NumberParameters >= 2) {
        const char* kind = ei->ExceptionRecord->ExceptionInformation[0] == 0 ? "read"
                         : ei->ExceptionRecord->ExceptionInformation[0] == 1 ? "write" : "execute(DEP)";
        spdlog::error("[FirstChance] AV {} of {:x}", kind, ei->ExceptionRecord->ExceptionInformation[1]);
    }

    if (const auto module_within = utility::get_module_within(rip)) {
        const auto module_path = utility::get_module_path(*module_within);
        spdlog::error("[FirstChance] RIP module: {} + {:x}", module_path.value_or("Unknown"), rip - (uintptr_t)*module_within);
    } else {
        spdlog::error("[FirstChance] RIP module: Unknown");
    }

    spdlog::error("[FirstChance] RAX {:x} RBX {:x} RCX {:x} RDX {:x} RSI {:x} RDI {:x} RBP {:x} R8 {:x} R9 {:x} R10 {:x} R11 {:x} R12 {:x} R13 {:x} R14 {:x} R15 {:x}",
        ei->ContextRecord->Rax, ei->ContextRecord->Rbx, ei->ContextRecord->Rcx, ei->ContextRecord->Rdx,
        ei->ContextRecord->Rsi, ei->ContextRecord->Rdi, ei->ContextRecord->Rbp,
        ei->ContextRecord->R8, ei->ContextRecord->R9, ei->ContextRecord->R10, ei->ContextRecord->R11,
        ei->ContextRecord->R12, ei->ContextRecord->R13, ei->ContextRecord->R14, ei->ContextRecord->R15);

    if (code != EXCEPTION_STACK_OVERFLOW) {
        const auto rsp = ei->ContextRecord->Rsp;
        int logged = 0;
        for (uintptr_t off = 0; off < 0x400 && logged < 12; off += sizeof(uintptr_t)) {
            const auto slot = rsp + off;
            if (IsBadReadPtr((void*)slot, sizeof(uintptr_t))) { break; }
            const auto val = *(uintptr_t*)slot;
            if (const auto mod = utility::get_module_within(val)) {
                const auto path = utility::get_module_path(*mod);
                spdlog::error("[FirstChance] Stack[rsp+{:x}]: {:x} ({} + {:x})", off, val, path.value_or("Unknown"), val - (uintptr_t)*mod);
                ++logged;
            }
        }
    } else {
        // A stack overflow's RIP is wherever the guard page happened to be hit —
        // often inside a lock or an allocator — so a single frame says nothing
        // about WHICH recursion ran away. The used stack ABOVE rsp is committed
        // and safe to read, and a runaway cycle stamps its return addresses into
        // it thousands of times. Count them and print the most frequent: that IS
        // the cycle. Fixed-size table, no heap, no unwinder — this runs on a
        // thread with one page of stack left.
        constexpr uintptr_t scan_bytes = 0x40000; // 256 KiB of already-used stack
        constexpr size_t max_tracked = 24;

        struct Frequent {
            uintptr_t addr{};
            uint32_t count{};
        };

        Frequent tracked[max_tracked]{};
        size_t tracked_count = 0;
        uint32_t matched = 0;
        uintptr_t scanned = 0;
        const auto rsp = ei->ContextRecord->Rsp;

        for (uintptr_t off = 0; off < scan_bytes; off += sizeof(uintptr_t)) {
            const auto slot = rsp + off;

            // Probe once per page instead of once per qword: each failed probe is
            // itself an exception, and 32k of them would take longer than the
            // process has left.
            if ((off & 0xfff) == 0 && IsBadReadPtr((void*)slot, 0x1000)) {
                break;
            }

            scanned = off;
            const auto val = *(uintptr_t*)slot;

            if (val < 0x10000 || !utility::get_module_within(val).has_value()) {
                continue;
            }

            ++matched;
            bool found = false;

            for (size_t i = 0; i < tracked_count; ++i) {
                if (tracked[i].addr == val) {
                    ++tracked[i].count;
                    found = true;
                    break;
                }
            }

            if (!found && tracked_count < max_tracked) {
                tracked[tracked_count].addr = val;
                tracked[tracked_count].count = 1;
                ++tracked_count;
            }
        }

        spdlog::error("[FirstChance] STACK OVERFLOW — scanned {:x} bytes of used stack, {} module return addresses, "
                      "{} distinct tracked. The repeated frames below are the recursion cycle:",
            scanned, matched, tracked_count);

        // Selection sort by count, descending — tiny table, and std::sort would
        // pull in more stack than this is worth here.
        for (size_t printed = 0; printed < tracked_count && printed < 10; ++printed) {
            size_t best = printed;

            for (size_t i = printed + 1; i < tracked_count; ++i) {
                if (tracked[i].count > tracked[best].count) {
                    best = i;
                }
            }

            const auto tmp = tracked[printed];
            tracked[printed] = tracked[best];
            tracked[best] = tmp;

            const auto addr = tracked[printed].addr;

            if (const auto mod = utility::get_module_within(addr)) {
                const auto path = utility::get_module_path(*mod);
                spdlog::error("[FirstChance]   x{:<6} {:x} ({} + {:x})",
                    tracked[printed].count, addr, path.value_or("Unknown"), addr - (uintptr_t)*mod);
            } else {
                spdlog::error("[FirstChance]   x{:<6} {:x}", tracked[printed].count, addr);
            }
        }
    }

    if (const auto logger = spdlog::default_logger()) { logger->flush(); }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Some titles surface a fatal error as a bare MessageBox and then terminate.
// Hook it to capture the dialog text plus a real backtrace of whoever raised it
// — i.e. the fatal call site — before the process goes down.
static void log_backtrace(const char* tag) {
    void* frames[32]{};
    const auto n = RtlCaptureStackBackTrace(1, 32, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        const auto addr = (uintptr_t)frames[i];
        if (const auto mod = utility::get_module_within(addr)) {
            const auto path = utility::get_module_path(*mod);
            spdlog::error("{} Frame[{}]: {:x} ({} + {:x})", tag, i, addr, path.value_or("Unknown"), addr - (uintptr_t)*mod);
        } else {
            spdlog::error("{} Frame[{}]: {:x}", tag, i, addr);
        }
    }
}

static safetyhook::InlineHook g_messagebox_a_hook{};
static safetyhook::InlineHook g_messagebox_w_hook{};

static int WINAPI messagebox_a_hooked(HWND hwnd, LPCSTR text, LPCSTR caption, UINT type) {
    spdlog::error("[MessageBoxA] caption=\"{}\" text=\"{}\" thread {}",
        caption ? caption : "(null)", text ? text : "(null)", GetCurrentThreadId());
    log_backtrace("[MessageBoxA]");
    if (const auto logger = spdlog::default_logger()) { logger->flush(); }
    return g_messagebox_a_hook.call<int>(hwnd, text, caption, type);
}

static int WINAPI messagebox_w_hooked(HWND hwnd, LPCWSTR text, LPCWSTR caption, UINT type) {
    spdlog::error("[MessageBoxW] caption=\"{}\" text=\"{}\" thread {}",
        caption ? utility::narrow(caption) : "(null)", text ? utility::narrow(text) : "(null)", GetCurrentThreadId());
    log_backtrace("[MessageBoxW]");
    if (const auto logger = spdlog::default_logger()) { logger->flush(); }
    return g_messagebox_w_hook.call<int>(hwnd, text, caption, type);
}

void framework::setup_exception_handler() {
    SetUnhandledExceptionFilter(global_exception_handler);

    // See first_chance_exception_logger: catches fatal exceptions the game's own
    // handler would otherwise swallow before our unhandled filter runs.
    AddVectoredExceptionHandler(0 /* last — after any XRSystem patcher VEH */, first_chance_exception_logger);

    if (const auto user32 = GetModuleHandleW(L"user32.dll"); user32 != nullptr) {
        if (const auto fn = GetProcAddress(user32, "MessageBoxA"); fn != nullptr) {
            g_messagebox_a_hook = safetyhook::create_inline((void*)fn, (void*)&messagebox_a_hooked);
        }
        if (const auto fn = GetProcAddress(user32, "MessageBoxW"); fn != nullptr) {
            g_messagebox_w_hook = safetyhook::create_inline((void*)fn, (void*)&messagebox_w_hooked);
        }
    }

    // diag1: no-op unless the host is SWZeroCompany.exe; runs once.
    swzc_diag_init();
}

// --- Hang diagnostics --------------------------------------------------------
// A hang leaves nothing in the log: the last line is wherever each thread got
// to, which is not the same as where it is STUCK. This walks every other thread
// in the process and reports its current RIP plus the module-resident values
// still sitting on its stack - enough to name the function that is not
// returning, and (by comparing two dumps a while apart) to tell a blocked
// thread from a spinning one.
//
// Everything is copied out while the thread is suspended and only formatted
// after it is resumed: spdlog allocates, and allocating while another thread
// holds the CRT heap lock in suspension is its own deadlock. ReadProcessMemory
// against our own process reads the stack without IsBadReadPtr's first-chance
// AV storm.
void framework::dump_all_thread_stacks(const char* reason) {
    constexpr int max_dumps = 3;
    constexpr auto min_interval = std::chrono::seconds(20);
    constexpr size_t stack_bytes = 0x600;
    constexpr size_t max_frames = 14;

    static std::mutex mtx{};
    static int dumps = 0;
    static std::chrono::steady_clock::time_point last{};

    std::scoped_lock _{mtx};

    const auto now = std::chrono::steady_clock::now();

    if (dumps >= max_dumps || (dumps > 0 && now - last < min_interval)) {
        return;
    }
    last = now;
    ++dumps;

    const auto self = GetCurrentThreadId();
    const auto pid = GetCurrentProcessId();

    spdlog::error("[HangDump #{}] {} (dumping threads of pid {}, this is thread {})", dumps, reason, pid, self);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        spdlog::error("[HangDump #{}] Could not snapshot threads ({})", dumps, GetLastError());
        return;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    for (auto ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self) {
            continue;
        }

        const auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, entry.th32ThreadID);

        if (thread == nullptr) {
            continue;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

        uint8_t stack[stack_bytes]{};
        SIZE_T stack_read = 0;
        bool have_ctx = false;
        // SuspendThread returns the PREVIOUS suspend count: anything above zero
        // means somebody else already had this thread frozen, which is the
        // difference between "stuck in a loop" and "not running at all".
        DWORD prev_suspend_count = 0;

        if (const auto count = SuspendThread(thread); count != (DWORD)-1) {
            prev_suspend_count = count;
            have_ctx = GetThreadContext(thread, &ctx) != FALSE;

            if (have_ctx) {
                ReadProcessMemory(GetCurrentProcess(), (void*)ctx.Rsp, stack, sizeof(stack), &stack_read);
            }

            ResumeThread(thread);
        }

        CloseHandle(thread);

        if (!have_ctx) {
            continue;
        }

        const auto describe = [](uintptr_t addr) {
            if (const auto module_within = utility::get_module_within(addr)) {
                const auto path = utility::get_module_path(*module_within);
                auto name = path.value_or("Unknown");

                if (const auto slash = name.find_last_of("\/"); slash != std::string::npos) {
                    name = name.substr(slash + 1);
                }

                return std::format("{} + {:x}", name, addr - (uintptr_t)*module_within);
            }

            return std::string{"<no module>"};
        };

        spdlog::error("[HangDump #{}] thread {} RIP {:x} ({}) RSP {:x} suspended_by_others={}", dumps,
                      entry.th32ThreadID, (uintptr_t)ctx.Rip, describe(ctx.Rip), (uintptr_t)ctx.Rsp,
                      prev_suspend_count);

        // Registers name the arguments of whatever call is stuck (a memcpy's
        // rcx/rdx/r8, say), and the region info says whether the addresses they
        // point at are even committed and writable.
        spdlog::error("[HangDump #{}]   RAX {:x} RBX {:x} RCX {:x} RDX {:x} RSI {:x} RDI {:x} RBP {:x} R8 {:x} R9 {:x}",
                      dumps, ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.R8, ctx.R9);

        const auto describe_region = [&](const char* label, uintptr_t addr) {
            if (addr < 0x10000) {
                return;
            }

            MEMORY_BASIC_INFORMATION mbi{};

            if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) {
                spdlog::error("[HangDump #{}]   {} {:x}: unmapped", dumps, label, addr);
                return;
            }

            spdlog::error("[HangDump #{}]   {} {:x}: base {:x} size {:x} state {:x} protect {:x} type {:x}", dumps,
                          label, addr, (uintptr_t)mbi.BaseAddress, (uintptr_t)mbi.RegionSize, mbi.State, mbi.Protect,
                          mbi.Type);
        };

        describe_region("rcx", ctx.Rcx);
        describe_region("rdx", ctx.Rdx);
        describe_region("rsi", ctx.Rsi);
        describe_region("rdi", ctx.Rdi);

        // Frames only for threads that are actually somewhere interesting. A
        // thread parked in an ntdll wait is the normal state of most of a
        // game's thread pool, and dumping fourteen frames for each of eighty of
        // them buries the one thread that matters.
        const auto rip_module = utility::get_module_within(ctx.Rip);
        const auto rip_path = rip_module ? utility::get_module_path(*rip_module).value_or("") : std::string{};
        const bool parked = rip_path.find("ntdll.dll") != std::string::npos && prev_suspend_count == 0;

        if (parked) {
            continue;
        }

        size_t logged = 0;

        for (size_t off = 0; off + sizeof(uintptr_t) <= stack_read && logged < max_frames; off += sizeof(uintptr_t)) {
            uintptr_t value{};
            memcpy(&value, stack + off, sizeof(value));

            if (value < 0x10000 || utility::get_module_within(value) == std::nullopt) {
                continue;
            }

            spdlog::error("[HangDump #{}]   [rsp+{:x}] {:x} ({})", dumps, off, value, describe(value));
            ++logged;
        }
    }

    CloseHandle(snapshot);

    if (const auto logger = spdlog::default_logger()) {
        logger->flush();
    }
}

// --- SW Zero Company diagnostic build (diag1) --------------------------------
// Purpose: find out what kills SWZeroCompany.exe right after Flat3D's native
// resize nudge runs engine->exec("r.SetRes ...") for the first time (the
// UEngine::Exec discovery scan). Observation only: nothing here changes what
// the game or the backend does. Everything is gated on the host executable
// being SWZeroCompany.exe.
//
// The side log is written with raw WriteFile on an append-only handle and a
// fixed-size, CRT-free line formatter, never through spdlog: the 00053 log
// showed another thread's once-a-second spdlog line stalling for 4.3 s during
// the fatal window, so spdlog (or a lock it needs) may itself be what is stuck.
namespace {
namespace swzc_diag {
std::atomic_bool g_enabled{false};
HANDLE g_file{INVALID_HANDLE_VALUE};
LARGE_INTEGER g_qpf{};
LARGE_INTEGER g_qpc0{};

std::atomic<uint64_t> g_exec_begin_us{0};
std::atomic<uint32_t> g_exec_tid{0};
std::atomic<int32_t> g_exec_depth{0};
std::atomic<uint32_t> g_exec_count{0};
std::atomic_bool g_veh_active{false};
std::atomic<uint64_t> g_head_n{0};
std::atomic<uint64_t> g_tail_n{0};
std::atomic<uint64_t> g_head_k32{0};
std::atomic<uint64_t> g_tail_k32{0};
std::atomic<uint32_t> g_veh_lines{0};

uintptr_t g_k32_base{0}, g_k32_end{0};
uintptr_t g_kb_base{0}, g_kb_end{0};

uint64_t now_us() {
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    if (g_qpf.QuadPart == 0) {
        return 0;
    }
    return (uint64_t)((c.QuadPart - g_qpc0.QuadPart) * 1000000 / g_qpf.QuadPart);
}

struct Line {
    char buf[1024];
    size_t n{0};

    Line& s(const char* str) {
        while (str != nullptr && *str != '\0' && n < sizeof(buf) - 2) {
            buf[n++] = *str++;
        }
        return *this;
    }
    Line& hex(uint64_t v) {
        char t[17];
        int i = 16;
        t[16] = '\0';
        do {
            t[--i] = "0123456789abcdef"[v & 15];
            v >>= 4;
        } while (v != 0 && i > 0);
        return s(t + i);
    }
    Line& dec(uint64_t v) {
        char t[21];
        int i = 20;
        t[20] = '\0';
        do {
            t[--i] = (char)('0' + (v % 10));
            v /= 10;
        } while (v != 0 && i > 0);
        return s(t + i);
    }
    Line& w(std::wstring_view ws) {
        for (size_t k = 0; k < ws.size() && k < 200 && n < sizeof(buf) - 2; ++k) {
            const auto c = ws[k];
            buf[n++] = (c >= 32 && c < 127) ? (char)c : '?';
        }
        return *this;
    }
};

Line begin_line() {
    Line l{};
    const auto t = now_us();
    l.s("[").dec(t / 1000000).s(".");
    const auto frac = t % 1000000;
    for (uint64_t d = 100000; d > 0; d /= 10) {
        l.buf[l.n++] = (char)('0' + (frac / d) % 10);
    }
    l.s("] t").dec(GetCurrentThreadId()).s(" ");
    return l;
}

void write(Line& l) {
    if (g_file == INVALID_HANDLE_VALUE) {
        return;
    }
    l.buf[l.n++] = '\n';
    DWORD written = 0;
    WriteFile(g_file, l.buf, (DWORD)l.n, &written, nullptr);
}

struct Mod {
    uintptr_t base;
    uintptr_t size;
    char name[48];
};
struct ModTable {
    Mod mods[768];
    uint32_t count;
};
ModTable g_tables[2]{};
std::atomic<int> g_cur_table{-1};
std::mutex g_refresh_mtx{};

// Only called from normal contexts (never from a VEH or while a thread is
// suspended): the psapi calls take the loader's module list lock.
void refresh_modules() {
    std::scoped_lock _{g_refresh_mtx};
    const int next = g_cur_table.load(std::memory_order_acquire) == 0 ? 1 : 0;
    auto& t = g_tables[next];
    HMODULE handles[768]{};
    DWORD needed = 0;

    if (!K32EnumProcessModules(GetCurrentProcess(), handles, sizeof(handles), &needed)) {
        return;
    }

    const auto count = (uint32_t)(std::min<size_t>)(needed / sizeof(HMODULE), 768);
    t.count = 0;

    for (uint32_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!K32GetModuleInformation(GetCurrentProcess(), handles[i], &mi, sizeof(mi))) {
            continue;
        }
        auto& m = t.mods[t.count++];
        m.base = (uintptr_t)mi.lpBaseOfDll;
        m.size = mi.SizeOfImage;
        char name[MAX_PATH]{};
        K32GetModuleBaseNameA(GetCurrentProcess(), handles[i], name, sizeof(name));
        size_t k = 0;
        for (; name[k] != '\0' && k < sizeof(m.name) - 1; ++k) {
            m.name[k] = name[k];
        }
        m.name[k] = '\0';
    }

    g_cur_table.store(next, std::memory_order_release);
}

const Mod* find_module(uintptr_t addr) {
    const auto idx = g_cur_table.load(std::memory_order_acquire);
    if (idx < 0) {
        return nullptr;
    }
    const auto& t = g_tables[idx];
    for (uint32_t i = 0; i < t.count && i < 768; ++i) {
        if (addr >= t.mods[i].base && addr < t.mods[i].base + t.mods[i].size) {
            return &t.mods[i];
        }
    }
    return nullptr;
}

Line& describe(Line& l, uintptr_t addr) {
    l.hex(addr);
    if (const auto m = find_module(addr); m != nullptr) {
        l.s("(").s(m->name).s("+").hex(addr - m->base).s(")");
    }
    return l;
}

bool read_mem(uintptr_t addr, void* out, size_t size) {
    SIZE_T got = 0;
    return addr >= 0x10000 &&
           ReadProcessMemory(GetCurrentProcess(), (const void*)addr, out, size, &got) != FALSE && got == size;
}

bool in_kernel32(uintptr_t rip) {
    return (rip >= g_k32_base && rip < g_k32_end) || (rip >= g_kb_base && rip < g_kb_end);
}

// Copies the thread's state while it is suspended and formats only after it is
// resumed. Nothing between SuspendThread and ResumeThread allocates or locks.
void sample_thread(DWORD tid, const char* tag, size_t max_frames) {
    const auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);

    if (thread == nullptr) {
        auto l = begin_line();
        l.s(tag).s(" tid ").dec(tid).s(" OpenThread failed ").dec(GetLastError());
        write(l);
        return;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    uint8_t stack[0x1000];
    SIZE_T stack_read = 0;
    bool have_ctx = false;
    const DWORD prev = SuspendThread(thread);

    if (prev != (DWORD)-1) {
        have_ctx = GetThreadContext(thread, &ctx) != FALSE;
        if (have_ctx) {
            ReadProcessMemory(GetCurrentProcess(), (const void*)ctx.Rsp, stack, sizeof(stack), &stack_read);
        }
        ResumeThread(thread);
    }

    CloseHandle(thread);

    if (!have_ctx) {
        auto l = begin_line();
        l.s(tag).s(" tid ").dec(tid).s(" no context (suspend=").hex(prev).s(")");
        write(l);
        return;
    }

    {
        auto l = begin_line();
        l.s(tag).s(" tid ").dec(tid).s(" RIP ");
        describe(l, ctx.Rip).s(" RSP ").hex(ctx.Rsp).s(" prev_suspend ").dec(prev);
        write(l);
    }
    {
        auto l = begin_line();
        l.s(tag).s("   RAX ").hex(ctx.Rax).s(" RBX ").hex(ctx.Rbx).s(" RCX ").hex(ctx.Rcx).s(" RDX ").hex(ctx.Rdx)
            .s(" RSI ").hex(ctx.Rsi).s(" RDI ").hex(ctx.Rdi).s(" R8 ").hex(ctx.R8).s(" R9 ").hex(ctx.R9)
            .s(" R12 ").hex(ctx.R12).s(" R13 ").hex(ctx.R13).s(" R14 ").hex(ctx.R14).s(" R15 ").hex(ctx.R15);
        write(l);
    }

    size_t logged = 0;
    Line fl = begin_line();
    fl.s(tag).s("   frames:");

    for (size_t off = 0; off + sizeof(uintptr_t) <= stack_read && logged < max_frames; off += sizeof(uintptr_t)) {
        uintptr_t value{};
        memcpy(&value, stack + off, sizeof(value));

        if (value < 0x10000 || find_module(value) == nullptr) {
            continue;
        }

        if (fl.n > sizeof(fl.buf) - 120) {
            write(fl);
            fl = begin_line();
            fl.s(tag).s("   frames:");
        }

        fl.s(" [").hex(off).s("]");
        describe(fl, value);
        ++logged;
    }

    write(fl);
}

void dump_all_threads(const char* reason) {
    {
        auto l = begin_line();
        l.s("[ALLTHREADS] begin: ").s(reason);
        write(l);
    }

    const auto self = GetCurrentThreadId();
    const auto pid = GetCurrentProcessId();
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        auto l = begin_line();
        l.s("[ALLTHREADS] snapshot failed ").dec(GetLastError());
        write(l);
        return;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    uint32_t n = 0;

    for (auto ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry)) {
        if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self) {
            continue;
        }
        sample_thread(entry.th32ThreadID, "[ALLTHREADS]", 10);
        ++n;
    }

    CloseHandle(snapshot);

    auto l = begin_line();
    l.s("[ALLTHREADS] end, threads=").dec(n);
    write(l);
}

DWORD WINAPI watchdog_thread(void*) {
    uint64_t tick = 0;
    bool dumped_1s = false;
    bool dumped_3s = false;
    uint32_t dumped_for_exec = 0;

    for (;;) {
        Sleep(250);
        ++tick;

        const auto begin = g_exec_begin_us.load(std::memory_order_acquire);
        const auto now = now_us();
        const bool active = begin != 0 && now - begin < 20 * 1000000ull;

        if (!active) {
            if (tick % 4 == 0) {
                auto l = begin_line();
                l.s("[HB] idle execs=").dec(g_exec_count.load());
                write(l);
            }
            if (tick % 8 == 0) {
                refresh_modules();
            }
            continue;
        }

        const auto exec_no = g_exec_count.load();
        if (dumped_for_exec != exec_no) {
            dumped_for_exec = exec_no;
            dumped_1s = false;
            dumped_3s = false;
        }

        const auto elapsed_ms = (now - begin) / 1000;
        const auto depth = g_exec_depth.load();

        {
            auto l = begin_line();
            l.s("[HB] exec#").dec(exec_no).s(" since_begin_ms=").dec(elapsed_ms).s(" inside_exec=")
                .dec(depth > 0 ? 1 : 0).s(" veh_head=").dec(g_head_n.load()).s(" veh_tail=").dec(g_tail_n.load())
                .s(" k32_head=").dec(g_head_k32.load()).s(" k32_tail=").dec(g_tail_k32.load());
            write(l);
        }

        if (const auto tid = g_exec_tid.load(); tid != 0 && tid != GetCurrentThreadId()) {
            sample_thread(tid, "[GAMETHREAD]", 24);
        }

        if (depth > 0 && !dumped_1s && elapsed_ms >= 1000) {
            dumped_1s = true;
            dump_all_threads("exec still running after 1 s");
        }
        if (depth > 0 && !dumped_3s && elapsed_ms >= 3000) {
            dumped_3s = true;
            dump_all_threads("exec still running after 3 s");
        }
    }
}

LONG veh_common(PEXCEPTION_POINTERS ei, bool head) {
    if (framework::is_module_detaching() || !g_veh_active.load(std::memory_order_acquire)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto code = ei->ExceptionRecord->ExceptionCode;
    const bool interesting = (code & 0xF0000000u) == 0xC0000000u || code == 1 || code == EXCEPTION_BREAKPOINT ||
                             code == 0xE06D7363u /* C++ throw */;

    if (!interesting) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto rip = (uintptr_t)ei->ContextRecord->Rip;
    const char* tag = head ? "[VEH-HEAD]" : "[VEH-TAIL]";

    if (code == EXCEPTION_ACCESS_VIOLATION && in_kernel32(rip)) {
        const auto c = ++(head ? g_head_k32 : g_tail_k32);
        if (c % 500 == 0) {
            auto l = begin_line();
            l.s(tag).s(" kernel32 AV (IsBadReadPtr) x").dec(c);
            write(l);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto n = ++(head ? g_head_n : g_tail_n);

    if (g_veh_lines.fetch_add(1) < 6000) {
        auto l = begin_line();
        l.s(tag).s(" #").dec(n).s(" code ").hex(code).s(" RIP ");
        describe(l, rip);
        if (code == EXCEPTION_ACCESS_VIOLATION && ei->ExceptionRecord->NumberParameters >= 2) {
            l.s(" av_kind ").dec(ei->ExceptionRecord->ExceptionInformation[0]).s(" addr ")
                .hex(ei->ExceptionRecord->ExceptionInformation[1]);
        }
        l.s(" RSP ").hex(ei->ContextRecord->Rsp).s(" exec_depth ").dec((uint64_t)(std::max)(0, (int)g_exec_depth.load()));
        write(l);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI veh_head(PEXCEPTION_POINTERS ei) { return veh_common(ei, true); }
LONG WINAPI veh_tail(PEXCEPTION_POINTERS ei) { return veh_common(ei, false); }

void log_backtrace(const char* tag) {
    void* frames[48]{};
    const auto n = RtlCaptureStackBackTrace(1, 48, frames, nullptr);
    Line l = begin_line();
    l.s(tag).s(" backtrace:");
    for (USHORT i = 0; i < n; ++i) {
        if (l.n > sizeof(l.buf) - 120) {
            write(l);
            l = begin_line();
            l.s(tag).s(" backtrace:");
        }
        l.s(" ");
        describe(l, (uintptr_t)frames[i]);
    }
    write(l);
}

safetyhook::InlineHook g_rtl_exit_hook{};
safetyhook::InlineHook g_terminate_hook{};
safetyhook::InlineHook g_failfast_hook{};

void NTAPI rtl_exit_user_process_hooked(LONG status) {
    auto l = begin_line();
    l.s("[TERM] RtlExitUserProcess status ").hex((uint32_t)status);
    write(l);
    log_backtrace("[TERM] RtlExitUserProcess");
    g_rtl_exit_hook.call<void>(status);
}

BOOL WINAPI terminate_process_hooked(HANDLE process, UINT code) {
    auto l = begin_line();
    l.s("[TERM] TerminateProcess handle ").hex((uint64_t)process).s(" code ").hex(code);
    write(l);
    log_backtrace("[TERM] TerminateProcess");
    return g_terminate_hook.call<BOOL>(process, code);
}

void WINAPI raise_fail_fast_hooked(PEXCEPTION_RECORD record, PCONTEXT context, DWORD flags) {
    auto l = begin_line();
    l.s("[TERM] RaiseFailFastException flags ").hex(flags);
    if (record != nullptr) {
        l.s(" code ").hex(record->ExceptionCode).s(" addr ");
        describe(l, (uintptr_t)record->ExceptionAddress);
    }
    if (context != nullptr) {
        l.s(" ctx_rip ");
        describe(l, (uintptr_t)context->Rip);
    }
    write(l);
    log_backtrace("[TERM] RaiseFailFastException");
    g_failfast_hook.call<void>(record, context, flags);
}

void module_range(const wchar_t* name, uintptr_t& base, uintptr_t& end) {
    const auto mod = GetModuleHandleW(name);
    MODULEINFO mi{};
    if (mod != nullptr && K32GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) {
        base = (uintptr_t)mi.lpBaseOfDll;
        end = base + mi.SizeOfImage;
    }
}

void install_hook(safetyhook::InlineHook& hook, const wchar_t* module, const char* export_name, void* detour) {
    const auto mod = GetModuleHandleW(module);
    const auto fn = mod != nullptr ? (void*)GetProcAddress(mod, export_name) : nullptr;
    auto l = begin_line();
    l.s("[DIAG1] hook ").s(export_name).s(" at ");
    if (fn == nullptr) {
        l.s("<not found>");
        write(l);
        return;
    }
    describe(l, (uintptr_t)fn);
    {
        // Written before installing, so a failure during installation is visible.
        auto pre = begin_line();
        pre.s("[DIAG1] installing hook ").s(export_name);
        write(pre);
    }
    hook = safetyhook::create_inline(fn, detour);
    l.s(hook ? " installed" : " FAILED");
    write(l);
}

bool is_swzc_executable() {
    wchar_t path[MAX_PATH]{};
    const auto len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    const std::wstring_view view{path, len};
    const std::wstring_view suffix{L"\\swzerocompany.exe"};
    if (view.size() < suffix.size()) {
        return false;
    }
    const auto tail = view.substr(view.size() - suffix.size());
    for (size_t i = 0; i < suffix.size(); ++i) {
        if ((wchar_t)towlower(tail[i]) != suffix[i]) {
            return false;
        }
    }
    return true;
}

void dump_engine_object(const void* engine) {
    auto l = begin_line();
    l.s("[ENGINE] UEngine object ").hex((uintptr_t)engine).s(" (the Exec scan walks qwords +0..+0x100 as vtables)");
    write(l);

    for (uintptr_t off = 0; off <= 0x100; off += sizeof(void*)) {
        uintptr_t q{};
        auto el = begin_line();
        el.s("[ENGINE] +").hex(off).s(" = ");
        if (!read_mem((uintptr_t)engine + off, &q, sizeof(q))) {
            el.s("<unreadable>");
            write(el);
            continue;
        }
        describe(el, q);
        uintptr_t entries[4]{};
        if (q != 0 && read_mem(q, entries, sizeof(entries))) {
            el.s(" vt:");
            for (auto e : entries) {
                el.s(" ");
                describe(el, e);
            }
        }
        write(el);
    }
}
} // namespace swzc_diag
} // namespace

bool framework::swzc_diag_enabled() {
    return swzc_diag::g_enabled.load(std::memory_order_acquire);
}

void framework::swzc_diag_init() {
    using namespace swzc_diag;
    static std::atomic_bool once{false};

    if (once.exchange(true)) {
        return;
    }

    if (!is_swzc_executable()) {
        return;
    }

    QueryPerformanceFrequency(&g_qpf);
    QueryPerformanceCounter(&g_qpc0);

    const auto path = (Framework::get_persistent_dir() / "swzc_diag1.txt").wstring();
    DeleteFileW(path.c_str());
    g_file = CreateFileW(path.c_str(), FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (g_file == INVALID_HANDLE_VALUE) {
        spdlog::error("[SWZC diag1] could not open side log ({})", GetLastError());
        return;
    }

    module_range(L"kernel32.dll", g_k32_base, g_k32_end);
    module_range(L"kernelbase.dll", g_kb_base, g_kb_end);
    refresh_modules();

    {
        auto l = begin_line();
        l.s("[DIAG1] uu3d-swzc-diag1 side log, pid ").dec(GetCurrentProcessId())
            .s(". Times are seconds since this line.");
        write(l);
    }

    g_enabled.store(true, std::memory_order_release);

    // NtTerminateProcess is deliberately NOT hooked: it is an ntdll syscall stub
    // and installing an inline hook there kills the process (verified in a
    // standalone smoke test). RtlExitUserProcess + TerminateProcess +
    // RaiseFailFastException cover the ordinary ways a process ends itself.
    install_hook(g_rtl_exit_hook, L"ntdll.dll", "RtlExitUserProcess", (void*)&rtl_exit_user_process_hooked);
    install_hook(g_terminate_hook, L"kernelbase.dll", "TerminateProcess", (void*)&terminate_process_hooked);
    install_hook(g_failfast_hook, L"kernelbase.dll", "RaiseFailFastException", (void*)&raise_fail_fast_hooked);

    if (const auto th = CreateThread(nullptr, 0, &watchdog_thread, nullptr, 0, nullptr); th != nullptr) {
        CloseHandle(th);
    }

    spdlog::info("[SWZC diag1] enabled; side log at {}", utility::narrow(path));
}

void framework::swzc_diag_exec_begin(const void* engine, std::wstring_view command, const char* site) {
    using namespace swzc_diag;

    if (!swzc_diag_enabled()) {
        return;
    }

    refresh_modules();

    const auto no = g_exec_count.fetch_add(1) + 1;
    {
        auto l = begin_line();
        l.s("[EXEC-BEGIN] #").dec(no).s(" site ").s(site).s(" cmd \"").w(command).s("\" engine ")
            .hex((uintptr_t)engine).s(" depth_before ").dec((uint64_t)(std::max)(0, (int)g_exec_depth.load()));
        write(l);
    }

    if (no == 1) {
        dump_engine_object(engine);

        // Head: registered now, after FFakeStereoRenderingHook's null-deref
        // patcher (First=1 at hook time), so it sees every exception first.
        // Tail: appended after the existing first-chance logger.
        AddVectoredExceptionHandler(1, &veh_head);
        AddVectoredExceptionHandler(0, &veh_tail);
        g_veh_active.store(true, std::memory_order_release);

        auto l = begin_line();
        l.s("[DIAG1] head/tail VEHs registered; main log now flushes every line");
        write(l);

        // Keep the main log's last info lines on disk too: the 00053 log could
        // only show lines up to the last error-level flush.
        spdlog::flush_on(spdlog::level::info);
    }

    if (const auto logger = spdlog::default_logger()) {
        logger->flush();
    }

    g_exec_tid.store(GetCurrentThreadId(), std::memory_order_release);
    g_exec_depth.fetch_add(1);
    g_exec_begin_us.store(now_us(), std::memory_order_release);
}

void framework::swzc_diag_exec_end(const char* site) {
    using namespace swzc_diag;

    if (!swzc_diag_enabled()) {
        return;
    }

    g_exec_depth.fetch_sub(1);
    auto l = begin_line();
    l.s("[EXEC-END] site ").s(site).s(" took_ms ").dec((now_us() - g_exec_begin_us.load()) / 1000);
    write(l);
}

void framework::swzc_diag_note_unhandled(struct _EXCEPTION_POINTERS* ei) {
    using namespace swzc_diag;

    if (!swzc_diag_enabled() || ei == nullptr) {
        return;
    }

    auto l = begin_line();
    l.s("[UNHANDLED] code ").hex(ei->ExceptionRecord->ExceptionCode).s(" RIP ");
    describe(l, (uintptr_t)ei->ContextRecord->Rip);
    write(l);
}
