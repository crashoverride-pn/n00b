// Windows/x86-64 debug-register backend for the debug substrate.
//
// Windows exposes the four x86 debug registers (Dr0-Dr3 + Dr7 control / Dr6
// status) through Get/SetThreadContext, and delivers debug exceptions as
// EXCEPTION_SINGLE_STEP to a vectored exception handler that runs IN the
// faulting thread (no separate server thread, unlike macOS).
//
// The four DRs are SHARED between data watchpoints and execute breakpoints, so
// this maps the registry's logical (watch|break, slot) handles onto physical
// DRs on demand and returns N00B_DEBUG_ERR_NO_SLOT when all four are in use.
//
// ALL-THREAD: a DR change is applied to every thread (Toolhelp enumeration,
// suspend/Get/Set/resume non-self); new threads enroll via
// n00b_debug_plat_enroll_self() from the n00b thread launcher.
//
// x86 trap timing: data watchpoints trap AFTER the access (CONTINUE = return);
// execute breakpoints trap BEFORE (CONTINUE sets EFLAGS.RF to resume once).
//
// !! UNVALIDATED on-target — authored, not compiled/run here (no Windows
// toolchain locally). Validate via CI.
//
// Platform-ABI boundary: raw Win32 calls live here.

#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#if defined(_WIN32)

#include <windows.h>
#include <tlhelp32.h>
#include <stdatomic.h>

#define N00B_DEBUG_DR_COUNT 4

// Physical DR table (the real hardware resource on x86).
typedef struct {
    atomic_int              used;
    void                   *addr;
    int32_t                 size;     // 1/2/4/8 (watch); exec uses len=1
    n00b_debug_watch_kind_t kind;
    bool                    is_break;
    int32_t                 logical;  // registry slot index
} n00b_debug_dr_t;
static n00b_debug_dr_t g_dr[N00B_DEBUG_DR_COUNT];

// Logical registry slot -> physical DR (or -1).
static int32_t g_watch_dr[N00B_DEBUG_MAX_SLOTS];
static int32_t g_break_dr[N00B_DEBUG_MAX_SLOTS];
static atomic_bool g_initialized = false;
static atomic_bool g_map_inited  = false;
static PVOID       g_veh;

static void
n00b_debug_init_map_once(void)
{
    bool expected = false;
    if (atomic_compare_exchange_strong(&g_map_inited, &expected, true)) {
        for (int i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
            g_watch_dr[i] = -1;
            g_break_dr[i] = -1;
        }
    }
}

// Build Dr7 from the active physical DR table.
static DWORD64
n00b_debug_make_dr7(void)
{
    DWORD64 dr7 = 0;
    for (int i = 0; i < N00B_DEBUG_DR_COUNT; i++) {
        if (!atomic_load(&g_dr[i].used)) {
            continue;
        }
        dr7 |= (DWORD64)1 << (i * 2); // local enable Li

        int rw;
        int len;
        if (g_dr[i].is_break) {
            rw  = 0; // execute
            len = 0; // 1 byte
        }
        else {
            rw = (g_dr[i].kind == N00B_DEBUG_WATCH_WRITE) ? 1 : 3; // W / RW
            switch (g_dr[i].size) {
            case 1:  len = 0; break;
            case 2:  len = 1; break;
            case 8:  len = 2; break;
            default: len = 3; break; // 4
            }
        }
        dr7 |= (DWORD64)rw << (16 + i * 4);
        dr7 |= (DWORD64)len << (18 + i * 4);
    }
    return dr7;
}

static void
n00b_debug_apply_to_thread(HANDLE h)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(h, &ctx)) {
        return;
    }
    ctx.Dr0 = atomic_load(&g_dr[0].used) ? (DWORD64)g_dr[0].addr : 0;
    ctx.Dr1 = atomic_load(&g_dr[1].used) ? (DWORD64)g_dr[1].addr : 0;
    ctx.Dr2 = atomic_load(&g_dr[2].used) ? (DWORD64)g_dr[2].addr : 0;
    ctx.Dr3 = atomic_load(&g_dr[3].used) ? (DWORD64)g_dr[3].addr : 0;
    ctx.Dr7 = n00b_debug_make_dr7();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(h, &ctx);
}

// Re-apply the active DR set to every thread in this process.
static void
n00b_debug_program_all_threads(void)
{
    DWORD  self = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        n00b_debug_apply_to_thread(GetCurrentThread());
        return;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }
            if (te.th32ThreadID == self) {
                n00b_debug_apply_to_thread(GetCurrentThread());
                continue;
            }
            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
                                      | THREAD_SUSPEND_RESUME,
                                  FALSE, te.th32ThreadID);
            if (h == nullptr) {
                continue;
            }
            SuspendThread(h);
            n00b_debug_apply_to_thread(h);
            ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// Find a free physical DR, or -1.
static int32_t
n00b_debug_alloc_dr(void)
{
    for (int32_t i = 0; i < N00B_DEBUG_DR_COUNT; i++) {
        int expected = 0;
        if (atomic_compare_exchange_strong(&g_dr[i].used, &expected, 1)) {
            return i;
        }
    }
    return -1;
}

static LONG CALLBACK
n00b_debug_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    CONTEXT *c   = ep->ContextRecord;
    DWORD64  dr6 = c->Dr6;

    int32_t dr = -1;
    for (int32_t i = 0; i < N00B_DEBUG_DR_COUNT; i++) {
        if ((dr6 & ((DWORD64)1 << i)) && atomic_load(&g_dr[i].used)) {
            dr = i;
            break;
        }
    }
    if (dr < 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    n00b_debug_hit_t hit = {};
    hit.regs[0]  = c->Rax;
    hit.regs[1]  = c->Rdx;
    hit.regs[2]  = c->Rcx;
    hit.regs[3]  = c->Rbx;
    hit.regs[4]  = c->Rsi;
    hit.regs[5]  = c->Rdi;
    hit.regs[6]  = c->Rbp;
    hit.regs[7]  = c->Rsp;
    hit.regs[8]  = c->R8;
    hit.regs[9]  = c->R9;
    hit.regs[10] = c->R10;
    hit.regs[11] = c->R11;
    hit.regs[12] = c->R12;
    hit.regs[13] = c->R13;
    hit.regs[14] = c->R14;
    hit.regs[15] = c->R15;
    hit.pc       = (void *)c->Rip;
    hit.sp       = (void *)c->Rsp;
    hit.addr     = g_dr[dr].addr;
    if (!g_dr[dr].is_break && hit.addr != nullptr) {
        hit.old_value = *(void *volatile *)hit.addr;
    }

    int32_t             slot   = g_dr[dr].logical;
    n00b_debug_action_t action = g_dr[dr].is_break
                                     ? n00b_debug_on_break_hit(slot, &hit)
                                     : n00b_debug_on_watch_hit(slot, &hit);

    if (hit.regs_dirty) {
        c->Rax = hit.regs[0];  c->Rdx = hit.regs[1];  c->Rcx = hit.regs[2];
        c->Rbx = hit.regs[3];  c->Rsi = hit.regs[4];  c->Rdi = hit.regs[5];
        c->Rbp = hit.regs[6];  c->R8  = hit.regs[8];  c->R9  = hit.regs[9];
        c->R10 = hit.regs[10]; c->R11 = hit.regs[11]; c->R12 = hit.regs[12];
        c->R13 = hit.regs[13]; c->R14 = hit.regs[14]; c->R15 = hit.regs[15];
    }

    c->Dr6 &= ~((DWORD64)1 << dr); // ack

    switch (action) {
    case N00B_DEBUG_DISABLE:
        atomic_store(&g_dr[dr].used, 0);
        if (g_dr[dr].is_break) {
            g_break_dr[slot] = -1;
            n00b_debug_slot_release_break(slot);
        }
        else {
            g_watch_dr[slot] = -1;
            n00b_debug_slot_release_watch(slot);
        }
        n00b_debug_program_all_threads();
        return EXCEPTION_CONTINUE_EXECUTION;
    case N00B_DEBUG_CONTINUE:
        if (g_dr[dr].is_break) {
            c->EFlags |= 0x10000; // RF: run the instruction once without re-trap
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    case N00B_DEBUG_TRAP:
    default:
        return EXCEPTION_CONTINUE_SEARCH; // hand to a debugger / default
    }
}

n00b_debug_err_t
n00b_debug_plat_init(void)
{
    n00b_debug_init_map_once();
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_initialized, &expected, true)) {
        return N00B_DEBUG_OK;
    }
    g_veh = AddVectoredExceptionHandler(1, n00b_debug_veh);
    if (g_veh == nullptr) {
        atomic_store(&g_initialized, false);
        return N00B_DEBUG_ERR_SIGNAL_HANDLER;
    }
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_watch_set(int32_t slot, void *addr, int32_t size,
                          n00b_debug_watch_kind_t kind)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    n00b_debug_init_map_once();
    int32_t dr = n00b_debug_alloc_dr();
    if (dr < 0) {
        return N00B_DEBUG_ERR_NO_SLOT;
    }
    g_dr[dr].addr     = addr;
    g_dr[dr].size     = size;
    g_dr[dr].kind     = kind;
    g_dr[dr].is_break = false;
    g_dr[dr].logical  = slot;
    g_watch_dr[slot]  = dr;
    n00b_debug_program_all_threads();
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_watch_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    int32_t dr = g_watch_dr[slot];
    if (dr >= 0) {
        atomic_store(&g_dr[dr].used, 0);
        g_watch_dr[slot] = -1;
        n00b_debug_program_all_threads();
    }
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_set(int32_t slot, void *addr)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    n00b_debug_init_map_once();
    int32_t dr = n00b_debug_alloc_dr();
    if (dr < 0) {
        return N00B_DEBUG_ERR_NO_SLOT;
    }
    g_dr[dr].addr     = addr;
    g_dr[dr].size     = 1;
    g_dr[dr].kind     = N00B_DEBUG_WATCH_WRITE;
    g_dr[dr].is_break = true;
    g_dr[dr].logical  = slot;
    g_break_dr[slot]  = dr;
    n00b_debug_program_all_threads();
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    int32_t dr = g_break_dr[slot];
    if (dr >= 0) {
        atomic_store(&g_dr[dr].used, 0);
        g_break_dr[slot] = -1;
        n00b_debug_program_all_threads();
    }
    return N00B_DEBUG_OK;
}

void
n00b_debug_plat_enroll_self(void)
{
    if (!atomic_load(&g_initialized)) {
        return;
    }
    n00b_debug_apply_to_thread(GetCurrentThread());
}

bool
n00b_debug_plat_is_attached(void)
{
    return IsDebuggerPresent() ? true : false;
}

#endif // _WIN32
