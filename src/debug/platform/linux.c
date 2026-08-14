// Linux/x86-64 debug-register backend for the debug substrate.
//
// Linux exposes hardware watch/breakpoints through perf_event_open() with
// PERF_TYPE_BREAKPOINT and pe.sigtrap=1, which delivers SIGTRAP to the thread
// that triggered. ALL-THREAD coverage means one perf event per (slot, thread):
//   - install: open an event for the slot on every thread in /proc/self/task
//   - new threads: n00b_debug_plat_enroll_self() opens events for live slots
//   - each event is tagged (pe.sig_data = slot) so the handler knows which
//     slot fired via siginfo.si_perf_data.
//
// x86-64 trap timing: DATA watchpoints trap AFTER the access, so CONTINUE is
// just "return". EXECUTE breakpoints trap BEFORE, so CONTINUE sets EFLAGS.RF to
// resume past the instruction once without re-triggering.
//
// !! UNVALIDATED on-target as of this writing — authored from the proven
// perf_event_open setup but compiled/run only via Docker/CI. Hardware events in
// a container need `sysctl kernel.perf_event_paranoid=-1` (or CAP_SYS_PTRACE).
// si_perf_data requires kernel >= 5.13 and a recent glibc.
//
// This file is the platform-ABI boundary: raw syscalls live here.
// (_GNU_SOURCE is supplied by the build's command line; do not redefine it.)

#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <ucontext.h>

#if defined(__x86_64__)

// Max simultaneously-open perf events: slots x a soft thread cap. A process
// with more live threads than this at install time silently under-covers the
// excess (logged is a future nicety); the enroll hook still covers new threads.
#define N00B_DEBUG_LINUX_MAX_EVENTS (N00B_DEBUG_MAX_SLOTS * 256)
#define N00B_DEBUG_LINUX_SI_PERF_DATA_OFFSET (sizeof(int) * 4u + sizeof(void *))

// TRAP_PERF is the si_code for a perf-event-delivered SIGTRAP (kernel UAPI,
// <asm-generic/siginfo.h>, since 5.13). Some header sets — notably the hermetic
// clang toolchain wax builds libn00b through — pull in <signal.h>/<linux/...>
// without exposing it, the same gap the si_perf_data accessor has above. Its
// value is a stable ABI constant, so define it when the headers don't. Without
// this, the x86-64 build fails at `info->si_code != TRAP_PERF` below with
// "use of undeclared identifier 'TRAP_PERF'".
#ifndef TRAP_PERF
#define TRAP_PERF 6
#endif

// Per-slot config mirror (the active slot-set).
typedef struct {
    atomic_int              live;
    void                   *addr;
    atomic_uintptr_t        last_value;
    int32_t                 size;
    n00b_debug_watch_kind_t kind;
    bool                    is_break;
} n00b_debug_slot_cfg_t;
static n00b_debug_slot_cfg_t g_slot[N00B_DEBUG_MAX_SLOTS];

// Open perf events: one per (slot, thread).
typedef struct {
    atomic_int fd_plus1; // 0 = empty; otherwise fd+1
    int32_t    slot;
    pid_t      tid;
} n00b_debug_event_t;
static n00b_debug_event_t g_events[N00B_DEBUG_LINUX_MAX_EVENTS];

static atomic_bool       g_initialized = false;
static struct sigaction  g_old_sigtrap;

static long
n00b_debug_perf_open(struct perf_event_attr *attr, pid_t pid)
{
    return syscall(__NR_perf_event_open, attr, pid, -1, -1,
                   PERF_FLAG_FD_CLOEXEC);
}

static pid_t
n00b_debug_gettid(void)
{
    return (pid_t)syscall(__NR_gettid);
}

static bool
n00b_debug_event_exists(int32_t slot, pid_t tid)
{
    for (int i = 0; i < N00B_DEBUG_LINUX_MAX_EVENTS; i++) {
        if (atomic_load(&g_events[i].fd_plus1) != 0
            && g_events[i].slot == slot && g_events[i].tid == tid) {
            return true;
        }
    }
    return false;
}

static uintptr_t
n00b_debug_read_watch_value(const n00b_debug_slot_cfg_t *slot)
{
    switch (slot->size) {
    case 1: return *(volatile uint8_t *)slot->addr;
    case 2: return *(volatile uint16_t *)slot->addr;
    case 4: return *(volatile uint32_t *)slot->addr;
    default: return *(volatile uint64_t *)slot->addr;
    }
}

// Open a perf event for @slot on thread @tid (idempotent per (slot,tid)).
static void
n00b_debug_open_for(int32_t slot, pid_t tid)
{
    if (!atomic_load(&g_slot[slot].live) || n00b_debug_event_exists(slot, tid)) {
        return;
    }
    struct perf_event_attr pe = {};
    pe.type          = PERF_TYPE_BREAKPOINT;
    pe.size          = sizeof(pe);
    pe.sample_period = 1;
    if (g_slot[slot].is_break) {
        pe.bp_type = HW_BREAKPOINT_X;
        pe.bp_len  = sizeof(long); // x86 execute breakpoint length
    }
    else {
        pe.bp_type = (g_slot[slot].kind == N00B_DEBUG_WATCH_WRITE)
                         ? HW_BREAKPOINT_W
                         : HW_BREAKPOINT_RW;
        pe.bp_len  = g_slot[slot].size;
    }
    pe.bp_addr        = (uint64_t)g_slot[slot].addr;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;
    pe.sigtrap        = 1;
    pe.remove_on_exec = 1;
    pe.sig_data       = (uint64_t)slot; // delivered as siginfo.si_perf_data

    int fd = (int)n00b_debug_perf_open(&pe, tid);
    if (fd < 0) {
        return;
    }
    // Route this fd's SIGTRAP to the owning thread.
    fcntl(fd, F_SETSIG, SIGTRAP);
    fcntl(fd, F_SETOWN, tid);

    for (int i = 0; i < N00B_DEBUG_LINUX_MAX_EVENTS; i++) {
        int expected = 0;
        if (atomic_compare_exchange_strong(&g_events[i].fd_plus1, &expected,
                                           fd + 1)) {
            g_events[i].slot = slot;
            g_events[i].tid  = tid;
            return;
        }
    }
    close(fd); // table full
}

static void
n00b_debug_close_slot(int32_t slot)
{
    for (int i = 0; i < N00B_DEBUG_LINUX_MAX_EVENTS; i++) {
        int fdp1 = atomic_load(&g_events[i].fd_plus1);
        if (fdp1 != 0 && g_events[i].slot == slot) {
            close(fdp1 - 1);
            atomic_store(&g_events[i].fd_plus1, 0);
        }
    }
}

static uint64_t
n00b_debug_perf_sigdata(const siginfo_t *info)
{
#ifdef si_perf_data
    return (uint64_t)info->si_perf_data;
#else
    unsigned long data = 0;
    // Some libc headers expose TRAP_PERF but not the si_perf_data accessor.
    // x86-64 kernel siginfo places perf data at this ABI slot for TRAP_PERF.
    memcpy(&data, (const char *)info + N00B_DEBUG_LINUX_SI_PERF_DATA_OFFSET,
           sizeof(data));
    return (uint64_t)data;
#endif
}

// Open events for @slot on every thread currently in /proc/self/task.
static void
n00b_debug_open_all_threads(int32_t slot)
{
    int dfd = open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
        n00b_debug_open_for(slot, n00b_debug_gettid()); // at least self
        return;
    }
    DIR *d = fdopendir(dfd);
    if (d == nullptr) {
        close(dfd);
        n00b_debug_open_for(slot, n00b_debug_gettid());
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') {
            continue;
        }
        pid_t tid = 0;
        // Declare the cursor as a block item, not in the for-init: ncc's
        // gc-stack-maps transform registers a non-literal-initialized pointer
        // (const char *p = e->d_name) as a GC root and cannot anchor a root
        // declared inside a for-statement init clause ("unsupported statement
        // context"). Hoisting the declaration gives it a block anchor; the
        // for-init becomes a plain assignment. (No behavior change.)
        const char *p = e->d_name;
        for (; *p >= '0' && *p <= '9'; p++) {
            tid = tid * 10 + (*p - '0');
        }
        n00b_debug_open_for(slot, tid);
    }
    closedir(d);
}

// ---- SIGTRAP handler (async-signal context on the faulting thread) ----------

static void
n00b_debug_sigtrap(int sig, siginfo_t *info, void *uctx_raw)
{
    if (info->si_code != TRAP_PERF) {
        // Not ours (could be a single-step we set, or a foreign SIGTRAP).
        if (g_old_sigtrap.sa_flags & SA_SIGINFO) {
            if (g_old_sigtrap.sa_sigaction) {
                g_old_sigtrap.sa_sigaction(sig, info, uctx_raw);
            }
        }
        else if (g_old_sigtrap.sa_handler != SIG_IGN
                 && g_old_sigtrap.sa_handler != SIG_DFL) {
            g_old_sigtrap.sa_handler(sig);
        }
        return;
    }

    ucontext_t *uc   = (ucontext_t *)uctx_raw;
    int32_t     slot = (int32_t)n00b_debug_perf_sigdata(info);
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS
        || !atomic_load(&g_slot[slot].live)) {
        return;
    }

    greg_t *g = uc->uc_mcontext.gregs;
    n00b_debug_hit_t hit = {};
    // x86-64 DWARF GPR order: rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp,r8..r15.
    hit.regs[0]  = (uint64_t)g[REG_RAX];
    hit.regs[1]  = (uint64_t)g[REG_RDX];
    hit.regs[2]  = (uint64_t)g[REG_RCX];
    hit.regs[3]  = (uint64_t)g[REG_RBX];
    hit.regs[4]  = (uint64_t)g[REG_RSI];
    hit.regs[5]  = (uint64_t)g[REG_RDI];
    hit.regs[6]  = (uint64_t)g[REG_RBP];
    hit.regs[7]  = (uint64_t)g[REG_RSP];
    hit.regs[8]  = (uint64_t)g[REG_R8];
    hit.regs[9]  = (uint64_t)g[REG_R9];
    hit.regs[10] = (uint64_t)g[REG_R10];
    hit.regs[11] = (uint64_t)g[REG_R11];
    hit.regs[12] = (uint64_t)g[REG_R12];
    hit.regs[13] = (uint64_t)g[REG_R13];
    hit.regs[14] = (uint64_t)g[REG_R14];
    hit.regs[15] = (uint64_t)g[REG_R15];
    hit.pc       = (void *)g[REG_RIP];
    hit.sp       = (void *)g[REG_RSP];
    hit.addr     = g_slot[slot].addr;
    if (!g_slot[slot].is_break && hit.addr != nullptr) {
        uintptr_t new_value = n00b_debug_read_watch_value(&g_slot[slot]);
        hit.old_value = (void *)atomic_load(&g_slot[slot].last_value);
        hit.new_value = (void *)new_value;
        atomic_store(&g_slot[slot].last_value, new_value);
    }

    n00b_debug_action_t action = g_slot[slot].is_break
                                     ? n00b_debug_on_break_hit(slot, &hit)
                                     : n00b_debug_on_watch_hit(slot, &hit);

    if (hit.regs_dirty) {
        g[REG_RAX] = (greg_t)hit.regs[0];
        g[REG_RDX] = (greg_t)hit.regs[1];
        g[REG_RCX] = (greg_t)hit.regs[2];
        g[REG_RBX] = (greg_t)hit.regs[3];
        g[REG_RSI] = (greg_t)hit.regs[4];
        g[REG_RDI] = (greg_t)hit.regs[5];
        g[REG_RBP] = (greg_t)hit.regs[6];
        g[REG_R8]  = (greg_t)hit.regs[8];
        g[REG_R9]  = (greg_t)hit.regs[9];
        g[REG_R10] = (greg_t)hit.regs[10];
        g[REG_R11] = (greg_t)hit.regs[11];
        g[REG_R12] = (greg_t)hit.regs[12];
        g[REG_R13] = (greg_t)hit.regs[13];
        g[REG_R14] = (greg_t)hit.regs[14];
        g[REG_R15] = (greg_t)hit.regs[15];
    }

    switch (action) {
    case N00B_DEBUG_DISABLE:
        atomic_store(&g_slot[slot].live, 0);
        n00b_debug_close_slot(slot);
        if (g_slot[slot].is_break) {
            n00b_debug_slot_release_break(slot);
        }
        else {
            n00b_debug_slot_release_watch(slot);
        }
        break;
    case N00B_DEBUG_CONTINUE:
        // Data WP traps AFTER the access: return resumes. Execute BP traps
        // BEFORE: set EFLAGS.RF so the instruction runs once without re-trap.
        if (g_slot[slot].is_break) {
            g[REG_EFL] |= 0x10000; // RF
        }
        break;
    case N00B_DEBUG_TRAP:
    default:
        // Re-raise to the previous handler / default disposition.
        if (g_old_sigtrap.sa_flags & SA_SIGINFO) {
            if (g_old_sigtrap.sa_sigaction) {
                g_old_sigtrap.sa_sigaction(sig, info, uctx_raw);
            }
        }
        else if (g_old_sigtrap.sa_handler != SIG_IGN
                 && g_old_sigtrap.sa_handler != SIG_DFL) {
            g_old_sigtrap.sa_handler(sig);
        }
        break;
    }
}

// ---- platform API ----------------------------------------------------------

n00b_debug_err_t
n00b_debug_plat_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_initialized, &expected, true)) {
        return N00B_DEBUG_OK;
    }
    struct sigaction sa = {};
    sa.sa_sigaction = n00b_debug_sigtrap;
    sa.sa_flags     = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, &g_old_sigtrap) != 0) {
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
    g_slot[slot].addr     = addr;
    g_slot[slot].size     = size;
    g_slot[slot].kind     = kind;
    g_slot[slot].is_break = false;
    atomic_store(&g_slot[slot].last_value,
                 n00b_debug_read_watch_value(&g_slot[slot]));
    atomic_store(&g_slot[slot].live, 1);
    // x86 has only 4 physical DRs shared by watch+break: open on self first to
    // surface exhaustion as NO_SLOT before fanning out to other threads.
    n00b_debug_open_for(slot, n00b_debug_gettid());
    if (!n00b_debug_event_exists(slot, n00b_debug_gettid())) {
        atomic_store(&g_slot[slot].live, 0);
        return N00B_DEBUG_ERR_NO_SLOT;
    }
    n00b_debug_open_all_threads(slot);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_watch_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    atomic_store(&g_slot[slot].live, 0);
    n00b_debug_close_slot(slot);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_set(int32_t slot, void *addr)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    g_slot[slot].addr     = addr;
    g_slot[slot].size     = (int32_t)sizeof(long);
    g_slot[slot].kind     = N00B_DEBUG_WATCH_WRITE;
    g_slot[slot].is_break = true;
    atomic_store(&g_slot[slot].live, 1);
    n00b_debug_open_for(slot, n00b_debug_gettid());
    if (!n00b_debug_event_exists(slot, n00b_debug_gettid())) {
        atomic_store(&g_slot[slot].live, 0);
        return N00B_DEBUG_ERR_NO_SLOT;
    }
    n00b_debug_open_all_threads(slot);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    atomic_store(&g_slot[slot].live, 0);
    n00b_debug_close_slot(slot);
    return N00B_DEBUG_OK;
}

void
n00b_debug_plat_enroll_self(void)
{
    if (!atomic_load(&g_initialized)) {
        return;
    }
    pid_t tid = n00b_debug_gettid();
    for (int32_t s = 0; s < N00B_DEBUG_MAX_SLOTS; s++) {
        if (atomic_load(&g_slot[s].live)) {
            n00b_debug_open_for(s, tid);
        }
    }
}

#else // Linux on a non-x86-64 arch: not yet implemented

n00b_debug_err_t n00b_debug_plat_init(void) { return N00B_DEBUG_ERR_UNSUPPORTED; }
n00b_debug_err_t
n00b_debug_plat_watch_set(int32_t slot, void *addr, int32_t size,
                          n00b_debug_watch_kind_t kind)
{
    (void)slot; (void)addr; (void)size; (void)kind;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}
n00b_debug_err_t n00b_debug_plat_watch_clear(int32_t slot) { (void)slot; return N00B_DEBUG_ERR_UNSUPPORTED; }
n00b_debug_err_t n00b_debug_plat_break_set(int32_t slot, void *addr) { (void)slot; (void)addr; return N00B_DEBUG_ERR_UNSUPPORTED; }
n00b_debug_err_t n00b_debug_plat_break_clear(int32_t slot) { (void)slot; return N00B_DEBUG_ERR_UNSUPPORTED; }
void n00b_debug_plat_enroll_self(void) {}

#endif

// Debugger-attach detection (OS-level, arch-independent): /proc/self/status has
// a "TracerPid:\t<n>" line; a non-zero n means a tracer is attached.
bool
n00b_debug_plat_is_attached(void)
{
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    char    buf[4096];
    ssize_t n    = read(fd, buf, sizeof(buf) - 1);
    bool    seen = false;
    if (n > 0) {
        buf[n]           = '\0';
        const char *line = strstr(buf, "TracerPid:");
        if (line != nullptr) {
            line += 10;
            while (*line == ' ' || *line == '\t') {
                line++;
            }
            seen = (*line != '0');
        }
    }
    close(fd);
    return seen;
}
