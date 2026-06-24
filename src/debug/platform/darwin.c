// macOS debug-register backend for the debug substrate.
//
// Hardware watchpoints (data, WVR/WCR) and hardware execute breakpoints
// (instruction, BVR/BCR) on Apple Silicon are delivered as Mach EXC_BREAKPOINT
// exceptions, NOT signals. A detached server thread runs the Mach exception
// protocol; on a hit it builds an n00b_debug_hit_t, asks the registry for an
// action, and applies it (disable / single-step-and-continue / forward).
//
// ALL-THREAD model: the active slot-set is mirrored here and applied to every
// thread (task_threads enumeration, suspending non-self) on install/clear, and
// to each newly-started thread via n00b_debug_plat_enroll_self() (called from
// the n00b thread launcher). The exception-server thread is excluded so it
// never self-traps.
//
// This file is the platform-ABI boundary: raw Mach/pthread calls live here.

#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif

#define N00B_DEBUG_MACH_MSG_SIZE 1024

// ---- active slot-set mirror (final register values; read on any thread) -----
// Watchpoint bank (WVR/WCR).
static atomic_int g_watch_live[N00B_DEBUG_MAX_SLOTS];
static uint64_t   g_watch_wvr[N00B_DEBUG_MAX_SLOTS];
static uint32_t   g_watch_wcr[N00B_DEBUG_MAX_SLOTS];
static void      *g_watch_addr[N00B_DEBUG_MAX_SLOTS]; // original addr (hit + match)
// Breakpoint bank (BVR/BCR).
static atomic_int g_break_live[N00B_DEBUG_MAX_SLOTS];
static void      *g_break_addr[N00B_DEBUG_MAX_SLOTS]; // bvr (4-aligned)

// ---- single-step state: which slot we disarmed to step over, per thread -----
typedef struct {
    thread_t thread;
    int32_t  slot;
    bool     is_break;
    bool     active;
} n00b_debug_step_t;
static n00b_debug_step_t g_steps[N00B_DEBUG_MAX_SLOTS * 2];

// ---- exception backend state ------------------------------------------------
static mach_port_t       g_exc_port      = MACH_PORT_NULL;
static pthread_t         g_exc_thread;
static _Atomic(thread_t) g_server_thread = MACH_PORT_NULL; // excluded from programming
static atomic_bool       g_running       = false;
static atomic_bool       g_initialized   = false;

typedef struct {
    mach_msg_header_t          Head;
    mach_msg_body_t            msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t               NDR;
    exception_type_t           exception;
    mach_msg_type_number_t     codeCnt;
    int64_t                    code[2];
} n00b_debug_exc_request_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t      NDR;
    kern_return_t     RetCode;
} n00b_debug_exc_reply_t;

#if defined(__aarch64__)

// Watchpoint Control Register: E | PAC(EL0) | LSC(load/store) | BAS(byte sel).
static uint32_t
n00b_debug_make_wcr(n00b_debug_watch_kind_t kind, int32_t size)
{
    uint32_t wcr = 1;
    wcr |= (2u << 1);
    int lsc = (kind == N00B_DEBUG_WATCH_WRITE) ? 2 : 3;
    wcr |= ((uint32_t)lsc << 3);
    uint32_t bas;
    switch (size) {
    case 1:  bas = 0x01; break;
    case 2:  bas = 0x03; break;
    case 4:  bas = 0x0f; break;
    default: bas = 0xff; break;
    }
    wcr |= (bas << 5);
    return wcr;
}

// Breakpoint Control Register: E | PAC(EL0) | BAS(all 4 bytes) | BT=address.
static uint32_t
n00b_debug_make_bcr(void)
{
    return 1u | (2u << 1) | (0xfu << 5);
}

// Program a single watchpoint slot on @thread (used by the step machinery).
static void
n00b_debug_prog_watch(thread_t thread, int32_t slot, uint64_t wvr, uint32_t wcr)
{
    arm_debug_state64_t    ds;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &count)
        != KERN_SUCCESS) {
        return;
    }
    ds.__wvr[slot] = wvr;
    ds.__wcr[slot] = wcr;
    thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds,
                     ARM_DEBUG_STATE64_COUNT);
}

// Program a single breakpoint slot on @thread (used by the step machinery).
static void
n00b_debug_prog_break(thread_t thread, int32_t slot, uint64_t bvr, uint32_t bcr)
{
    arm_debug_state64_t    ds;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &count)
        != KERN_SUCCESS) {
        return;
    }
    ds.__bvr[slot] = bvr;
    ds.__bcr[slot] = bcr;
    thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds,
                     ARM_DEBUG_STATE64_COUNT);
}

// Program the FULL active slot-set into @thread in one get/set (preserves the
// MDSCR single-step bit).
static void
n00b_debug_apply_all_to_thread(thread_t thread)
{
    arm_debug_state64_t    ds;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &count)
        != KERN_SUCCESS) {
        return;
    }
    for (int i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        if (atomic_load(&g_watch_live[i])) {
            ds.__wvr[i] = g_watch_wvr[i];
            ds.__wcr[i] = g_watch_wcr[i];
        }
        else {
            ds.__wvr[i] = 0;
            ds.__wcr[i] = 0;
        }
        if (atomic_load(&g_break_live[i])) {
            ds.__bvr[i] = (uint64_t)g_break_addr[i];
            ds.__bcr[i] = n00b_debug_make_bcr();
        }
        else {
            ds.__bvr[i] = 0;
            ds.__bcr[i] = 0;
        }
    }
    thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds,
                     ARM_DEBUG_STATE64_COUNT);
}

// Re-apply the active slot-set to every thread in the task. @exc_thread (if not
// NULL) is the faulting thread inside an exception handler: it is already
// stopped, so it is programmed without an extra suspend. The calling thread is
// likewise never suspended, and the exception-server thread is skipped entirely.
static void
n00b_debug_program_all_threads(thread_t exc_thread)
{
    thread_act_array_t     list;
    mach_msg_type_number_t cnt;
    if (task_threads(mach_task_self(), &list, &cnt) != KERN_SUCCESS) {
        return;
    }
    thread_t self   = mach_thread_self();
    thread_t server = atomic_load(&g_server_thread);

    for (mach_msg_type_number_t i = 0; i < cnt; i++) {
        thread_t t = list[i];
        if (t == server) {
            // never program the exception server (would self-trap)
        }
        else if (t == self || t == exc_thread) {
            n00b_debug_apply_all_to_thread(t);
        }
        else if (thread_suspend(t) == KERN_SUCCESS) {
            n00b_debug_apply_all_to_thread(t);
            thread_resume(t);
        }
        mach_port_deallocate(mach_task_self(), t);
    }
    mach_port_deallocate(mach_task_self(), self);
    vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(list[0]));
}

static bool
n00b_debug_get_ts(thread_t thread, arm_thread_state64_t *ts)
{
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    return thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)ts,
                            &count)
           == KERN_SUCCESS;
}

static uint64_t
n00b_debug_gpr(arm_thread_state64_t *ts, int r)
{
    if (r == 31) return 0;
    if (r == 30) return ts->__lr;
    if (r == 29) return ts->__fp;
    return ts->__x[r];
}

static bool
n00b_debug_decode_store(arm_thread_state64_t *ts, uint64_t *out)
{
    uint32_t insn = *(uint32_t *)ts->__pc;
    int      rt   = (int)(insn & 0x1f);
    if ((insn & 0xffc00000) == 0xf9000000) { *out = n00b_debug_gpr(ts, rt); return true; }
    if ((insn & 0xffe00c00) == 0xf8000000 ||
        (insn & 0xffe00c00) == 0xf8000400) { *out = n00b_debug_gpr(ts, rt); return true; }
    if ((insn & 0xffe00c00) == 0xf8200800) { *out = n00b_debug_gpr(ts, rt); return true; }
    return false;
}

static void
n00b_debug_fill_from_ts(arm_thread_state64_t *ts, n00b_debug_hit_t *hit)
{
    *hit = (n00b_debug_hit_t){};
    for (int i = 0; i < 29; i++) {
        hit->regs[i] = ts->__x[i];
    }
    hit->regs[29] = ts->__fp;
    hit->regs[30] = ts->__lr;
    hit->pc       = (void *)ts->__pc;
    hit->sp       = (void *)ts->__sp;
}

static void
n00b_debug_flush_regs(thread_t thread, n00b_debug_hit_t *hit)
{
    if (!hit->regs_dirty) {
        return;
    }
    arm_thread_state64_t ts;
    if (!n00b_debug_get_ts(thread, &ts)) {
        return;
    }
    for (int i = 0; i < 29; i++) {
        ts.__x[i] = hit->regs[i];
    }
    ts.__fp = hit->regs[29];
    ts.__lr = hit->regs[30];
    thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&ts,
                     ARM_THREAD_STATE64_COUNT);
}

static int32_t
n00b_debug_watch_slot_for_addr(uint64_t fault_addr)
{
    uint64_t aligned = fault_addr & ~7ull;
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        if (atomic_load(&g_watch_live[i])
            && ((uint64_t)g_watch_addr[i] & ~7ull) == aligned) {
            return i;
        }
    }
    return -1;
}

static int32_t
n00b_debug_break_slot_for_pc(uint64_t pc)
{
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        if (atomic_load(&g_break_live[i]) && (uint64_t)g_break_addr[i] == pc) {
            return i;
        }
    }
    return -1;
}

static n00b_debug_step_t *
n00b_debug_find_step(thread_t thread)
{
    for (size_t i = 0; i < sizeof(g_steps) / sizeof(g_steps[0]); i++) {
        if (g_steps[i].active && g_steps[i].thread == thread) {
            return &g_steps[i];
        }
    }
    return nullptr;
}

static n00b_debug_step_t *
n00b_debug_free_step(void)
{
    for (size_t i = 0; i < sizeof(g_steps) / sizeof(g_steps[0]); i++) {
        if (!g_steps[i].active) {
            return &g_steps[i];
        }
    }
    return nullptr;
}

static void
n00b_debug_set_single_step(thread_t thread, bool on)
{
    arm_debug_state64_t    ds;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &count)
        != KERN_SUCCESS) {
        return;
    }
    if (on) {
        ds.__mdscr_el1 |= 1ull;
    }
    else {
        ds.__mdscr_el1 &= ~1ull;
    }
    thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds,
                     ARM_DEBUG_STATE64_COUNT);
}

static kern_return_t
n00b_debug_apply(thread_t thread, int32_t slot, bool is_break,
                 n00b_debug_action_t action)
{
    switch (action) {
    case N00B_DEBUG_DISABLE:
        // Clear the slot across ALL threads so it stops trapping everywhere,
        // then let the faulting instruction re-execute untrapped.
        if (is_break) {
            atomic_store(&g_break_live[slot], 0);
            g_break_addr[slot] = nullptr;
            n00b_debug_slot_release_break(slot);
        }
        else {
            atomic_store(&g_watch_live[slot], 0);
            g_watch_addr[slot] = nullptr;
            n00b_debug_slot_release_watch(slot);
        }
        n00b_debug_program_all_threads(thread);
        return KERN_SUCCESS;

    case N00B_DEBUG_CONTINUE: {
        // Disarm this slot on the faulting thread only, single-step the
        // faulting instruction, and re-arm on the step-completion exception.
        n00b_debug_step_t *st = n00b_debug_find_step(thread);
        if (st == nullptr) {
            st = n00b_debug_free_step();
        }
        if (is_break) {
            n00b_debug_prog_break(thread, slot, 0, 0);
        }
        else {
            n00b_debug_prog_watch(thread, slot, 0, 0);
        }
        if (st != nullptr) {
            st->thread   = thread;
            st->slot     = slot;
            st->is_break = is_break;
            st->active   = true;
        }
        n00b_debug_set_single_step(thread, true);
        return KERN_SUCCESS;
    }

    case N00B_DEBUG_TRAP:
    default:
        return KERN_FAILURE;
    }
}

static kern_return_t
n00b_debug_handle_exc(thread_t thread)
{
    arm_exception_state64_t es;
    mach_msg_type_number_t  ec = ARM_EXCEPTION_STATE64_COUNT;
    if (thread_get_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t)&es, &ec)
        != KERN_SUCCESS) {
        return KERN_FAILURE;
    }
    uint32_t esr_ec = (uint32_t)((es.__esr >> 26) & 0x3f);

    // Software-step completion (0x32/0x33): re-arm the stepped slot.
    if (esr_ec == 0x32 || esr_ec == 0x33) {
        n00b_debug_step_t *st = n00b_debug_find_step(thread);
        n00b_debug_set_single_step(thread, false);
        if (st == nullptr) {
            return KERN_SUCCESS;
        }
        int32_t slot = st->slot;
        if (st->is_break) {
            n00b_debug_prog_break(thread, slot, (uint64_t)g_break_addr[slot],
                                  n00b_debug_make_bcr());
        }
        else {
            n00b_debug_prog_watch(thread, slot, g_watch_wvr[slot],
                                  g_watch_wcr[slot]);
        }
        st->active = false;
        return KERN_SUCCESS;
    }

    arm_thread_state64_t ts;
    if (!n00b_debug_get_ts(thread, &ts)) {
        return KERN_FAILURE;
    }

    // Watchpoint (0x34/0x35): data access.
    if (esr_ec == 0x34 || esr_ec == 0x35) {
        int32_t slot = n00b_debug_watch_slot_for_addr(es.__far);
        if (slot < 0) {
            return KERN_FAILURE;
        }
        n00b_debug_hit_t hit;
        n00b_debug_fill_from_ts(&ts, &hit);
        hit.addr = g_watch_addr[slot];
        if (hit.addr != nullptr) {
            hit.old_value = *(void *volatile *)hit.addr;
        }
        uint64_t newval;
        if (n00b_debug_decode_store(&ts, &newval)) {
            hit.new_value = (void *)newval;
        }
        n00b_debug_action_t action = n00b_debug_on_watch_hit(slot, &hit);
        n00b_debug_flush_regs(thread, &hit);
        return n00b_debug_apply(thread, slot, false, action);
    }

    // Hardware breakpoint (0x30/0x31): instruction address match (PC == BVR).
    if (esr_ec == 0x30 || esr_ec == 0x31) {
        int32_t slot = n00b_debug_break_slot_for_pc(ts.__pc);
        if (slot < 0) {
            return KERN_FAILURE;
        }
        n00b_debug_hit_t hit;
        n00b_debug_fill_from_ts(&ts, &hit);
        hit.addr = (void *)ts.__pc;
        n00b_debug_action_t action = n00b_debug_on_break_hit(slot, &hit);
        n00b_debug_flush_regs(thread, &hit);
        return n00b_debug_apply(thread, slot, true, action);
    }

    return KERN_FAILURE;
}

static void *
n00b_debug_exc_server(void *arg)
{
    (void)arg;
    atomic_store(&g_server_thread, mach_thread_self()); // exclude from programming

    while (atomic_load(&g_running)) {
        union [[n00b::raw_union]] {
            n00b_debug_exc_request_t req;
            char                     buf[N00B_DEBUG_MACH_MSG_SIZE];
        } msg;

        kern_return_t kr = mach_msg(&msg.req.Head,
                                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, sizeof(msg), g_exc_port, 1000,
                                    MACH_PORT_NULL);
        if (kr == MACH_RCV_TIMED_OUT || kr != KERN_SUCCESS) {
            continue;
        }

        kern_return_t ret = KERN_FAILURE;
        if (msg.req.exception == EXC_BREAKPOINT) {
            ret = n00b_debug_handle_exc(msg.req.thread.name);
        }

        n00b_debug_exc_reply_t reply = {};
        reply.Head.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.Head.msgh_size        = sizeof(reply);
        reply.Head.msgh_remote_port = msg.req.Head.msgh_remote_port;
        reply.Head.msgh_local_port  = MACH_PORT_NULL;
        reply.Head.msgh_id          = msg.req.Head.msgh_id + 100;
        reply.NDR                   = NDR_record;
        reply.RetCode               = ret;
        mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    return nullptr;
}

n00b_debug_err_t
n00b_debug_plat_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_initialized, &expected, true)) {
        return N00B_DEBUG_OK;
    }

    mach_port_t self = mach_task_self();
    if (mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &g_exc_port)
        != KERN_SUCCESS) {
        atomic_store(&g_initialized, false);
        return N00B_DEBUG_ERR_SIGNAL_HANDLER;
    }
    if (mach_port_insert_right(self, g_exc_port, g_exc_port,
                               MACH_MSG_TYPE_MAKE_SEND)
        != KERN_SUCCESS) {
        mach_port_deallocate(self, g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        atomic_store(&g_initialized, false);
        return N00B_DEBUG_ERR_SIGNAL_HANDLER;
    }
    if (task_set_exception_ports(self, EXC_MASK_BREAKPOINT, g_exc_port,
                                 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64)
        != KERN_SUCCESS) {
        mach_port_deallocate(self, g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        atomic_store(&g_initialized, false);
        return N00B_DEBUG_ERR_SIGNAL_HANDLER;
    }

    atomic_store(&g_running, true);
    if (pthread_create(&g_exc_thread, nullptr, n00b_debug_exc_server, nullptr)
        != 0) {
        atomic_store(&g_running, false);
        mach_port_deallocate(self, g_exc_port);
        g_exc_port = MACH_PORT_NULL;
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
    uint64_t aligned = (uint64_t)addr & ~7ull;
    uint32_t wcr     = n00b_debug_make_wcr(kind, size);
    uint32_t offset  = (uint32_t)((uint64_t)addr - aligned);
    uint32_t bas     = ((wcr >> 5) & 0xff) << offset;
    wcr              = (wcr & ~(0xffu << 5)) | (bas << 5);

    g_watch_wvr[slot]  = aligned;
    g_watch_wcr[slot]  = wcr;
    g_watch_addr[slot] = addr;
    atomic_store(&g_watch_live[slot], 1);
    n00b_debug_program_all_threads(MACH_PORT_NULL);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_watch_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    atomic_store(&g_watch_live[slot], 0);
    g_watch_addr[slot] = nullptr;
    n00b_debug_program_all_threads(MACH_PORT_NULL);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_set(int32_t slot, void *addr)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    g_break_addr[slot] = (void *)((uint64_t)addr & ~3ull);
    atomic_store(&g_break_live[slot], 1);
    n00b_debug_program_all_threads(MACH_PORT_NULL);
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_plat_break_clear(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    atomic_store(&g_break_live[slot], 0);
    g_break_addr[slot] = nullptr;
    n00b_debug_program_all_threads(MACH_PORT_NULL);
    return N00B_DEBUG_OK;
}

void
n00b_debug_plat_enroll_self(void)
{
    if (!atomic_load(&g_initialized)) {
        return; // nothing armed; cheap path for every thread spawn
    }
    thread_t self = mach_thread_self();
    n00b_debug_apply_all_to_thread(self);
    mach_port_deallocate(mach_task_self(), self);
}

#else // !__aarch64__ (macOS x86-64: not yet implemented)

n00b_debug_err_t
n00b_debug_plat_init(void)
{
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_watch_set(int32_t slot, void *addr, int32_t size,
                          n00b_debug_watch_kind_t kind)
{
    (void)slot; (void)addr; (void)size; (void)kind;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_watch_clear(int32_t slot)
{
    (void)slot;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_break_set(int32_t slot, void *addr)
{
    (void)slot; (void)addr;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_break_clear(int32_t slot)
{
    (void)slot;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

void
n00b_debug_plat_enroll_self(void)
{
}

#endif

// Debugger-attach detection (OS-level, arch-independent).
bool
n00b_debug_plat_is_attached(void)
{
    int               mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info   = {};
    size_t            sz      = sizeof(info);
    if (sysctl(mib, 4, &info, &sz, nullptr, 0) != 0) {
        return false;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
