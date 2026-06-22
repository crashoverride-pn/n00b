// WP-3b crash detection/delivery + guard-page stack-overflow handler.
//
// The fault handler runs on a per-thread alternate signal stack (SA_ONSTACK)
// so it survives a stack overflow.  CRITICAL: ncc GC-instruments every function
// it compiles — _n00b_crash_handler's own prologue emits an n00b_gc_stack_push
// that calls n00b_thread_self(), which masks the SP to a callstack region and
// reads the slot ID word at region_start + S - 8.  So the altstack cannot be a
// plain mmap (self() would mask to a wrong/garbage base and fault BEFORE the
// handler body).  Instead the altstack IS a full n00b callstack region (S-
// aligned, with the SP-mask geometry), and we stamp the owning thread's slot id
// into its ID word — so self() (and thus the prologue) resolves correctly when
// the handler runs on it.
//
// LIFETIME (D-039, superseding D-038's per-slot-forever model): the altstack is
// drawn from the shared callstack pool by the SPAWNER (a worker cannot allocate
// its own at launch — its launch-time default allocator returns guard-band
// memory) and returned to that pool by the REAPER at OS-confirmed death, exactly
// like the worker's primary callstack.  This bounds the live set to (live
// workers + pool keep-N) rather than N00B_THREADS_MAX * S.  It lives on the
// per-WORKER struct (n00b_thread_t::altstack), NOT the shared slot record, so a
// slot reused before its prior worker is reaped can never cause the reaper to
// return a live worker's region.  (Cost: a second S-sized pool region per live
// worker — an optimization opportunity, tracked.)

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/crash.h"
#include "core/crash_capture.h" // full capture+resolve+render (DWARF) path
#include "core/runtime.h"
#include "core/thread.h"
#include "core/stw.h"         // n00b_stop_the_world (break-in for in-handler DWARF)
#include "core/rwlock.h"      // n00b_rwlock_t .data (forge STW-gate ownership)
#include "core/lock_common.h" // n00b_core_lock_info_t
#include "core/callstack.h" // n00b_callstack_pool_get + region geometry
#include "core/mmaps.h"

// Output here goes through core/syscall.h's RAW (libc-free) write syscall, NOT
// libc write().  Two reasons: (1) no-libc — write() is a libc symbol this
// project removes (NCC.md "NO LIBC ALLOWED"); (2) a fault handler runs in
// async-signal context on a thread whose TSD may be wrecked, so the
// conduit/print stack is unusable (locks + allocation) and even libc's write()
// (errno-TLS) is unsafe — a bare syscall instruction takes no lock and touches
// no TLS.  sigaltstack/sigaction are the kernel signal surface (no n00b wrapper;
// permitted raw in a .c file per NCC.md, as callstack.c uses mprotect).
#if !defined(_WIN32)
#include <signal.h> // sigaltstack/sigaction/stack_t (kernel signal surface, not libpthread)
#if defined(__APPLE__)
#include <sys/ucontext.h> // ucontext_t register snapshot supplied by sigaction
#include <mach-o/dyld.h>  // pre-init image slide discovery; not used in handler
#include <mach-o/loader.h>
#elif defined(__linux__)
#include <ucontext.h> // ucontext_t register snapshot supplied by sigaction
#endif
#include "core/syscall.h" // n00b_raw_write — libc-free, AS-safe
#endif

static _Atomic int g_n00b_crash_log_fd = -1;

#if !defined(_WIN32)
static _Atomic uintptr_t g_n00b_crash_image_vmaddr    = 0;
static _Atomic uintptr_t g_n00b_crash_image_load_base = 0;
static _Atomic uintptr_t g_n00b_crash_image_slide     = 0;
static _Atomic uintptr_t g_n00b_crash_text_start      = 0;
static _Atomic uintptr_t g_n00b_crash_text_end        = 0;
#endif

void
n00b_crash_set_log_fd(int fd)
{
    n00b_atomic_store(&g_n00b_crash_log_fd, fd);
}

void
n00b_crash_install_altstack(n00b_callstack_t *as_cs)
{
#if !defined(_WIN32)
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr || as_cs == nullptr) {
        return; // best-effort: run without an altstack
    }

    // The region is supplied by the caller (drawn from the shared callstack pool
    // by the spawner via the bundle, or by n00b_crash_init for the main thread)
    // and returned to that pool at OS-confirmed death by the reaper — the SAME
    // bounded lifetime as the worker's primary callstack (D-039).  We do NOT
    // allocate here: a worker's launch-time default allocator returns guard-band
    // memory, and a never-freed per-slot region explodes to N00B_THREADS_MAX * S
    // (D-038's discarded model).

    // Stamp THIS thread's slot id into the region's ID word (region_start + S - 8
    // — the geometry n00b_thread_self() reads), so self() resolves back to this
    // thread when the handler (and its ncc gc_stack_push prologue) runs here.
    // Re-stamped on every install because a pooled region carries the prior
    // owner's id.
    uint64_t *id_word = (uint64_t *)((char *)as_cs->region_start
                                     + as_cs->region_size
                                     - N00B_CALLSTACK_ID_WORD_SIZE);
    *id_word          = (uint64_t)(uint32_t)self->id_info.parts.id;

    // Publish on the PER-WORKER struct (reached by the handler's range-scan via
    // rt->threads[i].thread->altstack) so a fault on this region maps back to
    // this thread.  On the struct, NOT the shared slot record: a slot reused
    // before this worker is reaped must not let the reaper return a live
    // worker's altstack (D-039).  The reaper clears it and returns the region at
    // death, so a stale slot never misleads the scan.
    n00b_atomic_store(&self->altstack, as_cs);

    // Hand the usable region to sigaltstack, reserving the top page so the
    // signal frame (placed at the high end, growing down) cannot clobber the ID
    // word at region_start + S - 8.
    char  *lo   = (char *)as_cs->stack_low;
    char  *hi   = (char *)as_cs->stack_high;
    size_t resv = (size_t)n00b_page_size;
    if ((size_t)(hi - lo) <= resv) {
        return;
    }

    stack_t ss = {
        .ss_sp    = lo,
        .ss_size  = (size_t)(hi - lo) - resv,
        .ss_flags = 0,
    };
    (void)sigaltstack(&ss, nullptr);
#else
    // Windows: VEH runs on the faulting stack (with the OS stack-guard
    // reserve); no alternate-stack install. Written-only (host-verified later).
    (void)0;
#endif
}

#if !defined(_WIN32)

// Async-signal-safe writes to stderr and, when configured, the durable crash
// fd. Raw syscalls only: no stdio, locks, allocation, errno TLS, or conduit.
static void
_n00b_crash_write_bytes(const char *s, size_t n)
{
    n00b_raw_write(2, s, n);
    int log_fd = n00b_atomic_load(&g_n00b_crash_log_fd);
    if (log_fd >= 0 && log_fd != 2) {
        n00b_raw_write(log_fd, s, n);
    }
}

static void
_n00b_crash_write(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    _n00b_crash_write_bytes(s, n);
}

static void
_n00b_crash_write_u64(uint64_t v)
{
    char b[20];
    int  n = 0;
    if (v == 0) {
        b[n++] = '0';
    } else {
        while (v != 0 && n < (int)sizeof(b)) {
            b[n++] = (char)('0' + (v % 10));
            v /= 10;
        }
        for (int i = 0, j = n - 1; i < j; i++, j--) {
            char t = b[i];
            b[i]   = b[j];
            b[j]   = t;
        }
    }
    _n00b_crash_write_bytes(b, (size_t)n);
}

static void
_n00b_crash_write_hex(uintptr_t v)
{
    char b[18];
    b[0] = '0';
    b[1] = 'x';
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (uint8_t)((v >> ((15 - i) * 4)) & 0xf);
        b[2 + i] = (char)(nibble < 10 ? '0' + nibble
                                      : 'a' + (nibble - 10));
    }
    _n00b_crash_write_bytes(b, sizeof(b));
}

static void
_n00b_crash_write_ptr(const void *p)
{
    _n00b_crash_write_hex((uintptr_t)p);
}

static bool
_n00b_crash_addr_offset(uintptr_t addr, uintptr_t *out)
{
    uintptr_t base = n00b_atomic_load(&g_n00b_crash_image_load_base);
    if (base == 0 || addr < base) {
        return false;
    }
    *out = addr - base;
    return true;
}

static void
_n00b_crash_write_addr_offset(const char *label, uintptr_t addr)
{
    uintptr_t offset = 0;
    _n00b_crash_write(label);
    if (!_n00b_crash_addr_offset(addr, &offset)) {
        _n00b_crash_write("unavailable");
        return;
    }
    _n00b_crash_write_hex(offset);
}

static void
_n00b_crash_dump_image_info(void)
{
    uintptr_t vmaddr = n00b_atomic_load(&g_n00b_crash_image_vmaddr);
    uintptr_t base   = n00b_atomic_load(&g_n00b_crash_image_load_base);
    uintptr_t slide  = n00b_atomic_load(&g_n00b_crash_image_slide);
    uintptr_t text_s = n00b_atomic_load(&g_n00b_crash_text_start);
    uintptr_t text_e = n00b_atomic_load(&g_n00b_crash_text_end);

    _n00b_crash_write("n00b: crash image vmaddr=");
    _n00b_crash_write_hex(vmaddr);
    _n00b_crash_write(" load_base=");
    _n00b_crash_write_hex(base);
    _n00b_crash_write(" slide=");
    _n00b_crash_write_hex(slide);
    _n00b_crash_write(" text=[");
    _n00b_crash_write_hex(text_s);
    _n00b_crash_write(",");
    _n00b_crash_write_hex(text_e);
    _n00b_crash_write(")\n");
}

static void
_n00b_crash_dump_frame_chain(uintptr_t fp)
{
    _n00b_crash_write("n00b: crash frames fp=");
    _n00b_crash_write_hex(fp);
    _n00b_crash_write("\n");

    // Best-effort raw frame-pointer walk. Every memory read can fault if the
    // stack is corrupt, so keep this bounded and monotonic. If the first read
    // would fault, SA_RESETHAND makes the default signal path take over.
    for (uint32_t i = 0; i < 16 && fp != 0; i++) {
        uintptr_t *frame = (uintptr_t *)fp;
        uintptr_t  next  = frame[0];
        uintptr_t  ret   = frame[1];

        _n00b_crash_write("n00b: crash frame[");
        _n00b_crash_write_u64(i);
        _n00b_crash_write("] fp=");
        _n00b_crash_write_hex(fp);
        _n00b_crash_write(" ret=");
        _n00b_crash_write_hex(ret);
        _n00b_crash_write(" ret_off=");
        uintptr_t off = 0;
        if (_n00b_crash_addr_offset(ret, &off)) {
            _n00b_crash_write_hex(off);
        } else {
            _n00b_crash_write("unavailable");
        }
        _n00b_crash_write("\n");

        if (next <= fp || (next - fp) > (uintptr_t)(16 * 1024 * 1024)) {
            break;
        }
        fp = next;
    }
}

static uintptr_t
_n00b_crash_ucontext_pc(void *uctx)
{
    if (uctx == nullptr) {
        return 0;
    }
    ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__APPLE__) && defined(__aarch64__)
    return (uintptr_t)__darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
#elif defined(__APPLE__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext->__ss.__rip;
#elif defined(__linux__) && defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.pc;
#elif defined(__linux__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#else
    (void)uc;
    return 0;
#endif
}

static uintptr_t
_n00b_crash_ucontext_lr(void *uctx)
{
    if (uctx == nullptr) {
        return 0;
    }
    ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__APPLE__) && defined(__aarch64__)
    return (uintptr_t)__darwin_arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
#elif defined(__linux__) && defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.regs[30];
#else
    (void)uc;
    return 0;
#endif
}

static uintptr_t
_n00b_crash_ucontext_sp(void *uctx)
{
    if (uctx == nullptr) {
        return 0;
    }
    ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__APPLE__) && defined(__aarch64__)
    return (uintptr_t)__darwin_arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
#elif defined(__APPLE__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext->__ss.__rsp;
#elif defined(__linux__) && defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.sp;
#elif defined(__linux__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
#else
    (void)uc;
    return 0;
#endif
}

static uintptr_t
_n00b_crash_ucontext_fp(void *uctx)
{
    if (uctx == nullptr) {
        return 0;
    }
    ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__APPLE__) && defined(__aarch64__)
    return (uintptr_t)__darwin_arm_thread_state64_get_fp(uc->uc_mcontext->__ss);
#elif defined(__APPLE__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext->__ss.__rbp;
#elif defined(__linux__) && defined(__aarch64__)
    return (uintptr_t)uc->uc_mcontext.regs[29];
#elif defined(__linux__) && defined(__x86_64__)
    return (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
#else
    (void)uc;
    return 0;
#endif
}

static void
_n00b_crash_dump_context(int sig,
                         siginfo_t *si,
                         void *uctx,
                         n00b_thread_t *faulting,
                         bool overflow)
{
    uintptr_t pc = _n00b_crash_ucontext_pc(uctx);
    uintptr_t lr = _n00b_crash_ucontext_lr(uctx);
    uintptr_t sp = _n00b_crash_ucontext_sp(uctx);
    uintptr_t fp = _n00b_crash_ucontext_fp(uctx);

    _n00b_crash_write("n00b: crash sig=");
    _n00b_crash_write_u64((uint64_t)sig);
    _n00b_crash_write(" fault_addr=");
    _n00b_crash_write_ptr(si != nullptr ? si->si_addr : nullptr);
    _n00b_crash_write(" overflow=");
    _n00b_crash_write(overflow ? "1" : "0");
    _n00b_crash_write(" pc=");
    _n00b_crash_write_hex(pc);
    _n00b_crash_write(" pc_off=");
    _n00b_crash_write_addr_offset("", pc);
    _n00b_crash_write(" lr=");
    _n00b_crash_write_hex(lr);
    _n00b_crash_write(" lr_off=");
    _n00b_crash_write_addr_offset("", lr);
    _n00b_crash_write(" sp=");
    _n00b_crash_write_hex(sp);
    _n00b_crash_write(" fp=");
    _n00b_crash_write_hex(fp);
    _n00b_crash_write("\n");
    _n00b_crash_dump_image_info();

    if (faulting != nullptr) {
        _n00b_crash_write("n00b: crash thread id=");
        _n00b_crash_write_u64((uint64_t)(uint32_t)faulting->id_info.parts.id);
        _n00b_crash_write(" generation=");
        _n00b_crash_write_u64((uint64_t)(uint32_t)faulting->id_info.parts.generation);
        _n00b_crash_write(" os_tid=");
        _n00b_crash_write_u64((uint64_t)faulting->os_tid);
        _n00b_crash_write(" guard=[");
        _n00b_crash_write_ptr(n00b_atomic_load(&faulting->guard_lo));
        _n00b_crash_write(",");
        _n00b_crash_write_ptr(n00b_atomic_load(&faulting->guard_hi));
        _n00b_crash_write(")");
        n00b_callstack_t *as = (n00b_callstack_t *)n00b_atomic_load(
            &faulting->altstack);
        _n00b_crash_write(" altstack=[");
        _n00b_crash_write_ptr(as != nullptr ? as->region_start : nullptr);
        _n00b_crash_write(",");
        _n00b_crash_write_ptr(as != nullptr
                                  ? (void *)((char *)as->region_start + as->region_size)
                                  : nullptr);
        _n00b_crash_write(")\n");
    } else {
        _n00b_crash_write("n00b: crash thread unresolved\n");
    }

    if (fp != 0) {
        _n00b_crash_dump_frame_chain(fp);
    }
}

// SIGSEGV/SIGBUS fault handler.  Runs in signal context on the faulting
// thread's alternate stack (SA_ONSTACK), which is an n00b callstack stamped
// with this thread's slot id — so n00b_thread_self() (and the ncc-emitted
// gc_stack_push in this function's own prologue) resolve correctly here.
// Async-signal-safe: stable reads and raw writes only.  The handler is installed
// with SA_RESETHAND; after the diagnostic write / optional callback it returns
// to the faulting context, which immediately re-faults under the default
// disposition.  That preserves n00b's one-line diagnosis while letting the OS
// crash reporter produce a normal report for the real fault.
static void
_n00b_crash_handler(int sig, siginfo_t *si, void *uctx)
{
    // Resolve the FAULTING thread by the altstack region we are running on (a
    // local's address lies in that slot's altstack-callstack region).  We do
    // NOT trust n00b_thread_self() for this: self() resolves via the altstack's
    // stamped ID word, which is enough to keep this function's gc_stack_push
    // PROLOGUE from faulting, but the range scan is what reliably identifies
    // which thread overflowed.  Async-signal-safe: stable per-slot reads.
    volatile int marker = 0;
    uintptr_t    hsp    = (uintptr_t)(void *)&marker;

    // AS-safe runtime access: n00b_get_runtime() goes through n00b_option_get,
    // whose assert() is NOT async-signal-safe.  Read the option directly; if the
    // runtime is not yet set (a fault before init completes), return so the
    // default disposition handles the original fault.
    if (!n00b_option_is_set(n00b_default_runtime)) {
        _n00b_crash_write("n00b: fatal: fault before runtime init\n");
        return;
    }
    n00b_runtime_t *rt       = n00b_option_get_or_else(n00b_default_runtime, nullptr);
    n00b_thread_t  *faulting = nullptr;

    if (rt != nullptr && rt->threads != nullptr) {
        for (uint32_t i = 0; i < rt->max_threads; i++) {
            // The altstack lives on the per-worker thread struct (D-039), so
            // reach it via the slot's published thread pointer.  Both reads are
            // stable (user_pool, non-moving) and async-signal-safe.
            n00b_thread_t *t = n00b_atomic_load(&rt->threads[i].thread);
            if (t == nullptr || (uintptr_t)t <= 1) {
                continue; // empty slot or placeholder
            }
            n00b_callstack_t *as = (n00b_callstack_t *)n00b_atomic_load(
                &t->altstack);
            if (as != nullptr) {
                uintptr_t lo = (uintptr_t)as->region_start;
                uintptr_t hi = lo + as->region_size;
                if (hsp >= lo && hsp < hi) {
                    faulting = t;
                    break;
                }
            }
        }
    }

    // Classify: a fault address inside the faulting thread's PROT_NONE guard
    // band is a stack overflow (lock-free range compare on the cached bounds).
    // guard_lo/hi are _Atomic — load with acquire to pair with the owning
    // thread's release store (it stores hi then lo before its altstack install).
    bool overflow = false;
    if (faulting != nullptr && si != nullptr) {
        void *glo = n00b_atomic_load(&faulting->guard_lo);
        void *ghi = n00b_atomic_load(&faulting->guard_hi);
        if (glo != nullptr) {
            uintptr_t fa = (uintptr_t)si->si_addr;
            if (fa >= (uintptr_t)glo && fa < (uintptr_t)ghi) {
                overflow = true;
            }
        }
    }

    _n00b_crash_write(sig == SIGABRT ? "n00b: fatal: aborted\n"
                      : overflow     ? "n00b: fatal: stack overflow\n"
                                     : "n00b: fatal: invalid memory access\n");
    _n00b_crash_dump_context(sig, si, uctx, faulting, overflow);

    // SYMBOLICATED (DWARF) backtrace via the full capture -> resolve -> render
    // path.  That path takes ordinary rwlocks (mmap registry / list / dict),
    // which assert in this non-TCB signal context unless the world is stopped, so
    // we STOP THE WORLD.  stop_the_world() first does a REAL
    // n00b_rw_write_lock(&critical_execution), which would block or assert here;
    // that write-lock is RE-ENTRANT, so we forge our ownership into the gate's
    // packed owner field first -- then stop_the_world's acquire is a no-op while
    // it still suspends every OTHER thread and sets the rwlock STW short-circuit,
    // and the walk runs ALONE.  We are terminating; we never restart the world.
    if (rt != nullptr) {
        if (!n00b_atomic_load(&rt->stw_active)) {
            n00b_core_lock_info_t cinfo = n00b_atomic_load(
                &rt->critical_execution.data);
            cinfo.owner = n00b_os_thread_id();
            if (cinfo.nesting < 1) {
                cinfo.nesting = 1;
            }
            n00b_atomic_store(&rt->critical_execution.data, cinfo);
            n00b_stop_the_world();
        }
        n00b_result_t(n00b_crash_capture_t *) cr = n00b_crash_capture(
            .uctx        = uctx,
            .siginfo     = si,
            .signal_num  = sig,
            .from_signal = true);
        if (n00b_result_is_ok(cr)) {
            n00b_crash_capture_t *cap = n00b_result_get(cr);
            (void)n00b_crash_resolve(cap); // Phase B: DWARF file:line
            n00b_string_t *rendered = n00b_crash_render(cap);
            if (rendered != nullptr && rendered->data != nullptr) {
                n00b_raw_write(2,
                               rendered->data,
                               (unsigned long)rendered->u8_bytes);
            }
        }
    }

    // Deliver to the faulting thread's registered crash handler (WP-2 surface),
    // if any; then return so the default disposition handles the original
    // fault. The handler cannot resume the faulting operation.
    if (faulting != nullptr && faulting->crash_handler != nullptr) {
        faulting->crash_handler(faulting, faulting->crash_handler_data);
    }

    return;
}

#endif // !_WIN32

#if !defined(_WIN32)
static void
_n00b_crash_init_image_info(void)
{
#if defined(__APPLE__)
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (mh == nullptr || mh->filetype != MH_EXECUTE) {
            continue;
        }

        uintptr_t vmaddr = 0;
        uintptr_t vmsize = 0;

        if (mh->magic == MH_MAGIC_64) {
            const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
            const char *cmd = (const char *)(mh64 + 1);
            for (uint32_t n = 0; n < mh64->ncmds; n++) {
                const struct load_command *lc = (const struct load_command *)cmd;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg =
                        (const struct segment_command_64 *)cmd;
                    if (seg->segname[0] == '_' && seg->segname[1] == '_' &&
                        seg->segname[2] == 'T' && seg->segname[3] == 'E' &&
                        seg->segname[4] == 'X' && seg->segname[5] == 'T' &&
                        seg->segname[6] == '\0') {
                        vmaddr = (uintptr_t)seg->vmaddr;
                        vmsize = (uintptr_t)seg->vmsize;
                        break;
                    }
                }
                cmd += lc->cmdsize;
            }
        }

        intptr_t  signed_slide = _dyld_get_image_vmaddr_slide(i);
        uintptr_t slide        = (uintptr_t)signed_slide;
        uintptr_t base         = vmaddr + slide;

        n00b_atomic_store(&g_n00b_crash_image_vmaddr, vmaddr);
        n00b_atomic_store(&g_n00b_crash_image_slide, slide);
        n00b_atomic_store(&g_n00b_crash_image_load_base, base);
        n00b_atomic_store(&g_n00b_crash_text_start, base);
        n00b_atomic_store(&g_n00b_crash_text_end, base + vmsize);
        return;
    }
#endif
}
#endif

void
n00b_crash_init(void)
{
#if !defined(_WIN32)
    _n00b_crash_init_image_info();

    // Main-thread altstack (deferred from P2 to here, where the mmap machinery
    // and the default allocator are fully up).  Workers install theirs in the
    // launcher from a bundle-carried pool region; the main thread draws its own
    // here.  Unlike a launching worker, the main thread's default allocator is
    // live, so a callstack-pool MISS (the pool is empty at init) falls back to a
    // clean n00b_callstack_alloc.  The main thread is never reaped, so this one
    // region is held for the runtime's lifetime (exactly one, not per-slot).
    n00b_result_t(n00b_callstack_t *) main_as = n00b_callstack_pool_get();
    n00b_crash_install_altstack(n00b_result_is_ok(main_as)
                                    ? n00b_result_get(main_as)
                                    : nullptr);

    struct sigaction sa = {};
    sa.sa_sigaction     = _n00b_crash_handler;
    sa.sa_flags         = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);

    // NOTE (WP-3b audit): we do not yet CHAIN a pre-existing SIGSEGV handler.
    // No fault handler is installed before n00b_crash_init (conduit/display
    // sigaction sites cover other signals / are armed on demand later); if a
    // SIGSEGV watch is ever armed before init, chaining via the saved oldact is
    // the follow-up.  GC memory-permission checks use poll/read, not faults, so
    // this handler does not intercept GC traffic.
    (void)sigaction(SIGSEGV, &sa, nullptr);
    (void)sigaction(SIGBUS, &sa, nullptr);
    // Also catch SIGABRT so a deliberate n00b_abort() (and any libc/3rd-party
    // abort raised on a thread that can deliver it) produces an n00b context
    // dump.  Delivered via kill()/raise(), not a synchronous fault: the handler
    // dumps and returns; n00b_abort then exits explicitly (the resumed caller),
    // and a default abort path proceeds to libc termination after the dump.
    (void)sigaction(SIGABRT, &sa, nullptr);
#else
    // Windows: AddVectoredExceptionHandler equivalent — written-only,
    // host-verified later (D-026/D-028).
    (void)0;
#endif
}
