// Generalized, structured crash-log / backtrace capability for libn00b.
//
// This is the structured, two-phase generalization of the diagnostic-only
// fault handler in crash.c.  It assembles EXISTING primitives -- the FP walk
// and per-arch register extraction from crash.c, n00b_mmap_handler_lookup for
// AS-safe module resolution, n00b_mmap(.skip_register=true) for registry-free
// scratch, n00b_find_alloc_info / n00b_type_info_for for gc-map info, and
// dladdr for Phase-B symbolication -- into a structured result.
//
// See include/core/crash_capture.h and the design spec for the full contract.
//
// SAFETY-CRITICAL (audit these two):
//  1. Recursion guard: a per-thread depth counter (indexed by the thread's slot
//     id, AS-safely) bounds re-entry to N00B_CRASH_MAX_REENTRY.  A fault during
//     capture returns a minimal, degraded result (reentered=true), never a loop.
//  2. Allocation contract: Phase A works in a throw-away per-thread scratch
//     arena grown via registry-free mmap; the finished result is copied ONCE
//     into the caller's destination arena.  Copy-out into the GC heap is REFUSED
//     while the world is stopped: the caller must supply a non-GC .dest, else
//     the capture fails with N00B_CRASH_ERR_NEED_NONGC_DEST -- there is no defer
//     and the GC heap is never written.

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/crash_capture.h"
#include "core/crash.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mmaps.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/stw.h"
#include "core/align.h"
#include "core/type_info.h"
#include "core/string.h"
#include "text/strings/string_ops.h"
#include "text/strings/format.h"
#include "adt/dict.h"                  // per-module DWARF cache (Phase B)
#include "compiler/objfile/abstract.h" // n00b_parse_file / n00b_binary_dwarf
#include "compiler/objfile/dwarf.h"    // DWARF file:line symbolication (Phase B)

#if !defined(_WIN32)
#include <signal.h>
#if defined(__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif
#include <sys/mman.h> // raw munmap for registry-free scratch teardown
#include <dlfcn.h>    // dladdr (Phase B symbol-only fallback) -- NOT AS-safe
#include "core/syscall.h" // n00b_raw_write -- libc-free, AS-safe
#endif

// ===========================================================================
// Recursion guard (safety-critical #1).
//
// Per-thread, no global cap (design section 6.1 / decision 3).  We do NOT add a
// field to n00b_thread_t (kept out of scope); instead a process-global atomic
// array indexed by the faulting thread's slot id (bounded by N00B_THREADS_MAX)
// holds the per-thread depth.  Reads/writes are atomic and allocation-free, so
// this is AS-safe.  The slot id is read AS-safely off the resolved thread the
// same way crash.c's handler does.
// ===========================================================================

// One extra slot beyond the valid thread-id range: index N00B_THREADS_MAX is a
// DEDICATED overflow slot for unresolvable / foreign threads, so it never
// collides with a real thread that happens to own the last valid slot
// (N00B_THREADS_MAX - 1).
#define N00B_CRASH_GUARD_OVERFLOW_SLOT N00B_THREADS_MAX
static _Atomic(uint8_t) g_crash_capture_depth[N00B_THREADS_MAX + 1];

// Returns the caller's slot id, or the dedicated overflow slot when the thread
// is unresolvable (e.g. a foreign thread) or carries an out-of-range id.  All
// such callers share the overflow slot (they serialize their guard, never
// under-count), but never share with a valid thread slot.
static inline uint32_t
crash_guard_slot(n00b_thread_t *t)
{
    if (t == nullptr) {
        return N00B_CRASH_GUARD_OVERFLOW_SLOT;
    }
    uint32_t id = (uint32_t)t->id_info.parts.id;
    if (id >= N00B_THREADS_MAX) {
        return N00B_CRASH_GUARD_OVERFLOW_SLOT;
    }
    return id;
}

// ===========================================================================
// Scratch arena (safety-critical #2, capture side).
//
// A throw-away bump arena that grows via n00b_mmap(.skip_register=true) -- pages
// that never enter the mmap registry, so growth touches no registry lock and no
// accounting from signal context (design section 5.2 / decision 5).  Freed
// wholesale at capture end via raw munmap (the pages are unregistered).
// ===========================================================================

typedef struct crash_scratch_chunk_t {
    struct crash_scratch_chunk_t *next;
    size_t                        size;  // total mapped bytes (incl. this header)
    size_t                        used;  // bytes consumed (incl. this header)
} crash_scratch_chunk_t;

typedef struct {
    crash_scratch_chunk_t *head;
    bool                   oom; // a growth mmap failed; capture degrades
} crash_scratch_t;

static crash_scratch_chunk_t *
crash_scratch_map_chunk(size_t want)
{
#if defined(_WIN32)
    (void)want;
    return nullptr;
#else
    size_t sz = n00b_page_align(want);
    n00b_result_t(void *) r = n00b_mmap(sz, .skip_register = true);
    if (n00b_result_is_err(r)) {
        return nullptr;
    }
    crash_scratch_chunk_t *c = (crash_scratch_chunk_t *)n00b_result_get(r);
    c->next                  = nullptr;
    c->size                  = sz;
    c->used                  = sizeof(crash_scratch_chunk_t);
    return c;
#endif
}

static void
crash_scratch_init(crash_scratch_t *s, size_t first_chunk)
{
    s->oom  = false;
    s->head = crash_scratch_map_chunk(first_chunk);
    if (s->head == nullptr) {
        s->oom = true;
    }
}

static void *
crash_scratch_alloc(crash_scratch_t *s, size_t n)
{
    n = (n + (N00B_ALIGN - 1)) & ~((size_t)N00B_ALIGN - 1);

    crash_scratch_chunk_t *c = s->head;
    if (c != nullptr && (c->size - c->used) >= n) {
        void *p = (char *)c + c->used;
        c->used += n;
        return p;
    }

    // Grow: a fresh chunk sized to hold at least n plus a header, but at least
    // a default chunk so deep walks do not thrash mmap.
    size_t want = n + sizeof(crash_scratch_chunk_t);
    size_t dflt = (size_t)N00B_CRASH_DEFAULT_SCRATCH_KB * 1024;
    if (want < dflt) {
        want = dflt;
    }
    crash_scratch_chunk_t *nc = crash_scratch_map_chunk(want);
    if (nc == nullptr) {
        s->oom = true;
        return nullptr;
    }
    nc->next = s->head;
    s->head  = nc;
    void *p  = (char *)nc + nc->used;
    nc->used += n;
    return p;
}

static void
crash_scratch_teardown(crash_scratch_t *s)
{
#if !defined(_WIN32)
    crash_scratch_chunk_t *c = s->head;
    while (c != nullptr) {
        crash_scratch_chunk_t *next = c->next;
        // Raw munmap (not n00b_munmap): these chunks were mapped with
        // n00b_mmap(.skip_register=true), so they are NOT in the mmap registry;
        // n00b_munmap would try to unregister them and misfire.  Same pattern as
        // pool.c uses for its own unregistered pages.
        munmap((void *)c, c->size);
        c = next;
    }
#endif
    s->head = nullptr;
}

// AS-safe bounded byte-copy of a NUL-terminated C string into scratch, as a
// length-prefixed record.  Returns the scratch pointer and the length so the
// copy-out phase can quantify the destination size and re-materialize a real
// n00b_string_t (design section 6.3).  Never calls n00b_string ctors.
typedef struct {
    const char *bytes; // points INTO scratch
    size_t      len;
} crash_scratch_str_t;

static crash_scratch_str_t
crash_scratch_strdup(crash_scratch_t *s, const char *src)
{
    crash_scratch_str_t out = {.bytes = nullptr, .len = 0};
    if (src == nullptr) {
        return out;
    }
    // Bounded length scan: a registry-stored module path is finite, but cap it
    // defensively so a torn registry pointer cannot run off the end.
    size_t len = 0;
    while (len < 4096 && src[len] != '\0') {
        len++;
    }
    char *dst = crash_scratch_alloc(s, len + 1);
    if (dst == nullptr) {
        return out;
    }
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
    dst[len]  = '\0';
    out.bytes = dst;
    out.len   = len;
    return out;
}

// ===========================================================================
// Register extraction (Phase A).  Reuses crash.c's per-arch ucontext reads and
// extends them to fill the full GPR union.
// ===========================================================================

static void
crash_fill_regs(n00b_crash_regs_t *regs, void *uctx)
{
    *regs = (n00b_crash_regs_t){.arch = N00B_CRASH_ARCH_UNKNOWN, .valid = false};

#if !defined(_WIN32)
    if (uctx == nullptr) {
        // Manual capture: read live pc/sp/fp/lr from the call site.  We use
        // builtins so the values reflect THIS frame; the walk starts here.
        regs->valid = true;
        regs->pc    = (uintptr_t)__builtin_return_address(0);
        regs->fp    = (uintptr_t)__builtin_frame_address(0);
        regs->lr    = 0;
        // The actual stack pointer (NOT a copy of fp): read it directly so
        // consumers (alloc-info classification, stack-range checks, marshaled
        // diagnostics) get a true SP.
#if defined(__aarch64__)
        regs->arch = N00B_CRASH_ARCH_ARM64;
        __asm__ volatile("mov %0, sp" : "=r"(regs->sp));
#elif defined(__x86_64__)
        regs->arch = N00B_CRASH_ARCH_X86_64;
        __asm__ volatile("movq %%rsp, %0" : "=r"(regs->sp));
#else
        regs->sp = 0; // unknown arch: 0 rather than a misleading fp copy
#endif
        return;
    }

    ucontext_t *uc = (ucontext_t *)uctx;
    regs->valid    = true;

#if defined(__APPLE__) && defined(__aarch64__)
    regs->arch = N00B_CRASH_ARCH_ARM64;
    regs->pc   = (uintptr_t)__darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    regs->sp   = (uintptr_t)__darwin_arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
    regs->fp   = (uintptr_t)__darwin_arm_thread_state64_get_fp(uc->uc_mcontext->__ss);
    regs->lr   = (uintptr_t)__darwin_arm_thread_state64_get_lr(uc->uc_mcontext->__ss);
    for (int i = 0; i < 29; i++) {
        regs->gpr[i] = (uintptr_t)uc->uc_mcontext->__ss.__x[i];
    }
    regs->gpr[29] = regs->fp;
    regs->gpr[30] = regs->lr;
    regs->gpr_aux = (uint64_t)uc->uc_mcontext->__ss.__cpsr;
#elif defined(__APPLE__) && defined(__x86_64__)
    regs->arch              = N00B_CRASH_ARCH_X86_64;
    regs->pc                = (uintptr_t)uc->uc_mcontext->__ss.__rip;
    regs->sp                = (uintptr_t)uc->uc_mcontext->__ss.__rsp;
    regs->fp                = (uintptr_t)uc->uc_mcontext->__ss.__rbp;
    regs->lr                = 0;
    regs->gpr[0]  = (uintptr_t)uc->uc_mcontext->__ss.__rax;
    regs->gpr[1]  = (uintptr_t)uc->uc_mcontext->__ss.__rbx;
    regs->gpr[2]  = (uintptr_t)uc->uc_mcontext->__ss.__rcx;
    regs->gpr[3]  = (uintptr_t)uc->uc_mcontext->__ss.__rdx;
    regs->gpr[4]  = (uintptr_t)uc->uc_mcontext->__ss.__rsi;
    regs->gpr[5]  = (uintptr_t)uc->uc_mcontext->__ss.__rdi;
    regs->gpr[6]  = (uintptr_t)uc->uc_mcontext->__ss.__rbp;
    regs->gpr[7]  = (uintptr_t)uc->uc_mcontext->__ss.__rsp;
    regs->gpr[8]  = (uintptr_t)uc->uc_mcontext->__ss.__r8;
    regs->gpr[9]  = (uintptr_t)uc->uc_mcontext->__ss.__r9;
    regs->gpr[10] = (uintptr_t)uc->uc_mcontext->__ss.__r10;
    regs->gpr[11] = (uintptr_t)uc->uc_mcontext->__ss.__r11;
    regs->gpr[12] = (uintptr_t)uc->uc_mcontext->__ss.__r12;
    regs->gpr[13] = (uintptr_t)uc->uc_mcontext->__ss.__r13;
    regs->gpr[14] = (uintptr_t)uc->uc_mcontext->__ss.__r14;
    regs->gpr[15] = (uintptr_t)uc->uc_mcontext->__ss.__r15;
    regs->gpr_aux = (uint64_t)uc->uc_mcontext->__ss.__rflags;
#elif defined(__linux__) && defined(__aarch64__)
    regs->arch = N00B_CRASH_ARCH_ARM64;
    regs->pc   = (uintptr_t)uc->uc_mcontext.pc;
    regs->sp   = (uintptr_t)uc->uc_mcontext.sp;
    regs->fp   = (uintptr_t)uc->uc_mcontext.regs[29];
    regs->lr   = (uintptr_t)uc->uc_mcontext.regs[30];
    for (int i = 0; i < 31; i++) {
        regs->gpr[i] = (uintptr_t)uc->uc_mcontext.regs[i];
    }
    regs->gpr_aux = (uint64_t)uc->uc_mcontext.pstate;
#elif defined(__linux__) && defined(__x86_64__)
    regs->arch             = N00B_CRASH_ARCH_X86_64;
    regs->pc               = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    regs->sp               = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    regs->fp               = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
    regs->lr               = 0;
    regs->gpr[0]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RAX];
    regs->gpr[1]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RBX];
    regs->gpr[2]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RCX];
    regs->gpr[3]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RDX];
    regs->gpr[4]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RSI];
    regs->gpr[5]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RDI];
    regs->gpr[6]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
    regs->gpr[7]  = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    regs->gpr[8]  = (uintptr_t)uc->uc_mcontext.gregs[REG_R8];
    regs->gpr[9]  = (uintptr_t)uc->uc_mcontext.gregs[REG_R9];
    regs->gpr[10] = (uintptr_t)uc->uc_mcontext.gregs[REG_R10];
    regs->gpr[11] = (uintptr_t)uc->uc_mcontext.gregs[REG_R11];
    regs->gpr[12] = (uintptr_t)uc->uc_mcontext.gregs[REG_R12];
    regs->gpr[13] = (uintptr_t)uc->uc_mcontext.gregs[REG_R13];
    regs->gpr[14] = (uintptr_t)uc->uc_mcontext.gregs[REG_R14];
    regs->gpr[15] = (uintptr_t)uc->uc_mcontext.gregs[REG_R15];
    regs->gpr_aux = (uint64_t)uc->uc_mcontext.gregs[REG_EFL];
#else
    regs->valid = false;
#endif
#else
    // TODO(crash): Windows -- map EXCEPTION_POINTERS->ContextRecord here.
    (void)uctx;
#endif
}

// ===========================================================================
// Phase A intermediate (scratch) representation.  Built in scratch, then copied
// out.  Strings are scratch_str records so copy-out can quantify + rebuild.
// ===========================================================================

typedef struct {
    uint32_t            index;
    uintptr_t           pc;
    bool                pc_is_return;
    bool                module_resolved;
    crash_scratch_str_t module;
    uintptr_t           module_offset;
    uintptr_t           load_slide;
    uintptr_t           module_start;
    uintptr_t           module_end;
    n00b_crash_meminfo_t meminfo; // type_name left option-none in Phase A
} crash_scratch_frame_t;

// AS-safe per-pc module resolution via the documented handler-safe lookup.
static void
crash_resolve_module(crash_scratch_t      *s,
                     crash_scratch_frame_t *f)
{
    uint64_t    mstart = 0, mend = 0;
    uint32_t    kind = 0, sline = 0;
    const char *file = nullptr, *sfile = nullptr;

    void *hit = n00b_mmap_handler_lookup(f->pc,
                                         &mstart,
                                         &mend,
                                         &kind,
                                         &file,
                                         &sfile,
                                         &sline);
    if (hit == nullptr) {
        f->module_resolved = false;
        return;
    }
    f->module_resolved = true;
    f->module_start    = (uintptr_t)mstart;
    f->module_end      = (uintptr_t)mend;
    // The registry stores slide as the negative load slide for static images
    // (memory_info.c uses .slide=-slide); module_offset = pc - load_base, which
    // for a registered static range is pc - mstart + binary_offset.  We expose
    // the simple, atos/addr2line-usable pc - mstart here and leave slide as the
    // registry's stored value where available (best-effort).
    f->module_offset = (f->pc >= (uintptr_t)mstart) ? (f->pc - (uintptr_t)mstart) : 0;
    f->load_slide    = 0; // registry slide not surfaced by handler_lookup; B can refine
    if (file != nullptr) {
        f->module = crash_scratch_strdup(s, file);
    }
}

// AS-safe-with-precondition per-pc gc/alloc info.  Skipped entirely when the
// world is stopped (design section 6.4): the allocator-metadata / type-registry
// dicts are only mid-mutation under STW, which stw_active gates.
static void
crash_resolve_meminfo(crash_scratch_frame_t *f, bool with_meminfo)
{
    f->meminfo = (n00b_crash_meminfo_t){
        .mem_class = N00B_CRASH_MEM_UNKNOWN,
        .resolved  = false,
        .type_name = nullptr,
    };
    if (!with_meminfo) {
        return;
    }

    n00b_alloc_info_t info = n00b_find_alloc_info((void *)f->pc);
    switch (info.kind) {
    case n00b_alloc_oob:
        f->meminfo.mem_class     = N00B_CRASH_MEM_HEAP_OOB;
        f->meminfo.resolved  = true;
        f->meminfo.type_hash  = info.hdr.oob->tinfo;
        f->meminfo.alloc_len = info.hdr.oob->alloc_len;
        f->meminfo.is_array  = info.hdr.oob->is_array;
        f->meminfo.no_scan   = info.hdr.oob->no_scan;
        break;
    case n00b_alloc_inline:
        f->meminfo.mem_class     = N00B_CRASH_MEM_HEAP_INLINE;
        f->meminfo.resolved  = true;
        f->meminfo.type_hash  = info.hdr.in_line->tinfo;
        f->meminfo.alloc_len = info.hdr.in_line->alloc_len;
        f->meminfo.is_array  = info.hdr.in_line->is_array;
        f->meminfo.no_scan   = info.hdr.in_line->no_scan;
        break;
    case n00b_alloc_static_range:
        f->meminfo.mem_class     = N00B_CRASH_MEM_STATIC_OBJECT;
        f->meminfo.resolved  = true;
        f->meminfo.type_hash  = info.hdr.range->tinfo;
        break;
    default:
        break;
    }
}

// ===========================================================================
// Copy-out helpers (Phase A -> destination arena).
// ===========================================================================

static n00b_string_t *
crash_dest_string(n00b_allocator_t *dest, crash_scratch_str_t s)
{
    if (s.bytes == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(s.bytes, (int64_t)s.len, .allocator = dest);
}

// ===========================================================================
// Core capture.
// ===========================================================================

// Resolve the destination allocator; nullptr from a manual capture means the GC
// heap (default allocator), nullptr from the signal path means the GC-hidden
// crash allocator.  We use n00b_system_allocator() (a non-moving, GC-visible
// pinned pool) as the durable signal-path default: it survives GC churn and is
// always safe to copy into (it is not the moving GC arena), satisfying the
// design's "non-moving / GC-hidden destination is always allowed" rule.
static n00b_allocator_t *
crash_signal_default_dest(void)
{
    return n00b_system_allocator();
}

// True iff copying out into `dest` is unsafe right now.  Per the contract,
// writing the MOVING GC heap during STW is forbidden; non-moving destinations
// (system pool / hidden pools, identified by allocator->hidden or by being the
// system pool) are always safe.
static bool
crash_dest_is_gc_heap(n00b_allocator_t *dest)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr) {
        return false;
    }
    n00b_allocator_t *def = n00b_atomic_load(&rt->default_allocator);
    return dest == def;
}

typedef n00b_list_t(n00b_crash_frame_t *) crash_frame_list_t;

// Allocate a frame list and box it (the schema stores `frames` as a pointer to
// the list struct so the capture object stays a flat, marshalable record).
static crash_frame_list_t *
crash_new_frame_list_boxed(n00b_allocator_t *dest, crash_frame_list_t **out_list)
{
    crash_frame_list_t  fl  = n00b_list_new(n00b_crash_frame_t *, .allocator = dest);
    crash_frame_list_t *box = n00b_alloc_with_opts(
        crash_frame_list_t, &(n00b_alloc_opts_t){.allocator = dest});
    *box      = fl;
    *out_list = box;
    return box;
}

static n00b_result_t(n00b_crash_capture_t *)
crash_capture_impl(void             *uctx,
                   void             *siginfo,
                   int               signal_num,
                   n00b_allocator_t *dest,
                   uint32_t          max_frames,
                   bool              with_meminfo,
                   bool              from_signal,
                   bool              manual_default_gc)
{
    // The n00b runtime must exist: capture relies on it for thread resolution,
    // alloc-info, and the destination allocator.  (n00b_crash_pool_init is a
    // soft arm-up only; scratch is on-demand, so it is not a hard precondition.)
    if (!n00b_option_is_set(n00b_default_runtime)) {
        return n00b_result_err(n00b_crash_capture_t *, (n00b_err_t)N00B_CRASH_ERR_NOT_INITIALIZED);
    }

    // ---- Resolve the destination arena + enforce the STW copy-out contract.
    if (dest == nullptr) {
        dest = manual_default_gc ? n00b_atomic_load(&n00b_get_runtime()->default_allocator)
                                 : crash_signal_default_dest();
    }

    // If copy-out would target the moving GC heap AND the world is stopped (or
    // otherwise GC-unsafe), refuse rather than defer.  An explicit non-GC dest
    // is always honored.
    bool stw = n00b_world_is_stopped();
    if (stw && crash_dest_is_gc_heap(dest)) {
        return n00b_result_err(n00b_crash_capture_t *, (n00b_err_t)N00B_CRASH_ERR_NEED_NONGC_DEST);
    }

    // ---- Recursion guard (safety-critical #1).
    n00b_thread_t *self = n00b_thread_self();
    uint32_t       slot = crash_guard_slot(self);
    uint8_t        prev = n00b_atomic_add(&g_crash_capture_depth[slot], 1);

    // Always-prepared regs (in hand from ucontext / live read; need no walk).
    n00b_crash_regs_t regs;
    crash_fill_regs(&regs, uctx);

    if (prev >= N00B_CRASH_MAX_REENTRY) {
        // Re-entry: return a MINIMAL degraded capture.  No walk, no alloc-info,
        // no module lookup -- those are exactly what can re-fault.  We still
        // must produce the object in `dest`; that is a single sized alloc and
        // does not re-enter capture.
        n00b_crash_capture_t *cap = n00b_alloc_with_opts(n00b_crash_capture_t,
                                                         &(n00b_alloc_opts_t){.allocator = dest});
        cap->cause            = (signal_num != 0) ? N00B_CRASH_CAUSE_OTHER
                                                  : N00B_CRASH_CAUSE_NONE;
        cap->signal_number    = signal_num;
        cap->regs             = regs;
        cap->reentered        = true;
        cap->frames_truncated = true;
        cap->frames_requested = max_frames;
        cap->frames_captured  = 0;
        cap->dest_arena       = (uintptr_t)dest;
        crash_frame_list_t *empty = nullptr;
        crash_new_frame_list_boxed(dest, &empty);
        cap->frames = empty;
        atomic_fetch_sub_explicit(&g_crash_capture_depth[slot], 1, memory_order_acq_rel);
        return n00b_result_ok(n00b_crash_capture_t *, cap);
    }

    // ---- Phase A in scratch.
    if (max_frames == 0) {
        max_frames = N00B_CRASH_DEFAULT_MAX_FRAMES;
    }
    // Under STW we cannot touch the alloc-metadata / type-registry dicts.
    bool do_meminfo = with_meminfo && !stw;

    crash_scratch_t scratch;
    crash_scratch_init(&scratch, (size_t)N00B_CRASH_DEFAULT_SCRATCH_KB * 1024);

    crash_scratch_frame_t *frames = crash_scratch_alloc(
        &scratch, sizeof(crash_scratch_frame_t) * max_frames);

    uint32_t n          = 0;
    bool     truncated  = false;

    // Innermost frame: the pc itself.
    uintptr_t pc = regs.pc;
    uintptr_t fp = regs.fp;

    if (frames != nullptr && pc != 0) {
        frames[n].index        = n;
        frames[n].pc           = pc;
        frames[n].pc_is_return = false;
        crash_resolve_module(&scratch, &frames[n]);
        crash_resolve_meminfo(&frames[n], do_meminfo);
        n++;
    }

    // Bounded, monotonic FP walk (generalized crash.c logic).  Every deref can
    // fault on a corrupt stack; the recursion guard (now held) covers a fault.
    for (; n < max_frames && fp != 0 && frames != nullptr; ) {
        uintptr_t *frame = (uintptr_t *)fp;
        uintptr_t  next  = frame[0];
        uintptr_t  ret   = frame[1];

        if (ret != 0) {
            frames[n].index        = n;
            frames[n].pc           = ret;
            frames[n].pc_is_return = true;
            crash_resolve_module(&scratch, &frames[n]);
            crash_resolve_meminfo(&frames[n], do_meminfo);
            n++;
        }

        if (next <= fp || (next - fp) > (uintptr_t)(16 * 1024 * 1024)) {
            break;
        }
        fp = next;
    }
    if (n >= max_frames && fp != 0) {
        truncated = true;
    }
    if (scratch.oom) {
        truncated = true;
    }

    // ---- Copy-out: one self-contained capture into `dest`.
    n00b_crash_capture_t *cap = n00b_alloc_with_opts(n00b_crash_capture_t,
                                                     &(n00b_alloc_opts_t){.allocator = dest});

    cap->signal_number      = signal_num;
    cap->regs               = regs;
    cap->reentered          = false;
    cap->frames_truncated   = truncated;
    cap->frames_requested   = max_frames;
    cap->frames_captured    = n;
    cap->dest_arena         = (uintptr_t)dest;
    cap->on_alternate_stack = from_signal;

    if (self != nullptr) {
        cap->thread_id         = (uint32_t)self->id_info.parts.id;
        cap->thread_generation = (uint32_t)self->id_info.parts.generation;
        cap->os_tid            = (uint64_t)self->os_tid;
    }

#if !defined(_WIN32)
    if (siginfo != nullptr) {
        siginfo_t *si       = (siginfo_t *)siginfo;
        cap->fault_address  = (uintptr_t)si->si_addr;
    }
#endif
    switch (signal_num) {
#if !defined(_WIN32)
    case SIGSEGV:
        cap->cause = N00B_CRASH_CAUSE_SEGV;
        break;
    case SIGBUS:
        cap->cause = N00B_CRASH_CAUSE_BUS;
        break;
#endif
    case 0:
        cap->cause = N00B_CRASH_CAUSE_NONE;
        break;
    default:
        cap->cause = N00B_CRASH_CAUSE_OTHER;
        break;
    }

    // Build the frame list in the destination arena.
    crash_frame_list_t *fl_box = nullptr;
    crash_new_frame_list_boxed(dest, &fl_box);
    for (uint32_t i = 0; i < n; i++) {
        n00b_crash_frame_t *df = n00b_alloc_with_opts(
            n00b_crash_frame_t, &(n00b_alloc_opts_t){.allocator = dest});
        df->index        = frames[i].index;
        df->pc           = frames[i].pc;
        df->pc_is_return = frames[i].pc_is_return;
        df->module_start = frames[i].module_start;
        df->module_end   = frames[i].module_end;
        df->meminfo      = frames[i].meminfo;

        if (frames[i].module_resolved) {
            df->module_resolved = true;
            df->module          = crash_dest_string(dest, frames[i].module);
            df->module_offset   = frames[i].module_offset;
            df->load_slide      = frames[i].load_slide;
        }
        n00b_list_push(*fl_box, df);
    }
    cap->frames = fl_box;

    // ---- Tear down scratch + release the recursion guard.
    crash_scratch_teardown(&scratch);
    atomic_fetch_sub_explicit(&g_crash_capture_depth[slot], 1, memory_order_acq_rel);

    return n00b_result_ok(n00b_crash_capture_t *, cap);
}

// ===========================================================================
// Public API.
// ===========================================================================

static _Atomic bool g_crash_capture_inited = false;

const char *
n00b_crash_err_str(n00b_crash_err_t err)
{
    switch (err) {
    case N00B_CRASH_ERR_NONE:
        return "no error";
    case N00B_CRASH_ERR_NOT_INITIALIZED:
        return "the n00b runtime is not yet initialized";
    case N00B_CRASH_ERR_NEED_NONGC_DEST:
        return "a non-GC destination allocator is required in this "
               "(GC-unsafe) context";
    default:
        return "unknown crash error";
    }
}

// clang-format off
void
n00b_crash_pool_init(void) _kargs
{
    uint32_t max_frames = N00B_CRASH_DEFAULT_MAX_FRAMES;
    uint32_t scratch_kb = N00B_CRASH_DEFAULT_SCRATCH_KB;
}
// clang-format on
{
    (void)max_frames;
    (void)scratch_kb;
    // Scratch is throw-away + per-thread + registry-free, so there is nothing
    // to pre-reserve here.  The signal-path default destination is the system
    // pool, which the runtime initializes before this point.  Mark armed.
    n00b_atomic_store(&g_crash_capture_inited, true);
}

// clang-format off
n00b_result_t(n00b_crash_capture_t *)
n00b_crash_capture(void) _kargs
{
    void             *uctx         = nullptr;
    void             *siginfo      = nullptr;
    int               signal_num   = 0;
    n00b_allocator_t *dest         = nullptr;
    uint32_t          max_frames   = 0;
    bool              with_meminfo = true;
    bool              from_signal  = false;
}
// clang-format on
{
    return crash_capture_impl(uctx,
                              siginfo,
                              signal_num,
                              dest,
                              max_frames,
                              with_meminfo,
                              from_signal,
                              /* manual_default_gc = */ false);
}

// clang-format off
n00b_result_t(n00b_crash_capture_t *)
n00b_backtrace_here(void) _kargs
{
    n00b_allocator_t *dest       = nullptr;
    uint32_t          max_frames = 0;
    bool              resolve    = true;
}
// clang-format on
{
    n00b_result_t(n00b_crash_capture_t *) r = crash_capture_impl(
        nullptr,
        nullptr,
        0,
        dest,
        max_frames,
        /* with_meminfo = */ true,
        /* from_signal  = */ false,
        /* manual_default_gc = */ true);

    if (resolve && n00b_result_is_ok(r)) {
        n00b_crash_resolve(n00b_result_get(r));
    }
    return r;
}

// ===========================================================================
// Phase B: resolve.  NOT signal-safe.  Uses the in-tree objfile + DWARF reader
// for file:line (cached per module), with dladdr as a symbol-only fallback.
// ===========================================================================

// DWARF symbolication cache.  Each module's on-disk objfile is parsed ONCE (via
// the in-tree elf/macho + DWARF reader) and the resulting n00b_dwarf_info_t* is
// cached by module path, so a multi-frame backtrace pays the parse at most once
// per module.  NOT signal-safe (allocates + reads files) — only reached from
// n00b_crash_resolve, the non-signal Phase B.  The cache is a GC root so the
// parsed DWARF graph (and the strings handed back from it) stay live.  Held as a
// void* at file scope (ncc does not parse a generic-struct type in a file-scope
// declaration); the typed n00b_dict_t handle is recovered inside the function.
static void *crash_dwarf_cache = nullptr;

// Sentinel cached for "parsed, but no usable DWARF" (system dylib / stripped /
// dyld-shared-cache path that is not a real file) so those modules are not
// re-parsed on every frame.
#define CRASH_DWARF_NONE ((void *)0x1)

static n00b_dwarf_info_t *
crash_dwarf_for_module(n00b_string_t *module)
{
    if (module == nullptr || module->data == nullptr) {
        return nullptr;
    }

    // crash_dwarf_cache is a file-scope static, so ncc auto-registers it as a GC
    // root (and traces the dict + parsed DWARF graph through it) — no manual
    // n00b_gc_register_root, which would walk it twice.
    n00b_dict_t(n00b_string_t *, void *) *cache = crash_dwarf_cache;
    if (cache == nullptr) {
        cache             = n00b_dict_new(n00b_string_t *, void *);
        crash_dwarf_cache = cache;
    }

    bool  found  = false;
    void *cached = n00b_dict_get(cache, module, &found);
    if (found) {
        return cached == CRASH_DWARF_NONE ? nullptr : (n00b_dwarf_info_t *)cached;
    }

    n00b_dwarf_info_t *info = nullptr;
    auto               br   = n00b_parse_file(module->data);
    if (n00b_result_is_ok(br)) {
        auto dr = n00b_binary_dwarf(n00b_result_get(br));
        if (n00b_result_is_ok(dr)) {
            info = n00b_result_get(dr);
        }
    }

    void *store = info != nullptr ? (void *)info : CRASH_DWARF_NONE;
    n00b_dict_put(cache, module, store);
    return info;
}

// clang-format off
bool
n00b_crash_resolve(n00b_crash_capture_t *capture) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    bool              demangle  = true;
}
// clang-format on
{
    n00b_require(capture != nullptr, "n00b_crash_resolve: null capture");
    (void)demangle;

    if (allocator == nullptr) {
        allocator = (n00b_allocator_t *)capture->dest_arena;
    }
    if (capture->frames == nullptr) {
        capture->phase_b_done = true;
        return false;
    }

    bool any = false;

#if !defined(_WIN32)
    n00b_list_t(n00b_crash_frame_t *) fl = *capture->frames;
    size_t count = n00b_list_len(fl);

    for (size_t i = 0; i < count; i++) {
        n00b_crash_frame_t *f = n00b_list_get(fl, i);
        if (f->symbol_resolved) {
            continue;
        }
        // For return addresses, look up pc-1 so we land inside the call, not on
        // the instruction after it.
        uintptr_t lookup = f->pc_is_return && f->pc > 0 ? f->pc - 1 : f->pc;
        Dl_info   di     = {};
        if (dladdr((void *)lookup, &di) != 0 && di.dli_sname != nullptr) {
            f->symbol          = n00b_string_from_cstr(di.dli_sname,
                                              .allocator = allocator);
            f->symbol_resolved = true;
            if (di.dli_saddr != nullptr) {
                f->symbol_offset = (lookup >= (uintptr_t)di.dli_saddr)
                                       ? (lookup - (uintptr_t)di.dli_saddr)
                                       : 0;
            }
            any = true;
        }
        // Full DWARF file:line via the in-tree objfile reader (parsed once per
        // module, cached).  Fills source_file/line/col and, if dladdr above
        // missed, the symbol name too.  DWARF addresses are link-time, so undo
        // the ASLR slide: link_addr = runtime_pc - load_slide.
        if (f->module_resolved && f->module != nullptr) {
            n00b_dwarf_info_t *dinfo = crash_dwarf_for_module(f->module);
            if (dinfo != nullptr) {
                uint64_t daddr = (uint64_t)lookup - (uint64_t)f->load_slide;

                n00b_dwarf_function_t *fn = n00b_dwarf_function_at_addr(dinfo,
                                                                        daddr);
                if (!f->symbol_resolved && fn != nullptr && fn->name != nullptr) {
                    f->symbol          = n00b_string_from_cstr(fn->name->data,
                                                      .allocator = allocator);
                    f->symbol_resolved = true;
                    f->symbol_offset   = daddr >= fn->low_pc ? daddr - fn->low_pc
                                                             : 0;
                    any                = true;
                }

                n00b_dwarf_line_entry_t *le = n00b_dwarf_line_at_addr(dinfo,
                                                                      daddr);
                if (le != nullptr && le->file != nullptr) {
                    f->source_file     = n00b_string_from_cstr(le->file,
                                                           .allocator = allocator);
                    f->source_line     = le->line;
                    f->source_col      = le->column;
                    f->source_resolved = true;
                    any                = true;
                }
                else if (fn != nullptr && fn->source_file != nullptr) {
                    f->source_file     = n00b_string_from_cstr(
                        fn->source_file->data,
                        .allocator = allocator);
                    f->source_line     = fn->source_line;
                    f->source_resolved = true;
                    any                = true;
                }
            }
        }
    }
#endif

    capture->phase_b_done = true;
    return any;
}

// ===========================================================================
// Rendering.
// ===========================================================================

// clang-format off
n00b_string_t *
n00b_crash_render(n00b_crash_capture_t *capture) _kargs
{
    bool              include_registers  = true;
    bool              include_meminfo    = true;
    bool              one_line_per_frame = true;
    n00b_allocator_t *allocator          = nullptr;
}
// clang-format on
{
    n00b_require(capture != nullptr, "n00b_crash_render: null capture");
    (void)one_line_per_frame;

    // Static literals are r"..." (no per-call allocation); the running `out`
    // accumulates into the caller's allocator via each cat's .allocator kwarg
    // (nullptr => GC heap).  Intermediate n00b_cformat temporaries land on the
    // GC heap, which is fine: render is a non-signal, non-STW consumer.
    n00b_string_t *out = r"n00b crash capture\n";

    if (capture->reentered) {
        out = n00b_unicode_str_cat(
            out,
            r"  [degraded: recursion guard re-entry]\n",
            .allocator = allocator);
    }
    if (capture->signal_number != 0) {
        out = n00b_unicode_str_cat(
            out,
            n00b_cformat("  signal=[|#|] fault_addr=0x[|#:x|]\n",
                         (int64_t)capture->signal_number,
                         (int64_t)capture->fault_address),
            .allocator = allocator);
    }

    if (include_registers && capture->regs.valid) {
        out = n00b_unicode_str_cat(
            out,
            n00b_cformat("  pc=0x[|#:x|] sp=0x[|#:x|] fp=0x[|#:x|] lr=0x[|#:x|]\n",
                         (int64_t)capture->regs.pc,
                         (int64_t)capture->regs.sp,
                         (int64_t)capture->regs.fp,
                         (int64_t)capture->regs.lr),
            .allocator = allocator);
    }

    if (capture->frames != nullptr) {
        n00b_list_t(n00b_crash_frame_t *) fl = *capture->frames;
        size_t count = n00b_list_len(fl);
        for (size_t i = 0; i < count; i++) {
            n00b_crash_frame_t *f   = n00b_list_get(fl, i);
            n00b_string_t      *sym = f->symbol;
            n00b_string_t      *mod = f->module;

            if (sym != nullptr) {
                int64_t soff = (int64_t)f->symbol_offset;
                out = n00b_unicode_str_cat(
                    out,
                    n00b_cformat("  #[|#|] 0x[|#:x|] [|#|]+0x[|#:x|]\n",
                                 (int64_t)f->index,
                                 (int64_t)f->pc,
                                 sym,
                                 soff),
                    .allocator = allocator);
            }
            else if (mod != nullptr) {
                int64_t moff = (int64_t)f->module_offset;
                out = n00b_unicode_str_cat(
                    out,
                    n00b_cformat("  #[|#|] 0x[|#:x|] [|#|]+0x[|#:x|]\n",
                                 (int64_t)f->index,
                                 (int64_t)f->pc,
                                 mod,
                                 moff),
                    .allocator = allocator);
            }
            else {
                out = n00b_unicode_str_cat(
                    out,
                    n00b_cformat("  #[|#|] 0x[|#:x|] <unresolved>\n",
                                 (int64_t)f->index,
                                 (int64_t)f->pc),
                    .allocator = allocator);
            }

            // Source file:line:col from DWARF (Phase B), when resolved.
            if (f->source_resolved && f->source_file != nullptr) {
                out = n00b_unicode_str_cat(
                    out,
                    n00b_cformat("       at [|#|]:[|#|]:[|#|]\n",
                                 f->source_file,
                                 (int64_t)f->source_line,
                                 (int64_t)f->source_col),
                    .allocator = allocator);
            }

            if (include_meminfo && f->meminfo.resolved) {
                out = n00b_unicode_str_cat(
                    out,
                    n00b_cformat("       mem: class=[|#|] typehash=0x[|#:x|] len=[|#|]\n",
                                 (int64_t)f->meminfo.mem_class,
                                 (int64_t)f->meminfo.type_hash,
                                 (int64_t)f->meminfo.alloc_len),
                    .allocator = allocator);
            }
        }
    }

    if (capture->frames_truncated) {
        out = n00b_unicode_str_cat(out,
                                   r"  [frames truncated]\n",
                                   .allocator = allocator);
    }
    return out;
}

#if !defined(_WIN32)
static void
crash_raw_hex(int fd, uintptr_t v)
{
    char b[18];
    b[0] = '0';
    b[1] = 'x';
    for (int i = 0; i < 16; i++) {
        uint8_t nib = (uint8_t)((v >> ((15 - i) * 4)) & 0xf);
        b[2 + i]    = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
    }
    n00b_raw_write(fd, b, sizeof(b));
}

static void
crash_raw_str(int fd, const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    n00b_raw_write(fd, s, n);
}
#endif

void
n00b_crash_render_raw_fd(n00b_crash_capture_t *capture, int fd)
{
#if !defined(_WIN32)
    if (capture == nullptr) {
        return;
    }
    crash_raw_str(fd, "n00b crash (raw): pc=");
    crash_raw_hex(fd, capture->regs.pc);
    crash_raw_str(fd, " sp=");
    crash_raw_hex(fd, capture->regs.sp);
    crash_raw_str(fd, " fp=");
    crash_raw_hex(fd, capture->regs.fp);
    crash_raw_str(fd, "\n");

    if (capture->frames != nullptr) {
        n00b_list_t(n00b_crash_frame_t *) fl = *capture->frames;
        // NOTE: in true signal context the list read lock is not AS-safe; the
        // raw renderer is intended for a capture whose frames live in a
        // non-moving dest and is read from a quiescent thread.  We bound by the
        // recorded frame count and read the backing array directly to avoid the
        // lock entirely.
        n00b_crash_frame_t **data  = fl.data;
        size_t               count = capture->frames_captured;
        for (size_t i = 0; i < count && data != nullptr; i++) {
            n00b_crash_frame_t *f = data[i];
            crash_raw_str(fd, "  pc=");
            crash_raw_hex(fd, f->pc);
            crash_raw_str(fd, "\n");
        }
    }
#else
    (void)capture;
    (void)fd;
#endif
}
