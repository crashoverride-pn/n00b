# Work Plan: Mostly-Copying (Pinning) GC for Preemptively-Suspended Thread Roots

Status: DESIGN COMPLETE, IMPLEMENTATION NOT STARTED.
Owner: (GC core — libn00b)
Last updated: 2026-06-16

This is a multi-step libn00b GC-core change. It must land incrementally, each
step green against the **full** `build_debug` unit suite, and clear the
prompt-auditor → n00b-code-auditor flow before push. Do NOT cram it in one edit:
a single segment-accounting mistake corrupts all allocation.

--------------------------------------------------------------------------------
## 1. The problem (PROVEN, not assumed)

The async rocs seal (`keep_standby=true`) runs the marshal on a **non-main**
worker thread. Under load it crashes at random sites (alloc / dict / vfs_write /
io-thread). Root cause, proven by instrumentation + ablation:

- n00b's GC is a **moving** (copying/compacting) collector over the shared
  default arena, with **preemptive** stop-the-world (Mach `thread_suspend` on
  macOS, RT-signal on Linux, `SuspendThread` on Windows).
- On STW, each non-self thread's registers are captured into
  `n00b_thread_t.gc_captured_regs` and the whole `n00b_thread_t` (incl. those
  regs) is conservatively scanned. The scan FORWARDS registers that point into
  the collected arena (object moves; captured slot rewritten to the new addr).
- BUT `_n00b_preempt_resume` (stw.c) then **zeroes the captured copy and
  `thread_resume`s the thread's ORIGINAL registers** — the forwarded values are
  discarded. So a thread holding a relocated heap pointer in a register resumes
  pointing into freed from-space → dangling → crash.
- PROOF: instrumented resume detected ~3 captured registers per rocs run that
  were forwarded, not copied back, and whose original value was now UNMAPPED.

The "register zero" only touches the captured COPY, never the real hardware
registers (confirmed) — so the bug is the MISSING copy-back, not a clobber.

### Why the obvious fixes are wrong (each tried, each reverted)

- **Blanket register copy-back** (write the forwarded `gc_captured_regs` back via
  `thread_set_state`/ucontext/`SetThreadContext`): PROVEN UNSAFE. Preemptive
  suspend lands a thread at an ARBITRARY PC, where its registers hold live
  INTERMEDIATE values, not clean roots. Conservative scanning can't distinguish
  an intermediate/integer from a real pointer; writing a "forwarded" value back
  into a live register corrupts busy threads. Empirically: without copy-back
  only the worker crashes (IO threads fine); with it the IO threads crash under
  load (`deliver_io_event` stack-overflow/abort, flaky). Skipping x18/fp/lr and
  guarding on "register actually changed" fixes the idle/syscall case but NOT the
  busy-in-user-code case. The C-stack slot scan gets away with forward+rewrite
  only because settled stack slots rarely false-positive and are usually dead;
  live registers are neither.
- **Keep the worker's allocations off the moving arena** (worker non-moving
  allocator; marshal ctx → user_pool; store VFS non-moving): whack-a-mole (each
  fix exposes the next moving object the worker holds), AND hit a separate latent
  bug — the pool registry uses a raw, non-STW-aware spinlock that deadlocks the
  collector. Not the real fix.

--------------------------------------------------------------------------------
## 2. The design: Bartlett-style mostly-copying GC

Precise roots (type-map / exact-stack-map / global) keep FORWARDING (compaction).
**Ambiguous** roots — a suspended thread's captured registers, and the
arbitrary-PC conservative C-stack — must PIN their target instead of moving it:
the ambiguous value can't be safely rewritten, so the object must not move.

Pin granularity = **page** (not segment — a stray register must pin a page, not
tens of MB; that is the gateway RSS constraint). At collect end: unpinned pages
are returned to the kernel; pinned pages survive in place, wrapped in fresh
NON-ALLOCATABLE segments hung off to-space.

### Segment representation change (prerequisite)

Today a segment is ONE mmap: `[n00b_segment_t header (inline) | mem[] data]`,
freed wholesale, scanned as `&seg->mem[0] .. seg->mem + (size - sizeof(header))`.
A retained pinned page can't host a header at its start (that's a live pinned
object). So:

- `n00b_segment_t` becomes a **descriptor allocated from `system_pool`**
  (non-moving, persistent), holding `{ size, next_segment, last_addr, data*,
  retained }`. The data region is a **separate mmap** referenced by `data`.
- Normal segment: descriptor (system_pool) + data mmap.
- Retained pinned run: descriptor (system_pool) + `data` → the surviving pages.
- Bump (`next_alloc`/`segment_end`), scan walk, `arena_used`/`arena_size`,
  `create_destination_arena`, and free all go through `desc->data`.
- Descriptors are freed via the **explicit-allocator free path** (system_pool has
  no metadata, so generic `n00b_free` can't reclaim it — must pass the allocator).

NOTE on `arena_overhead` (gc.c:1245): that is the per-ALLOCATION inline-header
size (`n00b_inline_hdr_t`), NOT the segment header — it is NOT affected by this
refactor. The forward/scan uses it for alloc user-ptr/len math; leave it alone.

--------------------------------------------------------------------------------
## 3. Build order (each step: full suite green before the next)

### Step 1 — Segment descriptor refactor (NO pin logic yet)  — DONE + VALIDATED 2026-06-16
Goal: every segment is `{descriptor in system_pool} + {separate data mmap}`,
behaviorally identical to today. This must regress nothing.

VALIDATION RESULT: full `build_debug` unit suite = 420 Ok / 10 Fail. All 10
failures accounted for as NON-regressions:
- 3 are the diagnostic repros (expected to crash — no pin logic yet):
  `rocs_async_seal_stress`, `worker_pool_gc_stress`, `gc_worker_trace`.
- 3 (`rocs_store_catalog`, `rocs_service_smoke`, `rocs_wax_cli`) were PROVEN
  pre-existing: built + ran on the clean parent commit `@-` (crash_capture, no
  session work at all) and fail IDENTICALLY there (store_catalog line 332
  rollback/path; service_smoke http!=200 line 203; wax_cli run_r not-ok). Their
  test files are unchanged this session. So neither Step 1 NOR the store.c
  async-seal work caused them.
- 4 pre-existing per memory: `gc_selective_scan` (= `test_bitmap_clearing`),
  `grammar_marshal_roundtrip`, `regex_engine` (flaky), `quic_sticky_secret`
  (flaky quic).
`test_condition` (exercises GC collect) passes; `gc_census` + the large-shard
seal test are green in-suite. Gate met: normal allocation does not regress.

FOLLOW-UP FALLOUT (found during Step 2 build-all): `test/integration/
test_arena_alloc.c:148` referenced the removed `seg->mem` field; fixed to
`seg->data` (integration tests are outside the `--suite unit` run, so this did
not surface in the Step 1 unit validation). No other `->mem` / `sizeof(
n00b_segment_t)` references remain repo-wide (grep clean).

Edits:
- `include/core/arena.h`: `struct n00b_segment_t` — drop `alignas(N00B_ALIGN)
  char mem[]`; add `char *data;` and `bool retained;`.
- `src/core/arena.c`:
  - `n00b_add_arena_segment` (~41): alloc descriptor from `system_pool`; mmap the
    data region (size = request + page; NO `+ sizeof(n00b_segment_t)` overhead);
    `desc->data = mmap`; `next_alloc = align(desc->data)`; `segment_end =
    desc->data + size`; `desc->last_addr = segment_end`; register the DATA range
    (`n00b_register_arena_segment(desc->data, segment_end, arena)`).
  - `arena_changed` (~112): compare `desired_value < current_segment->data`
    (was `< (char*)current_segment`).
  - `n00b_arena_delete` (~189): per segment, `munmap(seg->data, seg->size)` then
    free the descriptor via the explicit system_pool free; unregister data range.
  - `n00b_arena_reset` (~276): `&segment->mem[0]` → `segment->data`; the
    multi-segment collapse path mmaps a new data region + new descriptor.
- `include/core/gc.h`: `n00b_arena_used` (301) `&segment->mem[0]` → `segment->data`;
  `n00b_arena_size` (320) `size - sizeof(n00b_segment_t)` → `size`.
- `src/core/gc.c`: scan walk (2588-2589) `&seg->mem[0]`/`size - sizeof` →
  `seg->data`/`size`; `n00b_register_arena_segment` call (2950) pass data range;
  last_addr write (2998); verify `create_destination_arena` (1262) builds the new
  arena via the (now-fixed) `add_arena_segment` path.

HAZARD — bootstrap ordering: `system_pool` is initialized at init.c:352. MUST
confirm no arena/segment is created before that (slab setup at :345, the
bootstrap thread, the default arena). If any is, add a fallback (descriptor
inline in the data mmap for the pre-system_pool case, distinguished by a flag),
or move system_pool init earlier.

Validate: `meson test -C build_debug --suite unit` fully green; plus
`test_rocs_async_seal`, `test_rocs_large_shard_seal`, `test_condition`,
`test_gc_census`. The async STRESS repro still crashes here (expected — no pin
logic yet).

### Step 2 — Pin pre-pass + page bitmap  — IMPLEMENTED 2026-06-16
- Per from-space segment, a page pin bitmap (bit per `n00b_page_size` of `data`),
  stored transiently on the segment descriptor (`pin_bitmap`, allocated from
  system_pool at `n00b_collect_setup`, freed in `n00b_collection_cleanup`).
- A pre-pass (`n00b_pin_prepass`, BEFORE forwarding) marks the pages of objects
  implicated by each **preemptively-suspended** thread's captured registers
  (gated on `gc_preempt_suspended`, which also excludes the collector's own
  thread). `n00b_pin_candidate` resolves a candidate through the same filter as
  `n00b_visit_possible_pointer` and sets the bits spanning the object's in-arena
  footprint (inline: `[hdr, +alloc_len)`; OOB: `[oob->hcur, +alloc_len)`).

  SCOPE REFINEMENT (vs original plan): the pre-pass pins **captured registers
  only**, NOT the conservative C-stack. Reason: the C-stack scan forward+rewrites
  and is already correct, because a suspended thread's stack *memory* is shared
  and the GC rewrites the slot in place — on resume the thread reads the updated
  slot. A **register** is the unique failure: it is restored from a captured
  copy the GC discards, so a forwarded register dangles. Pinning registers is
  therefore the precise, minimal crash fix. (C-stack→pin remains an OPTIONAL
  robustness step, see Step 5; it is not required for correctness once Step 3
  makes forwarding bitmap-aware.)
  Step 2 is marking-only: the bitmap is built but unused until Step 3, so the
  full suite must stay at the same pass/fail set as Step 1.

### Step 3 — Forward-skip pinned pages
- In `n00b_visit_possible_pointer`/`n00b_forward_alloc`: if the target's page is
  pinned → mark visited, TRACE its outbound pointers (so what it references is
  still evacuated + those slots rewritten), but do NOT copy it and do NOT rewrite
  the referring slot. Precise roots still forward+rewrite.

### Step 4 — End-of-collect: return unpinned, retain pinned
- Per from-space segment, walk pages: `munmap` every unpinned run (return to
  kernel); for every pinned run, register it in the mmap tree as a managed
  segment and wrap it in a fresh `retained` descriptor (system_pool) chained into
  to-space **after** the active segment (never `current_segment`, so the bump
  allocator never uses it). Free the from-space descriptor.
- Eventual free is automatic: next collect's pre-pass sets no bits on a
  no-longer-pinned run → its pages return + descriptor freed.

### Step 5 — Move the C-stack scan to ambiguous/pin
- Today the conservative C-stack scan forward-rewrites slots. Switch it to
  pin-marking too (it's the same arbitrary-PC ambiguity). After this, only
  precise roots compact; all conservative roots pin. The main thread stops
  compacting stack-reachable objects (correct, less compaction).

--------------------------------------------------------------------------------
## 4. Cross-platform / cross-arch

Keep PREEMPTIVE everywhere; use platform APIs. The pin pre-pass reads
`gc_captured_regs` (already captured per-platform):
- macOS arm64 (and x86-64 if targeted): Mach capture exists.
- Linux arm64 + x86-64: RT-signal handler captures `ucontext` (`regs[]` / `gregs[]`).
- Windows arm64 + x86-64: `SuspendThread` + `GetThreadContext`.
Pinning needs NO register WRITE-back on any platform (that's the whole point —
pin, don't move), so the unsafe `thread_set_state`/ucontext-restore path is gone.

--------------------------------------------------------------------------------
## 5. Validation

Repros (already in `test/unit/`, registered):
- `test_rocs_async_seal_stress.c` — env `STRESS_COLLECT`/`STRESS_BIG`; the rocs
  async-seal corruption under forced GC.
- `test_worker_pool_gc_stress.c` — rocs-free; worker pool + heavy GC.
- `test_gc_worker_trace.c` — deterministic named O→T graph; the clean-case
  control (settled stack-pinned graph reconciles fine).

Each step: full unit suite + the three repros. Final: all three clean under
sustained load; prompt-auditor → n00b-code-auditor before push.

--------------------------------------------------------------------------------
## 6. Current tree state (2026-06-16)

- LIVE: `src/util/marshal.c` — marshal `ctx` allocated from `user_pool` (a
  workaround so the ctx + its embedded self-referential scratch pool aren't
  GC-relocated). Independently reasonable; decide keep-vs-drop once pinning lands.
- REVERTED: all register copy-back (stw.c), the explicit captured-reg scan
  (gc.c), the worker current_allocator override + non-moving-VFS (store.c / test),
  the unmanaged-skip experiment.
- Diagnostic tests added + registered (the three repros above).
- Build dir: `build_debug` (SDKROOT=$(xcrun --show-sdk-path)).

## 7. See also (auto-memory)
- `project_async_seal_gc_worker_race` — the full proven analysis + disproven
  hypotheses (held-spinlock, unsuspended-worker, register-restore ×2,
  stack-map-wrong, unmanaged-abort, marshal-returns-GC-buffer).
