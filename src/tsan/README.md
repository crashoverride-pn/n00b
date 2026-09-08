# n00b's own race detector

Compile with `-fsanitize=thread`, link **without** `libclang_rt.tsan`. The
compiler's instrumentation is useful; its runtime is not usable here, so this
directory implements the `__tsan_*` ABI instead.

## Why the stock runtime cannot be used

Measured on macOS arm64 against `build_dbgopt/libn00b.a`:

* Instrumented code on the **main thread** runs fine under the stock runtime.
* Instrumented code on **any n00b worker** dies on its first memory access:
  `ThreadSanitizer: CHECK failed: tsan_interceptors_posix.cpp:2184
  "((thr->slot)) != (0)"`, then a null-deref in `__tsan::TraceSwitchPart`
  reached from `n00b_thread_launcher`. The runtime allocates per-thread state
  inside its `pthread_create` interceptor, and n00b workers are Mach
  `thread_create` / raw `clone` threads that never go through it.
* Separately, linking the stock runtime makes `n00b_store_shard_seal` fail with
  `unsupported-static-pointer`: its shadow mapping reserves enough of the
  address space that a word resolves into a region the marshaller then refuses.

Both problems disappear when we own the runtime: we register a thread where it
is really born, and we map shadow through a hash instead of claiming a fixed
span of address space.

## Model

FastTrack-shaped.

* **Thread clock**: flat `uint64_t[N00B_TSAN_MAX_THREADS]`, indexed by slot.
  The access check reads it by index, so it stays flat.
* **Sync clock**: compact `(slot, epoch)` pairs. A process holds tens of
  thousands of locks and runs a handful of threads; a flat clock per lock would
  cost more than the program under test.
* **Shadow**: `N00B_TSAN_SHADOW_CELLS` cells per 8-byte granule, each packing
  `tid | epoch | byte mask | is_write | is_atomic` into 64 bits. Found through a
  lock-free hash on the containing 2 MiB region.
* **Race**: the accesses overlap in bytes, at least one is a write, they are not
  both atomic, and the remembered epoch is ahead of what our clock knows for
  that slot.

Happens-before comes from three places:

1. **The instrumented atomics.** `__tsan_atomic*_store` with release order calls
   `n00b_tsan_release` on the address; an acquiring load calls
   `n00b_tsan_acquire`. n00b's mutexes are a futex word driven by exactly those
   atomics, so most of the edges fall out without annotating anything.
2. **Explicit lock annotations** in `n00b_lock_acquire_accounting` /
   `n00b_lock_release_accounting`, which every n00b lock kind funnels through.
3. **Thread lifecycle** in `n00b_thread_spawn` / `n00b_thread_launcher` /
   `n00b_thread_join`, carried on the spawn bundle and the thread handle.

Stop-the-world brackets suppress checking outright: between them the collector
is the only runner, so nothing it touches can race.

## Files that belong to this change

Moving this to its own worktree means taking exactly:

    include/tsan/n00b_tsan.h        public API and the N00B_TSAN_* macro set
    src/tsan/                       the detector (abi, clock, shadow, report)
    .tsan_ignore                    per-file instrumentation opt-outs
    meson.options                   the use_n00b_tsan option
    meson.build                     option plumbing + the n00b_tsan static_library
    build.sh                        N00B_BUILD_TSAN=1
    src/core/thread.c               spawn / launcher / join hooks
    src/core/init.c                 N00B_TSAN_INIT
    src/core/stw.c                  STW brackets
    src/core/lock_accounting.c      lock acquire / release annotations

Every hook in an existing file is a `N00B_TSAN_*` macro that expands to
`((void)0)` when the option is off, so the default build is unchanged.

## Building

    N00B_BUILD_TSAN=1 N00B_BUILD_TESTS=1 \
      N00B_BUILD_TARGETS="test_rocs_plan_cost test_rocs_plan_cost_edges" \
      N00B_BUILD_TYPE=debugoptimized N00B_SKIP_VCS_CHECK=1 \
      bash build.sh build_tsan

## Known limits

* Thread slots are handed out monotonically and never reused, so a run that
  spawns more than `N00B_TSAN_MAX_THREADS` threads stops registering them.
* A report names the racing thread and epoch but carries a stack for the
  current access only; the remembered access has no stack behind it.
* The GC and the mmap tree are in `.tsan_ignore`. The collector reads other
  threads' stacks by design, so instrumenting it reports its own contract.
