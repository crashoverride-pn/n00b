# debug — hardware watchpoints & breakpoints

`include/debug/debug.h` is an in-process **debugger substrate**: a program sets
hardware data **watchpoints** and code **breakpoints** on itself at runtime, and
each trap either runs a callback (inspect/modify CPU state, decide how to
resume) or is handed to an attached debugger. It is the foundation an in-process
debugger is built on; the trap-to-debugger path is the interim story until that
debugger exists.

All symbols use the `n00b_debug_` prefix. Include `<debug/debug.h>` (it pulls in
`<n00b.h>` and `adt/result.h`).

## Quick start

```c
#include "debug/debug.h"

// Fire a callback whenever `counter` is written, from any thread.
static n00b_debug_action_t
on_write(n00b_debug_hit_t *hit, void *ud)
{
    // hit context: pc, sp, watched addr, old/new value, GPRs.
    return N00B_DEBUG_CONTINUE;   // keep watching; let the write land
}

n00b_result_t(n00b_debug_watchpoint_t *) r =
    n00b_debug_watch(&counter, .on_hit = on_write);   // .size, .kind also kwargs
n00b_debug_watchpoint_t *wp = n00b_result_get(r);
// ...
n00b_debug_watch_clear(wp);
```

```c
// Break when execution reaches a function; run it and stay armed.
n00b_debug_break(fn_addr, .on_hit = on_hit);

// No callback => deliver a debugger trap when hit.
n00b_debug_watch(&counter);                 // traps to a debugger on write
n00b_debug_trap();                          // trap right here
if (n00b_debug_is_attached()) { ... }
n00b_debug_wait_for_debugger(.timeout_ms = 5000);
```

## The hit callback

The callback receives an `n00b_debug_hit_t *` and returns an action:

| Action | Meaning |
|---|---|
| `N00B_DEBUG_CONTINUE` | Resume (with any register edits). The trap stays armed. |
| `N00B_DEBUG_DISABLE`  | One-shot: clear this trap everywhere, then resume. |
| `N00B_DEBUG_TRAP`     | Escalate: deliver a debugger trap. |

Hit context accessors: `n00b_debug_hit_pc`, `_sp`, `_addr`, `_reg`/`_set_reg`
(GPRs, by platform ABI/DWARF index), and — for watchpoints — `_old_value` /
`_new_value` (best-effort, pointer-word).

> **Signal-context safety.** Callbacks run in async exception context (a Mach
> exception-server thread on macOS, a signal handler on Linux, a vectored
> handler on Windows). Treat them like signal handlers: do **not** allocate from
> the GC heap, take GC locks, or call into the broader n00b runtime. Read the
> hit, decide, return.

## Enumeration

```c
static bool count(n00b_debug_watchpoint_t *wp, void *ud) { (*(int*)ud)++; return true; }
int n = 0;
n00b_debug_watch_foreach(count, &n);   // also n00b_debug_break_foreach
```

A callback `foreach` (rather than a returned container) because the handles are
non-GC and the registry is walked under a lock. Return `false` to stop early. Do
not install/clear traps from inside the callback.

## All-thread semantics

A watch/breakpoint set on one thread traps accesses on **all** threads:

- Threads that exist at install time are programmed via OS-native enumeration
  (`task_threads` / `/proc/self/task` / Toolhelp), suspending non-self briefly.
- Threads created later self-enroll from the n00b thread launcher (a weak
  `n00b_debug_thread_enroll` hook in `core/thread.c`).

Foreign (non-n00b) threads are covered only if they exist at install time.

## Memory & errors

Handles live in the runtime `system_pool` (non-GC, non-moving, exception-thread
reachable); they are not freed by `*_clear` (reclaimed at teardown). Fallible
constructors return `n00b_result_t(...)`; lifecycle/accessor calls return
`n00b_debug_err_t` (negative domain codes; `n00b_debug_err_str` describes them).

## Platform support

| Platform | Mechanism | Status |
|---|---|---|
| macOS / arm64 | `ARM_DEBUG_STATE64` (`WVR/WCR` + `BVR/BCR`) + Mach `EXC_BREAKPOINT` | implemented, tested |
| Linux / x86-64 | `perf_event_open(PERF_TYPE_BREAKPOINT)` + SIGTRAP | implemented, **CI-validated only** |
| Windows / x86-64 | `Get/SetThreadContext` `Dr0–Dr7` + vectored handler | implemented, **CI-validated only** |
| macOS / x86-64 | — | not yet implemented (`UNSUPPORTED`) |

Notes & limitations:

- **Slot counts.** arm64 has separate banks → up to 4 watch **and** 4 break.
  x86 shares 4 debug registers across watch+break combined → `NO_SLOT` past 4.
- **Software breakpoints** (`N00B_DEBUG_BREAK_SW`, unlimited via trap
  instructions) are not yet implemented (`UNSUPPORTED`); use the default
  hardware kind.
- **Linux** hardware events in a container need
  `sysctl kernel.perf_event_paranoid=-1` (or `CAP_SYS_PTRACE`); the SIGTRAP slot
  tag (`si_perf_data`) needs kernel ≥ 5.13.
- **Resume timing** differs by arch (handled internally): arm64 single-steps
  over the faulting instruction; x86 data watchpoints trap after the write
  (resume directly) and execute breakpoints resume via `EFLAGS.RF`.

## Tests

`test/unit/test_debug_{watch,break,allthread,attach}.c` (meson suite `unit`,
names `debug_watch` / `debug_break` / `debug_allthread` / `debug_attach`).
