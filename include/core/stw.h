/**
 * @file stw.h
 * @brief Stop-the-world (STW) synchronization infrastructure.
 *
 * Pure-preemptive stop-the-world (WP-001).  The initiator stops the world by
 * acquiring the single `critical_execution` gate (guaranteeing no other thread
 * is mid-critical-section) and then preemptively suspending every other
 * registered thread (macOS Mach thread_suspend; Linux RT-signal handler;
 * Windows SuspendThread), capturing each one's register file for the GC's
 * conservative scan.  There is NO cooperative safepoint: a thread never
 * self-parks or checks in.
 */
#pragma once

#include "n00b.h"
#include "core/thread.h"
#include "core/macros.h"
#include "core/runtime.h"

/**
 * @brief Halt all threads for GC.  Use the n00b_stop_the_world() macro.
 * @pre  Runtime must be initialized; caller must be a registered thread.
 * @post All other threads are suspended (preemptively) with their registers
 *       captured; rt->stw_active is set.
 */
extern void _n00b_stop_the_world(char *loc);

/**
 * @brief Resume all threads after GC.  Use the n00b_restart_the_world() macro.
 * @pre  The calling thread is the stop-the-world initiator (holds
 *       critical_execution).
 * @post rt->stw_active is clear and all suspended threads are resumed.
 */
extern void _n00b_restart_the_world(char *loc);

/**
 * @brief Install the WP-4 preemptive-STW suspend mechanism (D-040).
 *
 * Called once from n00b_init.  On Linux it installs the RT-signal handler used
 * to preemptively suspend RUNNING threads at GC time; a no-op where suspension
 * needs no signal (macOS Mach thread_suspend / Windows SuspendThread).
 */
extern void n00b_stw_init(void);

#define n00b_stop_the_world()    _n00b_stop_the_world(N00B_LOC_STRING())
#define n00b_restart_the_world() _n00b_restart_the_world(N00B_LOC_STRING())

// Pure-preemptive STW: a blocking call no longer needs to advertise GC-safe
// state (the initiator preempts the thread rather than waiting for it to
// self-park), so n00b_run_blocking is now just its body.
#define n00b_run_blocking(...) \
    {                          \
        __VA_ARGS__;           \
    }

/**
 * @brief True iff the world is currently stopped (rt->stw_active).
 * @pre Runtime must be initialized.
 */
static inline bool
n00b_world_is_stopped(void)
{
    return n00b_atomic_load(&n00b_get_runtime()->stw_active);
}
