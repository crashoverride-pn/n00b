#pragma once

/**
 * @brief Hybrid race detection for annotated fields.
 *
 * Two detectors, and a report needs both to agree.
 *
 * The lockset half (Eraser) tracks the locks common to every access of a
 * field and reports when that set empties. It is schedule-independent, so it
 * finds a race the run did not happen to expose, but it is blind to every
 * ordering that is not a lock and reports all of them.
 *
 * The happens-before half (vector clocks, with FastTrack's epoch for the
 * common case) tracks synchronization order. It has no false alarms and sees
 * unsynchronized publish, which lockset structurally cannot, but it only
 * judges the interleaving it observed.
 *
 * So a report means the lockset is empty AND the accesses are unordered. That
 * combination is not academic here: on the first run of the lockset half over
 * this tree, 161 of 162 reports were orderings that were not locks, and
 * happens-before pruned every one of them.
 *
 * Both inputs are cheap because they already exist. The set of locks held is
 * the two chains lock_accounting.c maintains on every acquire and release,
 * and the happens-before edges hang off those same two calls, so every lock
 * in the tree contributes ordering without being annotated.
 *
 * Orderings that are not locks -- a pin drain, a seal barrier, a queue
 * handoff -- are invisible until somebody says so. Annotate those with
 * @ref n00b_race_release_edge and @ref n00b_race_acquire_edge, or accept a
 * report where the ordering is real.
 *
 * Opt-in per field. Annotate an access with @ref n00b_race_read or
 * @ref n00b_race_write and nothing else changes; a field nobody annotates is
 * neither checked nor slowed. Compiled out entirely without @c N00B_DEBUG.
 *
 * A field that is deliberately lock-free -- an @c _Atomic counter, a pointer
 * published by CAS -- is correct and would report on every access. Mark it
 * once with @ref n00b_race_lockfree and it is never tracked.
 *
 * Reports name the field and the access; they do not abort, because one run
 * should surface every field that is wrong rather than the first.
 */

#include <stdint.h>

#ifdef N00B_DEBUG

/**
 * @brief Record a read of an annotated location.
 * @param addr Location being read.
 * @param name Field name, for the report. Not copied.
 */
extern void n00b_race_read(const void *addr, const char *name);

/**
 * @brief Record a write of an annotated location.
 * @param addr Location being written.
 * @param name Field name, for the report. Not copied.
 */
extern void n00b_race_write(const void *addr, const char *name);

/**
 * @brief Declare a location intentionally lock-free, so it is never tracked.
 *
 * For @c _Atomic fields and pointers published by CAS: correct without a
 * lock, and otherwise reported on every access.
 */
extern void n00b_race_lockfree(const void *addr);

/**
 * @brief Publish this thread's history against @p obj.
 *
 * The release half of a happens-before edge. Locks do this on release
 * automatically; call it by hand for the orderings that are not locks -- a pin
 * drain, a seal barrier, a queue handoff. Without it the detector cannot see
 * that ordering and reports accesses it separates.
 */
extern void n00b_race_release_edge(const void *obj);

/**
 * @brief Take on the history published against @p obj.
 *
 * The acquire half. Pair with @ref n00b_race_release_edge on the same object.
 */
extern void n00b_race_acquire_edge(const void *obj);

/**
 * @brief Return this thread's clock slot.
 *
 * Called from thread teardown. Slots are a fixed array, so a run that never
 * returned them would stop tracking once it had seen @c N00B_RACE_THREADS
 * threads, and stop reporting with it: an access by a thread with no slot is
 * treated as ordered, because a clock that cannot describe a thread must not
 * claim that thread raced.
 */
extern void n00b_race_thread_exit(void);

/**
 * @brief Forget every shadow entry in [lo, hi).
 *
 * Call when an allocator unmaps pages, so a recycled address does not inherit
 * the lockset of whatever lived there before. Mirrors
 * @c n00b_lock_chains_scrub_range.
 */
extern void n00b_race_scrub_range(uint64_t lo, uint64_t hi);

/** @brief Races reported since process start. For tests. */
extern uint64_t n00b_race_reports(void);

#else

#define n00b_race_read(a, n)   ((void)0)
#define n00b_race_write(a, n)  ((void)0)
#define n00b_race_lockfree(a)  ((void)0)
#define n00b_race_release_edge(o) ((void)0)
#define n00b_race_acquire_edge(o) ((void)0)
#define n00b_race_thread_exit()   ((void)0)
#define n00b_race_scrub_range(lo, hi) ((void)0)
#define n00b_race_reports()    UINT64_C(0)

#endif
