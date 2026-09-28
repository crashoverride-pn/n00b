#include <stdio.h>
#include <assert.h>
#if defined(__APPLE__) || defined(__linux__)
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#endif
// The late gate probe needs a raw pthread, and the parked check reads
// scheduler state through Mach on macOS and /proc on Linux.
#define HAVE_PARK_PROBE 1
#endif

// test_lock_chain and the parked reader read thread records via
// n00b_thread_self()->record, so the internal thread surface stays exposed.
#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/rwlock.h"
#include "core/lock_common.h"
#include "core/atomic.h"
#include "core/futex.h"
#include "core/platform.h"
#include "core/stw.h"

#define WAIT_DEADLINE_NS (10ull * 1000000000ull)
#define POLL_NS          1000000ull

// ============================================================================
// 1. Basic read/write lock
// ============================================================================

static void
test_basic_rw(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    // Write lock/unlock.
    n00b_rw_write_lock(&rw);
    n00b_rw_unlock(&rw);

    // Read lock/unlock.
    n00b_rw_read_lock(&rw);
    n00b_rw_unlock(&rw);

    printf("  [PASS] basic rw lock/unlock\n");
}

static void
test_expired_futex_wait(void)
{
    n00b_futex_t word = 1;
    assert(!n00b_futex_timed_wait_for_value(&word, 0, 0));
    assert(!n00b_futex_timed_wait_for_value(&word, 0, 10000));
    assert(word == 1);
    assert(n00b_futex_timed_wait_for_value(&word, 1, 0));
    printf("  [PASS] expired futex wait\n");
}

#if defined(HAVE_PARK_PROBE)
// Samples whether the kernel has a thread blocked, and its CPU time so far.
// os_id is n00b_os_thread_id() as read on that thread: a tid on Linux, the
// thread's Mach port on macOS. Allocation-free, so main can call it while it
// holds the world stopped.
static bool
os_thread_sample(int64_t os_id, bool *blocked, uint64_t *cpu_ns)
{
#if defined(__APPLE__)
    thread_basic_info_data_t info;
    mach_msg_type_number_t   count = THREAD_BASIC_INFO_COUNT;

    if (thread_info((thread_act_t)os_id,
                    THREAD_BASIC_INFO,
                    (thread_info_t)&info,
                    &count)
        != KERN_SUCCESS) {
        return false;
    }
    *blocked = info.run_state == TH_STATE_WAITING;
    *cpu_ns  = ((uint64_t)info.user_time.seconds + info.system_time.seconds)
                * 1000000000ull
            + ((uint64_t)info.user_time.microseconds
               + info.system_time.microseconds)
                  * 1000ull;
    return true;
#else
    char path[64];
    char buf[512];
    snprintf(path, sizeof(path), "/proc/self/task/%lld/stat", (long long)os_id);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    // The state letter follows the parenthesized command name.
    char *paren = strrchr(buf, ')');
    if (paren == nullptr || paren[1] != ' ') {
        return false;
    }
    *blocked = paren[2] == 'S';

    // The kernel's per-thread CPU clock id for a tid, built the way glibc's
    // pthread_getcpuclockid builds it.
    clockid_t       clock = (clockid_t)((~(uint32_t)os_id << 3) | 6u);
    struct timespec ts;
    if (clock_gettime(clock, &ts) != 0) {
        return false;
    }
    *cpu_ns = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    return true;
#endif
}

typedef enum {
    PARK_PARKED,
    PARK_ESCAPED,
    PARK_NEVER,
} park_result_t;

#define PARK_STREAK 5

// Waits until the thread has sat blocked, with its CPU time unchanged, for
// PARK_STREAK consecutive samples. A reader that spins on a futex wait with an
// expired timeout keeps running between samples and never qualifies. Stops
// early if *escaped turns true, which means the thread got past the lock.
static park_result_t
wait_until_parked(int64_t os_id, _Atomic bool *escaped)
{
    uint64_t start  = base_monotonic_ns();
    uint64_t frozen = 0;
    int      streak = 0;

    while (base_monotonic_ns() - start < WAIT_DEADLINE_NS) {
        if (atomic_load(escaped)) {
            return PARK_ESCAPED;
        }
        bool     blocked = false;
        uint64_t cpu     = 0;
        if (os_thread_sample(os_id, &blocked, &cpu) && blocked) {
            if (streak > 0 && cpu != frozen) {
                streak = 0;
            }
            frozen = cpu;
            if (++streak >= PARK_STREAK) {
                return PARK_PARKED;
            }
        }
        else {
            streak = 0;
        }
        base_nanosleep_ns(POLL_NS);
    }
    return atomic_load(escaped) ? PARK_ESCAPED : PARK_NEVER;
}

static const char *
park_result_name(park_result_t r)
{
    switch (r) {
    case PARK_PARKED:
        return "parked";
    case PARK_ESCAPED:
        return "got the lock";
    default:
        return "never parked (spinning?)";
    }
}

typedef struct {
    n00b_runtime_t *runtime;
    _Atomic int64_t os_id;
    _Atomic bool    entered;
} late_gate_probe_t;

static void *
late_gate_worker(void *arg)
{
    late_gate_probe_t *probe = arg;
    atomic_store(&probe->os_id, n00b_os_thread_id());
    n00b_rw_read_lock(&probe->runtime->critical_execution);
    atomic_store(&probe->entered, true);
    n00b_rw_unlock(&probe->runtime->critical_execution);
    return nullptr;
}

// A thread that reaches the gate while main holds the world stopped must park
// on it until restart. The probe is a raw pthread because the stop would
// suspend a registered worker before it reached the gate, and
// n00b_thread_spawn cannot start one here: it waits for the worker's init,
// which blocks on this same gate.
static void
test_late_gate_reader(n00b_runtime_t *runtime)
{
    late_gate_probe_t probe = {.runtime = runtime};
    pthread_t         worker;

    n00b_stop_the_world();
    assert(n00b_atomic_load(&runtime->stw_active));
    assert(n00b_atomic_load(&runtime->critical_execution.futex) & N00B_RW_W_LOCK);
    assert(pthread_create(&worker, nullptr, late_gate_worker, &probe) == 0);

    uint64_t start = base_monotonic_ns();
    int64_t  os_id = 0;
    while ((os_id = atomic_load(&probe.os_id)) == 0
           && base_monotonic_ns() - start < WAIT_DEADLINE_NS) {
        base_nanosleep_ns(POLL_NS);
    }
    park_result_t parked = os_id != 0 ? wait_until_parked(os_id, &probe.entered)
                                      : PARK_NEVER;
    bool entered_while_stopped = atomic_load(&probe.entered);

    n00b_restart_the_world();
    assert(pthread_join(worker, nullptr) == 0);

    if (parked != PARK_PARKED) {
        printf("  [FAIL] late STW gate reader %s while stopped\n",
               park_result_name(parked));
    }
    assert(parked == PARK_PARKED);
    assert(!entered_while_stopped);
    assert(atomic_load(&probe.entered));
    printf("  [PASS] late STW gate reader parks until restart\n");
}
#endif

typedef struct {
    n00b_rwlock_t                  *lock;
    _Atomic int64_t                 os_id;
    _Atomic(n00b_thread_record_t *) rec;
    _Atomic bool                    entered;
} parked_reader_t;

static n00b_rwlock_t parked_rw;

static void *
parked_reader_fn(void *arg)
{
    parked_reader_t *pr = arg;
    atomic_store(&pr->rec, n00b_thread_self()->record);
    atomic_store(&pr->os_id, n00b_os_thread_id());
    n00b_rw_read_lock(pr->lock);
    atomic_store(&pr->entered, true);
    n00b_rw_unlock(pr->lock);
    return nullptr;
}

// A worker reading behind main's write hold must wait for the release, and
// where the scheduler state is readable, wait parked in the kernel.
static void
test_reader_parks_behind_writer(void)
{
    memset(&parked_rw, 0, sizeof(parked_rw));
    n00b_rw_init(&parked_rw);
    parked_reader_t pr = {.lock = &parked_rw};

    n00b_rw_write_lock(&parked_rw);
    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(parked_reader_fn, &pr);
    assert(n00b_result_is_ok(r));

    // The reader publishes the lock it waits on just before it blocks.
    uint64_t start   = base_monotonic_ns();
    bool     waiting = false;
    while (!waiting && !atomic_load(&pr.entered)
           && base_monotonic_ns() - start < WAIT_DEADLINE_NS) {
        n00b_thread_record_t *rec = atomic_load(&pr.rec);
        waiting = rec != nullptr
               && __atomic_load_n(&rec->lock_wait_target, __ATOMIC_ACQUIRE)
                      == (n00b_lock_base_t *)&parked_rw;
        if (!waiting) {
            base_nanosleep_ns(POLL_NS);
        }
    }

#if defined(HAVE_PARK_PROBE)
    park_result_t parked = waiting
                             ? wait_until_parked(atomic_load(&pr.os_id), &pr.entered)
                             : PARK_NEVER;
#endif
    bool entered_while_held = atomic_load(&pr.entered);

    n00b_rw_unlock(&parked_rw);
    n00b_thread_join(n00b_result_get(r));

    assert(waiting);
    assert(!entered_while_held);
    assert(atomic_load(&pr.entered));
#if defined(HAVE_PARK_PROBE)
    if (parked != PARK_PARKED) {
        printf("  [FAIL] reader behind a writer %s\n", park_result_name(parked));
    }
    assert(parked == PARK_PARKED);
    printf("  [PASS] reader parks behind a writer\n");
#else
    printf("  [PASS] reader waits behind a writer\n");
#endif
}

// ============================================================================
// 2. Write-lock nesting
// ============================================================================

static void
test_write_nesting(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_write_lock(&rw);
    n00b_rw_write_lock(&rw); // nested
    n00b_rw_unlock(&rw);     // still held (nesting=1)
    n00b_rw_unlock(&rw);     // fully released

    printf("  [PASS] write nesting\n");
}

// ============================================================================
// 3. Read-lock nesting
// ============================================================================

static void
test_read_nesting(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_read_lock(&rw);
    n00b_rw_read_lock(&rw);  // nested read
    n00b_rw_unlock(&rw);     // still reading (level=1)
    n00b_rw_unlock(&rw);     // fully released

    printf("  [PASS] read nesting\n");
}

// ============================================================================
// 4. Read inside write
// ============================================================================

static void
test_read_inside_write(void)
{
    n00b_rwlock_t rw = {0};
    n00b_rw_init(&rw);

    n00b_rw_write_lock(&rw);
    // Acquiring a read lock while holding the write lock should be
    // treated as a write-lock nesting (since we already own it).
    n00b_rw_read_lock(&rw);
    n00b_rw_unlock(&rw);
    n00b_rw_unlock(&rw);

    printf("  [PASS] read inside write\n");
}

// ============================================================================
// 5. Multiple concurrent readers
// ============================================================================

static n00b_rwlock_t reader_rw;
static _Atomic int   reader_active;
static _Atomic int   max_readers_seen;

static void *
reader_worker(void *arg)
{
    (void)arg;

    for (int i = 0; i < 1000; i++) {
        n00b_rw_read_lock(&reader_rw);

        int cur = n00b_atomic_add(&reader_active, 1) + 1;

        // Track max concurrent readers.
        int prev_max = n00b_atomic_load(&max_readers_seen);
        while (cur > prev_max) {
            if (n00b_cas(&max_readers_seen, &prev_max, cur)) {
                break;
            }
        }

        n00b_atomic_add(&reader_active, -1);
        n00b_rw_unlock(&reader_rw);
    }

    return nullptr;
}

static void
test_concurrent_readers(void)
{
    memset(&reader_rw, 0, sizeof(reader_rw));
    n00b_rw_init(&reader_rw);
    atomic_store(&reader_active, 0);
    atomic_store(&max_readers_seen, 0);

    n00b_thread_t *threads[4];
    for (int i = 0; i < 4; i++) {
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(reader_worker,
                                                             nullptr);
        assert(n00b_result_is_ok(r));
        threads[i] = n00b_result_get(r);
    }
    for (int i = 0; i < 4; i++) {
        n00b_thread_join(threads[i]);
    }

    printf("  [PASS] concurrent readers (max concurrent: %d)\n",
           atomic_load(&max_readers_seen));
}

// ============================================================================
// 6. Writer exclusion
// ============================================================================

static n00b_rwlock_t excl_rw;
static _Atomic int   excl_counter;

static void *
writer_worker(void *arg)
{
    (void)arg;

    for (int i = 0; i < 5000; i++) {
        n00b_rw_write_lock(&excl_rw);
        n00b_atomic_add(&excl_counter, 1);
        n00b_rw_unlock(&excl_rw);
    }

    return nullptr;
}

static void
test_writer_exclusion(void)
{
    memset(&excl_rw, 0, sizeof(excl_rw));
    n00b_rw_init(&excl_rw);
    atomic_store(&excl_counter, 0);

    n00b_result_t(n00b_thread_t *) r1 = n00b_thread_spawn(writer_worker, nullptr);
    n00b_result_t(n00b_thread_t *) r2 = n00b_thread_spawn(writer_worker, nullptr);
    assert(n00b_result_is_ok(r1));
    assert(n00b_result_is_ok(r2));
    n00b_thread_join(n00b_result_get(r1));
    n00b_thread_join(n00b_result_get(r2));

    assert(atomic_load(&excl_counter) == 10000);

    printf("  [PASS] writer exclusion (counter=%d)\n",
           atomic_load(&excl_counter));
}

// ============================================================================
// 7. Lock chain verification
// ============================================================================

static void
test_lock_chain(void)
{
    n00b_rwlock_t rw1 = {0};
    n00b_rwlock_t rw2 = {0};
    n00b_rw_init(&rw1);
    n00b_rw_init(&rw2);

    n00b_lock_set_debug_name(&rw1, "rw1");
    n00b_lock_set_debug_name(&rw2, "rw2");

    n00b_rw_write_lock(&rw1);
    n00b_rw_write_lock(&rw2);

    // Both should be in the thread's lock chain.
    n00b_thread_t        *self = n00b_thread_self();
    n00b_thread_record_t *rec  = self->record;
    n00b_lock_base_t     *head = n00b_atomic_load(&rec->exclusive_locks);

    assert(head != nullptr);
    // rw2 was acquired last, should be at head.
    assert(head == (n00b_lock_base_t *)&rw2);
    n00b_lock_base_t *next = n00b_atomic_load(&head->next_thread_lock);
    assert(next == (n00b_lock_base_t *)&rw1);

    n00b_rw_unlock(&rw2);
    n00b_rw_unlock(&rw1);

    // Chain should be empty now.
    head = n00b_atomic_load(&rec->exclusive_locks);
    assert(head == nullptr);

    printf("  [PASS] lock chain verification\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_rwlock:\n");
    test_expired_futex_wait();
#if defined(HAVE_PARK_PROBE)
    test_late_gate_reader(n00b_get_runtime());
#endif
    test_reader_parks_behind_writer();
    test_basic_rw();
    test_write_nesting();
    test_read_nesting();
    test_read_inside_write();
    test_concurrent_readers();
    test_writer_exclusion();
    test_lock_chain();

    printf("All rwlock tests passed.\n");
    n00b_shutdown();
    return 0;
}
