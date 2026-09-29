// n00b_thread_os_id must return exactly what n00b_os_thread_id returns, on
// every kind of thread and in a fork() child. Lock owners are keyed on it, so
// a stale cached id would make a thread miss its own locks.

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "core/spinlock.h"
#include "core/futex.h"
#include "core/gc.h"
#include "core/platform.h"
#include "core/stw.h"
#if !defined(_WIN32)
#include "test_foreign_stack.h"
#endif

// Small enough that the round-robin slot allocator comes back to a slot
// within a few dozen spawns. On Linux ncc's crt sets the runtime up before
// main with the default table size, so the slot reuse test reads the live
// size and needs about 4096 spawns there.
#define TEST_MAX_THREADS 64

static int failures = 0;

#define CHECK_EQ(who, what, got, want)                                         \
    do {                                                                       \
        int64_t _g = (int64_t)(got);                                           \
        int64_t _w = (int64_t)(want);                                          \
        if (_g != _w) {                                                        \
            printf("  [FAIL] %s: %s = %lld, want %lld\n",                      \
                   (who), (what), (long long)_g, (long long)_w);               \
            failures++;                                                        \
        }                                                                      \
    } while (0)

// Runs on the thread under test. Threads run one at a time, joined before the
// next starts, so the shared counter needs no atomics.
static void
check_identity(const char *who)
{
    int            before = failures;
    int64_t        kernel = n00b_os_thread_id();
    n00b_thread_t *self   = n00b_thread_self();

    if (self == nullptr) {
        printf("  [FAIL] %s: n00b_thread_self() is null\n", who);
        failures++;
        return;
    }

    CHECK_EQ(who, "os_tid", self->os_tid, (uint32_t)kernel);
    CHECK_EQ(who, "n00b_thread_os_id(self)", n00b_thread_os_id(self), kernel);
    CHECK_EQ(who, "n00b_self_os_id()", n00b_self_os_id(), kernel);
    CHECK_EQ(who,
             "n00b_thread_os_id(nullptr)",
             n00b_thread_os_id((n00b_thread_t *)nullptr),
             kernel);

    n00b_spin_lock_t spin;
    n00b_spinlock_init(&spin);
    n00b_spinlock_lock(&spin);
    CHECK_EQ(who, "spinlock owner", n00b_atomic_load(&spin.data).owner, kernel);
    n00b_spinlock_unlock(&spin);

    n00b_mutex_t mutex;
    n00b_mutex_init(&mutex);
    n00b_mutex_lock(&mutex);
    CHECK_EQ(who, "mutex owner", n00b_atomic_load(&mutex.data).owner, kernel);
    CHECK_EQ(who,
             "n00b_lock_already_owner",
             n00b_lock_already_owner((n00b_lock_base_t *)&mutex),
             1);
    n00b_mutex_unlock(&mutex);

    if (failures == before) {
        printf("  [PASS] %s\n", who);
    }
}

static void *
worker_fn(void *arg)
{
    (void)arg;
    check_identity("worker");
    return nullptr;
}

typedef struct {
    int32_t  slot;
    uint32_t os_tid;
    int64_t  kernel;
    int64_t  keyed;
} spawn_ident_t;

static void *
ident_fn(void *arg)
{
    spawn_ident_t *io   = arg;
    n00b_thread_t *self = n00b_thread_self();

    io->slot   = self->id_info.parts.id;
    io->os_tid = self->os_tid;
    io->kernel = n00b_os_thread_id();
    io->keyed  = n00b_thread_os_id(self);
    return nullptr;
}

// Spawn and join until a slot comes back around. Its new occupant must carry
// its own id, not the one the slot's previous occupant left behind.
static void
test_slot_reuse(void)
{
    const char *who    = "reused slot";
    int         before = failures;
    uint32_t    slots  = n00b_get_runtime()->max_threads;
    int64_t    *prev   = calloc(slots, sizeof(int64_t));
    bool        reused = false;

    if (prev == nullptr) {
        printf("  [FAIL] %s: calloc\n", who);
        failures++;
        return;
    }

    for (uint32_t i = 0; i < 4 * slots && !reused; i++) {
        spawn_ident_t io      = {};
        auto          spawned = n00b_thread_spawn(ident_fn, &io);
        if (!n00b_result_is_ok(spawned)) {
            printf("  [FAIL] %s: n00b_thread_spawn\n", who);
            failures++;
            free(prev);
            return;
        }
        (void)n00b_thread_join(n00b_result_get(spawned));

        CHECK_EQ(who, "os_tid", io.os_tid, (uint32_t)io.kernel);
        CHECK_EQ(who, "n00b_thread_os_id(self)", io.keyed, io.kernel);
        if (io.slot < 0 || (uint32_t)io.slot >= slots) {
            printf("  [FAIL] %s: slot %d out of range\n", who, io.slot);
            failures++;
            free(prev);
            return;
        }
        if (prev[io.slot] != 0) {
            reused = true;
#if defined(__linux__)
            // Linux does not hand a live process's tids back out this soon,
            // so an equal id here would mean the check above proved nothing.
            if (io.kernel == prev[io.slot]) {
                printf("  [FAIL] %s: slot %d kept tid %lld\n",
                       who,
                       io.slot,
                       (long long)io.kernel);
                failures++;
            }
#endif
        }
        prev[io.slot] = io.kernel;
    }
    free(prev);

    if (!reused) {
        printf("  [FAIL] %s: no slot was reused\n", who);
        failures++;
    }
    if (failures == before) {
        printf("  [PASS] %s\n", who);
    }
}

#if !defined(_WIN32)
static void *
foreign_fn(void *arg)
{
    (void)arg;
    char *lo;
    char *hi;
    n00b_test_pthread_stack_bounds(&lo, &hi);
    n00b_thread_init(.foreign_stack_low = lo, .foreign_stack_high = hi);
    check_identity("attached foreign thread");
    n00b_thread_destroy();
    return nullptr;
}

// The child's one thread resolves to the forking thread's record, but the
// kernel gave it a new id. The child reports through its exit status and
// leaves with _exit so no atexit handler or runtime teardown runs there.
static void
test_fork_child(void)
{
    int64_t parent = n00b_os_thread_id();

    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        printf("  [FAIL] fork\n");
        failures++;
        return;
    }
    if (pid == 0) {
        int before = failures;
#if defined(__linux__)
        CHECK_EQ("fork child", "kernel id differs from parent's",
                 n00b_os_thread_id() != parent, 1);
#else
        (void)parent;
#endif
        check_identity("fork child");
        fflush(stdout);
        _exit(failures == before ? 0 : 1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)
        || WEXITSTATUS(status) != 0) {
        printf("  [FAIL] fork child exited with status 0x%x\n", status);
        failures++;
    }
}

#define FORK_DEADLINE_NS (10ull * 1000000000ull)
#define FORK_POLL_NS     (10ull * 1000000ull)

static n00b_futex_t parked_release;
static _Atomic int  parked_count;
static _Atomic bool child_worker_collected;

static void
park_until_released(void)
{
    atomic_fetch_add(&parked_count, 1);
    while (n00b_atomic_load(&parked_release) == 0) {
        (void)n00b_futex_wait(&parked_release, 0, 100000000);
    }
}

static void *
parked_worker_fn(void *arg)
{
    (void)arg;
    park_until_released();
    return nullptr;
}

static void *
parked_foreign_fn(void *arg)
{
    (void)arg;
    char *lo;
    char *hi;
    n00b_test_pthread_stack_bounds(&lo, &hi);
    n00b_thread_init(.foreign_stack_low = lo, .foreign_stack_high = hi);
    park_until_released();
    n00b_thread_destroy();
    return nullptr;
}

static void
churn_and_collect(void)
{
    for (int i = 0; i < 2000; i++) {
        char *p = n00b_alloc_array(char, 64 + (i % 512));
        p[0]    = (char)i;
    }
    n00b_collect(n00b_get_runtime()->default_arena);
}

static void *
child_collector_fn(void *arg)
{
    (void)arg;
    churn_and_collect();
    atomic_store(&child_worker_collected, true);
    return nullptr;
}

// Runs in the fork child. Exit codes: 0 pass, 2 wrong live count, 3 a worker
// spawned in the child failed or did not collect, 4 that worker's collection
// retired the forking thread.
static int
fork_child_stops_world(void)
{
    n00b_runtime_t *rt   = n00b_get_runtime();
    n00b_thread_t  *self = n00b_thread_self();

    n00b_stop_the_world();
    n00b_restart_the_world();
    churn_and_collect();

    if (n00b_atomic_load(&rt->live_threads) != 1) {
        return 2;
    }

    // A thread born in the child must be able to stop the forking thread, and
    // must see it as alive.
    auto spawned = n00b_thread_spawn(child_collector_fn, nullptr);
    if (!n00b_result_is_ok(spawned)) {
        return 3;
    }
    (void)n00b_thread_join(n00b_result_get(spawned));
    if (!atomic_load(&child_worker_collected)) {
        return 3;
    }
    if (n00b_thread_self() != self
        || n00b_atomic_load(&rt->threads[self->id_info.parts.id].thread) != self) {
        return 4;
    }
    return 0;
}

// The forking thread holds this across every fork below.
static n00b_mutex_t fork_held;
static const char  *fork_who;

// Runs in the fork child. Exit codes: 1 the identity check failed, 5 the held
// lock does not name this thread as its owner, 6 releasing it left an owner,
// and otherwise fork_child_stops_world's.
static int
fork_child_run(void)
{
    int before = failures;
    check_identity(fork_who);
    if (failures != before) {
        return 1;
    }

    if (!n00b_lock_already_owner((n00b_lock_base_t *)&fork_held)
        || n00b_atomic_load(&fork_held.data).owner != n00b_os_thread_id()) {
        return 5;
    }
    n00b_mutex_lock(&fork_held);
    n00b_mutex_unlock(&fork_held);
    n00b_mutex_unlock(&fork_held);
    if (n00b_atomic_load(&fork_held.data).owner != N00B_NO_OWNER) {
        return 6;
    }

    return fork_child_stops_world();
}

// Forks from the calling thread and runs child() in the child. Waits with a
// deadline and kills a child that hangs. True when the child exits 0.
static bool
run_forked(const char *who, int (*child)(void))
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        int rc = child();
        fflush(stdout);
        _exit(rc);
    }
    if (pid < 0) {
        printf("  [FAIL] %s: fork\n", who);
        failures++;
        return false;
    }

    int      status   = 0;
    bool     finished = false;
    uint64_t start    = base_monotonic_ns();
    while (base_monotonic_ns() - start < FORK_DEADLINE_NS) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            finished = true;
            break;
        }
        if (r < 0) {
            break;
        }
        base_nanosleep_ns(FORK_POLL_NS);
    }

    if (!finished) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        printf("  [FAIL] %s: child hung, killed after %llus\n",
               who,
               (unsigned long long)(FORK_DEADLINE_NS / 1000000000ull));
        failures++;
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("  [FAIL] %s: child exited with status 0x%x\n", who, status);
        failures++;
        return false;
    }
    return true;
}

// The child of a process with other registered threads holds only the forking
// thread, so a stop-the-world there must not wait on the parent's other
// threads. A worker and an attached foreign thread stay parked across the
// fork, and main holds a lock across it.
static void
test_fork_child_stops_world(void)
{
    const char *who = "fork child stops the world";

    n00b_futex_init(&parked_release);
    atomic_store(&parked_count, 0);

    auto spawned = n00b_thread_spawn(parked_worker_fn, nullptr);
    if (!n00b_result_is_ok(spawned)) {
        printf("  [FAIL] %s: n00b_thread_spawn\n", who);
        failures++;
        return;
    }
    pthread_t foreign;
    bool      have_foreign
        = pthread_create(&foreign, nullptr, parked_foreign_fn, nullptr) == 0;
    int want_parked = have_foreign ? 2 : 1;
    if (!have_foreign) {
        printf("  [FAIL] %s: pthread_create\n", who);
        failures++;
    }

    uint64_t start = base_monotonic_ns();
    while (atomic_load(&parked_count) < want_parked
           && base_monotonic_ns() - start < FORK_DEADLINE_NS) {
        base_nanosleep_ns(FORK_POLL_NS / 10);
    }

    int before = failures;
    fork_who   = "fork child of main";
    n00b_mutex_lock(&fork_held);
    (void)run_forked(who, fork_child_run);
    n00b_mutex_unlock(&fork_held);

    n00b_atomic_store(&parked_release, 1);
    n00b_futex_wake(&parked_release, true);
    (void)n00b_thread_join(n00b_result_get(spawned));
    if (have_foreign) {
        pthread_join(foreign, nullptr);
    }

    if (atomic_load(&parked_count) != want_parked) {
        printf("  [FAIL] %s: %d of %d threads parked\n",
               who,
               atomic_load(&parked_count),
               want_parked);
        failures++;
    }
    if (failures == before) {
        printf("  [PASS] %s\n", who);
    }
}

static void *
fork_from_here_fn(void *arg)
{
    bool *ok = arg;
    n00b_mutex_lock(&fork_held);
    *ok = run_forked(fork_who, fork_child_run);
    n00b_mutex_unlock(&fork_held);
    return nullptr;
}

static void *
fork_from_foreign_fn(void *arg)
{
    char *lo;
    char *hi;
    n00b_test_pthread_stack_bounds(&lo, &hi);
    n00b_thread_init(.foreign_stack_low = lo, .foreign_stack_high = hi);
    fork_from_here_fn(arg);
    n00b_thread_destroy();
    return nullptr;
}

static void *
pthread_mutex_fn(void *arg)
{
    const char         *who = arg;
    pthread_mutexattr_t attr;
    pthread_mutex_t     m;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&m, &attr);
    pthread_mutexattr_destroy(&attr);

    CHECK_EQ(who, "lock", pthread_mutex_lock(&m), 0);
    CHECK_EQ(who, "relock", pthread_mutex_lock(&m), EDEADLK);
    CHECK_EQ(who, "unlock", pthread_mutex_unlock(&m), 0);
    pthread_mutex_destroy(&m);
    return nullptr;
}

// glibc records a pthread mutex's owner as the tid in the caller's struct
// pthread, which on a Linux worker is n00b's TCB. A zero tid there matches an
// unowned mutex, so an error-checking lock reports a relock.
static void
test_worker_pthread_mutex(void)
{
    const char *who    = "pthread mutex on a worker";
    int         before = failures;
    auto spawned = n00b_thread_spawn(pthread_mutex_fn, (void *)who);
    if (!n00b_result_is_ok(spawned)) {
        printf("  [FAIL] %s: n00b_thread_spawn\n", who);
        failures++;
        return;
    }
    (void)n00b_thread_join(n00b_result_get(spawned));
    if (failures == before) {
        printf("  [PASS] %s\n", who);
    }
}

static int
fork_child_exits(void)
{
    return 0;
}

static void *
bare_fork_fn(void *arg)
{
    *(bool *)arg = run_forked("bare fork from a worker", fork_child_exits);
    return nullptr;
}

// A worker and an attached foreign thread can fork too. Their child keeps
// their record and their lock, and retires main's. On Linux a worker's
// thread pointer is n00b's own TCB, not a pthread's, and glibc's fork() still
// has to reach the child.
static void
test_fork_from_other_threads(void)
{
    bool ok      = false;
    auto spawned = n00b_thread_spawn(bare_fork_fn, &ok);
    if (!n00b_result_is_ok(spawned)) {
        printf("  [FAIL] bare fork from a worker: n00b_thread_spawn\n");
        failures++;
    }
    else {
        (void)n00b_thread_join(n00b_result_get(spawned));
        if (ok) {
            printf("  [PASS] bare fork from a worker\n");
        }
    }

    ok       = false;
    fork_who = "fork child of a worker";
    spawned  = n00b_thread_spawn(fork_from_here_fn, &ok);
    if (!n00b_result_is_ok(spawned)) {
        printf("  [FAIL] fork from a worker: n00b_thread_spawn\n");
        failures++;
    }
    else {
        (void)n00b_thread_join(n00b_result_get(spawned));
        if (ok) {
            printf("  [PASS] fork from a worker\n");
        }
    }

    ok       = false;
    fork_who = "fork child of a foreign thread";
    pthread_t foreign;
    if (pthread_create(&foreign, nullptr, fork_from_foreign_fn, &ok) != 0) {
        printf("  [FAIL] fork from a foreign thread: pthread_create\n");
        failures++;
    }
    else {
        pthread_join(foreign, nullptr);
        if (ok) {
            printf("  [PASS] fork from a foreign thread\n");
        }
    }
}
#endif

// A foreign record can be a dead thread's, so its cached id must never be
// used. A worker's and main's may be, on Linux only.
static void
test_which_records_are_trusted(void)
{
    const char *who    = "trusted records";
    int         before = failures;
    int64_t     kernel = n00b_os_thread_id();
    uint32_t    bogus  = (uint32_t)kernel + 7919u;

    n00b_thread_t foreign    = {};
    foreign.os_tid           = bogus;
    foreign.id_info.parts.id = 5;
    CHECK_EQ(who, "foreign record", n00b_thread_os_id(&foreign), kernel);

    n00b_thread_t unset = {};
    unset.callstack     = (struct n00b_callstack_t *)&unset;
    CHECK_EQ(who, "record with os_tid 0", n00b_thread_os_id(&unset), kernel);

    n00b_thread_t worker    = {};
    worker.os_tid           = bogus;
    worker.id_info.parts.id = 5;
    worker.callstack        = (struct n00b_callstack_t *)&worker;

    n00b_thread_t main_rec    = {};
    main_rec.os_tid           = bogus;
    main_rec.id_info.parts.id = (int32_t)N00B_MAIN_THREAD_SLOT;

#if defined(__linux__)
    CHECK_EQ(who, "worker record", n00b_thread_os_id(&worker), bogus);
    CHECK_EQ(who, "main record", n00b_thread_os_id(&main_rec), bogus);
#else
    CHECK_EQ(who, "worker record", n00b_thread_os_id(&worker), kernel);
    CHECK_EQ(who, "main record", n00b_thread_os_id(&main_rec), kernel);
#endif

    if (failures == before) {
        printf("  [PASS] %s\n", who);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv, .max_threads = TEST_MAX_THREADS);

    printf("Running thread_os_id tests...\n");

    check_identity("main");
    test_which_records_are_trusted();

    auto spawned = n00b_thread_spawn(worker_fn, nullptr);
    if (!n00b_result_is_ok(spawned)) {
        printf("  [FAIL] n00b_thread_spawn\n");
        failures++;
    }
    else {
        (void)n00b_thread_join(n00b_result_get(spawned));
    }

    test_slot_reuse();

#if !defined(_WIN32)
    pthread_t foreign;
    if (pthread_create(&foreign, nullptr, foreign_fn, nullptr) != 0) {
        printf("  [FAIL] pthread_create\n");
        failures++;
    }
    else {
        pthread_join(foreign, nullptr);
    }

    test_worker_pthread_mutex();
    n00b_mutex_init(&fork_held);
    test_fork_child();
    test_fork_child_stops_world();
    test_fork_from_other_threads();
#endif

    n00b_shutdown();

    if (failures != 0) {
        printf("%d thread_os_id check(s) failed.\n", failures);
        return 1;
    }
    printf("All thread_os_id tests passed.\n");
    return 0;
}
