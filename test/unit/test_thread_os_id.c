// n00b_thread_os_id must return exactly what n00b_os_thread_id returns, on
// every kind of thread, because lock owners stored through one are compared
// through the other (n00b_lock_already_owner, the STW gate checks).

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "core/spinlock.h"

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

static void *
foreign_fn(void *arg)
{
    (void)arg;
    char *lo;
    char *hi;
#if defined(__APPLE__)
    hi        = (char *)pthread_get_stackaddr_np(pthread_self());
    size_t sz = pthread_get_stacksize_np(pthread_self());
    lo        = hi - sz;
#else
    pthread_attr_t attr;
    void          *base;
    size_t         sz;
    pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &base, &sz);
    pthread_attr_destroy(&attr);
    lo = (char *)base;
    hi = lo + sz;
#endif
    n00b_thread_init(.foreign_stack_low = lo, .foreign_stack_high = hi);
    check_identity("attached foreign thread");
    n00b_thread_destroy();
    return nullptr;
}

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
    n00b_init(&runtime, argc, argv);

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

    pthread_t foreign;
    if (pthread_create(&foreign, nullptr, foreign_fn, nullptr) != 0) {
        printf("  [FAIL] pthread_create\n");
        failures++;
    }
    else {
        pthread_join(foreign, nullptr);
    }

    n00b_shutdown();

    if (failures != 0) {
        printf("%d thread_os_id check(s) failed.\n", failures);
        return 1;
    }
    printf("All thread_os_id tests passed.\n");
    return 0;
}
