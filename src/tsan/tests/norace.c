// Same shape as t_race.c, with the increment under a n00b mutex. Both workers
// are genuinely overlapping, so a report here is a false positive.
#define N00B_USE_INTERNAL_API
#define __N00B_THREAD_INTERNAL
#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/mutex.h"
#include "tsan/n00b_tsan.h"
#include <stdatomic.h>
#include <stdio.h>

static long                shared_counter = 0;
static n00b_mutex_t        guard;
static _Atomic(bool)       go             = false;
static _Atomic(int)        ready          = 0;

static void *
racer(void *arg)
{
    atomic_fetch_add(&ready, 1);
    while (!atomic_load(&go)) {
    }

    for (int i = 0; i < 200000; i++) {
        // The barrier keeps the loop from collapsing into a single add, so the
        // window the two workers overlap in is real.
        n00b_mutex_lock(&guard);
        shared_counter = shared_counter + 1;
        n00b_mutex_unlock(&guard);
    }
    return arg;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);
    n00b_mutex_init(&guard);

    auto a = n00b_thread_spawn(racer, nullptr);
    auto b = n00b_thread_spawn(racer, nullptr);
    printf("NORACE spawn ok: %d %d\n",
           (int)n00b_result_is_ok(a), (int)n00b_result_is_ok(b));
    fflush(stdout);

    while (atomic_load(&ready) < 2) {
    }
    atomic_store(&go, true);

    n00b_thread_join(n00b_result_get(a));
    n00b_thread_join(n00b_result_get(b));

    printf("NORACE counter=%ld (expect 400000) races=%llu (expect 0)\n",
           shared_counter, (unsigned long long)n00b_tsan_race_count());
    fflush(stdout);
    n00b_tsan_report_summary();
    return 0;
}
