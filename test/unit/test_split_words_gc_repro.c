/*
 * Standalone reproduction for a stale interior pointer in
 * n00b_unicode_str_split_words().
 *
 * The splitter caches `s->data` in a raw `const char *`, then performs many
 * allocations before using that pointer to copy the individual word-break
 * ranges.  A collection during that window may move the string backing store,
 * leaving the cached pointer stale.
 *
 * This test deliberately widens and exercises that window without Wax:
 *
 *   worker: create a large GC-backed string, then split it into words
 *   main:   repeatedly collect the shared default arena during the split
 *
 * Every returned segment is checked against a static, non-GC source buffer.
 * A segfault in n00b_string_init()/memcpy(), or a reconstruction mismatch,
 * reproduces the defect entirely inside libn00b.
 */

#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/string_ops.h"

#define SOURCE_BYTES   (16 * 1024)
#define DEFAULT_ROUNDS 4

static char         g_source[SOURCE_BYTES];
static _Atomic bool g_in_split = false;
static _Atomic bool g_collecting = false;
static _Atomic bool g_done     = false;
static _Atomic int  g_round    = 0;

typedef struct {
    int rounds;
} repro_args_t;

static void
fill_source(void)
{
    static const char seed[] =
        "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda ";
    const size_t seed_len = sizeof(seed) - 1;

    for (size_t i = 0; i < sizeof(g_source); i++) {
        g_source[i] = seed[i % seed_len];
    }
}

static void
verify_parts(n00b_array_t(n00b_string_t *) parts)
{
    size_t offset = 0;

    assert(parts.len > 0);
    for (size_t i = 0; i < parts.len; i++) {
        n00b_string_t *part = parts.data[i];

        assert(part != nullptr);
        assert(part->data != nullptr);
        assert(part->u8_bytes >= 0);
        assert(offset + (size_t)part->u8_bytes <= sizeof(g_source));
        assert(memcmp(part->data,
                      g_source + offset,
                      (size_t)part->u8_bytes)
               == 0);
        offset += (size_t)part->u8_bytes;
    }
    assert(offset == sizeof(g_source));
}

static void *
split_worker(void *raw)
{
    repro_args_t *args = raw;

    for (int round = 0; round < args->rounds; round++) {
        n00b_string_t *input =
            n00b_string_from_raw(g_source, sizeof(g_source));

        assert(input != nullptr);
        assert(input->data != nullptr);
        assert(input->u8_bytes == (int64_t)sizeof(g_source));

        atomic_store_explicit(&g_round, round, memory_order_release);
        atomic_store_explicit(&g_in_split, true, memory_order_release);

        n00b_array_t(n00b_string_t *) parts =
            n00b_unicode_str_split_words(input);

        atomic_store_explicit(&g_in_split, false, memory_order_release);
        while (atomic_load_explicit(&g_collecting, memory_order_acquire)) {
        }
        verify_parts(parts);
    }

    atomic_store_explicit(&g_done, true, memory_order_release);
    return nullptr;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    repro_args_t   args = {.rounds = DEFAULT_ROUNDS};

    if (argc == 2) {
        args.rounds = atoi(argv[1]);
        if (args.rounds <= 0) {
            fprintf(stderr, "usage: %s [positive-round-count]\n", argv[0]);
            return 2;
        }
    }

    n00b_init(&runtime, argc, argv);
    fill_source();

    n00b_result_t(n00b_thread_t *) spawned =
        n00b_thread_spawn(split_worker, &args);
    assert(n00b_result_is_ok(spawned));
    n00b_thread_t *worker = n00b_result_get(spawned);
    assert(worker != nullptr);

    uint64_t collections = 0;
    while (!atomic_load_explicit(&g_done, memory_order_acquire)) {
        if (!atomic_load_explicit(&g_in_split, memory_order_acquire)) {
            continue;
        }

        atomic_store_explicit(&g_collecting, true, memory_order_release);
        if (!atomic_load_explicit(&g_in_split, memory_order_acquire)) {
            atomic_store_explicit(&g_collecting, false, memory_order_release);
            continue;
        }

        /*
         * Churn makes relocation likely; the explicit collection makes the
         * timing independent of the arena's normal collection threshold.
         */
        for (int i = 0; i < 128; i++) {
            (void)n00b_string_from_raw(g_source, 96);
        }
        n00b_collect(runtime.default_arena);
        collections++;
        atomic_store_explicit(&g_collecting, false, memory_order_release);
    }

    (void)n00b_thread_join(worker);
    fprintf(stderr,
            "split_words_gc_repro survived %d rounds and %llu collections\n",
            atomic_load_explicit(&g_round, memory_order_acquire) + 1,
            (unsigned long long)collections);

    n00b_shutdown();
    return 0;
}
