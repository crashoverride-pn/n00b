// Strands one bucket's MUTEX with no owner and asserts the reader strand
// backoff's contract: waiters park (the backoff counter climbs), the diagnostic
// fires exactly once regardless of waiter count, unrelated keys stay
// serviceable, and every waiter completes correctly once the strand clears.
// The two cases must run in separate processes: the diagnostic guard is
// process-global, so a second case in the same process would see zero warnings.
//   get -> n00b_acquire_if_present
//   add -> n00b_acquire_or_add

#define N00B_USE_INTERNAL_API
#include <assert.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/dict_untyped.h"
#include "util/path.h"

#define STRANDED_KEY   ((void *)(uintptr_t)1)
#define STRANDED_VALUE ((void *)(uintptr_t)0xAA)
#define HEALTHY_KEY    ((void *)(uintptr_t)8)
#define HEALTHY_VALUE  ((void *)(uintptr_t)0x88)
#define N_WORKERS      4
#define BACKOFF_TARGET 8
#define DEADLINE_NS    (5ULL * 1000 * 1000 * 1000)
#define WARNING_NEEDLE "bucket mutex held past the reader wait gate"

static const char *g_case = "?";

static n00b_hash_value_t
identity_hash(void *key)
{
    return (n00b_hash_value_t)(uintptr_t)key;
}

static void
fail(const char *msg)
{
    fprintf(stderr, "  [FAIL] %s: %s\n", g_case, msg);
    exit(1);
}

// Locate the reserved bucket holding `key` (robust to the hash) and OR in MUTEX.
static n00b_dict_untyped_bucket_t *
strand_bucket(n00b_dict_untyped_t *d, void *key)
{
    n00b_dict_untyped_store_t *s = atomic_load(&d->store);
    for (uint32_t i = 0; i <= s->last_slot; i++) {
        n00b_dict_untyped_bucket_t *b = &s->buckets[i];
        if (b->hv != 0 && !(atomic_load(&b->flags) & N00B_HT_FLAG_DELETED)
            && b->key == key) {
            atomic_fetch_or(&b->flags, N00B_HT_FLAG_MUTEX);
            return b;
        }
    }
    return NULL;
}

typedef struct {
    n00b_dict_untyped_t *d;
    bool                 is_add;
    _Atomic bool         returned;
    void                *result;
} worker_t;

static void *
worker_fn(void *arg)
{
    worker_t *w = arg;
    if (w->is_add) {
        // Add an EXISTING key: it must probe to the stranded bucket without
        // filling a new one, or the put path could trigger a resize/migration
        // and the test would exercise the migrator instead of the reader wait.
        bool r     = _n00b_dict_untyped_add(w->d, STRANDED_KEY, STRANDED_VALUE);
        w->result  = (void *)(uintptr_t)r;
    }
    else {
        bool found;
        w->result = _n00b_dict_untyped_get(w->d, STRANDED_KEY, &found);
    }
    atomic_store(&w->returned, true);
    return w->result;
}

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void
sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static int
run_case(bool is_add)
{
    // Capture fd 2 BEFORE shrinking the gate: the gate is process-global, so a
    // preempted holder in any other dict could emit the one-shot diagnostic,
    // and it must land in the capture or the exactly-once assert fails.
    fflush(stderr);
    int saved_fd2 = dup(2);

    // n00b_new_temp_path rather than a hardcoded "/tmp/...XXXXXX" + mkstemp:
    // the tree's temp root is TMPDIR-aware, and Windows has no /tmp, so the
    // literal path made mkstemp fail there and took the whole case out
    // (n00b#319 -- this test had never run on Windows). The helper only builds
    // the path; O_CREAT|O_EXCL is what actually claims it, and its name
    // carries 64 bits of randomness, so this keeps mkstemp's no-clobber
    // property.
    n00b_string_t *cap_path = n00b_new_temp_path(
        n00b_string_from_cstr("n00b_reader_strand"),
        nullptr);
    const char *tmpl   = cap_path->data;
    int         cap_fd = open(tmpl, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (saved_fd2 < 0 || cap_fd < 0) {
        fail("could not set up stderr capture");
    }
    dup2(cap_fd, 2);

    n00b_dict_reader_strand_gate_set(2ULL * 1000 * 1000);

    n00b_dict_untyped_t d;
    n00b_dict_untyped_init(&d,
                           .hash          = identity_hash,
                           .skip_obj_hash = true,
                           .start_capacity = 16);

    _n00b_dict_untyped_put(&d, STRANDED_KEY, STRANDED_VALUE);
    _n00b_dict_untyped_put(&d, HEALTHY_KEY, HEALTHY_VALUE);

    n00b_dict_untyped_bucket_t *stranded = strand_bucket(&d, STRANDED_KEY);
    if (!stranded) {
        dup2(saved_fd2, 2);
        fail("stranded key not found");
    }

    worker_t       workers[N_WORKERS] = {};
    n00b_thread_t *threads[N_WORKERS] = {};
    for (int i = 0; i < N_WORKERS; i++) {
        workers[i].d      = &d;
        workers[i].is_add = is_add;
        n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(worker_fn, &workers[i]);
        if (!n00b_result_is_ok(r)) {
            dup2(saved_fd2, 2);
            fail("could not spawn worker");
        }
        threads[i] = n00b_result_get(r);
    }

    // Wait until the readers have parked (backoff ran several times).
    uint64_t deadline    = now_ns() + DEADLINE_NS;
    bool     reached     = false;
    while (now_ns() < deadline) {
        if (n00b_dict_reader_backoff_count_get() >= BACKOFF_TARGET) {
            reached = true;
            break;
        }
        sleep_ms(5);
    }

    // Sample these while the strand is still held; after the clear below the
    // workers legitimately return and the healthy-key read proves nothing.
    bool any_returned = false;
    for (int i = 0; i < N_WORKERS; i++) {
        if (atomic_load(&workers[i].returned)) {
            any_returned = true;
        }
    }
    bool  healthy_found = false;
    void *healthy       = _n00b_dict_untyped_get(&d, HEALTHY_KEY, &healthy_found);

    // Clear the strand and join EVERY worker before asserting anything, so a
    // failure never leaves wedged threads behind.
    atomic_fetch_and(&stranded->flags, ~N00B_HT_FLAG_MUTEX);
    bool results_ok = true;
    for (int i = 0; i < N_WORKERS; i++) {
        void *ret = n00b_thread_join(threads[i]);
        if (is_add) {
            if ((bool)(uintptr_t)ret != false) {
                results_ok = false;  // add of an existing key must report false
            }
        }
        else if (ret != STRANDED_VALUE) {
            results_ok = false;      // get must return the stored value
        }
    }

    fflush(stderr);
    dup2(saved_fd2, 2);
    close(saved_fd2);
    char buf[8192];
    // lseek + read rather than pread: llvm-mingw does not declare pread, and
    // this is the only use of it in the tree (n00b#319 builds every test
    // target on Windows). Nothing else holds this descriptor -- the capture
    // file is this process's private temp -- so the seek cannot race.
    ssize_t n = -1;
    if (lseek(cap_fd, 0, SEEK_SET) == 0) {
        n = read(cap_fd, buf, sizeof(buf) - 1);
    }
    if (n < 0) {
        n = 0;
    }
    buf[n] = '\0';
    close(cap_fd);
    unlink(tmpl);

    int   warnings = 0;
    char *p        = buf;
    while ((p = strstr(p, WARNING_NEEDLE))) {
        warnings++;
        p += 1;
    }

    if (!reached) {
        fail("readers never parked (backoff counter did not reach target)");
    }
    if (any_returned) {
        fail("a reader returned while the bucket was stranded");
    }
    if (!healthy_found || healthy != HEALTHY_VALUE) {
        fail("an unrelated key was not serviceable during the strand");
    }
    if (!results_ok) {
        fail("a worker returned the wrong result after the strand cleared");
    }
    if (warnings != 1) {
        char m[64];
        snprintf(m, sizeof(m), "diagnostic fired %d times, expected exactly 1", warnings);
        fail(m);
    }

    printf("  [PASS] dict_reader_strand:%s\n", g_case);
    return 0;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    bool is_add = (argc == 2 && strcmp(argv[1], "add") == 0);
    g_case      = is_add ? "add" : "get";

    printf("Running dict_reader_strand (%s)...\n", g_case);
    return run_case(is_add);
}
