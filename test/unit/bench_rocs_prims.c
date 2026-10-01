/* test/unit/bench_rocs_prims.c - which primitive is slow on which platform.
 *
 * test_rocs_plan_oracle runs 9.5x slower on arm64 Linux than on arm64 macOS,
 * and the gap is in user time rather than sys, so it is computation and not
 * the hypervisor. Other rocs tests on the same box run 1.7x to 2.3x, so
 * something the oracle leans on disproportionately is far worse than the
 * general penalty.
 *
 * Rather than guess which, this times the primitives it leans on, one at a
 * time, in loops big enough to swamp the harness. The one whose ratio between
 * the two platforms is far above the ~2x baseline is the answer.
 *
 * Same architecture on both sides (Apple Silicon, podman gives arm64 Linux),
 * so architecture is held fixed and only the OS and toolchain vary.
 */

#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include "internal/rocs/plan_ir.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "bench check failed: " #expr);                    \
    } while (0)

static uint64_t iters = 2000000;

static uint64_t
env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    if (v == nullptr || *v == '\0') {
        return fallback;
    }
    return (uint64_t)strtoull(v, nullptr, 10);
}

static void
report(const char *what, int64_t ns, uint64_t n)
{
    n00b_printf("  [|#|]: [|#|] ms total, [|#|] ns/op",
                n00b_string_from_cstr(what),
                (int64_t)(ns / 1000000),
                (int64_t)(ns / (int64_t)n));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    iters = env_u64("ROCS_BENCH_ITERS", 2000000);
    n00b_printf("primitives, [|#|] iterations each", (int64_t)iters);

    // 1. String equality on short equal strings, which every dedup, field
    //    lookup and value compare in the planner runs.
    n00b_string_t *a = n00b_cformat("trace-«#»", (int64_t)12345);
    n00b_string_t *b = n00b_cformat("trace-«#»", (int64_t)12345);
    volatile uint64_t sink = 0;
    int64_t start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        sink += n00b_unicode_str_eq(a, b) ? 1 : 0;
    }
    report("n00b_unicode_str_eq (equal)", n00b_ns_timestamp() - start, iters);

    // 2. The same when they differ in the last character, which is the
    //    common case in a dedup that finds nothing.
    n00b_string_t *c = n00b_cformat("trace-«#»", (int64_t)12346);
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        sink += n00b_unicode_str_eq(a, c) ? 1 : 0;
    }
    report("n00b_unicode_str_eq (differ)", n00b_ns_timestamp() - start, iters);

    // 3. Ordering, which the rewriter and the zone map both use.
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        sink += (uint64_t)(n00b_unicode_str_cmp(a, c) < 0 ? 1 : 0);
    }
    report("n00b_unicode_str_cmp", n00b_ns_timestamp() - start, iters);

    // 4. Allocation, which the oracle does enormously.
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters / 10; i++) {
        void *p = n00b_alloc(uint64_t);
        sink += (uint64_t)(uintptr_t)p;
    }
    report("n00b_alloc (1/10 iters)", n00b_ns_timestamp() - start, iters / 10);

    // 5. Building a small string, which the fixture does per row.
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters / 10; i++) {
        n00b_string_t *s = n00b_cformat("trace-«#»", (int64_t)i);
        sink += s->u8_bytes;
    }
    report("n00b_cformat (1/10 iters)", n00b_ns_timestamp() - start,
           iters / 10);

    // 6. JSON scalar equality through the shared comparator, which every
    //    predicate comparison and every zone bound check runs.
    n00b_json_node_t *ja = n00b_json_int_new(4242);
    n00b_json_node_t *jb = n00b_json_int_new(4242);
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        auto r = _rocs_plan_json_equal(nullptr, ja, jb);
        sink += n00b_result_is_ok(r) && n00b_result_get(r) ? 1 : 0;
    }
    report("_rocs_plan_json_equal (int)", n00b_ns_timestamp() - start, iters);

    // 7. The same over strings, which is what the oracle's fixture values are.
    n00b_json_node_t *js1 = n00b_json_string_new_from_n00b(a);
    n00b_json_node_t *js2 = n00b_json_string_new_from_n00b(b);
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        auto r = _rocs_plan_json_equal(nullptr, js1, js2);
        sink += n00b_result_is_ok(r) && n00b_result_get(r) ? 1 : 0;
    }
    report("_rocs_plan_json_equal (str)", n00b_ns_timestamp() - start, iters);

    // 8. Thread identity. A register read on macOS arm64 and a raw
    //    SYS_gettid on Linux, and the lock accounting every allocation runs
    //    through calls it. If one platform pays a syscall here and the other
    //    does not, everything allocation-heavy inherits the difference.
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        sink += (uint64_t)n00b_os_thread_id();
    }
    report("n00b_os_thread_id", n00b_ns_timestamp() - start, iters);

    // 9. The GC shadow stack push/pop that ncc emits in every framed
    //    function, reached here through a trivial framed call.
    start = n00b_ns_timestamp();
    for (uint64_t i = 0; i < iters; i++) {
        sink += (uint64_t)n00b_thread_unique_id();
    }
    report("n00b_thread_unique_id (framed)",
           n00b_ns_timestamp() - start,
           iters);

    n00b_printf("sink [|#|]", (int64_t)sink);
    n00b_shutdown();
    return 0;
}
