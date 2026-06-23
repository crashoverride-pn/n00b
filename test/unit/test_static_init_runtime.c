#include "core/runtime.h"
#include "core/static_init_runtime.h"
#include "util/assert.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

static int seen[8];
static int seen_count;

static int
record_one(void)
{
    seen[seen_count++] = 1;
    return 0;
}

static int
record_two(void)
{
    seen[seen_count++] = 2;
    return 0;
}

static int
record_fail(void)
{
    seen[seen_count++] = 9;
    return 73;
}

static void
expect_count(int count)
{
    CHECK(seen_count == count);
}

int
main(int argc, char **argv)
{
    n00b_static_init_fn_t ok[] = {
        record_one,
        nullptr,
        record_two,
    };
    CHECK(n00b_run_degraded_static_init_range(ok, ok + 3) == 0);
    expect_count(2);
    CHECK(seen[0] == 1);
    CHECK(seen[1] == 2);

    seen_count = 0;
    n00b_static_init_fn_t fail[] = {
        record_one,
        record_fail,
        record_two,
    };
    CHECK(n00b_run_degraded_static_init_range(fail, fail + 3) == 73);
    expect_count(2);
    CHECK(seen[0] == 1);
    CHECK(seen[1] == 9);

    seen_count = 0;
    CHECK(n00b_run_degraded_static_init_range(fail, fail) == 0);
    CHECK(n00b_run_degraded_static_init_range(nullptr, fail + 3) == 0);
    CHECK(n00b_run_degraded_static_init_range(fail + 3, fail) == 0);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    CHECK(n00b_run_degraded_static_inits() == 0);
    expect_count(0);
    n00b_shutdown();

    return 0;
}
