#include <unistd.h>

#include "n00b_crt.h"

static int n00b_crt_test_seen[8];
static int n00b_crt_test_count;

static void
n00b_crt_test_record(int value)
{
    if (n00b_crt_test_count < 8) {
        n00b_crt_test_seen[n00b_crt_test_count++] = value;
    }
}

static void
n00b_crt_fixture_one(void)
{
    n00b_crt_test_record(1);
}

static void
n00b_crt_fixture_two(void)
{
    n00b_crt_test_record(2);
}

static void
n00b_crt_fixture_three(void)
{
    n00b_crt_test_record(3);
}

[[gnu::constructor]] static void
n00b_crt_ctor_one(void)
{
    n00b_crt_test_record(4);
}

[[gnu::constructor]] static void
n00b_crt_ctor_two(void)
{
    n00b_crt_test_record(5);
}

static void
n00b_crt_test_expect(int code, int count, int a, int b, int c)
{
    if (n00b_crt_test_count != count) {
        _exit(code);
    }

    if (count > 0 && n00b_crt_test_seen[0] != a) {
        _exit(code);
    }

    if (count > 1 && n00b_crt_test_seen[1] != b) {
        _exit(code);
    }

    if (count > 2 && n00b_crt_test_seen[2] != c) {
        _exit(code);
    }
}

[[noreturn]] void
n00b_crt_main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;

    void (*fixture[])(void) = {
        n00b_crt_fixture_one,
        nullptr,
        n00b_crt_fixture_two,
        n00b_crt_fixture_three,
    };

    n00b_crt_test_count = 0;
    n00b_crt_run_init_array_range(fixture, fixture + 4);
    n00b_crt_test_expect(10, 3, 1, 2, 3);

    n00b_crt_test_count = 0;
    n00b_crt_run_init_array_range(fixture, fixture);
    n00b_crt_test_expect(11, 0, 0, 0, 0);

    n00b_crt_test_count = 0;
    n00b_crt_run_init_array();
    n00b_crt_test_expect(12, 2, 4, 5, 0);

    _exit(0);
}
