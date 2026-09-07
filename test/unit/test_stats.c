#include <stdio.h>
#include <assert.h>
#include <math.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/stats.h"

static void
test_running_stats_basics(void)
{
    n00b_running_stats_t s;
    n00b_running_stats_init(&s);

    assert(n00b_running_stats_count(&s) == 0);
    assert(n00b_running_stats_mean(&s) == 0.0);
    assert(n00b_running_stats_variance(&s) == 0.0);

    // Single observation: mean is the observation, variance is 0.
    n00b_running_stats_observe(&s, 7.0);
    assert(n00b_running_stats_count(&s) == 1);
    assert(fabs(n00b_running_stats_mean(&s) - 7.0) < 1e-12);
    assert(n00b_running_stats_variance(&s) == 0.0);

    // Add a second observation.  Mean = 5, sample variance = 8.
    n00b_running_stats_observe(&s, 3.0);
    assert(n00b_running_stats_count(&s) == 2);
    assert(fabs(n00b_running_stats_mean(&s) - 5.0) < 1e-12);
    assert(fabs(n00b_running_stats_variance(&s) - 8.0) < 1e-12);
    assert(fabs(n00b_running_stats_stddev(&s) - sqrt(8.0)) < 1e-12);
}

// Cross-check the running mean and variance against a known dataset.
static void
test_running_stats_known_dataset(void)
{
    // Sum 40, n=8 → mean = 5.0.  Σ(x−5)² = 32 → sample variance = 32/7.
    double xs[] = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
    int    n    = sizeof(xs) / sizeof(xs[0]);

    n00b_running_stats_t s;
    n00b_running_stats_init(&s);
    for (int i = 0; i < n; i++) {
        n00b_running_stats_observe(&s, xs[i]);
    }

    assert(n00b_running_stats_count(&s) == (uint64_t)n);
    assert(fabs(n00b_running_stats_mean(&s) - 5.0)          < 1e-12);
    assert(fabs(n00b_running_stats_variance(&s) - 32.0/7.0) < 1e-12);
}

// Welford avoids the catastrophic cancellation that the naive
// `Σx² − (Σx)²/n` formula suffers when values cluster far from zero.
// Variance of the run should be exactly 4.0 here.
static void
test_running_stats_numerical_stability(void)
{
    double base = 1e9;
    double xs[] = {base + 1.0, base + 3.0, base + 5.0, base + 7.0, base + 9.0};
    n00b_running_stats_t s;
    n00b_running_stats_init(&s);
    for (size_t i = 0; i < sizeof(xs)/sizeof(xs[0]); i++) {
        n00b_running_stats_observe(&s, xs[i]);
    }
    // Mean = base + 5, variance (sample) = 10.0.
    assert(fabs(n00b_running_stats_mean(&s) - (base + 5.0)) < 1e-3);
    assert(fabs(n00b_running_stats_variance(&s) - 10.0)     < 1e-3);
}

static void
test_ewma_basics(void)
{
    n00b_ewma_t e;
    n00b_ewma_init(&e, 0.5);

    // First observation primes the average.
    n00b_ewma_observe(&e, 10.0);
    assert(n00b_ewma_value(&e) == 10.0);

    // Second observation: 0.5*20 + 0.5*10 = 15.
    n00b_ewma_observe(&e, 20.0);
    assert(fabs(n00b_ewma_value(&e) - 15.0) < 1e-12);

    // Third: 0.5*0 + 0.5*15 = 7.5.
    n00b_ewma_observe(&e, 0.0);
    assert(fabs(n00b_ewma_value(&e) - 7.5) < 1e-12);
}

// On a constant stream, EWMA converges exactly to the constant after the
// first observation regardless of alpha.
static void
test_ewma_constant_stream(void)
{
    n00b_ewma_t e;
    n00b_ewma_init(&e, 0.01);
    for (int i = 0; i < 1000; i++) {
        n00b_ewma_observe(&e, 42.0);
    }
    assert(fabs(n00b_ewma_value(&e) - 42.0) < 1e-9);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_running_stats_basics();
    test_running_stats_known_dataset();
    test_running_stats_numerical_stability();
    test_ewma_basics();
    test_ewma_constant_stream();

    printf("All stats tests passed.\n");
    n00b_shutdown();
    return 0;
}
