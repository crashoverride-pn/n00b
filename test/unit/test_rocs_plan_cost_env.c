/*
 * The environment switch, on its own process.
 *
 * ROCS_PLAN_NO_COST is read once and cached for the life of the process, so
 * the parse and the caching cannot be exercised from a test that has already
 * asked the question: the first caller fixes the answer for everyone after it.
 * That makes this a whole binary rather than another case in the cost-model
 * suite, and it is why the setenv below is the first statement in main.
 *
 * Everything else that turns cost planning off goes through
 * n00b_plan_cost_set_enabled, which the rest of the suite uses. This is the
 * only place the documented spelling in docs/rocs_env.md is checked against
 * the code that reads it.
 */

#include <stdint.h>
#include <stdlib.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/plan.h"

#include "rocs_test_support.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

// The variable is documented as taking any value, so the value here is
// deliberately not "1": a check for a particular string would pass this test
// and fail every caller who wrote "true".
static void
test_the_environment_turns_cost_off(void)
{
    CHECK(!n00b_plan_cost_enabled());

    n00b_printf("  [PASS] ROCS_PLAN_NO_COST is read and turns cost off");
}

// Read once, then cached. Clearing the variable afterwards has to leave the
// answer where it was, because a process that changed its planning halfway
// through a run would make one query's plan depend on when it started.
static void
test_the_answer_is_cached(void)
{
    unsetenv("ROCS_PLAN_NO_COST");
    CHECK(!n00b_plan_cost_enabled());

    n00b_printf("  [PASS] the answer is cached past the environment");
}

// The in-process setter overrides the environment, in both directions, and
// keeps working after it has. That is what lets a test run a query both ways
// in one process without arranging for two of them.
static void
test_the_setter_overrides_it(void)
{
    n00b_plan_cost_set_enabled(true);
    CHECK(n00b_plan_cost_enabled());

    n00b_plan_cost_set_enabled(false);
    CHECK(!n00b_plan_cost_enabled());

    n00b_plan_cost_set_enabled(true);
    CHECK(n00b_plan_cost_enabled());

    n00b_printf("  [PASS] the setter overrides the environment either way");
}

int
main(int argc, char **argv)
{
    // Before anything else. n00b_plan_cost_enabled caches the first answer it
    // gives, so a call from inside startup would settle it while the variable
    // was still unset and leave this suite testing nothing.
    setenv("ROCS_PLAN_NO_COST", "yes", 1);

    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    n00b_printf("cost switch:");
    test_the_environment_turns_cost_off();
    test_the_answer_is_cached();
    test_the_setter_overrides_it();

    n00b_shutdown();
    return 0;
}
