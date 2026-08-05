/*
 * test_quic_phase5_k8s_smoke.c — meson wrapper around the
 * Phase 5 § 5.4 K8s fixture script.
 *
 * Forks `bash run.sh`.  When the fixture script exits 77 (kind /
 * kubectl / docker missing, or N00B_TEST_KIND not set), this test
 * reports SKIP.  Anything else is propagated as the test result.
 *
 * Set N00B_TEST_KIND=1 to actually run the fixture; otherwise the
 * test stays out of the way under the standard `bash build.sh`
 * invocation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "test_portability.h"

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    const char *script = getenv("N00B_PHASE5_K8S_SCRIPT");
    if (!script) {
        printf("test_quic_phase5_k8s_smoke:\n"
               "  [SKIP] N00B_PHASE5_K8S_SCRIPT not set\n");
        n00b_shutdown();
        return 77;
    }
    const char *flag = getenv("N00B_TEST_KIND");
    if (!flag || strcmp(flag, "1") != 0) {
        printf("test_quic_phase5_k8s_smoke:\n"
               "  [SKIP] N00B_TEST_KIND!=1\n");
        n00b_shutdown();
        return 77;
    }

    int rc = n00b_test_run_bash_script(script);
    if (rc < 0) {
        fprintf(stderr, "  fixture script terminated abnormally\n");
        n00b_shutdown();
        return 1;
    }
    if (rc == 77) {
        printf("test_quic_phase5_k8s_smoke:\n"
               "  [SKIP] fixture script reported skip\n");
        n00b_shutdown();
        return 77;
    }
    printf("test_quic_phase5_k8s_smoke:\n");
    if (rc != 0) {
        fprintf(stderr, "  [FAIL] fixture script exit=%d\n", rc);
        n00b_shutdown();
        return 1;
    }
    printf("  [PASS] kind cluster + n00b deploy + assert\n");
    n00b_shutdown();
    return 0;
}
