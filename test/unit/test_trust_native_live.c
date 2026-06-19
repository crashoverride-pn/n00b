/*
 * test_trust_native_live.c — live proof that the native trust backend verifies
 * real server certificate chains on an n00b worker without trapping, over BOTH
 * h1-over-TLS (the transport crayon-gw egress uses) and h3/QUIC (WP-042
 * Phase 4). The TLS handshake runs the picotls verify callback -> system trust
 * -> native verifier; before WP-042 that called SecTrust and trapped on
 * libsystem_malloc. Success here (any HTTP status = handshake completed) proves
 * the trap is gone and real multi-CA chains validate.
 *
 * This also guards the h1-headers-bag GC bug: the caller header bag is created
 * up front and read deep inside the h3 round trip after heavy allocation; if
 * the bag's list backing/lock were left in the GC heap (instead of the bag's
 * hidden/non-GC pool) a collection would dangle it and crash before the
 * handshake. Exercising h3 here keeps that fixed.
 *
 * Endpoints span CAs on purpose: Google (GTS), example.com (DigiCert),
 * Let's Encrypt (ISRG) — all in the shipped root bundle.
 *
 * Gated by N00B_TEST_NET=1 (network access required).
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_h1.h"

static int
fetch(const char *url, bool prefer_h3)
{
    /* A valid caller header bag, exactly as crayon-gw egress supplies. */
    n00b_http_h1_headers_t *extra = n00b_http_h1_headers_new();
    n00b_http_h1_headers_set(extra, "X-Crayon-Trust-Probe", "1");

    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(url),
        .extra           = extra,
        .prefer_h3       = prefer_h3,
        .h3_handshake_ms = 3000,
        .timeout_ms      = 15000);

    if (n00b_result_is_err(r)) {
        fprintf(stderr, "  [WARN] %s (h3=%d): transport err=%d (%s)\n", url,
                (int)prefer_h3, (int)n00b_result_get_err(r),
                n00b_quic_err_str((n00b_quic_err_t)n00b_result_get_err(r)));
        return 0;
    }
    n00b_http_response_t *resp   = n00b_result_get(r);
    int                   status = n00b_http_response_status(resp);
    fprintf(stderr, "  [OK] %s (h3=%d) -> status=%d (chain verified natively)\n",
            url, (int)prefer_h3, status);
    return (status >= 100 && status < 500) ? 1 : 0;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    if (!getenv("N00B_TEST_NET")) {
        fprintf(stderr, "Skipping trust_native_live (set N00B_TEST_NET=1).\n");
        return 0;
    }

    static const char *urls[] = {
        "https://www.google.com/",   /* Google Trust Services */
        "https://www.example.com/",  /* DigiCert */
        "https://letsencrypt.org/",  /* ISRG / Let's Encrypt */
    };
    const size_t n = sizeof(urls) / sizeof(urls[0]);

    /* h1-over-TLS: the transport egress uses; must validate all reachable. */
    int ok_h1 = 0;
    for (size_t i = 0; i < n; i++) {
        ok_h1 += fetch(urls[i], false);
    }
    fprintf(stderr, "[trust-native-live] h1: %d/%zu chains verified\n", ok_h1, n);
    assert(ok_h1 >= 2);

    /* h3/QUIC: must not crash (the headers-bag GC bug crashed here) and should
     * validate where h3 isn't blocked. */
    int ok_h3 = 0;
    for (size_t i = 0; i < n; i++) {
        ok_h3 += fetch(urls[i], true);
    }
    fprintf(stderr, "[trust-native-live] h3: %d/%zu chains verified\n", ok_h3, n);
    assert(ok_h3 >= 1);

    fprintf(stderr, "[trust-native-live] native trust handshake (h1+h3) — OK\n");
    return 0;
}
