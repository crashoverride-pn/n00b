/*
 * test_trust_native_live.c — live proof that the native trust backend verifies
 * real server certificate chains on an n00b worker thread without trapping
 * (WP-042 Phase 4). This is the exact shape of crayon-gw egress:
 * n00b_http_request_sync with prefer_h3=false (h1-over-TLS — the transport
 * upload.c uses), a caller-supplied header bag, whose TLS handshake runs the
 * picotls verify callback on a worker -> system trust -> native verifier.
 * Before WP-042 that callback called SecTrust and trapped on libsystem_malloc;
 * success here (any HTTP status, i.e. the handshake completed) proves the trap
 * is gone and real chains validate. (The h3/QUIC dispatcher has a separate,
 * pre-existing worker-thread crash in header building — unrelated to trust —
 * which is why egress and this test both stay on h1.)
 *
 * Endpoints span multiple CAs on purpose: Google (GTS), example.com (DigiCert),
 * Let's Encrypt (ISRG) — all in the shipped 156-root bundle.
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
fetch(const char *url)
{
    /* A valid caller header bag, exactly as crayon-gw egress supplies. */
    n00b_http_h1_headers_t *extra = n00b_http_h1_headers_new();
    n00b_http_h1_headers_set(extra, "X-Crayon-Trust-Probe", "1");

    auto r = n00b_http_request_sync(
        n00b_string_from_cstr(url),
        .extra      = extra,
        .prefer_h3  = false, /* h1-over-TLS path */
        .h3_handshake_ms = 3000,
        .timeout_ms = 15000);

    if (n00b_result_is_err(r)) {
        fprintf(stderr, "  [WARN] %s: transport err=%d (%s)\n", url,
                (int)n00b_result_get_err(r),
                n00b_quic_err_str((n00b_quic_err_t)n00b_result_get_err(r)));
        return 0;
    }
    n00b_http_response_t *resp   = n00b_result_get(r);
    int                   status = n00b_http_response_status(resp);
    fprintf(stderr, "  [OK] %s -> status=%d (TLS chain verified natively)\n",
            url, status);
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

    int ok = 0;
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        ok += fetch(urls[i]);
    }

    fprintf(stderr, "[trust-native-live] %d/3 real chains verified on worker\n",
            ok);
    /* At least two of three must validate (one origin may be h3-blocked or
     * transiently unreachable); a verify TRAP would crash, not return here. */
    assert(ok >= 2);
    fprintf(stderr, "[trust-native-live] native trust handshake — OK\n");
    return 0;
}
