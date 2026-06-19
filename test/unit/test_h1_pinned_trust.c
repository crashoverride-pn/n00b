/** @file test/unit/test_h1_pinned_trust.c — libn00b regression for
 *  caller-supplied trust threading through the h1 transport (DF-013).
 *
 *  Gated by `N00B_TEST_DOCKER=1`.  When the env var is unset the test
 *  exits 77 (meson's "skip" exit code) cleanly so the suite doesn't
 *  fail in environments without Docker.
 *
 *  Fixture: the zot OCI v2 registry running under
 *  `test/fixtures/zot/start.sh`.  zot speaks h1 + h2 over TLS (no h3
 *  ALPN), which makes it the canonical fixture for exercising the h1
 *  trust-threading path: the public dispatcher's h3-first race times
 *  out, falls back to h1, and the h1 round-trip must honor the
 *  caller-supplied `n00b_quic_trust_pinned(...)` handle in order for
 *  the picotls handshake to accept zot's self-signed leaf cert.
 *
 *  Sub-cases:
 *
 *    [1] Boot the zot fixture via `test/fixtures/zot/start.sh`.
 *    [2] Construct a pinned-fingerprint trust handle from the
 *        fixture's `N00B_TEST_DOCKER_ZOT_CERT_FP` export.
 *    [3] Issue `GET /v2/` via `n00b_http_request_sync` with
 *        `prefer_h3 = false` so the dispatcher goes straight to h1,
 *        and `.trust = pinned_trust`.  Asserts the response is
 *        200 OK (zot returns 200 on `GET /v2/` in anonymous mode).
 *    [4] Tear the zot fixture down via `test/fixtures/zot/stop.sh`
 *        on every exit path (success and failure).
 *
 *  Test-file carve-out (D-030) applies — libc I/O for spawning
 *  start/stop, environment access, and stdout logging is acceptable
 *  per the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "crypto/trust.h"
#include "net/http/http_client.h"

// ---------------------------------------------------------------------------
// Fixture lifecycle — spawn start.sh / stop.sh and parse exports.
//
// Same shape as test_attest_oci_push_smoke.c — we don't share the
// helpers because the smoke test has additional fields and we want
// this test to be a freestanding libn00b regression that doesn't
// reach into the attest-module test surface.
// ---------------------------------------------------------------------------

typedef struct {
    char container[256];
    char cert_dir[512];
    char url[256];
    char host[256];
    char cert_fp_hex[80];
} zot_fixture_t;

static bool
parse_export_line(const char *line, const char *name,
                  char *out_buf, size_t out_cap)
{
    static const char prefix[] = "export ";
    size_t plen = sizeof(prefix) - 1;
    if (strncmp(line, prefix, plen) != 0) {
        return false;
    }
    const char *p = line + plen;
    size_t nlen = strlen(name);
    if (strncmp(p, name, nlen) != 0 || p[nlen] != '=') {
        return false;
    }
    p += nlen + 1;
    bool quoted = false;
    if (*p == '\'') {
        quoted = true;
        p++;
    }
    size_t o = 0;
    while (*p && o + 1 < out_cap) {
        if (quoted && *p == '\'') break;
        if (!quoted && (*p == '\n' || *p == '\r')) break;
        out_buf[o++] = *p++;
    }
    out_buf[o] = '\0';
    return o > 0;
}

static bool
zot_fixture_start(zot_fixture_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *src_root = getenv("N00B_TEST_ZOT_SRC_ROOT");
    if (src_root == nullptr || src_root[0] == '\0') {
        src_root = getenv("MESON_SOURCE_ROOT");
    }
    char cmd[1024];
    if (src_root != nullptr && src_root[0] != '\0') {
        snprintf(cmd, sizeof(cmd),
                 "/bin/bash %s/test/fixtures/zot/start.sh 2>/dev/null",
                 src_root);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "/bin/bash test/fixtures/zot/start.sh 2>/dev/null");
    }
    FILE *fp = popen(cmd, "r");
    if (fp == nullptr) {
        fprintf(stderr, "popen(start.sh) failed: %s\n", strerror(errno));
        return false;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        size_t llen = strlen(line);
        while (llen > 0
               && (line[llen - 1] == '\n' || line[llen - 1] == '\r')) {
            line[--llen] = '\0';
        }
        parse_export_line(line, "ZOT_CONTAINER",
                          out->container, sizeof(out->container));
        parse_export_line(line, "ZOT_CERT_DIR",
                          out->cert_dir, sizeof(out->cert_dir));
        parse_export_line(line, "N00B_TEST_DOCKER_ZOT_URL",
                          out->url, sizeof(out->url));
        parse_export_line(line, "N00B_TEST_DOCKER_ZOT_HOST",
                          out->host, sizeof(out->host));
        parse_export_line(line, "N00B_TEST_DOCKER_ZOT_CERT_FP",
                          out->cert_fp_hex, sizeof(out->cert_fp_hex));
    }
    int rc = pclose(fp);
    if (rc != 0) {
        fprintf(stderr, "start.sh exited with status %d\n", rc);
        return false;
    }
    if (out->url[0] == '\0' || out->cert_fp_hex[0] == '\0'
        || out->host[0] == '\0') {
        fprintf(stderr, "start.sh did not emit the expected exports\n");
        return false;
    }
    return true;
}

static void
zot_fixture_stop(const zot_fixture_t *fx)
{
    if (fx->container[0] == '\0' && fx->cert_dir[0] == '\0') {
        return;
    }
    const char *src_root = getenv("N00B_TEST_ZOT_SRC_ROOT");
    if (src_root == nullptr || src_root[0] == '\0') {
        src_root = getenv("MESON_SOURCE_ROOT");
    }
    char cmd[2048];
    if (src_root != nullptr && src_root[0] != '\0') {
        snprintf(cmd, sizeof(cmd),
                 "ZOT_CONTAINER='%s' ZOT_CERT_DIR='%s' "
                 "/bin/bash %s/test/fixtures/zot/stop.sh >/dev/null 2>&1",
                 fx->container, fx->cert_dir, src_root);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "ZOT_CONTAINER='%s' ZOT_CERT_DIR='%s' "
                 "/bin/bash test/fixtures/zot/stop.sh >/dev/null 2>&1",
                 fx->container, fx->cert_dir);
    }
    int rc = system(cmd);
    (void)rc;
}

// ---------------------------------------------------------------------------
// Hex-string → 32-byte SHA-256 fingerprint.
// ---------------------------------------------------------------------------

static bool
hex_to_bytes32(const char *hex, uint8_t out[32])
{
    size_t hlen = strlen(hex);
    if (hlen != 64) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        int  h_val, l_val;
        if (hi >= '0' && hi <= '9')       h_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f')  h_val = 10 + hi - 'a';
        else if (hi >= 'A' && hi <= 'F')  h_val = 10 + hi - 'A';
        else return false;
        if (lo >= '0' && lo <= '9')       l_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f')  l_val = 10 + lo - 'a';
        else if (lo >= 'A' && lo <= 'F')  l_val = 10 + lo - 'A';
        else return false;
        out[i] = (uint8_t)((h_val << 4) | l_val);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_h1_pinned_trust:\n");

    const char *gate = getenv("N00B_TEST_DOCKER");
    if (gate == nullptr || strcmp(gate, "1") != 0) {
        printf("  [SKIP] N00B_TEST_DOCKER!=1 — zot fixture not booted\n");
        n00b_shutdown();
        return 77;
    }

    // 1. Boot the zot fixture.
    zot_fixture_t fx;
    if (!zot_fixture_start(&fx)) {
        fprintf(stderr,
                "  [FAIL] could not boot zot fixture; ensure Docker is "
                "running.\n");
        n00b_shutdown();
        return 1;
    }
    printf("  [INFO] zot fixture: url=%s host=%s fp=%s\n",
           fx.url, fx.host, fx.cert_fp_hex);

    int exit_code = 0;

    // 2. Construct a pinned-fingerprint trust handle from the leaf's
    //    SHA-256 captured by start.sh.
    uint8_t fp_bytes[32];
    if (!hex_to_bytes32(fx.cert_fp_hex, fp_bytes)) {
        fprintf(stderr,
                "  [FAIL] cert fingerprint not 64-char hex: %s\n",
                fx.cert_fp_hex);
        exit_code = 1;
        goto teardown;
    }
    n00b_quic_trust_t *trust = n00b_quic_trust_pinned(fp_bytes);
    if (trust == nullptr) {
        fprintf(stderr, "  [FAIL] n00b_quic_trust_pinned returned null\n");
        exit_code = 1;
        goto teardown;
    }

    // 3. Issue GET /v2/ via the public sync dispatcher with the
    //    pinned trust handle.  prefer_h3 = false so the dispatcher
    //    goes straight to h1 (zot doesn't advertise h3); the h1
    //    round-trip must thread the trust handle into
    //    n00b_acme_tls_connect_ex for the handshake to accept zot's
    //    self-signed leaf.
    char url_buf[320];
    int  url_n = snprintf(url_buf, sizeof(url_buf), "%s/v2/", fx.url);
    assert(url_n > 0 && (size_t)url_n < sizeof(url_buf));
    n00b_string_t *url = n00b_string_from_cstr(url_buf);

    auto rr = n00b_http_request_sync(url,
                                     .prefer_h3 = false,
                                     .trust     = trust,
                                     .timeout_ms = 15000);
    if (n00b_result_is_err(rr)) {
        fprintf(stderr,
                "  [FAIL] request_sync returned err=%d (TLS handshake "
                "rejected the pinned-trust chain?)\n",
                (int)n00b_result_get_err(rr));
        exit_code = 1;
        goto teardown;
    }

    n00b_http_response_t *resp = n00b_result_get(rr);
    int                   status = n00b_http_response_status(resp);
    if (status != 200) {
        fprintf(stderr,
                "  [FAIL] expected HTTP 200 from GET /v2/, got %d\n",
                status);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] GET /v2/ via h1 + pinned trust → 200 OK\n");

    printf("All test_h1_pinned_trust tests passed.\n");

teardown:
    zot_fixture_stop(&fx);
    n00b_shutdown();
    return exit_code;
}
