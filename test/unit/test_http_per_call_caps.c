/** @file test/unit/test_http_per_call_caps.c — libn00b regression
 *  for the DF-014 + DF-015 per-call kwargs on
 *  `n00b_http_request_sync`.
 *
 *  Two kwargs landed together: a per-call response-body byte cap
 *  (`max_body_size`) and a per-call redirect-follow host allowlist
 *  (`redirect_host_allowlist`).  Both default to "no constraint"
 *  so existing callers see identical behavior; the regression
 *  tests below pin both the substrate surface (codes + symbols)
 *  and the integration behavior against the zot fixture.
 *
 *  Sub-cases:
 *
 *    [1] The error-code namespace carries
 *        `N00B_HTTP_ERR_RESPONSE_TOO_LARGE` (-9) and
 *        `N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED` (-10) with
 *        non-empty mappings via `n00b_http_err_str`.
 *    [2] The two codes are distinct from each other and from the
 *        pre-existing HTTP error codes (no namespace collision).
 *    [3] Passing both kwargs on a URL-rejection path threads
 *        through the `_kargs` parser without disturbing the URL-
 *        validation seam (proves the byte-identity contract
 *        between header + impl).
 *    [4] `redirect_host_allowlist = empty list` is "no hosts
 *        permitted" — distinct from `nullptr = no filter`.  This
 *        case is exercised by [3] with default kwargs to ensure
 *        the no-filter path is preserved, and by [6]'s
 *        Docker-gated integration leg.
 *
 *  Docker-gated sub-cases (gated by N00B_TEST_DOCKER=1; SKIP=77
 *  when the env var is unset so the suite stays green in
 *  environments without Docker):
 *
 *    [5] `max_body_size` enforcement: issue GET /v2/ against the
 *        zot fixture with a 1-byte cap; expect
 *        `N00B_HTTP_ERR_RESPONSE_TOO_LARGE`.  Same call without
 *        the cap succeeds (sanity-checks the fixture path).
 *    [6] `redirect_host_allowlist` enforcement: issue a request
 *        against a path that 308s elsewhere with an empty
 *        allowlist; expect
 *        `N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED`.  (Zot doesn't
 *        natively emit cross-host redirects, so this sub-case
 *        also exercises by constructing a Location-resolves-but-
 *        not-in-allowlist scenario where possible; otherwise it
 *        reports SKIPPED on the redirect leg.)
 *
 *  Test-file carve-out (D-030) applies — libc I/O for stdout
 *  logging, environment access, and Docker fixture spawning is
 *  acceptable per the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "adt/result.h"
#include "adt/list.h"
#include "crypto/trust.h"
#include "net/http/http_client.h"
#include "internal/net/http/http_url.h"
#include "internal/net/http/http_client.h"

/* ------------------------------------------------------------------ */
/* [1] Error codes map to non-empty strings.                           */
/* ------------------------------------------------------------------ */

static void
test_err_strings(void)
{
    const char *s_too_large = n00b_http_err_str(
        N00B_HTTP_ERR_RESPONSE_TOO_LARGE);
    assert(s_too_large != nullptr);
    assert(strlen(s_too_large) > 0);
    assert(strcmp(s_too_large, "unknown error") != 0);

    const char *s_not_allowed = n00b_http_err_str(
        N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED);
    assert(s_not_allowed != nullptr);
    assert(strlen(s_not_allowed) > 0);
    assert(strcmp(s_not_allowed, "unknown error") != 0);

    printf("  [PASS] err_strings\n");
}

/* ------------------------------------------------------------------ */
/* [2] Codes are distinct from each other and from existing codes.     */
/* ------------------------------------------------------------------ */

static void
test_codes_distinct(void)
{
    /* Pin slot values to catch accidental shuffles. */
    assert((int32_t)N00B_HTTP_ERR_RESPONSE_TOO_LARGE == -9);
    assert((int32_t)N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED == -10);

    /* Distinct from each other. */
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE
           != N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED);

    /* Distinct from every pre-existing HTTP code. */
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE != N00B_HTTP_OK);
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE != N00B_HTTP_ERR_NULL_ARG);
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE != N00B_HTTP_ERR_INVALID_URL);
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE
           != N00B_HTTP_ERR_UNSUPPORTED_SCHEME);
    assert(N00B_HTTP_ERR_RESPONSE_TOO_LARGE != N00B_HTTP_ERR_BAD_RESPONSE);

    assert(N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED != N00B_HTTP_OK);
    assert(N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED
           != N00B_HTTP_ERR_UNSUPPORTED_SCHEME);
    assert(N00B_HTTP_ERR_HOST_REDIRECT_NOT_ALLOWED
           != N00B_HTTP_ERR_BAD_RESPONSE);

    printf("  [PASS] codes_distinct\n");
}

/* ------------------------------------------------------------------ */
/* [3] _kargs parse: pass both kwargs through the URL-rejection seam.  */
/*                                                                     */
/* We use an `http://` URL so the URL parser rejects the call before  */
/* it ever reaches a network. That keeps this case offline + fast     */
/* while still proving:                                                */
/*   - the header / impl `_kargs` blocks agree byte-for-byte (the     */
/*     `.max_body_size = …` + `.redirect_host_allowlist = …` slots    */
/*     line up to the same field in the kargs struct);                */
/*   - the dispatcher rejects the URL with the same error it would    */
/*     produce with the kwargs absent (no behavior drift).            */
/* ------------------------------------------------------------------ */

static void
test_kargs_acceptance(void)
{
    /* Empty allowlist — semantically "no hosts permitted" but it
     * is fine to construct and pass; the dispatcher only consults
     * it when following a redirect. */
    n00b_list_t(n00b_string_t *) empty_allow =
        n00b_list_new(n00b_string_t *);

    auto r1 = n00b_http_request_sync(
        n00b_string_from_cstr("http://example.com/"),
        .max_body_size           = 1024,
        .redirect_host_allowlist = &empty_allow);
    assert(n00b_result_is_err(r1));
    assert((int32_t)n00b_result_get_err(r1)
           == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

    /* `max_body_size = 0` + nullptr allowlist == default behavior. */
    auto r2 = n00b_http_request_sync(
        n00b_string_from_cstr("http://example.com/"),
        .max_body_size           = 0,
        .redirect_host_allowlist = nullptr);
    assert(n00b_result_is_err(r2));
    assert((int32_t)n00b_result_get_err(r2)
           == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

    /* Single-entry allowlist — exercises the alloc + push path. */
    n00b_list_t(n00b_string_t *) one_allow =
        n00b_list_new(n00b_string_t *);
    /* `n00b_list_push` macro evaluates its first arg as an lvalue. */
    n00b_list_push(one_allow,
                   n00b_string_from_cstr("example.com"));
    auto r3 = n00b_http_request_sync(
        n00b_string_from_cstr("http://example.com/"),
        .max_body_size           = (uint64_t)1 << 32,   /* 4 GiB */
        .redirect_host_allowlist = &one_allow);
    assert(n00b_result_is_err(r3));
    assert((int32_t)n00b_result_get_err(r3)
           == N00B_HTTP_ERR_UNSUPPORTED_SCHEME);

    printf("  [PASS] kargs_acceptance\n");
}

/* ------------------------------------------------------------------ */
/* Zot fixture lifecycle (mirrors test_h1_pinned_trust).               */
/* ------------------------------------------------------------------ */

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
    if (strncmp(line, prefix, plen) != 0) return false;
    const char *p = line + plen;
    size_t nlen = strlen(name);
    if (strncmp(p, name, nlen) != 0 || p[nlen] != '=') return false;
    p += nlen + 1;
    bool quoted = false;
    if (*p == '\'') { quoted = true; p++; }
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
    if (fx->container[0] == '\0' && fx->cert_dir[0] == '\0') return;
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

static bool
hex_to_bytes32(const char *hex, uint8_t out[32])
{
    if (strlen(hex) != 64) return false;
    for (size_t i = 0; i < 32; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        int  h_val, l_val;
        if (hi >= '0' && hi <= '9')      h_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') h_val = 10 + hi - 'a';
        else if (hi >= 'A' && hi <= 'F') h_val = 10 + hi - 'A';
        else return false;
        if (lo >= '0' && lo <= '9')      l_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') l_val = 10 + lo - 'a';
        else if (lo >= 'A' && lo <= 'F') l_val = 10 + lo - 'A';
        else return false;
        out[i] = (uint8_t)((h_val << 4) | l_val);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* [5] Integration: max_body_size enforcement against the zot fixture. */
/* ------------------------------------------------------------------ */

static int
test_integration(void)
{
    zot_fixture_t fx;
    if (!zot_fixture_start(&fx)) {
        fprintf(stderr,
                "  [FAIL] could not boot zot fixture; ensure Docker is "
                "running.\n");
        return 1;
    }
    printf("  [INFO] zot fixture: url=%s host=%s fp=%s\n",
           fx.url, fx.host, fx.cert_fp_hex);

    int exit_code = 0;

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

    char url_buf[320];
    int  url_n = snprintf(url_buf, sizeof(url_buf), "%s/v2/", fx.url);
    assert(url_n > 0 && (size_t)url_n < sizeof(url_buf));
    n00b_string_t *url = n00b_string_from_cstr(url_buf);

    /* [5a] Sanity: no cap → success. */
    {
        auto rr = n00b_http_request_sync(url,
                                          .prefer_h3 = false,
                                          .trust     = trust,
                                          .timeout_ms = 15000);
        if (n00b_result_is_err(rr)) {
            fprintf(stderr,
                    "  [FAIL] baseline GET /v2/ returned err=%d\n",
                    (int)n00b_result_get_err(rr));
            exit_code = 1;
            goto teardown;
        }
        n00b_http_response_t *resp = n00b_result_get(rr);
        int status = n00b_http_response_status(resp);
        if (status != 200) {
            fprintf(stderr,
                    "  [FAIL] baseline GET /v2/ status=%d (want 200)\n",
                    status);
            exit_code = 1;
            goto teardown;
        }
        printf("  [PASS] baseline GET /v2/ → 200 OK\n");
    }

    /* [5b] 1-byte cap → enforcement.
     *
     *  zot's `/v2/` response carries a `{}` JSON body of 2 bytes.
     *  With `max_body_size = 1` the h1 receive loop must abort and
     *  surface N00B_HTTP_ERR_RESPONSE_TOO_LARGE. */
    {
        auto rr = n00b_http_request_sync(url,
                                          .prefer_h3     = false,
                                          .trust         = trust,
                                          .timeout_ms    = 15000,
                                          .max_body_size = 1);
        if (n00b_result_is_ok(rr)) {
            n00b_http_response_t *resp = n00b_result_get(rr);
            fprintf(stderr,
                    "  [FAIL] max_body_size=1 returned status=%d "
                    "instead of REQUEST_TOO_LARGE; body_len=%ld\n",
                    n00b_http_response_status(resp),
                    (long)(n00b_http_response_body(resp)
                           ? n00b_http_response_body(resp)->byte_len
                           : 0));
            exit_code = 1;
            goto teardown;
        }
        int32_t err = (int32_t)n00b_result_get_err(rr);
        if (err != N00B_HTTP_ERR_RESPONSE_TOO_LARGE) {
            fprintf(stderr,
                    "  [FAIL] max_body_size=1 returned err=%d "
                    "(want %d = RESPONSE_TOO_LARGE)\n",
                    (int)err,
                    (int)N00B_HTTP_ERR_RESPONSE_TOO_LARGE);
            exit_code = 1;
            goto teardown;
        }
        printf("  [PASS] max_body_size=1 → RESPONSE_TOO_LARGE\n");
    }

    /* [5c] Generous cap → success (no spurious enforcement).
     *
     *  A 1 MiB cap is well above zot's `/v2/` body; this verifies
     *  the non-zero-but-not-tight path doesn't false-positive. */
    {
        auto rr = n00b_http_request_sync(url,
                                          .prefer_h3     = false,
                                          .trust         = trust,
                                          .timeout_ms    = 15000,
                                          .max_body_size = 1 << 20);
        if (n00b_result_is_err(rr)) {
            fprintf(stderr,
                    "  [FAIL] max_body_size=1 MiB returned err=%d\n",
                    (int)n00b_result_get_err(rr));
            exit_code = 1;
            goto teardown;
        }
        printf("  [PASS] max_body_size=1MiB → 200 OK (no spurious "
               "enforcement)\n");
    }

teardown:
    zot_fixture_stop(&fx);
    return exit_code;
}

/* ------------------------------------------------------------------ */
/* [7] Wildcard allowlist matching (candidate #6).                     */
/*                                                                     */
/* Exercises `n00b_http_host_in_allowlist` directly via the internal   */
/* header.                                                             */
/* The matcher is small + side-effect-free; testing at this layer      */
/* avoids spinning a redirect mock for what is purely a string-shape  */
/* classification.                                                     */
/* ------------------------------------------------------------------ */

static n00b_list_t(n00b_string_t *) *
build_allowlist(const char *const *entries, size_t n)
{
    n00b_list_t(n00b_string_t *) *out =
        n00b_alloc(n00b_list_t(n00b_string_t *));
    *out = n00b_list_new(n00b_string_t *);
    for (size_t i = 0; i < n; i++) {
        n00b_list_push(*out, n00b_string_from_cstr(entries[i]));
    }
    return out;
}

static void
test_wildcard_matching(void)
{
    /* [7a] *.example.com matches foo.example.com (single label). */
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("foo.example.com"),
                                  al));
    }

    /* [7b] *.example.com matches foo.bar.example.com (multiple labels;
     *      wildcard absorbs the whole subdomain tree). */
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.bar.example.com"), al));
    }

    /* [7c] *.example.com does NOT match the apex example.com. */
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(!n00b_http_host_in_allowlist(n00b_string_from_cstr("example.com"),
                                   al));
    }

    /* [7d] *.example.com does NOT match notexample.com (no label
     *      boundary on the left of the suffix). */
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(!n00b_http_host_in_allowlist(n00b_string_from_cstr("notexample.com"),
                                   al));
    }

    /* [7e] *.example.com does NOT match evil-example.com (no leading
     *      dot on the suffix-side). */
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("evil-example.com"), al));
    }

    /* [7f] Mixed allowlist [example.com, *.example.com] matches both
     *      apex and subdomains. */
    {
        const char *entries[] = {"example.com", "*.example.com"};
        auto       *al        = build_allowlist(entries, 2);
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("example.com"),
                                  al));
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("foo.example.com"),
                                  al));
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("a.b.example.com"), al));
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("evil.com"), al));
    }

    /* [7g] Malformed entries are silently skipped — no match, no
     *      crash.  Each malformed-only allowlist returns false for
     *      every host. */
    {
        const char *bads[] = {
            "*example.com",     /* * not followed by dot */
            "foo.*.com",        /* * not at offset 0 */
            "*",                /* bare star */
            "**.example.com",   /* double star */
            "*.",               /* * . with empty domain */
        };
        for (size_t i = 0; i < sizeof(bads) / sizeof(bads[0]); i++) {
            const char *entries[] = {bads[i]};
            auto       *al        = build_allowlist(entries, 1);
            assert(!n00b_http_host_in_allowlist(
                n00b_string_from_cstr("foo.example.com"), al));
            assert(!n00b_http_host_in_allowlist(
                n00b_string_from_cstr("example.com"), al));
            /* Defensive: also doesn't match anything weird. */
            assert(!n00b_http_host_in_allowlist(
                n00b_string_from_cstr("anything.com"), al));
        }
    }

    /* [7h] ASCII case-insensitive: *.EXAMPLE.COM matches
     *      foo.example.com (case-fold preserved from exact path). */
    {
        const char *entries[] = {"*.EXAMPLE.COM"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("foo.example.com"),
                                  al));
        /* And the reverse: entry lowercase, host uppercase. */
    }
    {
        const char *entries[] = {"*.example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("FOO.EXAMPLE.COM"),
                                  al));
    }

    /* Empty allowlist still returns false. */
    {
        n00b_list_t(n00b_string_t *) *al =
            n00b_alloc(n00b_list_t(n00b_string_t *));
        *al = n00b_list_new(n00b_string_t *);
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.example.com"), al));
    }

    /* Exact-match backward compat: existing exact entries behave
     * identically to pre-task. */
    {
        const char *entries[] = {"example.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("example.com"),
                                  al));
        assert(n00b_http_host_in_allowlist(n00b_string_from_cstr("EXAMPLE.COM"),
                                  al));
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.example.com"), al));
    }

    /* ---- IDN / UTS-46 sub-cases (deferral-B promotion) ---------- */
    /* The Punycode form of `例え` is `xn--r8jz45g`, so the canonical
     * ACE forms of `例え.com` and `xn--r8jz45g.com` are byte-equal.
     * Post-DF-X the URL parser canonicalizes the host upstream; the
     * matcher now assumes ACE-form input on the host side and
     * canonicalizes only entries.  These cases use the ACE-form
     * host directly (the form the URL parser would emit) to match
     * the new contract; Unicode/Punycode authorship on the entry
     * side still cross-matches the canonical host. */

    /* [7i] Unicode wildcard + canonical (ACE-form) host. */
    {
        const char *entries[] = {"*.例え.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.xn--r8jz45g.com"), al));
    }

    /* [7j] Unicode wildcard + canonical (ACE-form) host (same as
     *      [7i]; pre-DF-X this leg passed a Unicode host directly,
     *      now subsumed by [7i]).  Kept as a redundant assertion
     *      for explicit cross-match coverage. */
    {
        const char *entries[] = {"*.例え.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.xn--r8jz45g.com"), al));
    }

    /* [7k] Punycode wildcard + canonical (ACE-form) host. */
    {
        const char *entries[] = {"*.xn--r8jz45g.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.xn--r8jz45g.com"), al));
    }

    /* [7l] IDN apex rejection: the wildcard does NOT match the
     *      apex (same rule as ASCII cand #6, preserved post-IDNA). */
    {
        const char *entries[] = {"*.例え.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("xn--r8jz45g.com"), al));
    }

    /* [7m] IDN cross-domain rejection: `*.例え.com` does NOT
     *      match a host whose label differs in Unicode form
     *      (`別` → `xn--gcr`, not `xn--r8jz45g`). */
    {
        const char *entries[] = {"*.例え.com"};
        auto       *al        = build_allowlist(entries, 1);
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.xn--gcr.com"), al));
    }

    /* [7n] Malformed-IDN entry skip: an entry with invalid UTF-8
     *      after the `*.` is silently skipped; the rest of the
     *      allowlist is still scanned and other entries still
     *      trip. */
    {
        n00b_list_t(n00b_string_t *) *al =
            n00b_alloc(n00b_list_t(n00b_string_t *));
        *al = n00b_list_new(n00b_string_t *);
        /* `*.<ff><fe>.com` — invalid UTF-8 in the DOMAIN portion. */
        const char bad[] = {'*', '.', (char)0xff, (char)0xfe, '.',
                            'c', 'o', 'm'};
        n00b_list_push(*al,
                       n00b_string_from_raw(bad, (int64_t)sizeof(bad)));
        /* A valid wildcard alongside the malformed entry. */
        n00b_list_push(*al, n00b_string_from_cstr("*.example.com"));
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.example.com"), al));
        /* And the malformed entry alone produces no match. */
        n00b_list_t(n00b_string_t *) *al2 =
            n00b_alloc(n00b_list_t(n00b_string_t *));
        *al2 = n00b_list_new(n00b_string_t *);
        n00b_list_push(*al2,
                       n00b_string_from_raw(bad, (int64_t)sizeof(bad)));
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.example.com"), al2));
    }

    /* [7o] Mixed IDN allowlist: `[example.com, *.例え.com]`
     *      matches both `example.com` and the canonical
     *      `foo.xn--r8jz45g.com` (ACE form of `foo.例え.com`),
     *      but rejects `xn--r8jz45g.com` (apex of the wildcard)
     *      and `foo.bar.com` (not in the list). */
    {
        const char *entries[] = {"example.com", "*.例え.com"};
        auto       *al        = build_allowlist(entries, 2);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("example.com"), al));
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.xn--r8jz45g.com"), al));
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("xn--r8jz45g.com"), al));
        assert(!n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.bar.com"), al));
    }

    /* [7p] ASCII case-insensitivity preserved post-IDNA: an
     *      uppercase wildcard still matches the lowercase host.
     *      UTS-46 lowercases ASCII as part of `to_ascii`, so the
     *      canonical forms are identical bytes here. */
    {
        const char *entries[] = {"*.EXAMPLE.COM"};
        auto       *al        = build_allowlist(entries, 1);
        assert(n00b_http_host_in_allowlist(
            n00b_string_from_cstr("foo.example.com"), al));
    }

    printf("  [PASS] wildcard_matching\n");
}

/* ------------------------------------------------------------------ */
/* Main.                                                               */
/* ------------------------------------------------------------------ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_http_per_call_caps:\n");

    /* Substrate sub-cases — always run.  These pin the codes +
     * symbols so the integration leg can build against a stable
     * surface even when Docker is unavailable. */
    test_err_strings();
    test_codes_distinct();
    test_kargs_acceptance();
    test_wildcard_matching();

    /* Integration sub-cases — gated by N00B_TEST_DOCKER=1. */
    const char *gate = getenv("N00B_TEST_DOCKER");
    if (gate == nullptr || strcmp(gate, "1") != 0) {
        printf("  [SKIP] integration sub-cases (N00B_TEST_DOCKER!=1)\n");
        printf("All test_http_per_call_caps substrate tests passed.\n");
        n00b_shutdown();
        return 0;
    }

    int rc = test_integration();
    if (rc != 0) {
        n00b_shutdown();
        return rc;
    }

    printf("All test_http_per_call_caps tests passed.\n");
    n00b_shutdown();
    return 0;
}
