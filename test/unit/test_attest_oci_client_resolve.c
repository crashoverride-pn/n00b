/** @file test/unit/test_attest_oci_client_resolve.c — OCI client +
 *  auth resolver + URL parser regression (WP-004 Phase 1).
 *
 *  Exercises the OCI substrate against in-memory fixtures (no
 *  network). Sub-cases (per the WP-004 Phase 1 plan section 7):
 *
 *    [1] _client_new(registry_url) constructs cleanly + stores the
 *        origin correctly.
 *    [2] _client_new with malformed URL (no `https://` prefix or
 *        null) -> Err(_OCI_BAD_URL).
 *    [3] _auth_resolve(.sources = [_AUTH_CALLER]) is a documented
 *        no-op; the resolver does not produce a CALLER-source
 *        handle (callers thread a pre-built one in directly).
 *        With the default chain (CALLER, REGISTRIES_JSON,
 *        ANONYMOUS) and no env override the resolver lands on
 *        ANONYMOUS.
 *    [4] _auth_resolve(.sources = [_AUTH_REGISTRIES_JSON]) against
 *        a tempfile-written registries.json fixture with a
 *        bearer-token entry returns a handle with that token.
 *    [5] _auth_resolve(.sources = [_AUTH_REGISTRIES_JSON]) against
 *        a fixture with a basic-auth entry returns a handle with
 *        the basic bytes.
 *    [6] _auth_resolve(.sources = [_AUTH_ANONYMOUS]) returns a no-
 *        token handle unconditionally.
 *    [7] _auth_resolve(.sources = [_AUTH_CRED_HELPER]) ->
 *        Err(_OCI_AUTH_SOURCE_NOT_FOUND) per D-051 OQ-1's future-
 *        WP framing.
 *    [8] _auth_resolve(.sources = [_AUTH_KEYCHAIN]) ->
 *        Err(_OCI_AUTH_SOURCE_NOT_FOUND) per D-051 OQ-1's future-
 *        WP framing.
 *    [9] _oci_url_parse parse cases (covers § 4.1 colon-
 *        ambiguity rule): digest form, tag form, with-registry,
 *        without-registry, with-port, malformed.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for tempfile
 *  setup and stdout logging is acceptable per the established
 *  test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "test_portability.h"

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "attest/n00b_attest.h"
#include "internal/attest/oci/registry.h"

// The OCI substrate's Err legs carry bare `n00b_err_t` codes via the
// canonical `n00b_result_t(T)` shape (matching signer / verifier
// precedent from WP-002/3). Richer Err payloads are deferred to the
// libn00b typed-Err-payload future lift (DF-011).
#define ASSERT_OK(r) do { if (n00b_result_is_err(r)) { \
        fprintf(stderr, "FAIL @ %s:%d (err=%d)\n", __FILE__, __LINE__, \
                (int)n00b_result_get_err(r)); \
        assert(0); } } while (0)

// ---------------------------------------------------------------------------
// Tempdir + registries.json fixture helpers (test-file carve-out).
// ---------------------------------------------------------------------------

// Create a fresh temp directory, return a malloc'd path.
static char *
make_tempdir(void)
{
    char  path_template[] = "/tmp/n00b_attest_oci_XXXXXX";
    char *path            = strdup(path_template);
    assert(mkdtemp(path) != nullptr);
    return path;
}

// Write the given JSON content to <tempdir>/n00b-attest/
// registries.json. Creates the intermediate directory.
static void
write_registries_json(const char *tempdir, const char *json)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/n00b-attest", tempdir);
    assert(mkdir(dir, 0700) == 0);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/registries.json", dir);

    FILE *f = fopen(file_path, "wb");
    assert(f != nullptr);
    fputs(json, f);
    fclose(f);
}

// Clean up a tempdir created by make_tempdir + write_registries_json.
// Best-effort; failures are silent (the OS will reclaim eventually).
static void
cleanup_tempdir(const char *tempdir)
{
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/n00b-attest/registries.json",
             tempdir);
    unlink(file_path);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/n00b-attest", tempdir);
    rmdir(dir);
    rmdir(tempdir);
}

// ---------------------------------------------------------------------------
// Test cases — client lifecycle.
// ---------------------------------------------------------------------------

static void
test_client_new_ok(void)
{
    n00b_string_t *url = n00b_string_from_cstr("https://ghcr.io");
    auto r = n00b_attest_oci_client_new(url);
    ASSERT_OK(r);
    n00b_attest_oci_client_t *c = n00b_result_get(r);
    assert(c != nullptr);
    assert(c->registry_origin != nullptr);
    assert(c->registry_origin->u8_bytes == url->u8_bytes);
    assert(memcmp(c->registry_origin->data, url->data, url->u8_bytes) == 0);
    n00b_attest_oci_client_release(c);
    n00b_attest_oci_client_release(nullptr);  // null-release no-op.
    printf("  [PASS] client_new_ok\n");
}

static void
test_client_new_bad_url(void)
{
    auto r1 = n00b_attest_oci_client_new(nullptr);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ATTEST_ERR_OCI_BAD_URL);

    // Plain HTTP -> rejected; the OCI client enforces HTTPS.
    n00b_string_t *http_url = n00b_string_from_cstr("http://ghcr.io");
    auto           r2       = n00b_attest_oci_client_new(http_url);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_ATTEST_ERR_OCI_BAD_URL);

    // Empty string.
    n00b_string_t *empty = n00b_string_from_cstr("");
    auto           r3    = n00b_attest_oci_client_new(empty);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_ATTEST_ERR_OCI_BAD_URL);

    printf("  [PASS] client_new_bad_url\n");
}

static void
test_client_new_stores_kwargs(void)
{
    n00b_string_t *url = n00b_string_from_cstr("https://localhost:5000");
    n00b_list_t(n00b_string_t *) allowlist = n00b_list_new(n00b_string_t *);
    n00b_list_push(allowlist, n00b_string_from_cstr("localhost"));

    auto r = n00b_attest_oci_client_new(
        url,
        .timeout_ms              = 60000,
        .allow_redirects         = false,
        .redirect_host_allowlist = &allowlist);
    ASSERT_OK(r);
    n00b_attest_oci_client_t *c = n00b_result_get(r);
    assert(c->timeout_ms == 60000);
    assert(c->allow_redirects == false);
    assert(c->redirect_host_allowlist == &allowlist);

    n00b_attest_oci_client_release(c);
    printf("  [PASS] client_new_stores_kwargs\n");
}

// ---------------------------------------------------------------------------
// Test cases — auth resolver.
// ---------------------------------------------------------------------------

static void
test_auth_resolve_anonymous(void)
{
    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_ANONYMOUS);

    auto r = n00b_attest_oci_auth_resolve(.sources = &chain);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_ANONYMOUS);
    assert(a->bearer_token == nullptr);
    assert(a->basic_auth == nullptr);
    n00b_attest_oci_auth_release(a);
    printf("  [PASS] auth_resolve_anonymous\n");
}

static void
test_auth_resolve_caller_only_falls_through_to_err(void)
{
    // CALLER alone is a no-op in the resolver; with no fallback to
    // ANONYMOUS the resolver returns _OCI_AUTH_SOURCE_NOT_FOUND.
    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_CALLER);

    auto r = n00b_attest_oci_auth_resolve(.sources = &chain);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);
    printf("  [PASS] auth_resolve_caller_only_falls_through_to_err\n");
}

static void
test_auth_resolve_registries_json_bearer(void)
{
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"ghcr.io\": { \"token\": \"abc123tokenbytes\" } }\n");

    // Redirect the resolver to the tempdir via XDG_CONFIG_HOME.
    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("ghcr.io");
    auto r = n00b_attest_oci_auth_resolve(.sources = &chain,
                                          .registry = filter);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);
    assert(a->bearer_token != nullptr);
    assert(a->basic_auth == nullptr);
    assert(a->bearer_token->byte_len == strlen("abc123tokenbytes"));
    assert(memcmp(a->bearer_token->data,
                  "abc123tokenbytes",
                  a->bearer_token->byte_len)
           == 0);
    n00b_attest_oci_auth_release(a);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_registries_json_bearer\n");
}

static void
test_auth_resolve_registries_json_basic(void)
{
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"docker.io\": { \"auth\": \"dXNlcjpwYXNz\" } }\n");

    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("docker.io");
    auto r = n00b_attest_oci_auth_resolve(.sources = &chain,
                                          .registry = filter);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);
    assert(a->bearer_token == nullptr);
    assert(a->basic_auth != nullptr);
    assert(a->basic_auth->byte_len == strlen("dXNlcjpwYXNz"));
    assert(memcmp(a->basic_auth->data,
                  "dXNlcjpwYXNz",
                  a->basic_auth->byte_len)
           == 0);
    n00b_attest_oci_auth_release(a);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_registries_json_basic\n");
}

static void
test_auth_resolve_cred_helper_not_found(void)
{
    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_CRED_HELPER);

    auto r = n00b_attest_oci_auth_resolve(.sources = &chain);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);
    printf("  [PASS] auth_resolve_cred_helper_not_found\n");
}

static void
test_auth_resolve_keychain_not_found(void)
{
    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_KEYCHAIN);

    auto r = n00b_attest_oci_auth_resolve(.sources = &chain);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);
    printf("  [PASS] auth_resolve_keychain_not_found\n");
}

static void
test_auth_resolve_default_chain_lands_on_anonymous(void)
{
    // Ensure no $XDG_CONFIG_HOME registries.json file lingers from
    // earlier tests. With no caller-provided chain and no
    // registries.json hit, the default chain
    // [CALLER, REGISTRIES_JSON, ANONYMOUS] terminates on the
    // anonymous source.
    unsetenv("XDG_CONFIG_HOME");
    // We deliberately do NOT touch HOME — the fallback path requires
    // a non-existent file under ~/.config/n00b-attest/. The test
    // environment normally doesn't have that file; if it does, the
    // resolver may legitimately return a credentials handle instead.
    // To make the test deterministic, point HOME at an empty
    // tempdir so the fallback path also fails.
    char *empty_home = make_tempdir();
    char *old_home   = getenv("HOME");
    char *saved_home = old_home != nullptr ? strdup(old_home) : nullptr;
    setenv("HOME", empty_home, 1);

    auto r = n00b_attest_oci_auth_resolve();
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_ANONYMOUS);
    n00b_attest_oci_auth_release(a);

    if (saved_home != nullptr) {
        setenv("HOME", saved_home, 1);
        free(saved_home);
    } else {
        unsetenv("HOME");
    }
    cleanup_tempdir(empty_home);
    free(empty_home);
    printf("  [PASS] auth_resolve_default_chain_lands_on_anonymous\n");
}

// ---------------------------------------------------------------------------
// Test cases — image-ref URL parser.
// ---------------------------------------------------------------------------

static void
assert_str_eq(n00b_string_t *s, const char *expected)
{
    assert(s != nullptr);
    size_t elen = strlen(expected);
    if (s->u8_bytes != elen) {
        fprintf(stderr,
                "FAIL: string mismatch: expected '%s' (len %zu), got '%.*s' "
                "(len %zu)\n",
                expected,
                elen,
                (int)s->u8_bytes,
                s->data,
                s->u8_bytes);
        assert(0);
    }
    assert(memcmp(s->data, expected, elen) == 0);
}

static void
test_url_parse_registry_digest(void)
{
    n00b_string_t *r = n00b_string_from_cstr(
        "ghcr.io/foo/bar@sha256:abcdef0123456789");
    auto pr = n00b_attest_oci_url_parse(r);
    ASSERT_OK(pr);
    n00b_attest_oci_image_ref_t *ref = n00b_result_get(pr);
    assert_str_eq(ref->registry, "ghcr.io");
    assert_str_eq(ref->name, "foo/bar");
    assert_str_eq(ref->digest, "sha256:abcdef0123456789");
    assert(ref->tag == nullptr);
    printf("  [PASS] url_parse_registry_digest\n");
}

static void
test_url_parse_no_registry_digest(void)
{
    n00b_string_t *r = n00b_string_from_cstr(
        "foo/bar@sha256:abcdef0123456789");
    auto pr = n00b_attest_oci_url_parse(r);
    ASSERT_OK(pr);
    n00b_attest_oci_image_ref_t *ref = n00b_result_get(pr);
    assert(ref->registry == nullptr);  // No `.`/`:`/`localhost` in first
                                       // component -> caller's default
                                       // registry will apply.
    assert_str_eq(ref->name, "foo/bar");
    assert_str_eq(ref->digest, "sha256:abcdef0123456789");
    assert(ref->tag == nullptr);
    printf("  [PASS] url_parse_no_registry_digest\n");
}

static void
test_url_parse_no_registry_tag(void)
{
    n00b_string_t *r = n00b_string_from_cstr("foo/bar:latest");
    auto pr = n00b_attest_oci_url_parse(r);
    ASSERT_OK(pr);
    n00b_attest_oci_image_ref_t *ref = n00b_result_get(pr);
    assert(ref->registry == nullptr);
    assert_str_eq(ref->name, "foo/bar");
    assert_str_eq(ref->tag, "latest");
    assert(ref->digest == nullptr);
    printf("  [PASS] url_parse_no_registry_tag\n");
}

static void
test_url_parse_localhost_port_tag(void)
{
    // Colon in the FIRST component is a port.
    n00b_string_t *r = n00b_string_from_cstr("localhost:5000/foo/bar:tag");
    auto pr = n00b_attest_oci_url_parse(r);
    ASSERT_OK(pr);
    n00b_attest_oci_image_ref_t *ref = n00b_result_get(pr);
    assert_str_eq(ref->registry, "localhost:5000");
    assert_str_eq(ref->name, "foo/bar");
    assert_str_eq(ref->tag, "tag");
    assert(ref->digest == nullptr);
    printf("  [PASS] url_parse_localhost_port_tag\n");
}

static void
test_url_parse_localhost_port_digest(void)
{
    n00b_string_t *r = n00b_string_from_cstr(
        "localhost:5000/foo/bar@sha256:abc");
    auto pr = n00b_attest_oci_url_parse(r);
    ASSERT_OK(pr);
    n00b_attest_oci_image_ref_t *ref = n00b_result_get(pr);
    assert_str_eq(ref->registry, "localhost:5000");
    assert_str_eq(ref->name, "foo/bar");
    assert_str_eq(ref->digest, "sha256:abc");
    assert(ref->tag == nullptr);
    printf("  [PASS] url_parse_localhost_port_digest\n");
}

static void
test_url_parse_malformed(void)
{
    auto r1 = n00b_attest_oci_url_parse(nullptr);
    assert(n00b_result_is_err(r1));
    assert(n00b_result_get_err(r1) == N00B_ATTEST_ERR_OCI_BAD_URL);

    n00b_string_t *empty = n00b_string_from_cstr("");
    auto           r2    = n00b_attest_oci_url_parse(empty);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_ATTEST_ERR_OCI_BAD_URL);

    // No `@` and no `:` -> missing pin -> reject.
    n00b_string_t *bare = n00b_string_from_cstr("foo/bar");
    auto           r3   = n00b_attest_oci_url_parse(bare);
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_ATTEST_ERR_OCI_BAD_URL);

    // Empty digest suffix.
    n00b_string_t *empty_dig = n00b_string_from_cstr("foo/bar@");
    auto           r4        = n00b_attest_oci_url_parse(empty_dig);
    assert(n00b_result_is_err(r4));
    assert(n00b_result_get_err(r4) == N00B_ATTEST_ERR_OCI_BAD_URL);

    // Empty tag suffix.
    n00b_string_t *empty_tag = n00b_string_from_cstr("foo/bar:");
    auto           r5        = n00b_attest_oci_url_parse(empty_tag);
    assert(n00b_result_is_err(r5));
    assert(n00b_result_get_err(r5) == N00B_ATTEST_ERR_OCI_BAD_URL);

    printf("  [PASS] url_parse_malformed\n");
}

// ---------------------------------------------------------------------------
// Test cases — DF-J IDN host-canonicalization symmetry for the
// `registries.json` lookup.
//
// Pre-DF-J the `auth_from_registries_json` helper compared the
// caller's `registry_filter` against each JSON key via raw byte
// memcmp; that would silently fail to match when one side was
// authored in Unicode (`例え.com`) and the other in Punycode
// (`xn--r8jz45g.com`). DF-J introduces an IDNA-canonicalized
// compare with a raw-byte fast path; these tests cover both the
// fast path and the cross-encoding match in both directions.
// ---------------------------------------------------------------------------

static void
test_auth_resolve_idn_unicode_filter_punycode_key(void)
{
    // Filter is `例え.com` (Unicode); JSON key is the Punycode
    // form `xn--r8jz45g.com`. Pre-DF-J these would not match.
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"xn--r8jz45g.com\": { \"token\": \"idn-token-bytes\" } }\n");

    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("例え.com");
    auto r = n00b_attest_oci_auth_resolve(.sources  = &chain,
                                          .registry = filter);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);
    assert(a->bearer_token != nullptr);
    assert(a->bearer_token->byte_len == strlen("idn-token-bytes"));
    assert(memcmp(a->bearer_token->data,
                  "idn-token-bytes",
                  a->bearer_token->byte_len)
           == 0);
    n00b_attest_oci_auth_release(a);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_idn_unicode_filter_punycode_key\n");
}

static void
test_auth_resolve_idn_punycode_filter_unicode_key(void)
{
    // Filter is the Punycode form (`xn--r8jz45g.com`); JSON key is
    // the Unicode form (`例え.com`). Symmetric to the prior test.
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"例え.com\": { \"token\": \"idn-token-bytes-2\" } }\n");

    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("xn--r8jz45g.com");
    auto r = n00b_attest_oci_auth_resolve(.sources  = &chain,
                                          .registry = filter);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->source == N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);
    assert(a->bearer_token != nullptr);
    assert(a->bearer_token->byte_len == strlen("idn-token-bytes-2"));
    n00b_attest_oci_auth_release(a);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_idn_punycode_filter_unicode_key\n");
}

static void
test_auth_resolve_idn_ascii_with_port(void)
{
    // Pure-ASCII host:port — must continue to work byte-identically.
    // Exercises the `:port` split path inside the canonicalizer.
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"localhost:5000\": { \"token\": \"port-token\" } }\n");

    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("localhost:5000");
    auto r = n00b_attest_oci_auth_resolve(.sources  = &chain,
                                          .registry = filter);
    ASSERT_OK(r);
    n00b_attest_oci_auth_t *a = n00b_result_get(r);
    assert(a != nullptr);
    assert(a->bearer_token != nullptr);
    assert(a->bearer_token->byte_len == strlen("port-token"));
    n00b_attest_oci_auth_release(a);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_idn_ascii_with_port\n");
}

static void
test_auth_resolve_idn_no_match_falls_through(void)
{
    // A genuinely different host (different domain) still does NOT
    // match. Pre/post-DF-J this should both return no credentials
    // when REGISTRIES_JSON is the only source listed.
    char *tempdir = make_tempdir();
    write_registries_json(
        tempdir,
        "{ \"ghcr.io\": { \"token\": \"abc123\" } }\n");

    assert(setenv("XDG_CONFIG_HOME", tempdir, 1) == 0);

    n00b_list_t(n00b_attest_oci_auth_source_t) chain =
        n00b_list_new(n00b_attest_oci_auth_source_t);
    n00b_list_push(chain, N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON);

    n00b_string_t *filter = n00b_string_from_cstr("例え.com");
    auto r = n00b_attest_oci_auth_resolve(.sources  = &chain,
                                          .registry = filter);
    // No matching key + no ANONYMOUS fallback in the explicit chain
    // -> source-not-found.
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);

    unsetenv("XDG_CONFIG_HOME");
    cleanup_tempdir(tempdir);
    free(tempdir);
    printf("  [PASS] auth_resolve_idn_no_match_falls_through\n");
}

// ---------------------------------------------------------------------------
// main.
// ---------------------------------------------------------------------------

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);
    n00b_attest_module_init();

    printf("== n00b_attest OCI client + auth resolve + URL parse ==\n");
    test_client_new_ok();
    test_client_new_bad_url();
    test_client_new_stores_kwargs();
    test_auth_resolve_anonymous();
    test_auth_resolve_caller_only_falls_through_to_err();
    test_auth_resolve_registries_json_bearer();
    test_auth_resolve_registries_json_basic();
    test_auth_resolve_cred_helper_not_found();
    test_auth_resolve_keychain_not_found();
    test_auth_resolve_default_chain_lands_on_anonymous();
    test_auth_resolve_idn_unicode_filter_punycode_key();
    test_auth_resolve_idn_punycode_filter_unicode_key();
    test_auth_resolve_idn_ascii_with_port();
    test_auth_resolve_idn_no_match_falls_through();
    test_url_parse_registry_digest();
    test_url_parse_no_registry_digest();
    test_url_parse_no_registry_tag();
    test_url_parse_localhost_port_tag();
    test_url_parse_localhost_port_digest();
    test_url_parse_malformed();

    printf("All n00b_attest OCI substrate tests passed.\n");
    return 0;
}
