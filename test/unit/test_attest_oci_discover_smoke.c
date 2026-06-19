/** @file test/unit/test_attest_oci_discover_smoke.c — discover-side
 *  smoke against the zot fixture (WP-004 Phase 3).
 *
 *  Gated by `N00B_TEST_DOCKER=1`. When the env var is unset the test
 *  exits 77 (meson's "skip" exit code).
 *
 *  Body:
 *
 *    [1] Boot the zot fixture via `test/fixtures/zot/start.sh` and
 *        derive a pinned-fingerprint trust handle from the leaf cert.
 *    [2] Push a synthetic OCI "image" — empty config blob + minimal
 *        OCI 1.1 image manifest — and record the resulting subject
 *        manifest digest.
 *    [3] Sign + push TWO envelopes against the subject:
 *        - Envelope A: predicate-type `https://slsa.dev/provenance/v1`,
 *          RFC 8032 §7.1 vector #1 keyid.
 *        - Envelope B: predicate-type `https://crashoverride.com/sbom/v1`,
 *          same keyid.
 *    [4] Call `n00b_attest_oci_list_referrers` against the subject.
 *        Asserts:
 *          - Returns Ok.
 *          - The list has exactly 2 entries.
 *          - Both entries carry non-null `predicate_type` and
 *            `signer_keyid`.
 *          - The set of predicate-types on the discovered entries
 *            matches the set of predicate-types we pushed.
 *    [5] Tear the fixture down on every exit path.
 *
 *  Test-file carve-out (D-030) applies — libc I/O for spawning
 *  start/stop, environment access, tempfile setup, and stdout
 *  logging is acceptable per the established test-file precedent.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/runtime.h"
#include "attest/n00b_attest.h"
#include "internal/attest/oci/registry.h"
#include "crypto/trust.h"

// ---------------------------------------------------------------------------
// RFC 8032 §7.1 vector #1 — same fixture every WP-002/3/4 test uses.
// ---------------------------------------------------------------------------

static char *
write_pkcs8_pem_tempfile(void)
{
    char  path_template[] = "/tmp/n00b_attest_discover_smoke_key_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);
    static const char k_b64[]
        = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/Vpgun65gK9JLCxESVppezJpGXA7rAMcrn9g";
    fprintf(f, "-----BEGIN PRIVATE KEY-----\n");
    fprintf(f, "%s\n", k_b64);
    fprintf(f, "-----END PRIVATE KEY-----\n");
    fclose(f);
    return path;
}

// ---------------------------------------------------------------------------
// Fixture lifecycle — same shape as test_attest_oci_push_smoke.c.
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
        while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r')) {
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
// Build + sign envelopes with a given predicate-type.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_signed_envelope_with_predicate(const char *predicate_type_uri,
                                     const char *key_path)
{
    n00b_attest_statement_t *st = n00b_attest_statement_new();
    uint8_t d[32];
    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 11 + 5);
    }
    n00b_buffer_t *digest = n00b_buffer_from_bytes((char *)d, 32);
    auto ar = n00b_attest_statement_add_subject(
        st,
        .name   = n00b_string_from_cstr("discover-smoke-subject"),
        .digest = digest);
    assert(!n00b_result_is_err(ar));
    auto tr = n00b_attest_statement_set_predicate_type(
        st,
        n00b_string_from_cstr(predicate_type_uri));
    assert(!n00b_result_is_err(tr));
    static const char k_pred[] = "{\"foo\":42}";
    n00b_buffer_t *pred = n00b_buffer_from_bytes(
        (char *)k_pred, (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    assert(!n00b_result_is_err(pr));
    auto sr = n00b_attest_statement_serialize(st);
    assert(!n00b_result_is_err(sr));
    n00b_buffer_t *stmt_bytes = n00b_result_get(sr);

    char uri[600];
    snprintf(uri, sizeof(uri), "file://%s", key_path);
    n00b_string_t *key_uri = n00b_string_from_cstr(uri);

    auto sign_r = n00b_attest_cli_sign(stmt_bytes, key_uri);
    assert(!n00b_result_is_err(sign_r));
    return n00b_result_get(sign_r);
}

// ---------------------------------------------------------------------------
// Synthetic OCI image upload — copied from push smoke (this test is
// fixture-isolated from push_smoke; the helpers are duplicated rather
// than shared so the test files stand alone).
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_synthetic_image_manifest(n00b_string_t *config_digest,
                               uint64_t       config_size)
{
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "{\"schemaVersion\":2,"
                     "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                     "\"config\":{"
                     "\"mediaType\":\"application/vnd.oci.empty.v1+json\","
                     "\"digest\":\"%.*s\","
                     "\"size\":%llu"
                     "},"
                     "\"layers\":[]}",
                     (int)config_digest->u8_bytes,
                     config_digest->data,
                     (unsigned long long)config_size);
    assert(n > 0 && (size_t)n < sizeof(buf));
    return n00b_buffer_from_bytes(buf, (int64_t)n);
}

static n00b_string_t *
push_synthetic_image(n00b_attest_oci_client_t *client,
                     n00b_string_t            *name)
{
    static const char k_cfg[] = "{}";
    n00b_buffer_t *cfg = n00b_buffer_from_bytes((char *)k_cfg, 2);
    auto cfg_dig_r = n00b_attest_oci_digest_of_buffer(cfg);
    assert(!n00b_result_is_err(cfg_dig_r));
    n00b_string_t *cfg_digest = n00b_result_get(cfg_dig_r);
    auto blob_r = n00b_attest_oci_blob_upload(
        client, name, cfg, cfg_digest,
        .content_type = n00b_string_from_cstr(
            "application/vnd.oci.empty.v1+json"));
    if (n00b_result_is_err(blob_r)) {
        fprintf(stderr,
                "synthetic config-blob upload failed: err=%d\n",
                (int)n00b_result_get_err(blob_r));
        return nullptr;
    }
    n00b_buffer_t *manifest = build_synthetic_image_manifest(cfg_digest, 2);
    auto m_dig_r = n00b_attest_oci_digest_of_buffer(manifest);
    assert(!n00b_result_is_err(m_dig_r));
    n00b_string_t *manifest_digest = n00b_result_get(m_dig_r);
    auto up_r = n00b_attest_oci_manifest_upload(
        client, name, manifest_digest, manifest);
    if (n00b_result_is_err(up_r)) {
        fprintf(stderr,
                "synthetic image-manifest upload failed: err=%d\n",
                (int)n00b_result_get_err(up_r));
        return nullptr;
    }
    return n00b_result_get(up_r);
}

// ---------------------------------------------------------------------------
// Push an envelope against `subject_digest`, return its manifest digest.
// ---------------------------------------------------------------------------

static n00b_string_t *
push_envelope_as_referrer(n00b_attest_oci_client_t *client,
                          n00b_string_t            *name,
                          n00b_string_t            *subject_digest,
                          n00b_buffer_t            *envelope)
{
    auto env_r = n00b_attest_envelope_parse(envelope);
    assert(!n00b_result_is_err(env_r));
    n00b_attest_envelope_t *env = n00b_result_get(env_r);
    auto kid_r = n00b_attest_envelope_get_signature_keyid(env, 0);
    assert(!n00b_result_is_err(kid_r));
    n00b_string_t *signer_keyid = n00b_result_get(kid_r);
    auto pl_r = n00b_attest_envelope_get_payload(env);
    assert(!n00b_result_is_err(pl_r));
    n00b_buffer_t *payload = n00b_result_get(pl_r);
    auto st_r = n00b_attest_statement_parse(payload);
    assert(!n00b_result_is_err(st_r));
    n00b_option_t(n00b_string_t *) pt_opt
        = n00b_attest_statement_get_predicate_type(n00b_result_get(st_r));
    assert(n00b_option_is_set(pt_opt));
    n00b_string_t *predicate_type = n00b_option_get(pt_opt);

    auto push_r = n00b_attest_oci_push_attestation(
        client, name, subject_digest, envelope,
        .predicate_type = predicate_type,
        .signer_keyid   = signer_keyid);
    if (n00b_result_is_err(push_r)) {
        fprintf(stderr, "push_attestation failed: err=%d\n",
                (int)n00b_result_get_err(push_r));
        return nullptr;
    }
    return n00b_result_get(push_r);
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    n00b_attest_module_init();

    printf("test_attest_oci_discover_smoke:\n");

    const char *gate = getenv("N00B_TEST_DOCKER");
    if (gate == nullptr || strcmp(gate, "1") != 0) {
        printf("  [SKIP] N00B_TEST_DOCKER!=1 — zot fixture not booted\n");
        n00b_shutdown();
        return 77;
    }

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
    char *key_path = nullptr;

    uint8_t fp_bytes[32];
    if (!hex_to_bytes32(fx.cert_fp_hex, fp_bytes)) {
        fprintf(stderr, "  [FAIL] cert fingerprint not 64-char hex: %s\n",
                fx.cert_fp_hex);
        exit_code = 1;
        goto teardown;
    }
    n00b_quic_trust_t *trust = n00b_quic_trust_pinned(fp_bytes);
    assert(trust != nullptr);

    n00b_string_t *url = n00b_string_from_cstr(fx.url);
    auto auth_r = n00b_attest_oci_auth_resolve();
    assert(!n00b_result_is_err(auth_r));
    n00b_attest_oci_auth_t *auth = n00b_result_get(auth_r);

    auto cli_r = n00b_attest_oci_client_new(url,
                                             .auth  = auth,
                                             .trust = trust);
    assert(!n00b_result_is_err(cli_r));
    n00b_attest_oci_client_t *client = n00b_result_get(cli_r);

    n00b_string_t *repo = n00b_string_from_cstr("smoke/discover");
    n00b_string_t *subject_digest = push_synthetic_image(client, repo);
    if (subject_digest == nullptr) {
        fprintf(stderr, "  [FAIL] synthetic image push\n");
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] synthetic image: subject_digest=%.*s\n",
           (int)subject_digest->u8_bytes, subject_digest->data);

    key_path = write_pkcs8_pem_tempfile();

    static const char k_pred_a[] = "https://slsa.dev/provenance/v1";
    static const char k_pred_b[] = "https://crashoverride.com/sbom/v1";

    n00b_buffer_t *env_a = build_signed_envelope_with_predicate(k_pred_a,
                                                                 key_path);
    n00b_buffer_t *env_b = build_signed_envelope_with_predicate(k_pred_b,
                                                                 key_path);

    n00b_string_t *mdg_a = push_envelope_as_referrer(client, repo,
                                                     subject_digest, env_a);
    n00b_string_t *mdg_b = push_envelope_as_referrer(client, repo,
                                                     subject_digest, env_b);
    if (mdg_a == nullptr || mdg_b == nullptr) {
        fprintf(stderr, "  [FAIL] pushing fixture envelopes\n");
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] pushed 2 envelopes; mdg_a=%.*s mdg_b=%.*s\n",
           (int)mdg_a->u8_bytes, mdg_a->data,
           (int)mdg_b->u8_bytes, mdg_b->data);

    // ----- The discover dispatch under test.
    auto list_r = n00b_attest_oci_list_referrers(client, repo, subject_digest);
    if (n00b_result_is_err(list_r)) {
        fprintf(stderr, "  [FAIL] list_referrers: err=%d\n",
                (int)n00b_result_get_err(list_r));
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    n00b_list_t(n00b_attest_oci_referrer_t *) *refs = n00b_result_get(list_r);
    if (refs->len != 2) {
        fprintf(stderr, "  [FAIL] expected 2 referrers, got %zu\n",
                (size_t)refs->len);
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }

    bool saw_a = false, saw_b = false;
    for (size_t i = 0; i < refs->len; i++) {
        n00b_attest_oci_referrer_t *r = refs->data[i];
        if (r == nullptr || r->manifest_digest == nullptr) {
            fprintf(stderr, "  [FAIL] referrer entry missing manifest_digest\n");
            n00b_attest_oci_client_release(client);
            n00b_attest_oci_auth_release(auth);
            exit_code = 1;
            goto teardown;
        }
        if (r->predicate_type == nullptr || r->signer_keyid == nullptr) {
            fprintf(stderr, "  [FAIL] referrer entry missing annotations\n");
            n00b_attest_oci_client_release(client);
            n00b_attest_oci_auth_release(auth);
            exit_code = 1;
            goto teardown;
        }
        if (r->predicate_type->u8_bytes == sizeof(k_pred_a) - 1
            && memcmp(r->predicate_type->data, k_pred_a,
                       sizeof(k_pred_a) - 1) == 0) {
            saw_a = true;
        }
        if (r->predicate_type->u8_bytes == sizeof(k_pred_b) - 1
            && memcmp(r->predicate_type->data, k_pred_b,
                       sizeof(k_pred_b) - 1) == 0) {
            saw_b = true;
        }
    }
    if (!saw_a || !saw_b) {
        fprintf(stderr,
                "  [FAIL] expected both predicate-types in the referrers "
                "(saw_a=%d saw_b=%d)\n",
                (int)saw_a, (int)saw_b);
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] list_referrers returned both pushed envelopes\n");

    n00b_attest_oci_client_release(client);
    n00b_attest_oci_auth_release(auth);

    printf("All test_attest_oci_discover_smoke tests passed.\n");

teardown:
    if (key_path != nullptr) {
        unlink(key_path);
        free(key_path);
    }
    zot_fixture_stop(&fx);
    n00b_shutdown();
    return exit_code;
}
