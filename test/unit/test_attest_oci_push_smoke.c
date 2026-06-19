/** @file test/unit/test_attest_oci_push_smoke.c — full
 *  push-against-zot integration regression (WP-004 Phase 2 trailing
 *  addition).
 *
 *  Gated by `N00B_TEST_DOCKER=1`. When the env var is unset the test
 *  exits 77 (meson's "skip" exit code) cleanly so the suite doesn't
 *  fail in environments without Docker.
 *
 *  Fixture: a zot OCI v2 registry running under
 *  `test/fixtures/zot/start.sh`, listening on an ephemeral 127.0.0.1
 *  port over TLS with a fresh self-signed leaf cert.  The test
 *  invokes `start.sh`, parses the `export …` lines on its stdout
 *  for the registry URL + SHA-256 cert fingerprint, threads the
 *  fingerprint into a `n00b_quic_trust_pinned` trust handle, runs
 *  the full HEAD/POST/PUT/PUT push sequence, and tears the fixture
 *  down via `stop.sh` on exit.
 *
 *  Sub-cases:
 *
 *    [1] Boot the zot fixture via `test/fixtures/zot/start.sh`.
 *    [2] Push a synthetic OCI "image" — config blob `{}` + a
 *        minimal OCI 1.1 image manifest referencing it + an empty
 *        layers array — and record the resulting manifest digest.
 *        This gives the WP-004 push verb's `subject` something to
 *        refer to (the verb's pre-push HEAD would otherwise 404).
 *    [3] Build a fixture in-toto Statement via the WP-001 builder
 *        and sign it via `n00b_attest_cli_sign` against the
 *        RFC 8032 §7.1 vector #1 keypair to produce the envelope.
 *    [4] Construct an OCI client bound to the fixture's URL +
 *        pinned-fingerprint trust + anonymous auth, then invoke
 *        `n00b_attest_oci_push_attestation` against the synthetic
 *        image digest.  Asserts:
 *          - the call returns Ok;
 *          - the returned manifest digest is non-empty;
 *          - the digest matches the canonical
 *            `sha256:[0-9a-f]{64}` form (71 chars total).
 *    [5] Tear the zot fixture down via `test/fixtures/zot/stop.sh`
 *        on every exit path (success and failure).
 *
 *  Test-file carve-out (D-030) applies — libc I/O for spawning
 *  start/stop, environment access, tempfile setup, and stdout
 *  logging is acceptable per the established test-file precedent.
 *
 *  Note (D-054): zot's HEAD on a present manifest returns 200; the
 *  HEAD-primary path here never exercises the 405→GET-fallback leg.
 *  A future smoke against Harbor 1.x (or any registry that 405s on
 *  HEAD) would exercise that leg; flagged for the orchestrator as
 *  a known-uncovered branch under this fixture.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

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

static const uint8_t k_rfc8032_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};

// PKCS#8 Ed25519 wrapper bytes: 16-byte fixed prefix + 32-byte seed.
static void
build_ed25519_pkcs8_der(const uint8_t seed[32], uint8_t out[48])
{
    static const uint8_t k_prefix[16] = {
        0x30, 0x2E,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22,
        0x04, 0x20,
    };
    memcpy(out, k_prefix, 16);
    memcpy(out + 16, seed, 32);
}

// Hex-encode 48-byte DER into a tempfile-rendered PEM.
static char *
write_pkcs8_pem_tempfile(const uint8_t der[48])
{
    char  path_template[] = "/tmp/n00b_attest_push_smoke_key_XXXXXX";
    char *path            = strdup(path_template);
    int   fd              = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "wb");
    assert(f != nullptr);

    // 48 bytes -> base64 -> 64 chars on one line.  We use the
    // canonical RFC 8410 PEM produced by the same fixture pattern as
    // test_attest_cli_sign.c.
    static const char k_b64[]
        = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/Vpgun65gK9JLCxESVppezJpGXA7rAMcrn9g";
    (void)der;  // Tied to the well-known seed; we hardcode the b64.
    fprintf(f, "-----BEGIN PRIVATE KEY-----\n");
    fprintf(f, "%s\n", k_b64);
    fprintf(f, "-----END PRIVATE KEY-----\n");
    fclose(f);
    return path;
}

// ---------------------------------------------------------------------------
// Fixture lifecycle — spawn start.sh / stop.sh and parse exports.
// ---------------------------------------------------------------------------

typedef struct {
    char container[256];
    char cert_dir[512];
    char url[256];
    char host[256];
    char cert_fp_hex[80];  // 64-char hex + nul + a couple guard bytes
} zot_fixture_t;

// Parse one `export NAME='value'` line from start.sh's stdout into
// `out_buf` (sized `out_cap`).  Returns true on a successful match.
// We accept either single-quoted or unquoted values; start.sh emits
// single-quoted.
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

// Spawn `test/fixtures/zot/start.sh`, parse its stdout for the
// expected exports, populate `out`, propagate any error to stderr.
static bool
zot_fixture_start(zot_fixture_t *out)
{
    memset(out, 0, sizeof(*out));
    // popen with explicit /bin/bash so we don't depend on the
    // user's $SHELL.  meson tests run from build_*; the
    // N00B_TEST_ZOT_SRC_ROOT env-var is wired up in meson.build
    // (`env:` block on this test() entry) to the absolute repo-root
    // path so the test can resolve start.sh without depending on
    // the user-side `eval $(start.sh)` pre-step.  Fall back to
    // MESON_SOURCE_ROOT / cwd-relative path so direct manual runs
    // from the repo root work too.
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
        // Strip trailing newline / CR for nicer printing.
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

// Spawn stop.sh with the captured container / cert-dir env vars.
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
// Manifest-digest format check (canonical sha256 form).
// ---------------------------------------------------------------------------

static bool
is_canonical_sha256(const char *s, size_t len)
{
    static const char prefix[] = "sha256:";
    if (len != sizeof(prefix) - 1 + 64) {
        return false;
    }
    if (memcmp(s, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    for (size_t i = sizeof(prefix) - 1; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Build a fixture Statement + sign it via the WP-002 CLI core.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_signed_envelope_bytes(void)
{
    // 1. Build a Statement (one subject, predicate-type SLSA prov v1,
    //    predicate JSON `{"foo": 42}`).  Mirror of the WP-002
    //    test_attest_cli_sign.c shape.
    n00b_attest_statement_t *st = n00b_attest_statement_new();
    uint8_t d[32];
    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 7 + 3);
    }
    n00b_buffer_t *digest = n00b_buffer_from_bytes((char *)d, 32);
    auto ar = n00b_attest_statement_add_subject(
        st,
        .name   = n00b_string_from_cstr("hello"),
        .digest = digest);
    assert(!n00b_result_is_err(ar));
    auto tr = n00b_attest_statement_set_predicate_type(
        st,
        n00b_string_from_cstr("https://slsa.dev/provenance/v1"));
    assert(!n00b_result_is_err(tr));
    static const char k_pred[] = "{\"foo\":42}";
    n00b_buffer_t *pred = n00b_buffer_from_bytes(
        (char *)k_pred, (int64_t)(sizeof(k_pred) - 1));
    auto pr = n00b_attest_statement_set_predicate_json(st, pred);
    assert(!n00b_result_is_err(pr));
    auto sr = n00b_attest_statement_serialize(st);
    assert(!n00b_result_is_err(sr));
    n00b_buffer_t *stmt_bytes = n00b_result_get(sr);

    // 2. Drop the PKCS#8 PEM into a tempfile so the file-backed
    //    signer can resolve it via `file://...`.
    uint8_t der[48];
    build_ed25519_pkcs8_der(k_rfc8032_seed, der);
    char *key_path = write_pkcs8_pem_tempfile(der);
    char  uri[600];
    snprintf(uri, sizeof(uri), "file://%s", key_path);
    n00b_string_t *key_uri = n00b_string_from_cstr(uri);

    // 3. Sign.
    auto sign_r = n00b_attest_cli_sign(stmt_bytes, key_uri);
    assert(!n00b_result_is_err(sign_r));
    n00b_buffer_t *envelope = n00b_result_get(sign_r);

    unlink(key_path);
    free(key_path);
    return envelope;
}

// ---------------------------------------------------------------------------
// Synthetic OCI image upload — config blob + minimal image manifest.
// ---------------------------------------------------------------------------

// Build the minimal OCI 1.1 image manifest that the WP-004 push verb
// will refer to via `subject`.  The shape mirrors the manifest the
// push verb itself emits, minus the `subject` + `annotations` + the
// envelope layer (this is the SUBJECT, not the attestation).
//
// We use the empty-descriptor config blob (`{}` -> `sha256:4413...`)
// + a zero-length layers array.  Field order is byte-stable so the
// computed digest is reproducible.
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

// Push the empty-config blob + the synthetic image manifest, return
// the resulting manifest digest (`sha256:<hex>`).
static n00b_string_t *
push_synthetic_image(n00b_attest_oci_client_t *client,
                     n00b_string_t            *name)
{
    // 1. Empty config blob: literal bytes `{}` (size 2).
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

    // 2. Synthetic image manifest referencing the empty config blob.
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
    n00b_string_t *registry_digest = n00b_result_get(up_r);
    // Sanity: the registry-confirmed digest should match the local
    // one (manifest_upload already cross-checks; this prints it for
    // debug).
    return registry_digest;
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

    printf("test_attest_oci_push_smoke:\n");

    const char *gate = getenv("N00B_TEST_DOCKER");
    if (gate == nullptr || strcmp(gate, "1") != 0) {
        printf("  [SKIP] N00B_TEST_DOCKER!=1 — zot fixture not booted\n");
        n00b_shutdown();
        return 77;  // meson "skip" exit code
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

    // 3. Construct an OCI client bound to the fixture's URL +
    //    pinned trust.  Anonymous auth: the fixture is configured for
    //    anonymous push/pull, so the resolver's terminal ANONYMOUS
    //    source produces the right handle.
    n00b_string_t *url = n00b_string_from_cstr(fx.url);
    auto auth_r = n00b_attest_oci_auth_resolve();
    if (n00b_result_is_err(auth_r)) {
        fprintf(stderr, "  [FAIL] auth_resolve: err=%d\n",
                (int)n00b_result_get_err(auth_r));
        exit_code = 1;
        goto teardown;
    }
    n00b_attest_oci_auth_t *auth = n00b_result_get(auth_r);

    auto cli_r = n00b_attest_oci_client_new(url,
                                            .auth  = auth,
                                            .trust = trust);
    if (n00b_result_is_err(cli_r)) {
        fprintf(stderr, "  [FAIL] client_new: err=%d\n",
                (int)n00b_result_get_err(cli_r));
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    n00b_attest_oci_client_t *client = n00b_result_get(cli_r);

    // 4. Push the synthetic image (config blob + minimal manifest).
    n00b_string_t *repo = n00b_string_from_cstr("smoke/subject");
    n00b_string_t *subject_digest = push_synthetic_image(client, repo);
    if (subject_digest == nullptr) {
        fprintf(stderr, "  [FAIL] synthetic image push\n");
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    if (!is_canonical_sha256(subject_digest->data,
                             subject_digest->u8_bytes)) {
        fprintf(stderr,
                "  [FAIL] synthetic image manifest digest "
                "not canonical sha256: %.*s\n",
                (int)subject_digest->u8_bytes, subject_digest->data);
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] synthetic image: subject_digest=%.*s\n",
           (int)subject_digest->u8_bytes, subject_digest->data);

    // 5. Build + sign the fixture envelope via the WP-002 CLI core.
    n00b_buffer_t *envelope = build_signed_envelope_bytes();
    assert(envelope != nullptr && envelope->byte_len > 0);

    // Walk signatures[0].keyid + payload.predicate_type via the
    // existing public WP-001/2/3 surfaces (mirror of what cli_push
    // does internally).
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
    assert(predicate_type != nullptr && predicate_type->u8_bytes > 0);

    // 6. Run the full HEAD + POST + PUT (blob) + PUT (manifest)
    //    sequence via `_push_attestation` — the WP-004 Phase 2 verb
    //    surface this trailing-addition is closing the loop on.
    auto push_r = n00b_attest_oci_push_attestation(
        client, repo, subject_digest, envelope,
        .predicate_type = predicate_type,
        .signer_keyid   = signer_keyid);
    if (n00b_result_is_err(push_r)) {
        fprintf(stderr,
                "  [FAIL] push_attestation: err=%d\n",
                (int)n00b_result_get_err(push_r));
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    n00b_string_t *manifest_digest = n00b_result_get(push_r);
    if (manifest_digest == nullptr || manifest_digest->u8_bytes == 0) {
        fprintf(stderr, "  [FAIL] push returned empty manifest digest\n");
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    if (!is_canonical_sha256(manifest_digest->data,
                             manifest_digest->u8_bytes)) {
        fprintf(stderr,
                "  [FAIL] push manifest digest not canonical sha256: "
                "%.*s\n",
                (int)manifest_digest->u8_bytes,
                manifest_digest->data);
        n00b_attest_oci_client_release(client);
        n00b_attest_oci_auth_release(auth);
        exit_code = 1;
        goto teardown;
    }
    printf("  [PASS] push_attestation: manifest_digest=%.*s\n",
           (int)manifest_digest->u8_bytes, manifest_digest->data);

    n00b_attest_oci_client_release(client);
    n00b_attest_oci_auth_release(auth);

    printf("All test_attest_oci_push_smoke tests passed.\n");

teardown:
    zot_fixture_stop(&fx);
    n00b_shutdown();
    return exit_code;
}
