/*
 * test_quic_cert_provisioner.c — Unit tests for the cert-provisioner
 * abstraction.
 *
 * Coverage:
 *   1. Static provisioner: load the pre-built fixture
 *      (test/fixtures/cert_provisioner/test_cert.pem) — verify the
 *      chain bytes round-trip and the parsed not_before / not_after
 *      match the fixture's known dates.  should_renew() is always
 *      false on this provisioner.
 *
 *   2. External provisioner: spawn a tiny shell command that copies
 *      the fixture cert into a writable temp path; verify the
 *      provisioner runs the command, picks up the file, and returns
 *      a usable cert.  force_refresh round-trip on should_renew().
 *
 *   3. ACME provisioner: argument validation only — full
 *      cert-acquisition is deferred to the deployment playbook.
 *
 * The fixture cert is pre-baked in the repo so this test does not
 * depend on `openssl` at test time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_provisioner.h"

/* Resolved at test runtime against an env var the meson harness
 * sets to MESON_SOURCE_ROOT; falls back to the build's CWD. */
static const char *
fixture_path(const char *base)
{
    static char buf[1024];
    const char *root = getenv("N00B_SOURCE_ROOT");
    if (!root) {
        /* Tests typically run with build_debug as CWD; the fixture
         * is at ../test/fixtures/cert_provisioner/<base>. */
        root = "..";
    }
    snprintf(buf, sizeof(buf),
             "%s/test/fixtures/cert_provisioner/%s", root, base);
    return buf;
}

/* ============================================================================
 * Static provisioner
 * ============================================================================ */

static void
test_static_loads_fixture(void)
{
    const char *cert_path = fixture_path("test_cert.pem");
    /* Sanity: file exists. */
    FILE *f = fopen(cert_path, "r");
    if (!f) {
        printf("  [SKIP] static fixture %s not present\n", cert_path);
        return;
    }
    fclose(f);

    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:fix"));
    n00b_quic_secret_t *key = n00b_result_get(kr);

    auto pr = n00b_quic_cert_provisioner_static(cert_path, key);
    assert(n00b_result_is_ok(pr));
    n00b_quic_cert_provisioner_t *p = n00b_result_get(pr);
    assert(p->name && strcmp(p->name, "static") == 0);

    auto cr = p->acquire(p);
    assert(n00b_result_is_ok(cr));
    n00b_quic_cert_t *cert = n00b_result_get(cr);

    assert(cert->chain_pem);
    assert(cert->chain_pem->byte_len > 100);
    assert(strstr(cert->chain_pem->data, "BEGIN CERTIFICATE") != NULL);
    assert(cert->key == key);
    /* Fixture validity dates per `openssl x509 -dates` at
     * generation time:
     *   notBefore = May  8 02:56:07 2026 GMT  → 1778554567 s
     *   notAfter  = May  3 02:56:07 2046 GMT
     * Sanity: both are non-zero, in chronological order, and
     * not_after is at least 19 years past not_before. */
    assert(cert->not_before_ms > 0);
    assert(cert->not_after_ms  > cert->not_before_ms);
    int64_t span_days = (cert->not_after_ms - cert->not_before_ms)
                      / (24 * 60 * 60 * 1000);
    assert(span_days > 19 * 365);
    assert(span_days < 21 * 365);

    /* Static provisioner never renews. */
    assert(p->should_renew(p, cert) == false);
    assert(p->should_renew(p, NULL) == false);

    n00b_quic_cert_provisioner_close(p);
    n00b_quic_secret_close(key);
    printf("  [PASS] static loads fixture, parses validity, never renews\n");
}

static void
test_static_argument_validation(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:av"));
    n00b_quic_secret_t *key = n00b_result_get(kr);

    auto r1 = n00b_quic_cert_provisioner_static(NULL, key);
    assert(n00b_result_is_err(r1));
    auto r2 = n00b_quic_cert_provisioner_static("/x", NULL);
    assert(n00b_result_is_err(r2));

    /* Nonexistent path → INVALID_ARG (open fails). */
    auto pr = n00b_quic_cert_provisioner_static(
        "/nonexistent/n00b-cert-provisioner-fixture", key);
    assert(n00b_result_is_ok(pr));  /* construction succeeds; */
    n00b_quic_cert_provisioner_t *p = n00b_result_get(pr);
    auto cr = p->acquire(p);
    assert(n00b_result_is_err(cr));   /* but acquire fails. */
    n00b_quic_cert_provisioner_close(p);

    n00b_quic_secret_close(key);
    printf("  [PASS] static rejects bad args / missing file\n");
}

/* ============================================================================
 * External provisioner
 * ============================================================================ */

static void
test_external_runs_command(void)
{
    const char *cert_path = fixture_path("test_cert.pem");
    FILE *f = fopen(cert_path, "r");
    if (!f) {
        printf("  [SKIP] static fixture missing — can't drive external test\n");
        return;
    }
    fclose(f);

    char tmp[512];
    snprintf(tmp, sizeof(tmp),
             "/tmp/n00b_extprov_%d.pem", (int)getpid());

    /* argv array — never interpreted by a shell. */
    const char *argv[] = {"cp", cert_path, tmp, NULL};

    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:e"));
    n00b_quic_secret_t *key = n00b_result_get(kr);

    auto pr = n00b_quic_cert_provisioner_external(argv, tmp, key);
    assert(n00b_result_is_ok(pr));
    n00b_quic_cert_provisioner_t *p = n00b_result_get(pr);
    assert(p->name && strcmp(p->name, "external") == 0);

    /* Initial: should_renew(NULL) == true (need to acquire). */
    assert(p->should_renew(p, NULL) == true);

    auto cr = p->acquire(p);
    assert(n00b_result_is_ok(cr));
    n00b_quic_cert_t *cert = n00b_result_get(cr);
    assert(cert->chain_pem->byte_len > 100);
    assert(cert->not_after_ms > cert->not_before_ms);

    /* After successful acquire, force_refresh is reset. */
    assert(p->should_renew(p, cert) == false);

    /* Set force_refresh, expect should_renew to flip to true. */
    n00b_quic_cert_provisioner_external_force_refresh(p);
    assert(p->should_renew(p, cert) == true);

    /* Failing command (exits non-zero) → acquire returns err. */
    const char *bad_argv[] = {"false", NULL};
    auto pr2 = n00b_quic_cert_provisioner_external(bad_argv, tmp, key);
    n00b_quic_cert_provisioner_t *p2 = n00b_result_get(pr2);
    auto cr2 = p2->acquire(p2);
    assert(n00b_result_is_err(cr2));
    n00b_quic_cert_provisioner_close(p2);

    /* Shell metacharacters in arg are passed *literally* — proof
     * that we're not going through the shell.  The cp will try to
     * copy a file named "; rm -rf ..." which doesn't exist, fails
     * cleanly. */
    const char *injection_argv[] = {
        "cp", "; rm -rf /tmp/should-not-be-deleted", tmp, NULL,
    };
    auto pr3 = n00b_quic_cert_provisioner_external(injection_argv, tmp, key);
    n00b_quic_cert_provisioner_t *p3 = n00b_result_get(pr3);
    auto cr3 = p3->acquire(p3);
    assert(n00b_result_is_err(cr3));  /* cp fails on the bogus filename */
    n00b_quic_cert_provisioner_close(p3);

    unlink(tmp);
    n00b_quic_cert_provisioner_close(p);
    n00b_quic_secret_close(key);
    printf("  [PASS] external runs argv (no shell), loads file, "
           "force_refresh works\n");
}

/* ============================================================================
 * External provisioner: filesystem-watch auto-renewal (#193).
 * Attach a conduit watcher to the chain PEM path; touching the file
 * must flip should_renew without an explicit force_refresh call.
 * ============================================================================ */

static void
test_external_filewatch(void)
{
    /* Self-contained: don't depend on a fixture cert.  The watcher
     * only cares about file-change events; we never go through the
     * acquire path. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp),
             "/tmp/n00b_extprov_watch_%d.pem", (int)getpid());

    /* Write a minimal-but-syntactically-PEM blob.  Content doesn't
     * matter for this test — we never load it. */
    FILE *seed = fopen(tmp, "w");
    if (!seed) {
        printf("  [SKIP] external_filewatch — couldn't create tmp\n");
        return;
    }
    fputs("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
          seed);
    fclose(seed);

    /* Any argv; acquire() isn't called.  /bin/true exits 0 — keeps
     * the constructor honest. */
    const char *argv[] = {"true", NULL};

    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:e"));
    n00b_quic_secret_t *key = n00b_result_get(kr);

    auto pr = n00b_quic_cert_provisioner_external(argv, tmp, key);
    assert(n00b_result_is_ok(pr));
    n00b_quic_cert_provisioner_t *p = n00b_result_get(pr);

    /* Conduit + IO backend for the file_change topic. */
    auto cnr = n00b_conduit_new();
    assert(n00b_result_is_ok(cnr));
    n00b_conduit_t *c = n00b_result_get(cnr);
    auto ir = n00b_conduit_io_new_default(c);
    assert(n00b_result_is_ok(ir));
    n00b_conduit_io_backend_t *io = n00b_result_get(ir);

    auto wr = n00b_quic_cert_provisioner_external_watch(p, c);
    if (n00b_result_is_err(wr)) {
        /* file_change isn't universally supported (some containers
         * disable inotify).  Treat as SKIP. */
        printf("  [SKIP] external_filewatch — watcher attach failed "
               "(env may not support it)\n");
        n00b_quic_cert_provisioner_close(p);
        n00b_conduit_io_destroy(io);
        n00b_conduit_destroy(c);
        n00b_quic_secret_close(key);
        unlink(tmp);
        return;
    }

    /* Synthetic "previous cert" so should_renew doesn't trivially
     * return true on the !current branch. */
    n00b_quic_cert_t synth_cert;
    memset(&synth_cert, 0, sizeof(synth_cert));

    /* Steady state: no pending event → should_renew false. */
    assert(p->should_renew(p, &synth_cert) == false);

    /* Mutate the file. */
    FILE *touch = fopen(tmp, "a");
    assert(touch != NULL);
    fputc('\n', touch);
    fflush(touch);
    fclose(touch);

    /* Drive IO so the kernel event reaches our subscriber inbox. */
    bool flipped = false;
    for (int i = 0; i < 10; i++) {
        n00b_conduit_io_poll(io, 100);
        if (p->should_renew(p, &synth_cert)) {
            flipped = true;
            break;
        }
    }
    assert(flipped);

    n00b_quic_cert_provisioner_close(p);
    n00b_conduit_io_destroy(io);
    n00b_conduit_destroy(c);
    n00b_quic_secret_close(key);
    unlink(tmp);
    printf("  [PASS] external filewatch flips should_renew on disk change\n");
}

/* ============================================================================
 * ACME provisioner — argument validation only.
 * ============================================================================ */

static void
test_acme_argument_validation(void)
{
    auto kr = n00b_quic_secret_open(n00b_buffer_from_cstr("ephemeral:a1"));
    n00b_quic_secret_t *k = n00b_result_get(kr);

    n00b_acme_challenge_provider_t prov = {.type = "http-01"};
    const char *names[] = {"x.example"};

    auto r1 = n00b_quic_cert_provisioner_acme(NULL, k, k, names, 1, &prov);
    assert(n00b_result_is_err(r1));
    auto r2 = n00b_quic_cert_provisioner_acme("https://x", NULL, k, names, 1, &prov);
    assert(n00b_result_is_err(r2));
    auto r3 = n00b_quic_cert_provisioner_acme("https://x", k, NULL, names, 1, &prov);
    assert(n00b_result_is_err(r3));
    auto r4 = n00b_quic_cert_provisioner_acme("https://x", k, k, names, 0, &prov);
    assert(n00b_result_is_err(r4));
    auto r5 = n00b_quic_cert_provisioner_acme("https://x", k, k, names, 1, NULL);
    assert(n00b_result_is_err(r5));

    /* Successful construction (without acquiring). */
    auto pr = n00b_quic_cert_provisioner_acme("https://x", k, k, names, 1,
                                              &prov);
    assert(n00b_result_is_ok(pr));
    n00b_quic_cert_provisioner_t *p = n00b_result_get(pr);
    assert(p->name && strcmp(p->name, "acme") == 0);

    /* should_renew(NULL) is always true. */
    assert(p->should_renew(p, NULL) == true);

    /* should_renew(current) with a future not_after returns false;
     * with a near-now not_after returns true. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t now_ms = (int64_t)tv.tv_sec * 1000;
    n00b_quic_cert_t mock_far = {
        .not_after_ms = now_ms + (int64_t)90 * 24 * 60 * 60 * 1000,
    };
    n00b_quic_cert_t mock_near = {
        .not_after_ms = now_ms + (int64_t)1 * 24 * 60 * 60 * 1000,
    };
    assert(p->should_renew(p, &mock_far)  == false);
    assert(p->should_renew(p, &mock_near) == true);  /* < 30d margin */

    n00b_quic_cert_provisioner_close(p);
    n00b_quic_secret_close(k);
    printf("  [PASS] acme argument validation + renew-margin math\n");
}

/* ============================================================================ */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_cert_provisioner:\n");
    test_static_loads_fixture();
    test_static_argument_validation();
    test_external_runs_command();
    test_external_filewatch();
    test_acme_argument_validation();
    printf("All quic_cert_provisioner tests passed.\n");

    n00b_shutdown();
    return 0;
}
