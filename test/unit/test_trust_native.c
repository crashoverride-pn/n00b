/*
 * test_trust_native.c — native (libc-free) trust backend (WP-042 Phase 4).
 *
 * Drives n00b_quic_trust_verify() through the "native" backend, which uses the
 * in-tree X.509 verifier instead of SecTrust. Exercises:
 *   1. default anchors (full system root bundle) accept the real GTS WE1->R4
 *      chain (GTS Root R4 is among the shipped roots).
 *   2. replace-anchors (just GTS Root R4) accept the same chain.
 *   3. an untrusted leaf is rejected (anchor not present).
 *   4. exact-cert pin: a self-signed cert as its own anchor is accepted even
 *      though it is not a CA (the "self-signed endpoint" case).
 *
 * Needs workdir: meson.project_source_root() for the relative PEM + grammar
 * + CA-bundle paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "crypto/trust.h"

static const char k_we1_path[]    = "test/unit/data/x509_gts_we1.pem";
static const char k_root_path[]   = "test/unit/data/x509_gts_root_r4.pem";
static const char k_selfsig_path[] = "test/unit/data/pkcs7_fixture_cert.pem";

/* Whole-file bytes -> n00b_buffer (PEM, fed to the *_anchors constructor). */
static n00b_buffer_t *
read_pem_buffer(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "open %s failed (run from src root)\n", path);
        assert(0);
    }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)n);
    size_t got = fread(buf, 1, (size_t)n, fp);
    fclose(fp);
    assert(got == (size_t)n);
    n00b_buffer_t *b = n00b_buffer_from_bytes(buf, (int64_t)n);
    free(buf);
    return b;
}

/* First cert in a PEM file -> DER iovec. */
static ptls_iovec_t
load_der(const char *path)
{
    ptls_iovec_t vec = {0};
    size_t       cnt = 0;
    int rc = ptls_load_pem_objects(path, "CERTIFICATE", &vec, 1, &cnt);
    if (rc != 0 || cnt == 0) {
        fprintf(stderr, "ptls_load_pem_objects(%s) rc=%d n=%zu\n", path, rc, cnt);
        assert(0);
    }
    return vec;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    ptls_iovec_t we1 = load_der(k_we1_path);
    ptls_iovec_t self = load_der(k_selfsig_path);

    const uint8_t *we1_chain[1]   = {we1.base};
    size_t         we1_lens[1]    = {we1.len};
    const uint8_t *self_chain[1]  = {self.base};
    size_t         self_lens[1]   = {self.len};

    /* 1. default anchors (the shipped GTS R1-R4 bundle) accept WE1 -> R4. */
    {
        n00b_result_t(n00b_quic_trust_t *) tr = n00b_quic_trust_native();
        assert(n00b_result_is_ok(tr));
        n00b_quic_trust_t *trust = n00b_result_get(tr);

        n00b_result_t(bool) vr =
            n00b_quic_trust_verify(trust, we1_chain, we1_lens, 1, nullptr);
        assert(n00b_result_is_ok(vr) && n00b_result_get(vr));
        n00b_quic_trust_close(trust);
        fprintf(stderr, "[trust-native] default GTS bundle accepts WE1->R4 — OK\n");
    }

    /* 2. replace anchors with just GTS Root R4; same chain validates. */
    {
        n00b_buffer_t *root_pem = read_pem_buffer(k_root_path);
        n00b_result_t(n00b_quic_trust_t *) tr =
            n00b_quic_trust_native_anchors(root_pem);
        assert(n00b_result_is_ok(tr));
        n00b_quic_trust_t *trust = n00b_result_get(tr);

        n00b_result_t(bool) vr =
            n00b_quic_trust_verify(trust, we1_chain, we1_lens, 1, nullptr);
        assert(n00b_result_is_ok(vr) && n00b_result_get(vr));
        n00b_quic_trust_close(trust);
        fprintf(stderr, "[trust-native] replace-anchors (R4 only) accepts WE1 — OK\n");
    }

    /* 3. an unrelated leaf is rejected when its issuer is not an anchor. */
    {
        n00b_buffer_t *root_pem = read_pem_buffer(k_root_path);
        n00b_result_t(n00b_quic_trust_t *) tr =
            n00b_quic_trust_native_anchors(root_pem);
        assert(n00b_result_is_ok(tr));
        n00b_quic_trust_t *trust = n00b_result_get(tr);

        n00b_result_t(bool) vr =
            n00b_quic_trust_verify(trust, self_chain, self_lens, 1, nullptr);
        assert(n00b_result_is_err(vr)); /* self-signed, not chaining to R4 */
        n00b_quic_trust_close(trust);
        fprintf(stderr, "[trust-native] untrusted leaf rejected — OK\n");
    }

    /* 4. exact-cert pin: self-signed cert as its own anchor is accepted. */
    {
        n00b_buffer_t *self_pem = read_pem_buffer(k_selfsig_path);
        n00b_result_t(n00b_quic_trust_t *) tr =
            n00b_quic_trust_native_anchors(self_pem);
        assert(n00b_result_is_ok(tr));
        n00b_quic_trust_t *trust = n00b_result_get(tr);

        n00b_result_t(bool) vr =
            n00b_quic_trust_verify(trust, self_chain, self_lens, 1, nullptr);
        assert(n00b_result_is_ok(vr) && n00b_result_get(vr));
        n00b_quic_trust_close(trust);
        fprintf(stderr, "[trust-native] self-signed exact-cert pin accepted — OK\n");
    }

    fprintf(stderr, "[trust-native] all native trust tests passed\n");
    return 0;
}
