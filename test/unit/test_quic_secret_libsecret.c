/*
 * test_quic_secret_libsecret.c — end-to-end test for the
 * `libsecret:` secret provider.
 *
 * The test seeds an ECDSA-P256 PEM into the running Secret Service
 * daemon, then exercises `n00b_quic_secret_open("libsecret:<label>")`
 * → `n00b_quic_secret_sign` → uECC verification against the public
 * key we derived locally.  Both PKCS#8 and SEC1 PEM containers are
 * covered.
 *
 * If no Secret Service daemon is reachable (no `DBUS_SESSION_BUS_ADDRESS`,
 * no gnome-keyring running) the test exits SKIP without failing — so
 * builds on minimal Linux hosts still pass.  CI runs the test under
 * `dbus-run-session` with `gnome-keyring-daemon` pre-started so the
 * full path is exercised on every commit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uECC.h"
#include <libsecret/secret.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"

/* ----------------------------------------------------------------- */
/* Bytes → standard base64 (RFC 4648).                                */
/* ----------------------------------------------------------------- */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t
b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    size_t op = 0;
    size_t i  = 0;
    for (; i + 3 <= in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16)
                   | ((uint32_t)in[i + 1] << 8)
                   |  (uint32_t)in[i + 2];
        assert(op + 4 <= out_cap);
        out[op++] = B64[(v >> 18) & 0x3f];
        out[op++] = B64[(v >> 12) & 0x3f];
        out[op++] = B64[(v >>  6) & 0x3f];
        out[op++] = B64[ v        & 0x3f];
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        assert(op + 4 <= out_cap);
        out[op++] = B64[(v >> 18) & 0x3f];
        out[op++] = B64[(v >> 12) & 0x3f];
        out[op++] = '=';
        out[op++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        assert(op + 4 <= out_cap);
        out[op++] = B64[(v >> 18) & 0x3f];
        out[op++] = B64[(v >> 12) & 0x3f];
        out[op++] = B64[(v >>  6) & 0x3f];
        out[op++] = '=';
    }
    return op;
}

/* ----------------------------------------------------------------- */
/* DER builders for SEC1 ECPrivateKey and PKCS#8 PrivateKeyInfo.      */
/* Both wrap a 32-byte secp256r1 scalar; we emit the minimum legal    */
/* shape (no optional fields), which the libsecret bridge accepts.    */
/* ----------------------------------------------------------------- */
static const uint8_t OID_EC_PUBLIC_KEY[] = {
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
};
static const uint8_t OID_SECP256R1[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};

static size_t
build_sec1_der(const uint8_t priv[32], uint8_t out[64])
{
    /* SEQUENCE { INTEGER 1, OCTET STRING(32) }. */
    size_t op = 0;
    out[op++] = 0x30;
    out[op++] = 0x25;          /* len = 37 */
    out[op++] = 0x02;
    out[op++] = 0x01;
    out[op++] = 0x01;          /* version 1 */
    out[op++] = 0x04;
    out[op++] = 0x20;          /* len = 32 */
    memcpy(out + op, priv, 32);
    op += 32;
    return op;                 /* 39 bytes */
}

static size_t
build_pkcs8_der(const uint8_t priv[32], uint8_t out[128])
{
    /* Build the SEC1 inner first. */
    uint8_t sec1[64];
    size_t  sec1_len = build_sec1_der(priv, sec1);  /* 39 */

    /* AlgorithmIdentifier ::= SEQUENCE { OID ecPublicKey, OID secp256r1 }. */
    uint8_t alg[32];
    size_t  ap = 0;
    memcpy(alg + ap, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    ap += sizeof(OID_EC_PUBLIC_KEY);
    memcpy(alg + ap, OID_SECP256R1, sizeof(OID_SECP256R1));
    ap += sizeof(OID_SECP256R1);   /* 19 */

    /* Outer PKCS#8 PrivateKeyInfo = SEQUENCE { version=0, alg, octet }. */
    size_t op = 0;
    /* Compute total inner length: 3 (version) + 2+ap (alg) + 2+sec1_len. */
    size_t inner = 3 + 2 + ap + 2 + sec1_len;
    out[op++] = 0x30;
    out[op++] = (uint8_t)inner;    /* short form (inner < 128) */

    out[op++] = 0x02;
    out[op++] = 0x01;
    out[op++] = 0x00;              /* version 0 */

    out[op++] = 0x30;
    out[op++] = (uint8_t)ap;
    memcpy(out + op, alg, ap);
    op += ap;

    out[op++] = 0x04;
    out[op++] = (uint8_t)sec1_len;
    memcpy(out + op, sec1, sec1_len);
    op += sec1_len;
    return op;                     /* 67 bytes */
}

/* PEM-wrap @p der into @p label-tagged base64 lines. */
static char *
pem_wrap(const uint8_t *der, size_t der_len, const char *label)
{
    char   b64[256];
    size_t b64_len = b64_encode(der, der_len, b64, sizeof(b64));

    /* Generous output: header + footer + base64 + line breaks every 64. */
    char *out = malloc(b64_len + 128);
    assert(out);

    size_t off = 0;
    off += (size_t)snprintf(out + off, b64_len + 128 - off,
                            "-----BEGIN %s-----\n", label);
    for (size_t i = 0; i < b64_len; i += 64) {
        size_t n = (b64_len - i < 64) ? b64_len - i : 64;
        memcpy(out + off, b64 + i, n);
        off += n;
        out[off++] = '\n';
    }
    off += (size_t)snprintf(out + off, b64_len + 128 - off,
                            "-----END %s-----\n", label);
    out[off] = '\0';
    return out;
}

/* ----------------------------------------------------------------- */
/* Daemon-availability probe.                                         */
/* ----------------------------------------------------------------- */
static int
secret_service_available(void)
{
    if (!getenv("DBUS_SESSION_BUS_ADDRESS")) {
        return 0;
    }
    GError *gerr = nullptr;
    SecretService *svc = secret_service_get_sync(SECRET_SERVICE_NONE,
                                                  nullptr, &gerr);
    if (gerr) {
        g_error_free(gerr);
        if (svc) g_object_unref(svc);
        return 0;
    }
    if (!svc) return 0;
    g_object_unref(svc);
    return 1;
}

/* ----------------------------------------------------------------- */
/* Sign + verify round-trip.                                          */
/* ----------------------------------------------------------------- */
static void
sign_and_verify(n00b_quic_secret_t *s, const uint8_t pub[64], const char *what)
{
    auto pkr = n00b_quic_secret_pubkey(s, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(pkr));
    n00b_buffer_t *pkb = n00b_result_get(pkr);
    assert(pkb && pkb->byte_len == 64);
    assert(memcmp(pkb->data, pub, 64) == 0);

    n00b_buffer_t data;
    memset(&data, 0, sizeof(data));
    n00b_buffer_init(&data, .raw = (char *)what, .length = (int64_t)strlen(what));

    auto sr = n00b_quic_secret_sign(s, &data, N00B_QUIC_SIG_ECDSA_P256);
    assert(n00b_result_is_ok(sr));
    n00b_buffer_t *sig = n00b_result_get(sr);
    assert(sig && sig->byte_len == 64);

    uint8_t digest[32];
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    n00b_sha256_update(&ctx, (const uint8_t *)what, strlen(what));
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w = words[i];
        digest[i*4]     = (uint8_t)(w >> 24);
        digest[i*4 + 1] = (uint8_t)(w >> 16);
        digest[i*4 + 2] = (uint8_t)(w >> 8);
        digest[i*4 + 3] = (uint8_t)w;
    }

    int ok = uECC_verify(pub, digest, sizeof(digest),
                         (const uint8_t *)sig->data,
                         uECC_secp256r1());
    assert(ok);
}

static void
test_one_format(const char *label_suffix, const char *pem_label,
                size_t (*build_der)(const uint8_t *, uint8_t *))
{
    char label[64];
    snprintf(label, sizeof(label), "n00b-libsecret-test-%s", label_suffix);

    uint8_t priv[32], pub[64];
    int made = 0;
    for (int t = 0; t < 8 && !made; t++) {
        made = uECC_make_key(pub, priv, uECC_secp256r1());
    }
    assert(made);

    uint8_t der_buf[128];
    size_t  der_len = build_der(priv, der_buf);
    char   *pem     = pem_wrap(der_buf, der_len, pem_label);

    /* Store into the transient session collection — it's an
     * in-memory keyring that gnome-keyring-daemon manages without
     * any on-disk state, so headless test runs don't need a
     * pre-existing `login` keyring. */
    GError *gerr = nullptr;
    gboolean ok = secret_password_store_sync(
        SECRET_SCHEMA_COMPAT_NETWORK,
        SECRET_COLLECTION_SESSION,
        label, pem, nullptr, &gerr,
        "user", label, nullptr);
    if (gerr) {
        fprintf(stderr, "secret_password_store_sync: %s\n", gerr->message);
        g_error_free(gerr);
        free(pem);
        abort();
    }
    assert(ok);
    free(pem);

    char uri_cstr[96];
    snprintf(uri_cstr, sizeof(uri_cstr), "libsecret:%s", label);
    n00b_buffer_t *uri = n00b_buffer_from_cstr(uri_cstr);

    auto r = n00b_quic_secret_open(uri);
    assert(n00b_result_is_ok(r));
    n00b_quic_secret_t *s = n00b_result_get(r);
    assert(s);

    sign_and_verify(s, pub, "libsecret-test-message");

    n00b_quic_secret_close(s);

    /* Clean up — best-effort. */
    gerr = nullptr;
    secret_password_clear_sync(SECRET_SCHEMA_COMPAT_NETWORK, nullptr, &gerr,
                               "user", label, nullptr);
    if (gerr) g_error_free(gerr);

    /* Zero out local copies. */
    memset(priv, 0, sizeof(priv));
    memset(pub,  0, sizeof(pub));
    memset(der_buf, 0, sizeof(der_buf));

    printf("  [PASS] libsecret %s round-trip\n", pem_label);
}

static void
test_lookup_missing(void)
{
    n00b_buffer_t *uri = n00b_buffer_from_cstr(
        "libsecret:n00b-libsecret-this-label-should-not-exist-xyz");
    auto r = n00b_quic_secret_open(uri);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_QUIC_ERR_INVALID_ARG);
    printf("  [PASS] libsecret missing label → INVALID_ARG\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    if (!secret_service_available()) {
        printf("  [SKIP] no Secret Service daemon reachable "
               "(set DBUS_SESSION_BUS_ADDRESS and start gnome-keyring)\n");
        n00b_shutdown();
        return 77;  /* meson convention: skip exit code */
    }

    test_lookup_missing();
    test_one_format("sec1",  "EC PRIVATE KEY", build_sec1_der);
    test_one_format("pkcs8", "PRIVATE KEY",    build_pkcs8_der);

    printf("\nlibsecret secret-provider tests: all passed.\n");
    n00b_shutdown();
    return 0;
}
