/*
 * x509_verify.c — X.509 signature verification (WP-042 Phase 3).
 *
 * Verifies a child cert's signature under an issuer's public key. RSA PKCS#1
 * v1.5 (sha256/384/512WithRSA) is wired now via the existing
 * n00b_rsa_verify_pkcs1_v15 primitive; ECDSA (P-256 via uECC; P-384 is a known
 * gap) lands next. Default-deny: any unsupported algorithm or malformed key
 * fails closed.
 *
 * Key/signature/message buffers are n00b_buffer_t; the bytes are bridged to the
 * (uint8_t*,len) crypto primitive at the call site, the same way
 * src/crypto/picotls_certverify.c does.
 */

#include "n00b.h"

#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/quic_types.h" /* N00B_QUIC_OK */
#include "crypto/jwt.h"          /* n00b_jwk_t */
#include "internal/crypto/rsa_pkcs1.h"
#include "internal/crypto/x509_der_tok.h"
#include "crypto/x509.h"

static bool
buf_eq(n00b_buffer_t *a, n00b_buffer_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    n00b_size_t la = n00b_buffer_len(a);
    if (la != n00b_buffer_len(b)) {
        return false;
    }
    if (la == 0) {
        return true;
    }
    n00b_option_t(int64_t) f = n00b_buffer_find(a, b);
    return n00b_option_is_set(f) && n00b_option_get(f) == 0;
}

static n00b_buffer_t *
oid(char *bytes, int64_t len)
{
    return n00b_buffer_from_bytes(bytes, len);
}

/* Drop DER INTEGER leading 0x00 sign/pad bytes (the modulus carries one when
 * its top bit is set), leaving the raw big-endian magnitude. */
static n00b_buffer_t *
strip_leading_zeros(n00b_buffer_t *b)
{
    int64_t n = (int64_t)n00b_buffer_len(b);
    int64_t i = 0;
    while (i < n) {
        n00b_result_t(uint8_t) r = n00b_buffer_get_index(b, i);
        if (!n00b_result_is_ok(r) || n00b_result_get(r) != 0x00) {
            break;
        }
        i++;
    }
    if (i == 0) {
        return b;
    }
    if (i >= n) {
        return n00b_buffer_get_slice(b, n - 1, n); /* all-zero: keep one byte */
    }
    return n00b_buffer_get_slice(b, i, n);
}

/* sha{256,384,512}WithRSAEncryption -> the RS{256,384,512} alg string. */
static const char *
rsa_alg_for_oid(n00b_buffer_t *o)
{
    char rs256[] = {0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x0d, 0x01, 0x01, 0x0b};
    char rs384[] = {0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x0d, 0x01, 0x01, 0x0c};
    char rs512[] = {0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x0d, 0x01, 0x01, 0x0d};
    if (buf_eq(o, oid(rs256, 9))) {
        return "RS256";
    }
    if (buf_eq(o, oid(rs384, 9))) {
        return "RS384";
    }
    if (buf_eq(o, oid(rs512, 9))) {
        return "RS512";
    }
    return NULL;
}

/* Extract RSA (modulus, exponent) content buffers from a SubjectPublicKeyInfo
 * subjectPublicKey BIT STRING content (byte 0 = unused bits, then RSAPublicKey
 * ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }). */
static bool
rsa_pub_from_spki(n00b_buffer_t *spki_key, n00b_buffer_t **n_out,
                  n00b_buffer_t **e_out)
{
    if (spki_key == NULL || n00b_buffer_len(spki_key) < 2) {
        return false;
    }
    n00b_buffer_t *rsapub = n00b_buffer_get_slice(spki_key, 1,
                                                  (int64_t)n00b_buffer_len(spki_key));
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(rsapub, NULL);
    if (r.error != NULL || r.tokens == NULL) {
        return false;
    }
    int ints = 0;
    for (int i = 0; i < r.count; i++) {
        n00b_der_value_t *v = (n00b_der_value_t *)r.tokens[i]->user_info;
        if (v == NULL || v->constructed || v->tag_class != 0
            || v->tag_number != 2 || v->content == NULL) {
            continue; /* only universal-class INTEGERs */
        }
        if (ints == 0) {
            *n_out = v->content;
        }
        else if (ints == 1) {
            *e_out = v->content;
        }
        ints++;
    }
    return (*n_out != NULL && *e_out != NULL);
}

bool
n00b_x509_verify_signature(const n00b_x509_cert_t *child,
                           const n00b_x509_cert_t *issuer)
{
    if (child == NULL || issuer == NULL || child->tbs == NULL
        || child->signature == NULL) {
        return false;
    }

    const char *alg = rsa_alg_for_oid(child->sig_alg_oid);
    if (alg == NULL) {
        return false; /* ECDSA / unsupported — fail closed for now */
    }

    n00b_buffer_t *rsa_n = NULL;
    n00b_buffer_t *rsa_e = NULL;
    if (!rsa_pub_from_spki(issuer->spki_key, &rsa_n, &rsa_e)) {
        return false;
    }

    /* signatureValue BIT STRING: byte 0 = unused bits, rest = signature. */
    if (n00b_buffer_len(child->signature) < 2) {
        return false;
    }
    n00b_buffer_t *sig = n00b_buffer_get_slice(
        child->signature, 1, (int64_t)n00b_buffer_len(child->signature));

    rsa_n = strip_leading_zeros(rsa_n);
    rsa_e = strip_leading_zeros(rsa_e);

    n00b_jwk_t jwk = {
        .kty       = "RSA",
        .rsa_n     = (uint8_t *)rsa_n->data,
        .rsa_n_len = (size_t)rsa_n->byte_len,
        .rsa_e     = (uint8_t *)rsa_e->data,
        .rsa_e_len = (size_t)rsa_e->byte_len,
    };

    int rc = n00b_rsa_verify_pkcs1_v15(&jwk, alg,
                                       (uint8_t *)child->tbs->data,
                                       (size_t)child->tbs->byte_len,
                                       (uint8_t *)sig->data,
                                       (size_t)sig->byte_len);
    return rc == N00B_QUIC_OK;
}
