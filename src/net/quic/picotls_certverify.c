/*
 * picotls_certverify.c — CertificateVerify (TLS 1.3 § 4.4.3) signature
 * verification adapter for picotls.
 *
 * Why this file exists:
 *
 *   picotls's `verify_certificate` callback has TWO outputs that the
 *   chain verifier must populate:
 *     - `*verify_sign`: function pointer picotls calls during
 *       CertificateVerify processing.
 *     - `*verify_data`: opaque per-handshake context.
 *
 *   If we leave them unset (which the old verify_cb did via
 *   `(void)verify_sign; (void)verify_data;`), picotls's
 *   `handle_certificate_verify` (lib/picotls.c:3453-3458) takes the
 *   `cb == NULL → ret = 0` branch and silently accepts any
 *   signature.  That's a complete MITM defeat: an attacker with a
 *   chain-valid cert (any chain, not necessarily for the host they're
 *   impersonating) can sign CertificateVerify with the wrong private
 *   key and we'd accept.
 *
 *   This file fixes that by:
 *     - Walking the leaf cert (DER) to extract its
 *       SubjectPublicKeyInfo (algorithm + pubkey bytes).
 *     - Stashing the extracted key in a per-handshake `verify_ctx_t`.
 *     - Installing a `verify_sign` callback that uses the extracted
 *       key to verify the peer's CertificateVerify signature against
 *       the handshake transcript.
 *
 * Supported algorithms (must match `n00b_picotls_supported_sig_algs`):
 *   - ECDSA P-256 SHA-256 (uECC + n00b_sha256)
 *   - RSA-PKCS1 SHA-256 (only valid for cert-chain validation in
 *     TLS 1.3; never selected for handshake CertificateVerify, but
 *     left in the offered list for chain verification)
 *   - RSA-PSS SHA-256 / SHA-384 (rsa_pss_rsae_sha256/384; the
 *     mandatory TLS 1.3 RSA handshake sig — SHA-384 only when we
 *     vendor it; today only SHA-256)
 *
 * Anything else: fail closed.
 */

#define N00B_USE_INTERNAL_API
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "picotls.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/jwt.h"  /* n00b_jwk_t for n00b_rsa_verify_pkcs1_v15 */
#include "net/quic/secret.h"
#include "internal/crypto/rsa_pkcs1.h"
#include "internal/net/quic/picotls_certverify.h"

#include "uECC.h"

/* ===========================================================================
 * §1   Minimal ASN.1 / DER walker
 *
 * Enough to locate the SubjectPublicKeyInfo inside a TLS 1.3 leaf
 * cert.  Not a general-purpose X.509 parser — we don't need extensions,
 * issuer chains, or validity dates (the trust verifier handles those).
 *
 * X.509 cert layout (RFC 5280 § 4.1):
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate       TBSCertificate,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING }
 *   TBSCertificate ::= SEQUENCE {
 *     [0] EXPLICIT Version DEFAULT v1,
 *     serialNumber         CertificateSerialNumber,
 *     signature            AlgorithmIdentifier,
 *     issuer               Name,
 *     validity             Validity,
 *     subject              Name,
 *     subjectPublicKeyInfo SubjectPublicKeyInfo,
 *     ... }
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm            AlgorithmIdentifier,
 *     subjectPublicKey     BIT STRING }
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm            OBJECT IDENTIFIER,
 *     parameters           ANY DEFINED BY algorithm OPTIONAL }
 * =========================================================================== */

/* Read a TLV header: tag + length, return pointer to value bytes and
 * write the value length to *vlen.  Returns NULL on malformed DER. */
static const uint8_t *
asn1_header(const uint8_t *p, const uint8_t *end,
            uint8_t *tag_out, size_t *vlen)
{
    if (p >= end) return nullptr;
    *tag_out = *p++;
    if (p >= end) return nullptr;
    uint8_t b = *p++;
    if (b < 0x80) {
        *vlen = b;
    } else {
        size_t nb = b & 0x7f;
        if (nb == 0 || nb > 4) return nullptr;   /* indefinite/oversize */
        if (p + nb > end) return nullptr;
        size_t v = 0;
        for (size_t i = 0; i < nb; i++) v = (v << 8) | *p++;
        *vlen = v;
    }
    if (p + *vlen > end) return nullptr;
    return p;
}

/* Descend into a SEQUENCE: returns pointer to first child, sets *child_end. */
static const uint8_t *
asn1_into_seq(const uint8_t *p, const uint8_t *end,
              const uint8_t **child_end)
{
    uint8_t tag;
    size_t  vlen;
    const uint8_t *v = asn1_header(p, end, &tag, &vlen);
    if (!v || tag != 0x30) return nullptr;
    *child_end = v + vlen;
    return v;
}

/* Skip the current TLV.  Returns pointer past it, or NULL on bad DER. */
static const uint8_t *
asn1_skip(const uint8_t *p, const uint8_t *end)
{
    uint8_t tag;
    size_t  vlen;
    const uint8_t *v = asn1_header(p, end, &tag, &vlen);
    if (!v) return nullptr;
    return v + vlen;
}

/* Compare an OID's value bytes (already inside the OID TLV) to a
 * canonical encoding.  `lit` must be a byte-array (no trailing NUL);
 * the compiler computes its length via `sizeof`. */
#define OID_EQ(p, len, lit) \
    ((len) == sizeof(lit) && memcmp((p), (lit), sizeof(lit)) == 0)

/* OID encodings (DER content bytes, NOT including tag+length): */
static const uint8_t OID_EC_PUBKEY[]  = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t OID_RSA_ENC[]    = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const uint8_t OID_P256[]       = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

/* ===========================================================================
 * §2   SubjectPublicKeyInfo extraction
 *
 * Output kinds:
 *   - SPKI_EC_P256: uncompressed point in `ec_pub` (64 bytes, X||Y).
 *   - SPKI_RSA:     modulus in `rsa_n` / `rsa_n_len`, exponent in
 *                   `rsa_e` / `rsa_e_len`.  All bignum bytes are
 *                   conduit-pool-allocated copies.
 *
 * Anything else (Ed25519, P-384 today, etc.) → unsupported.
 * =========================================================================== */

typedef enum {
    SPKI_NONE     = 0,
    SPKI_EC_P256  = 1,
    SPKI_RSA      = 2,
} spki_kind_t;

typedef struct {
    spki_kind_t  kind;
    uint8_t      ec_pub[64];   /* X || Y for SPKI_EC_P256 */
    const uint8_t *rsa_n;      /* borrowed into pool storage */
    size_t        rsa_n_len;
    const uint8_t *rsa_e;
    size_t        rsa_e_len;
} spki_t;

static int
parse_spki(const uint8_t *der, size_t der_len, spki_t *out)
{
    memset(out, 0, sizeof(*out));
    const uint8_t *end = der + der_len;
    const uint8_t *cert_end;
    const uint8_t *p = asn1_into_seq(der, end, &cert_end);
    if (!p) return -1;
    /* Inside Certificate → first child is tbsCertificate. */
    const uint8_t *tbs_end;
    p = asn1_into_seq(p, cert_end, &tbs_end);
    if (!p) return -1;
    /* Inside TBSCertificate: optional [0] version, then serial, sig
     * algo, issuer, validity, subject, SPKI, ... */
    /* Skip the optional [0] EXPLICIT version (tag 0xa0). */
    if (p < tbs_end && *p == 0xa0) {
        p = asn1_skip(p, tbs_end);
        if (!p) return -1;
    }
    /* serialNumber INTEGER */
    p = asn1_skip(p, tbs_end); if (!p) return -1;
    /* signature AlgorithmIdentifier */
    p = asn1_skip(p, tbs_end); if (!p) return -1;
    /* issuer Name */
    p = asn1_skip(p, tbs_end); if (!p) return -1;
    /* validity */
    p = asn1_skip(p, tbs_end); if (!p) return -1;
    /* subject Name */
    p = asn1_skip(p, tbs_end); if (!p) return -1;
    /* subjectPublicKeyInfo SEQUENCE { algo, subjectPublicKey } */
    const uint8_t *spki_end;
    p = asn1_into_seq(p, tbs_end, &spki_end);
    if (!p) return -1;

    /* AlgorithmIdentifier SEQUENCE { OID, parameters } */
    const uint8_t *algo_end;
    const uint8_t *aip = asn1_into_seq(p, spki_end, &algo_end);
    if (!aip) return -1;

    /* OID */
    uint8_t tag;
    size_t  vlen;
    const uint8_t *oid_v = asn1_header(aip, algo_end, &tag, &vlen);
    if (!oid_v || tag != 0x06) return -1;
    const uint8_t *oid_bytes = oid_v;
    size_t         oid_len   = vlen;
    const uint8_t *params    = oid_v + vlen;  /* may be empty/NULL or OID for curve */

    /* subjectPublicKey BIT STRING.  First content byte is the unused-bits
     * count (0 for our use cases); the rest is the key. */
    const uint8_t *bs_v = asn1_header(algo_end, spki_end, &tag, &vlen);
    if (!bs_v || tag != 0x03 || vlen < 1) return -1;
    const uint8_t *bs_unused = bs_v;
    if (*bs_unused != 0x00) return -1;
    const uint8_t *bs_body = bs_v + 1;
    size_t         bs_len  = vlen - 1;

    if (OID_EQ(oid_bytes, oid_len, OID_EC_PUBKEY)) {
        /* Parameters MUST be the named-curve OID. */
        const uint8_t *param_oid_v = asn1_header(params, algo_end, &tag, &vlen);
        if (!param_oid_v || tag != 0x06) return -1;
        if (!OID_EQ(param_oid_v, vlen, OID_P256)) {
            /* P-384 / P-521: unsupported in v1. */
            return -1;
        }
        /* Uncompressed point: 0x04 || X (32) || Y (32). */
        if (bs_len != 65 || bs_body[0] != 0x04) return -1;
        out->kind = SPKI_EC_P256;
        memcpy(out->ec_pub, bs_body + 1, 64);
        return 0;
    }
    if (OID_EQ(oid_bytes, oid_len, OID_RSA_ENC)) {
        /* RSA SubjectPublicKey body = SEQUENCE { n INTEGER, e INTEGER }. */
        const uint8_t *rsa_end;
        const uint8_t *rp = asn1_into_seq(bs_body, bs_body + bs_len, &rsa_end);
        if (!rp) return -1;
        /* n */
        const uint8_t *n_v = asn1_header(rp, rsa_end, &tag, &vlen);
        if (!n_v || tag != 0x02 || vlen == 0) return -1;
        /* Strip leading 0x00 padding byte (ASN.1 INTEGER sign bit). */
        if (vlen > 1 && n_v[0] == 0x00) { n_v++; vlen--; }
        out->rsa_n     = n_v;
        out->rsa_n_len = vlen;
        rp = n_v + vlen;
        /* e */
        const uint8_t *e_v = asn1_header(rp, rsa_end, &tag, &vlen);
        if (!e_v || tag != 0x02 || vlen == 0) return -1;
        if (vlen > 1 && e_v[0] == 0x00) { e_v++; vlen--; }
        out->rsa_e     = e_v;
        out->rsa_e_len = vlen;
        out->kind = SPKI_RSA;
        return 0;
    }
    return -1;
}

/* ===========================================================================
 * §3   verify_sign callback
 *
 * picotls invokes this with the handshake transcript signing input
 * (signdata) and the peer's signature (sig).  We dispatch to the
 * algorithm appropriate for the cert's pubkey kind.
 * =========================================================================== */

typedef struct {
    spki_t key;
} verify_ctx_t;

/* Decode a DER ECDSA-SEQUENCE signature into a raw 64-byte r||s. */
static int
ecdsa_der_to_raw(const uint8_t *sig, size_t sig_len, uint8_t raw[64])
{
    const uint8_t *end = sig + sig_len;
    const uint8_t *seq_end;
    const uint8_t *p = asn1_into_seq(sig, end, &seq_end);
    if (!p) return -1;
    /* r INTEGER */
    uint8_t tag; size_t vlen;
    const uint8_t *r_v = asn1_header(p, seq_end, &tag, &vlen);
    if (!r_v || tag != 0x02 || vlen == 0) return -1;
    if (vlen > 1 && r_v[0] == 0x00) { r_v++; vlen--; }
    if (vlen > 32) return -1;
    memset(raw, 0, 32);
    memcpy(raw + (32 - vlen), r_v, vlen);
    p = r_v + vlen;
    /* s INTEGER */
    const uint8_t *s_v = asn1_header(p, seq_end, &tag, &vlen);
    if (!s_v || tag != 0x02 || vlen == 0) return -1;
    if (vlen > 1 && s_v[0] == 0x00) { s_v++; vlen--; }
    if (vlen > 32) return -1;
    memset(raw + 32, 0, 32);
    memcpy(raw + 32 + (32 - vlen), s_v, vlen);
    return 0;
}

static int
verify_sign_cb(void *data, uint16_t algo,
               ptls_iovec_t signdata, ptls_iovec_t signature)
{
    verify_ctx_t *ctx = (verify_ctx_t *)data;
    /* picotls calls us with empty buffers on cleanup — accept that
     * as a no-op success.  See picotls.c:5527-5528. */
    if (signdata.base == NULL && signature.base == NULL) {
        return 0;
    }
    if (!ctx) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    switch (algo) {
    case PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256: {
        if (ctx->key.kind != SPKI_EC_P256) {
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        }
        /* picotls hands us a DER-SEQUENCE ECDSA signature; convert to
         * raw r||s for uECC. */
        uint8_t raw[64];
        if (ecdsa_der_to_raw(signature.base, signature.len, raw) != 0) {
            return PTLS_ALERT_DECRYPT_ERROR;
        }
        /* SHA-256 over signdata. */
        uint8_t digest[32];
        {
            n00b_sha256_digest_t words;
            n00b_sha256_hash(signdata.base, signdata.len, words);
            for (int i = 0; i < 8; i++) {
                uint32_t w = words[i];
                digest[i*4]     = (uint8_t)(w >> 24);
                digest[i*4 + 1] = (uint8_t)(w >> 16);
                digest[i*4 + 2] = (uint8_t)(w >> 8);
                digest[i*4 + 3] = (uint8_t)w;
            }
        }
        if (!uECC_verify(ctx->key.ec_pub, digest, 32, raw, uECC_secp256r1())) {
            return PTLS_ALERT_DECRYPT_ERROR;
        }
        return 0;
    }
    case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256: {
        if (ctx->key.kind != SPKI_RSA) {
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        }
        int rc = n00b_rsa_verify_pss_sha256(ctx->key.rsa_n, ctx->key.rsa_n_len,
                                            ctx->key.rsa_e, ctx->key.rsa_e_len,
                                            signdata.base, signdata.len,
                                            signature.base, signature.len);
        return (rc == N00B_QUIC_OK) ? 0 : PTLS_ALERT_DECRYPT_ERROR;
    }
    case PTLS_SIGNATURE_RSA_PKCS1_SHA256: {
        /* RFC 8446 § 4.2.3: PKCS1 sigs are forbidden in
         * CertificateVerify; their presence in the offered list is for
         * cert-chain validation only.  A spec-conforming TLS 1.3
         * server never selects this for the handshake sig, but if one
         * does, validate it — better than blanket-accept. */
        if (ctx->key.kind != SPKI_RSA) {
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        }
        n00b_jwk_t jwk = {
            .kty       = "RSA",
            .rsa_n     = (uint8_t *)ctx->key.rsa_n,
            .rsa_n_len = ctx->key.rsa_n_len,
            .rsa_e     = (uint8_t *)ctx->key.rsa_e,
            .rsa_e_len = ctx->key.rsa_e_len,
        };
        int rc = n00b_rsa_verify_pkcs1_v15(&jwk, "RS256",
                                           signdata.base, signdata.len,
                                           signature.base, signature.len);
        return (rc == N00B_QUIC_OK) ? 0 : PTLS_ALERT_DECRYPT_ERROR;
    }
    default:
        /* Fail closed.  Any algorithm we can't verify is a handshake
         * failure — never silently accepted. */
        return PTLS_ALERT_ILLEGAL_PARAMETER;
    }
}

/* ===========================================================================
 * §4   Public installer
 * =========================================================================== */

const uint16_t n00b_picotls_supported_sig_algs[] = {
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    /* PKCS1 SHA-256 left in the offered list for the cert-chain
     * validation path (signature_algorithms also gates that in TLS 1.3
     * when signature_algorithms_cert is absent).  Never used for
     * CertificateVerify by spec-conforming peers. */
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    UINT16_MAX,
};

/* ===========================================================================
 * §5   Client-side mTLS: sign_certificate
 *
 * Called when the peer (acting as TLS 1.3 server) sent CertificateRequest
 * and we need to produce a CertificateVerify message proving possession
 * of the cert's private key.  We use the auth handle's
 * `n00b_quic_secret_sign` for the actual signing (which performs
 * SHA-256 + ECDSA-P-256 internally and returns raw r||s); we wrap r||s
 * as a DER SEQUENCE per RFC 8446 § 4.4.3.
 *
 * v1 supports ECDSA-P-256-SHA-256 only.  RSA client keys land when
 * `n00b_quic_secret_sign` gains an RSA-PSS path.
 * =========================================================================== */

static size_t
sigder_int_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    return 1 + 1 + mag + (size_t)pad;
}

static size_t
sigder_int_emit(uint8_t *out, const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) i++;
    size_t mag = len - i;
    int    pad = (be[i] & 0x80) ? 1 : 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(mag + (size_t)pad);
    size_t off = 2;
    if (pad) out[off++] = 0x00;
    memcpy(out + off, be + i, mag);
    return off + mag;
}

static int
client_sign_cb(ptls_sign_certificate_t *self_,
               ptls_t                  *tls,
               ptls_async_job_t       **async,
               uint16_t                *selected_algorithm,
               ptls_buffer_t           *output,
               ptls_iovec_t             input,
               const uint16_t          *algorithms,
               size_t                   num_algorithms)
{
    (void)tls; (void)async;

    /* Recover the enclosing storage struct so we can fetch the
     * caller's signing key. */
    n00b_picotls_client_auth_storage_t *st =
        (n00b_picotls_client_auth_storage_t *)
        ((char *)self_
         - offsetof(n00b_picotls_client_auth_storage_t, super));

    /* Walk the server's signature_algorithms list in offered order.
     * For each algorithm we recognize, ask the secret provider if it
     * can sign with it.  The first one the provider accepts is the
     * one we use — that lets a single client_sign_cb work for both
     * ECDSA-keyed and RSA-keyed providers without us having to
     * introspect the key.
     *
     * Recognized algorithms:
     *   - ECDSA-P-256-SHA-256 → N00B_QUIC_SIG_ECDSA_P256
     *   - RSA-PSS-RSAE-SHA-256 → N00B_QUIC_SIG_RSA_PSS_2048 */
    n00b_buffer_t in_buf;
    memset(&in_buf, 0, sizeof(in_buf));
    n00b_buffer_init(&in_buf,
                     .raw       = (char *)input.base,
                     .length    = (int64_t)input.len,
                     .allocator =
                     (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool);

    uint16_t            chosen     = 0;
    n00b_buffer_t      *raw_sig    = nullptr;
    for (size_t i = 0; i < num_algorithms && chosen == 0; i++) {
        n00b_quic_sig_alg_t try_alg;
        switch (algorithms[i]) {
        case PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
            try_alg = N00B_QUIC_SIG_ECDSA_P256;
            break;
        case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
            try_alg = N00B_QUIC_SIG_RSA_PSS_2048;
            break;
        default:
            continue;
        }
        auto sr = n00b_quic_secret_sign(st->key, &in_buf, try_alg);
        if (n00b_result_is_ok(sr)) {
            chosen  = algorithms[i];
            raw_sig = n00b_result_get(sr);
        }
        /* On err: try the next offered algorithm.  This is how a
         * provider that only supports ECDSA gracefully falls back
         * when the server lists PSS first. */
    }
    if (chosen == 0) {
        /* No offered algorithm was accepted by the secret provider.
         * Fail closed — we have no way to authenticate. */
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }
    *selected_algorithm = chosen;

    if (chosen == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
        if (raw_sig->byte_len != 64) return PTLS_ERROR_LIBRARY;
        const uint8_t *raw = (const uint8_t *)raw_sig->data;
        size_t r_sz   = sigder_int_size(raw,      32);
        size_t s_sz   = sigder_int_size(raw + 32, 32);
        size_t inner  = r_sz + s_sz;
        int rc = ptls_buffer_reserve(output, 2 + inner);
        if (rc != 0) return rc;
        output->base[output->off++] = 0x30;
        output->base[output->off++] = (uint8_t)inner;
        output->off += sigder_int_emit(output->base + output->off, raw,      32);
        output->off += sigder_int_emit(output->base + output->off, raw + 32, 32);
        return 0;
    }

    /* RSA-PSS: the provider returned the full PSS signature
     * (modulus_len bytes) already in wire format.  Copy verbatim. */
    int rc = ptls_buffer_reserve(output, (size_t)raw_sig->byte_len);
    if (rc != 0) return rc;
    memcpy(output->base + output->off, raw_sig->data,
           (size_t)raw_sig->byte_len);
    output->off += (size_t)raw_sig->byte_len;
    return 0;
}


int
n00b_picotls_install_client_auth(ptls_context_t                     *ctx,
                                 const uint8_t                      *cert_chain_der,
                                 const size_t                       *cert_chain_lens,
                                 size_t                              cert_chain_count,
                                 n00b_quic_secret_t                 *key,
                                 n00b_picotls_client_auth_storage_t *storage)
{
    if (!ctx || !cert_chain_der || !cert_chain_lens
        || cert_chain_count == 0 || !key || !storage) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    /* Build the iovec array used by `ctx->certificates.list`.  Pointers
     * are into the caller's chain bytes — caller owns the lifetime. */
    n00b_allocator_t *cp =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    storage->cert_iovecs = n00b_alloc_array_with_opts(
        ptls_iovec_t, (int64_t)cert_chain_count,
        &(n00b_alloc_opts_t){.allocator = cp});
    storage->cert_iovec_count = cert_chain_count;
    const uint8_t *p = cert_chain_der;
    for (size_t i = 0; i < cert_chain_count; i++) {
        storage->cert_iovecs[i].base = (uint8_t *)p;
        storage->cert_iovecs[i].len  = cert_chain_lens[i];
        p += cert_chain_lens[i];
    }

    storage->key      = key;
    storage->super.cb = client_sign_cb;

    ctx->certificates.list  = storage->cert_iovecs;
    ctx->certificates.count = storage->cert_iovec_count;
    ctx->sign_certificate   = &storage->super;
    return 0;
}

int
n00b_picotls_install_verify_sign(int (**verify_sign)(void *, uint16_t,
                                                    ptls_iovec_t,
                                                    ptls_iovec_t),
                                 void          **verify_data,
                                 const uint8_t  *leaf_der,
                                 size_t          leaf_len)
{
    if (!verify_sign || !verify_data || !leaf_der || leaf_len == 0) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    n00b_allocator_t *cp =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    /* Copy the leaf cert into pool storage before parsing — the
     * parser's pubkey pointers (rsa_n, rsa_e) borrow into this
     * storage, and the picotls cert iovec is only valid for the
     * duration of the verify_certificate callback.  We need the
     * pubkey to outlive that callback (until verify_sign fires later
     * in the handshake). */
    uint8_t *cert_copy = n00b_alloc_array_with_opts(uint8_t, (int64_t)leaf_len,
        &(n00b_alloc_opts_t){.allocator = cp, .no_scan = true});
    memcpy(cert_copy, leaf_der, leaf_len);

    verify_ctx_t *ctx = n00b_alloc_with_opts(verify_ctx_t,
        &(n00b_alloc_opts_t){.allocator = cp});
    if (parse_spki(cert_copy, leaf_len, &ctx->key) != 0
        || ctx->key.kind == SPKI_NONE) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    *verify_data = ctx;
    *verify_sign = verify_sign_cb;
    return 0;
}
