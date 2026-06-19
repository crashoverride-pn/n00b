/*
 * acme_csr.c — PKCS#10 (RFC 2986) CSR builder.
 *
 * Layout:
 *   §1   DER write primitives
 *   §2   ECDSA r||s → DER SEQUENCE(r INTEGER, s INTEGER)
 *   §3   SubjectPublicKeyInfo for ECDSA-P-256
 *   §4   SAN extension + extensionRequest attribute
 *   §5   CertificationRequestInfo + signature → CertificationRequest
 *
 * The DER encoder is intentionally tiny — we hand-roll a few
 * thousand bytes per CSR, and the structures are fixed.  No
 * arbitrary-depth recursion, no streaming.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme_csr.h"

/* ===========================================================================
 * §1   DER write primitives
 *
 * Builds DER into a growable byte vector.  We reserve generously up
 * front so we never reallocate mid-build (CSRs are 400-700 bytes).
 * =========================================================================== */

typedef struct {
    uint8_t *bytes;
    size_t   len;
    size_t   cap;
    /* Sticky overflow flag.  Once set, subsequent emit calls are
     * no-ops; the caller checks `err` once after the build phase
     * and returns an error result rather than aborting.  Earlier
     * versions called `abort()` on overflow; that was a footgun. */
    bool     err;
} der_buf_t;

static n00b_allocator_t *
csr_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static void
der_init(der_buf_t *b, size_t reserve)
{
    b->bytes = n00b_alloc_array_with_opts(uint8_t, (int64_t)reserve,
                                          &(n00b_alloc_opts_t){
                                              .allocator = csr_alloc(),
                                              .no_scan   = true,
                                          });
    b->len = 0;
    b->cap = reserve;
    b->err = false;
}

static void
der_emit(der_buf_t *b, const uint8_t *src, size_t n)
{
    /* Sizing reserve is the caller's job.  If a caller miscomputed
     * the reserve, set the sticky err flag and quietly drop the
     * bytes — the build wrapper checks `err` before publishing the
     * output. */
    if (b->err) {
        return;
    }
    if (b->len + n > b->cap) {
        b->err = true;
        return;
    }
    if (n > 0) {
        memcpy(b->bytes + b->len, src, n);
        b->len += n;
    }
}

static void
der_emit_byte(der_buf_t *b, uint8_t v)
{
    der_emit(b, &v, 1);
}

/* DER length octets per X.690 § 8.1.3.  Short form for len < 128,
 * long form otherwise (count of length bytes in the low 7 bits, then
 * the bytes big-endian). */
static void
der_emit_len(der_buf_t *b, size_t len)
{
    if (len < 0x80) {
        der_emit_byte(b, (uint8_t)len);
        return;
    }
    uint8_t buf[8];
    int     n = 0;
    while (len > 0 && n < (int)sizeof(buf)) {
        buf[n++] = (uint8_t)(len & 0xff);
        len >>= 8;
    }
    der_emit_byte(b, (uint8_t)(0x80 | n));
    /* big-endian: emit MSB-to-LSB */
    for (int i = n - 1; i >= 0; i--) {
        der_emit_byte(b, buf[i]);
    }
}

/* Compute the number of bytes der_emit_len would produce for `len`. */
static size_t
der_len_size(size_t len)
{
    if (len < 0x80)        return 1;
    if (len <= 0xff)       return 2;
    if (len <= 0xffff)     return 3;
    if (len <= 0xffffff)   return 4;
    return 5;  /* good up to 4 GiB which we'll never approach */
}

/* Write tag + length + body. */
static void
der_emit_tlv(der_buf_t *b, uint8_t tag,
             const uint8_t *body, size_t body_len)
{
    der_emit_byte(b, tag);
    der_emit_len(b, body_len);
    der_emit(b, body, body_len);
}

/* DER INTEGER encoding for an unsigned big-endian magnitude.
 * Strip leading zeros; if the high bit of the first surviving byte
 * is set, prepend a 0x00 to keep it positive. */
static void
der_emit_integer_unsigned(der_buf_t *b,
                          const uint8_t *be, size_t len)
{
    /* Strip leading zero bytes (but keep at least one if the value is 0). */
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) {
        i++;
    }
    size_t mag_len = len - i;
    int    pad     = (be[i] & 0x80) ? 1 : 0;

    der_emit_byte(b, 0x02);  /* INTEGER */
    der_emit_len(b, mag_len + (size_t)pad);
    if (pad) {
        der_emit_byte(b, 0x00);
    }
    der_emit(b, be + i, mag_len);
}

/* Returns the DER size of an unsigned-magnitude INTEGER. */
static size_t
der_integer_unsigned_tlv_size(const uint8_t *be, size_t len)
{
    size_t i = 0;
    while (i + 1 < len && be[i] == 0x00) {
        i++;
    }
    size_t mag_len = len - i;
    int    pad     = (be[i] & 0x80) ? 1 : 0;
    size_t body    = mag_len + (size_t)pad;
    return 1 /* tag */ + der_len_size(body) + body;
}

/* ===========================================================================
 * §2   ECDSA raw r||s (64 bytes) → DER SEQUENCE(r INTEGER, s INTEGER)
 *
 * X.509/PKCS#10 ECDSA signatures are DER-encoded as
 *   SEQUENCE { r INTEGER, s INTEGER }
 * not the raw r||s that JOSE uses.  This is § 2.2.3 of RFC 5480.
 * =========================================================================== */

static void
ecdsa_raw_to_der(const uint8_t raw[64], uint8_t **out, size_t *out_len)
{
    size_t r_size = der_integer_unsigned_tlv_size(raw,      32);
    size_t s_size = der_integer_unsigned_tlv_size(raw + 32, 32);
    size_t inner  = r_size + s_size;
    size_t total  = 1 + der_len_size(inner) + inner;

    der_buf_t b;
    der_init(&b, total);

    der_emit_byte(&b, 0x30);  /* SEQUENCE */
    der_emit_len(&b, inner);
    der_emit_integer_unsigned(&b, raw,      32);
    der_emit_integer_unsigned(&b, raw + 32, 32);

    *out     = b.bytes;
    *out_len = b.len;
}

/* ===========================================================================
 * §3   SubjectPublicKeyInfo for ECDSA-P-256
 *
 * RFC 5480 § 2.  The id-ecPublicKey OID is 1.2.840.10045.2.1; the
 * P-256 curve OID (id-secp256r1, prime256v1) is 1.2.840.10045.3.1.7.
 * The public key value goes into a BIT STRING; the EC public key is
 * written as 0x04 || X || Y (uncompressed point form, RFC 5480 § 2.2).
 * =========================================================================== */

/* SEQUENCE { OID id-ecPublicKey, OID id-secp256r1 } */
static const uint8_t algid_ecpub_p256[] = {
    0x30, 0x13,                                              /* SEQUENCE 19 */
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,    /* OID 1.2.840.10045.2.1 */
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 /* OID 1.2.840.10045.3.1.7 */
};

static void
emit_subject_pubkey_info(der_buf_t *b, const uint8_t pub[64])
{
    /*
     * SubjectPublicKeyInfo SEQUENCE {
     *   AlgorithmIdentifier,
     *   subjectPublicKey BIT STRING
     * }
     *
     * BIT STRING body = 0x00 (unused-bits) || 0x04 (uncompressed point) || X || Y
     * = 1 + 1 + 64 = 66 bytes
     */
    const size_t bitstring_body = 1 + 1 + 64;       /* unused-bits + 0x04 + XY */
    const size_t bitstring_tlv  = 1 + der_len_size(bitstring_body) + bitstring_body;
    const size_t spki_inner     = sizeof(algid_ecpub_p256) + bitstring_tlv;

    der_emit_byte(b, 0x30);  /* SEQUENCE */
    der_emit_len(b, spki_inner);
    der_emit(b, algid_ecpub_p256, sizeof(algid_ecpub_p256));
    der_emit_byte(b, 0x03);  /* BIT STRING */
    der_emit_len(b, bitstring_body);
    der_emit_byte(b, 0x00);  /* zero unused bits */
    der_emit_byte(b, 0x04);  /* uncompressed point form */
    der_emit(b, pub, 64);
}

/* ===========================================================================
 * §4   SAN extension + extensionRequest attribute
 *
 * SubjectAltName ::= SEQUENCE OF GeneralName
 * GeneralName for dNSName is [2] IMPLICIT IA5String — DER tag 0x82.
 *
 * An extension is wrapped as:
 *   SEQUENCE { OID extnID, [BOOLEAN critical,] OCTET STRING extnValue }
 * where extnValue is the DER of the *value* (so the SAN's SEQUENCE OF is
 * encapsulated in an OCTET STRING).
 *
 * For extensionRequest (PKCS#9, OID 1.2.840.113549.1.9.14):
 *   Attribute SEQUENCE {
 *     attrType OID 1.2.840.113549.1.9.14,
 *     attrValues SET { Extensions SEQUENCE OF Extension }
 *   }
 * =========================================================================== */

/* OID 2.5.29.17 — id-ce-subjectAltName */
static const uint8_t oid_san[] = {0x06, 0x03, 0x55, 0x1d, 0x11};

/* OID 1.2.840.113549.1.9.14 — pkcs-9-at-extensionRequest */
static const uint8_t oid_ext_req[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e
};

/* Compute size of dNSName GeneralName for a single name. */
static size_t
gn_dns_size(const char *dns)
{
    size_t l = strlen(dns);
    return 1 /* [2] tag */ + der_len_size(l) + l;
}

/* Emit a dNSName GeneralName: [2] IMPLICIT IA5String — context tag 0x82. */
static void
emit_gn_dns(der_buf_t *b, const char *dns)
{
    size_t l = strlen(dns);
    der_emit_byte(b, 0x82);
    der_emit_len(b, l);
    der_emit(b, (const uint8_t *)dns, l);
}

/* Compute the size of the extensionRequest attribute. */
static size_t
ext_req_attribute_size(const char *const *dns_names, size_t count)
{
    /* SAN value (SEQUENCE OF GeneralName) inner. */
    size_t san_seq_inner = 0;
    for (size_t i = 0; i < count; i++) {
        san_seq_inner += gn_dns_size(dns_names[i]);
    }
    /* Encapsulating SEQUENCE OF (the SAN value). */
    size_t san_seq_tlv = 1 + der_len_size(san_seq_inner) + san_seq_inner;
    /* OCTET STRING wrapping the SAN value. */
    size_t san_octet_tlv = 1 + der_len_size(san_seq_tlv) + san_seq_tlv;
    /* Extension SEQUENCE { OID, OCTET STRING } */
    size_t ext_inner = sizeof(oid_san) + san_octet_tlv;
    size_t ext_tlv   = 1 + der_len_size(ext_inner) + ext_inner;
    /* Extensions SEQUENCE OF Extension */
    size_t exts_inner = ext_tlv;
    size_t exts_tlv   = 1 + der_len_size(exts_inner) + exts_inner;
    /* SET of Extensions */
    size_t set_inner = exts_tlv;
    size_t set_tlv   = 1 + der_len_size(set_inner) + set_inner;
    /* Attribute SEQUENCE { OID, SET } */
    size_t attr_inner = sizeof(oid_ext_req) + set_tlv;
    size_t attr_tlv   = 1 + der_len_size(attr_inner) + attr_inner;
    return attr_tlv;
}

static void
emit_ext_req_attribute(der_buf_t *b, const char *const *dns_names,
                       size_t count)
{
    /* Compute layered sizes; we use the same recursion as the size
     * helper above so the structure is symmetric. */
    size_t san_seq_inner = 0;
    for (size_t i = 0; i < count; i++) {
        san_seq_inner += gn_dns_size(dns_names[i]);
    }
    size_t san_seq_tlv   = 1 + der_len_size(san_seq_inner) + san_seq_inner;
    size_t san_octet_tlv = 1 + der_len_size(san_seq_tlv) + san_seq_tlv;
    size_t ext_inner     = sizeof(oid_san) + san_octet_tlv;
    size_t ext_tlv       = 1 + der_len_size(ext_inner) + ext_inner;
    size_t exts_inner    = ext_tlv;
    size_t set_inner     = 1 + der_len_size(exts_inner) + exts_inner;
    size_t attr_inner    = sizeof(oid_ext_req)
                         + (1 + der_len_size(set_inner) + set_inner);

    /* Attribute SEQUENCE */
    der_emit_byte(b, 0x30);
    der_emit_len(b, attr_inner);
    /* attrType OID */
    der_emit(b, oid_ext_req, sizeof(oid_ext_req));
    /* attrValues SET */
    der_emit_byte(b, 0x31);
    der_emit_len(b, set_inner);
    /* Extensions SEQUENCE OF Extension */
    der_emit_byte(b, 0x30);
    der_emit_len(b, exts_inner);
    /* Extension SEQUENCE */
    der_emit_byte(b, 0x30);
    der_emit_len(b, ext_inner);
    /* extnID = id-ce-subjectAltName */
    der_emit(b, oid_san, sizeof(oid_san));
    /* extnValue OCTET STRING wrapping the SAN value */
    der_emit_byte(b, 0x04);
    der_emit_len(b, san_seq_tlv);
    /* SubjectAltName SEQUENCE OF GeneralName */
    der_emit_byte(b, 0x30);
    der_emit_len(b, san_seq_inner);
    for (size_t i = 0; i < count; i++) {
        emit_gn_dns(b, dns_names[i]);
    }
}

/* ===========================================================================
 * §5   CertificationRequestInfo + signature → CertificationRequest
 * =========================================================================== */

/* AlgorithmIdentifier for ecdsa-with-SHA256 (no parameters). */
static const uint8_t algid_ecdsa_sha256[] = {
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

n00b_result_t(n00b_buffer_t *)
n00b_acme_build_csr(n00b_quic_secret_t *cert_key,
                    const char *const   *dns_names,
                    size_t               count)
{
    if (!cert_key || !dns_names || count == 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_NULL_ARG);
    }

    /* 1. Get the cert key's public key. */
    auto pr = n00b_quic_secret_pubkey(cert_key, N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(pr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(pr));
    }
    n00b_buffer_t *pub = n00b_result_get(pr);
    if (pub->byte_len != 64) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_INVALID_ARG);
    }

    /* 2. Build the CertificationRequestInfo:
     *    SEQUENCE { version=0 INTEGER, subject Name, spki, [0] attrs }
     *    where subject is an empty SEQUENCE (RDNSequence with no RDN)
     *    and attrs holds the extensionRequest attribute.
     */
    /* version (INTEGER 0): 02 01 00 — 3 bytes */
    /* subject Name = empty SEQUENCE: 30 00 — 2 bytes */
    /* spki computed below. */
    /* [0] attrs IMPLICIT Attributes (one Attribute carrying ext_req). */
    static const uint8_t version_field[]  = {0x02, 0x01, 0x00};
    static const uint8_t empty_subject[]  = {0x30, 0x00};

    /* Sizes (no actual emission yet). */
    const size_t spki_inner = sizeof(algid_ecpub_p256)
                            + (1 + der_len_size(1 + 1 + 64) + 1 + 1 + 64);
    const size_t spki_tlv   = 1 + der_len_size(spki_inner) + spki_inner;

    const size_t attr_tlv      = ext_req_attribute_size(dns_names, count);
    const size_t attrs_inner   = attr_tlv;          /* one attribute */
    const size_t attrs_ctx_tlv = 1 + der_len_size(attrs_inner) + attrs_inner;

    const size_t cri_inner = sizeof(version_field)
                           + sizeof(empty_subject)
                           + spki_tlv
                           + attrs_ctx_tlv;
    const size_t cri_tlv   = 1 + der_len_size(cri_inner) + cri_inner;

    /* Emit the CertificationRequestInfo. */
    der_buf_t cri;
    der_init(&cri, cri_tlv + 16);
    der_emit_byte(&cri, 0x30);
    der_emit_len(&cri, cri_inner);
    der_emit(&cri, version_field, sizeof(version_field));
    der_emit(&cri, empty_subject, sizeof(empty_subject));
    emit_subject_pubkey_info(&cri, (const uint8_t *)pub->data);
    der_emit_byte(&cri, 0xa0);  /* [0] context-tagged */
    der_emit_len(&cri, attrs_inner);
    emit_ext_req_attribute(&cri, dns_names, count);

    if (cri.err) {
        /* Reserve was undersized for the configuration we just
         * emitted — should be caught in tests, but bail cleanly
         * rather than abort.  Indicates a bug in the size helpers. */
        return n00b_result_err(n00b_buffer_t *,
                               N00B_QUIC_ERR_FRAME_TOO_LARGE);
    }

    /* 3. Sign the DER bytes of CertificationRequestInfo. */
    n00b_buffer_t cri_buf;
    memset(&cri_buf, 0, sizeof(cri_buf));
    n00b_buffer_init(&cri_buf,
                     .raw = (char *)cri.bytes, .length = (int64_t)cri.len,
                     .allocator = csr_alloc());

    auto sigr = n00b_quic_secret_sign(cert_key, &cri_buf,
                                      N00B_QUIC_SIG_ECDSA_P256);
    if (!n00b_result_is_ok(sigr)) {
        return n00b_result_err(n00b_buffer_t *,
                               (int)n00b_result_get_err(sigr));
    }
    n00b_buffer_t *raw_sig = n00b_result_get(sigr);
    if (raw_sig->byte_len != 64) {
        return n00b_result_err(n00b_buffer_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    /* 4. Convert raw r||s to DER SEQUENCE(r INTEGER, s INTEGER). */
    uint8_t *sig_der    = nullptr;
    size_t   sig_der_len = 0;
    ecdsa_raw_to_der((const uint8_t *)raw_sig->data, &sig_der, &sig_der_len);

    /* 5. Wrap in a BIT STRING (zero unused bits prefix). */
    /* 6. Emit the outer CertificationRequest:
     *    SEQUENCE { CertificationRequestInfo,
     *               AlgorithmIdentifier,
     *               BIT STRING signature }
     */
    const size_t bs_body = 1 + sig_der_len;  /* unused-bits + DER signature */
    const size_t bs_tlv  = 1 + der_len_size(bs_body) + bs_body;
    const size_t cr_inner = cri.len
                          + sizeof(algid_ecdsa_sha256)
                          + bs_tlv;
    const size_t cr_tlv   = 1 + der_len_size(cr_inner) + cr_inner;

    der_buf_t cr;
    der_init(&cr, cr_tlv + 16);
    der_emit_byte(&cr, 0x30);
    der_emit_len(&cr, cr_inner);
    der_emit(&cr, cri.bytes, cri.len);
    der_emit(&cr, algid_ecdsa_sha256, sizeof(algid_ecdsa_sha256));
    der_emit_byte(&cr, 0x03);
    der_emit_len(&cr, bs_body);
    der_emit_byte(&cr, 0x00);                 /* unused bits */
    der_emit(&cr, sig_der, sig_der_len);

    if (cr.err) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_QUIC_ERR_FRAME_TOO_LARGE);
    }

    n00b_buffer_t *out = n00b_buffer_from_bytes((char *)cr.bytes,
                                                (int64_t)cr.len,
                                                .allocator = csr_alloc());
    return n00b_result_ok(n00b_buffer_t *, out);
}
