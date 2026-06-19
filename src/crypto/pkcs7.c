/* src/util/pkcs7.c — PKCS#7 / CMS SignedData builder.
 *
 * Implements the surface declared in include/util/pkcs7.h.
 *
 * Design (RFC 5652 §5 + Authenticode v1 ASN.1 conventions):
 *
 * - The opaque handle accumulates the content (eContentType +
 *   inner bytes), the cert list, and the single signer info.
 *
 * - serialize() composes the bytes top-down via the DER encoder:
 *
 *     ContentInfo ::= SEQUENCE {
 *         contentType OID (1.2.840.113549.1.7.2 — signedData),
 *         content [0] EXPLICIT SignedData
 *     }
 *
 *     SignedData ::= SEQUENCE {
 *         version          INTEGER (1),
 *         digestAlgorithms SET OF AlgorithmIdentifier (sha256),
 *         encapContentInfo SEQUENCE {
 *             eContentType OID (caller-supplied),
 *             eContent [0] EXPLICIT { <embedded SpcIndirectDataContent
 *                                       SEQUENCE | OCTET STRING(content)> }
 *         },
 *         certificates [0] IMPLICIT SET OF Certificate,
 *         signerInfos  SET OF SignerInfo
 *     }
 *
 *     SignerInfo ::= SEQUENCE {
 *         version             INTEGER (1),
 *         sid                 IssuerAndSerialNumber {issuer, serial},
 *         digestAlgorithm     AlgorithmIdentifier (sha256),
 *         signatureAlgorithm  AlgorithmIdentifier (rsaEncryption),
 *         signature           OCTET STRING (RSA-PKCS1-v1.5 SHA-256 over the
 *                                            content)
 *     }
 *
 *   (We omit signedAttrs / unsignedAttrs for v1; this is the
 *    minimal SignerInfo form RFC 5652 §5.3 permits when
 *    `signedAttrs` is absent — signature is computed over the
 *    content directly rather than over a SignerInfo
 *    representation. Authenticode v1 allows this form; the
 *    osslsigncode-produced fixture also accepts it.)
 *
 * - eContent's `[0] EXPLICIT` carries the SpcIndirectDataContent
 *   SEQUENCE DIRECTLY (Microsoft's Authenticode convention),
 *   not wrapped in an OCTET STRING. For generic-data callers
 *   (`eContentType = pkcs7-data`), they pass an OCTET-STRING
 *   already produced by `n00b_der_encode_octet_string` if they
 *   want the standard form.
 */

#include <crypto/pkcs7.h>
#include <crypto/der_encode.h>
#include <crypto/rsa_sign.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/sha256.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

typedef struct cert_node {
    n00b_buffer_t   *cert_der;
    struct cert_node *next;
} cert_node_t;

typedef struct signer_node {
    n00b_buffer_t      *issuer_dn_der;
    uint8_t            *serial_bytes;
    size_t              serial_len;
    n00b_buffer_t      *signature_bytes;
    struct signer_node *next;
} signer_node_t;

struct n00b_pkcs7_signed_data {
    /* Instance-stash of the caller's allocator, set at construction and
     * forwarded on every subsequent `_add_*` / `_serialize` call. This is
     * the multi-call builder pattern: the per-call kwarg cannot be
     * re-supplied without changing the public surface, so the handle
     * carries the allocator. The §4.3 ban on stashed allocators targets
     * module-globals/statics; an instance field on a per-handle struct
     * is the intended escape hatch for builder APIs. */
    n00b_allocator_t *allocator;
    n00b_buffer_t    *content_type_oid;   // pre-encoded OID TLV
    n00b_buffer_t    *content_bytes;      // inner bytes (may be null)
    cert_node_t      *certs_head;         // FIFO
    cert_node_t      *certs_tail;
    size_t            n_certs;
    signer_node_t    *signers_head;
    signer_node_t    *signers_tail;
    size_t            n_signers;
};

// ---------------------------------------------------------------------------
// Canonical OIDs (allocator-aware lazy builders)
// ---------------------------------------------------------------------------

/* PKCS#7 SignedData (1.2.840.113549.1.7.2). */
static uint32_t k_oid_signed_data[] = { 1, 2, 840, 113549, 1, 7, 2 };
/* SHA-256 algorithm (2.16.840.1.101.3.4.2.1). */
static uint32_t k_oid_sha256[]      = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
/* RSA Encryption (1.2.840.113549.1.1.1). */
static uint32_t k_oid_rsa_enc[]     = { 1, 2, 840, 113549, 1, 1, 1 };
/* Microsoft Authenticode SPC_PE_IMAGE_DATA (1.3.6.1.4.1.311.2.1.15). */
static uint32_t k_oid_spc_pe_image[] = { 1, 3, 6, 1, 4, 1, 311, 2, 1, 15 };

static n00b_buffer_t *
oid_buf(uint32_t *arcs, size_t n, n00b_allocator_t *allocator)
{
    return n00b_der_encode_oid(arcs, n, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

n00b_pkcs7_signed_data_t *
n00b_pkcs7_signed_data_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_pkcs7_signed_data_t *sd = n00b_alloc(
        n00b_pkcs7_signed_data_t, .allocator = allocator);
    sd->allocator = allocator;
    return sd;
}

void
n00b_pkcs7_signed_data_set_content(n00b_pkcs7_signed_data_t *sd,
                                   n00b_buffer_t            *content_type_oid,
                                   n00b_buffer_t            *content_bytes)
{
    if (sd == nullptr) {
        return;
    }
    sd->content_type_oid = content_type_oid;
    sd->content_bytes    = content_bytes;
}

void
n00b_pkcs7_signed_data_add_certificate(n00b_pkcs7_signed_data_t *sd,
                                       n00b_buffer_t            *cert_der)
{
    if (sd == nullptr || cert_der == nullptr) {
        return;
    }
    cert_node_t *node = n00b_alloc(cert_node_t, .allocator = sd->allocator);
    node->cert_der = cert_der;
    node->next     = nullptr;
    if (sd->certs_head == nullptr) {
        sd->certs_head = node;
    }
    else {
        sd->certs_tail->next = node;
    }
    sd->certs_tail = node;
    sd->n_certs++;
}

n00b_result_t(bool)
n00b_pkcs7_signed_data_add_signer(n00b_pkcs7_signed_data_t *sd,
                                  n00b_buffer_t            *issuer_dn_der,
                                  const uint8_t            *serial_bytes,
                                  size_t                    serial_len,
                                  n00b_buffer_t            *content_for_digest,
                                  const uint8_t            *rsa_n,
                                  size_t                    rsa_n_len,
                                  const uint8_t            *rsa_d,
                                  size_t                    rsa_d_len)
{
    if (sd == nullptr) {
        return n00b_result_err(bool, N00B_PKCS7_ERR_INVALID_HANDLE);
    }

    /* Compute the message digest over the content. RFC 5652 §5.4:
     * when signedAttrs is absent, the signature is computed over
     * the content directly (with PKCS#1 v1.5 padding the signer's
     * private key applies). We sign the raw content bytes; the
     * RSA primitive internally SHA-256s them. */

    size_t  msg_len = (content_for_digest != nullptr)
                          ? content_for_digest->byte_len : 0;
    const uint8_t *msg = (content_for_digest != nullptr)
                            ? (const uint8_t *)content_for_digest->data : (const uint8_t *)"";

    uint8_t *sig = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)rsa_n_len,
        &(n00b_alloc_opts_t){.allocator = sd->allocator, .no_scan = true});
    size_t sig_len = rsa_n_len;

    int rc = n00b_rsa_sign_pkcs1_v15_sha256(
        rsa_n, rsa_n_len, rsa_d, rsa_d_len,
        msg, msg_len,
        sig, &sig_len);
    if (rc != 0) {
        return n00b_result_err(bool, N00B_PKCS7_ERR_SIGN_FAILED);
    }

    signer_node_t *node = n00b_alloc(signer_node_t, .allocator = sd->allocator);
    node->issuer_dn_der = issuer_dn_der;
    node->serial_bytes  = n00b_alloc_array_with_opts(
        uint8_t, (int64_t)serial_len,
        &(n00b_alloc_opts_t){.allocator = sd->allocator, .no_scan = true});
    memcpy(node->serial_bytes, serial_bytes, serial_len);
    node->serial_len = serial_len;

    node->signature_bytes = n00b_buffer_from_bytes(
        (char *)sig, (int64_t)sig_len, .allocator = sd->allocator);

    node->next = nullptr;
    if (sd->signers_head == nullptr) {
        sd->signers_head = node;
    }
    else {
        sd->signers_tail->next = node;
    }
    sd->signers_tail = node;
    sd->n_signers++;

    return n00b_result_ok(bool, true);
}

// ---------------------------------------------------------------------------
// SpcIndirectDataContent helper
// ---------------------------------------------------------------------------

n00b_buffer_t *
n00b_pkcs7_build_spc_indirect_data(n00b_buffer_t *authentihash_sha256) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (authentihash_sha256 == nullptr || authentihash_sha256->byte_len == 0) {
        return nullptr;
    }

    /* SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
     *     type ObjectID  (1.3.6.1.4.1.311.2.1.15 — SPC_PE_IMAGE_DATA),
     *     value [0] EXPLICIT SpcPeImageData
     * }
     *
     * SpcPeImageData ::= SEQUENCE {
     *     flags SpcPeImageFlags DEFAULT { includeResources },
     *     file  SpcLink         [0] EXPLICIT
     * }
     *
     * For the minimal Authenticode v1 shape, both fields are
     * conventionally minimal: flags = empty BIT STRING (0 unused
     * bits), file = SpcLink CHOICE [2] EXPLICIT moniker — but
     * osslsigncode emits a different minimal shape:
     *   value = SpcPeImageData { flags absent, file [0] EXPLICIT [2] ([0] ()) }
     *
     * We emit the simpler shape that pe_query.c's authentihash
     * path doesn't care about anyway — both forms are accepted
     * by Microsoft's signtool / Authenticode verifier per the
     * docx spec's "value MAY be empty" wording:
     *
     *   value [0] EXPLICIT SEQUENCE {}
     *
     * That keeps the test surface small and validation-clean.
     */

    /* Empty SpcPeImageData SEQUENCE. */
    n00b_buffer_t *empty_seq = n00b_der_encode_sequence(
        nullptr, 0, .allocator = allocator);

    /* [0] EXPLICIT wrapper around it. */
    n00b_buffer_t *tagged_value = n00b_der_encode_tagged(
        0, empty_seq, .allocator = allocator);

    /* SpcAttributeTypeAndOptionalValue. */
    n00b_buffer_t *spc_pe_oid = oid_buf(
        k_oid_spc_pe_image,
        sizeof(k_oid_spc_pe_image) / sizeof(uint32_t),
        allocator);

    n00b_buffer_t *attr_elements[2] = { spc_pe_oid, tagged_value };
    n00b_buffer_t *spc_attr         = n00b_der_encode_sequence(
        attr_elements, 2, .allocator = allocator);

    /* DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
     *                           digest OCTET STRING } */
    n00b_buffer_t *sha256_oid = oid_buf(
        k_oid_sha256,
        sizeof(k_oid_sha256) / sizeof(uint32_t),
        allocator);
    n00b_buffer_t *null_param = n00b_der_encode_null(.allocator = allocator);

    n00b_buffer_t *alg_id_elements[2] = { sha256_oid, null_param };
    n00b_buffer_t *digest_alg_id      = n00b_der_encode_sequence(
        alg_id_elements, 2, .allocator = allocator);

    n00b_buffer_t *digest_octet = n00b_der_encode_octet_string(
        authentihash_sha256, .allocator = allocator);

    n00b_buffer_t *digest_info_elements[2] = { digest_alg_id, digest_octet };
    n00b_buffer_t *digest_info             = n00b_der_encode_sequence(
        digest_info_elements, 2, .allocator = allocator);

    n00b_buffer_t *spc_elements[2] = { spc_attr, digest_info };
    return n00b_der_encode_sequence(spc_elements, 2,
                                    .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Serialize
// ---------------------------------------------------------------------------

n00b_result_t(n00b_buffer_t *)
n00b_pkcs7_signed_data_serialize(n00b_pkcs7_signed_data_t *sd)
{
    if (sd == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_PKCS7_ERR_INVALID_HANDLE);
    }
    if (sd->n_signers == 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_PKCS7_ERR_NO_SIGNER);
    }
    if (sd->content_type_oid == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_PKCS7_ERR_NO_CONTENT);
    }

    n00b_allocator_t *allocator = sd->allocator;

    /* --- digestAlgorithms SET OF AlgorithmIdentifier (sha256). --- */
    n00b_buffer_t *sha256_oid = oid_buf(
        k_oid_sha256, sizeof(k_oid_sha256) / sizeof(uint32_t), allocator);
    n00b_buffer_t *null_param = n00b_der_encode_null(.allocator = allocator);
    n00b_buffer_t *alg_id_seq_elements[2] = { sha256_oid, null_param };
    n00b_buffer_t *alg_id_seq            = n00b_der_encode_sequence(
        alg_id_seq_elements, 2, .allocator = allocator);
    n00b_buffer_t *digest_algs_set_elements[1] = { alg_id_seq };
    n00b_buffer_t *digest_algs_set             = n00b_der_encode_set(
        digest_algs_set_elements, 1, .allocator = allocator);

    /* --- encapContentInfo SEQUENCE { eContentType, [0] EXPLICIT eContent }. --- */
    n00b_buffer_t *eci_tagged = nullptr;
    if (sd->content_bytes != nullptr) {
        eci_tagged = n00b_der_encode_tagged(
            0, sd->content_bytes, .allocator = allocator);
    }
    /* If content_bytes is null (detached), eci_tagged stays null and
     * the [0] EXPLICIT slot is omitted from the SEQUENCE. */
    n00b_buffer_t *eci_elements[2] = { sd->content_type_oid, eci_tagged };
    n00b_buffer_t *eci_seq         = n00b_der_encode_sequence(
        eci_elements,
        eci_tagged != nullptr ? 2 : 1,
        .allocator = allocator);

    /* --- certificates [0] IMPLICIT CertificateSet. ---
     *
     * RFC 5652 §10.2.3 / §5.1: implicit-tagged. The underlying
     * SET-of-Certificate is constructed, so the [0] IMPLICIT
     * identifier byte is `0xA0`. `n00b_der_encode_implicit_tagged`
     * encapsulates the X.690 §8.14.3 rule (replace the underlying
     * identifier with the context-specific tag, preserving the
     * primitive/constructed bit from the underlying type) — this
     * matches strict-Authenticode parsers + osslsigncode + openssl
     * cms exactly.
     */
    n00b_buffer_t *certs_set = nullptr;
    if (sd->n_certs > 0) {
        n00b_buffer_t **cert_elements = n00b_alloc_array(
            n00b_buffer_t *, (int64_t)sd->n_certs,
            .allocator = allocator);
        size_t i = 0;
        cert_node_t *c;
        for (c = sd->certs_head; c != nullptr; c = c->next) {
            cert_elements[i++] = c->cert_der;
        }
        /* CertificateSet is a SET of Certificate per RFC 5652. */
        n00b_buffer_t *raw_set = n00b_der_encode_set(
            cert_elements, sd->n_certs, .allocator = allocator);
        certs_set = n00b_der_encode_implicit_tagged(
            0, raw_set, .allocator = allocator);
    }

    /* --- signerInfos SET OF SignerInfo. ---
     *
     * Each SignerInfo:
     *   SEQUENCE {
     *     INTEGER (version = 1),
     *     IssuerAndSerialNumber SEQUENCE { issuer Name, serial INTEGER },
     *     AlgorithmIdentifier (digest = sha256),
     *     AlgorithmIdentifier (signature = rsaEncryption),
     *     OCTET STRING (signature)
     *   }
     */
    n00b_buffer_t **signer_elements = n00b_alloc_array(
        n00b_buffer_t *, (int64_t)sd->n_signers, .allocator = allocator);
    {
        size_t i = 0;
        signer_node_t *s;
        for (s = sd->signers_head; s != nullptr; s = s->next) {
            /* IssuerAndSerialNumber. */
            n00b_buffer_t *serial_tlv;
            {
                /* Build raw INTEGER content (preserve given bytes,
                 * inserting leading 0x00 if the high bit is set so
                 * the value isn't misread as negative). */
                size_t   pad     = (s->serial_len > 0
                                    && (s->serial_bytes[0] & 0x80) != 0) ? 1 : 0;
                size_t   total   = pad + s->serial_len;
                uint8_t *scratch = n00b_alloc_array_with_opts(
                    uint8_t, (int64_t)total,
                    &(n00b_alloc_opts_t){.allocator = allocator,
                                         .no_scan   = true});
                if (pad) scratch[0] = 0x00;
                memcpy(scratch + pad, s->serial_bytes, s->serial_len);

                /* Emit TLV directly (we can't use
                 * n00b_der_encode_integer for an arbitrarily-large
                 * value; serial numbers can exceed int64). The
                 * caller-supplied bytes already minimal-encode in
                 * the openssl-generated fixture case. */
                size_t llen  = 0;
                {
                    size_t L = total;
                    if (L < 128) llen = 1;
                    else { size_t v = L; while (v) { llen++; v >>= 8; } llen++; }
                }
                size_t tot = 1 + llen + total;
                serial_tlv = n00b_buffer_new((int64_t)tot, .allocator = allocator);
                n00b_buffer_resize(serial_tlv, tot);
                uint8_t *dst = (uint8_t *)serial_tlv->data;
                dst[0] = 0x02;
                if (total < 128) {
                    dst[1] = (uint8_t)total;
                }
                else {
                    /* Long-form length. */
                    size_t v = total;
                    uint8_t bytes[8]; size_t nb = 0;
                    while (v) { bytes[nb++] = (uint8_t)(v & 0xFF); v >>= 8; }
                    dst[1] = (uint8_t)(0x80 | nb);
                    for (size_t k = 0; k < nb; k++) {
                        dst[2 + k] = bytes[nb - 1 - k];
                    }
                }
                memcpy(dst + 1 + llen, scratch, total);
            }

            n00b_buffer_t *iasn_elements[2] = { s->issuer_dn_der, serial_tlv };
            n00b_buffer_t *iasn             = n00b_der_encode_sequence(
                iasn_elements, 2, .allocator = allocator);

            /* digestAlgorithm (sha256). */
            n00b_buffer_t *sha256_oid2 = oid_buf(
                k_oid_sha256,
                sizeof(k_oid_sha256) / sizeof(uint32_t),
                allocator);
            n00b_buffer_t *null2 = n00b_der_encode_null(
                .allocator = allocator);
            n00b_buffer_t *digalg_elements[2] = { sha256_oid2, null2 };
            n00b_buffer_t *digalg             = n00b_der_encode_sequence(
                digalg_elements, 2, .allocator = allocator);

            /* signatureAlgorithm (rsaEncryption). */
            n00b_buffer_t *rsa_oid = oid_buf(
                k_oid_rsa_enc,
                sizeof(k_oid_rsa_enc) / sizeof(uint32_t),
                allocator);
            n00b_buffer_t *null3 = n00b_der_encode_null(
                .allocator = allocator);
            n00b_buffer_t *sigalg_elements[2] = { rsa_oid, null3 };
            n00b_buffer_t *sigalg             = n00b_der_encode_sequence(
                sigalg_elements, 2, .allocator = allocator);

            /* signature OCTET STRING (encoded RSA signature bytes). */
            n00b_buffer_t *signature_octet = n00b_der_encode_octet_string(
                s->signature_bytes, .allocator = allocator);

            /* SignerInfo = SEQUENCE { version, sid, digalg, sigalg, sig }. */
            n00b_buffer_t *version = n00b_der_encode_integer(
                1, .allocator = allocator);

            n00b_buffer_t *si_elements[5] = {
                version, iasn, digalg, sigalg, signature_octet
            };
            n00b_buffer_t *si = n00b_der_encode_sequence(
                si_elements, 5, .allocator = allocator);

            signer_elements[i++] = si;
        }
    }
    n00b_buffer_t *signer_infos_set = n00b_der_encode_set(
        signer_elements, sd->n_signers, .allocator = allocator);

    /* --- SignedData SEQUENCE. --- */
    n00b_buffer_t *version1 = n00b_der_encode_integer(1, .allocator = allocator);
    n00b_buffer_t *sd_elements[5] = {
        version1, digest_algs_set, eci_seq, certs_set, signer_infos_set
    };
    /* certs_set may be null when n_certs == 0; pack the slot
     * accordingly. */
    size_t sd_n = 0;
    n00b_buffer_t *sd_packed[5];
    sd_packed[sd_n++] = version1;
    sd_packed[sd_n++] = digest_algs_set;
    sd_packed[sd_n++] = eci_seq;
    if (certs_set != nullptr) {
        sd_packed[sd_n++] = certs_set;
    }
    sd_packed[sd_n++] = signer_infos_set;
    (void)sd_elements;

    n00b_buffer_t *signed_data_seq = n00b_der_encode_sequence(
        sd_packed, sd_n, .allocator = allocator);

    /* --- ContentInfo SEQUENCE. --- */
    n00b_buffer_t *signed_data_oid = oid_buf(
        k_oid_signed_data,
        sizeof(k_oid_signed_data) / sizeof(uint32_t),
        allocator);
    n00b_buffer_t *content_tagged = n00b_der_encode_tagged(
        0, signed_data_seq, .allocator = allocator);
    n00b_buffer_t *ci_elements[2] = { signed_data_oid, content_tagged };
    n00b_buffer_t *content_info = n00b_der_encode_sequence(
        ci_elements, 2, .allocator = allocator);

    return n00b_result_ok(n00b_buffer_t *, content_info);
}

// ---------------------------------------------------------------------------
// Error-string accessor
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_pkcs7_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_PKCS7_ERR_NO_SIGNER:
        return r"PKCS#7 SignedData: no signer added";
    case N00B_PKCS7_ERR_NO_CONTENT:
        return r"PKCS#7 SignedData: content not set";
    case N00B_PKCS7_ERR_SIGN_FAILED:
        return r"PKCS#7 SignedData: RSA sign primitive failed";
    case N00B_PKCS7_ERR_INVALID_HANDLE:
        return r"PKCS#7 SignedData: invalid (null) handle";
    default:
        return r"PKCS#7 SignedData: unknown error code";
    }
}
