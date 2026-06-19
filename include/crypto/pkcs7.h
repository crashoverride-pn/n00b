#pragma once

/**
 * @file util/pkcs7.h
 * @brief PKCS#7 / CMS SignedData builder (RFC 5652) for libn00b.
 *
 * Allocator-aware producer for the RFC 5652 `ContentInfo` /
 * `SignedData` structure family. Designed for the Authenticode PE
 * resign path (WP-005 Phase 4) — embeds the
 * `SpcIndirectDataContent` content type (Microsoft OID
 * `1.3.6.1.4.1.311.2.1.4`) when called with that OID, but also
 * works as a general-purpose RFC 5652 SignedData producer for any
 * content type the caller hands it.
 *
 * # Symbol prefix
 *
 * `n00b_pkcs7_*` (lower-case symbols, `N00B_PKCS7_*` for the
 * error-code macros). Top-level libn00b utility namespace.
 *
 * # Scope (v1)
 *
 * - One signer per SignedData (multi-signer ECDSA/RSA hybrid
 *   blobs out of scope; documented as a follow-on if a consumer
 *   needs it).
 * - **RSA-PKCS1-v1_5 SHA-256 signatures only.** ECDSA signers
 *   deferred to a future ergonomics WP (D-039 in spirit). The
 *   DER encoder underneath is algorithm-agnostic; only the
 *   signer call binding is RSA-specific.
 * - Detached or attached content modes — the caller chooses by
 *   passing the content bytes or nullptr to
 *   @ref n00b_pkcs7_signed_data_set_content.
 * - No counter-signatures, no RFC 3161 timestamping (deferred).
 *
 * # Caller responsibilities
 *
 * The PKCS#7 builder does NOT parse the signer's X.509
 * certificate. The caller supplies:
 *
 * - The cert chain as a list of DER blobs (added one at a time
 *   via @ref n00b_pkcs7_signed_data_add_certificate). At least
 *   one cert (the signer's leaf) must be added before
 *   @ref n00b_pkcs7_signed_data_add_signer is called.
 * - The signer's issuer DN as a pre-encoded DER `Name` blob.
 * - The signer's serial-number INTEGER as raw big-endian bytes.
 * - The signer's RSA private key as `(n, d)` raw big-endian
 *   bytes — same shape the existing `n00b_rsa_sign_*`
 *   primitives consume.
 *
 * The test fixture demonstrates how to materialize these from a
 * PEM cert + key pair (manual DER skim of the
 * `Certificate.tbsCertificate.{issuer,serialNumber}` fields,
 * since libn00b has no public X.509 parser yet).
 *
 * # Allocator discipline
 *
 * Every entry point accepts `.allocator = nullptr`. The opaque
 * handle stores the caller's allocator at construction time and
 * threads it through every internal sub-allocation; callers
 * passing an arena can free the whole sub-graph in one go.
 *
 * # Authenticode v1 OIDs (for caller convenience)
 *
 * The OIDs the Authenticode PE path needs. Encoded as arc arrays
 * for direct use with `n00b_der_encode_oid` from `der_encode.h`.
 */

#include <n00b.h>
#include "adt/result.h"

/**
 * @brief Opaque PKCS#7 SignedData builder handle.
 *
 * Internally a small state struct holding the content blob, the
 * cert list, and the signer info. Construction allocates;
 * everything inside is GC-tracked / arena-tracked per the
 * caller's allocator.
 */
typedef struct n00b_pkcs7_signed_data n00b_pkcs7_signed_data_t;

/* Error codes (negative, libn00b convention). */
#define N00B_PKCS7_ERR_NO_SIGNER        (-3200)
#define N00B_PKCS7_ERR_NO_CONTENT       (-3201)
#define N00B_PKCS7_ERR_SIGN_FAILED      (-3202)
#define N00B_PKCS7_ERR_INVALID_HANDLE   (-3203)

/**
 * @brief Allocate an empty PKCS#7 SignedData builder.
 *
 * @kw allocator  Optional allocator (default: runtime); owned by
 *                the handle and threaded through every internal
 *                sub-allocation.
 *
 * @return A non-null `n00b_pkcs7_signed_data_t *`. The handle is
 *         GC-tracked; callers do NOT need to free it explicitly.
 */
extern n00b_pkcs7_signed_data_t *
n00b_pkcs7_signed_data_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Set the SignedData inner content (the data being signed).
 *
 * @param sd                  The builder handle.
 * @param content_type_oid    DER-encoded OBJECT IDENTIFIER for
 *                            the content type (e.g.,
 *                            `1.3.6.1.4.1.311.2.1.4` for the
 *                            Authenticode `SpcIndirectDataContent`
 *                            shape; `1.2.840.113549.1.7.1` for
 *                            generic `data`). MUST be the TLV
 *                            output of `n00b_der_encode_oid` or
 *                            equivalent — the builder uses it
 *                            verbatim.
 * @param content_bytes       The raw content bytes (typically the
 *                            DER-encoded `SpcIndirectDataContent`
 *                            structure, or arbitrary user data).
 *                            nullptr means "detached content" —
 *                            the SignedData omits the inner
 *                            content blob but still carries the
 *                            content type and the digest over
 *                            the (out-of-band) content bytes
 *                            supplied to
 *                            @ref n00b_pkcs7_signed_data_add_signer.
 *
 * @details Replaces any content set by a prior call.
 */
extern void
n00b_pkcs7_signed_data_set_content(n00b_pkcs7_signed_data_t *sd,
                                   n00b_buffer_t            *content_type_oid,
                                   n00b_buffer_t            *content_bytes);

/**
 * @brief Add an X.509 certificate to the SignedData chain.
 *
 * @param sd        The builder handle.
 * @param cert_der  The certificate as a DER-encoded blob (the
 *                  output of `openssl x509 -outform DER` over the
 *                  signer's PEM, or the post-Base64-decode bytes
 *                  from a PEM `-----BEGIN CERTIFICATE-----`
 *                  block). The first certificate added is treated
 *                  as the signer's leaf for matching against the
 *                  SignerInfo's IssuerAndSerialNumber.
 *
 * @details The cert chain emits as a SET OF Certificate in the
 * SignedData `certificates` field per RFC 5652 §5.1. Order is
 * preserved on input; the DER encoder canonically sorts on
 * serialization.
 */
extern void
n00b_pkcs7_signed_data_add_certificate(n00b_pkcs7_signed_data_t *sd,
                                       n00b_buffer_t            *cert_der);

/**
 * @brief Add a SignerInfo to the SignedData (v1: one signer only).
 *
 * Computes the message digest over @p content_for_digest (which
 * is typically what
 * @ref n00b_pkcs7_signed_data_set_content received as
 * `content_bytes`, but may differ when the caller is signing a
 * detached content blob), signs it with the supplied RSA private
 * key under PKCS1-v1.5 SHA-256, and records the SignerInfo for
 * emission during @ref n00b_pkcs7_signed_data_serialize.
 *
 * @param sd                   The builder handle.
 * @param issuer_dn_der        DER-encoded `Name` for the signer
 *                             cert's issuer. Caller extracts this
 *                             from the cert's
 *                             `tbsCertificate.issuer` field.
 * @param serial_bytes         Big-endian serial number bytes
 *                             (signed; high bit indicates sign).
 * @param serial_len           Length of @p serial_bytes.
 * @param content_for_digest   Bytes to digest. For Authenticode,
 *                             this is the full
 *                             `SpcIndirectDataContent` DER blob
 *                             (the content of the SignedData's
 *                             contentInfo, NOT the contentInfo's
 *                             outer wrapping). Must be non-null;
 *                             zero-length is permitted (the
 *                             digest of an empty input is the
 *                             SHA-256 of the empty byte string).
 * @param rsa_n                Signer's RSA modulus (big-endian).
 * @param rsa_n_len            Length of @p rsa_n.
 * @param rsa_d                Signer's RSA private exponent
 *                             (big-endian).
 * @param rsa_d_len            Length of @p rsa_d.
 *
 * @return `n00b_result_ok(bool, true)` on success;
 *         `n00b_result_err(bool, N00B_PKCS7_ERR_SIGN_FAILED)`
 *         if the underlying RSA sign primitive fails.
 *
 * @pre At least one certificate has been added via
 *      @ref n00b_pkcs7_signed_data_add_certificate.
 */
extern n00b_result_t(bool)
n00b_pkcs7_signed_data_add_signer(n00b_pkcs7_signed_data_t *sd,
                                  n00b_buffer_t            *issuer_dn_der,
                                  const uint8_t            *serial_bytes,
                                  size_t                    serial_len,
                                  n00b_buffer_t            *content_for_digest,
                                  const uint8_t            *rsa_n,
                                  size_t                    rsa_n_len,
                                  const uint8_t            *rsa_d,
                                  size_t                    rsa_d_len);

/**
 * @brief Serialize the SignedData to its DER-encoded `ContentInfo`
 *        wrapping.
 *
 * @param sd  The builder handle.
 *
 * @return On success, an `n00b_result_ok(n00b_buffer_t *, der)`
 *         carrying the full `ContentInfo { contentType =
 *         pkcs7-signedData, content = [0] EXPLICIT SignedData }`
 *         blob, ready for embedding in a PE certificate-table
 *         entry. On error
 *         (`N00B_PKCS7_ERR_NO_SIGNER` /
 *         `N00B_PKCS7_ERR_NO_CONTENT`), the err channel carries
 *         the code.
 *
 * @pre @ref n00b_pkcs7_signed_data_add_signer has been called at
 *      least once, and @ref n00b_pkcs7_signed_data_set_content
 *      has been called.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_pkcs7_signed_data_serialize(n00b_pkcs7_signed_data_t *sd);

/**
 * @brief Build the Authenticode `SpcIndirectDataContent` blob for
 *        a given PE Authenticode hash.
 *
 * Helper for the WP-005 Phase 4 PE resign path. Produces the
 * `SEQUENCE { SpcAttributeTypeAndOptionalValue, DigestInfo }`
 * shape Microsoft's "Authenticode_PE.docx" mandates as the inner
 * content of the Authenticode SignedData blob:
 *
 * ```
 * SpcIndirectDataContent ::= SEQUENCE {
 *     data SpcAttributeTypeAndOptionalValue,   -- OID 1.3.6.1.4.1.311.2.1.15 (SPC_PE_IMAGE_DATA)
 *     messageDigest DigestInfo
 * }
 * DigestInfo ::= SEQUENCE {
 *     digestAlgorithm AlgorithmIdentifier,     -- SHA-256
 *     digest OCTET STRING                      -- the Authenticode hash
 * }
 * ```
 *
 * The `SpcPeImageData` field is emitted as the minimal-shape
 * `(0x00, [0]([0] ()))` form osslsigncode also emits — flags
 * absent, file [0] absent, link [0] absent.
 *
 * @param authentihash_sha256  The 32-byte Authenticode hash
 *                             (output of
 *                             `n00b_pe_authentihash_sha256`).
 *                             nullptr is rejected (returns
 *                             nullptr).
 *
 * @kw allocator  Optional allocator (default: runtime).
 *
 * @return A new `n00b_buffer_t *` carrying the DER-encoded
 *         `SpcIndirectDataContent` SEQUENCE.
 */
extern n00b_buffer_t *
n00b_pkcs7_build_spc_indirect_data(n00b_buffer_t *authentihash_sha256) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up a human-readable string for an `N00B_PKCS7_ERR_*`
 *        error code.
 */
extern n00b_string_t *
n00b_pkcs7_err_str(n00b_err_t err);
