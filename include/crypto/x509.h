#pragma once

/*
 * x509.h — typed X.509 certificate extracted from DER (WP-042 Phase 1).
 *
 * n00b_x509_cert_from_der() parses a DER cert (via the slay x509_der grammar)
 * and walks the parse tree into this struct. All slices alias into the caller's
 * DER buffer (which must outlive the cert): content slices are the primitive
 * value bytes; `tbs`, `issuer`, `subject` are full TLV element slices (needed
 * for signature verification over the signed TBSCertificate and for DN equality
 * during chain building).
 *
 * v1 scope: the certificate envelope. Extension parsing (SAN, BasicConstraints,
 * KeyUsage, EKU) lands next — each extnValue is nested DER re-parsed separately.
 */

#include "n00b.h"

typedef struct {
    const uint8_t *p;
    size_t         len;
} n00b_der_slice_t;

typedef struct {
    int64_t          version;       /* 0=v1, 1=v2, 2=v3 (DEFAULT v1) */
    n00b_der_slice_t serial;        /* INTEGER content (may have a leading 0x00) */
    n00b_der_slice_t tbs;           /* TBSCertificate full TLV — the signed bytes */
    n00b_der_slice_t sig_alg_oid;   /* tbs.signature AlgorithmIdentifier OID */
    n00b_der_slice_t issuer;        /* issuer Name full TLV (DN) */
    n00b_der_slice_t subject;       /* subject Name full TLV (DN) */
    n00b_der_slice_t not_before;    /* Validity.notBefore content bytes */
    uint8_t          not_before_tag;/* 23 = UTCTime, 24 = GeneralizedTime */
    n00b_der_slice_t not_after;
    uint8_t          not_after_tag;
    n00b_der_slice_t spki_alg_oid;  /* SubjectPublicKeyInfo algorithm OID */
    n00b_der_slice_t spki_key;      /* subjectPublicKey BIT STRING content
                                     * (byte 0 = unused-bit count, normally 0) */
    n00b_der_slice_t sig_alg_oid_outer; /* outer signatureAlgorithm OID */
    n00b_der_slice_t signature;     /* signatureValue BIT STRING content */
} n00b_x509_cert_t;

typedef struct {
    bool             ok;
    n00b_x509_cert_t cert;
    n00b_string_t   *error;
} n00b_x509_cert_result_t;

extern n00b_x509_cert_result_t
n00b_x509_cert_from_der(const uint8_t *der, size_t len);
