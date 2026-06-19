#pragma once

/*
 * x509.h — typed X.509 certificate extracted from DER (WP-042 Phase 1).
 *
 * n00b_x509_cert_from_der() parses a DER cert (via the slay x509_der grammar)
 * and walks the parse tree into this struct. Every field is an n00b_buffer_t
 * holding the relevant DER bytes: value buffers are primitive content; `tbs`,
 * `issuer`, `subject` are full TLV elements (the signed TBSCertificate, and the
 * raw Names for DN equality during chain building).
 *
 * v1 scope: the certificate envelope + the extension list. Per-extension value
 * decoding (SAN dNSNames, BasicConstraints) re-parses each extnValue buffer.
 */

#include "n00b.h"
#include "core/buffer.h"

#define N00B_X509_MAX_EXTS 32

typedef struct {
    n00b_buffer_t *oid;      /* extnID OID content */
    bool           critical; /* critical BOOLEAN (DEFAULT FALSE) */
    n00b_buffer_t *value;    /* extnValue OCTET STRING content (nested DER) */
} n00b_x509_ext_t;

typedef struct {
    int64_t        version;        /* 0=v1, 1=v2, 2=v3 (DEFAULT v1) */
    n00b_buffer_t *serial;         /* INTEGER content (may have a leading 0x00) */
    n00b_buffer_t *tbs;            /* TBSCertificate full TLV — the signed bytes */
    n00b_buffer_t *sig_alg_oid;    /* tbs.signature AlgorithmIdentifier OID */
    n00b_buffer_t *issuer;         /* issuer Name full TLV (DN) */
    n00b_buffer_t *subject;        /* subject Name full TLV (DN) */
    n00b_buffer_t *not_before;     /* Validity.notBefore content bytes */
    uint8_t        not_before_tag; /* 23 = UTCTime, 24 = GeneralizedTime */
    n00b_buffer_t *not_after;
    uint8_t        not_after_tag;
    n00b_buffer_t *spki_alg_oid;   /* SubjectPublicKeyInfo algorithm OID */
    n00b_buffer_t *spki_key;       /* subjectPublicKey BIT STRING content
                                    * (byte 0 = unused-bit count, normally 0) */
    n00b_buffer_t *sig_alg_oid_outer; /* outer signatureAlgorithm OID */
    n00b_buffer_t *signature;      /* signatureValue BIT STRING content */
    n00b_x509_ext_t exts[N00B_X509_MAX_EXTS]; /* v3 extensions, in DER order */
    int              ext_count;
} n00b_x509_cert_t;

typedef struct {
    bool             ok;
    n00b_x509_cert_t cert;
    n00b_string_t   *error;
} n00b_x509_cert_result_t;

extern n00b_x509_cert_result_t
n00b_x509_cert_from_der(n00b_buffer_t *der);

/* Find an extension whose OID equals @p oid (content bytes); NULL if absent. */
extern const n00b_x509_ext_t *
n00b_x509_find_ext(const n00b_x509_cert_t *cert, n00b_buffer_t *oid);
