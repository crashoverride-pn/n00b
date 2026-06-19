/*
 * x509_ext.c — decode specific X.509 extension values (WP-042 Phase 1).
 *
 * Each extnValue is nested DER, re-tokenized with the libc-free DER tokenizer
 * (NULL grammar = decode mode, read der_value directly). n00b_buffer_t only.
 */

#include "n00b.h"

#include "core/buffer.h"
#include "core/string.h"
#include "adt/list.h"
#include "internal/crypto/x509_der_tok.h"
#include "crypto/x509.h"

/* id-ce-subjectAltName 2.5.29.17 / id-ce-basicConstraints 2.5.29.19 */
static n00b_buffer_t *
oid_san(void)
{
    char b[] = {0x55, 0x1d, 0x11};
    return n00b_buffer_from_bytes(b, 3);
}

static n00b_buffer_t *
oid_bc(void)
{
    char b[] = {0x55, 0x1d, 0x13};
    return n00b_buffer_from_bytes(b, 3);
}

n00b_list_t(n00b_string_t *)
n00b_x509_san_dns(const n00b_x509_cert_t *cert)
{
    n00b_list_t(n00b_string_t *) out = n00b_list_new(n00b_string_t *);

    const n00b_x509_ext_t *e = n00b_x509_find_ext(cert, oid_san());
    if (e == NULL || e->value == NULL) {
        return out;
    }

    /* extnValue = GeneralNames ::= SEQUENCE OF GeneralName; a dNSName is
     * [2] IMPLICIT IA5String (context-class, primitive, tag 2). */
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(e->value, NULL);
    if (r.error != NULL || r.tokens == NULL) {
        return out;
    }
    for (int i = 0; i < r.count; i++) {
        n00b_der_value_t *v = (n00b_der_value_t *)r.tokens[i]->user_info;
        if (v != NULL && !v->constructed && v->tag_class == 2
            && v->tag_number == 2 && v->content != NULL) {
            n00b_list_push(out, n00b_buffer_to_string(v->content));
        }
    }
    return out;
}

bool
n00b_x509_basic_constraints(const n00b_x509_cert_t *cert, bool *is_ca,
                            int64_t *pathlen)
{
    if (is_ca != NULL) {
        *is_ca = false;
    }
    if (pathlen != NULL) {
        *pathlen = -1;
    }

    const n00b_x509_ext_t *e = n00b_x509_find_ext(cert, oid_bc());
    if (e == NULL || e->value == NULL) {
        return false;
    }

    /* extnValue = SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPT }. */
    n00b_der_tok_result_t r = n00b_x509_der_tokenize(e->value, NULL);
    if (r.error != NULL || r.tokens == NULL) {
        return true; /* present; empty SEQUENCE => cA FALSE (the default) */
    }
    for (int i = 0; i < r.count; i++) {
        n00b_der_value_t *v = (n00b_der_value_t *)r.tokens[i]->user_info;
        if (v == NULL || v->constructed || v->content == NULL
            || v->tag_class != 0) {
            continue;
        }
        if (v->tag_number == 1) { /* BOOLEAN cA */
            n00b_result_t(uint8_t) br = n00b_buffer_get_index(v->content, 0);
            if (is_ca != NULL && n00b_result_is_ok(br)) {
                *is_ca = (n00b_result_get(br) != 0x00);
            }
        }
        else if (v->tag_number == 2) { /* INTEGER pathLenConstraint */
            int64_t pl   = 0;
            int64_t blen = (int64_t)n00b_buffer_len(v->content);
            for (int64_t k = 0; k < blen && k < 8; k++) {
                n00b_result_t(uint8_t) br = n00b_buffer_get_index(v->content, k);
                if (n00b_result_is_ok(br)) {
                    pl = (pl << 8) | (int64_t)n00b_result_get(br);
                }
            }
            if (pathlen != NULL) {
                *pathlen = pl;
            }
        }
    }
    return true;
}
