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
#include "adt/array.h"
#include "text/strings/string_ops.h"
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

static bool
pattern_matches_host(n00b_string_t *pat, n00b_string_t *host)
{
    n00b_string_t *dot  = n00b_string_from_cstr(".");
    n00b_string_t *star = n00b_string_from_cstr("*");

    n00b_array_t(n00b_string_t *) pl = n00b_unicode_str_split(pat, dot);
    n00b_array_t(n00b_string_t *) hl = n00b_unicode_str_split(host, dot);

    int64_t pn = n00b_array_len(pl);
    int64_t hn = n00b_array_len(hl);
    if (pn == 0 || pn != hn) {
        return false; /* wildcard matches exactly one label -> equal counts */
    }
    for (int64_t i = 0; i < pn; i++) {
        n00b_string_t *p = n00b_array_get(pl, i);
        n00b_string_t *h = n00b_array_get(hl, i);

        if (i == 0 && n00b_unicode_str_eq(p, star)) {
            /* leftmost full wildcard: need a registrable domain below it
             * (>= 3 labels) and a non-empty host label. */
            if (pn < 3 || h == NULL || h->u8_bytes == 0) {
                return false;
            }
            continue;
        }
        /* reject partial/embedded wildcards */
        if (n00b_unicode_str_contains(p, star)) {
            return false;
        }
        if (!n00b_unicode_str_eq(p, h, .case_sensitive = false)) {
            return false;
        }
    }
    return true;
}

bool
n00b_x509_host_matches(const n00b_x509_cert_t *cert, n00b_string_t *host)
{
    if (cert == NULL || host == NULL || host->u8_bytes == 0) {
        return false;
    }
    n00b_list_t(n00b_string_t *) sans = n00b_x509_san_dns(cert);
    int64_t n = n00b_list_len(sans);
    for (int64_t i = 0; i < n; i++) {
        if (pattern_matches_host(n00b_list_get(sans, i), host)) {
            return true;
        }
    }
    return false;
}
