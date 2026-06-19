/*
 * x509_cert.c — walk the x509_der parse tree into a typed n00b_x509_cert_t
 * (WP-042 Phase 1). See include/crypto/x509.h.
 *
 * The grammar (grammars/x509_der.bnf) maps 1:1 to RFC 5280, so the walk is
 * structural: each constructed NT has the OPEN bracket token as child 0 and the
 * CLOSE bracket token as the last child; optional/repetition operators wrap
 * content in $$group nodes.
 * collect_fields() flattens groups and drops the bracket tokens, yielding the
 * meaningful field nodes in order. Default-deny: any shape mismatch -> error.
 */

#include "n00b.h"

#include "core/string.h"
#include "slay/parse_tree.h"
#include "internal/crypto/x509_der_tok.h"
#include "internal/crypto/x509_parse.h"
#include "crypto/x509.h"

#define X509_MAX_FIELDS 32

static n00b_der_value_t *
tok_val(n00b_parse_tree_t *n)
{
    if (n == NULL || !n00b_pt_is_token(n)) {
        return NULL;
    }
    n00b_token_info_t *t = n00b_parse_node_token(n);
    return t ? (n00b_der_value_t *)t->user_info : NULL;
}

/* Meaningful children of a constructed NT, in order: NT children + primitive
 * tokens, with $$group nodes flattened and OPEN/CLOSE bracket tokens dropped. */
static void
collect_fields(n00b_parse_tree_t *nt, n00b_parse_tree_t **out, int *cnt)
{
    size_t n = n00b_pt_num_children(nt);
    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *c = n00b_pt_get_child(nt, i);
        if (n00b_pt_is_token(c)) {
            n00b_der_value_t *v = tok_val(c);
            if (v != NULL && v->constructed) {
                continue; /* OPEN / CLOSE bracket */
            }
            if (*cnt < X509_MAX_FIELDS) {
                out[(*cnt)++] = c; /* primitive token */
            }
        }
        else if (n00b_pt_is_group(c)) {
            collect_fields(c, out, cnt); /* flatten optional/repetition groups */
        }
        else if (*cnt < X509_MAX_FIELDS) {
            out[(*cnt)++] = c; /* non-terminal */
        }
    }
}

static n00b_der_slice_t
prim_content(n00b_parse_tree_t *tok)
{
    n00b_der_slice_t s = {0};
    n00b_der_value_t *v = tok_val(tok);
    if (v != NULL) {
        s.p   = v->content;
        s.len = v->content_len;
    }
    return s;
}

/* Full TLV slice of a constructed NT (its child-0 OPEN token carries `elem`). */
static n00b_der_slice_t
nt_elem(n00b_parse_tree_t *nt)
{
    n00b_der_slice_t s = {0};
    if (nt == NULL || n00b_pt_is_token(nt) || n00b_pt_num_children(nt) == 0) {
        return s;
    }
    n00b_der_value_t *v = tok_val(n00b_pt_get_child(nt, 0));
    if (v != NULL && v->elem != NULL) {
        s.p   = v->elem;
        s.len = v->elem_len;
    }
    return s;
}

/* AlgorithmIdentifier -> the algorithm OID content. */
static n00b_der_slice_t
algid_oid(n00b_parse_tree_t *algid)
{
    n00b_der_slice_t  s      = {0};
    n00b_parse_tree_t *f[X509_MAX_FIELDS];
    int                cnt   = 0;
    if (algid == NULL) {
        return s;
    }
    collect_fields(algid, f, &cnt);
    if (cnt >= 1) {
        return prim_content(f[0]); /* first field is the OID */
    }
    return s;
}

n00b_x509_cert_result_t
n00b_x509_cert_from_der(const uint8_t *der, size_t len)
{
    n00b_x509_cert_result_t res = {0};

    n00b_x509_parse_t p = n00b_x509_parse_der(der, len);
    if (!p.ok) {
        res.error = p.error;
        return res;
    }

    n00b_x509_cert_t cert = {0};

    /* Certificate ::= SEQ { TBSCertificate, AlgorithmIdentifier, BIT STRING } */
    n00b_parse_tree_t *cf[X509_MAX_FIELDS];
    int                cn = 0;
    collect_fields(p.tree, cf, &cn);
    if (cn < 3) {
        res.error = n00b_string_from_cstr("x509: malformed Certificate envelope");
        return res;
    }
    n00b_parse_tree_t *tbs_nt = cf[0];
    cert.tbs               = nt_elem(tbs_nt);
    cert.sig_alg_oid_outer = algid_oid(cf[1]);
    cert.signature         = prim_content(cf[2]);

    /* TBSCertificate ::= SEQ { [0] Version?, serial, sigAlg, issuer, validity,
     *                          subject, spki, ... } */
    n00b_parse_tree_t *tf[X509_MAX_FIELDS];
    int                tn = 0;
    collect_fields(tbs_nt, tf, &tn);

    int i = 0;
    cert.version = 0; /* DEFAULT v1 */
    if (i < tn && !n00b_pt_is_token(tf[i]) && n00b_pt_is_nt(tf[i], "Version")) {
        n00b_parse_tree_t *vf[X509_MAX_FIELDS];
        int                vn = 0;
        collect_fields(tf[i], vf, &vn);
        if (vn >= 1) {
            n00b_der_slice_t vs = prim_content(vf[0]);
            int64_t          v  = 0;
            for (size_t k = 0; k < vs.len && k < 8; k++) {
                v = (v << 8) | (int64_t)vs.p[k];
            }
            cert.version = v;
        }
        i++;
    }

    if (tn - i < 6) {
        res.error = n00b_string_from_cstr("x509: malformed TBSCertificate");
        return res;
    }

    cert.serial      = prim_content(tf[i++]);            /* INTEGER */
    cert.sig_alg_oid = algid_oid(tf[i++]);               /* AlgorithmIdentifier */
    cert.issuer      = nt_elem(tf[i++]);                 /* Name (DN) */

    /* Validity ::= SEQ { Time notBefore, Time notAfter } */
    n00b_parse_tree_t *validity = tf[i++];
    n00b_parse_tree_t *vfld[X509_MAX_FIELDS];
    int                vcnt = 0;
    collect_fields(validity, vfld, &vcnt);
    if (vcnt >= 2) {
        for (int t = 0; t < 2; t++) {
            /* each is a Time NT wrapping a UTCTime/GeneralizedTime token */
            n00b_parse_tree_t *tfl[X509_MAX_FIELDS];
            int                tc = 0;
            collect_fields(vfld[t], tfl, &tc);
            n00b_parse_tree_t *time_tok = (tc >= 1) ? tfl[0] : NULL;
            n00b_der_value_t  *tvv      = tok_val(time_tok);
            n00b_der_slice_t   ts       = prim_content(time_tok);
            if (t == 0) {
                cert.not_before     = ts;
                cert.not_before_tag = tvv ? (uint8_t)tvv->tag_number : 0;
            }
            else {
                cert.not_after     = ts;
                cert.not_after_tag = tvv ? (uint8_t)tvv->tag_number : 0;
            }
        }
    }

    cert.subject = nt_elem(tf[i++]);                     /* Name (DN) */

    /* SubjectPublicKeyInfo ::= SEQ { AlgorithmIdentifier, BIT STRING } */
    n00b_parse_tree_t *spki = tf[i++];
    n00b_parse_tree_t *sf[X509_MAX_FIELDS];
    int                sc = 0;
    collect_fields(spki, sf, &sc);
    if (sc >= 2) {
        cert.spki_alg_oid = algid_oid(sf[0]);
        cert.spki_key     = prim_content(sf[1]);
    }

    /* Extensions ([3]) + uniqueIDs deferred to the next step. */

    res.ok   = true;
    res.cert = cert;
    return res;
}
