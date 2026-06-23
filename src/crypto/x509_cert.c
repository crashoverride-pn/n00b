/*
 * x509_cert.c — walk the x509_der parse tree into a typed n00b_x509_cert_t
 * (WP-042 Phase 1). See include/crypto/x509.h.
 *
 * The grammar (grammars/x509_der.bnf) maps 1:1 to RFC 5280, so the walk is
 * structural: each constructed NT has the OPEN bracket token as child 0 and the
 * CLOSE bracket token as the last child; optional/repetition operators wrap
 * content in $$group nodes. collect_fields() flattens groups and drops the
 * bracket tokens, yielding the meaningful field nodes in order. All extracted
 * values are n00b_buffer_t slices. Default-deny: any shape mismatch -> error.
 */

#include "n00b.h"

#include "core/buffer.h"
#include "core/string.h"
#include "slay/parse_tree.h"
#include "internal/crypto/x509_der_tok.h"
#include "internal/crypto/x509_parse.h"
#include "crypto/x509.h"

#define X509_MAX_FIELDS 32

static n00b_der_value_t *
tok_val(n00b_parse_tree_t *n)
{
    if (n == nullptr || !n00b_pt_is_token(n)) {
        return nullptr;
    }
    n00b_token_info_t *t = n00b_parse_node_token(n);
    return t ? (n00b_der_value_t *)t->user_info : nullptr;
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
            if (v != nullptr && v->constructed) {
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

static n00b_buffer_t *
prim_content(n00b_parse_tree_t *tok)
{
    n00b_der_value_t *v = tok_val(tok);
    return v ? v->content : nullptr;
}

/* Full TLV slice of a constructed NT (its child-0 OPEN token carries `elem`). */
static n00b_buffer_t *
nt_elem(n00b_parse_tree_t *nt)
{
    if (nt == nullptr || n00b_pt_is_token(nt) || n00b_pt_num_children(nt) == 0) {
        return nullptr;
    }
    n00b_der_value_t *v = tok_val(n00b_pt_get_child(nt, 0));
    return v ? v->elem : nullptr;
}

/* AlgorithmIdentifier -> the algorithm OID content buffer. */
static n00b_buffer_t *
algid_oid(n00b_parse_tree_t *algid)
{
    n00b_parse_tree_t *f[X509_MAX_FIELDS];
    int                cnt = 0;
    if (algid == nullptr) {
        return nullptr;
    }
    collect_fields(algid, f, &cnt);
    return (cnt >= 1) ? prim_content(f[0]) : nullptr;
}

static bool
buf_eq(n00b_buffer_t *a, n00b_buffer_t *b)
{
    if (a == nullptr || b == nullptr) {
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

n00b_x509_cert_result_t
n00b_x509_cert_from_der(n00b_buffer_t *der)
{
    n00b_x509_cert_result_t res = {};

    n00b_x509_parse_t p = n00b_x509_parse_der(der);
    if (!p.ok) {
        res.error = p.error;
        return res;
    }

    n00b_x509_cert_t cert = {};

    /* Certificate ::= SEQ { TBSCertificate, AlgorithmIdentifier, BIT STRING } */
    n00b_parse_tree_t *cf[X509_MAX_FIELDS];
    int                cn = 0;
    collect_fields(p.tree, cf, &cn);
    if (cn < 3) {
        res.error = r"x509: malformed Certificate envelope";
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
            n00b_buffer_t *vb = prim_content(vf[0]);
            int64_t        v  = 0;
            if (vb != nullptr) {
                int64_t blen = (int64_t)n00b_buffer_len(vb);
                for (int64_t k = 0; k < blen && k < 8; k++) {
                    n00b_result_t(uint8_t) br = n00b_buffer_get_index(vb, k);
                    if (n00b_result_is_ok(br)) {
                        v = (v << 8) | (int64_t)n00b_result_get(br);
                    }
                }
            }
            cert.version = v;
        }
        i++;
    }

    if (tn - i < 6) {
        res.error = r"x509: malformed TBSCertificate";
        return res;
    }

    cert.serial      = prim_content(tf[i++]);
    cert.sig_alg_oid = algid_oid(tf[i++]);
    cert.issuer      = nt_elem(tf[i++]);

    /* Validity ::= SEQ { Time notBefore, Time notAfter } */
    n00b_parse_tree_t *validity = tf[i++];
    n00b_parse_tree_t *vfld[X509_MAX_FIELDS];
    int                vcnt = 0;
    collect_fields(validity, vfld, &vcnt);
    if (vcnt >= 2) {
        for (int t = 0; t < 2; t++) {
            n00b_parse_tree_t *tfl[X509_MAX_FIELDS];
            int                tc = 0;
            collect_fields(vfld[t], tfl, &tc);
            n00b_parse_tree_t *time_tok = (tc >= 1) ? tfl[0] : nullptr;
            n00b_der_value_t  *tvv      = tok_val(time_tok);
            n00b_buffer_t     *ts       = prim_content(time_tok);
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

    cert.subject = nt_elem(tf[i++]);

    /* SubjectPublicKeyInfo ::= SEQ { AlgorithmIdentifier, BIT STRING } */
    n00b_parse_tree_t *spki = tf[i++];
    n00b_parse_tree_t *sf[X509_MAX_FIELDS];
    int                sc = 0;
    collect_fields(spki, sf, &sc);
    if (sc >= 2) {
        cert.spki_alg_oid = algid_oid(sf[0]);
        cert.spki_key     = prim_content(sf[1]);
    }

    /* Extensions ([3] EXPLICIT SEQUENCE OF Extension), among the remaining TBS
     * fields after the optional [1]/[2] uniqueID tokens. Each Extension ::=
     * SEQ { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }. */
    for (int k = i; k < tn; k++) {
        if (n00b_pt_is_token(tf[k]) || !n00b_pt_is_nt(tf[k], "Extensions")) {
            continue;
        }
        n00b_parse_tree_t *enodes[X509_MAX_FIELDS];
        int                ecnt = 0;
        collect_fields(tf[k], enodes, &ecnt);
        for (int e = 0; e < ecnt && cert.ext_count < N00B_X509_MAX_EXTS; e++) {
            if (n00b_pt_is_token(enodes[e])
                || !n00b_pt_is_nt(enodes[e], "Extension")) {
                continue;
            }
            n00b_parse_tree_t *ef[X509_MAX_FIELDS];
            int                efc = 0;
            collect_fields(enodes[e], ef, &efc);
            if (efc < 2) {
                continue;
            }
            n00b_x509_ext_t ext = {};
            ext.oid = prim_content(ef[0]);
            if (efc >= 3) {
                n00b_buffer_t *b = prim_content(ef[1]); /* critical BOOLEAN */
                bool           crit = false;
                if (b != nullptr && n00b_buffer_len(b) >= 1) {
                    n00b_result_t(uint8_t) br = n00b_buffer_get_index(b, 0);
                    crit = n00b_result_is_ok(br) && n00b_result_get(br) != 0x00;
                }
                ext.critical = crit;
                ext.value    = prim_content(ef[2]);
            }
            else {
                ext.critical = false;
                ext.value    = prim_content(ef[1]);
            }
            cert.exts[cert.ext_count++] = ext;
        }
        break;
    }

    res.ok   = true;
    res.cert = cert;
    return res;
}

const n00b_x509_ext_t *
n00b_x509_find_ext(const n00b_x509_cert_t *cert, n00b_buffer_t *oid)
{
    if (cert == nullptr || oid == nullptr) {
        return nullptr;
    }
    for (int i = 0; i < cert->ext_count; i++) {
        if (buf_eq(cert->exts[i].oid, oid)) {
            return &cert->exts[i];
        }
    }
    return nullptr;
}
