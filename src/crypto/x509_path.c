/*
 * x509_path.c — trust-anchor store + path validation (WP-042 Phase 4).
 *
 * Builds leaf -> intermediates -> anchor by DN match, verifies each link's
 * signature, checks validity windows + issuer CA-ness, and requires termination
 * at a trust anchor. n00b_buffer_t / n00b_list only; default-deny.
 */

#include "n00b.h"

#include "core/buffer.h"
#include "adt/list.h"
#include "crypto/x509.h"

struct n00b_x509_trust_store_t {
    n00b_list_t(n00b_x509_cert_t *) anchors;
    n00b_allocator_t               *allocator; /* nullptr = current GC heap */
};

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

n00b_x509_trust_store_t *
n00b_x509_trust_store_new()
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_x509_trust_store_t *s;
    if (allocator != nullptr) {
        s = n00b_alloc_with_opts(n00b_x509_trust_store_t,
                                 &(n00b_alloc_opts_t){.allocator = allocator});
        s->anchors = n00b_list_new(n00b_x509_cert_t *, .allocator = allocator);
    }
    else {
        s          = n00b_alloc(n00b_x509_trust_store_t);
        s->anchors = n00b_list_new(n00b_x509_cert_t *);
    }
    s->allocator = allocator;
    return s;
}

/* Copy a buffer into @p a (or the current heap when nullptr); nullptr->nullptr. */
static n00b_buffer_t *
buf_dup(n00b_buffer_t *src, n00b_allocator_t *a)
{
    if (src == nullptr) {
        return nullptr;
    }
    int64_t len = (int64_t)n00b_buffer_len(src);
    if (a != nullptr) {
        return n00b_buffer_from_bytes(src->data, len, .allocator = a);
    }
    return n00b_buffer_from_bytes(src->data, len);
}

/* Deep-copy every n00b_buffer_t field of a parsed cert into @p a, so the stored
 * anchor no longer aliases the transient parse tree (which is otherwise
 * reclaimed/moved by the GC). */
static void
dup_cert_buffers(n00b_x509_cert_t *c, n00b_allocator_t *a)
{
    c->serial            = buf_dup(c->serial, a);
    c->tbs               = buf_dup(c->tbs, a);
    c->sig_alg_oid       = buf_dup(c->sig_alg_oid, a);
    c->issuer            = buf_dup(c->issuer, a);
    c->subject           = buf_dup(c->subject, a);
    c->not_before        = buf_dup(c->not_before, a);
    c->not_after         = buf_dup(c->not_after, a);
    c->spki_alg_oid      = buf_dup(c->spki_alg_oid, a);
    c->spki_key          = buf_dup(c->spki_key, a);
    c->sig_alg_oid_outer = buf_dup(c->sig_alg_oid_outer, a);
    c->signature         = buf_dup(c->signature, a);
    for (int i = 0; i < c->ext_count; i++) {
        c->exts[i].oid   = buf_dup(c->exts[i].oid, a);
        c->exts[i].value = buf_dup(c->exts[i].value, a);
    }
}

bool
n00b_x509_trust_store_add(n00b_x509_trust_store_t *store, n00b_buffer_t *der)
{
    if (store == nullptr) {
        return false;
    }
    n00b_x509_cert_result_t r = n00b_x509_cert_from_der(der);
    if (!r.ok) {
        return false;
    }
    n00b_allocator_t *a = store->allocator;
    n00b_x509_cert_t *c;
    if (a != nullptr) {
        c = n00b_alloc_with_opts(n00b_x509_cert_t,
                                 &(n00b_alloc_opts_t){.allocator = a});
    }
    else {
        c = n00b_alloc(n00b_x509_cert_t);
    }
    *c = r.cert;
    dup_cert_buffers(c, a);
    n00b_list_push(store->anchors, c);
    return true;
}

static n00b_x509_cert_t *
find_anchor(n00b_x509_trust_store_t *store, n00b_buffer_t *subject_dn)
{
    int64_t n = n00b_list_len(store->anchors);
    for (int64_t i = 0; i < n; i++) {
        n00b_x509_cert_t *c = n00b_list_get(store->anchors, i);
        if (buf_eq(c->subject, subject_dn)) {
            return c;
        }
    }
    return nullptr;
}

/* days since 1970-01-01 for a proleptic-Gregorian y/m/d (Hinnant). */
static int64_t
days_from_civil(int64_t y, int64_t m, int64_t d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int64_t
read_digits(n00b_buffer_t *b, int64_t off, int count)
{
    int64_t v = 0;
    for (int i = 0; i < count; i++) {
        n00b_result_t(uint8_t) r = n00b_buffer_get_index(b, off + i);
        if (!n00b_result_is_ok(r)) {
            return -1;
        }
        uint8_t c = n00b_result_get(r);
        if (c < '0' || c > '9') {
            return -1;
        }
        v = v * 10 + (int64_t)(c - '0');
    }
    return v;
}

/* UTCTime (tag 23, "YYMMDDHHMMSSZ") / GeneralizedTime (tag 24,
 * "YYYYMMDDHHMMSSZ") -> Unix epoch seconds. */
static bool
cert_time_epoch(n00b_buffer_t *t, uint8_t tag, int64_t *out)
{
    if (t == nullptr) {
        return false;
    }
    int64_t len = (int64_t)n00b_buffer_len(t);
    int64_t y;
    int64_t off;
    if (tag == 23) {
        if (len < 13) {
            return false;
        }
        int64_t yy = read_digits(t, 0, 2);
        if (yy < 0) {
            return false;
        }
        y   = (yy < 50) ? 2000 + yy : 1900 + yy; /* RFC 5280 sliding window */
        off = 2;
    }
    else if (tag == 24) {
        if (len < 15) {
            return false;
        }
        y   = read_digits(t, 0, 4);
        off = 4;
    }
    else {
        return false;
    }
    int64_t mo = read_digits(t, off, 2);
    int64_t d  = read_digits(t, off + 2, 2);
    int64_t h  = read_digits(t, off + 4, 2);
    int64_t mi = read_digits(t, off + 6, 2);
    int64_t s  = read_digits(t, off + 8, 2);
    if (y < 0 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || mi < 0
        || s < 0) {
        return false;
    }
    *out = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
    return true;
}

bool
n00b_x509_validity_epochs(const n00b_x509_cert_t *cert, int64_t *not_before,
                          int64_t *not_after)
{
    return cert_time_epoch(cert->not_before, cert->not_before_tag, not_before)
           && cert_time_epoch(cert->not_after, cert->not_after_tag, not_after);
}

static bool
cert_is_ca(const n00b_x509_cert_t *c)
{
    bool ca = false;
    n00b_x509_basic_constraints(c, &ca, nullptr);
    return ca;
}

static bool
within_validity(const n00b_x509_cert_t *c, int64_t now)
{
    int64_t nb;
    int64_t na;
    if (!n00b_x509_validity_epochs(c, &nb, &na)) {
        return false;
    }
    return now >= nb && now <= na;
}

n00b_x509_verdict_t
n00b_x509_verify_chain(n00b_x509_cert_t **chain, int chain_len,
                       n00b_x509_trust_store_t *store, int64_t now_unix)
{
    if (chain == nullptr || chain_len < 1 || store == nullptr) {
        return N00B_X509_E_CHAIN;
    }

    for (int i = 0; i < chain_len; i++) {
        if (!within_validity(chain[i], now_unix)) {
            return N00B_X509_E_EXPIRED;
        }
    }

    /* leaf -> intermediates: each issuer is the next cert. */
    for (int i = 0; i < chain_len - 1; i++) {
        n00b_x509_cert_t *issuer = chain[i + 1];
        if (!cert_is_ca(issuer)) {
            return N00B_X509_E_NOT_CA;
        }
        if (!buf_eq(chain[i]->issuer, issuer->subject)) {
            return N00B_X509_E_CHAIN;
        }
        if (!n00b_x509_verify_signature(chain[i], issuer)) {
            return N00B_X509_E_SIG;
        }
    }

    /* top of the presented chain must be issued by a trust anchor. */
    n00b_x509_cert_t *top    = chain[chain_len - 1];
    n00b_x509_cert_t *anchor = find_anchor(store, top->issuer);
    if (anchor == nullptr) {
        return N00B_X509_E_UNTRUSTED;
    }
    if (!cert_is_ca(anchor)) {
        return N00B_X509_E_NOT_CA;
    }
    if (!within_validity(anchor, now_unix)) {
        return N00B_X509_E_EXPIRED;
    }
    if (!n00b_x509_verify_signature(top, anchor)) {
        return N00B_X509_E_SIG;
    }
    return N00B_X509_OK;
}
