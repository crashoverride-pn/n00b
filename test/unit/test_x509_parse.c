/*
 * test_x509_parse.c — DER -> typed cert end-to-end (WP-042 Phase 1).
 *
 * Loads the committed PEM fixture cert, wraps the DER in an n00b_buffer, and
 * walks it into n00b_x509_cert_t. Asserts the extracted fields against openssl's
 * values (v1; serial AC6D74C811A0F556; self-signed CN=n00b-attest test fixture;
 * RSA-2048; sha256WithRSA; 2026-05-21 -> 2027-05-21).
 *
 * Needs workdir: meson.project_source_root() for the relative PEM + grammar path.
 */

#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"

#include "picotls.h"
#include "picotls/pembase64.h"
#include "crypto/x509.h"

static const char k_cert_pem_path[] = "test/unit/data/pkcs7_fixture_cert.pem";
static const char k_ext_pem_path[]  = "test/unit/data/x509_ext_fixture_cert.pem";
static const char k_wild_pem_path[] = "test/unit/data/x509_wild_fixture_cert.pem";
static const char k_ecp256_pem_path[] = "test/unit/data/x509_ecp256_fixture_cert.pem";
static const char k_chain_ca_path[]   = "test/unit/data/x509_chain_ca.pem";
static const char k_chain_leaf_path[] = "test/unit/data/x509_chain_leaf.pem";

static ptls_iovec_t
load_pem(const char *path, const char *label)
{
    ptls_iovec_t vec = {0};
    size_t       n   = 0;
    int          rc  = ptls_load_pem_objects(path, label, &vec, 1, &n);
    if (rc != 0 || n == 0) {
        fprintf(stderr, "ptls_load_pem_objects(%s,%s) rc=%d n=%zu (run from src root)\n",
                path, label, rc, n);
        assert(0);
    }
    return vec;
}

/* exact buffer equality via the buffer API (no memcmp). */
static bool
beq(n00b_buffer_t *a, n00b_buffer_t *b)
{
    if (a == NULL || b == NULL) {
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

static bool
eq_bytes(n00b_buffer_t *got, char *exp, int64_t len)
{
    return beq(got, n00b_buffer_from_bytes(exp, len));
}

static bool
eq_str(n00b_buffer_t *got, const char *s)
{
    return beq(got, n00b_buffer_from_cstr(s));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    ptls_iovec_t pem = load_pem(k_cert_pem_path, "CERTIFICATE");
    assert(pem.base != NULL && pem.len > 0);
    n00b_buffer_t *der = n00b_buffer_from_bytes((char *)pem.base, (int64_t)pem.len);
    fprintf(stderr, "[x509-parse] fixture cert: %lld DER bytes\n",
            (long long)n00b_buffer_len(der));

    n00b_x509_cert_result_t cr = n00b_x509_cert_from_der(der);
    if (!cr.ok) {
        fprintf(stderr, "[x509-parse] FAILED: %.*s\n",
                (int)(cr.error ? cr.error->u8_bytes : 0),
                cr.error ? (char *)cr.error->data : "");
        assert(0);
    }
    n00b_x509_cert_t *c = &cr.cert;

    assert(c->version == 0); /* v1 */

    char serial[] = {0x00, (char)0xac, 0x6d, 0x74, (char)0xc8, 0x11, (char)0xa0, (char)0xf5, 0x56};
    assert(eq_bytes(c->serial, serial, sizeof(serial)));

    char sha256rsa[] = {0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x0d, 0x01, 0x01, 0x0b};
    assert(eq_bytes(c->sig_alg_oid, sha256rsa, sizeof(sha256rsa)));
    assert(eq_bytes(c->sig_alg_oid_outer, sha256rsa, sizeof(sha256rsa)));

    assert(c->not_before_tag == 23 && eq_str(c->not_before, "260521213049Z"));
    assert(c->not_after_tag == 23 && eq_str(c->not_after, "270521213049Z"));

    /* self-signed: issuer DN == subject DN */
    assert(beq(c->issuer, c->subject));
    assert(c->issuer != NULL && n00b_buffer_len(c->issuer) > 0);

    char rsaenc[] = {0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x0d, 0x01, 0x01, 0x01};
    assert(eq_bytes(c->spki_alg_oid, rsaenc, sizeof(rsaenc)));
    assert(c->spki_key != NULL && n00b_buffer_len(c->spki_key) == 271);

    assert(c->signature != NULL && n00b_buffer_len(c->signature) == 257);

    assert(c->tbs != NULL && n00b_buffer_len(c->tbs) > 0);
    n00b_result_t(uint8_t) b0 = n00b_buffer_get_index(c->tbs, 0);
    assert(n00b_result_is_ok(b0) && n00b_result_get(b0) == 0x30); /* SEQUENCE */

    printf("[x509-parse] typed cert fields match openssl — OK\n");

    /* v3 cert with extensions: SAN, BasicConstraints(crit), KeyUsage(crit), EKU. */
    ptls_iovec_t epem = load_pem(k_ext_pem_path, "CERTIFICATE");
    n00b_buffer_t *eder = n00b_buffer_from_bytes((char *)epem.base,
                                                 (int64_t)epem.len);
    n00b_x509_cert_result_t er = n00b_x509_cert_from_der(eder);
    if (!er.ok) {
        fprintf(stderr, "[x509-parse] EXT cert FAILED: %.*s\n",
                (int)(er.error ? er.error->u8_bytes : 0),
                er.error ? (char *)er.error->data : "");
        assert(0);
    }
    n00b_x509_cert_t *ec = &er.cert;
    assert(ec->version == 2); /* v3 (encoded value 2) */
    assert(ec->ext_count == 4);

    char san_oid[] = {0x55, 0x1d, 0x11};
    char bc_oid[]  = {0x55, 0x1d, 0x13};
    char ku_oid[]  = {0x55, 0x1d, 0x0f};
    char eku_oid[] = {0x55, 0x1d, 0x25};

    const n00b_x509_ext_t *san = n00b_x509_find_ext(ec, n00b_buffer_from_bytes(san_oid, 3));
    const n00b_x509_ext_t *bc  = n00b_x509_find_ext(ec, n00b_buffer_from_bytes(bc_oid, 3));
    const n00b_x509_ext_t *ku  = n00b_x509_find_ext(ec, n00b_buffer_from_bytes(ku_oid, 3));
    const n00b_x509_ext_t *eku = n00b_x509_find_ext(ec, n00b_buffer_from_bytes(eku_oid, 3));
    assert(san && bc && ku && eku);
    assert(!san->critical && bc->critical && ku->critical && !eku->critical);
    assert(n00b_buffer_len(san->value) > 0 && n00b_buffer_len(bc->value) > 0);

    /* decode SAN dNSNames + BasicConstraints from the nested extnValue DER */
    n00b_list_t(n00b_string_t *) dns = n00b_x509_san_dns(ec);
    assert(n00b_list_len(dns) == 2);
    bool seen_ext = false, seen_www = false;
    for (int64_t di = 0; di < n00b_list_len(dns); di++) {
        n00b_string_t *s  = n00b_list_get(dns, di);
        n00b_buffer_t *sb = n00b_buffer_from_bytes(s->data, (int64_t)s->u8_bytes);
        if (beq(sb, n00b_buffer_from_cstr("ext.example.com"))) {
            seen_ext = true;
        }
        if (beq(sb, n00b_buffer_from_cstr("www.ext.example.com"))) {
            seen_www = true;
        }
    }
    assert(seen_ext && seen_www);

    bool    is_ca   = true;
    int64_t pathlen = 99;
    assert(n00b_x509_basic_constraints(ec, &is_ca, &pathlen));
    assert(is_ca == false);   /* CA:FALSE */
    assert(pathlen == -1);    /* no pathLenConstraint */

    printf("[x509-parse] v3 extensions + SAN dNSNames + BasicConstraints decoded — OK\n");

    /* hostname matching (RFC 6125). Exact SANs on the ext fixture: */
    assert(n00b_x509_host_matches(ec, n00b_string_from_cstr("ext.example.com")));
    assert(n00b_x509_host_matches(ec, n00b_string_from_cstr("ExT.Example.CoM")));
    assert(n00b_x509_host_matches(ec, n00b_string_from_cstr("www.ext.example.com")));
    assert(!n00b_x509_host_matches(ec, n00b_string_from_cstr("foo.ext.example.com")));
    assert(!n00b_x509_host_matches(ec, n00b_string_from_cstr("example.com")));
    assert(!n00b_x509_host_matches(ec, n00b_string_from_cstr("other.com")));

    /* wildcard SAN (*.wild.example.com) fixture: */
    ptls_iovec_t wpem = load_pem(k_wild_pem_path, "CERTIFICATE");
    n00b_buffer_t *wder = n00b_buffer_from_bytes((char *)wpem.base,
                                                 (int64_t)wpem.len);
    n00b_x509_cert_result_t wr = n00b_x509_cert_from_der(wder);
    assert(wr.ok);
    n00b_x509_cert_t *wc = &wr.cert;
    assert(n00b_x509_host_matches(wc, n00b_string_from_cstr("a.wild.example.com")));
    assert(n00b_x509_host_matches(wc, n00b_string_from_cstr("foo.wild.example.com")));
    assert(!n00b_x509_host_matches(wc, n00b_string_from_cstr("wild.example.com")));     /* needs a label */
    assert(!n00b_x509_host_matches(wc, n00b_string_from_cstr("a.b.wild.example.com"))); /* too many */
    assert(!n00b_x509_host_matches(wc, n00b_string_from_cstr("a.other.com")));

    printf("[x509-parse] RFC 6125 hostname matching (exact + wildcard) — OK\n");

    /* RSA signature verification: self-signed certs verify under their own key;
     * cross-pairs (wrong key) fail. */
    assert(n00b_x509_verify_signature(c, c));    /* v1 RSA self-signed */
    assert(n00b_x509_verify_signature(ec, ec));  /* v3 RSA self-signed */
    assert(!n00b_x509_verify_signature(ec, c));  /* wrong issuer key */
    assert(!n00b_x509_verify_signature(c, ec));  /* wrong issuer key */

    printf("[x509-parse] RSA signature verification (self-signed ok, wrong-key fails) — OK\n");

    /* ECDSA P-256 (ecdsa-with-SHA256) signature verification. */
    ptls_iovec_t ecpem = load_pem(k_ecp256_pem_path, "CERTIFICATE");
    n00b_buffer_t *ecder = n00b_buffer_from_bytes((char *)ecpem.base,
                                                  (int64_t)ecpem.len);
    n00b_x509_cert_result_t ecr = n00b_x509_cert_from_der(ecder);
    assert(ecr.ok);
    n00b_x509_cert_t *p256 = &ecr.cert;
    assert(n00b_x509_verify_signature(p256, p256));  /* self-signed P-256 */
    assert(!n00b_x509_verify_signature(p256, c));    /* wrong issuer key */
    assert(!n00b_x509_verify_signature(c, p256));    /* RSA child, EC issuer */

    printf("[x509-parse] ECDSA P-256 signature verification — OK\n");

    /* path validation: trust store = {CA}; chain = [leaf signed by CA]. */
    ptls_iovec_t capem = load_pem(k_chain_ca_path, "CERTIFICATE");
    n00b_buffer_t *cader = n00b_buffer_from_bytes((char *)capem.base,
                                                  (int64_t)capem.len);
    n00b_x509_trust_store_t *store = n00b_x509_trust_store_new();
    assert(n00b_x509_trust_store_add(store, cader));

    ptls_iovec_t lpem = load_pem(k_chain_leaf_path, "CERTIFICATE");
    n00b_buffer_t *lder = n00b_buffer_from_bytes((char *)lpem.base,
                                                 (int64_t)lpem.len);
    n00b_x509_cert_result_t lr = n00b_x509_cert_from_der(lder);
    assert(lr.ok);
    n00b_x509_cert_t *leaf = &lr.cert;
    n00b_x509_cert_t *chain[] = {leaf};

    int64_t nb = 0, na = 0;
    assert(n00b_x509_validity_epochs(leaf, &nb, &na));
    int64_t mid = nb + (na - nb) / 2;

    assert(n00b_x509_verify_chain(chain, 1, store, mid) == N00B_X509_OK);

    /* negatives */
    n00b_x509_trust_store_t *empty = n00b_x509_trust_store_new();
    assert(n00b_x509_verify_chain(chain, 1, empty, mid) == N00B_X509_E_UNTRUSTED);
    assert(n00b_x509_verify_chain(chain, 1, store, nb - 1) == N00B_X509_E_EXPIRED);
    assert(n00b_x509_verify_chain(chain, 1, store, na + 1) == N00B_X509_E_EXPIRED);

    /* wrong anchor (P-256 fixture as the only anchor): leaf issuer DN won't match */
    n00b_x509_trust_store_t *wrong = n00b_x509_trust_store_new();
    assert(n00b_x509_trust_store_add(wrong, ecder));
    assert(n00b_x509_verify_chain(chain, 1, wrong, mid) == N00B_X509_E_UNTRUSTED);

    printf("[x509-parse] path validation (anchor trust + validity + sig) — OK\n");
    return 0;
}
