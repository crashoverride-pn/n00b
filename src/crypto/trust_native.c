/*
 * trust_native.c — native (libc-free) trust backend for n00b-worker egress.
 *
 * Verifies a peer TLS certificate chain entirely with the in-tree X.509
 * verifier (crypto/x509.h): DER parse, RFC 6125 hostname match, per-link
 * signature (RSA PKCS#1v1.5 / ECDSA P-256 / P-384), validity windows,
 * BasicConstraints CA-ness, and termination at a trust anchor. No
 * Security.framework / SecTrust, no OpenSSL, no libc allocation — so unlike the
 * "system" backend it is safe to run on an n00b worker thread (which is not a
 * pthread and traps on libsystem_malloc).
 *
 * Default anchors: the full publicly-trusted root store in
 * pki/crayon-egress-roots.pem (the build host's Apple System Roots — Let's
 * Encrypt, GTS, DigiCert, etc.; provenance in that file), embedded at build
 * time and cached after parsing. n00b_quic_trust_native_anchors() replaces
 * them with a caller-supplied set (e.g. a self-signed endpoint).
 */

#define N00B_USE_INTERNAL_API
#include "n00b.h"

#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/time.h"
#include "adt/list.h"
#include "net/quic/quic_types.h"
#include "crypto/trust.h"
#include "crypto/x509.h"
#include "internal/crypto/trust_internal.h"
#include "internal/crypto/cert_provisioner_common.h"
#include "crayon_egress_roots.h"

typedef struct {
    n00b_x509_trust_store_t     *store;
    n00b_list_t(n00b_buffer_t *) anchor_ders; /* for exact-cert pinning */
} native_state_t;

/* ---- chain verification (the vtable hot path) ---------------------------- */

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

/* The leaf is an exact-match for a configured anchor: the operator pinned this
 * precise certificate (e.g. a self-signed endpoint). Trust it directly without
 * requiring CA:TRUE or chain building — the pin IS the identity. */
static bool
leaf_is_pinned_anchor(native_state_t *st, n00b_buffer_t *leaf_der)
{
    int64_t n = n00b_list_len(st->anchor_ders);
    for (int64_t i = 0; i < n; i++) {
        if (buf_eq(n00b_list_get(st->anchor_ders, i), leaf_der)) {
            return true;
        }
    }
    return false;
}

static int
native_verify(void           *state,
              const uint8_t **chain_der,
              const size_t   *chain_lens,
              size_t          count,
              const char     *sni)
{
    native_state_t *st = state;
    if (!st || !st->store || !chain_der || !chain_lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* parse every presented DER cert; any malformed cert => reject. */
    n00b_x509_cert_t **chain = n00b_alloc_array(n00b_x509_cert_t *,
                                                (int64_t)count);
    n00b_buffer_t     *leaf_der = nullptr;
    for (size_t i = 0; i < count; i++) {
        if (!chain_der[i] || chain_lens[i] == 0) {
            return N00B_QUIC_ERR_TRUST_REJECTED;
        }
        n00b_buffer_t *der = n00b_buffer_from_bytes((char *)chain_der[i],
                                                    (int64_t)chain_lens[i]);
        if (i == 0) {
            leaf_der = der;
        }
        n00b_x509_cert_result_t cr = n00b_x509_cert_from_der(der);
        if (!cr.ok) {
            return N00B_QUIC_ERR_TRUST_REJECTED;
        }
        n00b_x509_cert_t *c = n00b_alloc(n00b_x509_cert_t);
        *c       = cr.cert;
        chain[i] = c;
    }

    /* Exact-cert pin: operator explicitly trusts this precise leaf. */
    if (leaf_is_pinned_anchor(st, leaf_der)) {
        return N00B_QUIC_OK;
    }

    /* RFC 6125 hostname match against the leaf when an SNI was offered. */
    if (sni != nullptr && sni[0] != '\0') {
        n00b_string_t *host = n00b_string_from_cstr(sni);
        if (!n00b_x509_host_matches(chain[0], host)) {
            return N00B_QUIC_ERR_TRUST_REJECTED;
        }
    }

    int64_t now = n00b_us_timestamp() / N00B_USEC_PER_SEC;
    n00b_x509_verdict_t v = n00b_x509_verify_chain(chain, (int)count,
                                                   st->store, now);
    return (v == N00B_X509_OK) ? N00B_QUIC_OK : N00B_QUIC_ERR_TRUST_REJECTED;
}

static const n00b_quic_trust_vtbl_t native_vtbl = {
    .verify_chain = native_verify,
    .finalize     = nullptr, /* GC owns the store + its anchors */
    .name         = "native",
};

/* ---- anchor loading ------------------------------------------------------ */

/* Parse a PEM bundle into a populated native_state_t (trust store + the anchor
 * DER list used for exact-cert pinning). Allocated from the conduit pool. */
static native_state_t *
state_from_pem(n00b_buffer_t *pem, int *err_out)
{
    n00b_result_t(n00b_list_t(n00b_buffer_t *)) pr =
        n00b_certp_pem_all_certs_to_der(pem);
    if (n00b_result_is_err(pr)) {
        *err_out = n00b_result_get_err(pr);
        return nullptr;
    }
    n00b_list_t(n00b_buffer_t *) ders = n00b_result_get(pr);

    /* The store is referenced from the conduit_pool native_state (and via the
     * trust handle that picoquic holds by raw pointer), which the GC does not
     * trace; build it — and its deep-copied anchors — in conduit_pool too so
     * nothing is reclaimed/moved out from under those references. */
    n00b_allocator_t *cp =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    n00b_x509_trust_store_t *store = n00b_x509_trust_store_new(.allocator = cp);
    int64_t                  n     = n00b_list_len(ders);
    int64_t                  added = 0;
    for (int64_t i = 0; i < n; i++) {
        n00b_buffer_t *der = n00b_list_get(ders, i);
        if (der != nullptr && n00b_x509_trust_store_add(store, der)) {
            added++;
        }
    }
    if (added == 0) {
        *err_out = N00B_QUIC_ERR_PROTOCOL;
        return nullptr;
    }

    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
    native_state_t *ns = n00b_alloc_with_opts(native_state_t,
                             &(n00b_alloc_opts_t){.allocator = alloc});
    ns->store       = store;
    ns->anchor_ders = ders;

    *err_out = N00B_QUIC_OK;
    return ns;
}

/* Cached default anchor state + a once-mutex (mirrors src/crypto/x509_parse.c). */
static native_state_t *s_default_state       = nullptr;
static n00b_mutex_t    s_default_mutex;
static _Atomic int     s_default_mutex_state = 0;

static void
ensure_default_mutex(void)
{
    if (n00b_atomic_load(&s_default_mutex_state) == 2) {
        return;
    }
    int expected = 0;
    if (n00b_atomic_cas(&s_default_mutex_state, &expected, 1)) {
        n00b_sys_mutex_init(&s_default_mutex, (char *)__FILE__);
        n00b_atomic_store(&s_default_mutex_state, 2);
        return;
    }
    while (n00b_atomic_load(&s_default_mutex_state) != 2) {
        ; /* brief spin until the elected initializer publishes */
    }
}

static native_state_t *
load_default_state(int *err_out)
{
    ensure_default_mutex();
    n00b_mutex_lock(&s_default_mutex);

    if (s_default_state == nullptr) {
        n00b_buffer_t *pem = n00b_buffer_from_bytes(
            (char *)N00B_CRAYON_EGRESS_ROOTS_PEM,
            sizeof(N00B_CRAYON_EGRESS_ROOTS_PEM) - 1);
        int             e  = N00B_QUIC_OK;
        native_state_t *st = state_from_pem(pem, &e);
        if (st == nullptr) {
            n00b_mutex_unlock(&s_default_mutex);
            *err_out = e;
            return nullptr;
        }
        s_default_state = st;
    }

    native_state_t *st = s_default_state;
    n00b_mutex_unlock(&s_default_mutex);
    *err_out = N00B_QUIC_OK;
    return st;
}

/* ---- public constructors ------------------------------------------------- */

static n00b_quic_trust_t *
make_handle(native_state_t *ns)
{
    n00b_allocator_t *alloc =
        (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    n00b_quic_trust_t *t = n00b_alloc_with_opts(n00b_quic_trust_t,
                               &(n00b_alloc_opts_t){.allocator = alloc});
    t->vtbl          = &native_vtbl;
    t->backend_state = ns;
    t->purpose       = N00B_QUIC_TRUST_SERVER_AUTH;
    t->closed        = false;
    return t;
}

n00b_result_t(n00b_quic_trust_t *)
n00b_quic_trust_native(void)
{
    int             err = N00B_QUIC_OK;
    native_state_t *ns  = load_default_state(&err);
    if (ns == nullptr) {
        return n00b_result_err(n00b_quic_trust_t *, err);
    }
    return n00b_result_ok(n00b_quic_trust_t *, make_handle(ns));
}

n00b_result_t(n00b_quic_trust_t *)
n00b_quic_trust_native_anchors(n00b_buffer_t *anchors_pem)
{
    if (!anchors_pem || !anchors_pem->data || anchors_pem->byte_len == 0) {
        return n00b_result_err(n00b_quic_trust_t *, N00B_QUIC_ERR_NULL_ARG);
    }
    int             err = N00B_QUIC_OK;
    native_state_t *ns  = state_from_pem(anchors_pem, &err);
    if (ns == nullptr) {
        return n00b_result_err(n00b_quic_trust_t *, err);
    }
    return n00b_result_ok(n00b_quic_trust_t *, make_handle(ns));
}
