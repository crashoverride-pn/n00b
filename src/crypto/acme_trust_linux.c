/*
 * acme_trust_linux.c — Linux OS trust integration for the ACME HTTPS
 * shim.  Built only when target_os == 'linux'.
 *
 * Loads libssl/libcrypto at runtime via dlopen so n00b's build does
 * not pick up a hard build-time dependency on OpenSSL.  Distros that
 * do not ship libssl produce a clean
 * `N00B_QUIC_ERR_NOT_IMPLEMENTED` from the verify path; everything
 * else (the QUIC transport, picotls, picoquic) keeps working.
 *
 * The dynamic-resolution shape is the same trick OpenSSH uses to
 * support multiple libssl ABIs without a ton of build-time
 * configuration.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/mutex.h"
// The X509** arrays below are our-owned (we free them ourselves; OpenSSL only
// frees the individual elements via X509_free), so they are n00b-managed via
// the user pool (free-by-pointer, non-moving) instead of libc malloc. On Linux
// the strong-symbol interpose already routes here; this makes it explicit.
#include "core/alloc_interpose.h"
#include "net/quic/quic_types.h"
#include "internal/crypto/trust_system.h"

/* Opaque libssl/libcrypto types. */
typedef struct ossl_X509             X509;
typedef struct ossl_X509_STORE       X509_STORE;
typedef struct ossl_X509_STORE_CTX   X509_STORE_CTX;
typedef struct ossl_X509_VERIFY_PARAM X509_VERIFY_PARAM;
typedef struct ossl_OPENSSL_STACK    OPENSSL_STACK;

#define X509_V_FLAG_TRUSTED_FIRST 0x8000

typedef struct {
    void *handle_crypto;
    void *handle_ssl;

    X509 *(*d2i_X509)(X509 **, const unsigned char **, long);
    void  (*X509_free)(X509 *);

    X509_STORE *(*X509_STORE_new)(void);
    void        (*X509_STORE_free)(X509_STORE *);
    int         (*X509_STORE_set_default_paths)(X509_STORE *);
    int         (*X509_STORE_add_cert)(X509_STORE *, X509 *);

    X509_STORE_CTX *(*X509_STORE_CTX_new)(void);
    void            (*X509_STORE_CTX_free)(X509_STORE_CTX *);
    int             (*X509_STORE_CTX_init)(X509_STORE_CTX *, X509_STORE *,
                                           X509 *, OPENSSL_STACK *);
    X509_VERIFY_PARAM *(*X509_STORE_CTX_get0_param)(X509_STORE_CTX *);

    int (*X509_VERIFY_PARAM_set1_host)(X509_VERIFY_PARAM *, const char *,
                                       size_t);
    int (*X509_VERIFY_PARAM_set_flags)(X509_VERIFY_PARAM *, unsigned long);

    int (*X509_verify_cert)(X509_STORE_CTX *);

    OPENSSL_STACK *(*OPENSSL_sk_new_null)(void);
    int            (*OPENSSL_sk_push)(OPENSSL_STACK *, const void *);
    void           (*OPENSSL_sk_free)(OPENSSL_STACK *);
} ossl_t;

static ossl_t          g_ossl;
static int             g_ossl_loaded = 0;     /* 0 = unattempted, 1 = good, -1 = failed */
/* Lazy-initialized n00b_mutex (atomic-flag-guarded).  All callers
 * are post-runtime; no pre-`n00b_init` access. */
static n00b_mutex_t     g_ossl_mu;
static _Atomic uint32_t g_ossl_mu_inited;

static void
ensure_g_ossl_mu(void)
{
    uint32_t state = atomic_load(&g_ossl_mu_inited);
    if (state == 2) return;
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong(&g_ossl_mu_inited, &expected, 1)) {
        n00b_mutex_init(&g_ossl_mu);
        atomic_store(&g_ossl_mu_inited, 2);
        return;
    }
    while (atomic_load(&g_ossl_mu_inited) != 2) { /* tight spin */ }
}

#define LOAD_SYM(handle, sym)                                                  \
    do {                                                                       \
        g_ossl.sym = dlsym((handle), #sym);                                    \
        if (!g_ossl.sym) {                                                     \
            goto fail;                                                         \
        }                                                                      \
    } while (0)

static int
load_libssl(void)
{
    ensure_g_ossl_mu(); n00b_mutex_lock(&g_ossl_mu);
    if (g_ossl_loaded != 0) {
        int v = g_ossl_loaded;
        n00b_mutex_unlock(&g_ossl_mu);
        return v;
    }

    /* Prefer libssl 3, fall back to 1.1.  Most modern distros ship 3. */
    static const char *crypto_names[] = {"libcrypto.so.3", "libcrypto.so.1.1",
                                         "libcrypto.so", nullptr};
    static const char *ssl_names[]    = {"libssl.so.3", "libssl.so.1.1",
                                         "libssl.so", nullptr};

    void *crypto = nullptr;
    void *ssl    = nullptr;
    for (int i = 0; crypto_names[i]; i++) {
        crypto = dlopen(crypto_names[i], RTLD_NOW | RTLD_GLOBAL);
        if (crypto) {
            break;
        }
    }
    for (int i = 0; ssl_names[i]; i++) {
        ssl = dlopen(ssl_names[i], RTLD_NOW | RTLD_GLOBAL);
        if (ssl) {
            break;
        }
    }
    if (!crypto || !ssl) {
        goto fail;
    }
    g_ossl.handle_crypto = crypto;
    g_ossl.handle_ssl    = ssl;

    LOAD_SYM(crypto, d2i_X509);
    LOAD_SYM(crypto, X509_free);
    LOAD_SYM(crypto, X509_STORE_new);
    LOAD_SYM(crypto, X509_STORE_free);
    LOAD_SYM(crypto, X509_STORE_set_default_paths);
    LOAD_SYM(crypto, X509_STORE_add_cert);
    LOAD_SYM(crypto, X509_STORE_CTX_new);
    LOAD_SYM(crypto, X509_STORE_CTX_free);
    LOAD_SYM(crypto, X509_STORE_CTX_init);
    LOAD_SYM(crypto, X509_STORE_CTX_get0_param);
    LOAD_SYM(crypto, X509_VERIFY_PARAM_set1_host);
    LOAD_SYM(crypto, X509_VERIFY_PARAM_set_flags);
    LOAD_SYM(crypto, X509_verify_cert);
    LOAD_SYM(crypto, OPENSSL_sk_new_null);
    LOAD_SYM(crypto, OPENSSL_sk_push);
    LOAD_SYM(crypto, OPENSSL_sk_free);

    g_ossl_loaded = 1;
    n00b_mutex_unlock(&g_ossl_mu);
    return 1;

fail:
    if (crypto) {
        dlclose(crypto);
    }
    if (ssl) {
        dlclose(ssl);
    }
    memset(&g_ossl, 0, sizeof(g_ossl));
    g_ossl_loaded = -1;
    n00b_mutex_unlock(&g_ossl_mu);
    return -1;
}

int
n00b_quic_trust_system_verify_chain(const uint8_t **certs,
                             const size_t   *lens,
                             size_t          count,
                             const char     *sni)
{
    if (!certs || !lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (load_libssl() != 1) {
        return N00B_QUIC_ERR_NOT_IMPLEMENTED;
    }

    int             rc      = N00B_QUIC_ERR_TRUST_REJECTED;
    X509           *leaf    = nullptr;
    X509          **interms = nullptr;
    OPENSSL_STACK  *stack   = nullptr;
    X509_STORE     *store   = nullptr;
    X509_STORE_CTX *ctx     = nullptr;

    /* Parse leaf. */
    {
        const unsigned char *p = certs[0];
        leaf = g_ossl.d2i_X509(nullptr, &p, (long)lens[0]);
        if (!leaf) {
            return N00B_QUIC_ERR_TRUST_REJECTED;
        }
    }

    /* Parse intermediates and push onto a stack. */
    if (count > 1) {
        /* Our-owned array of (OpenSSL-owned) X509* pointers: we push the
         * elements onto a stack (OPENSSL_sk_push), but the storage array itself
         * is freed by us below (sk_free does not free elements; we X509_free
         * each, then free the array). So it is n00b-managed via the user pool. */
        interms = (X509 **)n00b_interposed_calloc(count - 1, sizeof(X509 *));
        if (!interms) {
            goto cleanup;
        }
        stack = g_ossl.OPENSSL_sk_new_null();
        if (!stack) {
            goto cleanup;
        }
        for (size_t i = 1; i < count; i++) {
            const unsigned char *p = certs[i];
            X509 *x                = g_ossl.d2i_X509(nullptr, &p, (long)lens[i]);
            if (!x) {
                goto cleanup;
            }
            interms[i - 1] = x;
            g_ossl.OPENSSL_sk_push(stack, x);
        }
    }

    store = g_ossl.X509_STORE_new();
    if (!store || !g_ossl.X509_STORE_set_default_paths(store)) {
        goto cleanup;
    }

    ctx = g_ossl.X509_STORE_CTX_new();
    if (!ctx || !g_ossl.X509_STORE_CTX_init(ctx, store, leaf, stack)) {
        goto cleanup;
    }

    if (sni) {
        X509_VERIFY_PARAM *param = g_ossl.X509_STORE_CTX_get0_param(ctx);
        if (param) {
            g_ossl.X509_VERIFY_PARAM_set1_host(param, sni, strlen(sni));
            g_ossl.X509_VERIFY_PARAM_set_flags(param,
                                               X509_V_FLAG_TRUSTED_FIRST);
        }
    }

    rc = (g_ossl.X509_verify_cert(ctx) == 1) ? N00B_QUIC_OK
                                              : N00B_QUIC_ERR_TRUST_REJECTED;

cleanup:
    if (ctx) {
        g_ossl.X509_STORE_CTX_free(ctx);
    }
    if (store) {
        g_ossl.X509_STORE_free(store);
    }
    if (stack) {
        g_ossl.OPENSSL_sk_free(stack);
    }
    if (interms) {
        for (size_t i = 0; i + 1 < count; i++) {
            if (interms[i]) {
                g_ossl.X509_free(interms[i]);
            }
        }
        n00b_interposed_free(interms);
    }
    if (leaf) {
        g_ossl.X509_free(leaf);
    }
    return rc;
}

int
n00b_quic_trust_system_verify_chain_ex(const uint8_t **certs,
                                       const size_t   *lens,
                                       size_t          count,
                                       const char     *sni,
                                       const uint8_t **extras_der,
                                       const size_t   *extras_lens,
                                       size_t          extras_count)
{
    if (extras_count == 0 || !extras_der || !extras_lens) {
        return n00b_quic_trust_system_verify_chain(certs, lens, count, sni);
    }
    if (!certs || !lens || count == 0) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (load_libssl() != 1) {
        return N00B_QUIC_ERR_NOT_IMPLEMENTED;
    }

    int             rc            = N00B_QUIC_ERR_TRUST_REJECTED;
    X509           *leaf          = nullptr;
    X509          **interms       = nullptr;
    X509          **extra_x509s   = nullptr;
    OPENSSL_STACK  *stack         = nullptr;
    X509_STORE     *store         = nullptr;
    X509_STORE_CTX *ctx           = nullptr;

    {
        const unsigned char *p = certs[0];
        leaf = g_ossl.d2i_X509(nullptr, &p, (long)lens[0]);
        if (!leaf) {
            return N00B_QUIC_ERR_TRUST_REJECTED;
        }
    }

    if (count > 1) {
        interms = (X509 **)n00b_interposed_calloc(count - 1, sizeof(X509 *));
        if (!interms) goto cleanup;
        stack = g_ossl.OPENSSL_sk_new_null();
        if (!stack)   goto cleanup;
        for (size_t i = 1; i < count; i++) {
            const unsigned char *p = certs[i];
            X509 *x = g_ossl.d2i_X509(nullptr, &p, (long)lens[i]);
            if (!x) goto cleanup;
            interms[i - 1] = x;
            g_ossl.OPENSSL_sk_push(stack, x);
        }
    }

    store = g_ossl.X509_STORE_new();
    if (!store || !g_ossl.X509_STORE_set_default_paths(store)) {
        goto cleanup;
    }

    /* Layer in the additional trust anchors. */
    extra_x509s = (X509 **)n00b_interposed_calloc(extras_count, sizeof(X509 *));
    if (!extra_x509s) goto cleanup;
    for (size_t i = 0; i < extras_count; i++) {
        const unsigned char *p = extras_der[i];
        X509 *x = g_ossl.d2i_X509(nullptr, &p, (long)extras_lens[i]);
        if (!x) goto cleanup;
        extra_x509s[i] = x;
        /* X509_STORE_add_cert increments the refcount; we keep our
         * reference until cleanup and the store's reference stays
         * alive through X509_STORE_free. */
        if (g_ossl.X509_STORE_add_cert(store, x) != 1) {
            goto cleanup;
        }
    }

    ctx = g_ossl.X509_STORE_CTX_new();
    if (!ctx || !g_ossl.X509_STORE_CTX_init(ctx, store, leaf, stack)) {
        goto cleanup;
    }

    if (sni) {
        X509_VERIFY_PARAM *param = g_ossl.X509_STORE_CTX_get0_param(ctx);
        if (param) {
            g_ossl.X509_VERIFY_PARAM_set1_host(param, sni, strlen(sni));
            g_ossl.X509_VERIFY_PARAM_set_flags(param,
                                               X509_V_FLAG_TRUSTED_FIRST);
        }
    }

    rc = (g_ossl.X509_verify_cert(ctx) == 1) ? N00B_QUIC_OK
                                              : N00B_QUIC_ERR_TRUST_REJECTED;

cleanup:
    if (ctx)   g_ossl.X509_STORE_CTX_free(ctx);
    if (store) g_ossl.X509_STORE_free(store);
    if (stack) g_ossl.OPENSSL_sk_free(stack);
    if (extra_x509s) {
        for (size_t i = 0; i < extras_count; i++) {
            if (extra_x509s[i]) g_ossl.X509_free(extra_x509s[i]);
        }
        n00b_interposed_free(extra_x509s);
    }
    if (interms) {
        for (size_t i = 0; i + 1 < count; i++) {
            if (interms[i]) g_ossl.X509_free(interms[i]);
        }
        n00b_interposed_free(interms);
    }
    if (leaf) g_ossl.X509_free(leaf);
    return rc;
}
