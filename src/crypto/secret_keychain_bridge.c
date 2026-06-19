/*
 * secret_keychain_bridge.c — n00b vtable + n00b-type wrapping for the
 * macOS Keychain secret provider.
 *
 * The Security.framework boundary lives in `secret_keychain.m`; this
 * file is the n00b side and is compiled through ncc.  Together they
 * implement the `keychain:` URI scheme for `n00b_quic_secret_open`.
 */

#define N00B_USE_INTERNAL_API
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/secret_internal.h"
#include "internal/crypto/secret_keychain_raw.h"

typedef struct {
    void   *sec_key;        /* opaque SecKeyRef */
    uint8_t pub[64];        /* cached public key (X || Y) */
    int     have_pub;
} keychain_state_t;

static n00b_allocator_t *
keychain_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static int
kc_open(const char              *uri_rest,
        n00b_quic_secret_kind_t  hint_kind,
        void                   **state_out,
        n00b_quic_secret_kind_t *kind_out,
        n00b_string_t          **label_out)
{
    (void)hint_kind;
    if (!uri_rest || !*uri_rest) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    size_t label_len = strlen(uri_rest);
    void  *sec_key   = nullptr;
    int    rc        = n00b_keychain_open_raw(uri_rest, label_len, &sec_key);
    if (rc != N00B_QUIC_OK) {
        return rc;
    }

    keychain_state_t *st = n00b_alloc_with_opts(
        keychain_state_t,
        &(n00b_alloc_opts_t){.allocator = keychain_alloc()});
    st->sec_key  = sec_key;
    st->have_pub = 0;

    rc = n00b_keychain_pubkey_raw(sec_key, st->pub);
    if (rc != N00B_QUIC_OK) {
        n00b_keychain_close_raw(sec_key);
        return rc;
    }
    st->have_pub = 1;

    *state_out = st;
    *kind_out  = N00B_QUIC_SECRET_PRIVKEY;
    *label_out = n00b_string_from_raw(uri_rest, (int64_t)label_len);
    return N00B_QUIC_OK;
}

static int
kc_sign(void                 *state,
        const uint8_t        *data,
        size_t                data_len,
        n00b_quic_sig_alg_t   alg,
        n00b_buffer_t       **out_sig)
{
    keychain_state_t *st = state;
    if (!st || !st->sec_key) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }

    /* Stack buffer at the DER cap.  The Apple side fills it; we
     * then n00b_buffer_init into a fresh pool-allocated buffer.
     * No malloc/free crosses the boundary. */
    uint8_t scratch[N00B_KEYCHAIN_SIG_MAX];
    size_t  sig_len = 0;
    int     rc      = n00b_keychain_sign_raw(st->sec_key,
                                             data, data_len,
                                             scratch,
                                             N00B_KEYCHAIN_SIG_MAX,
                                             &sig_len);
    if (rc != N00B_QUIC_OK) {
        return rc;
    }

    n00b_buffer_t *out = n00b_alloc_with_opts(
        n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = keychain_alloc()});
    n00b_buffer_init(out,
                     .raw       = (char *)scratch,
                     .length    = (int64_t)sig_len,
                     .allocator = keychain_alloc());

    *out_sig = out;
    return N00B_QUIC_OK;
}

static int
kc_pubkey(void                 *state,
          n00b_quic_sig_alg_t   alg,
          n00b_buffer_t       **out_pub)
{
    keychain_state_t *st = state;
    if (!st) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (alg != N00B_QUIC_SIG_ECDSA_P256) {
        return N00B_QUIC_ERR_INVALID_ARG;
    }
    if (!st->have_pub) {
        int rc = n00b_keychain_pubkey_raw(st->sec_key, st->pub);
        if (rc != N00B_QUIC_OK) {
            return rc;
        }
        st->have_pub = 1;
    }
    n00b_buffer_t *out = n00b_alloc_with_opts(
        n00b_buffer_t,
        &(n00b_alloc_opts_t){.allocator = keychain_alloc()});
    n00b_buffer_init(out,
                     .raw       = (char *)st->pub,
                     .length    = 64,
                     .allocator = keychain_alloc());
    *out_pub = out;
    return N00B_QUIC_OK;
}

static int
kc_wrap(void           *state,
        const uint8_t  *data,
        size_t          data_len,
        n00b_buffer_t **out_wrapped)
{
    (void)state;
    (void)data;
    (void)data_len;
    (void)out_wrapped;
    return N00B_QUIC_ERR_NOT_IMPLEMENTED;
}

static void
kc_close(void *state)
{
    keychain_state_t *st = state;
    if (!st) return;
    if (st->sec_key) {
        n00b_keychain_close_raw(st->sec_key);
        st->sec_key = nullptr;
    }
    memset(st->pub, 0, sizeof(st->pub));
    st->have_pub = 0;
}

const n00b_quic_secret_vtbl_t n00b_keychain_vtbl = {
    .scheme = "keychain",
    .open   = kc_open,
    .sign   = kc_sign,
    .wrap   = kc_wrap,
    .pubkey = kc_pubkey,
    .close  = kc_close,
};
