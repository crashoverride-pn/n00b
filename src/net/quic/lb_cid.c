/*
 * lb_cid.c — LB-CID encoding (block-cipher mode, 16-byte fixed CIDs).
 */

#define N00B_USE_INTERNAL_API
#include <string.h>

#include "picotls.h"
#include "picotls/minicrypto.h"

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/random.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/lb_cid.h"

#define N00B_PICO_ALLOC ((n00b_allocator_t *)&n00b_get_runtime()->user_pool)

struct n00b_quic_lb_cid_config {
    ptls_cipher_context_t *enc;     /* AES-128-ECB encrypt context. */
    ptls_cipher_context_t *dec;     /* AES-128-ECB decrypt context. */
    n00b_rwlock_t        *lock;    /* picotls cipher contexts aren't thread-safe. */
    uint64_t               server_id;
    uint8_t                server_id_len;
    bool                   closed;
};

static n00b_allocator_t *
lb_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

n00b_result_t(n00b_quic_lb_cid_config_t *)
n00b_quic_lb_cid_config_new(const uint8_t key[N00B_QUIC_LB_CID_LEN],
                            uint64_t      server_id,
                            uint8_t       server_id_len)
{
    n00b_allocator_scope_t pico_scope;

    if (!key || server_id_len < 1 || server_id_len > 15) {
        return n00b_result_err(n00b_quic_lb_cid_config_t *,
                               N00B_QUIC_ERR_INVALID_ARG);
    }

    n00b_quic_lb_cid_config_t *cfg = n00b_alloc_with_opts(
        n00b_quic_lb_cid_config_t,
        &(n00b_alloc_opts_t){.allocator = lb_alloc()});

    pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
    cfg->enc = ptls_cipher_new(&ptls_minicrypto_aes128ecb,
                               /* is_enc = */ 1,
                               key);
    cfg->dec = ptls_cipher_new(&ptls_minicrypto_aes128ecb,
                               /* is_enc = */ 0,
                               key);
    n00b_allocator_scope_exit(&pico_scope);
    if (!cfg->enc || !cfg->dec) {
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        if (cfg->enc) ptls_cipher_free(cfg->enc);
        if (cfg->dec) ptls_cipher_free(cfg->dec);
        n00b_allocator_scope_exit(&pico_scope);
        return n00b_result_err(n00b_quic_lb_cid_config_t *,
                               N00B_QUIC_ERR_HANDSHAKE);
    }

    cfg->server_id     = server_id;
    cfg->server_id_len = server_id_len;
    cfg->closed        = false;
    cfg->lock = n00b_data_lock_new(); 

    return n00b_result_ok(n00b_quic_lb_cid_config_t *, cfg);
}

n00b_result_t(bool)
n00b_quic_lb_cid_encode(n00b_quic_lb_cid_config_t *cfg,
                        uint8_t                    out[N00B_QUIC_LB_CID_LEN])
{
    if (!cfg || cfg->closed || !out) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }

    /* Plaintext layout: [server_id MSB-first, server_id_len bytes]
     *                   [random nonce, (16 - server_id_len) bytes].
     */
    uint8_t pt[N00B_QUIC_LB_CID_LEN];

    /* Server-id big-endian, padded into the high bytes. */
    uint64_t sid = cfg->server_id;
    for (int i = (int)cfg->server_id_len - 1; i >= 0; i--) {
        pt[i] = (uint8_t)(sid & 0xff);
        sid >>= 8;
    }
    /* Nonce. */
    n00b_random_bytes((char *)(pt + cfg->server_id_len),
                      (size_t)(N00B_QUIC_LB_CID_LEN - cfg->server_id_len));

    /* picotls's AES-ECB cipher has do_init = NULL because ECB has
     * no IV; calling ptls_cipher_init would deref a NULL fnptr.
     * Go straight to encrypt. */
    n00b_data_write_lock(cfg->lock);
    ptls_cipher_encrypt(cfg->enc, out, pt, N00B_QUIC_LB_CID_LEN);
    n00b_data_unlock(cfg->lock);

    /* Don't leave plaintext on the stack longer than needed. */
    memset(pt, 0, sizeof(pt));
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_quic_lb_cid_decode(n00b_quic_lb_cid_config_t *cfg,
                        const uint8_t              encrypted_cid[N00B_QUIC_LB_CID_LEN],
                        uint64_t                  *server_id_out)
{
    if (!cfg || cfg->closed || !encrypted_cid || !server_id_out) {
        return n00b_result_err(bool, N00B_QUIC_ERR_NULL_ARG);
    }

    uint8_t pt[N00B_QUIC_LB_CID_LEN];
    n00b_data_write_lock(cfg->lock);
    /* AES-ECB: skip ptls_cipher_init (do_init is NULL). */
    ptls_cipher_encrypt(cfg->dec, pt, encrypted_cid, N00B_QUIC_LB_CID_LEN);
    n00b_data_unlock(cfg->lock);

    uint64_t sid = 0;
    for (uint8_t i = 0; i < cfg->server_id_len; i++) {
        sid = (sid << 8) | pt[i];
    }
    *server_id_out = sid;

    memset(pt, 0, sizeof(pt));
    return n00b_result_ok(bool, true);
}

void
n00b_quic_lb_cid_config_close(n00b_quic_lb_cid_config_t *cfg)
{
    n00b_allocator_scope_t pico_scope;

    if (!cfg || cfg->closed) {
        return;
    }
    cfg->closed = true;
    if (cfg->enc) {
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        ptls_cipher_free(cfg->enc);
        n00b_allocator_scope_exit(&pico_scope);
        cfg->enc = nullptr;
    }
    if (cfg->dec) {
        pico_scope = n00b_allocator_scope_enter(N00B_PICO_ALLOC);
        ptls_cipher_free(cfg->dec);
        n00b_allocator_scope_exit(&pico_scope);
        cfg->dec = nullptr;
    }
    
}
