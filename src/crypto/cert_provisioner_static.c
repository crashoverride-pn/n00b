/*
 * cert_provisioner_static.c — provisioner that loads PEM material
 * from disk.  Renewal is the operator's problem; should_renew()
 * always returns false.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/cert_provisioner.h"
#include "internal/crypto/cert_provisioner_common.h"

typedef struct {
    char               *chain_pem_path;
    n00b_quic_secret_t *key_secret;  /* borrowed */
} static_state_t;

static n00b_allocator_t *
sp_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
sp_strdup(const char *s)
{
    size_t l = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = sp_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, l + 1);
    return out;
}

static n00b_result_t(n00b_quic_cert_t *)
sp_acquire(n00b_quic_cert_provisioner_t *self)
{
    static_state_t *st = self->ctx;

    auto fr = n00b_certp_load_file(st->chain_pem_path);
    if (!n00b_result_is_ok(fr)) {
        return n00b_result_err(n00b_quic_cert_t *,
                               (int)n00b_result_get_err(fr));
    }
    n00b_buffer_t *pem = n00b_result_get(fr);

    auto dr = n00b_certp_pem_first_cert_to_der(pem);
    if (!n00b_result_is_ok(dr)) {
        return n00b_result_err(n00b_quic_cert_t *,
                               (int)n00b_result_get_err(dr));
    }
    n00b_buffer_t *der = n00b_result_get(dr);

    int64_t nb = 0, na = 0;
    if (n00b_certp_parse_validity((const uint8_t *)der->data,
                                  (size_t)der->byte_len, &nb, &na) != 0) {
        return n00b_result_err(n00b_quic_cert_t *, N00B_QUIC_ERR_PROTOCOL);
    }

    n00b_quic_cert_t *cert = n00b_alloc_with_opts(n00b_quic_cert_t,
        &(n00b_alloc_opts_t){.allocator = sp_alloc()});
    cert->chain_pem      = pem;
    cert->key            = st->key_secret;
    cert->not_before_ms  = nb;
    cert->not_after_ms   = na;
    return n00b_result_ok(n00b_quic_cert_t *, cert);
}

static bool
sp_should_renew(n00b_quic_cert_provisioner_t *self,
                const n00b_quic_cert_t       *current)
{
    (void)self;
    (void)current;
    /* Static provisioner never renews — the operator manages the
     * file on disk and restarts (or re-loads) the server when they
     * change it. */
    return false;
}

static void
sp_close(n00b_quic_cert_provisioner_t *self)
{
    if (!self || !self->ctx) return;
    static_state_t *st = self->ctx;
    st->chain_pem_path = nullptr;
    st->key_secret     = nullptr;
    self->ctx          = nullptr;
}

n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_static(const char         *chain_pem_path,
                                  n00b_quic_secret_t *key_secret)
{
    if (!chain_pem_path || !key_secret) {
        return n00b_result_err(n00b_quic_cert_provisioner_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    static_state_t *st = n00b_alloc_with_opts(static_state_t,
        &(n00b_alloc_opts_t){.allocator = sp_alloc()});
    st->chain_pem_path = sp_strdup(chain_pem_path);
    st->key_secret     = key_secret;

    n00b_quic_cert_provisioner_t *p = n00b_alloc_with_opts(
        n00b_quic_cert_provisioner_t,
        &(n00b_alloc_opts_t){.allocator = sp_alloc()});
    p->name         = "static";
    p->acquire      = sp_acquire;
    p->should_renew = sp_should_renew;
    p->close        = sp_close;
    p->ctx          = st;
    return n00b_result_ok(n00b_quic_cert_provisioner_t *, p);
}
