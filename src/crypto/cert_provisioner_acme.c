/*
 * cert_provisioner_acme.c — provisioner that drives the ACME state
 * machine via n00b_acme_acquire_certificate.
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "crypto/secret.h"
#include "internal/crypto/acme.h"
#include "internal/crypto/cert_provisioner.h"
#include "internal/crypto/cert_provisioner_common.h"

typedef struct {
    char                           *directory_url;
    n00b_quic_secret_t             *account_key;   /* borrowed */
    n00b_quic_secret_t             *cert_key;      /* borrowed */
    char                          **dns_names;     /* owned copies */
    size_t                          dns_name_count;
    n00b_acme_challenge_provider_t *provider;      /* borrowed */
    int64_t                         renew_margin_ms;
    int32_t                         timeout_ms;
    int32_t                         poll_max_wait_ms;
} acme_state_t;

static n00b_allocator_t *
ap_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
ap_strdup(const char *s)
{
    size_t l = strlen(s);
    char  *out = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                            &(n00b_alloc_opts_t){
                                                .allocator = ap_alloc(),
                                                .no_scan   = true,
                                            });
    memcpy(out, s, l + 1);
    return out;
}

static int64_t
now_ms_unix(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static n00b_result_t(n00b_quic_cert_t *)
ap_acquire(n00b_quic_cert_provisioner_t *self)
{
    acme_state_t *st = self->ctx;

    auto cr = n00b_acme_acquire_certificate(
        st->directory_url,
        st->account_key,
        st->cert_key,
        (const char *const *)st->dns_names, st->dns_name_count,
        st->provider,
        .timeout_ms       = st->timeout_ms,
        .poll_max_wait_ms = st->poll_max_wait_ms);
    if (!n00b_result_is_ok(cr)) {
        return n00b_result_err(n00b_quic_cert_t *,
                               (int)n00b_result_get_err(cr));
    }
    n00b_buffer_t *chain_pem = n00b_result_get(cr);

    /* Parse the leaf cert's not_before / not_after for renewal math. */
    auto dr = n00b_certp_pem_first_cert_to_der(chain_pem);
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
        &(n00b_alloc_opts_t){.allocator = ap_alloc()});
    cert->chain_pem      = chain_pem;
    cert->key            = st->cert_key;
    cert->not_before_ms  = nb;
    cert->not_after_ms   = na;
    return n00b_result_ok(n00b_quic_cert_t *, cert);
}

static bool
ap_should_renew(n00b_quic_cert_provisioner_t *self,
                const n00b_quic_cert_t       *current)
{
    if (!current) {
        return true;  /* first acquisition */
    }
    acme_state_t *st = self->ctx;
    int64_t now = now_ms_unix();
    return now > (current->not_after_ms - st->renew_margin_ms);
}

static void
ap_close(n00b_quic_cert_provisioner_t *self)
{
    if (!self || !self->ctx) return;
    acme_state_t *st = self->ctx;
    /* Owned strings live in the conduit pool; nothing to free
     * explicitly.  Borrowed pointers we just drop. */
    st->account_key = nullptr;
    st->cert_key    = nullptr;
    st->provider    = nullptr;
    self->ctx       = nullptr;
}

n00b_result_t(n00b_quic_cert_provisioner_t *)
n00b_quic_cert_provisioner_acme(const char                     *directory_url,
                                n00b_quic_secret_t             *account_key,
                                n00b_quic_secret_t             *cert_key,
                                const char *const              *dns_names,
                                size_t                          dns_name_count,
                                n00b_acme_challenge_provider_t *provider) _kargs
{
    int64_t renew_margin_ms = (int64_t)30 * 24 * 60 * 60 * 1000;
    int32_t timeout_ms       = 30000;
    int32_t poll_max_wait_ms = 60000;
}
{
    if (!directory_url || !account_key || !cert_key || !dns_names
        || dns_name_count == 0 || !provider) {
        return n00b_result_err(n00b_quic_cert_provisioner_t *,
                               N00B_QUIC_ERR_NULL_ARG);
    }

    acme_state_t *st = n00b_alloc_with_opts(acme_state_t,
        &(n00b_alloc_opts_t){.allocator = ap_alloc()});
    st->directory_url    = ap_strdup(directory_url);
    st->account_key      = account_key;
    st->cert_key         = cert_key;
    st->dns_name_count   = dns_name_count;
    st->dns_names = n00b_alloc_array_with_opts(char *,
                                               (int64_t)dns_name_count,
                                               &(n00b_alloc_opts_t){
                                                   .allocator = ap_alloc(),
                                               });
    for (size_t i = 0; i < dns_name_count; i++) {
        st->dns_names[i] = ap_strdup(dns_names[i]);
    }
    st->provider         = provider;
    st->renew_margin_ms  = renew_margin_ms;
    st->timeout_ms       = timeout_ms;
    st->poll_max_wait_ms = poll_max_wait_ms;

    n00b_quic_cert_provisioner_t *p = n00b_alloc_with_opts(
        n00b_quic_cert_provisioner_t,
        &(n00b_alloc_opts_t){.allocator = ap_alloc()});
    p->name         = "acme";
    p->acquire      = ap_acquire;
    p->should_renew = ap_should_renew;
    p->close        = ap_close;
    p->ctx          = st;
    return n00b_result_ok(n00b_quic_cert_provisioner_t *, p);
}
