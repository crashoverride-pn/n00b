/*
 * acme_dns01.c — bridge a DNS provider to the ACME challenge
 * provider trait.
 */

#define N00B_USE_INTERNAL_API
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/dns_provider.h"
#include "internal/net/quic/acme.h"
#include "internal/net/quic/acme_dns01.h"
#include "internal/crypto/jws.h"

typedef struct {
    n00b_quic_dns_provider_t *dns;     /* borrowed */
    int32_t                   propagation_timeout_ms;
    bool                      skip_propagation_wait;
} dns01_state_t;

static n00b_allocator_t *
d1_alloc(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static char *
d1_strdup(const char *s)
{
    if (!s) return nullptr;
    size_t l = strlen(s);
    char  *o = n00b_alloc_array_with_opts(char, (int64_t)(l + 1),
                                          &(n00b_alloc_opts_t){
                                              .allocator = d1_alloc(),
                                              .no_scan   = true,
                                          });
    memcpy(o, s, l + 1);
    return o;
}

/* ===========================================================================
 * RFC 8555 § 8.4: TXT value = base64url(SHA-256(key authorization))
 * =========================================================================== */

char *
n00b_acme_dns01_txt_value(const char *key_authorization)
{
    if (!key_authorization) return nullptr;
    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    n00b_sha256_update(&ctx, (const uint8_t *)key_authorization,
                       strlen(key_authorization));
    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    uint8_t fp[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        fp[i*4]      = (uint8_t)(w >> 24);
        fp[i*4 + 1]  = (uint8_t)(w >> 16);
        fp[i*4 + 2]  = (uint8_t)(w >> 8);
        fp[i*4 + 3]  = (uint8_t)w;
    }
    return n00b_b64url_encode(fp, sizeof(fp));
}

/* ===========================================================================
 * Propagation polling — query a public resolver until our value
 * shows up.
 *
 * Uses `res_query` via getaddrinfo's TXT-record API.  Not all libc
 * exposes this directly; we shell out to /dev/null safe-mode by
 * doing a getaddrinfo on the parent domain (a sanity check that
 * DNS works) and trust the provider's set_txt return.  The full
 * "TXT record matches expected value" poll is deferred to a future
 * pass that vendors a small DNS resolver.
 * =========================================================================== */

static int64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int
wait_for_propagation(const char *fqdn, int32_t timeout_ms)
{
    int64_t deadline = now_ms() + timeout_ms;
    /* Fixed minimum wait — DNS propagation is best-effort here.
     * Most providers (Cloudflare, Route53) settle in 5-30s; the
     * manual provider has already gotten operator confirmation
     * before we reach this point. */
    int slept_ms = 0;
    while (now_ms() < deadline && slept_ms < 5000) {
        usleep(500 * 1000);
        slept_ms += 500;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *res = nullptr;
        /* Best-effort check that the parent domain resolves at all
         * (sanity check — doesn't validate the TXT contents). */
        const char *parent = strchr(fqdn, '.');
        if (!parent) parent = fqdn;
        else parent += 1;
        int rc = getaddrinfo(parent, "443", &hints, &res);
        if (res) freeaddrinfo(res);
        if (rc == 0) {
            return N00B_QUIC_OK;
        }
    }
    /* We didn't crash; we'll let the ACME server's validation tell
     * us whether the record actually propagated. */
    return N00B_QUIC_OK;
}

/* ===========================================================================
 * Challenge provider hooks
 * =========================================================================== */

static int
dns01_provision(n00b_acme_challenge_provider_t *self,
                const n00b_acme_challenge_t    *challenge,
                const char                     *identifier,
                const char                     *key_authz)
{
    dns01_state_t *st = self->ctx;
    (void)challenge;

    if (!identifier || !key_authz) {
        return N00B_QUIC_ERR_NULL_ARG;
    }

    /* Compose the FQDN: _acme-challenge.<identifier> */
    char fqdn[512];
    int n = snprintf(fqdn, sizeof(fqdn),
                     "_acme-challenge.%s", identifier);
    if (n < 0 || n >= (int)sizeof(fqdn)) {
        return N00B_QUIC_ERR_FRAME_TOO_LARGE;
    }

    /* TXT value = base64url(SHA-256(key_authorization)). */
    char *value = n00b_acme_dns01_txt_value(key_authz);
    if (!value) {
        return N00B_QUIC_ERR_PROTOCOL;
    }

    int rc = st->dns->set_txt(st->dns, fqdn, value);
    if (rc != N00B_QUIC_OK) {
        return rc;
    }

    if (!st->skip_propagation_wait) {
        rc = wait_for_propagation(fqdn, st->propagation_timeout_ms);
        if (rc != N00B_QUIC_OK) {
            /* set_txt succeeded; let the ACME server tell us if the
             * propagation actually didn't happen.  Do not report
             * the wait timeout as a hard failure. */
        }
    }
    return N00B_QUIC_OK;
}

static int
dns01_deprovision(n00b_acme_challenge_provider_t *self,
                  const n00b_acme_challenge_t    *challenge,
                  const char                     *identifier)
{
    dns01_state_t *st = self->ctx;
    (void)challenge;

    if (!identifier) return N00B_QUIC_ERR_NULL_ARG;

    char fqdn[512];
    int n = snprintf(fqdn, sizeof(fqdn),
                     "_acme-challenge.%s", identifier);
    if (n < 0 || n >= (int)sizeof(fqdn)) {
        return N00B_QUIC_ERR_FRAME_TOO_LARGE;
    }
    /* We don't have the value at deprovision time (the orchestrator
     * doesn't pass it).  Pass an empty string; providers that need
     * exact-value matching may walk all TXT records at the FQDN and
     * delete the one we authored.  The manual provider just prints
     * a cleanup hint. */
    return st->dns->remove_txt(st->dns, fqdn, "");
}

n00b_acme_challenge_provider_t *
n00b_acme_dns01_provider_new(n00b_quic_dns_provider_t *dns) _kargs
{
    int32_t propagation_timeout_ms = 60000;
    bool    skip_propagation_wait  = false;
}
{
    if (!dns) return nullptr;

    dns01_state_t *st = n00b_alloc_with_opts(dns01_state_t,
        &(n00b_alloc_opts_t){.allocator = d1_alloc()});
    st->dns                    = dns;
    st->propagation_timeout_ms = propagation_timeout_ms;
    st->skip_propagation_wait  = skip_propagation_wait;

    n00b_acme_challenge_provider_t *p = n00b_alloc_with_opts(
        n00b_acme_challenge_provider_t,
        &(n00b_alloc_opts_t){.allocator = d1_alloc()});
    p->type        = d1_strdup("dns-01");
    p->provision   = dns01_provision;
    p->deprovision = dns01_deprovision;
    p->ctx         = st;
    return p;
}
