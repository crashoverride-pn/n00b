/**
 * @file acme_dns01.h
 * @internal
 * @brief Bridge a `n00b_quic_dns_provider_t` to the ACME challenge
 *        provider trait.
 *
 * The ACME orchestrator (Phase 2.3c) talks to a generic
 * `n00b_acme_challenge_provider_t`.  For DNS-01 specifically,
 * `provision()` must:
 *
 *   1. Compute the **key authorization** (RFC 8555 § 8.1):
 *      `<token>.<base64url(SHA-256(canonical-JWK(account-pubkey)))>`.
 *      We've shipped this as `n00b_acme_http01_key_authz()` in
 *      `acme.c`; same function for both HTTP-01 and DNS-01.
 *
 *   2. Compute the **TXT record value** (RFC 8555 § 8.4):
 *      `base64url(SHA-256(key_authorization))`.
 *
 *   3. Write the TXT record at `_acme-challenge.<identifier>` via
 *      the wrapped DNS provider.
 *
 *   4. Wait for global propagation: poll a public resolver until
 *      the new TXT value is reachable.
 *
 *   5. Return.  The orchestrator then POSTs the challenge URL,
 *      polls the authz, deprovisions.
 *
 * @see ~/dd/quic_2.md § 5.4
 */
#pragma once

#include "n00b.h"
#include "internal/crypto/acme.h"
#include "net/quic/dns_provider.h"

/**
 * @brief Wrap a DNS provider into an ACME challenge provider.
 *
 * The returned provider's `type` is `"dns-01"`.  Used by the
 * orchestrator's challenge-type matching against authz challenges.
 *
 * @param dns      The DNS provider to delegate set/remove TXT calls to.
 *                 Borrowed; caller manages its lifecycle.
 *
 * @kw propagation_timeout_ms  How long to wait for the TXT record
 *                             to be visible via a public resolver.
 *                             Default 60000 (60 s).  Cloudflare /
 *                             Route53 typically propagate in <30 s;
 *                             a slow-DNS environment may need more.
 * @kw skip_propagation_wait   When true, skip the public-resolver
 *                             poll and trust that the provider's
 *                             set_txt completed.  Useful for
 *                             test/dev where the provider IS the
 *                             authoritative server.
 *
 * @return Owned challenge provider; the caller doesn't free it
 *         (it lives in the conduit pool until process exit).
 */
extern n00b_acme_challenge_provider_t *
n00b_acme_dns01_provider_new(n00b_quic_dns_provider_t *dns)
    _kargs {
        int32_t propagation_timeout_ms = 60000;
        bool    skip_propagation_wait  = false;
    };

/**
 * @brief Compute the DNS-01 TXT record value for a given key
 *        authorization, per RFC 8555 § 8.4.
 *
 * Useful for the manual-DNS-provider workflow (operator computes
 * the value out-of-band) and for tests.
 *
 * @return Heap-allocated NUL-terminated string in the conduit pool.
 */
extern char *
n00b_acme_dns01_txt_value(const char *key_authorization);
