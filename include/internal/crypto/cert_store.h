/**
 * @file cert_store.h
 * @internal
 * @brief SNI-keyed cert store with hot-reload semantics.
 *
 * This is the data structure picotls's `sign_certificate` callback
 * consults during the TLS handshake.  Three guarantees:
 *
 *   - **Atomic swap**: a writer that calls `install` or `replace`
 *     publishes a complete new view in a single store-release; readers
 *     never see a partially-rebuilt store.
 *   - **No reader lock**: lookups go through one acquire-load on an
 *     `_Atomic(view_t *)` followed by a small linear scan; no mutex
 *     on the read path.
 *   - **No use-after-free for in-flight handshakes**: a handshake
 *     that captured the previous view continues to operate on it
 *     until the handshake completes.  Old views are retained in a
 *     graveyard so their entry pointers stay valid; the graveyard
 *     never shrinks across a single endpoint's lifetime, which keeps
 *     the structure simple.  Memory cost: one entry per swap, each
 *     a few dozen bytes — acceptable for cert renewals on the order
 *     of weeks.
 *
 * Wildcard rules (RFC 6125 § 6.4.3, simplified):
 *   - `"example.com"`            matches only `"example.com"`
 *   - `"*.example.com"`          matches one DNS label under
 *                                `example.com` (e.g.,
 *                                `"foo.example.com"` but not
 *                                `"foo.bar.example.com"`).
 *   - `"*"`                      matches anything (catch-all);
 *                                used as the last-resort fallback.
 *
 * Match precedence on lookup: exact > one-label wildcard > catch-all.
 *
 * @see ~/dd/quic_2.md § 6
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "crypto/secret.h"

typedef struct n00b_quic_cert_store n00b_quic_cert_store_t;

/**
 * @brief A single cert chain + its signing key, plus the SNI pattern
 *        that selects it.
 *
 * Returned by @c n00b_quic_cert_store_lookup; caller must NOT mutate
 * any of the fields.  Lifetime is tied to the cert store (entries
 * stay alive for the store's lifetime).
 */
typedef struct {
    char               *sni_pattern;
    n00b_buffer_t      *chain_pem;
    n00b_quic_secret_t *key;
    int64_t             not_after_ms;
} n00b_quic_cert_entry_t;

/**
 * @brief Allocate an empty cert store.
 *
 * @return Owned handle; close with @c n00b_quic_cert_store_close.
 */
extern n00b_quic_cert_store_t *
n00b_quic_cert_store_new(void);

/**
 * @brief Append a new entry, atomically.
 *
 * Errors if @p sni_pattern is already present (use
 * @c n00b_quic_cert_store_replace to update an existing entry).
 *
 * @param cs           Cert store.
 * @param sni_pattern  Wildcard or exact pattern (see file header).
 * @param chain_pem    PEM-encoded certificate chain.
 * @param key          Signing-key secret handle.
 * @param not_after_ms Unix-epoch ms at which the cert expires.
 *
 * @return Result: ok(true) on success;
 *         err(@c N00B_QUIC_ERR_INVALID_ARG) if the pattern already
 *         exists.
 */
extern n00b_result_t(bool)
n00b_quic_cert_store_install(n00b_quic_cert_store_t *cs,
                             const char             *sni_pattern,
                             n00b_buffer_t          *chain_pem,
                             n00b_quic_secret_t     *key,
                             int64_t                 not_after_ms);

/**
 * @brief Insert or replace the entry for @p sni_pattern, atomically.
 *
 * Existing in-flight handshakes that captured the previous view
 * continue to operate on the old entry.  New handshakes after this
 * call see the new entry.
 */
extern n00b_result_t(bool)
n00b_quic_cert_store_replace(n00b_quic_cert_store_t *cs,
                             const char             *sni_pattern,
                             n00b_buffer_t          *chain_pem,
                             n00b_quic_secret_t     *key,
                             int64_t                 not_after_ms);

/**
 * @brief Look up the best entry for @p sni_name.
 *
 * @p sni_name is the literal SNI hostname from a ClientHello (no
 * wildcards).  Match precedence: exact > "*.suffix" > "*".
 *
 * @return The matching entry pointer, or NULL if no entry matches.
 *         The pointer remains valid for as long as the cert store
 *         is alive.
 */
extern const n00b_quic_cert_entry_t *
n00b_quic_cert_store_lookup(n00b_quic_cert_store_t *cs,
                            const char             *sni_name);

/** @brief Number of entries in the current view (for diagnostics). */
extern size_t
n00b_quic_cert_store_count(n00b_quic_cert_store_t *cs);

/** @brief Close the store.  Idempotent. */
extern void
n00b_quic_cert_store_close(n00b_quic_cert_store_t *cs);
