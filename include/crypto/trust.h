/**
 * @file trust.h
 * @brief Trust-store abstraction for the QUIC module.
 *
 * A `n00b_quic_trust_t` is the source of trusted root CAs against which
 * a peer's TLS 1.3 certificate chain is verified during the QUIC
 * handshake.  The transport delegates the verification verdict to
 * whatever backend is plugged into the handle: OS-native trust stores
 * (Security.framework on macOS, the distro PEM dir on Linux), an
 * additive corporate / internal CA on top of the system store, or a
 * test-only pinned-fingerprint store for unit tests and CI.
 *
 * **There is no `n00b_quic_trust_disabled()`.**  No `--insecure`
 * switch.  Connections that cannot verify their peer simply do not
 * come up.  This is deliberate; see `~/dd/quic_1.md § 9` for the
 * design rationale.
 *
 * ### Composition
 *
 * Backends compose by stacking — `n00b_quic_trust_with_extra` wraps a
 * base store with an additional set of trust anchors.  The base is
 * unaffected; the returned handle accepts a chain that validates
 * against either the base store or the additional anchors.  This is
 * the supported pattern for corporate MITM / internal PKI on top of
 * the system trust store.
 *
 * ### Phase 1 ships
 *
 * - `n00b_quic_trust_pinned` — pin a single leaf cert by SHA-256
 *   fingerprint.  Test-only; primary use is CI integration tests
 *   that need to validate against a known cert without depending on
 *   the host's trust store.
 *
 * Real backends (macOS Security.framework, Linux PEM dir,
 * `n00b_quic_trust_system`, `n00b_quic_trust_with_extra`) ship in the
 * follow-up that wires picotls into the handshake path.  Until then
 * those entry points return @c N00B_QUIC_ERR_NOT_IMPLEMENTED.
 *
 * @see secret.h, quic_types.h
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "adt/option.h"
#include "core/buffer.h"
#include "net/quic/quic_types.h"

/**
 * @brief Purpose for which a trust anchor is asserted.
 *
 * Constrains what an additional CA added via
 * @c n00b_quic_trust_with_extra is allowed to vouch for.  Today only
 * @c SERVER_AUTH is honoured by the pinned-fingerprint backend; the
 * other purposes will become meaningful once OS-native backends ship.
 */
typedef enum : uint8_t {
    N00B_QUIC_TRUST_SERVER_AUTH = 0, /**< CA may vouch for server certs. */
    N00B_QUIC_TRUST_CLIENT_AUTH = 1, /**< CA may vouch for client certs (mTLS). */
    N00B_QUIC_TRUST_BOTH        = 2, /**< CA may vouch for both. */
} n00b_quic_trust_purpose_t;

/**
 * @brief Get the platform-default system trust store.
 *
 * On macOS this delegates to Security.framework / SecTrust; on Linux
 * to OpenSSL's default verify paths against the distro PEM
 * directory; on Windows to SChannel/CNG (Phase 2); on Android to
 * AndroidCAStore (Phase 2).
 *
 * @return Result: ok with the system trust handle on supported
 *         platforms; err(@c N00B_QUIC_ERR_NOT_IMPLEMENTED) until
 *         picotls integration ships.
 *
 * @post On success the returned handle is owned by the caller; close
 *       via @c n00b_quic_trust_close when finished.
 */
extern n00b_result_t(n00b_quic_trust_t *) n00b_quic_trust_system(void);

/**
 * @brief Augment a trust store with an additional CA chain.
 *
 * The new store accepts a peer chain that validates against either
 * @p base or the additional anchors in @p ca_chain.  @p base is
 * unaffected.  This is the supported path for corporate MITM and
 * internal-PKI deployments on top of the system store.
 *
 * @param base     Existing trust store (typically @c n00b_quic_trust_system()).
 * @param ca_chain PEM- or DER-encoded chain (borrowed; copied internally).
 *
 * @kw purpose Default: @c N00B_QUIC_TRUST_SERVER_AUTH.  Restricts the
 *             EKU the additional CA may vouch for.
 *
 * @return Result: ok with the augmented store; err on parse failure
 *         or @c N00B_QUIC_ERR_NOT_IMPLEMENTED until picotls
 *         integration ships.
 *
 * @pre @p base and @p ca_chain are non-NULL.
 */
extern n00b_result_t(n00b_quic_trust_t *)
    n00b_quic_trust_with_extra(n00b_quic_trust_t *base,
                               n00b_buffer_t     *ca_chain)
    _kargs {
        n00b_quic_trust_purpose_t purpose = N00B_QUIC_TRUST_SERVER_AUTH;
    };

/**
 * @brief Test-only: pin the leaf cert by SHA-256 fingerprint.
 *
 * Verification accepts a presented chain only if the SHA-256 of the
 * leaf cert (chain[0]) matches @p fingerprint exactly.  No
 * intermediate or root validation is performed; this backend is for
 * unit/integration tests where the test setup knows the exact cert
 * that will be presented.
 *
 * **Not for production use.**  A pinned-fingerprint backend has no
 * defence against compromise of the pinned key beyond rotation, and
 * it does not validate the chain or its EKU.
 *
 * @param fingerprint 32 bytes of SHA-256 over the DER encoding of
 *                    the leaf cert.  Caller-allocated; copied
 *                    internally.
 *
 * @return Owned handle; never NULL.  Close with
 *         @c n00b_quic_trust_close.
 */
extern n00b_quic_trust_t *
    n00b_quic_trust_pinned(const uint8_t fingerprint[32]);

/**
 * @brief Verify a peer cert chain against the trust store.
 *
 * Internal-facing today; will be the entry point picotls's verify
 * callback hooks into when the handshake path lands.  Exposed in
 * the public header so test code can drive verification without
 * spinning up a TLS stack.
 *
 * @param trust       Trust store to consult.
 * @param chain_der   Array of pointers to DER-encoded certificates;
 *                    @p chain_der[0] is the peer leaf,
 *                    @p chain_der[count-1] is the closest issuer to
 *                    a trust anchor.
 * @param chain_lens  Per-cert lengths in bytes.
 * @param count       Number of certs in the chain (must be ≥ 1).
 * @param sni         Server Name Indication for hostname checking;
 *                    nullptr to skip hostname checking (e.g., for
 *                    pinned-fingerprint).
 *
 * @return Result of bool: ok(true) if accepted; err(@c
 *         N00B_QUIC_ERR_TRUST_REJECTED) if rejected; err(@c
 *         N00B_QUIC_ERR_NOT_IMPLEMENTED) if the underlying backend
 *         doesn't support verification yet.
 */
extern n00b_result_t(bool)
    n00b_quic_trust_verify(n00b_quic_trust_t *trust,
                           const uint8_t    **chain_der,
                           const size_t      *chain_lens,
                           size_t             count,
                           const char        *sni);

/**
 * @brief Close a trust handle and release its backend state.
 *
 * Idempotent.  After return, @p trust may not be dereferenced.
 *
 * @param trust Handle to close (may be NULL).
 */
extern void n00b_quic_trust_close(n00b_quic_trust_t *trust);
