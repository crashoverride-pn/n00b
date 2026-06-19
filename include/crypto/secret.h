/**
 * @file secret.h
 * @brief Secret-handle abstraction for the QUIC module.
 *
 * `n00b_quic_secret_t` is an opaque handle to material stored in a
 * "blessed" source (Keychain, libsecret, PKCS#11 token, TPM, cloud
 * KMS, ...).  The transport never sees the underlying bytes; it
 * delegates verb operations (sign, wrap-session-key, bearer-for) to
 * the provider that backs the handle.
 *
 * ### What this exists to forbid
 *
 * Any path that would surface raw secret bytes through the public API.
 * Logging, formatting, accessor functions, debug dumps — none of them
 * stringify the underlying material.  `n00b_quic_secret_format`
 * returns a stable opaque tag.  This is the discipline that makes
 * "we don't accidentally log a private key" a property of the type
 * system rather than a code-review hope.
 *
 * ### Phase 1 ships
 *
 * - `ephemeral:<label>` URI scheme — in-memory test-only provider.
 *   Stores 32 random bytes as the "key material"; sign is a SHA-256
 *   marker (not a real signature); wrap is NOT_IMPLEMENTED.  Used
 *   exclusively by unit tests; the URI scheme is documented as
 *   test-only.
 *
 * Real providers (Keychain on macOS, libsecret on Linux, PKCS#11,
 * TPM 2.0, cloud KMS, systemd LoadCredential) ship in follow-ups.
 * Their URIs follow the design in `~/dd/quic_1.md § 10`.
 *
 * ### What is explicitly refused
 *
 * Per the source design § 8.2:
 *
 * - `env:` URI scheme.  Environment variables leak into core dumps,
 *   `ps`, accidental child processes, log lines.
 * - `file:` URI scheme.  Plain files at arbitrary paths.
 * - Any verb that returns the raw bytes through the public API.
 *
 * @see trust.h, quic_types.h
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "adt/option.h"
#include "core/string.h"
#include "core/buffer.h"
#include "net/quic/quic_types.h"

/**
 * @brief What the secret is — drives provider routing and format tags.
 */
typedef enum : uint8_t {
    N00B_QUIC_SECRET_PRIVKEY = 0, /**< TLS server / client private key. */
    N00B_QUIC_SECRET_SYM_KEY = 1, /**< Symmetric key (stateless-reset, address-validation). */
    N00B_QUIC_SECRET_CERT    = 2, /**< Certificate / chain bytes. */
} n00b_quic_secret_kind_t;

/**
 * @brief Signature algorithms supported by the secret-handle sign verb.
 *
 * Concrete algorithms beyond `ED25519_PURE` ship as the corresponding
 * provider gains support.  Phase 1's ephemeral provider only honours
 * the test-marker algorithm and rejects the rest.
 */
typedef enum : uint8_t {
    N00B_QUIC_SIG_TEST_MARKER = 0, /**< SHA-256(key || data); not a real signature. */
    N00B_QUIC_SIG_ED25519     = 1, /**< RFC 8032 Ed25519. */
    N00B_QUIC_SIG_ECDSA_P256  = 2,
    N00B_QUIC_SIG_RSA_PSS_2048 = 3,
} n00b_quic_sig_alg_t;

/**
 * @brief Open a secret handle from a URI.
 *
 * The URI's scheme prefix (everything before the first `:`) selects
 * the provider:
 *
 * | Scheme        | Provider                     | Phase |
 * |---------------|------------------------------|-------|
 * | `ephemeral:`  | In-memory test-only          | 1     |
 * | `keychain:`   | macOS Keychain               | 1 follow-up |
 * | `libsecret:`  | Linux Secret Service         | 1 follow-up |
 * | `pkcs11:`     | PKCS#11 token / HSM          | 2     |
 * | `tpm:`        | TPM 2.0 / Secure Enclave     | 2     |
 * | `vault:`      | HashiCorp Vault              | 2     |
 * | `kms:`        | AWS / GCP / Azure KMS        | 2     |
 *
 * URIs whose scheme isn't backed by a registered provider produce
 * @c N00B_QUIC_ERR_NOT_IMPLEMENTED.  `env:` and `file:` are
 * explicitly refused with @c N00B_QUIC_ERR_INVALID_ARG.
 *
 * @param uri Provider-prefixed URI identifying the secret.
 *
 * @kw provider Override URI-prefix routing.  Rare; default
 *              (`nullptr`) uses the URI scheme.
 *
 * @return Result: ok with the open handle on success.
 *
 * @pre  @p uri is non-NULL and non-empty.
 * @post On success the caller owns the handle; close with
 *       @c n00b_quic_secret_close.
 */
extern n00b_result_t(n00b_quic_secret_t *)
    n00b_quic_secret_open(n00b_buffer_t *uri)
    _kargs {
        n00b_buffer_t *provider = nullptr;
    };

/**
 * @brief Stable opaque tag for a secret handle.
 *
 * Format: `<secret kind=<kind> provider=<provider> label=<label>>`.
 * The label is a short, non-secret identifier from the URI.  Safe to
 * include in logs.  Never includes the underlying material.
 *
 * @param s Secret handle.
 * @return Owned string; lifetime managed by the GC.
 */
extern n00b_string_t *
n00b_quic_secret_format(n00b_quic_secret_t *s);

/**
 * @brief Query the kind of secret behind the handle.
 *
 * @param s Secret handle.
 * @return The handle's @c n00b_quic_secret_kind_t.
 *
 * @pre @p s is non-NULL and not closed.
 */
extern n00b_quic_secret_kind_t
n00b_quic_secret_kind(n00b_quic_secret_t *s);

/**
 * @brief Sign @p data with the handle's key material.
 *
 * The provider performs the signing in its own trust boundary; the
 * key never leaves the provider.  For the ephemeral test provider,
 * @c alg must be @c N00B_QUIC_SIG_TEST_MARKER and the result is
 * SHA-256(key || data) — not a real signature.
 *
 * @param s    Secret handle (must be a privkey).
 * @param data Bytes to sign.
 * @param alg  Signature algorithm.
 *
 * @return Result: ok with a signature buffer on success;
 *         err(@c N00B_QUIC_ERR_INVALID_ARG) on wrong kind /
 *         unsupported alg; err(@c N00B_QUIC_ERR_NOT_IMPLEMENTED) if
 *         the provider doesn't support signing.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_sign(n00b_quic_secret_t  *s,
                      n00b_buffer_t       *data,
                      n00b_quic_sig_alg_t  alg);

/**
 * @brief Export the public-key counterpart of a privkey handle.
 *
 * The byte layout depends on @p alg:
 *   - @c N00B_QUIC_SIG_ECDSA_P256 → 64 bytes, X || Y (uncompressed,
 *     no SEC1 0x04 prefix).
 *
 * Useful for embedding the key into a JWK or printing a fingerprint.
 *
 * @param s   Secret handle (must be @c N00B_QUIC_SECRET_PRIVKEY).
 * @param alg The signature algorithm whose public-key format you want.
 *
 * @return Result: ok with a freshly-allocated buffer on success;
 *         err(@c N00B_QUIC_ERR_INVALID_ARG) on wrong kind / wrong alg /
 *         closed handle; err(@c N00B_QUIC_ERR_NOT_IMPLEMENTED) when
 *         the provider has no exportable public key.
 *
 * @pre @p s is non-NULL and not closed.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_pubkey(n00b_quic_secret_t *s, n00b_quic_sig_alg_t alg);

/**
 * @brief Wrap @p data using the handle as the key-encryption key.
 *
 * Pending — Phase 1 returns @c N00B_QUIC_ERR_NOT_IMPLEMENTED.  Lands
 * with the picotls AEAD wiring.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_quic_secret_wrap(n00b_quic_secret_t *s,
                      n00b_buffer_t      *data);

/**
 * @brief Close a secret handle and zero any in-memory key material.
 *
 * Idempotent.  After return, @p s may not be dereferenced and the
 * provider has zeroed and freed any bytes it was holding for this
 * handle.
 */
extern void n00b_quic_secret_close(n00b_quic_secret_t *s);
