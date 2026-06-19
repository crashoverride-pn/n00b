/**
 * @file acme.h
 * @internal
 * @brief ACME (RFC 8555) client state machine — internal API.
 *
 * Sequencing:
 *
 *   1. `n00b_acme_session_open(directory_url, account_key)` —
 *      fetches the ACME directory + a fresh Replay-Nonce; caches both
 *      on the session.  No protocol traffic happens beyond this until
 *      a verb is invoked.
 *   2. `n00b_acme_new_account(session, ...)` — registers the account
 *      key by POSTing the newAccount endpoint with the JWS in
 *      jwk-form.  On success the session caches the account URL,
 *      which becomes the `kid` for every subsequent JWS.
 *   3. `n00b_acme_new_order(...)` — POST newOrder with kid form;
 *      returns Authz URLs + finalize URL.  *(Phase 2.3b.)*
 *   4. Challenge submission + polling.  *(Phase 2.3b.)*
 *   5. `n00b_acme_finalize(...)` with a CSR; cert pickup.  *(Phase 2.3c.)*
 *
 * The session is **synchronous, single-threaded, one outstanding
 * request at a time** — same model as `acme_http`.  ACME is a
 * sequential protocol; concurrency would only complicate nonce
 * management.
 *
 * @see ~/dd/quic_2.md § 5.5
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "crypto/secret.h"

/* ===========================================================================
 * ACME directory — discovered via GET /directory.
 *
 * Only the fields we currently exercise are stored as named members;
 * the rest of the discovered URLs sit in the `extra` dict for the
 * occasional uncommon endpoint (revokeCert, keyChange, etc.).  All
 * strings are heap-allocated NUL-terminated C strings owned by the
 * session's allocator (conduit_pool).
 * =========================================================================== */

typedef struct {
    char *new_nonce;
    char *new_account;
    char *new_order;
    char *revoke_cert;   /**< nullable */
    char *key_change;    /**< nullable */
    char *terms_of_service; /**< from the optional `meta` dict; nullable */
} n00b_acme_directory_t;

/* ===========================================================================
 * ACME account.
 * =========================================================================== */

typedef struct {
    char *url;       /**< account URL — used as `kid` in every signed request */
    char *status;    /**< "valid", "deactivated", "revoked" */
} n00b_acme_account_t;

/* ===========================================================================
 * ACME session — opaque to callers.
 *
 * Holds the directory, the cached nonce, the account signing key, and
 * (after registration) the account URL.  Built once per certificate-
 * acquisition flow.
 * =========================================================================== */

typedef struct n00b_acme_session n00b_acme_session_t;

/**
 * @brief Open a new ACME session against @p directory_url.
 *
 * Performs:
 *   - GET @p directory_url       (parsed into n00b_acme_directory_t)
 *   - HEAD <newNonce>            (caches the first Replay-Nonce)
 *
 * @param directory_url Full HTTPS URL of the ACME directory
 *                      (e.g., `https://acme-v02.api.letsencrypt.org/directory`).
 * @param account_key   Privkey secret handle for the ACME account
 *                      (must support @c N00B_QUIC_SIG_ECDSA_P256).
 *
 * @kw timeout_ms       Per-request timeout (default 30000).
 *
 * @return Result: ok with an opened session on success.
 */
extern n00b_result_t(n00b_acme_session_t *)
n00b_acme_session_open(const char         *directory_url,
                       n00b_quic_secret_t *account_key)
    _kargs {
        int32_t timeout_ms = 30000;
    };

/** @brief Free a session.  Idempotent. */
extern void
n00b_acme_session_close(n00b_acme_session_t *s);

/** @brief Inspect the discovered directory. */
extern const n00b_acme_directory_t *
n00b_acme_session_directory(n00b_acme_session_t *s);

/**
 * @brief Register the session's account key with the ACME server.
 *
 * Issues `POST <newAccount>` with the JWS in jwk-form (the ACME server
 * has not seen the key before).  On success, the session caches the
 * account URL and uses it as `kid` for every subsequent signed call.
 *
 * @kw contact            Optional contact URI list (e.g., ["mailto:..."]).
 *                        Each entry copied verbatim into the JSON `contact`
 *                        array.  Pass nullptr for an empty contact list.
 * @kw contact_count      Number of entries in @p contact.
 * @kw terms_agreed       Whether to set `termsOfServiceAgreed=true`.
 *                        Required by Let's Encrypt; step-ca doesn't care.
 *
 * @return Result: ok with the freshly registered account on success.
 *         Server error responses (e.g., already-exists) come back as
 *         err with @c N00B_QUIC_ERR_PROTOCOL — the user can re-attempt
 *         with a different key, or use account-key-rollover (post-Phase 2).
 */
extern n00b_result_t(n00b_acme_account_t *)
n00b_acme_new_account(n00b_acme_session_t *s)
    _kargs {
        const char **contact       = nullptr;
        size_t       contact_count = 0;
        bool         terms_agreed  = true;
    };

/**
 * @brief Inspect the registered account on a session.
 *
 * @return The account if `n00b_acme_new_account` has been called and
 *         succeeded; nullptr otherwise.
 */
extern const n00b_acme_account_t *
n00b_acme_session_account(n00b_acme_session_t *s);

/* ===========================================================================
 * Order, Authorization, Challenge — RFC 8555 § 7.1.
 *
 * All strings live in the conduit pool; the caller doesn't free them.
 * Lists are flat C arrays sized by the matching `_count` field — the
 * ACME protocol caps these tightly (one identifier per order in
 * practice, a handful of challenges per authz).
 * =========================================================================== */

typedef struct {
    char *type;   /**< Currently always "dns". */
    char *value;  /**< The DNS name. */
} n00b_acme_identifier_t;

typedef struct {
    char *type;     /**< "http-01" / "dns-01" / "tls-alpn-01" — RFC 8555 § 8. */
    char *url;      /**< POST here (kid-form) to signal "ready to validate". */
    char *token;    /**< Bytes the client splices into its challenge response. */
    char *status;   /**< "pending" / "processing" / "valid" / "invalid". */
} n00b_acme_challenge_t;

typedef struct {
    n00b_acme_identifier_t   identifier;
    char                    *status;     /**< "pending" / "valid" / "invalid" / ... */
    char                    *expires;    /**< RFC 3339 timestamp, nullable. */
    bool                     wildcard;
    n00b_acme_challenge_t  **challenges;
    size_t                   challenge_count;
} n00b_acme_authz_t;

typedef struct {
    char  *url;          /**< Order URL (from the Location header on newOrder). */
    char  *status;       /**< "pending" / "ready" / "processing" / "valid" / "invalid". */
    char  *expires;      /**< RFC 3339 timestamp, nullable. */
    char  *finalize;     /**< Where to POST the CSR once authz is satisfied. */
    char  *certificate;  /**< Set once status=="valid"; nullable. */
    n00b_acme_identifier_t  *identifiers;
    size_t                   identifier_count;
    char                   **authorizations;  /**< Authz URLs (POST-as-GET them). */
    size_t                   authorization_count;
} n00b_acme_order_t;

/**
 * @brief Place a new ACME order for one or more DNS identifiers.
 *
 * RFC 8555 § 7.4.  Signed with the JWS in kid-form, so the session
 * must already have a registered account.
 *
 * @param s          Session with a registered account.
 * @param dns_names  Array of DNS names to include in the order.
 * @param count      Number of names (≥ 1).
 *
 * @return Result: ok with the order on success.
 */
extern n00b_result_t(n00b_acme_order_t *)
n00b_acme_new_order(n00b_acme_session_t *s,
                    const char *const   *dns_names,
                    size_t               count);

/**
 * @brief Fetch one authorization (POST-as-GET).
 *
 * @param s          Session.
 * @param authz_url  Authorization URL from a previously-fetched order.
 *
 * @return Result: ok with the authz state on success.
 */
extern n00b_result_t(n00b_acme_authz_t *)
n00b_acme_get_authz(n00b_acme_session_t *s, const char *authz_url);

/**
 * @brief Compute the RFC 8555 § 8.1 key authorization string.
 *
 * `<token>.<base64url(SHA-256(canonical-JWK(account-pubkey)))>`
 *
 * The same string is the response body for HTTP-01 and the value of
 * the `_acme-challenge.<domain>` TXT record (after a fresh SHA-256
 * + base64url) for DNS-01.
 *
 * @param s     Session whose account key drives the thumbprint.
 * @param token Token from a Challenge object.
 *
 * @return Owned NUL-terminated string in the conduit pool, or NULL
 *         on bad arguments.
 */
extern char *
n00b_acme_http01_key_authz(n00b_acme_session_t *s, const char *token);

/**
 * @brief Tell the ACME server "I'm ready for you to validate this
 *        challenge" by POSTing `{}` to the challenge URL (RFC 8555
 *        § 7.5.1).
 *
 * The caller MUST have provisioned the corresponding challenge
 * response (HTTP-01 endpoint, DNS TXT record, etc.) before calling
 * this — the server will start its outbound validation request as
 * soon as it receives the POST.
 *
 * @return Result: ok with the (server-side) challenge state on
 *         success, err otherwise.
 */
extern n00b_result_t(n00b_acme_challenge_t *)
n00b_acme_signal_challenge_ready(n00b_acme_session_t   *s,
                                 n00b_acme_challenge_t *challenge);

/**
 * @brief Poll an authorization until its status leaves "pending" or
 *        the deadline elapses.
 *
 * Issues `n00b_acme_get_authz` in a linear-backoff loop (1 s, 2 s,
 * 4 s, capped at 5 s).  Returns the latest authz state regardless
 * of final status — caller checks `status` to see how it ended.
 *
 * @kw max_wait_ms  Default 60000 (60 s).
 */
extern n00b_result_t(n00b_acme_authz_t *)
n00b_acme_poll_authz(n00b_acme_session_t *s, const char *authz_url)
    _kargs {
        int32_t max_wait_ms = 60000;
    };

/**
 * @brief Poll an order until its status leaves "pending" /
 *        "processing" or the deadline elapses.
 *
 * Same backoff strategy as `n00b_acme_poll_authz`.
 *
 * @kw max_wait_ms  Default 60000 (60 s).
 */
extern n00b_result_t(n00b_acme_order_t *)
n00b_acme_poll_order(n00b_acme_session_t *s, const char *order_url)
    _kargs {
        int32_t max_wait_ms = 60000;
    };

/**
 * @brief Submit a CSR to the order's finalize URL (RFC 8555 § 7.4).
 *
 * Body is `{"csr":"<base64url(DER CSR)>"}`.  Server returns the
 * updated Order; if its `status` is "processing" the caller should
 * follow up with `n00b_acme_poll_order` until "valid", then call
 * `n00b_acme_get_certificate`.
 *
 * @param s        Session.
 * @param order    Order returned by `n00b_acme_new_order`.
 * @param csr_der  DER-encoded PKCS#10 CSR (from `n00b_acme_build_csr`).
 */
extern n00b_result_t(n00b_acme_order_t *)
n00b_acme_finalize(n00b_acme_session_t *s,
                   n00b_acme_order_t   *order,
                   n00b_buffer_t       *csr_der);

/**
 * @brief Download the issued certificate chain.
 *
 * POST-as-GETs the order's `certificate` URL once the order is in
 * "valid" status.  Response body is `application/pem-certificate-chain`
 * — one or more PEM `CERTIFICATE` blocks back-to-back, leaf first,
 * intermediates after.
 *
 * @return Result: ok with the response body buffer (the raw PEM
 *         bytes) on success.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_acme_get_certificate(n00b_acme_session_t *s,
                          n00b_acme_order_t   *order);

/* ===========================================================================
 * Challenge provider trait.
 *
 * Concrete provider implementations (HTTP-01-bound-to-port-80, DNS-01
 * with route53/gcp/cloudflare/manual, TLS-ALPN-01) live alongside
 * the deployment playbook — they're operational infrastructure, not
 * library code.  This header defines the shape every provider has
 * to expose so the high-level orchestrator can talk to it
 * uniformly.
 *
 * The orchestrator calls `provision` *before* signalling the
 * challenge ready, and `deprovision` after the authz settles
 * (success or failure).  The provider must guarantee the
 * provisioned response is reachable at the moment `provision`
 * returns.
 * =========================================================================== */

typedef struct n00b_acme_challenge_provider {
    /**
     * @brief Challenge type this provider handles.
     *
     * Match against `n00b_acme_challenge_t.type`.  Examples:
     * `"http-01"`, `"dns-01"`, `"tls-alpn-01"`.
     */
    const char *type;

    /**
     * @brief Stand up the response material so the ACME server can
     *        validate it.
     *
     * For HTTP-01: serve `key_authz` at `/.well-known/acme-challenge/<token>`
     * on `http://<identifier>/`.  For DNS-01: write the SHA-256 of
     * `key_authz` (base64url-encoded) to a TXT record at
     * `_acme-challenge.<identifier>`.  Etc.
     *
     * Synchronous: must return only after the response is reachable.
     *
     * @return @c N00B_QUIC_OK on success, a negative
     *         @c n00b_quic_err_t otherwise.
     */
    int (*provision)(struct n00b_acme_challenge_provider *self,
                     const n00b_acme_challenge_t         *challenge,
                     const char                          *identifier,
                     const char                          *key_authz);

    /**
     * @brief Tear down whatever `provision` set up.  Idempotent.
     */
    int (*deprovision)(struct n00b_acme_challenge_provider *self,
                       const n00b_acme_challenge_t         *challenge,
                       const char                          *identifier);

    /** @brief Provider-private state.  Opaque to the orchestrator. */
    void *ctx;
} n00b_acme_challenge_provider_t;

/**
 * @brief One-call certificate acquisition: directory → account →
 *        order → authz/challenge dance → finalize → cert pickup.
 *
 * The orchestrator picks the first challenge whose `type` matches
 * @p provider->type for each authorization; if no compatible
 * challenge exists, returns @c N00B_QUIC_ERR_NOT_IMPLEMENTED.
 *
 * @param directory_url ACME directory URL.
 * @param account_key   Privkey for the ACME account (ECDSA-P-256).
 * @param cert_key      Privkey for the certificate to be issued
 *                      (ECDSA-P-256; can be the same handle as
 *                      @p account_key, but typically a separate key).
 * @param dns_names     Identifiers to include in the order.
 * @param dns_name_count Number of names (≥ 1).
 * @param provider      Challenge provider for the validation step.
 *
 * @kw timeout_ms       Per-request timeout (default 30000).
 * @kw poll_max_wait_ms Max wait when polling authz / order
 *                      (default 60000).
 *
 * @return Result: ok with the PEM-encoded cert chain (leaf + any
 *         intermediates) on success.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_acme_acquire_certificate(const char                     *directory_url,
                              n00b_quic_secret_t             *account_key,
                              n00b_quic_secret_t             *cert_key,
                              const char *const              *dns_names,
                              size_t                          dns_name_count,
                              n00b_acme_challenge_provider_t *provider)
    _kargs {
        int32_t timeout_ms       = 30000;
        int32_t poll_max_wait_ms = 60000;
    };
