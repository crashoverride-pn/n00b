#pragma once

/**
 * @file n00b_attest_oci.h
 * @brief OCI integration public surface — client handle, auth handle,
 *        and lifecycle entry points.
 *
 * Declarations for the opaque `n00b_attest_oci_client_t` and
 * `n00b_attest_oci_auth_t` types and the resolver / construction /
 * release entry points. The OCI client is the narrow HTTPS request /
 * response edge tailored to OCI 1.1 distribution-spec registries:
 * the substrate Phase 2's push and Phase 3's pull / discover verbs
 * compose on top of (D-051 OQ-2 + D-044 library-API-first split).
 *
 * # Algorithm-agnostic by construction (D-016)
 *
 * The OCI client is algorithm-agnostic by design: it ferries opaque
 * bytes (manifests, blobs, descriptors) to and from a registry. The
 * public surface bakes in no Ed25519-specific symbols and no other
 * algorithm tags. The signer / verifier abstractions handle algorithm
 * dispatch one layer up; the OCI client carries the resulting bytes.
 *
 * # Auth-source dispatch (D-051 OQ-1)
 *
 * WP-004 Phase 1 ships three of the five planned auth sources:
 *
 *   - @ref N00B_ATTEST_OCI_AUTH_CALLER — caller passes a pre-built
 *     auth handle to @ref n00b_attest_oci_client_new.
 *   - @ref N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON — reads
 *     `$XDG_CONFIG_HOME/n00b-attest/registries.json` (or
 *     `~/.config/n00b-attest/registries.json` when the env var is
 *     unset). NOT a drop-in `~/.docker/config.json` reader; the
 *     schema is N00B-specific.
 *   - @ref N00B_ATTEST_OCI_AUTH_ANONYMOUS — no token; the request
 *     helper omits the `Authorization` header.
 *
 * The remaining two sources are declared NOW in @ref
 * n00b_attest_oci_auth_source_t for forward-compat:
 *
 *   - @ref N00B_ATTEST_OCI_AUTH_CRED_HELPER — docker-credential-
 *     helper subprocess; requires `n00b_subproc_*` substrate that
 *     does not exist yet. Future Tier-2 WP.
 *   - @ref N00B_ATTEST_OCI_AUTH_KEYCHAIN — macOS Keychain via
 *     `Security.framework`; requires Objective-C bridging +
 *     entitlement disposition. Future Tier-2 WP.
 *
 * Invoking @ref n00b_attest_oci_auth_resolve with one of the
 * not-yet-shipped sources returns @ref
 * N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND.
 *
 * # Token-exchange (OCI distribution-spec § 5)
 *
 * On a 401 with `WWW-Authenticate: Bearer realm=...,service=...,
 * scope=...`, the request helper performs a second un-authenticated
 * GET against the realm URL (passing `service` + `scope` query
 * params), parses the `{"token": "..."}` (or `{"access_token":
 * "..."}`) response, caches the token on the client handle, and
 * retries the original request with the new bearer. A second 401
 * surfaces @ref N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED. The
 * token-exchange flow lives behind the internal `_request` helper
 * in `include/internal/attest/oci/registry.h` (not visible to
 * library consumers).
 *
 * # Lifetime
 *
 * Client and auth handles are reusable for the duration of a
 * publish / fetch session: build once, request many, release once.
 * The library maintains NO process-wide cache. Both `_release`
 * entry points are no-ops on null and tolerate double-release
 * silently (matches the libn00b release-then-use convention).
 *
 * @ref n00b_attest_oci_auth_release does NOT `crypto_wipe` the
 * held bearer / basic credentials in WP-004 Phase 1: bearer tokens
 * are short-lived (registry-issued, scope-bounded), and the
 * `crypto_wipe` discipline applies to long-lived secret-key material
 * (signer release). Defensive wipe of bearer-token state is a
 * Phase 4 hardening concern.
 *
 * # Allocator discipline
 *
 * Every allocating entry point on this surface carries
 * `.allocator = nullptr`. Threading an arena through
 * @ref n00b_attest_oci_client_new makes every byte the client
 * produces while serving subsequent requests live in that arena
 * (FR-21 / FR-22).
 *
 * # Optional-pointer kwargs (D-035 part 2 / DF-009)
 *
 * Optional pointer kwargs on this surface use `T * = nullptr`
 * rather than `n00b_option_t(T) = n00b_option_none(T)`, matching
 * the existing WP-001 / WP-002 / WP-003 module surfaces. This is a
 * project-local exception to the cross-project canonical
 * `n00b_option_t` shape; cross-project normalization is a later
 * cleanup WP.
 *
 * # No public symbols beyond this header
 *
 * The OCI substrate ships exactly: two opaque types + one auth-
 * source enum + four lifecycle entry points (`_client_new`,
 * `_auth_resolve`, `_client_release`, `_auth_release`). Internal
 * helpers (`_request`, `_url_parse`) live in
 * `include/internal/attest/oci/registry.h` for Phase 2+ consumers.
 */

#include <n00b.h>
#include "adt/result.h"
#include "adt/list.h"
#include "core/buffer.h"
#include "core/string.h"
#include <attest/n00b_attest_error.h>
#include "crypto/trust.h"

/*
 * The 4 OCI-domain error codes (-6001, -6003, -6004, -6005) live in
 * `n00b_attest_error.h` per the established error-namespace pattern
 * (Statement -1001…, DSSE -2001…, signer -4001…, verifier -5001…,
 * OCI -6001… per D-051 OQ-6). This header references them via
 * @ref tags only:
 *
 *   - @ref N00B_ATTEST_ERR_OCI_BAD_URL               (-6001)
 *   - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR            (-6003)
 *   - @ref N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED   (-6004)
 *   - @ref N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND (-6005)
 *
 * The two transport-distinction codes `_OCI_TLS_HANDSHAKE` (-6002)
 * and `_OCI_NETWORK_TIMEOUT` (-6006) are reserved-but-not-declared in
 * Phase 1 per D-046 strict (phase-introduces-codes-when-it-uses-them):
 * Phase 1's `_request` collapses every libn00b transport-level error
 * onto `_OCI_HTTP_ERROR`. Phase 2/3 reintroduces the distinctions when
 * the verb shims need them.
 */

/**
 * @brief Opaque OCI client handle.
 *
 * Constructed by @ref n00b_attest_oci_client_new, consumed by the
 * package-private `n00b_attest_oci_request` helper (Phase 2+ verb
 * shims compose on top of it), freed by
 * @ref n00b_attest_oci_client_release. The struct definition is
 * private to the module's `src/attest/oci/` translation units and
 * lives in the internal `registry.h` header; the concrete shape
 * (registry origin, auth handle, trust handle, redirect policy,
 * cached bearer token) is not exposed to library consumers.
 */
typedef struct n00b_attest_oci_client n00b_attest_oci_client_t;

/**
 * @brief Opaque OCI auth handle.
 *
 * Constructed by @ref n00b_attest_oci_auth_resolve, threaded into
 * @ref n00b_attest_oci_client_new via the `.auth` kwarg, freed by
 * @ref n00b_attest_oci_auth_release. The struct definition is
 * private to `src/attest/oci/auth.c`; the concrete shape (source
 * tag, registry filter, bearer / basic credential bytes) is not
 * exposed to library consumers.
 */
typedef struct n00b_attest_oci_auth n00b_attest_oci_auth_t;

/**
 * @brief Auth-source tags for @ref n00b_attest_oci_auth_resolve.
 *
 * WP-004 Phase 1 ships @ref N00B_ATTEST_OCI_AUTH_CALLER, @ref
 * N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON, and @ref
 * N00B_ATTEST_OCI_AUTH_ANONYMOUS. The remaining two sources are
 * declared NOW for forward-compat with the planned Tier-2 follow-on
 * WP (D-051 OQ-1) but their resolve path returns @ref
 * N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND until that WP lands.
 *
 * Default resolve order when @c .sources is `nullptr`:
 * `[CALLER, REGISTRIES_JSON, ANONYMOUS]`. The Tier-2 WP that ships
 * @ref N00B_ATTEST_OCI_AUTH_CRED_HELPER and @ref
 * N00B_ATTEST_OCI_AUTH_KEYCHAIN inserts them at their appropriate
 * ordering positions inside the resolver's default chain.
 */
typedef enum {
    /** Caller passes a pre-built auth handle to @ref
     *  n00b_attest_oci_client_new via the `.auth` kwarg. The
     *  resolver itself does not construct anything for this source;
     *  it is included in the default chain so the resolver can
     *  return @c Ok(nullptr) cleanly when no other source matches
     *  and the caller intends to thread an auth handle in directly.
     *  Ships unconditionally. */
    N00B_ATTEST_OCI_AUTH_CALLER         = 1,
    /** Reads `$XDG_CONFIG_HOME/n00b-attest/registries.json` (or
     *  `~/.config/n00b-attest/registries.json` when the env var is
     *  unset). The schema is N00B-specific (NOT a drop-in
     *  `~/.docker/config.json` reader): each top-level key is a
     *  registry hostname (e.g. `"ghcr.io"`) mapped to an object
     *  carrying either an `"auth"` field (base64 of `user:pass` —
     *  Basic auth) or a `"token"` field (bearer-token string).
     *  Missing file is NOT an error — the resolver falls through to
     *  the next source. Malformed JSON surfaces as @ref
     *  N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND (NOT a bad-JSON
     *  code — the user's broader auth resolution may still succeed
     *  via another source). Ships unconditionally. */
    N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON = 2,
    /** No-token auth handle. The request helper omits the
     *  `Authorization` header when this is the resolved shape.
     *  Ships unconditionally as the terminal fallback. */
    N00B_ATTEST_OCI_AUTH_ANONYMOUS      = 3,
    /** Future Tier-2 WP: docker-credential-helper subprocess.
     *  Declared NOW for forward-compat; the WP-004 Phase 1
     *  resolver returns @ref
     *  N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND when invoked. */
    N00B_ATTEST_OCI_AUTH_CRED_HELPER    = 4,
    /** Future Tier-2 WP: macOS Keychain via `Security.framework`.
     *  Declared NOW for forward-compat; the WP-004 Phase 1
     *  resolver returns @ref
     *  N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND when invoked. */
    N00B_ATTEST_OCI_AUTH_KEYCHAIN       = 5,
} n00b_attest_oci_auth_source_t;

/**
 * @brief Construct an OCI client bound to one registry origin.
 *
 * @param registry_url  Absolute HTTPS URL of the registry origin
 *                      (e.g. `"https://ghcr.io"`). The OCI request
 *                      helper composes per-call paths against this
 *                      origin; the origin itself is not contacted
 *                      at client-construction time. Required.
 *
 * @kw auth                     Optional pre-built auth handle (per
 *                              @ref N00B_ATTEST_OCI_AUTH_CALLER). When
 *                              `nullptr` the client is anonymous
 *                              until the request helper performs a
 *                              token-exchange against a registry
 *                              `WWW-Authenticate: Bearer` challenge.
 * @kw trust                    Optional libn00b trust handle for the
 *                              underlying HTTPS layer. When
 *                              `nullptr` the dispatcher uses system
 *                              trust. Test fixtures pass an explicit
 *                              `n00b_quic_trust_pinned(...)` for
 *                              self-signed registries (e.g.
 *                              `localhost:5000` zot in `N00B_TEST_
 *                              DOCKER=1` integration).
 * @kw timeout_ms               Client-level per-request wall-clock
 *                              deadline in milliseconds. Sets the
 *                              default applied by every verb-level
 *                              operation when its own
 *                              `timeout_ms` kwarg is `0`. `0` at
 *                              this level means "use the op-
 *                              specific default" (push 60s, pull
 *                              30s, discover 10s per D-051 OQ-8 +
 *                              Phase 4 hardening). The full
 *                              precedence chain is therefore:
 *                              op-level kwarg (non-zero) → this
 *                              client-level default (non-zero) →
 *                              op-specific default. Default `0`.
 * @kw allow_redirects          When `true` the OCI client passes
 *                              `follow_redirects = true,
 *                              max_redirects = 1` into libn00b's
 *                              dispatcher; libn00b enforces the
 *                              HTTPS-only-on-3xx policy (RFC 9110
 *                              § 15.4 + the cross-scheme reject
 *                              documented on @ref
 *                              n00b_http_request_sync). When
 *                              `false` 3xx responses surface
 *                              directly to the caller. Default
 *                              `true`. Per the WP-004 Phase 4
 *                              hardening mandate (D-051 OQ-7 +
 *                              user direction 2026-05-19), the OCI
 *                              client delegates redirect-policy
 *                              enforcement to libn00b's machinery
 *                              rather than rolling its own.
 * @kw redirect_host_allowlist  Optional list of registry hostnames
 *                              the dispatcher is allowed to redirect
 *                              to. `nullptr` means "no host
 *                              allowlisting" (per D-051 OQ-7: this
 *                              is a per-call kwarg, not process-
 *                              wide state). Each entry is one of:
 *
 *                                - An exact host (no `*`) —
 *                                  matched ASCII-CI byte equality
 *                                  in ACE / Punycode space.
 *                                - A wildcard `*.DOMAIN` with at
 *                                  least one label after the
 *                                  leading `*.` — matches any host
 *                                  of the form `X.DOMAIN` for
 *                                  non-empty `X`.  The apex
 *                                  `DOMAIN` itself is NOT matched;
 *                                  add a second non-wildcard entry
 *                                  `DOMAIN` to permit it.
 *                                - Anything else (`foo.*.com`,
 *                                  `**.example.com`, `*example.com`,
 *                                  bare `*`) — malformed and
 *                                  silently skipped.
 *
 *                              **IDN / UTS-46 support.**  Both the
 *                              next-hop host and each entry are
 *                              IDNA-canonicalized via @ref
 *                              n00b_unicode_idna_to_ascii before
 *                              comparison; for a wildcard entry,
 *                              only the `DOMAIN` portion after the
 *                              literal `*.` is canonicalized.
 *                              Unicode (`*.例え.com`) and Punycode
 *                              (`*.xn--r8jz45g.com`) forms cross-
 *                              match in either direction.  Pure-
 *                              ASCII entries behave byte-identically
 *                              to the pre-IDN matcher.  Entries
 *                              whose canonicalizable portion fails
 *                              IDNA are silently skipped like any
 *                              other malformed entry.
 *
 *                              Threading is full end-to-end as of
 *                              the DF-014/15 + Phase-5 closeout
 *                              lifts: libn00b's @ref
 *                              n00b_http_request_sync carries the
 *                              matching per-call kwarg and the OCI
 *                              client forwards the stored list
 *                              verbatim.  Entries are stored
 *                              as-passed; classification +
 *                              canonicalization happen per-entry
 *                              at match time, not at insertion.
 * @kw allocator                Optional allocator (defaults to the
 *                              runtime allocator). Owns the returned
 *                              client handle plus every byte the
 *                              client produces while serving
 *                              subsequent requests.
 *
 * @return `n00b_result_ok(n00b_attest_oci_client_t *, client)` on
 *         success; `n00b_result_err(n00b_attest_oci_client_t *,
 *         N00B_ATTEST_ERR_OCI_BAD_URL)` when @p registry_url is null,
 *         empty, or otherwise malformed (e.g. does not start with
 *         `https://`). All other failures surface from the underlying
 *         HTTPS dispatcher at request time, not at construction
 *         time.
 *
 *         Phase 1 ships bare-code Err legs; richer Err payloads
 *         (HTTP status, response body, human-readable diagnostic
 *         text) are deferred to the libn00b typed-Err-payload lift
 *         tracked as DF-011.
 *
 * @post The returned client handle owns a copy of its registry
 *       origin and (if set) the redirect host allowlist. The
 *       caller MUST call @ref n00b_attest_oci_client_release at
 *       end-of-use to free the client handle's cached state.
 */
extern n00b_result_t(n00b_attest_oci_client_t *)
n00b_attest_oci_client_new(n00b_string_t *registry_url)
    _kargs {
        n00b_attest_oci_auth_t       *auth                    = nullptr;
        n00b_quic_trust_t            *trust                   = nullptr;
        uint64_t                      timeout_ms              = 0;
        bool                          allow_redirects         = true;
        n00b_list_t(n00b_string_t *) *redirect_host_allowlist = nullptr;
        n00b_allocator_t             *allocator               = nullptr;
    };

/**
 * @brief Resolve an OCI auth handle by walking the configured
 *        auth sources.
 *
 * @kw registry   Optional registry hostname filter. When set, the
 *                resolver only considers credentials whose source-
 *                emitted scope matches this hostname (e.g. for
 *                @ref N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON the
 *                resolver looks up the JSON object keyed by this
 *                hostname). When `nullptr` the resolver returns
 *                the first non-empty credential found in any source.
 *                Default `nullptr`.
 *
 *                **IDN / UTS-46 support (DF-J, 2026-05-20).** The
 *                filter is matched against `registries.json` keys
 *                under IDNA canonicalization via @ref
 *                n00b_unicode_idna_to_ascii: pure-ASCII filters
 *                behave byte-identically (modulo UTS-46 case
 *                folding); a Unicode filter (`例え.com`) cross-
 *                matches a Punycode JSON key (`xn--r8jz45g.com`)
 *                and vice versa. The optional `:port` suffix is
 *                preserved verbatim across canonicalization. The
 *                helper's fast path is raw byte equality so the
 *                dominant ASCII case has no per-call IDNA cost;
 *                IDNA is only invoked when the byte compare fails.
 * @kw sources    Optional ordered list of @ref
 *                n00b_attest_oci_auth_source_t enum values
 *                indicating which sources to walk and in what
 *                order. When `nullptr` the resolver uses the
 *                default order: @c [CALLER, REGISTRIES_JSON,
 *                ANONYMOUS]. Default `nullptr`.
 * @kw allocator  Optional allocator (defaults to the runtime
 *                allocator). Owns the returned auth handle plus
 *                every byte the resolver allocates while walking
 *                the source chain.
 *
 * @return `n00b_result_ok(n00b_attest_oci_auth_t *, auth)` on
 *         success; `n00b_result_err(n00b_attest_oci_auth_t *,
 *         N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND)` when no
 *         configured source yielded credentials (the trivial
 *         @ref N00B_ATTEST_OCI_AUTH_ANONYMOUS source always
 *         succeeds with a no-token handle, so this error surfaces
 *         only when the caller explicitly limited the source chain
 *         to a non-trivial subset that all failed, OR when the
 *         caller requested one of the future-WP sources
 *         @ref N00B_ATTEST_OCI_AUTH_CRED_HELPER or @ref
 *         N00B_ATTEST_OCI_AUTH_KEYCHAIN which are reserved-but-
 *         not-implemented in WP-004 Phase 1).
 *
 *         Phase 1 ships bare-code Err legs; richer Err payloads
 *         (per-source diagnostic detail) are deferred to the
 *         libn00b typed-Err-payload lift tracked as DF-011.
 *
 * @note Per @ref N00B_ATTEST_OCI_AUTH_CALLER's documentation, the
 *       resolver's @c CALLER source slot is a no-op: a caller that
 *       has a pre-built auth handle threads it directly into @ref
 *       n00b_attest_oci_client_new via the `.auth` kwarg without
 *       calling this resolver. The slot exists in the default
 *       source chain so that "caller-provided" remains a documented
 *       step in the resolution order; the resolver itself
 *       constructs nothing for it.
 *
 * @post The returned auth handle owns a copy of the credential
 *       bytes (bearer token, or base64-of-user:pass for Basic).
 *       The caller MUST call @ref n00b_attest_oci_auth_release at
 *       end-of-use to free the cached state.
 */
extern n00b_result_t(n00b_attest_oci_auth_t *)
n00b_attest_oci_auth_resolve()
    _kargs {
        n00b_string_t                                 *registry  = nullptr;
        n00b_list_t(n00b_attest_oci_auth_source_t)    *sources   = nullptr;
        n00b_allocator_t                              *allocator = nullptr;
    };

/**
 * @brief Release an OCI client handle.
 *
 * @param client  The client handle to release. Calling on a null
 *                pointer is a no-op.
 *
 * @details
 *
 * Symmetric with @ref n00b_attest_signer_release / @ref
 * n00b_attest_verifier_release. No `crypto_wipe` is performed: the
 * client holds an HTTPS origin URL, an auth-handle pointer (whose
 * lifetime is the caller's), an optional trust handle (whose
 * lifetime is the caller's), and a per-scope cache of the most
 * recent bearer token returned by the registry's token-exchange
 * flow. None of these are long-lived secret material; the
 * defensive-wipe discipline that applies to signer-side private-
 * key bytes does NOT apply here. Defensive wipe of cached bearer
 * tokens is a Phase 4 hardening concern.
 *
 * @post Every cached buffer the client held is returned to the
 *       allocator. Calling any other entry point with this client
 *       handle after release is undefined behavior (matching the
 *       libn00b release-then-use convention). The handles
 *       threaded in via `.auth` and `.trust` are NOT released by
 *       this call — the caller owns their lifetime.
 */
extern void
n00b_attest_oci_client_release(n00b_attest_oci_client_t *client);

/**
 * @brief Release an OCI auth handle.
 *
 * @param auth  The auth handle to release. Calling on a null
 *              pointer is a no-op.
 *
 * @details
 *
 * Symmetric with @ref n00b_attest_oci_client_release. No
 * `crypto_wipe` is performed in WP-004 Phase 1: bearer tokens are
 * short-lived and registry-issued, and the Basic-auth credentials
 * (base64 of `user:pass`) are loaded fresh from disk on each
 * resolve. Defensive wipe of the held credential bytes is a Phase
 * 4 hardening concern.
 *
 * @post Every cached buffer the auth handle held is returned to
 *       the allocator. Calling any other entry point with this
 *       auth handle after release is undefined behavior. Releasing
 *       an auth handle that is currently threaded into a live
 *       client handle's `.auth` slot is a use-after-free; callers
 *       MUST release the client first.
 */
extern void
n00b_attest_oci_auth_release(n00b_attest_oci_auth_t *auth);

/**
 * @brief Push a DSSE envelope to an OCI 1.1 registry as a referrer
 *        of an existing image manifest.
 *
 * Orchestrates the producer-side flow specified in
 * `docs/attest/02-architecture.md` §8.2:
 *
 *   1. Compute the envelope's SHA-256 digest.
 *   2. HEAD the subject image manifest to learn its byte-size
 *      (HEAD-primary + GET-fallback per D-054; some non-strict
 *      registries 405 HEAD).
 *   3. POST + PUT-upload the envelope bytes as a blob with
 *      `Content-Type: application/vnd.in-toto+json`.
 *   4. Build the canonical OCI 1.1 artifact-manifest JSON
 *      referring to the subject image manifest and the envelope
 *      layer, carrying the predicate-type and signer-keyid
 *      annotations.
 *   5. Compute the manifest's own SHA-256 digest.
 *   6. PUT-upload the manifest at
 *      `/v2/<name>/manifests/<manifest-digest>`. The registry
 *      treats the upload as a referrer of the subject by virtue
 *      of the `subject` field inside the manifest.
 *   7. Return the manifest digest.
 *
 * The function is **algorithm-agnostic at this surface** (D-016):
 * the envelope's signing algorithm is captured only inside the
 * envelope itself; the OCI surface ferries opaque bytes.
 *
 * @param client          The OCI client handle (constructed via
 *                        @ref n00b_attest_oci_client_new).
 *                        Required.
 * @param name            Repository name (e.g. `"foo/bar"`).
 *                        Required.
 * @param image_digest    The subject image manifest's digest
 *                        (e.g. `"sha256:abc..."`). The caller
 *                        typically extracts this from the
 *                        `--image foo/bar@sha256:...` ref via
 *                        @ref n00b_attest_oci_url_parse (internal).
 *                        Required.
 * @param envelope_bytes  The DSSE envelope JSON bytes to push.
 *                        Required.
 *
 * @kw predicate_type  Required-at-runtime predicate-type URI for
 *                     the `com.crashoverride.attestation.predicate-
 *                     type` annotation. Null surfaces as @ref
 *                     N00B_ATTEST_ERR_DSSE_BAD_INPUT (caller-side
 *                     validation; verb shim derives this from the
 *                     envelope payload before invoking).
 * @kw signer_keyid    Required-at-runtime canonical lowercase-hex
 *                     SHA-256 of the signer's SPKI DER (per D-039)
 *                     for the `com.crashoverride.attestation.
 *                     signer-keyid` annotation. Null surfaces as
 *                     @ref N00B_ATTEST_ERR_DSSE_BAD_INPUT.
 * @kw timeout_ms      Optional per-call wall-clock deadline in
 *                     milliseconds for the entire push sequence
 *                     (HEAD subject + POST/PUT blob + PUT
 *                     manifest). `0` falls through to the
 *                     client-level `timeout_ms` set at @ref
 *                     n00b_attest_oci_client_new; if that is also
 *                     `0`, the push-specific default of 60000 ms
 *                     applies per D-051 OQ-8. The push-side
 *                     default is the largest of the three per-op
 *                     defaults because push has the most sub-
 *                     requests (4 round-trips) and the largest
 *                     body sizes (envelope blob upload). Default
 *                     `0`.
 * @kw allocator      Optional allocator (defaults to the client's
 *                     construction-time allocator). Owns every
 *                     byte the push produces.
 *
 * @return `n00b_result_ok(n00b_string_t *, manifest_digest)` on
 *         success — the canonical `sha256:<hex>` digest of the
 *         uploaded artifact manifest, as confirmed by the
 *         registry (or computed locally when the registry omitted
 *         `Docker-Content-Digest`). Err legs route through:
 *
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_URL — null required
 *           inputs / malformed registry-side URL.
 *         - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR — transport or
 *           non-success status on any sub-step (HEAD subject,
 *           POST blob upload init, PUT blob upload finish, PUT
 *           manifest upload).
 *         - @ref N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED — bearer
 *           token-exchange flow failed on any sub-step.
 *         - @ref N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH —
 *           the registry-reported manifest digest disagreed with
 *           the locally-computed digest (integrity concern;
 *           registry transformed the manifest in transit).
 *         - @ref N00B_ATTEST_ERR_DSSE_BAD_INPUT — a required
 *           kwarg was null at call time.
 *
 *         Phase 2 ships bare-code Err legs per D-053; richer Err
 *         payloads (HTTP status, registry response body, human-
 *         readable diagnostic text) are deferred to the libn00b
 *         typed-Err-payload future lift tracked as DF-011.
 *
 * @note No module-level state — the function is safe to invoke
 *       concurrently from multiple threads against DIFFERENT
 *       client handles. The single client handle itself is
 *       single-owner; concurrent calls against the same client
 *       are not safe (matches the libn00b convention).
 *
 * @pre The OCI client + auth handles in @p client were
 *      constructed against the same registry origin to which the
 *      caller intends to push. The subject image manifest
 *      identified by @p image_digest must already be present in
 *      that registry — Step 2 above HEADs the subject pre-push
 *      and surfaces 404 as @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR.
 * @post The envelope blob, the artifact manifest, and the
 *       referrer link from the artifact manifest's `subject`
 *       field to the subject image manifest are durably stored
 *       in the registry. The client's cached bearer token (if
 *       any) may have rotated.
 */
extern n00b_result_t(n00b_string_t *)
n00b_attest_oci_push_attestation(n00b_attest_oci_client_t *client,
                                 n00b_string_t            *name,
                                 n00b_string_t            *image_digest,
                                 n00b_buffer_t            *envelope_bytes)
    _kargs {
        n00b_string_t    *predicate_type = nullptr;
        n00b_string_t    *signer_keyid   = nullptr;
        uint64_t          timeout_ms     = 0;
        n00b_allocator_t *allocator      = nullptr;
    };

/**
 * @brief A single referrer entry returned by
 *        @ref n00b_attest_oci_list_referrers.
 *
 * Each entry corresponds to one manifest in the OCI 1.1 referrers
 * index for a subject digest. The struct is a public POD: callers
 * read fields directly (e.g. `r->predicate_type`) — no
 * getters/setters per the D-055 carve-out (D-055's read-side getter
 * pattern applies to opaque parse-surface types, not to public PODs).
 *
 * # Annotation extraction
 *
 * The `predicate_type` and `signer_keyid` fields are populated from
 * the referrer manifest's `annotations` map: the verb-side push
 * (`n00b_attest_oci_push_attestation`) writes
 * `com.crashoverride.attestation.predicate-type` and
 * `com.crashoverride.attestation.signer-keyid` annotations on the
 * artifact manifest; the discover-side listing surfaces those values
 * back via these fields. Either annotation absent on the referrer
 * surfaces as `nullptr` on the corresponding field (not an error;
 * older / third-party tooling may write referrer manifests without
 * the project's annotation conventions).
 *
 * # manifest_bytes
 *
 * The verb-side `_list_referrers` does NOT fetch each referrer's full
 * manifest bytes; the `manifest_bytes` field is reserved for future
 * use (a caller-side `_full = true` flag on `_list_referrers` could
 * populate it). At Phase 3 the field is always `nullptr`; downstream
 * consumers that need the manifest bytes should call
 * @ref n00b_attest_oci_manifest_fetch(client, name, manifest_digest)
 * explicitly.
 */
typedef struct n00b_attest_oci_referrer {
    /** Manifest digest (`sha256:<hex>`) of the referrer manifest as
     *  reported by the registry's referrers index. Required (never
     *  `nullptr` on a valid entry). */
    n00b_string_t *manifest_digest;
    /** Value of the `com.crashoverride.attestation.predicate-type`
     *  annotation on the referrer manifest, or `nullptr` if the
     *  annotation is absent. */
    n00b_string_t *predicate_type;
    /** Value of the `com.crashoverride.attestation.signer-keyid`
     *  annotation on the referrer manifest, or `nullptr` if the
     *  annotation is absent. */
    n00b_string_t *signer_keyid;
    /** Reserved — always `nullptr` at WP-004 Phase 3. A future verb-
     *  level flag may populate this field with the full referrer
     *  manifest bytes. */
    n00b_buffer_t *manifest_bytes;
} n00b_attest_oci_referrer_t;

/**
 * @brief List the OCI 1.1 referrers of a subject digest.
 *
 * Hits `/v2/<name>/referrers/<image_digest>[?artifactType=<type>]`,
 * parses the returned OCI index, and follows the `Link: </next>;
 * rel="next"` pagination chain (RFC 8288) until exhausted.
 * Concatenates all pages into one returned list.
 *
 * # Server-side vs client-side filtering (D-051 OQ-3 BOTH)
 *
 * When `.artifact_type` is set, the URL gets `?artifactType=<value>`
 * (server-side filter per OCI distribution-spec § 4.5). When null,
 * the URL omits the query parameter and the registry returns the
 * full referrers index. The verb-core consumer
 * (`n00b_attest_cli_pull`) layers a client-side `predicate_type`
 * post-filter on top of the returned list — defense-in-depth in
 * case the registry ignores the `?artifactType=` parameter (older
 * Harbor / Docker Hub historic behavior). This helper does NOT
 * post-filter; it returns what the server returned.
 *
 * # Empty list and 404
 *
 * A 200-OK response with empty `manifests[]` returns
 * `n00b_result_ok([])`. Per OCI distribution-spec § 4.5 some
 * registries return 404 when the subject does not exist; this is
 * ALSO treated as `n00b_result_ok([])` — the caller's semantic is
 * "tell me what referrers exist for this digest"; both shapes
 * answer "none."
 *
 * # Pagination cap
 *
 * Phase 3 imposes a soft cap of 100 pages to prevent pathological
 * cases. The cap is internal to this helper; Phase 4 hardening will
 * replace with a configurable kwarg. Hitting the cap stops the walk
 * and returns whatever was accumulated so far without an error
 * (the caller sees a partial list; flagged for future hardening).
 *
 * @param client        OCI client handle (constructed via
 *                      @ref n00b_attest_oci_client_new). Required.
 * @param name          Repository name (e.g. `"foo/bar"`). Required.
 * @param image_digest  Subject manifest digest (`sha256:<hex>`).
 *                      Required.
 *
 * @kw artifact_type  Optional server-side artifact-type filter
 *                    (e.g. `r"application/vnd.in-toto+dsse"`). When
 *                    null, no filter is applied at the server.
 * @kw timeout_ms     Optional per-call wall-clock deadline in
 *                    milliseconds applied to EACH page-request
 *                    round-trip (NOT the cumulative pagination
 *                    walk). `0` falls through to the client-level
 *                    `timeout_ms` set at @ref
 *                    n00b_attest_oci_client_new; if that is also
 *                    `0`, the discover-specific default of 10000
 *                    ms applies per D-051 OQ-8. Default `0`.
 * @kw allocator      Optional allocator (defaults to the client's
 *                    construction-time allocator). Owns the returned
 *                    list and every byte it points at.
 *
 * @return `n00b_result_ok(n00b_list_t *, list)` on success — a
 *         `n00b_list_t(n00b_attest_oci_referrer_t *)` carrying zero
 *         or more entries. The list itself is non-null even when
 *         empty; iterate via `n00b_list_foreach`.
 *
 *         Err legs route through:
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_URL — null required inputs.
 *         - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR — transport or
 *           non-success status (other than 404, which is `Ok([])`).
 *         - @ref N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED — bearer
 *           token-exchange flow failed.
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX — server
 *           returned 200 OK but the response body is not a
 *           well-formed OCI referrers index.
 *
 * @pre The OCI client in @p client was constructed against the
 *      registry origin to which the caller intends to list.
 * @post The returned list is owned by the per-call allocator.
 */
extern n00b_result_t(n00b_list_t(n00b_attest_oci_referrer_t *) *)
n00b_attest_oci_list_referrers(n00b_attest_oci_client_t      *client,
                               n00b_string_t                 *name,
                               n00b_string_t                 *image_digest)
    _kargs {
        n00b_string_t    *artifact_type = nullptr;
        uint64_t          timeout_ms    = 0;
        n00b_allocator_t *allocator     = nullptr;
    };

/**
 * @brief Pull a DSSE envelope from an OCI 1.1 registry given the
 *        referrer manifest digest.
 *
 * Composes:
 *   1. Fetch the referrer manifest via
 *      @ref n00b_attest_oci_manifest_fetch.
 *   2. Parse the manifest JSON; walk `layers[0].digest` (the
 *      envelope blob digest, per spec §8.2).
 *   3. Fetch the envelope blob via internal blob-fetch.
 *   4. Return the envelope bytes.
 *
 * **Does NOT verify the envelope.** Verification is a separate
 * @ref n00b_attest_cli_verify invocation. Pull's job is exactly the
 * round-trip "get me the bytes back"; signature verification is a
 * deliberately-distinct verb so the consumer can audit the bytes
 * in-place before trusting them.
 *
 * The function assumes the referrer manifest follows the spec §8.2
 * shape that the push side produces: single `layers[]` entry whose
 * `mediaType` is `application/vnd.in-toto+json` and whose `digest`
 * points at the envelope blob. A `layers[]` count other than 1, or
 * a missing `digest` field, surfaces as
 * @ref N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX.
 *
 * @param client            OCI client handle. Required.
 * @param name              Repository name. Required.
 * @param manifest_digest   Referrer manifest digest (`sha256:<hex>`).
 *                          Required.
 *
 * @kw timeout_ms  Optional per-call wall-clock deadline in
 *                 milliseconds applied to EACH of the two
 *                 round-trips this verb composes (manifest fetch
 *                 + blob fetch). `0` falls through to the client-
 *                 level `timeout_ms` set at @ref
 *                 n00b_attest_oci_client_new; if that is also
 *                 `0`, the pull-specific default of 30000 ms
 *                 applies per D-051 OQ-8. Default `0`.
 * @kw allocator  Optional allocator (defaults to the client's
 *                construction-time allocator). Owns the returned
 *                envelope buffer.
 *
 * @return `n00b_result_ok(n00b_buffer_t *, envelope_bytes)` on
 *         success. Err legs route through:
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_URL — null inputs.
 *         - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR — transport / non-
 *           success status on the manifest fetch or blob fetch.
 *         - @ref N00B_ATTEST_ERR_OCI_BLOB_DIGEST_MISMATCH — fetched
 *           blob's SHA-256 disagrees with the manifest's claimed
 *           `layers[0].digest`.
 *         - @ref N00B_ATTEST_ERR_OCI_BLOB_TOO_LARGE — fetched blob
 *           exceeds the size cap (1 MiB by default per NFR-5).
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_REFERRER_INDEX — manifest
 *           JSON shape did not match spec §8.2 single-layer
 *           in-toto+json expectation.
 *
 * @post The returned envelope buffer is owned by the per-call
 *       allocator. The caller can pass it directly into
 *       @ref n00b_attest_cli_verify for verification, or into
 *       @ref n00b_attest_envelope_parse for inspection.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_pull_envelope(n00b_attest_oci_client_t *client,
                              n00b_string_t            *name,
                              n00b_string_t            *manifest_digest)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    };
