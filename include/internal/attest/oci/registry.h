#pragma once

/**
 * @file include/internal/attest/oci/registry.h
 * @internal
 * @brief Package-private OCI helpers — request dispatch + URL parse +
 *        struct definitions.
 *
 * Internal header consumed by `src/attest/oci/registry.c`,
 * `src/attest/oci/auth.c`, and (in Phase 2/3) the verb-shim
 * implementations under `src/attest/oci/` and the CLI cores under
 * `src/attest/cli.c`. NOT visible to library consumers — the public
 * surface lives in `include/attest/n00b_attest_oci.h`.
 *
 * # File-organization note
 *
 * Per D-051 OQ-9 the file path is `include/internal/attest/oci/...`
 * (NOT `include/private/attest/oci/...`; the latter framing was a
 * stale orchestrator-prompt typo — no `include/private/` tree exists
 * in this codebase). The OCI sub-tree under `include/internal/`
 * mirrors the `verifier_backends/` precedent from WP-003.
 */

#include <n00b.h>
#include "adt/result.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "core/string.h"
#include "core/buffer.h"
#include "net/http/http_client.h"
#include "crypto/trust.h"
#include <attest/n00b_attest_oci.h>

// ---------------------------------------------------------------------------
// Concrete struct definitions.
// ---------------------------------------------------------------------------

/**
 * @internal
 * @brief Concrete OCI client struct.
 *
 * Owned by @ref n00b_attest_oci_client_new; freed by @ref
 * n00b_attest_oci_client_release. Per the WP-004 Phase 1 simplest-
 * shipping shape the client caches the most recent bearer token
 * keyed by scope; subsequent requests for the same scope reuse it;
 * a different scope triggers a fresh exchange. Phase 4 hardening
 * may revisit the caching model (LRU multi-scope cache, expiry
 * tracking).
 */
struct n00b_attest_oci_client {
    /** Registry origin (e.g. `"https://ghcr.io"`). Owned by the
     *  client allocator. */
    n00b_string_t                *registry_origin;
    /** Optional caller-provided auth handle. The client does NOT
     *  own the lifetime of this handle (the caller does); the
     *  pointer is stored for use by `n00b_attest_oci_request` and
     *  must remain valid for as long as the client is in use. */
    n00b_attest_oci_auth_t       *auth;
    /** Optional libn00b HTTPS trust handle. Not owned by the
     *  client. */
    n00b_quic_trust_t            *trust;
    /** Client-level per-request timeout in ms. `0` means "use
     *  per-op defaults" (push 60s / pull 30s / discover 10s as
     *  set by the verb-level shims per D-051 OQ-8 + WP-004 Phase
     *  4 hardening). The verb shims resolve the effective
     *  per-call timeout via the precedence chain `op-level kwarg
     *  → client-level → op-specific default`. */
    uint64_t                      timeout_ms;
    /** Follow 3xx redirects. */
    bool                          allow_redirects;
    /** Optional redirect host allowlist (D-051 OQ-7). `nullptr`
     *  means no host-allowlisting is applied. WP-004 Phase 4
     *  flagged a libn00b gap: the underlying
     *  @ref n00b_http_request_sync does NOT (yet) carry a
     *  matching kwarg, so host-allowlist enforcement is currently
     *  delegated to libn00b but not actually wired. The kwarg is
     *  preserved on the handle for forward-compat with the
     *  libn00b lift, tracked as **DF-015**; callers passing the
     *  list today get the storage but no active enforcement. */
    n00b_list_t(n00b_string_t *) *redirect_host_allowlist;
    /** Most-recently-fetched bearer token cached for re-use on
     *  same-scope requests (Phase 1's simplest-shipping shape per
     *  D-051 plan section "bearer token caching"). `nullptr` means no
     *  cached token yet. */
    n00b_buffer_t                *cached_bearer_token;
    /** Scope string that produced @c cached_bearer_token. The
     *  request helper invalidates the cache when the next request's
     *  scope kwarg does not byte-equal this string. */
    n00b_string_t                *cached_bearer_scope;
    /** Allocator the client was constructed with (kept on the
     *  handle so internal allocations during request dispatch can
     *  thread it through). */
    n00b_allocator_t             *allocator;
};

/**
 * @internal
 * @brief Concrete OCI auth struct.
 *
 * Owned by @ref n00b_attest_oci_auth_resolve (or constructed
 * directly by a caller invoking the resolver-with-CALLER source);
 * freed by @ref n00b_attest_oci_auth_release.
 */
struct n00b_attest_oci_auth {
    /** Tag indicating which source produced this handle. The
     *  source informs how the request helper applies the
     *  credential (bearer vs basic vs anonymous). */
    n00b_attest_oci_auth_source_t  source;
    /** Optional registry hostname filter (e.g. `"ghcr.io"`). When
     *  set, the handle is only valid for the matching registry. */
    n00b_string_t                 *registry;
    /** Bearer token bytes (e.g. JWT). Set for handles produced
     *  from `"token"` JSON entries or caller-constructed bearer
     *  handles. `nullptr` otherwise. */
    n00b_buffer_t                 *bearer_token;
    /** Base64-of-user:pass bytes for Basic auth. Set for handles
     *  produced from `"auth"` JSON entries. `nullptr` otherwise. */
    n00b_buffer_t                 *basic_auth;
    /** Allocator the handle was constructed with. */
    n00b_allocator_t              *allocator;
};

/**
 * @internal
 * @brief Parsed OCI image reference.
 *
 * The `[<registry>/]<name>{@<digest>|:<tag>}` form per OCI
 * distribution-spec § 4.1. One of `digest` / `tag` is always set;
 * the other is `nullptr`. `registry` is `nullptr` when the input
 * reference omits the registry prefix (the caller supplies a
 * default registry at construction time).
 *
 * The struct lives in this internal header (not the public one)
 * because Phase 1 ships only the URL parser substrate; Phase 2's
 * push verb shim is the first consumer of the parsed shape.
 */
typedef struct n00b_attest_oci_image_ref {
    /** Registry hostname (with optional `:port`), or `nullptr` if
     *  the input omitted the prefix. Owned by the parser's
     *  allocator.
     *
     *  **Form: raw, NOT IDNA-canonicalized.** The parser slices
     *  the registry substring verbatim from the input image ref.
     *  Downstream consumers that build a wire URL (e.g. via
     *  `build_registry_origin` in `src/attest/cli.c`) get the
     *  URL parser's DF-X IDNA canonicalization for free; consumers
     *  that compare this field directly against another host
     *  string (e.g. `n00b_attest_oci_auth_resolve`'s `.registry`
     *  kwarg lookup against `registries.json` keys) must
     *  re-canonicalize at compare time. The auth-side helper does
     *  this internally (DF-J, 2026-05-20). */
    n00b_string_t *registry;
    /** Repository name (e.g. `"foo/bar"`). Required (never
     *  `nullptr` on success). */
    n00b_string_t *name;
    /** Digest reference (e.g. `"sha256:abcdef..."`), or `nullptr`
     *  if the input was tag-form. Mutually exclusive with @c tag. */
    n00b_string_t *digest;
    /** Tag reference (e.g. `"latest"`), or `nullptr` if the input
     *  was digest-form. Mutually exclusive with @c digest. */
    n00b_string_t *tag;
    /** Original `image_ref` input verbatim, retained for audit /
     *  error-context use. */
    n00b_string_t *full_ref;
} n00b_attest_oci_image_ref_t;

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/**
 * @internal
 * @brief Central HTTP request dispatch helper for the OCI client.
 *
 * Builds the absolute URL from `client->registry_origin` + @p path,
 * injects the `Authorization` header from the client's bound auth
 * handle (if any), threads `client->timeout_ms` and `client->trust`
 * into the libn00b HTTPS dispatcher, and performs the OCI
 * distribution-spec § 5 token-exchange retry transparently:
 *
 *   1. Issue the request.
 *   2. If the response status is 401 AND carries a
 *      `WWW-Authenticate: Bearer realm=...,service=...,scope=...`
 *      header, perform a second un-authenticated GET against the
 *      realm URL (passing `service` + `scope` as query params),
 *      parse the JSON response (accept both `{"token": "..."}` and
 *      `{"access_token": "..."}` per real-world registry variance),
 *      cache the token on the client (`cached_bearer_token` +
 *      `cached_bearer_scope`), and retry the original request with
 *      the new bearer.
 *   3. If the retry is also 401 (or the token-exchange JSON is
 *      malformed), return @ref
 *      N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED.
 *
 * HTTPS is enforced — Plain HTTP at the underlying libn00b layer
 * returns @ref N00B_ATTEST_ERR_OCI_BAD_URL.
 *
 * @param client  The OCI client handle. Required.
 * @param method  HTTP method verb (`"GET"`, `"POST"`, `"PUT"`,
 *                `"DELETE"`, etc.). Required.
 * @param path    Path component (e.g. `"/v2/foo/bar/manifests/
 *                sha256:abc..."`). The helper composes it against
 *                `client->registry_origin`. Required.
 *
 * @kw body          Optional request body.
 * @kw content_type  Required when @c body is non-null. No default;
 *                   caller picks the appropriate OCI media type
 *                   (e.g. `"application/vnd.oci.image.manifest.v1
 *                   +json"`).
 * @kw headers       Optional caller-supplied extra headers as a
 *                   `{name: value}` dict. The helper merges these
 *                   into the request bag after `Authorization`,
 *                   so caller-set values win on key collision.
 * @kw scope         OCI bearer-token-exchange scope string (e.g.
 *                   `"repository:foo/bar:pull"`). When set, the
 *                   helper uses this scope for the token-exchange
 *                   retry's `scope=` query param and for the
 *                   `cached_bearer_scope` cache key. When `nullptr`
 *                   the helper does not perform scope-based cache
 *                   matching and the token-exchange retry uses the
 *                   scope value from the `WWW-Authenticate`
 *                   challenge.
 * @kw timeout_ms    Optional per-call wall-clock deadline override
 *                   in milliseconds. `0` means "fall through to
 *                   the client-level default at @c
 *                   client->timeout_ms"; if that is also `0`, the
 *                   helper falls through to libn00b's
 *                   30000 ms default. Verb shims that need an
 *                   op-specific default (push 60s / pull 30s /
 *                   discover 10s per D-051 OQ-8) resolve the
 *                   precedence chain themselves and pass the
 *                   resolved value here. Phase 4 hardening
 *                   introduced this kwarg so the precedence chain
 *                   does not require mutating the client handle.
 * @kw allocator    Optional allocator (defaults to the client's
 *                   construction-time allocator).
 *
 * @return `n00b_result_ok(n00b_http_response_t *, response)` on
 *         success — the parsed HTTP response, whose status may be
 *         any value HTTP allows (2xx success, 4xx/5xx error, 3xx
 *         redirect-not-followed, etc.). The helper does NOT collapse
 *         non-2xx responses to an Err leg at the substrate layer; it
 *         only returns Err for failures that prevent a response from
 *         being parsed at all. The Err leg uses
 *         `n00b_result_err(n00b_http_response_t *, code)` with one
 *         of:
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_URL — malformed
 *           constructed URL or null input.
 *         - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR — underlying
 *           dispatcher returned a transport-level error (no
 *           parseable HTTP response).
 *         - @ref N00B_ATTEST_ERR_OCI_BEARER_TOKEN_FAILED — the
 *           token-exchange flow's second request returned 401 or
 *           a malformed JSON response.
 *
 *         Phase 1 ships bare-code Err legs; richer Err payloads
 *         (HTTP status, response body, human-readable diagnostic
 *         text) are deferred to the libn00b typed-Err-payload lift
 *         tracked as DF-011. Verb shims that need specific
 *         user-facing diagnostics inspect the libn00b HTTP response
 *         handle directly via per-call state.
 */
extern n00b_result_t(n00b_http_response_t *)
n00b_attest_oci_request(n00b_attest_oci_client_t *client,
                        n00b_string_t            *method,
                        n00b_string_t            *path)
    _kargs {
        n00b_buffer_t                                 *body         = nullptr;
        n00b_string_t                                 *content_type = nullptr;
        n00b_dict_t(n00b_string_t *, n00b_string_t *) *headers     = nullptr;
        n00b_string_t                                 *scope        = nullptr;
        uint64_t                                       timeout_ms   = 0;
        n00b_allocator_t                              *allocator    = nullptr;
    };

/**
 * @internal
 * @brief Parse an OCI image reference into its components.
 *
 * Handles the `[<registry>/]<name>{@<digest>|:<tag>}` form per OCI
 * distribution-spec § 4.1. The parser disambiguates colons by
 * position:
 *
 *   - A colon in the FIRST slash-separated component (before the
 *     first `/`) is a port (e.g. `localhost:5000/foo/bar`).
 *   - A colon in the LAST slash-separated component (after the
 *     last `/`) is a tag (`foo/bar:latest`).
 *
 * `@sha256:...` always denotes a digest reference regardless of
 * position. References without an `@` and without a colon in the
 * last component are rejected as malformed
 * (@ref N00B_ATTEST_ERR_OCI_BAD_URL); OCI requires explicit
 * digest- or tag-pinning at the substrate layer.
 *
 * @param image_ref  The image reference string. Required.
 *
 * @kw allocator     Optional allocator (defaults to the runtime
 *                   allocator). Owns the returned struct + every
 *                   sub-string it points to.
 *
 * @return `n00b_result_ok(n00b_attest_oci_image_ref_t *, ref)` on
 *         success; `n00b_result_err(n00b_attest_oci_image_ref_t *,
 *         N00B_ATTEST_ERR_OCI_BAD_URL)` when the input is null,
 *         empty, missing the required digest-or-tag suffix, has an
 *         empty name, or is otherwise structurally invalid.
 *
 *         Phase 1 ships bare-code Err legs; richer Err payloads
 *         (which structural violation triggered the reject) are
 *         deferred to the libn00b typed-Err-payload lift tracked as
 *         DF-011.
 */
extern n00b_result_t(n00b_attest_oci_image_ref_t *)
n00b_attest_oci_url_parse(n00b_string_t *image_ref)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

// ---------------------------------------------------------------------------
// WP-004 Phase 2 — blob upload + manifest upload + manifest pre-fetch +
// manifest serializer + buffer-digest helper.
// ---------------------------------------------------------------------------

/**
 * @internal
 * @brief Compute `sha256:<hex>` of a buffer's bytes.
 *
 * Wraps libn00b's SHA-256 primitive (the same one the signer
 * backend uses for SPKI-keyid derivation per D-039). The output
 * is the OCI distribution-spec / cosign / sigstore canonical
 * digest string: the prefix `sha256:` followed by the lowercase
 * hex of the 32-byte digest (64 hex characters, total 71 bytes).
 *
 * @param buf  The buffer whose bytes to hash. Required (null
 *             surfaces as `_OCI_BAD_URL`).
 *
 * @kw allocator  Optional allocator (defaults to the runtime
 *                allocator). Owns the returned string.
 *
 * @return `n00b_result_ok(n00b_string_t *, digest)` on success;
 *         `n00b_result_err(..., N00B_ATTEST_ERR_OCI_BAD_URL)` if
 *         @p buf is null.
 */
extern n00b_result_t(n00b_string_t *)
n00b_attest_oci_digest_of_buffer(n00b_buffer_t *buf)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @internal
 * @brief Build the canonical OCI 1.1 artifact-manifest JSON for a
 *        DSSE envelope referrer of an existing image manifest.
 *
 * Emits the exact JSON shape specified in `docs/attest/02-
 * architecture.md` §8.2:
 *
 * ```json
 * {
 *   "schemaVersion": 2,
 *   "mediaType": "application/vnd.oci.image.manifest.v1+json",
 *   "artifactType": "application/vnd.in-toto+dsse",
 *   "config": { "mediaType": "application/vnd.oci.empty.v1+json",
 *               "digest": "sha256:<empty-blob>", "size": 2 },
 *   "layers": [
 *     { "mediaType": "application/vnd.in-toto+json",
 *       "digest": "sha256:<envelope-digest>",
 *       "size": <envelope-bytes> }
 *   ],
 *   "subject": {
 *     "mediaType": "application/vnd.oci.image.manifest.v1+json",
 *     "digest": "<image_digest>",
 *     "size": <image-manifest-size>
 *   },
 *   "annotations": {
 *     "com.crashoverride.attestation.predicate-type": "<URI>",
 *     "com.crashoverride.attestation.signer-keyid": "<hex>"
 *   }
 * }
 * ```
 *
 * **Byte-stability is load-bearing.** Field order is fixed at the
 * spec §8.2 order (NOT alphabetical, NOT hashmap-iteration-order)
 * because the bytes are the cross-tool interop surface: cosign /
 * sigstore-python read this manifest and the manifest's own
 * SHA-256 digest is the OCI tag the registry stores under. The
 * builder uses ordered string concatenation (NOT a dict-iter
 * encoder); JSON string fields are escaped per RFC 8259 § 7.
 *
 * Per D-024 (canonical wire JSON) the output is `.pretty = false`.
 *
 * @param image_digest         The subject image manifest's digest
 *                             (e.g. `"sha256:abc123..."`).
 *                             Required.
 * @param image_manifest_size  The subject image manifest's size
 *                             in bytes (learned via @ref
 *                             n00b_attest_oci_manifest_head).
 * @param envelope_digest      The DSSE envelope blob's digest
 *                             (e.g. `"sha256:def456..."`).
 *                             Required.
 * @param envelope_size        The DSSE envelope blob's byte size.
 * @param predicate_type       The predicate-type URI for the
 *                             `predicate-type` annotation (e.g.
 *                             `"https://slsa.dev/provenance/v1"`).
 *                             Required.
 * @param signer_keyid         The signer's keyid (canonical
 *                             lowercase-hex SHA-256 of SPKI DER
 *                             per D-039) for the `signer-keyid`
 *                             annotation. Required.
 *
 * @kw allocator   Optional allocator (defaults to the runtime
 *                 allocator). Owns the returned buffer.
 *
 * @return `n00b_result_ok(n00b_buffer_t *, manifest_bytes)` on
 *         success; `n00b_result_err(...,
 *         N00B_ATTEST_ERR_OCI_BAD_URL)` when a required argument
 *         is null or empty.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_manifest_build(n00b_string_t *image_digest,
                               uint64_t       image_manifest_size,
                               n00b_string_t *envelope_digest,
                               uint64_t       envelope_size,
                               n00b_string_t *predicate_type,
                               n00b_string_t *signer_keyid)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @internal
 * @brief HEAD a manifest to learn its byte-size (with GET fallback
 *        for non-strict registries that 405 HEAD).
 *
 * Per D-054 (amends D-051 OQ-4): the pre-push size-discovery
 * path is HEAD-primary + GET-fallback. The fallback triggers
 * ONLY on HEAD returning 405 Method Not Allowed (older non-strict
 * registries — zot supports HEAD, ghcr.io supports HEAD, but
 * Harbor 1.x emits 405). All other non-success statuses on either
 * method surface as @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR.
 *
 * The helper hits `/v2/<name>/manifests/<digest>` and returns the
 * byte-size from the `Content-Length` response header (HEAD) or
 * from the response body length (GET fallback; body is discarded
 * after length is read).
 *
 * @param client   The OCI client handle. Required.
 * @param name     Repository name (e.g. `"foo/bar"`). Required.
 * @param digest   Subject manifest digest (e.g. `"sha256:abc..."`).
 *                 Required.
 *
 * @kw allocator  Optional allocator (defaults to the client's
 *                construction-time allocator).
 *
 * @return `n00b_result_ok(uint64_t *, size_ptr)` on success — the
 *         pointed-to value is the manifest's byte-size as reported
 *         by the registry; the @c uint64_t lives in the per-call
 *         allocator. Err legs route through
 *         @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR (transport / non-
 *         success status) or @ref N00B_ATTEST_ERR_OCI_BAD_URL
 *         (null inputs / null Content-Length on HEAD without
 *         fallback) per the canonical Phase 1 bare-code-on-Err
 *         shape inherited via D-053.
 */
extern n00b_result_t(uint64_t *)
n00b_attest_oci_manifest_head(n00b_attest_oci_client_t *client,
                              n00b_string_t            *name,
                              n00b_string_t            *digest)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    };

/**
 * @internal
 * @brief Upload a blob via the two-step OCI distribution-spec
 *        POST-then-PUT protocol.
 *
 * Step (1): POST `/v2/<name>/blobs/uploads/` with an empty body.
 *           The registry returns 202 Accepted + a `Location`
 *           response header (absolute or relative URL).
 * Step (2): PUT `<Location>?digest=<digest>` with the blob bytes
 *           as body + the supplied content-type. The registry
 *           returns 201 Created on success.
 *
 * Phase 2 surfaces 4xx + 5xx as @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR
 * (no retry shape; retry policy is a Phase 4 hardening concern).
 *
 * @param client        The OCI client handle. Required.
 * @param name          Repository name (e.g. `"foo/bar"`).
 *                      Required.
 * @param blob          The blob bytes to upload. Required.
 * @param digest        The blob's `sha256:<hex>` digest (matched
 *                      verbatim by the registry via the `?digest=`
 *                      query parameter on the PUT). Required.
 *
 * @kw content_type  Optional MIME type (default
 *                   `"application/octet-stream"`). Pushed verbatim
 *                   into the PUT's `Content-Type` header.
 * @kw allocator     Optional allocator (defaults to the client's
 *                   construction-time allocator).
 *
 * @return `n00b_result_ok(void *, nullptr)` on success — the Ok
 *         value carries no payload; only the success / error
 *         discrimination matters. Err legs:
 *         - @ref N00B_ATTEST_ERR_OCI_BAD_URL — null inputs / no
 *           `Location` header on the POST response / malformed
 *           upload URL.
 *         - @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR — transport or
 *           4xx/5xx status on either step.
 */
extern n00b_result_t(void *)
n00b_attest_oci_blob_upload(n00b_attest_oci_client_t *client,
                            n00b_string_t            *name,
                            n00b_buffer_t            *blob,
                            n00b_string_t            *digest)
    _kargs {
        n00b_string_t    *content_type = nullptr;
        uint64_t          timeout_ms   = 0;
        n00b_allocator_t *allocator    = nullptr;
    };

/**
 * @internal
 * @brief Upload an OCI 1.1 artifact manifest via PUT
 *        `/v2/<name>/manifests/<ref>`.
 *
 * Sets `Content-Type: application/vnd.oci.image.manifest.v1+json`
 * and the manifest bytes as body. `<ref>` is the manifest's own
 * digest (`sha256:...`); the registry treats the upload as a
 * referrer of the subject image manifest by virtue of the
 * `subject` field inside the manifest itself.
 *
 * On success, the helper reads `Docker-Content-Digest` from the
 * response (OCI v2 mandates the header on manifest PUT but some
 * registries omit it in non-strict mode); falls back to computing
 * `sha256(manifest_bytes)` locally if the header is missing; and
 * cross-checks the registry-reported digest against the locally-
 * computed digest when both are present. A disagreement surfaces
 * as @ref N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH.
 *
 * Phase 2 surfaces 4xx + 5xx as @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR.
 *
 * @param client          The OCI client handle. Required.
 * @param name            Repository name (e.g. `"foo/bar"`).
 *                        Required.
 * @param ref             Manifest reference — typically the
 *                        manifest's own digest. Required.
 * @param manifest_bytes  The manifest JSON bytes. Required.
 *
 * @kw allocator  Optional allocator (defaults to the client's
 *                construction-time allocator).
 *
 * @return `n00b_result_ok(n00b_string_t *, digest)` on success —
 *         the canonical manifest digest as confirmed by the
 *         registry (or computed locally if the header was
 *         absent). Err legs route through
 *         @ref N00B_ATTEST_ERR_OCI_BAD_URL,
 *         @ref N00B_ATTEST_ERR_OCI_HTTP_ERROR, or
 *         @ref N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH per
 *         the conditions documented above.
 */
extern n00b_result_t(n00b_string_t *)
n00b_attest_oci_manifest_upload(n00b_attest_oci_client_t *client,
                                n00b_string_t            *name,
                                n00b_string_t            *ref,
                                n00b_buffer_t            *manifest_bytes)
    _kargs {
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    };

// ---------------------------------------------------------------------------
// WP-004 Phase 3 — discover + pull substrate: blob fetch + manifest fetch.
// ---------------------------------------------------------------------------

/**
 * @internal
 * @brief Fetch a blob by digest via GET `/v2/<name>/blobs/<digest>`.
 *
 * Includes the symmetric integrity guard to push's
 * `_OCI_MANIFEST_DIGEST_MISMATCH`: after fetching, the helper
 * recomputes `sha256(body)` and compares it against the requested
 * @p digest. Disagreement surfaces as
 * @ref N00B_ATTEST_ERR_OCI_BLOB_DIGEST_MISMATCH.
 *
 * Phase 3 surfaces the response status to OCI codes:
 *   - 2xx + length <= @p max_size → Ok(body buffer).
 *   - 2xx + length > @p max_size → Err(_OCI_BLOB_TOO_LARGE).
 *   - sha256 disagreement → Err(_OCI_BLOB_DIGEST_MISMATCH).
 *   - any other non-success status → Err(_OCI_HTTP_ERROR).
 *
 * @param client  OCI client handle. Required.
 * @param name    Repository name. Required.
 * @param digest  Blob digest (`sha256:<hex>`). Required.
 *
 * @kw max_size   Maximum acceptable blob body size in bytes. `0`
 *                applies the Phase-3 default cap of 1 MiB (per
 *                NFR-5; typical envelopes are <= 50 KB per NFR-6).
 * @kw allocator  Optional allocator (defaults to the client's
 *                construction-time allocator).
 *
 * @return `n00b_result_ok(n00b_buffer_t *, body)` on success;
 *         `n00b_result_err(...)` on the error legs documented above.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_blob_fetch(n00b_attest_oci_client_t *client,
                           n00b_string_t            *name,
                           n00b_string_t            *digest)
    _kargs {
        uint64_t          max_size   = 0;
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    };

/**
 * @internal
 * @brief Fetch a manifest by digest via GET
 *        `/v2/<name>/manifests/<digest>` with the
 *        `Accept: application/vnd.oci.image.manifest.v1+json` header.
 *
 * Symmetric integrity guard: recomputes `sha256(body)` after fetch
 * and compares against the requested digest;
 * @ref N00B_ATTEST_ERR_OCI_MANIFEST_DIGEST_MISMATCH on disagreement.
 *
 * @param client  OCI client handle. Required.
 * @param name    Repository name. Required.
 * @param digest  Manifest digest (`sha256:<hex>`). Required.
 *
 * @kw max_size   Maximum acceptable manifest body size in bytes.
 *                `0` applies the Phase-3 default cap of 1 MiB.
 * @kw allocator  Optional allocator (defaults to the client's
 *                construction-time allocator).
 *
 * @return `n00b_result_ok(n00b_buffer_t *, body)` on success;
 *         `n00b_result_err(...)` on the error legs.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_attest_oci_manifest_fetch(n00b_attest_oci_client_t *client,
                               n00b_string_t            *name,
                               n00b_string_t            *digest)
    _kargs {
        uint64_t          max_size   = 0;
        uint64_t          timeout_ms = 0;
        n00b_allocator_t *allocator  = nullptr;
    };
