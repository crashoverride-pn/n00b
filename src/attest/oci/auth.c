/* src/attest/oci/auth.c — OCI auth-resolver edge + auth-handle
 * lifecycle.
 *
 * Implements the auth-resolver half of the surface declared in
 * include/attest/n00b_attest_oci.h:
 *   - n00b_attest_oci_auth_resolve   (walks the source chain per
 *                                     OQ-1's 3-of-5 subset)
 *   - n00b_attest_oci_auth_release   (no-op-on-null; no crypto_wipe
 *                                     in Phase 1 per the header's
 *                                     "@details" framing)
 *
 * The 3-of-5 source dispatch (D-051 OQ-1):
 *
 *   - N00B_ATTEST_OCI_AUTH_CALLER          — no-op in the resolver
 *                                             (caller threads a
 *                                             pre-built handle into
 *                                             _client_new directly).
 *   - N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON — reads
 *                                             $XDG_CONFIG_HOME/
 *                                             n00b-attest/
 *                                             registries.json (or
 *                                             ~/.config/n00b-attest/
 *                                             registries.json when
 *                                             XDG_CONFIG_HOME is
 *                                             unset). The schema is
 *                                             N00B-specific.
 *   - N00B_ATTEST_OCI_AUTH_ANONYMOUS       — terminal fallback;
 *                                             returns a no-token
 *                                             handle.
 *   - N00B_ATTEST_OCI_AUTH_CRED_HELPER     — future Tier-2 WP;
 *                                             surfaces
 *                                             _OCI_AUTH_SOURCE_NOT_FOUND.
 *   - N00B_ATTEST_OCI_AUTH_KEYCHAIN        — future Tier-2 WP;
 *                                             surfaces
 *                                             _OCI_AUTH_SOURCE_NOT_FOUND.
 *
 * D-045 `alloc_for_call` idiom: every allocating function threads
 * one `alloc_for_call` local through every allocation site.
 *
 * Test-file carve-out (D-030) does NOT apply here — this is a
 * source file, so libc I/O is banned by the standing rule. The
 * registries.json read uses libn00b's n00b_file_open / read
 * surface; the JSON parse uses n00b_json_parse.
 *
 * The registries.json path lookup is delegated to libn00b core's
 * `n00b_xdg_config_path` typed-variadic builder
 * (include/util/path.h), which composes
 * `$XDG_CONFIG_HOME/n00b-attest/registries.json` (or the
 * `$HOME/.config/...` fallback per the XDG Base Directory spec).
 * The `getenv` exception (D-052) now lives in libn00b core; a
 * future libn00b `n00b_getenv` lift removes the exception
 * project-wide.
 */

#include "internal/attest/oci/registry.h"
#include "internal/attest/json_util.h"
#include <attest/n00b_attest_oci.h>
#include <attest/n00b_attest_error.h>

#include "core/string.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "text/unicode/idna.h"
#include "util/path.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Helpers — registries.json path resolution lifted to libn00b core's
// `n00b_xdg_config_path` typed-variadic builder (include/util/path.h).
// The byte-identical clone pattern that previously lived here is now
// codified in libn00b core, shared with src/chalk/resign_identity.c.
// The app namespace `"n00b-attest"` and the leaf `"registries.json"`
// flow through as variadic pieces; the builder resolves
// `$XDG_CONFIG_HOME/n00b-attest/registries.json` or
// `$HOME/.config/n00b-attest/registries.json` per the XDG spec.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Helpers — read a file in full to a buffer.
//
// Returns nullptr on any I/O error (open / read / size-query). The
// resolver treats nullptr as "file not present or unreadable" and
// falls through to the next source per the source-chain semantics.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
read_file_to_buffer(n00b_string_t *path, n00b_allocator_t *alloc_for_call)
{
    if (path == nullptr) {
        return nullptr;
    }
    auto open_r = n00b_file_open(path);
    if (n00b_result_is_err(open_r)) {
        return nullptr;
    }
    n00b_file_t *f = n00b_result_get(open_r);

    int64_t sz = n00b_file_size(f);
    if (sz < 0) {
        n00b_file_close(f);
        return nullptr;
    }
    auto read_r = n00b_file_read(f, (size_t)sz);
    if (n00b_result_is_err(read_r)) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *raw = n00b_result_get(read_r);
    n00b_file_close(f);

    // The mmap-backed substrate may hand back a buffer aliased into
    // the mapping; copy into an allocator-owned buffer to decouple
    // lifetime.
    if (raw == nullptr || raw->byte_len == 0) {
        return nullptr;
    }
    return n00b_buffer_from_bytes(raw->data,
                                  (int64_t)raw->byte_len,
                                  .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Helpers — registries.json source dispatch.
//
// Schema: top-level object keyed by registry hostname. Each entry
// is an object carrying either an `"auth"` field (base64 of
// user:pass — Basic auth) or a `"token"` field (bearer-token
// string). Missing file is NOT an error; malformed JSON surfaces
// to the resolver as nullptr (treated identically to "no
// credentials in this source").
//
// # IDN / UTS-46 host comparison (DF-J, 2026-05-20)
//
// The `registry_filter` kwarg flows in from CLI consumers as the
// raw substring extracted by `n00b_attest_oci_url_parse` (which
// slices the registry component verbatim — it does NOT canonicalize;
// the URL parser's IDNA lift in DF-X applies to wire URLs, not to
// the OCI image-ref substring). The `host_key` from
// `registries.json` is the raw byte-key as the user wrote it in
// the config file. A pure byte compare between these two sources
// would silently fail to match when the user types one logical
// host in two encodings (e.g. `例え.com` in the image ref vs
// `xn--r8jz45g.com` in `registries.json`).
//
// To close the asymmetry, both sides are IDNA-canonicalized via
// `n00b_unicode_idna_to_ascii` before the byte compare. Pure-ASCII
// entries (the dominant case — `ghcr.io`, `docker.io`,
// `localhost:5000`) behave byte-identically post-canonicalization
// modulo UTS-46 case folding. The host substring may carry a port
// suffix (`localhost:5000`); IDNA applies only to the host portion,
// so the helper splits at the last `:` (if any) and canonicalizes
// just the host. On any IDNA failure (malformed UTF-8, disallowed
// codepoints, etc.) the helper falls back to the raw byte compare
// — this preserves backward-compat for pathological entries and
// matches the matcher-side fallback convention established by the
// allowlist code in `src/net/http/http_client.c`.
// ---------------------------------------------------------------------------

/* Split `src[0..len)` at the last `:` for `host:port` separation.
 * On match: `*host_len_out` is set to the byte length of the host
 * portion (the bytes preceding the colon), and `*port_start_out` to
 * the colon byte itself (the caller appends `src + *port_start_out`
 * onto the canonicalized host to reconstruct the full form). On no
 * match: `*host_len_out = len` and `*port_start_out = len`. The
 * helper assumes IPv6-literal hosts (`[::1]`) are not used in OCI
 * registries.json keys — OCI doesn't define a bracketed-host form
 * for registry hostnames, and the existing `_url_parse` substring
 * slicer doesn't emit one. */
static void
split_host_port(const char *src,
                size_t      len,
                size_t     *host_len_out,
                size_t     *port_start_out)
{
    *host_len_out   = len;
    *port_start_out = len;
    for (size_t i = len; i > 0; i--) {
        if (src[i - 1] == ':') {
            *host_len_out   = i - 1;
            *port_start_out = i - 1;
            return;
        }
    }
}

/* IDNA-canonicalize `src[0..len)` (which may include a `:port`
 * suffix). Returns the canonical-form string on success, or
 * `nullptr` on any IDNA failure. The caller's fallback policy on
 * `nullptr` is "use the raw bytes" — this preserves the historical
 * byte-compare semantics for entries that don't survive IDNA. */
static n00b_string_t *
canonicalize_host_or_null(const char       *src,
                          size_t            len,
                          n00b_allocator_t *alloc_for_call)
{
    if (src == nullptr || len == 0) {
        return nullptr;
    }
    size_t host_len;
    size_t port_start;
    split_host_port(src, len, &host_len, &port_start);
    if (host_len == 0) {
        return nullptr;
    }
    n00b_string_t *host = n00b_string_from_raw(src,
                                               (int64_t)host_len,
                                               .allocator = alloc_for_call);
    if (host == nullptr) {
        return nullptr;
    }
    n00b_unicode_idna_result_t r = n00b_unicode_idna_to_ascii(
        host,
        .allocator = alloc_for_call);
    if (r.error != N00B_UNICODE_IDNA_OK || r.value == nullptr
        || r.value->u8_bytes == 0) {
        return nullptr;
    }
    if (port_start == len) {
        // No port suffix — return the canonicalized host directly.
        return r.value;
    }
    // Re-attach the `:port` portion verbatim.
    size_t port_len  = len - port_start;
    size_t total_len = r.value->u8_bytes + port_len;
    char  *buf = n00b_alloc_array_with_opts(
        char,
        total_len + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, r.value->data, r.value->u8_bytes);
    memcpy(buf + r.value->u8_bytes, src + port_start, port_len);
    buf[total_len] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)total_len,
                                .allocator = alloc_for_call);
}

/* Compare a `registries.json` host key against the caller's
 * registry filter under IDNA canonicalization. Returns true iff
 * the two strings name the same logical host. Pure-ASCII inputs
 * behave byte-identically (modulo UTS-46 case folding); Unicode
 * vs. Punycode inputs cross-match in either direction; entries
 * that fail IDNA on either side fall back to the raw byte
 * compare. */
static bool
host_keys_match(const char       *host_key,
                size_t            host_len,
                n00b_string_t    *registry_filter,
                n00b_allocator_t *alloc_for_call)
{
    // Raw byte compare first — fast path for the dominant pure-
    // ASCII case (`ghcr.io` == `ghcr.io`). This also covers the
    // pathological "both sides fail IDNA but byte-equal" case.
    if (host_len == registry_filter->u8_bytes
        && memcmp(host_key, registry_filter->data, host_len) == 0) {
        return true;
    }

    // Asymmetric-encoding case: try IDNA-canonicalize both sides.
    n00b_string_t *key_canon = canonicalize_host_or_null(
        host_key, host_len, alloc_for_call);
    n00b_string_t *filter_canon = canonicalize_host_or_null(
        registry_filter->data,
        registry_filter->u8_bytes,
        alloc_for_call);
    if (key_canon == nullptr || filter_canon == nullptr) {
        // Either side failed IDNA — fall back to the raw byte
        // compare, which already failed above. The two hosts do
        // not match.
        return false;
    }
    if (key_canon->u8_bytes != filter_canon->u8_bytes) {
        return false;
    }
    return memcmp(key_canon->data,
                  filter_canon->data,
                  key_canon->u8_bytes)
           == 0;
}


static n00b_attest_oci_auth_t *
auth_from_registries_json(n00b_string_t    *registry_filter,
                          n00b_allocator_t *alloc_for_call)
{
    n00b_string_t *path = n00b_xdg_config_path(r"n00b-attest",
                                               r"registries.json");
    if (path == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *raw = read_file_to_buffer(path, alloc_for_call);
    if (raw == nullptr) {
        // File absent or unreadable — fall through to next source.
        return nullptr;
    }

    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(raw->data, raw->byte_len, &err);
    if (root == nullptr || !n00b_json_is_object(root)) {
        return nullptr;
    }

    // The resolver walks the object keys to find an entry. Two
    // policies, per the header doxygen:
    //   - With a registry filter: return only the entry whose key
    //     byte-equals the filter string. No match -> nullptr.
    //   - Without a filter: return the first entry that yields
    //     usable credentials.
    //
    n00b_string_t *bearer_key = r"token";
    n00b_string_t *basic_key  = r"auth";

    n00b_json_object_t *registries = n00b_json_as_object(root);
    if (registries == nullptr) {
        return nullptr;
    }

    n00b_dict_foreach(registries, host_key_n00b, entry, {
        const char *host_key = host_key_n00b == nullptr ? nullptr : host_key_n00b->data;
        if (host_key == nullptr || !n00b_json_is_object(entry)) {
            continue;
        }
        size_t host_len = host_key_n00b->u8_bytes;
        if (registry_filter != nullptr) {
            // DF-J (2026-05-20): IDNA-canonicalized host compare,
            // not raw byte compare. Closes the asymmetric-
            // canonicalization hazard between the OCI image-ref
            // substring (`parsed->registry`, raw per `_url_parse`'s
            // contract) and the user-authored `registries.json`
            // key. Pure-ASCII inputs behave byte-identically modulo
            // UTS-46 case folding; Unicode / Punycode mixed inputs
            // cross-match in either direction.
            if (!host_keys_match(host_key,
                                 host_len,
                                 registry_filter,
                                 alloc_for_call)) {
                continue;
            }
        }

        // Look up "token" (Bearer) and "auth" (Basic). Prefer
        // token over auth when both are present (modern bearer
        // shape over legacy basic).
        n00b_json_node_t *tok = n00b_attest_json_obj_lookup(entry, bearer_key);
        n00b_json_node_t *bas = n00b_attest_json_obj_lookup(entry, basic_key);
        const char *tok_s = n00b_json_as_cstr(tok);
        const char *bas_s = n00b_json_as_cstr(bas);

        if (tok_s != nullptr) {
            n00b_attest_oci_auth_t *a = n00b_alloc_with_opts(
                n00b_attest_oci_auth_t,
                &(n00b_alloc_opts_t){.allocator = alloc_for_call});
            a->source   = N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON;
            a->registry = n00b_string_from_raw(host_key,
                                               (int64_t)host_len,
                                               .allocator = alloc_for_call);
            a->bearer_token = n00b_buffer_from_bytes(
                (char *)tok_s,
                (int64_t)strlen(tok_s),
                .allocator = alloc_for_call);
            a->basic_auth = nullptr;
            a->allocator  = alloc_for_call;
            return a;
        }
        if (bas_s != nullptr) {
            n00b_attest_oci_auth_t *a = n00b_alloc_with_opts(
                n00b_attest_oci_auth_t,
                &(n00b_alloc_opts_t){.allocator = alloc_for_call});
            a->source   = N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON;
            a->registry = n00b_string_from_raw(host_key,
                                               (int64_t)host_len,
                                               .allocator = alloc_for_call);
            a->bearer_token = nullptr;
            a->basic_auth   = n00b_buffer_from_bytes(
                (char *)bas_s,
                (int64_t)strlen(bas_s),
                .allocator = alloc_for_call);
            a->allocator    = alloc_for_call;
            return a;
        }
        if (registry_filter != nullptr) {
            // We matched the filter but the entry had neither
            // field; do not fall through to a different key.
            return nullptr;
        }
    });

    return nullptr;
}

// ---------------------------------------------------------------------------
// Helpers — anonymous source.
// ---------------------------------------------------------------------------

static n00b_attest_oci_auth_t *
auth_anonymous(n00b_string_t    *registry_filter,
               n00b_allocator_t *alloc_for_call)
{
    n00b_attest_oci_auth_t *a = n00b_alloc_with_opts(
        n00b_attest_oci_auth_t,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    a->source       = N00B_ATTEST_OCI_AUTH_ANONYMOUS;
    a->registry     = registry_filter;
    a->bearer_token = nullptr;
    a->basic_auth   = nullptr;
    a->allocator    = alloc_for_call;
    return a;
}

// ---------------------------------------------------------------------------
// Public surface — auth resolver edge.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_attest_oci_auth_t *)
n00b_attest_oci_auth_resolve()
    _kargs {
        n00b_string_t                                 *registry  = nullptr;
        n00b_list_t(n00b_attest_oci_auth_source_t)    *sources   = nullptr;
        n00b_allocator_t                              *allocator = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    // Determine the source-chain ordering. nullptr -> default chain
    // [CALLER, REGISTRIES_JSON, ANONYMOUS] per the header doxygen.
    n00b_attest_oci_auth_source_t default_chain[3] = {
        N00B_ATTEST_OCI_AUTH_CALLER,
        N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON,
        N00B_ATTEST_OCI_AUTH_ANONYMOUS,
    };

    size_t                          n_sources = 0;
    n00b_attest_oci_auth_source_t  *src_arr   = nullptr;

    if (sources == nullptr) {
        n_sources = 3;
        src_arr   = default_chain;
    } else {
        // Read the caller's list into a stack-allocated array so the
        // dispatch loop below is uniform across both the default-
        // chain and caller-list paths. The list-element type is the
        // enum itself (not a pointer); n00b_list_len / _get expect
        // an lvalue list (NOT a pointer) so we deref the kwarg.
        size_t len = (size_t)n00b_list_len(*sources);
        if (len == 0) {
            // Caller passed an empty list — no sources to walk.
            return n00b_result_err(
                n00b_attest_oci_auth_t *,
                N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);
        }
        src_arr = n00b_alloc_array_with_opts(
            n00b_attest_oci_auth_source_t,
            len,
            &(n00b_alloc_opts_t){.allocator = alloc_for_call});
        for (size_t i = 0; i < len; i++) {
            src_arr[i] = n00b_list_get(*sources, (int64_t)i);
        }
        n_sources = len;
    }

    for (size_t i = 0; i < n_sources; i++) {
        switch (src_arr[i]) {
        case N00B_ATTEST_OCI_AUTH_CALLER:
            // No-op in the resolver per the header doxygen. The
            // caller threads a pre-built auth handle into
            // _client_new directly; this slot exists for
            // documentation symmetry with the other sources.
            break;
        case N00B_ATTEST_OCI_AUTH_REGISTRIES_JSON: {
            n00b_attest_oci_auth_t *a = auth_from_registries_json(
                registry, alloc_for_call);
            if (a != nullptr) {
                return n00b_result_ok(n00b_attest_oci_auth_t *, a);
            }
            break;
        }
        case N00B_ATTEST_OCI_AUTH_ANONYMOUS: {
            n00b_attest_oci_auth_t *a = auth_anonymous(registry,
                                                       alloc_for_call);
            return n00b_result_ok(n00b_attest_oci_auth_t *, a);
        }
        case N00B_ATTEST_OCI_AUTH_CRED_HELPER:
        case N00B_ATTEST_OCI_AUTH_KEYCHAIN:
            // Reserved-but-not-implemented in WP-004 Phase 1 per
            // D-051 OQ-1. If the caller listed one of these
            // explicitly, fail with the dedicated code; if it's
            // a falling-through-from-an-earlier-source path (i.e.
            // the next iteration of the loop) we keep walking the
            // chain — but since the default chain doesn't include
            // these, the only way we land here is if the caller
            // passed an explicit list. Treat as "no credentials
            // from this source" and continue walking.
            break;
        default:
            // Unknown enum value — treat as "no credentials" and
            // continue walking. Defensive; the enum is closed in
            // Phase 1 but a future-WP-added value could land here
            // before the dispatch is updated.
            break;
        }
    }

    return n00b_result_err(n00b_attest_oci_auth_t *,
                           N00B_ATTEST_ERR_OCI_AUTH_SOURCE_NOT_FOUND);
}

void
n00b_attest_oci_auth_release(n00b_attest_oci_auth_t *auth)
{
    // No crypto_wipe in WP-004 Phase 1 per the header doxygen
    // ("@details" block on n00b_attest_oci_auth_release). Bearer
    // tokens are short-lived and Basic creds are loaded fresh from
    // disk on each resolve. Under the n00b GC convention the
    // allocator owns the lifetime and reclaims on scope / arena
    // teardown; explicit deallocation here would be premature
    // (the caller may still hold references to fields they pulled
    // out of the handle). This function exists to satisfy the
    // surface-symmetry contract with the verifier-side release
    // (the public surface declares a release entry point).
    (void)auth;
}
