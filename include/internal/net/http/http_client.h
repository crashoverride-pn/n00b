/**
 * @file include/internal/net/http/http_client.h
 * @brief Internal-only HTTP client helpers exposed for unit testing.
 *
 * The public surface lives in `include/net/http/http_client.h`; this
 * sibling internal header surfaces matcher primitives that the public
 * dispatcher uses internally but that unit tests need to exercise
 * directly (the matchers are small, side-effect-free, and exercising
 * them at the dispatcher level would require either a live network
 * fixture or a heavyweight redirect mock).
 *
 * Operators should not include this header; the symbols here are not
 * part of the project's API stability promise.
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "adt/list.h"
#include "conduit/topic.h"

/**
 * @brief Test if @p host matches any entry in @p allowlist, with
 *        wildcard + IDN support.
 *
 * @param host       Host string from the parsed URL's authority
 *                   component.  **Assumed already in pure-ASCII
 *                   canonical form** — the URL parser runs
 *                   RFC 3986 § 3.2.2 case-folding and UTS #46
 *                   ToASCII at parse time (DF-X), so the bytes
 *                   that reach this matcher are ACE-form Punycode
 *                   for non-ASCII labels and lowercased ASCII for
 *                   ASCII labels.
 * @param allowlist  Pointer to a `n00b_list_t(n00b_string_t *)`
 *                   lvalue.  Each entry is either an exact host
 *                   (no `*`), a wildcard of the form `*.DOMAIN`
 *                   with at least one label after the leading
 *                   `*.`, or malformed (silently skipped).  The
 *                   `DOMAIN` portion of a wildcard entry may be
 *                   authored in Unicode or already-Punycode; the
 *                   matcher canonicalizes the entry side before
 *                   comparing.
 *
 * @return `true` on the first matching entry; `false` if the loop
 *         exhausts without a match (including the empty-allowlist
 *         case) or if @p host is empty.
 *
 * @pre  @p host is pure ASCII (callers pass `n00b_http_url_t::host`
 *       directly; the URL parser enforces this).
 * @pre  @p allowlist may be `nullptr` (returns false defensively)
 *       but in production the caller checks
 *       `redirect_host_allowlist != nullptr` before this call.
 * @post Side-effect-free at the API boundary.  Internally
 *       allocates transient ACE-form strings on the runtime
 *       default allocator for entry canonicalization; the GC
 *       reclaims them.
 *
 * @details Wildcard semantics:
 *
 *   - `*.example.com` matches `foo.example.com`, `a.b.example.com`,
 *     etc. (one or more labels before the dot).
 *   - `*.example.com` does NOT match the apex `example.com`; callers
 *     who want the apex too must add a second non-wildcard entry.
 *   - Only a single leading `*.` is supported.  `foo.*.com`,
 *     `**.example.com`, `*example.com`, and bare `*` are malformed
 *     and silently skipped.
 *   - Exact-match entries behave identically to the pre-IDN
 *     dispatcher on pure-ASCII input (ASCII Punycode is a fixed
 *     point of UTS-46 `to_ascii` modulo case folding).
 *
 * @details IDN semantics:
 *
 *   - The host arrives pre-canonicalized from the URL parser; the
 *     matcher does NOT re-run UTS-46 ToASCII on it.
 *   - The canonicalizable portion of each entry (the whole entry
 *     for exact match; the `DOMAIN` after `*.` for a wildcard) is
 *     passed through @ref n00b_unicode_idna_to_ascii so a
 *     Unicode-authored entry cross-matches the ACE-form host.
 *     Comparison happens in ACE (Punycode) space using the
 *     existing ASCII-CI primitive.
 *   - A wildcard's `*.` prefix is literal ASCII and is NOT fed
 *     to the IDNA pipeline.
 *   - IDNA failure on a single entry → skip that entry, keep
 *     scanning the rest of the list.
 */
extern bool
n00b_http_host_in_allowlist(n00b_string_t                *host,
                            n00b_list_t(n00b_string_t *) *allowlist);

#ifdef N00B_DEBUG
/**
 * @brief Called by an async request's worker after it delivers the response
 *        and before it closes the response topic. Only under @c N00B_DEBUG.
 *
 * Lets a test hold the worker inside that window. Process-wide, and only a
 * test has any reason to set it.
 */
extern void (*n00b_http_test_before_response_close)(
    n00b_conduit_topic_base_t *topic);
#endif
