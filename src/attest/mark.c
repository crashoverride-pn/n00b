/* src/attest/mark.c — n00b_attest ↔ libchalk bridge (WP-005 Phase 1 +
 *                       Phase 6 signer_identity dispatch).
 *
 * Implements the three "Cut M" library entry points declared in
 * `include/attest/n00b_attest_mark.h`:
 *
 *   - n00b_attest_mark_artifact
 *   - n00b_attest_unmark
 *   - n00b_attest_extract_from_artifact
 *
 * Plus the package-private ATTESTATION JSON builder + parser that
 * the mark and extract entry points compose over.
 *
 * # Phase 1 scope (per the WP-005 plan + 2026-05-21 orchestrator
 *   prompt correction)
 *
 * - Consume libchalk's existing public API only
 *   (`n00b_chalk_mark_new`, `_mark_set_attestation`,
 *   `_insert_file`, `_extract_file`, `_delete_file`,
 *   `_detect_file`, `_hash_file`).
 * - Validate `registry_hint` (when non-null) via the internal
 *   `n00b_attest_oci_url_parse`.
 * - Build the ATTESTATION JSON via ordered string concatenation
 *   per D-024 + D-056 (the canonical wire JSON serialization
 *   precedent for n00b_attest, identical to the OCI manifest
 *   serializer in `src/attest/oci/manifest.c`).
 * - Return the unchalked SHA-256 as 32 raw bytes (the IC-4 hash
 *   enabler) NOT as `sha256:<hex>` — the CLI verb shim (Phase 2)
 *   formats to hex for `extract --json`.
 *
 * # mark_artifact step ordering (orchestrator prompt correction)
 *
 * The plan.md body says step (5) "harvest the unchalked SHA-256
 * from the `n00b_chalk_mark_finalize` path or via re-running
 * `n00b_chalk_hash_file(path)`." Reading
 * `include/chalk/n00b_chalk_mark.h` reveals that
 * `n00b_chalk_mark_finalize` TAKES the unchalked SHA-256 as an
 * INPUT parameter (signature
 * `n00b_chalk_mark_finalize(mark, unchalked_sha256_32)`) rather
 * than producing it. Furthermore, reading the codec layer
 * (`src/chalk/elf.c:95` in the n00b-host repo + the equivalent
 * paths in `macho.c` / `pe.c`) shows that the per-codec
 * `_insert_buffer` body computes the unchalked hash internally
 * AND calls `_mark_finalize` against it, but does NOT surface
 * that hash on the `n00b_chalk_io_result_t` row type — the
 * `bytes` + `kind` + `sidecar_suffix` are all the result
 * carries.
 *
 * The correct sequence is therefore:
 *
 *   1. `n00b_chalk_hash_file(path)` — pre-insert hash. This is
 *      the value `_mark_artifact` returns AND (implicitly) the
 *      value libchalk will compute again during `_insert_file`
 *      to finalize the mark; the two values byte-equal because
 *      `_hash_file` and the codec's internal unchalked-hash path
 *      walk the same code (strip-then-hash for ELF / Mach-O / PE).
 *   2. Build ATTESTATION JSON tree (parse via
 *      `n00b_json_parse`).
 *   3. `n00b_chalk_mark_new()` + `_mark_set_attestation(mark,
 *      tree)`.
 *   4. `n00b_chalk_insert_file(path, mark)` — libchalk
 *      internally re-computes the unchalked hash + calls
 *      `_mark_finalize` against it.
 *   5. Return `Ok({ unchalked_sha256_32 = pre_insert_hash, kind,
 *      sidecar_suffix })`.
 *
 * The pre-insert hash and libchalk's internal-during-insert hash
 * MUST match for the CHALK_ID + HASH fields of the mark to align
 * with the value we return to the caller (the IC-4 cross-check
 * relies on byte-equality). The double-hash is a constant-factor
 * cost; a future libchalk lift can elide it by exposing the
 * internal hash on the result row, but that's outside Phase 1.
 *
 * # Allocator threading (D-045)
 *
 * Every entry point captures the caller's `.allocator` kwarg
 * into a local `alloc_for_call` and threads it through every
 * downstream allocation site (libchalk dispatches don't take an
 * allocator kwarg, so per-call scratch they produce lives in
 * the GC heap; the values we KEEP — the returned row type, its
 * fields, the buffers we own — all live in `alloc_for_call`).
 *
 * # Symbol visibility
 *
 * Public entries declared in `n00b_attest_mark.h`; helpers in
 * this file are `static`. No new internal header is needed:
 * `mark.c` is the only consumer of its own helpers.
 */

#include <attest/n00b_attest.h>
#include "internal/attest/oci/registry.h"

#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/sha256.h"
#include "core/string.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "crypto/base64.h"
#include "util/path.h"

#include <chalk/n00b_chalk.h>

#include <string.h>

// ---------------------------------------------------------------------------
// Local helpers — string copy + JSON escape + decimal encoding (mirror the
// `src/attest/oci/manifest.c` shape; D-056 ordered-string-concat for the
// canonical-byte-stable ATTESTATION JSON shape).
// ---------------------------------------------------------------------------

static const char k_hex_lower[] = "0123456789abcdef";

// Copy a string into `alloc_for_call`. Allocates a fresh
// `n00b_string_t *`; callers may free the input immediately.
static n00b_string_t *
copy_string_into(n00b_string_t *src, n00b_allocator_t *alloc_for_call)
{
    if (src == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(src->data,
                                (int64_t)src->u8_bytes,
                                .allocator = alloc_for_call);
}

// Compute the byte count required to JSON-string-escape `s[0..len)`
// per RFC 8259 § 7 (no surrounding quotes).
static size_t
json_escaped_size(const char *s, size_t len)
{
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':
        case '\\':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            n += 2;
            break;
        default:
            if (c < 0x20) {
                n += 6;  // \uXXXX
            }
            else {
                n += 1;
            }
            break;
        }
    }
    return n;
}

// Write `s[0..len)` into `out` with RFC 8259 § 7 JSON-string
// escaping; returns the bytes written.
static size_t
json_escape_into(char *out, const char *s, size_t len)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':
            out[o++] = '\\';
            out[o++] = '"';
            break;
        case '\\':
            out[o++] = '\\';
            out[o++] = '\\';
            break;
        case '\b':
            out[o++] = '\\';
            out[o++] = 'b';
            break;
        case '\f':
            out[o++] = '\\';
            out[o++] = 'f';
            break;
        case '\n':
            out[o++] = '\\';
            out[o++] = 'n';
            break;
        case '\r':
            out[o++] = '\\';
            out[o++] = 'r';
            break;
        case '\t':
            out[o++] = '\\';
            out[o++] = 't';
            break;
        default:
            if (c < 0x20) {
                out[o++] = '\\';
                out[o++] = 'u';
                out[o++] = '0';
                out[o++] = '0';
                out[o++] = k_hex_lower[(c >> 4) & 0xf];
                out[o++] = k_hex_lower[c & 0xf];
            }
            else {
                out[o++] = (char)c;
            }
            break;
        }
    }
    return o;
}

// Format `sha256:<lowercase-hex>` of `bytes[0..len)` into a freshly-
// allocated `n00b_string_t *` owned by `alloc_for_call`.
static n00b_string_t *
sha256_prefixed_hex(const uint8_t   *bytes,
                    size_t           len,
                    n00b_allocator_t *alloc_for_call)
{
    n00b_sha256_digest_t digest;
    n00b_sha256_hash(bytes, len, digest);
    uint8_t out_bytes[32];
    for (int i = 0; i < 8; i++) {
        uint32_t w = digest[i];
        out_bytes[i * 4 + 0] = (uint8_t)((w >> 24) & 0xff);
        out_bytes[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        out_bytes[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        out_bytes[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
    char *buf = n00b_alloc_array_with_opts(
        char,
        72,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, "sha256:", 7);
    for (size_t i = 0; i < 32; i++) {
        buf[7 + i * 2 + 0] = k_hex_lower[(out_bytes[i] >> 4) & 0xf];
        buf[7 + i * 2 + 1] = k_hex_lower[out_bytes[i] & 0xf];
    }
    buf[71] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)71,
                                .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// ATTESTATION JSON builder (D-056 — ordered string concatenation).
//
// Field order, byte-stable, LEXICOGRAPHIC (canonical / RFC-8785-style)
// — matches the order libchalk's n00b_json_encode(.canonical = true)
// re-emits the subtree in, so the ATTESTATION JSON round-trips
// byte-stably through libchalk parse + reserialize:
//
//   envelope_digest
//   envelopes       (only when bundled mode)
//   predicate_types
//   registry_hint   (only when non-null)
//   signer_keyid
//
// Entries within envelopes[] also use lexicographic field order:
//
//   envelope_base64
//   predicate_type
//
// Each envelope contributes (a) its base64-of-wire bytes, (b) the
// predicate type from its embedded Statement, and (c) its keyid
// (used as the mark's `signer_keyid` from envelope[0]).
// ---------------------------------------------------------------------------

// Per-envelope working set: kept in parallel arrays so the
// serializer walks linearly without intermediate dict allocations.
typedef struct {
    n00b_string_t *predicate_type;     // borrowed from envelope's Statement
    n00b_string_t *envelope_base64;    // base64-of-wire for bundled mode
    n00b_string_t *envelope_digest;    // sha256:<hex>(wire) for envelope[0]
    n00b_string_t *signer_keyid;       // signatures[0].keyid (if any)
} per_envelope_t;

// Walk one envelope and populate a `per_envelope_t`. Returns an
// `n00b_result_t(int)`: Ok(0) on success, Err(N00B_ATTEST_ERR_CHALK_
// BAD_ENVELOPE) on any malformed-envelope condition.
//
// Allocates everything in `alloc_for_call`.
static n00b_result_t(int)
prep_envelope(n00b_attest_envelope_t *env,
              per_envelope_t         *out,
              n00b_allocator_t       *alloc_for_call)
{
    if (env == nullptr) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }

    // Wire bytes.
    auto wire_r = n00b_attest_envelope_serialize(env,
                                                  .allocator = alloc_for_call);
    if (n00b_result_is_err(wire_r)) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    n00b_buffer_t *wire = n00b_result_get(wire_r);

    // SHA-256(wire) → sha256:<hex>.
    out->envelope_digest = sha256_prefixed_hex((const uint8_t *)wire->data,
                                                (size_t)wire->byte_len,
                                                alloc_for_call);

    // Base64 of wire (for envelopes[].envelope_base64).
    auto b64_r = n00b_base64_encode(wire, .allocator = alloc_for_call);
    if (n00b_result_is_err(b64_r)) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    out->envelope_base64 = n00b_result_get(b64_r);

    // Predicate type: parse the envelope's payload (the Statement
    // bytes) and read the predicateType via the existing D-055
    // sibling getter.
    auto pay_r = n00b_attest_envelope_get_payload(env);
    if (n00b_result_is_err(pay_r)) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    n00b_buffer_t *pay = n00b_result_get(pay_r);

    auto st_r = n00b_attest_statement_parse(pay,
                                            .allocator = alloc_for_call);
    if (n00b_result_is_err(st_r)) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    n00b_attest_statement_t *st = n00b_result_get(st_r);
    n00b_option_t(n00b_string_t *) pt_opt
        = n00b_attest_statement_get_predicate_type(st);
    if (!n00b_option_is_set(pt_opt)) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    n00b_string_t *pt = n00b_option_get(pt_opt);
    if (pt == nullptr || pt->u8_bytes == 0) {
        return n00b_result_err(int, N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
    }
    out->predicate_type = pt;

    // Signer keyid (optional — used only for envelope[0]'s slot in
    // the ATTESTATION JSON). The envelope's parser does not
    // currently re-populate `signatures[]` on parse (WP-001's
    // structural-parse precedent); for envelopes built in-process
    // we read signatures[0] via the public getter. If the envelope
    // has no signatures attached we leave the slot null and the
    // builder substitutes an empty string for that field — the
    // ATTESTATION shape requires the key to be present but the
    // value is opaque (D-039); empty is a documented degenerate
    // form. (Tests construct envelopes with at least one signature.)
    if (n00b_attest_envelope_signature_count(env) > 0) {
        auto kid_r = n00b_attest_envelope_get_signature_keyid(env, 0);
        if (n00b_result_is_ok(kid_r)) {
            out->signer_keyid = n00b_result_get(kid_r);
        }
        else {
            out->signer_keyid = nullptr;
        }
    }
    else {
        out->signer_keyid = nullptr;
    }
    return n00b_result_ok(int, 0);
}

// Build the canonical ATTESTATION JSON bytes per
// docs/attest/04-in-container-identity.md §1 via ordered string
// concatenation. `registry_hint` may be nullptr (field is omitted
// in that case). Returns a buffer owned by `alloc_for_call`.
static n00b_buffer_t *
build_attestation_json(const per_envelope_t *envs,
                       size_t                n_envs,
                       bool                  bundled,
                       n00b_string_t        *registry_hint,
                       n00b_allocator_t     *alloc_for_call)
{
    // The signer_keyid in the mark is envelope[0]'s keyid (the
    // canonical D-039 form). If envelope[0] has no keyid we fall
    // back to the empty string — see `prep_envelope` for the
    // degenerate-shape rationale.
    n00b_string_t *signer_keyid = envs[0].signer_keyid;
    const char    *sk_data      = signer_keyid ? signer_keyid->data : "";
    size_t         sk_len       = signer_keyid ? signer_keyid->u8_bytes : 0;

    // envelope_digest = digest of envelope[0]'s wire (the spec
    // §1-of-file-04 field is singular; multi-envelope marks expose
    // per-envelope digests via `envelopes[]`).
    n00b_string_t *env0_digest = envs[0].envelope_digest;

    // Pre-compute escaped sizes for every user-supplied string field
    // so we can allocate the upper-bound output buffer up-front
    // (mirrors the OCI manifest serializer's strategy).
    size_t escaped_env0_digest = json_escaped_size(env0_digest->data,
                                                    env0_digest->u8_bytes);
    size_t escaped_signer_keyid = json_escaped_size(sk_data, sk_len);
    size_t escaped_registry_hint = 0;
    if (registry_hint != nullptr) {
        escaped_registry_hint = json_escaped_size(registry_hint->data,
                                                   registry_hint->u8_bytes);
    }

    // Per-envelope sizes — predicate_types[] entries + (bundled mode)
    // envelopes[] entries.
    size_t predicate_types_sum = 0;
    size_t envelopes_sum       = 0;
    for (size_t i = 0; i < n_envs; i++) {
        size_t pt_esc = json_escaped_size(envs[i].predicate_type->data,
                                          envs[i].predicate_type->u8_bytes);
        // Per entry in predicate_types[]: `"..."` plus optional comma.
        predicate_types_sum += 2 + pt_esc + (i + 1 < n_envs ? 1 : 0);

        if (bundled) {
            size_t b64_esc = json_escaped_size(envs[i].envelope_base64->data,
                                               envs[i].envelope_base64->u8_bytes);
            // Per entry in envelopes[]:
            //   {"predicate_type":"<pt>","envelope_base64":"<b64>"}
            // plus optional comma between entries.
            envelopes_sum += 1                  // '{'
                            + 17                // "predicate_type":
                            + 1 + pt_esc + 1    // "..."
                            + 1                 // ','
                            + 18                // "envelope_base64":
                            + 1 + b64_esc + 1   // "..."
                            + 1                 // '}'
                            + (i + 1 < n_envs ? 1 : 0); // ','
        }
    }

    size_t cap = 0;
    cap += 1;  // '{'
    cap += sizeof("\"envelope_digest\":\"") - 1 + escaped_env0_digest
           + 1; // closing '"'
    cap += sizeof(",\"predicate_types\":[") - 1 + predicate_types_sum
           + 1; // closing ']'
    if (registry_hint != nullptr) {
        cap += sizeof(",\"registry_hint\":\"") - 1 + escaped_registry_hint
               + 1; // closing '"'
    }
    cap += sizeof(",\"signer_keyid\":\"") - 1 + escaped_signer_keyid
           + 1; // closing '"'
    if (bundled) {
        cap += sizeof(",\"envelopes\":[") - 1 + envelopes_sum
               + 1; // closing ']'
    }
    cap += 2; // '}' + trailing NUL

    char *out = n00b_alloc_array_with_opts(
        char,
        cap,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    size_t o = 0;

#define APPEND_LIT(s) do {                                              \
        memcpy(out + o, (s), sizeof(s) - 1);                            \
        o += sizeof(s) - 1;                                             \
    } while (0)
#define APPEND_RAW(p, n) do {                                           \
        memcpy(out + o, (p), (n));                                      \
        o += (n);                                                       \
    } while (0)

    // Field order is LEXICOGRAPHIC (canonical / RFC-8785-style) so
    // the wire output is byte-stable across the libchalk
    // parse-then-reserialize round-trip (libchalk emits in
    // canonical order via n00b_json_encode(.canonical = true)).
    // Order: envelope_digest, envelopes, predicate_types,
    // registry_hint (optional), signer_keyid.
    // Each entry within envelopes[] also uses lexicographic order
    // (envelope_base64, predicate_type).
    APPEND_LIT("{\"envelope_digest\":\"");
    o += json_escape_into(out + o, env0_digest->data, env0_digest->u8_bytes);
    APPEND_LIT("\"");

    if (bundled) {
        APPEND_LIT(",\"envelopes\":[");
        for (size_t i = 0; i < n_envs; i++) {
            APPEND_LIT("{\"envelope_base64\":\"");
            o += json_escape_into(out + o,
                                  envs[i].envelope_base64->data,
                                  envs[i].envelope_base64->u8_bytes);
            APPEND_LIT("\",\"predicate_type\":\"");
            o += json_escape_into(out + o,
                                  envs[i].predicate_type->data,
                                  envs[i].predicate_type->u8_bytes);
            APPEND_LIT("\"}");
            if (i + 1 < n_envs) {
                APPEND_LIT(",");
            }
        }
        APPEND_LIT("]");
    }

    APPEND_LIT(",\"predicate_types\":[");
    for (size_t i = 0; i < n_envs; i++) {
        APPEND_LIT("\"");
        o += json_escape_into(out + o,
                              envs[i].predicate_type->data,
                              envs[i].predicate_type->u8_bytes);
        APPEND_LIT("\"");
        if (i + 1 < n_envs) {
            APPEND_LIT(",");
        }
    }
    APPEND_LIT("]");

    if (registry_hint != nullptr) {
        APPEND_LIT(",\"registry_hint\":\"");
        o += json_escape_into(out + o,
                              registry_hint->data,
                              registry_hint->u8_bytes);
        APPEND_LIT("\"");
    }

    APPEND_LIT(",\"signer_keyid\":\"");
    if (signer_keyid != nullptr) {
        o += json_escape_into(out + o, sk_data, sk_len);
    }
    APPEND_LIT("\"");

    APPEND_LIT("}");

#undef APPEND_LIT
#undef APPEND_RAW

    return n00b_buffer_from_bytes(out,
                                  (int64_t)o,
                                  .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// File-IO helpers — read the artifact bytes into memory, dispatch via the
// libchalk *_buffer entry points (which detect by magic bytes rather than
// extension), then write the result back via the n00b file API.
//
// We deliberately do NOT use libchalk's file-mode dispatch
// (`n00b_chalk_insert_file` / `_hash_file` / `_extract_file` /
// `_delete_file`) because that path detects codecs via path extension
// only — extensionless tempfiles (a common test pattern) fall through
// to CODEC_NONE even when the bytes are a perfectly valid ELF / Mach-O
// / PE. The buffer-based entries detect by magic, which is the right
// behavior for n00b-attest's mark surface (callers may hand us paths
// with arbitrary suffixes).
//
// In-band codecs rewrite the artifact in place. Sidecar codecs leave
// the artifact bytes untouched and emit the mark into
// `<artifact_path>.chalk`.
// ---------------------------------------------------------------------------

// Read the full contents of `path` into a `n00b_buffer_t *`.
// Returns null on any open / mmap / read failure.
static n00b_buffer_t *
read_file_bytes(n00b_string_t *path, n00b_allocator_t *alloc_for_call)
{
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f = n00b_result_get(fr);
    auto br = n00b_file_as_buffer(f);
    if (n00b_result_is_err(br)) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *mmapped = n00b_result_get(br);
    // Copy out — the mmap-backed buffer's lifetime is tied to the
    // file handle, so we close + return a heap-owned copy that
    // outlives the close.
    n00b_buffer_t *out = n00b_buffer_from_bytes(
        mmapped->data,
        mmapped->byte_len,
        .allocator = alloc_for_call);
    n00b_file_close(f);
    return out;
}

// Write `bytes` to `path`, truncating any existing content.
// Returns true on success, false on any open / write failure.
static bool
write_file_bytes(n00b_string_t *path, n00b_buffer_t *bytes)
{
    auto fr = n00b_file_open(path,
                              .mode = N00B_FILE_W,
                              .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) {
        return false;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         wr = n00b_file_write(f, bytes->data, (size_t)bytes->byte_len);
    n00b_file_close(f);
    return n00b_result_is_ok(wr);
}

// Sidecar suffix matches libchalk's `file_io.c::sidecar_path` (".chalk").
// We keep this string in sync with libchalk; if libchalk lifts the
// sidecar suffix to a public constant later we should consume that.
static n00b_string_t *
sidecar_path_for(n00b_string_t *path, n00b_allocator_t *alloc_for_call)
{
    size_t plen = (size_t)path->u8_bytes;
    char  *buf  = n00b_alloc_array_with_opts(
        char,
        plen + 6 + 1,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    memcpy(buf, path->data, plen);
    memcpy(buf + plen, ".chalk", 6);
    buf[plen + 6] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)(plen + 6),
                                .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Public surface — n00b_attest_mark_artifact.
// ---------------------------------------------------------------------------

n00b_result_t(n00b_attest_mark_result_t *)
n00b_attest_mark_artifact(n00b_string_t                       *artifact_path,
                          n00b_list_t(n00b_attest_envelope_t *) *envelopes)
    _kargs {
        bool                          bundled         = true;
        n00b_string_t                *registry_hint   = nullptr;
        n00b_allocator_t             *allocator       = nullptr;
        n00b_chalk_signer_identity_t *signer_identity = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    if (artifact_path == nullptr || artifact_path->u8_bytes == 0
        || envelopes == nullptr) {
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    size_t n_envs = (size_t)n00b_list_len(*envelopes);
    if (n_envs == 0) {
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // (1) Validate registry_hint, if non-null, BEFORE any byte-
    // mutating operation.
    if (registry_hint != nullptr) {
        auto rh_r = n00b_attest_oci_url_parse(registry_hint,
                                              .allocator = alloc_for_call);
        if (n00b_result_is_err(rh_r)) {
            return n00b_result_err(n00b_attest_mark_result_t *,
                                   N00B_ATTEST_ERR_CHALK_BAD_REGISTRY_HINT);
        }
    }

    // (2) Read the artifact bytes once and compute the pre-insert
    // unchalked hash via libchalk's *_buffer entry point. Going
    // through the buffer API rather than the file API lets libchalk
    // detect the codec by magic bytes (the file API can only detect
    // via extension — that's a libchalk-side limitation that costs
    // us interop with extensionless binaries).
    n00b_buffer_t *artifact_bytes = read_file_bytes(artifact_path,
                                                    alloc_for_call);
    if (artifact_bytes == nullptr) {
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
    }
    auto hash_r = n00b_chalk_hash_buffer(artifact_bytes);
    if (n00b_result_is_err(hash_r)) {
        // No codec recognized the bytes, OR the codec's hash path
        // failed. Map both to INSERT_FAILED — the caller asked us
        // to mark and we can't proceed.
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
    }
    n00b_buffer_t *pre_insert_hash = n00b_result_get(hash_r);

    // (3) Prepare per-envelope working set + build ATTESTATION
    // JSON bytes. Errors in per-envelope prep surface as
    // CHALK_BAD_ENVELOPE; no byte-mutating op has run yet.
    per_envelope_t *envs = n00b_alloc_array_with_opts(
        per_envelope_t,
        n_envs,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});

    for (size_t i = 0; i < n_envs; i++) {
        n00b_attest_envelope_t *env = n00b_list_get(*envelopes,
                                                     (int64_t)i);
        auto pr = prep_envelope(env, &envs[i], alloc_for_call);
        if (n00b_result_is_err(pr)) {
            return n00b_result_err(n00b_attest_mark_result_t *,
                                   N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE);
        }
    }

    n00b_buffer_t *att_json = build_attestation_json(envs,
                                                      n_envs,
                                                      bundled,
                                                      registry_hint,
                                                      alloc_for_call);

    // (4) Parse the JSON bytes into a `n00b_json_node_t *` tree
    // — that's the shape libchalk's `_mark_set_attestation`
    // expects. The serializer + parser round-trip is canonical
    // (D-024 `.pretty = false`).
    const char       *jerr = nullptr;
    n00b_json_node_t *att_tree = n00b_json_parse(att_json->data,
                                                  (size_t)att_json->byte_len,
                                                  &jerr);
    if (att_tree == nullptr) {
        // The bytes we just emitted should always parse; if they
        // don't there's a bug in the builder. Surface as
        // INSERT_FAILED since the caller cannot do anything else.
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
    }

    // (5) Build the chalk mark + attach ATTESTATION + insert.
    n00b_chalk_mark_t *mark = n00b_chalk_mark_new();
    auto setatt_r = n00b_chalk_mark_set_attestation(mark, att_tree);
    if (n00b_result_is_err(setatt_r)) {
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
    }

    auto ins_r = n00b_chalk_insert_buffer(artifact_bytes, mark);
    if (n00b_result_is_err(ins_r)) {
        return n00b_result_err(n00b_attest_mark_result_t *,
                               N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
    }
    n00b_chalk_io_result_t *io = n00b_result_get(ins_r);

    // (5b) Write the rewritten bytes back to disk. In-band codecs
    // overwrite the artifact path; sidecar codecs write to
    // `<artifact_path>.chalk` and leave the artifact untouched.
    if (io->kind == N00B_CHALK_OUT_IN_BAND) {
        if (!write_file_bytes(artifact_path, io->bytes)) {
            return n00b_result_err(n00b_attest_mark_result_t *,
                                   N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
        }
    }
    else {  // sidecar
        n00b_string_t *sc_path = sidecar_path_for(artifact_path,
                                                   alloc_for_call);
        if (!write_file_bytes(sc_path, io->bytes)) {
            return n00b_result_err(n00b_attest_mark_result_t *,
                                   N00B_ATTEST_ERR_CHALK_INSERT_FAILED);
        }
    }

    // (5c) Post-insert re-sign dispatch (WP-005 Phase 6).
    //
    // When the caller supplied a non-null signer_identity AND the
    // codec is PE or Mach-O, dispatch the corresponding libchalk
    // re-sign primitive against the now-rewritten artifact bytes.
    // ELF and all other codecs (ZIP, .pyc, GGUF, safetensors,
    // source, sidecar) do not have a platform signature concept on
    // the mark surface and are skipped regardless of identity.
    //
    // The re-sign reads the post-mark bytes from disk, computes
    // the platform-specific code hash, builds the signature blob,
    // and writes the signed binary back in place. Sidecar codecs
    // are not affected (`io->kind == N00B_CHALK_OUT_SIDECAR` means
    // the artifact bytes themselves were never rewritten; the
    // signer would have nothing to operate on).
    //
    // We detect the codec on the original (pre-insert) artifact
    // bytes because (a) it costs us nothing — `_detect_buffer` is
    // a magic-byte scan we already amortized via the insert path
    // — and (b) post-insert detection over an in-band-rewritten
    // binary returns the same codec id (the chalk section is an
    // additive transform that does not change the file's magic).
    if (signer_identity != nullptr
        && io->kind == N00B_CHALK_OUT_IN_BAND) {
        n00b_chalk_codec_id_t codec = n00b_chalk_detect_buffer(artifact_bytes,
                                                                artifact_path);
        if (codec == N00B_CHALK_CODEC_PE) {
            auto rsr = n00b_chalk_pe_resign(artifact_path,
                                             .signer_identity = signer_identity,
                                             .allocator       = alloc_for_call);
            if (n00b_result_is_err(rsr)) {
                return n00b_result_err(n00b_attest_mark_result_t *,
                                       N00B_ATTEST_ERR_CHALK_RESIGN_FAILED);
            }
        }
        else if (codec == N00B_CHALK_CODEC_MACHO) {
            auto rsr = n00b_chalk_macho_resign(artifact_path,
                                                .signer_identity = signer_identity,
                                                .allocator       = alloc_for_call);
            if (n00b_result_is_err(rsr)) {
                return n00b_result_err(n00b_attest_mark_result_t *,
                                       N00B_ATTEST_ERR_CHALK_RESIGN_FAILED);
            }
        }
        // All other codecs: no platform-signature step. The
        // `signer_identity` kwarg is documented as ignored for
        // those codecs (per `_mark_artifact`'s @kw doc).
    }

    // (6) Assemble the row type. We copy the pre-insert hash into
    // `alloc_for_call` so the returned buffer's lifetime is
    // controlled by the caller's allocator (libchalk's hash buf
    // lives in the GC heap; the caller may want to keep the row
    // beyond the next collection).
    n00b_buffer_t *hash_copy = n00b_buffer_from_bytes(
        pre_insert_hash->data,
        pre_insert_hash->byte_len,
        .allocator = alloc_for_call);

    n00b_attest_mark_result_t *row = n00b_alloc_with_opts(
        n00b_attest_mark_result_t,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    row->unchalked_sha256_32 = hash_copy;
    row->kind                = io->kind;
    row->sidecar_suffix      = io->sidecar_suffix
                                  ? copy_string_into(io->sidecar_suffix,
                                                     alloc_for_call)
                                  : nullptr;
    return n00b_result_ok(n00b_attest_mark_result_t *, row);
}

// ---------------------------------------------------------------------------
// Public surface — n00b_attest_unmark.
// ---------------------------------------------------------------------------

n00b_result_t(bool)
n00b_attest_unmark(n00b_string_t *artifact_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    if (artifact_path == nullptr || artifact_path->u8_bytes == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // Read bytes, dispatch via buffer API (magic-byte detection),
    // write back. Symmetric with mark_artifact's read/dispatch/write
    // shape; same rationale for avoiding the file dispatcher.
    n00b_buffer_t *artifact_bytes = read_file_bytes(artifact_path,
                                                    alloc_for_call);
    if (artifact_bytes == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_CHALK_DELETE_FAILED);
    }
    auto dr = n00b_chalk_delete_buffer(artifact_bytes);
    if (n00b_result_is_err(dr)) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_CHALK_DELETE_FAILED);
    }
    n00b_chalk_io_result_t *io = n00b_result_get(dr);
    if (io->kind == N00B_CHALK_OUT_IN_BAND) {
        if (!write_file_bytes(artifact_path, io->bytes)) {
            return n00b_result_err(bool, N00B_ATTEST_ERR_CHALK_DELETE_FAILED);
        }
    }
    else {  // sidecar — empty bytes from delete means "remove the
            // sidecar"; nonempty means "overwrite the sidecar". The
            // libchalk file_io.c::write_io_result branch handles
            // the empty case via unlink; mirror that here.
        n00b_string_t *sc_path = sidecar_path_for(artifact_path,
                                                   alloc_for_call);
        if (io->bytes == nullptr || io->bytes->byte_len == 0) {
            auto ur = n00b_file_unlink(sc_path, .ignore_missing = true);
            if (n00b_result_is_err(ur)) {
                return n00b_result_err(bool,
                                       N00B_ATTEST_ERR_CHALK_DELETE_FAILED);
            }
        }
        else if (!write_file_bytes(sc_path, io->bytes)) {
            return n00b_result_err(bool, N00B_ATTEST_ERR_CHALK_DELETE_FAILED);
        }
    }
    return n00b_result_ok(bool, true);
}

// ---------------------------------------------------------------------------
// Public surface — n00b_attest_extract_from_artifact.
// ---------------------------------------------------------------------------

// Walk a `n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *` and
// return the value for key `key_cstr`, or nullptr if absent.
static n00b_json_node_t *
mark_dict_lookup(n00b_dict_t(n00b_string_t *, n00b_json_node_t *) *d,
                 const char *key_cstr)
{
    if (d == nullptr) {
        return nullptr;
    }
    size_t klen = strlen(key_cstr);
    n00b_dict_foreach(d, k, v, {
        if (k->u8_bytes == klen && memcmp(k->data, key_cstr, klen) == 0) {
            return v;
        }
    });
    return nullptr;
}

// Pull a JSON-string field out of an object; nullptr-safe. Returns
// the borrowed string node value or nullptr if missing/wrong type.
static const char *
obj_get_string(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = n00b_json_object_get_cstr(obj, key);
    if (!n00b_json_is_string(v)) {
        return nullptr;
    }
    return n00b_json_as_cstr(v);
}

// Pull a JSON-array field out of an object; nullptr-safe.
static n00b_json_node_t *
obj_get_array(n00b_json_node_t *obj, const char *key)
{
    n00b_json_node_t *v = n00b_json_object_get_cstr(obj, key);
    if (!n00b_json_is_array(v)) {
        return nullptr;
    }
    return v;
}

n00b_result_t(n00b_attest_extract_result_t *)
n00b_attest_extract_from_artifact(n00b_string_t *artifact_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    n00b_allocator_t *alloc_for_call = allocator;

    if (artifact_path == nullptr || artifact_path->u8_bytes == 0) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // (i) Read the artifact bytes once + detect codec by magic.
    // Use the buffer API for the same rationale as mark_artifact:
    // the file dispatcher only knows extensions, which fails for
    // extensionless binaries.
    n00b_buffer_t *artifact_bytes = read_file_bytes(artifact_path,
                                                    alloc_for_call);
    if (artifact_bytes == nullptr) {
        // Cannot read the file at all — treat as codec-lookup
        // failure (the IC-5 (iv) shape). The next finer-grained
        // distinction (file-not-found vs no-codec) is a future
        // refinement.
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_CODEC_LOOKUP_FAILED);
    }
    n00b_chalk_codec_id_t codec = n00b_chalk_detect_buffer(artifact_bytes,
                                                             artifact_path);
    if (codec == N00B_CHALK_CODEC_NONE) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_CODEC_LOOKUP_FAILED);
    }

    // Run libchalk extract via the buffer API. The current libchalk
    // Err-code shape does not differentiate "no mark in artifact"
    // from "any other codec-internal failure" — both surface as a
    // numeric code that's opaque at this layer. We map ALL Err
    // codes to NO_MARK for the IC-5-(i) case. A future libchalk lift
    // that splits these would let us route the other paths to
    // EXTRACT_FAILED; until then, NO_MARK is the load-bearing case
    // (a file the codec recognizes but that carries no chalk
    // section) and codec-internal failures of marked-binary parsing
    // are rare edge cases that don't matter for the IC-5 mapping
    // the caller actually queries.
    auto ext_r = n00b_chalk_extract_buffer(artifact_bytes);
    if (n00b_result_is_err(ext_r)) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_NO_MARK);
    }
    n00b_chalk_extract_result_t *cr = n00b_result_get(ext_r);
    if (cr == nullptr || cr->mark == nullptr) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_NO_MARK);
    }

    // (ii) ATTESTATION field. Missing → IC-5 case (ii).
    n00b_json_node_t *att = mark_dict_lookup(cr->mark, "ATTESTATION");
    if (att == nullptr) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_NO_ATTESTATION);
    }
    if (!n00b_json_is_object(att)) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
    }

    // (iii) Parse the canonical ATTESTATION shape.
    const char *env_digest_cstr = obj_get_string(att, "envelope_digest");
    if (env_digest_cstr == nullptr) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
    }
    const char *signer_keyid_cstr = obj_get_string(att, "signer_keyid");
    if (signer_keyid_cstr == nullptr) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
    }
    n00b_json_node_t *pt_arr = obj_get_array(att, "predicate_types");
    if (pt_arr == nullptr || n00b_json_array_len(pt_arr) == 0) {
        return n00b_result_err(n00b_attest_extract_result_t *,
                               N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
    }

    // Optional registry_hint.
    const char *reg_hint_cstr = obj_get_string(att, "registry_hint");
    // (Not finding the key is OK; finding it as the wrong type is
    // a structural violation.)
    if (reg_hint_cstr == nullptr) {
        n00b_json_node_t *v = n00b_json_object_get_cstr(att, "registry_hint");
        if (v != nullptr && !n00b_json_is_string(v)) {
            return n00b_result_err(n00b_attest_extract_result_t *,
                                   N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
        }
    }

    // Collect predicate_types into a fresh list. The public surface
    // exposes the list as a pointer-to-struct; allocate the struct
    // under `alloc_for_call` and initialize it via
    // `n00b_list_new` (which returns a struct-by-value).
    n00b_list_t(n00b_string_t *) *predicate_types = n00b_alloc_with_opts(
        n00b_list_t(n00b_string_t *),
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    *predicate_types = n00b_list_new(n00b_string_t *,
                                      .allocator = alloc_for_call);
    for (size_t i = 0; i < n00b_json_array_len(pt_arr); i++) {
        n00b_json_node_t *pt_node = n00b_json_array_get(pt_arr, i);
        if (!n00b_json_is_string(pt_node)) {
            return n00b_result_err(n00b_attest_extract_result_t *,
                                   N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
        }
        n00b_string_t *pt = n00b_string_from_cstr(n00b_json_as_cstr(pt_node),
                                                   .allocator = alloc_for_call);
        n00b_list_push(*predicate_types, pt);
    }

    // envelopes[] (optional — present only in bundled mode).
    n00b_list_t(n00b_attest_envelope_t *) *envs_out = n00b_alloc_with_opts(
        n00b_list_t(n00b_attest_envelope_t *),
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    *envs_out = n00b_list_new(n00b_attest_envelope_t *,
                               .allocator = alloc_for_call);
    bool                              bundled  = false;
    n00b_json_node_t                 *envs_arr = obj_get_array(att, "envelopes");
    if (envs_arr != nullptr) {
        bundled = true;
        for (size_t i = 0; i < n00b_json_array_len(envs_arr); i++) {
            n00b_json_node_t *entry = n00b_json_array_get(envs_arr, i);
            if (!n00b_json_is_object(entry)) {
                return n00b_result_err(n00b_attest_extract_result_t *,
                    N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
            }
            const char *b64 = obj_get_string(entry, "envelope_base64");
            if (b64 == nullptr) {
                return n00b_result_err(n00b_attest_extract_result_t *,
                    N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
            }
            n00b_string_t *b64_str = n00b_string_from_cstr(b64,
                                                    .allocator = alloc_for_call);
            auto dec_r = n00b_base64_decode(b64_str,
                                             .allocator = alloc_for_call);
            if (n00b_result_is_err(dec_r)) {
                return n00b_result_err(n00b_attest_extract_result_t *,
                    N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
            }
            n00b_buffer_t *wire = n00b_result_get(dec_r);
            auto env_r = n00b_attest_envelope_parse(wire,
                                                     .allocator = alloc_for_call);
            if (n00b_result_is_err(env_r)) {
                return n00b_result_err(n00b_attest_extract_result_t *,
                    N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION);
            }
            n00b_list_push(*envs_out, n00b_result_get(env_r));
        }
    }

    // unchalked hash from the mark's HASH field (advisory — same
    // value libchalk's _hash_file returns for the unchalked bytes).
    const char *hash_hex_cstr = nullptr;
    n00b_json_node_t *hash_node = mark_dict_lookup(cr->mark, "HASH");
    if (n00b_json_is_string(hash_node)) {
        hash_hex_cstr = n00b_json_as_cstr(hash_node);
    }

    // Assemble row.
    n00b_attest_extract_result_t *row = n00b_alloc_with_opts(
        n00b_attest_extract_result_t,
        &(n00b_alloc_opts_t){.allocator = alloc_for_call});
    row->unchalked_hash_hex = hash_hex_cstr
                                  ? n00b_string_from_cstr(hash_hex_cstr,
                                                          .allocator = alloc_for_call)
                                  : nullptr;
    row->envelope_digest   = n00b_string_from_cstr(env_digest_cstr,
                                                    .allocator = alloc_for_call);
    row->registry_hint     = reg_hint_cstr
                                  ? n00b_string_from_cstr(reg_hint_cstr,
                                                          .allocator = alloc_for_call)
                                  : nullptr;
    row->signer_keyid      = n00b_string_from_cstr(signer_keyid_cstr,
                                                    .allocator = alloc_for_call);
    row->predicate_types   = predicate_types;
    row->envelopes         = envs_out;
    row->bundled           = bundled;
    return n00b_result_ok(n00b_attest_extract_result_t *, row);
}
