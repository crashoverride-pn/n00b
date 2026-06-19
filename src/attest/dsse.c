/* src/attest/dsse.c — DSSE envelope encode/decode body.
 *
 * Implements the surface declared in include/attest/n00b_attest_dsse.h:
 *   - n00b_attest_envelope_new
 *   - n00b_attest_envelope_set_payload    (BORROW semantics, D-030/W-3)
 *   - n00b_attest_envelope_serialize
 *   - n00b_attest_envelope_parse
 *   - n00b_attest_envelope_get_payload
 *   - n00b_attest_envelope_pae_bytes
 *
 * Per WP-001 scope: signatures[] is always emitted as []. The shape
 * matches the canonical DSSE per-entry layout `{keyid, sig}` (D-016)
 * so WP-002 can populate it without a header break.
 *
 * PAE byte string (DSSE v1 spec): `DSSEv1 SP <decimal-len(payloadType)>
 * SP <payloadType> SP <decimal-len(payload)> SP <payload>`, where
 * <payload> is the **unencoded** Statement bytes (NOT the base64-wrapped
 * form). The architecture text in docs/attest/02-architecture.md §5.2
 * agrees with this; no drift surfaced during implementation.
 *
 * Base64 (RFC 4648 with '=' padding) is delegated to the
 * libn00b util `n00b_base64_*` (include/util/base64.h, lifted in
 * WP-002 Phase 1; thin wrapper around picotls's `ptls_base64_*`
 * primitives). The dsse.c-local inline encoder/decoder removed in
 * that same lift — libchalk's `src/chalk/macos_wrap.c` now consumes
 * the same util.
 */

#include <attest/n00b_attest.h>
#include <crypto/base64.h>

#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "adt/result.h"
#include "text/strings/string_ops.h"  // n00b_unicode_str_eq

#include "internal/attest/json_util.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Module-domain error codes are now declared in
// `include/attest/n00b_attest_error.h` (V-2 fix during WP-002 Phase 3 — see
// D-031 A-1 closure). The umbrella header pulls them in.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// DSSE constants.
// ---------------------------------------------------------------------------

static const char k_dsse_payload_type[] = "application/vnd.in-toto+json";
static const char k_dsse_pae_prefix[]   = "DSSEv1";

// ---------------------------------------------------------------------------
// Private type.
//
// The envelope holds a borrowed pointer to the payload buffer per D-030
// W-3 (no copy, no allocator threading on set_payload), plus a parallel
// pair of lists carrying the (keyid, sig) signature entries appended via
// `n00b_attest_envelope_add_signature` / `n00b_attest_envelope_sign`. The
// per-entry shape (D-016) is `{ "keyid": "<hex>", "sig": "<base64>" }` —
// algorithm-agnostic; the envelope code does not interpret either field.
//
// We use parallel lists rather than a struct array because the existing
// `subject_entry_t` precedent in `statement.c` uses the same shape and the
// number of signatures per envelope is small (typically 1 — the multi-
// signer flow FR-11 is deferred). No header break.
// ---------------------------------------------------------------------------

struct n00b_attest_envelope {
    n00b_buffer_t    *payload;     // borrowed; lifetime managed by caller
    n00b_allocator_t *allocator;   // for everything the envelope itself produces

    // signature_keyids[i] paired with signature_sigs[i]; both lists grow
    // together via `n00b_attest_envelope_add_signature`. Stored as private
    // copies — the caller may free the inputs immediately after the call.
    n00b_list_t(n00b_string_t *) signature_keyids;
    n00b_list_t(n00b_buffer_t *) signature_sigs;
    bool signatures_initialized;
};

// ---------------------------------------------------------------------------
// Decimal-ASCII helpers (PAE length fields).
// ---------------------------------------------------------------------------

static size_t
dec_ascii_len(size_t v)
{
    size_t n = 1;
    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

static void
dec_ascii_write(char *dst, size_t v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        dst[n - 1 - i] = (char)('0' + (v % 10));
        v /= 10;
    }
}

// ---------------------------------------------------------------------------
// Public surface.
// ---------------------------------------------------------------------------

// Lazy-initialize the signature lists on first append. We don't
// build them in `_envelope_new` because every envelope produced
// pre-Phase-3 went without — the lazy-init keeps the construct-
// then-discard fast path (the existing roundtrip test pattern)
// unchanged while making the lists available the moment a
// signature is appended.
static void
ensure_signatures_initialized(n00b_attest_envelope_t *env,
                              n00b_allocator_t       *alloc_for_call)
{
    if (env->signatures_initialized) {
        return;
    }
    env->signature_keyids = n00b_list_new(n00b_string_t *,
                                          .allocator = alloc_for_call);
    env->signature_sigs   = n00b_list_new(n00b_buffer_t *,
                                          .allocator = alloc_for_call);
    env->signatures_initialized = true;
}

n00b_attest_envelope_t *
n00b_attest_envelope_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_attest_envelope_t *env = n00b_alloc_with_opts(
        n00b_attest_envelope_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    env->payload                = nullptr;
    env->allocator              = allocator;
    env->signatures_initialized = false;
    return env;
}

// D-030 / W-3: BORROW semantics. The body stores the pointer and
// allocates nothing — no allocator parameter (the declaration has no
// _kargs block). The caller's contract per the doxygen: keep
// `payload`'s bytes valid until _serialize runs.
n00b_result_t(bool)
n00b_attest_envelope_set_payload(n00b_attest_envelope_t *env,
                                 n00b_buffer_t          *payload)
{
    if (env == nullptr || payload == nullptr || payload->byte_len == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    env->payload = payload;
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_envelope_serialize(n00b_attest_envelope_t *env) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (env->payload == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_NO_PAYLOAD);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    auto enc_r = n00b_base64_encode(env->payload,
                                    .allocator = alloc_for_call);
    if (n00b_result_is_err(enc_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    n00b_string_t *b64 = n00b_result_get(enc_r);

    // NUL-terminate the base64 string for n00b_json_string_new.
    char *b64_cstr = n00b_alloc_array_with_opts(
        char,
        b64->u8_bytes + 1,
        &(n00b_alloc_opts_t){
            .allocator = alloc_for_call,
        });
    memcpy(b64_cstr, b64->data, b64->u8_bytes);
    b64_cstr[b64->u8_bytes] = '\0';

    n00b_json_node_t *root = n00b_json_object_new();
    n00b_json_object_put(root,
                         "payloadType",
                         n00b_json_string_new(k_dsse_payload_type));
    n00b_json_object_put(root,
                         "payload",
                         n00b_json_string_new(b64_cstr));

    // WP-002 Phase 3: emit each appended `{keyid, sig}` pair into the
    // `signatures[]` array. The per-entry shape (D-016) is
    // `{ "keyid": "<hex>", "sig": "<base64>" }` — algorithm-agnostic.
    // If no signatures were appended the array is emitted empty
    // (matching the WP-001 behavior for envelopes that go through
    // serialize without signing — e.g., the existing roundtrip test).
    n00b_json_node_t *sigs_arr = n00b_json_array_new();
    if (env->signatures_initialized) {
        size_t nsigs = env->signature_keyids.len;
        for (size_t i = 0; i < nsigs; i++) {
            n00b_string_t *kid = env->signature_keyids.data[i];
            n00b_buffer_t *sig = env->signature_sigs.data[i];

            // Base64-encode the sig bytes per DSSE wire shape.
            auto sig_enc_r = n00b_base64_encode(sig,
                                                .allocator = alloc_for_call);
            if (n00b_result_is_err(sig_enc_r)) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_ATTEST_ERR_DSSE_BAD_INPUT);
            }
            n00b_string_t *sig_b64 = n00b_result_get(sig_enc_r);

            // NUL-terminate keyid + sig_b64 so the JSON helpers can
            // ingest them (`n00b_json_string_new` takes `const char *`).
            char *kid_cstr = n00b_alloc_array_with_opts(
                char,
                kid->u8_bytes + 1,
                &(n00b_alloc_opts_t){.allocator = alloc_for_call});
            memcpy(kid_cstr, kid->data, kid->u8_bytes);
            kid_cstr[kid->u8_bytes] = '\0';

            char *sig_b64_cstr = n00b_alloc_array_with_opts(
                char,
                sig_b64->u8_bytes + 1,
                &(n00b_alloc_opts_t){.allocator = alloc_for_call});
            memcpy(sig_b64_cstr, sig_b64->data, sig_b64->u8_bytes);
            sig_b64_cstr[sig_b64->u8_bytes] = '\0';

            n00b_json_node_t *entry = n00b_json_object_new();
            n00b_json_object_put(entry,
                                 "keyid",
                                 n00b_json_string_new(kid_cstr));
            n00b_json_object_put(entry,
                                 "sig",
                                 n00b_json_string_new(sig_b64_cstr));
            n00b_json_array_push(sigs_arr, entry);
        }
    }
    n00b_json_object_put(root, "signatures", sigs_arr);

    char *encoded = n00b_json_encode(root, .pretty = false);
    if (encoded == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_JSON);
    }
    n00b_buffer_t *out = n00b_buffer_from_bytes(encoded,
                                                (int64_t)strlen(encoded),
                                                .allocator = alloc_for_call);
    return n00b_result_ok(n00b_buffer_t *, out);
}

// JSON-object key lookup lives in the shared internal helper:
// `n00b_attest_json_obj_lookup` (declared in
// `include/internal/attest/json_util.h`, defined in
// `src/attest/json_util.c`). Used here and by `statement.c`.

n00b_result_t(n00b_attest_envelope_t *)
n00b_attest_envelope_parse(n00b_buffer_t *bytes) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bytes == nullptr || bytes->byte_len == 0) {
        return n00b_result_err(n00b_attest_envelope_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(bytes->data,
                                              bytes->byte_len,
                                              &err);
    if (!n00b_json_is_object(root)) {
        return n00b_result_err(n00b_attest_envelope_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_JSON);
    }

    n00b_json_node_t *pt_node      = n00b_attest_json_obj_lookup(root, r"payloadType");
    n00b_json_node_t *payload_node = n00b_attest_json_obj_lookup(root, r"payload");
    if (!n00b_json_is_string(pt_node) || !n00b_json_is_string(payload_node)) {
        return n00b_result_err(n00b_attest_envelope_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_JSON);
    }
    if (strcmp(n00b_json_as_cstr(pt_node), k_dsse_payload_type) != 0) {
        return n00b_result_err(n00b_attest_envelope_t *,
                               N00B_ATTEST_ERR_DSSE_WRONG_TYPE);
    }

    n00b_attest_envelope_t *env = n00b_attest_envelope_new(
        .allocator = allocator);

    // Allocator threading symmetry with the write side (D-041): a
    // single `alloc_for_call` local sourced from the caller's
    // optional `allocator` kwarg (falling back to `env->allocator`,
    // which `_envelope_new` set from the same kwarg). All allocating
    // calls below — string materialization, base64 decode,
    // `ensure_signatures_initialized` — thread this single local.
    // Mirrors the `alloc_for_call = allocator ? allocator :
    // env->allocator` pattern used by `_serialize`, `_pae_bytes`,
    // `_add_signature`, and `_sign`.
    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    n00b_string_t *b64_in = n00b_string_from_cstr(n00b_json_as_cstr(payload_node),
                                                  .allocator = alloc_for_call);
    auto dec_r = n00b_base64_decode(b64_in,
                                    .allocator = alloc_for_call);
    if (n00b_result_is_err(dec_r)) {
        return n00b_result_err(n00b_attest_envelope_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_BASE64);
    }
    n00b_buffer_t *decoded = n00b_result_get(dec_r);

    // The decoded payload is owned by `allocator` (per the @kw on
    // _envelope_parse). Storing it as the envelope's borrowed payload
    // is correct — `decoded` lives in the same allocator scope as the
    // envelope.
    env->payload = decoded;

    // WP-003 Phase 1 (DF-006 closure): reconstruct `signatures[]`.
    // Symmetry with the write side per D-041 — reuse
    // `ensure_signatures_initialized` (the lazy-init helper used by
    // `_add_signature`) and append into the SAME parallel keyid/sig
    // lists, threading the same `alloc_for_call` local through every
    // new allocation per D-042. The parser does NOT validate
    // algorithm or keyid shape (D-016 + D-039): it preserves bytes
    // verbatim and lets the verifier (future Phase 2/3) interpret.
    //
    // Failure modes:
    //   - Field missing entirely  → empty signatures list (NOT an
    //     error; matches WP-001 round-trip where the field was
    //     absent because no signing had occurred).
    //   - Field is `[]`           → empty signatures list.
    //   - Field present but not an array, or any entry malformed
    //     (non-object, missing keyid/sig, non-string fields)
    //                             → BAD_JSON.
    //   - Per-entry sig field is not valid base64 → BAD_BASE64.
    //     Mirrors the top-level payload-base64 precedent so audit
    //     logs can distinguish structural-JSON failures (missing
    //     field, wrong type) from base64-content failures
    //     regardless of nesting depth.
    n00b_json_node_t *sigs_node = n00b_attest_json_obj_lookup(root,
                                                              r"signatures");
    if (sigs_node != nullptr) {
        if (!n00b_json_is_array(sigs_node)) {
            return n00b_result_err(n00b_attest_envelope_t *,
                                   N00B_ATTEST_ERR_DSSE_BAD_JSON);
        }
        size_t nsigs = n00b_json_array_len(sigs_node);
        if (nsigs > 0) {
            ensure_signatures_initialized(env, alloc_for_call);
            for (size_t i = 0; i < nsigs; i++) {
                n00b_json_node_t *entry = n00b_json_array_get(sigs_node, i);
                if (!n00b_json_is_object(entry)) {
                    return n00b_result_err(n00b_attest_envelope_t *,
                                           N00B_ATTEST_ERR_DSSE_BAD_JSON);
                }
                n00b_json_node_t *kid_node = n00b_attest_json_obj_lookup(
                    entry,
                    r"keyid");
                n00b_json_node_t *sig_node = n00b_attest_json_obj_lookup(
                    entry,
                    r"sig");
                if (!n00b_json_is_string(kid_node)
                    || !n00b_json_is_string(sig_node)) {
                    return n00b_result_err(n00b_attest_envelope_t *,
                                           N00B_ATTEST_ERR_DSSE_BAD_JSON);
                }

                // Materialize keyid as an allocator-owned
                // n00b_string_t; same private-copy discipline as the
                // write-side `_add_signature` path.
                n00b_string_t *kid_copy = n00b_string_from_cstr(
                    n00b_json_as_cstr(kid_node),
                    .allocator = alloc_for_call);

                // Base64-decode the wire sig field into an allocator-
                // owned buffer. Malformed base64 surfaces as
                // BAD_BASE64 (NOT BAD_JSON), mirroring the top-level
                // payload-base64 precedent above: structural-JSON
                // failures (missing field, wrong type) stay BAD_JSON,
                // base64-content failures become BAD_BASE64
                // regardless of nesting depth. Audit logs preserve
                // the structural-vs-content distinction.
                n00b_string_t *sig_b64 = n00b_string_from_cstr(
                    n00b_json_as_cstr(sig_node),
                    .allocator = alloc_for_call);
                auto sig_dec_r = n00b_base64_decode(
                    sig_b64,
                    .allocator = alloc_for_call);
                if (n00b_result_is_err(sig_dec_r)) {
                    return n00b_result_err(n00b_attest_envelope_t *,
                                           N00B_ATTEST_ERR_DSSE_BAD_BASE64);
                }
                n00b_buffer_t *sig_copy = n00b_result_get(sig_dec_r);

                n00b_list_push(env->signature_keyids, kid_copy);
                n00b_list_push(env->signature_sigs, sig_copy);
            }
        }
    }

    return n00b_result_ok(n00b_attest_envelope_t *, env);
}

// WP-003 Phase 1 — public accessors for the parsed (or built)
// `signatures[]` list. These borrow into the envelope's internal
// parallel-list storage; the doxygen in the header is the
// authoritative borrow-semantics contract. The count accessor is
// allocation-free; the two getters bounds-check and return
// `N00B_ATTEST_ERR_DSSE_BAD_INPUT` for OOB / null env. No new
// error codes added this phase (reuses the existing DSSE codes).

size_t
n00b_attest_envelope_signature_count(n00b_attest_envelope_t *env)
{
    if (env == nullptr) {
        return 0;
    }
    if (!env->signatures_initialized) {
        return 0;
    }
    return (size_t)env->signature_keyids.len;
}

n00b_result_t(n00b_string_t *)
n00b_attest_envelope_get_signature_keyid(n00b_attest_envelope_t *env,
                                         size_t                  idx)
{
    if (env == nullptr || !env->signatures_initialized) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (idx >= (size_t)env->signature_keyids.len) {
        return n00b_result_err(n00b_string_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    return n00b_result_ok(n00b_string_t *,
                          env->signature_keyids.data[idx]);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_envelope_get_signature_sig(n00b_attest_envelope_t *env,
                                       size_t                  idx)
{
    if (env == nullptr || !env->signatures_initialized) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (idx >= (size_t)env->signature_sigs.len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    return n00b_result_ok(n00b_buffer_t *,
                          env->signature_sigs.data[idx]);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_envelope_get_payload(n00b_attest_envelope_t *env)
{
    if (env == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (env->payload == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_NO_PAYLOAD);
    }
    return n00b_result_ok(n00b_buffer_t *, env->payload);
}

n00b_result_t(n00b_buffer_t *)
n00b_attest_envelope_pae_bytes(n00b_attest_envelope_t *env) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (env->payload == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ATTEST_ERR_DSSE_NO_PAYLOAD);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    // PAE = "DSSEv1" SP <len(type)> SP <type> SP <len(payload)> SP <payload>
    size_t prefix_len  = sizeof(k_dsse_pae_prefix) - 1;       // 6
    size_t type_len    = sizeof(k_dsse_payload_type) - 1;     // 28
    size_t type_lenlen = dec_ascii_len(type_len);
    size_t payload_len = env->payload->byte_len;
    size_t payload_lenlen = dec_ascii_len(payload_len);

    // 4 separator spaces between the 5 fields.
    size_t total = prefix_len + 1 + type_lenlen + 1 + type_len + 1
                 + payload_lenlen + 1 + payload_len;

    char *buf = n00b_alloc_array_with_opts(
        char,
        total,
        &(n00b_alloc_opts_t){
            .allocator = alloc_for_call,
        });
    size_t op = 0;

    memcpy(buf + op, k_dsse_pae_prefix, prefix_len);
    op += prefix_len;
    buf[op++] = ' ';
    dec_ascii_write(buf + op, type_len, type_lenlen);
    op += type_lenlen;
    buf[op++] = ' ';
    memcpy(buf + op, k_dsse_payload_type, type_len);
    op += type_len;
    buf[op++] = ' ';
    dec_ascii_write(buf + op, payload_len, payload_lenlen);
    op += payload_lenlen;
    buf[op++] = ' ';
    if (payload_len > 0) {
        memcpy(buf + op, env->payload->data, payload_len);
        op += payload_len;
    }
    (void)op;

    n00b_buffer_t *out = n00b_buffer_from_bytes(buf,
                                                (int64_t)total,
                                                .allocator = alloc_for_call);
    return n00b_result_ok(n00b_buffer_t *, out);
}

// ---------------------------------------------------------------------------
// Envelope signature population (Phase 3).
//
// `_add_signature` is the low-level entry point: appends a pre-computed
// `{keyid, sig}` pair to the envelope. Stores PRIVATE COPIES of both
// inputs — the caller may free `keyid` and `sig` immediately after the
// call. `_sign` is the high-level composition: it computes the PAE
// bytes, runs the signer over them, fetches the cached keyid from the
// signer, and dispatches the pair through `_add_signature`.
//
// Errors are surfaced through the same `N00B_ATTEST_ERR_*` namespace as
// the rest of the module. The signer's `N00B_ATTEST_ERR_SIGN_FAILED`
// propagates verbatim when sign fails.
// ---------------------------------------------------------------------------

n00b_result_t(bool)
n00b_attest_envelope_add_signature(n00b_attest_envelope_t *env,
                                   n00b_string_t          *keyid,
                                   n00b_buffer_t          *sig) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr || keyid == nullptr || sig == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (keyid->u8_bytes == 0 || sig->byte_len == 0) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    ensure_signatures_initialized(env, alloc_for_call);

    // Store private copies — the caller may free `keyid` / `sig`
    // immediately after this call (per the header's doxygen). The
    // copies are owned by the envelope's effective allocator.
    n00b_string_t *kid_copy = n00b_string_from_raw(keyid->data,
                                                   (int64_t)keyid->u8_bytes,
                                                   .allocator = alloc_for_call);
    n00b_buffer_t *sig_copy = n00b_buffer_from_bytes(sig->data,
                                                     (int64_t)sig->byte_len,
                                                     .allocator = alloc_for_call);

    n00b_list_push(env->signature_keyids, kid_copy);
    n00b_list_push(env->signature_sigs, sig_copy);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_attest_envelope_sign(n00b_attest_envelope_t *env,
                          n00b_attest_signer_t   *signer) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr || signer == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (env->payload == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_NO_PAYLOAD);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    // PAE the envelope. Failures propagate via the envelope-domain
    // error namespace (e.g., NO_PAYLOAD if the caller forgot
    // _set_payload — but we already checked above).
    auto pae_r = n00b_attest_envelope_pae_bytes(env,
                                                .allocator = alloc_for_call);
    if (n00b_result_is_err(pae_r)) {
        return n00b_result_err(bool, n00b_result_get_err(pae_r));
    }
    n00b_buffer_t *pae = n00b_result_get(pae_r);

    // Sign the PAE bytes. Failures propagate through the signer-domain
    // error namespace (typically N00B_ATTEST_ERR_SIGN_FAILED).
    auto sig_r = n00b_attest_signer_sign(signer,
                                         pae,
                                         .allocator = alloc_for_call);
    if (n00b_result_is_err(sig_r)) {
        return n00b_result_err(bool, n00b_result_get_err(sig_r));
    }
    n00b_buffer_t *sig = n00b_result_get(sig_r);

    // Fetch the cached keyid (SHA-256 of SPKI DER, hex-encoded per
    // D-039 — the file backend computes + caches at load time, so
    // this is a pointer lookup, NOT a recomputation).
    n00b_string_t *keyid = n00b_attest_signer_keyid(signer);
    if (keyid == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // Dispatch through the low-level entry so multi-signer flows
    // (FR-11, deferred) can use the same path against pre-computed
    // signatures.
    return n00b_attest_envelope_add_signature(env,
                                              keyid,
                                              sig,
                                              .allocator = alloc_for_call);
}

// ---------------------------------------------------------------------------
// Envelope signature verification (Phase 3).
//
// `_verify_signature` is the low-level entry point: re-derives PAE,
// fetches `{keyid, sig}` at `idx`, and runs the crypto check
// through `_verifier_check`. NO keyid-match (single-entry semantic
// is "verify THIS index, no policy"; keyid-match policy lives in
// `_verify` below). `_verify` is the high-level composition: it
// derives PAE ONCE at the top, fetches the verifier's keyid ONCE,
// then walks `signatures[]` running the keyid-match-then-check
// policy per D-044 Q3 (sigstore "any-signature-passes"). The two
// wrappers are the duals of `_envelope_add_signature` and
// `_envelope_sign` per D-041 (storage + idiom symmetry).
//
// **Verdict vs. machinery (D-044 OQ-1).** Both wrappers preserve
// the `Ok(true)` / `Ok(false)` / `Err(...)` three-way semantic:
// the crypto verdict rides the Ok-channel, the machinery failure
// rides the Err-channel. Phase 4's 3-code exit shape (exit 0 =
// Ok(true), exit 1 = Ok(false), exit 2 = Err) depends on this
// distinction; **do NOT collapse `Ok(false)` into `Err`** under
// any code path here.
// ---------------------------------------------------------------------------

n00b_result_t(bool)
n00b_attest_envelope_verify_signature(n00b_attest_envelope_t *env,
                                      size_t                  idx,
                                      n00b_attest_verifier_t *verifier) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr || verifier == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }
    if (idx >= n00b_attest_envelope_signature_count(env)) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    // Fetch the entry's keyid + sig via the Phase 1 getters. The
    // bounds check above + the getters' own null-env / OOB guards
    // are belt-and-suspenders here; we already know `idx` is in
    // range and `env` is non-null, so neither getter will Err in
    // practice.
    auto kid_r = n00b_attest_envelope_get_signature_keyid(env, idx);
    if (n00b_result_is_err(kid_r)) {
        return n00b_result_err(bool, n00b_result_get_err(kid_r));
    }
    auto sig_r = n00b_attest_envelope_get_signature_sig(env, idx);
    if (n00b_result_is_err(sig_r)) {
        return n00b_result_err(bool, n00b_result_get_err(sig_r));
    }
    n00b_buffer_t *sig = n00b_result_get(sig_r);

    // Re-derive PAE bytes. Single-entry verification re-derives
    // per call (the entry point is self-contained); callers
    // verifying multiple entries on the same envelope should use
    // `_envelope_verify` (which derives once and walks).
    auto pae_r = n00b_attest_envelope_pae_bytes(env,
                                                .allocator = alloc_for_call);
    if (n00b_result_is_err(pae_r)) {
        return n00b_result_err(bool, n00b_result_get_err(pae_r));
    }
    n00b_buffer_t *pae = n00b_result_get(pae_r);

    // Pass-through: the verdict (Ok(true) / Ok(false)) and any
    // machinery failure (Err) propagate verbatim from
    // `_verifier_check`. Do NOT collapse Ok(false) into Err.
    return n00b_attest_verifier_check(verifier,
                                      pae,
                                      sig,
                                      .allocator = alloc_for_call);
}

n00b_result_t(bool)
n00b_attest_envelope_verify(n00b_attest_envelope_t *env,
                            n00b_attest_verifier_t *verifier) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (env == nullptr || verifier == nullptr) {
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // Architecture §9 FAIL_NO_SIGNATURES: an envelope with no
    // signature entries is rejected with Ok(false). The verify
    // machinery did run (we inspected the count); the verdict is
    // "envelope was rejected." Routing this through Err would
    // conflate "no signatures to check" (verdict) with "machinery
    // could not check" (failure).
    size_t nsigs = n00b_attest_envelope_signature_count(env);
    if (nsigs == 0) {
        return n00b_result_ok(bool, false);
    }

    n00b_allocator_t *alloc_for_call = allocator ? allocator : env->allocator;

    // Derive PAE ONCE at the top. Per-entry re-derivation would
    // multiply allocator pressure by N for an N-signature
    // envelope; the high-level wrapper trades the low-level
    // wrapper's self-containment for a single PAE allocation.
    auto pae_r = n00b_attest_envelope_pae_bytes(env,
                                                .allocator = alloc_for_call);
    if (n00b_result_is_err(pae_r)) {
        return n00b_result_err(bool, n00b_result_get_err(pae_r));
    }
    n00b_buffer_t *pae = n00b_result_get(pae_r);

    // Fetch the verifier's keyid ONCE. Same rationale as PAE: the
    // verifier's keyid is a pointer-stable cached value (D-039);
    // re-fetching per entry is harmless but unnecessary.
    n00b_string_t *verifier_kid = n00b_attest_verifier_keyid(verifier);
    if (verifier_kid == nullptr) {
        // Should not happen for a verifier returned by
        // `_verifier_resolve`, but defensive: route through Err
        // (machinery failure, not verdict).
        return n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT);
    }

    // Walk: keyid-match-then-check policy per D-044 Q3. Non-
    // matching entries skip silently; matching entries dispatch
    // to `_verifier_check`. Short-circuit on first Ok(true);
    // propagate Err immediately; continue on Ok(false).
    //
    // Plan deviation note (per Phase 3 prompt rationale): the
    // high-level wrapper calls `_verifier_check` directly with
    // the pre-derived `pae` buffer rather than dispatching
    // through `_envelope_verify_signature`. The low-level wrapper
    // re-derives PAE per call (self-contained); calling it from
    // the walk would re-derive PAE N times, defeating the
    // once-at-top optimization. The low-level wrapper remains
    // for callers who want single-entry verification without
    // owning a pre-derived PAE buffer.
    for (size_t i = 0; i < nsigs; i++) {
        auto kid_r = n00b_attest_envelope_get_signature_keyid(env, i);
        if (n00b_result_is_err(kid_r)) {
            return n00b_result_err(bool, n00b_result_get_err(kid_r));
        }
        n00b_string_t *entry_kid = n00b_result_get(kid_r);

        // D-039 keyid equality. Both keyids are produced by the
        // same `lowercase-hex(SHA-256(SPKI DER))` derivation, so
        // they are pure 64-char ASCII hex strings. `n00b_unicode_str_eq`
        // with its `.normalize = false` + `.case_sensitive = true`
        // defaults is bit-equivalent to `memcmp` on ASCII inputs
        // — the Unicode-aware comparison layer is a no-op here
        // because the keyids contain no characters that would
        // canonicalize differently.
        if (!n00b_unicode_str_eq(verifier_kid, entry_kid)) {
            continue;  // skip silently per Known Deferral 1
        }

        auto sig_r = n00b_attest_envelope_get_signature_sig(env, i);
        if (n00b_result_is_err(sig_r)) {
            return n00b_result_err(bool, n00b_result_get_err(sig_r));
        }
        n00b_buffer_t *entry_sig = n00b_result_get(sig_r);

        auto check_r = n00b_attest_verifier_check(verifier,
                                                  pae,
                                                  entry_sig,
                                                  .allocator = alloc_for_call);
        if (n00b_result_is_err(check_r)) {
            // Machinery failure aborts the walk. Phase 4's exit
            // shape will surface this as exit-code-2 (the
            // verdict cases — Ok(true) and Ok(false) — surface
            // as 0 and 1).
            return n00b_result_err(bool, n00b_result_get_err(check_r));
        }
        if (n00b_result_get(check_r)) {
            // First matching-keyid entry that verifies wins;
            // sigstore "any-passes" semantics complete on the
            // first success.
            return n00b_result_ok(bool, true);
        }
        // Ok(false) — this entry did not verify; continue to the
        // next entry (a different matching-keyid sig might).
    }

    // Walk completed with no matching-keyid entry verifying.
    return n00b_result_ok(bool, false);
}
