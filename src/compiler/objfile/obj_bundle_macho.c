/**
 * @file obj_bundle_macho.c
 * @brief Internal Mach-O object-bundle carrier backend implementation.
 *
 * Implements the WP-008 METADATA slice of the Mach-O carrier backend (detect,
 * reserved-namespace/guard check, raw-metadata read, and the METADATA path of
 * write_carrier). The carrier lives in an `LC_NOTE` whose `data_owner` is the
 * reserved bundle token `N00B_MACHO_BUNDLE_NOTE_OWNER` (D-010/D-030); the kind
 * is discriminated by the descriptor magic at the note payload (D-023). The
 * write path reuses the WP-005/006 surgical `LC_NOTE` rewrite — no hand-rolled
 * load-command editing. LOADABLE/SPLIT read and write are stubbed to
 * `Err(N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER)` until WP-009/WP-010.
 *
 * Mirrors the ELF carrier internals in `obj_bundle.c`, keyed on `data_owner`
 * rather than a section name.
 */
#include "internal/compiler/objfile/obj_bundle_arith.h"
#include "internal/compiler/objfile/obj_bundle_macho.h"

#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "compiler/objfile/writer.h"
#include "core/crc32.h"
#include "text/strings/string_ops.h"

// On-disk LC_NOTE command layout (40 bytes): cmd(4) cmdsize(4) data_owner[16]
// offset(8) size(8). Mirrors macho_rewrite_admit.c:N00B_MACHO_LC_NOTE_CMD_SIZE
// and the chalk LC_NOTE reader (src/chalk/macho_core.c:535-538).
#define MACHO_NOTE_CMD_SIZE    40u
#define MACHO_NOTE_OWNER_OFF   8u
#define MACHO_NOTE_OWNER_LEN   16u
#define MACHO_NOTE_OFFSET_OFF  24u
#define MACHO_NOTE_SIZE_OFF    32u

// ============================================================================
// LC_NOTE owner discrimination + parsed-note facts
// ============================================================================

// Read a little-endian u64 from raw bytes (header-only libc byte work for raw
// on-disk decoding is permitted; D-007 § 2.10).
static uint64_t
note_read_u64(const uint8_t *p)
{
    uint64_t v = 0;

    for (uint32_t i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }

    return v;
}

// True when this command is an LC_NOTE owned by the reserved bundle token
// (data_owner == N00B_MACHO_BUNDLE_NOTE_OWNER, NUL-padded to 16 bytes).
static bool
note_is_bundle_owned(n00b_macho_command_t *cmd, n00b_allocator_t *allocator)
{
    if (cmd->cmd != LC_NOTE) {
        return false;
    }

    if (cmd->raw_data == nullptr
        || (uint64_t)cmd->raw_data->byte_len < MACHO_NOTE_CMD_SIZE) {
        return false;
    }

    const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;

    // The 16-byte field is NUL-padded; trim at the first NUL so the comparison
    // matches the variable-length token.
    int64_t actual = 0;

    while (actual < (int64_t)MACHO_NOTE_OWNER_LEN
           && raw[MACHO_NOTE_OWNER_OFF + actual] != 0) {
        actual++;
    }

    n00b_string_t *owner = n00b_string_from_raw(
        (char *)(raw + MACHO_NOTE_OWNER_OFF),
        actual,
        .allocator = allocator);

    return n00b_unicode_str_eq(owner,
                               n00b_string_from_cstr(
                                   N00B_MACHO_BUNDLE_NOTE_OWNER,
                                   .allocator = allocator));
}

// Slice the carrier note's payload region out of the stream buffer into a fresh
// buffer. Errs with N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER if the note's
// size is zero or its offset/size run past the stream buffer (a malformed
// note). The note's stored offset is absolute into the stream buffer (matches
// the chalk LC_NOTE reader convention).
static n00b_result_t(n00b_buffer_t *)
note_payload_copy(n00b_macho_binary_t *bin,
                  n00b_macho_command_t *cmd,
                  n00b_allocator_t     *allocator)
{
    const uint8_t *raw          = (const uint8_t *)cmd->raw_data->data;
    uint64_t       payload_off  = note_read_u64(raw + MACHO_NOTE_OFFSET_OFF);
    uint64_t       payload_size = note_read_u64(raw + MACHO_NOTE_SIZE_OFF);
    uint64_t       buf_len      = (uint64_t)bin->stream->buf->byte_len;

    if (payload_size == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    if (UINT64_MAX - payload_off < payload_size
        || payload_off + payload_size > buf_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_buffer_t *buf = n00b_buffer_from_bytes(
        (char *)bin->stream->buf->data + payload_off,
        (int64_t)payload_size,
        .allocator = allocator);

    return n00b_result_ok(n00b_buffer_t *, buf);
}

// ============================================================================
// #1 — detect_carrier
// ============================================================================

n00b_result_t(n00b_obj_bundle_macho_carrier_state_t)
_n00b_obj_bundle_macho_detect_carrier(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
    }
    ensures {}
{
    n00b_macho_command_t *carrier = nullptr;
    uint64_t              count   = 0;

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (note_is_bundle_owned(&bin->commands[i], allocator)) {
            count++;

            if (carrier == nullptr) {
                carrier = &bin->commands[i];
            }
        }
    }

    if (count == 0) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE);
    }

    if (count > 1) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_DUPLICATE);
    }

    // Single owned carrier: classify the kind by the descriptor magic at the
    // note payload's offset 0 (D-023). Magic absent ⇒ METADATA_RAW; present ⇒
    // DESCRIPTOR_LOADABLE/_SPLIT by carrier_kind; short/garbled ⇒ MALFORMED.
    auto payload_res = note_payload_copy(bin, carrier, allocator);

    if (n00b_result_is_err(payload_res)) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED);
    }

    n00b_buffer_t *payload = n00b_result_get(payload_res);

    if ((uint64_t)payload->byte_len < N00B_MACHO_CARRIER_MAGIC_LEN) {
        // Too short to carry a descriptor magic; raw canonical bytes.
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW);
    }

    const uint8_t *pbytes      = (const uint8_t *)payload->data;
    bool           magic_match = true;

    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_MAGIC_LEN; i++) {
        if (pbytes[i] != N00B_MACHO_CARRIER_MAGIC[i]) {
            magic_match = false;
            break;
        }
    }

    if (!magic_match) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW);
    }

    auto decoded = n00b_macho_carrier_descriptor_decode(payload,
                                                        .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED);
    }

    n00b_macho_carrier_descriptor_t *desc = n00b_result_get(decoded);

    if (desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT) {
        return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                              N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_SPLIT);
    }

    return n00b_result_ok(n00b_obj_bundle_macho_carrier_state_t,
                          N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_LOADABLE);
}

// ============================================================================
// #2 — check_reserved
// ============================================================================

n00b_result_t(n00b_obj_bundle_error_code_t)
_n00b_obj_bundle_macho_check_reserved(
    n00b_macho_binary_t              *bin,
    n00b_obj_bundle_replace_policy_t  replace) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
    }
    ensures {}
{
    auto detected = _n00b_obj_bundle_macho_detect_carrier(bin,
                                                          .allocator = allocator);

    if (n00b_result_is_err(detected)) {
        return n00b_result_err(n00b_obj_bundle_error_code_t,
                               n00b_result_get_err(detected));
    }

    n00b_obj_bundle_macho_carrier_state_t state = n00b_result_get(detected);

    switch (state) {
    case N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE:
        return n00b_result_ok(n00b_obj_bundle_error_code_t,
                              N00B_OBJ_BUNDLE_ERR_OK);

    case N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW:
        // A present N00b-owned carrier may be replaced only with an explicit
        // replace policy; otherwise the reserved namespace is occupied.
        if (replace == N00B_OBJ_BUNDLE_REPLACE_EXISTING) {
            return n00b_result_ok(n00b_obj_bundle_error_code_t,
                                  N00B_OBJ_BUNDLE_ERR_OK);
        }

        return n00b_result_ok(n00b_obj_bundle_error_code_t,
                              N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED);

    case N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_LOADABLE:
    case N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_SPLIT:
        // Replacing a descriptor-backed carrier is not yet supported (WP-009/
        // WP-010); reject before any write regardless of replace policy.
        return n00b_result_ok(n00b_obj_bundle_error_code_t,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);

    case N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED:
    case N00B_OBJ_BUNDLE_MACHO_CARRIER_DUPLICATE:
        // Malformed/duplicate owned carriers reject regardless of replace.
        return n00b_result_ok(n00b_obj_bundle_error_code_t,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    return n00b_result_ok(n00b_obj_bundle_error_code_t,
                          N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
}

// ============================================================================
// #3 — read_metadata
// ============================================================================

n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_metadata(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
        bin->stream != nullptr;
        bin->stream->buf != nullptr;
    }
    ensures {
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len != 0);
    }
{
    n00b_macho_command_t *carrier = nullptr;
    uint64_t              count   = 0;

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (note_is_bundle_owned(&bin->commands[i], allocator)) {
            count++;

            if (carrier == nullptr) {
                carrier = &bin->commands[i];
            }
        }
    }

    if (count == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND);
    }

    if (count > 1) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER);
    }

    auto payload_res = note_payload_copy(bin, carrier, allocator);

    if (n00b_result_is_err(payload_res)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(payload_res));
    }

    n00b_buffer_t *payload = n00b_result_get(payload_res);

    if (payload == nullptr || payload->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    return n00b_result_ok(n00b_buffer_t *, payload);
}

// ============================================================================
// #4 — read_loadable (WP-009)
// ============================================================================

// Locate the single bundle-owned carrier LC_NOTE command. Mirrors the
// count/duplicate handling of read_metadata; maps the location outcome to the
// obj_bundle error surface in `*err`. Returns the command, or nullptr (with a
// set error) when none/duplicate.
static n00b_macho_command_t *
locate_single_carrier(n00b_macho_binary_t       *bin,
                      n00b_allocator_t          *allocator,
                      n00b_obj_bundle_error_code_t *err)
{
    n00b_macho_command_t *carrier = nullptr;
    uint64_t              count   = 0;

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (note_is_bundle_owned(&bin->commands[i], allocator)) {
            count++;

            if (carrier == nullptr) {
                carrier = &bin->commands[i];
            }
        }
    }

    if (count == 0) {
        *err = N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND;
        return nullptr;
    }

    if (count > 1) {
        *err = N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER;
        return nullptr;
    }

    *err = N00B_OBJ_BUNDLE_ERR_OK;
    return carrier;
}

// Compute the file extent (offset, end) of the LC_SEGMENT_64 that carries the
// loadable payload range, bounding `payload_off + payload_len` against the named
// segment when found, else against the whole stream buffer. Returns false when
// the range overflows or runs past the bounding extent.
static bool
loadable_payload_in_bounds(n00b_macho_binary_t *bin,
                           uint64_t             payload_off,
                           uint64_t             payload_len)
{
    uint64_t payload_end = 0;

    // Overflow + signed-slice guards (mirror obj_bundle.c:7464-7479).
    if (UINT64_MAX - payload_off < payload_len) {
        return false;
    }

    payload_end = payload_off + payload_len;

    if (payload_off > (uint64_t)INT64_MAX || payload_end > (uint64_t)INT64_MAX) {
        return false;
    }

    // Prefer the carrying segment's file extent: find a segment whose
    // [fileoff, fileoff+filesize) contains the payload range.
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg     = &bin->segments[i];
        uint64_t              seg_off  = seg->fileoff;
        uint64_t              seg_end  = 0;

        if (UINT64_MAX - seg_off < seg->filesize) {
            continue;
        }

        seg_end = seg_off + seg->filesize;

        if (payload_off >= seg_off && payload_end <= seg_end) {
            return true;
        }
    }

    // No bounding segment located: fall back to the stream buffer extent.
    return payload_end <= (uint64_t)bin->stream->buf->byte_len;
}

n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_loadable(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
        bin->stream != nullptr;
        bin->stream->buf != nullptr;
    }
    ensures {
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len != 0);
    }
{
    n00b_obj_bundle_error_code_t  loc_err = N00B_OBJ_BUNDLE_ERR_OK;
    n00b_macho_command_t         *carrier =
        locate_single_carrier(bin, allocator, &loc_err);

    if (carrier == nullptr) {
        return n00b_result_err(n00b_buffer_t *, loc_err);
    }

    // The carrier note payload IS the descriptor bytes (the LOADABLE carrier
    // stores the descriptor in the LC_NOTE; the canonical bytes live in the new
    // LC_SEGMENT_64 the descriptor points at).
    auto desc_bytes_res = note_payload_copy(bin, carrier, allocator);

    if (n00b_result_is_err(desc_bytes_res)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(desc_bytes_res));
    }

    n00b_buffer_t *desc_bytes = n00b_result_get(desc_bytes_res);

    auto decoded = n00b_macho_carrier_descriptor_decode(desc_bytes,
                                                        .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_macho_carrier_descriptor_t *desc = n00b_result_get(decoded);

    if (desc->kind != N00B_MACHO_CARRIER_KIND_LOADABLE) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Bounds-check the payload range vs the carrying segment file extent
    // (mirror obj_bundle.c:7464-7479) -> OUT_OF_BOUNDS on failure.
    if (!loadable_payload_in_bounds(bin,
                                    desc->payload_file_offset,
                                    desc->payload_len)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS);
    }

    n00b_buffer_t *payload = n00b_buffer_get_slice(
        bin->stream->buf,
        (int64_t)desc->payload_file_offset,
        (int64_t)(desc->payload_file_offset + desc->payload_len),
        .allocator = allocator);

    // The payload slice must be present and non-empty before we can verify its
    // digest (verify_digest's `requires` lists payload != nullptr).
    if (payload == nullptr || payload->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Verify the SHA-256 digest -> DIGEST_MISMATCH on mismatch.
    auto verified = n00b_macho_carrier_verify_digest(desc, payload);

    if (n00b_result_is_err(verified)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    if (!n00b_result_get(verified)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH);
    }

    return n00b_result_ok(n00b_buffer_t *, payload);
}

// ============================================================================
// #5 — read_split (WP-010 Phase 2)
// ============================================================================

// Checked-arithmetic helpers for the SPLIT reconstruct path
// (`_n00b_obj_bundle_{u64_add,range_end,range_within,ranges_overlap}`) are shared
// with the ELF/neutral core via internal/compiler/objfile/obj_bundle_arith.h
// (included above) — no longer duplicated here.

n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_split(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
        bin->stream != nullptr;
        bin->stream->buf != nullptr;
    }
    ensures {
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len != 0);
    }
{
    // Release-path guard mirroring the `requires` (D-031): the stream/buf are
    // genuine internal preconditions, but never trap on a malformed input.
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_NULL_INPUT);
    }

    // Locate the single bundle-owned carrier LC_NOTE (count/duplicate handling
    // matches read_loadable).
    n00b_obj_bundle_error_code_t  loc_err = N00B_OBJ_BUNDLE_ERR_OK;
    n00b_macho_command_t         *carrier =
        locate_single_carrier(bin, allocator, &loc_err);

    if (carrier == nullptr) {
        return n00b_result_err(n00b_buffer_t *, loc_err);
    }

    // The carrier note payload IS the descriptor bytes; the slices live in the
    // separate LC_SEGMENT_64 the descriptor points at.
    auto desc_bytes_res = note_payload_copy(bin, carrier, allocator);

    if (n00b_result_is_err(desc_bytes_res)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(desc_bytes_res));
    }

    n00b_buffer_t *desc_bytes = n00b_result_get(desc_bytes_res);

    // Decode the descriptor + D-040 trailer (skeleton blob + slice records). The
    // codec validates note_size == 64 + 16 + skeleton_len + record_count*48 and
    // the trailer-region arithmetic, returning N00B_MACHO_CARRIER_ERR_* on a
    // malformed trailer (RECORD_COUNT / BOUNDS).
    auto decoded = n00b_macho_carrier_descriptor_decode(desc_bytes,
                                                        .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(decoded));
    }

    n00b_macho_carrier_descriptor_t *desc = n00b_result_get(decoded);

    if (desc->kind != N00B_MACHO_CARRIER_KIND_SPLIT) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BAD_KIND);
    }

    // A SPLIT carrier must carry the excised skeleton + at least one slice
    // record (D-040). decode already guarantees skeleton != nullptr for SPLIT.
    if (desc->record_count == 0 || desc->records == nullptr
        || desc->skeleton == nullptr
        || (uint64_t)desc->skeleton->byte_len != desc->skeleton_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
    }

    // Bound the slices-only segment payload range against the carrying segment
    // file extent (mirror read_loadable). The payload must be non-empty so we
    // can both digest-check it and slice from it.
    if (!loadable_payload_in_bounds(bin,
                                    desc->payload_file_offset,
                                    desc->payload_len)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    n00b_buffer_t *segment_payload = n00b_buffer_get_slice(
        bin->stream->buf,
        (int64_t)desc->payload_file_offset,
        (int64_t)(desc->payload_file_offset + desc->payload_len),
        .allocator = allocator);

    if (segment_payload == nullptr
        || (uint64_t)segment_payload->byte_len != desc->payload_len
        || segment_payload->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    // Authoritative-ish gate #1: the segment-payload SHA-256 must match the
    // descriptor digest (verify_digest requires payload_len == byte_len, met
    // above). The bundle-level SHA-256 (Hook A's n00b_obj_bundle_decode over the
    // reconstructed bytes) is the final authority; this rejects a tampered
    // slices-only segment early.
    auto verified = n00b_macho_carrier_verify_digest(desc, segment_payload);

    if (n00b_result_is_err(verified)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(verified));
    }

    if (!n00b_result_get(verified)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_DIGEST);
    }

    // Validate every slice record and accumulate Σ slice_len. Record-driven:
    // slices may be stored out-of-canonical-order in the segment, but
    // reconstruct_offset must be monotonic and non-overlapping in canonical.
    uint64_t previous_canonical_end = 0;
    uint64_t total_slice_len        = 0;

    for (uint64_t i = 0; i < desc->record_count; i++) {
        n00b_macho_carrier_split_record_t *record = &desc->records[i];
        uint64_t canonical_end = 0;

        if (record->slice_len == 0
            || !_n00b_obj_bundle_range_within(record->slice_payload_offset,
                                         record->slice_len,
                                         desc->payload_len)
            || !_n00b_obj_bundle_range_end(record->reconstruct_offset,
                                      record->slice_len,
                                      &canonical_end)
            || (i != 0
                && record->reconstruct_offset < previous_canonical_end)
            || !_n00b_obj_bundle_u64_add(total_slice_len,
                                    record->slice_len,
                                    &total_slice_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        // Non-overlap of the slice ranges within the segment payload (slices may
        // be physically reordered there).
        for (uint64_t j = 0; j < i; j++) {
            if (_n00b_obj_bundle_ranges_overlap(record->slice_payload_offset,
                                           record->slice_len,
                                           desc->records[j].slice_payload_offset,
                                           desc->records[j].slice_len)) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_CARRIER_ERR_BOUNDS);
            }
        }

        // Per-slice CRC-32 fast pre-check (D-039) vs slice_digest_crc.
        uint32_t crc = n00b_crc32(
            (const uint8_t *)segment_payload->data
                + record->slice_payload_offset,
            (size_t)record->slice_len);

        if (crc != record->slice_digest_crc) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_DIGEST);
        }

        previous_canonical_end = canonical_end;
    }

    // reconstructed_len = skeleton_len + Σ slice_len (the canonical partition).
    uint64_t reconstructed_len = 0;

    if (!_n00b_obj_bundle_u64_add(desc->skeleton_len,
                             total_slice_len,
                             &reconstructed_len)
        || reconstructed_len == 0
        || reconstructed_len > SIZE_MAX) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    // Reconstruct by interleaving skeleton gaps + segment slices in
    // reconstruct_offset order (mirror the ELF writer loop, obj_bundle.c:7652).
    n00b_writer_t *writer           = n00b_writer_new((size_t)reconstructed_len,
                                              .allocator = allocator);
    uint64_t       canonical_cursor = 0;
    uint64_t       skeleton_cursor  = 0;

    for (uint64_t i = 0; i < desc->record_count; i++) {
        n00b_macho_carrier_split_record_t *record = &desc->records[i];
        uint64_t canonical_end = 0;

        if (!_n00b_obj_bundle_range_end(record->reconstruct_offset,
                                   record->slice_len,
                                   &canonical_end)
            || record->reconstruct_offset < canonical_cursor) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        uint64_t gap_len = record->reconstruct_offset - canonical_cursor;

        // The gap must come from the remaining skeleton bytes.
        if (!_n00b_obj_bundle_range_within(skeleton_cursor,
                                      gap_len,
                                      desc->skeleton_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        n00b_writer_write_bytes(writer,
                                desc->skeleton->data + skeleton_cursor,
                                (size_t)gap_len);
        n00b_writer_write_bytes(writer,
                                segment_payload->data
                                    + record->slice_payload_offset,
                                (size_t)record->slice_len);

        skeleton_cursor += gap_len;
        canonical_cursor = canonical_end;
    }

    // Flush the trailing skeleton (everything after the last slice). The leftover
    // skeleton bytes must exactly close out skeleton_len and canonical length.
    if (canonical_cursor > reconstructed_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    uint64_t trailing_len   = reconstructed_len - canonical_cursor;
    uint64_t skeleton_final = 0;

    if (!_n00b_obj_bundle_range_within(skeleton_cursor,
                                  trailing_len,
                                  desc->skeleton_len)
        || !_n00b_obj_bundle_u64_add(skeleton_cursor,
                                trailing_len,
                                &skeleton_final)
        || skeleton_final != desc->skeleton_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    n00b_writer_write_bytes(writer,
                            desc->skeleton->data + skeleton_cursor,
                            (size_t)trailing_len);
    n00b_writer_setpos(writer, (size_t)reconstructed_len);

    if (n00b_writer_has_error(writer)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    n00b_buffer_t *reconstructed = n00b_writer_finalize(writer);

    if (reconstructed == nullptr || reconstructed->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    // The writer's backing buffer is allocated from the caller's allocator
    // (threaded into n00b_writer_new above), so the finalized buffer is already
    // allocator-owned — no re-home copy needed (zero-copy; cf. DF-007-01).
    //
    // The authoritative integrity gate is Hook A's bundle-level SHA-256 over
    // these reconstructed bytes (n00b_obj_bundle_decode); this function returns
    // the raw canonical bytes, matching the LOADABLE reader's contract.
    return n00b_result_ok(n00b_buffer_t *, reconstructed);
}

// ============================================================================
// LOADABLE write arm (WP-009)
// ============================================================================

// Mach-O VM protection bits (mach/vm_prot.h): VM_PROT_READ 0x1, _EXECUTE 0x4.
// The no-host-entry LOADABLE carrier is read-only; the host-entry case maps the
// segment read+execute (MACHO_LOADABLE_INITPROT_RX) so the loader can run the
// redirected LC_MAIN target inside the inserted segment (WP-009 Phase 2).
#define MACHO_LOADABLE_INITPROT_R   0x1u
#define MACHO_LOADABLE_INITPROT_RX  0x5u

// Page-granular alignment for the inserted loadable segment (arm64 16 KiB page).
#define MACHO_LOADABLE_PAGE 0x4000u

// ============================================================================
// #4b — enable_host_entrypoint (WP-009 Phase 2)
// ============================================================================

// The Mach-O analog of `_n00b_obj_bundle_enable_host_entrypoint`
// (obj_bundle.c:8704): drive the WP-006 arm64 LC_MAIN redirect planner against
// an accepted loadable plan and fold the redirect into that plan before apply.
// Maps the WP-006 host-entrypoint rejection reasons (macho_rewrite.h:245-253) to
// the obj_bundle error surface, never UB (D-031). The redirect target is a range
// `[target_payload_offset, target_payload_offset + target_size)` within the
// planned loadable segment payload (i.e. within the canonical bundle bytes).
static n00b_result_t(bool)
_n00b_obj_bundle_macho_enable_host_entrypoint(
    n00b_macho_binary_t                *bin,
    n00b_macho_rewrite_loadable_plan_t *plan,
    uint64_t                            target_payload_offset,
    uint64_t                            target_size)
    requires {
        bin != nullptr;
        plan != nullptr;
        target_size != 0;
    }
    ensures {}
{
    auto target_result =
        n00b_macho_rewrite_plan_host_entrypoint_target(
            bin,
            plan,
            target_payload_offset,
            target_size);

    if (n00b_result_is_err(target_result)) {
        return n00b_result_err(bool, N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_rewrite_host_entrypoint_target_t target =
        n00b_result_get(target_result);

    if (target.outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        // Map the WP-006 host-entrypoint rejection reasons to obj_bundle errors,
        // mirroring the ELF enable helper's rejected-error path
        // (obj_bundle.c:8340/8742), which routes every host-entrypoint rejection
        // to UNSUPPORTED_EXEC_MODE. The TARGET_OUT_OF_RANGE/OVERFLOW reasons are
        // a bounds condition and map to OUT_OF_BOUNDS for a precise diagnosis.
        // The default arm keeps this total — no UB on an unforeseen reason
        // (D-031).
        n00b_obj_bundle_error_code_t code;

        switch (target.rejection_reason) {
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW:
            code = N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS;
            break;
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CPUTYPE:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_FILETYPE:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN:
        case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE:
        default:
            code = N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE;
            break;
        }

        return n00b_result_err(bool, code);
    }

    auto enabled = n00b_macho_rewrite_loadable_plan_enable_entrypoint(
        plan,
        target.replacement_entryoff);

    if (n00b_result_is_err(enabled) || n00b_result_get(enabled) != true) {
        return n00b_result_err(bool, N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    return n00b_result_ok(bool, true);
}

// Compose the LOADABLE carrier: place the canonical bundle bytes in a new
// read-only LC_SEGMENT_64 (WP-006 loadable insert), then record a LOADABLE
// descriptor in the carrier LC_NOTE pointing at the segment's planned file
// offset (WP-005/006 metadata insert). Mirrors the ELF arm at
// obj_bundle.c:9235 (apply loadable, build descriptor from the planned segment
// offset, write the descriptor note into the loadable output). No resign
// (WP-011); host-entrypoint redirect is Phase 2.
static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_loadable_carrier(
    n00b_macho_binary_t             *bin,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_replace_policy_t replace,
    n00b_option_t(uint64_t)          host_entry_payload_offset,
    uint64_t                         host_entry_size,
    n00b_allocator_t                *allocator)
{
    // When a host entrypoint is requested (offset present + non-zero size, per
    // the public writer's `requires`) the loadable segment is mapped read+exec
    // and the arm64 LC_MAIN is redirected into it (WP-009 Phase 2). Otherwise
    // the carrier segment stays read-only (Phase-1 behavior).
    bool host_entry_requested = host_entry_payload_offset.has_value
                                && host_entry_size != 0;

    // Reject an existing N00b-owned carrier unless replacement is permitted
    // (mirror the METADATA arm's reserved-namespace guard).
    auto detected = _n00b_obj_bundle_macho_detect_carrier(bin,
                                                          .allocator = allocator);

    if (n00b_result_is_err(detected)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    if (n00b_result_get(detected) != N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE
        && replace != N00B_OBJ_BUNDLE_REPLACE_EXISTING) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED);
    }

    // (1) Plan the loadable LC_SEGMENT_64 carrying the canonical bytes. The
    // host-entry case maps the segment read+execute so the loader can run the
    // redirected LC_MAIN target inside it; otherwise the segment is read-only.
    uint32_t loadable_initprot = host_entry_requested
                                     ? MACHO_LOADABLE_INITPROT_RX
                                     : MACHO_LOADABLE_INITPROT_R;

    // vmsize must cover the (page-aligned) on-disk filesize the apply emits
    // (the payload is padded up to MACHO_LOADABLE_PAGE), or the loader rejects
    // the segment ("filesize exceeds vmsize"). Page-round the payload length.
    uint64_t payload_len    = (uint64_t)canonical_bundle->byte_len;
    uint64_t segment_vmsize =
        (payload_len + (MACHO_LOADABLE_PAGE - 1)) & ~((uint64_t)MACHO_LOADABLE_PAGE - 1);

    n00b_macho_rewrite_loadable_request_t request =
        (n00b_macho_rewrite_loadable_request_t){
            .payload         = canonical_bundle,
            .initprot        = loadable_initprot,
            .maxprot         = MACHO_LOADABLE_INITPROT_RX,
            .file_alignment  = MACHO_LOADABLE_PAGE,
            .vaddr_alignment = MACHO_LOADABLE_PAGE,
            .vmsize          = segment_vmsize,
            .policy          = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    auto plan_result = n00b_macho_rewrite_plan_loadable_insert(
        bin,
        &request,
        .allocator = allocator);

    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(plan_result);

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    // (1b) Host-entrypoint: fold the arm64 LC_MAIN redirect into the accepted
    // loadable plan BEFORE apply. The redirect target is the requested range
    // within the segment payload (i.e. within the canonical bundle bytes); the
    // enable helper drives the WP-006 planner and maps any rejection to the
    // obj_bundle error surface. Mirrors the ELF arm (obj_bundle.c:9339-9389):
    // enable on the plan, then a single apply writes the redirected entryoff.
    if (host_entry_requested) {
        auto enabled = _n00b_obj_bundle_macho_enable_host_entrypoint(
            bin,
            plan,
            n00b_option_get(host_entry_payload_offset),
            host_entry_size);

        if (n00b_result_is_err(enabled)) {
            return n00b_result_err(n00b_buffer_t *,
                                   n00b_result_get_err(enabled));
        }
    }

    // (2) Apply the loadable insert. The planned segment file offset is final
    // (the new segment is placed last before __LINKEDIT).
    uint64_t segment_file_offset = plan->new_segment_file_offset;

    auto loadable_applied = n00b_macho_rewrite_apply_loadable_insert_plan(
        bin,
        plan,
        .allocator = allocator);

    if (n00b_result_is_err(loadable_applied)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_buffer_t *with_segment = n00b_result_get(loadable_applied);

    // (3) Build + encode the LOADABLE descriptor pointing at the new segment.
    n00b_macho_carrier_descriptor_t desc = {
        .kind                = N00B_MACHO_CARRIER_KIND_LOADABLE,
        .version_major       = N00B_MACHO_CARRIER_MAJOR,
        .version_minor       = N00B_MACHO_CARRIER_MINOR,
        .payload_file_offset = segment_file_offset,
        .payload_len         = (uint64_t)canonical_bundle->byte_len,
        .records             = nullptr,
        .record_count        = 0,
    };

    n00b_macho_carrier_compute_digest(canonical_bundle, desc.payload_digest);

    auto encoded = n00b_macho_carrier_descriptor_encode(&desc,
                                                        .allocator = allocator);

    if (n00b_result_is_err(encoded)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_buffer_t *descriptor_payload = n00b_result_get(encoded);

    // (4) Re-parse the segment-bearing output and insert the descriptor carrier
    // LC_NOTE via the WP-005/006 metadata insert. The metadata insert appends
    // its payload to the file tail and does not move the loadable segment, so
    // the descriptor's stored segment offset remains valid.
    n00b_bstream_t *stream = n00b_bstream_new(with_segment, .allocator = allocator);
    auto            reparsed = n00b_macho_parse_single(stream);

    if (n00b_result_is_err(reparsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_binary_t *with_segment_bin = n00b_result_get(reparsed);

    n00b_macho_rewrite_metadata_request_t note_request =
        (n00b_macho_rewrite_metadata_request_t){
            .note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER,
                                                .allocator = allocator),
            .note_name  = r"object-bundle",
            .payload    = descriptor_payload,
            .file_alignment        = 0,
            .preferred_file_offset = n00b_option_none(uint64_t),
            .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    auto note_applied = n00b_macho_rewrite_apply_object_bundle_insert(
        with_segment_bin,
        &note_request,
        .allocator = allocator);

    if (n00b_result_is_err(note_applied)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(note_applied));
}

// ============================================================================
// SPLIT write arm (WP-010 — D-040 true excised split)
// ============================================================================

// Compose the SPLIT carrier (D-040, literal ELF mirror). The artifact-aware
// planner `_n00b_obj_bundle_macho_plan_split` excises the executable-compatible
// artifact slices from the canonical bundle: the concatenated slices ONLY become
// the new LC_SEGMENT_64 payload, and the excised skeleton (canonical − slices) is
// carried in the carrier LC_NOTE descriptor trailer. There is NO skeleton record
// and the segment does NOT hold the whole bundle. The descriptor
// `payload_*`/`payload_digest` describe the slices-only segment payload.
//
// Requires the decoded `bundle` (to enumerate artifacts + excise slices) and ≥1
// executable slice; a bundle with no executable-compatible artifact is a
// documented Err(UNSUPPORTED_CARRIER) (mirrors the ELF "no movable payloads"
// path). Mirrors the LOADABLE arm's segment-insert + descriptor-note write; the
// differences are the slices-only segment payload and the SPLIT descriptor
// (kind + skeleton + records). No resign (WP-011).
static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_split_carrier(
    n00b_macho_binary_t             *bin,
    n00b_obj_bundle_t               *bundle,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_replace_policy_t replace,
    n00b_option_t(uint64_t)          host_entry_payload_offset,
    uint64_t                         host_entry_size,
    n00b_allocator_t                *allocator)
{
    bool host_entry_requested = host_entry_payload_offset.has_value
                                && host_entry_size != 0;

    // Reject an existing N00b-owned carrier unless replacement is permitted
    // (mirror the LOADABLE/METADATA reserved-namespace guard).
    auto detected = _n00b_obj_bundle_macho_detect_carrier(bin,
                                                          .allocator = allocator);

    if (n00b_result_is_err(detected)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    if (n00b_result_get(detected) != N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE
        && replace != N00B_OBJ_BUNDLE_REPLACE_EXISTING) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED);
    }

    // (0) Plan the split: excise the executable slices into the slices-only
    // segment payload + build the descriptor (excised skeleton + slice records).
    // A bundle with no executable-compatible artifact maps to UNSUPPORTED_CARRIER.
    n00b_buffer_t *segment_payload = nullptr;

    auto planned = _n00b_obj_bundle_macho_plan_split(
        bundle,
        canonical_bundle,
        .segment_payload_out = &segment_payload,
        .allocator           = allocator);

    if (n00b_result_is_err(planned)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }

    n00b_macho_carrier_descriptor_t *desc = n00b_result_get(planned);

    // (1) Plan the loadable LC_SEGMENT_64 carrying the slices-only payload. The
    // host-entry case maps the segment read+execute for the LC_MAIN redirect.
    uint32_t loadable_initprot = host_entry_requested
                                     ? MACHO_LOADABLE_INITPROT_RX
                                     : MACHO_LOADABLE_INITPROT_R;

    uint64_t payload_len    = (uint64_t)segment_payload->byte_len;
    uint64_t segment_vmsize =
        (payload_len + (MACHO_LOADABLE_PAGE - 1)) & ~((uint64_t)MACHO_LOADABLE_PAGE - 1);

    n00b_macho_rewrite_loadable_request_t request =
        (n00b_macho_rewrite_loadable_request_t){
            .payload         = segment_payload,
            .initprot        = loadable_initprot,
            .maxprot         = MACHO_LOADABLE_INITPROT_RX,
            .file_alignment  = MACHO_LOADABLE_PAGE,
            .vaddr_alignment = MACHO_LOADABLE_PAGE,
            .vmsize          = segment_vmsize,
            .policy          = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    auto plan_result = n00b_macho_rewrite_plan_loadable_insert(
        bin,
        &request,
        .allocator = allocator);

    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(plan_result);

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    // (1b) Host-entrypoint: fold the arm64 LC_MAIN redirect into the accepted
    // plan before apply (the §5.1 #6 contract admits SPLIT for the redirect).
    if (host_entry_requested) {
        auto enabled = _n00b_obj_bundle_macho_enable_host_entrypoint(
            bin,
            plan,
            n00b_option_get(host_entry_payload_offset),
            host_entry_size);

        if (n00b_result_is_err(enabled)) {
            return n00b_result_err(n00b_buffer_t *,
                                   n00b_result_get_err(enabled));
        }
    }

    // (2) Apply the loadable insert; the planned segment file offset is final.
    uint64_t segment_file_offset = plan->new_segment_file_offset;

    auto loadable_applied = n00b_macho_rewrite_apply_loadable_insert_plan(
        bin,
        plan,
        .allocator = allocator);

    if (n00b_result_is_err(loadable_applied)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_buffer_t *with_segment = n00b_result_get(loadable_applied);

    // (3) Finalize the SPLIT descriptor's segment file offset (plan_split left it
    // 0; the slices-only payload now lives at the planned segment offset). The
    // skeleton blob + slice records + slices-only payload_digest are already set.
    desc->payload_file_offset = segment_file_offset;

    auto encoded = n00b_macho_carrier_descriptor_encode(desc,
                                                        .allocator = allocator);

    if (n00b_result_is_err(encoded)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_BUILD);
    }

    n00b_buffer_t *descriptor_payload = n00b_result_get(encoded);

    // (4) Re-parse the segment-bearing output and insert the descriptor carrier
    // LC_NOTE via the WP-005/006 metadata insert (reuse the WP-008 token; do not
    // mint a new owner). The metadata insert appends to the file tail and does
    // not move the loadable segment, so the stored segment offset stays valid.
    n00b_bstream_t *stream = n00b_bstream_new(with_segment, .allocator = allocator);
    auto            reparsed = n00b_macho_parse_single(stream);

    if (n00b_result_is_err(reparsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_binary_t *with_segment_bin = n00b_result_get(reparsed);

    n00b_macho_rewrite_metadata_request_t note_request =
        (n00b_macho_rewrite_metadata_request_t){
            .note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER,
                                                .allocator = allocator),
            .note_name  = r"object-bundle",
            .payload    = descriptor_payload,
            .file_alignment        = 0,
            .preferred_file_offset = n00b_option_none(uint64_t),
            .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    auto note_applied = n00b_macho_rewrite_apply_object_bundle_insert(
        with_segment_bin,
        &note_request,
        .allocator = allocator);

    if (n00b_result_is_err(note_applied)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(note_applied));
}

// ============================================================================
// #6 — write_carrier (METADATA + LOADABLE + SPLIT paths)
// ============================================================================

n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_carrier(
    n00b_macho_binary_t             *bin,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_carrier_t        carrier,
    n00b_obj_bundle_replace_policy_t replace) _kargs {
    n00b_option_t(uint64_t) host_entry_payload_offset = n00b_option_none(uint64_t);
    uint64_t                host_entry_size           = 0;
    n00b_obj_bundle_t      *bundle                    = nullptr;
    n00b_allocator_t       *allocator                 = nullptr;
}
    requires {
        bin != nullptr;
        bin->stream != nullptr;
        bin->stream->buf != nullptr;
        canonical_bundle != nullptr;
        canonical_bundle->byte_len != 0;
        (!host_entry_payload_offset.has_value)
            || (host_entry_size != 0
                && (carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE
                    || carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT));
        // NOTE (D-031): SPLIT needs `bundle` to enumerate artifacts + excise
        // slices, but a null `bundle` on a SPLIT request is a DOCUMENTED Err, NOT
        // a trapping requires — it is body-guarded below to
        // Err(N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER), with an advisory `@pre`.
    }
    ensures {
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len >= bin->stream->buf->byte_len);
    }
{
    if (carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT) {
        // D-040: SPLIT requires the decoded bundle (to enumerate artifacts +
        // excise slices). A null bundle is body-guarded to a documented Err
        // (D-031), never a trap.
        if (bundle == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
        }

        return _n00b_obj_bundle_macho_write_split_carrier(
            bin,
            bundle,
            canonical_bundle,
            replace,
            host_entry_payload_offset,
            host_entry_size,
            allocator);
    }

    if (carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE) {
        return _n00b_obj_bundle_macho_write_loadable_carrier(
            bin,
            canonical_bundle,
            replace,
            host_entry_payload_offset,
            host_entry_size,
            allocator);
    }

    // AUTO maps to METADATA for Mach-O. Determine whether an N00b-owned carrier
    // already exists so we choose surgical insert vs. replace.
    auto detected = _n00b_obj_bundle_macho_detect_carrier(bin,
                                                          .allocator = allocator);

    if (n00b_result_is_err(detected)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_obj_bundle_macho_carrier_state_t state = n00b_result_get(detected);
    bool                                  has_carrier =
        (state != N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE);

    if (has_carrier && replace != N00B_OBJ_BUNDLE_REPLACE_EXISTING) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED);
    }

    n00b_macho_rewrite_metadata_request_t request =
        (n00b_macho_rewrite_metadata_request_t){
            .note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER,
                                                .allocator = allocator),
            .note_name  = r"object-bundle",
            .payload    = canonical_bundle,
            .file_alignment        = 0,
            .preferred_file_offset = n00b_option_none(uint64_t),
            .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };

    if (!has_carrier) {
        auto inserted = n00b_macho_rewrite_apply_object_bundle_insert(
            bin,
            &request,
            .allocator = allocator);
        if (n00b_result_is_err(inserted)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
        }
        return n00b_result_ok(n00b_buffer_t *, n00b_result_get(inserted));
    }

    // REPLACE: inspect at the PLAN level (D-037). The apply path collapses every
    // rejection to Err(PLAN_REJECTED), so a growth rejection cannot be told from
    // the apply error alone — plan first, then branch on outcome/reason.
    auto plan_result =
        n00b_macho_rewrite_plan_object_bundle_replace(bin,
                                                      &request,
                                                      .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);

    if (plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        // Same-or-smaller payload: fast in-slot replace.
        auto in_slot =
            n00b_macho_rewrite_apply_object_bundle_plan(bin,
                                                        plan,
                                                        .allocator = allocator);
        if (n00b_result_is_err(in_slot)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
        }
        return n00b_result_ok(n00b_buffer_t *, n00b_result_get(in_slot));
    }

    // A larger payload does not fit the located slot (REJECT_LC_PLACEMENT).
    // Compose delete-then-insert: drop the existing carrier (shrinks the file
    // and keeps __LINKEDIT last), re-parse the detached result, then insert the
    // larger carrier into the re-parsed binary (D-037). Any other rejection is
    // a real failure.
    if (plan->rejection_reason != N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    auto deleted =
        n00b_macho_rewrite_apply_object_bundle_delete(bin, .allocator = allocator);
    if (n00b_result_is_err(deleted)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_buffer_t  *shrunk = n00b_result_get(deleted);
    n00b_bstream_t *stream = n00b_bstream_new(shrunk, .allocator = allocator);
    auto            reparsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(reparsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    n00b_macho_binary_t *thin = n00b_result_get(reparsed);

    auto inserted = n00b_macho_rewrite_apply_object_bundle_insert(
        thin,
        &request,
        .allocator = allocator);
    if (n00b_result_is_err(inserted)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(inserted));
}

// ============================================================================
// Fat/universal carrier write (WP-014)
//
// Orchestrates the already-landed primitives: select slices (arm64-only),
// per-REWRITE slice detach+reparse and run the thin carrier engine, copy
// PASSTHROUGH slices byte-identical, then re-fat. No new fat machinery.
// ============================================================================

// Extract a slice's on-disk bytes from the fat input buffer into a fresh,
// detached buffer (D-034). Mirrors macho_fat_rewrite.c:fat_extract_slice_bytes:
// the slice extent is read from the parsed binary's own stream buffer (the whole
// fat file), copying [offset, offset + size). Returns nullptr on a bad extent.
static n00b_result_t(n00b_buffer_t *)
fat_carrier_detach_slice_bytes(n00b_macho_fat_t *fat,
                               uint32_t          index,
                               n00b_allocator_t *allocator)
{
    n00b_macho_binary_t    *bin   = fat->binaries[index];
    n00b_macho_fat_slice_t *slice = &fat->slices[index];

    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_buffer_t *src = bin->stream->buf;
    uint64_t       off = slice->offset;
    uint64_t       sz  = slice->size;

    if (sz == 0 || off > (uint64_t)src->byte_len
        || sz > (uint64_t)src->byte_len - off) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    return n00b_result_ok(n00b_buffer_t *,
                          n00b_buffer_from_bytes(src->data + off,
                                                 (int64_t)sz,
                                                 .allocator = allocator));
}

n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_carrier_fat(
    n00b_macho_fat_t                *fat,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_carrier_t        carrier,
    n00b_obj_bundle_replace_policy_t replace) _kargs {
    n00b_obj_bundle_t *bundle    = nullptr;
    n00b_allocator_t  *allocator = nullptr;
}
    // No trapping `requires` (D-031): null fat/binaries/slices and an empty
    // canonical bundle are documented, body-guarded `Err` returns. A trapping
    // `requires` would SIGTRAP in debug before the body could return the
    // documented Err.
    ensures {
        // On Ok the returned fat buffer is non-null. The "re-parses as fat with
        // fat->count slices; arm64 slice carries the bundle; non-arm64 slices
        // byte-identical" postcondition is a structural relation over the
        // re-parsed output (ncc forbids function calls in contracts, §0.3); it
        // is enforced by the per-slice loop + n00b_macho_refat and verified by
        // the P1 test matrix. Guarded by success (D-028).
        !result.is_ok || result.ok != nullptr;
    }
{
    if (fat == nullptr || fat->binaries == nullptr || fat->slices == nullptr
        || fat->count == 0 || canonical_bundle == nullptr
        || canonical_bundle->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Classify every slice (arm64-only default policy, D-002/D-035). The
    // selector returns Err(NO_TARGET_SLICE) when no arm64 slice is present; map
    // that to the obj_bundle UNSUPPORTED_CARRIER code.
    n00b_macho_fat_rewrite_request_t req = (n00b_macho_fat_rewrite_request_t){
        .policy = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
    };

    auto sel = n00b_macho_fat_select(fat, &req, .allocator = allocator);

    if (n00b_result_is_err(sel)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }

    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans
        = n00b_result_get(sel);

    uint32_t count = fat->count;

    // fat_select's contract is one plan per slice (length == fat->count). Guard
    // defensively: a short/null list would make the indexed reads below abort on
    // the list bounds check; surface a structured error instead.
    if (plans == nullptr || (uint32_t)n00b_list_len(*plans) != count) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Per-slice thin bytes + the identity n00b_macho_refat needs.
    n00b_buffer_t **thin_bufs   = n00b_alloc_array(n00b_buffer_t *, count,
                                                   .allocator = allocator);
    uint32_t       *cputypes    = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);
    uint32_t       *cpusubtypes = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);
    uint32_t       *aligns      = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);

    uint32_t rewrite_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *plan = n00b_list_get(*plans, i);

        if (plan->disposition == N00B_MACHO_FAT_SLICE_REJECT) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
        }

        // Detach the slice's on-disk bytes into a fresh buffer (D-034).
        auto slice_r = fat_carrier_detach_slice_bytes(fat,
                                                      plan->index,
                                                      allocator);

        if (n00b_result_is_err(slice_r)) {
            return slice_r;
        }

        n00b_buffer_t *slice_bytes = n00b_result_get(slice_r);

        if (plan->disposition == N00B_MACHO_FAT_SLICE_PASSTHROUGH) {
            // Non-arm64 slices pass through byte-identical (NFR-01, D-002/D-035).
            thin_bufs[i] = slice_bytes;
        }
        else {
            // REWRITE: re-parse the detached bytes as a thin object so
            // fat_offset == 0 (D-034), then run the thin carrier engine
            // slice-relative, threading the SPLIT .bundle kwarg (D-040).
            n00b_bstream_t *stream
                = n00b_bstream_new(slice_bytes, .allocator = allocator);

            auto parsed = n00b_macho_parse_single(stream);

            if (n00b_result_is_err(parsed)) {
                return n00b_result_err(
                    n00b_buffer_t *,
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
            }

            n00b_macho_binary_t *thin = n00b_result_get(parsed);

            // D-034 invariant: the detached re-parse must be slice-relative.
            if (thin->fat_offset != 0) {
                return n00b_result_err(
                    n00b_buffer_t *,
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
            }

            auto written = _n00b_obj_bundle_macho_write_carrier(
                thin,
                canonical_bundle,
                carrier,
                replace,
                .bundle    = bundle,
                .allocator = allocator);

            if (n00b_result_is_err(written)) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
            }

            thin_bufs[i] = n00b_result_get(written);
            rewrite_count++;
        }

        // Per-slice cputype/align from the D-020 slice descriptor; cpusubtype
        // from the parsed binary header (not carried in the slice descriptor —
        // OQ-1, mirrors macho_fat_rewrite.c:394).
        cputypes[i]    = fat->slices[plan->index].cputype;
        cpusubtypes[i] = fat->binaries[plan->index]->header.cpusubtype;
        aligns[i]      = fat->slices[plan->index].align;
    }

    // The selector guarantees >= 1 REWRITE, but guard defensively per the
    // contract (>= 1 REWRITE slice else UNSUPPORTED_CARRIER).
    if (rewrite_count == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }

    // Re-assemble the per-slice thin buffers into a loader-valid fat container
    // (NFR-11 alignment is enforced inside n00b_macho_refat). A -43xx failure
    // maps to REWRITE_FAILURE.
    auto refat = n00b_macho_refat(thin_bufs,
                                  cputypes,
                                  cpusubtypes,
                                  aligns,
                                  count,
                                  .allocator = allocator);

    if (n00b_result_is_err(refat)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(refat));
}

// ============================================================================
// Fat/universal carrier read (WP-015)
//
// Read-side slice selection: mirror the write path's selection to isolate the
// arm64 carrier slice as a detached thin binary (fat_offset==0, D-034) so the
// existing thin detect/per-kind read switch in obj_bundle.c runs unchanged.
// ============================================================================

n00b_result_t(n00b_macho_binary_t *)
_n00b_obj_bundle_macho_select_carrier_slice(n00b_macho_fat_t *fat) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    // No trapping `requires` (D-031): null fat/binaries/slices and an empty
    // fat are documented, body-guarded `Err` returns so the documented Err can
    // escape instead of a debug SIGTRAP.
    ensures {
        // On Ok the returned thin binary is non-null. The "arm64 carrier slice
        // with fat_offset == 0" relation is a structural property over the
        // re-parsed slice (ncc forbids function calls in contracts); the body
        // guards fat_offset != 0 and the P1 test matrix verifies it. Guarded by
        // success (D-028).
        !result.is_ok || result.ok != nullptr;
    }
{
    if (fat == nullptr || fat->binaries == nullptr || fat->slices == nullptr
        || fat->count == 0) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Classify slices under the arm64-only default policy (D-002/D-035): the
    // carrier lives in the arm64 slice only. No arm64/REWRITE slice (fat_select
    // NO_TARGET) maps to the obj_bundle UNSUPPORTED_CARRIER code.
    n00b_macho_fat_rewrite_request_t req = (n00b_macho_fat_rewrite_request_t){
        .policy = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
    };

    auto sel = n00b_macho_fat_select(fat, &req, .allocator = allocator);

    if (n00b_result_is_err(sel)) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }

    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans
        = n00b_result_get(sel);

    // fat_select's contract is one plan per slice (length == fat->count). Guard
    // defensively: a short/null list would make the indexed reads below abort on
    // the list bounds check; surface a structured error instead.
    if (plans == nullptr || (uint32_t)n00b_list_len(*plans) != fat->count) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    // Take the REWRITE slice's index from the returned per-slice plan list (one
    // plan per slice, index order). fat_select guarantees >= 1 REWRITE on Ok,
    // but guard defensively → UNSUPPORTED_CARRIER if none is found.
    uint32_t rewrite_index = UINT32_MAX;

    for (uint32_t i = 0; i < fat->count; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *plan = n00b_list_get(*plans, i);

        if (plan->disposition == N00B_MACHO_FAT_SLICE_REWRITE) {
            rewrite_index = plan->index;
            break;
        }
    }

    if (rewrite_index == UINT32_MAX) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }

    // Detach the arm64 slice's on-disk bytes into a fresh buffer (D-034).
    auto slice_r = fat_carrier_detach_slice_bytes(fat,
                                                  rewrite_index,
                                                  allocator);

    if (n00b_result_is_err(slice_r)) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_buffer_t *slice_bytes = n00b_result_get(slice_r);

    // Re-parse the detached bytes as a thin object so fat_offset == 0 (D-034)
    // and the existing thin read switch applies unchanged.
    n00b_bstream_t *stream = n00b_bstream_new(slice_bytes, .allocator = allocator);

    auto parsed = n00b_macho_parse_single(stream);

    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    n00b_macho_binary_t *thin = n00b_result_get(parsed);

    // D-034 invariant: the detached re-parse must be slice-relative.
    if (thin->fat_offset != 0) {
        return n00b_result_err(n00b_macho_binary_t *,
                               N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER);
    }

    return n00b_result_ok(n00b_macho_binary_t *, thin);
}
