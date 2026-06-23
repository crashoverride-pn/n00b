/**
 * @file macho_carrier.c
 * @brief Mach-O object-bundle carrier descriptor codec.
 *
 * WP-008 landed @ref n00b_macho_carrier_descriptor_decode (the dependency of the
 * carrier-detect backend, which uses it to discriminate a descriptor-backed
 * LOADABLE/SPLIT carrier from a raw METADATA carrier by the 8-byte magic at
 * payload offset 0, D-023). The canonical magic bytes are also defined here so
 * the carrier translation unit owns them. WP-009 adds the LOADABLE path of
 * @ref n00b_macho_carrier_descriptor_encode (the 64-byte header only,
 * `record_count == 0`, no aux records) and @ref n00b_macho_carrier_verify_digest
 * (SHA-256 over the payload, verdict carried in the result). WP-010 reworks the
 * SPLIT path of encode/decode to the D-040 LC_NOTE trailer: after the shared
 * 64-byte header, `skeleton_len` + `record_count` words + the excised skeleton
 * blob + `record_count` 48-byte slice records.
 *
 * All multi-byte integers in the on-disk descriptor are little-endian (arm64
 * native; matches the Mach-O load-command convention, 04 §3).
 */
#include "compiler/objfile/macho_carrier.h"

#include "core/sha256.h"

// The 8-byte descriptor magic `"\x00" "0c001MO"` (04 §4.1; distinct from the
// ELF carrier magic). Defined out-of-line so this translation unit owns the
// canonical bytes; readers compare the first N00B_MACHO_CARRIER_MAGIC_LEN bytes.
const uint8_t N00B_MACHO_CARRIER_MAGIC[N00B_MACHO_CARRIER_MAGIC_LEN] = {
    0x00,
    '0',
    'c',
    '0',
    '0',
    '1',
    'M',
    'O',
};

// On-disk header field offsets (04 §4.1 byte-layout table).
#define MACHO_CARRIER_OFF_MAGIC          0u
#define MACHO_CARRIER_OFF_VERSION_MAJOR  8u
#define MACHO_CARRIER_OFF_VERSION_MINOR  10u
#define MACHO_CARRIER_OFF_HEADER_SIZE    12u
#define MACHO_CARRIER_OFF_KIND           14u
#define MACHO_CARRIER_OFF_PAYLOAD_OFFSET 16u
#define MACHO_CARRIER_OFF_PAYLOAD_LEN    24u
#define MACHO_CARRIER_OFF_PAYLOAD_DIGEST 32u

// ============================================================================
// Little-endian readers over the raw descriptor bytes (header-only libc byte
// work is permitted for raw on-disk decoding; D-007 § 2.10).
// ============================================================================

static uint16_t
carrier_read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
carrier_read_u32(const uint8_t *p)
{
    uint32_t v = 0;

    for (uint32_t i = 0; i < 4; i++) {
        v |= (uint32_t)p[i] << (8 * i);
    }

    return v;
}

static uint64_t
carrier_read_u64(const uint8_t *p)
{
    uint64_t v = 0;

    for (uint32_t i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8 * i);
    }

    return v;
}

static bool
carrier_magic_matches(const uint8_t *p)
{
    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_MAGIC_LEN; i++) {
        if (p[i] != N00B_MACHO_CARRIER_MAGIC[i]) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// Little-endian writers over the raw descriptor bytes (header-only libc byte
// work is permitted for raw on-disk encoding; D-007 § 2.10).
// ============================================================================

static void
carrier_write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void
carrier_write_u32(uint8_t *p, uint32_t v)
{
    for (uint32_t i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void
carrier_write_u64(uint8_t *p, uint64_t v)
{
    for (uint32_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

// ============================================================================
// Decode
// ============================================================================

n00b_result_t(n00b_macho_carrier_descriptor_t *)
n00b_macho_carrier_descriptor_decode(n00b_buffer_t *bytes) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bytes != nullptr;
    }
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->kind == N00B_MACHO_CARRIER_KIND_LOADABLE)
                    || (result.ok->kind == N00B_MACHO_CARRIER_KIND_SPLIT)));
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->kind != N00B_MACHO_CARRIER_KIND_SPLIT)
                    || ((result.ok->record_count == 0)
                        == (result.ok->records == nullptr))));
        // SPLIT decode yields the excised skeleton blob (D-040).
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->kind != N00B_MACHO_CARRIER_KIND_SPLIT)
                    || (result.ok->skeleton != nullptr
                        && (uint64_t)result.ok->skeleton->byte_len
                               == result.ok->skeleton_len)));
    }
{
    if (bytes->data == nullptr
        || (uint64_t)bytes->byte_len < N00B_MACHO_CARRIER_HEADER_SIZE) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_SHORT_HEADER);
    }

    const uint8_t *raw = (const uint8_t *)bytes->data;

    if (!carrier_magic_matches(raw + MACHO_CARRIER_OFF_MAGIC)) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_BAD_MAGIC);
    }

    uint16_t version_major = carrier_read_u16(raw + MACHO_CARRIER_OFF_VERSION_MAJOR);
    uint16_t version_minor = carrier_read_u16(raw + MACHO_CARRIER_OFF_VERSION_MINOR);

    if (version_major != N00B_MACHO_CARRIER_MAJOR) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_BAD_VERSION);
    }

    uint16_t header_size = carrier_read_u16(raw + MACHO_CARRIER_OFF_HEADER_SIZE);

    if (header_size < N00B_MACHO_CARRIER_HEADER_SIZE) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_BAD_HEADER_SIZE);
    }

    uint16_t kind_raw = carrier_read_u16(raw + MACHO_CARRIER_OFF_KIND);

    if (kind_raw != N00B_MACHO_CARRIER_KIND_LOADABLE
        && kind_raw != N00B_MACHO_CARRIER_KIND_SPLIT) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_BAD_KIND);
    }

    n00b_macho_carrier_kind_t kind = (n00b_macho_carrier_kind_t)kind_raw;

    uint64_t payload_file_offset =
        carrier_read_u64(raw + MACHO_CARRIER_OFF_PAYLOAD_OFFSET);
    uint64_t payload_len = carrier_read_u64(raw + MACHO_CARRIER_OFF_PAYLOAD_LEN);

    if (UINT64_MAX - payload_file_offset < payload_len) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    // SPLIT carries the trailer (D-040): skeleton_len + record_count words FROM
    // the trailer (NOT derived from note size), then the skeleton blob, then the
    // 48-byte slice records. LOADABLE carries no trailer (bare 64-byte header).
    uint64_t note_size     = (uint64_t)bytes->byte_len;
    uint64_t record_count  = 0;
    uint64_t skeleton_len  = 0;
    uint64_t skeleton_off  = 0;
    uint64_t records_off   = 0;

    if (kind == N00B_MACHO_CARRIER_KIND_SPLIT) {
        if (note_size < (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                            + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE) {
            return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                                   N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
        }

        skeleton_len = carrier_read_u64(raw + N00B_MACHO_CARRIER_HEADER_SIZE);
        record_count = carrier_read_u64(raw + N00B_MACHO_CARRIER_HEADER_SIZE
                                        + 8);

        // Guard the record-region size math so a hostile record_count cannot
        // overflow the trailer length we validate against the note size.
        if (record_count != 0
            && record_count
                   > (UINT64_MAX
                      - N00B_MACHO_CARRIER_HEADER_SIZE
                      - N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE)
                         / N00B_MACHO_CARRIER_RECORD_SIZE) {
            return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                                   N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
        }

        uint64_t records_bytes = record_count * N00B_MACHO_CARRIER_RECORD_SIZE;

        if (UINT64_MAX - skeleton_len < records_bytes) {
            return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        uint64_t trailer_body = skeleton_len + records_bytes;

        if (UINT64_MAX - trailer_body
            < (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                  + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE) {
            return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        // Note size must be EXACTLY header + trailer words + skeleton + records.
        if (note_size != (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                             + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE
                             + trailer_body) {
            return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                                   N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
        }

        skeleton_off = (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                       + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE;
        records_off  = skeleton_off + skeleton_len;
    }
    else if (note_size != N00B_MACHO_CARRIER_HEADER_SIZE) {
        // A LOADABLE descriptor is exactly the fixed header; trailing bytes are
        // a structural inconsistency.
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
    }

    n00b_macho_carrier_descriptor_t *desc =
        n00b_alloc(n00b_macho_carrier_descriptor_t, .allocator = allocator);

    desc->kind                = kind;
    desc->version_major       = version_major;
    desc->version_minor       = version_minor;
    desc->payload_file_offset = payload_file_offset;
    desc->payload_len         = payload_len;
    desc->skeleton            = nullptr;
    desc->skeleton_len        = skeleton_len;
    desc->record_count        = record_count;
    desc->records             = nullptr;

    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_DIGEST_LEN; i++) {
        desc->payload_digest[i] = raw[MACHO_CARRIER_OFF_PAYLOAD_DIGEST + i];
    }

    if (kind == N00B_MACHO_CARRIER_KIND_SPLIT) {
        // The excised skeleton blob lives in the trailer (D-040). Copy it into a
        // buffer owned by `allocator` so the descriptor's skeleton is independent
        // of the source note buffer.
        desc->skeleton = n00b_buffer_get_slice(
            bytes,
            (int64_t)skeleton_off,
            (int64_t)(skeleton_off + skeleton_len),
            .allocator = allocator);
    }

    if (record_count != 0) {
        desc->records = n00b_alloc_array(n00b_macho_carrier_split_record_t,
                                         record_count,
                                         .allocator = allocator);

        for (uint64_t r = 0; r < record_count; r++) {
            const uint8_t *rec = raw + records_off
                               + r * N00B_MACHO_CARRIER_RECORD_SIZE;

            // W-1 fix (WP-010): read the four trailing u32 fields from the wire
            // (offsets 32/36/40/44 within the 48-byte record, §4.1) instead of
            // hard-zeroing them, so a non-zero slice_digest_crc round-trips.
            desc->records[r] = (n00b_macho_carrier_split_record_t){
                .slice_payload_offset = carrier_read_u64(rec + 0),
                .slice_len            = carrier_read_u64(rec + 8),
                .reconstruct_offset   = carrier_read_u64(rec + 16),
                .artifact_id          = carrier_read_u64(rec + 24),
                .slice_flags          = carrier_read_u32(rec + 32),
                .pad                  = carrier_read_u32(rec + 36),
                .slice_digest_crc     = carrier_read_u32(rec + 40),
                .pad2                 = carrier_read_u32(rec + 44),
            };
        }
    }

    return n00b_result_ok(n00b_macho_carrier_descriptor_t *, desc);
}

// ============================================================================
// Encode
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_macho_carrier_descriptor_encode(
    n00b_macho_carrier_descriptor_t *desc) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        desc != nullptr;
        desc->kind == N00B_MACHO_CARRIER_KIND_LOADABLE
            || desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT;
        // SPLIT (D-040): ≥1 slice record, the records + skeleton blob present,
        // and the skeleton blob length agrees with skeleton_len.
        (desc->kind != N00B_MACHO_CARRIER_KIND_SPLIT)
            || (desc->record_count > 0
                && desc->records != nullptr
                && desc->skeleton != nullptr
                && (uint64_t)desc->skeleton->byte_len == desc->skeleton_len);
    }
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null. LOADABLE ⇒ a
        // bare 64-byte header; SPLIT ⇒ header + 16-byte trailer words +
        // skeleton_len + record_count * 48 (D-040).
        !result.is_ok
            || (result.ok != nullptr
                && ((desc->kind != N00B_MACHO_CARRIER_KIND_SPLIT
                     && (uint64_t)result.ok->byte_len
                            == (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE)
                    || (desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT
                        && (uint64_t)result.ok->byte_len
                               == (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                                      + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE
                                      + desc->skeleton_len
                                      + desc->record_count
                                            * N00B_MACHO_CARRIER_RECORD_SIZE)));
    }
{
    if (UINT64_MAX - desc->payload_file_offset < desc->payload_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    bool is_split = (desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT);

    // SPLIT emits the 64-byte header + the trailer (skeleton_len + record_count
    // words + skeleton bytes + 48-byte slice records); LOADABLE emits only the
    // header. The `requires` pins the SPLIT preconditions.
    uint64_t record_count = is_split ? desc->record_count : 0;
    uint64_t skeleton_len = is_split ? desc->skeleton_len : 0;

    // Guard the record-region size math so a hostile record_count cannot
    // overflow the byte length we allocate (documented Err, never UB; D-031).
    if (record_count != 0
        && record_count
               > (UINT64_MAX
                  - N00B_MACHO_CARRIER_HEADER_SIZE
                  - N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE)
                     / N00B_MACHO_CARRIER_RECORD_SIZE) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
    }

    uint64_t records_bytes = record_count * N00B_MACHO_CARRIER_RECORD_SIZE;
    uint64_t trailer_size  = is_split
                                ? N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE
                                : 0;

    if (UINT64_MAX - skeleton_len < records_bytes) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    uint64_t trailer_body = skeleton_len + records_bytes;

    if (UINT64_MAX - trailer_body
        < (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE + trailer_size) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    uint64_t total_len = (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                       + trailer_size + trailer_body;

    if (total_len > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
    }

    n00b_buffer_t *out = n00b_buffer_new((int64_t)total_len,
                                         .allocator = allocator);
    // Grow byte_len to the full encoded size; resize zero-fills the new bytes so
    // the reserved/pad fields default to 0 unless written below.
    n00b_buffer_resize(out, total_len);

    uint8_t *bytes = (uint8_t *)out->data;

    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_MAGIC_LEN; i++) {
        bytes[MACHO_CARRIER_OFF_MAGIC + i] = N00B_MACHO_CARRIER_MAGIC[i];
    }

    carrier_write_u16(bytes + MACHO_CARRIER_OFF_VERSION_MAJOR,
                      N00B_MACHO_CARRIER_MAJOR);
    carrier_write_u16(bytes + MACHO_CARRIER_OFF_VERSION_MINOR,
                      N00B_MACHO_CARRIER_MINOR);
    carrier_write_u16(bytes + MACHO_CARRIER_OFF_HEADER_SIZE,
                      (uint16_t)N00B_MACHO_CARRIER_HEADER_SIZE);
    carrier_write_u16(bytes + MACHO_CARRIER_OFF_KIND,
                      (uint16_t)desc->kind);
    carrier_write_u64(bytes + MACHO_CARRIER_OFF_PAYLOAD_OFFSET,
                      desc->payload_file_offset);
    carrier_write_u64(bytes + MACHO_CARRIER_OFF_PAYLOAD_LEN,
                      desc->payload_len);

    // payload_digest written in the SAME byte order the decoder reads it (the
    // 32 raw SHA-256 bytes, in order; decode at MACHO_CARRIER_OFF_PAYLOAD_DIGEST).
    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_DIGEST_LEN; i++) {
        bytes[MACHO_CARRIER_OFF_PAYLOAD_DIGEST + i] = desc->payload_digest[i];
    }

    // SPLIT trailer (D-040): skeleton_len + record_count words, then the excised
    // skeleton bytes, then `record_count` fixed 48-byte slice records.
    if (is_split) {
        carrier_write_u64(bytes + N00B_MACHO_CARRIER_HEADER_SIZE,
                          skeleton_len);
        carrier_write_u64(bytes + N00B_MACHO_CARRIER_HEADER_SIZE + 8,
                          record_count);

        uint8_t *skel = bytes + N00B_MACHO_CARRIER_HEADER_SIZE
                      + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE;

        for (uint64_t i = 0; i < skeleton_len; i++) {
            skel[i] = ((const uint8_t *)desc->skeleton->data)[i];
        }

        uint8_t *records_base = skel + skeleton_len;

        // Each record is the fixed 48-byte little-endian layout (§4.1) —
        // slice_payload_offset/slice_len/reconstruct_offset/artifact_id as u64,
        // then slice_flags/pad/slice_digest_crc/pad2 as u32 at 32/36/40/44.
        for (uint64_t r = 0; r < record_count; r++) {
            const n00b_macho_carrier_split_record_t *rec = &desc->records[r];
            uint8_t *p = records_base + r * N00B_MACHO_CARRIER_RECORD_SIZE;

            carrier_write_u64(p + 0, rec->slice_payload_offset);
            carrier_write_u64(p + 8, rec->slice_len);
            carrier_write_u64(p + 16, rec->reconstruct_offset);
            carrier_write_u64(p + 24, rec->artifact_id);
            carrier_write_u32(p + 32, rec->slice_flags);
            carrier_write_u32(p + 36, rec->pad);
            carrier_write_u32(p + 40, rec->slice_digest_crc);
            carrier_write_u32(p + 44, rec->pad2);
        }
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

// ============================================================================
// Digest serialization + verify
// ============================================================================

// Serialize the SHA-256 of `payload` into `out` in the canonical
// big-endian-per-word byte order. The single source of truth for the digest
// byte layout, shared by the descriptor writer and verify_digest so they never
// diverge.
void
n00b_macho_carrier_compute_digest(
    n00b_buffer_t *payload,
    uint8_t        out[N00B_MACHO_CARRIER_DIGEST_LEN])
{
    n00b_sha256_digest_t digest;
    n00b_sha256_hash(payload->data, (size_t)payload->byte_len, digest);

    // n00b_sha256_hash produces the 8 hash-state words in host order; the
    // canonical SHA-256 octet string is each word big-endian. Lay them out so.
    for (uint32_t w = 0; w < N00B_SHA256_DIGEST_WORDS; w++) {
        for (uint32_t b = 0; b < 4; b++) {
            out[w * 4 + b] = (uint8_t)(digest[w] >> (8 * (3 - b)));
        }
    }
}

n00b_result_t(bool)
n00b_macho_carrier_verify_digest(
    n00b_macho_carrier_descriptor_t *desc,
    n00b_buffer_t                   *payload)
    requires {
        desc != nullptr;
        payload != nullptr;
        desc->payload_len == (uint64_t)payload->byte_len;
    }
    ensures {}
{
    // SHA-256 is computed in the body (a hash call cannot appear in a contract
    // block); the verdict is carried in result.ok, never asserted in `ensures`.
    uint8_t computed[N00B_MACHO_CARRIER_DIGEST_LEN];
    n00b_macho_carrier_compute_digest(payload, computed);

    bool match = true;

    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_DIGEST_LEN; i++) {
        if (computed[i] != desc->payload_digest[i]) {
            match = false;
            break;
        }
    }

    return n00b_result_ok(bool, match);
}

// ============================================================================
// Enum-name / error-string helpers (D-029: pointer return, no `ensures`)
// ============================================================================

n00b_string_t *
n00b_macho_carrier_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_MACHO_CARRIER_OK:
        return r"Mach-O carrier: ok";
    case N00B_MACHO_CARRIER_ERR_NULL_INPUT:
        return r"Mach-O carrier: null input";
    case N00B_MACHO_CARRIER_ERR_SHORT_HEADER:
        return r"Mach-O carrier: descriptor shorter than the fixed header";
    case N00B_MACHO_CARRIER_ERR_BAD_MAGIC:
        return r"Mach-O carrier: bad descriptor magic";
    case N00B_MACHO_CARRIER_ERR_BAD_VERSION:
        return r"Mach-O carrier: unsupported descriptor version";
    case N00B_MACHO_CARRIER_ERR_BAD_HEADER_SIZE:
        return r"Mach-O carrier: bad header size field";
    case N00B_MACHO_CARRIER_ERR_BAD_KIND:
        return r"Mach-O carrier: unknown carrier kind";
    case N00B_MACHO_CARRIER_ERR_BOUNDS:
        return r"Mach-O carrier: payload offset/length out of bounds";
    case N00B_MACHO_CARRIER_ERR_DIGEST:
        return r"Mach-O carrier: payload digest mismatch";
    case N00B_MACHO_CARRIER_ERR_RECORD_COUNT:
        return r"Mach-O carrier: malformed split record count";
    case N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER:
        return r"Mach-O carrier: SPLIT requires an executable-compatible slice";
    default:
        return r"Mach-O carrier: unknown error code";
    }
}

n00b_string_t *
n00b_macho_carrier_kind_str(n00b_macho_carrier_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_CARRIER_KIND_LOADABLE:
        return r"loadable";
    case N00B_MACHO_CARRIER_KIND_SPLIT:
        return r"split";
    default:
        return r"unknown-macho-carrier-kind";
    }
}
