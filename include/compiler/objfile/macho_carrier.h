/**
 * @file macho_carrier.h
 * @brief Mach-O object-bundle carrier descriptor wire format (encode/decode).
 *
 * The carrier descriptor is the byte payload stored in the carrier `LC_NOTE`
 * (`data_owner = n00b.0c001`, D-010) for the LOADABLE and SPLIT carriers. It
 * records the magic, version, header size, carrier kind, the payload file
 * offset/length, a SHA-256 digest of the payload bytes, and (SPLIT only) a
 * contiguous run of 48-byte split aux records describing how payload slices
 * reconstruct the canonical object bundle.
 *
 * For the METADATA carrier the `LC_NOTE` holds raw canonical bundle bytes with
 * no descriptor; the reader discriminates "descriptor present" by the 8-byte
 * magic (OQ-2: magic present => LOADABLE/SPLIT by carrier_kind; absent =>
 * METADATA_RAW). All multi-byte integers are little-endian (arm64 native;
 * matches the Mach-O load-command convention, 04 §0/§3).
 *
 * This header is the public surface; the obj_bundle Mach-O backend that consumes
 * it lives in the internal `obj_bundle_macho.{c,h}` (D-011). Mirrors the ELF
 * carrier descriptor internals; the encode/decode/verify functions are pinned by
 * WP-002 and their bodies are filled by WP-008/WP-010.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"

// ============================================================================
// Constants
// ============================================================================

#define N00B_MACHO_CARRIER_MAGIC_LEN         8u
#define N00B_MACHO_CARRIER_HEADER_SIZE       64u
#define N00B_MACHO_CARRIER_RECORD_SIZE       48u
#define N00B_MACHO_CARRIER_DIGEST_LEN        32u
#define N00B_MACHO_CARRIER_MAJOR             1u
#define N00B_MACHO_CARRIER_MINOR             0u

// SPLIT-only LC_NOTE trailer prefix: the `skeleton_len`(u64) + `record_count`(u64)
// words that immediately follow the fixed 64-byte header (D-040). The excised
// skeleton bytes and the 48-byte slice records follow these two words.
#define N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE 16u

/**
 * @brief The 8-byte descriptor magic: `"\x00" "0c001MO"` (distinct from ELF).
 *
 * Present at offset 0 of every LOADABLE/SPLIT descriptor; its presence is the
 * metadata-vs-loadable discriminant (OQ-2). Defined out-of-line so the carrier
 * `.c` owns the canonical bytes; readers compare the first
 * `N00B_MACHO_CARRIER_MAGIC_LEN` bytes against it.
 */
extern const uint8_t
    N00B_MACHO_CARRIER_MAGIC[N00B_MACHO_CARRIER_MAGIC_LEN];

// ============================================================================
// Error codes
// ============================================================================

#define N00B_MACHO_CARRIER_OK                  0
#define N00B_MACHO_CARRIER_ERR_NULL_INPUT      (-4101)
#define N00B_MACHO_CARRIER_ERR_SHORT_HEADER    (-4102)
#define N00B_MACHO_CARRIER_ERR_BAD_MAGIC       (-4103)
#define N00B_MACHO_CARRIER_ERR_BAD_VERSION     (-4104)
#define N00B_MACHO_CARRIER_ERR_BAD_HEADER_SIZE (-4105)
#define N00B_MACHO_CARRIER_ERR_BAD_KIND        (-4106)
#define N00B_MACHO_CARRIER_ERR_BOUNDS          (-4107)
#define N00B_MACHO_CARRIER_ERR_DIGEST          (-4108)
#define N00B_MACHO_CARRIER_ERR_RECORD_COUNT    (-4109)
// SPLIT planning: the bundle has no executable-compatible artifact slice, so a
// SPLIT carrier cannot be built (D-040; mirrors the ELF "no movable payloads"
// path). The #6 write arm maps this to N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER.
#define N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER (-4110)

// ============================================================================
// Carrier-kind enum + descriptor / split-record types
// ============================================================================

typedef enum {
    N00B_MACHO_CARRIER_KIND_LOADABLE = 1,
    N00B_MACHO_CARRIER_KIND_SPLIT    = 2,
} n00b_macho_carrier_kind_t;

/**
 * @brief One 48-byte split aux record (SPLIT carrier only).
 *
 * Maps an executable-compatible payload slice in the slices-only segment to its
 * position in the rebuilt canonical bundle. There is one record per executable
 * slice (D-040: NO skeleton record — the excised skeleton is a contiguous blob
 * in the LC_NOTE trailer). The slices are non-overlapping in canonical and
 * ordered by the deterministic artifact comparator (NFR-02). Together the
 * skeleton (gaps) + slices reconstruct `[0, canonical_len)` (the WP-010
 * reconstruction invariant). `slice_digest_crc` is a fast structural pre-check
 * only; the bundle-level SHA-256 over the reconstructed canonical bytes is the
 * real integrity gate (re-validated by the neutral core). The `pad`/`pad2`
 * fields are zero and exist so the struct matches the fixed 48-byte on-disk
 * record layout.
 */
typedef struct n00b_macho_carrier_split_record {
    uint64_t slice_payload_offset;  // offset within the slices-only segment
    uint64_t slice_len;             // bytes of this slice
    uint64_t reconstruct_offset;    // offset within the rebuilt canonical bundle
    uint64_t artifact_id;           // logical artifact id of the executable slice
    uint32_t slice_flags;           // reserved; 0
    uint32_t pad;                   // 0; aligns slice_digest_crc to offset 40
    uint32_t slice_digest_crc;      // quick CRC32 of the slice (cheap pre-check)
    uint32_t pad2;                  // 0; pads the record to the fixed 48 bytes
} n00b_macho_carrier_split_record_t;

/**
 * @brief Decoded Mach-O carrier descriptor (in-memory form).
 *
 * The on-disk encoding is the fixed 64-byte header followed, for SPLIT, by the
 * trailer: `skeleton_len`(u64) + `record_count`(u64) + `skeleton_len` skeleton
 * bytes + `record_count` 48-byte records (D-040). `records` is non-null iff
 * `record_count > 0` (and only for SPLIT). `skeleton`/`skeleton_len` carry the
 * excised skeleton (canonical bundle minus the executable slices); `skeleton` is
 * non-null and `skeleton->byte_len == skeleton_len` for SPLIT, else nullptr.
 * `payload_digest` is the SHA-256 of the `payload_len` slices-only segment
 * payload bytes; this layer never hashes — the caller supplies the digest on
 * encode and verifies it via @ref n00b_macho_carrier_verify_digest on decode.
 */
typedef struct n00b_macho_carrier_descriptor {
    // In-memory enum (compiler-sized). Decoded from the 2-byte on-disk
    // `carrier_kind` field (§4.1) — do NOT bitwise-copy it from the wire; the
    // WP-008 codec reads/writes the 2-byte field explicitly.
    n00b_macho_carrier_kind_t          kind;
    uint16_t                           version_major;
    uint16_t                           version_minor;
    uint64_t                           payload_file_offset;
    uint64_t                           payload_len;
    uint8_t                            payload_digest[N00B_MACHO_CARRIER_DIGEST_LEN];
    n00b_buffer_t                     *skeleton;  // SPLIT only; else nullptr
    uint64_t                           skeleton_len;
    n00b_macho_carrier_split_record_t *records;  // SPLIT only; else nullptr
    uint64_t                           record_count;
} n00b_macho_carrier_descriptor_t;

// ============================================================================
// Encode / decode / verify
// ============================================================================

/**
 * @brief Encode a Mach-O carrier descriptor to its on-disk byte form.
 *
 * Writes the fixed 64-byte little-endian header and, for SPLIT, the trailer
 * (D-040): `skeleton_len`(u64) + `record_count`(u64) + the `desc->skeleton`
 * bytes + `record_count` 48-byte slice records. The caller is responsible for
 * having computed `payload_digest` (SHA-256 of the slices-only segment payload);
 * this function does not hash.
 *
 * @param desc Descriptor to encode.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) or Err(N00B_MACHO_CARRIER_ERR_*).
 * @pre `desc` is non-null.
 * @pre `desc->kind` is LOADABLE or SPLIT.
 * @pre When `desc->kind == SPLIT`: `desc->record_count > 0`,
 *      `desc->records` is non-null, `desc->skeleton` is non-null, and
 *      `desc->skeleton->byte_len == desc->skeleton_len`.
 * @post On success, the encoded buffer length equals
 *       `kind == SPLIT ? 64 + 16 + skeleton_len + record_count * 48 : 64`.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_carrier_descriptor_encode(
    n00b_macho_carrier_descriptor_t *desc) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Decode and structurally validate a Mach-O carrier descriptor.
 *
 * Validates magic, version, header size, kind, and that
 * `payload_file_offset + payload_len` does not overflow. For SPLIT it reads the
 * trailer (D-040): `skeleton_len` + `record_count` from the trailer words (NOT
 * derived from note size), then the skeleton blob into `result.ok->skeleton`,
 * then the records; it validates the note size equals
 * `64 + 16 + skeleton_len + record_count * 48`. It does NOT verify the SHA-256
 * digest against payload bytes — decode is pure structure; the reader checks the
 * digest against the actual slices-only segment payload via
 * @ref n00b_macho_carrier_verify_digest.
 *
 * @param bytes Descriptor bytes from the carrier LC_NOTE.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned descriptor, its skeleton, and any decoded records.
 * @return Ok(descriptor) or Err(N00B_MACHO_CARRIER_ERR_*).
 * @pre `bytes` is non-null.
 * @post On success, `result.ok->kind` is LOADABLE or SPLIT, and for SPLIT,
 *       `result.ok->records` is non-null iff `result.ok->record_count > 0`,
 *       `result.ok->skeleton != nullptr`, and
 *       `result.ok->skeleton->byte_len == result.ok->skeleton_len`.
 * @post Round-trips: encoding `result.ok` reproduces `bytes`. (Relational
 *       round-trip is test-verified — see §7 of the contract design.)
 */
extern n00b_result_t(n00b_macho_carrier_descriptor_t *)
n00b_macho_carrier_descriptor_decode(n00b_buffer_t *bytes) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Compute the canonical 32-byte payload digest for a carrier descriptor.
 *
 * Computes SHA-256 over @p payload and serializes the digest into @p out in the
 * canonical big-endian-per-word byte order. This is the single serialization
 * routine shared by the descriptor writer (which fills
 * `descriptor->payload_digest`) and @ref n00b_macho_carrier_verify_digest, so the
 * two never diverge on byte order.
 *
 * @param payload Payload bytes to hash.
 * @param out 32-byte digest output buffer.
 * @pre `payload` and `out` are non-null.
 */
extern void
n00b_macho_carrier_compute_digest(
    n00b_buffer_t *payload,
    uint8_t        out[N00B_MACHO_CARRIER_DIGEST_LEN]);

/**
 * @brief Verify a descriptor's payload digest against actual payload bytes.
 *
 * Computes SHA-256 over @p payload and compares it to `desc->payload_digest`.
 * The hash is computed in the function body (a SHA-256 call cannot appear in a
 * `requires`/`ensures` block), so the boolean verdict is carried in the result
 * rather than asserted in the contract.
 *
 * @param desc Decoded descriptor.
 * @param payload Actual payload bytes from the new segment.
 * @return Ok(true) on digest match, Ok(false) on mismatch, or
 *         Err(N00B_MACHO_CARRIER_ERR_*).
 * @pre `desc` and `payload` are non-null.
 * @pre `desc->payload_len == payload->byte_len`.
 * @post The result is a clean boolean verdict; no allocation, no mutation.
 */
extern n00b_result_t(bool)
n00b_macho_carrier_verify_digest(
    n00b_macho_carrier_descriptor_t *desc,
    n00b_buffer_t                   *payload);

// ============================================================================
// Enum-name / error-string helpers
// ============================================================================

/**
 * @brief Look up a human-readable string for an `N00B_MACHO_CARRIER_ERR_*` code.
 *
 * @param err Error code returned by the Mach-O carrier API.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_carrier_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for a Mach-O carrier kind.
 *
 * @param kind Carrier kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_carrier_kind_str(n00b_macho_carrier_kind_t kind);
