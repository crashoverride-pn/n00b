/**
 * @file obj_bundle_macho.h
 * @brief Internal Mach-O object-bundle carrier backend (detect / reserved /
 *        read / write).
 *
 * These are the Mach-O analogues of the ELF carrier backend that the neutral
 * `obj_bundle` core already calls. They consume the parsed Mach-O model
 * (@ref n00b_macho_binary_t), the WP-005/006 surgical `LC_NOTE` rewrite
 * (@ref macho_rewrite.h), and the WP-008 carrier descriptor codec
 * (@ref macho_carrier.h). The carrier is identified by the reserved
 * `LC_NOTE.data_owner` token `N00B_MACHO_BUNDLE_NOTE_OWNER` ("n00b.0c001",
 * D-010/D-030, defined once in `macho_rewrite_admit.h`) — never a section name
 * (Mach-O has no section-name carrier slot like ELF's `.0c001.bundle`).
 *
 * The METADATA carrier stores raw canonical object-bundle bytes directly in the
 * carrier `LC_NOTE` (no descriptor), exactly as ELF stores raw bytes in
 * `.0c001.bundle`. The descriptor-backed LOADABLE/SPLIT carriers are projected
 * to WP-009/WP-010; their read and the LOADABLE/SPLIT bodies of `write_carrier`
 * are declared here but return `Err(N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER)`
 * until then.
 *
 * Dispatch wiring (the two `obj_bundle.c` hooks) is a separate concern (WP-008
 * Phase 2); these functions are invoked directly by the dispatch hooks with
 * already-parsed (non-null) inputs.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "adt/result.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "compiler/objfile/macho_carrier.h"
#include "compiler/objfile/obj_bundle.h"

// ============================================================================
// Carrier-state classification (03 §5.1)
// ============================================================================

/**
 * @brief Classification of the Mach-O object-bundle carrier `LC_NOTE` state.
 *
 * Discriminated by @ref _n00b_obj_bundle_macho_detect_carrier: an owned carrier
 * is an `LC_NOTE` whose `data_owner` equals `N00B_MACHO_BUNDLE_NOTE_OWNER`; the
 * kind is then discriminated by the 8-byte `N00B_MACHO_CARRIER_MAGIC` at the
 * note payload's offset 0 (D-023): absent ⇒ `METADATA_RAW`; present ⇒
 * `DESCRIPTOR_LOADABLE`/`DESCRIPTOR_SPLIT` by the descriptor's `carrier_kind`;
 * short/garbled ⇒ `MALFORMED`; more than one owned note ⇒ `DUPLICATE`; none
 * owned ⇒ `NONE`.
 */
typedef enum {
    N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE,
    N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW,
    N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_LOADABLE,
    N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_SPLIT,
    N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED,
    N00B_OBJ_BUNDLE_MACHO_CARRIER_DUPLICATE,
} n00b_obj_bundle_macho_carrier_state_t;

// ============================================================================
// Backend functions
// ============================================================================

/**
 * @brief Detect and classify the Mach-O object-bundle carrier `LC_NOTE`.
 *
 * Walks the parsed binary's `LC_NOTE` load commands, identifies those owned by
 * the reserved bundle token (`data_owner == N00B_MACHO_BUNDLE_NOTE_OWNER`), and
 * classifies the carrier state per D-023. Read-only: never mutates @p bin.
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr` (current runtime allocator).
 * @return Ok(state) or Err(N00B_MACHO_CARRIER_ERR_*) when an owned carrier's
 *         descriptor bytes cannot be decoded for kind discrimination.
 * @pre `bin` is non-null.
 */
extern n00b_result_t(n00b_obj_bundle_macho_carrier_state_t)
_n00b_obj_bundle_macho_detect_carrier(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Reserved-namespace / guard check before writing a Mach-O carrier.
 *
 * Returns `N00B_OBJ_BUNDLE_ERR_OK` when a write may proceed. Rejects a present
 * N00b-owned carrier unless @p replace permits replacement
 * (`N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED`), a malformed/duplicate
 * owned carrier (`N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER`), or an existing
 * descriptor-backed carrier whose replacement is not yet supported
 * (`N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER`). The returned obj_bundle error
 * code is carried in the result's Ok payload (0 == clear to proceed); a true
 * `Err` is reserved for descriptor-decode failures during detection.
 *
 * @param bin Parsed Mach-O object.
 * @param replace Whether an existing N00b-owned carrier may be replaced.
 * @kw allocator Defaults to `nullptr` (current runtime allocator).
 * @return Ok(code) or Err(N00B_MACHO_CARRIER_ERR_*).
 * @pre `bin` is non-null.
 */
extern n00b_result_t(n00b_obj_bundle_error_code_t)
_n00b_obj_bundle_macho_check_reserved(
    n00b_macho_binary_t              *bin,
    n00b_obj_bundle_replace_policy_t  replace) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Read the raw canonical bundle bytes from a METADATA_RAW carrier.
 *
 * Locates the N00b-owned METADATA carrier `LC_NOTE` and slices its data region
 * (from the stream buffer, using the note's parsed file offset/size) into a
 * fresh buffer. The byte-extraction analogue of the ELF metadata-carrier read.
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) of canonical bundle bytes, or Err(N00B_OBJ_BUNDLE_ERR_*).
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post On success, the returned buffer is non-null and non-empty.
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_metadata(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Read+validate a descriptor-loadable carrier (WP-009).
 *
 * Locates the N00b-owned LOADABLE carrier `LC_NOTE` (data_owner ==
 * `N00B_MACHO_BUNDLE_NOTE_OWNER`), decodes its descriptor
 * (@ref n00b_macho_carrier_descriptor_decode), bounds-checks
 * `payload_file_offset + payload_len` against the carrying `LC_SEGMENT_64` file
 * extent (mirroring the ELF loadable reader), slices the payload out of the
 * stream buffer, verifies the SHA-256 digest
 * (@ref n00b_macho_carrier_verify_digest), and returns the canonical bundle
 * bytes (Hook A then decodes them). The Mach-O analog of
 * `_n00b_obj_bundle_read_elf_loadable_descriptor`.
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) of canonical bundle bytes, or Err(N00B_OBJ_BUNDLE_ERR_*) —
 *         `N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND`/`_DUPLICATE_BUNDLE_CARRIER`/
 *         `_MALFORMED_BUNDLE_CARRIER` on carrier-location/decode failure,
 *         `N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS` on a payload range past the
 *         segment/stream extent, and `N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH` on a
 *         payload digest mismatch.
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post On success, the returned buffer is non-null and non-empty.
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_loadable(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Read+validate a descriptor-split carrier and reconstruct canonical bytes.
 *
 * Locates the N00b-owned carrier `LC_NOTE` (data_owner ==
 * `N00B_MACHO_BUNDLE_NOTE_OWNER`), decodes its SPLIT descriptor
 * (@ref n00b_macho_carrier_descriptor_decode — which reads the D-040 LC_NOTE
 * trailer: `skeleton_len` + `record_count` words, the excised skeleton blob into
 * `desc->skeleton`, and the 48-byte slice records), bounds-checks the slices-only
 * segment payload range (`payload_file_offset` + `payload_len`), validates every
 * slice record (slice range within the segment payload, monotonic non-overlapping
 * `reconstruct_offset`, per-slice CRC-32 fast pre-check vs `slice_digest_crc`),
 * verifies the segment-payload SHA-256 against `desc->payload_digest`, and rebuilds
 * the canonical bundle bytes by INTERLEAVING the skeleton gaps + segment slices in
 * `reconstruct_offset` order (record-driven, not positional). The bundle-level
 * SHA-256 over the reconstructed bytes is the authoritative integrity gate; Hook A
 * re-checks it via @ref n00b_obj_bundle_decode. The Mach-O analog of
 * `_n00b_obj_bundle_read_elf_split_descriptor`.
 *
 * @param bin Parsed Mach-O object (already classified SPLIT by detect).
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) of reconstructed canonical bundle bytes (non-empty), or
 *         Err: `N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND`/`_DUPLICATE_BUNDLE_CARRIER`
 *         on carrier location failure; `N00B_MACHO_CARRIER_ERR_*` on structural
 *         reject — `_ERR_RECORD_COUNT` for a malformed trailer / record count,
 *         `_ERR_BOUNDS` for an out-of-bounds or overlapping slice / overflow, and
 *         `_ERR_DIGEST` for a segment-payload digest mismatch. Never crashes,
 *         never silently accepts.
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post On success, the returned buffer is non-null and non-empty.
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_read_split(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan a SPLIT carrier (D-040): excise the executable-compatible artifact
 *        slices from the canonical bundle into a slices-only segment payload, and
 *        build the descriptor (the excised skeleton blob + per-slice reconstruction
 *        records). Mirrors the ELF excised split.
 *
 * Selects executable-compatible artifact slices (ordered deterministically, exactly
 * as the ELF split path orders them — NFR-02), excises them to form the segment
 * payload `[slice0][slice1]…` (slices only), builds the skeleton = canonical bundle
 * with those ranges removed (concatenated gaps), one 48-byte slice record per slice
 * (each with a `slice_digest_crc` CRC-32 fast pre-check), and computes the
 * `payload_digest` SHA-256 over the slices-only segment payload. There is NO
 * skeleton record — the skeleton is a contiguous blob on `result.ok->skeleton`.
 * The returned descriptor's `payload_file_offset` is 0; the write_carrier SPLIT
 * arm sets it to the planned `LC_SEGMENT_64` file offset.
 *
 * @param bundle Decoded object bundle whose artifacts drive slice selection.
 * @param canonical_bundle Canonical object-bundle bytes.
 * @kw segment_payload_out REQUIRED; receives the slices-only segment-payload buffer
 *     that the #6 SPLIT arm lays into the LC_SEGMENT_64.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *     returned descriptor + skeleton + records + the segment payload.
 * @return Ok(descriptor) with `kind == SPLIT`, `record_count == executable_slice_count`
 *     (≥1), and `skeleton != nullptr`; or Err(N00B_MACHO_CARRIER_ERR_*):
 *     `_ERR_NULL_INPUT` for null/empty inputs, `_ERR_UNSUPPORTED_CARRIER` when the
 *     bundle has no executable-compatible artifact (mirrors the ELF "no movable
 *     payloads" path), `_ERR_BOUNDS` when a slice range overflows/runs past canonical.
 * @pre `bundle` and `canonical_bundle` are non-null; `canonical_bundle->byte_len`
 *     is nonzero; `segment_payload_out` is non-null (a genuine internal precondition,
 *     trapping `requires` — D-031 governs documented-Err *user* inputs, not this).
 * @post On success: `result.ok->kind == SPLIT`, `result.ok->record_count >= 1`,
 *     `result.ok->skeleton != nullptr`.
 */
extern n00b_result_t(n00b_macho_carrier_descriptor_t *)
_n00b_obj_bundle_macho_plan_split(
    n00b_obj_bundle_t *bundle,
    n00b_buffer_t     *canonical_bundle) _kargs {
    n00b_buffer_t   **segment_payload_out = nullptr;
    n00b_allocator_t *allocator           = nullptr;
};

/**
 * @brief Write the selected Mach-O bundle carrier into a new object buffer.
 *
 * AUTO/METADATA store the raw canonical bytes in the carrier `LC_NOTE`,
 * inserting a fresh carrier or — when @p replace permits and an owned carrier
 * already exists — replacing it, both via the WP-005/006 surgical rewrite
 * (`n00b_macho_rewrite_apply_object_bundle_insert` / `_replace`). LOADABLE
 * (WP-009) places the full canonical bundle bytes in a new read-only
 * `LC_SEGMENT_64` via the WP-006 loadable insert
 * (`n00b_macho_rewrite_plan_loadable_insert`), then records a LOADABLE carrier
 * descriptor (whose `payload_file_offset` points at the new segment's planned
 * file offset and whose digest is SHA-256 of the canonical bytes) in the carrier
 * `LC_NOTE` via the WP-005/006 metadata insert. SPLIT (D-040) stores, in the
 * carrier `LC_NOTE`, the descriptor + the EXCISED skeleton blob + the slice
 * records, and stores the concatenated executable slices (slices ONLY) in a new
 * `LC_SEGMENT_64` — the skeleton is the canonical bundle with the executable
 * slices excised (mirrors the ELF excised split). SPLIT therefore REQUIRES the
 * `.bundle` kwarg (to enumerate artifacts) and ≥1 executable slice. The host-entry
 * redirect kwargs only apply to LOADABLE/SPLIT; the METADATA path leaves them
 * unset. Re-signing is not done here (WP-011).
 *
 * @param bin Parsed Mach-O object whose stream supplies the original bytes.
 * @param canonical_bundle Canonical object-bundle bytes from the neutral core.
 * @param carrier Carrier selection (AUTO maps to METADATA for Mach-O).
 * @param replace Whether an existing N00b-owned carrier may be replaced.
 * @kw host_entry_payload_offset Offset within the payload to redirect LC_MAIN
 *     to; default none (preserve entrypoint; LOADABLE/SPLIT only).
 * @kw host_entry_size Bytes of the entrypoint target range; default 0.
 * @kw bundle The decoded object bundle; REQUIRED when `carrier == SPLIT` (drives
 *     slice excision via plan_split); ignored for METADATA/LOADABLE. Default
 *     `nullptr`.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) of rewritten Mach-O bytes, or Err(N00B_OBJ_BUNDLE_ERR_*).
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @pre `canonical_bundle` is non-null and `canonical_bundle->byte_len` is
 *      nonzero.
 * @pre A host-entry redirect requires a sized target and a LOADABLE/SPLIT
 *      carrier:
 *      `!host_entry_payload_offset.has_value
 *       || (host_entry_size != 0 && carrier is LOADABLE or SPLIT)`.
 * @pre (advisory, NOT a trapping requires — D-031) when `carrier == SPLIT`,
 *      `bundle` is non-null and has ≥1 executable-compatible artifact; a null
 *      bundle on a SPLIT request is body-guarded → Err(UNSUPPORTED_CARRIER).
 * @post On success, the output is at least as large as the input:
 *       `result.ok->byte_len >= bin->stream->buf->byte_len`.
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_carrier(
    n00b_macho_binary_t             *bin,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_carrier_t        carrier,
    n00b_obj_bundle_replace_policy_t replace) _kargs {
    n00b_option_t(uint64_t) host_entry_payload_offset = n00b_option_none(uint64_t);
    uint64_t                host_entry_size           = 0;
    n00b_obj_bundle_t      *bundle                    = nullptr;
    n00b_allocator_t       *allocator                 = nullptr;
};

/**
 * @brief Write the selected bundle carrier into a fat/universal Mach-O,
 *        producing a rewritten fat output (WP-014).
 *
 * Orchestrates the already-landed primitives — it adds no new fat machinery.
 * The fat is classified with @ref n00b_macho_fat_select under the arm64-only
 * default policy (`N00B_MACHO_FAT_SELECT_ARM64_ONLY`, D-002/D-035): the first
 * arm64 slice is a `REWRITE` target, every other slice is `PASSTHROUGH`.
 *
 * For each `REWRITE` slice the slice's on-disk bytes are detached into a fresh
 * buffer and re-parsed as a thin object via @ref n00b_macho_parse_single (so
 * `bin->fat_offset == 0`, D-034); the thin carrier engine
 * (@ref _n00b_obj_bundle_macho_write_carrier) then embeds the carrier
 * slice-relative, threading the `.bundle` kwarg (required for SPLIT, D-040).
 * Each `PASSTHROUGH` slice is copied through byte-identical (NFR-01); a `REJECT`
 * slice is a structured error. The per-slice thin buffers are then re-assembled
 * with @ref n00b_macho_refat, sourcing each slice's cputype/align from the
 * D-020 slice descriptor (`fat->slices[i]`) and its cpusubtype from the parsed
 * binary header (`fat->binaries[i]->header.cpusubtype`), since the slice
 * descriptor does not carry cpusubtype.
 *
 * @param fat Parsed fat container from @ref n00b_macho_parse (count >= 1).
 * @param canonical_bundle Canonical object-bundle bytes from the neutral core.
 * @param carrier Carrier selection (AUTO maps to METADATA for Mach-O).
 * @param replace Whether an existing N00b-owned carrier may be replaced.
 * @kw bundle The decoded object bundle; REQUIRED when `carrier == SPLIT`
 *     (drives per-slice slice excision); threaded to each REWRITE slice.
 *     Default `nullptr`.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned buffer.
 * @return Ok(buffer) of rewritten fat Mach-O bytes, or Err(N00B_OBJ_BUNDLE_ERR_*):
 *         `N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER` when the fat has no arm64
 *         (REWRITE) slice; `N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE` wrapping a
 *         per-slice carrier failure or a `-43xx` re-fat failure;
 *         `N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER` on a slice re-parse
 *         failure.
 * @pre (advisory, NOT a trapping requires — D-031) `fat`, `fat->binaries`,
 *      `fat->slices`, and `canonical_bundle` are non-null and `fat->count >= 1`;
 *      null/empty inputs are documented body-guarded `Err` returns.
 * @post On success, the output re-parses as a fat container with `fat->count`
 *       slices: the arm64 REWRITE slice(s) carry the bundle and every non-arm64
 *       slice is byte-identical to the input slice (NFR-01). On Err the Ok
 *       payload is invalid (D-028).
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_write_carrier_fat(
    n00b_macho_fat_t                *fat,
    n00b_buffer_t                   *canonical_bundle,
    n00b_obj_bundle_carrier_t        carrier,
    n00b_obj_bundle_replace_policy_t replace) _kargs {
    n00b_obj_bundle_t *bundle    = nullptr;
    n00b_allocator_t  *allocator = nullptr;
};

/**
 * @brief Select the carrier-bearing arm64 slice of a fat/universal Mach-O and
 *        return it re-parsed as a THIN binary ready for the thin read switch
 *        (WP-015).
 *
 * The read-side analogue of @ref _n00b_obj_bundle_macho_write_carrier_fat's
 * slice selection. Classifies the fat container with @ref n00b_macho_fat_select
 * under the arm64-only default policy (`N00B_MACHO_FAT_SELECT_ARM64_ONLY`,
 * D-002/D-035): the carrier lives in the arm64 slice only. The chosen
 * (`REWRITE`) slice's index is taken from the returned per-slice plan list, the
 * slice's on-disk bytes are detached into a fresh buffer
 * (`fat_carrier_detach_slice_bytes`), and those bytes are re-parsed thin via
 * @ref n00b_macho_parse_single so the returned binary's `fat_offset == 0`
 * (D-034) and the existing thin detect/per-kind read switch applies unchanged.
 *
 * This helper does NOT detect or read the carrier itself; it only isolates the
 * arm64 slice as a thin binary. Carrier detection, per-kind reading, and
 * decoding happen in the caller's existing thin read flow operating on the
 * returned binary.
 *
 * @param fat Parsed fat container from @ref n00b_macho_parse (count >= 1).
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Backs the
 *               detach buffer / re-parse and owns the returned binary's stream.
 * @return Ok(thin binary) for the arm64 carrier slice (with `fat_offset == 0`),
 *         or Err(N00B_OBJ_BUNDLE_ERR_*):
 *         `N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER` when the fat has no arm64
 *         (REWRITE) slice (fat_select NO_TARGET);
 *         `N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER` on a slice detach /
 *         re-parse failure or when the re-parsed slice has `fat_offset != 0`.
 * @pre (advisory, NOT a trapping requires — D-031) `fat`, `fat->binaries`, and
 *      `fat->slices` are non-null and `fat->count >= 1`; null/empty inputs are
 *      documented body-guarded `Err` returns.
 * @post `!result.is_ok || result.ok != nullptr`; on Ok the returned thin binary
 *       is the arm64 carrier slice with `fat_offset == 0` (D-028, D-034).
 */
extern n00b_result_t(n00b_macho_binary_t *)
_n00b_obj_bundle_macho_select_carrier_slice(n00b_macho_fat_t *fat) _kargs {
    n00b_allocator_t *allocator = nullptr;
};
