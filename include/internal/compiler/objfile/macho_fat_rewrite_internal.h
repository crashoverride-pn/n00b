#pragma once

/**
 * @file macho_fat_rewrite_internal.h
 * @brief Internal seam for the Mach-O fat-rewrite layer (WP-007).
 *
 * This header is NOT part of the public `macho_fat_rewrite.h` (§8) surface. It
 * exposes the per-slice thin-bytes producer that both the orchestration
 * entrypoint (`n00b_macho_fat_rewrite`, Phase 2) and the WP-007 Phase 1
 * regression test need to drive directly: given a parsed fat container, a slice
 * index, and that slice's disposition, produce the slice's thin output bytes.
 *
 * Per D-034, a `REWRITE` slice is rewritten as a DETACHED thin object — its
 * bytes are extracted into a fresh buffer and re-parsed with
 * `n00b_macho_parse_single` so the resulting `n00b_macho_binary_t` has
 * `fat_offset == 0`, and the thin rewrite engine emits slice-relative bytes. A
 * `PASSTHROUGH` slice is copied byte-identically from the fat input buffer's
 * extent `[fat->slices[i].offset, +fat->slices[i].size)`.
 *
 * The producer never mutates the parsed fat container, its slices, or the
 * source buffer.
 */

#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_fat_rewrite.h"

/**
 * @brief Produce one slice's thin output bytes per its disposition.
 *
 * @param fat Parsed fat container.
 * @param index Slice index in `fat->binaries` / `fat->slices`.
 * @param disposition Disposition chosen by `n00b_macho_fat_select`.
 * @param carrier Thin metadata-carrier request applied to a `REWRITE` slice
 *        (may be nullptr — the slice is still re-emitted as detached thin bytes).
 * @param allocator Allocator for the returned buffer + intermediates.
 * @return Ok(thin bytes) or Err(N00B_MACHO_FAT_ERR_*).
 *
 * For `PASSTHROUGH` the result is byte-identical to the input slice extent.
 * For `REWRITE` the result is a re-parseable detached thin object (D-034);
 * with a non-null carrier the thin metadata rewrite is applied.
 * `REJECT` returns Err(N00B_MACHO_FAT_ERR_NO_TARGET_SLICE).
 *
 * @pre Advisory only (D-031): null `fat`/`fat->binaries`/`fat->slices`,
 *      `index >= fat->count`, and a `REJECT` disposition are all validated as
 *      documented `Err(...)` returns, NOT trapping preconditions.
 * @post On Ok the returned buffer is non-null.
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_macho_fat_slice_thin_bytes(
    n00b_macho_fat_t                      *fat,
    uint32_t                               index,
    n00b_macho_fat_slice_disposition_t     disposition,
    n00b_macho_rewrite_metadata_request_t *carrier,
    n00b_allocator_t                      *allocator);

/**
 * @brief Serialize thin slices into a big-endian fat/universal container.
 *
 * This is the shared re-fat serialization seam: it places each thin slice at a
 * running `2^aligns[i]`-aligned cursor, writes the big-endian `fat_header` +
 * `fat_arch[]` table (`FAT_MAGIC`), and emits each slice at its computed offset
 * (final length padded to the cursor). Both `n00b_macho_build_fat`
 * (`src/compiler/objfile/macho_build.c`, every slice align == 14, preserving
 * its historical output byte-for-byte) and `n00b_macho_refat`
 * (`src/compiler/objfile/macho_fat_rewrite.c`, per-slice alignment) call it.
 *
 * Cursor overflow, or a slice whose 2^align-padded offset/size exceeds the
 * `fat_arch` u32 field (`macho_types.h` `n00b_macho_fat_arch_t`), is reported as
 * `Err(N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW)` / `Err(N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE)`
 * rather than silently truncated (NFR-11). For the inputs `n00b_macho_build_fat`
 * historically produced (slices well under 4 GiB), the non-error output is
 * byte-identical to the pre-refactor builder.
 *
 * Defined in `src/compiler/objfile/macho_build.c` (it reuses that file's
 * `swap32_be` / `align_up` / page constant). Declared here so the fat-rewrite
 * translation unit can reuse it without widening the public §8 surface.
 *
 * @param thin_bufs Array of `count` thin slice buffers, in output order.
 * @param cputypes Per-slice CPU types (`count` entries).
 * @param cpusubtypes Per-slice CPU subtypes (`count` entries).
 * @param aligns Per-slice 2^align exponents (`count` entries).
 * @param count Number of slices; nonzero.
 * @param allocator Backs the serializer's scratch `slice_offsets`/`slice_sizes`
 *        arrays AND the serialized output buffer (may be nullptr for the default
 *        allocator). The output is produced by the object writer via
 *        `n00b_writer_new(..., .allocator = allocator)`, so the finalized fat
 *        buffer is owned by @p allocator directly, with no re-home copy
 *        (DF-007-01 / NFR-05).
 * @return Ok(fat buffer) or Err(N00B_MACHO_FAT_ERR_*).
 */
extern n00b_result_t(n00b_buffer_t *)
_n00b_macho_refat_serialize(n00b_buffer_t   **thin_bufs,
                            uint32_t         *cputypes,
                            uint32_t         *cpusubtypes,
                            uint32_t         *aligns,
                            uint32_t          count,
                            n00b_allocator_t *allocator);
