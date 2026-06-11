/**
 * @file macho_layout.h
 * @brief File and virtual-address interval model for parsed Mach-O 64 objects.
 *
 * The layout model is a structural analysis layer. It records where the parsed
 * mach_header, load-command region, each `LC_SEGMENT_64` (file and vm extents
 * separately), each section, the symtab/strtab/`__LINKEDIT` sub-regions, the
 * code-signature region, and any overlay live, but it does not decide whether
 * a later rewrite is admissible. Overlap and collision are facts, not verdicts.
 *
 * All intervals are half-open: `[start, end)`. Empty ranges are skipped.
 *
 * Mirrors `elf_layout.h` one-for-one for the Mach-O arm64 backend.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "adt/interval_tree.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/macho.h"

// ============================================================================
// Error codes
// ============================================================================

#define N00B_MACHO_LAYOUT_OK           0
#define N00B_MACHO_LAYOUT_ERR_INVALID  (-4201)
#define N00B_MACHO_LAYOUT_ERR_OVERFLOW (-4202)
#define N00B_MACHO_LAYOUT_ERR_INTERVAL (-4203)

#define N00B_MACHO_LAYOUT_NO_INDEX UINT32_MAX

// Convenience constant for the arm64 page size (OQ-4 home). Page size is a
// parameter everywhere it is used (`n00b_macho_layout_page_segment_vaddr_collision`,
// the loadable-request `vaddr_alignment`), so this is a shared default the
// WP-004 admission and WP-006 rewrite callers reference to agree on one value.
#define N00B_MACHO_ARM64_PAGE_SIZE 0x4000u

// ============================================================================
// Interval / coverage / gap kinds and supporting types
// ============================================================================

typedef enum {
    N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER,        // mach_header_64
    N00B_MACHO_LAYOUT_INTERVAL_LOAD_COMMANDS,      // the LC region after header
    N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_FILE,       // LC_SEGMENT_64 file extent
    N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_VM,         // LC_SEGMENT_64 vm extent
    N00B_MACHO_LAYOUT_INTERVAL_LINKEDIT_FILE,      // __LINKEDIT file extent
    N00B_MACHO_LAYOUT_INTERVAL_SECTION_FILE,       // one section's file bytes
    N00B_MACHO_LAYOUT_INTERVAL_SECTION_ZEROFILL,   // S_ZEROFILL (vm only)
    N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_NLIST,       // symoff..symoff+nsyms*16
    N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_STRINGS,     // stroff..stroff+strsize
    N00B_MACHO_LAYOUT_INTERVAL_DYSYMTAB_INDIRECT,  // indirect symbol table
    N00B_MACHO_LAYOUT_INTERVAL_DYLD_INFO,          // rebase/bind/export blobs
    N00B_MACHO_LAYOUT_INTERVAL_FUNCTION_STARTS,    // LC_FUNCTION_STARTS data
    N00B_MACHO_LAYOUT_INTERVAL_DATA_IN_CODE,       // LC_DATA_IN_CODE data
    N00B_MACHO_LAYOUT_INTERVAL_CHAINED_FIXUPS,     // LC_DYLD_CHAINED_FIXUPS data
    N00B_MACHO_LAYOUT_INTERVAL_CODE_SIGNATURE,     // LC_CODE_SIGNATURE region
    N00B_MACHO_LAYOUT_INTERVAL_OVERLAY,            // bytes past last modeled obj
} n00b_macho_layout_interval_kind_t;

typedef enum {
    N00B_MACHO_LAYOUT_COVERAGE_MODELED,
    N00B_MACHO_LAYOUT_COVERAGE_ZERO_PADDING,
    N00B_MACHO_LAYOUT_COVERAGE_UNKNOWN_NONZERO,
    N00B_MACHO_LAYOUT_COVERAGE_OVERLAY,
} n00b_macho_layout_coverage_kind_t;

typedef enum {
    N00B_MACHO_LAYOUT_GAP_ZERO_PADDING,
    N00B_MACHO_LAYOUT_GAP_UNKNOWN_NONZERO,
    N00B_MACHO_LAYOUT_GAP_OVERLAY,
    N00B_MACHO_LAYOUT_GAP_EOF_TAIL,
    N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED,
} n00b_macho_layout_gap_kind_t;

typedef struct n00b_macho_layout_interval {
    n00b_macho_layout_interval_kind_t kind;
    uint64_t                          start;   // half-open [start, end)
    uint64_t                          end;
    uint32_t                          index;   // segment/section/command index
    uint64_t                          flags;   // initprot/section flags, kind-specific
} n00b_macho_layout_interval_t;

typedef struct n00b_macho_layout_coverage {
    n00b_macho_layout_coverage_kind_t kind;
    uint64_t                          start;
    uint64_t                          end;
} n00b_macho_layout_coverage_t;

typedef struct n00b_macho_layout_interval_list {
    n00b_macho_layout_interval_t *items;
    uint64_t                      count;
} n00b_macho_layout_interval_list_t;

typedef struct n00b_macho_layout_collision {
    uint64_t                      start;
    uint64_t                      end;
    n00b_macho_layout_interval_t *intervals;
    uint64_t                      interval_count;
} n00b_macho_layout_collision_t;

typedef struct n00b_macho_layout_gap {
    n00b_macho_layout_gap_kind_t kind;
    uint64_t                     start;
    uint64_t                     end;
} n00b_macho_layout_gap_t;

#define n00b_macho_layout_interval_node_t \
    n00b_interval_node_t(n00b_macho_layout_interval_t)
#define n00b_macho_layout_interval_tree_t \
    n00b_interval_tree_t(n00b_macho_layout_interval_t)

typedef struct n00b_macho_layout {
    n00b_macho_layout_interval_tree_t *file_intervals;
    n00b_macho_layout_interval_tree_t *vaddr_intervals;
    n00b_macho_layout_coverage_t      *coverage;
    uint64_t                           file_size;
    uint64_t                           file_interval_count;
    uint64_t                           vaddr_interval_count;
    uint64_t                           coverage_count;
} n00b_macho_layout_t;

// ============================================================================
// Layout construction
// ============================================================================

/**
 * @brief Build structural Mach-O file and virtual-address interval trees.
 *
 * The returned layout borrows facts from @p bin but retains no pointers to its
 * segments, sections, or buffers. It does not reflect later mutations.
 *
 * @param bin Parsed single-slice Mach-O object from @ref n00b_macho_parse_single.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned layout and all interval-tree nodes.
 * @return Ok(layout) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post Every recorded interval and coverage record satisfies `start < end`.
 * @post `result.ok->file_size == bin->stream->buf->byte_len`.
 */
extern n00b_result_t(n00b_macho_layout_t *)
n00b_macho_layout_build(n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Overlap / collision / gap queries
// ============================================================================

/**
 * @brief Find any file interval overlapping `[start, end)`.
 *
 * Empty queries, and queries with no matching interval, return `Ok(none)`.
 * Overlap is a query helper only; it is not itself a rewrite-admission failure.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @return Ok(some(node)), Ok(none), or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_interval_node_t *))
n00b_macho_layout_file_overlap(n00b_macho_layout_t *layout,
                               uint64_t             start,
                               uint64_t             end);

/**
 * @brief Find any virtual-address interval overlapping `[start, end)`.
 *
 * Segment vm intervals use `vmaddr`/`vmsize`; they are intentionally separate
 * from segment file intervals. Empty/no-match queries return `Ok(none)`.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @return Ok(some(node)), Ok(none), or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_interval_node_t *))
n00b_macho_layout_vaddr_overlap(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end);

/**
 * @brief Copy all file intervals overlapping `[start, end)` in low-offset order.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned `items` array when `count > 0`.
 * @return Ok(list) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 * @post On `count > 0`, `result.ok.items` is non-null. (Array contents are
 *       test-verified.)
 */
extern n00b_result_t(n00b_macho_layout_interval_list_t)
n00b_macho_layout_file_overlaps(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Copy all virtual-address intervals overlapping `[start, end)`.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned `items` array when `count > 0`.
 * @return Ok(list) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 * @post On `count > 0`, `result.ok.items` is non-null. (Array contents are
 *       test-verified.)
 */
extern n00b_result_t(n00b_macho_layout_interval_list_t)
n00b_macho_layout_vaddr_overlaps(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Summarize factual file-interval collisions for `[start, end)`.
 *
 * This is not an admission verdict. It reports only the interval facts that
 * overlap the candidate range.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned `intervals` array when `interval_count > 0`.
 * @return Ok(summary) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 */
extern n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_file_collision(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Summarize factual virtual-address collisions for `[start, end)`.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned `intervals` array when `interval_count > 0`.
 * @return Ok(summary) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `start <= end`.
 */
extern n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_vaddr_collision(n00b_macho_layout_t *layout,
                                  uint64_t             start,
                                  uint64_t             end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the first file interval whose low offset is at or after `start`.
 *
 * This is a factual interval query; callers decide whether the next modeled
 * object makes a rewrite placement safe.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start Inclusive lower-bound search offset.
 * @return Ok(some(interval)), Ok(none), or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_interval_t))
n00b_macho_layout_next_file_interval(n00b_macho_layout_t *layout,
                                     uint64_t             start);

/**
 * @brief Summarize loadable-segment vm collisions using page-rounded low bounds.
 *
 * Each segment vm extent starts at `vmaddr` rounded down to `page_size` and
 * ends at `vmaddr + vmsize` without rounding the high address. This matches
 * loader-style mapping pressure checks where implied page space before a
 * segment is occupied but tail slack after `vmsize` may be usable.
 *
 * @param bin Parsed Mach-O object from @ref n00b_macho_parse_single.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @param page_size Page size used for low-bound rounding; must be nonzero.
 * @kw allocator Defaults to `nullptr` (current runtime allocator). Owns the
 *               returned `intervals` array when `interval_count > 0`.
 * @return Ok(summary) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `bin` is non-null.
 * @pre `page_size` is nonzero.
 * @pre `start <= end`.
 */
extern n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_page_segment_vaddr_collision(n00b_macho_binary_t *bin,
                                                uint64_t             start,
                                                uint64_t             end,
                                                uint64_t             page_size) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Find the first aligned non-modeled file range in `[start, end)`.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 * The returned gap begins at an aligned offset and runs to the end of the
 * contiguous factual gap.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start  Inclusive search offset.
 * @param end    Exclusive search offset.
 * @param min_size Required minimum gap size; nonzero.
 * @param alignment Required start alignment; `0` means `1`.
 * @return Ok(some(gap)), Ok(none), or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `min_size` is nonzero.
 * @pre `start <= end`.
 * @post On `some`, the returned gap is aligned and at least `min_size` wide:
 *       `(result.ok.value.start % (alignment ? alignment : 1)) == 0` and
 *       `result.ok.value.end - result.ok.value.start >= min_size`.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_find_file_gap(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end,
                                uint64_t             min_size,
                                uint64_t             alignment);

/**
 * @brief Find the first aligned virtual-address range not modeled as occupied.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param start  Inclusive search address.
 * @param end    Exclusive search address.
 * @param min_size Required minimum gap size; nonzero.
 * @param alignment Required start alignment; `0` means `1`.
 * @return Ok(some(gap)), Ok(none), or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `min_size` is nonzero.
 * @pre `start <= end`.
 * @post On `some`, the returned gap is aligned and at least `min_size` wide.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_find_vaddr_gap(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end,
                                 uint64_t             min_size,
                                 uint64_t             alignment);

/**
 * @brief Return the EOF-tail placement range starting at or after file size.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 *
 * @param layout Layout from @ref n00b_macho_layout_build.
 * @param min_size Required minimum tail size; nonzero.
 * @param alignment Required start alignment; `0` means `1`.
 * @return Ok(some(gap)) or Err(N00B_MACHO_LAYOUT_ERR_*).
 * @pre `layout` is non-null.
 * @pre `min_size` is nonzero.
 * @post On `some`, `result.ok.value.start >= layout->file_size`.
 */
extern n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_eof_tail_gap(n00b_macho_layout_t *layout,
                               uint64_t             min_size,
                               uint64_t             alignment);

// ============================================================================
// Enum-name / error-string helpers
// ============================================================================

/**
 * @brief Look up a human-readable string for an `N00B_MACHO_LAYOUT_ERR_*` code.
 *
 * @param err Error code returned by the Mach-O layout API.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for a Mach-O layout interval kind.
 *
 * @param kind Interval kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_interval_kind_str(n00b_macho_layout_interval_kind_t kind);

/**
 * @brief Look up a stable name for a Mach-O layout coverage kind.
 *
 * @param kind Coverage kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_coverage_kind_str(n00b_macho_layout_coverage_kind_t kind);

/**
 * @brief Look up a stable name for a Mach-O layout gap kind.
 *
 * @param kind Gap kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_gap_kind_str(n00b_macho_layout_gap_kind_t kind);

/**
 * @brief Look up a stable name for a single Mach-O segment protection flag bit.
 *
 * @param flag One `VM_PROT_*` (initprot/maxprot) flag bit.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_segment_flag_str(uint64_t flag);

/**
 * @brief Look up a stable name for a single Mach-O section flag bit.
 *
 * @param flag One section `S_*`/`S_ATTR_*` flag bit.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_layout_section_flag_str(uint64_t flag);
