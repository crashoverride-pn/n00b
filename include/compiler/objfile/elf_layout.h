/**
 * @file elf_layout.h
 * @brief File and virtual-address interval model for parsed ELF64 objects.
 *
 * The layout model is a structural analysis layer. It records where the
 * parsed ELF header, tables, sections, segments, and overlay bytes live, but
 * it does not decide whether a later rewrite is admissible.
 *
 * All intervals are half-open: `[start, end)`. Empty ranges are skipped.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "adt/interval_tree.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/elf.h"

#define N00B_ELF_LAYOUT_OK           0
#define N00B_ELF_LAYOUT_ERR_INVALID  (-3401)
#define N00B_ELF_LAYOUT_ERR_OVERFLOW (-3402)
#define N00B_ELF_LAYOUT_ERR_INTERVAL (-3403)

#define N00B_ELF_LAYOUT_NO_INDEX UINT32_MAX

typedef enum {
    N00B_ELF_LAYOUT_INTERVAL_ELF_HEADER,
    N00B_ELF_LAYOUT_INTERVAL_PHTAB,
    N00B_ELF_LAYOUT_INTERVAL_SHTAB,
    N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE,
    N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE,
    N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE,
    N00B_ELF_LAYOUT_INTERVAL_SYMBOL_STRING_TABLE,
    N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE,
    N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE,
    N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY,
    N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY,
    N00B_ELF_LAYOUT_INTERVAL_INTERPRETER_STRING,
    N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE,
    N00B_ELF_LAYOUT_INTERVAL_OVERLAY,
} n00b_elf_layout_interval_kind_t;

typedef enum {
    N00B_ELF_LAYOUT_COVERAGE_MODELED,
    N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING,
    N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO,
    N00B_ELF_LAYOUT_COVERAGE_OVERLAY,
} n00b_elf_layout_coverage_kind_t;

typedef enum {
    N00B_ELF_LAYOUT_GAP_ZERO_PADDING,
    N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO,
    N00B_ELF_LAYOUT_GAP_OVERLAY,
    N00B_ELF_LAYOUT_GAP_EOF_TAIL,
    N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED,
} n00b_elf_layout_gap_kind_t;

typedef struct n00b_elf_layout_interval {
    n00b_elf_layout_interval_kind_t kind;
    uint64_t                        start;
    uint64_t                        end;
    uint32_t                        index;
    uint64_t                        flags;
} n00b_elf_layout_interval_t;

typedef struct n00b_elf_layout_coverage {
    n00b_elf_layout_coverage_kind_t kind;
    uint64_t                        start;
    uint64_t                        end;
} n00b_elf_layout_coverage_t;

typedef struct n00b_elf_layout_interval_list {
    n00b_elf_layout_interval_t *items;
    uint64_t                    count;
} n00b_elf_layout_interval_list_t;

typedef struct n00b_elf_layout_collision {
    uint64_t                    start;
    uint64_t                    end;
    n00b_elf_layout_interval_t *intervals;
    uint64_t                    interval_count;
} n00b_elf_layout_collision_t;

typedef struct n00b_elf_layout_gap {
    n00b_elf_layout_gap_kind_t kind;
    uint64_t                   start;
    uint64_t                   end;
} n00b_elf_layout_gap_t;

#define n00b_elf_layout_interval_node_t \
    n00b_interval_node_t(n00b_elf_layout_interval_t)
#define n00b_elf_layout_interval_tree_t \
    n00b_interval_tree_t(n00b_elf_layout_interval_t)

typedef struct n00b_elf_layout {
    n00b_elf_layout_interval_tree_t *file_intervals;
    n00b_elf_layout_interval_tree_t *vaddr_intervals;
    n00b_elf_layout_coverage_t      *coverage;
    uint64_t                         file_size;
    uint64_t                         file_interval_count;
    uint64_t                         vaddr_interval_count;
    uint64_t                         coverage_count;
} n00b_elf_layout_t;

/**
 * @brief Build structural ELF file and virtual-address interval trees.
 *
 * The returned layout borrows facts from `bin` but does not retain pointers to
 * sections, segments, or buffers. It may therefore outlive local mutations to
 * those parsed arrays, but it will not reflect later mutations.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned layout and interval tree nodes.
 *
 * @return Ok(layout) or Err(N00B_ELF_LAYOUT_ERR_*).
 *
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post Every recorded interval and coverage record satisfies `start < end`.
 */
extern n00b_result_t(n00b_elf_layout_t *)
n00b_elf_layout_build(n00b_elf_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Find any file interval overlapping `[start, end)`.
 *
 * Empty queries, and queries with no matching interval, return `Ok(none)`.
 * This is a query helper only; overlap is not itself a rewrite-admission
 * failure.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 *
 * @return Ok(some(node)), Ok(none), or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_interval_node_t *))
n00b_elf_layout_file_overlap(n00b_elf_layout_t *layout,
                             uint64_t           start,
                             uint64_t           end);

/**
 * @brief Find any virtual-address interval overlapping `[start, end)`.
 *
 * Empty queries, and queries with no matching interval, return `Ok(none)`.
 * Segment memory intervals use `p_vaddr`
 * and `p_memsz`; they are intentionally separate from segment file intervals.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 *
 * @return Ok(some(node)), Ok(none), or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_interval_node_t *))
n00b_elf_layout_vaddr_overlap(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end);

/**
 * @brief Copy all file intervals overlapping `[start, end)` in low-offset order.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned `items` array when `count > 0`.
 *
 * @return Ok(list) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_elf_layout_interval_list_t)
n00b_elf_layout_file_overlaps(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Copy all virtual-address intervals overlapping `[start, end)`.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned `items` array when `count > 0`.
 *
 * @return Ok(list) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_elf_layout_interval_list_t)
n00b_elf_layout_vaddr_overlaps(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Summarize factual file-interval collisions for `[start, end)`.
 *
 * This is not an admission verdict. It reports only the interval facts that
 * overlap the candidate range.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive file offset.
 * @param end Exclusive file offset.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned `intervals` array when
 *               `interval_count > 0`.
 *
 * @return Ok(summary) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_file_collision(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Summarize factual virtual-address collisions for `[start, end)`.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned `intervals` array when
 *               `interval_count > 0`.
 *
 * @return Ok(summary) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_vaddr_collision(n00b_elf_layout_t *layout,
                                uint64_t           start,
                                uint64_t           end) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the first file interval whose low offset is at or after `start`.
 *
 * This is a factual interval query; callers decide whether the next modeled
 * object makes a rewrite placement safe.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive lower-bound search offset.
 *
 * @return Ok(some(interval)), Ok(none), or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_interval_t))
n00b_elf_layout_next_file_interval(n00b_elf_layout_t *layout,
                                   uint64_t           start);

/**
 * @brief Summarize `PT_LOAD` memory collisions using page-rounded low bounds.
 *
 * Each `PT_LOAD` interval starts at `p_vaddr` rounded down to `page_size` and
 * ends at `p_vaddr + p_memsz` without rounding the high address. This matches
 * loader-style mapping pressure checks where implied page space before a
 * segment is occupied but tail slack after `p_memsz` may be usable.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param start Inclusive virtual address.
 * @param end Exclusive virtual address.
 * @param page_size Page size used for low-bound rounding; must be nonzero.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned `intervals` array when
 *               `interval_count > 0`.
 *
 * @return Ok(summary) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_page_load_vaddr_collision(n00b_elf_binary_t *bin,
                                          uint64_t           start,
                                          uint64_t           end,
                                          uint64_t           page_size) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Find the first aligned non-modeled file range in `[start, end)`.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 * The returned gap range begins at an aligned offset and extends to the end of
 * the contiguous factual gap. The kind distinguishes zero padding, unknown
 * nonzero bytes, overlay, and EOF tail.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive search offset.
 * @param end Exclusive search offset.
 * @param min_size Required minimum gap size.
 * @param alignment Required start alignment; `0` means `1`.
 *
 * @return Ok(some(gap)), Ok(none), or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_find_file_gap(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end,
                              uint64_t           min_size,
                              uint64_t           alignment);

/**
 * @brief Find the first aligned virtual-address range not modeled as occupied.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param start Inclusive search address.
 * @param end Exclusive search address.
 * @param min_size Required minimum gap size.
 * @param alignment Required start alignment; `0` means `1`.
 *
 * @return Ok(some(gap)), Ok(none), or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_find_vaddr_gap(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end,
                               uint64_t           min_size,
                               uint64_t           alignment);

/**
 * @brief Return the EOF-tail placement range starting at or after file size.
 *
 * `min_size` must be nonzero. `alignment == 0` is treated as byte alignment.
 *
 * @param layout Layout returned by @ref n00b_elf_layout_build.
 * @param min_size Required minimum tail size.
 * @param alignment Required start alignment; `0` means `1`.
 *
 * @return Ok(some(gap)) or Err(N00B_ELF_LAYOUT_ERR_*).
 */
extern n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_eof_tail_gap(n00b_elf_layout_t *layout,
                             uint64_t           min_size,
                             uint64_t           alignment);

/**
 * @brief Look up a human-readable string for an `N00B_ELF_LAYOUT_ERR_*`
 *        error code.
 *
 * @param err Error code returned by the ELF layout API.
 *
 * @return A process-lifetime string literal. Unknown codes return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for an ELF layout interval kind.
 *
 * @param kind Interval kind value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_interval_kind_str(n00b_elf_layout_interval_kind_t kind);

/**
 * @brief Look up a stable name for an ELF layout coverage kind.
 *
 * @param kind Coverage kind value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_coverage_kind_str(n00b_elf_layout_coverage_kind_t kind);

/**
 * @brief Look up a stable name for an ELF layout gap kind.
 *
 * @param kind Gap kind value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_gap_kind_str(n00b_elf_layout_gap_kind_t kind);

/**
 * @brief Look up a stable name for a single ELF section flag bit.
 *
 * @param flag One `SHF_*` flag bit.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_section_flag_str(uint64_t flag);

/**
 * @brief Look up a stable name for a single ELF segment flag bit.
 *
 * @param flag One `PF_*` flag bit.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_layout_segment_flag_str(uint64_t flag);
