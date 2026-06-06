#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "adt/interval_tree.h"
#include "adt/result.h"
#include "adt/stack.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_layout.h"

#include "objfile_elf_casegen.h"

static n00b_elf_binary_t *
parse_case(const char *name)
{
    const n00b_test_elf_case_t *test_case = n00b_test_elf_case_by_name(name);
    assert(test_case != nullptr);

    n00b_buffer_t  *buf    = n00b_test_elf_case_generate(test_case);
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            parsed = n00b_elf_parse(stream);

    assert(n00b_result_is_ok(parsed));
    return n00b_result_get(parsed);
}

static n00b_elf_layout_t *
layout_for_case(const char *name)
{
    n00b_elf_binary_t *bin    = parse_case(name);
    auto               layout = n00b_elf_layout_build(bin);

    assert(n00b_result_is_ok(layout));
    return n00b_result_get(layout);
}

static size_t
count_kind(n00b_elf_layout_interval_tree_t *tree,
           uint64_t                         start,
           uint64_t                         end,
           n00b_elf_layout_interval_kind_t  kind)
{
    n00b_stack_t(void *) hits = n00b_stack_new(void *);
    auto                 res  = n00b_interval_search_ordered(tree,
                                                              start,
                                                              end,
                                                              &hits);

    assert(n00b_result_is_ok(res));

    size_t count = 0;
    n00b_stack_foreach(hits, p) {
        n00b_elf_layout_interval_node_t *node =
            (n00b_elf_layout_interval_node_t *)*p;

        if (node->data.kind == kind) {
            count++;
        }
    }

    n00b_stack_free(hits);
    return count;
}

static bool
coverage_has_exact(n00b_elf_layout_t              *layout,
                   n00b_elf_layout_coverage_kind_t kind,
                   uint64_t                        start,
                   uint64_t                        end)
{
    for (uint64_t i = 0; i < layout->coverage_count; i++) {
        n00b_elf_layout_coverage_t *coverage = &layout->coverage[i];

        if (coverage->kind == kind && coverage->start == start
            && coverage->end == end) {
            return true;
        }
    }

    return false;
}

static size_t
interval_list_count_kind(n00b_elf_layout_interval_list_t *list,
                         n00b_elf_layout_interval_kind_t  kind)
{
    size_t count = 0;

    for (uint64_t i = 0; i < list->count; i++) {
        if (list->items[i].kind == kind) {
            count++;
        }
    }

    return count;
}

static n00b_elf_layout_gap_t
require_file_gap(n00b_elf_layout_t *layout,
                 uint64_t           start,
                 uint64_t           end,
                 uint64_t           min_size,
                 uint64_t           alignment)
{
    auto gap = n00b_elf_layout_find_file_gap(layout,
                                             start,
                                             end,
                                             min_size,
                                             alignment);

    assert(n00b_result_is_ok(gap));
    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap);
    assert(n00b_option_is_set(gap_opt));
    return n00b_option_get(gap_opt);
}

static void
assert_no_file_gap(n00b_elf_layout_t *layout,
                   uint64_t           start,
                   uint64_t           end,
                   uint64_t           min_size,
                   uint64_t           alignment)
{
    auto gap = n00b_elf_layout_find_file_gap(layout,
                                             start,
                                             end,
                                             min_size,
                                             alignment);

    assert(n00b_result_is_ok(gap));
    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap);
    assert(!n00b_option_is_set(gap_opt));
}

static n00b_elf_layout_gap_t
require_vaddr_gap(n00b_elf_layout_t *layout,
                  uint64_t           start,
                  uint64_t           end,
                  uint64_t           min_size,
                  uint64_t           alignment)
{
    auto gap = n00b_elf_layout_find_vaddr_gap(layout,
                                              start,
                                              end,
                                              min_size,
                                              alignment);

    assert(n00b_result_is_ok(gap));
    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap);
    assert(n00b_option_is_set(gap_opt));
    return n00b_option_get(gap_opt);
}

static void
assert_no_vaddr_gap(n00b_elf_layout_t *layout,
                    uint64_t           start,
                    uint64_t           end,
                    uint64_t           min_size,
                    uint64_t           alignment)
{
    auto gap = n00b_elf_layout_find_vaddr_gap(layout,
                                              start,
                                              end,
                                              min_size,
                                              alignment);

    assert(n00b_result_is_ok(gap));
    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap);
    assert(!n00b_option_is_set(gap_opt));
}

static void
assert_empty_file_overlap(n00b_elf_layout_t *layout,
                          uint64_t           start,
                          uint64_t           end)
{
    auto found = n00b_elf_layout_file_overlap(layout, start, end);

    assert(n00b_result_is_ok(found));
    n00b_option_t(n00b_elf_layout_interval_node_t *) node_opt =
        n00b_result_get(found);
    assert(!n00b_option_is_set(node_opt));
}

static n00b_elf_layout_interval_node_t *
require_file_overlap(n00b_elf_layout_t *layout,
                     uint64_t           start,
                     uint64_t           end)
{
    auto found = n00b_elf_layout_file_overlap(layout, start, end);

    assert(n00b_result_is_ok(found));
    n00b_option_t(n00b_elf_layout_interval_node_t *) node_opt =
        n00b_result_get(found);
    assert(n00b_option_is_set(node_opt));
    return n00b_option_get(node_opt);
}

static n00b_elf_layout_interval_node_t *
require_vaddr_overlap(n00b_elf_layout_t *layout,
                      uint64_t           start,
                      uint64_t           end)
{
    auto found = n00b_elf_layout_vaddr_overlap(layout, start, end);

    assert(n00b_result_is_ok(found));
    n00b_option_t(n00b_elf_layout_interval_node_t *) node_opt =
        n00b_result_get(found);
    assert(n00b_option_is_set(node_opt));
    return n00b_option_get(node_opt);
}

static void
test_valid_minimal_exec_layout(void)
{
    n00b_elf_layout_t *layout = layout_for_case("valid_minimal_exec");

    assert(layout->file_size == 512);
    assert(layout->file_interval_count == 7);
    assert(layout->vaddr_interval_count == 1);
    assert(layout->coverage_count == 1);

    assert(count_kind(layout->file_intervals,
                      0,
                      64,
                      N00B_ELF_LAYOUT_INTERVAL_ELF_HEADER) == 1);
    assert(count_kind(layout->file_intervals,
                      64,
                      120,
                      N00B_ELF_LAYOUT_INTERVAL_PHTAB) == 1);
    assert(count_kind(layout->file_intervals,
                      256,
                      384,
                      N00B_ELF_LAYOUT_INTERVAL_SHTAB) == 1);
    assert(count_kind(layout->file_intervals,
                      384,
                      395,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE) == 1);
    assert(count_kind(layout->file_intervals,
                      0,
                      512,
                      N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 1);
    assert(count_kind(layout->vaddr_intervals,
                      0x400000,
                      0x400200,
                      N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY) == 1);
    assert(count_kind(layout->file_intervals,
                      384,
                      395,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE) == 1);
    assert(count_kind(layout->file_intervals,
                      384,
                      395,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE) == 1);
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_MODELED,
                              0,
                              512));

    assert_empty_file_overlap(layout, 512, 528);

    printf("  [PASS] valid_minimal_exec_layout\n");
}

static void
test_overlay_after_segments(void)
{
    n00b_elf_layout_t *layout = layout_for_case("overlay_after_segments");

    assert(layout->file_size == 528);
    assert(layout->file_interval_count == 8);
    assert(layout->coverage_count == 2);
    assert(count_kind(layout->file_intervals,
                      512,
                      528,
                      N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 0);
    assert(count_kind(layout->file_intervals,
                      512,
                      528,
                      N00B_ELF_LAYOUT_INTERVAL_OVERLAY) == 1);

    n00b_elf_layout_interval_node_t *found =
        require_file_overlap(layout, 512, 528);
    assert(found->data.kind == N00B_ELF_LAYOUT_INTERVAL_OVERLAY);
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_MODELED,
                              0,
                              512));
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_OVERLAY,
                              512,
                              528));

    printf("  [PASS] overlay_after_segments\n");
}

static void
test_segment_memory_is_separate_from_file_bytes(void)
{
    n00b_elf_layout_t *layout = layout_for_case("entry_in_mem_not_file");

    assert(count_kind(layout->file_intervals,
                      0x101,
                      0x102,
                      N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 0);
    assert(count_kind(layout->vaddr_intervals,
                      0x400101,
                      0x400102,
                      N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY) == 1);

    n00b_elf_layout_interval_node_t *found =
        require_vaddr_overlap(layout, 0x400101, 0x400102);
    assert(found->data.kind == N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY);

    printf("  [PASS] segment_memory_is_separate_from_file_bytes\n");
}

static void
test_half_open_section_boundary(void)
{
    n00b_elf_layout_t *layout = layout_for_case("valid_minimal_exec");

    assert(count_kind(layout->file_intervals,
                      394,
                      395,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE) == 1);
    assert(count_kind(layout->file_intervals,
                      395,
                      396,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE) == 0);

    auto empty = n00b_elf_layout_file_overlap(layout, 395, 395);
    assert(n00b_result_is_ok(empty));
    n00b_option_t(n00b_elf_layout_interval_node_t *) node_opt =
        n00b_result_get(empty);
    assert(!n00b_option_is_set(node_opt));

    printf("  [PASS] half_open_section_boundary\n");
}

static void
test_specialized_interval_classification(void)
{
    n00b_elf_layout_t *layout = layout_for_case("layout_classification");

    assert(layout->file_size == 1152);
    assert(count_kind(layout->file_intervals,
                      320,
                      374,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE) == 1);
    assert(count_kind(layout->file_intervals,
                      320,
                      374,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE) == 1);
    assert(count_kind(layout->file_intervals,
                      384,
                      400,
                      N00B_ELF_LAYOUT_INTERVAL_SYMBOL_STRING_TABLE) == 1);
    assert(count_kind(layout->file_intervals,
                      416,
                      432,
                      N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE) == 1);
    assert(count_kind(layout->file_intervals,
                      240,
                      256,
                      N00B_ELF_LAYOUT_INTERVAL_INTERPRETER_STRING) == 1);
    assert(count_kind(layout->file_intervals,
                      256,
                      288,
                      N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE) == 2);
    assert(count_kind(layout->vaddr_intervals,
                      0x400600,
                      0x400620,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY) == 1);
    assert(count_kind(layout->file_intervals,
                      576,
                      608,
                      N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY) == 0);
    assert_empty_file_overlap(layout, 576, 608);

    printf("  [PASS] specialized_interval_classification\n");
}

static void
test_coverage_classification(void)
{
    n00b_elf_layout_t *layout = layout_for_case("layout_classification");

    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_MODELED,
                              0,
                              232));
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING,
                              232,
                              240));
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_MODELED,
                              240,
                              288));
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING,
                              288,
                              320));
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING,
                              560,
                              640));

    layout = layout_for_case("layout_nonzero_unknown");
    assert(coverage_has_exact(layout,
                              N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO,
                              288,
                              320));

    printf("  [PASS] coverage_classification\n");
}

static void
test_ordered_overlaps_and_collisions(void)
{
    n00b_elf_layout_t *layout = layout_for_case("layout_classification");

    auto file_overlaps = n00b_elf_layout_file_overlaps(layout, 256, 288);
    assert(n00b_result_is_ok(file_overlaps));
    n00b_elf_layout_interval_list_t file_list =
        n00b_result_get(file_overlaps);

    assert(file_list.count == 4);
    assert(interval_list_count_kind(
               &file_list,
               N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE) == 1);
    assert(interval_list_count_kind(
               &file_list,
               N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 1);
    assert(interval_list_count_kind(
               &file_list,
               N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE) == 2);
    for (uint64_t i = 1; i < file_list.count; i++) {
        assert(file_list.items[i - 1].start <= file_list.items[i].start);
    }

    auto file_collision = n00b_elf_layout_file_collision(layout, 256, 288);
    assert(n00b_result_is_ok(file_collision));
    n00b_elf_layout_collision_t collision =
        n00b_result_get(file_collision);
    assert(collision.start == 256);
    assert(collision.end == 288);
    assert(collision.interval_count == file_list.count);
    assert(interval_list_count_kind(
               &(n00b_elf_layout_interval_list_t){
                   .items = collision.intervals,
                   .count = collision.interval_count,
               },
               N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE) == 2);

    auto vaddr_overlaps = n00b_elf_layout_vaddr_overlaps(layout,
                                                         0x400600,
                                                         0x400620);
    assert(n00b_result_is_ok(vaddr_overlaps));
    n00b_elf_layout_interval_list_t vaddr_list =
        n00b_result_get(vaddr_overlaps);
    assert(vaddr_list.count == 1);
    assert(vaddr_list.items[0].kind
           == N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY);

    auto vaddr_collision = n00b_elf_layout_vaddr_collision(layout,
                                                           0x400600,
                                                           0x400620);
    assert(n00b_result_is_ok(vaddr_collision));
    collision = n00b_result_get(vaddr_collision);
    assert(collision.interval_count == 1);
    assert(collision.intervals[0].kind
           == N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY);

    printf("  [PASS] ordered_overlaps_and_collisions\n");
}

static void
test_file_gap_queries(void)
{
    n00b_elf_layout_t   *layout = layout_for_case("layout_classification");
    n00b_elf_layout_gap_t gap   = require_file_gap(layout, 0, 1152, 8, 8);

    assert(gap.kind == N00B_ELF_LAYOUT_GAP_ZERO_PADDING);
    assert(gap.start == 232);
    assert(gap.end == 240);

    gap = require_file_gap(layout, 288, 320, 4, 16);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_ZERO_PADDING);
    assert(gap.start == 288);
    assert(gap.end == 320);

    layout = layout_for_case("layout_nonzero_unknown");
    gap    = require_file_gap(layout, 288, 320, 4, 16);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO);
    assert(gap.start == 288);
    assert(gap.end == 320);

    layout = layout_for_case("overlay_after_segments");
    gap    = require_file_gap(layout, 512, 528, 8, 1);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_OVERLAY);
    assert(gap.start == 512);
    assert(gap.end == 528);

    layout = layout_for_case("layout_classification");
    gap    = require_file_gap(layout, 1152, 1200, 16, 16);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_EOF_TAIL);
    assert(gap.start == 1152);
    assert(gap.end == 1200);

    auto eof_gap = n00b_elf_layout_eof_tail_gap(layout, 32, 64);
    assert(n00b_result_is_ok(eof_gap));
    n00b_option_t(n00b_elf_layout_gap_t) eof_gap_opt =
        n00b_result_get(eof_gap);
    assert(n00b_option_is_set(eof_gap_opt));
    gap = n00b_option_get(eof_gap_opt);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_EOF_TAIL);
    assert(gap.start == 1152);
    assert(gap.end == 1184);

    layout = layout_for_case("valid_minimal_exec");
    assert_no_file_gap(layout, 0, 512, 1, 1);

    auto invalid = n00b_elf_layout_find_file_gap(layout, 0, 512, 0, 1);
    assert(n00b_result_is_err(invalid));
    assert(n00b_result_get_err(invalid) == N00B_ELF_LAYOUT_ERR_INVALID);

    printf("  [PASS] file_gap_queries\n");
}

static void
test_vaddr_gap_queries(void)
{
    n00b_elf_layout_t   *layout = layout_for_case("layout_classification");
    n00b_elf_layout_gap_t gap =
        require_vaddr_gap(layout, 0x4000e8, 0x4000f0, 8, 8);

    assert(gap.kind == N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED);
    assert(gap.start == 0x4000e8);
    assert(gap.end == 0x4000f0);

    gap = require_vaddr_gap(layout, 0x400580, 0x400640, 0x20, 0x20);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED);
    assert(gap.start == 0x400580);
    assert(gap.end == 0x400600);

    assert_no_vaddr_gap(layout, 0x400600, 0x400620, 1, 1);

    auto invalid = n00b_elf_layout_find_vaddr_gap(layout,
                                                  0x400620,
                                                  0x400600,
                                                  1,
                                                  1);
    assert(n00b_result_is_err(invalid));
    assert(n00b_result_get_err(invalid) == N00B_ELF_LAYOUT_ERR_INVALID);

    printf("  [PASS] vaddr_gap_queries\n");
}

static void
test_phtab_adjustment_layout_helpers(void)
{
    n00b_elf_binary_t *bin = parse_case("phtab_adjust_accepted");
    n00b_elf_layout_t *layout = layout_for_case("phtab_adjust_accepted");

    auto next = n00b_elf_layout_next_file_interval(layout, 200);
    assert(n00b_result_is_ok(next));
    n00b_option_t(n00b_elf_layout_interval_t) next_opt =
        n00b_result_get(next);
    assert(n00b_option_is_set(next_opt));
    n00b_elf_layout_interval_t interval = n00b_option_get(next_opt);
    assert(interval.start == 512);
    assert(interval.kind == N00B_ELF_LAYOUT_INTERVAL_SHTAB);

    auto collision = n00b_elf_layout_page_load_vaddr_collision(bin,
                                                               0x4000c8,
                                                               0x400170,
                                                               0x1000);
    assert(n00b_result_is_ok(collision));
    assert(n00b_result_get(collision).interval_count == 0);

    bin = parse_case("phtab_adjust_memory_collision");
    collision = n00b_elf_layout_page_load_vaddr_collision(bin,
                                                          0x4000f0,
                                                          0x4001d0,
                                                          0x1000);
    assert(n00b_result_is_ok(collision));
    n00b_elf_layout_collision_t facts = n00b_result_get(collision);
    assert(facts.interval_count == 1);
    assert(facts.intervals[0].index == 2);
    assert(facts.intervals[0].start == 0x400000);
    assert(facts.intervals[0].end == 0x400880);

    bin = parse_case("phtab_adjust_accepted");
    bin->num_segments       = 1;
    bin->segments[0].type   = PT_LOAD;
    bin->segments[0].offset = 0x20;
    bin->segments[0].vaddr  = 0x401123;
    bin->segments[0].memsz  = 0;
    collision = n00b_elf_layout_page_load_vaddr_collision(bin,
                                                          0x401000,
                                                          0x401124,
                                                          0x1000);
    assert(n00b_result_is_ok(collision));
    facts = n00b_result_get(collision);
    assert(facts.interval_count == 1);
    assert(facts.intervals[0].start == 0x401000);
    assert(facts.intervals[0].end == 0x401123);

    bin->segments[0].offset = 0;
    collision = n00b_elf_layout_page_load_vaddr_collision(bin,
                                                          0x401000,
                                                          0x401124,
                                                          0x1000);
    assert(n00b_result_is_ok(collision));
    assert(n00b_result_get(collision).interval_count == 0);

    printf("  [PASS] phtab_adjustment_layout_helpers\n");
}

static void
test_overflow_failure_is_deterministic(void)
{
    n00b_elf_binary_t *bin = parse_case("valid_minimal_exec");

    bin->segments[0].offset = UINT64_MAX - 1;
    bin->segments[0].filesz = 4;

    auto layout = n00b_elf_layout_build(bin);
    assert(n00b_result_is_err(layout));
    assert(n00b_result_get_err(layout) == N00B_ELF_LAYOUT_ERR_OVERFLOW);

    printf("  [PASS] overflow_failure_is_deterministic\n");
}

static void
test_layout_error_strings(void)
{
    assert(n00b_elf_layout_err_str(N00B_ELF_LAYOUT_ERR_INVALID)->u8_bytes > 0);
    assert(n00b_elf_layout_err_str(N00B_ELF_LAYOUT_ERR_OVERFLOW)->u8_bytes > 0);
    assert(n00b_elf_layout_err_str(N00B_ELF_LAYOUT_ERR_INTERVAL)->u8_bytes > 0);
    assert(n00b_elf_layout_err_str(-1)->u8_bytes > 0);
    assert(n00b_elf_layout_interval_kind_str(
               N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE)->u8_bytes > 0);
    assert(n00b_elf_layout_interval_kind_str(-1)->u8_bytes > 0);
    assert(n00b_elf_layout_coverage_kind_str(
               N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO)->u8_bytes > 0);
    assert(n00b_elf_layout_coverage_kind_str(-1)->u8_bytes > 0);
    assert(n00b_elf_layout_gap_kind_str(
               N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED)->u8_bytes > 0);
    assert(n00b_elf_layout_gap_kind_str(-1)->u8_bytes > 0);
    assert(n00b_elf_layout_section_flag_str(SHF_ALLOC)->u8_bytes > 0);
    assert(n00b_elf_layout_section_flag_str(UINT64_MAX)->u8_bytes > 0);
    assert(n00b_elf_layout_segment_flag_str(PF_R)->u8_bytes > 0);
    assert(n00b_elf_layout_segment_flag_str(UINT64_MAX)->u8_bytes > 0);

    printf("  [PASS] layout_error_strings\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running ELF layout tests...\n");
    test_valid_minimal_exec_layout();
    test_overlay_after_segments();
    test_segment_memory_is_separate_from_file_bytes();
    test_half_open_section_boundary();
    test_specialized_interval_classification();
    test_coverage_classification();
    test_ordered_overlaps_and_collisions();
    test_file_gap_queries();
    test_vaddr_gap_queries();
    test_phtab_adjustment_layout_helpers();
    test_overflow_failure_is_deterministic();
    test_layout_error_strings();
    printf("All ELF layout tests passed.\n");
    return 0;
}
