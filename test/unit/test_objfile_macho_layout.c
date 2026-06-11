#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "n00b.h"
#include "adt/interval_tree.h"
#include "adt/result.h"
#include "adt/stack.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_layout.h"
#include "text/strings/string_ops.h"

// WP-003 Phase 1 known-answer tests. Deterministic, host-neutral, always-run
// (no Darwin/codesign gate, D-006). The committed fixtures are resolved via
// MESON_SOURCE_ROOT (wired in meson for this target), mirroring the
// resolution pattern in test_objfile_macho.c.

// Resolve a committed fixture path under test/unit/data, trying
// MESON_SOURCE_ROOT first, then a project-root-relative path. Returns a
// parsed single-slice binary, or nullptr if the fixture cannot be opened
// (caller [SKIP]s — e.g. the committed fixture is absent on this checkout).
static n00b_macho_binary_t *
parse_fixture(const char *rel)
{
    n00b_bstream_t *stream = nullptr;
    const char     *root   = getenv("MESON_SOURCE_ROOT");
    char            path[1024];

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            auto r = n00b_bstream_from_file(path);
            if (n00b_result_is_ok(r)) {
                stream = n00b_result_get(r);
            }
        }
    }

    if (stream == nullptr) {
        auto r = n00b_bstream_from_file(rel);
        if (n00b_result_is_ok(r)) {
            stream = n00b_result_get(r);
        }
    }

    if (stream == nullptr) {
        return nullptr;
    }

    auto parsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(parsed)) {
        return nullptr;
    }

    return n00b_result_get(parsed);
}

static size_t
count_kind(n00b_macho_layout_interval_tree_t *tree,
           uint64_t                           start,
           uint64_t                           end,
           n00b_macho_layout_interval_kind_t  kind)
{
    n00b_stack_t(void *) hits = n00b_stack_new(void *);
    auto                 res  = n00b_interval_search_ordered(tree,
                                                             start,
                                                             end,
                                                             &hits);

    assert(n00b_result_is_ok(res));

    size_t count = 0;
    n00b_stack_foreach(hits, p) {
        n00b_macho_layout_interval_node_t *node =
            (n00b_macho_layout_interval_node_t *)*p;

        if (node->data.kind == kind) {
            count++;
        }
    }

    n00b_stack_free(hits);
    return count;
}

// Sum of non-zerofill sections across all segments — the file-tree
// SECTION_FILE interval count should match this.
static uint64_t
nonzerofill_section_count(n00b_macho_binary_t *bin)
{
    uint64_t total = 0;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        for (uint32_t j = 0; j < seg->nsects; j++) {
            uint32_t type = seg->sections[j].flags & SECTION_TYPE;
            if (type != S_ZEROFILL) {
                total++;
            }
        }
    }

    return total;
}

// P1-a: hello.macho — header [0,32), a LOAD_COMMANDS interval, at least one
// SEGMENT_FILE and matching SEGMENT_VM, and a SECTION_FILE count matching the
// parsed non-zerofill section sum.
static void
test_hello_layout(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] hello_layout (fixture test/unit/data/hello.macho "
               "not found)\n");
        return;
    }

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    // Postcondition shadow: file_size tracks the backing buffer length.
    assert(layout->file_size == (uint64_t)n00b_buffer_len(bin->stream->buf));

    // mach_header_64 is exactly [0, 32).
    assert(count_kind(layout->file_intervals,
                      0,
                      N00B_MACHO_HEADER_64_SIZE,
                      N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER)
           == 1);

    // The header interval ends precisely at offset 32 (half-open).
    assert(count_kind(layout->file_intervals,
                      N00B_MACHO_HEADER_64_SIZE,
                      N00B_MACHO_HEADER_64_SIZE + 1,
                      N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER)
           == 0);

    // The load-command region begins right after the header.
    uint64_t lc_end = (uint64_t)N00B_MACHO_HEADER_64_SIZE
                      + (uint64_t)bin->header.sizeofcmds;
    assert(count_kind(layout->file_intervals,
                      N00B_MACHO_HEADER_64_SIZE,
                      lc_end,
                      N00B_MACHO_LAYOUT_INTERVAL_LOAD_COMMANDS)
           == 1);

    // At least one segment file extent and one segment vm extent.
    assert(count_kind(layout->file_intervals,
                      0,
                      layout->file_size,
                      N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_FILE)
           >= 1);
    assert(count_kind(layout->vaddr_intervals,
                      0,
                      UINT64_MAX,
                      N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_VM)
           >= 1);

    // SECTION_FILE intervals match the parsed non-zerofill section count.
    uint64_t expected_sections = nonzerofill_section_count(bin);
    assert(count_kind(layout->file_intervals,
                      0,
                      layout->file_size,
                      N00B_MACHO_LAYOUT_INTERVAL_SECTION_FILE)
           == expected_sections);

    printf("  [PASS] hello_layout\n");
}

// P1-b: signed fixture — a CODE_SIGNATURE interval whose [start, end) matches
// bin->code_signature->{dataoff, dataoff + datasize}.
static void
test_signed_code_signature_interval(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_signed_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] signed_code_signature_interval (committed fixture "
               "test/unit/data/hello_signed_arm64.macho not found)\n");
        return;
    }

    // The signed fixture must carry a code signature for this assertion.
    assert(bin->code_signature != nullptr);

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    uint64_t cs_start = (uint64_t)bin->code_signature->dataoff;
    uint64_t cs_end   = cs_start + (uint64_t)bin->code_signature->datasize;

    // Exactly one CODE_SIGNATURE interval covering the signature range.
    assert(count_kind(layout->file_intervals,
                      cs_start,
                      cs_end,
                      N00B_MACHO_LAYOUT_INTERVAL_CODE_SIGNATURE)
           == 1);

    // Locate the node and confirm its [start, end) matches the parsed region.
    n00b_stack_t(void *) hits = n00b_stack_new(void *);
    auto                 res  = n00b_interval_search_ordered(layout
                                                                 ->file_intervals,
                                                             cs_start,
                                                             cs_end,
                                                             &hits);
    assert(n00b_result_is_ok(res));

    bool found = false;
    n00b_stack_foreach(hits, p) {
        n00b_macho_layout_interval_node_t *node =
            (n00b_macho_layout_interval_node_t *)*p;

        if (node->data.kind == N00B_MACHO_LAYOUT_INTERVAL_CODE_SIGNATURE) {
            assert(node->data.start == cs_start);
            assert(node->data.end == cs_end);
            found = true;
        }
    }
    n00b_stack_free(hits);
    assert(found);

    printf("  [PASS] signed_code_signature_interval\n");
}

// P1-c: a crafted overflowing segment file extent → Err(...OVERFLOW).
static void
test_overflow_is_deterministic(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] overflow_is_deterministic (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    assert(bin->num_segments >= 1);

    // Force fileoff + filesize to overflow uint64.
    bin->segments[0].fileoff  = UINT64_MAX - 1;
    bin->segments[0].filesize = 4;

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_err(layout_r));
    assert(n00b_result_get_err(layout_r) == N00B_MACHO_LAYOUT_ERR_OVERFLOW);

    printf("  [PASS] overflow_is_deterministic\n");
}

// P2-a: hello.macho — coverage tiles [0, file_size) with no holes and no
// UNKNOWN_NONZERO run (the parsed object models every byte).
static void
test_coverage_contiguous(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] coverage_contiguous (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    // At least one coverage run, tiling [0, file_size) contiguously.
    assert(layout->coverage_count >= 1);
    assert(layout->coverage[0].start == 0);

    uint64_t cursor = 0;
    for (uint64_t i = 0; i < layout->coverage_count; i++) {
        n00b_macho_layout_coverage_t *cov = &layout->coverage[i];

        // Each run is well-ordered and abuts the previous (no holes).
        assert(cov->start == cursor);
        assert(cov->end > cov->start);
        // hello is fully modeled: no unknown-nonzero bytes.
        assert(cov->kind != N00B_MACHO_LAYOUT_COVERAGE_UNKNOWN_NONZERO);
        cursor = cov->end;
    }
    assert(cursor == layout->file_size);

    printf("  [PASS] coverage_contiguous\n");
}

// P2-b: synthetic trailing overlay — the parsed binary is rebuilt with a
// nonzero trailing overlay buffer; the final coverage run is OVERLAY and
// _eof_tail_gap places at/after file_size.
static void
test_overlay_tail_and_eof_gap(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] overlay_tail_and_eof_gap (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    // Attach a 64-byte nonzero trailing overlay (the tail of the backing
    // bytes is reinterpreted as overlay, mirroring an appended carrier).
    uint8_t payload[64];
    for (int i = 0; i < 64; i++) {
        payload[i] = (uint8_t)(i + 1);
    }
    bin->overlay = n00b_buffer_from_bytes((char *)payload, 64);

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    // The last coverage run is the OVERLAY tail and reaches file_size.
    assert(layout->coverage_count >= 1);
    n00b_macho_layout_coverage_t *last =
        &layout->coverage[layout->coverage_count - 1];
    assert(last->kind == N00B_MACHO_LAYOUT_COVERAGE_OVERLAY);
    assert(last->end == layout->file_size);

    // _eof_tail_gap places at or after file_size.
    auto eof_r = n00b_macho_layout_eof_tail_gap(layout, 16, 16);
    assert(n00b_result_is_ok(eof_r));
    n00b_option_t(n00b_macho_layout_gap_t) eof_opt = n00b_result_get(eof_r);
    assert(n00b_option_is_set(eof_opt));
    n00b_macho_layout_gap_t eof = n00b_option_get(eof_opt);
    assert(eof.kind == N00B_MACHO_LAYOUT_GAP_EOF_TAIL);
    assert(eof.start >= layout->file_size);
    assert((eof.start % 16) == 0);
    assert(eof.end - eof.start >= 16);

    printf("  [PASS] overlay_tail_and_eof_gap\n");
}

// P2-c: zero-padding gap classification. A synthetic trailing overlay of all
// zero bytes is classified ZERO_PADDING (not OVERLAY) by the byte reader when
// queried as a file gap. We craft an in-file zero gap by shrinking the parsed
// __LINKEDIT file extent so a run of zero backing bytes becomes a factual gap,
// then assert _find_file_gap returns GAP_ZERO_PADDING for it.
static void
test_zero_padding_gap(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] zero_padding_gap (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    // Append a 32-byte all-zero overlay region. The byte classifier reads the
    // backing buffer for the modeled gap between the last modeled object and
    // the (zero) overlay-adjacent tail; here we force a zero run by extending
    // the backing buffer with zero bytes and NOT modeling them, so the gap
    // search over that range classifies ZERO_PADDING.
    //
    // Extend the backing stream buffer with 64 zero bytes past the modeled
    // file extent (file_size grows; the new bytes are unmodeled and zero).
    uint64_t orig_size = (uint64_t)n00b_buffer_len(bin->stream->buf);
    uint8_t  zeros[64];
    for (int i = 0; i < 64; i++) {
        zeros[i] = 0;
    }
    n00b_buffer_concat(bin->stream->buf,
                       n00b_buffer_from_bytes((char *)zeros, 64));

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);
    assert(layout->file_size == orig_size + 64);

    // The trailing 64 zero bytes are an unmodeled in-file gap; classified
    // ZERO_PADDING (all-zero backing bytes), not UNKNOWN_NONZERO.
    auto gap_r = n00b_macho_layout_find_file_gap(layout,
                                                 orig_size,
                                                 layout->file_size,
                                                 16,
                                                 1);
    assert(n00b_result_is_ok(gap_r));
    n00b_option_t(n00b_macho_layout_gap_t) gap_opt = n00b_result_get(gap_r);
    assert(n00b_option_is_set(gap_opt));
    n00b_macho_layout_gap_t gap = n00b_option_get(gap_opt);
    assert(gap.kind == N00B_MACHO_LAYOUT_GAP_ZERO_PADDING);
    assert(gap.start == orig_size);
    assert(gap.end - gap.start >= 16);

    printf("  [PASS] zero_padding_gap\n");
}

// P2-d: __PAGEZERO / unmapped vaddr — querying a vaddr range above the last
// mapped segment classifies GAP_VADDR_UNMAPPED, never an error.
static void
test_vaddr_unmapped_gap(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] vaddr_unmapped_gap (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    // Find the highest mapped segment vm extent end.
    uint64_t high = 0;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *s = &bin->segments[i];
        uint64_t              e = s->vmaddr + s->vmsize;
        if (e > high) {
            high = e;
        }
    }
    assert(high != 0);

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    // Search a window entirely above all mapped segments — unmapped, not error.
    uint64_t start = high;
    uint64_t end   = high + 0x100000000ULL;
    auto     gap_r = n00b_macho_layout_find_vaddr_gap(layout,
                                                  start,
                                                  end,
                                                  0x1000,
                                                  0x4000);
    assert(n00b_result_is_ok(gap_r));
    n00b_option_t(n00b_macho_layout_gap_t) gap_opt = n00b_result_get(gap_r);
    assert(n00b_option_is_set(gap_opt));
    n00b_macho_layout_gap_t gap = n00b_option_get(gap_opt);
    assert(gap.kind == N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED);
    assert((gap.start % 0x4000) == 0);
    assert(gap.end - gap.start >= 0x1000);

    printf("  [PASS] vaddr_unmapped_gap\n");
}

// P2-e: collision enumeration — a well-formed file region carries facts; a
// tight window inside __LINKEDIT overlaps multiple modeled intervals (the
// segment file extent, the LINKEDIT_FILE extent, and at least one symtab
// sub-region), so the collision summary reports interval_count >= 2.
static void
test_collision_enumerates_facts(void)
{
    n00b_macho_binary_t *bin = parse_fixture("test/unit/data/hello.macho");
    if (bin == nullptr) {
        printf("  [SKIP] collision_enumerates_facts (fixture "
               "test/unit/data/hello.macho not found)\n");
        return;
    }

    // Locate __LINKEDIT to query a window guaranteed to sit inside it.
    n00b_macho_segment_t *linkedit = nullptr;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (n00b_unicode_str_eq(n00b_string_from_cstr(bin->segments[i].name),
                                r"__LINKEDIT")) {
            linkedit = &bin->segments[i];
            break;
        }
    }
    if (linkedit == nullptr || linkedit->filesize == 0) {
        printf("  [SKIP] collision_enumerates_facts (__LINKEDIT absent)\n");
        return;
    }

    auto layout_r = n00b_macho_layout_build(bin);
    assert(n00b_result_is_ok(layout_r));
    n00b_macho_layout_t *layout = n00b_result_get(layout_r);

    // A 4-byte window at the start of __LINKEDIT overlaps the segment file
    // extent, the LINKEDIT_FILE extent, and the first __LINKEDIT sub-region.
    uint64_t qs = linkedit->fileoff;
    uint64_t qe = qs + 4;
    auto     coll_r = n00b_macho_layout_file_collision(layout, qs, qe);
    assert(n00b_result_is_ok(coll_r));
    n00b_macho_layout_collision_t coll = n00b_result_get(coll_r);
    assert(coll.interval_count >= 2);
    assert(coll.intervals != nullptr);
    assert(coll.start == qs);
    assert(coll.end == qe);

    // A clearly out-of-range window (well above EOF, before any modeled vm)
    // returns no file collisions on a well-formed object.
    auto empty_r = n00b_macho_layout_file_collision(layout,
                                                    layout->file_size + 4096,
                                                    layout->file_size + 8192);
    assert(n00b_result_is_ok(empty_r));
    n00b_macho_layout_collision_t empty = n00b_result_get(empty_r);
    assert(empty.interval_count == 0);

    printf("  [PASS] collision_enumerates_facts\n");
}

// P2-f: enum + flag mapper sweep — each defined enum value maps to a
// non-fallback string; out-of-range values map to a stable fallback; the flag
// mappers map known bits to non-fallback names and undefined bits to fallback.
static void
test_name_mapper_sweep(void)
{
    // Error codes.
    assert(!n00b_unicode_str_eq(
        n00b_macho_layout_err_str(N00B_MACHO_LAYOUT_ERR_INVALID),
        r"Mach-O layout: unknown error code"));
    assert(!n00b_unicode_str_eq(
        n00b_macho_layout_err_str(N00B_MACHO_LAYOUT_ERR_OVERFLOW),
        r"Mach-O layout: unknown error code"));
    assert(!n00b_unicode_str_eq(
        n00b_macho_layout_err_str(N00B_MACHO_LAYOUT_ERR_INTERVAL),
        r"Mach-O layout: unknown error code"));
    assert(n00b_unicode_str_eq(n00b_macho_layout_err_str(12345),
                               r"Mach-O layout: unknown error code"));

    // Interval kinds: every defined value is non-fallback.
    for (int k = N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER;
         k <= N00B_MACHO_LAYOUT_INTERVAL_OVERLAY;
         k++) {
        assert(!n00b_unicode_str_eq(
            n00b_macho_layout_interval_kind_str(
                (n00b_macho_layout_interval_kind_t)k),
            r"unknown-macho-layout-interval-kind"));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_layout_interval_kind_str(
            (n00b_macho_layout_interval_kind_t)0xffff),
        r"unknown-macho-layout-interval-kind"));

    // Coverage kinds.
    for (int k = N00B_MACHO_LAYOUT_COVERAGE_MODELED;
         k <= N00B_MACHO_LAYOUT_COVERAGE_OVERLAY;
         k++) {
        assert(!n00b_unicode_str_eq(
            n00b_macho_layout_coverage_kind_str(
                (n00b_macho_layout_coverage_kind_t)k),
            r"unknown-macho-layout-coverage-kind"));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_layout_coverage_kind_str(
            (n00b_macho_layout_coverage_kind_t)0xffff),
        r"unknown-macho-layout-coverage-kind"));

    // Gap kinds.
    for (int k = N00B_MACHO_LAYOUT_GAP_ZERO_PADDING;
         k <= N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED;
         k++) {
        assert(!n00b_unicode_str_eq(
            n00b_macho_layout_gap_kind_str((n00b_macho_layout_gap_kind_t)k),
            r"unknown-macho-layout-gap-kind"));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_layout_gap_kind_str((n00b_macho_layout_gap_kind_t)0xffff),
        r"unknown-macho-layout-gap-kind"));

    // Segment flag bits (VM_PROT_*): known bits non-fallback, undefined bit
    // (0x8) falls back.
    assert(!n00b_unicode_str_eq(n00b_macho_layout_segment_flag_str(0x1),
                                r"unknown-macho-segment-flag"));
    assert(!n00b_unicode_str_eq(n00b_macho_layout_segment_flag_str(0x2),
                                r"unknown-macho-segment-flag"));
    assert(!n00b_unicode_str_eq(n00b_macho_layout_segment_flag_str(0x4),
                                r"unknown-macho-segment-flag"));
    assert(n00b_unicode_str_eq(n00b_macho_layout_segment_flag_str(0x8),
                               r"unknown-macho-segment-flag"));

    // Section flag bits: known section types/attrs non-fallback, undefined
    // value falls back.
    assert(!n00b_unicode_str_eq(n00b_macho_layout_section_flag_str(S_ZEROFILL),
                                r"unknown-macho-section-flag"));
    assert(!n00b_unicode_str_eq(
        n00b_macho_layout_section_flag_str(S_CSTRING_LITERALS),
        r"unknown-macho-section-flag"));
    assert(!n00b_unicode_str_eq(
        n00b_macho_layout_section_flag_str(S_ATTR_PURE_INSTRUCTIONS),
        r"unknown-macho-section-flag"));
    assert(n00b_unicode_str_eq(n00b_macho_layout_section_flag_str(0x12345600),
                               r"unknown-macho-section-flag"));

    printf("  [PASS] name_mapper_sweep\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running Mach-O layout tests...\n");
    test_hello_layout();
    test_signed_code_signature_interval();
    test_overflow_is_deterministic();
    test_coverage_contiguous();
    test_overlay_tail_and_eof_gap();
    test_zero_padding_gap();
    test_vaddr_unmapped_gap();
    test_collision_enumerates_facts();
    test_name_mapper_sweep();
    printf("All Mach-O layout tests passed.\n");
    return 0;
}
