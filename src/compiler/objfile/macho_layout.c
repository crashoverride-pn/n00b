#include "compiler/objfile/macho_layout.h"

#include "text/strings/string_ops.h"

// WP-003 Phase 1+2: header verification + file/vmaddr interval construction,
// plus the coverage / overlap / collision / gap query surface and the `*_str`
// name mappers.
//
// This file mirrors `elf_layout.c` structurally for the Mach-O arm64 backend.
// Phase 1 implements `n00b_macho_layout_build` (plus the overflow-safe interval
// helpers it needs). Phase 2 adds byte coverage classification, the
// overlap/collision/gap query surface over both coordinate spaces, and the
// CR-08 `*_str` enum/flag name mappers.
//
// All intervals are half-open `[start, end)`; empty ranges are skipped.

// VM protection flag bits (`initprot`/`maxprot`). These are the standard
// Mach-O `VM_PROT_*` ABI values; they are not defined in `macho_types.h`
// (which only declares the `initprot`/`maxprot` fields), so they are defined
// here for the `n00b_macho_layout_segment_flag_str` mapper. File-local to
// avoid leaking a new public macro from the layout layer.
#define N00B_MACHO_VM_PROT_READ    0x1u
#define N00B_MACHO_VM_PROT_WRITE   0x2u
#define N00B_MACHO_VM_PROT_EXECUTE 0x4u

static bool
checked_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static bool
checked_mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return false;
    }

    *out = a * b;
    return true;
}

static n00b_result_t(bool)
add_interval(n00b_macho_layout_interval_tree_t *tree,
             uint64_t                          *count,
             n00b_macho_layout_interval_kind_t  kind,
             uint32_t                           index,
             uint64_t                           flags,
             uint64_t                           start,
             uint64_t                           size)
{
    uint64_t end;

    if (tree == nullptr || count == nullptr) {
        return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (size == 0) {
        return n00b_result_ok(bool, true);
    }

    if (!checked_add_u64(start, size, &end)) {
        return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_OVERFLOW);
    }

    n00b_macho_layout_interval_t interval = {
        .kind  = kind,
        .start = start,
        .end   = end,
        .index = index,
        .flags = flags,
    };

    auto insert = n00b_interval_insert(tree, start, end, interval);
    if (n00b_result_is_err(insert)) {
        return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    *count += 1;
    return n00b_result_ok(bool, true);
}

// Add a `[offset, offset + size)` __LINKEDIT sub-region from a D-019
// `n00b_macho_linkedit_region_t {file_offset, size}`. Absent regions
// (offset == 0 && size == 0) are skipped, as are zero-size regions.
static n00b_result_t(bool)
add_sized_table(n00b_macho_layout_interval_tree_t *tree,
                uint64_t                          *count,
                n00b_macho_layout_interval_kind_t  kind,
                uint64_t                           offset,
                uint64_t                           size)
{
    if (offset == 0 && size == 0) {
        return n00b_result_ok(bool, true);
    }

    return add_interval(tree,
                        count,
                        kind,
                        N00B_MACHO_LAYOUT_NO_INDEX,
                        0,
                        offset,
                        size);
}

// Classify a non-modeled byte range `[start, end)` by reading the backing
// buffer: all-zero ⇒ ZERO_PADDING, any nonzero byte ⇒ UNKNOWN_NONZERO. Bytes
// are read through the n00b buffer's backing store (`buf->data`, the n00b
// buffer API per core/buffer.h), not via libc scanning.
static n00b_macho_layout_coverage_kind_t
classify_gap_bytes(n00b_buffer_t *buf, uint64_t start, uint64_t end)
{
    const uint8_t *bytes = (const uint8_t *)buf->data;

    for (uint64_t i = start; i < end; i++) {
        if (bytes[i] != 0) {
            return N00B_MACHO_LAYOUT_COVERAGE_UNKNOWN_NONZERO;
        }
    }

    return N00B_MACHO_LAYOUT_COVERAGE_ZERO_PADDING;
}

static n00b_result_t(bool)
push_coverage(n00b_stack_t(n00b_macho_layout_coverage_t) *coverage,
              n00b_macho_layout_coverage_kind_t           kind,
              uint64_t                                    start,
              uint64_t                                    end)
{
    if (coverage == nullptr || start > end) {
        return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(bool, true);
    }

    n00b_stack_push(*coverage,
                    ((n00b_macho_layout_coverage_t){
                        .kind  = kind,
                        .start = start,
                        .end   = end,
                    }));
    return n00b_result_ok(bool, true);
}

static bool
align_up_u64(uint64_t value, uint64_t alignment, uint64_t *out)
{
    if (alignment == 0) {
        alignment = 1;
    }

    uint64_t rem = value % alignment;
    if (rem == 0) {
        *out = value;
        return true;
    }

    return checked_add_u64(value, alignment - rem, out);
}

static uint64_t
align_down_u64(uint64_t value, uint64_t alignment)
{
    if (alignment == 0) {
        alignment = 1;
    }

    return value - (value % alignment);
}

static n00b_macho_layout_gap_kind_t
gap_kind_from_coverage(n00b_macho_layout_coverage_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_LAYOUT_COVERAGE_ZERO_PADDING:
        return N00B_MACHO_LAYOUT_GAP_ZERO_PADDING;
    case N00B_MACHO_LAYOUT_COVERAGE_UNKNOWN_NONZERO:
        return N00B_MACHO_LAYOUT_GAP_UNKNOWN_NONZERO;
    case N00B_MACHO_LAYOUT_COVERAGE_OVERLAY:
        return N00B_MACHO_LAYOUT_GAP_OVERLAY;
    case N00B_MACHO_LAYOUT_COVERAGE_MODELED:
    default:
        return N00B_MACHO_LAYOUT_GAP_UNKNOWN_NONZERO;
    }
}

static n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
gap_if_satisfies(n00b_macho_layout_gap_kind_t kind,
                 uint64_t                     start,
                 uint64_t                     end,
                 uint64_t                     min_size,
                 uint64_t                     alignment)
{
    if (start >= end) {
        return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                              n00b_option_none(n00b_macho_layout_gap_t));
    }

    uint64_t aligned;
    if (!align_up_u64(start, alignment, &aligned)) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_OVERFLOW);
    }

    if (aligned >= end || end - aligned < min_size) {
        return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                              n00b_option_none(n00b_macho_layout_gap_t));
    }

    n00b_macho_layout_gap_t gap = {
        .kind  = kind,
        .start = aligned,
        .end   = end,
    };
    return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                          n00b_option_set(n00b_macho_layout_gap_t, gap));
}

static n00b_result_t(n00b_macho_layout_interval_list_t)
collect_overlaps(n00b_macho_layout_interval_tree_t *tree,
                 uint64_t                           start,
                 uint64_t                           end,
                 n00b_allocator_t                  *allocator)
{
    n00b_macho_layout_interval_list_t list = {
        .items = nullptr,
        .count = 0,
    };

    if (tree == nullptr || start > end) {
        return n00b_result_err(n00b_macho_layout_interval_list_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_macho_layout_interval_list_t, list);
    }

    n00b_stack_t(void *) hits = n00b_stack_new_private(void *, .allocator = allocator);
    auto search = n00b_interval_search_ordered(tree, start, end, &hits);
    if (n00b_result_is_err(search)) {
        n00b_stack_free(hits);
        return n00b_result_err(n00b_macho_layout_interval_list_t,
                               N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    list.count = n00b_stack_len(hits);
    if (list.count != 0) {
        list.items = n00b_alloc_array_with_opts(
            n00b_macho_layout_interval_t,
            (size_t)list.count,
            &(n00b_alloc_opts_t){.allocator = allocator});

        size_t i = 0;
        n00b_stack_foreach(hits, p) {
            n00b_macho_layout_interval_node_t *node =
                (n00b_macho_layout_interval_node_t *)*p;
            list.items[i] = node->data;
            i++;
        }
    }

    n00b_stack_free(hits);
    return n00b_result_ok(n00b_macho_layout_interval_list_t, list);
}

// Build the byte-coverage map over `[0, file_size)`. Modeled file intervals
// (merged) are MODELED; the gaps between them are classified by reading the
// backing bytes (ZERO_PADDING / UNKNOWN_NONZERO); any trailing overlay region
// is OVERLAY. The result tiles `[0, file_size)` with no holes.
static n00b_result_t(bool)
build_coverage(n00b_macho_layout_t *layout,
               n00b_macho_binary_t *bin,
               uint64_t             overlay_start,
               n00b_allocator_t    *allocator)
{
    n00b_stack_t(n00b_interval_range_t) ranges =
        n00b_stack_new_private(n00b_interval_range_t, .allocator = allocator);
    n00b_stack_t(n00b_macho_layout_coverage_t) coverage =
        n00b_stack_new_private(n00b_macho_layout_coverage_t, .allocator = allocator);

    auto merge = n00b_interval_merge_ranges(layout->file_intervals,
                                            0,
                                            overlay_start,
                                            &ranges);
    if (n00b_result_is_err(merge)) {
        n00b_stack_free(ranges);
        n00b_stack_free(coverage);
        return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    uint64_t cursor = 0;
    for (size_t i = 0; i < n00b_stack_len(ranges); i++) {
        n00b_interval_range_t range = ranges.data[i];

        if (cursor < range.low) {
            auto pushed = push_coverage(&coverage,
                                        classify_gap_bytes(bin->stream->buf,
                                                           cursor,
                                                           range.low),
                                        cursor,
                                        range.low);
            if (n00b_result_is_err(pushed)) {
                n00b_stack_free(ranges);
                n00b_stack_free(coverage);
                return pushed;
            }
        }

        auto pushed = push_coverage(&coverage,
                                    N00B_MACHO_LAYOUT_COVERAGE_MODELED,
                                    range.low,
                                    range.high);
        if (n00b_result_is_err(pushed)) {
            n00b_stack_free(ranges);
            n00b_stack_free(coverage);
            return pushed;
        }

        cursor = range.high;
    }

    if (cursor < overlay_start) {
        auto pushed = push_coverage(&coverage,
                                    classify_gap_bytes(bin->stream->buf,
                                                       cursor,
                                                       overlay_start),
                                    cursor,
                                    overlay_start);
        if (n00b_result_is_err(pushed)) {
            n00b_stack_free(ranges);
            n00b_stack_free(coverage);
            return pushed;
        }
    }

    if (overlay_start < layout->file_size) {
        auto pushed = push_coverage(&coverage,
                                    N00B_MACHO_LAYOUT_COVERAGE_OVERLAY,
                                    overlay_start,
                                    layout->file_size);
        if (n00b_result_is_err(pushed)) {
            n00b_stack_free(ranges);
            n00b_stack_free(coverage);
            return pushed;
        }
    }

    layout->coverage_count = n00b_stack_len(coverage);
    if (layout->coverage_count != 0) {
        layout->coverage = n00b_alloc_array_with_opts(
            n00b_macho_layout_coverage_t,
            (size_t)layout->coverage_count,
            &(n00b_alloc_opts_t){.allocator = allocator});
        // Element-wise copy (no libc memcpy): the layout layer is libc-free.
        for (uint64_t i = 0; i < layout->coverage_count; i++) {
            layout->coverage[i] = coverage.data[i];
        }
    }

    n00b_stack_free(ranges);
    n00b_stack_free(coverage);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_option_t(n00b_macho_layout_interval_node_t *))
tree_overlap(n00b_macho_layout_interval_tree_t *tree,
             uint64_t                           start,
             uint64_t                           end)
{
    if (tree == nullptr || start > end) {
        return n00b_result_err(
            n00b_option_t(n00b_macho_layout_interval_node_t *),
            N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(
            n00b_option_t(n00b_macho_layout_interval_node_t *),
            n00b_option_none(n00b_macho_layout_interval_node_t *));
    }

    auto found = n00b_interval_search_any(tree, start, end);
    if (n00b_result_is_err(found)) {
        return n00b_result_err(
            n00b_option_t(n00b_macho_layout_interval_node_t *),
            N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    return n00b_result_ok(
        n00b_option_t(n00b_macho_layout_interval_node_t *),
        n00b_option_from_nullable(n00b_macho_layout_interval_node_t *,
                                  n00b_result_get(found)));
}

n00b_result_t(n00b_macho_layout_t *)
n00b_macho_layout_build(n00b_macho_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
        bin->stream != nullptr;
        bin->stream->buf != nullptr;
    }
    ensures {
        // Structural shadow; per-interval start<end is enforced while building
        // (add_interval skips empty ranges) and verified by the P1 test matrix.
        // Each statement is an independent (unguarded) debug assertion, so the
        // `result.ok` dereference is guarded by `result.is_ok` to stay valid on
        // the error-return path (e.g. the crafted-overflow case).
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->file_size == bin->stream->buf->byte_len);
    }
{
    // Release-path guard paired with the debug `requires` (D-004): contracts
    // are debug-only assertions, so the body must still reject null input.
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_macho_layout_t *,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    n00b_macho_layout_t *layout = n00b_alloc_with_opts(
        n00b_macho_layout_t,
        &(n00b_alloc_opts_t){.allocator = allocator});

    layout->file_intervals = n00b_alloc_with_opts(
        n00b_macho_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    layout->vaddr_intervals = n00b_alloc_with_opts(
        n00b_macho_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});

    n00b_interval_tree_init(layout->file_intervals, .allocator = allocator);
    n00b_interval_tree_init(layout->vaddr_intervals, .allocator = allocator);

    layout->file_size            = n00b_buffer_len(bin->stream->buf);
    layout->file_interval_count  = 0;
    layout->vaddr_interval_count = 0;
    layout->coverage             = nullptr;
    layout->coverage_count       = 0;

    // mach_header_64 occupies [0, N00B_MACHO_HEADER_64_SIZE) (D-019 constant).
    auto add = add_interval(layout->file_intervals,
                            &layout->file_interval_count,
                            N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER,
                            N00B_MACHO_LAYOUT_NO_INDEX,
                            0,
                            0,
                            N00B_MACHO_HEADER_64_SIZE);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    // Load-command region: [header_end, header_end + sizeofcmds). FR-01 Q1
    // confirmed `header.sizeofcmds` is exposed; the constant is D-019.
    add = add_interval(layout->file_intervals,
                       &layout->file_interval_count,
                       N00B_MACHO_LAYOUT_INTERVAL_LOAD_COMMANDS,
                       N00B_MACHO_LAYOUT_NO_INDEX,
                       0,
                       N00B_MACHO_HEADER_64_SIZE,
                       (uint64_t)bin->header.sizeofcmds);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        // Segment file extent (file tree).
        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_FILE,
                           i,
                           seg->initprot,
                           seg->fileoff,
                           seg->filesize);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_macho_layout_t *,
                                   n00b_result_get_err(add));
        }

        // __LINKEDIT segment's file extent is additionally tagged as a
        // first-class LINKEDIT_FILE interval (classification map).
        if (n00b_unicode_str_eq(n00b_string_from_cstr(seg->name),
                                r"__LINKEDIT")) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_MACHO_LAYOUT_INTERVAL_LINKEDIT_FILE,
                               i,
                               seg->initprot,
                               seg->fileoff,
                               seg->filesize);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_macho_layout_t *,
                                       n00b_result_get_err(add));
            }
        }

        // Segment vm extent (vaddr tree).
        add = add_interval(layout->vaddr_intervals,
                           &layout->vaddr_interval_count,
                           N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_VM,
                           i,
                           seg->initprot,
                           seg->vmaddr,
                           seg->vmsize);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_macho_layout_t *,
                                   n00b_result_get_err(add));
        }

        // Sections: non-zerofill go in the file tree at [offset, offset+size);
        // S_ZEROFILL (bss) has no file bytes and goes in the vaddr tree.
        for (uint32_t j = 0; j < seg->nsects; j++) {
            n00b_macho_section_t *sec = &seg->sections[j];

            // The section type is the low byte of flags (SECTION_TYPE mask,
            // macho_types.h:164); S_ZEROFILL (0x01) is bss with no file bytes.
            uint32_t section_type = sec->flags & SECTION_TYPE;

            if (section_type == S_ZEROFILL) {
                add = add_interval(layout->vaddr_intervals,
                                   &layout->vaddr_interval_count,
                                   N00B_MACHO_LAYOUT_INTERVAL_SECTION_ZEROFILL,
                                   j,
                                   sec->flags,
                                   sec->addr,
                                   sec->size);
                if (n00b_result_is_err(add)) {
                    return n00b_result_err(n00b_macho_layout_t *,
                                           n00b_result_get_err(add));
                }
                continue;
            }

            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_MACHO_LAYOUT_INTERVAL_SECTION_FILE,
                               j,
                               sec->flags,
                               (uint64_t)sec->offset,
                               sec->size);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_macho_layout_t *,
                                       n00b_result_get_err(add));
            }
        }
    }

    // __LINKEDIT sub-regions come from the D-019 {file_offset, size} fields,
    // NOT a section walk (__LINKEDIT carries no sections).
    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_NLIST,
                          bin->symtab_nlist.file_offset,
                          bin->symtab_nlist.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_STRINGS,
                          bin->symtab_strings.file_offset,
                          bin->symtab_strings.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_DYSYMTAB_INDIRECT,
                          bin->indirect_symtab.file_offset,
                          bin->indirect_symtab.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_DYLD_INFO,
                          bin->dyld_info.file_offset,
                          bin->dyld_info.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_FUNCTION_STARTS,
                          bin->function_starts_region.file_offset,
                          bin->function_starts_region.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_DATA_IN_CODE,
                          bin->data_in_code_region.file_offset,
                          bin->data_in_code_region.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_MACHO_LAYOUT_INTERVAL_CHAINED_FIXUPS,
                          bin->chained_fixups_region.file_offset,
                          bin->chained_fixups_region.size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    // Code signature is a pointer (not an n00b_macho_linkedit_region_t):
    // null-check, then [dataoff, dataoff + datasize) (macho.h:238-242).
    if (bin->code_signature != nullptr) {
        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_MACHO_LAYOUT_INTERVAL_CODE_SIGNATURE,
                           N00B_MACHO_LAYOUT_NO_INDEX,
                           0,
                           (uint64_t)bin->code_signature->dataoff,
                           (uint64_t)bin->code_signature->datasize);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_macho_layout_t *,
                                   n00b_result_get_err(add));
        }
    }

    // Overlay: bytes past the last modeled object, recorded as a tail interval
    // ending at file_size (macho.h:417).
    uint64_t overlay_start = layout->file_size;
    if (bin->overlay != nullptr) {
        uint64_t overlay_size = n00b_buffer_len(bin->overlay);

        if (overlay_size > layout->file_size) {
            return n00b_result_err(n00b_macho_layout_t *,
                                   N00B_MACHO_LAYOUT_ERR_INVALID);
        }

        overlay_start = layout->file_size - overlay_size;
        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_MACHO_LAYOUT_INTERVAL_OVERLAY,
                           N00B_MACHO_LAYOUT_NO_INDEX,
                           0,
                           overlay_start,
                           overlay_size);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_macho_layout_t *,
                                   n00b_result_get_err(add));
        }
    }

    // Coverage: tile [0, file_size) into MODELED / ZERO_PADDING /
    // UNKNOWN_NONZERO / OVERLAY runs with no holes (DoD P2-a).
    add = build_coverage(layout, bin, overlay_start, allocator);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_macho_layout_t *, n00b_result_get_err(add));
    }

    return n00b_result_ok(n00b_macho_layout_t *, layout);
}

// ============================================================================
// Overlap / collision / gap queries
// ============================================================================

n00b_result_t(n00b_option_t(n00b_macho_layout_interval_node_t *))
n00b_macho_layout_file_overlap(n00b_macho_layout_t *layout,
                               uint64_t             start,
                               uint64_t             end)
    requires {
        layout != nullptr;
        start <= end;
    }
{
    if (layout == nullptr) {
        return n00b_result_err(
            n00b_option_t(n00b_macho_layout_interval_node_t *),
            N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    return tree_overlap(layout->file_intervals, start, end);
}

n00b_result_t(n00b_option_t(n00b_macho_layout_interval_node_t *))
n00b_macho_layout_vaddr_overlap(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end)
    requires {
        layout != nullptr;
        start <= end;
    }
{
    if (layout == nullptr) {
        return n00b_result_err(
            n00b_option_t(n00b_macho_layout_interval_node_t *),
            N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    return tree_overlap(layout->vaddr_intervals, start, end);
}

n00b_result_t(n00b_macho_layout_interval_list_t)
n00b_macho_layout_file_overlaps(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        layout != nullptr;
        start <= end;
    }
    ensures {
        // count==0 || items!=nullptr; guarded by success (D-028).
        !result.is_ok
            || (result.ok.count == 0 || result.ok.items != nullptr);
    }
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_macho_layout_interval_list_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    return collect_overlaps(layout->file_intervals, start, end, allocator);
}

n00b_result_t(n00b_macho_layout_interval_list_t)
n00b_macho_layout_vaddr_overlaps(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        layout != nullptr;
        start <= end;
    }
    ensures {
        // count==0 || items!=nullptr; guarded by success (D-028).
        !result.is_ok
            || (result.ok.count == 0 || result.ok.items != nullptr);
    }
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_macho_layout_interval_list_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    return collect_overlaps(layout->vaddr_intervals, start, end, allocator);
}

n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_file_collision(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        layout != nullptr;
        start <= end;
    }
    ensures {
        // interval_count==0 || intervals!=nullptr; guarded by success (D-028).
        !result.is_ok
            || (result.ok.interval_count == 0
                || result.ok.intervals != nullptr);
    }
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    auto overlaps = collect_overlaps(layout->file_intervals,
                                     start,
                                     end,
                                     allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_macho_layout_interval_list_t list      = n00b_result_get(overlaps);
    n00b_macho_layout_collision_t     collision = {
            .start          = start,
            .end            = end,
            .intervals      = list.items,
            .interval_count = list.count,
    };
    return n00b_result_ok(n00b_macho_layout_collision_t, collision);
}

n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_vaddr_collision(n00b_macho_layout_t *layout,
                                  uint64_t             start,
                                  uint64_t             end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        layout != nullptr;
        start <= end;
    }
    ensures {
        // interval_count==0 || intervals!=nullptr; guarded by success (D-028).
        !result.is_ok
            || (result.ok.interval_count == 0
                || result.ok.intervals != nullptr);
    }
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    auto overlaps = collect_overlaps(layout->vaddr_intervals,
                                     start,
                                     end,
                                     allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_macho_layout_interval_list_t list      = n00b_result_get(overlaps);
    n00b_macho_layout_collision_t     collision = {
            .start          = start,
            .end            = end,
            .intervals      = list.items,
            .interval_count = list.count,
    };
    return n00b_result_ok(n00b_macho_layout_collision_t, collision);
}

n00b_result_t(n00b_option_t(n00b_macho_layout_interval_t))
n00b_macho_layout_next_file_interval(n00b_macho_layout_t *layout,
                                     uint64_t             start)
    requires {
        layout != nullptr;
    }
{
    if (layout == nullptr || layout->file_intervals == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_interval_t),
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    auto next = n00b_interval_next_low(layout->file_intervals, start);
    if (n00b_result_is_err(next)) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_interval_t),
                               N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    n00b_macho_layout_interval_node_t *node =
        (n00b_macho_layout_interval_node_t *)n00b_result_get(next);
    if (node == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_macho_layout_interval_t),
                              n00b_option_none(n00b_macho_layout_interval_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_macho_layout_interval_t),
                          n00b_option_set(n00b_macho_layout_interval_t,
                                          node->data));
}

n00b_result_t(n00b_macho_layout_collision_t)
n00b_macho_layout_page_segment_vaddr_collision(n00b_macho_binary_t *bin,
                                                uint64_t             start,
                                                uint64_t             end,
                                                uint64_t             page_size) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        bin != nullptr;
        page_size != 0;
        start <= end;
    }
    ensures {
        // interval_count==0 || intervals!=nullptr; guarded by success (D-028).
        !result.is_ok
            || (result.ok.interval_count == 0
                || result.ok.intervals != nullptr);
    }
{
    n00b_macho_layout_collision_t collision = {
        .start = start,
        .end   = end,
    };

    if (bin == nullptr || start > end || page_size == 0) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_macho_layout_collision_t, collision);
    }

    // Build a transient vm tree of page-rounded segment extents: each segment
    // occupies [align_down(vmaddr, page_size), vmaddr + vmsize) (loader-style
    // mapping pressure; tail slack after vmsize stays usable).
    n00b_macho_layout_interval_tree_t *tree = n00b_alloc_with_opts(
        n00b_macho_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_interval_tree_init(tree, .allocator = allocator);

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        if (seg->vmaddr == 0 && seg->vmsize == 0) {
            continue;
        }

        uint64_t high;
        if (!checked_add_u64(seg->vmaddr, seg->vmsize, &high)) {
            return n00b_result_err(n00b_macho_layout_collision_t,
                                   N00B_MACHO_LAYOUT_ERR_OVERFLOW);
        }

        n00b_macho_layout_interval_t interval = {
            .kind  = N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_VM,
            .start = align_down_u64(seg->vmaddr, page_size),
            .end   = high,
            .index = i,
            .flags = seg->initprot,
        };
        if (interval.start == interval.end) {
            continue;
        }

        auto insert = n00b_interval_insert(tree,
                                           interval.start,
                                           interval.end,
                                           interval);
        if (n00b_result_is_err(insert)) {
            return n00b_result_err(n00b_macho_layout_collision_t,
                                   N00B_MACHO_LAYOUT_ERR_INTERVAL);
        }
    }

    auto overlaps = collect_overlaps(tree, start, end, allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_macho_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_macho_layout_interval_list_t list = n00b_result_get(overlaps);
    collision.intervals      = list.items;
    collision.interval_count = list.count;
    return n00b_result_ok(n00b_macho_layout_collision_t, collision);
}

n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_find_file_gap(n00b_macho_layout_t *layout,
                                uint64_t             start,
                                uint64_t             end,
                                uint64_t             min_size,
                                uint64_t             alignment)
    requires {
        layout != nullptr;
        min_size != 0;
        start <= end;
    }
    ensures {
        // when a gap is found, it is aligned and wide enough.
        // Guarded by success (D-028): on Err, result.ok is invalid.
        uint64_t a = alignment ? alignment : 1;
        !result.is_ok
            || (!result.ok.has_value)
            || ((result.ok.value.start % a) == 0
                && (result.ok.value.end - result.ok.value.start) >= min_size);
    }
{
    if (layout == nullptr || start > end || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                              n00b_option_none(n00b_macho_layout_gap_t));
    }

    uint64_t file_end = end < layout->file_size ? end : layout->file_size;
    for (uint64_t i = 0; i < layout->coverage_count; i++) {
        n00b_macho_layout_coverage_t *coverage = &layout->coverage[i];

        if (coverage->end <= start) {
            continue;
        }

        if (coverage->start >= file_end) {
            break;
        }

        if (coverage->kind == N00B_MACHO_LAYOUT_COVERAGE_MODELED) {
            continue;
        }

        uint64_t gap_start = coverage->start > start ? coverage->start : start;
        uint64_t gap_end   = coverage->end < file_end ? coverage->end : file_end;
        auto     gap = gap_if_satisfies(gap_kind_from_coverage(coverage->kind),
                                        gap_start,
                                        gap_end,
                                        min_size,
                                        alignment);
        if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
            return gap;
        }
    }

    if (end > layout->file_size) {
        uint64_t tail_start = start > layout->file_size ? start
                                                        : layout->file_size;
        auto gap = gap_if_satisfies(N00B_MACHO_LAYOUT_GAP_EOF_TAIL,
                                    tail_start,
                                    end,
                                    min_size,
                                    alignment);
        if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
            return gap;
        }
    }

    return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                          n00b_option_none(n00b_macho_layout_gap_t));
}

n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_find_vaddr_gap(n00b_macho_layout_t *layout,
                                 uint64_t             start,
                                 uint64_t             end,
                                 uint64_t             min_size,
                                 uint64_t             alignment)
    requires {
        layout != nullptr;
        min_size != 0;
        start <= end;
    }
    ensures {
        // when a gap is found, it is aligned and wide enough.
        // Guarded by success (D-028): on Err, result.ok is invalid.
        uint64_t a = alignment ? alignment : 1;
        !result.is_ok
            || (!result.ok.has_value)
            || ((result.ok.value.start % a) == 0
                && (result.ok.value.end - result.ok.value.start) >= min_size);
    }
{
    if (layout == nullptr || start > end || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                              n00b_option_none(n00b_macho_layout_gap_t));
    }

    n00b_stack_t(n00b_interval_range_t) ranges =
        n00b_stack_new_private(n00b_interval_range_t,
                               .allocator = layout->vaddr_intervals->allocator);
    auto merge = n00b_interval_merge_ranges(layout->vaddr_intervals,
                                            start,
                                            end,
                                            &ranges);
    if (n00b_result_is_err(merge)) {
        n00b_stack_free(ranges);
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_INTERVAL);
    }

    uint64_t cursor = start;
    for (size_t i = 0; i < n00b_stack_len(ranges); i++) {
        n00b_interval_range_t range = ranges.data[i];

        if (cursor < range.low) {
            auto gap = gap_if_satisfies(N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED,
                                        cursor,
                                        range.low,
                                        min_size,
                                        alignment);
            if (n00b_result_is_err(gap)
                || n00b_option_is_set(n00b_result_get(gap))) {
                n00b_stack_free(ranges);
                return gap;
            }
        }

        if (range.high > cursor) {
            cursor = range.high;
        }
    }

    if (cursor < end) {
        auto gap = gap_if_satisfies(N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED,
                                    cursor,
                                    end,
                                    min_size,
                                    alignment);
        if (n00b_result_is_err(gap)
            || n00b_option_is_set(n00b_result_get(gap))) {
            n00b_stack_free(ranges);
            return gap;
        }
    }

    n00b_stack_free(ranges);
    return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                          n00b_option_none(n00b_macho_layout_gap_t));
}

n00b_result_t(n00b_option_t(n00b_macho_layout_gap_t))
n00b_macho_layout_eof_tail_gap(n00b_macho_layout_t *layout,
                               uint64_t             min_size,
                               uint64_t             alignment)
    requires {
        layout != nullptr;
        min_size != 0;
    }
    ensures {
        // start >= file_size on some; guarded by success (D-028).
        !result.is_ok
            || (!result.ok.has_value)
            || (result.ok.value.start >= layout->file_size);
    }
{
    if (layout == nullptr || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_INVALID);
    }

    uint64_t start;
    if (!align_up_u64(layout->file_size, alignment, &start)) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_OVERFLOW);
    }

    uint64_t end;
    if (!checked_add_u64(start, min_size, &end)) {
        return n00b_result_err(n00b_option_t(n00b_macho_layout_gap_t),
                               N00B_MACHO_LAYOUT_ERR_OVERFLOW);
    }

    n00b_macho_layout_gap_t gap = {
        .kind  = N00B_MACHO_LAYOUT_GAP_EOF_TAIL,
        .start = start,
        .end   = end,
    };
    return n00b_result_ok(n00b_option_t(n00b_macho_layout_gap_t),
                          n00b_option_set(n00b_macho_layout_gap_t, gap));
}

// ============================================================================
// Enum-name / error-string helpers (CR-08)
// ============================================================================

n00b_string_t *
n00b_macho_layout_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_MACHO_LAYOUT_ERR_INVALID:
        return r"Mach-O layout: invalid input";
    case N00B_MACHO_LAYOUT_ERR_OVERFLOW:
        return r"Mach-O layout: arithmetic overflow";
    case N00B_MACHO_LAYOUT_ERR_INTERVAL:
        return r"Mach-O layout: interval tree operation failed";
    default:
        return r"Mach-O layout: unknown error code";
    }
}

n00b_string_t *
n00b_macho_layout_interval_kind_str(n00b_macho_layout_interval_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_LAYOUT_INTERVAL_MACH_HEADER:
        return r"mach-header";
    case N00B_MACHO_LAYOUT_INTERVAL_LOAD_COMMANDS:
        return r"load-commands";
    case N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_FILE:
        return r"segment-file";
    case N00B_MACHO_LAYOUT_INTERVAL_SEGMENT_VM:
        return r"segment-vm";
    case N00B_MACHO_LAYOUT_INTERVAL_LINKEDIT_FILE:
        return r"linkedit-file";
    case N00B_MACHO_LAYOUT_INTERVAL_SECTION_FILE:
        return r"section-file";
    case N00B_MACHO_LAYOUT_INTERVAL_SECTION_ZEROFILL:
        return r"section-zerofill";
    case N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_NLIST:
        return r"symtab-nlist";
    case N00B_MACHO_LAYOUT_INTERVAL_SYMTAB_STRINGS:
        return r"symtab-strings";
    case N00B_MACHO_LAYOUT_INTERVAL_DYSYMTAB_INDIRECT:
        return r"dysymtab-indirect";
    case N00B_MACHO_LAYOUT_INTERVAL_DYLD_INFO:
        return r"dyld-info";
    case N00B_MACHO_LAYOUT_INTERVAL_FUNCTION_STARTS:
        return r"function-starts";
    case N00B_MACHO_LAYOUT_INTERVAL_DATA_IN_CODE:
        return r"data-in-code";
    case N00B_MACHO_LAYOUT_INTERVAL_CHAINED_FIXUPS:
        return r"chained-fixups";
    case N00B_MACHO_LAYOUT_INTERVAL_CODE_SIGNATURE:
        return r"code-signature";
    case N00B_MACHO_LAYOUT_INTERVAL_OVERLAY:
        return r"overlay";
    default:
        return r"unknown-macho-layout-interval-kind";
    }
}

n00b_string_t *
n00b_macho_layout_coverage_kind_str(n00b_macho_layout_coverage_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_LAYOUT_COVERAGE_MODELED:
        return r"modeled";
    case N00B_MACHO_LAYOUT_COVERAGE_ZERO_PADDING:
        return r"zero-padding";
    case N00B_MACHO_LAYOUT_COVERAGE_UNKNOWN_NONZERO:
        return r"unknown-nonzero";
    case N00B_MACHO_LAYOUT_COVERAGE_OVERLAY:
        return r"overlay";
    default:
        return r"unknown-macho-layout-coverage-kind";
    }
}

n00b_string_t *
n00b_macho_layout_gap_kind_str(n00b_macho_layout_gap_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_LAYOUT_GAP_ZERO_PADDING:
        return r"zero-padding";
    case N00B_MACHO_LAYOUT_GAP_UNKNOWN_NONZERO:
        return r"unknown-nonzero";
    case N00B_MACHO_LAYOUT_GAP_OVERLAY:
        return r"overlay";
    case N00B_MACHO_LAYOUT_GAP_EOF_TAIL:
        return r"eof-tail";
    case N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED:
        return r"vaddr-unmapped";
    default:
        return r"unknown-macho-layout-gap-kind";
    }
}

n00b_string_t *
n00b_macho_layout_segment_flag_str(uint64_t flag)
{
    switch (flag) {
    case N00B_MACHO_VM_PROT_READ:
        return r"VM_PROT_READ";
    case N00B_MACHO_VM_PROT_WRITE:
        return r"VM_PROT_WRITE";
    case N00B_MACHO_VM_PROT_EXECUTE:
        return r"VM_PROT_EXECUTE";
    default:
        return r"unknown-macho-segment-flag";
    }
}

n00b_string_t *
n00b_macho_layout_section_flag_str(uint64_t flag)
{
    switch (flag) {
    case S_ZEROFILL:
        return r"S_ZEROFILL";
    case S_CSTRING_LITERALS:
        return r"S_CSTRING_LITERALS";
    case S_4BYTE_LITERALS:
        return r"S_4BYTE_LITERALS";
    case S_8BYTE_LITERALS:
        return r"S_8BYTE_LITERALS";
    case S_LITERAL_POINTERS:
        return r"S_LITERAL_POINTERS";
    case S_NON_LAZY_SYMBOL_POINTERS:
        return r"S_NON_LAZY_SYMBOL_POINTERS";
    case S_LAZY_SYMBOL_POINTERS:
        return r"S_LAZY_SYMBOL_POINTERS";
    case S_SYMBOL_STUBS:
        return r"S_SYMBOL_STUBS";
    case S_MOD_INIT_FUNC_POINTERS:
        return r"S_MOD_INIT_FUNC_POINTERS";
    case S_MOD_TERM_FUNC_POINTERS:
        return r"S_MOD_TERM_FUNC_POINTERS";
    case S_ATTR_PURE_INSTRUCTIONS:
        return r"S_ATTR_PURE_INSTRUCTIONS";
    case S_ATTR_SOME_INSTRUCTIONS:
        return r"S_ATTR_SOME_INSTRUCTIONS";
    default:
        return r"unknown-macho-section-flag";
    }
}
