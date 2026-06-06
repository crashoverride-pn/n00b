#include "compiler/objfile/elf_layout.h"

#include <string.h>

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
add_interval(n00b_elf_layout_interval_tree_t *tree,
             uint64_t                        *count,
             n00b_elf_layout_interval_kind_t  kind,
             uint32_t                         index,
             uint64_t                         flags,
             uint64_t                         start,
             uint64_t                         size)
{
    uint64_t end;

    if (tree == nullptr || count == nullptr) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (size == 0) {
        return n00b_result_ok(bool, true);
    }

    if (!checked_add_u64(start, size, &end)) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_OVERFLOW);
    }

    n00b_elf_layout_interval_t interval = {
        .kind  = kind,
        .start = start,
        .end   = end,
        .index = index,
        .flags = flags,
    };

    auto insert = n00b_interval_insert(tree, start, end, interval);
    if (n00b_result_is_err(insert)) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_INTERVAL);
    }

    *count += 1;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
add_sized_table(n00b_elf_layout_interval_tree_t *tree,
                uint64_t                        *count,
                n00b_elf_layout_interval_kind_t  kind,
                uint64_t                         offset,
                uint64_t                         entry_size,
                uint64_t                         entry_count)
{
    uint64_t table_size;

    if (offset == 0 || entry_size == 0 || entry_count == 0) {
        return n00b_result_ok(bool, true);
    }

    if (!checked_mul_u64(entry_size, entry_count, &table_size)) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_OVERFLOW);
    }

    return add_interval(tree,
                        count,
                        kind,
                        N00B_ELF_LAYOUT_NO_INDEX,
                        0,
                        offset,
                        table_size);
}

static n00b_option_t(uint64_t)
find_dynamic_value(n00b_elf_binary_t *bin, int64_t tag)
{
    for (uint32_t i = 0; i < bin->num_dynamic; i++) {
        if (bin->dynamic_entries[i].tag == tag) {
            return n00b_option_set(uint64_t, bin->dynamic_entries[i].value);
        }
    }

    return n00b_option_none(uint64_t);
}

static n00b_result_t(n00b_option_t(uint64_t))
file_offset_for_vaddr(n00b_elf_binary_t *bin, uint64_t vaddr)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD || vaddr < seg->vaddr) {
            continue;
        }

        uint64_t delta = vaddr - seg->vaddr;
        if (delta >= seg->filesz) {
            continue;
        }

        uint64_t offset;
        if (!checked_add_u64(seg->offset, delta, &offset)) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   N00B_ELF_LAYOUT_ERR_OVERFLOW);
        }

        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_set(uint64_t, offset));
    }

    return n00b_result_ok(n00b_option_t(uint64_t),
                          n00b_option_none(uint64_t));
}

static n00b_elf_layout_coverage_kind_t
classify_gap_bytes(n00b_buffer_t *buf, uint64_t start, uint64_t end)
{
    const uint8_t *bytes = (const uint8_t *)buf->data;

    for (uint64_t i = start; i < end; i++) {
        if (bytes[i] != 0) {
            return N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO;
        }
    }

    return N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING;
}

static n00b_result_t(bool)
push_coverage(n00b_stack_t(n00b_elf_layout_coverage_t) *coverage,
              n00b_elf_layout_coverage_kind_t           kind,
              uint64_t                                  start,
              uint64_t                                  end)
{
    if (coverage == nullptr || start > end) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(bool, true);
    }

    n00b_stack_push(*coverage,
                    ((n00b_elf_layout_coverage_t){
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

static n00b_elf_layout_gap_kind_t
gap_kind_from_coverage(n00b_elf_layout_coverage_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING:
        return N00B_ELF_LAYOUT_GAP_ZERO_PADDING;
    case N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO:
        return N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO;
    case N00B_ELF_LAYOUT_COVERAGE_OVERLAY:
        return N00B_ELF_LAYOUT_GAP_OVERLAY;
    case N00B_ELF_LAYOUT_COVERAGE_MODELED:
    default:
        return N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO;
    }
}

static n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
gap_if_satisfies(n00b_elf_layout_gap_kind_t kind,
                 uint64_t                   start,
                 uint64_t                   end,
                 uint64_t                   min_size,
                 uint64_t                   alignment)
{
    if (start >= end) {
        return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                              n00b_option_none(n00b_elf_layout_gap_t));
    }

    uint64_t aligned;
    if (!align_up_u64(start, alignment, &aligned)) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_OVERFLOW);
    }

    if (aligned >= end || end - aligned < min_size) {
        return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                              n00b_option_none(n00b_elf_layout_gap_t));
    }

    n00b_elf_layout_gap_t gap = {
        .kind  = kind,
        .start = aligned,
        .end   = end,
    };
    return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                          n00b_option_set(n00b_elf_layout_gap_t, gap));
}

static n00b_result_t(n00b_elf_layout_interval_list_t)
collect_overlaps(n00b_elf_layout_interval_tree_t *tree,
                 uint64_t                         start,
                 uint64_t                         end,
                 n00b_allocator_t                 *allocator)
{
    n00b_elf_layout_interval_list_t list = {
        .items = nullptr,
        .count = 0,
    };

    if (tree == nullptr || start > end) {
        return n00b_result_err(n00b_elf_layout_interval_list_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_elf_layout_interval_list_t, list);
    }

    n00b_stack_t(void *) hits =
        n00b_stack_new_private(void *, .allocator = allocator);
    auto search = n00b_interval_search_ordered(tree, start, end, &hits);
    if (n00b_result_is_err(search)) {
        n00b_stack_free(hits);
        return n00b_result_err(n00b_elf_layout_interval_list_t,
                               N00B_ELF_LAYOUT_ERR_INTERVAL);
    }

    list.count = n00b_stack_len(hits);
    if (list.count != 0) {
        list.items = n00b_alloc_array_with_opts(
            n00b_elf_layout_interval_t,
            (size_t)list.count,
            &(n00b_alloc_opts_t){.allocator = allocator});

        size_t i = 0;
        n00b_stack_foreach(hits, p) {
            n00b_elf_layout_interval_node_t *node =
                (n00b_elf_layout_interval_node_t *)*p;
            list.items[i] = node->data;
            i++;
        }
    }

    n00b_stack_free(hits);
    return n00b_result_ok(n00b_elf_layout_interval_list_t, list);
}

static n00b_result_t(bool)
build_coverage(n00b_elf_layout_t *layout,
               n00b_elf_binary_t *bin,
               uint64_t           overlay_start,
               n00b_allocator_t  *allocator)
{
    n00b_stack_t(n00b_interval_range_t) ranges =
        n00b_stack_new_private(n00b_interval_range_t, .allocator = allocator);
    n00b_stack_t(n00b_elf_layout_coverage_t) coverage =
        n00b_stack_new_private(n00b_elf_layout_coverage_t,
                               .allocator = allocator);

    auto merge = n00b_interval_merge_ranges(layout->file_intervals,
                                            0,
                                            overlay_start,
                                            &ranges);
    if (n00b_result_is_err(merge)) {
        return n00b_result_err(bool, N00B_ELF_LAYOUT_ERR_INTERVAL);
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
                return pushed;
            }
        }

        auto pushed = push_coverage(&coverage,
                                    N00B_ELF_LAYOUT_COVERAGE_MODELED,
                                    range.low,
                                    range.high);
        if (n00b_result_is_err(pushed)) {
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
            return pushed;
        }
    }

    if (overlay_start < layout->file_size) {
        auto pushed = push_coverage(&coverage,
                                    N00B_ELF_LAYOUT_COVERAGE_OVERLAY,
                                    overlay_start,
                                    layout->file_size);
        if (n00b_result_is_err(pushed)) {
            return pushed;
        }
    }

    layout->coverage_count = n00b_stack_len(coverage);
    if (layout->coverage_count != 0) {
        layout->coverage = n00b_alloc_array_with_opts(
            n00b_elf_layout_coverage_t,
            (size_t)layout->coverage_count,
            &(n00b_alloc_opts_t){.allocator = allocator});
        memcpy(layout->coverage,
               coverage.data,
               (size_t)layout->coverage_count
                   * sizeof(n00b_elf_layout_coverage_t));
    }

    n00b_stack_free(ranges);
    n00b_stack_free(coverage);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_option_t(n00b_elf_layout_interval_node_t *))
tree_overlap(n00b_elf_layout_interval_tree_t *tree,
             uint64_t                         start,
             uint64_t                         end)
{
    if (tree == nullptr || start > end) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_node_t *),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(
            n00b_option_t(n00b_elf_layout_interval_node_t *),
            n00b_option_none(n00b_elf_layout_interval_node_t *));
    }

    auto found = n00b_interval_search_any(tree, start, end);
    if (n00b_result_is_err(found)) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_node_t *),
                               N00B_ELF_LAYOUT_ERR_INTERVAL);
    }

    return n00b_result_ok(
        n00b_option_t(n00b_elf_layout_interval_node_t *),
        n00b_option_from_nullable(n00b_elf_layout_interval_node_t *,
                                  n00b_result_get(found)));
}

n00b_result_t(n00b_elf_layout_t *)
n00b_elf_layout_build(n00b_elf_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_elf_layout_t *,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    n00b_elf_layout_t *layout = n00b_alloc_with_opts(
        n00b_elf_layout_t,
        &(n00b_alloc_opts_t){.allocator = allocator});

    layout->file_intervals = n00b_alloc_with_opts(
        n00b_elf_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    layout->vaddr_intervals = n00b_alloc_with_opts(
        n00b_elf_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});

    n00b_interval_tree_init(layout->file_intervals, .allocator = allocator);
    n00b_interval_tree_init(layout->vaddr_intervals, .allocator = allocator);

    layout->file_size            = (uint64_t)n00b_buffer_len(bin->stream->buf);
    layout->file_interval_count  = 0;
    layout->vaddr_interval_count = 0;
    layout->coverage             = nullptr;
    layout->coverage_count       = 0;

    uint64_t header_size = bin->header.ehsize;
    if (header_size == 0) {
        header_size = sizeof(n00b_elf64_ehdr_t);
    }

    auto add = add_interval(layout->file_intervals,
                            &layout->file_interval_count,
                            N00B_ELF_LAYOUT_INTERVAL_ELF_HEADER,
                            N00B_ELF_LAYOUT_NO_INDEX,
                            0,
                            0,
                            header_size);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_elf_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_ELF_LAYOUT_INTERVAL_PHTAB,
                          bin->header.phoff,
                          bin->header.phentsize,
                          bin->header.phnum);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_elf_layout_t *, n00b_result_get_err(add));
    }

    add = add_sized_table(layout->file_intervals,
                          &layout->file_interval_count,
                          N00B_ELF_LAYOUT_INTERVAL_SHTAB,
                          bin->header.shoff,
                          bin->header.shentsize,
                          bin->header.shnum);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_elf_layout_t *, n00b_result_get_err(add));
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if (sec->type == SHT_NOBITS) {
            continue;
        }

        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE,
                           i,
                           sec->flags,
                           sec->offset,
                           sec->size);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   n00b_result_get_err(add));
        }

        if (sec->type == SHT_STRTAB) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE,
                               i,
                               sec->flags,
                               sec->offset,
                               sec->size);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }

            if (i == bin->header.shstrndx) {
                add = add_interval(
                    layout->file_intervals,
                    &layout->file_interval_count,
                    N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE,
                    i,
                    sec->flags,
                    sec->offset,
                    sec->size);
                if (n00b_result_is_err(add)) {
                    return n00b_result_err(n00b_elf_layout_t *,
                                           n00b_result_get_err(add));
                }
            }
        }
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if ((sec->type == SHT_SYMTAB || sec->type == SHT_DYNSYM)
            && sec->link < bin->num_sections) {
            n00b_elf_section_t *strtab = &bin->sections[sec->link];
            if (strtab->type != SHT_STRTAB) {
                continue;
            }

            n00b_elf_layout_interval_kind_t kind =
                sec->type == SHT_DYNSYM
                    ? N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE
                    : N00B_ELF_LAYOUT_INTERVAL_SYMBOL_STRING_TABLE;
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               kind,
                               sec->link,
                               strtab->flags,
                               strtab->offset,
                               strtab->size);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }

        if (sec->type == SHT_NOTE) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE,
                               i,
                               sec->flags,
                               sec->offset,
                               sec->size);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }

        if (sec->type == SHT_NOBITS && (sec->flags & SHF_ALLOC) != 0) {
            add = add_interval(layout->vaddr_intervals,
                               &layout->vaddr_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY,
                               i,
                               sec->flags,
                               sec->addr,
                               sec->size);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE,
                           i,
                           seg->flags,
                           seg->offset,
                           seg->filesz);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   n00b_result_get_err(add));
        }

        if (seg->type == PT_INTERP) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_INTERPRETER_STRING,
                               i,
                               seg->flags,
                               seg->offset,
                               seg->filesz);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }

        if (seg->type == PT_NOTE) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE,
                               i,
                               seg->flags,
                               seg->offset,
                               seg->filesz);
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }

        add = add_interval(layout->vaddr_intervals,
                           &layout->vaddr_interval_count,
                           N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY,
                           i,
                           seg->flags,
                           seg->vaddr,
                           seg->memsz);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   n00b_result_get_err(add));
        }
    }

    n00b_option_t(uint64_t) dynstr_vaddr_opt =
        find_dynamic_value(bin, DT_STRTAB);
    n00b_option_t(uint64_t) dynstr_size_opt =
        find_dynamic_value(bin, DT_STRSZ);
    if (n00b_option_is_set(dynstr_vaddr_opt)
        && n00b_option_is_set(dynstr_size_opt)) {
        auto dynstr_off = file_offset_for_vaddr(bin,
                                                n00b_option_get(dynstr_vaddr_opt));
        if (n00b_result_is_err(dynstr_off)) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   n00b_result_get_err(dynstr_off));
        }

        n00b_option_t(uint64_t) dynstr_off_opt = n00b_result_get(dynstr_off);
        if (n00b_option_is_set(dynstr_off_opt)) {
            add = add_interval(layout->file_intervals,
                               &layout->file_interval_count,
                               N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE,
                               N00B_ELF_LAYOUT_NO_INDEX,
                               0,
                               n00b_option_get(dynstr_off_opt),
                               n00b_option_get(dynstr_size_opt));
            if (n00b_result_is_err(add)) {
                return n00b_result_err(n00b_elf_layout_t *,
                                       n00b_result_get_err(add));
            }
        }
    }

    uint64_t overlay_start = layout->file_size;
    if (bin->overlay != nullptr) {
        uint64_t overlay_size = (uint64_t)n00b_buffer_len(bin->overlay);

        if (overlay_size > layout->file_size) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   N00B_ELF_LAYOUT_ERR_INVALID);
        }

        overlay_start = layout->file_size - overlay_size;
        add = add_interval(layout->file_intervals,
                           &layout->file_interval_count,
                           N00B_ELF_LAYOUT_INTERVAL_OVERLAY,
                           N00B_ELF_LAYOUT_NO_INDEX,
                           0,
                           overlay_start,
                           overlay_size);
        if (n00b_result_is_err(add)) {
            return n00b_result_err(n00b_elf_layout_t *,
                                   n00b_result_get_err(add));
        }
    }

    add = build_coverage(layout, bin, overlay_start, allocator);
    if (n00b_result_is_err(add)) {
        return n00b_result_err(n00b_elf_layout_t *, n00b_result_get_err(add));
    }

    return n00b_result_ok(n00b_elf_layout_t *, layout);
}

n00b_result_t(n00b_option_t(n00b_elf_layout_interval_node_t *))
n00b_elf_layout_file_overlap(n00b_elf_layout_t *layout,
                             uint64_t           start,
                             uint64_t           end)
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_node_t *),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    return tree_overlap(layout->file_intervals, start, end);
}

n00b_result_t(n00b_option_t(n00b_elf_layout_interval_node_t *))
n00b_elf_layout_vaddr_overlap(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end)
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_node_t *),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    return tree_overlap(layout->vaddr_intervals, start, end);
}

n00b_result_t(n00b_elf_layout_interval_list_t)
n00b_elf_layout_file_overlaps(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_elf_layout_interval_list_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    return collect_overlaps(layout->file_intervals, start, end, allocator);
}

n00b_result_t(n00b_elf_layout_interval_list_t)
n00b_elf_layout_vaddr_overlaps(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_elf_layout_interval_list_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    return collect_overlaps(layout->vaddr_intervals, start, end, allocator);
}

n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_file_collision(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    auto overlaps = collect_overlaps(layout->file_intervals,
                                     start,
                                     end,
                                     allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);
    n00b_elf_layout_collision_t collision = {
        .start          = start,
        .end            = end,
        .intervals      = list.items,
        .interval_count = list.count,
    };
    return n00b_result_ok(n00b_elf_layout_collision_t, collision);
}

n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_vaddr_collision(n00b_elf_layout_t *layout,
                                uint64_t           start,
                                uint64_t           end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (layout == nullptr) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    auto overlaps = collect_overlaps(layout->vaddr_intervals,
                                     start,
                                     end,
                                     allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);
    n00b_elf_layout_collision_t collision = {
        .start          = start,
        .end            = end,
        .intervals      = list.items,
        .interval_count = list.count,
    };
    return n00b_result_ok(n00b_elf_layout_collision_t, collision);
}

n00b_result_t(n00b_option_t(n00b_elf_layout_interval_t))
n00b_elf_layout_next_file_interval(n00b_elf_layout_t *layout,
                                   uint64_t           start)
{
    if (layout == nullptr || layout->file_intervals == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_t),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    auto next = n00b_interval_next_low(layout->file_intervals, start);
    if (n00b_result_is_err(next)) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_interval_t),
                               N00B_ELF_LAYOUT_ERR_INTERVAL);
    }

    n00b_elf_layout_interval_node_t *node =
        (n00b_elf_layout_interval_node_t *)n00b_result_get(next);
    if (node == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_elf_layout_interval_t),
                              n00b_option_none(n00b_elf_layout_interval_t));
    }

    return n00b_result_ok(n00b_option_t(n00b_elf_layout_interval_t),
                          n00b_option_set(n00b_elf_layout_interval_t,
                                          node->data));
}

n00b_result_t(n00b_elf_layout_collision_t)
n00b_elf_layout_page_load_vaddr_collision(n00b_elf_binary_t *bin,
                                          uint64_t           start,
                                          uint64_t           end,
                                          uint64_t           page_size) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_elf_layout_collision_t collision = {
        .start = start,
        .end   = end,
    };

    if (bin == nullptr || start > end || page_size == 0) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_elf_layout_collision_t, collision);
    }

    n00b_elf_layout_interval_tree_t *tree = n00b_alloc_with_opts(
        n00b_elf_layout_interval_tree_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_interval_tree_init(tree, .allocator = allocator);

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD
            || (seg->offset == 0 && seg->memsz == 0)) {
            continue;
        }

        uint64_t high;
        if (!checked_add_u64(seg->vaddr, seg->memsz, &high)) {
            return n00b_result_err(n00b_elf_layout_collision_t,
                                   N00B_ELF_LAYOUT_ERR_OVERFLOW);
        }

        n00b_elf_layout_interval_t interval = {
            .kind  = N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY,
            .start = align_down_u64(seg->vaddr, page_size),
            .end   = high,
            .index = i,
            .flags = seg->flags,
        };
        if (interval.start == interval.end) {
            continue;
        }

        auto insert = n00b_interval_insert(tree,
                                           interval.start,
                                           interval.end,
                                           interval);
        if (n00b_result_is_err(insert)) {
            return n00b_result_err(n00b_elf_layout_collision_t,
                                   N00B_ELF_LAYOUT_ERR_INTERVAL);
        }
    }

    auto overlaps = collect_overlaps(tree, start, end, allocator);
    if (n00b_result_is_err(overlaps)) {
        return n00b_result_err(n00b_elf_layout_collision_t,
                               n00b_result_get_err(overlaps));
    }

    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);
    collision.intervals      = list.items;
    collision.interval_count = list.count;
    return n00b_result_ok(n00b_elf_layout_collision_t, collision);
}

n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_find_file_gap(n00b_elf_layout_t *layout,
                              uint64_t           start,
                              uint64_t           end,
                              uint64_t           min_size,
                              uint64_t           alignment)
{
    if (layout == nullptr || start > end || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                              n00b_option_none(n00b_elf_layout_gap_t));
    }

    uint64_t file_end = end < layout->file_size ? end : layout->file_size;
    for (uint64_t i = 0; i < layout->coverage_count; i++) {
        n00b_elf_layout_coverage_t *coverage = &layout->coverage[i];

        if (coverage->end <= start) {
            continue;
        }

        if (coverage->start >= file_end) {
            break;
        }

        if (coverage->kind == N00B_ELF_LAYOUT_COVERAGE_MODELED) {
            continue;
        }

        uint64_t gap_start = coverage->start > start ? coverage->start : start;
        uint64_t gap_end   = coverage->end < file_end ? coverage->end : file_end;
        auto gap = gap_if_satisfies(gap_kind_from_coverage(coverage->kind),
                                    gap_start,
                                    gap_end,
                                    min_size,
                                    alignment);
        if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
            return gap;
        }
    }

    if (end > layout->file_size) {
        uint64_t tail_start = start > layout->file_size ? start : layout->file_size;
        auto gap = gap_if_satisfies(N00B_ELF_LAYOUT_GAP_EOF_TAIL,
                                    tail_start,
                                    end,
                                    min_size,
                                    alignment);
        if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
            return gap;
        }
    }

    return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                          n00b_option_none(n00b_elf_layout_gap_t));
}

n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_find_vaddr_gap(n00b_elf_layout_t *layout,
                               uint64_t           start,
                               uint64_t           end,
                               uint64_t           min_size,
                               uint64_t           alignment)
{
    if (layout == nullptr || start > end || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    if (start == end) {
        return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                              n00b_option_none(n00b_elf_layout_gap_t));
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
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_INTERVAL);
    }

    uint64_t cursor = start;
    for (size_t i = 0; i < n00b_stack_len(ranges); i++) {
        n00b_interval_range_t range = ranges.data[i];

        if (cursor < range.low) {
            auto gap = gap_if_satisfies(N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED,
                                        cursor,
                                        range.low,
                                        min_size,
                                        alignment);
            if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
                n00b_stack_free(ranges);
                return gap;
            }
        }

        if (range.high > cursor) {
            cursor = range.high;
        }
    }

    if (cursor < end) {
        auto gap = gap_if_satisfies(N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED,
                                    cursor,
                                    end,
                                    min_size,
                                    alignment);
        if (n00b_result_is_err(gap) || n00b_option_is_set(n00b_result_get(gap))) {
            n00b_stack_free(ranges);
            return gap;
        }
    }

    n00b_stack_free(ranges);
    return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                          n00b_option_none(n00b_elf_layout_gap_t));
}

n00b_result_t(n00b_option_t(n00b_elf_layout_gap_t))
n00b_elf_layout_eof_tail_gap(n00b_elf_layout_t *layout,
                             uint64_t           min_size,
                             uint64_t           alignment)
{
    if (layout == nullptr || min_size == 0) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_INVALID);
    }

    uint64_t start;
    if (!align_up_u64(layout->file_size, alignment, &start)) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_OVERFLOW);
    }

    uint64_t end;
    if (!checked_add_u64(start, min_size, &end)) {
        return n00b_result_err(n00b_option_t(n00b_elf_layout_gap_t),
                               N00B_ELF_LAYOUT_ERR_OVERFLOW);
    }

    n00b_elf_layout_gap_t gap = {
        .kind  = N00B_ELF_LAYOUT_GAP_EOF_TAIL,
        .start = start,
        .end   = end,
    };
    return n00b_result_ok(n00b_option_t(n00b_elf_layout_gap_t),
                          n00b_option_set(n00b_elf_layout_gap_t, gap));
}

n00b_string_t *
n00b_elf_layout_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ELF_LAYOUT_ERR_INVALID:
        return r"ELF layout: invalid input";
    case N00B_ELF_LAYOUT_ERR_OVERFLOW:
        return r"ELF layout: arithmetic overflow";
    case N00B_ELF_LAYOUT_ERR_INTERVAL:
        return r"ELF layout: interval tree operation failed";
    default:
        return r"ELF layout: unknown error code";
    }
}

n00b_string_t *
n00b_elf_layout_interval_kind_str(n00b_elf_layout_interval_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_LAYOUT_INTERVAL_ELF_HEADER:
        return r"elf-header";
    case N00B_ELF_LAYOUT_INTERVAL_PHTAB:
        return r"program-header-table";
    case N00B_ELF_LAYOUT_INTERVAL_SHTAB:
        return r"section-header-table";
    case N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE:
        return r"section-file";
    case N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE:
        return r"section-string-table";
    case N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE:
        return r"section-name-string-table";
    case N00B_ELF_LAYOUT_INTERVAL_SYMBOL_STRING_TABLE:
        return r"symbol-string-table";
    case N00B_ELF_LAYOUT_INTERVAL_DYNAMIC_STRING_TABLE:
        return r"dynamic-string-table";
    case N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE:
        return r"segment-file";
    case N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY:
        return r"segment-memory";
    case N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY:
        return r"section-nobits-memory";
    case N00B_ELF_LAYOUT_INTERVAL_INTERPRETER_STRING:
        return r"interpreter-string";
    case N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE:
        return r"note-file";
    case N00B_ELF_LAYOUT_INTERVAL_OVERLAY:
        return r"overlay";
    default:
        return r"unknown-elf-layout-interval-kind";
    }
}

n00b_string_t *
n00b_elf_layout_coverage_kind_str(n00b_elf_layout_coverage_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_LAYOUT_COVERAGE_MODELED:
        return r"modeled";
    case N00B_ELF_LAYOUT_COVERAGE_ZERO_PADDING:
        return r"zero-padding";
    case N00B_ELF_LAYOUT_COVERAGE_UNKNOWN_NONZERO:
        return r"unknown-nonzero";
    case N00B_ELF_LAYOUT_COVERAGE_OVERLAY:
        return r"overlay";
    default:
        return r"unknown-elf-layout-coverage-kind";
    }
}

n00b_string_t *
n00b_elf_layout_gap_kind_str(n00b_elf_layout_gap_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_LAYOUT_GAP_ZERO_PADDING:
        return r"zero-padding";
    case N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO:
        return r"unknown-nonzero";
    case N00B_ELF_LAYOUT_GAP_OVERLAY:
        return r"overlay";
    case N00B_ELF_LAYOUT_GAP_EOF_TAIL:
        return r"eof-tail";
    case N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED:
        return r"vaddr-unmapped";
    default:
        return r"unknown-elf-layout-gap-kind";
    }
}

n00b_string_t *
n00b_elf_layout_section_flag_str(uint64_t flag)
{
    switch (flag) {
    case SHF_WRITE:
        return r"SHF_WRITE";
    case SHF_ALLOC:
        return r"SHF_ALLOC";
    case SHF_EXECINSTR:
        return r"SHF_EXECINSTR";
    case SHF_MERGE:
        return r"SHF_MERGE";
    case SHF_STRINGS:
        return r"SHF_STRINGS";
    case SHF_INFO_LINK:
        return r"SHF_INFO_LINK";
    case SHF_LINK_ORDER:
        return r"SHF_LINK_ORDER";
    case SHF_OS_NONCONFORMING:
        return r"SHF_OS_NONCONFORMING";
    case SHF_GROUP:
        return r"SHF_GROUP";
    case SHF_TLS:
        return r"SHF_TLS";
    default:
        return r"unknown-elf-section-flag";
    }
}

n00b_string_t *
n00b_elf_layout_segment_flag_str(uint64_t flag)
{
    switch (flag) {
    case PF_X:
        return r"PF_X";
    case PF_W:
        return r"PF_W";
    case PF_R:
        return r"PF_R";
    default:
        return r"unknown-elf-segment-flag";
    }
}
