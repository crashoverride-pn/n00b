#include "compiler/objfile/elf_rewrite.h"

#include <string.h>

#include "compiler/objfile/elf_layout.h"
#include "text/strings/string_ops.h"

#define N00B_ELF_SHN_LORESERVE 0xff00u
#define N00B_ELF_PN_XNUM       0xffffu
#define N00B_ELF64_EHDR_SIZE   64u
#define N00B_ELF64_PHDR_SIZE   56u
#define N00B_ELF64_SHDR_SIZE   64u
#define N00B_ELF64_E_ENTRY_OFF 24u
#define N00B_ELF64_E_PHOFF_OFF 32u
#define N00B_ELF64_E_PHNUM_OFF 56u
#define N00B_ELF_LOAD_PAGE_SIZE 0x1000u
#define N00B_ELF_REWRITE_MAX_PATCHES 8u

typedef struct raw_shdr {
    uint32_t name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
} raw_shdr_t;

typedef enum {
    TRUSTED_METADATA_TARGET_NONE,
    TRUSTED_METADATA_TARGET_CHALK_MARK,
    TRUSTED_METADATA_TARGET_OBJECT_BUNDLE,
} trusted_metadata_target_t;

typedef enum {
    TRUSTED_METADATA_SHAPE_OK,
    TRUSTED_METADATA_SHAPE_NOT_FOUND,
    TRUSTED_METADATA_SHAPE_DUPLICATE,
    TRUSTED_METADATA_SHAPE_UNSUPPORTED,
} trusted_metadata_shape_status_t;

typedef struct trusted_metadata_shape {
    uint64_t target_index;
    uint32_t target_name_index;
    uint64_t removed_name_start;
    uint64_t removed_name_end;
    uint64_t removed_name_size;
    uint64_t compact_strtab_size;
    uint64_t new_strtab_size;
    uint64_t new_shtab_size;
    uint32_t replacement_name_index;
    uint16_t new_shstrndx;
} trusted_metadata_shape_t;

typedef struct loadable_profile {
    uint32_t pt_phdr_index;
    uint32_t containing_load_index;
    uint64_t phtab_offset;
    uint64_t phtab_size;
    uint64_t phtab_end;
    uint64_t phtab_vaddr;
    uint64_t highest_load_end;
} loadable_profile_t;

typedef struct loadable_segment_facts {
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
    uint32_t flags;
} loadable_segment_facts_t;

static bool
section_name_write_size(n00b_string_t *section_name, uint64_t *out);

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

static bool
validate_packager_bounds(uint64_t obj_size,
                         uint64_t obj_offset,
                         uint64_t file_size,
                         uint64_t *out_end)
{
    uint64_t end;

    if (!checked_add_u64(obj_size, obj_offset, &end)) {
        return false;
    }

    if (end <= obj_size || end > file_size) {
        return false;
    }

    if (out_end != nullptr) {
        *out_end = end;
    }
    return true;
}

static bool
is_big_endian(n00b_elf_binary_t *bin)
{
    return bin->header.ident[EI_DATA] == ELFDATA2MSB;
}

static uint32_t
raw_u32(const uint8_t *p, bool big_endian)
{
    if (big_endian) {
        return ((uint32_t)p[0] << 24)
             | ((uint32_t)p[1] << 16)
             | ((uint32_t)p[2] << 8)
             | (uint32_t)p[3];
    }

    return ((uint32_t)p[3] << 24)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[1] << 8)
         | (uint32_t)p[0];
}

static uint64_t
raw_u64(const uint8_t *p, bool big_endian)
{
    if (big_endian) {
        return ((uint64_t)raw_u32(p, true) << 32) | raw_u32(p + 4, true);
    }

    return ((uint64_t)raw_u32(p + 4, false) << 32) | raw_u32(p, false);
}

static int
packager_errcode_for_profile(n00b_elf_rewrite_target_profile_reason_t reason)
{
    switch (reason) {
    case N00B_ELF_REWRITE_PROFILE_OK:                         return 0;
    case N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE:             return 11;
    case N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE:          return 15;
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE:          return 16;
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO:          return 17;
    case N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE:                 return 18;
    case N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS:       return 19;
    case N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM:                 return 20;
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM:          return 21;
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB:              return 22;
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB_BOUNDS:       return 23;
    case N00B_ELF_REWRITE_PROFILE_NO_STRTAB:                  return 24;
    case N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE_WRAP:           return 25;
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO:   return 26;
    case N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX:       return 27;
    case N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE:        return 28;
    case N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE:                return 29;
    case N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX:         return 35;
    }

    return -1;
}

static n00b_elf_rewrite_target_profile_t
profile_with_reason(n00b_elf_binary_t *bin,
                    n00b_elf_rewrite_target_profile_reason_t reason)
{
    n00b_elf_rewrite_target_profile_t profile = {
        .reason           = reason,
        .packager_errcode = packager_errcode_for_profile(reason),
    };

    if (bin != nullptr) {
        profile.section_count = bin->header.shnum;
        profile.segment_count = bin->header.phnum;
        if (bin->stream != nullptr && bin->stream->buf != nullptr) {
            profile.file_size = bin->stream->buf->byte_len;
        }
    }

    return profile;
}

static bool
read_raw_shdr(n00b_elf_binary_t *bin,
              uint64_t           index,
              raw_shdr_t        *out)
{
    n00b_buffer_t *buf = bin->stream->buf;
    uint64_t       off;
    uint64_t       shoff = bin->header.shoff;
    bool           big   = is_big_endian(bin);

    if (!checked_mul_u64(index, N00B_ELF64_SHDR_SIZE, &off)
        || !checked_add_u64(shoff, off, &off)
        || off > UINT64_MAX - N00B_ELF64_SHDR_SIZE
        || off + N00B_ELF64_SHDR_SIZE > buf->byte_len) {
        return false;
    }

    const uint8_t *p = (const uint8_t *)buf->data + off;
    *out = (raw_shdr_t){
        .name      = raw_u32(p + 0, big),
        .type      = raw_u32(p + 4, big),
        .flags     = raw_u64(p + 8, big),
        .addr      = raw_u64(p + 16, big),
        .offset    = raw_u64(p + 24, big),
        .size      = raw_u64(p + 32, big),
        .link      = raw_u32(p + 40, big),
        .info      = raw_u32(p + 44, big),
        .addralign = raw_u64(p + 48, big),
        .entsize   = raw_u64(p + 56, big),
    };
    return true;
}

static bool
zero_padding_gap_covers(n00b_elf_layout_t *layout, uint64_t start, uint64_t end)
{
    if (start == end) {
        return true;
    }

    if (layout == nullptr || end > layout->file_size) {
        return false;
    }

    auto gap_result = n00b_elf_layout_find_file_gap(layout,
                                                    start,
                                                    end,
                                                    end - start,
                                                    1);
    if (n00b_result_is_err(gap_result)) {
        return false;
    }

    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap_result);
    if (!n00b_option_is_set(gap_opt)) {
        return false;
    }

    n00b_elf_layout_gap_t gap = n00b_option_get(gap_opt);
    return gap.kind == N00B_ELF_LAYOUT_GAP_ZERO_PADDING
        && gap.start == start
        && gap.end >= end;
}

static n00b_err_t
layout_err_to_rewrite_err(n00b_err_t err)
{
    return err == N00B_ELF_LAYOUT_ERR_OVERFLOW
        ? N00B_ELF_REWRITE_ERR_OVERFLOW
        : N00B_ELF_REWRITE_ERR_ADMISSION;
}

static bool
range_contains(uint64_t start, uint64_t end, uint64_t value)
{
    return value >= start && value < end;
}

static bool
ranges_overlap(uint64_t a_start, uint64_t a_end, uint64_t b_start, uint64_t b_end)
{
    return a_start < b_end && b_start < a_end;
}

static bool
policy_allows_append_after_overlay(n00b_elf_rewrite_admit_policy_t policy)
{
    return (policy.flags & N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY) != 0
        && (policy.flags & N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY)
               != 0;
}

static uint64_t
effective_section_alignment(uint64_t requested)
{
    return requested == 0 ? 1 : requested;
}

static uint64_t
max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
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

static void
write_u16(uint8_t *p, uint16_t value, bool big_endian)
{
    if (big_endian) {
        p[0] = (uint8_t)(value >> 8);
        p[1] = (uint8_t)value;
        return;
    }

    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void
write_u32(uint8_t *p, uint32_t value, bool big_endian)
{
    if (big_endian) {
        p[0] = (uint8_t)(value >> 24);
        p[1] = (uint8_t)(value >> 16);
        p[2] = (uint8_t)(value >> 8);
        p[3] = (uint8_t)value;
        return;
    }

    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void
write_u64(uint8_t *p, uint64_t value, bool big_endian)
{
    if (big_endian) {
        write_u32(p, (uint32_t)(value >> 32), true);
        write_u32(p + 4, (uint32_t)value, true);
        return;
    }

    write_u32(p, (uint32_t)value, false);
    write_u32(p + 4, (uint32_t)(value >> 32), false);
}

static void
zero_byte_range(uint8_t *p, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

static n00b_buffer_t *
new_zero_buffer(uint64_t size, n00b_allocator_t *allocator)
{
    if (size > (uint64_t)INT64_MAX || size > (uint64_t)SIZE_MAX) {
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_buffer_new((int64_t)size,
                                         .allocator = allocator);
    zero_byte_range((uint8_t *)buf->data, size);
    buf->byte_len = (size_t)size;
    return buf;
}

static bool
section_name_is_chalk_mark(n00b_string_t *name)
{
    return name != nullptr && n00b_unicode_str_eq(name, r".chalk.mark");
}

static bool
section_name_is_object_bundle(n00b_string_t *name)
{
    return name != nullptr && n00b_unicode_str_eq(name, r".0c001.bundle");
}

static n00b_string_t *
trusted_metadata_target_name(trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        return r"";
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return r".chalk.mark";
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return r".0c001.bundle";
    }

    return r"";
}

static bool
section_name_is_trusted_metadata(n00b_string_t *name,
                                 trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        return false;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return section_name_is_chalk_mark(name);
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return section_name_is_object_bundle(name);
    }

    return false;
}

static bool
section_is_metadata_chalk_mark(n00b_elf_section_t *sec)
{
    if (sec == nullptr || !section_name_is_chalk_mark(sec->name)
        || sec->flags != 0) {
        return false;
    }

    return sec->type == SHT_PROGBITS || sec->type == SHT_NOTE;
}

static bool
section_is_metadata_object_bundle(n00b_elf_section_t *sec)
{
    if (sec == nullptr || !section_name_is_object_bundle(sec->name)
        || sec->flags != 0 || sec->type != SHT_PROGBITS || sec->size == 0
        || sec->content == nullptr || sec->content->data == nullptr) {
        return false;
    }

    return sec->content->byte_len == sec->size;
}

static bool
section_is_metadata_trusted(n00b_elf_section_t *sec,
                            trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        return false;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return section_is_metadata_chalk_mark(sec);
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return section_is_metadata_object_bundle(sec);
    }

    return false;
}

static trusted_metadata_shape_status_t
find_single_trusted_metadata(n00b_elf_binary_t        *bin,
                             trusted_metadata_target_t target,
                             uint64_t                 *index_out)
{
    bool     found = false;
    uint64_t found_index = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (!section_name_is_trusted_metadata(bin->sections[i].name,
                                              target)) {
            continue;
        }

        if (found) {
            return TRUSTED_METADATA_SHAPE_DUPLICATE;
        }

        found = true;
        found_index = i;
    }

    if (!found) {
        return TRUSTED_METADATA_SHAPE_NOT_FOUND;
    }

    *index_out = found_index;
    return TRUSTED_METADATA_SHAPE_OK;
}

static bool
find_nul_in_strtab(n00b_elf_binary_t                 *bin,
                   n00b_elf_rewrite_target_profile_t *profile,
                   uint64_t                           start,
                   uint64_t                          *end_out)
{
    if (start >= profile->shstrtab_complete_size) {
        return false;
    }

    uint64_t raw_end;
    if (!checked_add_u64(profile->shstrtab_offset,
                         profile->shstrtab_reported_size,
                         &raw_end)
        || raw_end > bin->stream->buf->byte_len) {
        return false;
    }

    const uint8_t *bytes =
        (const uint8_t *)bin->stream->buf->data + profile->shstrtab_offset;
    for (uint64_t i = start; i < profile->shstrtab_reported_size; i++) {
        if (bytes[i] == 0) {
            *end_out = i;
            return true;
        }
    }

    if (profile->shstrtab_requires_terminator
        && profile->shstrtab_reported_size == profile->shstrtab_complete_size - 1
        && start <= profile->shstrtab_reported_size) {
        *end_out = profile->shstrtab_reported_size;
        return true;
    }

    return false;
}

static bool
name_index_survives_removed_span(uint32_t index,
                                 trusted_metadata_shape_t *shape)
{
    if ((uint64_t)index < shape->removed_name_start) {
        return true;
    }

    return (uint64_t)index >= shape->removed_name_end;
}

static n00b_result_t(bool)
trusted_metadata_payload_range_is_exclusive(
    n00b_elf_binary_t          *bin,
    n00b_elf_section_t         *old_mark,
    trusted_metadata_shape_t   *shape,
    uint64_t                    old_payload_end,
    n00b_allocator_t           *allocator)
{
    auto layout_result = n00b_elf_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        return n00b_result_err(bool,
                               layout_err_to_rewrite_err(
                                   n00b_result_get_err(layout_result)));
    }

    n00b_elf_layout_t *layout = n00b_result_get(layout_result);
    auto collision_result =
        n00b_elf_layout_file_collision(layout,
                                       old_mark->offset,
                                       old_payload_end,
                                       .allocator = allocator);
    if (n00b_result_is_err(collision_result)) {
        return n00b_result_err(bool,
                               layout_err_to_rewrite_err(
                                   n00b_result_get_err(collision_result)));
    }

    n00b_elf_layout_collision_t collision =
        n00b_result_get(collision_result);
    bool saw_mark_section = false;

    for (uint64_t i = 0; i < collision.interval_count; i++) {
        n00b_elf_layout_interval_t *interval = &collision.intervals[i];
        bool same_section = interval->index == shape->target_index
                         && interval->start == old_mark->offset
                         && interval->end == old_payload_end;

        if (same_section
            && interval->kind == N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE) {
            saw_mark_section = true;
            continue;
        }

        if (same_section
            && old_mark->type == SHT_NOTE
            && interval->kind == N00B_ELF_LAYOUT_INTERVAL_NOTE_FILE) {
            continue;
        }

        return n00b_result_ok(bool, false);
    }

    return n00b_result_ok(bool, saw_mark_section);
}

static uint32_t
adjusted_name_index(uint32_t index, trusted_metadata_shape_t *shape)
{
    if ((uint64_t)index < shape->removed_name_end) {
        return index;
    }

    return (uint32_t)((uint64_t)index - shape->removed_name_size);
}

static trusted_metadata_shape_status_t
compute_trusted_metadata_shape(n00b_elf_binary_t                 *bin,
                               n00b_elf_rewrite_target_profile_t *profile,
                               trusted_metadata_target_t          target,
                               bool                               replacement,
                               trusted_metadata_shape_t          *shape)
{
    uint64_t target_index;
    uint64_t name_end;
    uint64_t name_bytes;

    if (bin == nullptr || profile == nullptr || shape == nullptr
        || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    trusted_metadata_shape_status_t find_status =
        find_single_trusted_metadata(bin, target, &target_index);
    if (find_status != TRUSTED_METADATA_SHAPE_OK) {
        return find_status;
    }

    if (target_index == bin->header.shstrndx
        || target_index >= profile->section_count
        || !section_is_metadata_trusted(&bin->sections[target_index], target)) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    raw_shdr_t target_shdr;
    if (!read_raw_shdr(bin, target_index, &target_shdr)
        || !find_nul_in_strtab(bin, profile, target_shdr.name, &name_end)
        || !checked_add_u64(name_end, 1, &name_end)
        || name_end <= target_shdr.name) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    if (!section_name_write_size(trusted_metadata_target_name(target),
                                 &name_bytes)) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    *shape = (trusted_metadata_shape_t){
        .target_index       = target_index,
        .target_name_index  = target_shdr.name,
        .removed_name_start = target_shdr.name,
        .removed_name_end   = name_end,
        .removed_name_size  = name_end - target_shdr.name,
    };

    if (profile->shstrtab_complete_size < shape->removed_name_size) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    shape->compact_strtab_size =
        profile->shstrtab_complete_size - shape->removed_name_size;
    shape->new_strtab_size = shape->compact_strtab_size;
    if (replacement) {
        if (!checked_add_u64(shape->compact_strtab_size,
                             name_bytes,
                             &shape->new_strtab_size)
            || shape->compact_strtab_size > UINT32_MAX) {
            return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
        }
        shape->replacement_name_index = (uint32_t)shape->compact_strtab_size;
    }

    uint64_t new_section_count =
        profile->section_count - 1 + (replacement ? 1u : 0u);
    if (new_section_count > UINT16_MAX
        || !checked_mul_u64(new_section_count,
                            N00B_ELF64_SHDR_SIZE,
                            &shape->new_shtab_size)) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }

    uint64_t new_shstrndx = bin->header.shstrndx;
    if (target_index < bin->header.shstrndx) {
        new_shstrndx--;
    }
    if (new_shstrndx > UINT16_MAX) {
        return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
    }
    shape->new_shstrndx = (uint16_t)new_shstrndx;

    for (uint64_t i = 0; i < profile->section_count; i++) {
        raw_shdr_t shdr;
        if (!read_raw_shdr(bin, i, &shdr)) {
            return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
        }

        if (i == target_index) {
            continue;
        }

        if (!name_index_survives_removed_span(shdr.name, shape)) {
            return TRUSTED_METADATA_SHAPE_UNSUPPORTED;
        }
    }

    return TRUSTED_METADATA_SHAPE_OK;
}

n00b_result_t(n00b_elf_rewrite_target_profile_t)
n00b_elf_rewrite_target_profile(n00b_elf_binary_t *bin)
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_target_profile_t,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    n00b_buffer_t *buf       = bin->stream->buf;
    uint64_t       file_size = buf->byte_len;
    uint64_t       table_end;

    if (bin->header.ehsize != N00B_ELF64_EHDR_SIZE) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE));
    }

    if (bin->header.shentsize != N00B_ELF64_SHDR_SIZE) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE));
    }

    if (bin->header.phentsize != N00B_ELF64_PHDR_SIZE) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE));
    }

    if (bin->header.shnum >= N00B_ELF_SHN_LORESERVE) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO));
    }

    if (bin->header.shoff == 0 || bin->header.shnum < 2) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE));
    }

    uint64_t shtab_size;
    if (!checked_mul_u64(bin->header.shnum,
                         N00B_ELF64_SHDR_SIZE,
                         &shtab_size)
        || !validate_packager_bounds(shtab_size,
                                     bin->header.shoff,
                                     file_size,
                                     &table_end)) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS));
    }

    if (bin->header.phnum == 0) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM));
    }

    if (bin->header.phnum == N00B_ELF_PN_XNUM) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM));
    }

    if (bin->header.phoff == 0) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB));
    }

    uint64_t phtab_size;
    if (!checked_mul_u64(bin->header.phnum,
                         N00B_ELF64_PHDR_SIZE,
                         &phtab_size)
        || !validate_packager_bounds(phtab_size,
                                     bin->header.phoff,
                                     file_size,
                                     nullptr)) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB_BOUNDS));
    }

    if (bin->header.shstrndx == 0) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_NO_STRTAB));
    }

    if (bin->header.shstrndx >= N00B_ELF_SHN_LORESERVE) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(
                bin,
                N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO));
    }

    if (bin->header.shstrndx >= bin->header.shnum) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(
                bin,
                N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX));
    }

    raw_shdr_t shstrtab;
    if (!read_raw_shdr(bin, bin->header.shstrndx, &shstrtab)) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS));
    }

    if (shstrtab.type != SHT_STRTAB) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE));
    }

    uint64_t shstrtab_end;
    if (!validate_packager_bounds(shstrtab.size,
                                  shstrtab.offset,
                                  file_size,
                                  &shstrtab_end)) {
        return n00b_result_ok(
            n00b_elf_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE));
    }

    n00b_elf_rewrite_target_profile_t profile =
        profile_with_reason(bin, N00B_ELF_REWRITE_PROFILE_OK);
    profile.shstrtab_offset        = shstrtab.offset;
    profile.shstrtab_reported_size = shstrtab.size;
    profile.shstrtab_complete_size = shstrtab.size;

    bool needs_terminator = shstrtab.size == 0;
    if (shstrtab.size != 0) {
        const uint8_t *p = (const uint8_t *)buf->data + shstrtab_end - 1;
        needs_terminator = *p != 0;
    }

    if (needs_terminator) {
        if (profile.shstrtab_complete_size == UINT64_MAX) {
            return n00b_result_ok(
                n00b_elf_rewrite_target_profile_t,
                profile_with_reason(
                    bin,
                    N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE_WRAP));
        }
        profile.shstrtab_complete_size++;
        profile.shstrtab_requires_terminator = true;
    }

    for (uint64_t i = 0; i < bin->header.shnum; i++) {
        raw_shdr_t section;
        if (!read_raw_shdr(bin, i, &section)) {
            return n00b_result_ok(
                n00b_elf_rewrite_target_profile_t,
                profile_with_reason(
                    bin,
                    N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS));
        }

        if (section.name >= profile.shstrtab_reported_size) {
            return n00b_result_ok(
                n00b_elf_rewrite_target_profile_t,
                profile_with_reason(
                    bin,
                    N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX));
        }
    }

    return n00b_result_ok(n00b_elf_rewrite_target_profile_t, profile);
}

static n00b_elf_rewrite_plan_t *
new_plan(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_elf_rewrite_plan_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
}

static n00b_elf_rewrite_loadable_plan_t *
new_loadable_plan(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_elf_rewrite_loadable_plan_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
}

static void
record_loadable_entrypoint_facts(n00b_elf_rewrite_loadable_plan_t *plan,
                                 n00b_elf_binary_t                *bin)
{
    plan->original_entrypoint    = bin->header.entry;
    plan->replacement_entrypoint = bin->header.entry;
    plan->entrypoint_patch_enabled = false;
}

static n00b_elf_rewrite_loadable_relocation_t
no_loadable_relocation(void)
{
    return (n00b_elf_rewrite_loadable_relocation_t){
        .status                = N00B_ELF_REWRITE_LOADABLE_RELOCATION_NONE,
        .rejection_reason      = N00B_ELF_REWRITE_REJECT_NONE,
        .source_in_place_rejection = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .pt_phdr_index         = N00B_ELF_LAYOUT_NO_INDEX,
        .new_pt_load_index     = N00B_ELF_LAYOUT_NO_INDEX,
    };
}

static n00b_elf_rewrite_loadable_phtab_adjustment_t
no_phtab_adjustment(void)
{
    return (n00b_elf_rewrite_loadable_phtab_adjustment_t){
        .status                = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE,
        .rejection_reason      = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .containing_load_index = N00B_ELF_LAYOUT_NO_INDEX,
        .pt_phdr_index         = N00B_ELF_LAYOUT_NO_INDEX,
    };
}

static n00b_elf_rewrite_loadable_relocation_t
rejected_loadable_relocation(
    n00b_elf_rewrite_rejection_reason_t       reason,
    n00b_elf_rewrite_admit_rejection_reason_t source_in_place_rejection)
{
    n00b_elf_rewrite_loadable_relocation_t facts =
        no_loadable_relocation();

    facts.status                    =
        N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED;
    facts.rejection_reason          = reason;
    facts.source_in_place_rejection = source_in_place_rejection;
    return facts;
}

static n00b_result_t(n00b_elf_rewrite_plan_t *)
rejected_plan(n00b_allocator_t                         *allocator,
              n00b_elf_rewrite_rejection_reason_t      reason,
              n00b_elf_rewrite_target_profile_t        profile,
              n00b_elf_rewrite_admit_result_t         *admission)
{
    n00b_elf_rewrite_plan_t *plan = new_plan(allocator);

    plan->operation              = N00B_ELF_REWRITE_OPERATION_METADATA_INSERT;
    plan->outcome                = N00B_ELF_REWRITE_PLAN_REJECTED;
    plan->rejection_reason       = reason;
    plan->target_profile         = profile;
    plan->table_strategy         = N00B_ELF_REWRITE_TABLE_STRATEGY_NONE;
    plan->file_size              = profile.file_size;
    plan->original_section_count = profile.section_count;
    plan->new_section_count      = profile.section_count;
    plan->new_shstrndx           = 0;
    if (admission != nullptr) {
        plan->admission = *admission;
        plan->file_size = admission->file_size;
    }

    return n00b_result_ok(n00b_elf_rewrite_plan_t *, plan);
}

static n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
rejected_loadable_plan(
    n00b_allocator_t                         *allocator,
    n00b_elf_rewrite_rejection_reason_t       reason,
    n00b_elf_rewrite_target_profile_t         profile,
    n00b_elf_rewrite_admit_loadable_result_t *admission)
{
    n00b_elf_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);

    plan->outcome                = N00B_ELF_REWRITE_PLAN_REJECTED;
    plan->rejection_reason       = reason;
    plan->target_profile         = profile;
    plan->file_size              = profile.file_size;
    plan->original_segment_count = profile.segment_count;
    plan->new_segment_count      = profile.segment_count;
    plan->phtab_strategy         = N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE;
    plan->payload_placement      = (n00b_elf_rewrite_loadable_placement_t){
        .kind = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_NONE,
    };
    plan->phtab_placement        = (n00b_elf_rewrite_loadable_placement_t){
        .kind = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_NONE,
    };
    plan->phtab_relocation       = no_loadable_relocation();

    if (admission != nullptr) {
        plan->admission                  = *admission;
        plan->file_size                  = admission->file_size;
        plan->original_segment_count     = admission->original_segment_count;
        plan->new_segment_count          = admission->new_segment_count;
        plan->phtab_strategy             = admission->phtab_strategy;
        plan->payload_placement          = admission->payload_placement;
        plan->phtab_placement            = admission->phtab_placement;
        plan->phtab_adjustment           = admission->phtab_adjustment;
        plan->p_memsz                    = admission->p_memsz;
        plan->file_alignment             = admission->effective_file_alignment;
        plan->vaddr_alignment            = admission->effective_vaddr_alignment;
        plan->segment_flags              = admission->segment_flags;
        plan->entrypoint_policy_deferred =
            admission->entrypoint_policy_deferred;
    }

    return n00b_result_ok(n00b_elf_rewrite_loadable_plan_t *, plan);
}

static bool
section_name_write_size(n00b_string_t *section_name, uint64_t *out)
{
    if (section_name->u8_bytes > UINT64_MAX - 1) {
        return false;
    }

    *out = (uint64_t)section_name->u8_bytes + 1;
    return true;
}

static bool
can_grow_tables_in_place(n00b_elf_binary_t                 *bin,
                         n00b_elf_layout_t                 *layout,
                         n00b_elf_rewrite_target_profile_t *profile,
                         n00b_string_t                     *section_name,
                         n00b_elf_rewrite_admit_placement_t placement)
{
    n00b_buffer_t *buf = bin->stream->buf;
    uint64_t       old_shtab_size;
    uint64_t       old_shtab_end;
    uint64_t       new_shtab_size;
    uint64_t       new_shtab_end;
    uint64_t       name_bytes;
    uint64_t       new_shstrtab_end;

    if (!section_name_write_size(section_name, &name_bytes)
        || !checked_mul_u64(profile->section_count,
                            N00B_ELF64_SHDR_SIZE,
                            &old_shtab_size)
        || !checked_mul_u64(profile->section_count + 1,
                            N00B_ELF64_SHDR_SIZE,
                            &new_shtab_size)
        || !checked_add_u64(bin->header.shoff,
                            old_shtab_size,
                            &old_shtab_end)
        || !checked_add_u64(bin->header.shoff,
                            new_shtab_size,
                            &new_shtab_end)
        || !checked_add_u64(profile->shstrtab_offset,
                            profile->shstrtab_complete_size,
                            &new_shstrtab_end)
        || !checked_add_u64(new_shstrtab_end,
                            name_bytes,
                            &new_shstrtab_end)) {
        return false;
    }

    if (new_shtab_end > profile->shstrtab_offset
        || new_shstrtab_end > buf->byte_len) {
        return false;
    }

    if (ranges_overlap(placement.file_offset,
                       placement.file_end,
                       bin->header.shoff,
                       new_shtab_end)
        || ranges_overlap(placement.file_offset,
                          placement.file_end,
                          profile->shstrtab_offset,
                          new_shstrtab_end)) {
        return false;
    }

    if (!zero_padding_gap_covers(layout, old_shtab_end, new_shtab_end)) {
        return false;
    }

    uint64_t old_shstrtab_file_end;
    if (!checked_add_u64(profile->shstrtab_offset,
                         profile->shstrtab_reported_size,
                         &old_shstrtab_file_end)
        || old_shstrtab_file_end > new_shstrtab_end) {
        return false;
    }

    return zero_padding_gap_covers(layout,
                                   old_shstrtab_file_end,
                                   new_shstrtab_end);
}

static bool
terminal_interval_allowed(n00b_elf_binary_t                 *bin,
                          n00b_elf_rewrite_target_profile_t *profile,
                          n00b_elf_layout_interval_t        *interval,
                          uint64_t                           shtab_end,
                          uint64_t                           shstrtab_end)
{
    if (interval->kind == N00B_ELF_LAYOUT_INTERVAL_SHTAB
        && interval->start == bin->header.shoff
        && interval->end == shtab_end) {
        return true;
    }

    if (interval->index != bin->header.shstrndx
        || interval->start != profile->shstrtab_offset
        || interval->end != shstrtab_end) {
        return false;
    }

    return interval->kind == N00B_ELF_LAYOUT_INTERVAL_SECTION_FILE
        || interval->kind == N00B_ELF_LAYOUT_INTERVAL_SECTION_STRING_TABLE
        || interval->kind == N00B_ELF_LAYOUT_INTERVAL_SECTION_NAME_STRING_TABLE;
}

static bool
terminal_tail_candidate(n00b_elf_binary_t                 *bin,
                        n00b_elf_layout_t                 *layout,
                        n00b_elf_rewrite_target_profile_t *profile,
                        uint64_t                           candidate,
                        uint64_t                           shtab_end,
                        uint64_t                           shstrtab_end,
                        n00b_allocator_t                  *allocator)
{
    auto overlaps = n00b_elf_layout_file_overlaps(layout,
                                                  candidate,
                                                  profile->file_size,
                                                  .allocator = allocator);
    if (n00b_result_is_err(overlaps)) {
        return false;
    }

    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);
    bool saw_terminal_table = false;
    for (uint64_t i = 0; i < list.count; i++) {
        if (!terminal_interval_allowed(bin,
                                       profile,
                                       &list.items[i],
                                       shtab_end,
                                       shstrtab_end)) {
            return false;
        }

        saw_terminal_table = true;
    }

    if (!saw_terminal_table) {
        return false;
    }

    const uint8_t *bytes = (const uint8_t *)bin->stream->buf->data;
    for (uint64_t i = candidate; i < profile->file_size; i++) {
        if (range_contains(bin->header.shoff, shtab_end, i)
            || range_contains(profile->shstrtab_offset, shstrtab_end, i)
            || bytes[i] == 0) {
            continue;
        }

        return false;
    }

    return true;
}

static bool
terminal_tail_incision(n00b_elf_binary_t                 *bin,
                       n00b_elf_layout_t                 *layout,
                       n00b_elf_rewrite_target_profile_t *profile,
                       uint64_t                          *incision,
                       n00b_allocator_t                  *allocator)
{
    if (bin->overlay != nullptr) {
        return false;
    }

    n00b_buffer_t *buf = bin->stream->buf;
    uint64_t       shtab_size;
    uint64_t       shtab_end;
    uint64_t       shstrtab_end;

    if (!checked_mul_u64(profile->section_count,
                         N00B_ELF64_SHDR_SIZE,
                         &shtab_size)
        || !checked_add_u64(bin->header.shoff, shtab_size, &shtab_end)
        || !checked_add_u64(profile->shstrtab_offset,
                            profile->shstrtab_reported_size,
                            &shstrtab_end)
        || shtab_end > buf->byte_len
        || shstrtab_end > buf->byte_len) {
        return false;
    }

    uint64_t start = bin->header.shoff < profile->shstrtab_offset
                   ? bin->header.shoff
                   : profile->shstrtab_offset;

    if (terminal_tail_candidate(bin,
                                layout,
                                profile,
                                start,
                                shtab_end,
                                shstrtab_end,
                                allocator)) {
        *incision = start;
        return true;
    }

    uint64_t higher = bin->header.shoff > profile->shstrtab_offset
                    ? bin->header.shoff
                    : profile->shstrtab_offset;
    if (higher != start
        && terminal_tail_candidate(bin,
                                   layout,
                                   profile,
                                   higher,
                                   shtab_end,
                                   shstrtab_end,
                                   allocator)) {
        *incision = higher;
        return true;
    }

    return false;
}

static n00b_elf_rewrite_table_strategy_t
choose_table_strategy(n00b_elf_binary_t                         *bin,
                      n00b_elf_layout_t                         *layout,
                      n00b_elf_rewrite_metadata_request_t       *request,
                      n00b_elf_rewrite_target_profile_t         *profile,
                      n00b_elf_rewrite_admit_placement_t         placement,
                      uint64_t                                  *incision,
                      n00b_allocator_t                          *allocator)
{
    n00b_elf_rewrite_admit_placement_kind_t placement_kind = placement.kind;

    if (placement_kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY) {
        return N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT;
    }

    if (can_grow_tables_in_place(bin,
                                 layout,
                                 profile,
                                 request->section_name,
                                 placement)) {
        return N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH;
    }

    if (bin->overlay != nullptr
        && policy_allows_append_after_overlay(request->policy)) {
        return N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT;
    }

    if (placement_kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL
        && terminal_tail_incision(bin, layout, profile, incision, allocator)) {
        return N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION;
    }

    return N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT;
}

static bool
append_patch(n00b_elf_rewrite_patch_t *patches,
             uint64_t                  capacity,
             uint64_t                 *count,
             n00b_elf_rewrite_patch_t  patch)
{
    if (patch.file_offset > patch.file_end) {
        return false;
    }

    if (*count == capacity) {
        return false;
    }

    uint64_t insert_at = 0;
    while (insert_at < *count
           && patches[insert_at].file_offset <= patch.file_offset) {
        insert_at++;
    }

    if (insert_at != 0 && patches[insert_at - 1].file_end > patch.file_offset) {
        return false;
    }

    if (insert_at != *count && patch.file_end > patches[insert_at].file_offset) {
        return false;
    }

    for (uint64_t i = *count; i > insert_at; i--) {
        patches[i] = patches[i - 1];
    }

    patches[insert_at] = patch;
    *count += 1;
    return true;
}

static bool
append_patch_if_nonempty(n00b_elf_rewrite_patch_t *patches,
                         uint64_t                  capacity,
                         uint64_t                 *count,
                         n00b_elf_rewrite_patch_t  patch)
{
    if (patch.file_offset == patch.file_end) {
        return true;
    }

    return append_patch(patches, capacity, count, patch);
}

static bool
table_replacement_start(n00b_elf_binary_t                         *bin,
                        n00b_elf_rewrite_metadata_request_t       *request,
                        n00b_elf_rewrite_target_profile_t         *profile,
                        n00b_elf_rewrite_table_strategy_t          strategy,
                        n00b_elf_rewrite_admit_placement_t         placement,
                        uint64_t                                  *start)
{
    switch (strategy) {
    case N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION:
        *start = placement.file_end;
        return placement.kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL;
    case N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT:
        if (placement.kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL) {
            *start = placement.file_end;
            return true;
        }

        if (bin->overlay != nullptr
            && !policy_allows_append_after_overlay(request->policy)) {
            return false;
        }

        *start = profile->file_size;
        return true;
    case N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT:
        if (placement.kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY) {
            *start = placement.file_end;
            return true;
        }

        if (bin->overlay != nullptr
            && policy_allows_append_after_overlay(request->policy)) {
            *start = profile->file_size;
            return true;
        }

        return false;
    case N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_NONE:
        return false;
    }

    return false;
}

static bool
append_table_replacement_patch(n00b_elf_rewrite_patch_t       *patches,
                               uint64_t                       *count,
                               uint64_t                        start,
                               n00b_elf_rewrite_target_profile_t *profile,
                               n00b_string_t                   *section_name)
{
    uint64_t name_bytes;
    uint64_t new_strtab_size;
    uint64_t new_shtab_size;
    uint64_t table_bytes;
    uint64_t end;

    if (!section_name_write_size(section_name, &name_bytes)
        || !checked_add_u64(profile->shstrtab_complete_size,
                            name_bytes,
                            &new_strtab_size)
        || !checked_mul_u64(profile->section_count + 1,
                            N00B_ELF64_SHDR_SIZE,
                            &new_shtab_size)
        || !checked_add_u64(new_strtab_size, new_shtab_size, &table_bytes)
        || !checked_add_u64(start, table_bytes, &end)) {
        return false;
    }

    return append_patch(
        patches,
        N00B_ELF_REWRITE_MAX_PATCHES,
        count,
        (n00b_elf_rewrite_patch_t){
            .kind                 = N00B_ELF_REWRITE_PATCH_APPENDED_TABLES,
            .file_offset          = start,
            .file_end             = end,
            .original_file_offset = start,
            .original_file_end    = start,
        });
}

static n00b_result_t(n00b_elf_rewrite_plan_t *)
accepted_plan(n00b_allocator_t                         *allocator,
              n00b_elf_binary_t                        *bin,
              n00b_elf_rewrite_metadata_request_t      *request,
              n00b_elf_rewrite_target_profile_t         profile,
              n00b_elf_rewrite_admit_result_t           admission,
              n00b_elf_rewrite_admit_placement_t        placement)
{
    auto layout_result = n00b_elf_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        n00b_err_t err = n00b_result_get_err(layout_result);
        return n00b_result_err(
            n00b_elf_rewrite_plan_t *,
            err == N00B_ELF_LAYOUT_ERR_OVERFLOW
                ? N00B_ELF_REWRITE_ERR_OVERFLOW
                : N00B_ELF_REWRITE_ERR_ADMISSION);
    }

    n00b_elf_layout_t *layout = n00b_result_get(layout_result);
    uint64_t incision = 0;
    n00b_elf_rewrite_table_strategy_t strategy =
        choose_table_strategy(bin,
                              layout,
                              request,
                              &profile,
                              placement,
                              &incision,
                              allocator);

    n00b_elf_rewrite_patch_t local[N00B_ELF_REWRITE_MAX_PATCHES] = {};
    uint64_t                 count    = 0;

    if (!append_patch(local,
                      N00B_ELF_REWRITE_MAX_PATCHES,
                      &count,
                      (n00b_elf_rewrite_patch_t){
                          .kind                 = N00B_ELF_REWRITE_PATCH_ELF_HEADER,
                          .file_offset          = 0,
                          .file_end             = N00B_ELF64_EHDR_SIZE,
                          .original_file_offset = 0,
                          .original_file_end    = N00B_ELF64_EHDR_SIZE,
                      })) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    switch (strategy) {
    case N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH: {
        uint64_t old_shtab_size;
        uint64_t new_shtab_size;
        uint64_t new_shtab_end;
        uint64_t name_bytes;
        uint64_t new_shstrtab_size;
        uint64_t new_shstrtab_end;
        if (!checked_mul_u64(profile.section_count,
                             N00B_ELF64_SHDR_SIZE,
                             &old_shtab_size)
            || !checked_mul_u64(profile.section_count + 1,
                                N00B_ELF64_SHDR_SIZE,
                                &new_shtab_size)
            || !section_name_write_size(request->section_name, &name_bytes)
            || !checked_add_u64(profile.shstrtab_complete_size,
                                name_bytes,
                                &new_shstrtab_size)
            || !checked_add_u64(bin->header.shoff,
                                new_shtab_size,
                                &new_shtab_end)
            || !checked_add_u64(profile.shstrtab_offset,
                                new_shstrtab_size,
                                &new_shstrtab_end)
            || !append_patch(
                local,
                N00B_ELF_REWRITE_MAX_PATCHES,
                &count,
                (n00b_elf_rewrite_patch_t){
                    .kind                 = N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE,
                    .file_offset          = bin->header.shoff,
                    .file_end             = new_shtab_end,
                    .original_file_offset = bin->header.shoff,
                    .original_file_end    = bin->header.shoff
                                       + old_shtab_size,
                })
            || !append_patch(
                local,
                N00B_ELF_REWRITE_MAX_PATCHES,
                &count,
                (n00b_elf_rewrite_patch_t){
                    .kind                 = N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB,
                    .file_offset          = profile.shstrtab_offset,
                    .file_end             = new_shstrtab_end,
                    .original_file_offset = profile.shstrtab_offset,
                    .original_file_end    = profile.shstrtab_offset
                                       + profile.shstrtab_reported_size,
                })) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }
        break;
    }
    case N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION:
        if (!append_patch(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_TABLE_TAIL,
                .file_offset          = incision,
                .file_end             = profile.file_size,
                .original_file_offset = incision,
                .original_file_end    = profile.file_size,
            })) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }
        break;
    case N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_NONE:
        break;
    }

    uint64_t payload_original_end = placement.kind
                                  == N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP
                                    ? placement.file_end
                                    : placement.file_offset;
    if (!append_patch(local,
                      N00B_ELF_REWRITE_MAX_PATCHES,
                      &count,
                      (n00b_elf_rewrite_patch_t){
                          .kind                 = N00B_ELF_REWRITE_PATCH_PAYLOAD,
                          .file_offset          = placement.file_offset,
                          .file_end             = placement.file_end,
                          .original_file_offset = placement.file_offset,
                          .original_file_end    = payload_original_end,
                      })) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    if (strategy == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT
        || strategy == N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT
        || strategy == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION) {
        uint64_t tables_start;
        if (!table_replacement_start(bin,
                                     request,
                                     &profile,
                                     strategy,
                                     placement,
                                     &tables_start)) {
            return rejected_plan(allocator,
                                 N00B_ELF_REWRITE_REJECT_TABLE_PLACEMENT,
                                 profile,
                                 &admission);
        }

        if (!append_table_replacement_patch(local,
                                            &count,
                                            tables_start,
                                            &profile,
                                            request->section_name)) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }
    }

    n00b_array_t(n00b_elf_rewrite_patch_t) patches =
        n00b_array_new(n00b_elf_rewrite_patch_t,
                       count,
                       .allocator = allocator);
    memcpy(patches.data, local, count * sizeof(n00b_elf_rewrite_patch_t));
    patches.len = count;

    n00b_elf_rewrite_plan_t *plan = new_plan(allocator);
    plan->operation              = N00B_ELF_REWRITE_OPERATION_METADATA_INSERT;
    plan->outcome                = N00B_ELF_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason       = N00B_ELF_REWRITE_REJECT_NONE;
    plan->target_profile         = profile;
    plan->admission              = admission;
    plan->table_strategy         = strategy;
    plan->patches                = patches;
    plan->section_name           = request->section_name;
    plan->payload                = request->payload;
    plan->section_alignment      = effective_section_alignment(
        request->file_alignment);
    plan->section_type           = request->section_type;
    plan->section_flags          = request->section_flags;
    plan->file_size              = admission.file_size;
    plan->original_section_count = profile.section_count;
    plan->new_section_count      = profile.section_count + 1;
    plan->new_shstrndx           = bin->header.shstrndx;
    plan->payload_offset         = placement.file_offset;
    plan->payload_end            = placement.file_end;

    return n00b_result_ok(n00b_elf_rewrite_plan_t *, plan);
}

static n00b_result_t(n00b_elf_rewrite_plan_t *)
plan_metadata_insert_impl(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request,
    trusted_metadata_target_t            trusted_target,
    n00b_allocator_t                    *allocator)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->section_name == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);
    }

    auto profile_result = n00b_elf_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_elf_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_ELF_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_ELF_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    if (profile.section_count + 1 >= N00B_ELF_SHN_LORESERVE) {
        return rejected_plan(allocator,
                             N00B_ELF_REWRITE_REJECT_SECTION_COUNT_PROMOTION,
                             profile,
                             nullptr);
    }

    n00b_elf_rewrite_admit_metadata_request_t admission_request = {
        .section_name          = request->section_name,
        .payload_size          = request->payload->byte_len,
        .file_alignment        = request->file_alignment,
        .section_type          = request->section_type,
        .section_flags         = request->section_flags,
        .preferred_file_offset = request->preferred_file_offset,
        .policy                = request->policy,
    };

    auto admission_result =
        trusted_target == TRUSTED_METADATA_TARGET_CHALK_MARK
            ? n00b_elf_rewrite_admit_chalk_mark_insert(
                  bin,
                  &admission_request,
                  .allocator = allocator)
        : trusted_target == TRUSTED_METADATA_TARGET_OBJECT_BUNDLE
            ? n00b_elf_rewrite_admit_object_bundle_insert(
                  bin,
                  &admission_request,
                  .allocator = allocator)
            : n00b_elf_rewrite_admit_metadata_insert(
                  bin,
                  &admission_request,
                  .allocator = allocator);
    if (n00b_result_is_err(admission_result)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_ADMISSION);
    }

    n00b_elf_rewrite_admit_result_t admission =
        n00b_result_get(admission_result);
    if (admission.outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED) {
        return rejected_plan(allocator,
                             N00B_ELF_REWRITE_REJECT_ADMISSION,
                             profile,
                             &admission);
    }

    if (!n00b_option_is_set(admission.placement)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_ADMISSION);
    }

    return accepted_plan(allocator,
                         bin,
                         request,
                         profile,
                         admission,
                         n00b_option_get(admission.placement));
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_metadata_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_metadata_insert_impl(bin,
                                     request,
                                     TRUSTED_METADATA_TARGET_NONE,
                                     allocator);
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_metadata_insert_impl(bin,
                                     request,
                                     TRUSTED_METADATA_TARGET_CHALK_MARK,
                                     allocator);
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_object_bundle_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_metadata_insert_impl(bin,
                                     request,
                                     TRUSTED_METADATA_TARGET_OBJECT_BUNDLE,
                                     allocator);
}

static bool
loadable_in_place_rejection_allows_relocation(
    n00b_elf_rewrite_loadable_phtab_adjustment_t *adjustment)
{
    return adjustment->status
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE;
}

static n00b_result_t(bool)
loadable_profile_for_relocation(n00b_elf_binary_t *bin,
                                loadable_profile_t *profile)
{
    uint64_t phtab_size;
    uint64_t phtab_end;

    if (bin == nullptr || profile == nullptr) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    *profile = (loadable_profile_t){
        .pt_phdr_index         = N00B_ELF_LAYOUT_NO_INDEX,
        .containing_load_index = N00B_ELF_LAYOUT_NO_INDEX,
    };

    if (!checked_mul_u64(bin->header.phnum,
                         N00B_ELF64_PHDR_SIZE,
                         &phtab_size)
        || !checked_add_u64(bin->header.phoff, phtab_size, &phtab_end)) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    profile->phtab_offset = bin->header.phoff;
    profile->phtab_size   = phtab_size;
    profile->phtab_end    = phtab_end;

    bool saw_load = false;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD) {
            continue;
        }

        uint64_t load_end;
        if (!checked_add_u64(seg->vaddr, seg->memsz, &load_end)) {
            return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_OVERFLOW);
        }

        if (!(seg->offset == 0 && seg->memsz == 0)) {
            saw_load = true;
            if (load_end > profile->highest_load_end) {
                profile->highest_load_end = load_end;
            }
        }

        if (bin->header.phoff < seg->offset) {
            continue;
        }

        uint64_t seg_file_end;
        if (!checked_add_u64(seg->offset, seg->filesz, &seg_file_end)) {
            return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_OVERFLOW);
        }

        if (phtab_end > seg_file_end) {
            continue;
        }

        uint64_t delta = bin->header.phoff - seg->offset;
        uint64_t vaddr;
        if (!checked_add_u64(seg->vaddr, delta, &vaddr)) {
            return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_OVERFLOW);
        }

        profile->containing_load_index = i;
        profile->phtab_vaddr          = vaddr;
    }

    if (!saw_load
        || profile->containing_load_index == N00B_ELF_LAYOUT_NO_INDEX) {
        return n00b_result_ok(bool, false);
    }

    bool saw_pt_phdr = false;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_PHDR) {
            continue;
        }

        if (saw_pt_phdr || seg->offset != bin->header.phoff
            || seg->filesz != phtab_size || seg->memsz != phtab_size
            || seg->vaddr != profile->phtab_vaddr) {
            return n00b_result_ok(bool, false);
        }

        profile->pt_phdr_index = i;
        saw_pt_phdr            = true;
    }

    return n00b_result_ok(bool, saw_pt_phdr);
}

static n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
rejected_relocated_loadable_plan(
    n00b_allocator_t                         *allocator,
    n00b_elf_rewrite_rejection_reason_t       reason,
    n00b_elf_rewrite_target_profile_t         profile,
    n00b_elf_rewrite_admit_loadable_result_t *admission,
    n00b_elf_rewrite_loadable_phtab_adjustment_t source_adjustment)
{
    auto rejected = rejected_loadable_plan(allocator, reason, profile, admission);
    if (n00b_result_is_err(rejected)) {
        return rejected;
    }

    n00b_elf_rewrite_loadable_plan_t *plan = n00b_result_get(rejected);
    plan->phtab_strategy             =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    plan->phtab_adjustment           = source_adjustment;
    plan->phtab_relocation           = rejected_loadable_relocation(
        reason,
        source_adjustment.rejection_reason);
    return n00b_result_ok(n00b_elf_rewrite_loadable_plan_t *, plan);
}

static n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
plan_relocated_loadable(
    n00b_allocator_t                         *allocator,
    n00b_elf_binary_t                        *bin,
    n00b_elf_rewrite_loadable_request_t      *request,
    n00b_elf_rewrite_target_profile_t         profile,
    n00b_elf_rewrite_admit_loadable_result_t  admission,
    n00b_elf_rewrite_loadable_phtab_adjustment_t source_adjustment)
{
    if (bin->overlay != nullptr
        && !policy_allows_append_after_overlay(request->policy)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
            profile,
            &admission,
            source_adjustment);
    }

    loadable_profile_t loadable = {};
    auto profile_ok = loadable_profile_for_relocation(bin, &loadable);
    if (n00b_result_is_err(profile_ok)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               n00b_result_get_err(profile_ok));
    }

    if (!n00b_result_get(profile_ok)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_ADMISSION,
            profile,
            &admission,
            source_adjustment);
    }

    uint64_t segment_align = max_u64(N00B_ELF_LOAD_PAGE_SIZE,
                                     admission.effective_vaddr_alignment);
    uint64_t new_phtab_size;
    uint64_t segment_offset;
    uint64_t relocated_phtab_end;
    uint64_t payload_offset;
    uint64_t payload_end;
    if (!checked_mul_u64(admission.new_segment_count,
                         N00B_ELF64_PHDR_SIZE,
                         &new_phtab_size)
        || !align_up_u64(admission.file_size, segment_align, &segment_offset)
        || !checked_add_u64(segment_offset,
                            new_phtab_size,
                            &relocated_phtab_end)
        || !align_up_u64(relocated_phtab_end,
                         admission.effective_file_alignment,
                         &payload_offset)
        || !checked_add_u64(payload_offset,
                            (uint64_t)request->payload->byte_len,
                            &payload_end)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
            profile,
            &admission,
            source_adjustment);
    }

    uint64_t payload_delta = payload_offset - segment_offset;
    uint64_t segment_filesz = payload_end - segment_offset;
    uint64_t segment_memsz;
    if (!checked_add_u64(payload_delta, admission.p_memsz, &segment_memsz)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
            profile,
            &admission,
            source_adjustment);
    }

    uint64_t segment_vaddr;
    uint64_t relocated_phtab_vaddr_end;
    uint64_t payload_vaddr;
    uint64_t payload_vaddr_end;
    if (!align_up_u64(loadable.highest_load_end,
                      segment_align,
                      &segment_vaddr)
        || !checked_add_u64(segment_vaddr,
                            new_phtab_size,
                            &relocated_phtab_vaddr_end)
        || !checked_add_u64(segment_vaddr, payload_delta, &payload_vaddr)
        || !checked_add_u64(payload_vaddr,
                            admission.p_memsz,
                            &payload_vaddr_end)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS,
            profile,
            &admission,
            source_adjustment);
    }

    uint64_t pt_phdr_delta;
    uint64_t pt_phdr_entry_offset;
    uint64_t pt_phdr_entry_end;
    uint64_t new_pt_load_delta;
    uint64_t new_pt_load_entry_offset;
    uint64_t new_pt_load_entry_end;
    if (!checked_mul_u64(loadable.pt_phdr_index,
                         N00B_ELF64_PHDR_SIZE,
                         &pt_phdr_delta)
        || !checked_add_u64(segment_offset,
                            pt_phdr_delta,
                            &pt_phdr_entry_offset)
        || !checked_add_u64(pt_phdr_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &pt_phdr_entry_end)
        || !checked_mul_u64(admission.original_segment_count,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_delta)
        || !checked_add_u64(segment_offset,
                            new_pt_load_delta,
                            &new_pt_load_entry_offset)
        || !checked_add_u64(new_pt_load_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_entry_end)) {
        return rejected_relocated_loadable_plan(
            allocator,
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
            profile,
            &admission,
            source_adjustment);
    }

    n00b_elf_rewrite_patch_t local[N00B_ELF_REWRITE_MAX_PATCHES] = {};
    uint64_t                 count = 0;
    if (!append_patch(local,
                      N00B_ELF_REWRITE_MAX_PATCHES,
                      &count,
                      (n00b_elf_rewrite_patch_t){
                          .kind                 = N00B_ELF_REWRITE_PATCH_ELF_HEADER,
                          .file_offset          = 0,
                          .file_end             = N00B_ELF64_EHDR_SIZE,
                          .original_file_offset = 0,
                          .original_file_end    = N00B_ELF64_EHDR_SIZE,
                      })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                .file_offset          = admission.file_size,
                .file_end             = segment_offset,
                .original_file_offset = admission.file_size,
                .original_file_end    = admission.file_size,
            })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB,
                .file_offset          = segment_offset,
                .file_end             = pt_phdr_entry_offset,
                .original_file_offset = segment_offset,
                .original_file_end    = segment_offset,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR,
                             .file_offset          = pt_phdr_entry_offset,
                             .file_end             = pt_phdr_entry_end,
                             .original_file_offset = pt_phdr_entry_offset,
                             .original_file_end    = pt_phdr_entry_offset,
                         })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB,
                .file_offset          = pt_phdr_entry_end,
                .file_end             = new_pt_load_entry_offset,
                .original_file_offset = pt_phdr_entry_end,
                .original_file_end    = pt_phdr_entry_end,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD,
                             .file_offset          = new_pt_load_entry_offset,
                             .file_end             = new_pt_load_entry_end,
                             .original_file_offset = new_pt_load_entry_offset,
                             .original_file_end    = new_pt_load_entry_offset,
                         })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                .file_offset          = relocated_phtab_end,
                .file_end             = payload_offset,
                .original_file_offset = relocated_phtab_end,
                .original_file_end    = relocated_phtab_end,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD,
                             .file_offset          = payload_offset,
                             .file_end             = payload_end,
                             .original_file_offset = payload_offset,
                             .original_file_end    = payload_offset,
                         })) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_array_t(n00b_elf_rewrite_patch_t) patches =
        n00b_array_new(n00b_elf_rewrite_patch_t,
                       count,
                       .allocator = allocator);
    memcpy(patches.data, local, count * sizeof(n00b_elf_rewrite_patch_t));
    patches.len = count;

    n00b_elf_rewrite_loadable_relocation_t relocation =
        no_loadable_relocation();
    relocation.status                    =
        N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED;
    relocation.source_in_place_rejection =
        source_adjustment.rejection_reason;
    relocation.elf_header_patch_offset   = 0;
    relocation.elf_header_patch_end      = N00B_ELF64_EHDR_SIZE;
    relocation.elf_header_new_phoff      = segment_offset;
    relocation.elf_header_new_phnum      = admission.new_segment_count;
    relocation.elf_header_entry          = bin->header.entry;
    relocation.original_phtab_offset     = loadable.phtab_offset;
    relocation.original_phtab_size       = loadable.phtab_size;
    relocation.original_phtab_end        = loadable.phtab_end;
    relocation.original_phtab_vaddr      = loadable.phtab_vaddr;
    relocation.relocated_phtab_offset    = segment_offset;
    relocation.relocated_phtab_size      = new_phtab_size;
    relocation.relocated_phtab_end       = relocated_phtab_end;
    relocation.relocated_phtab_vaddr     = segment_vaddr;
    relocation.relocated_phtab_vaddr_end = relocated_phtab_vaddr_end;
    relocation.pt_phdr_present           = true;
    relocation.pt_phdr_index             = loadable.pt_phdr_index;
    relocation.pt_phdr_entry_offset      = pt_phdr_entry_offset;
    relocation.pt_phdr_new_offset        = segment_offset;
    relocation.pt_phdr_new_filesz        = new_phtab_size;
    relocation.pt_phdr_new_memsz         = new_phtab_size;
    relocation.pt_phdr_new_vaddr         = segment_vaddr;
    relocation.pt_phdr_new_paddr         = segment_vaddr;
    relocation.new_pt_load_index         = (uint32_t)admission.original_segment_count;
    relocation.new_pt_load_entry_offset  = new_pt_load_entry_offset;
    relocation.new_pt_load_offset        = segment_offset;
    relocation.new_pt_load_vaddr         = segment_vaddr;
    relocation.new_pt_load_paddr         = segment_vaddr;
    relocation.new_pt_load_filesz        = segment_filesz;
    relocation.new_pt_load_memsz         = segment_memsz;
    relocation.new_pt_load_flags         = admission.segment_flags;
    relocation.new_pt_load_align         = segment_align;
    relocation.payload_offset            = payload_offset;
    relocation.payload_end               = payload_end;
    relocation.payload_vaddr             = payload_vaddr;
    relocation.payload_vaddr_end         = payload_vaddr_end;

    n00b_elf_rewrite_loadable_placement_t phtab_placement = {
        .kind        = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB,
        .file_offset = segment_offset,
        .file_end    = relocated_phtab_end,
        .vaddr       = segment_vaddr,
        .vaddr_end   = relocated_phtab_vaddr_end,
        .alignment   = segment_align,
    };
    n00b_elf_rewrite_loadable_placement_t payload_placement = {
        .kind        = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD,
        .file_offset = payload_offset,
        .file_end    = payload_end,
        .vaddr       = payload_vaddr,
        .vaddr_end   = payload_vaddr_end,
        .alignment   = admission.effective_file_alignment,
    };

    n00b_elf_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);
    plan->outcome                    = N00B_ELF_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason           = N00B_ELF_REWRITE_REJECT_NONE;
    plan->target_profile             = profile;
    plan->admission                  = admission;
    plan->patches                    = patches;
    plan->phtab_strategy             =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    plan->payload_placement          = payload_placement;
    plan->phtab_placement            = phtab_placement;
    plan->phtab_adjustment           = source_adjustment;
    plan->phtab_relocation           = relocation;
    plan->source_binary              = bin;
    plan->payload                    = request->payload;
    record_loadable_entrypoint_facts(plan, bin);
    plan->file_size                  = admission.file_size;
    plan->original_segment_count     = admission.original_segment_count;
    plan->new_segment_count          = admission.new_segment_count;
    plan->p_memsz                    = admission.p_memsz;
    plan->file_alignment             = admission.effective_file_alignment;
    plan->vaddr_alignment            = admission.effective_vaddr_alignment;
    plan->segment_flags              = admission.segment_flags;
    plan->entrypoint_policy_deferred =
        admission.entrypoint_policy_deferred;

    return n00b_result_ok(n00b_elf_rewrite_loadable_plan_t *, plan);
}

static n00b_result_t(loadable_segment_facts_t)
plan_loadable_payload_segment(n00b_elf_binary_t *bin,
                              uint64_t           file_start,
                              uint64_t           vaddr_start,
                              n00b_elf_rewrite_admit_loadable_result_t admission,
                              n00b_buffer_t     *payload)
{
    uint64_t segment_align = max_u64(N00B_ELF_LOAD_PAGE_SIZE,
                                     admission.effective_vaddr_alignment);
    uint64_t payload_offset;
    uint64_t payload_vaddr;
    uint64_t payload_end;
    uint64_t payload_vaddr_end;

    if (bin == nullptr || payload == nullptr
        || !align_up_u64(file_start, segment_align, &payload_offset)
        || !align_up_u64(vaddr_start, segment_align, &payload_vaddr)
        || !checked_add_u64(payload_offset,
                            (uint64_t)payload->byte_len,
                            &payload_end)
        || !checked_add_u64(payload_vaddr,
                            admission.p_memsz,
                            &payload_vaddr_end)) {
        return n00b_result_err(loadable_segment_facts_t,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    loadable_segment_facts_t facts = {
        .offset = payload_offset,
        .vaddr  = payload_vaddr,
        .paddr  = payload_vaddr,
        .filesz = (uint64_t)payload->byte_len,
        .memsz  = admission.p_memsz,
        .align  = segment_align,
        .flags  = admission.segment_flags,
    };

    return n00b_result_ok(loadable_segment_facts_t, facts);
}

static n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
plan_in_place_loadable(
    n00b_allocator_t                         *allocator,
    n00b_elf_binary_t                        *bin,
    n00b_elf_rewrite_loadable_request_t      *request,
    n00b_elf_rewrite_target_profile_t         profile,
    n00b_elf_rewrite_admit_loadable_result_t  admission)
{
    n00b_elf_rewrite_loadable_phtab_adjustment_t adj =
        admission.phtab_adjustment;

    if (adj.status != N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED
        || adj.containing_load_index >= bin->num_segments
        || adj.pt_phdr_index >= bin->header.phnum
        || admission.new_segment_count != admission.original_segment_count + 1) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t phtab_end;
    uint64_t pt_phdr_delta;
    uint64_t pt_phdr_entry_offset;
    uint64_t pt_phdr_entry_end;
    uint64_t new_pt_load_delta;
    uint64_t new_pt_load_entry_offset;
    uint64_t new_pt_load_entry_end;
    if (!checked_add_u64(adj.adjusted_phtab_offset,
                         adj.adjusted_phtab_size,
                         &phtab_end)
        || !checked_mul_u64(adj.pt_phdr_index,
                            N00B_ELF64_PHDR_SIZE,
                            &pt_phdr_delta)
        || !checked_add_u64(adj.adjusted_phtab_offset,
                            pt_phdr_delta,
                            &pt_phdr_entry_offset)
        || !checked_add_u64(pt_phdr_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &pt_phdr_entry_end)
        || !checked_mul_u64(admission.original_segment_count,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_delta)
        || !checked_add_u64(adj.adjusted_phtab_offset,
                            new_pt_load_delta,
                            &new_pt_load_entry_offset)
        || !checked_add_u64(new_pt_load_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_entry_end)
        || pt_phdr_entry_end > new_pt_load_entry_offset
        || new_pt_load_entry_end != phtab_end) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_elf_segment_t *containing_load =
        &bin->segments[adj.containing_load_index];
    uint64_t extended_load_memsz;
    uint64_t extended_load_vaddr_end;
    if (!checked_add_u64(containing_load->memsz,
                         adj.required_memory_extension,
                         &extended_load_memsz)
        || !checked_add_u64(containing_load->vaddr,
                            extended_load_memsz,
                            &extended_load_vaddr_end)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    uint64_t highest_load_end = extended_load_vaddr_end;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];
        if (seg->type != PT_LOAD) {
            continue;
        }

        uint64_t load_end;
        if (i == adj.containing_load_index) {
            load_end = extended_load_vaddr_end;
        } else if (!checked_add_u64(seg->vaddr, seg->memsz, &load_end)) {
            return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }

        if (load_end > highest_load_end) {
            highest_load_end = load_end;
        }
    }

    uint64_t payload_file_start = max_u64(admission.file_size, phtab_end);
    auto segment_result =
        plan_loadable_payload_segment(bin,
                                      payload_file_start,
                                      highest_load_end,
                                      admission,
                                      request->payload);
    if (n00b_result_is_err(segment_result)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               n00b_result_get_err(segment_result));
    }
    loadable_segment_facts_t segment = n00b_result_get(segment_result);

    uint64_t payload_end;
    uint64_t payload_vaddr_end;
    if (!checked_add_u64(segment.offset,
                         (uint64_t)request->payload->byte_len,
                         &payload_end)
        || !checked_add_u64(segment.vaddr,
                            admission.p_memsz,
                            &payload_vaddr_end)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_elf_rewrite_patch_t local[N00B_ELF_REWRITE_MAX_PATCHES] = {};
    uint64_t                 count = 0;
    if (!append_patch(local,
                      N00B_ELF_REWRITE_MAX_PATCHES,
                      &count,
                      (n00b_elf_rewrite_patch_t){
                          .kind                 = N00B_ELF_REWRITE_PATCH_ELF_HEADER,
                          .file_offset          = 0,
                          .file_end             = N00B_ELF64_EHDR_SIZE,
                          .original_file_offset = 0,
                          .original_file_end    = N00B_ELF64_EHDR_SIZE,
                      })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                .file_offset          = adj.containing_load_file_end,
                .file_end             = adj.adjusted_phtab_offset,
                .original_file_offset = adj.containing_load_file_end,
                .original_file_end    = adj.containing_load_file_end,
            })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB,
                .file_offset          = adj.adjusted_phtab_offset,
                .file_end             = pt_phdr_entry_offset,
                .original_file_offset = adj.adjusted_phtab_offset,
                .original_file_end    = adj.adjusted_phtab_offset,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR,
                             .file_offset          = pt_phdr_entry_offset,
                             .file_end             = pt_phdr_entry_end,
                             .original_file_offset = pt_phdr_entry_offset,
                             .original_file_end    = pt_phdr_entry_offset,
                         })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB,
                .file_offset          = pt_phdr_entry_end,
                .file_end             = new_pt_load_entry_offset,
                .original_file_offset = pt_phdr_entry_end,
                .original_file_end    = pt_phdr_entry_end,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD,
                             .file_offset          = new_pt_load_entry_offset,
                             .file_end             = new_pt_load_entry_end,
                             .original_file_offset = new_pt_load_entry_offset,
                             .original_file_end    = new_pt_load_entry_offset,
                         })
        || !append_patch_if_nonempty(
            local,
            N00B_ELF_REWRITE_MAX_PATCHES,
            &count,
            (n00b_elf_rewrite_patch_t){
                .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                .file_offset          = admission.file_size,
                .file_end             = segment.offset,
                .original_file_offset = admission.file_size,
                .original_file_end    = admission.file_size,
            })
        || !append_patch(local,
                         N00B_ELF_REWRITE_MAX_PATCHES,
                         &count,
                         (n00b_elf_rewrite_patch_t){
                             .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD,
                             .file_offset          = segment.offset,
                             .file_end             = payload_end,
                             .original_file_offset = segment.offset,
                             .original_file_end    = segment.offset,
                         })) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_array_t(n00b_elf_rewrite_patch_t) patches =
        n00b_array_new(n00b_elf_rewrite_patch_t,
                       count,
                       .allocator = allocator);
    memcpy(patches.data, local, count * sizeof(n00b_elf_rewrite_patch_t));
    patches.len = count;

    n00b_elf_rewrite_loadable_placement_t payload_placement = {
        .kind        = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD,
        .file_offset = segment.offset,
        .file_end    = payload_end,
        .vaddr       = segment.vaddr,
        .vaddr_end   = payload_vaddr_end,
        .alignment   = segment.align,
    };

    n00b_elf_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);
    plan->outcome                    = N00B_ELF_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason           = N00B_ELF_REWRITE_REJECT_NONE;
    plan->target_profile             = profile;
    plan->admission                  = admission;
    plan->patches                    = patches;
    plan->phtab_strategy             =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;
    plan->payload_placement          = payload_placement;
    plan->phtab_placement            = admission.phtab_placement;
    plan->phtab_adjustment           = adj;
    plan->phtab_relocation           = no_loadable_relocation();
    plan->source_binary              = bin;
    plan->payload                    = request->payload;
    record_loadable_entrypoint_facts(plan, bin);
    plan->file_size                  = admission.file_size;
    plan->original_segment_count     = admission.original_segment_count;
    plan->new_segment_count          = admission.new_segment_count;
    plan->p_memsz                    = admission.p_memsz;
    plan->file_alignment             = admission.effective_file_alignment;
    plan->vaddr_alignment            = admission.effective_vaddr_alignment;
    plan->segment_flags              = admission.segment_flags;
    plan->entrypoint_policy_deferred =
        admission.entrypoint_policy_deferred;

    return n00b_result_ok(n00b_elf_rewrite_loadable_plan_t *, plan);
}

n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
n00b_elf_rewrite_plan_loadable_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_loadable_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);
    }

    auto profile_result = n00b_elf_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_elf_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_ELF_REWRITE_PROFILE_OK) {
        return rejected_loadable_plan(allocator,
                                      N00B_ELF_REWRITE_REJECT_TARGET_PROFILE,
                                      profile,
                                      nullptr);
    }

    n00b_elf_rewrite_admit_loadable_request_t admission_request = {
        .payload_size     = request->payload->byte_len,
        .segment_flags    = request->segment_flags,
        .file_alignment   = request->file_alignment,
        .vaddr_alignment  = request->vaddr_alignment,
        .p_memsz          = request->p_memsz,
        .phtab_strategy   = request->phtab_strategy,
        .policy           = request->policy,
    };

    auto admission_result =
        n00b_elf_rewrite_admit_loadable_insert(bin,
                                               &admission_request,
                                               .allocator = allocator);
    if (n00b_result_is_err(admission_result)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                               N00B_ELF_REWRITE_ERR_ADMISSION);
    }

    n00b_elf_rewrite_admit_loadable_result_t admission =
        n00b_result_get(admission_result);
    if (admission.outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED) {
        if (request->phtab_strategy
                == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST
            && loadable_in_place_rejection_allows_relocation(
                   &admission.phtab_adjustment)) {
            n00b_elf_rewrite_loadable_phtab_adjustment_t source_adjustment =
                admission.phtab_adjustment;
            n00b_elf_rewrite_admit_loadable_request_t relocate_request =
                admission_request;
            relocate_request.phtab_strategy =
                N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

            admission_result =
                n00b_elf_rewrite_admit_loadable_insert(
                    bin,
                    &relocate_request,
                    .allocator = allocator);
            if (n00b_result_is_err(admission_result)) {
                return n00b_result_err(n00b_elf_rewrite_loadable_plan_t *,
                                       N00B_ELF_REWRITE_ERR_ADMISSION);
            }

            admission = n00b_result_get(admission_result);
            if (admission.outcome
                == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED) {
                return plan_relocated_loadable(allocator,
                                               bin,
                                               request,
                                               profile,
                                               admission,
                                               source_adjustment);
            }
        }

        return rejected_loadable_plan(allocator,
                                      N00B_ELF_REWRITE_REJECT_ADMISSION,
                                      profile,
                                      &admission);
    }

    if (request->phtab_strategy
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE) {
        return plan_relocated_loadable(allocator,
                                       bin,
                                       request,
                                       profile,
                                       admission,
                                       no_phtab_adjustment());
    }

    if (request->phtab_strategy
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST) {
        return plan_in_place_loadable(allocator,
                                      bin,
                                      request,
                                      profile,
                                      admission);
    }

    n00b_elf_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);
    plan->outcome                    = N00B_ELF_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason           = N00B_ELF_REWRITE_REJECT_NONE;
    plan->target_profile             = profile;
    plan->admission                  = admission;
    plan->patches                    = (n00b_array_t(n00b_elf_rewrite_patch_t)){};
    plan->phtab_strategy             = admission.phtab_strategy;
    plan->payload_placement          = admission.payload_placement;
    plan->phtab_placement            = admission.phtab_placement;
    plan->phtab_adjustment           = admission.phtab_adjustment;
    plan->phtab_relocation           = no_loadable_relocation();
    plan->source_binary              = bin;
    plan->payload                    = request->payload;
    record_loadable_entrypoint_facts(plan, bin);
    plan->file_size                  = admission.file_size;
    plan->original_segment_count     = admission.original_segment_count;
    plan->new_segment_count          = admission.new_segment_count;
    plan->p_memsz                    = admission.p_memsz;
    plan->file_alignment             = admission.effective_file_alignment;
    plan->vaddr_alignment            = admission.effective_vaddr_alignment;
    plan->segment_flags              = admission.segment_flags;
    plan->entrypoint_policy_deferred =
        admission.entrypoint_policy_deferred;

    return n00b_result_ok(n00b_elf_rewrite_loadable_plan_t *, plan);
}

n00b_result_t(bool)
n00b_elf_rewrite_loadable_plan_enable_entrypoint(
    n00b_elf_rewrite_loadable_plan_t *plan,
    uint64_t                          replacement_entrypoint)
{
    if (plan == nullptr) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->phtab_strategy == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE
        || plan->phtab_strategy
               == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    if (plan->source_binary == nullptr
        || plan->source_binary->header.ehsize != N00B_ELF64_EHDR_SIZE
        || plan->source_binary->header.entry != plan->original_entrypoint
        || plan->payload_placement.kind
               != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD) {
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_APPLY);
    }

    switch (plan->phtab_strategy) {
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST:
        if (plan->phtab_adjustment.status
                != N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED
            || plan->phtab_placement.kind
                   != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB) {
            return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_APPLY);
        }
        break;
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE:
        if (plan->phtab_relocation.status
                != N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED
            || plan->phtab_placement.kind
                   != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB) {
            return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_APPLY);
        }
        break;
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE:
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED:
        return n00b_result_err(bool, N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    plan->replacement_entrypoint = replacement_entrypoint;
    plan->entrypoint_patch_enabled = true;
    return n00b_result_ok(bool, true);
}

static bool
request_is_nonloadable_metadata(n00b_elf_rewrite_metadata_request_t *request)
{
    if (request->section_flags != 0) {
        return false;
    }

    return request->section_type == SHT_PROGBITS
        || request->section_type == SHT_NOTE;
}

static bool
request_is_object_bundle_metadata(n00b_elf_rewrite_metadata_request_t *request)
{
    return request->section_flags == 0
        && request->section_type == SHT_PROGBITS;
}

static bool
request_matches_trusted_target(n00b_elf_rewrite_metadata_request_t *request,
                               trusted_metadata_target_t target)
{
    if (!section_name_is_trusted_metadata(request->section_name, target)) {
        return false;
    }

    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        return false;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return request_is_nonloadable_metadata(request);
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return request_is_object_bundle_metadata(request);
    }

    return false;
}

static bool
replacement_plan_shape_matches_trusted_target(
    n00b_elf_rewrite_plan_t *plan,
    trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        return false;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return plan->section_flags == 0
            && (plan->section_type == SHT_PROGBITS
                || plan->section_type == SHT_NOTE);
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return plan->section_flags == 0
            && plan->section_type == SHT_PROGBITS;
    }

    return false;
}

static n00b_elf_rewrite_operation_t
trusted_metadata_replace_operation(trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        break;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return N00B_ELF_REWRITE_OPERATION_CHALK_MARK_REPLACE;
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return N00B_ELF_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE;
    }

    return N00B_ELF_REWRITE_OPERATION_METADATA_INSERT;
}

static n00b_elf_rewrite_rejection_reason_t
trusted_metadata_shape_rejection(trusted_metadata_target_t target,
                                 trusted_metadata_shape_status_t status)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        break;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        if (status == TRUSTED_METADATA_SHAPE_UNSUPPORTED) {
            return N00B_ELF_REWRITE_REJECT_CHALK_MARK_NOT_FOUND;
        }
        return N00B_ELF_REWRITE_REJECT_CHALK_MARK_NOT_FOUND;
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        switch (status) {
        case TRUSTED_METADATA_SHAPE_NOT_FOUND:
            return N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND;
        case TRUSTED_METADATA_SHAPE_DUPLICATE:
            return N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE;
        case TRUSTED_METADATA_SHAPE_UNSUPPORTED:
            return N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED;
        case TRUSTED_METADATA_SHAPE_OK:
            break;
        }
        return N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED;
    }

    return N00B_ELF_REWRITE_REJECT_TRUSTED_NAME;
}

static n00b_elf_rewrite_rejection_reason_t
trusted_metadata_overlap_rejection(trusted_metadata_target_t target)
{
    switch (target) {
    case TRUSTED_METADATA_TARGET_NONE:
        break;
    case TRUSTED_METADATA_TARGET_CHALK_MARK:
        return N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED;
    case TRUSTED_METADATA_TARGET_OBJECT_BUNDLE:
        return N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED;
    }

    return N00B_ELF_REWRITE_REJECT_TRUSTED_NAME;
}

static n00b_result_t(n00b_elf_rewrite_plan_t *)
plan_trusted_metadata_delete_or_replace(
    trusted_metadata_target_t            target,
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request,
    bool                                 replacement,
    n00b_allocator_t                    *allocator)
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (replacement) {
        if (request == nullptr) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_NULL_REQUEST);
        }

        if (request->section_name == nullptr) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME);
        }

        if (request->payload == nullptr) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);
        }

        if (request->payload->byte_len == 0) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);
        }
    }

    auto profile_result = n00b_elf_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_elf_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_ELF_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_ELF_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    if (replacement
        && !request_matches_trusted_target(request, target)) {
        return rejected_plan(allocator,
                             N00B_ELF_REWRITE_REJECT_TRUSTED_NAME,
                             profile,
                             nullptr);
    }

    trusted_metadata_shape_t shape = {};
    trusted_metadata_shape_status_t shape_status =
        compute_trusted_metadata_shape(bin,
                                       &profile,
                                       target,
                                       replacement,
                                       &shape);
    if (shape_status != TRUSTED_METADATA_SHAPE_OK) {
        return rejected_plan(allocator,
                             trusted_metadata_shape_rejection(target,
                                                              shape_status),
                             profile,
                             nullptr);
    }

    n00b_elf_section_t *old_mark = &bin->sections[shape.target_index];
    uint64_t old_payload_end;
    if (!checked_add_u64(old_mark->offset, old_mark->size, &old_payload_end)
        || old_payload_end > profile.file_size
        || old_mark->size > (uint64_t)SIZE_MAX) {
        return rejected_plan(allocator,
                             trusted_metadata_overlap_rejection(target),
                             profile,
                             nullptr);
    }

    auto exclusive_result =
        trusted_metadata_payload_range_is_exclusive(bin,
                                                    old_mark,
                                                    &shape,
                                                    old_payload_end,
                                                    allocator);
    if (n00b_result_is_err(exclusive_result)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               n00b_result_get_err(exclusive_result));
    }
    if (!n00b_result_get(exclusive_result)) {
        return rejected_plan(allocator,
                             trusted_metadata_overlap_rejection(target),
                             profile,
                             nullptr);
    }

    uint64_t new_payload_offset = 0;
    uint64_t new_payload_end    = 0;
    uint64_t tables_start       = profile.file_size;
    if (replacement) {
        new_payload_offset = profile.file_size;
        if (!checked_add_u64(new_payload_offset,
                             request->payload->byte_len,
                             &new_payload_end)) {
            return n00b_result_err(n00b_elf_rewrite_plan_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }
        tables_start = new_payload_end;
    }

    uint64_t tables_size;
    uint64_t tables_end;
    if (!checked_add_u64(shape.new_strtab_size,
                         shape.new_shtab_size,
                         &tables_size)
        || !checked_add_u64(tables_start, tables_size, &tables_end)) {
        return n00b_result_err(n00b_elf_rewrite_plan_t *,
                               N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_elf_rewrite_patch_t local[N00B_ELF_REWRITE_MAX_PATCHES] = {};
    uint64_t count = 0;
    bool patch_ok =
        append_patch(local,
                     N00B_ELF_REWRITE_MAX_PATCHES,
                     &count,
                     (n00b_elf_rewrite_patch_t){
                         .kind                 = N00B_ELF_REWRITE_PATCH_ELF_HEADER,
                         .file_offset          = 0,
                         .file_end             = N00B_ELF64_EHDR_SIZE,
                         .original_file_offset = 0,
                         .original_file_end    = N00B_ELF64_EHDR_SIZE,
                     })
        && append_patch(local,
                        N00B_ELF_REWRITE_MAX_PATCHES,
                        &count,
                        (n00b_elf_rewrite_patch_t){
                            .kind                 = N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD,
                            .file_offset          = old_mark->offset,
                            .file_end             = old_payload_end,
                            .original_file_offset = old_mark->offset,
                            .original_file_end    = old_payload_end,
                        });

    if (replacement) {
        patch_ok =
            patch_ok
            && append_patch(local,
                            N00B_ELF_REWRITE_MAX_PATCHES,
                            &count,
                            (n00b_elf_rewrite_patch_t){
                                .kind                 = N00B_ELF_REWRITE_PATCH_PAYLOAD,
                                .file_offset          = new_payload_offset,
                                .file_end             = new_payload_end,
                                .original_file_offset = new_payload_offset,
                                .original_file_end    = new_payload_offset,
                            });
    }

    patch_ok =
        patch_ok
        && append_patch(local,
                        N00B_ELF_REWRITE_MAX_PATCHES,
                        &count,
                        (n00b_elf_rewrite_patch_t){
                            .kind                 = N00B_ELF_REWRITE_PATCH_APPENDED_TABLES,
                            .file_offset          = tables_start,
                            .file_end             = tables_end,
                            .original_file_offset = tables_start,
                            .original_file_end    = tables_start,
                        });

    if (!patch_ok) {
        return rejected_plan(allocator,
                             trusted_metadata_overlap_rejection(target),
                             profile,
                             nullptr);
    }

    n00b_array_t(n00b_elf_rewrite_patch_t) patches =
        n00b_array_new(n00b_elf_rewrite_patch_t,
                       count,
                       .allocator = allocator);
    memcpy(patches.data, local, count * sizeof(n00b_elf_rewrite_patch_t));
    patches.len = count;

    n00b_elf_rewrite_plan_t *plan = new_plan(allocator);
    plan->operation = replacement
        ? trusted_metadata_replace_operation(target)
        : N00B_ELF_REWRITE_OPERATION_CHALK_MARK_DELETE;
    plan->outcome                = N00B_ELF_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason       = N00B_ELF_REWRITE_REJECT_NONE;
    plan->target_profile         = profile;
    plan->table_strategy         = N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT;
    plan->patches                = patches;
    plan->section_name           = trusted_metadata_target_name(target);
    plan->payload                = replacement ? request->payload : nullptr;
    plan->section_alignment      =
        replacement ? effective_section_alignment(request->file_alignment) : 1;
    plan->section_type           = replacement ? request->section_type : 0;
    plan->section_flags          = replacement ? request->section_flags : 0;
    plan->file_size              = profile.file_size;
    plan->original_section_count = profile.section_count;
    plan->new_section_count      = profile.section_count - 1
                                 + (replacement ? 1u : 0u);
    plan->removed_section_index  = shape.target_index;
    plan->removed_payload_offset = old_mark->offset;
    plan->removed_payload_end    = old_payload_end;
    plan->new_shstrndx           = shape.new_shstrndx;
    plan->payload_offset         = new_payload_offset;
    plan->payload_end            = new_payload_end;

    return n00b_result_ok(n00b_elf_rewrite_plan_t *, plan);
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_delete(
    n00b_elf_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_trusted_metadata_delete_or_replace(
        TRUSTED_METADATA_TARGET_CHALK_MARK,
        bin,
        nullptr,
        false,
        allocator);
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_trusted_metadata_delete_or_replace(
        TRUSTED_METADATA_TARGET_CHALK_MARK,
        bin,
        request,
        true,
        allocator);
}

n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_object_bundle_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return plan_trusted_metadata_delete_or_replace(
        TRUSTED_METADATA_TARGET_OBJECT_BUNDLE,
        bin,
        request,
        true,
        allocator);
}

static n00b_elf_rewrite_patch_t *
find_plan_patch(n00b_elf_rewrite_plan_t *plan,
                n00b_elf_rewrite_patch_kind_t kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static bool
new_strtab_size_and_name_index(n00b_elf_rewrite_plan_t *plan,
                               uint64_t                *size_out,
                               uint32_t                *name_index_out)
{
    uint64_t name_bytes;
    uint64_t new_size;

    if (plan->target_profile.shstrtab_complete_size > UINT32_MAX
        || !section_name_write_size(plan->section_name, &name_bytes)
        || !checked_add_u64(plan->target_profile.shstrtab_complete_size,
                            name_bytes,
                            &new_size)) {
        return false;
    }

    *size_out       = new_size;
    *name_index_out =
        (uint32_t)plan->target_profile.shstrtab_complete_size;
    return true;
}

static n00b_buffer_t *
build_rewrite_shstrtab(n00b_elf_binary_t       *bin,
                       n00b_elf_rewrite_plan_t *plan,
                       n00b_allocator_t        *allocator)
{
    uint64_t new_size;
    uint32_t name_index;

    if (!new_strtab_size_and_name_index(plan, &new_size, &name_index)) {
        return nullptr;
    }

    uint64_t original_end;
    if (!checked_add_u64(plan->target_profile.shstrtab_offset,
                         plan->target_profile.shstrtab_reported_size,
                         &original_end)
        || original_end > bin->stream->buf->byte_len) {
        return nullptr;
    }

    n00b_buffer_t *strtab = new_zero_buffer(new_size, allocator);
    if (strtab == nullptr) {
        return nullptr;
    }

    memcpy(strtab->data,
           bin->stream->buf->data + plan->target_profile.shstrtab_offset,
           (size_t)plan->target_profile.shstrtab_reported_size);

    if (plan->target_profile.shstrtab_requires_terminator) {
        strtab->data[plan->target_profile.shstrtab_reported_size] = '\0';
    }

    memcpy(strtab->data + name_index,
           plan->section_name->data,
           plan->section_name->u8_bytes);
    strtab->data[name_index + plan->section_name->u8_bytes] = '\0';
    return strtab;
}

static n00b_buffer_t *
build_rewrite_shtab(n00b_elf_binary_t       *bin,
                    n00b_elf_rewrite_plan_t *plan,
                    uint64_t                 shstrtab_offset,
                    uint64_t                 shstrtab_size,
                    uint32_t                 name_index,
                    n00b_allocator_t        *allocator)
{
    uint64_t old_shtab_size;
    uint64_t new_shtab_size;
    uint64_t old_shtab_end;
    bool     big = is_big_endian(bin);

    if (plan->payload_end < plan->payload_offset
        || (uint64_t)plan->payload->byte_len
               != plan->payload_end - plan->payload_offset
        || plan->new_section_count != plan->original_section_count + 1
        || !checked_mul_u64(plan->original_section_count,
                            N00B_ELF64_SHDR_SIZE,
                            &old_shtab_size)
        || !checked_mul_u64(plan->new_section_count,
                            N00B_ELF64_SHDR_SIZE,
                            &new_shtab_size)
        || !checked_add_u64(bin->header.shoff,
                            old_shtab_size,
                            &old_shtab_end)
        || old_shtab_end > bin->stream->buf->byte_len) {
        return nullptr;
    }

    n00b_buffer_t *shtab = new_zero_buffer(new_shtab_size, allocator);
    if (shtab == nullptr) {
        return nullptr;
    }

    memcpy(shtab->data,
           bin->stream->buf->data + bin->header.shoff,
           (size_t)old_shtab_size);

    uint64_t shstrtab_header;
    if (!checked_mul_u64(bin->header.shstrndx,
                         N00B_ELF64_SHDR_SIZE,
                         &shstrtab_header)
        || shstrtab_header > old_shtab_size
        || old_shtab_size - shstrtab_header < N00B_ELF64_SHDR_SIZE) {
        return nullptr;
    }

    uint8_t *shstrtab_shdr = (uint8_t *)shtab->data + shstrtab_header;
    write_u64(shstrtab_shdr + 24, shstrtab_offset, big);
    write_u64(shstrtab_shdr + 32, shstrtab_size, big);

    uint8_t *new_shdr = (uint8_t *)shtab->data + old_shtab_size;
    write_u32(new_shdr + 0, name_index, big);
    write_u32(new_shdr + 4, plan->section_type, big);
    write_u64(new_shdr + 8, plan->section_flags, big);
    write_u64(new_shdr + 16, 0, big);
    write_u64(new_shdr + 24, plan->payload_offset, big);
    write_u64(new_shdr + 32, plan->payload->byte_len, big);
    write_u32(new_shdr + 40, 0, big);
    write_u32(new_shdr + 44, 0, big);
    write_u64(new_shdr + 48, effective_section_alignment(
                                  plan->section_alignment),
              big);
    write_u64(new_shdr + 56, 0, big);

    return shtab;
}

static void
write_raw_shdr(uint8_t *p, raw_shdr_t *shdr, bool big)
{
    write_u32(p + 0, shdr->name, big);
    write_u32(p + 4, shdr->type, big);
    write_u64(p + 8, shdr->flags, big);
    write_u64(p + 16, shdr->addr, big);
    write_u64(p + 24, shdr->offset, big);
    write_u64(p + 32, shdr->size, big);
    write_u32(p + 40, shdr->link, big);
    write_u32(p + 44, shdr->info, big);
    write_u64(p + 48, shdr->addralign, big);
    write_u64(p + 56, shdr->entsize, big);
}

static bool
trusted_metadata_plan_is_replacement(n00b_elf_rewrite_plan_t *plan)
{
    return plan->operation == N00B_ELF_REWRITE_OPERATION_CHALK_MARK_REPLACE
        || plan->operation == N00B_ELF_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE;
}

static n00b_buffer_t *
build_trusted_metadata_shstrtab(n00b_elf_binary_t       *bin,
                                n00b_elf_rewrite_plan_t *plan,
                                trusted_metadata_shape_t *shape,
                                n00b_allocator_t        *allocator)
{
    n00b_buffer_t *old_strtab =
        new_zero_buffer(plan->target_profile.shstrtab_complete_size,
                        allocator);
    n00b_buffer_t *new_strtab =
        new_zero_buffer(shape->new_strtab_size, allocator);

    if (old_strtab == nullptr || new_strtab == nullptr) {
        return nullptr;
    }

    uint64_t raw_end;
    if (!checked_add_u64(plan->target_profile.shstrtab_offset,
                         plan->target_profile.shstrtab_reported_size,
                         &raw_end)
        || raw_end > bin->stream->buf->byte_len) {
        return nullptr;
    }

    memcpy(old_strtab->data,
           bin->stream->buf->data + plan->target_profile.shstrtab_offset,
           (size_t)plan->target_profile.shstrtab_reported_size);

    if (plan->target_profile.shstrtab_requires_terminator) {
        old_strtab->data[plan->target_profile.shstrtab_reported_size] = '\0';
    }

    memcpy(new_strtab->data,
           old_strtab->data,
           (size_t)shape->removed_name_start);
    memcpy(new_strtab->data + shape->removed_name_start,
           old_strtab->data + shape->removed_name_end,
           (size_t)(plan->target_profile.shstrtab_complete_size
                    - shape->removed_name_end));

    if (trusted_metadata_plan_is_replacement(plan)) {
        memcpy(new_strtab->data + shape->replacement_name_index,
               plan->section_name->data,
               plan->section_name->u8_bytes);
        new_strtab->data[shape->replacement_name_index
                         + plan->section_name->u8_bytes] = '\0';
    }

    return new_strtab;
}

static n00b_buffer_t *
build_trusted_metadata_shtab(n00b_elf_binary_t       *bin,
                             n00b_elf_rewrite_plan_t *plan,
                             trusted_metadata_shape_t *shape,
                             uint64_t                 shstrtab_offset,
                             uint64_t                 shstrtab_size,
                             n00b_allocator_t        *allocator)
{
    n00b_buffer_t *shtab = new_zero_buffer(shape->new_shtab_size, allocator);
    if (shtab == nullptr) {
        return nullptr;
    }

    bool     big = is_big_endian(bin);
    uint64_t out_index = 0;
    for (uint64_t i = 0; i < plan->original_section_count; i++) {
        if (i == shape->target_index) {
            continue;
        }

        raw_shdr_t shdr;
        if (!read_raw_shdr(bin, i, &shdr)
            || !name_index_survives_removed_span(shdr.name, shape)) {
            return nullptr;
        }

        shdr.name = adjusted_name_index(shdr.name, shape);
        if (i == bin->header.shstrndx) {
            shdr.offset = shstrtab_offset;
            shdr.size   = shstrtab_size;
        }

        write_raw_shdr((uint8_t *)shtab->data + out_index * N00B_ELF64_SHDR_SIZE,
                       &shdr,
                       big);
        out_index++;
    }

    if (trusted_metadata_plan_is_replacement(plan)) {
        raw_shdr_t shdr = {
            .name      = shape->replacement_name_index,
            .type      = plan->section_type,
            .flags     = plan->section_flags,
            .addr      = 0,
            .offset    = plan->payload_offset,
            .size      = plan->payload->byte_len,
            .link      = 0,
            .info      = 0,
            .addralign = effective_section_alignment(plan->section_alignment),
            .entsize   = 0,
        };
        write_raw_shdr((uint8_t *)shtab->data + out_index * N00B_ELF64_SHDR_SIZE,
                       &shdr,
                       big);
        out_index++;
    }

    if (out_index != plan->new_section_count) {
        return nullptr;
    }

    return shtab;
}

static bool
plan_output_size(n00b_elf_binary_t       *bin,
                 n00b_elf_rewrite_plan_t *plan,
                 uint64_t                *size_out)
{
    uint64_t output_size = bin->stream->buf->byte_len;

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];
        if (patch->file_offset > patch->file_end) {
            return false;
        }

        if (patch->file_end > output_size) {
            output_size = patch->file_end;
        }
    }

    *size_out = output_size;
    return true;
}

static bool
write_output_bytes(n00b_buffer_t *out,
                   uint64_t       offset,
                   const void    *bytes,
                   uint64_t       len)
{
    uint64_t end;

    if (len == 0) {
        return true;
    }

    if (!checked_add_u64(offset, len, &end)
        || end > out->byte_len
        || offset > (uint64_t)SIZE_MAX
        || len > (uint64_t)SIZE_MAX) {
        return false;
    }

    memcpy(out->data + offset, bytes, (size_t)len);
    return true;
}

static void
write_phdr(uint8_t *p,
           uint32_t type,
           uint32_t flags,
           uint64_t offset,
           uint64_t vaddr,
           uint64_t paddr,
           uint64_t filesz,
           uint64_t memsz,
           uint64_t align,
           bool     big)
{
    write_u32(p + 0, type, big);
    write_u32(p + 4, flags, big);
    write_u64(p + 8, offset, big);
    write_u64(p + 16, vaddr, big);
    write_u64(p + 24, paddr, big);
    write_u64(p + 32, filesz, big);
    write_u64(p + 40, memsz, big);
    write_u64(p + 48, align, big);
}

static bool
zero_output_range(n00b_buffer_t *out, uint64_t offset, uint64_t end)
{
    if (offset > end || end > out->byte_len
        || offset > (uint64_t)SIZE_MAX
        || end - offset > (uint64_t)SIZE_MAX) {
        return false;
    }

    zero_byte_range((uint8_t *)out->data + offset, end - offset);
    return true;
}

static bool
patch_output_header(n00b_buffer_t           *out,
                    n00b_elf_binary_t       *bin,
                    n00b_elf_rewrite_plan_t *plan,
                    uint64_t                 shtab_offset)
{
    if (out->byte_len < N00B_ELF64_EHDR_SIZE
        || plan->new_section_count > UINT16_MAX
        || plan->new_shstrndx > UINT16_MAX) {
        return false;
    }

    bool     big = is_big_endian(bin);
    uint8_t *p   = (uint8_t *)out->data;

    write_u64(p + 40, shtab_offset, big);
    write_u16(p + 60, (uint16_t)plan->new_section_count, big);
    write_u16(p + 62, plan->new_shstrndx, big);
    return true;
}

static bool
compute_live_table_offsets(n00b_elf_rewrite_plan_t *plan,
                           uint64_t                 strtab_size,
                           uint64_t                *shstrtab_offset,
                           uint64_t                *shtab_offset)
{
    switch (plan->table_strategy) {
    case N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH: {
        n00b_elf_rewrite_patch_t *strtab_patch =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB);
        n00b_elf_rewrite_patch_t *shtab_patch =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE);

        if (strtab_patch == nullptr || shtab_patch == nullptr) {
            return false;
        }

        *shstrtab_offset = strtab_patch->file_offset;
        *shtab_offset    = shtab_patch->file_offset;
        return true;
    }
    case N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT: {
        n00b_elf_rewrite_patch_t *tables =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);

        if (tables == nullptr
            || !checked_add_u64(tables->file_offset,
                                strtab_size,
                                shtab_offset)) {
            return false;
        }

        *shstrtab_offset = tables->file_offset;
        return true;
    }
    case N00B_ELF_REWRITE_TABLE_STRATEGY_NONE:
        return false;
    }

    return false;
}

static n00b_buffer_t *
combine_replacement_tables(n00b_buffer_t    *strtab,
                           n00b_buffer_t    *shtab,
                           n00b_allocator_t *allocator)
{
    uint64_t size;

    if (!checked_add_u64(strtab->byte_len, shtab->byte_len, &size)) {
        return nullptr;
    }

    n00b_buffer_t *tables = new_zero_buffer(size, allocator);
    if (tables == nullptr) {
        return nullptr;
    }

    memcpy(tables->data, strtab->data, strtab->byte_len);
    memcpy(tables->data + strtab->byte_len, shtab->data, shtab->byte_len);
    return tables;
}

static bool
apply_supports_placement_kind(n00b_elf_rewrite_admit_placement_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL:
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP:
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY:
        return true;
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE:
        return false;
    }

    return false;
}

static bool
apply_supports_table_strategy(n00b_elf_rewrite_table_strategy_t strategy)
{
    switch (strategy) {
    case N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT:
    case N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT:
        return true;
    case N00B_ELF_REWRITE_TABLE_STRATEGY_NONE:
        return false;
    }

    return false;
}

static bool
apply_supports_overlay_shape(n00b_elf_binary_t                  *bin,
                             n00b_elf_rewrite_plan_t            *plan,
                             n00b_elf_rewrite_admit_placement_t  placement)
{
    bool append_after_overlay =
        policy_allows_append_after_overlay(plan->admission.policy);

    if (placement.kind == N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY) {
        return bin->overlay != nullptr
            && append_after_overlay
            && plan->table_strategy
                   == N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT;
    }

    if (bin->overlay == nullptr) {
        return plan->table_strategy
            != N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT;
    }

    return append_after_overlay
        && plan->table_strategy
               == N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT;
}

static n00b_elf_rewrite_patch_t *
find_loadable_plan_patch(n00b_elf_rewrite_loadable_plan_t *plan,
                         n00b_elf_rewrite_patch_kind_t     kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static bool
loadable_plan_output_size(n00b_elf_binary_t                  *bin,
                          n00b_elf_rewrite_loadable_plan_t   *plan,
                          uint64_t                           *size_out)
{
    uint64_t output_size = bin->stream->buf->byte_len;

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];
        if (patch->file_offset > patch->file_end) {
            return false;
        }

        if (patch->file_end > output_size) {
            output_size = patch->file_end;
        }
    }

    *size_out = output_size;
    return true;
}

static bool
loadable_patch_is_header(n00b_elf_rewrite_patch_t *patch)
{
    return patch->kind == N00B_ELF_REWRITE_PATCH_ELF_HEADER
        && patch->file_offset == 0
        && patch->file_end == N00B_ELF64_EHDR_SIZE
        && patch->original_file_offset == 0
        && patch->original_file_end == N00B_ELF64_EHDR_SIZE;
}

static bool
loadable_patch_is_insert(n00b_elf_rewrite_patch_t *patch,
                         n00b_elf_rewrite_patch_kind_t kind,
                         uint64_t start,
                         uint64_t end)
{
    return patch->kind == kind
        && patch->file_offset == start
        && patch->file_end == end
        && patch->original_file_offset == start
        && patch->original_file_end == start
        && start < end;
}

static bool
loadable_validate_patch_coverage(uint64_t *covered, uint64_t start, uint64_t end)
{
    uint64_t len;

    if (start >= end || !checked_add_u64(*covered, end - start, &len)) {
        return false;
    }

    *covered = len;
    return true;
}

static bool
loadable_patch_matches_optional_padding(n00b_elf_rewrite_patch_t *patch,
                                        uint64_t start,
                                        uint64_t end,
                                        bool    *seen)
{
    if (start == end) {
        return false;
    }

    if (!*seen
        && loadable_patch_is_insert(patch,
                                    N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                                    start,
                                    end)) {
        *seen = true;
        return true;
    }

    return false;
}

static bool
loadable_patch_matches_optional_phtab(n00b_elf_rewrite_patch_t *patch,
                                      n00b_elf_rewrite_patch_kind_t kind,
                                      uint64_t start,
                                      uint64_t end,
                                      bool    *seen)
{
    if (start == end) {
        return false;
    }

    if (!*seen && loadable_patch_is_insert(patch, kind, start, end)) {
        *seen = true;
        return true;
    }

    return false;
}

static bool
validate_loadable_patch_set(n00b_elf_rewrite_loadable_plan_t *plan,
                            bool relocated,
                            uint64_t live_phtab_offset,
                            uint64_t live_phtab_end,
                            uint64_t pt_phdr_entry_offset,
                            uint64_t new_pt_load_entry_offset,
                            uint64_t first_padding_offset,
                            uint64_t first_padding_end,
                            uint64_t second_padding_offset,
                            uint64_t second_padding_end)
{
    uint64_t phtab_covered = 0;
    bool     saw_header    = false;
    bool     saw_payload   = false;
    bool     saw_pt_phdr   = false;
    bool     saw_new_load  = false;
    bool     saw_first_pad = first_padding_offset == first_padding_end;
    bool     saw_second_pad = second_padding_offset == second_padding_end;
    uint64_t pt_phdr_entry_end;
    uint64_t new_pt_load_entry_end;
    bool     saw_first_phtab;
    bool     saw_second_phtab;
    n00b_elf_rewrite_patch_kind_t phtab_kind =
        relocated
            ? N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB
            : N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB;

    if (plan->patches.data == nullptr || plan->patches.len == 0
        || !checked_add_u64(pt_phdr_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &pt_phdr_entry_end)
        || !checked_add_u64(new_pt_load_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_entry_end)
        || live_phtab_offset >= live_phtab_end
        || pt_phdr_entry_offset < live_phtab_offset
        || pt_phdr_entry_end > live_phtab_end
        || new_pt_load_entry_offset < live_phtab_offset
        || new_pt_load_entry_end > live_phtab_end) {
        return false;
    }

    saw_first_phtab = live_phtab_offset == pt_phdr_entry_offset;
    saw_second_phtab = pt_phdr_entry_end == new_pt_load_entry_offset;

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];

        if (patch->file_offset >= patch->file_end
            || patch->original_file_offset > patch->original_file_end
            || (i != 0
                && plan->patches.data[i - 1].file_end
                       > patch->file_offset)) {
            return false;
        }

        switch (patch->kind) {
        case N00B_ELF_REWRITE_PATCH_ELF_HEADER:
            if (saw_header || !loadable_patch_is_header(patch)) {
                return false;
            }
            saw_header = true;
            break;
        case N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD:
            if (saw_payload
                || !loadable_patch_is_insert(
                    patch,
                    N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD,
                    plan->payload_placement.file_offset,
                    plan->payload_placement.file_end)) {
                return false;
            }
            saw_payload = true;
            break;
        case N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING:
            if (!loadable_patch_matches_optional_padding(patch,
                                                         first_padding_offset,
                                                         first_padding_end,
                                                         &saw_first_pad)
                && !loadable_patch_matches_optional_padding(
                    patch,
                    second_padding_offset,
                    second_padding_end,
                    &saw_second_pad)) {
                return false;
            }
            break;
        case N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB:
            if (relocated
                || (!loadable_patch_matches_optional_phtab(
                        patch,
                        phtab_kind,
                        live_phtab_offset,
                        pt_phdr_entry_offset,
                        &saw_first_phtab)
                    && !loadable_patch_matches_optional_phtab(
                        patch,
                        phtab_kind,
                        pt_phdr_entry_end,
                        new_pt_load_entry_offset,
                        &saw_second_phtab))
                || !loadable_validate_patch_coverage(&phtab_covered,
                                                     patch->file_offset,
                                                     patch->file_end)) {
                return false;
            }
            break;
        case N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR:
            if (relocated || saw_pt_phdr
                || !loadable_patch_is_insert(
                    patch,
                    N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR,
                    pt_phdr_entry_offset,
                    pt_phdr_entry_end)
                || !loadable_validate_patch_coverage(&phtab_covered,
                                                     patch->file_offset,
                                                     patch->file_end)) {
                return false;
            }
            saw_pt_phdr = true;
            break;
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB:
            if (!relocated
                || (!loadable_patch_matches_optional_phtab(
                        patch,
                        phtab_kind,
                        live_phtab_offset,
                        pt_phdr_entry_offset,
                        &saw_first_phtab)
                    && !loadable_patch_matches_optional_phtab(
                        patch,
                        phtab_kind,
                        pt_phdr_entry_end,
                        new_pt_load_entry_offset,
                        &saw_second_phtab))
                || !loadable_validate_patch_coverage(&phtab_covered,
                                                     patch->file_offset,
                                                     patch->file_end)) {
                return false;
            }
            break;
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR:
            if (!relocated || saw_pt_phdr
                || !loadable_patch_is_insert(
                    patch,
                    N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR,
                    pt_phdr_entry_offset,
                    pt_phdr_entry_end)
                || !loadable_validate_patch_coverage(&phtab_covered,
                                                     patch->file_offset,
                                                     patch->file_end)) {
                return false;
            }
            saw_pt_phdr = true;
            break;
        case N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD:
            if (saw_new_load
                || !loadable_patch_is_insert(
                    patch,
                    N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD,
                    new_pt_load_entry_offset,
                    new_pt_load_entry_end)
                || !loadable_validate_patch_coverage(&phtab_covered,
                                                     patch->file_offset,
                                                     patch->file_end)) {
                return false;
            }
            saw_new_load = true;
            break;
        case N00B_ELF_REWRITE_PATCH_PAYLOAD:
        case N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB:
        case N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE:
        case N00B_ELF_REWRITE_PATCH_TABLE_TAIL:
        case N00B_ELF_REWRITE_PATCH_APPENDED_TABLES:
        case N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD:
            return false;
        }
    }

    return saw_header
        && saw_payload
        && saw_pt_phdr
        && saw_new_load
        && saw_first_pad
        && saw_second_pad
        && saw_first_phtab
        && saw_second_phtab
        && phtab_covered == live_phtab_end - live_phtab_offset;
}

static bool
patch_output_loadable_header(n00b_buffer_t     *out,
                             n00b_elf_binary_t *bin,
                             n00b_elf_rewrite_loadable_plan_t *plan,
                             uint64_t           phoff)
{
    if (out->byte_len < N00B_ELF64_EHDR_SIZE
        || plan->new_segment_count > UINT16_MAX) {
        return false;
    }

    bool     big = is_big_endian(bin);
    uint8_t *p   = (uint8_t *)out->data;

    if (plan->entrypoint_patch_enabled) {
        write_u64(p + N00B_ELF64_E_ENTRY_OFF,
                  plan->replacement_entrypoint,
                  big);
    }
    write_u64(p + N00B_ELF64_E_PHOFF_OFF, phoff, big);
    write_u16(p + N00B_ELF64_E_PHNUM_OFF,
              (uint16_t)plan->new_segment_count,
              big);
    return true;
}

static bool
loadable_phtab_patch_coverage(n00b_elf_rewrite_loadable_plan_t *plan,
                              uint64_t                          start,
                              uint64_t                          end,
                              bool                              relocated,
                              uint64_t                         *covered_out)
{
    uint64_t covered = 0;

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];

        if (patch->file_offset < start || patch->file_end > end) {
            continue;
        }

        bool covers_phtab = false;
        switch (patch->kind) {
        case N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB:
        case N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR:
            covers_phtab = !relocated;
            break;
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB:
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR:
            covers_phtab = relocated;
            break;
        case N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD:
            covers_phtab = true;
            break;
        default:
            covers_phtab = false;
            break;
        }

        if (!covers_phtab
            || !checked_add_u64(covered,
                                patch->file_end - patch->file_offset,
                                &covered)) {
            return false;
        }
    }

    *covered_out = covered;
    return true;
}

static n00b_buffer_t *
build_in_place_phtab(n00b_elf_binary_t                  *bin,
                     n00b_elf_rewrite_loadable_plan_t   *plan,
                     n00b_allocator_t                   *allocator)
{
    n00b_elf_rewrite_loadable_phtab_adjustment_t *adj =
        &plan->phtab_adjustment;
    bool big = is_big_endian(bin);
    uint64_t original_phtab_end;

    if (adj->adjusted_phtab_size > (uint64_t)SIZE_MAX
        || adj->original_phtab_offset > (uint64_t)SIZE_MAX
        || adj->original_phtab_size > (uint64_t)SIZE_MAX
        || !checked_add_u64(adj->original_phtab_offset,
                            adj->original_phtab_size,
                            &original_phtab_end)
        || original_phtab_end > bin->stream->buf->byte_len
        || adj->containing_load_index >= bin->num_segments
        || adj->pt_phdr_index >= plan->original_segment_count) {
        return nullptr;
    }

    n00b_buffer_t *phtab = new_zero_buffer(adj->adjusted_phtab_size,
                                           allocator);
    if (phtab == nullptr) {
        return nullptr;
    }

    memcpy(phtab->data,
           bin->stream->buf->data + adj->original_phtab_offset,
           (size_t)adj->original_phtab_size);

    n00b_elf_segment_t *containing_load =
        &bin->segments[adj->containing_load_index];
    uint64_t containing_entry_offset =
        (uint64_t)adj->containing_load_index * N00B_ELF64_PHDR_SIZE;
    uint64_t pt_phdr_entry_offset =
        (uint64_t)adj->pt_phdr_index * N00B_ELF64_PHDR_SIZE;
    uint64_t new_pt_load_entry_offset =
        plan->original_segment_count * N00B_ELF64_PHDR_SIZE;
    uint64_t containing_entry_end;
    uint64_t pt_phdr_entry_end;
    uint64_t new_pt_load_entry_end;
    uint64_t new_containing_filesz;
    uint64_t new_containing_memsz;

    if (!checked_add_u64(containing_load->filesz,
                         adj->required_file_extension,
                         &new_containing_filesz)
        || !checked_add_u64(containing_load->memsz,
                            adj->required_memory_extension,
                            &new_containing_memsz)
        || !checked_add_u64(containing_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &containing_entry_end)
        || !checked_add_u64(pt_phdr_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &pt_phdr_entry_end)
        || !checked_add_u64(new_pt_load_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_entry_end)
        || containing_entry_end > phtab->byte_len
        || pt_phdr_entry_end > phtab->byte_len
        || new_pt_load_entry_end > phtab->byte_len) {
        return nullptr;
    }

    uint8_t *containing_entry = (uint8_t *)phtab->data + containing_entry_offset;
    write_u64(containing_entry + 32, new_containing_filesz, big);
    write_u64(containing_entry + 40, new_containing_memsz, big);

    uint8_t *pt_phdr = (uint8_t *)phtab->data + pt_phdr_entry_offset;
    write_u64(pt_phdr + 8, adj->pt_phdr_new_offset, big);
    write_u64(pt_phdr + 16, adj->pt_phdr_new_vaddr, big);
    write_u64(pt_phdr + 24, adj->pt_phdr_new_vaddr, big);
    write_u64(pt_phdr + 32, adj->pt_phdr_new_filesz, big);
    write_u64(pt_phdr + 40, adj->pt_phdr_new_memsz, big);

    uint8_t *new_load = (uint8_t *)phtab->data + new_pt_load_entry_offset;
    write_phdr(new_load,
               PT_LOAD,
               plan->segment_flags,
               plan->payload_placement.file_offset,
               plan->payload_placement.vaddr,
               plan->payload_placement.vaddr,
               plan->payload->byte_len,
               plan->p_memsz,
               plan->payload_placement.alignment,
               big);

    return phtab;
}

static n00b_buffer_t *
build_relocated_phtab(n00b_elf_binary_t                  *bin,
                      n00b_elf_rewrite_loadable_plan_t   *plan,
                      n00b_allocator_t                   *allocator)
{
    n00b_elf_rewrite_loadable_relocation_t *rel =
        &plan->phtab_relocation;
    bool big = is_big_endian(bin);
    uint64_t original_phtab_end;

    if (rel->relocated_phtab_size > (uint64_t)SIZE_MAX
        || rel->original_phtab_offset > (uint64_t)SIZE_MAX
        || rel->original_phtab_size > (uint64_t)SIZE_MAX
        || !checked_add_u64(rel->original_phtab_offset,
                            rel->original_phtab_size,
                            &original_phtab_end)
        || original_phtab_end > bin->stream->buf->byte_len
        || rel->pt_phdr_index >= plan->original_segment_count
        || rel->new_pt_load_index != plan->original_segment_count) {
        return nullptr;
    }

    n00b_buffer_t *phtab = new_zero_buffer(rel->relocated_phtab_size,
                                           allocator);
    if (phtab == nullptr) {
        return nullptr;
    }

    memcpy(phtab->data,
           bin->stream->buf->data + rel->original_phtab_offset,
           (size_t)rel->original_phtab_size);

    uint64_t pt_phdr_entry_offset =
        (uint64_t)rel->pt_phdr_index * N00B_ELF64_PHDR_SIZE;
    uint64_t new_pt_load_entry_offset =
        (uint64_t)rel->new_pt_load_index * N00B_ELF64_PHDR_SIZE;
    uint64_t pt_phdr_entry_end;
    uint64_t new_pt_load_entry_end;
    if (!checked_add_u64(pt_phdr_entry_offset,
                         N00B_ELF64_PHDR_SIZE,
                         &pt_phdr_entry_end)
        || !checked_add_u64(new_pt_load_entry_offset,
                            N00B_ELF64_PHDR_SIZE,
                            &new_pt_load_entry_end)
        || pt_phdr_entry_end > phtab->byte_len
        || new_pt_load_entry_end > phtab->byte_len) {
        return nullptr;
    }

    uint8_t *pt_phdr = (uint8_t *)phtab->data + pt_phdr_entry_offset;
    write_u64(pt_phdr + 8, rel->pt_phdr_new_offset, big);
    write_u64(pt_phdr + 16, rel->pt_phdr_new_vaddr, big);
    write_u64(pt_phdr + 24, rel->pt_phdr_new_paddr, big);
    write_u64(pt_phdr + 32, rel->pt_phdr_new_filesz, big);
    write_u64(pt_phdr + 40, rel->pt_phdr_new_memsz, big);

    uint8_t *new_load = (uint8_t *)phtab->data + new_pt_load_entry_offset;
    write_phdr(new_load,
               PT_LOAD,
               rel->new_pt_load_flags,
               rel->new_pt_load_offset,
               rel->new_pt_load_vaddr,
               rel->new_pt_load_paddr,
               rel->new_pt_load_filesz,
               rel->new_pt_load_memsz,
               rel->new_pt_load_align,
               big);

    return phtab;
}

static bool
loadable_source_matches_in_place(n00b_elf_binary_t *bin,
                                 n00b_elf_rewrite_loadable_plan_t *plan,
                                 uint64_t phtab_size,
                                 uint64_t phtab_end)
{
    n00b_elf_rewrite_loadable_phtab_adjustment_t *adj =
        &plan->phtab_adjustment;
    uint64_t original_phtab_end;
    uint64_t load_file_end;
    uint64_t load_memory_end;
    uint64_t adjusted_delta;
    uint64_t adjusted_vaddr;

    if (!checked_add_u64(adj->original_phtab_offset,
                         adj->original_phtab_size,
                         &original_phtab_end)
        || adj->status != N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED
        || !adj->pt_phdr_present
        || bin->header.entry != plan->original_entrypoint
        || adj->original_phtab_offset != bin->header.phoff
        || adj->original_phtab_size != phtab_size
        || original_phtab_end != phtab_end
        || adj->containing_load_index >= bin->num_segments
        || adj->pt_phdr_index >= bin->num_segments) {
        return false;
    }

    n00b_elf_segment_t *load = &bin->segments[adj->containing_load_index];
    n00b_elf_segment_t *phdr = &bin->segments[adj->pt_phdr_index];

    if (adj->adjusted_phtab_offset < load->offset
        || !checked_add_u64(load->offset, load->filesz, &load_file_end)
        || !checked_add_u64(load->vaddr, load->memsz, &load_memory_end)
        || !checked_add_u64(load->vaddr,
                            adj->adjusted_phtab_offset - load->offset,
                            &adjusted_vaddr)) {
        return false;
    }

    adjusted_delta = adjusted_vaddr - load->vaddr;
    return load->type == PT_LOAD
        && phdr->type == PT_PHDR
        && phdr->offset == bin->header.phoff
        && phdr->filesz == phtab_size
        && phdr->memsz == phtab_size
        && load_file_end == adj->containing_load_file_end
        && load_memory_end == adj->containing_load_memory_end
        && adjusted_delta == adj->adjusted_phtab_offset - load->offset
        && adjusted_vaddr == adj->adjusted_phtab_vaddr;
}

static bool
loadable_source_matches_relocated(n00b_elf_binary_t *bin,
                                  n00b_elf_rewrite_loadable_plan_t *plan,
                                  uint64_t phtab_size,
                                  uint64_t phtab_end)
{
    n00b_elf_rewrite_loadable_relocation_t *rel =
        &plan->phtab_relocation;

    if (rel->status != N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED
        || !rel->pt_phdr_present
        || rel->original_phtab_offset != bin->header.phoff
        || rel->original_phtab_size != phtab_size
        || rel->original_phtab_end != phtab_end
        || bin->header.entry != plan->original_entrypoint
        || rel->elf_header_entry != bin->header.entry
        || rel->pt_phdr_index >= bin->num_segments) {
        return false;
    }

    n00b_elf_segment_t *phdr = &bin->segments[rel->pt_phdr_index];
    return phdr->type == PT_PHDR
        && phdr->offset == rel->original_phtab_offset
        && phdr->filesz == rel->original_phtab_size
        && phdr->memsz == rel->original_phtab_size
        && phdr->vaddr == rel->original_phtab_vaddr;
}

static bool
loadable_source_binary_matches(n00b_elf_binary_t *bin,
                               n00b_elf_rewrite_loadable_plan_t *plan)
{
    uint64_t phtab_size;
    uint64_t phtab_end;

    if (plan->source_binary != bin
        || bin->stream == nullptr
        || bin->stream->buf == nullptr
        || bin->stream->buf->byte_len != plan->file_size
        || plan->target_profile.reason != N00B_ELF_REWRITE_PROFILE_OK
        || plan->target_profile.file_size != plan->file_size
        || plan->target_profile.segment_count
               != plan->original_segment_count
        || plan->admission.file_size != plan->file_size
        || plan->admission.original_segment_count
               != plan->original_segment_count
        || plan->admission.new_segment_count != plan->new_segment_count
        || (!plan->entrypoint_patch_enabled
            && plan->replacement_entrypoint != plan->original_entrypoint)
        || bin->num_segments != plan->original_segment_count
        || bin->header.phnum != plan->original_segment_count
        || bin->header.phentsize != N00B_ELF64_PHDR_SIZE
        || !checked_mul_u64(bin->header.phnum,
                            N00B_ELF64_PHDR_SIZE,
                            &phtab_size)
        || !checked_add_u64(bin->header.phoff, phtab_size, &phtab_end)
        || phtab_end > bin->stream->buf->byte_len) {
        return false;
    }

    switch (plan->phtab_strategy) {
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST:
        return loadable_source_matches_in_place(bin,
                                                plan,
                                                phtab_size,
                                                phtab_end);
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE:
        return loadable_source_matches_relocated(bin,
                                                 plan,
                                                 phtab_size,
                                                 phtab_end);
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE:
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED:
        return false;
    }

    return false;
}

static n00b_elf_rewrite_host_entrypoint_target_t
host_entrypoint_rejected(
    n00b_elf_binary_t *bin,
    n00b_elf_rewrite_loadable_plan_t *plan,
    n00b_elf_rewrite_host_entrypoint_rejection_reason_t reason)
{
    n00b_elf_rewrite_host_entrypoint_target_t target = {
        .outcome          = N00B_ELF_REWRITE_PLAN_REJECTED,
        .rejection_reason = reason,
    };

    if (plan != nullptr) {
        target.original_entrypoint    = plan->original_entrypoint;
        target.replacement_entrypoint = plan->replacement_entrypoint;
        target.payload_file_offset    = plan->payload_placement.file_offset;
        target.payload_file_end       = plan->payload_placement.file_end;
        target.payload_vaddr          = plan->payload_placement.vaddr;
        target.payload_vaddr_end      = plan->payload_placement.vaddr_end;
        target.payload_memory_size    = plan->p_memsz;
        if (plan->payload != nullptr) {
            target.payload_file_size = (uint64_t)plan->payload->byte_len;
        }
    } else if (bin != nullptr) {
        target.original_entrypoint    = bin->header.entry;
        target.replacement_entrypoint = bin->header.entry;
    }

    return target;
}

n00b_result_t(n00b_elf_rewrite_host_entrypoint_target_t)
n00b_elf_rewrite_plan_host_entrypoint_target(
    n00b_elf_binary_t                  *bin,
    n00b_elf_rewrite_loadable_plan_t   *plan,
    uint64_t                            target_payload_offset,
    uint64_t                            target_size)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_host_entrypoint_target_t,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_host_entrypoint_target_t,
                               N00B_ELF_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN));
    }

    if (plan->phtab_strategy == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE
        || plan->phtab_strategy
               == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED
        || plan->payload == nullptr
        || plan->payload->byte_len == 0
        || plan->payload_placement.kind
               != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN));
    }

    if (bin->header.ident[EI_CLASS] != ELFCLASS64) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CLASS));
    }

    if (bin->header.ident[EI_DATA] != ELFDATA2LSB) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_ENDIAN));
    }

    if (bin->header.machine != EM_X86_64) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_MACHINE));
    }

    if ((plan->segment_flags & PF_X) == 0) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NON_EXECUTABLE));
    }

    if (!loadable_source_binary_matches(bin, plan)) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN));
    }

    uint64_t target_payload_end;
    if (target_size == 0) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE));
    }

    if (!checked_add_u64(target_payload_offset,
                         target_size,
                         &target_payload_end)) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW));
    }

    if (target_payload_end > plan->p_memsz) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE));
    }

    if (target_payload_offset >= (uint64_t)plan->payload->byte_len
        || target_payload_end > (uint64_t)plan->payload->byte_len) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_MEMORY_ONLY));
    }

    uint64_t target_file_offset;
    uint64_t target_file_end;
    uint64_t target_vaddr;
    uint64_t target_vaddr_end;
    if (!checked_add_u64(plan->payload_placement.file_offset,
                         target_payload_offset,
                         &target_file_offset)
        || !checked_add_u64(plan->payload_placement.file_offset,
                            target_payload_end,
                            &target_file_end)
        || !checked_add_u64(plan->payload_placement.vaddr,
                            target_payload_offset,
                            &target_vaddr)
        || !checked_add_u64(plan->payload_placement.vaddr,
                            target_payload_end,
                            &target_vaddr_end)) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW));
    }

    if (target_file_offset < plan->payload_placement.file_offset
        || target_file_end > plan->payload_placement.file_end
        || target_vaddr < plan->payload_placement.vaddr
        || target_vaddr_end > plan->payload_placement.vaddr_end) {
        return n00b_result_ok(
            n00b_elf_rewrite_host_entrypoint_target_t,
            host_entrypoint_rejected(
                bin,
                plan,
                N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE));
    }

    n00b_elf_rewrite_host_entrypoint_target_t target = {
        .outcome               = N00B_ELF_REWRITE_PLAN_ACCEPTED,
        .rejection_reason      = N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NONE,
        .original_entrypoint   = plan->original_entrypoint,
        .replacement_entrypoint = target_vaddr,
        .target_payload_offset = target_payload_offset,
        .target_size           = target_size,
        .target_file_offset    = target_file_offset,
        .target_file_end       = target_file_end,
        .target_vaddr          = target_vaddr,
        .target_vaddr_end      = target_vaddr_end,
        .payload_file_offset   = plan->payload_placement.file_offset,
        .payload_file_end      = plan->payload_placement.file_end,
        .payload_vaddr         = plan->payload_placement.vaddr,
        .payload_vaddr_end     = plan->payload_placement.vaddr_end,
        .payload_file_size     = (uint64_t)plan->payload->byte_len,
        .payload_memory_size   = plan->p_memsz,
        .trampoline_emitted    = false,
        .trampoline_size       = 0,
    };

    return n00b_result_ok(n00b_elf_rewrite_host_entrypoint_target_t, target);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_loadable_insert_plan(
    n00b_elf_binary_t                  *bin,
    n00b_elf_rewrite_loadable_plan_t   *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->phtab_strategy == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE
        || plan->phtab_strategy
               == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    if (plan->payload == nullptr || plan->payload->byte_len == 0
        || plan->patches.data == nullptr || plan->patches.len == 0
        || plan->admission.outcome != N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED
        || plan->new_segment_count != plan->original_segment_count + 1
        || bin->header.phnum != plan->original_segment_count
        || plan->payload_placement.kind
               != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    if (!loadable_source_binary_matches(bin, plan)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_elf_rewrite_patch_t *header =
        find_loadable_plan_patch(plan, N00B_ELF_REWRITE_PATCH_ELF_HEADER);
    n00b_elf_rewrite_patch_t *payload =
        find_loadable_plan_patch(plan, N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD);
    if (header == nullptr || payload == nullptr
        || header->file_offset != 0
        || header->file_end != N00B_ELF64_EHDR_SIZE
        || payload->file_offset != plan->payload_placement.file_offset
        || payload->file_end != plan->payload_placement.file_end
        || payload->original_file_offset != payload->file_offset
        || payload->original_file_end != payload->file_offset
        || payload->file_end - payload->file_offset
               != (uint64_t)plan->payload->byte_len) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    bool           relocated = false;
    uint64_t       live_phtab_offset;
    uint64_t       live_phtab_end;
    uint64_t       live_phtab_size;
    uint64_t       pt_phdr_entry_offset = 0;
    uint64_t       new_pt_load_entry_offset = 0;
    uint64_t       first_padding_offset = 0;
    uint64_t       first_padding_end = 0;
    uint64_t       second_padding_offset = 0;
    uint64_t       second_padding_end = 0;
    n00b_buffer_t *phtab = nullptr;

    switch (plan->phtab_strategy) {
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST:
        {
        uint64_t adjusted_phtab_end;
        uint64_t pt_phdr_delta;
        uint64_t new_pt_load_delta;
        if (!checked_add_u64(plan->phtab_adjustment.adjusted_phtab_offset,
                             plan->phtab_adjustment.adjusted_phtab_size,
                             &adjusted_phtab_end)
            || !checked_mul_u64(plan->phtab_adjustment.pt_phdr_index,
                                N00B_ELF64_PHDR_SIZE,
                                &pt_phdr_delta)
            || !checked_add_u64(plan->phtab_adjustment.adjusted_phtab_offset,
                                pt_phdr_delta,
                                &pt_phdr_entry_offset)
            || !checked_mul_u64(plan->original_segment_count,
                                N00B_ELF64_PHDR_SIZE,
                                &new_pt_load_delta)
            || !checked_add_u64(plan->phtab_adjustment.adjusted_phtab_offset,
                                new_pt_load_delta,
                                &new_pt_load_entry_offset)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_OVERFLOW);
        }
        if (plan->phtab_adjustment.status
                != N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED
            || plan->phtab_placement.kind
                   != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB
            || plan->phtab_placement.file_offset
                   != plan->phtab_adjustment.adjusted_phtab_offset
            || plan->phtab_placement.file_end != adjusted_phtab_end) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }
        live_phtab_offset = plan->phtab_adjustment.adjusted_phtab_offset;
        live_phtab_size   = plan->phtab_adjustment.adjusted_phtab_size;
        live_phtab_end    = plan->phtab_placement.file_end;
        first_padding_offset =
            plan->phtab_adjustment.containing_load_file_end;
        first_padding_end = plan->phtab_adjustment.adjusted_phtab_offset;
        second_padding_offset = plan->file_size;
        second_padding_end    = plan->payload_placement.file_offset;
        phtab             = build_in_place_phtab(bin, plan, allocator);
        break;
        }
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE:
        relocated = true;
        if (plan->phtab_relocation.status
                != N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED
            || plan->phtab_placement.kind
                   != N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB
            || plan->phtab_placement.file_offset
                   != plan->phtab_relocation.relocated_phtab_offset
            || plan->phtab_placement.file_end
                   != plan->phtab_relocation.relocated_phtab_end) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }
        live_phtab_offset = plan->phtab_relocation.relocated_phtab_offset;
        live_phtab_size   = plan->phtab_relocation.relocated_phtab_size;
        live_phtab_end    = plan->phtab_relocation.relocated_phtab_end;
        pt_phdr_entry_offset =
            plan->phtab_relocation.pt_phdr_entry_offset;
        new_pt_load_entry_offset =
            plan->phtab_relocation.new_pt_load_entry_offset;
        first_padding_offset = plan->file_size;
        first_padding_end    = plan->phtab_relocation.new_pt_load_offset;
        second_padding_offset = plan->phtab_relocation.relocated_phtab_end;
        second_padding_end    = plan->phtab_relocation.payload_offset;
        phtab             = build_relocated_phtab(bin, plan, allocator);
        break;
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE:
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED:
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    uint64_t covered;
    if (phtab == nullptr
        || phtab->byte_len != live_phtab_size
        || live_phtab_end != live_phtab_offset + live_phtab_size
        || first_padding_offset > first_padding_end
        || second_padding_offset > second_padding_end
        || !validate_loadable_patch_set(plan,
                                        relocated,
                                        live_phtab_offset,
                                        live_phtab_end,
                                        pt_phdr_entry_offset,
                                        new_pt_load_entry_offset,
                                        first_padding_offset,
                                        first_padding_end,
                                        second_padding_offset,
                                        second_padding_end)
        || !loadable_phtab_patch_coverage(plan,
                                          live_phtab_offset,
                                          live_phtab_end,
                                          relocated,
                                          &covered)
        || covered != live_phtab_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t output_size;
    if (!loadable_plan_output_size(bin, plan, &output_size)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *out = new_zero_buffer(output_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    memcpy(out->data, bin->stream->buf->data, bin->stream->buf->byte_len);

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];
        if (patch->kind == N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING
            && !zero_output_range(out, patch->file_offset, patch->file_end)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }
    }

    if (!write_output_bytes(out,
                            live_phtab_offset,
                            phtab->data,
                            phtab->byte_len)
        || !write_output_bytes(out,
                               payload->file_offset,
                               plan->payload->data,
                               plan->payload->byte_len)
        || !patch_output_loadable_header(out,
                                         bin,
                                         plan,
                                         live_phtab_offset)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_elf_parse(stream, .allocator = allocator);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    n00b_elf_binary_t *rewritten = n00b_result_get(parsed);
    uint64_t expected_entry = plan->entrypoint_patch_enabled
                            ? plan->replacement_entrypoint
                            : plan->original_entrypoint;
    if (rewritten->header.entry != expected_entry) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_metadata_insert_plan(
    n00b_elf_binary_t       *bin,
    n00b_elf_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->section_name == nullptr
        || plan->payload == nullptr
        || plan->patches.data == nullptr
        || plan->patches.len == 0
        || plan->operation != N00B_ELF_REWRITE_OPERATION_METADATA_INSERT
        || plan->admission.outcome != N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED
        || !n00b_option_is_set(plan->admission.placement)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_elf_rewrite_admit_placement_t placement =
        n00b_option_get(plan->admission.placement);
    if (placement.file_offset != plan->payload_offset
        || placement.file_end != plan->payload_end) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    if (!apply_supports_placement_kind(placement.kind)
        || !apply_supports_table_strategy(plan->table_strategy)
        || !apply_supports_overlay_shape(bin, plan, placement)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    uint64_t strtab_size;
    uint32_t name_index;
    if (!new_strtab_size_and_name_index(plan, &strtab_size, &name_index)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    uint64_t shstrtab_offset;
    uint64_t shtab_offset;
    if (!compute_live_table_offsets(plan,
                                    strtab_size,
                                    &shstrtab_offset,
                                    &shtab_offset)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *strtab = build_rewrite_shstrtab(bin, plan, allocator);
    if (strtab == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *shtab = build_rewrite_shtab(bin,
                                               plan,
                                               shstrtab_offset,
                                               strtab_size,
                                               name_index,
                                               allocator);
    if (shtab == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t output_size;
    if (!plan_output_size(bin, plan, &output_size)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *out = new_zero_buffer(output_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    memcpy(out->data, bin->stream->buf->data, bin->stream->buf->byte_len);

    n00b_elf_rewrite_patch_t *tail =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_TABLE_TAIL);
    if (tail != nullptr && !zero_output_range(out, tail->file_offset, tail->file_end)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_elf_rewrite_patch_t *payload =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_PAYLOAD);
    n00b_elf_rewrite_patch_t *header =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_ELF_HEADER);
    if (payload == nullptr || header == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t expected_payload_original_end = placement.kind
        == N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP
            ? payload->file_end
            : payload->file_offset;
    if (header->file_offset != 0
        || header->file_end != N00B_ELF64_EHDR_SIZE
        || payload->file_offset != plan->payload_offset
        || payload->file_end != plan->payload_end
        || payload->original_file_offset != payload->file_offset
        || payload->original_file_end != expected_payload_original_end
        || !write_output_bytes(out,
                               payload->file_offset,
                               plan->payload->data,
                               plan->payload->byte_len)
        || !patch_output_header(out, bin, plan, shtab_offset)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    if (plan->table_strategy
        == N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH) {
        n00b_elf_rewrite_patch_t *strtab_patch =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB);
        n00b_elf_rewrite_patch_t *shtab_patch =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE);

        if (strtab_patch == nullptr
            || shtab_patch == nullptr
            || strtab_patch->file_end != strtab_patch->file_offset
                                      + strtab->byte_len
            || shtab_patch->file_end != shtab_patch->file_offset
                                    + shtab->byte_len
            || !write_output_bytes(out,
                                   shtab_patch->file_offset,
                                   shtab->data,
                                   shtab->byte_len)
            || !write_output_bytes(out,
                                   strtab_patch->file_offset,
                                   strtab->data,
                                   strtab->byte_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }
    }
    else {
        n00b_elf_rewrite_patch_t *tables_patch =
            find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
        n00b_buffer_t *tables =
            combine_replacement_tables(strtab, shtab, allocator);

        if (tables_patch == nullptr
            || tables == nullptr
            || tables_patch->file_end != tables_patch->file_offset
                                       + tables->byte_len
            || !write_output_bytes(out,
                                   tables_patch->file_offset,
                                   tables->data,
                                   tables->byte_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }
    }

    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_elf_parse(stream, .allocator = allocator);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

static n00b_result_t(n00b_buffer_t *)
apply_trusted_metadata_plan(trusted_metadata_target_t target,
                            n00b_elf_binary_t       *bin,
                            n00b_elf_rewrite_plan_t *plan,
                            n00b_allocator_t        *allocator)
{
    if (bin == nullptr || bin->stream == nullptr || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    bool replacement =
        plan->operation == trusted_metadata_replace_operation(target);
    bool deletion =
        target == TRUSTED_METADATA_TARGET_CHALK_MARK
        && plan->operation == N00B_ELF_REWRITE_OPERATION_CHALK_MARK_DELETE;
    if (!deletion && !replacement) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    if (plan->patches.data == nullptr || plan->patches.len == 0
        || plan->section_name == nullptr
        || !section_name_is_trusted_metadata(plan->section_name, target)
        || (replacement
            && (plan->payload == nullptr
                || !replacement_plan_shape_matches_trusted_target(plan,
                                                                  target)))) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    trusted_metadata_shape_t shape = {};
    if (compute_trusted_metadata_shape(bin,
                                       &plan->target_profile,
                                       target,
                                       replacement,
                                       &shape)
            != TRUSTED_METADATA_SHAPE_OK
        || shape.target_index != plan->removed_section_index
        || shape.new_shstrndx != plan->new_shstrndx
        || plan->new_section_count
               != plan->original_section_count - 1 + (replacement ? 1u : 0u)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    n00b_elf_rewrite_patch_t *header =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_ELF_HEADER);
    n00b_elf_rewrite_patch_t *stale =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD);
    n00b_elf_rewrite_patch_t *tables_patch =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);

    if (header == nullptr || stale == nullptr || tables_patch == nullptr
        || header->file_offset != 0
        || header->file_end != N00B_ELF64_EHDR_SIZE
        || stale->file_offset != plan->removed_payload_offset
        || stale->file_end != plan->removed_payload_end) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_elf_rewrite_patch_t *payload =
        find_plan_patch(plan, N00B_ELF_REWRITE_PATCH_PAYLOAD);
    if (replacement
        && (payload == nullptr
            || payload->file_offset != plan->payload_offset
            || payload->file_end != plan->payload_end
            || payload->original_file_offset != payload->file_offset
            || payload->original_file_end != payload->file_offset)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    if (!replacement && payload != nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t output_size;
    if (!plan_output_size(bin, plan, &output_size)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *strtab =
        build_trusted_metadata_shstrtab(bin, plan, &shape, allocator);
    if (strtab == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    uint64_t shstrtab_offset = tables_patch->file_offset;
    uint64_t shtab_offset;
    if (!checked_add_u64(shstrtab_offset, strtab->byte_len, &shtab_offset)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    n00b_buffer_t *shtab = build_trusted_metadata_shtab(bin,
                                                        plan,
                                                        &shape,
                                                        shstrtab_offset,
                                                        strtab->byte_len,
                                                        allocator);
    n00b_buffer_t *tables = nullptr;
    if (shtab != nullptr) {
        tables = combine_replacement_tables(strtab, shtab, allocator);
    }
    uint64_t tables_end;
    if (shtab == nullptr || tables == nullptr
        || !checked_add_u64(tables_patch->file_offset,
                            tables->byte_len,
                            &tables_end)
        || tables_patch->file_end != tables_end) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_buffer_t *out = new_zero_buffer(output_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_OVERFLOW);
    }

    memcpy(out->data, bin->stream->buf->data, bin->stream->buf->byte_len);

    if (!zero_output_range(out, stale->file_offset, stale->file_end)
        || (replacement
            && !write_output_bytes(out,
                                   payload->file_offset,
                                   plan->payload->data,
                                   plan->payload->byte_len))
        || !patch_output_header(out, bin, plan, shtab_offset)
        || !write_output_bytes(out,
                               tables_patch->file_offset,
                               tables->data,
                               tables->byte_len)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ELF_REWRITE_ERR_APPLY);
    }

    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_elf_parse(stream, .allocator = allocator);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_plan(
    n00b_elf_binary_t       *bin,
    n00b_elf_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return apply_trusted_metadata_plan(TRUSTED_METADATA_TARGET_CHALK_MARK,
                                       bin,
                                       plan,
                                       allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_plan(
    n00b_elf_binary_t       *bin,
    n00b_elf_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (plan != nullptr
        && plan->operation == N00B_ELF_REWRITE_OPERATION_METADATA_INSERT) {
        if (plan->section_name == nullptr
            || !section_name_is_object_bundle(plan->section_name)
            || plan->section_type != SHT_PROGBITS
            || plan->section_flags != 0) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ELF_REWRITE_ERR_APPLY);
        }

        return n00b_elf_rewrite_apply_metadata_insert_plan(
            bin,
            plan,
            .allocator = allocator);
    }

    return apply_trusted_metadata_plan(TRUSTED_METADATA_TARGET_OBJECT_BUNDLE,
                                       bin,
                                       plan,
                                       allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_metadata_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto plan_result = n00b_elf_rewrite_plan_metadata_insert(bin,
                                                             request,
                                                             .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_elf_rewrite_apply_metadata_insert_plan(bin,
                                                       plan,
                                                       .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_delete(
    n00b_elf_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_delete(bin,
                                                               .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_elf_rewrite_apply_chalk_mark_plan(bin,
                                                  plan,
                                                  .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_replace(
        bin,
        request,
        .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_elf_rewrite_apply_chalk_mark_plan(bin,
                                                  plan,
                                                  .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto plan_result = n00b_elf_rewrite_plan_object_bundle_insert(
        bin,
        request,
        .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_elf_rewrite_apply_object_bundle_plan(bin,
                                                     plan,
                                                     .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto plan_result = n00b_elf_rewrite_plan_object_bundle_replace(
        bin,
        request,
        .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_elf_rewrite_apply_object_bundle_plan(bin,
                                                     plan,
                                                     .allocator = allocator);
}

n00b_string_t *
n00b_elf_rewrite_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ELF_REWRITE_OK:                         return r"ok";
    case N00B_ELF_REWRITE_ERR_NULL_BINARY:            return r"ELF rewrite: null binary";
    case N00B_ELF_REWRITE_ERR_NULL_REQUEST:           return r"ELF rewrite: null request";
    case N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME:      return r"ELF rewrite: null section name";
    case N00B_ELF_REWRITE_ERR_NULL_PAYLOAD:           return r"ELF rewrite: null payload";
    case N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE:      return r"ELF rewrite: zero payload size";
    case N00B_ELF_REWRITE_ERR_TARGET_PROFILE:         return r"ELF rewrite: target profile error";
    case N00B_ELF_REWRITE_ERR_ADMISSION:              return r"ELF rewrite: admission error";
    case N00B_ELF_REWRITE_ERR_OVERFLOW:               return r"ELF rewrite: integer overflow";
    case N00B_ELF_REWRITE_ERR_NULL_PLAN:              return r"ELF rewrite: null plan";
    case N00B_ELF_REWRITE_ERR_PLAN_REJECTED:          return r"ELF rewrite: rejected plan";
    case N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN:       return r"ELF rewrite: unsupported plan";
    case N00B_ELF_REWRITE_ERR_APPLY:                  return r"ELF rewrite: apply error";
    case N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY:      return r"ELF rewrite: output parse failed";
    case N00B_ELF_REWRITE_ERR_MARK_NOT_FOUND:         return r"ELF rewrite: mark not found";
    case N00B_ELF_REWRITE_ERR_TRUSTED_NAME:           return r"ELF rewrite: trusted name mismatch";
    default:                                          return r"ELF rewrite: unknown error code";
    }
}

n00b_string_t *
n00b_elf_rewrite_plan_outcome_str(n00b_elf_rewrite_plan_outcome_t outcome)
{
    switch (outcome) {
    case N00B_ELF_REWRITE_PLAN_ACCEPTED: return r"accepted";
    case N00B_ELF_REWRITE_PLAN_REJECTED: return r"rejected";
    }

    return r"unknown-elf-rewrite-plan-outcome";
}

n00b_string_t *
n00b_elf_rewrite_rejection_reason_str(
    n00b_elf_rewrite_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_ELF_REWRITE_REJECT_NONE:                    return r"none";
    case N00B_ELF_REWRITE_REJECT_TARGET_PROFILE:          return r"target-profile";
    case N00B_ELF_REWRITE_REJECT_ADMISSION:               return r"admission";
    case N00B_ELF_REWRITE_REJECT_TABLE_PLACEMENT:         return r"table-placement";
    case N00B_ELF_REWRITE_REJECT_SECTION_COUNT_PROMOTION: return r"section-count-promotion";
    case N00B_ELF_REWRITE_REJECT_OVERFLOW:                return r"overflow";
    case N00B_ELF_REWRITE_REJECT_CHALK_MARK_NOT_FOUND:    return r"chalk-mark-not-found";
    case N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED:  return r"chalk-mark-unsupported";
    case N00B_ELF_REWRITE_REJECT_TRUSTED_NAME:            return r"trusted-name";
    case N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND: return r"object-bundle-not-found";
    case N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE: return r"object-bundle-duplicate";
    case N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED:
        return r"object-bundle-unsupported";
    case N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT:      return r"loadable-placement";
    case N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS:        return r"loadable-address";
    }

    return r"unknown-elf-rewrite-rejection-reason";
}

n00b_string_t *
n00b_elf_rewrite_target_profile_reason_str(
    n00b_elf_rewrite_target_profile_reason_t reason)
{
    switch (reason) {
    case N00B_ELF_REWRITE_PROFILE_OK:                       return r"ok";
    case N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE:           return r"invalid-ehsize";
    case N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE:        return r"invalid-shentsize";
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE:        return r"invalid-phentsize";
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO:        return r"unsupported-shnlo";
    case N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE:               return r"shtab-size";
    case N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS:     return r"invalid-shtab-bounds";
    case N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM:               return r"zero-phnum";
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM:        return r"unsupported-pxnum";
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB:            return r"invalid-phtab";
    case N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB_BOUNDS:     return r"invalid-phtab-bounds";
    case N00B_ELF_REWRITE_PROFILE_NO_STRTAB:                return r"no-strtab";
    case N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE_WRAP:         return r"strtab-size-wrap";
    case N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO: return r"unsupported-strtab-shnlo";
    case N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX:     return r"invalid-strtab-index";
    case N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE:      return r"invalid-strtab-type";
    case N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE:              return r"strtab-size";
    case N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX:       return r"section-name-index";
    }

    return r"unknown-elf-rewrite-target-profile-reason";
}

n00b_string_t *
n00b_elf_rewrite_table_strategy_str(
    n00b_elf_rewrite_table_strategy_t strategy)
{
    switch (strategy) {
    case N00B_ELF_REWRITE_TABLE_STRATEGY_NONE:                    return r"none";
    case N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH:
        return r"in-place-shstrtab-growth";
    case N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION:  return r"terminal-tail-incision";
    case N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT:         return r"eof-replacement";
    case N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT:
        return r"after-overlay-replacement";
    }

    return r"unknown-elf-rewrite-table-strategy";
}

n00b_string_t *
n00b_elf_rewrite_patch_kind_str(n00b_elf_rewrite_patch_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_REWRITE_PATCH_ELF_HEADER:           return r"elf-header";
    case N00B_ELF_REWRITE_PATCH_PAYLOAD:              return r"payload";
    case N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB:  return r"section-name-strtab";
    case N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE: return r"section-header-table";
    case N00B_ELF_REWRITE_PATCH_TABLE_TAIL:           return r"table-tail";
    case N00B_ELF_REWRITE_PATCH_APPENDED_TABLES:      return r"appended-tables";
    case N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD:        return r"stale-payload";
    case N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB:       return r"adjusted-phtab";
    case N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR:     return r"adjusted-pt-phdr";
    case N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING:     return r"loadable-padding";
    case N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB:      return r"relocated-phtab";
    case N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR:    return r"relocated-pt-phdr";
    case N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD:          return r"new-pt-load";
    case N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD:     return r"loadable-payload";
    }

    return r"unknown-elf-rewrite-patch-kind";
}

n00b_string_t *
n00b_elf_rewrite_loadable_relocation_status_str(
    n00b_elf_rewrite_loadable_relocation_status_t status)
{
    switch (status) {
    case N00B_ELF_REWRITE_LOADABLE_RELOCATION_NONE:
        return r"none";
    case N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED:
        return r"accepted";
    case N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED:
        return r"rejected";
    }

    return r"unknown-elf-rewrite-loadable-relocation-status";
}
