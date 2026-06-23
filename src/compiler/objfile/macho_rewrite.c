/**
 * @file macho_rewrite.c
 * @brief Surgical Mach-O rewrite planning + apply (WP-005 Phase 1: metadata
 *        insert).
 *
 * Generalizes the narrow, in-place chalk `LC_NOTE` splice
 * (`src/chalk/macho_core.c`) into a planned, admission-gated, COPY-OUT rewrite
 * that mirrors the ELF rewrite template (`elf_rewrite.{h,c}`): admit → plan
 * (patch array) → apply (executes the plan into a FRESH buffer, preserving
 * every non-planned byte). Planning never mutates `bin`/stream/parsed arrays;
 * apply allocates a new `n00b_buffer_t` and never writes through
 * `bin->stream->buf->data`. This is the defining break from `macho_core.c`,
 * which mutates `buf->data` in place.
 *
 * Phase 1 implements the metadata-INSERT path (`target_profile`,
 * `plan_metadata_insert`, `apply_metadata_insert_plan`). Phase 2 adds the rest
 * of the metadata path: the trusted-insert planners
 * (`plan_chalk_mark_insert`, `plan_object_bundle_insert`), the replace/delete
 * planners (`plan_chalk_mark_replace`, `plan_object_bundle_replace`,
 * `plan_chalk_mark_delete`), the corresponding apply functions
 * (`apply_chalk_mark_plan`, `apply_object_bundle_plan`), the §3.5 convenience
 * wrappers, and the five `*_str` mappers. WP-006 Phase 1 added the loadable
 * insert + `__TEXT`-reflow bodies (`plan_loadable_insert`,
 * `apply_loadable_insert_plan`). WP-006 Phase 2 added the arm64 host-entrypoint
 * bodies (`plan_host_entrypoint_target`, `loadable_plan_enable_entrypoint`) and
 * wired the `LC_MAIN_ENTRYOFF` redirect into the loadable apply path (FR-13/FR-14).
 */
#include "compiler/objfile/macho_rewrite.h"

#include "compiler/objfile/macho_layout.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "internal/compiler/objfile/macho_rewrite_shared.h"
#include "internal/chalk/macho_core.h"
#include "text/strings/string_ops.h"

// ============================================================================
// On-disk geometry constants (named, not magic literals)
// ============================================================================

// On-disk size of an LC_NOTE load command: cmd(4) + cmdsize(4) + data_owner(16)
// + offset(8) + size(8) = 40. Matches chalk's private `MACHO_NOTE_CMD_SIZE`
// (`src/chalk/macho_core.c:186`) and admission's `N00B_MACHO_LC_NOTE_CMD_SIZE`
// (`src/compiler/objfile/macho_rewrite_admit.c:15`).
#define N00B_MACHO_LC_NOTE_CMD_SIZE 40u

// Field offsets within the 64-bit mach_header (mach_header_64). ncmds is the
// 5th u32, sizeofcmds the 6th (`n00b_macho_header_t`, macho.h:87-96).
#define N00B_MACHO_HDR_NCMDS_OFF      16u
#define N00B_MACHO_HDR_SIZEOFCMDS_OFF 20u

// Field offsets within an LC_NOTE command (chalk `add_note_insert`,
// macho_core.c:725-732): cmd@0, cmdsize@4, data_owner[16]@8, offset(u64)@24,
// size(u64)@32. data_owner is a fixed 16-byte field.
#define N00B_MACHO_NOTE_DATA_OWNER_OFF 8u
#define N00B_MACHO_NOTE_DATA_OWNER_LEN 16u
#define N00B_MACHO_NOTE_OFFSET_OFF     24u
#define N00B_MACHO_NOTE_SIZE_OFF       32u

// Field offsets within an LC_SEGMENT_64 command (chalk SEGCMD_*,
// macho_core.c:201-205): segname[16]@8, vmsize(u64)@32, filesize(u64)@48.
// Full field set (macho_types.h n00b_macho_segment_command64_t):
//   cmd@0 cmdsize@4 segname[16]@8 vmaddr@24 vmsize@32 fileoff@40 filesize@48
//   maxprot@56 initprot@60 nsects@64 flags@68 -> total 72 bytes.
#define N00B_MACHO_SEG64_SEGNAME_OFF  8u
#define N00B_MACHO_SEG64_VMADDR_OFF   24u
#define N00B_MACHO_SEG64_VMSIZE_OFF   32u
#define N00B_MACHO_SEG64_FILEOFF_OFF  40u
#define N00B_MACHO_SEG64_FILESIZE_OFF 48u
#define N00B_MACHO_SEG64_MAXPROT_OFF  56u
#define N00B_MACHO_SEG64_INITPROT_OFF 60u
#define N00B_MACHO_SEG64_NSECTS_OFF   64u
#define N00B_MACHO_SEG64_FLAGS_OFF    68u

// On-disk size of an LC_SEGMENT_64 command with zero sections (the new loadable
// segment carries no sections). Matches admit's N00B_MACHO_LC_SEGMENT_64_CMD_SIZE
// and macho_types.h n00b_macho_segment_command64_t (#pragma pack 1).
#define N00B_MACHO_SEG64_CMD_SIZE 72u

// section_64 record size (macho_types.h n00b_macho_section64_t): sectname[16] +
// segname[16] + addr(8) + size(8) + offset(4) + ... = 80 bytes; the file
// `offset` field sits at +48.
#define N00B_MACHO_SECT64_SIZE       80u
#define N00B_MACHO_SECT64_OFFSET_OFF 48u

// LC_SYMTAB *off fields into __LINKEDIT (macho_types.h n00b_macho_symtab_command_t):
//   cmd@0 cmdsize@4 symoff@8 nsyms@12 stroff@16 strsize@20.
#define N00B_MACHO_SYMTAB_SYMOFF_OFF 8u
#define N00B_MACHO_SYMTAB_STROFF_OFF 16u

// LC_DYSYMTAB __LINKEDIT-indexing *off fields (macho_types.h
// n00b_macho_dysymtab_command_t): cmd,cmdsize then 18 u32 fields. The six file
// offsets into __LINKEDIT are tocoff@32, modtaboff@40, extrefsymoff@48,
// indirectsymoff@56, extreloff@64, locreloff@72.
#define N00B_MACHO_DYSYM_TOCOFF_OFF         32u
#define N00B_MACHO_DYSYM_MODTABOFF_OFF      40u
#define N00B_MACHO_DYSYM_EXTREFSYMOFF_OFF   48u
#define N00B_MACHO_DYSYM_INDIRECTSYMOFF_OFF 56u
#define N00B_MACHO_DYSYM_EXTRELOFF_OFF      64u
#define N00B_MACHO_DYSYM_LOCRELOFF_OFF      72u

// LC_DYLD_INFO[_ONLY] *off fields (macho_types.h n00b_macho_dyld_info_command_t):
//   rebase_off@8 bind_off@16 weak_bind_off@24 lazy_bind_off@32 export_off@40.
#define N00B_MACHO_DYLD_INFO_REBASE_OFF    8u
#define N00B_MACHO_DYLD_INFO_BIND_OFF      16u
#define N00B_MACHO_DYLD_INFO_WEAK_BIND_OFF 24u
#define N00B_MACHO_DYLD_INFO_LAZY_BIND_OFF 32u
#define N00B_MACHO_DYLD_INFO_EXPORT_OFF    40u

// linkedit_data_command (macho_types.h n00b_macho_linkedit_data_command_t):
//   cmd@0 cmdsize@4 dataoff@8 datasize@12.
#define N00B_MACHO_LEDATA_DATAOFF_OFF 8u

// LC_MAIN entry_point_command (macho_types.h n00b_macho_entry_point_command_t):
//   cmd@0 cmdsize@4 entryoff(u64)@8 stacksize(u64)@16.
#define N00B_MACHO_LCMAIN_ENTRYOFF_OFF 8u

// arm64 page size for the __LINKEDIT vmsize round-up (mirrors chalk's 0x4000
// page rounding, macho_core.c:737). Sourced from macho_layout.h's D-025
// constant.
#define N00B_MACHO_REWRITE_PAGE N00B_MACHO_ARM64_PAGE_SIZE

// ============================================================================
// Overflow-safe scalar arithmetic (mirror elf_rewrite.c:82/93)
// ============================================================================

static bool
checked_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

// Round `value` up to the next multiple of `align` (a power of two, e.g. the
// arm64 page size). `align == 0` is the identity. Overflow-checked. Mirrors
// elf_rewrite.c:309 align_up_u64.
static bool
align_up_u64(uint64_t value, uint64_t align, uint64_t *out)
{
    if (align == 0) {
        *out = value;
        return true;
    }

    uint64_t rounded;
    if (!checked_add_u64(value, align - 1, &rounded)) {
        return false;
    }

    *out = rounded & ~(align - 1);
    return true;
}

// ============================================================================
// Little-endian field writers (copy-out: write into the FRESH output buffer,
// never `bin->stream->buf->data`). Mirror chalk set_le_u32/set_le_u64
// (macho_core.c:99-113), but Mach-O arm64 is fixed little-endian so there is no
// endian parameter (cf. ELF's big-endian variants).
// ============================================================================

static void
set_le_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void
set_le_u64(uint8_t *p, uint64_t v)
{
    set_le_u32(p, (uint32_t)(v & 0xFFFFFFFFu));
    set_le_u32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

static uint32_t
get_le_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t
get_le_u64(const uint8_t *p)
{
    return (uint64_t)get_le_u32(p) | ((uint64_t)get_le_u32(p + 4) << 32);
}

static void
zero_byte_range(uint8_t *p, uint64_t len)
{
    for (uint64_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

// Allocate a zero-filled output buffer of `size` bytes via the threaded
// allocator (copy-out target). Mirrors elf_rewrite.c:375 new_zero_buffer.
static n00b_buffer_t *
new_zero_buffer(uint64_t size, n00b_allocator_t *allocator)
{
    if (size > (uint64_t)INT64_MAX || size > (uint64_t)SIZE_MAX) {
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_buffer_new((int64_t)size, .allocator = allocator);
    if (buf == nullptr) {
        return nullptr;
    }

    zero_byte_range((uint8_t *)buf->data, size);
    buf->byte_len = (size_t)size;
    return buf;
}

// Bounds-checked splice into the FRESH output buffer. Never targets
// `bin->stream->buf->data`.
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
        || end > (uint64_t)out->byte_len
        || offset > (uint64_t)SIZE_MAX
        || len > (uint64_t)SIZE_MAX) {
        return false;
    }

    memcpy((uint8_t *)out->data + offset, bytes, (size_t)len);
    return true;
}

// ============================================================================
// Plan allocation helpers (mirror elf_rewrite.c:902 new_plan)
// ============================================================================

static n00b_macho_rewrite_plan_t *
new_plan(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_macho_rewrite_plan_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
}

// ============================================================================
// Target profile evaluation
// ============================================================================

// Map a raw layout-layer error (`N00B_MACHO_LAYOUT_ERR_*`) into the Mach-O
// rewrite error block (`-44xx`). Mirrors the inline layout-error handling
// `n00b_macho_rewrite_target_profile` already uses for
// `n00b_macho_layout_build`: a layout OVERFLOW maps to the rewrite OVERFLOW
// code, every other layout error to the rewrite layout-substrate code.
static n00b_err_t
layout_err_to_rewrite_err(n00b_err_t err)
{
    if (err == N00B_MACHO_LAYOUT_ERR_OVERFLOW) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }

    return N00B_MACHO_REWRITE_ERR_TARGET_PROFILE;
}

// Is the parsed filetype a rewrite target (executable or dylib/bundle)? arm64
// MH_EXECUTE is the headline case; MH_DYLIB is also a valid LC_NOTE carrier.
static bool
filetype_is_supported(uint32_t filetype)
{
    return filetype == (uint32_t)MH_EXECUTE
        || filetype == (uint32_t)MH_DYLIB
        || filetype == (uint32_t)MH_BUNDLE;
}

static n00b_macho_rewrite_target_profile_t
profile_with_reason(n00b_macho_binary_t                       *bin,
                    n00b_macho_rewrite_target_profile_reason_t reason)
{
    n00b_macho_rewrite_target_profile_t profile = {
        .reason           = reason,
        .packager_errcode = reason == N00B_MACHO_REWRITE_PROFILE_OK ? 0 : -1,
    };

    if (bin != nullptr) {
        profile.command_count = (uint64_t)bin->header.ncmds;
        profile.sizeofcmds    = (uint64_t)bin->header.sizeofcmds;
        profile.segment_count = (uint64_t)bin->num_segments;
        if (bin->stream != nullptr && bin->stream->buf != nullptr) {
            profile.file_size = (uint64_t)bin->stream->buf->byte_len;
        }
    }

    return profile;
}

n00b_result_t(n00b_macho_rewrite_target_profile_t)
n00b_macho_rewrite_target_profile(n00b_macho_binary_t *bin)
    // No live `requires` (D-031): a null `bin`/`bin->stream` is a documented
    // `Err(N00B_MACHO_REWRITE_ERR_NULL_BINARY)` return, not a trapping
    // precondition; the guard lives in the body and the `@pre` survives as
    // advisory header Doxygen. There is no expressible success postcondition: a
    // bare `result.is_ok;` would trap on the valid `Err` (D-028), and the
    // profile-shape facts are relational (asserted by the unit oracle). The
    // block is therefore intentionally empty (design §3.5) to give the function
    // its D-004 contract block.
    ensures {
    }
{
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_target_profile_t,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    uint64_t file_size = (uint64_t)bin->stream->buf->byte_len;

    // -- MH_MAGIC_64 (single-slice, little-endian 64-bit) ------------------
    if (bin->header.magic != MH_MAGIC_64) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_MACHO_REWRITE_PROFILE_BAD_MAGIC));
    }

    // -- Fat is single-slice-API only (a fat input is parsed per-slice; a
    //    binary still flagged fat here is out of scope). --------------------
    if (bin->is_fat) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_MACHO_REWRITE_PROFILE_FAT_UNSUPPORTED));
    }

    // -- arm64 rewrite target ----------------------------------------------
    if (bin->header.cputype != (uint32_t)CPU_TYPE_ARM64) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_MACHO_REWRITE_PROFILE_BAD_CPUTYPE));
    }

    // -- Supported filetype ------------------------------------------------
    if (!filetype_is_supported(bin->header.filetype)) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_MACHO_REWRITE_PROFILE_BAD_FILETYPE));
    }

    // -- LC region bounds: header + sizeofcmds must not overflow and must
    //    fit within the file. ----------------------------------------------
    uint64_t lc_offset = (uint64_t)N00B_MACHO_HEADER_64_SIZE;
    uint64_t lc_used   = (uint64_t)bin->header.sizeofcmds;
    uint64_t lc_end;
    if (!checked_add_u64(lc_offset, lc_used, &lc_end) || lc_end > file_size) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_MACHO_REWRITE_PROFILE_LC_REGION_BOUNDS));
    }

    // -- Build the layout to derive the LC-slack capacity and confirm the LC
    //    region is consistent with the parsed sizeofcmds. -------------------
    auto layout_result = n00b_macho_layout_build(bin);
    if (n00b_result_is_err(layout_result)) {
        n00b_err_t err = n00b_result_get_err(layout_result);
        if (err == N00B_MACHO_LAYOUT_ERR_OVERFLOW) {
            return n00b_result_err(n00b_macho_rewrite_target_profile_t,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_MACHO_REWRITE_PROFILE_LC_REGION_BOUNDS));
    }

    n00b_macho_layout_t *layout = n00b_result_get(layout_result);

    // -- __LINKEDIT present + last; file ends at its end -------------------
    uint64_t linkedit_offset = 0;
    uint64_t linkedit_end    = 0;
    bool     have_linkedit   = false;
    auto     le_result       = n00b_macho_rewrite_linkedit_is_last(
        bin,
        &linkedit_offset,
        &linkedit_end,
        &have_linkedit);
    if (n00b_result_is_err(le_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_target_profile_t,
            layout_err_to_rewrite_err(n00b_result_get_err(le_result)));
    }

    if (!have_linkedit) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin, N00B_MACHO_REWRITE_PROFILE_NO_LINKEDIT));
    }

    if (!n00b_result_get(le_result) || linkedit_end != file_size) {
        return n00b_result_ok(
            n00b_macho_rewrite_target_profile_t,
            profile_with_reason(bin,
                                N00B_MACHO_REWRITE_PROFILE_LINKEDIT_NOT_LAST));
    }

    // -- Code-signature (if present) must sit at the __LINKEDIT tail -------
    bool     cs_present = false;
    uint64_t cs_offset  = 0;
    uint64_t cs_size    = 0;
    if (bin->code_signature != nullptr) {
        cs_present = true;
        cs_offset  = (uint64_t)bin->code_signature->dataoff;
        cs_size    = (uint64_t)bin->code_signature->datasize;

        uint64_t cs_end;
        if (!checked_add_u64(cs_offset, cs_size, &cs_end)) {
            return n00b_result_err(n00b_macho_rewrite_target_profile_t,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }

        if (cs_end != linkedit_end) {
            return n00b_result_ok(
                n00b_macho_rewrite_target_profile_t,
                profile_with_reason(
                    bin,
                    N00B_MACHO_REWRITE_PROFILE_CODESIG_NOT_LAST));
        }
    }

    // -- LC-region capacity: the first-segment section file base (the room the
    //    LC region can grow into), bounded by the file size when no section
    //    sits above the LC region. Mirrors admit's derivation (V-2). ---------
    auto first_sec_result =
        n00b_macho_rewrite_first_section_start_after(layout, lc_end);
    if (n00b_result_is_err(first_sec_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_target_profile_t,
            layout_err_to_rewrite_err(n00b_result_get_err(first_sec_result)));
    }

    n00b_option_t(uint64_t) first_sec = n00b_result_get(first_sec_result);
    uint64_t lc_region_capacity = first_sec.has_value
                                      ? n00b_option_get(first_sec)
                                      : file_size;

    // -- OK: populate the profile fact block ------------------------------
    n00b_macho_rewrite_target_profile_t profile =
        profile_with_reason(bin, N00B_MACHO_REWRITE_PROFILE_OK);
    profile.file_size              = file_size;
    profile.lc_region_offset       = lc_offset;
    profile.lc_region_capacity     = lc_region_capacity;
    profile.linkedit_offset        = linkedit_offset;
    profile.linkedit_size          = linkedit_end - linkedit_offset;
    profile.code_signature_present = cs_present;
    profile.code_signature_offset  = cs_offset;
    profile.code_signature_size    = cs_size;

    return n00b_result_ok(n00b_macho_rewrite_target_profile_t, profile);
}

// ============================================================================
// Metadata-insert plan
// ============================================================================

static n00b_result_t(n00b_macho_rewrite_plan_t *)
rejected_plan(n00b_allocator_t                     *allocator,
              n00b_macho_rewrite_rejection_reason_t reason,
              n00b_macho_rewrite_target_profile_t   profile,
              n00b_macho_rewrite_admit_result_t    *admission)
{
    n00b_macho_rewrite_plan_t *plan = new_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->operation              = N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT;
    plan->outcome                = N00B_MACHO_REWRITE_PLAN_REJECTED;
    plan->rejection_reason       = reason;
    plan->target_profile         = profile;
    plan->file_size              = profile.file_size;
    plan->original_command_count = profile.command_count;
    plan->new_command_count      = profile.command_count;
    if (admission != nullptr) {
        plan->admission = *admission;
        plan->file_size = admission->file_size;
    }

    return n00b_result_ok(n00b_macho_rewrite_plan_t *, plan);
}

// Locate the __LINKEDIT LC_SEGMENT_64 command's on-disk file offset (the start
// of the command in the load-command region), so apply can patch its
// filesize/vmsize fields. Returns false if no such command is found.
static bool
linkedit_command_offset(n00b_macho_binary_t *bin, uint64_t *out)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_SEGMENT_64) {
            continue;
        }

        if (cmd->raw_data == nullptr
            || cmd->raw_data->byte_len
                   < (int64_t)(N00B_MACHO_SEG64_SEGNAME_OFF
                               + N00B_MACHO_NOTE_DATA_OWNER_LEN)) {
            continue;
        }

        const char *segname =
            (const char *)cmd->raw_data->data + N00B_MACHO_SEG64_SEGNAME_OFF;
        if (n00b_macho_segment_name_is_linkedit(
                n00b_string_from_cstr(segname))) {
            *out = cmd->file_offset;
            return true;
        }
    }

    return false;
}

static n00b_result_t(n00b_macho_rewrite_plan_t *)
accepted_plan(n00b_allocator_t                            *allocator,
              n00b_macho_binary_t                         *bin,
              n00b_macho_rewrite_metadata_request_t       *request,
              n00b_macho_rewrite_target_profile_t          profile,
              n00b_macho_rewrite_admit_result_t            admission,
              n00b_macho_rewrite_admit_placement_t         placement)
{
    uint64_t payload_len = (uint64_t)request->payload->byte_len;

    // -- Load-command region: append one LC_NOTE command in the LC slack. --
    uint64_t lc_offset = profile.lc_region_offset;
    uint64_t lc_used   = profile.sizeofcmds;
    uint64_t lc_end;
    uint64_t lc_new_end;
    if (!checked_add_u64(lc_offset, lc_used, &lc_end)
        || !checked_add_u64(lc_end,
                            (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE,
                            &lc_new_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- mach_header ncmds/sizeofcmds bump; reject sizeofcmds overflow. ----
    uint64_t new_sizeofcmds;
    if (!checked_add_u64(lc_used,
                         (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE,
                         &new_sizeofcmds)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    uint64_t new_command_count;
    if (new_sizeofcmds > UINT32_MAX
        || !checked_add_u64(profile.command_count, 1, &new_command_count)
        || new_command_count > UINT32_MAX) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_NCMDS_PROMOTION,
                             profile,
                             &admission);
    }

    // -- Payload placement: the admitted placement (the __LINKEDIT-end / EOF
    //    tail), recorded as-is. The payload lands at the old __LINKEDIT end,
    //    so no existing byte moves (profile guarantees __LINKEDIT is last and
    //    the file ends at its end). ----------------------------------------
    uint64_t payload_offset = placement.file_offset;
    uint64_t payload_end;
    if (!checked_add_u64(payload_offset, payload_len, &payload_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- __LINKEDIT segment command location (apply patches its file/vm size).
    uint64_t linkedit_cmd_offset;
    if (!linkedit_command_offset(bin, &linkedit_cmd_offset)) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             &admission);
    }

    // Output file size: the payload is purely additive at the tail.
    uint64_t output_size;
    if (!checked_add_u64(profile.file_size, payload_len, &output_size)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- Build the patch array (recorded, NOT written). -------------------
    n00b_array_t(n00b_macho_rewrite_patch_t) patches =
        n00b_array_new(n00b_macho_rewrite_patch_t, 4, .allocator = allocator);

    // PATCH_MACH_HEADER: ncmds (u32@16) + sizeofcmds (u32@20).
    patches.data[0] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_MACH_HEADER,
        .file_offset          = (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
        .file_end             = (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u,
        .original_file_offset = (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
        .original_file_end    = (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u,
    };

    // PATCH_LOAD_COMMANDS: the grown LC region (new LC_NOTE command at lc_end).
    patches.data[1] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS,
        .file_offset          = lc_offset,
        .file_end             = lc_new_end,
        .original_file_offset = lc_offset,
        .original_file_end    = lc_end,
    };

    // PATCH_PAYLOAD: the new LC_NOTE payload bytes at the __LINKEDIT-end tail.
    patches.data[2] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_PAYLOAD,
        .file_offset          = payload_offset,
        .file_end             = payload_end,
        .original_file_offset = payload_offset,
        .original_file_end    = payload_offset,
    };

    // PATCH_LINKEDIT_CMD: the __LINKEDIT segment command's vmsize/filesize
    // fields (the patched span covers [vmsize_off, filesize_off+8)).
    uint64_t le_field_start;
    uint64_t le_field_end;
    if (!checked_add_u64(linkedit_cmd_offset,
                         (uint64_t)N00B_MACHO_SEG64_VMSIZE_OFF,
                         &le_field_start)
        || !checked_add_u64(linkedit_cmd_offset,
                            (uint64_t)N00B_MACHO_SEG64_FILESIZE_OFF + 8u,
                            &le_field_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    patches.data[3] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD,
        .file_offset          = le_field_start,
        .file_end             = le_field_end,
        .original_file_offset = le_field_start,
        .original_file_end    = le_field_end,
    };

    patches.len = 4;

    n00b_macho_rewrite_plan_t *plan = new_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->operation              = N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT;
    plan->outcome                = N00B_MACHO_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason       = N00B_MACHO_REWRITE_REJECT_NONE;
    plan->target_profile         = profile;
    plan->admission              = admission;
    plan->patches                = patches;
    plan->note_owner             = request->note_owner;
    plan->note_name              = request->note_name;
    plan->payload                = request->payload;
    plan->note_alignment         = admission.effective_alignment;
    plan->file_size              = output_size;
    plan->original_command_count = profile.command_count;
    plan->new_command_count      = new_command_count;
    plan->payload_offset         = payload_offset;
    plan->payload_end            = payload_end;

    return n00b_result_ok(n00b_macho_rewrite_plan_t *, plan);
}

static n00b_result_t(n00b_macho_rewrite_plan_t *)
plan_metadata_insert_impl(n00b_macho_binary_t                   *bin,
                          n00b_macho_rewrite_metadata_request_t *request,
                          n00b_allocator_t                      *allocator)
{
    // -- D-031: null/zero inputs are documented Err returns, guarded here --
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->note_owner == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD);
    }

    // -- Target profile (reject on non-OK) --------------------------------
    auto profile_result = n00b_macho_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_macho_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_MACHO_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    // -- Consult WP-004 admission (never re-derive layout) ----------------
    n00b_macho_rewrite_admit_metadata_request_t admit_request = {
        .note_owner            = request->note_owner,
        .note_name             = request->note_name,
        .payload_size          = (uint64_t)request->payload->byte_len,
        .file_alignment        = request->file_alignment,
        .preferred_file_offset = request->preferred_file_offset,
        .policy                = request->policy,
    };

    auto admit_result = n00b_macho_rewrite_admit_metadata_insert(
        bin,
        &admit_request,
        .allocator = allocator);
    if (n00b_result_is_err(admit_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ADMISSION);
    }

    n00b_macho_rewrite_admit_result_t admission =
        n00b_result_get(admit_result);
    if (admission.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_ADMISSION,
                             profile,
                             &admission);
    }

    if (!admission.placement.has_value) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ADMISSION);
    }

    return accepted_plan(allocator,
                         bin,
                         request,
                         profile,
                         admission,
                         n00b_option_get(admission.placement));
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_metadata_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null `bin`/`request`/`note_owner`/`payload`
    // and a zero `payload->byte_len` are documented `Err` returns (P1-f), not
    // trapping preconditions; the guards live in `plan_metadata_insert_impl`.
    // The `@pre` survives as header Doxygen. Mirrors the WP-004 admit twin.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || ((result.ok->payload_end - result.ok->payload_offset)
                            == request->payload->byte_len
                        && result.ok->new_command_count
                            >= result.ok->original_command_count)));
    }
{
    return plan_metadata_insert_impl(bin, request, allocator);
}

// ============================================================================
// Metadata-insert apply (COPY-OUT: fresh buffer, never mutate bin/stream)
// ============================================================================

static n00b_macho_rewrite_patch_t *
find_patch(n00b_macho_rewrite_plan_t      *plan,
           n00b_macho_rewrite_patch_kind_t kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

// Build the 40-byte LC_NOTE command bytes for the new metadata note, writing
// data_owner (NUL-padded to 16B), the payload file offset, and the payload
// size. Mirrors chalk add_note_insert's command build (macho_core.c:721-732),
// but into a caller-owned 40-byte scratch, not `buf->data`.
static void
build_note_command(uint8_t       *cmd,
                   n00b_string_t *note_owner,
                   uint64_t       payload_offset,
                   uint64_t       payload_size)
{
    zero_byte_range(cmd, (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE);
    set_le_u32(cmd, (uint32_t)LC_NOTE);
    set_le_u32(cmd + 4, (uint32_t)N00B_MACHO_LC_NOTE_CMD_SIZE);

    // data_owner: up to 16 bytes of the owner string (the rest stays zero).
    uint64_t want = (uint64_t)note_owner->u8_bytes;
    if (want > (uint64_t)N00B_MACHO_NOTE_DATA_OWNER_LEN) {
        want = (uint64_t)N00B_MACHO_NOTE_DATA_OWNER_LEN;
    }
    for (uint64_t i = 0; i < want; i++) {
        cmd[N00B_MACHO_NOTE_DATA_OWNER_OFF + i] =
            ((const uint8_t *)note_owner->data)[i];
    }

    set_le_u64(cmd + N00B_MACHO_NOTE_OFFSET_OFF, payload_offset);
    set_le_u64(cmd + N00B_MACHO_NOTE_SIZE_OFF, payload_size);
}

static n00b_result_t(n00b_buffer_t *)
apply_metadata_insert_impl(n00b_macho_binary_t       *bin,
                           n00b_macho_rewrite_plan_t *plan,
                           n00b_allocator_t          *allocator)
{
    // -- D-031: null/state-malformed inputs are documented Err returns -----
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->operation != N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT
        || plan->payload == nullptr
        || plan->note_owner == nullptr
        || plan->patches.data == nullptr
        || plan->patches.len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    uint64_t input_size = (uint64_t)bin->stream->buf->byte_len;
    if (plan->file_size < input_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    n00b_macho_rewrite_patch_t *header_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_MACH_HEADER);
    n00b_macho_rewrite_patch_t *lc_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS);
    n00b_macho_rewrite_patch_t *payload_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_PAYLOAD);
    n00b_macho_rewrite_patch_t *le_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD);
    if (header_patch == nullptr || lc_patch == nullptr
        || payload_patch == nullptr || le_patch == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    if (payload_patch->file_offset != plan->payload_offset
        || payload_patch->file_end != plan->payload_end
        || plan->payload_end - plan->payload_offset
               != (uint64_t)plan->payload->byte_len
        || plan->payload_offset != input_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- COPY-OUT: allocate a fresh buffer and copy the WHOLE input first.
    //    Every non-planned byte is then already correct (NFR-01 mechanism). -
    n00b_buffer_t *out = new_zero_buffer(plan->file_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    memcpy((uint8_t *)out->data,
           (const uint8_t *)bin->stream->buf->data,
           (size_t)input_size);

    // -- Patch mach_header ncmds + sizeofcmds ------------------------------
    if (header_patch->file_offset != (uint64_t)N00B_MACHO_HDR_NCMDS_OFF) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }
    {
        uint8_t  hdr[8];
        uint64_t lc_used = lc_patch->original_file_end - lc_patch->file_offset;
        uint64_t new_sizeofcmds;
        if (!checked_add_u64(lc_used,
                             (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE,
                             &new_sizeofcmds)
            || new_sizeofcmds > UINT32_MAX
            || plan->new_command_count > UINT32_MAX) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        set_le_u32(hdr, (uint32_t)plan->new_command_count);
        set_le_u32(hdr + 4, (uint32_t)new_sizeofcmds);
        if (!write_output_bytes(out,
                                (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
                                hdr,
                                sizeof(hdr))) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Write the new LC_NOTE command in the LC slack (at lc_patch end) ----
    {
        uint64_t cmd_offset = lc_patch->original_file_end;
        if (lc_patch->file_end - lc_patch->original_file_end
                != (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint8_t note_cmd[N00B_MACHO_LC_NOTE_CMD_SIZE];
        build_note_command(note_cmd,
                           plan->note_owner,
                           plan->payload_offset,
                           (uint64_t)plan->payload->byte_len);
        if (!write_output_bytes(out,
                                cmd_offset,
                                note_cmd,
                                (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Append the payload at the __LINKEDIT-end tail (old EOF) ------------
    if (!write_output_bytes(out,
                            plan->payload_offset,
                            plan->payload->data,
                            (uint64_t)plan->payload->byte_len)) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- Grow __LINKEDIT.filesize (+ payload) and vmsize (page-rounded) -----
    {
        uint64_t le_cmd_offset = le_patch->file_offset
                               - (uint64_t)N00B_MACHO_SEG64_VMSIZE_OFF;
        uint64_t filesize_off;
        if (!checked_add_u64(le_cmd_offset,
                             (uint64_t)N00B_MACHO_SEG64_FILESIZE_OFF,
                             &filesize_off)
            || filesize_off + 8u > (uint64_t)out->byte_len) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // Read the original __LINKEDIT filesize/vmsize from the parsed model
        // (segment fields), grow them, and write into the fresh output.
        uint64_t old_filesize = 0;
        uint64_t old_vmsize   = 0;
        bool     found        = false;
        for (uint32_t i = 0; i < bin->num_segments; i++) {
            if (n00b_macho_segment_name_is_linkedit(
                    n00b_string_from_cstr(bin->segments[i].name))) {
                old_filesize = bin->segments[i].filesize;
                old_vmsize   = bin->segments[i].vmsize;
                found        = true;
                break;
            }
        }
        if (!found) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint64_t new_filesize;
        if (!checked_add_u64(old_filesize,
                             (uint64_t)plan->payload->byte_len,
                             &new_filesize)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // vmsize must cover the new filesize, page-rounded; never shrink it.
        uint64_t page = (uint64_t)N00B_MACHO_REWRITE_PAGE;
        uint64_t rounded;
        if (!checked_add_u64(new_filesize, page - 1, &rounded)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t new_vmsize = rounded & ~(page - 1);
        if (new_vmsize < old_vmsize) {
            new_vmsize = old_vmsize;
        }

        uint8_t vm_bytes[8];
        uint8_t file_bytes[8];
        set_le_u64(vm_bytes, new_vmsize);
        set_le_u64(file_bytes, new_filesize);
        if (!write_output_bytes(out,
                                le_cmd_offset
                                    + (uint64_t)N00B_MACHO_SEG64_VMSIZE_OFF,
                                vm_bytes,
                                sizeof(vm_bytes))
            || !write_output_bytes(out, filesize_off, file_bytes,
                                   sizeof(file_bytes))) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Reparse the output; on failure return PARSE_AFTER_APPLY -----------
    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_metadata_insert_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin`/`plan`, a non-ACCEPTED plan, and
    // a mismatched operation are documented `Err` returns (P1-e), not trapping
    // preconditions; the guards live in `apply_metadata_insert_impl`. The
    // `@pre` survives as header Doxygen. NFR-01 byte-preservation and the
    // reparse postcondition are authoritative prose `@post` + test oracle (no
    // `old()`/no calls in contracts), not `ensures`.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len >= bin->stream->buf->byte_len);
    }
{
    return apply_metadata_insert_impl(bin, plan, allocator);
}

// ============================================================================
// Phase 2 — trusted-insert planners (chalk mark + object bundle)
// ============================================================================
//
// The trusted distinction is the admission path + the reserved-owner guard, NOT
// a distinct operation enum value: both trusted-insert planners set
// `operation = N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT` and their accepted
// plans are applied by the Phase-1 `apply_metadata_insert_plan` engine. They
// reuse `plan_metadata_insert_impl`'s profile→admission→accepted_plan core but
// (a) require the request's `note_owner` to equal the reserved token and
// (b) consult the matching trusted admit function (D-030, reserved tokens via
// their `#define`s).

// True when `owner` equals `token` (a NUL-terminated reserved-owner C string).
// When `owner` is built from a parsed 16-byte NUL-padded `data_owner` via
// `n00b_string_from_cstr`, the conversion stops at the first NUL, so the field
// padding does not affect the comparison. Pure read; uses the n00b string
// primitive (no `strcmp`).
static bool
note_owner_matches_token(n00b_string_t *owner, const char *token)
{
    return n00b_unicode_str_eq(owner, n00b_string_from_cstr(token));
}

// Shared trusted-insert core. `token` is the reserved owner the request must
// carry; `is_chalk` selects which trusted admission path to consult (chalk vs
// object-bundle). A non-matching owner is `Ok(rejected, REJECT_TRUSTED_NAME)`
// (D-031: not a trap). On accept the operation stays METADATA_INSERT so the
// Phase-1 apply engine handles it.
static n00b_result_t(n00b_macho_rewrite_plan_t *)
plan_trusted_insert_impl(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request,
    n00b_allocator_t                      *allocator,
    const char                            *token,
    bool                                   is_chalk)
{
    // -- D-031: null/zero inputs are documented Err returns, guarded here --
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->note_owner == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD);
    }

    // -- Target profile (reject on non-OK) --------------------------------
    auto profile_result = n00b_macho_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_macho_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_MACHO_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    // -- Reserved-owner guard (the trusted distinction) -------------------
    if (!note_owner_matches_token(request->note_owner, token)) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TRUSTED_NAME,
                             profile,
                             nullptr);
    }

    // -- Consult the trusted WP-004 admission path ------------------------
    n00b_macho_rewrite_admit_metadata_request_t admit_request = {
        .note_owner            = request->note_owner,
        .note_name             = request->note_name,
        .payload_size          = (uint64_t)request->payload->byte_len,
        .file_alignment        = request->file_alignment,
        .preferred_file_offset = request->preferred_file_offset,
        .policy                = request->policy,
    };

    auto admit_result =
        is_chalk
            ? n00b_macho_rewrite_admit_chalk_mark_insert(bin,
                                                         &admit_request,
                                                         .allocator = allocator)
            : n00b_macho_rewrite_admit_object_bundle_insert(
                  bin,
                  &admit_request,
                  .allocator = allocator);
    if (n00b_result_is_err(admit_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ADMISSION);
    }

    n00b_macho_rewrite_admit_result_t admission =
        n00b_result_get(admit_result);
    if (admission.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_ADMISSION,
                             profile,
                             &admission);
    }

    if (!admission.placement.has_value) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ADMISSION);
    }

    return accepted_plan(allocator,
                         bin,
                         request,
                         profile,
                         admission,
                         n00b_option_get(admission.placement));
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null `bin`/`request`/`note_owner`/`payload`
    // and a zero `payload->byte_len` are documented `Err` returns, guarded in
    // `plan_trusted_insert_impl`; `@pre` survives as header Doxygen. The
    // trusted-name shadow is part of the accepted post (the operation stays
    // METADATA_INSERT, applied by the Phase-1 engine).
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || ((result.ok->payload_end - result.ok->payload_offset)
                            == request->payload->byte_len
                        && result.ok->new_command_count
                            >= result.ok->original_command_count)));
    }
{
    return plan_trusted_insert_impl(bin,
                                    request,
                                    allocator,
                                    CHALK_MACHO_NOTE_OWNER,
                                    true);
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs are documented `Err` returns
    // guarded in `plan_trusted_insert_impl`. The reserved owner is matched via
    // `N00B_MACHO_BUNDLE_NOTE_OWNER` (D-030), not a duplicated literal.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || ((result.ok->payload_end - result.ok->payload_offset)
                            == request->payload->byte_len
                        && result.ok->new_command_count
                            >= result.ok->original_command_count)));
    }
{
    return plan_trusted_insert_impl(bin,
                                    request,
                                    allocator,
                                    N00B_MACHO_BUNDLE_NOTE_OWNER,
                                    false);
}

// ============================================================================
// Phase 2 — carrier-note finder (mirror chalk find_chalk_command_index)
// ============================================================================

// A located carrier LC_NOTE: its command index, on-disk command file offset
// (slice-relative, the parsed `cmd->file_offset`), command size, and the
// payload file range [payload_offset, payload_offset+payload_size).
typedef struct {
    bool     found;
    uint32_t command_index;
    uint64_t command_file_offset;
    uint64_t command_size;
    uint64_t payload_offset;
    uint64_t payload_size;
} located_note_t;

// Scan `bin->commands[]` for an LC_NOTE whose `data_owner` matches `token`
// (NUL-padded to 16 bytes). Mirrors chalk's `find_chalk_command_index` +
// `data_owner` parse (`macho_core.c:282-324, 523-538`), but reads only the
// parsed model and the reserved token's `#define` (D-030). Pure read.
static located_note_t
find_carrier_note(n00b_macho_binary_t *bin, const char *token)
{
    located_note_t out = {};

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];

        if (cmd->cmd != LC_NOTE) {
            continue;
        }

        if (cmd->raw_data == nullptr
            || cmd->raw_data->byte_len < (int64_t)N00B_MACHO_LC_NOTE_CMD_SIZE) {
            continue;
        }

        const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;
        const char    *owner =
            (const char *)(raw + N00B_MACHO_NOTE_DATA_OWNER_OFF);

        // Compare the data_owner field (16 bytes, NUL-padded) to the token.
        if (!note_owner_matches_token(n00b_string_from_cstr(owner), token)) {
            continue;
        }

        // little-endian u64 reads of offset@24 and size@32.
        uint64_t payload_offset;
        uint64_t payload_size;
        payload_offset = (uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF]
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 1] << 8)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 2] << 16)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 3] << 24)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 4] << 32)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 5] << 40)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 6] << 48)
                       | ((uint64_t)raw[N00B_MACHO_NOTE_OFFSET_OFF + 7] << 56);
        payload_size = (uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF]
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 1] << 8)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 2] << 16)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 3] << 24)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 4] << 32)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 5] << 40)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 6] << 48)
                     | ((uint64_t)raw[N00B_MACHO_NOTE_SIZE_OFF + 7] << 56);

        out.found               = true;
        out.command_index       = i;
        out.command_file_offset = cmd->file_offset;
        out.command_size        = (uint64_t)cmd->cmdsize;
        out.payload_offset      = payload_offset;
        out.payload_size        = payload_size;
        return out;
    }

    return out;
}

// ============================================================================
// Phase 2 — replace planners (in-slot only; growth-replace tracked as DF-008-01)
// ============================================================================

// Common replace core. `token` selects the carrier owner; `operation` /
// `not_found_reason` distinguish the chalk vs object-bundle paths. In-slot
// only: if the new payload fits the located slot, emit PATCH_PAYLOAD (new
// bytes) + PATCH_STALE_PAYLOAD (the zeroed tail of the old slot); otherwise
// `Ok(rejected, REJECT_LC_PLACEMENT)`. Larger-payload (growth) replace is the
// tracked deferral DF-008-01 (delete-then-insert composition; destination set at
// the WP-008 close check-in). No header growth here.
static n00b_result_t(n00b_macho_rewrite_plan_t *)
plan_replace_impl(n00b_macho_binary_t                   *bin,
                  n00b_macho_rewrite_metadata_request_t *request,
                  n00b_allocator_t                      *allocator,
                  const char                            *token,
                  n00b_macho_rewrite_operation_t         operation,
                  n00b_macho_rewrite_rejection_reason_t  not_found_reason)
{
    // -- D-031: null/zero inputs are documented Err returns, guarded here --
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->note_owner == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD);
    }

    // -- Target profile (reject on non-OK) --------------------------------
    auto profile_result = n00b_macho_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_macho_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_MACHO_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    // -- Locate the existing carrier note ---------------------------------
    located_note_t note = find_carrier_note(bin, token);
    if (!note.found) {
        return rejected_plan(allocator, not_found_reason, profile, nullptr);
    }

    uint64_t new_size = (uint64_t)request->payload->byte_len;

    // The located payload range must be in-bounds for the input file.
    uint64_t old_payload_end;
    if (!checked_add_u64(note.payload_offset, note.payload_size,
                         &old_payload_end)
        || old_payload_end > profile.file_size) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- In-slot check: the new payload must fit the located slot. --------
    if (new_size > note.payload_size) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT,
                             profile,
                             nullptr);
    }

    uint64_t new_payload_end;
    if (!checked_add_u64(note.payload_offset, new_size, &new_payload_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- Build the patch array: PATCH_PAYLOAD (new bytes at the old offset)
    //    + PATCH_STALE_PAYLOAD (the zeroed tail of the old slot). No header
    //    growth: the slot stays, so file size is unchanged. ----------------
    n00b_array_t(n00b_macho_rewrite_patch_t) patches =
        n00b_array_new(n00b_macho_rewrite_patch_t, 2, .allocator = allocator);

    patches.data[0] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_PAYLOAD,
        .file_offset          = note.payload_offset,
        .file_end             = new_payload_end,
        .original_file_offset = note.payload_offset,
        .original_file_end    = old_payload_end,
    };

    patches.data[1] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD,
        .file_offset          = new_payload_end,
        .file_end             = old_payload_end,
        .original_file_offset = new_payload_end,
        .original_file_end    = old_payload_end,
    };

    patches.len = 2;

    n00b_macho_rewrite_plan_t *plan = new_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->operation              = operation;
    plan->outcome                = N00B_MACHO_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason       = N00B_MACHO_REWRITE_REJECT_NONE;
    plan->target_profile         = profile;
    plan->patches                = patches;
    plan->note_owner             = request->note_owner;
    plan->note_name              = request->note_name;
    plan->payload                = request->payload;
    plan->file_size              = profile.file_size; // in-slot: unchanged
    plan->original_command_count = profile.command_count;
    plan->new_command_count      = profile.command_count;
    plan->removed_payload_offset = note.payload_offset;
    plan->removed_payload_end    = old_payload_end;
    plan->payload_offset         = note.payload_offset;
    plan->payload_end            = new_payload_end;

    return n00b_result_ok(n00b_macho_rewrite_plan_t *, plan);
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs are documented `Err` returns
    // guarded in `plan_replace_impl`; `@pre` survives as header Doxygen. On
    // accept a prior carrier was located, so the removed range is non-empty.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || (result.ok->removed_payload_end
                        > result.ok->removed_payload_offset)));
    }
{
    return plan_replace_impl(
        bin,
        request,
        allocator,
        CHALK_MACHO_NOTE_OWNER,
        N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_REPLACE,
        N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND);
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs are documented `Err` returns
    // guarded in `plan_replace_impl`. Reserved owner via
    // `N00B_MACHO_BUNDLE_NOTE_OWNER` (D-030).
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || (result.ok->removed_payload_end
                        > result.ok->removed_payload_offset)));
    }
{
    return plan_replace_impl(
        bin,
        request,
        allocator,
        N00B_MACHO_BUNDLE_NOTE_OWNER,
        N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE,
        N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND);
}

// ============================================================================
// Phase 2 — delete planner (shrinks the file); owner-parameterized core
// ============================================================================
//
// Delete removes the carrier LC_NOTE command from the LC region and drops its
// payload from __LINKEDIT, producing an output SMALLER than the input. The plan
// records:
//   PATCH_MACH_HEADER     — ncmds-1, sizeofcmds -= the note cmd size.
//   PATCH_LOAD_COMMANDS   — the shrunk LC region (trailing LCs shifted up by
//                           the note cmd size; the freed tail zeroed).
//   PATCH_STALE_PAYLOAD   — the removed payload range; OMITTED from the copy-out
//                           (this is the shrink, not a zero-fill).
// The note's payload is required to be the last bytes of __LINKEDIT (the file
// tail), the carrier insert/marking invariant (file ends at __LINKEDIT's end),
// so dropping it keeps __LINKEDIT last and the file ending at its end.
//
// `plan_delete_impl` is owner-agnostic given the located note: `owner_token`
// selects the carrier owner (chalk vs object-bundle) via the owner-keyed
// `find_carrier_note`, and `not_found_reason` is the rejection reported when no
// such carrier is present. `n00b_macho_rewrite_plan_chalk_mark_delete` and
// `n00b_macho_rewrite_plan_object_bundle_delete` are thin delegates (D-037).
// The output plan's `operation` is selected by `operation`.

static n00b_result_t(n00b_macho_rewrite_plan_t *)
plan_delete_impl(n00b_macho_binary_t                  *bin,
                 const char                           *owner_token,
                 n00b_macho_rewrite_operation_t        operation,
                 n00b_macho_rewrite_rejection_reason_t not_found_reason,
                 n00b_allocator_t                     *allocator)
{
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    // -- Target profile (reject on non-OK) --------------------------------
    auto profile_result = n00b_macho_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_macho_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_MACHO_REWRITE_PROFILE_OK) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                             profile,
                             nullptr);
    }

    // -- Locate the carrier note ------------------------------------------
    located_note_t note = find_carrier_note(bin, owner_token);
    if (!note.found) {
        return rejected_plan(allocator, not_found_reason, profile, nullptr);
    }

    uint64_t old_payload_end;
    if (!checked_add_u64(note.payload_offset, note.payload_size,
                         &old_payload_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // The deleted payload must be the file tail (the chalk marking invariant:
    // the file ends at __LINKEDIT's end, and the note payload is appended
    // there). If not, the slice-out shrink would move other bytes — out of
    // scope for the in-place metadata path (WP-006).
    if (old_payload_end != profile.file_size || note.payload_size == 0) {
        return rejected_plan(allocator,
                             N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT,
                             profile,
                             nullptr);
    }

    // -- mach_header: ncmds-1, sizeofcmds -= the note command size --------
    if (profile.command_count == 0
        || profile.sizeofcmds < note.command_size) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- LC region: shift the trailing LCs up over the deleted command. ---
    uint64_t lc_offset = profile.lc_region_offset;
    uint64_t lc_end;
    if (!checked_add_u64(lc_offset, profile.sizeofcmds, &lc_end)) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    uint64_t output_size = profile.file_size - note.payload_size;

    n00b_array_t(n00b_macho_rewrite_patch_t) patches =
        n00b_array_new(n00b_macho_rewrite_patch_t, 3, .allocator = allocator);

    // PATCH_MACH_HEADER: ncmds (u32@16) + sizeofcmds (u32@20).
    patches.data[0] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_MACH_HEADER,
        .file_offset          = (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
        .file_end             = (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u,
        .original_file_offset = (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
        .original_file_end    = (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u,
    };

    // PATCH_LOAD_COMMANDS: the LC region shrinks by the note command; the
    // trailing LCs slide up over the deleted command, the freed tail zeroed.
    //   file_offset          = deleted-command start (dest of the slide)
    //   original_file_offset  = trailing-LC source start (= cmd start + cmd size)
    //   original_file_end     = LC region end in the input
    //   file_end              = LC region end in the output (-= cmd size)
    uint64_t trailing_src_start;
    if (!checked_add_u64(note.command_file_offset, note.command_size,
                         &trailing_src_start)
        || trailing_src_start > lc_end) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    patches.data[1] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS,
        .file_offset          = note.command_file_offset,
        .file_end             = lc_end - note.command_size,
        .original_file_offset = trailing_src_start,
        .original_file_end    = lc_end,
    };

    // PATCH_STALE_PAYLOAD: the removed payload range. For DELETE this range is
    // OMITTED from the copy-out (a shrink), not zero-filled.
    patches.data[2] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD,
        .file_offset          = note.payload_offset,
        .file_end             = old_payload_end,
        .original_file_offset = note.payload_offset,
        .original_file_end    = old_payload_end,
    };

    patches.len = 3;

    n00b_macho_rewrite_plan_t *plan = new_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->operation              = operation;
    plan->outcome                = N00B_MACHO_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason       = N00B_MACHO_REWRITE_REJECT_NONE;
    plan->target_profile         = profile;
    plan->patches                = patches;
    plan->file_size              = output_size;
    plan->original_command_count = profile.command_count;
    plan->new_command_count      = profile.command_count - 1;
    plan->removed_payload_offset = note.payload_offset;
    plan->removed_payload_end    = old_payload_end;

    return n00b_result_ok(n00b_macho_rewrite_plan_t *, plan);
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_delete(
    n00b_macho_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin`/`bin->stream` is a documented
    // `Err` return guarded in `plan_delete_impl`; `@pre` survives as header
    // Doxygen. On accept a prior carrier was located, so the removed range is
    // non-empty.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || (result.ok->removed_payload_end
                        > result.ok->removed_payload_offset)));
    }
{
    return plan_delete_impl(
        bin,
        CHALK_MACHO_NOTE_OWNER,
        N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_DELETE,
        N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND,
        allocator);
}

n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_delete(
    n00b_macho_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin`/`bin->stream` is a documented
    // `Err` return guarded in `plan_delete_impl`; `@pre` survives as header
    // Doxygen. Reserved owner via `N00B_MACHO_BUNDLE_NOTE_OWNER` (D-030). On
    // accept a prior carrier was located, so the removed range is non-empty.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || (result.ok->removed_payload_end
                        > result.ok->removed_payload_offset)));
    }
{
    return plan_delete_impl(
        bin,
        N00B_MACHO_BUNDLE_NOTE_OWNER,
        N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_DELETE,
        N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND,
        allocator);
}

// ============================================================================
// Phase 2 — apply (COPY-OUT): chalk-mark delete/replace + object-bundle replace
// ============================================================================

// Read the parsed __LINKEDIT segment's filesize/vmsize and command file offset
// (pure read of the parsed model). Returns false if there is no __LINKEDIT.
static bool
linkedit_segment_facts(n00b_macho_binary_t *bin,
                       uint64_t            *cmd_offset_out,
                       uint64_t            *filesize_out,
                       uint64_t            *vmsize_out)
{
    uint64_t cmd_offset;
    if (!linkedit_command_offset(bin, &cmd_offset)) {
        return false;
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (n00b_macho_segment_name_is_linkedit(
                n00b_string_from_cstr(bin->segments[i].name))) {
            *cmd_offset_out = cmd_offset;
            *filesize_out   = bin->segments[i].filesize;
            *vmsize_out     = bin->segments[i].vmsize;
            return true;
        }
    }

    return false;
}

// Apply an in-slot replace: copy the whole input, overwrite the payload slot
// with the new bytes, zero the stale tail, and shrink the note command's size
// field to the new payload size. The output is the same size as the input.
static n00b_result_t(n00b_buffer_t *)
apply_replace_impl(n00b_macho_binary_t       *bin,
                   n00b_macho_rewrite_plan_t *plan,
                   n00b_allocator_t          *allocator,
                   const char                *token)
{
    uint64_t input_size = (uint64_t)bin->stream->buf->byte_len;

    n00b_macho_rewrite_patch_t *payload_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_PAYLOAD);
    n00b_macho_rewrite_patch_t *stale_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD);
    if (payload_patch == nullptr || stale_patch == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    uint64_t new_size = (uint64_t)plan->payload->byte_len;
    if (plan->file_size != input_size
        || plan->payload_offset != payload_patch->file_offset
        || plan->payload_end != payload_patch->file_end
        || plan->payload_end - plan->payload_offset != new_size
        || stale_patch->file_offset != plan->payload_end
        || stale_patch->file_end != plan->removed_payload_end
        || plan->removed_payload_end > input_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // Re-locate the note command so we can shrink its size field in the output.
    located_note_t note = find_carrier_note(bin, token);
    if (!note.found
        || note.payload_offset != plan->payload_offset
        || note.command_file_offset + N00B_MACHO_NOTE_SIZE_OFF + 8u
               > input_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- COPY-OUT: fresh buffer, copy the whole input. --------------------
    n00b_buffer_t *out = new_zero_buffer(plan->file_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    memcpy((uint8_t *)out->data,
           (const uint8_t *)bin->stream->buf->data,
           (size_t)input_size);

    // -- Overwrite the slot with the new payload bytes. -------------------
    if (!write_output_bytes(out,
                            plan->payload_offset,
                            plan->payload->data,
                            new_size)) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- Zero the stale tail of the old slot (REPLACE semantics). ---------
    {
        uint64_t stale_len = stale_patch->file_end - stale_patch->file_offset;
        if (stale_len > 0) {
            uint8_t *p = (uint8_t *)out->data + stale_patch->file_offset;
            if (stale_patch->file_end > (uint64_t)out->byte_len) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_REWRITE_ERR_APPLY);
            }
            zero_byte_range(p, stale_len);
        }
    }

    // -- Shrink the note command's size field to the new payload size. ----
    {
        uint8_t size_bytes[8];
        set_le_u64(size_bytes, new_size);
        if (!write_output_bytes(out,
                                note.command_file_offset
                                    + (uint64_t)N00B_MACHO_NOTE_SIZE_OFF,
                                size_bytes,
                                sizeof(size_bytes))) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Reparse the output. ----------------------------------------------
    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

// Apply a chalk-mark delete: copy [0, removed_offset) into a smaller output,
// slide the trailing load commands up over the deleted note command, patch the
// mach_header (ncmds-1, sizeofcmds -= note cmd size), shrink __LINKEDIT, and
// drop the payload (the file tail) entirely from the copy-out.
static n00b_result_t(n00b_buffer_t *)
apply_delete_impl(n00b_macho_binary_t       *bin,
                  n00b_macho_rewrite_plan_t *plan,
                  n00b_allocator_t          *allocator)
{
    uint64_t input_size = (uint64_t)bin->stream->buf->byte_len;

    n00b_macho_rewrite_patch_t *header_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_MACH_HEADER);
    n00b_macho_rewrite_patch_t *lc_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS);
    n00b_macho_rewrite_patch_t *stale_patch =
        find_patch(plan, N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD);
    if (header_patch == nullptr || lc_patch == nullptr
        || stale_patch == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // The deleted payload is the file tail: removed_end == input EOF and the
    // output is the input minus the payload bytes. The LC patch encodes:
    //   file_offset          = deleted-command start (dest of the slide)
    //   original_file_offset  = trailing-LC source start (cmd start + cmd size)
    //   original_file_end     = LC region end (input); file_end = end (output).
    uint64_t removed_offset = plan->removed_payload_offset;
    uint64_t removed_end    = plan->removed_payload_end;
    if (lc_patch->original_file_offset < lc_patch->file_offset) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }
    uint64_t note_cmd_size = lc_patch->original_file_offset
                           - lc_patch->file_offset;
    if (removed_end != input_size
        || removed_offset >= removed_end
        || stale_patch->file_offset != removed_offset
        || stale_patch->file_end != removed_end
        || plan->file_size != input_size - (removed_end - removed_offset)
        || note_cmd_size == 0
        || lc_patch->original_file_end > input_size
        || lc_patch->original_file_offset > lc_patch->original_file_end
        || lc_patch->file_end != lc_patch->original_file_end - note_cmd_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- COPY-OUT: a fresh, SMALLER buffer. Copy [0, removed_offset). The
    //    deleted payload range is OMITTED (the shrink); [removed_end, EOF) is
    //    empty because the payload is the tail. -------------------------------
    n00b_buffer_t *out = new_zero_buffer(plan->file_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    if (removed_offset > plan->file_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }
    memcpy((uint8_t *)out->data,
           (const uint8_t *)bin->stream->buf->data,
           (size_t)removed_offset);

    // -- Slide the trailing load commands up over the deleted note command.
    //    Source: [original_file_offset, original_file_end) in the COPIED bytes;
    //    dest:   [file_offset, original_file_end - note_cmd_size). ------------
    {
        uint64_t src_start = lc_patch->original_file_offset;
        uint64_t src_end   = lc_patch->original_file_end;
        uint64_t dst_start = lc_patch->file_offset;
        uint64_t move_len  = src_end - src_start;

        if (src_end > (uint64_t)out->byte_len
            || dst_start + move_len > (uint64_t)out->byte_len) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // memmove via a forward copy: dst < src and ranges may abut, so use
        // memmove semantics through the n00b buffer's own bytes.
        memmove((uint8_t *)out->data + dst_start,
                (uint8_t *)out->data + src_start,
                (size_t)move_len);

        // Zero the freed tail of the LC region (slack left by the shift).
        uint64_t freed_start = dst_start + move_len;
        if (freed_start < src_end) {
            zero_byte_range((uint8_t *)out->data + freed_start,
                            src_end - freed_start);
        }
    }

    // -- Patch mach_header ncmds-1 + sizeofcmds -= note cmd size. ----------
    {
        if (plan->new_command_count > UINT32_MAX
            || plan->target_profile.sizeofcmds < note_cmd_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t new_sizeofcmds = plan->target_profile.sizeofcmds
                                - note_cmd_size;
        if (new_sizeofcmds > UINT32_MAX) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint8_t hdr[8];
        set_le_u32(hdr, (uint32_t)plan->new_command_count);
        set_le_u32(hdr + 4, (uint32_t)new_sizeofcmds);
        if (!write_output_bytes(out,
                                (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
                                hdr,
                                sizeof(hdr))) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Shrink __LINKEDIT.filesize by the dropped payload (keep vmsize). --
    {
        uint64_t le_cmd_offset;
        uint64_t old_filesize;
        uint64_t old_vmsize;
        if (!linkedit_segment_facts(bin, &le_cmd_offset, &old_filesize,
                                    &old_vmsize)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint64_t payload_len = removed_end - removed_offset;
        if (old_filesize < payload_len) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t new_filesize = old_filesize - payload_len;

        uint64_t filesize_off;
        if (!checked_add_u64(le_cmd_offset,
                             (uint64_t)N00B_MACHO_SEG64_FILESIZE_OFF,
                             &filesize_off)
            || filesize_off + 8u > (uint64_t)out->byte_len) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint8_t file_bytes[8];
        set_le_u64(file_bytes, new_filesize);
        if (!write_output_bytes(out, filesize_off, file_bytes,
                                sizeof(file_bytes))) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Reparse the output. ----------------------------------------------
    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

static n00b_result_t(n00b_buffer_t *)
apply_chalk_mark_impl(n00b_macho_binary_t       *bin,
                      n00b_macho_rewrite_plan_t *plan,
                      n00b_allocator_t          *allocator)
{
    // -- D-031: null/state-malformed inputs are documented Err returns -----
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->patches.data == nullptr || plan->patches.len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    switch (plan->operation) {
    case N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_DELETE:
        return apply_delete_impl(bin, plan, allocator);
    case N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_REPLACE:
        if (plan->payload == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
        }
        return apply_replace_impl(bin,
                                  plan,
                                  allocator,
                                  CHALK_MACHO_NOTE_OWNER);
    default:
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/non-accepted/mismatched inputs are
    // documented `Err` returns guarded in `apply_chalk_mark_impl`; `@pre`
    // survives as header Doxygen. NFR-01 byte-preservation, stale-byte zeroing
    // (REPLACE) / omission (DELETE), and reparse are authoritative prose
    // `@post` + test oracle, not `ensures`.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null. Replace keeps
        // the size; delete shrinks it — both stay within the input bound.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len <= bin->stream->buf->byte_len);
    }
{
    return apply_chalk_mark_impl(bin, plan, allocator);
}

static n00b_result_t(n00b_buffer_t *)
apply_object_bundle_impl(n00b_macho_binary_t       *bin,
                         n00b_macho_rewrite_plan_t *plan,
                         n00b_allocator_t          *allocator)
{
    // -- D-031: null/state-malformed inputs are documented Err returns -----
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->patches.data == nullptr || plan->patches.len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    // OBJECT_BUNDLE_DELETE (D-037) shares the owner-agnostic delete apply;
    // OBJECT_BUNDLE_REPLACE is the in-slot replace. No other operation applies
    // through this path.
    switch (plan->operation) {
    case N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_DELETE:
        return apply_delete_impl(bin, plan, allocator);
    case N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE:
        if (plan->payload == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
        }
        return apply_replace_impl(bin,
                                  plan,
                                  allocator,
                                  N00B_MACHO_BUNDLE_NOTE_OWNER);
    default:
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/non-accepted/mismatched inputs are
    // documented `Err` returns guarded in `apply_object_bundle_impl`; `@pre`
    // survives as header Doxygen. NFR-01 + stale-byte zeroing + reparse are
    // authoritative prose `@post` + test oracle, not `ensures`.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null. The in-slot
        // replace keeps the size, so the output equals the input length.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len <= bin->stream->buf->byte_len);
    }
{
    return apply_object_bundle_impl(bin, plan, allocator);
}

// ============================================================================
// Phase 2 — §3.5 convenience wrappers (plan-then-apply compositions)
// ============================================================================
//
// Each wrapper plans then applies, propagating Err/rejection unchanged: a plan
// `Err` is returned as-is; an accepted-but-rejected plan becomes
// `Err(N00B_MACHO_REWRITE_ERR_PLAN_REJECTED)`; an accepted plan is applied. A
// trusted chalk insert is applied via the Phase-1 apply engine (the operation
// stays METADATA_INSERT); there is intentionally no `apply_chalk_mark_insert`
// wrapper (none is declared in the header).

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_metadata_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs propagate from the planner
    // as documented `Err` returns; `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_metadata_insert(bin,
                                                request,
                                                .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_metadata_insert_plan(bin,
                                                         plan,
                                                         .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_delete(
    n00b_macho_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin` propagates from the planner as a
    // documented `Err` return; `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_chalk_mark_delete(bin, .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_chalk_mark_plan(bin,
                                                    plan,
                                                    .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_delete(
    n00b_macho_binary_t *bin) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin` propagates from the planner as a
    // documented `Err` return; `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_object_bundle_delete(bin, .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_object_bundle_plan(bin,
                                                       plan,
                                                       .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs propagate from the planner
    // as documented `Err` returns; `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_chalk_mark_replace(bin,
                                                   request,
                                                   .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_chalk_mark_plan(bin,
                                                    plan,
                                                    .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs propagate from the planner
    // as documented `Err` returns; `@pre` survives as header Doxygen. A trusted
    // bundle insert is applied via the Phase-1 metadata-insert apply engine.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_object_bundle_insert(bin,
                                                     request,
                                                     .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_metadata_insert_plan(bin,
                                                         plan,
                                                         .allocator = allocator);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null/zero inputs propagate from the planner
    // as documented `Err` returns; `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok || result.ok != nullptr;
    }
{
    auto plan_result =
        n00b_macho_rewrite_plan_object_bundle_replace(bin,
                                                      request,
                                                      .allocator = allocator);
    if (n00b_result_is_err(plan_result)) {
        return n00b_result_err(n00b_buffer_t *,
                               n00b_result_get_err(plan_result));
    }

    n00b_macho_rewrite_plan_t *plan = n00b_result_get(plan_result);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    return n00b_macho_rewrite_apply_object_bundle_plan(bin,
                                                       plan,
                                                       .allocator = allocator);
}

// ============================================================================
// WP-006 Phase 1 — loadable LC_SEGMENT_64 insert + __LINKEDIT relocation +
//                  offset patching, with the D-021/D-032 __TEXT-reflow branch.
// ============================================================================
//
// COPY-OUT discipline (same as the metadata path): planning never mutates
// `bin`/stream/parsed arrays; apply allocates a FRESH buffer and reparses the
// output. The new segment goes BEFORE __LINKEDIT in file+VM order (`04:116-122`);
// __LINKEDIT must stay last and the file must end at its end.
//
// Two LC-header-slack branches (D-021), selected by the WP-004 admission's
// `entrypoint_policy_deferred` flag (= `lc_slack_bytes < required_lc_growth`):
//   (a) accept-without-reflow: LC slack >= 72 B; the new LC grows the LC region
//       in place; __LINKEDIT slides by the padded new-segment size.
//   (b) accept-with-reflow: LC slack < 72 B; slide __TEXT sections forward by a
//       page-aligned `text_slide` to open >= 72 B of LC header room, grow __TEXT,
//       and slide __LINKEDIT by (text growth + padded new-segment size).
// All reflow geometry is computed DYNAMICALLY from the parsed layout — the WP-001
// spike's +1/+2/+3-page constants are fixture-specific and are NOT hardcoded.

// New loadable LC_SEGMENT_64 cmdsize (no sections).
#define N00B_MACHO_LOADABLE_CMD_SIZE N00B_MACHO_SEG64_CMD_SIZE

// VM protection bits for the new r-x loadable segment. Source:
// MacOSX.sdk/usr/include/mach/vm_prot.h VM_PROT_READ 0x01, VM_PROT_EXECUTE 0x04.
#define N00B_MACHO_VM_PROT_READ    0x1u
#define N00B_MACHO_VM_PROT_EXECUTE 0x4u

static n00b_macho_rewrite_loadable_plan_t *
new_loadable_plan(n00b_allocator_t *allocator)
{
    return n00b_alloc_with_opts(
        n00b_macho_rewrite_loadable_plan_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
}

static n00b_result_t(n00b_macho_rewrite_loadable_plan_t *)
rejected_loadable_plan(n00b_allocator_t                          *allocator,
                       n00b_macho_rewrite_rejection_reason_t      reason,
                       n00b_macho_rewrite_target_profile_t        profile,
                       n00b_macho_rewrite_admit_loadable_result_t admission,
                       bool                                       have_admission)
{
    n00b_macho_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->outcome          = N00B_MACHO_REWRITE_PLAN_REJECTED;
    plan->rejection_reason = reason;
    plan->target_profile   = profile;
    plan->file_size        = profile.file_size;
    plan->original_segment_count = profile.segment_count;
    plan->new_segment_count      = profile.segment_count;
    if (have_admission) {
        plan->admission = admission;
    }

    return n00b_result_ok(n00b_macho_rewrite_loadable_plan_t *, plan);
}

// Locate the on-disk command file offset of a named LC_SEGMENT_64 (the start of
// the command in the load-command region). Returns false if not found. Pure
// read of the parsed model (`cmd->raw_data` segname + `cmd->file_offset`).
static bool
segment_command_offset(n00b_macho_binary_t *bin,
                       const char          *segname,
                       uint64_t            *out)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_SEGMENT_64 || cmd->raw_data == nullptr
            || cmd->raw_data->byte_len
                   < (int64_t)(N00B_MACHO_SEG64_SEGNAME_OFF + 16u)) {
            continue;
        }

        const char *raw =
            (const char *)cmd->raw_data->data + N00B_MACHO_SEG64_SEGNAME_OFF;
        // segname is a 16-byte field; n00b_string_from_cstr stops at the first
        // NUL, so the field padding does not affect the comparison.
        if (n00b_unicode_str_eq(n00b_string_from_cstr(segname),
                                n00b_string_from_cstr(raw))) {
            *out = cmd->file_offset;
            return true;
        }
    }

    return false;
}

// Read the parsed __TEXT segment facts (file/vm placement + section count).
// Returns false when there is no __TEXT segment.
static bool
text_segment_facts(n00b_macho_binary_t *bin,
                   uint32_t            *seg_index_out,
                   uint64_t            *fileoff_out,
                   uint64_t            *filesize_out,
                   uint64_t            *vmaddr_out,
                   uint64_t            *vmsize_out)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (n00b_unicode_str_eq(n00b_string_from_cstr("__TEXT"),
                                n00b_string_from_cstr(bin->segments[i].name))) {
            *seg_index_out = i;
            *fileoff_out   = bin->segments[i].fileoff;
            *filesize_out  = bin->segments[i].filesize;
            *vmaddr_out    = bin->segments[i].vmaddr;
            *vmsize_out    = bin->segments[i].vmsize;
            return true;
        }
    }

    return false;
}

// Smallest nonzero section file offset across all segments (the __TEXT-reflow
// slide point — bytes from here onward move). Returns false if no section has a
// nonzero file offset (a degenerate object we will not reflow). Pure read.
static bool
first_section_file_offset(n00b_macho_binary_t *bin, uint64_t *out)
{
    uint64_t best  = UINT64_MAX;
    bool     found = false;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        for (uint32_t j = 0; j < bin->segments[i].nsects; j++) {
            uint32_t so = bin->segments[i].sections[j].offset;
            if (so > 0 && (uint64_t)so < best) {
                best  = (uint64_t)so;
                found = true;
            }
        }
    }

    if (!found) {
        return false;
    }

    *out = best;
    return true;
}

// A growable-by-index patch accumulator: a pre-sized patch array plus its live
// count. The array is allocated with capacity >= the maximum possible patch
// count (fixed overhead + one per command), so `push_patch` writes by index
// (mirroring the WP-005 `patches.data[i] = ...; patches.len = ...` pattern; the
// array API has no append macro). `push_patch` returns false on a capacity
// overrun (a guarded impossibility given the sizing).
typedef struct {
    n00b_array_t(n00b_macho_rewrite_patch_t) array;
    uint64_t count;
    uint64_t cap;
} patch_accum_t;

static bool
push_patch(patch_accum_t                  *acc,
           n00b_macho_rewrite_patch_kind_t kind,
           uint64_t                        file_offset,
           uint64_t                        file_end,
           uint64_t                        original_file_offset,
           uint64_t                        original_file_end)
{
    if (acc->count >= acc->cap) {
        return false;
    }

    acc->array.data[acc->count] = (n00b_macho_rewrite_patch_t){
        .kind                 = kind,
        .file_offset          = file_offset,
        .file_end             = file_end,
        .original_file_offset = original_file_offset,
        .original_file_end    = original_file_end,
    };
    acc->count++;
    acc->array.len = acc->count;
    return true;
}

// True when `cmd` is a linkedit_data_command-shaped command (its single
// __LINKEDIT file offset is `dataoff`@8). Drives the offset-patch walk off the
// command's structural shape, NOT a fixed id subset (the codesign-rejection
// hazard, `04:124-136`). LC_CODE_SIGNATURE is also linkedit_data-shaped but is
// recorded under its own patch kind so a stale CS is patched explicitly.
static bool
is_linkedit_data_command(uint32_t cmd)
{
    switch (cmd) {
    case LC_DYLD_CHAINED_FIXUPS:
    case LC_DYLD_EXPORTS_TRIE:
    case LC_FUNCTION_STARTS:
    case LC_DATA_IN_CODE:
    case LC_SEGMENT_SPLIT_INFO:
    case LC_DYLIB_CODE_SIGN_DRS:
    case LC_LINKER_OPTIMIZATION_HINT:
        return true;
    default:
        return false;
    }
}

// Read the u32 *off field at `cmd->raw_data[field]`; true (with `*out` set) iff
// the field is present and nonzero (a present-but-zero offset is not a
// __LINKEDIT reference and must not be patched).
static bool
command_off_field_nonzero(n00b_macho_command_t *cmd,
                          uint64_t              field,
                          uint32_t             *out)
{
    if (cmd->raw_data == nullptr
        || (uint64_t)cmd->raw_data->byte_len < field + 4u) {
        return false;
    }

    uint32_t v = get_le_u32((const uint8_t *)cmd->raw_data->data + field);
    if (v == 0) {
        return false;
    }

    *out = v;
    return true;
}

// THE OFFSET-PATCH WALK (the hazard, `04:124-136`). Walk `bin->commands[]`; for
// EVERY command whose payload references a __LINKEDIT-relative file offset, emit
// one patch (its kind keyed by the command's structural shape). A field present
// but unpatched is the canonical "verifies-but-codesign-rejects" bug, so the
// walk is exhaustive over present commands, never a hardcoded id list. The P1-b
// 1:1 assertion enforces completeness. Returns false on overflow.
static bool
emit_linkedit_offset_patches(n00b_macho_binary_t *bin, patch_accum_t *patches)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        uint64_t              span_end;
        if (!checked_add_u64(cmd->file_offset, (uint64_t)cmd->cmdsize,
                             &span_end)) {
            return false;
        }

        uint32_t scratch;
        switch (cmd->cmd) {
        case LC_SYMTAB:
            // symoff/stroff -> SYMTAB_CMD (only if at least one is a real ref).
            if (command_off_field_nonzero(cmd, N00B_MACHO_SYMTAB_SYMOFF_OFF,
                                          &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_SYMTAB_STROFF_OFF,
                                             &scratch)) {
                if (!push_patch(patches,
                                N00B_MACHO_REWRITE_PATCH_SYMTAB_CMD,
                                cmd->file_offset, span_end,
                                cmd->file_offset, span_end)) {
                    return false;
                }
            }
            break;
        case LC_DYSYMTAB:
            // LC_DYSYMTAB offsets share the SYMTAB_CMD patch kind with LC_SYMTAB
            // (both are symbol-table LC offsets into __LINKEDIT; see the enum
            // comment). The apply walk re-derives the exact fields per command.
            if (command_off_field_nonzero(cmd, N00B_MACHO_DYSYM_TOCOFF_OFF,
                                          &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_DYSYM_MODTABOFF_OFF,
                                             &scratch)
                || command_off_field_nonzero(
                       cmd, N00B_MACHO_DYSYM_EXTREFSYMOFF_OFF, &scratch)
                || command_off_field_nonzero(
                       cmd, N00B_MACHO_DYSYM_INDIRECTSYMOFF_OFF, &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_DYSYM_EXTRELOFF_OFF,
                                             &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_DYSYM_LOCRELOFF_OFF,
                                             &scratch)) {
                if (!push_patch(patches,
                                N00B_MACHO_REWRITE_PATCH_SYMTAB_CMD,
                                cmd->file_offset, span_end,
                                cmd->file_offset, span_end)) {
                    return false;
                }
            }
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            if (command_off_field_nonzero(cmd, N00B_MACHO_DYLD_INFO_REBASE_OFF,
                                          &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_DYLD_INFO_BIND_OFF,
                                             &scratch)
                || command_off_field_nonzero(
                       cmd, N00B_MACHO_DYLD_INFO_WEAK_BIND_OFF, &scratch)
                || command_off_field_nonzero(
                       cmd, N00B_MACHO_DYLD_INFO_LAZY_BIND_OFF, &scratch)
                || command_off_field_nonzero(cmd, N00B_MACHO_DYLD_INFO_EXPORT_OFF,
                                             &scratch)) {
                if (!push_patch(patches,
                                N00B_MACHO_REWRITE_PATCH_DYLD_INFO_CMD,
                                cmd->file_offset, span_end,
                                cmd->file_offset, span_end)) {
                    return false;
                }
            }
            break;
        case LC_CODE_SIGNATURE:
            if (command_off_field_nonzero(cmd, N00B_MACHO_LEDATA_DATAOFF_OFF,
                                          &scratch)) {
                if (!push_patch(patches,
                                N00B_MACHO_REWRITE_PATCH_CODESIG_CMD,
                                cmd->file_offset, span_end,
                                cmd->file_offset, span_end)) {
                    return false;
                }
            }
            break;
        default:
            if (is_linkedit_data_command(cmd->cmd)
                && command_off_field_nonzero(cmd, N00B_MACHO_LEDATA_DATAOFF_OFF,
                                             &scratch)) {
                if (!push_patch(patches,
                                N00B_MACHO_REWRITE_PATCH_LINKEDIT_DATA_CMD,
                                cmd->file_offset, span_end,
                                cmd->file_offset, span_end)) {
                    return false;
                }
            }
            break;
        }
    }

    return true;
}

// Record the entrypoint facts on the plan (disabled by default; FR-13). The
// original `LC_MAIN.entryoff` is taken from the parsed `bin->entrypoint` and
// preserved; the replacement is set by Phase 2's enable path. Mirrors ELF's
// record_loadable_entrypoint_facts.
static void
record_entrypoint_facts(n00b_macho_binary_t                *bin,
                        n00b_macho_rewrite_loadable_plan_t *plan)
{
    plan->original_entryoff       = bin->entrypoint;
    plan->replacement_entryoff    = 0;
    plan->entrypoint_patch_enabled = false;
}

// Computed loadable-insert geometry (file layout, dynamic). All file offsets are
// page-aligned where they matter (the new segment fileoff and __LINKEDIT base).
typedef struct {
    bool     reflow;
    uint64_t text_slide;         // 0 in the non-reflow branch
    uint64_t text_new_filesize;  // grown __TEXT filesize (reflow), else original
    uint64_t text_new_vmsize;    // grown __TEXT vmsize (reflow), else original
    uint64_t new_segment_fileoff;
    uint64_t new_segment_file_end;
    uint64_t padded_segment_size; // page-aligned payload size in file
    uint64_t linkedit_old_offset;
    uint64_t linkedit_new_offset;
    uint64_t linkedit_size;
    uint64_t le_delta;
    uint64_t first_section;       // slide point (reflow only)
    uint64_t output_size;
    // The new segment vaddr is file-offset-mapped: text_vmaddr +
    // new_segment_fileoff. This is REQUIRED for the arm64 LC_MAIN entrypoint
    // redirect (FR-13/FR-14): LC_MAIN.entryoff is a file offset the loader
    // resolves relative to __TEXT.vmaddr (since __TEXT.fileoff == 0), so the
    // trampoline's vaddr must equal text_vmaddr + new_segment_fileoff or the
    // redirected entry maps into a hole. (The admission's gap-based vaddr does
    // not satisfy this; the spike used text_vmaddr + new_seg_fileoff.)
    uint64_t new_segment_vaddr;
    uint64_t new_segment_vaddr_end;
} loadable_geometry_t;

// Compute the loadable-insert file geometry dynamically from the parsed layout.
// Returns N00B_MACHO_REWRITE_OK on success; on a genuine window-overflow it
// returns N00B_MACHO_REWRITE_REJECT_OVERFLOW (caller turns that into
// Ok(rejected, REJECT_OVERFLOW)); on an arithmetic overflow / structural
// surprise it returns N00B_MACHO_REWRITE_ERR_OVERFLOW.
static n00b_err_t
compute_loadable_geometry(n00b_macho_binary_t                 *bin,
                          n00b_macho_rewrite_target_profile_t  profile,
                          uint64_t                             payload_len,
                          uint64_t                             lc_slack,
                          uint64_t                             required_lc_growth,
                          uint64_t                             page,
                          loadable_geometry_t                 *geo)
{
    *geo = (loadable_geometry_t){};

    uint32_t text_idx;
    uint64_t text_fileoff;
    uint64_t text_filesize;
    uint64_t text_vmaddr;
    uint64_t text_vmsize;
    if (!text_segment_facts(bin, &text_idx, &text_fileoff, &text_filesize,
                            &text_vmaddr, &text_vmsize)) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }

    // The page-aligned file size occupied by the new segment payload.
    uint64_t padded_segment_size;
    if (!align_up_u64(payload_len, page, &padded_segment_size)
        || padded_segment_size == 0) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }

    uint64_t le_old = profile.linkedit_offset;
    uint64_t le_size = profile.linkedit_size;

    geo->linkedit_old_offset = le_old;
    geo->linkedit_size       = le_size;
    geo->padded_segment_size = padded_segment_size;

    bool reflow = lc_slack < required_lc_growth;
    geo->reflow = reflow;

    if (!reflow) {
        // (a) accept-without-reflow. The new segment takes the old __LINKEDIT
        // file slot (page-aligned); __LINKEDIT slides up by the padded size.
        geo->text_slide        = 0;
        geo->text_new_filesize = text_filesize;
        geo->text_new_vmsize   = text_vmsize;

        // __LINKEDIT base is page-aligned in a well-formed object; place the new
        // segment there and slide __LINKEDIT after it.
        if (le_old % page != 0) {
            return N00B_MACHO_REWRITE_REJECT_OVERFLOW;
        }
        geo->new_segment_fileoff = le_old;
        if (!checked_add_u64(le_old, padded_segment_size,
                             &geo->new_segment_file_end)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        geo->linkedit_new_offset = geo->new_segment_file_end;
        geo->le_delta            = padded_segment_size;
    }
    else {
        // (b) accept-with-__TEXT-reflow. Slide __TEXT sections forward by a
        // page-aligned `text_slide` large enough to open >= required_lc_growth
        // of LC header room: lc_end + growth <= first_section + text_slide.
        uint64_t first_section;
        if (!first_section_file_offset(bin, &first_section)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        geo->first_section = first_section;

        uint64_t lc_end;
        if (!checked_add_u64((uint64_t)N00B_MACHO_HEADER_64_SIZE,
                             profile.sizeofcmds, &lc_end)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }

        // Minimum slide so the grown LC region fits before the slid sections.
        uint64_t lc_need;
        if (!checked_add_u64(lc_end, required_lc_growth, &lc_need)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        if (lc_need < first_section) {
            // Slack was (just) enough after all; a 0-page slide can't help and
            // means we mis-branched — treat as a window overflow defensively.
            return N00B_MACHO_REWRITE_REJECT_OVERFLOW;
        }
        uint64_t min_slide = lc_need - first_section;
        uint64_t text_slide;
        if (!align_up_u64(min_slide, page, &text_slide) || text_slide == 0) {
            // min_slide could round to 0 only if it was 0; force one page so the
            // LC region genuinely gains room.
            text_slide = page;
        }
        geo->text_slide = text_slide;

        // Grow __TEXT to cover the slid section bytes. __TEXT body originally
        // ends at le_old (the file tail of __TEXT == __LINKEDIT base for these
        // objects); after the slide it ends at le_old + text_slide.
        uint64_t text_new_filesize;
        if (!checked_add_u64(text_filesize, text_slide, &text_new_filesize)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        // vmsize grows by the same slide so the section vmaddrs (unchanged) stay
        // inside the segment.
        uint64_t text_new_vmsize;
        if (!checked_add_u64(text_vmsize, text_slide, &text_new_vmsize)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        geo->text_new_filesize = text_new_filesize;
        geo->text_new_vmsize   = text_new_vmsize;

        // Confirm the slid sections fit the grown __TEXT window (the spike's
        // explicit fit check, generalized): the slid body must end at exactly
        // text_fileoff + text_new_filesize.
        uint64_t slid_body_end;
        if (!checked_add_u64(le_old, text_slide, &slid_body_end)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        uint64_t text_window_end;
        if (!checked_add_u64(text_fileoff, text_new_filesize,
                             &text_window_end)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        if (slid_body_end > text_window_end) {
            return N00B_MACHO_REWRITE_REJECT_OVERFLOW;
        }

        // The new segment goes after the grown __TEXT body, page-aligned.
        uint64_t new_seg_fileoff;
        if (!align_up_u64(text_window_end, page, &new_seg_fileoff)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        geo->new_segment_fileoff = new_seg_fileoff;
        if (!checked_add_u64(new_seg_fileoff, padded_segment_size,
                             &geo->new_segment_file_end)) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }

        // __LINKEDIT base = the new segment file end (page-aligned). le_delta is
        // the total upward shift: text growth + padded new-segment size.
        geo->linkedit_new_offset = geo->new_segment_file_end;
        if (geo->linkedit_new_offset < le_old) {
            return N00B_MACHO_REWRITE_ERR_OVERFLOW;
        }
        geo->le_delta = geo->linkedit_new_offset - le_old;
    }

    // Output size = old __LINKEDIT end + le_delta (the file ends at __LINKEDIT's
    // new end; everything below is preserved/relaid).
    uint64_t le_end;
    if (!checked_add_u64(le_old, le_size, &le_end)) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }
    if (!checked_add_u64(le_end, geo->le_delta, &geo->output_size)) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }

    // The new segment vaddr is file-offset-mapped (text_vmaddr +
    // new_segment_fileoff) so the file-offset LC_MAIN.entryoff redirect resolves
    // to the trampoline's vaddr (FR-13/FR-14). __TEXT.fileoff == 0 in a
    // well-formed object, so file offset N maps to vaddr text_vmaddr + N.
    if (!checked_add_u64(text_vmaddr, geo->new_segment_fileoff,
                         &geo->new_segment_vaddr)
        || !checked_add_u64(text_vmaddr, geo->new_segment_file_end,
                            &geo->new_segment_vaddr_end)) {
        return N00B_MACHO_REWRITE_ERR_OVERFLOW;
    }

    return N00B_MACHO_REWRITE_OK;
}

static n00b_result_t(n00b_macho_rewrite_loadable_plan_t *)
plan_loadable_insert_impl(n00b_macho_binary_t                   *bin,
                          n00b_macho_rewrite_loadable_request_t *request,
                          n00b_allocator_t                      *allocator)
{
    // -- D-031: null/zero/undersized inputs are documented Err returns ------
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_REQUEST);
    }

    if (request->payload == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD);
    }

    if (request->payload->byte_len == 0) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD);
    }

    uint64_t payload_len = (uint64_t)request->payload->byte_len;
    if (request->vmsize < payload_len) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- Target profile (reject non-arm64 / LINKEDIT_NOT_LAST / fat / ...) --
    auto profile_result = n00b_macho_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               n00b_result_get_err(profile_result));
    }

    n00b_macho_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    if (profile.reason != N00B_MACHO_REWRITE_PROFILE_OK) {
        n00b_macho_rewrite_admit_loadable_result_t empty = {};
        return rejected_loadable_plan(allocator,
                                      N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                                      profile,
                                      empty,
                                      false);
    }

    // -- Consult WP-004 loadable admission (never re-derive layout) --------
    n00b_macho_rewrite_admit_loadable_request_t admit_request = {
        .payload_size    = payload_len,
        .initprot        = request->initprot,
        .maxprot         = request->maxprot,
        .file_alignment  = request->file_alignment,
        .vaddr_alignment = request->vaddr_alignment,
        .vmsize          = request->vmsize,
        .policy          = request->policy,
    };

    auto admit_result = n00b_macho_rewrite_admit_loadable_insert(
        bin,
        &admit_request,
        .allocator = allocator);
    if (n00b_result_is_err(admit_result)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_ADMISSION);
    }

    n00b_macho_rewrite_admit_loadable_result_t admission =
        n00b_result_get(admit_result);
    if (admission.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED) {
        return rejected_loadable_plan(allocator,
                                      N00B_MACHO_REWRITE_REJECT_ADMISSION,
                                      profile,
                                      admission,
                                      true);
    }

    // -- Compute the loadable-insert geometry dynamically (D-021 branch on
    //    admission.entrypoint_policy_deferred = slack-exhaustion). -----------
    uint64_t page = (uint64_t)N00B_MACHO_ARM64_PAGE_SIZE;
    uint64_t required_lc_growth = (uint64_t)N00B_MACHO_LOADABLE_CMD_SIZE;
    uint64_t lc_slack = admission.lc_slack_bytes;

    loadable_geometry_t geo;
    n00b_err_t geo_err = compute_loadable_geometry(bin,
                                                   profile,
                                                   payload_len,
                                                   lc_slack,
                                                   required_lc_growth,
                                                   page,
                                                   &geo);
    if (geo_err == N00B_MACHO_REWRITE_REJECT_OVERFLOW) {
        return rejected_loadable_plan(allocator,
                                      N00B_MACHO_REWRITE_REJECT_OVERFLOW,
                                      profile,
                                      admission,
                                      true);
    }
    if (geo_err != N00B_MACHO_REWRITE_OK) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *, geo_err);
    }

    // -- mach_header growth: ncmds+1, sizeofcmds += 72; reject u32 overflow. -
    uint64_t new_sizeofcmds;
    if (!checked_add_u64(profile.sizeofcmds, required_lc_growth,
                         &new_sizeofcmds)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    uint64_t new_command_count;
    if (new_sizeofcmds > UINT32_MAX
        || !checked_add_u64(profile.command_count, 1, &new_command_count)
        || new_command_count > UINT32_MAX) {
        return rejected_loadable_plan(allocator,
                                      N00B_MACHO_REWRITE_REJECT_OVERFLOW,
                                      profile,
                                      admission,
                                      true);
    }

    // -- Locate the on-disk __TEXT and __LINKEDIT command offsets -----------
    uint64_t text_cmd_offset = 0;
    uint64_t le_cmd_offset   = 0;
    if (!segment_command_offset(bin, "__TEXT", &text_cmd_offset)
        || !segment_command_offset(bin, "__LINKEDIT", &le_cmd_offset)) {
        n00b_macho_rewrite_admit_loadable_result_t a = admission;
        return rejected_loadable_plan(allocator,
                                      N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
                                      profile,
                                      a,
                                      true);
    }

    // -- Build the patch array (recorded, NOT written). Pre-size for the worst
    //    case: fixed overhead (8) + one offset patch per present command. ----
    uint64_t patch_cap = (uint64_t)bin->num_commands + 16u;
    patch_accum_t acc = {
        .array = n00b_array_new(n00b_macho_rewrite_patch_t,
                                (int64_t)patch_cap,
                                .allocator = allocator),
        .count = 0,
        .cap   = patch_cap,
    };
    acc.array.len = 0;

    // MACH_HEADER: ncmds (u32@16) + sizeofcmds (u32@20).
    if (!push_patch(&acc,
                    N00B_MACHO_REWRITE_PATCH_MACH_HEADER,
                    (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
                    (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u,
                    (uint64_t)N00B_MACHO_HDR_NCMDS_OFF,
                    (uint64_t)N00B_MACHO_HDR_SIZEOFCMDS_OFF + 4u)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // __TEXT reflow patches (branch b only).
    if (geo.reflow) {
        // TEXT_SECTIONS_RELOCATED: the slid __TEXT section file bytes
        // [first_section, le_old) -> +text_slide.
        uint64_t src_end = geo.linkedit_old_offset;
        uint64_t dst_start;
        uint64_t dst_end;
        if (!checked_add_u64(geo.first_section, geo.text_slide, &dst_start)
            || !checked_add_u64(src_end, geo.text_slide, &dst_end)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
        if (!push_patch(&acc,
                        N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED,
                        dst_start, dst_end,
                        geo.first_section, src_end)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }

        // TEXT_CMD: the __TEXT segment command (filesize/vmsize grow + each
        // section offset bump). Patch spans the full 72-byte command header.
        uint64_t text_cmd_end;
        if (!checked_add_u64(text_cmd_offset,
                             (uint64_t)N00B_MACHO_SEG64_CMD_SIZE, &text_cmd_end)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
        if (!push_patch(&acc,
                        N00B_MACHO_REWRITE_PATCH_TEXT_CMD,
                        text_cmd_offset, text_cmd_end,
                        text_cmd_offset, text_cmd_end)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
    }

    // NEW_SEGMENT_CMD: the appended LC_SEGMENT_64, inserted right after __TEXT's
    // command (so segment order stays monotonic __TEXT < new < __LINKEDIT). The
    // patch records the output insert position (apply shifts trailing LCs).
    uint64_t insert_at;
    if (!segment_command_offset(bin, "__TEXT", &insert_at)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    // The new command goes after __TEXT's own command.
    {
        // Find __TEXT command's cmdsize to compute the insert position.
        uint64_t text_cmdsize = 0;
        for (uint32_t i = 0; i < bin->num_commands; i++) {
            if (bin->commands[i].file_offset == text_cmd_offset) {
                text_cmdsize = (uint64_t)bin->commands[i].cmdsize;
                break;
            }
        }
        if (text_cmdsize == 0
            || !checked_add_u64(text_cmd_offset, text_cmdsize, &insert_at)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
    }
    uint64_t insert_end;
    if (!checked_add_u64(insert_at, (uint64_t)N00B_MACHO_SEG64_CMD_SIZE,
                         &insert_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    if (!push_patch(&acc,
                    N00B_MACHO_REWRITE_PATCH_NEW_SEGMENT_CMD,
                    insert_at, insert_end,
                    insert_at, insert_at)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // LOADABLE_PAYLOAD + LOADABLE_PADDING: the new segment's payload bytes and
    // zeroed page padding in the output.
    uint64_t payload_end;
    if (!checked_add_u64(geo.new_segment_fileoff, payload_len, &payload_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    if (!push_patch(&acc,
                    N00B_MACHO_REWRITE_PATCH_LOADABLE_PAYLOAD,
                    geo.new_segment_fileoff, payload_end,
                    geo.new_segment_fileoff, geo.new_segment_fileoff)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    if (payload_end < geo.new_segment_file_end) {
        if (!push_patch(&acc,
                        N00B_MACHO_REWRITE_PATCH_LOADABLE_PADDING,
                        payload_end, geo.new_segment_file_end,
                        payload_end, payload_end)) {
            return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                                   N00B_MACHO_REWRITE_ERR_OVERFLOW);
        }
    }

    // LINKEDIT_RELOCATED: the moved __LINKEDIT bytes (src -> dst by le_delta).
    uint64_t le_src_end;
    if (!checked_add_u64(geo.linkedit_old_offset, geo.linkedit_size,
                         &le_src_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    uint64_t le_dst_end;
    if (!checked_add_u64(geo.linkedit_new_offset, geo.linkedit_size,
                         &le_dst_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    if (!push_patch(&acc,
                    N00B_MACHO_REWRITE_PATCH_LINKEDIT_RELOCATED,
                    geo.linkedit_new_offset, le_dst_end,
                    geo.linkedit_old_offset, le_src_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // LINKEDIT_CMD: the __LINKEDIT segment command (fileoff@40 + vmaddr@24).
    uint64_t le_cmd_end;
    if (!checked_add_u64(le_cmd_offset, (uint64_t)N00B_MACHO_SEG64_CMD_SIZE,
                         &le_cmd_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    if (!push_patch(&acc,
                    N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD,
                    le_cmd_offset, le_cmd_end,
                    le_cmd_offset, le_cmd_end)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // THE OFFSET-PATCH WALK: every __LINKEDIT-referencing command.
    if (!emit_linkedit_offset_patches(bin, &acc)) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    // -- Assemble the plan -------------------------------------------------
    n00b_macho_rewrite_loadable_plan_t *plan = new_loadable_plan(allocator);
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_loadable_plan_t *,
                               N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }

    plan->outcome          = N00B_MACHO_REWRITE_PLAN_ACCEPTED;
    plan->rejection_reason = N00B_MACHO_REWRITE_REJECT_NONE;
    plan->target_profile   = profile;
    plan->admission        = admission;
    plan->patches          = acc.array;
    plan->source_binary    = bin;
    plan->payload          = request->payload;
    plan->new_segment_file_offset = geo.new_segment_fileoff;
    plan->new_segment_file_end    = geo.new_segment_file_end;
    // File-offset-mapped vaddr (text_vmaddr + new_segment_fileoff), REQUIRED for
    // the LC_MAIN entryoff (a file offset) to resolve to the trampoline — see the
    // geometry note. Supersedes the admission's gap-based vaddr for this engine.
    plan->new_segment_vaddr       = geo.new_segment_vaddr;
    plan->new_segment_vaddr_end   = geo.new_segment_vaddr_end;
    plan->vmsize                  = request->vmsize;
    plan->linkedit_old_offset     = geo.linkedit_old_offset;
    plan->linkedit_new_offset     = geo.linkedit_new_offset;
    plan->linkedit_moved          = geo.le_delta != 0;
    plan->code_signature_present  = profile.code_signature_present;
    plan->file_size               = geo.output_size;
    plan->original_segment_count  = profile.segment_count;
    plan->new_segment_count       = profile.segment_count + 1;
    plan->initprot                = request->initprot;
    plan->maxprot                 = request->maxprot;
    plan->file_alignment          = request->file_alignment;
    plan->vaddr_alignment         = request->vaddr_alignment;
    plan->entrypoint_policy_deferred = admission.entrypoint_policy_deferred;
    plan->text_reflow_active      = geo.reflow;
    plan->text_slide_bytes        = geo.text_slide;
    plan->text_new_filesize       = geo.text_new_filesize;
    plan->text_new_vmsize         = geo.text_new_vmsize;

    record_entrypoint_facts(bin, plan);

    return n00b_result_ok(n00b_macho_rewrite_loadable_plan_t *, plan);
}

n00b_result_t(n00b_macho_rewrite_loadable_plan_t *)
n00b_macho_rewrite_plan_loadable_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_loadable_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null `bin`/`request`/`payload`, a zero
    // `payload->byte_len`, and `vmsize < payload->byte_len` are documented
    // `Err`/reject returns, guarded in `plan_loadable_insert_impl`; `@pre`
    // survives as advisory header Doxygen.
    ensures {
        // entrypoint defaults off; on accept, exactly one new segment.
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && ((result.ok->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
                    || (result.ok->new_segment_count
                            == result.ok->original_segment_count + 1
                        && result.ok->entrypoint_patch_enabled == false)));
    }
{
    return plan_loadable_insert_impl(bin, request, allocator);
}

// ============================================================================
// WP-006 Phase 1 — loadable apply (COPY-OUT: fresh buffer, never mutate bin)
// ============================================================================

// Apply the offset-patch walk to the OUTPUT bytes: re-walk `bin->commands[]`
// (its on-disk offsets are still valid — the new LC has NOT yet been inserted at
// this point) and bump every __LINKEDIT-referencing *off by `le_delta`. Mirrors
// the spike do_surgery Step C exactly, but writes the fresh output buffer.
static void
apply_offset_bump(uint8_t *base, uint64_t cmd_off, uint64_t field,
                  uint64_t le_delta)
{
    uint32_t v = get_le_u32(base + cmd_off + field);
    if (v != 0) {
        set_le_u32(base + cmd_off + field, v + (uint32_t)le_delta);
    }
}

static void
apply_linkedit_offset_walk(n00b_macho_binary_t *bin,
                           uint8_t             *base,
                           uint64_t             le_delta)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        uint64_t              off = cmd->file_offset;

        switch (cmd->cmd) {
        case LC_SYMTAB:
            apply_offset_bump(base, off, N00B_MACHO_SYMTAB_SYMOFF_OFF, le_delta);
            apply_offset_bump(base, off, N00B_MACHO_SYMTAB_STROFF_OFF, le_delta);
            break;
        case LC_DYSYMTAB:
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_TOCOFF_OFF, le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_MODTABOFF_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_EXTREFSYMOFF_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_INDIRECTSYMOFF_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_EXTRELOFF_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYSYM_LOCRELOFF_OFF,
                              le_delta);
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            apply_offset_bump(base, off, N00B_MACHO_DYLD_INFO_REBASE_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYLD_INFO_BIND_OFF, le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYLD_INFO_WEAK_BIND_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYLD_INFO_LAZY_BIND_OFF,
                              le_delta);
            apply_offset_bump(base, off, N00B_MACHO_DYLD_INFO_EXPORT_OFF,
                              le_delta);
            break;
        case LC_CODE_SIGNATURE:
            apply_offset_bump(base, off, N00B_MACHO_LEDATA_DATAOFF_OFF,
                              le_delta);
            break;
        default:
            if (is_linkedit_data_command(cmd->cmd)) {
                apply_offset_bump(base, off, N00B_MACHO_LEDATA_DATAOFF_OFF,
                                  le_delta);
            }
            break;
        }
    }
}

// Find the first patch of `kind` in a loadable plan (mirrors find_patch for the
// metadata plan type). Returns nullptr if absent.
static n00b_macho_rewrite_patch_t *
find_loadable_patch(n00b_macho_rewrite_loadable_plan_t *plan,
                    n00b_macho_rewrite_patch_kind_t     kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static n00b_result_t(n00b_buffer_t *)
apply_loadable_insert_impl(n00b_macho_binary_t                *bin,
                           n00b_macho_rewrite_loadable_plan_t *plan,
                           n00b_allocator_t                   *allocator)
{
    // -- D-031: null/state-malformed inputs are documented Err returns -----
    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    if (plan == nullptr) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    if (plan->source_binary != bin || plan->payload == nullptr
        || plan->patches.data == nullptr || plan->patches.len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    uint64_t input_size = (uint64_t)bin->stream->buf->byte_len;
    uint64_t payload_len = (uint64_t)plan->payload->byte_len;
    uint64_t le_delta;
    if (plan->linkedit_new_offset < plan->linkedit_old_offset) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }
    le_delta = plan->linkedit_new_offset - plan->linkedit_old_offset;

    if (plan->file_size < input_size) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_APPLY);
    }

    // -- COPY-OUT: a fresh, larger buffer. Copy the whole input first; the
    //    relayout below moves regions into their new positions. -------------
    n00b_buffer_t *out = new_zero_buffer(plan->file_size, allocator);
    if (out == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    memcpy((uint8_t *)out->data,
           (const uint8_t *)bin->stream->buf->data,
           (size_t)input_size);

    uint8_t *base = (uint8_t *)out->data;

    uint64_t le_old  = plan->linkedit_old_offset;
    uint64_t le_new  = plan->linkedit_new_offset;
    uint64_t le_size = plan->target_profile.linkedit_size;

    // -- Move __LINKEDIT to its new (highest) offset FIRST (avoid clobber). --
    {
        uint64_t src_end;
        uint64_t dst_end;
        if (!checked_add_u64(le_old, le_size, &src_end)
            || !checked_add_u64(le_new, le_size, &dst_end)
            || src_end > input_size || dst_end > plan->file_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        memmove(base + le_new, base + le_old, (size_t)le_size);
    }

    // -- Reflow: slide __TEXT section bytes by text_slide, then zero vacated
    //    regions between the old layout and the relaid regions. -------------
    if (plan->text_reflow_active) {
        n00b_macho_rewrite_patch_t *tsr =
            find_loadable_patch(plan,
                                N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED);
        if (tsr == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t src_start = tsr->original_file_offset;
        uint64_t src_end   = tsr->original_file_end;
        uint64_t dst_start = tsr->file_offset;
        uint64_t move_len  = src_end - src_start;
        if (src_end > input_size
            || dst_start + move_len > plan->file_size
            || dst_start < src_start) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        memmove(base + dst_start, base + src_start, (size_t)move_len);
        // Zero the slide hole [src_start, dst_start) (tail of __TEXT page 0).
        zero_byte_range(base + src_start, dst_start - src_start);
    }

    // -- Zero the region between the (post-move) relaid __TEXT/new-segment and
    //    the new __LINKEDIT base, then write the new segment payload+padding. -
    {
        n00b_macho_rewrite_patch_t *payload_patch =
            find_loadable_patch(plan,
                                N00B_MACHO_REWRITE_PATCH_LOADABLE_PAYLOAD);
        if (payload_patch == nullptr
            || payload_patch->file_end - payload_patch->file_offset
                   != payload_len
            || payload_patch->file_offset != plan->new_segment_file_offset) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // Zero the whole new-segment file extent first (covers payload slot +
        // padding + any gap left by the move), then drop the payload.
        if (plan->new_segment_file_end > plan->file_size
            || plan->new_segment_file_end > le_new) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        zero_byte_range(base + plan->new_segment_file_offset,
                        plan->new_segment_file_end
                            - plan->new_segment_file_offset);
        if (!write_output_bytes(out,
                                plan->new_segment_file_offset,
                                plan->payload->data,
                                payload_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Reflow: grow __TEXT (filesize/vmsize) + bump each section offset. ---
    if (plan->text_reflow_active) {
        n00b_macho_rewrite_patch_t *text_cmd_patch =
            find_loadable_patch(plan, N00B_MACHO_REWRITE_PATCH_TEXT_CMD);
        if (text_cmd_patch == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t tc = text_cmd_patch->file_offset;
        if (tc + N00B_MACHO_SEG64_CMD_SIZE > input_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint8_t fs[8];
        uint8_t vs[8];
        set_le_u64(fs, plan->text_new_filesize);
        set_le_u64(vs, plan->text_new_vmsize);
        if (!write_output_bytes(out, tc + N00B_MACHO_SEG64_FILESIZE_OFF, fs, 8)
            || !write_output_bytes(out, tc + N00B_MACHO_SEG64_VMSIZE_OFF, vs,
                                   8)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // Bump each __TEXT section's file `offset` by text_slide (NOT addr).
        uint32_t text_idx;
        uint64_t tf, tfs, tva, tvs;
        if (!text_segment_facts(bin, &text_idx, &tf, &tfs, &tva, &tvs)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        for (uint32_t j = 0; j < bin->segments[text_idx].nsects; j++) {
            uint64_t sec_off = tc + N00B_MACHO_SEG64_CMD_SIZE
                             + (uint64_t)j * N00B_MACHO_SECT64_SIZE;
            if (sec_off + N00B_MACHO_SECT64_OFFSET_OFF + 4u > input_size) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_REWRITE_ERR_APPLY);
            }
            uint32_t so = get_le_u32(base + sec_off
                                     + N00B_MACHO_SECT64_OFFSET_OFF);
            if (so != 0) {
                uint8_t nb[4];
                set_le_u32(nb, so + (uint32_t)plan->text_slide_bytes);
                if (!write_output_bytes(out,
                                        sec_off + N00B_MACHO_SECT64_OFFSET_OFF,
                                        nb, 4)) {
                    return n00b_result_err(n00b_buffer_t *,
                                           N00B_MACHO_REWRITE_ERR_APPLY);
                }
            }
        }
    }

    // -- Patch the __LINKEDIT segment command (fileoff@40 + vmaddr@24). ------
    {
        n00b_macho_rewrite_patch_t *le_cmd_patch =
            find_loadable_patch(plan, N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD);
        if (le_cmd_patch == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t lc = le_cmd_patch->file_offset;
        if (lc + N00B_MACHO_SEG64_CMD_SIZE > input_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t old_vmaddr = get_le_u64(base + lc + N00B_MACHO_SEG64_VMADDR_OFF);
        uint8_t  fo[8];
        uint8_t  va[8];
        set_le_u64(fo, le_new);
        set_le_u64(va, old_vmaddr + le_delta);
        if (!write_output_bytes(out, lc + N00B_MACHO_SEG64_FILEOFF_OFF, fo, 8)
            || !write_output_bytes(out, lc + N00B_MACHO_SEG64_VMADDR_OFF, va,
                                   8)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- THE OFFSET-PATCH WALK on the output: bump every __LINKEDIT-referencing
    //    *off by le_delta (before inserting the new LC, while offsets valid). -
    apply_linkedit_offset_walk(bin, base, le_delta);

    // -- Phase 2 (FR-13): when the entrypoint patch is enabled, redirect
    //    LC_MAIN.entryoff to the replacement (a RAW FILE OFFSET, OQ-3). The
    //    write goes at the LC_MAIN command's input file_offset (D-019 per-command
    //    offset) + entryoff field@8; because LC_MAIN sits after __TEXT's command
    //    (the insertion point below), the new-LC insert memmove carries this
    //    write to LC_MAIN's post-insert position, exactly as the WP-001 spike's
    //    Step F redirect. With the patch disabled, LC_MAIN.entryoff is preserved
    //    (this block is skipped). The reparse below re-verifies the value. ------
    if (plan->entrypoint_patch_enabled) {
        n00b_macho_rewrite_patch_t *em_patch =
            find_loadable_patch(plan, N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF);
        if (em_patch == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        // Locate the LC_MAIN command in bin->commands[] (input coords). The
        // has_lc_main fact is determined by scanning commands[] for LC_MAIN, not
        // by inferring from bin->entrypoint (LC_UNIXTHREAD also sets it; D-019).
        uint64_t lc_main_off = 0;
        bool     have_lc_main = false;
        for (uint32_t i = 0; i < bin->num_commands; i++) {
            if (bin->commands[i].cmd == LC_MAIN) {
                lc_main_off  = bin->commands[i].file_offset;
                have_lc_main = true;
                break;
            }
        }
        if (!have_lc_main) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint64_t entryoff_at;
        if (!checked_add_u64(lc_main_off,
                             (uint64_t)N00B_MACHO_LCMAIN_ENTRYOFF_OFF,
                             &entryoff_at)
            || entryoff_at + 8u > input_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        uint8_t eb[8];
        set_le_u64(eb, plan->replacement_entryoff);
        if (!write_output_bytes(out, entryoff_at, eb, 8)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- Insert the new LC_SEGMENT_64 after __TEXT's command (shift trailing
    //    LCs down by 72 within the now-roomy LC region). ---------------------
    {
        n00b_macho_rewrite_patch_t *new_cmd_patch =
            find_loadable_patch(plan, N00B_MACHO_REWRITE_PATCH_NEW_SEGMENT_CMD);
        if (new_cmd_patch == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t insert_at = new_cmd_patch->file_offset;
        uint64_t old_lc_end;
        if (!checked_add_u64((uint64_t)N00B_MACHO_HEADER_64_SIZE,
                             plan->target_profile.sizeofcmds, &old_lc_end)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        if (insert_at > old_lc_end || old_lc_end > input_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t tail_len = old_lc_end - insert_at;
        uint64_t new_lc_end;
        if (!checked_add_u64(old_lc_end, (uint64_t)N00B_MACHO_SEG64_CMD_SIZE,
                             &new_lc_end)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        // The grown LC region must not overrun the first content that follows
        // it in the output: the (possibly slid) first __TEXT section. In the
        // reflow branch that section moved up by text_slide; in the non-reflow
        // branch it is unchanged. Recomputed from the parsed model (pure read).
        uint64_t first_section = 0;
        if (first_section_file_offset(bin, &first_section)) {
            uint64_t bound;
            if (!checked_add_u64(first_section, plan->text_slide_bytes,
                                 &bound)) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_REWRITE_ERR_APPLY);
            }
            if (new_lc_end > bound) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_REWRITE_ERR_APPLY);
            }
        }
        if (new_lc_end > plan->file_size) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }

        memmove(base + insert_at + N00B_MACHO_SEG64_CMD_SIZE,
                base + insert_at,
                (size_t)tail_len);

        // Build the new LC_SEGMENT_64 ("__N00B", r-x) in place.
        uint8_t *nc = base + insert_at;
        zero_byte_range(nc, (uint64_t)N00B_MACHO_SEG64_CMD_SIZE);
        set_le_u32(nc + 0, (uint32_t)LC_SEGMENT_64);
        set_le_u32(nc + 4, (uint32_t)N00B_MACHO_SEG64_CMD_SIZE);
        const char *segname = "__N00B";
        for (uint64_t i = 0; segname[i] != '\0' && i < 16; i++) {
            nc[N00B_MACHO_SEG64_SEGNAME_OFF + i] = (uint8_t)segname[i];
        }
        set_le_u64(nc + N00B_MACHO_SEG64_VMADDR_OFF, plan->new_segment_vaddr);
        set_le_u64(nc + N00B_MACHO_SEG64_VMSIZE_OFF, plan->vmsize);
        set_le_u64(nc + N00B_MACHO_SEG64_FILEOFF_OFF,
                   plan->new_segment_file_offset);
        set_le_u64(nc + N00B_MACHO_SEG64_FILESIZE_OFF,
                   plan->new_segment_file_end - plan->new_segment_file_offset);
        uint32_t prot = plan->initprot != 0
                            ? plan->initprot
                            : (N00B_MACHO_VM_PROT_READ | N00B_MACHO_VM_PROT_EXECUTE);
        uint32_t mprot = plan->maxprot != 0
                             ? plan->maxprot
                             : (N00B_MACHO_VM_PROT_READ | N00B_MACHO_VM_PROT_EXECUTE);
        set_le_u32(nc + N00B_MACHO_SEG64_MAXPROT_OFF, mprot);
        set_le_u32(nc + N00B_MACHO_SEG64_INITPROT_OFF, prot);
        set_le_u32(nc + N00B_MACHO_SEG64_NSECTS_OFF, 0);
        set_le_u32(nc + N00B_MACHO_SEG64_FLAGS_OFF, 0);
    }

    // -- Patch the mach_header: ncmds+1, sizeofcmds += 72. ------------------
    {
        uint64_t new_sizeofcmds;
        if (!checked_add_u64(plan->target_profile.sizeofcmds,
                             (uint64_t)N00B_MACHO_SEG64_CMD_SIZE,
                             &new_sizeofcmds)
            || new_sizeofcmds > UINT32_MAX
            || plan->new_segment_count == 0) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint64_t new_ncmds;
        if (!checked_add_u64(plan->target_profile.command_count, 1, &new_ncmds)
            || new_ncmds > UINT32_MAX) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
        uint8_t hdr[8];
        set_le_u32(hdr, (uint32_t)new_ncmds);
        set_le_u32(hdr + 4, (uint32_t)new_sizeofcmds);
        if (!write_output_bytes(out, (uint64_t)N00B_MACHO_HDR_NCMDS_OFF, hdr,
                                8)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_APPLY);
        }
    }

    // -- The LC_MAIN.entryoff redirect (when enabled) was written above, before
    //    the new-LC insert memmove carried it to its post-insert position.
    //    Without an enabled entrypoint patch, LC_MAIN.entryoff is preserved.

    // -- Reparse the output; on failure return PARSE_AFTER_APPLY. -----------
    n00b_bstream_t *stream = n00b_bstream_new(out, .allocator = allocator);
    auto            parsed = n00b_macho_parse_single(stream);
    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
    }

    // -- With the entrypoint patch enabled, verify the reparsed LC_MAIN carries
    //    the replacement entryoff (the spike Step-F invariant, in the engine). --
    if (plan->entrypoint_patch_enabled) {
        n00b_macho_binary_t *re = n00b_result_get(parsed);
        if (re == nullptr) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
        }
        bool verified = false;
        for (uint32_t i = 0; i < re->num_commands; i++) {
            if (re->commands[i].cmd != LC_MAIN
                || re->commands[i].raw_data == nullptr
                || re->commands[i].raw_data->byte_len
                       < (int64_t)(N00B_MACHO_LCMAIN_ENTRYOFF_OFF + 8u)) {
                continue;
            }
            uint64_t got = get_le_u64(
                (const uint8_t *)re->commands[i].raw_data->data
                + N00B_MACHO_LCMAIN_ENTRYOFF_OFF);
            verified = (got == plan->replacement_entryoff);
            break;
        }
        if (!verified) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY);
        }
    }

    return n00b_result_ok(n00b_buffer_t *, out);
}

n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_loadable_insert_plan(
    n00b_macho_binary_t                *bin,
    n00b_macho_rewrite_loadable_plan_t *plan) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): a null `bin`/`plan`, a non-ACCEPTED plan, a
    // `source_binary != bin`, and a malformed plan are documented `Err` returns,
    // guarded in `apply_loadable_insert_impl`; `@pre` survives as advisory
    // header Doxygen. NFR-01 byte-preservation + reparse are test-verified, not
    // `ensures` (no `old()`, no calls in contracts).
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->byte_len
                       >= bin->stream->buf->byte_len + plan->payload->byte_len);
    }
{
    return apply_loadable_insert_impl(bin, plan, allocator);
}

// ============================================================================
// WP-006 Phase 2 — arm64 LC_MAIN host-entrypoint redirect (plan + enable)
// ============================================================================

// True iff the parsed binary carries an LC_MAIN command. Determined by scanning
// `bin->commands[]` (D-019): a parsed LC_UNIXTHREAD also writes `bin->entrypoint`,
// so a nonzero `entrypoint` alone does NOT prove LC_MAIN. Pure read.
static bool
binary_has_lc_main(n00b_macho_binary_t *bin, uint64_t *original_entryoff_out)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd != LC_MAIN) {
            continue;
        }
        if (bin->commands[i].raw_data != nullptr
            && bin->commands[i].raw_data->byte_len
                   >= (int64_t)(N00B_MACHO_LCMAIN_ENTRYOFF_OFF + 8u)) {
            *original_entryoff_out = get_le_u64(
                (const uint8_t *)bin->commands[i].raw_data->data
                + N00B_MACHO_LCMAIN_ENTRYOFF_OFF);
        }
        else {
            *original_entryoff_out = bin->entrypoint;
        }
        return true;
    }

    return false;
}

// Build a rejected host-entrypoint target with a stable reason (Ok(rejected)).
static n00b_macho_rewrite_host_entrypoint_target_t
rejected_entrypoint_target(
    n00b_macho_rewrite_host_entrypoint_rejection_reason_t reason)
{
    return (n00b_macho_rewrite_host_entrypoint_target_t){
        .outcome          = N00B_MACHO_REWRITE_PLAN_REJECTED,
        .rejection_reason = reason,
    };
}

static n00b_result_t(n00b_macho_rewrite_host_entrypoint_target_t)
plan_host_entrypoint_target_impl(n00b_macho_binary_t                *bin,
                                 n00b_macho_rewrite_loadable_plan_t *plan,
                                 uint64_t target_payload_offset,
                                 uint64_t target_size)
{
    // -- D-031: null/zero inputs are documented Err/reject returns, guarded
    //    here, not trapping `requires`. -----------------------------------
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_host_entrypoint_target_t,
                               N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }
    if (plan == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_host_entrypoint_target_t,
                               N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    // -- Gate order (per 03 §3.3): cputype -> filetype -> LC_MAIN -> plan
    //    state -> target range -> overflow. Each documented gate is an
    //    Ok(rejected, <reason>), not an Err. ---------------------------------

    // (1) arm64 only. Reject UNSUPPORTED_CPUTYPE.
    if (bin->header.cputype != (uint32_t)CPU_TYPE_ARM64) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CPUTYPE));
    }

    // (2) MH_EXECUTE only. Reject UNSUPPORTED_FILETYPE.
    if (bin->header.filetype != (uint32_t)MH_EXECUTE) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_FILETYPE));
    }

    // (3) An LC_MAIN must be present (scan commands[], NOT bin->entrypoint, per
    //     D-019). Reject NO_LC_MAIN.
    uint64_t original_entryoff = 0;
    if (!binary_has_lc_main(bin, &original_entryoff)) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN));
    }

    // (4) The plan must be an accepted loadable-insert plan tied to this binary.
    //     A non-accepted plan -> REJECT_PLAN; a plan from a different binary ->
    //     REJECT_UNSUPPORTED_PLAN.
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN));
    }
    if (plan->source_binary != bin
        || plan->new_segment_file_end <= plan->new_segment_file_offset) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN));
    }

    // (5) A zero-size target is out of range; the [offset, offset+size) range
    //     must lie within the planned new-segment payload extent
    //     [0, segment_file_end - segment_file_offset). Reject TARGET_OUT_OF_RANGE.
    if (target_size == 0) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE));
    }
    uint64_t segment_payload_size =
        plan->new_segment_file_end - plan->new_segment_file_offset;
    uint64_t target_payload_end;
    if (!checked_add_u64(target_payload_offset, target_size,
                         &target_payload_end)) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW));
    }
    if (target_payload_end > segment_payload_size) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE));
    }

    // (6) Derive the placement facts. The replacement entryoff is a RAW FILE
    //     OFFSET (OQ-3, spike Step F): new-segment fileoff + target_payload_offset
    //     == target_file_offset. The target vaddr derives from the new segment's
    //     vaddr likewise.
    uint64_t target_file_offset;
    uint64_t target_file_end;
    if (!checked_add_u64(plan->new_segment_file_offset, target_payload_offset,
                         &target_file_offset)
        || !checked_add_u64(target_file_offset, target_size,
                            &target_file_end)) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW));
    }
    uint64_t target_vaddr;
    uint64_t target_vaddr_end;
    if (!checked_add_u64(plan->new_segment_vaddr, target_payload_offset,
                         &target_vaddr)
        || !checked_add_u64(target_vaddr, target_size, &target_vaddr_end)) {
        return n00b_result_ok(
            n00b_macho_rewrite_host_entrypoint_target_t,
            rejected_entrypoint_target(
                N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW));
    }

    n00b_macho_rewrite_host_entrypoint_target_t target = {
        .outcome               = N00B_MACHO_REWRITE_PLAN_ACCEPTED,
        .rejection_reason      = N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE,
        .original_entryoff     = original_entryoff,
        .replacement_entryoff  = target_file_offset,
        .target_payload_offset = target_payload_offset,
        .target_size           = target_size,
        .target_file_offset    = target_file_offset,
        .target_file_end       = target_file_end,
        .target_vaddr          = target_vaddr,
        .target_vaddr_end      = target_vaddr_end,
        .segment_file_offset   = plan->new_segment_file_offset,
        .segment_file_end      = plan->new_segment_file_end,
        .segment_vaddr         = plan->new_segment_vaddr,
        .segment_vaddr_end     = plan->new_segment_vaddr_end,
        .cputype               = (uint32_t)CPU_TYPE_ARM64,
        .trampoline_emitted    = false,
        .trampoline_size       = 0,
    };

    return n00b_result_ok(n00b_macho_rewrite_host_entrypoint_target_t, target);
}

n00b_result_t(n00b_macho_rewrite_host_entrypoint_target_t)
n00b_macho_rewrite_plan_host_entrypoint_target(
    n00b_macho_binary_t                *bin,
    n00b_macho_rewrite_loadable_plan_t *plan,
    uint64_t                            target_payload_offset,
    uint64_t                            target_size)
    // No live `requires` (D-031): null bin/plan, a non-accepted/mismatched plan,
    // a missing LC_MAIN, a non-arm64/non-MH_EXECUTE target, a zero/out-of-range
    // target, and overflow are documented `Err`/`Ok(rejected)` returns, guarded
    // in `plan_host_entrypoint_target_impl`; `@pre` survives as advisory Doxygen.
    ensures {
        // accept => arm64 and replacement_entryoff == target_file_offset.
        // Guarded by success (D-028).
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED)
            || (result.ok.cputype == (uint32_t)CPU_TYPE_ARM64
                && result.ok.replacement_entryoff
                       == result.ok.target_file_offset);
    }
{
    return plan_host_entrypoint_target_impl(bin,
                                            plan,
                                            target_payload_offset,
                                            target_size);
}

static n00b_result_t(bool)
enable_entrypoint_impl(n00b_macho_rewrite_loadable_plan_t *plan,
                       uint64_t                            replacement_entryoff)
{
    // -- D-031: null/non-accepted plan are documented Err returns, guarded here.
    if (plan == nullptr) {
        return n00b_result_err(bool, N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return n00b_result_err(bool, N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }
    if (plan->patches.data == nullptr) {
        return n00b_result_err(bool, N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN);
    }

    // -- Record the replacement (original_entryoff untouched), append the
    //    LC_MAIN_ENTRYOFF patch, and flip the opt-in flag (CR-11). Push by index,
    //    mirroring push_patch.
    //    NOTE (see the patch-kind enum doc): this patch's file_offset is the
    //    LC_MAIN-command-RELATIVE entryoff offset (8), NOT an absolute offset like
    //    every other patch kind. The absolute write location is apply-resolved
    //    (apply scans the OUTPUT for LC_MAIN, whose position shifts under the
    //    inserted LC_SEGMENT_64 + any __TEXT reflow) — enable cannot know it here
    //    (the output layout isn't built yet, and this fn only has `plan`). ----
    if ((uint64_t)plan->patches.len >= (uint64_t)plan->patches.cap) {
        return n00b_result_err(bool, N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    plan->patches.data[plan->patches.len] = (n00b_macho_rewrite_patch_t){
        .kind                 = N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF,
        .file_offset          = (uint64_t)N00B_MACHO_LCMAIN_ENTRYOFF_OFF,
        .file_end             = (uint64_t)N00B_MACHO_LCMAIN_ENTRYOFF_OFF + 8u,
        .original_file_offset = (uint64_t)N00B_MACHO_LCMAIN_ENTRYOFF_OFF,
        .original_file_end    = (uint64_t)N00B_MACHO_LCMAIN_ENTRYOFF_OFF + 8u,
    };
    plan->patches.len++;

    plan->replacement_entryoff     = replacement_entryoff;
    plan->entrypoint_patch_enabled = true;

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_macho_rewrite_loadable_plan_enable_entrypoint(
    n00b_macho_rewrite_loadable_plan_t *plan,
    uint64_t                            replacement_entryoff)
    // No live `requires` (D-031): null plan / non-accepted plan are documented
    // `Err` returns, guarded in `enable_entrypoint_impl`; `@pre` survives as
    // advisory header Doxygen.
    ensures {
        // On Ok(true) the patch is recorded; original entryoff preserved.
        // Guarded by success (D-028).
        (!result.is_ok) || (!result.ok)
            || (plan->entrypoint_patch_enabled
                && plan->replacement_entryoff == replacement_entryoff);
    }
{
    return enable_entrypoint_impl(plan, replacement_entryoff);
}

// ============================================================================
// Phase 2 — `*_str` mappers (D-029: pointer return, NO `ensures` block)
// ============================================================================
//
// One stable `r"..."` rstr literal per enum value + a stable fallback. These
// live in the `.c`, so rstr literals are correct here (the static-object
// transform fires per-TU). Mirror the ELF mapper pattern
// (`elf_rewrite.c` `n00b_elf_rewrite_*_str`).

n00b_string_t *
n00b_macho_rewrite_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_MACHO_REWRITE_OK:                       return r"ok";
    case N00B_MACHO_REWRITE_ERR_NULL_BINARY:          return r"null-binary";
    case N00B_MACHO_REWRITE_ERR_NULL_REQUEST:         return r"null-request";
    case N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER:      return r"null-note-owner";
    case N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD:         return r"null-payload";
    case N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD:         return r"zero-payload";
    case N00B_MACHO_REWRITE_ERR_TARGET_PROFILE:       return r"target-profile";
    case N00B_MACHO_REWRITE_ERR_ADMISSION:            return r"admission";
    case N00B_MACHO_REWRITE_ERR_OVERFLOW:             return r"overflow";
    case N00B_MACHO_REWRITE_ERR_NULL_PLAN:            return r"null-plan";
    case N00B_MACHO_REWRITE_ERR_PLAN_REJECTED:        return r"plan-rejected";
    case N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN:     return r"unsupported-plan";
    case N00B_MACHO_REWRITE_ERR_APPLY:                return r"apply";
    case N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY:    return r"parse-after-apply";
    case N00B_MACHO_REWRITE_ERR_NOTE_NOT_FOUND:       return r"note-not-found";
    case N00B_MACHO_REWRITE_ERR_TRUSTED_NAME:         return r"trusted-name";
    }

    return r"unknown-macho-rewrite-err";
}

n00b_string_t *
n00b_macho_rewrite_plan_outcome_str(
    n00b_macho_rewrite_plan_outcome_t outcome)
{
    switch (outcome) {
    case N00B_MACHO_REWRITE_PLAN_ACCEPTED: return r"accepted";
    case N00B_MACHO_REWRITE_PLAN_REJECTED: return r"rejected";
    }

    return r"unknown-macho-rewrite-plan-outcome";
}

n00b_string_t *
n00b_macho_rewrite_rejection_reason_str(
    n00b_macho_rewrite_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_MACHO_REWRITE_REJECT_NONE:           return r"none";
    case N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE: return r"target-profile";
    case N00B_MACHO_REWRITE_REJECT_ADMISSION:      return r"admission";
    case N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT:   return r"lc-placement";
    case N00B_MACHO_REWRITE_REJECT_NCMDS_PROMOTION:
        return r"ncmds-promotion";
    case N00B_MACHO_REWRITE_REJECT_OVERFLOW:       return r"overflow";
    case N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND:
        return r"chalk-mark-not-found";
    case N00B_MACHO_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED:
        return r"chalk-mark-unsupported";
    case N00B_MACHO_REWRITE_REJECT_TRUSTED_NAME:   return r"trusted-name";
    case N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND:
        return r"object-bundle-not-found";
    case N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE:
        return r"object-bundle-duplicate";
    case N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED:
        return r"object-bundle-unsupported";
    case N00B_MACHO_REWRITE_REJECT_LOADABLE_PLACEMENT:
        return r"loadable-placement";
    case N00B_MACHO_REWRITE_REJECT_LOADABLE_ADDRESS:
        return r"loadable-address";
    case N00B_MACHO_REWRITE_REJECT_LINKEDIT_RELOCATION:
        return r"linkedit-relocation";
    case N00B_MACHO_REWRITE_REJECT_CODESIG_INTERACTION:
        return r"codesig-interaction";
    }

    return r"unknown-macho-rewrite-rejection-reason";
}

n00b_string_t *
n00b_macho_rewrite_target_profile_reason_str(
    n00b_macho_rewrite_target_profile_reason_t reason)
{
    switch (reason) {
    case N00B_MACHO_REWRITE_PROFILE_OK:            return r"ok";
    case N00B_MACHO_REWRITE_PROFILE_BAD_MAGIC:     return r"bad-magic";
    case N00B_MACHO_REWRITE_PROFILE_BAD_CPUTYPE:   return r"bad-cputype";
    case N00B_MACHO_REWRITE_PROFILE_BAD_FILETYPE:  return r"bad-filetype";
    case N00B_MACHO_REWRITE_PROFILE_LC_REGION_BOUNDS:
        return r"lc-region-bounds";
    case N00B_MACHO_REWRITE_PROFILE_NO_LINKEDIT:   return r"no-linkedit";
    case N00B_MACHO_REWRITE_PROFILE_LINKEDIT_NOT_LAST:
        return r"linkedit-not-last";
    case N00B_MACHO_REWRITE_PROFILE_CODESIG_NOT_LAST:
        return r"codesig-not-last";
    case N00B_MACHO_REWRITE_PROFILE_FAT_UNSUPPORTED:
        return r"fat-unsupported";
    case N00B_MACHO_REWRITE_PROFILE_OVERLAP:       return r"overlap";
    }

    return r"unknown-macho-rewrite-target-profile-reason";
}

n00b_string_t *
n00b_macho_rewrite_patch_kind_str(
    n00b_macho_rewrite_patch_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_REWRITE_PATCH_MACH_HEADER:   return r"mach-header";
    case N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS: return r"load-commands";
    case N00B_MACHO_REWRITE_PATCH_PAYLOAD:       return r"payload";
    case N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD: return r"stale-payload";
    case N00B_MACHO_REWRITE_PATCH_LINKEDIT_RELOCATED:
        return r"linkedit-relocated";
    case N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD:  return r"linkedit-cmd";
    case N00B_MACHO_REWRITE_PATCH_SYMTAB_CMD:    return r"symtab-cmd";
    case N00B_MACHO_REWRITE_PATCH_DYLD_INFO_CMD: return r"dyld-info-cmd";
    case N00B_MACHO_REWRITE_PATCH_LINKEDIT_DATA_CMD:
        return r"linkedit-data-cmd";
    case N00B_MACHO_REWRITE_PATCH_CODESIG_CMD:   return r"codesig-cmd";
    case N00B_MACHO_REWRITE_PATCH_NEW_SEGMENT_CMD:
        return r"new-segment-cmd";
    case N00B_MACHO_REWRITE_PATCH_LOADABLE_PAYLOAD:
        return r"loadable-payload";
    case N00B_MACHO_REWRITE_PATCH_LOADABLE_PADDING:
        return r"loadable-padding";
    case N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED:
        return r"text-sections-relocated";
    case N00B_MACHO_REWRITE_PATCH_TEXT_CMD:
        return r"text-cmd";
    case N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF:
        return r"lc-main-entryoff";
    }

    return r"unknown-macho-rewrite-patch-kind";
}

n00b_string_t *
n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
    n00b_macho_rewrite_host_entrypoint_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE:
        return r"none";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN:
        return r"plan";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN:
        return r"unsupported-plan";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CPUTYPE:
        return r"unsupported-cputype";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_FILETYPE:
        return r"unsupported-filetype";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN:
        return r"no-lc-main";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE:
        return r"target-out-of-range";
    case N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW:
        return r"overflow";
    }

    return r"unknown-macho-rewrite-host-entrypoint-rejection-reason";
}
