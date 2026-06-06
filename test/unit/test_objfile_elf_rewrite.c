#include <string.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_rewrite.h"
#include "compiler/objfile/elf_types.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include "objfile_elf_casegen.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)
#define E_TYPE      16
#define E_MACHINE   18
#define E_VERSION   20
#define E_ENTRY     24
#define E_PHOFF     32
#define E_SHOFF     40
#define E_EHSIZE    52
#define E_PHENTSIZE 54
#define E_PHNUM     56
#define E_SHENTSIZE 58
#define E_SHNUM     60
#define E_SHSTRNDX  62
#define SH_NAME     0
#define SH_TYPE     4
#define SH_OFFSET   24
#define SH_SIZE     32
#define SHSTRTAB_SH 320
#define N00B_TEST_ELF64_EHDR_SIZE 64u
#define N00B_TEST_ELF64_PHDR_SIZE 56u
#define N00B_TEST_ELF64_SHDR_SIZE 64u
#define N00B_TEST_SHN_LORESERVE 0xff00u

typedef void (*mutator_fn)(n00b_buffer_t *);

typedef struct profile_case {
    const char                                    *name;
    mutator_fn                                    mutate;
    n00b_elf_rewrite_target_profile_reason_t      reason;
    int                                           packager_errcode;
} profile_case_t;

static n00b_buffer_t *
payload_new(uint8_t fill, size_t len)
{
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);

    memset(payload->data, fill, len);
    payload->byte_len = len;
    return payload;
}

static n00b_buffer_t *
valid_target_buffer(void)
{
    n00b_buffer_t *buf = n00b_test_elf_minimal_exec(0x400080,
                                                    0,
                                                    0x400000,
                                                    256,
                                                    512,
                                                    true,
                                                    false,
                                                    true,
                                                    false);
    buf->byte_len = 395;
    return buf;
}

static n00b_buffer_t *
valid_dyn_target_buffer(void)
{
    n00b_buffer_t *buf = valid_target_buffer();

    n00b_test_elf_put16((uint8_t *)buf->data + E_TYPE, ET_DYN);
    return buf;
}

static n00b_buffer_t *
shstrtab_then_shtab_buffer(void)
{
    const size_t phoff        = 64;
    const size_t shstrtab_off = 256;
    const size_t shoff        = 320;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(448);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, 0x400080, phoff, 2, shoff, 2, 1);
    n00b_test_elf_write_phdr(p + phoff,
                             PT_LOAD,
                             PF_R | PF_X,
                             0,
                             0x400000,
                             256,
                             512,
                             0x1000);
    n00b_test_elf_write_phdr(p + phoff + 56,
                             PT_PHDR,
                             PF_R,
                             phoff,
                             0x400000 + phoff,
                             112,
                             112,
                             8);
    n00b_test_elf_write_shstrtab(p, shstrtab_off, true);
    n00b_test_elf_write_shdr(p + shoff + 64,
                             1,
                             SHT_STRTAB,
                             0,
                             0,
                             shstrtab_off,
                             11,
                             0,
                             0,
                             1,
                             0);
    return buf;
}

static void
put16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void
put32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void
put64_be(uint8_t *p, uint64_t v)
{
    put32_be(p, (uint32_t)(v >> 32));
    put32_be(p + 4, (uint32_t)v);
}

static uint16_t
get16_be(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t
get32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

static uint32_t
get32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t
get64_be(const uint8_t *p)
{
    return ((uint64_t)get32_be(p) << 32) | get32_be(p + 4);
}

static void
write_header_be(uint8_t *p,
                uint16_t type,
                uint64_t entry,
                uint64_t phoff,
                uint16_t phnum,
                uint64_t shoff,
                uint16_t shnum,
                uint16_t shstrndx)
{
    p[0] = 0x7f;
    p[1] = 'E';
    p[2] = 'L';
    p[3] = 'F';
    p[EI_CLASS]   = ELFCLASS64;
    p[EI_DATA]    = ELFDATA2MSB;
    p[EI_VERSION] = EV_CURRENT;

    put16_be(p + E_TYPE, type);
    put16_be(p + E_MACHINE, EM_X86_64);
    put32_be(p + E_VERSION, EV_CURRENT);
    put64_be(p + E_ENTRY, entry);
    put64_be(p + E_PHOFF, phoff);
    put64_be(p + E_SHOFF, shoff);
    put16_be(p + E_EHSIZE, 64);
    put16_be(p + E_PHENTSIZE, 56);
    put16_be(p + E_PHNUM, phnum);
    put16_be(p + E_SHENTSIZE, 64);
    put16_be(p + E_SHNUM, shnum);
    put16_be(p + E_SHSTRNDX, shstrndx);
}

static void
write_phdr_be(uint8_t *p,
              uint32_t type,
              uint32_t flags,
              uint64_t offset,
              uint64_t vaddr,
              uint64_t filesz,
              uint64_t memsz,
              uint64_t align)
{
    put32_be(p + 0, type);
    put32_be(p + 4, flags);
    put64_be(p + 8, offset);
    put64_be(p + 16, vaddr);
    put64_be(p + 24, vaddr);
    put64_be(p + 32, filesz);
    put64_be(p + 40, memsz);
    put64_be(p + 48, align);
}

static void
write_shdr_be(uint8_t *p,
              uint32_t name,
              uint32_t type,
              uint64_t flags,
              uint64_t addr,
              uint64_t offset,
              uint64_t size,
              uint32_t link,
              uint32_t info,
              uint64_t addralign,
              uint64_t entsize)
{
    put32_be(p + SH_NAME, name);
    put32_be(p + SH_TYPE, type);
    put64_be(p + 8, flags);
    put64_be(p + 16, addr);
    put64_be(p + SH_OFFSET, offset);
    put64_be(p + SH_SIZE, size);
    put32_be(p + 40, link);
    put32_be(p + 44, info);
    put64_be(p + 48, addralign);
    put64_be(p + 56, entsize);
}

static n00b_buffer_t *
valid_big_endian_target_buffer(void)
{
    const size_t phoff        = 64;
    const size_t shoff        = 256;
    const size_t shstrtab_off = 384;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed(512);
    uint8_t       *p   = (uint8_t *)buf->data;

    write_header_be(p, ET_EXEC, 0x400080, phoff, 2, shoff, 2, 1);
    write_phdr_be(p + phoff,
                  PT_LOAD,
                  PF_R | PF_X,
                  0,
                  0x400000,
                  256,
                  512,
                  0x1000);
    write_phdr_be(p + phoff + 56,
                  PT_PHDR,
                  PF_R,
                  phoff,
                  0x400000 + phoff,
                  112,
                  112,
                  8);
    n00b_test_elf_write_shstrtab(p, shstrtab_off, true);
    write_shdr_be(p + shoff + 64,
                  1,
                  SHT_STRTAB,
                  0,
                  0,
                  shstrtab_off,
                  11,
                  0,
                  0,
                  1,
                  0);
    buf->byte_len = 395;
    return buf;
}

static n00b_elf_binary_t *
parse_buffer(n00b_buffer_t *buf)
{
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            result = n00b_elf_parse(stream);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_elf_rewrite_metadata_request_t
default_request(void)
{
    return (n00b_elf_rewrite_metadata_request_t){
        .section_name   = r".n00b.test",
        .payload        = payload_new(0x42, 16),
        .file_alignment = 8,
        .section_type   = SHT_PROGBITS,
        .section_flags  = 0,
        .policy         = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };
}

static n00b_elf_rewrite_loadable_request_t
default_loadable_request(void)
{
    return (n00b_elf_rewrite_loadable_request_t){
        .payload          = payload_new(0x90, 32),
        .segment_flags    = PF_R | PF_X,
        .file_alignment   = 8,
        .vaddr_alignment  = 0x1000,
        .p_memsz          = 32,
        .phtab_strategy   = N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED,
        .policy           = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };
}

static n00b_elf_rewrite_metadata_request_t
chalk_mark_request(uint8_t fill, size_t len)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.section_name = r".chalk.mark";
    request.payload = payload_new(fill, len);
    request.file_alignment = 8;
    request.section_type = SHT_PROGBITS;
    request.section_flags = 0;
    return request;
}

static n00b_elf_rewrite_metadata_request_t
object_bundle_request(uint8_t fill, size_t len)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.section_name = r".0c001.bundle";
    request.payload = payload_new(fill, len);
    request.file_alignment = 8;
    request.section_type = SHT_PROGBITS;
    request.section_flags = 0;
    return request;
}

static n00b_elf_rewrite_admit_metadata_request_t
chalk_mark_admit_request(size_t len)
{
    return (n00b_elf_rewrite_admit_metadata_request_t){
        .section_name    = r".chalk.mark",
        .payload_size    = len,
        .file_alignment  = 8,
        .section_type    = SHT_PROGBITS,
        .section_flags   = 0,
        .policy          = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };
}

static n00b_elf_rewrite_plan_t *
require_accepted_plan(n00b_buffer_t *buf,
                      n00b_elf_rewrite_metadata_request_t *request)
{
    n00b_elf_binary_t *bin    = parse_buffer(buf);
    auto               result = n00b_elf_rewrite_plan_metadata_insert(bin,
                                                                      request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == N00B_ELF_REWRITE_REJECT_NONE);
    N00B_TEST_REQUIRE(plan->target_profile.reason == N00B_ELF_REWRITE_PROFILE_OK);
    N00B_TEST_REQUIRE(plan->new_section_count
                      == plan->original_section_count + 1);
    return plan;
}

static n00b_elf_rewrite_plan_t *
require_accepted_plan_for_bin(n00b_elf_binary_t *bin,
                              n00b_elf_rewrite_metadata_request_t *request)
{
    auto result = n00b_elf_rewrite_plan_metadata_insert(bin, request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == N00B_ELF_REWRITE_REJECT_NONE);
    return plan;
}

static n00b_elf_rewrite_plan_t *
require_rejected_plan(n00b_buffer_t *buf,
                      n00b_elf_rewrite_metadata_request_t *request,
                      n00b_elf_rewrite_rejection_reason_t reason)
{
    n00b_elf_binary_t *bin    = parse_buffer(buf);
    auto               result = n00b_elf_rewrite_plan_metadata_insert(bin,
                                                                      request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == reason);
    return plan;
}

static n00b_elf_rewrite_plan_t *
require_rejected_plan_for_bin(n00b_elf_binary_t *bin,
                              n00b_elf_rewrite_metadata_request_t *request,
                              n00b_elf_rewrite_rejection_reason_t reason)
{
    auto result = n00b_elf_rewrite_plan_metadata_insert(bin, request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == reason);
    return plan;
}

static n00b_elf_rewrite_loadable_plan_t *
require_accepted_loadable_plan(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_loadable_request_t *request)
{
    auto result = n00b_elf_rewrite_plan_loadable_insert(bin, request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_loadable_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == N00B_ELF_REWRITE_REJECT_NONE);
    N00B_TEST_REQUIRE(plan->target_profile.reason == N00B_ELF_REWRITE_PROFILE_OK);
    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(plan->source_binary == bin);
    return plan;
}

static n00b_elf_rewrite_loadable_plan_t *
require_rejected_loadable_plan(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_loadable_request_t *request,
    n00b_elf_rewrite_rejection_reason_t  reason)
{
    auto result = n00b_elf_rewrite_plan_loadable_insert(bin, request);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_loadable_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason == reason);
    return plan;
}

static void
assert_err(n00b_result_t(n00b_elf_rewrite_plan_t *) result, n00b_err_t err)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result) == err);
}

static void
assert_loadable_err(n00b_result_t(n00b_elf_rewrite_loadable_plan_t *) result,
                    n00b_err_t                                       err)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result) == err);
}

static void
assert_buffer_err(n00b_result_t(n00b_buffer_t *) result, n00b_err_t err)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result) == err);
}

static void
assert_bool_err(n00b_result_t(bool) result, n00b_err_t err)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result) == err);
}

static void
assert_entrypoint_target_err(
    n00b_result_t(n00b_elf_rewrite_host_entrypoint_target_t) result,
    n00b_err_t                                               err)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(n00b_result_get_err(result) == err);
}

static n00b_elf_rewrite_host_entrypoint_target_t
require_accepted_entrypoint_target(
    n00b_elf_binary_t *bin,
    n00b_elf_rewrite_loadable_plan_t *plan,
    uint64_t target_payload_offset,
    uint64_t target_size)
{
    auto result =
        n00b_elf_rewrite_plan_host_entrypoint_target(bin,
                                                     plan,
                                                     target_payload_offset,
                                                     target_size);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_host_entrypoint_target_t target =
        n00b_result_get(result);
    N00B_TEST_REQUIRE(target.outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(target.rejection_reason
                      == N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NONE);
    return target;
}

static n00b_elf_rewrite_host_entrypoint_target_t
require_rejected_entrypoint_target(
    n00b_elf_binary_t *bin,
    n00b_elf_rewrite_loadable_plan_t *plan,
    uint64_t target_payload_offset,
    uint64_t target_size,
    n00b_elf_rewrite_host_entrypoint_rejection_reason_t reason)
{
    auto result =
        n00b_elf_rewrite_plan_host_entrypoint_target(bin,
                                                     plan,
                                                     target_payload_offset,
                                                     target_size);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_host_entrypoint_target_t target =
        n00b_result_get(result);
    N00B_TEST_REQUIRE(target.outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(target.rejection_reason == reason);
    return target;
}

static void
assert_patches_ordered(n00b_elf_rewrite_plan_t *plan)
{
    N00B_TEST_REQUIRE(plan->patches.len != 0);

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        N00B_TEST_REQUIRE(plan->patches.data[i].file_offset
                          <= plan->patches.data[i].file_end);

        if (i != 0) {
            N00B_TEST_REQUIRE(plan->patches.data[i - 1].file_end
                              <= plan->patches.data[i].file_offset);
        }
    }
}

static n00b_elf_rewrite_patch_t *
find_loadable_patch(n00b_elf_rewrite_loadable_plan_t *plan,
                    n00b_elf_rewrite_patch_kind_t     kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static n00b_elf_rewrite_patch_t *
find_loadable_patch_range(n00b_elf_rewrite_loadable_plan_t *plan,
                          n00b_elf_rewrite_patch_kind_t     kind,
                          uint64_t                          start,
                          uint64_t                          end)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind
            && plan->patches.data[i].file_offset == start
            && plan->patches.data[i].file_end == end) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static uint64_t
relocated_phtab_patch_coverage(n00b_elf_rewrite_loadable_plan_t *plan,
                               uint64_t                          start,
                               uint64_t                          end)
{
    uint64_t covered = 0;

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];

        if (patch->file_offset < start || patch->file_end > end) {
            continue;
        }

        switch (patch->kind) {
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB:
        case N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR:
        case N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD:
            covered += patch->file_end - patch->file_offset;
            break;
        default:
            N00B_TEST_REQUIRE(false);
        }
    }

    return covered;
}

static void
assert_loadable_patches_ordered(n00b_elf_rewrite_loadable_plan_t *plan)
{
    N00B_TEST_REQUIRE(plan->patches.len != 0);

    for (uint64_t i = 0; i < plan->patches.len; i++) {
        N00B_TEST_REQUIRE(plan->patches.data[i].file_offset
                          <= plan->patches.data[i].file_end);

        if (i != 0) {
            N00B_TEST_REQUIRE(plan->patches.data[i - 1].file_end
                              <= plan->patches.data[i].file_offset);
        }
    }
}

static void
assert_relocated_loadable_plan(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_loadable_request_t *request,
    n00b_elf_rewrite_loadable_plan_t    *plan,
    n00b_elf_rewrite_admit_rejection_reason_t source_reason)
{
    n00b_elf_rewrite_loadable_relocation_t *rel =
        &plan->phtab_relocation;
    uint64_t old_phtab_size =
        (uint64_t)bin->header.phnum * N00B_TEST_ELF64_PHDR_SIZE;
    uint64_t new_phtab_size =
        (uint64_t)(bin->header.phnum + 1) * N00B_TEST_ELF64_PHDR_SIZE;
    uint64_t payload_delta;

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE);
    N00B_TEST_REQUIRE(!plan->entrypoint_patch_enabled);
    N00B_TEST_REQUIRE(plan->original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->replacement_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->phtab_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB);
    N00B_TEST_REQUIRE(plan->payload_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD);
    N00B_TEST_REQUIRE(rel->status
                      == N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED);
    N00B_TEST_REQUIRE(rel->source_in_place_rejection == source_reason);
    N00B_TEST_REQUIRE(rel->elf_header_patch_offset == 0);
    N00B_TEST_REQUIRE(rel->elf_header_patch_end
                      == N00B_TEST_ELF64_EHDR_SIZE);
    N00B_TEST_REQUIRE(rel->elf_header_new_phoff
                      == rel->relocated_phtab_offset);
    N00B_TEST_REQUIRE(rel->elf_header_new_phnum == bin->header.phnum + 1);
    N00B_TEST_REQUIRE(rel->elf_header_entry == bin->header.entry);
    N00B_TEST_REQUIRE(rel->original_phtab_offset == bin->header.phoff);
    N00B_TEST_REQUIRE(rel->original_phtab_size == old_phtab_size);
    N00B_TEST_REQUIRE(rel->original_phtab_end
                      == bin->header.phoff + old_phtab_size);
    N00B_TEST_REQUIRE(rel->relocated_phtab_size == new_phtab_size);
    N00B_TEST_REQUIRE(rel->relocated_phtab_end
                      == rel->relocated_phtab_offset + new_phtab_size);
    N00B_TEST_REQUIRE(rel->relocated_phtab_vaddr_end
                      == rel->relocated_phtab_vaddr + new_phtab_size);
    N00B_TEST_REQUIRE(rel->pt_phdr_present);
    N00B_TEST_REQUIRE(rel->pt_phdr_entry_offset
                      == rel->relocated_phtab_offset
                       + (uint64_t)rel->pt_phdr_index
                             * N00B_TEST_ELF64_PHDR_SIZE);
    N00B_TEST_REQUIRE(rel->pt_phdr_new_offset
                      == rel->relocated_phtab_offset);
    N00B_TEST_REQUIRE(rel->pt_phdr_new_filesz == new_phtab_size);
    N00B_TEST_REQUIRE(rel->pt_phdr_new_memsz == new_phtab_size);
    N00B_TEST_REQUIRE(rel->pt_phdr_new_vaddr
                      == rel->relocated_phtab_vaddr);
    N00B_TEST_REQUIRE(rel->pt_phdr_new_paddr
                      == rel->relocated_phtab_vaddr);
    N00B_TEST_REQUIRE(rel->new_pt_load_index == bin->header.phnum);
    N00B_TEST_REQUIRE(rel->new_pt_load_entry_offset
                      == rel->relocated_phtab_offset
                       + (uint64_t)bin->header.phnum
                             * N00B_TEST_ELF64_PHDR_SIZE);
    N00B_TEST_REQUIRE(rel->new_pt_load_offset
                      == rel->relocated_phtab_offset);
    N00B_TEST_REQUIRE(rel->new_pt_load_vaddr
                      == rel->relocated_phtab_vaddr);
    N00B_TEST_REQUIRE(rel->new_pt_load_paddr
                      == rel->relocated_phtab_vaddr);
    N00B_TEST_REQUIRE(rel->new_pt_load_flags == request->segment_flags);
    N00B_TEST_REQUIRE(rel->new_pt_load_align >= 0x1000);
    N00B_TEST_REQUIRE(rel->new_pt_load_offset % rel->new_pt_load_align
                      == rel->new_pt_load_vaddr % rel->new_pt_load_align);
    N00B_TEST_REQUIRE(rel->payload_offset >= rel->relocated_phtab_end);
    N00B_TEST_REQUIRE(rel->payload_end
                      == rel->payload_offset + request->payload->byte_len);
    payload_delta = rel->payload_offset - rel->new_pt_load_offset;
    N00B_TEST_REQUIRE(rel->payload_vaddr
                      == rel->new_pt_load_vaddr + payload_delta);
    N00B_TEST_REQUIRE(rel->payload_vaddr_end
                      == rel->payload_vaddr + request->p_memsz);
    N00B_TEST_REQUIRE(rel->new_pt_load_filesz
                      == rel->payload_end - rel->new_pt_load_offset);
    N00B_TEST_REQUIRE(rel->new_pt_load_memsz
                      == payload_delta + request->p_memsz);
    N00B_TEST_REQUIRE(plan->phtab_placement.file_offset
                      == rel->relocated_phtab_offset);
    N00B_TEST_REQUIRE(plan->phtab_placement.file_end
                      == rel->relocated_phtab_end);
    N00B_TEST_REQUIRE(plan->payload_placement.file_offset
                      == rel->payload_offset);
    N00B_TEST_REQUIRE(plan->payload_placement.file_end
                      == rel->payload_end);

    n00b_elf_rewrite_patch_t *header =
        find_loadable_patch(plan, N00B_ELF_REWRITE_PATCH_ELF_HEADER);
    n00b_elf_rewrite_patch_t *pt_phdr =
        find_loadable_patch_range(
            plan,
            N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR,
            rel->pt_phdr_entry_offset,
            rel->pt_phdr_entry_offset + N00B_TEST_ELF64_PHDR_SIZE);
    n00b_elf_rewrite_patch_t *new_pt_load =
        find_loadable_patch_range(
            plan,
            N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD,
            rel->new_pt_load_entry_offset,
            rel->new_pt_load_entry_offset + N00B_TEST_ELF64_PHDR_SIZE);
    n00b_elf_rewrite_patch_t *payload =
        find_loadable_patch(plan, N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD);

    N00B_TEST_REQUIRE(header != nullptr);
    N00B_TEST_REQUIRE(pt_phdr != nullptr);
    N00B_TEST_REQUIRE(new_pt_load != nullptr);
    N00B_TEST_REQUIRE(payload != nullptr);
    N00B_TEST_REQUIRE(header->file_offset == 0);
    N00B_TEST_REQUIRE(header->file_end == N00B_TEST_ELF64_EHDR_SIZE);
    N00B_TEST_REQUIRE(
        relocated_phtab_patch_coverage(plan,
                                       rel->relocated_phtab_offset,
                                       rel->relocated_phtab_end)
        == rel->relocated_phtab_size);
    if (plan->file_size < rel->new_pt_load_offset) {
        N00B_TEST_REQUIRE(
            find_loadable_patch_range(
                plan,
                N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                plan->file_size,
                rel->new_pt_load_offset)
            != nullptr);
    }
    if (rel->relocated_phtab_end < rel->payload_offset) {
        N00B_TEST_REQUIRE(
            find_loadable_patch_range(
                plan,
                N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
                rel->relocated_phtab_end,
                rel->payload_offset)
            != nullptr);
    }
    N00B_TEST_REQUIRE(payload->file_offset == rel->payload_offset);
    N00B_TEST_REQUIRE(payload->file_end == rel->payload_end);
    N00B_TEST_REQUIRE(payload->original_file_offset == payload->file_offset);
    N00B_TEST_REQUIRE(payload->original_file_end == payload->file_offset);
    assert_loadable_patches_ordered(plan);
}

static void
mutate_shnum_zero(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHNUM, 0);
}

static void
mutate_ehsize(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_EHSIZE, 65);
}

static void
mutate_phentsize(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_PHENTSIZE, 57);
}

static void
mutate_shentsize(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHENTSIZE, 65);
}

static n00b_elf_rewrite_patch_t *
find_patch(n00b_elf_rewrite_plan_t *plan, n00b_elf_rewrite_patch_kind_t kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return &plan->patches.data[i];
        }
    }

    return nullptr;
}

static bool
offset_is_planned_change(n00b_elf_rewrite_plan_t *plan, uint64_t offset)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (offset >= plan->patches.data[i].file_offset
            && offset < plan->patches.data[i].file_end) {
            return true;
        }
    }

    return false;
}

static bool
offset_is_planned_loadable_change(n00b_elf_rewrite_loadable_plan_t *plan,
                                  uint64_t                          offset)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (offset >= plan->patches.data[i].file_offset
            && offset < plan->patches.data[i].file_end) {
            return true;
        }
    }

    return false;
}

static void
assert_unplanned_original_bytes_preserved(n00b_buffer_t *before,
                                          n00b_buffer_t *after,
                                          n00b_elf_rewrite_plan_t *plan)
{
    N00B_TEST_REQUIRE(after->byte_len >= before->byte_len);

    for (uint64_t i = 0; i < before->byte_len; i++) {
        if (offset_is_planned_change(plan, i)) {
            continue;
        }

        N00B_TEST_REQUIRE(before->data[i] == after->data[i]);
    }
}

static void
assert_unplanned_original_loadable_bytes_preserved(
    n00b_buffer_t *before,
    n00b_buffer_t *after,
    n00b_elf_rewrite_loadable_plan_t *plan)
{
    N00B_TEST_REQUIRE(after->byte_len >= before->byte_len);

    for (uint64_t i = 0; i < before->byte_len; i++) {
        if (offset_is_planned_loadable_change(plan, i)) {
            continue;
        }

        N00B_TEST_REQUIRE(before->data[i] == after->data[i]);
    }
}

static void
assert_original_range_preserved(n00b_buffer_t *before,
                                n00b_buffer_t *after,
                                uint64_t       start,
                                uint64_t       end)
{
    N00B_TEST_REQUIRE(start <= end);
    N00B_TEST_REQUIRE(end <= before->byte_len);
    N00B_TEST_REQUIRE(end <= after->byte_len);
    N00B_TEST_REQUIRE(memcmp(before->data + start,
                             after->data + start,
                             (size_t)(end - start)) == 0);
}

static void
assert_overlay_bytes_preserved(n00b_buffer_t     *before,
                               n00b_buffer_t     *after,
                               n00b_elf_binary_t *bin)
{
    N00B_TEST_REQUIRE(bin->overlay != nullptr);
    N00B_TEST_REQUIRE(bin->overlay->byte_len <= before->byte_len);

    uint64_t overlay_size  = bin->overlay->byte_len;
    uint64_t overlay_start = before->byte_len - overlay_size;

    assert_original_range_preserved(before,
                                    after,
                                    overlay_start,
                                    before->byte_len);
    N00B_TEST_REQUIRE(memcmp(after->data + overlay_start,
                             bin->overlay->data,
                             (size_t)overlay_size) == 0);
}

static void
assert_range_zeroed(n00b_buffer_t *buf, uint64_t start, uint64_t end)
{
    N00B_TEST_REQUIRE(start <= end);
    N00B_TEST_REQUIRE(end <= buf->byte_len);

    for (uint64_t i = start; i < end; i++) {
        N00B_TEST_REQUIRE(buf->data[i] == 0);
    }
}

static n00b_elf_section_t *
require_section_named(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            return &bin->sections[i];
        }
    }

    N00B_TEST_REQUIRE(false);
    return nullptr;
}

static uint32_t
require_section_index_named(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            return i;
        }
    }

    N00B_TEST_REQUIRE(false);
    return 0;
}

static uint64_t
count_sections_named(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    uint64_t count = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            count++;
        }
    }

    return count;
}

static void
assert_no_section_named(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    N00B_TEST_REQUIRE(count_sections_named(bin, name) == 0);
}

static n00b_buffer_t *
apply_plan_and_parse(n00b_buffer_t *input,
                     n00b_elf_binary_t *bin,
                     n00b_elf_rewrite_plan_t *plan,
                     n00b_elf_binary_t **parsed_out)
{
    n00b_buffer_t *input_snapshot = n00b_buffer_new((int64_t)input->byte_len);
    n00b_elf_header_t header_snapshot = bin->header;
    uint32_t num_sections_snapshot = bin->num_sections;
    uint32_t num_segments_snapshot = bin->num_segments;

    memcpy(input_snapshot->data, input->data, input->byte_len);
    input_snapshot->byte_len = input->byte_len;

    auto applied = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *output = n00b_result_get(applied);
    n00b_bstream_t *stream = n00b_bstream_new(output);
    auto parsed = n00b_elf_parse(stream);

    N00B_TEST_REQUIRE(n00b_result_is_ok(parsed));
    *parsed_out = n00b_result_get(parsed);
    N00B_TEST_REQUIRE(input->byte_len == input_snapshot->byte_len);
    N00B_TEST_REQUIRE(memcmp(input->data,
                             input_snapshot->data,
                             input_snapshot->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(bin->header.ident,
                             header_snapshot.ident,
                             sizeof(header_snapshot.ident)) == 0);
    N00B_TEST_REQUIRE(bin->header.type == header_snapshot.type);
    N00B_TEST_REQUIRE(bin->header.machine == header_snapshot.machine);
    N00B_TEST_REQUIRE(bin->header.version == header_snapshot.version);
    N00B_TEST_REQUIRE(bin->header.entry == header_snapshot.entry);
    N00B_TEST_REQUIRE(bin->header.phoff == header_snapshot.phoff);
    N00B_TEST_REQUIRE(bin->header.shoff == header_snapshot.shoff);
    N00B_TEST_REQUIRE(bin->header.flags == header_snapshot.flags);
    N00B_TEST_REQUIRE(bin->header.ehsize == header_snapshot.ehsize);
    N00B_TEST_REQUIRE(bin->header.phentsize == header_snapshot.phentsize);
    N00B_TEST_REQUIRE(bin->header.phnum == header_snapshot.phnum);
    N00B_TEST_REQUIRE(bin->header.shentsize == header_snapshot.shentsize);
    N00B_TEST_REQUIRE(bin->header.shnum == header_snapshot.shnum);
    N00B_TEST_REQUIRE(bin->header.shstrndx == header_snapshot.shstrndx);
    N00B_TEST_REQUIRE(bin->num_sections == num_sections_snapshot);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_snapshot);
    assert_unplanned_original_bytes_preserved(input_snapshot, output, plan);
    return output;
}

static n00b_buffer_t *
apply_chalk_plan_and_parse(n00b_buffer_t *input,
                           n00b_elf_binary_t *bin,
                           n00b_elf_rewrite_plan_t *plan,
                           n00b_elf_binary_t **parsed_out)
{
    n00b_buffer_t *input_snapshot = n00b_buffer_new((int64_t)input->byte_len);
    n00b_elf_header_t header_snapshot = bin->header;
    uint32_t num_sections_snapshot = bin->num_sections;
    uint32_t num_segments_snapshot = bin->num_segments;

    memcpy(input_snapshot->data, input->data, input->byte_len);
    input_snapshot->byte_len = input->byte_len;

    auto applied = n00b_elf_rewrite_apply_chalk_mark_plan(bin, plan);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *output = n00b_result_get(applied);
    n00b_bstream_t *stream = n00b_bstream_new(output);
    auto parsed = n00b_elf_parse(stream);

    N00B_TEST_REQUIRE(n00b_result_is_ok(parsed));
    *parsed_out = n00b_result_get(parsed);
    N00B_TEST_REQUIRE(input->byte_len == input_snapshot->byte_len);
    N00B_TEST_REQUIRE(memcmp(input->data,
                             input_snapshot->data,
                             input_snapshot->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(bin->header.ident,
                             header_snapshot.ident,
                             sizeof(header_snapshot.ident)) == 0);
    N00B_TEST_REQUIRE(bin->header.type == header_snapshot.type);
    N00B_TEST_REQUIRE(bin->header.machine == header_snapshot.machine);
    N00B_TEST_REQUIRE(bin->header.version == header_snapshot.version);
    N00B_TEST_REQUIRE(bin->header.entry == header_snapshot.entry);
    N00B_TEST_REQUIRE(bin->header.phoff == header_snapshot.phoff);
    N00B_TEST_REQUIRE(bin->header.shoff == header_snapshot.shoff);
    N00B_TEST_REQUIRE(bin->header.flags == header_snapshot.flags);
    N00B_TEST_REQUIRE(bin->header.ehsize == header_snapshot.ehsize);
    N00B_TEST_REQUIRE(bin->header.phentsize == header_snapshot.phentsize);
    N00B_TEST_REQUIRE(bin->header.phnum == header_snapshot.phnum);
    N00B_TEST_REQUIRE(bin->header.shentsize == header_snapshot.shentsize);
    N00B_TEST_REQUIRE(bin->header.shnum == header_snapshot.shnum);
    N00B_TEST_REQUIRE(bin->header.shstrndx == header_snapshot.shstrndx);
    N00B_TEST_REQUIRE(bin->num_sections == num_sections_snapshot);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_snapshot);
    assert_unplanned_original_bytes_preserved(input_snapshot, output, plan);
    return output;
}

static n00b_buffer_t *
apply_object_bundle_plan_and_parse(n00b_buffer_t *input,
                                   n00b_elf_binary_t *bin,
                                   n00b_elf_rewrite_plan_t *plan,
                                   n00b_elf_binary_t **parsed_out)
{
    n00b_buffer_t *input_snapshot = n00b_buffer_new((int64_t)input->byte_len);
    n00b_elf_header_t header_snapshot = bin->header;
    uint32_t num_sections_snapshot = bin->num_sections;
    uint32_t num_segments_snapshot = bin->num_segments;

    memcpy(input_snapshot->data, input->data, input->byte_len);
    input_snapshot->byte_len = input->byte_len;

    auto applied = n00b_elf_rewrite_apply_object_bundle_plan(bin, plan);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *output = n00b_result_get(applied);
    n00b_bstream_t *stream = n00b_bstream_new(output);
    auto parsed = n00b_elf_parse(stream);

    N00B_TEST_REQUIRE(n00b_result_is_ok(parsed));
    *parsed_out = n00b_result_get(parsed);
    N00B_TEST_REQUIRE(input->byte_len == input_snapshot->byte_len);
    N00B_TEST_REQUIRE(memcmp(input->data,
                             input_snapshot->data,
                             input_snapshot->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(bin->header.ident,
                             header_snapshot.ident,
                             sizeof(header_snapshot.ident)) == 0);
    N00B_TEST_REQUIRE(bin->header.type == header_snapshot.type);
    N00B_TEST_REQUIRE(bin->header.machine == header_snapshot.machine);
    N00B_TEST_REQUIRE(bin->header.version == header_snapshot.version);
    N00B_TEST_REQUIRE(bin->header.entry == header_snapshot.entry);
    N00B_TEST_REQUIRE(bin->header.phoff == header_snapshot.phoff);
    N00B_TEST_REQUIRE(bin->header.shoff == header_snapshot.shoff);
    N00B_TEST_REQUIRE(bin->header.flags == header_snapshot.flags);
    N00B_TEST_REQUIRE(bin->header.ehsize == header_snapshot.ehsize);
    N00B_TEST_REQUIRE(bin->header.phentsize == header_snapshot.phentsize);
    N00B_TEST_REQUIRE(bin->header.phnum == header_snapshot.phnum);
    N00B_TEST_REQUIRE(bin->header.shentsize == header_snapshot.shentsize);
    N00B_TEST_REQUIRE(bin->header.shnum == header_snapshot.shnum);
    N00B_TEST_REQUIRE(bin->header.shstrndx == header_snapshot.shstrndx);
    N00B_TEST_REQUIRE(bin->num_sections == num_sections_snapshot);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_snapshot);
    assert_unplanned_original_bytes_preserved(input_snapshot, output, plan);
    return output;
}

static n00b_buffer_t *
apply_loadable_plan_and_parse(n00b_buffer_t *input,
                              n00b_elf_binary_t *bin,
                              n00b_elf_rewrite_loadable_plan_t *plan,
                              n00b_elf_binary_t **parsed_out)
{
    n00b_buffer_t *input_snapshot = n00b_buffer_new((int64_t)input->byte_len);
    n00b_elf_header_t header_snapshot = bin->header;
    uint32_t num_sections_snapshot = bin->num_sections;
    uint32_t num_segments_snapshot = bin->num_segments;
    n00b_elf_segment_t segments_snapshot[8];
    n00b_elf_section_t sections_snapshot[8];

    N00B_TEST_REQUIRE(num_segments_snapshot <= 8);
    N00B_TEST_REQUIRE(num_sections_snapshot <= 8);
    memcpy(input_snapshot->data, input->data, input->byte_len);
    input_snapshot->byte_len = input->byte_len;
    memcpy(segments_snapshot,
           bin->segments,
           (size_t)num_segments_snapshot * sizeof(n00b_elf_segment_t));
    memcpy(sections_snapshot,
           bin->sections,
           (size_t)num_sections_snapshot * sizeof(n00b_elf_section_t));

    auto applied = n00b_elf_rewrite_apply_loadable_insert_plan(bin, plan);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *output = n00b_result_get(applied);
    n00b_bstream_t *stream = n00b_bstream_new(output);
    auto parsed = n00b_elf_parse(stream);

    N00B_TEST_REQUIRE(n00b_result_is_ok(parsed));
    *parsed_out = n00b_result_get(parsed);
    N00B_TEST_REQUIRE(input->byte_len == input_snapshot->byte_len);
    N00B_TEST_REQUIRE(memcmp(input->data,
                             input_snapshot->data,
                             input_snapshot->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(&header_snapshot,
                             &bin->header,
                             sizeof(n00b_elf_header_t)) == 0);
    N00B_TEST_REQUIRE(bin->num_sections == num_sections_snapshot);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_snapshot);
    N00B_TEST_REQUIRE(memcmp(segments_snapshot,
                             bin->segments,
                             (size_t)num_segments_snapshot
                                 * sizeof(n00b_elf_segment_t)) == 0);
    N00B_TEST_REQUIRE(memcmp(sections_snapshot,
                             bin->sections,
                             (size_t)num_sections_snapshot
                                 * sizeof(n00b_elf_section_t)) == 0);
    assert_unplanned_original_loadable_bytes_preserved(input_snapshot,
                                                       output,
                                                       plan);
    return output;
}

static void
assert_inserted_section(n00b_elf_binary_t *bin,
                        n00b_elf_rewrite_plan_t *plan,
                        n00b_elf_rewrite_metadata_request_t *request)
{
    n00b_elf_section_t *sec = require_section_named(bin, request->section_name);
    uint64_t            expected_align = request->file_alignment == 0
                                       ? 1
                                       : request->file_alignment;

    N00B_TEST_REQUIRE(bin->header.shnum == plan->new_section_count);
    N00B_TEST_REQUIRE(bin->header.shstrndx < bin->header.shnum);
    N00B_TEST_REQUIRE(sec == &bin->sections[bin->header.shnum - 1]);
    N00B_TEST_REQUIRE(sec->type == request->section_type);
    N00B_TEST_REQUIRE(sec->flags == request->section_flags);
    N00B_TEST_REQUIRE(sec->offset == plan->payload_offset);
    N00B_TEST_REQUIRE(sec->size == request->payload->byte_len);
    N00B_TEST_REQUIRE(sec->addralign == expected_align);
    N00B_TEST_REQUIRE(sec->link == 0);
    N00B_TEST_REQUIRE(sec->info == 0);
    N00B_TEST_REQUIRE(sec->entsize == 0);
    N00B_TEST_REQUIRE(sec->content != nullptr);
    N00B_TEST_REQUIRE(sec->content->byte_len == request->payload->byte_len);
    N00B_TEST_REQUIRE(memcmp(sec->content->data,
                             request->payload->data,
                             request->payload->byte_len) == 0);
}

static void
assert_object_bundle_section(n00b_elf_section_t *sec,
                             n00b_elf_rewrite_metadata_request_t *request)
{
    N00B_TEST_REQUIRE(sec != nullptr);
    N00B_TEST_REQUIRE(sec->type == SHT_PROGBITS);
    N00B_TEST_REQUIRE(sec->flags == 0);
    N00B_TEST_REQUIRE(sec->addr == 0);
    N00B_TEST_REQUIRE(sec->size == request->payload->byte_len);
    N00B_TEST_REQUIRE(sec->content != nullptr);
    N00B_TEST_REQUIRE(sec->content->byte_len == request->payload->byte_len);
    N00B_TEST_REQUIRE(memcmp(sec->content->data,
                             request->payload->data,
                             request->payload->byte_len) == 0);
}

static uint64_t
section_header_offset(n00b_elf_binary_t *bin, uint32_t section_index)
{
    uint64_t offset = bin->header.shoff
                    + (uint64_t)section_index * bin->header.shentsize;

    N00B_TEST_REQUIRE(section_index < bin->num_sections);
    N00B_TEST_REQUIRE(offset + N00B_TEST_ELF64_SHDR_SIZE
                      <= bin->stream->buf->byte_len);
    return offset;
}

static void
duplicate_object_bundle_section_name(n00b_buffer_t *buf,
                                      n00b_elf_binary_t *bin)
{
    uint32_t bundle_index =
        require_section_index_named(bin, r".0c001.bundle");
    uint64_t bundle_shdr = section_header_offset(bin, bundle_index);
    uint64_t shstr_shdr = section_header_offset(bin, bin->header.shstrndx);
    uint32_t bundle_name_index =
        get32_le((const uint8_t *)buf->data + bundle_shdr + SH_NAME);

    n00b_test_elf_put32((uint8_t *)buf->data + shstr_shdr + SH_NAME,
                        bundle_name_index);
}

static void
mutate_object_bundle_section_type(n00b_buffer_t *buf,
                                  n00b_elf_binary_t *bin,
                                  uint32_t type)
{
    uint32_t bundle_index =
        require_section_index_named(bin, r".0c001.bundle");
    uint64_t bundle_shdr = section_header_offset(bin, bundle_index);

    n00b_test_elf_put32((uint8_t *)buf->data + bundle_shdr + SH_TYPE,
                        type);
}

static void
mutate_object_bundle_section_flags(n00b_buffer_t *buf,
                                   n00b_elf_binary_t *bin,
                                   uint64_t flags)
{
    uint32_t bundle_index =
        require_section_index_named(bin, r".0c001.bundle");
    uint64_t bundle_shdr = section_header_offset(bin, bundle_index);

    n00b_test_elf_put64((uint8_t *)buf->data + bundle_shdr + 8,
                        flags);
}

static void
mutate_object_bundle_section_offset(n00b_buffer_t *buf,
                                    n00b_elf_binary_t *bin,
                                    uint64_t offset)
{
    uint32_t bundle_index =
        require_section_index_named(bin, r".0c001.bundle");
    uint64_t bundle_shdr = section_header_offset(bin, bundle_index);

    n00b_test_elf_put64((uint8_t *)buf->data + bundle_shdr + SH_OFFSET,
                        offset);
}

static void
mutate_object_bundle_section_size(n00b_buffer_t *buf,
                                  n00b_elf_binary_t *bin,
                                  uint64_t size)
{
    uint32_t bundle_index =
        require_section_index_named(bin, r".0c001.bundle");
    uint64_t bundle_shdr = section_header_offset(bin, bundle_index);

    n00b_test_elf_put64((uint8_t *)buf->data + bundle_shdr + SH_SIZE,
                        size);
}

static void
assert_loader_metadata_preserved(n00b_elf_binary_t *before,
                                 n00b_elf_binary_t *after)
{
    N00B_TEST_REQUIRE(after->header.type == before->header.type);
    N00B_TEST_REQUIRE(after->header.machine == before->header.machine);
    N00B_TEST_REQUIRE(after->header.version == before->header.version);
    N00B_TEST_REQUIRE(after->header.entry == before->header.entry);
    N00B_TEST_REQUIRE(after->header.phoff == before->header.phoff);
    N00B_TEST_REQUIRE(after->header.flags == before->header.flags);
    N00B_TEST_REQUIRE(after->header.ehsize == before->header.ehsize);
    N00B_TEST_REQUIRE(after->header.phentsize == before->header.phentsize);
    N00B_TEST_REQUIRE(after->header.phnum == before->header.phnum);
    N00B_TEST_REQUIRE(after->header.shentsize == before->header.shentsize);
    N00B_TEST_REQUIRE(after->header.shstrndx == before->header.shstrndx);
    N00B_TEST_REQUIRE(after->num_segments == before->num_segments);

    for (uint32_t i = 0; i < before->num_segments; i++) {
        N00B_TEST_REQUIRE(after->segments[i].type == before->segments[i].type);
        N00B_TEST_REQUIRE(after->segments[i].flags == before->segments[i].flags);
        N00B_TEST_REQUIRE(after->segments[i].offset == before->segments[i].offset);
        N00B_TEST_REQUIRE(after->segments[i].vaddr == before->segments[i].vaddr);
        N00B_TEST_REQUIRE(after->segments[i].paddr == before->segments[i].paddr);
        N00B_TEST_REQUIRE(after->segments[i].filesz == before->segments[i].filesz);
        N00B_TEST_REQUIRE(after->segments[i].memsz == before->segments[i].memsz);
        N00B_TEST_REQUIRE(after->segments[i].align == before->segments[i].align);
    }
}

static void
assert_live_shstrtab_terminated(n00b_elf_binary_t *bin)
{
    N00B_TEST_REQUIRE(bin->header.shstrndx < bin->num_sections);

    n00b_elf_section_t *shstrtab = &bin->sections[bin->header.shstrndx];
    N00B_TEST_REQUIRE(shstrtab->content != nullptr);
    N00B_TEST_REQUIRE(shstrtab->content->byte_len != 0);
    N00B_TEST_REQUIRE(shstrtab->content->data[shstrtab->content->byte_len - 1]
                      == '\0');
}

static void
add_note_segment(n00b_buffer_t *buf, uint64_t offset, uint64_t size)
{
    uint8_t *p = (uint8_t *)buf->data;
    uint64_t end = offset + size;

    n00b_test_elf_put16(p + E_PHNUM, 3);
    n00b_test_elf_put64(p + 64 + 56 + 32, 168);
    n00b_test_elf_put64(p + 64 + 56 + 40, 168);
    n00b_test_elf_write_phdr(p + 64 + 112,
                             PT_NOTE,
                             PF_R,
                             offset,
                             0x400000 + offset,
                             size,
                             size,
                             4);
    if (buf->byte_len < end) {
        buf->byte_len = end;
    }
}

static n00b_buffer_t *
higher_terminal_tail_candidate_buffer(void)
{
    n00b_buffer_t *buf = shstrtab_then_shtab_buffer();

    add_note_segment(buf, 288, 16);
    return buf;
}

static void
mutate_shnum_one(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHNUM, 1);
}

static void
mutate_shnum_xindex(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHNUM, SHN_XINDEX);
}

static void
mutate_shnum_loreserve(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHNUM,
                        N00B_TEST_SHN_LORESERVE);
}

static void
mutate_shoff_zero(n00b_buffer_t *buf)
{
    n00b_test_elf_put64((uint8_t *)buf->data + E_SHOFF, 0);
}

static void
mutate_shstrndx_zero(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHSTRNDX, 0);
}

static void
mutate_shstrndx_xindex(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHSTRNDX, SHN_XINDEX);
}

static void
mutate_shstrndx_loreserve(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHSTRNDX,
                        N00B_TEST_SHN_LORESERVE);
}

static void
mutate_shstrndx_out_of_range(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_SHSTRNDX, 2);
}

static void
mutate_shstrtab_type(n00b_buffer_t *buf)
{
    n00b_test_elf_put32((uint8_t *)buf->data + SHSTRTAB_SH + SH_TYPE,
                        SHT_PROGBITS);
}

static void
mutate_shstrtab_bounds(n00b_buffer_t *buf)
{
    n00b_test_elf_put64((uint8_t *)buf->data + SHSTRTAB_SH + SH_SIZE, 1024);
}

static void
mutate_section_name_index(n00b_buffer_t *buf)
{
    n00b_test_elf_put32((uint8_t *)buf->data + SHSTRTAB_SH + SH_NAME, 11);
}

static void
mutate_phnum_zero(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_PHNUM, 0);
}

static void
mutate_phnum_xnum(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + E_PHNUM, 0xffff);
}

static void
test_invalid_inputs(void)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_binary_t                  *bin     = parse_buffer(valid_target_buffer());

    assert_err(n00b_elf_rewrite_plan_metadata_insert(nullptr, &request),
               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_err(n00b_elf_rewrite_plan_metadata_insert(bin, nullptr),
               N00B_ELF_REWRITE_ERR_NULL_REQUEST);

    request.section_name = nullptr;
    assert_err(n00b_elf_rewrite_plan_metadata_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME);

    request = default_request();
    request.payload = nullptr;
    assert_err(n00b_elf_rewrite_plan_metadata_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);

    request = default_request();
    request.payload->byte_len = 0;
    assert_err(n00b_elf_rewrite_plan_metadata_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);

    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert_plan(nullptr,
                                                                  nullptr),
                      N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert_plan(bin,
                                                                  nullptr),
                      N00B_ELF_REWRITE_ERR_NULL_PLAN);

    request = object_bundle_request(0x90, 24);
    assert_err(n00b_elf_rewrite_plan_object_bundle_insert(nullptr,
                                                          &request),
               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_err(n00b_elf_rewrite_plan_object_bundle_insert(bin, nullptr),
               N00B_ELF_REWRITE_ERR_NULL_REQUEST);
    assert_err(n00b_elf_rewrite_plan_object_bundle_replace(bin, nullptr),
               N00B_ELF_REWRITE_ERR_NULL_REQUEST);

    request.section_name = nullptr;
    assert_err(n00b_elf_rewrite_plan_object_bundle_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME);

    request = object_bundle_request(0x91, 24);
    request.payload = nullptr;
    assert_err(n00b_elf_rewrite_plan_object_bundle_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);

    request = object_bundle_request(0x92, 24);
    request.payload->byte_len = 0;
    assert_err(n00b_elf_rewrite_plan_object_bundle_insert(bin, &request),
               N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);

    assert_buffer_err(n00b_elf_rewrite_apply_object_bundle_plan(bin,
                                                                nullptr),
                      N00B_ELF_REWRITE_ERR_NULL_PLAN);
}

static void
test_loadable_invalid_inputs(void)
{
    n00b_elf_binary_t *bin = parse_buffer(valid_target_buffer());
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    assert_loadable_err(n00b_elf_rewrite_plan_loadable_insert(nullptr,
                                                              &request),
                        N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_loadable_err(n00b_elf_rewrite_plan_loadable_insert(bin, nullptr),
                        N00B_ELF_REWRITE_ERR_NULL_REQUEST);

    request.payload = nullptr;
    assert_loadable_err(n00b_elf_rewrite_plan_loadable_insert(bin, &request),
                        N00B_ELF_REWRITE_ERR_NULL_PAYLOAD);

    request = default_loadable_request();
    request.payload->byte_len = 0;
    assert_loadable_err(n00b_elf_rewrite_plan_loadable_insert(bin, &request),
                        N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE);
}

static void
test_loadable_phase1_strategy_plans(void)
{
    n00b_elf_binary_t *bin = parse_buffer(valid_target_buffer());
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED);
    N00B_TEST_REQUIRE(plan->payload == request.payload);
    N00B_TEST_REQUIRE(plan->file_size == bin->stream->buf->byte_len);
    N00B_TEST_REQUIRE(plan->original_segment_count == bin->header.phnum);
    N00B_TEST_REQUIRE(plan->new_segment_count == bin->header.phnum + 1);
    N00B_TEST_REQUIRE(plan->p_memsz == request.p_memsz);
    N00B_TEST_REQUIRE(plan->file_alignment == request.file_alignment);
    N00B_TEST_REQUIRE(plan->vaddr_alignment == request.vaddr_alignment);
    N00B_TEST_REQUIRE(plan->segment_flags == request.segment_flags);
    N00B_TEST_REQUIRE(plan->entrypoint_policy_deferred);
    N00B_TEST_REQUIRE(!plan->entrypoint_patch_enabled);
    N00B_TEST_REQUIRE(plan->original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->replacement_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->patches.len == 0);
    N00B_TEST_REQUIRE(plan->phtab_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_DEFERRED);
    N00B_TEST_REQUIRE(
        plan->phtab_adjustment.status
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE);
    N00B_TEST_REQUIRE(plan->phtab_relocation.status
                      == N00B_ELF_REWRITE_LOADABLE_RELOCATION_NONE);
}

static void
test_loadable_in_place_phtab_plan_facts(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("phtab_adjust_accepted");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->phtab_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB);
    N00B_TEST_REQUIRE(!plan->entrypoint_patch_enabled);
    N00B_TEST_REQUIRE(plan->original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->replacement_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(
        plan->phtab_adjustment.status
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED);
    N00B_TEST_REQUIRE(plan->phtab_adjustment.adjusted_phtab_offset == 200);
    N00B_TEST_REQUIRE(plan->phtab_adjustment.adjusted_phtab_size == 168);
    N00B_TEST_REQUIRE(plan->admission.phtab_adjustment.adjusted_phtab_offset
                      == plan->phtab_adjustment.adjusted_phtab_offset);
}

static void
test_loadable_admission_rejections_propagate(void)
{
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.p_memsz = request.payload->byte_len - 1;
    n00b_elf_rewrite_loadable_plan_t *plan =
        require_rejected_loadable_plan(parse_buffer(valid_target_buffer()),
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_ADMISSION);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_PAYLOAD_MEMSZ);

    request = default_loadable_request();
    plan = require_rejected_loadable_plan(
        parse_buffer(n00b_test_elf_minimal_exec(0x400080,
                                                0,
                                                0x400000,
                                                512,
                                                512,
                                                false,
                                                false,
                                                true,
                                                false)),
        &request,
        N00B_ELF_REWRITE_REJECT_ADMISSION);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING);

    request = default_loadable_request();
    plan = require_rejected_loadable_plan(
        parse_buffer(n00b_test_elf_minimal_exec(0x400080,
                                                0,
                                                0x400000,
                                                512,
                                                512,
                                                true,
                                                true,
                                                true,
                                                false)),
        &request,
        N00B_ELF_REWRITE_REJECT_ADMISSION);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT);
}

static void
test_loadable_target_profile_rejections(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    mutate_phnum_xnum(buf);
    n00b_elf_rewrite_loadable_plan_t *plan =
        require_rejected_loadable_plan(parse_buffer(buf),
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_TARGET_PROFILE);

    N00B_TEST_REQUIRE(plan->target_profile.reason
                      == N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM);
    N00B_TEST_REQUIRE(plan->target_profile.packager_errcode == 21);
}

static void
test_loadable_no_mutation(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();
    size_t before_len = buf->byte_len;
    uint8_t before[512];
    n00b_elf_header_t header_before = bin->header;
    uint32_t num_segments_before = bin->num_segments;

    memcpy(before, buf->data, before_len);

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(buf->byte_len == before_len);
    N00B_TEST_REQUIRE(memcmp(before, buf->data, before_len) == 0);
    N00B_TEST_REQUIRE(bin->header.phnum == header_before.phnum);
    N00B_TEST_REQUIRE(bin->header.phoff == header_before.phoff);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_before);
}

static void
test_loadable_relocated_phtab_direct_plan_facts(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(plan->admission.phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE);
    N00B_TEST_REQUIRE(
        plan->phtab_adjustment.status
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE);
    assert_relocated_loadable_plan(bin,
                                   &request,
                                   plan,
                                   N00B_ELF_REWRITE_ADMIT_REJECT_NONE);
}

static void
test_loadable_relocation_fallback_after_file_collision(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("phtab_adjust_file_collision");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(plan->admission.phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE);
    N00B_TEST_REQUIRE(plan->phtab_adjustment.status
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE);
    N00B_TEST_REQUIRE(
        plan->phtab_adjustment.rejection_reason
        == N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION);
    assert_relocated_loadable_plan(
        bin,
        &request,
        plan,
        N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION);
}

static void
test_loadable_relocation_rejects_address_overflow(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_address_overflow");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_rejected_loadable_plan(bin,
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(plan->admission.phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE);
    N00B_TEST_REQUIRE(plan->phtab_relocation.status
                      == N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED);
    N00B_TEST_REQUIRE(plan->phtab_relocation.rejection_reason
                      == N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS);
}

static void
test_loadable_relocation_rejects_overlay_without_append(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_overlay_rejected");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_rejected_loadable_plan(
            bin,
            &request,
            N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(plan->admission.phtab_strategy
                      == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE);
    N00B_TEST_REQUIRE(plan->phtab_relocation.status
                      == N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED);
    N00B_TEST_REQUIRE(plan->phtab_relocation.rejection_reason
                      == N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT);
}

static void
test_loadable_relocation_no_mutation(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();
    size_t before_len = buf->byte_len;
    uint8_t before[512];
    n00b_elf_header_t header_before = bin->header;
    uint32_t num_segments_before = bin->num_segments;
    uint32_t num_sections_before = bin->num_sections;
    n00b_elf_segment_t segments_before[8];
    n00b_elf_section_t sections_before[8];

    N00B_TEST_REQUIRE(before_len <= sizeof(before));
    N00B_TEST_REQUIRE(num_segments_before <= 8);
    N00B_TEST_REQUIRE(num_sections_before <= 8);
    memcpy(before, buf->data, before_len);
    memcpy(segments_before,
           bin->segments,
           (size_t)num_segments_before * sizeof(n00b_elf_segment_t));
    memcpy(sections_before,
           bin->sections,
           (size_t)num_sections_before * sizeof(n00b_elf_section_t));

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);

    N00B_TEST_REQUIRE(plan->phtab_relocation.status
                      == N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED);
    N00B_TEST_REQUIRE(buf->byte_len == before_len);
    N00B_TEST_REQUIRE(memcmp(before, buf->data, before_len) == 0);
    N00B_TEST_REQUIRE(memcmp(&header_before,
                             &bin->header,
                             sizeof(n00b_elf_header_t)) == 0);
    N00B_TEST_REQUIRE(bin->num_segments == num_segments_before);
    N00B_TEST_REQUIRE(bin->num_sections == num_sections_before);
    N00B_TEST_REQUIRE(memcmp(segments_before,
                             bin->segments,
                             (size_t)num_segments_before
                                 * sizeof(n00b_elf_segment_t)) == 0);
    N00B_TEST_REQUIRE(memcmp(sections_before,
                             bin->sections,
                             (size_t)num_sections_before
                                 * sizeof(n00b_elf_section_t)) == 0);
}

static void
assert_rewritten_loadable_payload(n00b_buffer_t *out,
                                  n00b_elf_rewrite_loadable_plan_t *plan)
{
    N00B_TEST_REQUIRE(plan->payload != nullptr);
    N00B_TEST_REQUIRE(plan->payload_placement.file_end
                      == plan->payload_placement.file_offset
                       + plan->payload->byte_len);
    N00B_TEST_REQUIRE(plan->payload_placement.file_end <= out->byte_len);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_placement.file_offset,
                             plan->payload->data,
                             plan->payload->byte_len) == 0);
}

static void
assert_rewritten_new_pt_load(n00b_elf_binary_t *rewritten,
                             n00b_elf_rewrite_loadable_plan_t *plan,
                             uint64_t offset,
                             uint64_t vaddr,
                             uint64_t paddr,
                             uint64_t filesz,
                             uint64_t memsz,
                             uint64_t align)
{
    N00B_TEST_REQUIRE(rewritten->num_segments == plan->new_segment_count);
    N00B_TEST_REQUIRE(plan->new_segment_count
                      == plan->original_segment_count + 1);

    n00b_elf_segment_t *seg =
        &rewritten->segments[plan->original_segment_count];
    N00B_TEST_REQUIRE(seg->type == PT_LOAD);
    N00B_TEST_REQUIRE(seg->flags == plan->segment_flags);
    N00B_TEST_REQUIRE(seg->offset == offset);
    N00B_TEST_REQUIRE(seg->vaddr == vaddr);
    N00B_TEST_REQUIRE(seg->paddr == paddr);
    N00B_TEST_REQUIRE(seg->filesz == filesz);
    N00B_TEST_REQUIRE(seg->memsz == memsz);
    N00B_TEST_REQUIRE(seg->align == align);
    N00B_TEST_REQUIRE(seg->align != 0);
    N00B_TEST_REQUIRE(seg->vaddr % seg->align == seg->offset % seg->align);
    N00B_TEST_REQUIRE(seg->content != nullptr);
    N00B_TEST_REQUIRE(seg->content->byte_len == filesz);
    N00B_TEST_REQUIRE(plan->payload_placement.file_offset >= offset);
    uint64_t payload_delta = plan->payload_placement.file_offset - offset;
    N00B_TEST_REQUIRE(payload_delta + plan->payload->byte_len
                      <= seg->content->byte_len);
    N00B_TEST_REQUIRE(memcmp(seg->content->data + payload_delta,
                             plan->payload->data,
                             plan->payload->byte_len) == 0);
}

static void
assert_loadable_padding_zeroed(n00b_buffer_t *out,
                               n00b_elf_rewrite_loadable_plan_t *plan)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];

        if (patch->kind == N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING) {
            assert_range_zeroed(out, patch->file_offset, patch->file_end);
        }
    }
}

static void
append_loadable_plan_patch(n00b_elf_rewrite_loadable_plan_t *plan,
                           n00b_elf_rewrite_patch_t          patch)
{
    size_t count = plan->patches.len;
    n00b_array_t(n00b_elf_rewrite_patch_t) patches =
        n00b_array_new(n00b_elf_rewrite_patch_t,
                       count + 1,
                       .allocator = nullptr);

    memcpy(patches.data,
           plan->patches.data,
           count * sizeof(n00b_elf_rewrite_patch_t));
    patches.data[count] = patch;
    patches.len = count + 1;
    plan->patches = patches;
}

static void
test_apply_loadable_in_place_phtab_adjustment(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("phtab_adjust_accepted");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    n00b_elf_rewrite_loadable_phtab_adjustment_t *adj =
        &plan->phtab_adjustment;

    N00B_TEST_REQUIRE(plan->patches.len != 0);
    N00B_TEST_REQUIRE(plan->payload_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD);
    N00B_TEST_REQUIRE(find_loadable_patch(plan,
                                          N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR)
                      != nullptr);
    N00B_TEST_REQUIRE(find_loadable_patch(plan,
                                          N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD)
                      != nullptr);
    assert_loadable_patches_ordered(plan);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *out = apply_loadable_plan_and_parse(buf,
                                                       bin,
                                                       plan,
                                                       &rewritten);
    n00b_elf_segment_t *old_load =
        &bin->segments[adj->containing_load_index];
    n00b_elf_segment_t *new_load =
        &rewritten->segments[adj->containing_load_index];
    n00b_elf_segment_t *pt_phdr =
        &rewritten->segments[adj->pt_phdr_index];

    N00B_TEST_REQUIRE(rewritten->header.phoff == adj->adjusted_phtab_offset);
    N00B_TEST_REQUIRE(rewritten->header.phnum == bin->header.phnum + 1);
    N00B_TEST_REQUIRE(rewritten->header.entry == bin->header.entry);
    N00B_TEST_REQUIRE(rewritten->header.shoff == bin->header.shoff);
    N00B_TEST_REQUIRE(new_load->type == PT_LOAD);
    N00B_TEST_REQUIRE(new_load->filesz
                      == old_load->filesz + adj->required_file_extension);
    N00B_TEST_REQUIRE(new_load->memsz
                      == old_load->memsz + adj->required_memory_extension);
    N00B_TEST_REQUIRE(pt_phdr->type == PT_PHDR);
    N00B_TEST_REQUIRE(pt_phdr->offset == adj->pt_phdr_new_offset);
    N00B_TEST_REQUIRE(pt_phdr->filesz == adj->pt_phdr_new_filesz);
    N00B_TEST_REQUIRE(pt_phdr->memsz == adj->pt_phdr_new_memsz);
    N00B_TEST_REQUIRE(pt_phdr->vaddr == adj->pt_phdr_new_vaddr);
    N00B_TEST_REQUIRE(pt_phdr->paddr == adj->pt_phdr_new_vaddr);

    assert_rewritten_new_pt_load(rewritten,
                                 plan,
                                 plan->payload_placement.file_offset,
                                 plan->payload_placement.vaddr,
                                 plan->payload_placement.vaddr,
                                 plan->payload->byte_len,
                                 plan->p_memsz,
                                 plan->payload_placement.alignment);
    assert_rewritten_loadable_payload(out, plan);
    assert_loadable_padding_zeroed(out, plan);
    assert_original_range_preserved(buf,
                                    out,
                                    bin->header.phoff,
                                    bin->header.phoff
                                        + (uint64_t)bin->header.phnum
                                              * N00B_TEST_ELF64_PHDR_SIZE);
}

static void
test_apply_loadable_in_place_entrypoint_patch(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("phtab_adjust_accepted");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    uint64_t replacement = plan->payload_placement.vaddr;
    auto     enabled =
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(plan, replacement);

    N00B_TEST_REQUIRE(n00b_result_is_ok(enabled));
    N00B_TEST_REQUIRE(n00b_result_get(enabled));
    N00B_TEST_REQUIRE(plan->entrypoint_patch_enabled);
    N00B_TEST_REQUIRE(plan->original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->replacement_entrypoint == replacement);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_loadable_plan_and_parse(buf, bin, plan, &rewritten);

    N00B_TEST_REQUIRE(rewritten->header.entry == replacement);
    N00B_TEST_REQUIRE(rewritten->header.entry != bin->header.entry);
    N00B_TEST_REQUIRE(rewritten->header.phoff
                      == plan->phtab_adjustment.adjusted_phtab_offset);
    N00B_TEST_REQUIRE(rewritten->header.phnum == bin->header.phnum + 1);
}

static void
test_apply_loadable_relocated_phtab(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    n00b_elf_rewrite_loadable_relocation_t *rel =
        &plan->phtab_relocation;

    assert_relocated_loadable_plan(bin,
                                   &request,
                                   plan,
                                   N00B_ELF_REWRITE_ADMIT_REJECT_NONE);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *out = apply_loadable_plan_and_parse(buf,
                                                       bin,
                                                       plan,
                                                       &rewritten);
    n00b_elf_segment_t *pt_phdr =
        &rewritten->segments[rel->pt_phdr_index];

    N00B_TEST_REQUIRE(rewritten->header.phoff == rel->relocated_phtab_offset);
    N00B_TEST_REQUIRE(rewritten->header.phnum == bin->header.phnum + 1);
    N00B_TEST_REQUIRE(rewritten->header.entry == bin->header.entry);
    N00B_TEST_REQUIRE(rewritten->header.shoff == bin->header.shoff);
    N00B_TEST_REQUIRE(pt_phdr->type == PT_PHDR);
    N00B_TEST_REQUIRE(pt_phdr->offset == rel->pt_phdr_new_offset);
    N00B_TEST_REQUIRE(pt_phdr->filesz == rel->pt_phdr_new_filesz);
    N00B_TEST_REQUIRE(pt_phdr->memsz == rel->pt_phdr_new_memsz);
    N00B_TEST_REQUIRE(pt_phdr->vaddr == rel->pt_phdr_new_vaddr);
    N00B_TEST_REQUIRE(pt_phdr->paddr == rel->pt_phdr_new_paddr);

    assert_rewritten_new_pt_load(rewritten,
                                 plan,
                                 rel->new_pt_load_offset,
                                 rel->new_pt_load_vaddr,
                                 rel->new_pt_load_paddr,
                                 rel->new_pt_load_filesz,
                                 rel->new_pt_load_memsz,
                                 rel->new_pt_load_align);
    assert_rewritten_loadable_payload(out, plan);
    assert_loadable_padding_zeroed(out, plan);
    assert_original_range_preserved(buf,
                                    out,
                                    rel->original_phtab_offset,
                                    rel->original_phtab_end);
}

static void
test_apply_loadable_relocated_entrypoint_patch(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    uint64_t replacement = plan->phtab_relocation.payload_vaddr;
    auto     enabled =
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(plan, replacement);

    N00B_TEST_REQUIRE(n00b_result_is_ok(enabled));
    N00B_TEST_REQUIRE(n00b_result_get(enabled));
    N00B_TEST_REQUIRE(plan->entrypoint_patch_enabled);
    N00B_TEST_REQUIRE(plan->original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(plan->replacement_entrypoint == replacement);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_loadable_plan_and_parse(buf, bin, plan, &rewritten);

    N00B_TEST_REQUIRE(rewritten->header.entry == replacement);
    N00B_TEST_REQUIRE(rewritten->header.entry != bin->header.entry);
    N00B_TEST_REQUIRE(rewritten->header.phoff
                      == plan->phtab_relocation.relocated_phtab_offset);
    N00B_TEST_REQUIRE(rewritten->header.phnum == bin->header.phnum + 1);
}

static void
test_loadable_apply_rejects_bad_plans(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(nullptr,
                                                                  nullptr),
                      N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  nullptr),
                      N00B_ELF_REWRITE_ERR_NULL_PLAN);

    n00b_elf_rewrite_loadable_plan_t *deferred =
        require_accepted_loadable_plan(bin, &request);
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  deferred),
                      N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);

    request.p_memsz = request.payload->byte_len - 1;
    n00b_elf_rewrite_loadable_plan_t *rejected =
        require_rejected_loadable_plan(bin,
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_ADMISSION);
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  rejected),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    n00b_elf_rewrite_loadable_plan_t *accepted =
        require_accepted_loadable_plan(bin, &request);
    accepted->payload = nullptr;
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  accepted),
                      N00B_ELF_REWRITE_ERR_APPLY);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    accepted = require_accepted_loadable_plan(bin, &request);
    uint64_t extra_start = accepted->payload_placement.file_end + 8;
    append_loadable_plan_patch(
        accepted,
        (n00b_elf_rewrite_patch_t){
            .kind                 = N00B_ELF_REWRITE_PATCH_PAYLOAD,
            .file_offset          = extra_start,
            .file_end             = extra_start + 8,
            .original_file_offset = extra_start,
            .original_file_end    = extra_start,
        });
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  accepted),
                      N00B_ELF_REWRITE_ERR_APPLY);

    accepted = require_accepted_loadable_plan(bin, &request);
    extra_start = accepted->payload_placement.file_end + 8;
    append_loadable_plan_patch(
        accepted,
        (n00b_elf_rewrite_patch_t){
            .kind                 = N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
            .file_offset          = extra_start,
            .file_end             = extra_start + 8,
            .original_file_offset = extra_start,
            .original_file_end    = extra_start,
        });
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  accepted),
                      N00B_ELF_REWRITE_ERR_APPLY);

    accepted = require_accepted_loadable_plan(bin, &request);
    N00B_TEST_REQUIRE(accepted->patches.len > 1);
    accepted->patches.data[1].file_offset =
        accepted->patches.data[0].file_offset;
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(bin,
                                                                  accepted),
                      N00B_ELF_REWRITE_ERR_APPLY);

    assert_bool_err(n00b_elf_rewrite_loadable_plan_enable_entrypoint(nullptr,
                                                                     0x401000),
                    N00B_ELF_REWRITE_ERR_NULL_PLAN);

    request = default_loadable_request();
    n00b_elf_rewrite_loadable_plan_t *deferred_for_entry =
        require_accepted_loadable_plan(bin, &request);
    assert_bool_err(
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(deferred_for_entry,
                                                         0x401000),
        N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN);
    N00B_TEST_REQUIRE(!deferred_for_entry->entrypoint_patch_enabled);

    request.p_memsz = request.payload->byte_len - 1;
    n00b_elf_rewrite_loadable_plan_t *rejected_for_entry =
        require_rejected_loadable_plan(bin,
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_ADMISSION);
    assert_bool_err(
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(rejected_for_entry,
                                                         0x401000),
        N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_loadable_apply_rejects_mismatched_source(void)
{
    const n00b_test_elf_case_t *in_place_case =
        n00b_test_elf_case_by_name("phtab_adjust_accepted");
    n00b_buffer_t *in_place_buf_a =
        n00b_test_elf_case_generate(in_place_case);
    n00b_buffer_t *in_place_buf_b =
        n00b_test_elf_case_generate(in_place_case);
    n00b_elf_binary_t *in_place_bin_a = parse_buffer(in_place_buf_a);
    n00b_elf_binary_t *in_place_bin_b = parse_buffer(in_place_buf_b);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;
    n00b_elf_rewrite_loadable_plan_t *in_place_plan =
        require_accepted_loadable_plan(in_place_bin_a, &request);

    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(
                          in_place_bin_b,
                          in_place_plan),
                      N00B_ELF_REWRITE_ERR_APPLY);

    n00b_elf_segment_t *load =
        &in_place_bin_a->segments[
            in_place_plan->phtab_adjustment.containing_load_index];
    load->filesz++;
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(
                          in_place_bin_a,
                          in_place_plan),
                      N00B_ELF_REWRITE_ERR_APPLY);

    n00b_buffer_t *in_place_buf_c =
        n00b_test_elf_case_generate(in_place_case);
    n00b_elf_binary_t *in_place_bin_c = parse_buffer(in_place_buf_c);
    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;
    n00b_elf_rewrite_loadable_plan_t *in_place_entry_plan =
        require_accepted_loadable_plan(in_place_bin_c, &request);
    auto enabled =
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(
            in_place_entry_plan,
            in_place_entry_plan->payload_placement.vaddr);
    N00B_TEST_REQUIRE(n00b_result_is_ok(enabled));
    in_place_bin_c->header.entry++;
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(
                          in_place_bin_c,
                          in_place_entry_plan),
                      N00B_ELF_REWRITE_ERR_APPLY);

    const n00b_test_elf_case_t *relocated_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_buffer_t *relocated_buf_a =
        n00b_test_elf_case_generate(relocated_case);
    n00b_buffer_t *relocated_buf_b =
        n00b_test_elf_case_generate(relocated_case);
    n00b_elf_binary_t *relocated_bin_a = parse_buffer(relocated_buf_a);
    n00b_elf_binary_t *relocated_bin_b = parse_buffer(relocated_buf_b);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    n00b_elf_rewrite_loadable_plan_t *relocated_plan =
        require_accepted_loadable_plan(relocated_bin_a, &request);

    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(
                          relocated_bin_b,
                          relocated_plan),
                      N00B_ELF_REWRITE_ERR_APPLY);

    relocated_bin_a->header.entry++;
    assert_buffer_err(n00b_elf_rewrite_apply_loadable_insert_plan(
                          relocated_bin_a,
                          relocated_plan),
                      N00B_ELF_REWRITE_ERR_APPLY);
}

static void
test_host_entrypoint_target_accepts_x86_64(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    uint64_t target_offset = 4;
    uint64_t target_size   = 8;
    n00b_elf_rewrite_host_entrypoint_target_t target =
        require_accepted_entrypoint_target(bin,
                                           plan,
                                           target_offset,
                                           target_size);

    N00B_TEST_REQUIRE(target.original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(target.replacement_entrypoint
                      == plan->payload_placement.vaddr + target_offset);
    N00B_TEST_REQUIRE(target.target_payload_offset == target_offset);
    N00B_TEST_REQUIRE(target.target_size == target_size);
    N00B_TEST_REQUIRE(target.target_file_offset
                      == plan->payload_placement.file_offset + target_offset);
    N00B_TEST_REQUIRE(target.target_file_end
                      == target.target_file_offset + target_size);
    N00B_TEST_REQUIRE(target.target_vaddr
                      == target.replacement_entrypoint);
    N00B_TEST_REQUIRE(target.target_vaddr_end
                      == target.target_vaddr + target_size);
    N00B_TEST_REQUIRE(target.payload_file_offset
                      == plan->payload_placement.file_offset);
    N00B_TEST_REQUIRE(target.payload_file_end
                      == plan->payload_placement.file_end);
    N00B_TEST_REQUIRE(target.payload_vaddr == plan->payload_placement.vaddr);
    N00B_TEST_REQUIRE(target.payload_vaddr_end
                      == plan->payload_placement.vaddr_end);
    N00B_TEST_REQUIRE(target.payload_file_size == plan->payload->byte_len);
    N00B_TEST_REQUIRE(target.payload_memory_size == plan->p_memsz);
    N00B_TEST_REQUIRE(!target.trampoline_emitted);
    N00B_TEST_REQUIRE(target.trampoline_size == 0);

    auto enabled =
        n00b_elf_rewrite_loadable_plan_enable_entrypoint(
            plan,
            target.replacement_entrypoint);
    N00B_TEST_REQUIRE(n00b_result_is_ok(enabled));
    N00B_TEST_REQUIRE(n00b_result_get(enabled));

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_loadable_plan_and_parse(buf, bin, plan, &rewritten);
    N00B_TEST_REQUIRE(rewritten->header.entry
                      == target.replacement_entrypoint);
}

static void
test_host_entrypoint_target_accepts_in_place_plan(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("phtab_adjust_accepted");
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;

    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    n00b_elf_rewrite_host_entrypoint_target_t target =
        require_accepted_entrypoint_target(bin, plan, 0, 4);

    N00B_TEST_REQUIRE(target.replacement_entrypoint
                      == plan->payload_placement.vaddr);
    N00B_TEST_REQUIRE(target.original_entrypoint == bin->header.entry);
    N00B_TEST_REQUIRE(!target.trampoline_emitted);
}

static void
test_host_entrypoint_target_rejects_architecture(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;

    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    bin->header.ident[EI_CLASS] = ELFCLASS32;
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CLASS);

    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    bin->header.ident[EI_DATA] = ELFDATA2MSB;
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_ENDIAN);

    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    bin->header.machine = EM_AARCH64;
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_MACHINE);
}

static void
test_host_entrypoint_target_rejects_bad_plan_shapes(void)
{
    n00b_elf_binary_t *bin = parse_buffer(valid_target_buffer());
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    assert_entrypoint_target_err(
        n00b_elf_rewrite_plan_host_entrypoint_target(nullptr,
                                                     nullptr,
                                                     0,
                                                     4),
        N00B_ELF_REWRITE_ERR_NULL_BINARY);
    assert_entrypoint_target_err(
        n00b_elf_rewrite_plan_host_entrypoint_target(bin,
                                                     nullptr,
                                                     0,
                                                     4),
        N00B_ELF_REWRITE_ERR_NULL_PLAN);

    n00b_elf_rewrite_loadable_plan_t *deferred =
        require_accepted_loadable_plan(bin, &request);
    (void)require_rejected_entrypoint_target(
        bin,
        deferred,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN);

    request.p_memsz = request.payload->byte_len - 1;
    n00b_elf_rewrite_loadable_plan_t *rejected =
        require_rejected_loadable_plan(bin,
                                       &request,
                                       N00B_ELF_REWRITE_REJECT_ADMISSION);
    (void)require_rejected_entrypoint_target(
        bin,
        rejected,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN);
}

static void
test_host_entrypoint_target_rejects_unsafe_targets(void)
{
    const n00b_test_elf_case_t *test_case =
        n00b_test_elf_case_by_name("loadable_relocate_direct");
    n00b_elf_rewrite_loadable_request_t request =
        default_loadable_request();

    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    request.segment_flags = PF_R;
    n00b_elf_binary_t *bin =
        parse_buffer(n00b_test_elf_case_generate(test_case));
    n00b_elf_rewrite_loadable_plan_t *plan =
        require_accepted_loadable_plan(bin, &request);
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NON_EXECUTABLE);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        plan->payload->byte_len,
        1,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    request.p_memsz = request.payload->byte_len + 8;
    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        plan->payload->byte_len - 4,
        8,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_MEMORY_ONLY);

    request = default_loadable_request();
    request.phtab_strategy =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    plan->payload_placement.vaddr_end = plan->payload_placement.vaddr + 1;
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        0,
        4,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE);

    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        UINT64_MAX,
        2,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW);

    bin = parse_buffer(n00b_test_elf_case_generate(test_case));
    plan = require_accepted_loadable_plan(bin, &request);
    plan->payload_placement.vaddr = UINT64_MAX - 1;
    plan->payload_placement.vaddr_end = UINT64_MAX;
    (void)require_rejected_entrypoint_target(
        bin,
        plan,
        1,
        1,
        N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW);
}

static void
test_valid_plan_tail_incision(void)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan(valid_target_buffer(), &request);

    N00B_TEST_REQUIRE(plan->original_section_count == 2);
    N00B_TEST_REQUIRE(plan->new_section_count == 3);
    N00B_TEST_REQUIRE(plan->payload_offset == 400);
    N00B_TEST_REQUIRE(plan->payload_end == 416);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);
    assert_patches_ordered(plan);
}

static n00b_buffer_t *
in_place_growth_buffer(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    uint8_t       *p   = (uint8_t *)buf->data;

    buf->byte_len = 512;
    for (size_t i = 384; i < 512; i++) {
        p[i] = 0;
    }
    n00b_test_elf_write_shstrtab(p, 448, true);
    n00b_test_elf_put64(p + SHSTRTAB_SH + SH_OFFSET, 448);
    n00b_test_elf_put64(p + SHSTRTAB_SH + SH_SIZE, 11);
    add_note_segment(buf, 500, 12);
    return buf;
}

static n00b_buffer_t *
in_place_growth_unterminated_buffer(void)
{
    n00b_buffer_t *buf = in_place_growth_buffer();
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_shstrtab(p, 448, false);
    n00b_test_elf_put64(p + SHSTRTAB_SH + SH_SIZE, 10);
    return buf;
}

static void
test_table_strategy_in_place_growth(void)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan(in_place_growth_buffer(), &request);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH);
    assert_patches_ordered(plan);
}

static void
test_in_place_growth_rejects_modeled_zero_slack(void)
{
    n00b_buffer_t *buf = in_place_growth_buffer();
    add_note_segment(buf, 384, 128);

    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan = require_accepted_plan(buf, &request);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT);
    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(tables->file_offset == plan->payload_end);
    assert_patches_ordered(plan);
}

static void
test_in_place_growth_rejects_payload_slack_overlap(void)
{
    n00b_buffer_t *buf = in_place_growth_buffer();
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.preferred_file_offset = n00b_option_set(uint64_t, 384);

    n00b_elf_rewrite_plan_t *plan = require_accepted_plan(buf, &request);
    n00b_elf_rewrite_admit_placement_t placement =
        n00b_option_get(plan->admission.placement);

    N00B_TEST_REQUIRE(placement.kind
                      == N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP);
    N00B_TEST_REQUIRE(plan->payload_offset == 384);
    N00B_TEST_REQUIRE(plan->payload_end == 400);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT);

    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(tables->file_offset == buf->byte_len);
    assert_patches_ordered(plan);
}

static void
test_tail_incision_rejects_modeled_zero_tail(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    add_note_segment(buf, 400, 16);

    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan = require_accepted_plan(buf, &request);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT);
    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(tables->file_offset == plan->payload_end);
    assert_patches_ordered(plan);
}

static void
test_apply_tail_incision_shtab_then_shstrtab(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_TABLE_TAIL)
                      != nullptr);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
}

static void
test_apply_tail_incision_shstrtab_then_shtab(void)
{
    n00b_buffer_t *buf = shstrtab_then_shtab_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_patch_t *tail =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_TABLE_TAIL);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);
    N00B_TEST_REQUIRE(tail != nullptr);
    N00B_TEST_REQUIRE(tail->file_offset == plan->target_profile.shstrtab_offset);
    N00B_TEST_REQUIRE(plan->target_profile.shstrtab_offset < bin->header.shoff);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
}

static void
test_tail_incision_uses_higher_terminal_candidate(void)
{
    n00b_buffer_t *buf = higher_terminal_tail_candidate_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_patch_t *tail =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_TABLE_TAIL);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);
    N00B_TEST_REQUIRE(tail != nullptr);
    N00B_TEST_REQUIRE(tail->file_offset == bin->header.shoff);
    N00B_TEST_REQUIRE(tail->file_offset
                      > plan->target_profile.shstrtab_offset);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
}

static void
test_apply_convenience_wrapper(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_buffer_t *snapshot = n00b_buffer_new((int64_t)buf->byte_len);

    memcpy(snapshot->data, buf->data, buf->byte_len);
    snapshot->byte_len = buf->byte_len;

    auto applied = n00b_elf_rewrite_apply_metadata_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *output = n00b_result_get(applied);
    n00b_elf_binary_t *rewritten = parse_buffer(output);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    assert_unplanned_original_bytes_preserved(snapshot, output, plan);
    N00B_TEST_REQUIRE(buf->byte_len == snapshot->byte_len);
    N00B_TEST_REQUIRE(memcmp(buf->data,
                             snapshot->data,
                             snapshot->byte_len) == 0);

    request = default_request();
    request.section_name = r".chalk.mark";
    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert(bin, &request),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_apply_big_endian_tail_incision(void)
{
    n00b_buffer_t *buf = valid_big_endian_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);

    N00B_TEST_REQUIRE(bin->header.ident[EI_DATA] == ELFDATA2MSB);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *output = apply_plan_and_parse(buf, bin, plan, &rewritten);
    const uint8_t *raw = (const uint8_t *)output->data;

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    N00B_TEST_REQUIRE(raw[EI_DATA] == ELFDATA2MSB);
    N00B_TEST_REQUIRE(get64_be(raw + E_SHOFF) == rewritten->header.shoff);
    N00B_TEST_REQUIRE(get16_be(raw + E_SHNUM) == rewritten->header.shnum);
    N00B_TEST_REQUIRE(get16_be(raw + E_SHSTRNDX)
                      == rewritten->header.shstrndx);

    uint64_t shstrtab_sh = rewritten->header.shoff
                         + rewritten->header.shstrndx * 64;
    uint64_t new_sh = rewritten->header.shoff
                    + (rewritten->header.shnum - 1) * 64;
    n00b_elf_section_t *shstrtab =
        &rewritten->sections[rewritten->header.shstrndx];
    n00b_elf_section_t *inserted =
        require_section_named(rewritten, request.section_name);

    N00B_TEST_REQUIRE(get32_be(raw + shstrtab_sh + SH_TYPE) == SHT_STRTAB);
    N00B_TEST_REQUIRE(get64_be(raw + shstrtab_sh + SH_OFFSET)
                      == shstrtab->offset);
    N00B_TEST_REQUIRE(get64_be(raw + shstrtab_sh + SH_SIZE)
                      == shstrtab->size);
    N00B_TEST_REQUIRE(get32_be(raw + new_sh + SH_TYPE)
                      == request.section_type);
    N00B_TEST_REQUIRE(get64_be(raw + new_sh + SH_OFFSET)
                      == inserted->offset);
    N00B_TEST_REQUIRE(get64_be(raw + new_sh + SH_SIZE)
                      == request.payload->byte_len);
}

static void
test_apply_minimal_dyn_tail_incision(void)
{
    n00b_buffer_t *buf = valid_dyn_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);

    N00B_TEST_REQUIRE(bin->header.type == ET_DYN);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    N00B_TEST_REQUIRE(rewritten->header.type == ET_DYN);
    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
}

static n00b_buffer_t *
overlay_target_buffer(void)
{
    return n00b_test_elf_minimal_exec(0x400080,
                                      0,
                                      0x400000,
                                      512,
                                      512,
                                      true,
                                      false,
                                      true,
                                      true);
}

static void
test_overlay_preserve_without_append_rejects(void)
{
    n00b_buffer_t *buf = overlay_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_rejected_plan_for_bin(bin,
                                      &request,
                                      N00B_ELF_REWRITE_REJECT_ADMISSION);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_apply_append_after_overlay(void)
{
    n00b_buffer_t *buf = overlay_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.policy.flags |= N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);

    N00B_TEST_REQUIRE(n00b_option_is_set(plan->admission.placement));
    N00B_TEST_REQUIRE(n00b_option_get(plan->admission.placement).kind
                      == N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(plan->payload_offset >= buf->byte_len);
    N00B_TEST_REQUIRE(tables->file_offset == plan->payload_end);
    N00B_TEST_REQUIRE(tables->file_offset > buf->byte_len);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *out = apply_plan_and_parse(buf, bin, plan, &rewritten);
    n00b_elf_section_t *live_shstrtab =
        &rewritten->sections[rewritten->header.shstrndx];

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    assert_overlay_bytes_preserved(buf, out, bin);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_offset,
                             request.payload->data,
                             request.payload->byte_len) == 0);
    N00B_TEST_REQUIRE(live_shstrtab->offset == tables->file_offset);
    N00B_TEST_REQUIRE(rewritten->header.shoff
                      == live_shstrtab->offset + live_shstrtab->size);
}

static void
test_preferred_gap_payload_appends_tables_at_eof(void)
{
    n00b_buffer_t *buf =
        n00b_test_elf_case_generate(n00b_test_elf_case_by_name(
            "layout_classification"));
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.policy.flags = N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY;
    request.preferred_file_offset = n00b_option_set(uint64_t, 288);

    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_admit_placement_t placement =
        n00b_option_get(plan->admission.placement);

    N00B_TEST_REQUIRE(placement.kind
                      == N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP);
    N00B_TEST_REQUIRE(plan->payload_offset == 288);
    N00B_TEST_REQUIRE(plan->payload_end == 304);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT);

    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
    n00b_elf_rewrite_patch_t *payload =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_PAYLOAD);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(payload != nullptr);
    N00B_TEST_REQUIRE(payload->original_file_offset == plan->payload_offset);
    N00B_TEST_REQUIRE(payload->original_file_end == plan->payload_end);
    N00B_TEST_REQUIRE(tables->file_offset == buf->byte_len);
    N00B_TEST_REQUIRE(tables->file_offset > plan->payload_end);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *out = apply_plan_and_parse(buf, bin, plan, &rewritten);
    n00b_elf_section_t *live_shstrtab =
        &rewritten->sections[rewritten->header.shstrndx];

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_offset,
                             request.payload->data,
                             request.payload->byte_len) == 0);
    N00B_TEST_REQUIRE(live_shstrtab->offset == tables->file_offset);
    N00B_TEST_REQUIRE(rewritten->header.shoff
                      == live_shstrtab->offset + live_shstrtab->size);
    assert_original_range_preserved(buf, out, 64, 80);
    assert_original_range_preserved(buf, out, 240, 288);
    assert_original_range_preserved(buf, out, 304, 320);
}

static void
test_apply_in_place_growth(void)
{
    n00b_buffer_t *buf = in_place_growth_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_patch_t *strtab_patch =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB);

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH);
    N00B_TEST_REQUIRE(strtab_patch != nullptr);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    N00B_TEST_REQUIRE(rewritten->header.shoff == bin->header.shoff);
    N00B_TEST_REQUIRE(rewritten->sections[rewritten->header.shstrndx].offset
                      == strtab_patch->file_offset);
    N00B_TEST_REQUIRE(rewritten->sections[rewritten->header.shstrndx].size
                      == strtab_patch->file_end - strtab_patch->file_offset);
}

static void
test_apply_unterminated_in_place_growth_terminates(void)
{
    n00b_buffer_t *buf = in_place_growth_unterminated_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);

    N00B_TEST_REQUIRE(plan->target_profile.shstrtab_requires_terminator);
    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);

    n00b_elf_section_t *shstrtab =
        &rewritten->sections[rewritten->header.shstrndx];
    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    N00B_TEST_REQUIRE(shstrtab->content->byte_len
                      > plan->target_profile.shstrtab_reported_size);
    N00B_TEST_REQUIRE(shstrtab->content->data[
                          plan->target_profile.shstrtab_reported_size] == '\0');
}

static void
test_apply_eof_replacement_fallback(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    add_note_segment(buf, 400, 16);

    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan_for_bin(bin, &request);
    n00b_elf_rewrite_patch_t *tables =
        find_patch(plan, N00B_ELF_REWRITE_PATCH_APPENDED_TABLES);
    uint64_t old_shtab_size = plan->original_section_count * 64;

    N00B_TEST_REQUIRE(plan->table_strategy
                      == N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT);
    N00B_TEST_REQUIRE(tables != nullptr);
    N00B_TEST_REQUIRE(tables->file_offset == plan->payload_end);

    n00b_elf_binary_t *rewritten = nullptr;
    n00b_buffer_t *out = apply_plan_and_parse(buf, bin, plan, &rewritten);

    assert_inserted_section(rewritten, plan, &request);
    assert_live_shstrtab_terminated(rewritten);
    assert_loader_metadata_preserved(bin, rewritten);
    N00B_TEST_REQUIRE(rewritten->header.shoff != bin->header.shoff);
    N00B_TEST_REQUIRE(memcmp(out->data + bin->header.shoff,
                             buf->data + bin->header.shoff,
                             (size_t)old_shtab_size) == 0);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->target_profile.shstrtab_offset,
                             buf->data + plan->target_profile.shstrtab_offset,
                             (size_t)plan->target_profile.shstrtab_reported_size)
                      == 0);
}

static void
test_preferred_gap_rejects_nonzero_unknown(void)
{
    n00b_buffer_t *buf =
        n00b_test_elf_case_generate(n00b_test_elf_case_by_name(
            "layout_nonzero_unknown"));
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.policy.flags = N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY;
    request.preferred_file_offset = n00b_option_set(uint64_t, 288);

    n00b_elf_rewrite_plan_t *plan =
        require_rejected_plan_for_bin(bin,
                                      &request,
                                      N00B_ELF_REWRITE_REJECT_ADMISSION);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES);
    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_admission_rejection_propagates(void)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();

    request.section_name = r".chalk.mark";
    n00b_elf_rewrite_plan_t *plan =
        require_rejected_plan(valid_target_buffer(),
                              &request,
                              N00B_ELF_REWRITE_REJECT_ADMISSION);

    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);

    request = default_request();
    request.section_name = r".chalk.any";
    plan = require_rejected_plan(valid_target_buffer(),
                                 &request,
                                 N00B_ELF_REWRITE_REJECT_ADMISSION);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);

    request = default_request();
    request.section_name = r".0c001.any";
    plan = require_rejected_plan(valid_target_buffer(),
                                 &request,
                                 N00B_ELF_REWRITE_REJECT_ADMISSION);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);
}

static void
test_object_bundle_ordinary_insert_rejects_reserved_name(void)
{
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x50, 24);
    n00b_elf_rewrite_plan_t *plan =
        require_rejected_plan(valid_target_buffer(),
                              &request,
                              N00B_ELF_REWRITE_REJECT_ADMISSION);

    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);

    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    assert_buffer_err(n00b_elf_rewrite_apply_metadata_insert(bin,
                                                             &request),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_trusted_object_bundle_insert_policy(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x51, 24);

    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_METADATA_INSERT);
    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_object_bundle_plan_and_parse(buf, bin, plan, &rewritten);
    n00b_elf_section_t *bundle =
        require_section_named(rewritten, r".0c001.bundle");
    assert_object_bundle_section(bundle, &request);
    N00B_TEST_REQUIRE(count_sections_named(rewritten, r".0c001.bundle") == 1);

    n00b_string_t *bad_names[] = {
        r".0c001.file",
        r".0c001.wrap",
        r".0c001.code",
        r".0c001.extra",
        r".chalk.mark",
        r".chalk.free",
        r".n00b.test",
    };

    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        request = object_bundle_request(0x52, 16);
        request.section_name = bad_names[i];

        plan_result =
            n00b_elf_rewrite_plan_object_bundle_insert(bin, &request);
        N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
        plan = n00b_result_get(plan_result);
        N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
        N00B_TEST_REQUIRE(plan->rejection_reason
                          == N00B_ELF_REWRITE_REJECT_ADMISSION);
        N00B_TEST_REQUIRE(plan->admission.rejection_reason
                          == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);
    }

    request = object_bundle_request(0x53, 16);
    request.section_type = SHT_NOTE;
    plan_result = n00b_elf_rewrite_plan_object_bundle_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA);

    request = object_bundle_request(0x54, 16);
    request.section_flags = SHF_ALLOC;
    plan_result = n00b_elf_rewrite_plan_object_bundle_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA);

    request = object_bundle_request(0x55, 16);
    request.section_type = 0xc001u;
    plan_result = n00b_elf_rewrite_plan_object_bundle_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA);
}

static n00b_buffer_t *
trusted_marked_buffer(uint8_t fill,
                      size_t len,
                      n00b_elf_rewrite_plan_t **plan_out)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(fill, len);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_METADATA_INSERT);
    N00B_TEST_REQUIRE(plan->section_name == request.section_name);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *marked = nullptr;
    n00b_buffer_t *out = apply_plan_and_parse(buf, bin, plan, &marked);

    assert_inserted_section(marked, plan, &request);
    N00B_TEST_REQUIRE(count_sections_named(marked, r".chalk.mark") == 1);

    if (plan_out != nullptr) {
        *plan_out = plan;
    }
    return out;
}

static n00b_buffer_t *
trusted_bundle_buffer(uint8_t fill,
                      size_t len,
                      n00b_elf_rewrite_plan_t **plan_out)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(fill, len);

    auto plan_result = n00b_elf_rewrite_plan_object_bundle_insert(bin,
                                                                  &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_METADATA_INSERT);
    N00B_TEST_REQUIRE(plan->section_name == request.section_name);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *bundled = nullptr;
    n00b_buffer_t *out =
        apply_object_bundle_plan_and_parse(buf, bin, plan, &bundled);

    assert_inserted_section(bundled, plan, &request);
    N00B_TEST_REQUIRE(count_sections_named(bundled, r".0c001.bundle") == 1);

    if (plan_out != nullptr) {
        *plan_out = plan;
    }
    return out;
}

static void
test_direct_trusted_chalk_mark_admit_public_api(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_admit_metadata_request_t request =
        chalk_mark_admit_request(24);

    auto admit_result = n00b_elf_rewrite_admit_chalk_mark_insert(bin,
                                                                 &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(admit_result));
    n00b_elf_rewrite_admit_result_t admit = n00b_result_get(admit_result);

    N00B_TEST_REQUIRE(admit.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    N00B_TEST_REQUIRE(admit.rejection_reason
                      == N00B_ELF_REWRITE_ADMIT_REJECT_NONE);
    N00B_TEST_REQUIRE(n00b_option_is_set(admit.placement));

    n00b_string_t *bad_names[] = {
        r".chalk.free",
        r".chalk.any",
        r".0c001.any",
        r".n00b.test",
    };

    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        request = chalk_mark_admit_request(16);
        request.section_name = bad_names[i];

        admit_result = n00b_elf_rewrite_admit_chalk_mark_insert(bin,
                                                                &request);
        N00B_TEST_REQUIRE(n00b_result_is_ok(admit_result));
        admit = n00b_result_get(admit_result);
        N00B_TEST_REQUIRE(admit.outcome
                          == N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED);
        N00B_TEST_REQUIRE(admit.rejection_reason
                          == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);
    }
}

static void
test_trusted_chalk_mark_insert_policy(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(0x43, 24);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                               &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->admission.outcome
                      == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *rewritten = nullptr;
    (void)apply_plan_and_parse(buf, bin, plan, &rewritten);
    assert_inserted_section(rewritten, plan, &request);
    N00B_TEST_REQUIRE(count_sections_named(rewritten, r".chalk.mark") == 1);

    n00b_string_t *bad_names[] = {
        r".chalk.free",
        r".chalk.any",
        r".0c001.any",
        r".n00b.test",
    };

    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        request = chalk_mark_request(0x44, 16);
        request.section_name = bad_names[i];

        plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                              &request);
        N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
        plan = n00b_result_get(plan_result);
        N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
        N00B_TEST_REQUIRE(plan->rejection_reason
                          == N00B_ELF_REWRITE_REJECT_ADMISSION);
        N00B_TEST_REQUIRE(plan->admission.rejection_reason
                          == N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);
    }
}

static void
test_apply_chalk_mark_delete_wrapper_public_api(void)
{
    n00b_buffer_t *marked_bytes = trusted_marked_buffer(0x65, 32, nullptr);
    n00b_elf_binary_t *marked = parse_buffer(marked_bytes);
    n00b_elf_section_t *old_mark =
        require_section_named(marked, r".chalk.mark");
    uint64_t old_payload_offset = old_mark->offset;
    uint64_t old_payload_end = old_mark->offset + old_mark->size;

    auto applied = n00b_elf_rewrite_apply_chalk_mark_delete(marked);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *out = n00b_result_get(applied);
    n00b_elf_binary_t *unchalked = parse_buffer(out);

    assert_no_section_named(unchalked, r".chalk.mark");
    assert_range_zeroed(out, old_payload_offset, old_payload_end);
}

static void
test_chalk_mark_delete_removes_live_section_and_zeroes_payload(void)
{
    n00b_buffer_t *marked_bytes = trusted_marked_buffer(0x5a, 32, nullptr);
    n00b_elf_binary_t *marked = parse_buffer(marked_bytes);
    n00b_elf_section_t *old_mark =
        require_section_named(marked, r".chalk.mark");

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_delete(marked);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_CHALK_MARK_DELETE);
    N00B_TEST_REQUIRE(plan->new_section_count
                      == plan->original_section_count - 1);
    N00B_TEST_REQUIRE(plan->removed_payload_offset == old_mark->offset);
    N00B_TEST_REQUIRE(plan->removed_payload_end
                      == old_mark->offset + old_mark->size);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD)
                      != nullptr);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *unchalked = nullptr;
    n00b_buffer_t *out =
        apply_chalk_plan_and_parse(marked_bytes, marked, plan, &unchalked);

    assert_no_section_named(unchalked, r".chalk.mark");
    N00B_TEST_REQUIRE(unchalked->header.shnum == plan->new_section_count);
    assert_range_zeroed(out,
                        plan->removed_payload_offset,
                        plan->removed_payload_end);
}

static void
test_chalk_mark_delete_replace_reject_colliding_payload(void)
{
    n00b_buffer_t *marked_bytes = trusted_marked_buffer(0x71, 32, nullptr);
    n00b_elf_binary_t *marked = parse_buffer(marked_bytes);
    uint32_t mark_index = require_section_index_named(marked, r".chalk.mark");
    uint64_t shdr_offset = marked->header.shoff
                         + (uint64_t)mark_index * marked->header.shentsize;

    N00B_TEST_REQUIRE(shdr_offset + SH_OFFSET + 8 <= marked_bytes->byte_len);
    n00b_test_elf_put64((uint8_t *)marked_bytes->data
                            + shdr_offset
                            + SH_OFFSET,
                        0);

    marked = parse_buffer(marked_bytes);
    n00b_elf_section_t *old_mark =
        require_section_named(marked, r".chalk.mark");
    N00B_TEST_REQUIRE(old_mark->offset == 0);

    auto delete_plan = n00b_elf_rewrite_plan_chalk_mark_delete(marked);
    N00B_TEST_REQUIRE(n00b_result_is_ok(delete_plan));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(delete_plan);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED);
    assert_buffer_err(n00b_elf_rewrite_apply_chalk_mark_delete(marked),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);

    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(0x72, 24);
    auto replace_plan = n00b_elf_rewrite_plan_chalk_mark_replace(marked,
                                                                 &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(replace_plan));
    plan = n00b_result_get(replace_plan);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED);
    assert_buffer_err(n00b_elf_rewrite_apply_chalk_mark_replace(marked,
                                                                &request),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_apply_chalk_mark_replace_wrapper_public_api(void)
{
    n00b_buffer_t *marked_bytes = trusted_marked_buffer(0x6d, 20, nullptr);
    n00b_elf_binary_t *marked = parse_buffer(marked_bytes);
    n00b_elf_section_t *old_mark =
        require_section_named(marked, r".chalk.mark");
    uint64_t old_payload_offset = old_mark->offset;
    uint64_t old_payload_end = old_mark->offset + old_mark->size;
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(0x7d, 28);

    auto applied = n00b_elf_rewrite_apply_chalk_mark_replace(marked,
                                                             &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *out = n00b_result_get(applied);
    n00b_elf_binary_t *remarked = parse_buffer(out);
    n00b_elf_section_t *new_mark =
        require_section_named(remarked, r".chalk.mark");

    N00B_TEST_REQUIRE(count_sections_named(remarked, r".chalk.mark") == 1);
    N00B_TEST_REQUIRE(new_mark->size == request.payload->byte_len);
    N00B_TEST_REQUIRE(new_mark->content != nullptr);
    N00B_TEST_REQUIRE(memcmp(new_mark->content->data,
                             request.payload->data,
                             request.payload->byte_len) == 0);
    assert_range_zeroed(out, old_payload_offset, old_payload_end);
}

static void
test_chalk_mark_replace_produces_one_live_mark(void)
{
    n00b_buffer_t *marked_bytes = trusted_marked_buffer(0x61, 20, nullptr);
    n00b_elf_binary_t *marked = parse_buffer(marked_bytes);
    n00b_elf_section_t *old_mark =
        require_section_named(marked, r".chalk.mark");
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(0x7c, 28);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_replace(marked,
                                                                &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_CHALK_MARK_REPLACE);
    N00B_TEST_REQUIRE(plan->new_section_count
                      == plan->original_section_count);
    N00B_TEST_REQUIRE(plan->removed_payload_offset == old_mark->offset);
    N00B_TEST_REQUIRE(plan->removed_payload_end
                      == old_mark->offset + old_mark->size);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD)
                      != nullptr);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_PAYLOAD)
                      != nullptr);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *remarked = nullptr;
    n00b_buffer_t *out =
        apply_chalk_plan_and_parse(marked_bytes, marked, plan, &remarked);
    n00b_elf_section_t *new_mark =
        require_section_named(remarked, r".chalk.mark");

    N00B_TEST_REQUIRE(count_sections_named(remarked, r".chalk.mark") == 1);
    N00B_TEST_REQUIRE(new_mark->offset == plan->payload_offset);
    N00B_TEST_REQUIRE(new_mark->size == request.payload->byte_len);
    N00B_TEST_REQUIRE(new_mark->content != nullptr);
    N00B_TEST_REQUIRE(memcmp(new_mark->content->data,
                             request.payload->data,
                             request.payload->byte_len) == 0);
    assert_range_zeroed(out,
                        plan->removed_payload_offset,
                        plan->removed_payload_end);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_offset,
                             request.payload->data,
                             request.payload->byte_len) == 0);
}

static void
test_apply_object_bundle_insert_wrapper_public_api(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    n00b_elf_binary_t *bin = parse_buffer(buf);
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x80, 24);

    auto applied = n00b_elf_rewrite_apply_object_bundle_insert(bin,
                                                               &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *out = n00b_result_get(applied);
    n00b_elf_binary_t *bundled = parse_buffer(out);
    n00b_elf_section_t *bundle =
        require_section_named(bundled, r".0c001.bundle");

    assert_object_bundle_section(bundle, &request);
    N00B_TEST_REQUIRE(count_sections_named(bundled, r".0c001.bundle") == 1);
}

static void
test_object_bundle_replace_produces_one_live_bundle(void)
{
    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x81, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    n00b_elf_section_t *old_bundle =
        require_section_named(bundled, r".0c001.bundle");
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x82, 28);

    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(plan->operation
                      == N00B_ELF_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE);
    N00B_TEST_REQUIRE(plan->new_section_count
                      == plan->original_section_count);
    N00B_TEST_REQUIRE(plan->removed_payload_offset == old_bundle->offset);
    N00B_TEST_REQUIRE(plan->removed_payload_end
                      == old_bundle->offset + old_bundle->size);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD)
                      != nullptr);
    N00B_TEST_REQUIRE(find_patch(plan, N00B_ELF_REWRITE_PATCH_PAYLOAD)
                      != nullptr);
    assert_patches_ordered(plan);

    n00b_elf_binary_t *replaced = nullptr;
    n00b_buffer_t *out =
        apply_object_bundle_plan_and_parse(bundled_bytes,
                                           bundled,
                                           plan,
                                           &replaced);
    n00b_elf_section_t *new_bundle =
        require_section_named(replaced, r".0c001.bundle");

    N00B_TEST_REQUIRE(count_sections_named(replaced, r".0c001.bundle") == 1);
    N00B_TEST_REQUIRE(new_bundle->offset == plan->payload_offset);
    assert_object_bundle_section(new_bundle, &request);
    assert_range_zeroed(out,
                        plan->removed_payload_offset,
                        plan->removed_payload_end);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_offset,
                             request.payload->data,
                             request.payload->byte_len) == 0);
}

static void
test_apply_object_bundle_replace_wrapper_public_api(void)
{
    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x83, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    n00b_elf_section_t *old_bundle =
        require_section_named(bundled, r".0c001.bundle");
    uint64_t old_payload_offset = old_bundle->offset;
    uint64_t old_payload_end = old_bundle->offset + old_bundle->size;
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x84, 32);

    auto applied = n00b_elf_rewrite_apply_object_bundle_replace(bundled,
                                                                &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *out = n00b_result_get(applied);
    n00b_elf_binary_t *replaced = parse_buffer(out);
    n00b_elf_section_t *new_bundle =
        require_section_named(replaced, r".0c001.bundle");

    N00B_TEST_REQUIRE(count_sections_named(replaced, r".0c001.bundle") == 1);
    assert_object_bundle_section(new_bundle, &request);
    assert_range_zeroed(out, old_payload_offset, old_payload_end);
}

static void
test_object_bundle_replace_rejects_absent_and_duplicate(void)
{
    n00b_elf_binary_t *bin = parse_buffer(valid_target_buffer());
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x85, 24);

    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND);

    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x86, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    duplicate_object_bundle_section_name(bundled_bytes, bundled);
    bundled = parse_buffer(bundled_bytes);

    plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE);
}

static void
test_object_bundle_replace_rejects_malformed_existing_carrier(void)
{
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x87, 24);

    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x88, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    mutate_object_bundle_section_type(bundled_bytes, bundled, SHT_NOTE);
    bundled = parse_buffer(bundled_bytes);

    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED);

    bundled_bytes = trusted_bundle_buffer(0x89, 20, nullptr);
    bundled = parse_buffer(bundled_bytes);
    mutate_object_bundle_section_flags(bundled_bytes, bundled, SHF_ALLOC);
    bundled = parse_buffer(bundled_bytes);

    plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED);

    bundled_bytes = trusted_bundle_buffer(0x8a, 20, nullptr);
    bundled = parse_buffer(bundled_bytes);
    mutate_object_bundle_section_size(bundled_bytes, bundled, 0);
    bundled = parse_buffer(bundled_bytes);

    plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED);
}

static void
test_object_bundle_replace_rejects_shared_payload_range(void)
{
    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x8b, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x8c, 24);

    mutate_object_bundle_section_offset(bundled_bytes, bundled, 0);
    bundled = parse_buffer(bundled_bytes);
    n00b_elf_section_t *old_bundle =
        require_section_named(bundled, r".0c001.bundle");
    N00B_TEST_REQUIRE(old_bundle->offset == 0);

    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED);
    assert_buffer_err(n00b_elf_rewrite_apply_object_bundle_replace(bundled,
                                                                   &request),
                      N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_object_bundle_replace_rejects_wrong_request_shape(void)
{
    n00b_buffer_t *bundled_bytes = trusted_bundle_buffer(0x8d, 20, nullptr);
    n00b_elf_binary_t *bundled = parse_buffer(bundled_bytes);
    n00b_elf_rewrite_metadata_request_t request =
        object_bundle_request(0x8e, 24);
    n00b_string_t *bad_names[] = {
        r".0c001.file",
        r".0c001.wrap",
        r".0c001.code",
        r".0c001.extra",
        r".chalk.mark",
        r".n00b.test",
    };

    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
        request = object_bundle_request(0x8f, 24);
        request.section_name = bad_names[i];

        auto plan_result =
            n00b_elf_rewrite_plan_object_bundle_replace(bundled,
                                                        &request);
        N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
        n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
        N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
        N00B_TEST_REQUIRE(plan->rejection_reason
                          == N00B_ELF_REWRITE_REJECT_TRUSTED_NAME);
    }

    request = object_bundle_request(0x90, 24);
    request.section_type = SHT_NOTE;
    auto plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_TRUSTED_NAME);

    request = object_bundle_request(0x91, 24);
    request.section_flags = SHF_ALLOC;
    plan_result =
        n00b_elf_rewrite_plan_object_bundle_replace(bundled, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));
    plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_TRUSTED_NAME);
}

static void
test_packager_profile_matrix(void)
{
    static const profile_case_t cases[] = {
        {"e_ehsize", mutate_ehsize,
         N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE, 11},
        {"e_shentsize", mutate_shentsize,
         N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE, 15},
        {"e_phentsize", mutate_phentsize,
         N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE, 16},
        {"e_shnum_zero", mutate_shnum_zero,
         N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE, 18},
        {"e_shnum_one", mutate_shnum_one,
         N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE, 18},
        {"e_shnum_loreserve", mutate_shnum_loreserve,
         N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO, 17},
        {"e_shnum_xindex", mutate_shnum_xindex,
         N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO, 17},
        {"e_shoff_zero", mutate_shoff_zero,
         N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE, 18},
        {"e_shstrndx_zero", mutate_shstrndx_zero,
         N00B_ELF_REWRITE_PROFILE_NO_STRTAB, 24},
        {"e_shstrndx_loreserve", mutate_shstrndx_loreserve,
         N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO, 26},
        {"e_shstrndx_xindex", mutate_shstrndx_xindex,
         N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO, 26},
        {"e_shstrndx_out_of_range", mutate_shstrndx_out_of_range,
         N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX, 27},
        {"shstrtab_wrong_type", mutate_shstrtab_type,
         N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE, 28},
        {"shstrtab_bounds", mutate_shstrtab_bounds,
         N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE, 29},
        {"section_name_index", mutate_section_name_index,
         N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX, 35},
        {"e_phnum_zero", mutate_phnum_zero,
         N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM, 20},
        {"e_phnum_xnum", mutate_phnum_xnum,
         N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM, 21},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        n00b_buffer_t *buf = valid_target_buffer();
        cases[i].mutate(buf);

        n00b_elf_rewrite_metadata_request_t request = default_request();
        n00b_elf_rewrite_plan_t *plan =
            require_rejected_plan(buf,
                                  &request,
                                  N00B_ELF_REWRITE_REJECT_TARGET_PROFILE);

        N00B_TEST_REQUIRE(plan->target_profile.reason == cases[i].reason);
        N00B_TEST_REQUIRE(plan->target_profile.packager_errcode
                          == cases[i].packager_errcode);
        (void)cases[i].name;
    }
}

static void
test_unterminated_shstrtab_is_profile_ok(void)
{
    n00b_buffer_t *buf = n00b_test_elf_minimal_exec(0x400080,
                                                    0,
                                                    0x400000,
                                                    512,
                                                    512,
                                                    true,
                                                    false,
                                                    false,
                                                    false);
    n00b_elf_binary_t *bin = parse_buffer(buf);

    auto result = n00b_elf_rewrite_target_profile(bin);
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_elf_rewrite_target_profile_t profile = n00b_result_get(result);

    N00B_TEST_REQUIRE(profile.reason == N00B_ELF_REWRITE_PROFILE_OK);
    N00B_TEST_REQUIRE(profile.shstrtab_requires_terminator);
    N00B_TEST_REQUIRE(profile.shstrtab_reported_size == 10);
    N00B_TEST_REQUIRE(profile.shstrtab_complete_size == 11);
}

static n00b_buffer_t *
section_count_promotion_buffer(void)
{
    const uint16_t raw_shnum  = 2;
    const uint64_t phoff      = 64;
    const uint64_t shoff      = 256;
    const uint64_t shtab_size = (uint64_t)0xfeff * 64;
    const uint64_t strtab_off = shoff + shtab_size;
    const uint64_t total_size = strtab_off + 1;

    n00b_buffer_t *buf = n00b_test_elf_new_zeroed((size_t)total_size);
    uint8_t       *p   = (uint8_t *)buf->data;

    n00b_test_elf_write_header(p, ET_EXEC, 0, phoff, 1, shoff, raw_shnum, 1);
    n00b_test_elf_write_phdr(p + phoff,
                             PT_NULL,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0);
    n00b_test_elf_write_shdr(p + shoff + 64,
                             0,
                             SHT_STRTAB,
                             0,
                             0,
                             strtab_off,
                             1,
                             0,
                             0,
                             1,
                             0);

    return buf;
}

static void
test_section_count_promotion_rejects(void)
{
    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_binary_t *bin = parse_buffer(section_count_promotion_buffer());

    bin->header.shnum = 0xfeff;

    n00b_elf_rewrite_plan_t *plan =
        require_rejected_plan_for_bin(bin,
                              &request,
                              N00B_ELF_REWRITE_REJECT_SECTION_COUNT_PROMOTION);

    N00B_TEST_REQUIRE(plan->target_profile.reason == N00B_ELF_REWRITE_PROFILE_OK);
    N00B_TEST_REQUIRE(plan->original_section_count == 0xfeff);
    N00B_TEST_REQUIRE(plan->new_section_count == 0xfeff);
}

static void
test_no_mutation(void)
{
    n00b_buffer_t *buf = valid_target_buffer();
    size_t         before_len = buf->byte_len;
    uint8_t        before[512];

    memcpy(before, buf->data, before_len);

    n00b_elf_rewrite_metadata_request_t request = default_request();
    n00b_elf_rewrite_plan_t *plan =
        require_accepted_plan(buf, &request);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);
    N00B_TEST_REQUIRE(buf->byte_len == before_len);
    N00B_TEST_REQUIRE(memcmp(before, buf->data, before_len) == 0);
}

static void
test_stringifiers(void)
{
    N00B_TEST_REQUIRE(n00b_elf_rewrite_err_str(
                          N00B_ELF_REWRITE_ERR_NULL_BINARY)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_err_str(
                          N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_err_str(
                          N00B_ELF_REWRITE_ERR_TRUSTED_NAME)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_plan_outcome_str(
                          N00B_ELF_REWRITE_PLAN_ACCEPTED)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_TABLE_PLACEMENT)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_rejection_reason_str(
                          N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_target_profile_reason_str(
                          N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_table_strategy_str(
                          N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_PAYLOAD)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_patch_kind_str(
                          N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_phtab_strategy_str(
                          N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_placement_kind_str(
                          N00B_ELF_REWRITE_LOADABLE_PLACEMENT_DEFERRED)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_placement_kind_str(
                          N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_placement_kind_str(
                          N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_placement_kind_str(
                          N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_phtab_adjust_status_str(
                          N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED)->u8_bytes != 0);
    N00B_TEST_REQUIRE(n00b_elf_rewrite_loadable_relocation_status_str(
                          N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED)->u8_bytes != 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_stringifiers();
    test_invalid_inputs();
    test_loadable_invalid_inputs();
    test_valid_plan_tail_incision();
    test_loadable_phase1_strategy_plans();
    test_loadable_in_place_phtab_plan_facts();
    test_loadable_admission_rejections_propagate();
    test_loadable_target_profile_rejections();
    test_loadable_no_mutation();
    test_loadable_relocated_phtab_direct_plan_facts();
    test_loadable_relocation_fallback_after_file_collision();
    test_loadable_relocation_rejects_address_overflow();
    test_loadable_relocation_rejects_overlay_without_append();
    test_loadable_relocation_no_mutation();
    test_apply_loadable_in_place_phtab_adjustment();
    test_apply_loadable_in_place_entrypoint_patch();
    test_apply_loadable_relocated_phtab();
    test_apply_loadable_relocated_entrypoint_patch();
    test_loadable_apply_rejects_bad_plans();
    test_loadable_apply_rejects_mismatched_source();
    test_host_entrypoint_target_accepts_x86_64();
    test_host_entrypoint_target_accepts_in_place_plan();
    test_host_entrypoint_target_rejects_architecture();
    test_host_entrypoint_target_rejects_bad_plan_shapes();
    test_host_entrypoint_target_rejects_unsafe_targets();
    test_table_strategy_in_place_growth();
    test_in_place_growth_rejects_modeled_zero_slack();
    test_in_place_growth_rejects_payload_slack_overlap();
    test_tail_incision_rejects_modeled_zero_tail();
    test_apply_tail_incision_shtab_then_shstrtab();
    test_apply_tail_incision_shstrtab_then_shtab();
    test_tail_incision_uses_higher_terminal_candidate();
    test_apply_convenience_wrapper();
    test_apply_big_endian_tail_incision();
    test_apply_minimal_dyn_tail_incision();
    test_overlay_preserve_without_append_rejects();
    test_apply_append_after_overlay();
    test_preferred_gap_payload_appends_tables_at_eof();
    test_apply_in_place_growth();
    test_apply_unterminated_in_place_growth_terminates();
    test_apply_eof_replacement_fallback();
    test_preferred_gap_rejects_nonzero_unknown();
    test_admission_rejection_propagates();
    test_object_bundle_ordinary_insert_rejects_reserved_name();
    test_trusted_object_bundle_insert_policy();
    test_direct_trusted_chalk_mark_admit_public_api();
    test_trusted_chalk_mark_insert_policy();
    test_apply_chalk_mark_delete_wrapper_public_api();
    test_chalk_mark_delete_removes_live_section_and_zeroes_payload();
    test_chalk_mark_delete_replace_reject_colliding_payload();
    test_apply_chalk_mark_replace_wrapper_public_api();
    test_chalk_mark_replace_produces_one_live_mark();
    test_apply_object_bundle_insert_wrapper_public_api();
    test_object_bundle_replace_produces_one_live_bundle();
    test_apply_object_bundle_replace_wrapper_public_api();
    test_object_bundle_replace_rejects_absent_and_duplicate();
    test_object_bundle_replace_rejects_malformed_existing_carrier();
    test_object_bundle_replace_rejects_shared_payload_range();
    test_object_bundle_replace_rejects_wrong_request_shape();
    test_packager_profile_matrix();
    test_unterminated_shstrtab_is_profile_ok();
    test_section_count_promotion_rejects();
    test_no_mutation();
    return 0;
}
