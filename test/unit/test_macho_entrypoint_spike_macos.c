/**
 * @file test_macho_entrypoint_spike_macos.c
 * @brief D-009 / FR-14 feasibility spike: signed-arm64 loadable-segment
 *        insert + LC_MAIN redirect + __LINKEDIT relocation + resign
 *        round-trip.
 *
 * ============================================================================
 * NON-SHIPPING THROWAWAY PROBE.
 *
 * This file is NOT the WP-006 rewrite engine and is NOT shipping code.
 * It is the empirical de-risking probe for DECISION D-009 ("de-risk the
 * signed arm64 entrypoint first") and FR-14: prove or disprove that a
 * *signed* arm64 Mach-O can have
 *
 *   1. its existing signature stripped (via the EXISTING chalk path),
 *   2. a new loadable LC_SEGMENT_64 inserted (carrying a tiny arm64
 *      trampoline that exits with a known sentinel code),
 *   3. __LINKEDIT relocated to a higher page-aligned file/VM offset,
 *      with every __LINKEDIT-referencing load-command offset patched,
 *   4. LC_MAIN.entryoff redirected to the inserted trampoline,
 *   5. re-signed ad-hoc via the EXISTING chalk resign path
 *      (n00b_chalk_macho_resign, signer_identity = nullptr),
 *
 * and STILL pass `codesign --verify --deep --strict` AND run, returning
 * the injected sentinel exit code.
 *
 * The byte surgery here is hand-rolled (it reuses only the *shape* of the
 * chalk helpers in src/chalk/macho_core.c; the production rewrite engine
 * does not exist yet). Do not promote this file into a carrier path.
 * ============================================================================
 *
 * Gating (mirrors test_objfile_macho_oracle.c, D-006 / NFR-06):
 *   - N00B_TEST_MACHO_ORACLE unset / != "1": print
 *     `[SKIP] N00B_TEST_MACHO_ORACLE!=1` and exit 0. Never silent-pass.
 *   - == "1" on non-Darwin: print `[FAIL]` (codesign(1) is macOS-only).
 *   - == "1" on Darwin: run the full round-trip; a set gate never
 *     silently passes.
 *
 * D-018 test-fixture-scaffolding libc exemption: this harness/process
 * file uses getenv/printf/snprintf/fork/exec/stat for harness and
 * process work; that is covered by the n00b-api-guidelines §1 exemption.
 *
 * Numeric constants are verified from SDK headers / a disassembler and
 * cited inline; none are guessed (MEMORY: never invent numeric values).
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"

#if !defined(__APPLE__)

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    const char *gate = getenv("N00B_TEST_MACHO_ORACLE");
    if (gate == nullptr || strcmp(gate, "1") != 0) {
        printf("  [SKIP] N00B_TEST_MACHO_ORACLE!=1\n");
        return 0;
    }

    // Gate is set but this is the crux runtime probe, which needs
    // codesign(1) + the macOS loader: do not silently pass.
    printf("  [FAIL] N00B_TEST_MACHO_ORACLE=1 but this host is not macOS; "
           "the Mach-O entrypoint spike requires codesign(1) + the macOS "
           "loader.\n");
    return 1;
}

#else // __APPLE__

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "chalk/n00b_chalk_resign.h"

// Public chalk strip entry (src/chalk/macho.c).
extern n00b_result_t(n00b_buffer_t *)
    n00b_chalk_macho_strip_signature(n00b_buffer_t *bytes);

// ============================================================================
// Verified numeric constants (each cited to its source).
// ============================================================================

// arm64 macOS page size. Source: MacOSX.sdk/usr/include/mach/arm/vm_param.h
//   PAGE_MAX_SHIFT 14  ->  PAGE_MAX_SIZE (1 << 14) = 0x4000 = 16384.
#define ARM64_PAGE_SIZE 0x4000u

// LC_SEGMENT_64 command size with zero sections: segment_command_64 is
//   cmd(4) cmdsize(4) segname[16] vmaddr(8) vmsize(8) fileoff(8)
//   filesize(8) maxprot(4) initprot(4) nsects(4) flags(4) = 72 bytes.
// Source: macho_types.h n00b_macho_segment_command64_t (#pragma pack 1).
#define SEG64_CMD_SIZE 72u

// section_64 record size: sectname16 segname16 addr8 size8 offset4 align4
//   reloff4 nreloc4 flags4 reserved1/2/3 (3*4) = 80 bytes. The file
//   `offset` field sits at +48. Source: macho_types.h n00b_macho_section64_t.
#define SECT64_SIZE       80u
#define SECT64_OFF_OFFSET 48

// segment_command_64 field offsets relative to the command start (mirror
// of src/chalk/macho_core.c SEGCMD_* and macho_types.h field order).
#define SEGOFF_SEGNAME   8
#define SEGOFF_VMADDR    24
#define SEGOFF_VMSIZE    32
#define SEGOFF_FILEOFF   40
#define SEGOFF_FILESIZE  48
#define SEGOFF_MAXPROT   56
#define SEGOFF_INITPROT  60
#define SEGOFF_NSECTS    64
#define SEGOFF_FLAGS     68

// VM protection bits. Source: MacOSX.sdk/usr/include/mach/vm_prot.h
//   VM_PROT_READ 0x01, VM_PROT_EXECUTE 0x04.
#define VM_PROT_R 0x1u
#define VM_PROT_X 0x4u

// mach_header_64 field offsets. Source: macho_types.h n00b_macho_header64_t.
#define MH_OFF_NCMDS       16
#define MH_OFF_SIZEOFCMDS  20
#define MH_HEADER_SIZE     32

// linkedit_data_command: cmd(4) cmdsize(4) dataoff(4) datasize(4).
// Used by LC_DYLD_CHAINED_FIXUPS / LC_DYLD_EXPORTS_TRIE /
// LC_FUNCTION_STARTS / LC_DATA_IN_CODE / LC_CODE_SIGNATURE.
// Source: macho_types.h n00b_macho_linkedit_data_command_t.
#define LEDATA_OFF_DATAOFF 8

// symtab_command: cmd(4) cmdsize(4) symoff(4) nsyms(4) stroff(4) strsize(4).
// Source: macho_types.h n00b_macho_symtab_command_t.
#define SYMTAB_OFF_SYMOFF 8
#define SYMTAB_OFF_STROFF 16

// dysymtab_command __LINKEDIT-indexing *off fields. Source: macho_types.h
//   n00b_macho_dysymtab_command_t (cmd,cmdsize then 18 u32 fields).
#define DYSYM_OFF_TOCOFF         32
#define DYSYM_OFF_MODTABOFF      40
#define DYSYM_OFF_EXTREFSYMOFF   48
#define DYSYM_OFF_INDIRECTSYMOFF 56
#define DYSYM_OFF_EXTRELOFF      64
#define DYSYM_OFF_LOCRELOFF      72

// LC_MAIN entry_point_command: cmd(4) cmdsize(4) entryoff(8) stacksize(8).
// Source: macho_types.h n00b_macho_entry_point_command_t.
#define LCMAIN_OFF_ENTRYOFF 8

// Trampoline: exit(SENTINEL) via the macOS arm64 SYS_exit (number 1).
//   SYS_exit source: MacOSX.sdk/usr/include/sys/syscall.h:41 (#define SYS_exit 1)
//   Instruction encodings verified with clang+otool on this host:
//     mov  x0, #42  -> 0xd2800540 -> LE bytes 40 05 80 d2
//     mov  x16, #1  -> 0xd2800030 -> LE bytes 30 00 80 d2  (x16 = svc selector)
//     svc  #0x80    -> 0xd4001001 -> LE bytes 01 10 00 d4
#define SENTINEL_EXIT_CODE 42
static const uint8_t trampoline_bytes[] = {
    0x40, 0x05, 0x80, 0xd2, // mov  x0, #42
    0x30, 0x00, 0x80, 0xd2, // mov  x16, #1   (SYS_exit)
    0x01, 0x10, 0x00, 0xd4, // svc  #0x80
};

// ============================================================================
// Little-endian byte accessors (mirror src/chalk/macho_core.c set_le_*).
// ============================================================================

static void
set_le_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
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

// ============================================================================
// Harness helpers (mirror test_objfile_macho_oracle.c).
// ============================================================================

static bool
env_is_one(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && strcmp(value, "1") == 0;
}

static bool
file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool
resolve_fixture(char *out, size_t out_len)
{
    static const char *rel = "test/unit/data/hello_signed_arm64.macho";

    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(out, out_len, "%s/%s", root, rel);
        if (n > 0 && (size_t)n < out_len && file_exists(out)) {
            return true;
        }
    }

    int n = snprintf(out, out_len, "%s", rel);
    if (n > 0 && (size_t)n < out_len && file_exists(out)) {
        return true;
    }

    return false;
}

static int
run_to_exit(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        // 128 + signal so a crash is distinguishable from a normal exit.
        return 128 + WTERMSIG(status);
    }
    return -1;
}

// ============================================================================
// Command-walking over bin->commands[] (mirror chalk command_offset()).
// ============================================================================

static size_t
command_offset(n00b_macho_binary_t *bin, uint32_t index)
{
    size_t off = bin->fat_offset + MH_HEADER_SIZE;
    for (uint32_t i = 0; i < index && i < bin->num_commands; i++) {
        off += bin->commands[i].cmdsize;
    }
    return off;
}

static int
find_segment_index(n00b_macho_binary_t *bin, const char *segname)
{
    size_t want = strlen(segname);
    if (want > 16) {
        return -1;
    }
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_SEGMENT_64 || cmd->raw_data == nullptr
            || cmd->raw_data->byte_len < SEGOFF_FILEOFF + 16) {
            continue;
        }
        const char *raw = cmd->raw_data->data + SEGOFF_SEGNAME;
        if (memcmp(raw, segname, want) == 0
            && (want == 16 || raw[want] == '\0')) {
            return (int)i;
        }
    }
    return -1;
}

// Bump a u32 *off field at (cmd_off + field) by `delta` if it is nonzero.
static void
bump_off_field(uint8_t *base, size_t cmd_off, size_t field, uint32_t delta)
{
    uint32_t v = get_le_u32(base + cmd_off + field);
    if (v != 0) {
        set_le_u32(base + cmd_off + field, v + delta);
    }
}

// ============================================================================
// Facts recorded for the verdict.
// ============================================================================

typedef struct {
    uint64_t orig_entryoff;
    uint64_t new_entryoff;
    uint64_t linkedit_delta;
    uint64_t new_seg_fileoff;
    uint64_t new_seg_vmaddr;
} spike_facts_t;

// ============================================================================
// The round-trip surgery on an already-stripped buffer.
//
// Single, page-faithful strategy:
//   * The fixture's native LC slack (~32 B) is far short of the 72 B a new
//     LC_SEGMENT_64 needs, AND the trampoline's new loadable segment needs
//     a page-aligned file offset that does not collide with the (grown) LC
//     region or any existing section. `first_section` (808 here) is not
//     page-aligned, so a single-page slide opens a page-sized but
//     mis-aligned hole with no page-aligned page inside it. We therefore
//     slide every byte from the first section onward forward by TWO pages
//     (2 * 0x4000). The freed region [first_section .. first_section +
//     2*page) then contains a fully page-aligned page that we hand to the
//     trampoline segment. Because the slide is a whole multiple of the
//     page size, the low-14 bits of every file offset are preserved, so we
//     simply add `slide` to each section's `offset` field, to __TEXT's
//     file/vm size, and to every __LINKEDIT-referencing load-command
//     offset.
//   * We carve a brand-new loadable LC_SEGMENT_64 ("__N00B", r-x) that
//     maps the page-aligned freed page, write the trampoline at its start,
//     and redirect LC_MAIN.entryoff to the trampoline's file offset.
//
// Returns true on success; on any structural surprise prints [FAIL] and
// returns false (a set gate never silently passes).
// ============================================================================

static bool
do_surgery(n00b_buffer_t *buf, spike_facts_t *facts)
{
    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto            r = n00b_macho_parse(s);
    if (n00b_result_is_err(r)) {
        printf("  [FAIL] re-parse of stripped buffer failed\n");
        return false;
    }
    n00b_macho_fat_t *fat = n00b_result_get(r);
    if (fat->count != 1) {
        printf("  [FAIL] expected non-fat (count=1), got %u\n", fat->count);
        return false;
    }
    n00b_macho_binary_t *bin = fat->binaries[0];

    if (bin->fat_offset != 0) {
        printf("  [FAIL] probe assumes fat_offset==0; got %llu\n",
               (unsigned long long)bin->fat_offset);
        return false;
    }

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_CODE_SIGNATURE) {
            printf("  [FAIL] LC_CODE_SIGNATURE still present after strip\n");
            return false;
        }
    }

    int text_idx = find_segment_index(bin, "__TEXT");
    int le_idx   = find_segment_index(bin, "__LINKEDIT");
    if (text_idx < 0 || le_idx < 0) {
        printf("  [FAIL] missing __TEXT or __LINKEDIT segment\n");
        return false;
    }

    uint8_t *base        = (uint8_t *)buf->data;
    size_t   text_cmd0   = command_offset(bin, (uint32_t)text_idx);
    size_t   le_cmd0     = command_offset(bin, (uint32_t)le_idx);

    uint64_t text_fileoff  = get_le_u64(base + text_cmd0 + SEGOFF_FILEOFF);
    uint64_t text_filesize = get_le_u64(base + text_cmd0 + SEGOFF_FILESIZE);
    uint64_t text_vmaddr   = get_le_u64(base + text_cmd0 + SEGOFF_VMADDR);
    uint64_t le_fileoff    = get_le_u64(base + le_cmd0 + SEGOFF_FILEOFF);
    uint64_t le_filesize   = get_le_u64(base + le_cmd0 + SEGOFF_FILESIZE);

    if (text_fileoff != 0) {
        printf("  [FAIL] probe assumes __TEXT.fileoff==0; got %llu\n",
               (unsigned long long)text_fileoff);
        return false;
    }

    // The stripped file must end exactly at __LINKEDIT's end.
    if (le_fileoff + le_filesize != buf->byte_len) {
        printf("  [FAIL] stripped file does not end at __LINKEDIT end "
               "(le_fileoff=%llu le_filesize=%llu eof=%zu)\n",
               (unsigned long long)le_fileoff,
               (unsigned long long)le_filesize,
               (size_t)buf->byte_len);
        return false;
    }

    // Find the first section file offset (the slide point).
    uint64_t first_section = UINT64_MAX;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        for (uint32_t j = 0; j < bin->segments[i].nsects; j++) {
            uint32_t so = bin->segments[i].sections[j].offset;
            if (so > 0 && so < first_section) {
                first_section = so;
            }
        }
    }
    if (first_section == UINT64_MAX) {
        printf("  [FAIL] no section with a nonzero file offset\n");
        return false;
    }

    const uint64_t page  = ARM64_PAGE_SIZE;
    uint64_t       lc_end = MH_HEADER_SIZE + bin->header.sizeofcmds;

    // After we open one page of LC room (Step A), the LC region grows by
    // SEG64_CMD_SIZE and must still fit before the new first-section page.
    if (lc_end + SEG64_CMD_SIZE > page) {
        printf("  [FAIL] header+LCs+new-cmd (%llu) exceed one page (%llu)\n",
               (unsigned long long)(lc_end + SEG64_CMD_SIZE),
               (unsigned long long)page);
        return false;
    }

    // ----------------------------------------------------------------
    // Target layout (all page-aligned where it matters):
    //   file [0 .. page)          __TEXT page 0: header + LCs(+72) + slack
    //   file [page .. 2*page)     __TEXT page 1: the slid sections
    //   file [2*page .. 3*page)   __N00B: the trampoline page (page-aligned)
    //   file [3*page .. EOF+3p)   __LINKEDIT (slid up by 3 pages from its
    //                             original page-aligned fileoff)
    //
    // Sections slide by +page (into __TEXT page 1). __LINKEDIT was at the
    // page-aligned fileoff `le_fileoff`; it slides by +`le_delta` so it now
    // begins at 3*page. Because the fixture's __LINKEDIT starts at exactly
    // one page above __TEXT's end, `le_delta` == 2*page here; we compute it
    // from the actual geometry rather than assume.
    // ----------------------------------------------------------------
    uint64_t sect_delta = page;                 // sections move up one page
    uint64_t new_seg_fileoff = 2 * page;        // trampoline page (aligned)
    uint64_t le_new_fileoff  = 3 * page;        // __LINKEDIT new base
    uint64_t le_delta        = le_new_fileoff - le_fileoff;

    // The slid sections must still fall inside the file region __TEXT will
    // cover. With __TEXT grown to [0, 2*page) and sections at
    // [first_section+page, ...), require they end within 2*page.
    uint64_t text_body_end = (text_fileoff + text_filesize); // == le_fileoff
    if (first_section + sect_delta < page
        || text_body_end + sect_delta > 2 * page) {
        printf("  [FAIL] slid __TEXT sections (end=%llu) do not fit in the "
               "2-page __TEXT window\n",
               (unsigned long long)(text_body_end + sect_delta));
        return false;
    }

    // ----------------------------------------------------------------
    // Step A: grow the buffer by le_delta (the largest slide) and re-lay
    // the file. The file MUST end exactly at __LINKEDIT's new end (no
    // trailing bytes), or codesign rejects it with "main executable
    // failed strict validation" (design 04-...:16-27).
    //   - keep [0 .. first_section)           (header + LCs) in place
    //   - move [first_section .. le_fileoff)  (__TEXT sections) +sect_delta
    //   - move [le_fileoff .. EOF)            (__LINKEDIT)      +le_delta
    //   - zero the gaps; the trampoline goes at 2*page.
    // ----------------------------------------------------------------
    size_t old_len = buf->byte_len;
    size_t new_len = old_len + (size_t)le_delta;

    n00b_buffer_resize(buf, new_len);
    if (buf->byte_len < new_len) {
        printf("  [FAIL] buffer resize to %zu failed\n", new_len);
        return false;
    }
    base = (uint8_t *)buf->data; // resize may move the allocation

    // Move __LINKEDIT first (highest source offset) to avoid clobbering.
    size_t le_len = (size_t)(old_len - le_fileoff);
    memmove(base + le_fileoff + le_delta, base + le_fileoff, le_len);

    // Move __TEXT sections up by one page.
    size_t sect_len = (size_t)(le_fileoff - first_section);
    memmove(base + first_section + sect_delta, base + first_section, sect_len);

    // Zero the now-vacated regions, then drop the trampoline.
    memset(base + first_section, 0, (size_t)sect_delta); // tail of __TEXT pg0
    memset(base + new_seg_fileoff, 0, (size_t)page);      // trampoline page
    // (region between slid sections and trampoline is already covered.)
    memcpy(base + new_seg_fileoff, trampoline_bytes, sizeof(trampoline_bytes));

    uint64_t new_seg_vmaddr = text_vmaddr + new_seg_fileoff;

    // ----------------------------------------------------------------
    // Step B: grow __TEXT to a contiguous 2-page r-x window [0, 2*page)
    // and bump its section file offsets by +page.
    // ----------------------------------------------------------------
    set_le_u64(base + text_cmd0 + SEGOFF_FILESIZE, 2 * page);
    set_le_u64(base + text_cmd0 + SEGOFF_VMSIZE, 2 * page);
    for (uint32_t j = 0; j < bin->segments[text_idx].nsects; j++) {
        size_t sec_off = text_cmd0 + SEG64_CMD_SIZE + (size_t)j * SECT64_SIZE;
        bump_off_field(base, sec_off, SECT64_OFF_OFFSET, (uint32_t)sect_delta);
    }

    // ----------------------------------------------------------------
    // Step C: slide __LINKEDIT (file + VM) up by le_delta and patch every
    // __LINKEDIT-referencing load-command offset by +le_delta. Walk
    // bin->commands[] (offsets here are still valid: we have not yet
    // inserted the new LC, which goes after this).
    // ----------------------------------------------------------------
    set_le_u64(base + le_cmd0 + SEGOFF_FILEOFF, le_fileoff + le_delta);
    uint64_t le_vmaddr = get_le_u64(base + le_cmd0 + SEGOFF_VMADDR);
    set_le_u64(base + le_cmd0 + SEGOFF_VMADDR, le_vmaddr + le_delta);

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *c   = &bin->commands[i];
        size_t                off = command_offset(bin, i);

        switch (c->cmd) {
        case LC_DYLD_CHAINED_FIXUPS:
        case LC_DYLD_EXPORTS_TRIE:
        case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE:
        case LC_SEGMENT_SPLIT_INFO:
        case LC_DYLIB_CODE_SIGN_DRS:
        case LC_LINKER_OPTIMIZATION_HINT:
            bump_off_field(base, off, LEDATA_OFF_DATAOFF, (uint32_t)le_delta);
            break;
        case LC_SYMTAB:
            bump_off_field(base, off, SYMTAB_OFF_SYMOFF, (uint32_t)le_delta);
            bump_off_field(base, off, SYMTAB_OFF_STROFF, (uint32_t)le_delta);
            break;
        case LC_DYSYMTAB:
            bump_off_field(base, off, DYSYM_OFF_TOCOFF, (uint32_t)le_delta);
            bump_off_field(base, off, DYSYM_OFF_MODTABOFF, (uint32_t)le_delta);
            bump_off_field(base, off, DYSYM_OFF_EXTREFSYMOFF,
                           (uint32_t)le_delta);
            bump_off_field(base, off, DYSYM_OFF_INDIRECTSYMOFF,
                           (uint32_t)le_delta);
            bump_off_field(base, off, DYSYM_OFF_EXTRELOFF, (uint32_t)le_delta);
            bump_off_field(base, off, DYSYM_OFF_LOCRELOFF, (uint32_t)le_delta);
            break;
        default:
            break;
        }
    }

    // ----------------------------------------------------------------
    // Step D: insert the new loadable LC_SEGMENT_64 ("__N00B") into the LC
    // region, immediately after __TEXT's command, so segment order stays
    // monotonic in file/VM (__TEXT < __N00B < __LINKEDIT). Shift the later
    // LCs down by 72 bytes within the (now roomy) LC region, write the new
    // command, and patch ncmds/sizeofcmds.
    // ----------------------------------------------------------------
    size_t insert_lc_at = text_cmd0 + bin->commands[text_idx].cmdsize;
    size_t old_lc_end   = MH_HEADER_SIZE + bin->header.sizeofcmds;
    size_t tail_lc_len  = old_lc_end - insert_lc_at;

    if (old_lc_end + SEG64_CMD_SIZE > first_section + sect_delta) {
        printf("  [FAIL] new LC would overrun the slid first section "
               "(lc_end=%zu + 72 > %llu)\n",
               old_lc_end,
               (unsigned long long)(first_section + sect_delta));
        return false;
    }

    memmove(base + insert_lc_at + SEG64_CMD_SIZE,
            base + insert_lc_at,
            tail_lc_len);

    uint8_t *nc = base + insert_lc_at;
    memset(nc, 0, SEG64_CMD_SIZE);
    set_le_u32(nc + 0, LC_SEGMENT_64);
    set_le_u32(nc + 4, SEG64_CMD_SIZE);
    memcpy(nc + SEGOFF_SEGNAME, "__N00B", 6);
    set_le_u64(nc + SEGOFF_VMADDR, new_seg_vmaddr);
    set_le_u64(nc + SEGOFF_VMSIZE, page);
    set_le_u64(nc + SEGOFF_FILEOFF, new_seg_fileoff);
    set_le_u64(nc + SEGOFF_FILESIZE, page);
    set_le_u32(nc + SEGOFF_MAXPROT, VM_PROT_R | VM_PROT_X);
    set_le_u32(nc + SEGOFF_INITPROT, VM_PROT_R | VM_PROT_X);
    set_le_u32(nc + SEGOFF_NSECTS, 0);
    set_le_u32(nc + SEGOFF_FLAGS, 0);

    // Patch header ncmds += 1, sizeofcmds += 72.
    set_le_u32(base + MH_OFF_NCMDS, bin->header.ncmds + 1);
    set_le_u32(base + MH_OFF_SIZEOFCMDS,
               bin->header.sizeofcmds + SEG64_CMD_SIZE);

    // ----------------------------------------------------------------
    // Step F: redirect LC_MAIN.entryoff to the trampoline file offset.
    // NOTE: entryoff is a *file* offset relative to the start of the
    // mach_header (Apple's LC_MAIN semantics), so it equals
    // new_seg_fileoff (the trampoline's file position).
    //
    // The LC_MAIN command moved when we inserted the new segment LC
    // before it (it sits after __TEXT). Re-walk to find it post-insert.
    // bin->commands[] is now stale for offsets past the insertion, so
    // recompute by scanning the on-disk LC table directly.
    // ----------------------------------------------------------------
    uint32_t ncmds_now = bin->header.ncmds + 1;
    size_t   walk      = MH_HEADER_SIZE;
    uint64_t orig_entryoff = UINT64_MAX;
    bool     patched_main  = false;

    for (uint32_t i = 0; i < ncmds_now; i++) {
        uint32_t cmd  = get_le_u32(base + walk);
        uint32_t csz  = get_le_u32(base + walk + 4);
        if (csz < 8) {
            printf("  [FAIL] zero/short cmdsize while walking LCs\n");
            return false;
        }
        if (cmd == LC_MAIN) {
            orig_entryoff = get_le_u64(base + walk + LCMAIN_OFF_ENTRYOFF);
            set_le_u64(base + walk + LCMAIN_OFF_ENTRYOFF, new_seg_fileoff);
            patched_main = true;
            break;
        }
        walk += csz;
    }

    if (!patched_main) {
        printf("  [FAIL] no LC_MAIN found to redirect\n");
        return false;
    }

    facts->orig_entryoff   = orig_entryoff;
    facts->new_entryoff    = new_seg_fileoff;
    facts->linkedit_delta  = le_delta;
    facts->new_seg_fileoff = new_seg_fileoff;
    facts->new_seg_vmaddr  = new_seg_vmaddr;
    return true;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    if (!env_is_one("N00B_TEST_MACHO_ORACLE")) {
        printf("  [SKIP] N00B_TEST_MACHO_ORACLE!=1\n");
        return 0;
    }

    char fixture[1024];
    if (!resolve_fixture(fixture, sizeof(fixture))) {
        printf("  [FAIL] could not locate committed fixture "
               "test/unit/data/hello_signed_arm64.macho.\n");
        return 1;
    }

    // ---- Step 1: parse the fixture. ----
    auto stream_r = n00b_bstream_from_file(fixture);
    if (n00b_result_is_err(stream_r)) {
        printf("  [FAIL] could not open fixture %s\n", fixture);
        return 1;
    }
    n00b_bstream_t *s    = n00b_result_get(stream_r);
    auto            pr   = n00b_macho_parse(s);
    if (n00b_result_is_err(pr)) {
        printf("  [FAIL] parse of fixture failed\n");
        return 1;
    }
    n00b_macho_fat_t *fat = n00b_result_get(pr);
    if (fat->count != 1) {
        printf("  [FAIL] expected non-fat fixture, got count=%u\n",
               fat->count);
        return 1;
    }

    // ---- Step 2: strip the existing signature (chalk public path). ----
    // Copy the raw bytes into a fresh buffer the strip path can own.
    n00b_buffer_t *orig = s->buf;
    n00b_buffer_t *work = n00b_buffer_from_bytes(orig->data,
                                                 (int64_t)orig->byte_len);
    auto strip_r = n00b_chalk_macho_strip_signature(work);
    if (n00b_result_is_err(strip_r)) {
        printf("  [FAIL] n00b_chalk_macho_strip_signature failed\n");
        return 1;
    }
    n00b_buffer_t *stripped = n00b_result_get(strip_r);
    if (stripped == nullptr) {
        printf("  [FAIL] strip returned null buffer\n");
        return 1;
    }

    // ---- Steps 3-5 surgery: insert segment, slide __LINKEDIT, redirect. --
    spike_facts_t facts = {};
    if (!do_surgery(stripped, &facts)) {
        // do_surgery already printed a [FAIL] line.
        return 1;
    }

    // ---- Write the modified buffer to a temp file. ----
    char tmpl[] = "/tmp/n00b_macho_spike_XXXXXX";
    int  fd     = mkstemp(tmpl);
    if (fd < 0) {
        printf("  [FAIL] mkstemp failed: %s\n", strerror(errno));
        return 1;
    }
    {
        const uint8_t *p   = (const uint8_t *)stripped->data;
        size_t         rem = (size_t)stripped->byte_len;
        while (rem > 0) {
            ssize_t w = write(fd, p, rem);
            if (w <= 0) {
                printf("  [FAIL] write to temp file failed: %s\n",
                       strerror(errno));
                close(fd);
                unlink(tmpl);
                return 1;
            }
            p   += (size_t)w;
            rem -= (size_t)w;
        }
    }
    close(fd);
    chmod(tmpl, 0755);

    // ---- Step 5: re-sign ad-hoc through the EXISTING chalk path. ----
    n00b_string_t *tmp_path = n00b_string_from_cstr(tmpl);
    auto           resign_r = n00b_chalk_macho_resign(tmp_path);
    if (n00b_result_is_err(resign_r)) {
        printf("  [FAIL] n00b_chalk_macho_resign failed on %s\n", tmpl);
        unlink(tmpl);
        return 1;
    }

    // ---- Step 6a: codesign --verify --deep --strict must exit 0. ----
    char *const codesign_argv[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        (char *)"--deep",
        (char *)"--strict",
        tmpl,
        nullptr,
    };
    int verify_rc = run_to_exit(codesign_argv);

    // ---- Step 6b: run it; the loader must return the sentinel code. ----
    char *const run_argv[] = {tmpl, nullptr};
    int         run_rc     = run_to_exit(run_argv);

    // ---- Report every fact for the verdict. ----
    printf("  [FACT] original LC_MAIN.entryoff = %llu (0x%llx)\n",
           (unsigned long long)facts.orig_entryoff,
           (unsigned long long)facts.orig_entryoff);
    printf("  [FACT] new      LC_MAIN.entryoff = %llu (0x%llx)\n",
           (unsigned long long)facts.new_entryoff,
           (unsigned long long)facts.new_entryoff);
    printf("  [FACT] __LINKEDIT slid by        = %llu (0x%llx)\n",
           (unsigned long long)facts.linkedit_delta,
           (unsigned long long)facts.linkedit_delta);
    printf("  [FACT] new __N00B seg fileoff    = %llu (0x%llx)\n",
           (unsigned long long)facts.new_seg_fileoff,
           (unsigned long long)facts.new_seg_fileoff);
    printf("  [FACT] new __N00B seg vmaddr     = 0x%llx\n",
           (unsigned long long)facts.new_seg_vmaddr);
    printf("  [FACT] codesign --verify --deep --strict exit = %d\n",
           verify_rc);
    printf("  [FACT] run exit = %d (expected sentinel %d)\n",
           run_rc, SENTINEL_EXIT_CODE);
    printf("  [FACT] temp binary: %s\n", tmpl);

    bool verify_ok = (verify_rc == 0);
    bool run_ok    = (run_rc == SENTINEL_EXIT_CODE);

    // Optional: keep the produced binary for external inspection
    // (otool -l / codesign -dvvv). Set N00B_TEST_MACHO_SPIKE_KEEP=<path>.
    const char *keep = getenv("N00B_TEST_MACHO_SPIKE_KEEP");
    if (keep != nullptr && keep[0] != '\0') {
        char cmd[2200];
        int  n = snprintf(cmd, sizeof(cmd), "/bin/cp %s %s", tmpl, keep);
        if (n > 0 && (size_t)n < sizeof(cmd)) {
            (void)system(cmd);
            printf("  [FACT] kept copy at %s\n", keep);
        }
    }

    if (verify_ok && run_ok) {
        printf("  [PASS] VERDICT=FEASIBLE: signed-arm64 loadable-insert + "
               "LC_MAIN redirect + __LINKEDIT relocation + chalk ad-hoc "
               "resign round-trips; codesign verifies and the loader runs "
               "the injected trampoline (exit %d).\n",
               SENTINEL_EXIT_CODE);
        unlink(tmpl);
        return 0;
    }

    printf("  [FAIL] VERDICT=INFEASIBLE (as built): verify_ok=%d run_ok=%d. "
           "See [FACT] lines above for the exact codesign/loader result; "
           "this re-scopes the MVP per D-009.\n",
           (int)verify_ok, (int)run_ok);
    // Leave tmpl on disk for post-mortem (codesign -dvvv, otool -l).
    printf("  [FAIL] left %s on disk for post-mortem.\n", tmpl);
    return 1;
}

#endif // __APPLE__
