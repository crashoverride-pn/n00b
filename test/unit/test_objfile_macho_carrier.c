/**
 * @file test_objfile_macho_carrier.c
 * @brief WP-008 Phase 1 regression tests for the Mach-O object-bundle carrier
 *        backend (detect / reserved / read / write METADATA path).
 *
 * Direct backend calls (no dispatch — that is Phase 2). Deterministic,
 * host-neutral, always-run: the carrier is exercised by writing a real METADATA
 * carrier through the WP-005/006 surgical LC_NOTE rewrite, reparsing the output,
 * and asserting the backend's classification / round-trip. Synthetic
 * doubled/truncated/descriptor states are built by editing the bytes of a real
 * carrier write (test-local scaffolding, D-018: header-only libc for raw byte
 * work is permitted; every n00b_* call uses the n00b surface).
 *
 * Cases P1-a..P1-h per the Phase 1 matrix.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/crc32.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h" // n00b_unicode_str_eq
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_carrier.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_rewrite_admit.h" // N00B_MACHO_BUNDLE_NOTE_OWNER
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_macho.h"

// Fixtures. P1-a asserts the NONE state on the committed `hello.macho`. The
// write-dependent cases need a base that the surgical insert can accept: the
// committed `hello.macho` is code-signed, and the WP-008 write path does not
// set ALLOW_RESIGN (re-signing reconciliation is WP-011, out of scope), so a
// surgical insert into a signed binary is rejected. The always-run write
// round-trip therefore uses the committed unsigned fixture, exactly as every
// WP-005/006/007 rewrite test does. Both are deterministic + host-neutral.
#define TEST_FIXTURE_CLEAN  "test/unit/data/hello.macho"
#define TEST_FIXTURE_WRITE  "test/unit/data/hello_unsigned_arm64.macho"

// On-disk LC_NOTE layout: cmd(4) cmdsize(4) data_owner[16] offset(8) size(8).
#define TEST_NOTE_CMD_SIZE   40u
#define TEST_NOTE_OWNER_OFF  8u
#define TEST_NOTE_OFFSET_OFF 24u
#define TEST_NOTE_SIZE_OFF   32u
// Mach-O 64-bit header: magic cputype cpusubtype filetype ncmds sizeofcmds ...
#define TEST_MACHO_HDR_SIZE   32u
#define TEST_MACHO_NCMDS_OFF  16u

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                                       \
    do {                                                         \
        if (cond) {                                              \
            printf("  [PASS] %s\n", (label));                    \
            g_pass++;                                            \
        }                                                        \
        else {                                                   \
            printf("  [FAIL] %s\n", (label));                    \
            g_fail++;                                            \
        }                                                        \
    } while (0)

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_rewrite.c:parse_fixture)
// ---------------------------------------------------------------------------
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

static n00b_macho_binary_t *
reparse(n00b_buffer_t *bytes)
{
    n00b_bstream_t *stream = n00b_bstream_new(bytes);
    auto            parsed = n00b_macho_parse_single(stream);

    assert(n00b_result_is_ok(parsed));
    return n00b_result_get(parsed);
}

static n00b_buffer_t *
make_canonical(const char *fill, size_t len)
{
    // Test scaffolding (D-018): assemble fill bytes in a raw C array, then copy
    // into a properly-initialized n00b buffer via the public constructor.
    uint8_t *tmp = malloc(len);

    for (size_t i = 0; i < len; i++) {
        tmp[i] = (uint8_t)fill[i % strlen(fill)];
    }

    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)tmp, (int64_t)len);
    free(tmp);
    return buf;
}

// Write a METADATA carrier into a clean fixture and return the rewritten object
// bytes. Returns nullptr if the base fixture is unavailable.
static n00b_buffer_t *
write_metadata_carrier(n00b_macho_binary_t *base, n00b_buffer_t *canonical)
{
    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_AUTO,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    if (n00b_result_is_err(wr)) {
        return nullptr;
    }

    return n00b_result_get(wr);
}

// Locate the bundle-owned LC_NOTE command's slice-relative file offset in the
// reparsed binary. Returns SIZE_MAX if absent.
static size_t
bundle_note_command_offset(n00b_macho_binary_t *bin)
{
    size_t want = strlen(N00B_MACHO_BUNDLE_NOTE_OWNER);

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];

        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || (size_t)cmd->raw_data->byte_len < TEST_NOTE_CMD_SIZE) {
            continue;
        }

        const uint8_t *raw   = (const uint8_t *)cmd->raw_data->data;
        const char    *owner = (const char *)(raw + TEST_NOTE_OWNER_OFF);

        if (want <= 16
            && memcmp(owner, N00B_MACHO_BUNDLE_NOTE_OWNER, want) == 0) {
            bool ok = true;
            for (size_t k = want; k < 16; k++) {
                if (owner[k] != '\0') {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                return (size_t)cmd->file_offset;
            }
        }
    }

    return SIZE_MAX;
}

static void
put32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void
put64_le(uint8_t *p, uint64_t v)
{
    put32_le(p, (uint32_t)v);
    put32_le(p + 4, (uint32_t)(v >> 32));
}

static uint32_t
get32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ============================================================================
// P1-a: clean fixture -> NONE
// ============================================================================
static void
test_p1a_detect_none(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_CLEAN);

    if (base == nullptr) {
        printf("  [FAIL] P1-a: base fixture hello.macho unavailable\n");
        g_fail++;
        return;
    }

    (void)canonical;
    auto d = _n00b_obj_bundle_macho_detect_carrier(base);

    CHECK("P1-a detect_carrier(clean hello.macho) == NONE",
          n00b_result_is_ok(d)
              && n00b_result_get(d) == N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE);
}

// ============================================================================
// P1-b: write_carrier(AUTO) -> reparse -> METADATA_RAW + owner token <=16B
// ============================================================================
static void
test_p1b_detect_metadata_raw(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P1-b: base fixture unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *out = write_metadata_carrier(base, canonical);

    if (out == nullptr) {
        printf("  [FAIL] P1-b: write_carrier(AUTO) failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);
    auto                 d   = _n00b_obj_bundle_macho_detect_carrier(bin);

    CHECK("P1-b detect_carrier(written) == METADATA_RAW",
          n00b_result_is_ok(d)
              && n00b_result_get(d)
                     == N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW);

    size_t note_off = bundle_note_command_offset(bin);

    CHECK("P1-b owner token present (<=16B field matches reserved token)",
          note_off != SIZE_MAX
              && strlen(N00B_MACHO_BUNDLE_NOTE_OWNER) <= 16);
}

// ============================================================================
// P1-c: read_metadata -> byte-equal to canonical
// ============================================================================
static void
test_p1c_read_roundtrip(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P1-c: base fixture unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *out = write_metadata_carrier(base, canonical);

    if (out == nullptr) {
        printf("  [FAIL] P1-c: write_carrier(AUTO) failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);
    auto                 rd  = _n00b_obj_bundle_macho_read_metadata(bin);

    bool ok = n00b_result_is_ok(rd);
    if (ok) {
        n00b_buffer_t *got = n00b_result_get(rd);
        ok = got != nullptr
             && got->byte_len == canonical->byte_len
             && memcmp(got->data, canonical->data, canonical->byte_len) == 0;
    }

    CHECK("P1-c read_metadata round-trips canonical byte-for-byte", ok);
}

// ============================================================================
// P1-e / P1-f: check_reserved REJECT vs REPLACE, + replace round-trip
// ============================================================================
static void
test_p1ef_check_reserved(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P1-e/f: base fixture unavailable\n");
        g_fail += 4;
        return;
    }

    // Clean: check_reserved must be OK.
    auto clean = _n00b_obj_bundle_macho_check_reserved(
        base,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    CHECK("P1-e check_reserved(clean) == OK",
          n00b_result_is_ok(clean)
              && n00b_result_get(clean) == N00B_OBJ_BUNDLE_ERR_OK);

    n00b_buffer_t *out = write_metadata_carrier(base, canonical);

    if (out == nullptr) {
        printf("  [FAIL] P1-e/f: write_carrier(AUTO) failed\n");
        g_fail += 3;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);

    // P1-e: existing carrier + REJECT_EXISTING -> RESERVED_NAMESPACE_OCCUPIED
    auto reject = _n00b_obj_bundle_macho_check_reserved(
        bin,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    CHECK("P1-e check_reserved(existing, REJECT) == RESERVED_NAMESPACE_OCCUPIED",
          n00b_result_is_ok(reject)
              && n00b_result_get(reject)
                     == N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED);

    // P1-f: existing carrier + REPLACE_EXISTING -> OK
    auto allow = _n00b_obj_bundle_macho_check_reserved(
        bin,
        N00B_OBJ_BUNDLE_REPLACE_EXISTING);

    CHECK("P1-f check_reserved(existing, REPLACE) == OK",
          n00b_result_is_ok(allow)
              && n00b_result_get(allow) == N00B_OBJ_BUNDLE_ERR_OK);

    // P1-f: replace with a DIFFERENT canonical, then read back round-trips it.
    // The WP-005/006 surgical replace is in-slot (it reuses the existing
    // LC_NOTE payload slot), so the replacement must be no larger than the
    // original payload (193 bytes). A larger-payload replace would require a
    // grow-then-relocate two-step rewrite — surfaced as deferral #1; not in
    // WP-008 scope. 128 < 193 exercises the supported in-slot replace with a
    // genuinely different canonical.
    n00b_buffer_t *canonical2 = make_canonical("REPLACEMENT-BYTES-2", 128);

    auto wr2 = _n00b_obj_bundle_macho_write_carrier(
        bin,
        canonical2,
        N00B_OBJ_BUNDLE_CARRIER_AUTO,
        N00B_OBJ_BUNDLE_REPLACE_EXISTING);

    bool ok = n00b_result_is_ok(wr2);
    if (ok) {
        n00b_macho_binary_t *bin2 = reparse(n00b_result_get(wr2));
        auto                 rd   = _n00b_obj_bundle_macho_read_metadata(bin2);
        ok = n00b_result_is_ok(rd);
        if (ok) {
            n00b_buffer_t *got = n00b_result_get(rd);
            ok = got->byte_len == canonical2->byte_len
                 && memcmp(got->data, canonical2->data, canonical2->byte_len)
                        == 0;
        }
    }

    CHECK("P1-f replace round-trips a different canonical", ok);
}

// ============================================================================
// P3-a: growth replace (delete-then-insert) round-trip.
//
// Write a carrier with canonical A, then replace it with a STRICTLY LARGER
// canonical B. The in-slot fast path rejects B (REJECT_LC_PLACEMENT); the
// write_carrier replace path must fall back to delete-then-insert (D-037) and
// produce a binary whose bundle carrier reads back as B byte-for-byte, with
// exactly one carrier (detect == METADATA_RAW). Deterministic, always-run.
// ============================================================================
static void
test_p3a_growth_replace_roundtrip(n00b_buffer_t *canonical_a)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P3-a: base fixture unavailable\n");
        g_fail += 2;
        return;
    }

    // Establish a carrier with canonical A (193 bytes).
    n00b_buffer_t *out_a = write_metadata_carrier(base, canonical_a);

    if (out_a == nullptr) {
        printf("  [FAIL] P3-a: initial write_carrier(A) failed\n");
        g_fail += 2;
        return;
    }

    n00b_macho_binary_t *bin_a = reparse(out_a);

    // Replace with a STRICTLY LARGER canonical B (512 > 193) -> growth path.
    n00b_buffer_t *canonical_b = make_canonical("GROWTH-REPLACEMENT-BYTES", 512);

    auto wr_b = _n00b_obj_bundle_macho_write_carrier(
        bin_a,
        canonical_b,
        N00B_OBJ_BUNDLE_CARRIER_AUTO,
        N00B_OBJ_BUNDLE_REPLACE_EXISTING);

    if (n00b_result_is_err(wr_b)) {
        printf("  [FAIL] P3-a: growth replace write failed\n");
        printf("  [FAIL] P3-a: growth replace read-back unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t       *out_b = n00b_result_get(wr_b);
    n00b_macho_binary_t *bin_b = reparse(out_b);

    // The larger output proves growth occurred (delete-then-insert grows the
    // file past the in-slot size).
    CHECK("P3-a growth replace produced a larger object than A",
          out_b->byte_len > out_a->byte_len);

    auto rd = _n00b_obj_bundle_macho_read_metadata(bin_b);
    bool ok = n00b_result_is_ok(rd);
    if (ok) {
        n00b_buffer_t *got = n00b_result_get(rd);
        ok = got != nullptr
             && got->byte_len == canonical_b->byte_len
             && memcmp(got->data, canonical_b->data, canonical_b->byte_len) == 0;
    }

    // Exactly one carrier survives the delete-then-insert.
    auto d = _n00b_obj_bundle_macho_detect_carrier(bin_b);
    ok = ok
         && n00b_result_is_ok(d)
         && n00b_result_get(d) == N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW;

    CHECK("P3-a growth replace round-trips larger canonical B byte-for-byte "
          "(single METADATA_RAW carrier)",
          ok);
}

// ============================================================================
// P1-g: hand-doubled carrier LC_NOTE -> DUPLICATE
//
// Build a real single-carrier object, then splice a duplicate of the 40-byte
// bundle LC_NOTE command into the load-command region, growing the file and
// relocating all post-LC content + segment/section file offsets by 40 bytes.
// Both notes reuse the same (now shifted) payload offset, so they are both
// bundle-owned and well-formed -> detect must report DUPLICATE.
// ============================================================================
static n00b_buffer_t *
build_doubled_carrier(n00b_buffer_t *single)
{
    const uint8_t *src     = (const uint8_t *)single->data;
    uint64_t       src_len = (uint64_t)single->byte_len;

    n00b_macho_binary_t *bin      = reparse(single);
    size_t               note_off = bundle_note_command_offset(bin);

    if (note_off == SIZE_MAX || note_off + TEST_NOTE_CMD_SIZE > src_len) {
        return nullptr;
    }

    // Original note's payload offset/size (absolute into the file). After the
    // 40-byte insert, payload that lived after the insertion point shifts by 40.
    const uint8_t *note    = src + note_off;
    uint64_t       p_off   = (uint64_t)note[TEST_NOTE_OFFSET_OFF]
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 1] << 8)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 2] << 16)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 3] << 24)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 4] << 32)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 5] << 40)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 6] << 48)
                       | ((uint64_t)note[TEST_NOTE_OFFSET_OFF + 7] << 56);

    size_t   insert_at = note_off + TEST_NOTE_CMD_SIZE;
    uint64_t out_len   = src_len + TEST_NOTE_CMD_SIZE;
    uint8_t *out       = malloc(out_len);

    // Copy [0, insert_at) verbatim (header + LCs up to and incl. the note).
    memcpy(out, src, insert_at);
    // Insert a duplicate of the 40-byte note command.
    memcpy(out + insert_at, note, TEST_NOTE_CMD_SIZE);
    // Copy the remainder, shifted by 40 bytes.
    memcpy(out + insert_at + TEST_NOTE_CMD_SIZE,
           src + insert_at,
           src_len - insert_at);

    // Bump ncmds (+1) and sizeofcmds (+40) in the header.
    uint32_t ncmds = get32_le(out + TEST_MACHO_NCMDS_OFF);
    put32_le(out + TEST_MACHO_NCMDS_OFF, ncmds + 1);
    uint32_t sizeofcmds = get32_le(out + TEST_MACHO_NCMDS_OFF + 4);
    put32_le(out + TEST_MACHO_NCMDS_OFF + 4, sizeofcmds + TEST_NOTE_CMD_SIZE);

    // Relocate every segment fileoff and section offset that lay at/after the
    // insertion point by +40, and fix both note commands' payload offsets.
    // Walk the (new) LC list.
    uint32_t new_ncmds = ncmds + 1;
    size_t   off       = TEST_MACHO_HDR_SIZE;

    for (uint32_t i = 0; i < new_ncmds; i++) {
        uint32_t cmd     = get32_le(out + off);
        uint32_t cmdsize = get32_le(out + off + 4);

        if (cmd == LC_SEGMENT_64) {
            // segname[16] @ +8; vmaddr,vmsize,fileoff,filesize @ +24..
            uint8_t *fileoff_p = out + off + 24 + 16;
            uint64_t fileoff   = (uint64_t)fileoff_p[0]
                               | ((uint64_t)fileoff_p[1] << 8)
                               | ((uint64_t)fileoff_p[2] << 16)
                               | ((uint64_t)fileoff_p[3] << 24)
                               | ((uint64_t)fileoff_p[4] << 32)
                               | ((uint64_t)fileoff_p[5] << 40)
                               | ((uint64_t)fileoff_p[6] << 48)
                               | ((uint64_t)fileoff_p[7] << 56);
            if (fileoff >= (uint64_t)insert_at) {
                put64_le(fileoff_p, fileoff + TEST_NOTE_CMD_SIZE);
            }

            uint32_t nsects = get32_le(out + off + 64);
            size_t   so     = off + 72;
            for (uint32_t s = 0; s < nsects; s++) {
                uint32_t sect_off = get32_le(out + so + 48);
                if ((size_t)sect_off >= insert_at) {
                    put32_le(out + so + 48, sect_off + TEST_NOTE_CMD_SIZE);
                }
                so += 80;
            }
        }
        else if (cmd == LC_NOTE && cmdsize >= TEST_NOTE_CMD_SIZE) {
            // Fix payload offset if it lay at/after the insertion point.
            uint8_t *po = out + off + TEST_NOTE_OFFSET_OFF;
            uint64_t v  = (uint64_t)po[0] | ((uint64_t)po[1] << 8)
                       | ((uint64_t)po[2] << 16) | ((uint64_t)po[3] << 24)
                       | ((uint64_t)po[4] << 32) | ((uint64_t)po[5] << 40)
                       | ((uint64_t)po[6] << 48) | ((uint64_t)po[7] << 56);
            if (v >= (uint64_t)insert_at) {
                put64_le(po, v + TEST_NOTE_CMD_SIZE);
            }
        }

        off += cmdsize;
    }

    (void)p_off;
    n00b_buffer_t *result = n00b_buffer_from_bytes((char *)out, (int64_t)out_len);
    free(out);
    return result;
}

static void
test_p1g_detect_duplicate(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P1-g: base fixture unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *single = write_metadata_carrier(base, canonical);

    if (single == nullptr) {
        printf("  [FAIL] P1-g: write_carrier(AUTO) failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *doubled = build_doubled_carrier(single);

    if (doubled == nullptr) {
        printf("  [FAIL] P1-g: could not synthesize doubled carrier\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(doubled);
    auto                 d   = _n00b_obj_bundle_macho_detect_carrier(bin);

    CHECK("P1-g detect_carrier(doubled) == DUPLICATE",
          n00b_result_is_ok(d)
              && n00b_result_get(d)
                     == N00B_OBJ_BUNDLE_MACHO_CARRIER_DUPLICATE);
}

// ============================================================================
// P1-h: truncated carrier LC_NOTE -> MALFORMED
//
// Patch the single carrier note's on-disk `size` field to overrun the buffer,
// so the payload slice is out of bounds -> detect reports MALFORMED.
// ============================================================================
static void
test_p1h_detect_malformed(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] P1-h: base fixture unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *single = write_metadata_carrier(base, canonical);

    if (single == nullptr) {
        printf("  [FAIL] P1-h: write_carrier(AUTO) failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *probe    = reparse(single);
    size_t               note_off = bundle_note_command_offset(probe);

    if (note_off == SIZE_MAX) {
        printf("  [FAIL] P1-h: bundle note not found in written output\n");
        g_fail++;
        return;
    }

    uint64_t  len = (uint64_t)single->byte_len;
    uint8_t  *out = malloc(len);
    memcpy(out, single->data, len);

    // Overrun the note payload size so the slice runs past EOF.
    put64_le(out + note_off + TEST_NOTE_SIZE_OFF, len + 0x1000);

    n00b_buffer_t *truncated =
        n00b_buffer_from_bytes((char *)out, (int64_t)len);
    free(out);

    n00b_macho_binary_t *bin = reparse(truncated);
    auto                 d   = _n00b_obj_bundle_macho_detect_carrier(bin);

    CHECK("P1-h detect_carrier(truncated note) == MALFORMED",
          n00b_result_is_ok(d)
              && n00b_result_get(d)
                     == N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED);
}

// ============================================================================
// Descriptor-decode exercise: a METADATA carrier whose payload begins with the
// descriptor magic + a valid LOADABLE descriptor header makes detect run the
// codec and classify DESCRIPTOR_LOADABLE (D-023). Exercises
// n00b_macho_carrier_descriptor_decode through the detect path.
// ============================================================================
static n00b_buffer_t *
make_loadable_descriptor_payload(void)
{
    uint8_t hdr[N00B_MACHO_CARRIER_HEADER_SIZE] = {};

    memcpy(hdr, N00B_MACHO_CARRIER_MAGIC, N00B_MACHO_CARRIER_MAGIC_LEN);
    // version_major @ 8, version_minor @ 10, header_size @ 12, kind @ 14
    hdr[8]  = (uint8_t)N00B_MACHO_CARRIER_MAJOR;
    hdr[9]  = (uint8_t)(N00B_MACHO_CARRIER_MAJOR >> 8);
    hdr[10] = (uint8_t)N00B_MACHO_CARRIER_MINOR;
    hdr[11] = (uint8_t)(N00B_MACHO_CARRIER_MINOR >> 8);
    hdr[12] = (uint8_t)N00B_MACHO_CARRIER_HEADER_SIZE;
    hdr[13] = (uint8_t)(N00B_MACHO_CARRIER_HEADER_SIZE >> 8);
    hdr[14] = (uint8_t)N00B_MACHO_CARRIER_KIND_LOADABLE;
    hdr[15] = (uint8_t)(N00B_MACHO_CARRIER_KIND_LOADABLE >> 8);

    return n00b_buffer_from_bytes((char *)hdr,
                                  (int64_t)N00B_MACHO_CARRIER_HEADER_SIZE);
}

static void
test_descriptor_magic_classified_loadable(void)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] descriptor-magic: base fixture unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *desc_payload = make_loadable_descriptor_payload();
    n00b_buffer_t *out          = write_metadata_carrier(base, desc_payload);

    if (out == nullptr) {
        printf("  [FAIL] descriptor-magic: write failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);
    auto                 d   = _n00b_obj_bundle_macho_detect_carrier(bin);

    CHECK("descriptor-magic payload classified DESCRIPTOR_LOADABLE (decode run)",
          n00b_result_is_ok(d)
              && n00b_result_get(d)
                     == N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_LOADABLE);
}

// ===========================================================================
// Phase 2: public-API round-trip through n00b_obj_bundle_read / _write.
//
// These exercise the two dispatch hooks (n00b_obj_bundle_read /
// n00b_obj_bundle_write) wired in Phase 2, so they go through the full
// encode -> write -> read -> decode public surface (FR-17/FR-20/FR-21).
// The write-dependent cases reuse the unsigned fixture (the surgical insert
// rejects a signed binary; re-signing is WP-011).
// ===========================================================================

// Load the raw object bytes of a fixture (for the public API, which takes the
// raw n00b_buffer_t, not a parsed n00b_macho_binary_t).
static n00b_buffer_t *
load_fixture_bytes(const char *rel)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (n > 0 && (size_t)n < sizeof(path)) {
            auto r = n00b_bstream_from_file(path);
            if (n00b_result_is_ok(r)) {
                return n00b_result_get(r)->buf;
            }
        }
    }

    auto r = n00b_bstream_from_file(rel);
    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

// Build a small obj bundle with a single executable artifact. The artifact
// payload distinguishes B (P2-a/b/e) from B' (P2-f) so round-trip equality is
// meaningful.
static n00b_obj_bundle_t *
make_test_bundle(n00b_string_t *payload_text)
{
    auto created = n00b_obj_bundle_new();
    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(created);
    // No dedicated n00b_string_t -> n00b_buffer_t primitive exists (buffer.h
    // only ships n00b_buffer_to_string the other way). Build the buffer from
    // the string's public bytes + length instead of reaching for the raw
    // char * via n00b_buffer_from_cstr, which would re-strlen and truncate on
    // any embedded NUL.
    n00b_buffer_t *payload = n00b_buffer_from_bytes(payload_text->data,
                                                    (int64_t)payload_text->u8_bytes);

    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            r"bin/tool",
                                            payload,
                                            .mode = 0755);
    if (n00b_result_is_err(add)) {
        return nullptr;
    }

    auto set_exec = n00b_obj_bundle_set_default_exec(bundle, r"bin/tool");
    if (n00b_result_is_err(set_exec)) {
        return nullptr;
    }

    return bundle;
}

// Encode a bundle to its canonical bytes (the equality oracle: two bundles are
// "equal" iff their canonical encodings are byte-identical, mirroring the ELF
// carrier suite's require_read_success).
static n00b_buffer_t *
encode_bundle(n00b_obj_bundle_t *bundle)
{
    auto encoded = n00b_obj_bundle_encode(bundle);
    if (n00b_result_is_err(encoded)) {
        return nullptr;
    }
    return n00b_result_get(encoded);
}

static bool
buffers_equal(n00b_buffer_t *a, n00b_buffer_t *b)
{
    return a != nullptr && b != nullptr && a->byte_len == b->byte_len
           && memcmp(a->data, b->data, a->byte_len) == 0;
}

// Extract the obj_bundle error code from a read result (the error struct is
// opaque; use the public accessor).
static n00b_obj_bundle_error_code_t
read_err_code(n00b_result_t(n00b_obj_bundle_t *) r)
{
    return n00b_obj_bundle_error_code(
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, r));
}

static n00b_obj_bundle_error_code_t
write_err_code(n00b_result_t(n00b_buffer_t *) r)
{
    return n00b_obj_bundle_error_code(
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, r));
}

// P2-a: write(macho_bytes, B) -> Ok (not UNSUPPORTED_CARRIER).
static void
test_p2a_write_ok(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-B");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-a: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    auto wr = n00b_obj_bundle_write(object_bytes, bundle);

    CHECK("P2-a public write(macho, B) == Ok (not UNSUPPORTED_CARRIER)",
          n00b_result_is_ok(wr));
}

// P2-b: read(write output) -> Ok; decoded bundle equals B.
static void
test_p2b_read_roundtrip(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-B");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-b: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *expected = encode_bundle(bundle);
    auto           wr       = n00b_obj_bundle_write(object_bytes, bundle);

    bool ok = n00b_result_is_ok(wr) && expected != nullptr;
    if (ok) {
        auto rd = n00b_obj_bundle_read(n00b_result_get(wr));
        ok      = n00b_result_is_ok(rd);
        if (ok) {
            n00b_buffer_t *got = encode_bundle(n00b_result_get(rd));
            ok = buffers_equal(got, expected);
        }
    }

    CHECK("P2-b public encode->write->read->decode round-trips B", ok);
}

// P2-c: read(unmodified macho, no carrier) -> BUNDLE_NOT_FOUND.
static void
test_p2c_read_not_found(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(TEST_FIXTURE_WRITE);

    if (object_bytes == nullptr) {
        printf("  [FAIL] P2-c: fixture unavailable\n");
        g_fail++;
        return;
    }

    auto rd = n00b_obj_bundle_read(object_bytes);

    CHECK("P2-c read(clean macho) == Err(BUNDLE_NOT_FOUND)",
          n00b_result_is_err(rd)
              && read_err_code(rd) == N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND);
}

// P2-d: unknown/corrupt format -> UNSUPPORTED_CARRIER (fallthrough intact).
static void
test_p2d_unknown_unsupported(void)
{
    // 64 bytes of a non-ELF / non-Mach-O / non-PE blob: format detection yields
    // UNKNOWN, so neither the ELF nor the Mach-O arm fires and the fallthrough
    // returns UNSUPPORTED_CARRIER.
    uint8_t blob[64];
    for (size_t i = 0; i < sizeof(blob); i++) {
        blob[i] = (uint8_t)(0x5a ^ i);
    }

    n00b_buffer_t *bytes = n00b_buffer_from_bytes((char *)blob,
                                                  (int64_t)sizeof(blob));
    auto           rd    = n00b_obj_bundle_read(bytes);

    CHECK("P2-d read(unknown blob) == Err(UNSUPPORTED_CARRIER)",
          n00b_result_is_err(rd)
              && read_err_code(rd) == N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
}

// P2-e: write into a binary that already has a carrier, REJECT_EXISTING ->
// RESERVED_NAMESPACE_OCCUPIED surfaced through the public API.
static void
test_p2e_reject_existing(void)
{
    n00b_buffer_t     *object_bytes = load_fixture_bytes(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t *bundle       = make_test_bundle(r"PAYLOAD-B");

    if (object_bytes == nullptr || bundle == nullptr) {
        printf("  [FAIL] P2-e: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    auto first = n00b_obj_bundle_write(object_bytes, bundle);

    bool ok = n00b_result_is_ok(first);
    if (ok) {
        auto second = n00b_obj_bundle_write(n00b_result_get(first),
                                            bundle,
                                            .replace = N00B_OBJ_BUNDLE_REJECT_EXISTING);
        ok = n00b_result_is_err(second)
             && write_err_code(second)
                    == N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED;
    }

    CHECK("P2-e public write(existing, REJECT) == "
          "Err(RESERVED_NAMESPACE_OCCUPIED)",
          ok);
}

// P2-f: write into a binary that already has a carrier, REPLACE_EXISTING with a
// new (smaller, in-slot) bundle B' -> read back equals B'.
//
// The WP-005/006 surgical replace is in-slot, so the replacement canonical must
// be no larger than the original payload slot (deferral #1: larger payloads
// need grow-then-relocate, out of WP-008 scope). B is given a longer artifact
// payload than B' so the in-slot replace is exercised with a genuinely
// different, smaller canonical.
static void
test_p2f_replace_roundtrip(void)
{
    n00b_buffer_t *object_bytes = load_fixture_bytes(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t *bundle_b  = make_test_bundle(
        r"PAYLOAD-B-LONGER-INITIAL-CONTENTS-FOR-IN-SLOT-REPLACE");
    n00b_obj_bundle_t *bundle_bp = make_test_bundle(r"B2");

    if (object_bytes == nullptr || bundle_b == nullptr || bundle_bp == nullptr) {
        printf("  [FAIL] P2-f: fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *expected_bp = encode_bundle(bundle_bp);
    auto           first       = n00b_obj_bundle_write(object_bytes, bundle_b);

    bool ok = n00b_result_is_ok(first) && expected_bp != nullptr;
    if (ok) {
        auto replaced = n00b_obj_bundle_write(
            n00b_result_get(first),
            bundle_bp,
            .replace = N00B_OBJ_BUNDLE_REPLACE_EXISTING);
        ok = n00b_result_is_ok(replaced);
        if (ok) {
            auto rd = n00b_obj_bundle_read(n00b_result_get(replaced));
            ok      = n00b_result_is_ok(rd);
            if (ok) {
                n00b_buffer_t *got = encode_bundle(n00b_result_get(rd));
                ok = buffers_equal(got, expected_bp);
            }
        }
    }

    CHECK("P2-f public write(existing, REPLACE, B') round-trips B'", ok);
}

// P2-g: ELF carrier round-trip stays green (D-005 no-regression). The
// substantive ELF encode->write->read->decode round-trip through the public API
// is covered by the companion suite test_objfile_obj_bundle_carrier
// (test_read_valid_elf_carrier / the ELF write tests), which the WP-008 Phase 2
// build runs as its second target precisely to prove the ELF path did not
// regress. Building a valid ELF carrier from scratch here would duplicate that
// suite's ~500 lines of ELF writer scaffolding (which lives only in that test,
// not a shared header), so P2-g asserts the dispatch invariant the Mach-O arm
// must preserve: format detection still routes ELF-magic bytes to the ELF arm
// (not the Mach-O arm). An ELF arm hitting non-carrier ELF returns
// BUNDLE_NOT_FOUND; the Mach-O arm on the same bytes would never run.
static void
test_p2g_elf_not_regressed(void)
{
    // 64-byte ELF64 little-endian header stub: enough magic for n00b_detect_format
    // to classify ELF and route to the ELF arm. The ELF arm then parses it and,
    // finding no .0c001.bundle carrier (or a malformed object), returns an
    // obj_bundle error that is NOT the Mach-O arm's path. The point is the route:
    // a value other than the Mach-O fallthrough proves ELF dispatch is intact.
    uint8_t elf[64] = {};
    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB

    n00b_buffer_t *bytes = n00b_buffer_from_bytes((char *)elf, (int64_t)sizeof(elf));
    auto           rd    = n00b_obj_bundle_read(bytes);

    // ELF dispatch is intact iff the result is NOT the unsupported-format
    // fallthrough (which is what a non-ELF/non-Mach-O blob yields, P2-d) and NOT
    // a Mach-O-specific code path. A malformed/short ELF surfaces a malformed or
    // not-found carrier error from the ELF arm.
    bool routed_to_elf =
        n00b_result_is_err(rd)
        && read_err_code(rd) != N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER;

    CHECK("P2-g ELF-magic bytes still route to the ELF arm "
          "(full ELF round-trip green in companion suite)",
          routed_to_elf);
}

// ===========================================================================
// WP-009 Phase 1: LOADABLE carrier (descriptor codec + read/write round-trip).
//
// Direct backend calls; deterministic, host-neutral, always-run (D-006). Matrix
// cases P1-a..P1-f per the WP-009 plan. Labeled "W9 P1-x" so the per-case output
// is distinct from the WP-008 P1-x lines above.
// ===========================================================================

// Find the loadable LC_NOTE descriptor payload in a reparsed binary and decode
// it. Returns the decoded descriptor, or nullptr if absent/undecodable.
static n00b_macho_carrier_descriptor_t *
find_loadable_descriptor(n00b_macho_binary_t *bin)
{
    size_t want = strlen(N00B_MACHO_BUNDLE_NOTE_OWNER);

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];

        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || (size_t)cmd->raw_data->byte_len < TEST_NOTE_CMD_SIZE) {
            continue;
        }

        const uint8_t *raw   = (const uint8_t *)cmd->raw_data->data;
        const char    *owner = (const char *)(raw + TEST_NOTE_OWNER_OFF);

        if (want > 16 || memcmp(owner, N00B_MACHO_BUNDLE_NOTE_OWNER, want) != 0) {
            continue;
        }

        uint64_t p_off = (uint64_t)raw[TEST_NOTE_OFFSET_OFF]
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 1] << 8)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 2] << 16)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 3] << 24)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 4] << 32)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 5] << 40)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 6] << 48)
                       | ((uint64_t)raw[TEST_NOTE_OFFSET_OFF + 7] << 56);
        uint64_t p_sz  = (uint64_t)raw[TEST_NOTE_SIZE_OFF]
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 1] << 8)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 2] << 16)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 3] << 24)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 4] << 32)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 5] << 40)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 6] << 48)
                       | ((uint64_t)raw[TEST_NOTE_SIZE_OFF + 7] << 56);

        if (p_off + p_sz > (uint64_t)bin->stream->buf->byte_len) {
            return nullptr;
        }

        n00b_buffer_t *payload = n00b_buffer_from_bytes(
            (char *)bin->stream->buf->data + p_off,
            (int64_t)p_sz);

        auto decoded = n00b_macho_carrier_descriptor_decode(payload);

        if (n00b_result_is_err(decoded)) {
            return nullptr;
        }

        return n00b_result_get(decoded);
    }

    return nullptr;
}

// True if the reparsed binary has a non-__LINKEDIT, non-__PAGEZERO segment whose
// initprot grants read (the inserted read-only loadable carrier segment).
static bool
has_readonly_payload_segment(n00b_macho_binary_t *bin, uint64_t want_fileoff)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        if (seg->fileoff == want_fileoff && (seg->initprot & 0x1u) != 0) {
            return true;
        }
    }

    return false;
}

// W9 P1-a: hand-built LOADABLE descriptor -> encode/decode reproduces fields;
// encoded length == 64.
static void
test_w9_p1a_descriptor_roundtrip(void)
{
    n00b_macho_carrier_descriptor_t desc = {
        .kind                = N00B_MACHO_CARRIER_KIND_LOADABLE,
        .version_major       = N00B_MACHO_CARRIER_MAJOR,
        .version_minor       = N00B_MACHO_CARRIER_MINOR,
        .payload_file_offset = 0x4000,
        .payload_len         = 193,
        .records             = nullptr,
        .record_count        = 0,
    };

    for (uint32_t i = 0; i < N00B_MACHO_CARRIER_DIGEST_LEN; i++) {
        desc.payload_digest[i] = (uint8_t)(0xA0 + i);
    }

    auto enc = n00b_macho_carrier_descriptor_encode(&desc);

    bool ok = n00b_result_is_ok(enc);
    if (ok) {
        n00b_buffer_t *bytes = n00b_result_get(enc);
        ok = bytes != nullptr
             && bytes->byte_len == (int64_t)N00B_MACHO_CARRIER_HEADER_SIZE;

        if (ok) {
            auto dec = n00b_macho_carrier_descriptor_decode(bytes);
            ok       = n00b_result_is_ok(dec);
            if (ok) {
                n00b_macho_carrier_descriptor_t *back = n00b_result_get(dec);
                ok = back->kind == desc.kind
                     && back->payload_file_offset == desc.payload_file_offset
                     && back->payload_len == desc.payload_len
                     && back->record_count == 0
                     && back->records == nullptr
                     && memcmp(back->payload_digest,
                               desc.payload_digest,
                               N00B_MACHO_CARRIER_DIGEST_LEN)
                            == 0;
            }
        }
    }

    CHECK("W9 P1-a LOADABLE descriptor encode->decode reproduces fields, "
          "encoded len == 64",
          ok);
}

// W9 P1-b: write_carrier(LOADABLE) -> Ok; output parses; a token-matched LOADABLE
// LC_NOTE + a new read-only LC_SEGMENT_64 present; out >= in.
static void
test_w9_p1b_write_loadable(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] W9 P1-b: base fixture unavailable\n");
        g_fail += 2;
        return;
    }

    uint64_t in_len = (uint64_t)base->stream->buf->byte_len;

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] W9 P1-b: write_carrier(LOADABLE) failed\n");
        printf("  [FAIL] W9 P1-b: descriptor/segment unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t *out = n00b_result_get(wr);

    CHECK("W9 P1-b write_carrier(LOADABLE) Ok, output >= input",
          out != nullptr && (uint64_t)out->byte_len >= in_len);

    n00b_macho_binary_t *bin = reparse(out);

    n00b_macho_carrier_descriptor_t *desc = find_loadable_descriptor(bin);
    bool                             ok   =
        desc != nullptr
        && desc->kind == N00B_MACHO_CARRIER_KIND_LOADABLE
        && desc->payload_len == canonical->byte_len
        && has_readonly_payload_segment(bin, desc->payload_file_offset);

    CHECK("W9 P1-b output has token-matched LOADABLE LC_NOTE + read-only "
          "LC_SEGMENT_64",
          ok);
}

// W9 P1-c: read_loadable(P1-b output) -> the exact canonical bundle bytes.
static void
test_w9_p1c_read_loadable_roundtrip(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] W9 P1-c: base fixture unavailable\n");
        g_fail++;
        return;
    }

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] W9 P1-c: write_carrier(LOADABLE) failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(n00b_result_get(wr));
    auto                 rd  = _n00b_obj_bundle_macho_read_loadable(bin);

    bool ok = n00b_result_is_ok(rd);
    if (ok) {
        n00b_buffer_t *got = n00b_result_get(rd);
        ok = got != nullptr
             && got->byte_len == canonical->byte_len
             && memcmp(got->data, canonical->data, canonical->byte_len) == 0;
    }

    CHECK("W9 P1-c read_loadable round-trips canonical byte-for-byte", ok);
}

// W9 P1-d: one payload byte flipped -> read_loadable -> Err(DIGEST_MISMATCH).
static void
test_w9_p1d_digest_mismatch(n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] W9 P1-d: base fixture unavailable\n");
        g_fail++;
        return;
    }

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] W9 P1-d: write_carrier(LOADABLE) failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *out = n00b_result_get(wr);

    // Locate the descriptor to find the payload offset, then flip one payload
    // byte in a copy of the output.
    n00b_macho_binary_t             *probe = reparse(out);
    n00b_macho_carrier_descriptor_t *desc  = find_loadable_descriptor(probe);

    if (desc == nullptr || desc->payload_len == 0
        || desc->payload_file_offset + desc->payload_len
               > (uint64_t)out->byte_len) {
        printf("  [FAIL] W9 P1-d: could not locate payload to corrupt\n");
        g_fail++;
        return;
    }

    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);
    buf[desc->payload_file_offset] ^= 0xFF; // flip first payload byte

    n00b_buffer_t *corrupt = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(corrupt);
    auto                 rd  = _n00b_obj_bundle_macho_read_loadable(bin);

    CHECK("W9 P1-d read_loadable(flipped payload byte) == Err(DIGEST_MISMATCH)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd)
                     == N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH);
}

// W9 P1-e: out-of-range payload_file_offset+payload_len -> decode/read ->
// Err(BOUNDS). Two assertions: (1) the codec overflow guard on decode;
// (2) the read-path segment-extent bounds check via a patched descriptor.
static void
test_w9_p1e_bounds(n00b_buffer_t *canonical)
{
    // (1) Decode-level overflow: payload_file_offset + payload_len overflows.
    uint8_t hdr[N00B_MACHO_CARRIER_HEADER_SIZE] = {};
    memcpy(hdr, N00B_MACHO_CARRIER_MAGIC, N00B_MACHO_CARRIER_MAGIC_LEN);
    hdr[8]  = (uint8_t)N00B_MACHO_CARRIER_MAJOR;
    hdr[10] = (uint8_t)N00B_MACHO_CARRIER_MINOR;
    hdr[12] = (uint8_t)N00B_MACHO_CARRIER_HEADER_SIZE;
    hdr[13] = (uint8_t)(N00B_MACHO_CARRIER_HEADER_SIZE >> 8);
    hdr[14] = (uint8_t)N00B_MACHO_CARRIER_KIND_LOADABLE;
    // payload_file_offset = UINT64_MAX - 1 (@16), payload_len = 16 (@24).
    put64_le(hdr + 16, UINT64_MAX - 1);
    put64_le(hdr + 24, 16);

    n00b_buffer_t *bytes = n00b_buffer_from_bytes(
        (char *)hdr,
        (int64_t)N00B_MACHO_CARRIER_HEADER_SIZE);
    auto dec = n00b_macho_carrier_descriptor_decode(bytes);

    CHECK("W9 P1-e decode(payload off+len overflow) == Err(BOUNDS)",
          n00b_result_is_err(dec)
              && n00b_result_get_err(dec) == N00B_MACHO_CARRIER_ERR_BOUNDS);

    // (2) Read-path segment-extent bounds: write a real LOADABLE carrier, then
    // patch the descriptor's payload_file_offset+payload_len to run past the
    // file, and confirm read_loadable rejects with OUT_OF_BOUNDS.
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        printf("  [FAIL] W9 P1-e: base fixture unavailable\n");
        g_fail++;
        return;
    }

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        N00B_OBJ_BUNDLE_REJECT_EXISTING);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] W9 P1-e: write_carrier(LOADABLE) failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t       *out   = n00b_result_get(wr);
    n00b_macho_binary_t *probe = reparse(out);

    // Find the descriptor note's on-disk location to patch the payload_len
    // field inside the encoded descriptor.
    size_t   note_off  = SIZE_MAX;
    uint64_t desc_poff = 0;
    size_t   want      = strlen(N00B_MACHO_BUNDLE_NOTE_OWNER);

    for (uint32_t i = 0; i < probe->num_commands; i++) {
        n00b_macho_command_t *cmd = &probe->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || (size_t)cmd->raw_data->byte_len < TEST_NOTE_CMD_SIZE) {
            continue;
        }
        const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;
        if (want <= 16
            && memcmp(raw + TEST_NOTE_OWNER_OFF,
                      N00B_MACHO_BUNDLE_NOTE_OWNER,
                      want)
                   == 0) {
            const uint8_t *po = raw + TEST_NOTE_OFFSET_OFF;
            desc_poff         = (uint64_t)po[0] | ((uint64_t)po[1] << 8)
                      | ((uint64_t)po[2] << 16) | ((uint64_t)po[3] << 24)
                      | ((uint64_t)po[4] << 32) | ((uint64_t)po[5] << 40)
                      | ((uint64_t)po[6] << 48) | ((uint64_t)po[7] << 56);
            note_off = (size_t)desc_poff;
            break;
        }
    }

    if (note_off == SIZE_MAX) {
        printf("  [FAIL] W9 P1-e: descriptor note not found to patch\n");
        g_fail++;
        return;
    }

    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);
    // The descriptor's payload_len is at offset 24 within the descriptor bytes,
    // which start at desc_poff in the file. Patch it to overrun the file.
    put64_le(buf + desc_poff + 24, len + 0x10000);

    n00b_buffer_t *patched = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(patched);
    auto                 rd  = _n00b_obj_bundle_macho_read_loadable(bin);

    CHECK("W9 P1-e read_loadable(payload range past segment) == "
          "Err(OUT_OF_BOUNDS)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd) == N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS);
}

// W9 P1-f: err_str / kind_str sweep -> non-null + non-fallback for defined
// values (already implemented in WP-008; assert here).
static void
test_w9_p1f_str_sweep(void)
{
    n00b_string_t *fallback_err =
        n00b_macho_carrier_err_str((n00b_err_t)0x7ffffff);
    n00b_string_t *fallback_kind =
        n00b_macho_carrier_kind_str((n00b_macho_carrier_kind_t)0x7fff);

    const n00b_err_t errs[] = {
        N00B_MACHO_CARRIER_OK,
        N00B_MACHO_CARRIER_ERR_NULL_INPUT,
        N00B_MACHO_CARRIER_ERR_SHORT_HEADER,
        N00B_MACHO_CARRIER_ERR_BAD_MAGIC,
        N00B_MACHO_CARRIER_ERR_BAD_VERSION,
        N00B_MACHO_CARRIER_ERR_BAD_HEADER_SIZE,
        N00B_MACHO_CARRIER_ERR_BAD_KIND,
        N00B_MACHO_CARRIER_ERR_BOUNDS,
        N00B_MACHO_CARRIER_ERR_DIGEST,
        N00B_MACHO_CARRIER_ERR_RECORD_COUNT,
    };

    bool ok = fallback_err != nullptr && fallback_kind != nullptr;

    for (size_t i = 0; ok && i < sizeof(errs) / sizeof(errs[0]); i++) {
        n00b_string_t *s = n00b_macho_carrier_err_str(errs[i]);
        ok = s != nullptr && !n00b_unicode_str_eq(s, fallback_err);
    }

    const n00b_macho_carrier_kind_t kinds[] = {
        N00B_MACHO_CARRIER_KIND_LOADABLE,
        N00B_MACHO_CARRIER_KIND_SPLIT,
    };

    for (size_t i = 0; ok && i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        n00b_string_t *s = n00b_macho_carrier_kind_str(kinds[i]);
        ok = s != nullptr && !n00b_unicode_str_eq(s, fallback_kind);
    }

    CHECK("W9 P1-f err_str/kind_str non-null + non-fallback for defined values",
          ok);
}

// ===========================================================================
// WP-010 Phase 1: SPLIT carrier (plan / descriptor-with-aux encode / write).
//
// Direct backend calls; deterministic, host-neutral, always-run (D-006). Matrix
// cases P1-a..P1-d per the WP-010 plan. Labeled "W10 P1-x".
// ===========================================================================

// W10 P1-0: D-039 CRC-32 known-answer — n00b_crc32("123456789") == 0xCBF43926
// (the standard IEEE 802.3 / zlib check value), plus crc32("") == 0.
static void
test_w10_p10_crc32_kat(void)
{
    uint32_t check = n00b_crc32("123456789", 9);
    uint32_t empty = n00b_crc32(nullptr, 0);

    CHECK("W10 P1-0 n00b_crc32 KAT: \"123456789\"==0xCBF43926, \"\"==0",
          check == 0xCBF43926u && empty == 0u);
}

// W10 P1-a: plan_split(bundle, canonical) -> Ok, kind==SPLIT, skeleton blob
// present (D-040: NO skeleton record), record_count == executable_slice_count.
// The test bundle has exactly one executable artifact ("bin/tool"), so
// record_count == 1.
static void
test_w10_p1a_plan_split(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-A");

    if (bundle == nullptr) {
        printf("  [FAIL] W10 P1-a: bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);

    if (canonical == nullptr) {
        printf("  [FAIL] W10 P1-a: bundle encode failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *segment = nullptr;
    auto           plan    = _n00b_obj_bundle_macho_plan_split(
        bundle,
        canonical,
        .segment_payload_out = &segment);

    bool ok = n00b_result_is_ok(plan);
    if (ok) {
        n00b_macho_carrier_descriptor_t *desc = n00b_result_get(plan);

        ok = desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT
             && desc->record_count == 1 // one executable slice ("bin/tool")
             && desc->records != nullptr
             && desc->skeleton != nullptr
             && segment != nullptr
             && (uint64_t)desc->skeleton->byte_len == desc->skeleton_len;
    }

    CHECK("W10 P1-a plan_split Ok, kind==SPLIT, skeleton blob present (NO "
          "skeleton record), record_count == executable_slice_count",
          ok);
}

// W10 P1-a2: plan_split on a bundle with NO executable artifact ->
// Err(UNSUPPORTED_CARRIER) (D-040: SPLIT requires ≥1 executable slice).
static void
test_w10_p1a2_plan_split_no_exec(void)
{
    auto created = n00b_obj_bundle_new();

    if (n00b_result_is_err(created)) {
        printf("  [FAIL] W10 P1-a2: bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(created);
    // A single NON-executable artifact (default mode, no set_default_exec).
    n00b_buffer_t     *payload =
        n00b_buffer_from_bytes("DATA-ONLY-ARTIFACT", 18);

    auto add = n00b_obj_bundle_add_artifact(bundle, r"share/data", payload);

    if (n00b_result_is_err(add)) {
        printf("  [FAIL] W10 P1-a2: add_artifact failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);

    if (canonical == nullptr) {
        printf("  [FAIL] W10 P1-a2: bundle encode failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *segment = nullptr;
    auto           plan    = _n00b_obj_bundle_macho_plan_split(
        bundle,
        canonical,
        .segment_payload_out = &segment);

    bool ok = n00b_result_is_err(plan)
              && n00b_result_get_err(plan)
                     == N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER;

    CHECK("W10 P1-a2 plan_split on no-executable bundle -> "
          "Err(UNSUPPORTED_CARRIER)",
          ok);
}

// W10 P1-b: real excision (skeleton_len < canonical_len; skeleton_len + Σ
// slice_len == canonical_len; non-overlapping slices), encode length ==
// 64 + 16 + skeleton_len + record_count*48, and decode round-trips the skeleton
// + every record field (incl. slice_flags / slice_digest_crc — the W-1 fix).
static void
test_w10_p1b_descriptor_roundtrip(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-B");

    if (bundle == nullptr) {
        printf("  [FAIL] W10 P1-b: bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);

    if (canonical == nullptr) {
        printf("  [FAIL] W10 P1-b: bundle encode failed\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *segment = nullptr;
    auto           plan    = _n00b_obj_bundle_macho_plan_split(
        bundle,
        canonical,
        .segment_payload_out = &segment);

    if (n00b_result_is_err(plan)) {
        printf("  [FAIL] W10 P1-b: plan_split failed\n");
        g_fail++;
        return;
    }

    n00b_macho_carrier_descriptor_t *desc = n00b_result_get(plan);

    // Real excision: skeleton strictly smaller than canonical, and
    // skeleton_len + Σ slice_len == canonical_len (a partition of the bytes).
    uint64_t canonical_len = (uint64_t)canonical->byte_len;
    uint64_t sum_slice_len = 0;
    bool     non_overlap   = true;

    for (uint64_t i = 0; i < desc->record_count; i++) {
        sum_slice_len += desc->records[i].slice_len;
        for (uint64_t j = i + 1; j < desc->record_count; j++) {
            uint64_t a_off = desc->records[i].reconstruct_offset;
            uint64_t a_end = a_off + desc->records[i].slice_len;
            uint64_t b_off = desc->records[j].reconstruct_offset;
            uint64_t b_end = b_off + desc->records[j].slice_len;
            if (a_off < b_end && b_off < a_end) {
                non_overlap = false;
            }
        }
    }

    bool ok = desc->skeleton_len < canonical_len
              && desc->skeleton_len + sum_slice_len == canonical_len
              && (uint64_t)segment->byte_len == sum_slice_len
              && non_overlap;

    auto enc = n00b_macho_carrier_descriptor_encode(desc);

    if (ok) {
        ok = n00b_result_is_ok(enc);
    }

    if (ok) {
        n00b_buffer_t *bytes = n00b_result_get(enc);
        uint64_t       want  = (uint64_t)N00B_MACHO_CARRIER_HEADER_SIZE
                       + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE
                       + desc->skeleton_len
                       + desc->record_count * N00B_MACHO_CARRIER_RECORD_SIZE;
        ok = bytes != nullptr && (uint64_t)bytes->byte_len == want;

        if (ok) {
            auto dec = n00b_macho_carrier_descriptor_decode(bytes);
            ok       = n00b_result_is_ok(dec);
            if (ok) {
                n00b_macho_carrier_descriptor_t *back = n00b_result_get(dec);
                ok = back->kind == N00B_MACHO_CARRIER_KIND_SPLIT
                     && back->record_count == desc->record_count
                     && back->records != nullptr
                     && back->skeleton != nullptr
                     && back->skeleton_len == desc->skeleton_len
                     && (uint64_t)back->skeleton->byte_len == desc->skeleton_len
                     && buffers_equal(back->skeleton, desc->skeleton);

                for (uint64_t i = 0; ok && i < desc->record_count; i++) {
                    n00b_macho_carrier_split_record_t *a = &desc->records[i];
                    n00b_macho_carrier_split_record_t *b = &back->records[i];
                    ok = a->slice_payload_offset == b->slice_payload_offset
                         && a->slice_len == b->slice_len
                         && a->reconstruct_offset == b->reconstruct_offset
                         && a->artifact_id == b->artifact_id
                         && a->slice_flags == b->slice_flags
                         && a->slice_digest_crc == b->slice_digest_crc;
                }
            }
        }
    }

    CHECK("W10 P1-b SPLIT real excision (skeleton_len<canonical; "
          "skeleton_len+Σslice==canonical; non-overlapping); encode "
          "len==64+16+skeleton_len+rec*48; decode round-trips skeleton+records",
          ok);
}

// W10 P1-c: write_carrier(SPLIT, .bundle=...) -> output byte_len >= input;
// carrier LC_NOTE decodes kind==SPLIT with skeleton+records; LC_SEGMENT_64 holds
// the SLICES-ONLY payload (payload_len < canonical_len AND payload_len ==
// Σ slice_len); the segment payload SHA-256 == descriptor payload_digest
// (verify_digest -> Ok(true)).
static void
test_w10_p1c_write_split(void)
{
    n00b_macho_binary_t *base   = parse_fixture(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t   *bundle = make_test_bundle(r"SPLIT-PAYLOAD-C");

    if (base == nullptr || bundle == nullptr) {
        printf("  [FAIL] W10 P1-c: base fixture/bundle unavailable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);

    if (canonical == nullptr) {
        printf("  [FAIL] W10 P1-c: bundle encode failed\n");
        printf("  [FAIL] W10 P1-c: descriptor/digest unreachable\n");
        g_fail += 2;
        return;
    }

    uint64_t in_len        = (uint64_t)base->stream->buf->byte_len;
    uint64_t canonical_len = (uint64_t)canonical->byte_len;

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        N00B_OBJ_BUNDLE_REJECT_EXISTING,
        .bundle = bundle);

    if (n00b_result_is_err(wr)) {
        printf("  [FAIL] W10 P1-c: write_carrier(SPLIT) failed\n");
        printf("  [FAIL] W10 P1-c: descriptor/digest unreachable\n");
        g_fail += 2;
        return;
    }

    n00b_buffer_t *out = n00b_result_get(wr);

    CHECK("W10 P1-c write_carrier(SPLIT) Ok, output >= input",
          out != nullptr && (uint64_t)out->byte_len >= in_len);

    n00b_macho_binary_t             *bin  = reparse(out);
    n00b_macho_carrier_descriptor_t *desc = find_loadable_descriptor(bin);

    // The segment holds the SLICES ONLY: payload_len < canonical_len and equals
    // the sum of slice lengths (D-040).
    uint64_t sum_slice_len = 0;

    bool ok = desc != nullptr
              && desc->kind == N00B_MACHO_CARRIER_KIND_SPLIT
              && desc->record_count >= 1
              && desc->skeleton != nullptr
              && desc->payload_len < canonical_len
              && desc->payload_file_offset + desc->payload_len
                     <= (uint64_t)out->byte_len;

    if (ok) {
        for (uint64_t i = 0; i < desc->record_count; i++) {
            sum_slice_len += desc->records[i].slice_len;
        }
        ok = desc->payload_len == sum_slice_len;
    }

    if (ok) {
        n00b_buffer_t *segment_payload = n00b_buffer_get_slice(
            bin->stream->buf,
            (int64_t)desc->payload_file_offset,
            (int64_t)(desc->payload_file_offset + desc->payload_len));

        auto verified = n00b_macho_carrier_verify_digest(desc, segment_payload);
        ok = n00b_result_is_ok(verified) && n00b_result_get(verified);
    }

    CHECK("W10 P1-c carrier LC_NOTE decodes kind==SPLIT w/ skeleton+records; "
          "LC_SEGMENT_64 holds slices-only payload (payload_len<canonical and "
          "==Σslice); segment SHA-256 == payload_digest (verify_digest->Ok)",
          ok);
}

// W10 P1-d: write the same bundle twice -> byte-identical outputs (determinism).
static void
test_w10_p1d_determinism(void)
{
    n00b_macho_binary_t *base1  = parse_fixture(TEST_FIXTURE_WRITE);
    n00b_macho_binary_t *base2  = parse_fixture(TEST_FIXTURE_WRITE);
    n00b_obj_bundle_t   *bundle = make_test_bundle(r"SPLIT-PAYLOAD-D");

    if (base1 == nullptr || base2 == nullptr || bundle == nullptr) {
        printf("  [FAIL] W10 P1-d: base fixture/bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);

    if (canonical == nullptr) {
        printf("  [FAIL] W10 P1-d: bundle encode failed\n");
        g_fail++;
        return;
    }

    auto wr1 = _n00b_obj_bundle_macho_write_carrier(
        base1,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        N00B_OBJ_BUNDLE_REJECT_EXISTING,
        .bundle = bundle);
    auto wr2 = _n00b_obj_bundle_macho_write_carrier(
        base2,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        N00B_OBJ_BUNDLE_REJECT_EXISTING,
        .bundle = bundle);

    bool ok = n00b_result_is_ok(wr1) && n00b_result_is_ok(wr2)
              && buffers_equal(n00b_result_get(wr1), n00b_result_get(wr2));

    CHECK("W10 P1-d two SPLIT writes of the same bundle are byte-identical",
          ok);
}

// ===========================================================================
// WP-010 Phase 2: SPLIT carrier read / reconstruction + round-trip.
//
// Direct backend calls + one end-to-end public-API case; deterministic,
// host-neutral, always-run. Matrix cases P2-a..P2-g per the WP-010 plan.
// Labeled "W10 P2-x".
// ===========================================================================

// Write a SPLIT carrier into the unsigned base fixture and return the rewritten
// object bytes (or nullptr on failure). Shared P2 setup.
static n00b_buffer_t *
write_split_object(n00b_obj_bundle_t *bundle, n00b_buffer_t *canonical)
{
    n00b_macho_binary_t *base = parse_fixture(TEST_FIXTURE_WRITE);

    if (base == nullptr) {
        return nullptr;
    }

    auto wr = _n00b_obj_bundle_macho_write_carrier(
        base,
        canonical,
        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        N00B_OBJ_BUNDLE_REJECT_EXISTING,
        .bundle = bundle);

    if (n00b_result_is_err(wr)) {
        return nullptr;
    }

    return n00b_result_get(wr);
}

// Locate the SPLIT descriptor note's on-disk descriptor-byte offset (where the
// 64-byte header begins) in a reparsed binary. Returns SIZE_MAX if absent.
static size_t
split_descriptor_offset(n00b_macho_binary_t *bin)
{
    size_t want = strlen(N00B_MACHO_BUNDLE_NOTE_OWNER);

    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];

        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || (size_t)cmd->raw_data->byte_len < TEST_NOTE_CMD_SIZE) {
            continue;
        }

        const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;

        if (want > 16
            || memcmp(raw + TEST_NOTE_OWNER_OFF,
                      N00B_MACHO_BUNDLE_NOTE_OWNER,
                      want)
                   != 0) {
            continue;
        }

        const uint8_t *po = raw + TEST_NOTE_OFFSET_OFF;
        uint64_t       off =
            (uint64_t)po[0] | ((uint64_t)po[1] << 8) | ((uint64_t)po[2] << 16)
            | ((uint64_t)po[3] << 24) | ((uint64_t)po[4] << 32)
            | ((uint64_t)po[5] << 40) | ((uint64_t)po[6] << 48)
            | ((uint64_t)po[7] << 56);

        return (size_t)off;
    }

    return SIZE_MAX;
}

// W10 P2-a: write(SPLIT) -> read_split reconstructs canonical bytes
// byte-identical to the input canonical bundle.
static void
test_w10_p2a_read_roundtrip(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2A");

    if (bundle == nullptr) {
        printf("  [FAIL] W10 P2-a: bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);
    n00b_buffer_t *out = canonical ? write_split_object(bundle, canonical)
                                   : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-a: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *bin = reparse(out);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    bool ok = n00b_result_is_ok(rd);
    if (ok) {
        ok = buffers_equal(n00b_result_get(rd), canonical);
    }

    CHECK("W10 P2-a read_split reconstructs canonical byte-for-byte", ok);
}

// Build a bundle with TWO equal-length executable artifacts. Used by P2-b to
// produce a real two-slice SPLIT carrier whose segment layout can be reordered
// independently of canonical order. Both payloads are 16 bytes so the two slice
// byte-runs can be swapped in place.
static n00b_obj_bundle_t *
make_two_exec_bundle(void)
{
    auto created = n00b_obj_bundle_new();
    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(created);

    // Distinct 16-byte payloads so a wrong reconstruction is detectable.
    n00b_buffer_t *p1 = n00b_buffer_from_bytes("AAAAAAAA11111111", 16);
    n00b_buffer_t *p2 = n00b_buffer_from_bytes("BBBBBBBB22222222", 16);

    auto a1 = n00b_obj_bundle_add_artifact(bundle, r"bin/one", p1, .mode = 0755);
    auto a2 = n00b_obj_bundle_add_artifact(bundle, r"bin/two", p2, .mode = 0755);

    if (n00b_result_is_err(a1) || n00b_result_is_err(a2)) {
        return nullptr;
    }

    auto set_exec = n00b_obj_bundle_set_default_exec(bundle, r"bin/one");
    if (n00b_result_is_err(set_exec)) {
        return nullptr;
    }

    return bundle;
}

// W10 P2-b: reconstruction is record-driven (not positional). Build a two-slice
// SPLIT carrier, then PHYSICALLY swap the two equal-length slice byte-runs in the
// slices-only segment and swap the two records' slice_payload_offset fields to
// match — leaving record-array order and reconstruct_offset unchanged. The
// segment is now stored out-of-canonical-order, yet read_split must rebuild the
// canonical bytes byte-identically by keying off reconstruct_offset.
static void
test_w10_p2b_record_driven(void)
{
    n00b_obj_bundle_t *bundle = make_two_exec_bundle();

    if (bundle == nullptr) {
        printf("  [FAIL] W10 P2-b: two-exec bundle unavailable\n");
        g_fail++;
        return;
    }

    n00b_buffer_t *canonical = encode_bundle(bundle);
    n00b_buffer_t *out = canonical ? write_split_object(bundle, canonical)
                                   : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-b: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t             *probe = reparse(out);
    n00b_macho_carrier_descriptor_t *desc  = find_loadable_descriptor(probe);
    size_t                           desc_off = split_descriptor_offset(probe);

    // The reorder requires exactly two equal-length slices stored contiguously.
    bool eligible = desc != nullptr && desc->record_count == 2
                    && desc->records != nullptr && desc_off != SIZE_MAX
                    && desc->records[0].slice_len == desc->records[1].slice_len;

    if (!eligible) {
        printf("  [FAIL] W10 P2-b: expected two equal-length slices\n");
        g_fail++;
        return;
    }

    uint64_t slice_len = desc->records[0].slice_len;
    uint64_t seg_off   = desc->payload_file_offset;
    uint64_t s0_off    = desc->records[0].slice_payload_offset; // == 0
    uint64_t s1_off    = desc->records[1].slice_payload_offset; // == slice_len

    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);

    // Swap the two slice byte-runs in the segment payload.
    for (uint64_t k = 0; k < slice_len; k++) {
        uint8_t t                       = buf[seg_off + s0_off + k];
        buf[seg_off + s0_off + k]       = buf[seg_off + s1_off + k];
        buf[seg_off + s1_off + k]       = t;
    }

    // Swap the two records' slice_payload_offset so each record still points at
    // its own (relocated) bytes; reconstruct_offset is untouched. Record offsets:
    // skeleton begins at desc_off + 64 + 16; record[0] follows the skeleton.
    uint64_t skeleton_len =
        (uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE)
        | ((uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                              + 4)
           << 32);
    uint64_t rec0_off = desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                        + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE + skeleton_len;
    uint64_t rec1_off = rec0_off + N00B_MACHO_CARRIER_RECORD_SIZE;

    put64_le(buf + rec0_off + 0, s1_off); // record[0] now reads relocated slice0
    put64_le(buf + rec1_off + 0, s0_off); // record[1] now reads relocated slice1

    // The segment-payload SHA-256 is over the physical (now-reordered) bytes;
    // recompute it and patch the descriptor's payload_digest (offset 32 within
    // the descriptor) so the digest gate reflects the legitimate out-of-order
    // layout we just produced.
    n00b_buffer_t *new_segment = n00b_buffer_from_bytes(
        (char *)buf + seg_off,
        (int64_t)desc->payload_len);
    uint8_t new_digest[N00B_MACHO_CARRIER_DIGEST_LEN];
    n00b_macho_carrier_compute_digest(new_segment, new_digest);
    memcpy(buf + desc_off + 32, new_digest, N00B_MACHO_CARRIER_DIGEST_LEN);

    n00b_buffer_t *reordered = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(reordered);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    bool ok = n00b_result_is_ok(rd)
              && buffers_equal(n00b_result_get(rd), canonical);

    CHECK("W10 P2-b out-of-canonical-order segment slices still reconstruct "
          "byte-identical via reconstruct_offset (record-driven)",
          ok);
}

// W10 P2-c: corrupted segment payload (flip a byte) -> the per-slice CRC and the
// segment-payload SHA-256 both fail -> Err(DIGEST). (Patching the slice bytes is
// the cleanest way to break the digest without touching the descriptor.)
static void
test_w10_p2c_corrupt_digest(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2C");
    n00b_buffer_t     *canonical =
        bundle ? encode_bundle(bundle) : nullptr;
    n00b_buffer_t     *out =
        canonical ? write_split_object(bundle, canonical) : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-c: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t             *probe = reparse(out);
    n00b_macho_carrier_descriptor_t *desc  = find_loadable_descriptor(probe);

    if (desc == nullptr || desc->payload_len == 0) {
        printf("  [FAIL] W10 P2-c: descriptor/payload unavailable\n");
        g_fail++;
        return;
    }

    // Flip the first segment-payload (slices-only) byte.
    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);
    buf[desc->payload_file_offset] ^= 0xFF;

    n00b_buffer_t *corrupt = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(corrupt);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    CHECK("W10 P2-c read_split(corrupted payload digest) == Err(DIGEST)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd) == N00B_MACHO_CARRIER_ERR_DIGEST);
}

// W10 P2-d: tamper a single descriptor record's slice_digest_crc so it no longer
// matches the (unmodified) segment slice. The segment-payload SHA-256 still
// matches (we did not touch the slice bytes), so this isolates the per-slice CRC
// pre-check -> structured Err(DIGEST).
static void
test_w10_p2d_tampered_slice_crc(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2D");
    n00b_buffer_t     *canonical =
        bundle ? encode_bundle(bundle) : nullptr;
    n00b_buffer_t     *out =
        canonical ? write_split_object(bundle, canonical) : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-d: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *probe   = reparse(out);
    size_t               desc_off = split_descriptor_offset(probe);

    if (desc_off == SIZE_MAX) {
        printf("  [FAIL] W10 P2-d: descriptor note not found\n");
        g_fail++;
        return;
    }

    // First record begins at desc_off + 64 (header) + 16 (trailer words) +
    // skeleton_len. We read skeleton_len from the trailer to find it.
    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);

    uint64_t skeleton_len =
        (uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE)
        | ((uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                              + 4)
           << 32);
    uint64_t rec0_off = desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                        + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE + skeleton_len;
    // slice_digest_crc is at offset 40 within the 48-byte record (§4.1).
    put32_le(buf + rec0_off + 40,
             get32_le(buf + rec0_off + 40) ^ 0xFFFFFFFFu);

    n00b_buffer_t *tampered = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(tampered);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    CHECK("W10 P2-d read_split(tampered slice CRC) == Err(DIGEST)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd) == N00B_MACHO_CARRIER_ERR_DIGEST);
}

// W10 P2-e: malformed trailer — bump record_count so the LC_NOTE size no longer
// equals 64 + 16 + skeleton_len + record_count*48 -> decode rejects with
// Err(RECORD_COUNT) (surfaced through read_split).
static void
test_w10_p2e_malformed_trailer(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2E");
    n00b_buffer_t     *canonical =
        bundle ? encode_bundle(bundle) : nullptr;
    n00b_buffer_t     *out =
        canonical ? write_split_object(bundle, canonical) : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-e: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *probe   = reparse(out);
    size_t               desc_off = split_descriptor_offset(probe);

    if (desc_off == SIZE_MAX) {
        printf("  [FAIL] W10 P2-e: descriptor note not found\n");
        g_fail++;
        return;
    }

    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);

    // record_count is the second trailer word (at header + 8).
    size_t   rc_off = desc_off + N00B_MACHO_CARRIER_HEADER_SIZE + 8;
    uint64_t rc     = (uint64_t)get32_le(buf + rc_off)
                  | ((uint64_t)get32_le(buf + rc_off + 4) << 32);
    put64_le(buf + rc_off, rc + 1); // claim one more record than present

    n00b_buffer_t *bad = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(bad);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    CHECK("W10 P2-e read_split(record_count != note size) == Err(RECORD_COUNT)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd)
                     == N00B_MACHO_CARRIER_ERR_RECORD_COUNT);
}

// W10 P2-f: out-of-bounds slice_payload_offset — push record[0]'s
// slice_payload_offset past the slices-only segment payload -> Err(BOUNDS).
static void
test_w10_p2f_oob_slice(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2F");
    n00b_buffer_t     *canonical =
        bundle ? encode_bundle(bundle) : nullptr;
    n00b_buffer_t     *out =
        canonical ? write_split_object(bundle, canonical) : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-f: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    n00b_macho_binary_t *probe   = reparse(out);
    size_t               desc_off = split_descriptor_offset(probe);

    if (desc_off == SIZE_MAX) {
        printf("  [FAIL] W10 P2-f: descriptor note not found\n");
        g_fail++;
        return;
    }

    uint64_t len = (uint64_t)out->byte_len;
    uint8_t *buf = malloc(len);
    memcpy(buf, out->data, len);

    uint64_t skeleton_len =
        (uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE)
        | ((uint64_t)get32_le(buf + desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                              + 4)
           << 32);
    uint64_t rec0_off = desc_off + N00B_MACHO_CARRIER_HEADER_SIZE
                        + N00B_MACHO_CARRIER_SPLIT_TRAILER_SIZE + skeleton_len;
    // slice_payload_offset is at offset 0 within the record; set it way past the
    // segment payload so [off, off+len) escapes payload_len.
    put64_le(buf + rec0_off + 0, UINT64_MAX - 8);

    n00b_buffer_t *bad = n00b_buffer_from_bytes((char *)buf, (int64_t)len);
    free(buf);

    n00b_macho_binary_t *bin = reparse(bad);
    auto                 rd  = _n00b_obj_bundle_macho_read_split(bin);

    CHECK("W10 P2-f read_split(OOB slice_payload_offset) == Err(BOUNDS)",
          n00b_result_is_err(rd)
              && n00b_result_get_err(rd) == N00B_MACHO_CARRIER_ERR_BOUNDS);
}

// W10 P2-g: end-to-end public API — n00b_obj_bundle_read on a SPLIT-carrier
// object returns a bundle whose canonical encoding equals the source bundle's
// (Hook A success path + bundle-level SHA-256 re-validation).
static void
test_w10_p2g_end_to_end(void)
{
    n00b_obj_bundle_t *bundle = make_test_bundle(r"SPLIT-PAYLOAD-P2G");
    n00b_buffer_t     *canonical =
        bundle ? encode_bundle(bundle) : nullptr;
    n00b_buffer_t     *out =
        canonical ? write_split_object(bundle, canonical) : nullptr;

    if (out == nullptr) {
        printf("  [FAIL] W10 P2-g: write(SPLIT) setup failed\n");
        g_fail++;
        return;
    }

    auto rd = n00b_obj_bundle_read(out);
    bool ok = n00b_result_is_ok(rd);

    if (ok) {
        n00b_buffer_t *got = encode_bundle(n00b_result_get(rd));
        ok = buffers_equal(got, canonical);
    }

    CHECK("W10 P2-g n00b_obj_bundle_read(SPLIT object) == source artifacts",
          ok);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_buffer_t *canonical = make_canonical("CANONICAL-BUNDLE-BYTES", 193);

    printf("== WP-008 Phase 1: Mach-O carrier backend ==\n");
    test_p1a_detect_none(canonical);
    test_p1b_detect_metadata_raw(canonical);
    test_p1c_read_roundtrip(canonical);
    test_p1ef_check_reserved(canonical);
    test_p1g_detect_duplicate(canonical);
    test_p1h_detect_malformed(canonical);
    test_descriptor_magic_classified_loadable();

    printf("\n== WP-008 Phase 3: growth (larger-payload) METADATA replace ==\n");
    test_p3a_growth_replace_roundtrip(canonical);

    printf("\n== WP-008 Phase 2: public-API dispatch round-trip ==\n");
    test_p2a_write_ok();
    test_p2b_read_roundtrip();
    test_p2c_read_not_found();
    test_p2d_unknown_unsupported();
    test_p2e_reject_existing();
    test_p2f_replace_roundtrip();
    test_p2g_elf_not_regressed();

    printf("\n== WP-009 Phase 1: LOADABLE carrier round-trip ==\n");
    test_w9_p1a_descriptor_roundtrip();
    test_w9_p1b_write_loadable(canonical);
    test_w9_p1c_read_loadable_roundtrip(canonical);
    test_w9_p1d_digest_mismatch(canonical);
    test_w9_p1e_bounds(canonical);
    test_w9_p1f_str_sweep();

    printf("\n== WP-010 Phase 1: SPLIT carrier plan/encode/write ==\n");
    test_w10_p10_crc32_kat();
    test_w10_p1a_plan_split();
    test_w10_p1a2_plan_split_no_exec();
    test_w10_p1b_descriptor_roundtrip();
    test_w10_p1c_write_split();
    test_w10_p1d_determinism();

    printf("\n== WP-010 Phase 2: SPLIT carrier read / reconstruction ==\n");
    test_w10_p2a_read_roundtrip();
    test_w10_p2b_record_driven();
    test_w10_p2c_corrupt_digest();
    test_w10_p2d_tampered_slice_crc();
    test_w10_p2e_malformed_trailer();
    test_w10_p2f_oob_slice();
    test_w10_p2g_end_to_end();

    printf("\n== summary: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
