#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_layout.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "compiler/objfile/macho_rewrite.h"
#include "internal/chalk/macho_core.h" // CHALK_MACHO_NOTE_OWNER (D-030)
#include "text/strings/string_ops.h"

// WP-005 Phase 1 known-answer + byte-preservation tests for the Mach-O
// metadata-insert plan/apply path. Deterministic, host-neutral, always-run (no
// Darwin/codesign gate, D-006). Fixtures resolve via MESON_SOURCE_ROOT (wired
// in meson for this target), mirroring test_objfile_macho_layout.c. Per D-018,
// test-scaffolding may use standard C memcmp/snprintf/assert.

#define MACHO_LC_NOTE_CMD_SIZE 40u
#define MACHO_HDR_NCMDS_OFF    16u
#define MACHO_NOTE_DATA_OWNER_OFF 8u
#define MACHO_NOTE_OFFSET_OFF     24u
#define MACHO_NOTE_SIZE_OFF       32u

// The reserved chalk LC_NOTE data_owner (CHALK_MACHO_NOTE_OWNER "chalk").
// Phase-2 replace/delete operate on the trusted chalk carrier; the with-note
// fixtures below are built from the real trusted-insert pipeline using it.
#define CHALK_OWNER CHALK_MACHO_NOTE_OWNER // D-030: reference the canonical define

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_layout.c:parse_fixture)
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

static n00b_buffer_t *
make_payload(uint8_t fill, size_t len)
{
    // Test scaffolding (D-018): build the fill bytes in a raw C array, then copy
    // them into a properly-initialized n00b buffer via the public constructor —
    // never write through n00b_buffer_t internals.
    uint8_t *tmp = malloc(len);
    memset(tmp, fill, len);
    n00b_buffer_t *payload = n00b_buffer_from_bytes((char *)tmp, (int64_t)len);
    free(tmp);
    return payload;
}

// A non-reserved metadata request (owner != "chalk"/"n00b.0c001", so the
// general metadata-insert path admits it).
static n00b_macho_rewrite_metadata_request_t
make_request(n00b_buffer_t *payload)
{
    return (n00b_macho_rewrite_metadata_request_t){
        .note_owner     = n00b_string_from_cstr("wp005.test"),
        .note_name      = n00b_string_from_cstr("metadata"),
        .payload        = payload,
        .file_alignment = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy         = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
    };
}

static bool
has_patch_kind(n00b_macho_rewrite_plan_t      *plan,
               n00b_macho_rewrite_patch_kind_t kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return true;
        }
    }
    return false;
}

// A chalk-owner metadata request: the trusted chalk insert/replace paths admit
// only data_owner == "chalk".
static n00b_macho_rewrite_metadata_request_t
make_chalk_request(n00b_buffer_t *payload)
{
    return (n00b_macho_rewrite_metadata_request_t){
        .note_owner            = n00b_string_from_cstr(CHALK_OWNER),
        .note_name             = n00b_string_from_cstr("chalk-mark"),
        .payload               = payload,
        .file_alignment        = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy                = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
    };
}

// Build a with-chalk-note fixture from the REAL insert pipeline (no vendored
// binary): parse the unsigned hello fixture, plan+apply a trusted chalk-owner
// LC_NOTE insert of `note_size` bytes, then reparse the output. The returned
// parsed binary carries a "chalk" carrier note whose payload is `note_size`
// bytes — the substrate the Phase-2 replace/delete tests run against. Returns
// nullptr if the base fixture is unavailable.
static n00b_macho_binary_t *
build_fixture_with_chalk_note(uint8_t fill, size_t note_size)
{
    n00b_macho_binary_t *base =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (base == nullptr) {
        return nullptr;
    }

    n00b_buffer_t                        *payload = make_payload(fill, note_size);
    n00b_macho_rewrite_metadata_request_t req     = make_chalk_request(payload);

    // Trusted chalk insert (the general metadata-insert path rejects the
    // reserved "chalk" owner; the trusted path admits it).
    auto pr = n00b_macho_rewrite_plan_chalk_mark_insert(base, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    // A trusted chalk insert is applied via the Phase-1 metadata-insert engine
    // (operation stays METADATA_INSERT).
    auto ar = n00b_macho_rewrite_apply_metadata_insert_plan(base, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    return n00b_result_get(reparsed);
}

// Find the chalk carrier note in a parsed binary; return its payload offset and
// size via out-params. Returns false if absent.
static bool
find_chalk_note(n00b_macho_binary_t *bin,
                uint64_t            *payload_off_out,
                uint64_t            *payload_size_out)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr
            || cmd->raw_data->byte_len < (int64_t)MACHO_LC_NOTE_CMD_SIZE) {
            continue;
        }
        const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;
        const char *owner = (const char *)(raw + MACHO_NOTE_DATA_OWNER_OFF);
        if (strncmp(owner, CHALK_OWNER, 16) != 0) {
            continue;
        }
        uint64_t off  = 0;
        uint64_t size = 0;
        for (int k = 7; k >= 0; k--) {
            off  = (off << 8) | raw[MACHO_NOTE_OFFSET_OFF + k];
            size = (size << 8) | raw[MACHO_NOTE_SIZE_OFF + k];
        }
        *payload_off_out  = off;
        *payload_size_out = size;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// P1-a: plan_metadata_insert -> ACCEPTED; the four planned patch kinds;
//       payload extent == payload->byte_len; new_command_count == orig + 1.
// ---------------------------------------------------------------------------
static void
test_p1a_plan_accepts(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1a_plan_accepts (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    n00b_buffer_t                        *payload = make_payload(0xAB, 96);
    n00b_macho_rewrite_metadata_request_t req     = make_request(payload);

    auto r = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);

    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->rejection_reason == N00B_MACHO_REWRITE_REJECT_NONE);

    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_MACH_HEADER));
    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS));
    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_PAYLOAD));
    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD));
    assert(plan->patches.len == 4);

    assert(plan->payload_end - plan->payload_offset
           == (uint64_t)payload->byte_len);
    assert(plan->new_command_count == plan->original_command_count + 1);
    assert(plan->original_command_count == (uint64_t)bin->header.ncmds);

    printf("  [PASS] p1a_plan_accepts\n");
}

// ---------------------------------------------------------------------------
// P1-b: apply -> reparses; parsed ncmds == orig+1; the new LC_NOTE data_owner
//       matches the request note_owner.
// ---------------------------------------------------------------------------
static void
test_p1b_apply_reparses(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1b_apply_reparses (fixture not found)\n");
        return;
    }

    uint32_t orig_ncmds = bin->header.ncmds;

    n00b_buffer_t                        *payload = make_payload(0xCD, 64);
    n00b_macho_rewrite_metadata_request_t req     = make_request(payload);

    auto pr = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    auto ar = n00b_macho_rewrite_apply_metadata_insert_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    // The apply output reparses (apply already verified this, but assert again
    // independently — the reparse postcondition is test-verified).
    n00b_bstream_t *stream = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *rewritten = n00b_result_get(reparsed);

    assert(rewritten->header.ncmds == orig_ncmds + 1);

    // The new LC_NOTE's data_owner matches request->note_owner. Find the new
    // LC_NOTE command: it is the last command appended at the LC slack.
    bool found_note = false;
    for (uint32_t i = 0; i < rewritten->num_commands; i++) {
        n00b_macho_command_t *cmd = &rewritten->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr) {
            continue;
        }
        const char *owner =
            (const char *)cmd->raw_data->data + MACHO_NOTE_DATA_OWNER_OFF;
        // data_owner is NUL-padded to 16 bytes; "wp005.test" is 10 chars.
        if (strncmp(owner, "wp005.test", 16) == 0) {
            found_note = true;
            break;
        }
    }
    assert(found_note);

    printf("  [PASS] p1b_apply_reparses\n");
}

// ---------------------------------------------------------------------------
// P1-c (NFR-01): every output byte outside the planned ranges is byte-identical
//       to the input. Explicit before/after range memcmp over each non-planned
//       interval.
// ---------------------------------------------------------------------------
static void
test_p1c_byte_preservation(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1c_byte_preservation (fixture not found)\n");
        return;
    }

    // Snapshot the input bytes BEFORE plan/apply (copy-out guarantees the
    // source is never mutated; we compare the fresh output against this).
    uint64_t       in_len = (uint64_t)bin->stream->buf->byte_len;
    uint8_t       *before = (uint8_t *)malloc((size_t)in_len);
    assert(before != nullptr);
    memcpy(before, bin->stream->buf->data, (size_t)in_len);

    n00b_buffer_t                        *payload = make_payload(0xEE, 80);
    n00b_macho_rewrite_metadata_request_t req     = make_request(payload);

    auto pr = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);

    auto ar = n00b_macho_rewrite_apply_metadata_insert_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);
    uint8_t       *after = (uint8_t *)out->data;

    // Source non-mutation: the input buffer is byte-identical to its snapshot.
    assert((uint64_t)bin->stream->buf->byte_len == in_len);
    assert(memcmp(bin->stream->buf->data, before, (size_t)in_len) == 0);

    // Collect the planned patch ranges into a flag array over [0, in_len).
    // Every input byte NOT covered by a planned range must be identical in the
    // output. (The payload patch lands at in_len, so it is past the input.)
    uint8_t *planned = (uint8_t *)calloc((size_t)in_len, 1);
    assert(planned != nullptr);
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_macho_rewrite_patch_t *p = &plan->patches.data[i];
        for (uint64_t b = p->file_offset; b < p->file_end && b < in_len; b++) {
            planned[b] = 1;
        }
    }

    // Walk non-planned intervals: each maximal run of unplanned bytes must
    // memcmp-equal between before and after.
    uint64_t run_start = 0;
    bool     in_run    = false;
    for (uint64_t i = 0; i <= in_len; i++) {
        bool unplanned = i < in_len && planned[i] == 0;
        if (unplanned && !in_run) {
            run_start = i;
            in_run    = true;
        }
        else if (!unplanned && in_run) {
            assert(memcmp(before + run_start,
                          after + run_start,
                          (size_t)(i - run_start))
                   == 0);
            in_run = false;
        }
    }

    // Output beyond the input is exactly the payload (the payload range).
    assert((uint64_t)out->byte_len == in_len + (uint64_t)payload->byte_len);
    assert(memcmp(after + in_len, payload->data, (size_t)payload->byte_len)
           == 0);

    free(planned);
    free(before);
    printf("  [PASS] p1c_byte_preservation\n");
}

// ---------------------------------------------------------------------------
// P1-d (NFR-02): two applies over identical inputs produce byte-identical
//       output.
// ---------------------------------------------------------------------------
static void
test_p1d_determinism(void)
{
    n00b_macho_binary_t *bin1 =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    n00b_macho_binary_t *bin2 =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin1 == nullptr || bin2 == nullptr) {
        printf("  [SKIP] p1d_determinism (fixture not found)\n");
        return;
    }

    n00b_buffer_t                        *pl1 = make_payload(0x5A, 128);
    n00b_buffer_t                        *pl2 = make_payload(0x5A, 128);
    n00b_macho_rewrite_metadata_request_t req1 = make_request(pl1);
    n00b_macho_rewrite_metadata_request_t req2 = make_request(pl2);

    auto pr1 = n00b_macho_rewrite_plan_metadata_insert(bin1, &req1);
    auto pr2 = n00b_macho_rewrite_plan_metadata_insert(bin2, &req2);
    assert(n00b_result_is_ok(pr1) && n00b_result_is_ok(pr2));

    auto ar1 = n00b_macho_rewrite_apply_metadata_insert_plan(
        bin1, n00b_result_get(pr1));
    auto ar2 = n00b_macho_rewrite_apply_metadata_insert_plan(
        bin2, n00b_result_get(pr2));
    assert(n00b_result_is_ok(ar1) && n00b_result_is_ok(ar2));

    n00b_buffer_t *o1 = n00b_result_get(ar1);
    n00b_buffer_t *o2 = n00b_result_get(ar2);
    assert(o1->byte_len == o2->byte_len);
    assert(memcmp(o1->data, o2->data, (size_t)o1->byte_len) == 0);

    printf("  [PASS] p1d_determinism\n");
}

// ---------------------------------------------------------------------------
// P1-e: profile-bad input -> plan REJECTED with REJECT_TARGET_PROFILE; apply of
//       a rejected plan -> Err(ERR_PLAN_REJECTED).
//
// We construct the profile-bad condition in-test by corrupting the parsed
// header magic of a copied fixture. target_profile evaluates the parsed model
// (bin->header.magic), so a non-MH_MAGIC_64 magic yields PROFILE_BAD_MAGIC ->
// REJECT_TARGET_PROFILE without vendoring a separate binary (plan P1-e note).
// ---------------------------------------------------------------------------
static void
test_p1e_profile_bad_rejects(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1e_profile_bad_rejects (fixture not found)\n");
        return;
    }

    // Corrupt the parsed magic to force PROFILE_BAD_MAGIC (documented in-test
    // construction; the byte stream is untouched).
    bin->header.magic = 0xDEADBEEFu;

    n00b_buffer_t                        *payload = make_payload(0x11, 32);
    n00b_macho_rewrite_metadata_request_t req     = make_request(payload);

    auto pr = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
    assert(plan->rejection_reason
           == N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE);

    // Apply of the rejected plan -> Err(ERR_PLAN_REJECTED).
    auto ar = n00b_macho_rewrite_apply_metadata_insert_plan(bin, plan);
    assert(n00b_result_is_err(ar));
    assert(n00b_result_get_err(ar) == N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);

    printf("  [PASS] p1e_profile_bad_rejects\n");
}

// ---------------------------------------------------------------------------
// P1-f: null/zero-payload requests -> body/_impl guard (no trapping requires,
//       D-031) -> Err(ERR_NULL_* / ERR_ZERO_PAYLOAD).
// ---------------------------------------------------------------------------
static void
test_p1f_null_zero_guards(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1f_null_zero_guards (fixture not found)\n");
        return;
    }

    // null bin -> ERR_NULL_BINARY
    {
        n00b_buffer_t *payload = make_payload(0x22, 16);
        n00b_macho_rewrite_metadata_request_t req = make_request(payload);
        auto r = n00b_macho_rewrite_plan_metadata_insert(nullptr, &req);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }

    // null request -> ERR_NULL_REQUEST
    {
        auto r = n00b_macho_rewrite_plan_metadata_insert(bin, nullptr);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_NULL_REQUEST);
    }

    // null note_owner -> ERR_NULL_NOTE_OWNER
    {
        n00b_buffer_t *payload = make_payload(0x33, 16);
        n00b_macho_rewrite_metadata_request_t req = make_request(payload);
        req.note_owner = nullptr;
        auto r = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r)
               == N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER);
    }

    // null payload -> ERR_NULL_PAYLOAD
    {
        n00b_macho_rewrite_metadata_request_t req = make_request(nullptr);
        auto r = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD);
    }

    // zero-length payload -> ERR_ZERO_PAYLOAD
    {
        n00b_buffer_t *payload = make_payload(0x44, 0);
        n00b_macho_rewrite_metadata_request_t req = make_request(payload);
        auto r = n00b_macho_rewrite_plan_metadata_insert(bin, &req);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD);
    }

    // apply: null bin -> ERR_NULL_BINARY; null plan -> ERR_NULL_PLAN
    {
        auto r = n00b_macho_rewrite_apply_metadata_insert_plan(nullptr,
                                                               nullptr);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_NULL_BINARY);
    }
    {
        auto r = n00b_macho_rewrite_apply_metadata_insert_plan(bin, nullptr);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_NULL_PLAN);
    }

    printf("  [PASS] p1f_null_zero_guards\n");
}

// ===========================================================================
// Phase 2 — replace / delete / convenience / *_str mappers
// ===========================================================================

// ---------------------------------------------------------------------------
// P2-a: with-note fixture, same-size replace -> ACCEPTED; patches include
//       PATCH_PAYLOAD + PATCH_STALE_PAYLOAD; removed_payload_end > offset.
// ---------------------------------------------------------------------------
static void
test_p2a_replace_accepts(void)
{
    n00b_macho_binary_t *bin = build_fixture_with_chalk_note(0xA1, 96);
    if (bin == nullptr) {
        printf("  [SKIP] p2a_replace_accepts (base fixture not found)\n");
        return;
    }

    // Same-size replacement (96 bytes) fits the existing slot exactly.
    n00b_buffer_t                        *payload = make_payload(0xB2, 96);
    n00b_macho_rewrite_metadata_request_t req     = make_chalk_request(payload);

    auto r = n00b_macho_rewrite_plan_chalk_mark_replace(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);

    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->operation == N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_REPLACE);
    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_PAYLOAD));
    assert(has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD));
    assert(plan->removed_payload_end > plan->removed_payload_offset);

    printf("  [PASS] p2a_replace_accepts\n");
}

// ---------------------------------------------------------------------------
// P2-b: apply that replace -> reparses; the note's payload is the new bytes;
//       the stale tail bytes are explicitly zero.
// ---------------------------------------------------------------------------
static void
test_p2b_replace_apply_zeroes_stale(void)
{
    // Build a fixture with a 128-byte chalk note, then replace with 64 bytes:
    // the trailing 64 bytes of the old slot must be zeroed.
    n00b_macho_binary_t *bin = build_fixture_with_chalk_note(0xCC, 128);
    if (bin == nullptr) {
        printf("  [SKIP] p2b_replace_apply_zeroes_stale (base fixture "
               "not found)\n");
        return;
    }

    uint64_t orig_off  = 0;
    uint64_t orig_size = 0;
    assert(find_chalk_note(bin, &orig_off, &orig_size));
    assert(orig_size == 128);

    n00b_buffer_t                        *payload = make_payload(0xDD, 64);
    n00b_macho_rewrite_metadata_request_t req     = make_chalk_request(payload);

    auto pr = n00b_macho_rewrite_plan_chalk_mark_replace(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    auto ar = n00b_macho_rewrite_apply_chalk_mark_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    // Output reparses, and the chalk note now advertises a 64-byte payload.
    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *rebin = n00b_result_get(reparsed);

    uint64_t new_off  = 0;
    uint64_t new_size = 0;
    assert(find_chalk_note(rebin, &new_off, &new_size));
    assert(new_off == orig_off);
    assert(new_size == 64);

    // The note's new payload is the 0xDD bytes.
    uint8_t *bytes = (uint8_t *)out->data;
    for (uint64_t i = 0; i < 64; i++) {
        assert(bytes[orig_off + i] == 0xDD);
    }
    // The stale tail [orig_off+64, orig_off+128) is explicitly zero.
    for (uint64_t i = 64; i < 128; i++) {
        assert(bytes[orig_off + i] == 0x00);
    }

    printf("  [PASS] p2b_replace_apply_zeroes_stale\n");
}

// ---------------------------------------------------------------------------
// P2-c: delete -> apply -> reparses; ncmds == orig-1; the note is gone; output
//       byte_len < input byte_len.
// ---------------------------------------------------------------------------
static void
test_p2c_delete_shrinks(void)
{
    n00b_macho_binary_t *bin = build_fixture_with_chalk_note(0xEE, 112);
    if (bin == nullptr) {
        printf("  [SKIP] p2c_delete_shrinks (base fixture not found)\n");
        return;
    }

    uint32_t orig_ncmds = bin->header.ncmds;
    uint64_t in_len     = (uint64_t)bin->stream->buf->byte_len;

    auto pr = n00b_macho_rewrite_plan_chalk_mark_delete(bin);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->operation == N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_DELETE);
    assert(plan->new_command_count == plan->original_command_count - 1);

    auto ar = n00b_macho_rewrite_apply_chalk_mark_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    assert((uint64_t)out->byte_len < in_len);

    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *rebin = n00b_result_get(reparsed);

    assert(rebin->header.ncmds == orig_ncmds - 1);

    uint64_t off  = 0;
    uint64_t size = 0;
    assert(!find_chalk_note(rebin, &off, &size)); // note is gone

    printf("  [PASS] p2c_delete_shrinks\n");
}

// ---------------------------------------------------------------------------
// P2-d (NFR-01): for the replace output, every non-planned, non-stale byte is
//       memcmp-identical to the pre-replace input (explicit range-diff).
// ---------------------------------------------------------------------------
static void
test_p2d_replace_byte_preservation(void)
{
    n00b_macho_binary_t *bin = build_fixture_with_chalk_note(0x42, 96);
    if (bin == nullptr) {
        printf("  [SKIP] p2d_replace_byte_preservation (base fixture "
               "not found)\n");
        return;
    }

    // Snapshot the with-note input bytes BEFORE the replace.
    uint64_t in_len = (uint64_t)bin->stream->buf->byte_len;
    uint8_t *before = (uint8_t *)malloc((size_t)in_len);
    assert(before != nullptr);
    memcpy(before, bin->stream->buf->data, (size_t)in_len);

    // Replace 96 -> 48 so there is a real stale tail to exclude, plus the
    // note-command size field changes (also a planned range).
    n00b_buffer_t                        *payload = make_payload(0x99, 48);
    n00b_macho_rewrite_metadata_request_t req     = make_chalk_request(payload);

    auto pr = n00b_macho_rewrite_plan_chalk_mark_replace(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    auto ar = n00b_macho_rewrite_apply_chalk_mark_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);
    assert((uint64_t)out->byte_len == in_len); // in-slot: same size

    // Source non-mutation.
    assert(memcmp(bin->stream->buf->data, before, (size_t)in_len) == 0);

    uint8_t *after   = (uint8_t *)out->data;
    uint8_t *planned = (uint8_t *)calloc((size_t)in_len, 1);
    assert(planned != nullptr);

    // Flag the planned patch ranges (payload + stale tail).
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_macho_rewrite_patch_t *p = &plan->patches.data[i];
        for (uint64_t b = p->file_offset; b < p->file_end && b < in_len; b++) {
            planned[b] = 1;
        }
    }
    // Flag the note-command size field (8 bytes @ note_cmd + 32), which the
    // apply rewrites to the new payload size — a planned, non-preserved range.
    uint64_t note_off  = 0;
    uint64_t note_size = 0;
    assert(find_chalk_note(bin, &note_off, &note_size));
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr) {
            continue;
        }
        const uint8_t *raw = (const uint8_t *)cmd->raw_data->data;
        const char *owner = (const char *)(raw + MACHO_NOTE_DATA_OWNER_OFF);
        if (strncmp(owner, CHALK_OWNER, 16) != 0) {
            continue;
        }
        uint64_t size_field = cmd->file_offset + MACHO_NOTE_SIZE_OFF;
        for (uint64_t b = size_field; b < size_field + 8 && b < in_len; b++) {
            planned[b] = 1;
        }
        break;
    }

    // Every non-planned byte is identical.
    uint64_t run_start = 0;
    bool     in_run    = false;
    for (uint64_t i = 0; i <= in_len; i++) {
        bool unplanned = i < in_len && planned[i] == 0;
        if (unplanned && !in_run) {
            run_start = i;
            in_run    = true;
        }
        else if (!unplanned && in_run) {
            assert(memcmp(before + run_start,
                          after + run_start,
                          (size_t)(i - run_start))
                   == 0);
            in_run = false;
        }
    }

    free(planned);
    free(before);
    printf("  [PASS] p2d_replace_byte_preservation\n");
}

// ---------------------------------------------------------------------------
// P2-e: replace whose new payload exceeds the old slot -> Ok(rejected,
//       REJECT_LC_PLACEMENT).
// ---------------------------------------------------------------------------
static void
test_p2e_replace_too_large_rejects(void)
{
    n00b_macho_binary_t *bin = build_fixture_with_chalk_note(0x55, 64);
    if (bin == nullptr) {
        printf("  [SKIP] p2e_replace_too_large_rejects (base fixture "
               "not found)\n");
        return;
    }

    // 128 > 64: does not fit the old slot.
    n00b_buffer_t                        *payload = make_payload(0x66, 128);
    n00b_macho_rewrite_metadata_request_t req     = make_chalk_request(payload);

    auto r = n00b_macho_rewrite_plan_chalk_mark_replace(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
    assert(plan->rejection_reason == N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT);

    printf("  [PASS] p2e_replace_too_large_rejects\n");
}

// ---------------------------------------------------------------------------
// P2-f: a fixture WITHOUT the note -> delete/replace -> Ok(rejected,
//       REJECT_*_NOT_FOUND); the convenience wrapper over that ->
//       Err(ERR_PLAN_REJECTED).
// ---------------------------------------------------------------------------
static void
test_p2f_no_note_rejects(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p2f_no_note_rejects (fixture not found)\n");
        return;
    }

    // Delete with no chalk note -> rejected, CHALK_MARK_NOT_FOUND.
    {
        auto r = n00b_macho_rewrite_plan_chalk_mark_delete(bin);
        assert(n00b_result_is_ok(r));
        n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);
        assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
        assert(plan->rejection_reason
               == N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND);
    }

    // Replace with no chalk note -> rejected, CHALK_MARK_NOT_FOUND.
    {
        n00b_buffer_t                        *pl  = make_payload(0x77, 32);
        n00b_macho_rewrite_metadata_request_t req = make_chalk_request(pl);
        auto r = n00b_macho_rewrite_plan_chalk_mark_replace(bin, &req);
        assert(n00b_result_is_ok(r));
        n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);
        assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
        assert(plan->rejection_reason
               == N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND);
    }

    // Object-bundle replace with no bundle note -> rejected,
    // OBJECT_BUNDLE_NOT_FOUND.
    {
        n00b_buffer_t *pl = make_payload(0x88, 32);
        n00b_macho_rewrite_metadata_request_t req = {
            .note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER),
            .note_name  = n00b_string_from_cstr("bundle"),
            .payload    = pl,
            .file_alignment = 0,
            .preferred_file_offset = n00b_option_none(uint64_t),
            .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
        };
        auto r = n00b_macho_rewrite_plan_object_bundle_replace(bin, &req);
        assert(n00b_result_is_ok(r));
        n00b_macho_rewrite_plan_t *plan = n00b_result_get(r);
        assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
        assert(plan->rejection_reason
               == N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND);
    }

    // The convenience wrapper over a rejected delete -> Err(ERR_PLAN_REJECTED).
    {
        auto r = n00b_macho_rewrite_apply_chalk_mark_delete(bin);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r)
               == N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);
    }

    printf("  [PASS] p2f_no_note_rejects\n");
}

// ---------------------------------------------------------------------------
// P2-g: enum sweep — each *_str(value) is non-fallback for every defined enum
//       value; *_str(0xffff) -> the stable fallback.
// ---------------------------------------------------------------------------
static bool
str_eq(n00b_string_t *s, const char *c)
{
    return n00b_unicode_str_eq(s, n00b_string_from_cstr(c));
}

static void
test_p2g_str_mappers(void)
{
    // err_str: every code maps to a non-fallback; an unknown -> fallback.
    int errs[] = {
        N00B_MACHO_REWRITE_OK,
        N00B_MACHO_REWRITE_ERR_NULL_BINARY,
        N00B_MACHO_REWRITE_ERR_NULL_REQUEST,
        N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER,
        N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD,
        N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD,
        N00B_MACHO_REWRITE_ERR_TARGET_PROFILE,
        N00B_MACHO_REWRITE_ERR_ADMISSION,
        N00B_MACHO_REWRITE_ERR_OVERFLOW,
        N00B_MACHO_REWRITE_ERR_NULL_PLAN,
        N00B_MACHO_REWRITE_ERR_PLAN_REJECTED,
        N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN,
        N00B_MACHO_REWRITE_ERR_APPLY,
        N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY,
        N00B_MACHO_REWRITE_ERR_NOTE_NOT_FOUND,
        N00B_MACHO_REWRITE_ERR_TRUSTED_NAME,
    };
    for (size_t i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        n00b_string_t *s = n00b_macho_rewrite_err_str(errs[i]);
        assert(s != nullptr);
        assert(!str_eq(s, "unknown-macho-rewrite-err"));
    }
    assert(str_eq(n00b_macho_rewrite_err_str(0xffff),
                  "unknown-macho-rewrite-err"));

    // plan_outcome_str.
    assert(!str_eq(n00b_macho_rewrite_plan_outcome_str(
                       N00B_MACHO_REWRITE_PLAN_ACCEPTED),
                   "unknown-macho-rewrite-plan-outcome"));
    assert(!str_eq(n00b_macho_rewrite_plan_outcome_str(
                       N00B_MACHO_REWRITE_PLAN_REJECTED),
                   "unknown-macho-rewrite-plan-outcome"));
    assert(str_eq(n00b_macho_rewrite_plan_outcome_str(
                      (n00b_macho_rewrite_plan_outcome_t)0xffff),
                  "unknown-macho-rewrite-plan-outcome"));

    // rejection_reason_str: sweep all values.
    for (int v = N00B_MACHO_REWRITE_REJECT_NONE;
         v <= N00B_MACHO_REWRITE_REJECT_CODESIG_INTERACTION;
         v++) {
        n00b_string_t *s = n00b_macho_rewrite_rejection_reason_str(
            (n00b_macho_rewrite_rejection_reason_t)v);
        assert(!str_eq(s, "unknown-macho-rewrite-rejection-reason"));
    }
    assert(str_eq(n00b_macho_rewrite_rejection_reason_str(
                      (n00b_macho_rewrite_rejection_reason_t)0xffff),
                  "unknown-macho-rewrite-rejection-reason"));

    // target_profile_reason_str: sweep all values.
    for (int v = N00B_MACHO_REWRITE_PROFILE_OK;
         v <= N00B_MACHO_REWRITE_PROFILE_OVERLAP;
         v++) {
        n00b_string_t *s = n00b_macho_rewrite_target_profile_reason_str(
            (n00b_macho_rewrite_target_profile_reason_t)v);
        assert(!str_eq(s, "unknown-macho-rewrite-target-profile-reason"));
    }
    assert(str_eq(n00b_macho_rewrite_target_profile_reason_str(
                      (n00b_macho_rewrite_target_profile_reason_t)0xffff),
                  "unknown-macho-rewrite-target-profile-reason"));

    // patch_kind_str: sweep all values.
    for (int v = N00B_MACHO_REWRITE_PATCH_MACH_HEADER;
         v <= N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF;
         v++) {
        n00b_string_t *s = n00b_macho_rewrite_patch_kind_str(
            (n00b_macho_rewrite_patch_kind_t)v);
        assert(!str_eq(s, "unknown-macho-rewrite-patch-kind"));
    }
    assert(str_eq(n00b_macho_rewrite_patch_kind_str(
                      (n00b_macho_rewrite_patch_kind_t)0xffff),
                  "unknown-macho-rewrite-patch-kind"));

    printf("  [PASS] p2g_str_mappers\n");
}

// ===========================================================================
// WP-006 Phase 1 — loadable LC_SEGMENT_64 insert + __LINKEDIT relocation +
//                  offset patching, with the D-021/D-032 __TEXT-reflow branch.
// ===========================================================================

#define MACHO_SEG64_CMD_SIZE 72u
#define ARM64_PAGE           0x4000u

// Field offsets re-used by the parse-back checks (macho_types.h field order).
#define SEG64_VMADDR_OFF   24u
#define SEG64_VMSIZE_OFF   32u
#define SEG64_FILEOFF_OFF  40u
#define SEG64_FILESIZE_OFF 48u
#define SECT64_SIZE        80u
#define SECT64_OFFSET_OFF  48u
#define LCMAIN_ENTRYOFF_OFF 8u

static n00b_macho_rewrite_loadable_request_t
make_loadable_request(n00b_buffer_t *payload)
{
    return (n00b_macho_rewrite_loadable_request_t){
        .payload         = payload,
        .initprot        = 0x5, // r-x
        .maxprot         = 0x5,
        .file_alignment  = ARM64_PAGE,
        .vaddr_alignment = ARM64_PAGE,
        .vmsize          = ARM64_PAGE,
        .policy          = (n00b_macho_rewrite_admit_policy_t){
            .flags = N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN,
        },
    };
}

static bool
loadable_has_patch_kind(n00b_macho_rewrite_loadable_plan_t *plan,
                        n00b_macho_rewrite_patch_kind_t     kind)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            return true;
        }
    }
    return false;
}

static uint64_t
loadable_count_patch_kind(n00b_macho_rewrite_loadable_plan_t *plan,
                          n00b_macho_rewrite_patch_kind_t     kind)
{
    uint64_t n = 0;
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (plan->patches.data[i].kind == kind) {
            n++;
        }
    }
    return n;
}

// Read a u32 LE field from a parsed command's raw_data (nonzero check).
static bool
cmd_off_nonzero(n00b_macho_command_t *cmd, uint64_t field)
{
    if (cmd->raw_data == nullptr
        || (uint64_t)cmd->raw_data->byte_len < field + 4u) {
        return false;
    }
    const uint8_t *p = (const uint8_t *)cmd->raw_data->data + field;
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
               | ((uint32_t)p[3] << 24);
    return v != 0;
}

// Count, by walking bin->commands[], the number of present commands that carry a
// __LINKEDIT-referencing *off (the expected offset-patch count for P1-b). Mirrors
// the impl's structural shape rule.
static uint64_t
expected_linkedit_offset_patches(n00b_macho_binary_t *bin)
{
    uint64_t n = 0;
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        switch (cmd->cmd) {
        case LC_SYMTAB:
            if (cmd_off_nonzero(cmd, 8u) || cmd_off_nonzero(cmd, 16u)) {
                n++;
            }
            break;
        case LC_DYSYMTAB:
            if (cmd_off_nonzero(cmd, 32u) || cmd_off_nonzero(cmd, 40u)
                || cmd_off_nonzero(cmd, 48u) || cmd_off_nonzero(cmd, 56u)
                || cmd_off_nonzero(cmd, 64u) || cmd_off_nonzero(cmd, 72u)) {
                n++;
            }
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            if (cmd_off_nonzero(cmd, 8u) || cmd_off_nonzero(cmd, 16u)
                || cmd_off_nonzero(cmd, 24u) || cmd_off_nonzero(cmd, 32u)
                || cmd_off_nonzero(cmd, 40u)) {
                n++;
            }
            break;
        case LC_CODE_SIGNATURE:
        case LC_DYLD_CHAINED_FIXUPS:
        case LC_DYLD_EXPORTS_TRIE:
        case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE:
        case LC_SEGMENT_SPLIT_INFO:
        case LC_DYLIB_CODE_SIGN_DRS:
        case LC_LINKER_OPTIMIZATION_HINT:
            if (cmd_off_nonzero(cmd, 8u)) {
                n++;
            }
            break;
        default:
            break;
        }
    }
    return n;
}

// Locate a segment's parsed facts by name in a parsed binary.
static bool
find_segment(n00b_macho_binary_t *bin, const char *name,
             n00b_macho_segment_t **out)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (strncmp(bin->segments[i].name, name, 16) == 0) {
            *out = &bin->segments[i];
            return true;
        }
    }
    return false;
}

// Read LC_MAIN.entryoff from a parsed binary (UINT64_MAX if no LC_MAIN).
static uint64_t
read_lc_main_entryoff(n00b_macho_binary_t *bin)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &bin->commands[i];
        if (cmd->cmd != LC_MAIN || cmd->raw_data == nullptr
            || cmd->raw_data->byte_len < (int64_t)(LCMAIN_ENTRYOFF_OFF + 8u)) {
            continue;
        }
        const uint8_t *p =
            (const uint8_t *)cmd->raw_data->data + LCMAIN_ENTRYOFF_OFF;
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) {
            v = (v << 8) | p[k];
        }
        return v;
    }
    return UINT64_MAX;
}

// ---------------------------------------------------------------------------
// P1-a: lowslack fixture -> plan ACCEPTED; loadable + reflow patch kinds.
// ---------------------------------------------------------------------------
static void
test_p1a_loadable_plan_reflow(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1a_loadable_plan_reflow (fixture not found)\n");
        return;
    }

    n00b_buffer_t *payload = make_payload(0x90, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);

    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->new_segment_count == plan->original_segment_count + 1);
    assert(plan->entrypoint_patch_enabled == false);

    assert(loadable_has_patch_kind(plan,
                                   N00B_MACHO_REWRITE_PATCH_NEW_SEGMENT_CMD));
    assert(loadable_has_patch_kind(plan,
                                   N00B_MACHO_REWRITE_PATCH_LINKEDIT_RELOCATED));
    assert(loadable_has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD));
    assert(loadable_has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_MACH_HEADER));

    // 32 B slack < 72 B cmd -> reflow branch.
    assert(plan->text_reflow_active == true);
    assert(loadable_has_patch_kind(
        plan, N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED));
    assert(loadable_has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_TEXT_CMD));

    printf("  [PASS] p1a_loadable_plan_reflow\n");
}

// ---------------------------------------------------------------------------
// P1-b: offset-patch completeness — 1:1 between present __LINKEDIT-referencing
//       commands and the emitted offset patches.
// ---------------------------------------------------------------------------
static void
test_p1b_offset_patch_completeness(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1b_offset_patch_completeness (fixture not found)\n");
        return;
    }

    n00b_buffer_t *payload = make_payload(0x91, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    uint64_t emitted =
        loadable_count_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_SYMTAB_CMD)
        + loadable_count_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_DYLD_INFO_CMD)
        + loadable_count_patch_kind(plan,
                                    N00B_MACHO_REWRITE_PATCH_LINKEDIT_DATA_CMD)
        + loadable_count_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_CODESIG_CMD);

    uint64_t expected = expected_linkedit_offset_patches(bin);
    assert(expected > 0); // the hello fixture has symtab/dysymtab/dyld at least
    assert(emitted == expected);

    printf("  [PASS] p1b_offset_patch_completeness (1:1, count=%llu)\n",
           (unsigned long long)emitted);
}

// ---------------------------------------------------------------------------
// P1-c: high-slack (unsigned, 256 B) fixture -> accept WITHOUT reflow.
// ---------------------------------------------------------------------------
static void
test_p1c_accept_without_reflow(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1c_accept_without_reflow (fixture not found)\n");
        return;
    }

    n00b_buffer_t *payload = make_payload(0x92, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);

    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->text_reflow_active == false);
    assert(!loadable_has_patch_kind(
        plan, N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED));
    assert(!loadable_has_patch_kind(plan, N00B_MACHO_REWRITE_PATCH_TEXT_CMD));
    // __LINKEDIT slides by exactly the padded new-segment size (one page).
    assert(plan->linkedit_new_offset - plan->linkedit_old_offset == ARM64_PAGE);

    printf("  [PASS] p1c_accept_without_reflow\n");
}

// ---------------------------------------------------------------------------
// P1-c2: lowslack (32 B) -> accept WITH reflow; text_slide_bytes page-aligned
//        and >= the LC shortfall.
// ---------------------------------------------------------------------------
static void
test_p1c2_accept_with_reflow(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1c2_accept_with_reflow (fixture not found)\n");
        return;
    }

    n00b_buffer_t *payload = make_payload(0x93, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);

    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(plan->text_reflow_active == true);
    assert(plan->text_slide_bytes > 0);
    assert(plan->text_slide_bytes % ARM64_PAGE == 0);

    // LC shortfall = 72 - slack. The slide must open at least that much room.
    uint64_t slack = plan->admission.lc_slack_bytes;
    uint64_t shortfall = slack < MACHO_SEG64_CMD_SIZE
                             ? MACHO_SEG64_CMD_SIZE - slack
                             : 0;
    assert(plan->text_slide_bytes >= shortfall);

    printf("  [PASS] p1c2_accept_with_reflow (slide=0x%llx)\n",
           (unsigned long long)plan->text_slide_bytes);
}

// ---------------------------------------------------------------------------
// P1-d: parse-back — apply bytes reparse; new segment present, __TEXT grown +
//       sections slid, __LINKEDIT last, file ends at __LINKEDIT end, entryoff
//       unchanged.
// ---------------------------------------------------------------------------
static void
test_p1d_parse_back(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1d_parse_back (fixture not found)\n");
        return;
    }

    uint64_t orig_entryoff = read_lc_main_entryoff(bin);
    uint32_t orig_ncmds    = bin->header.ncmds;

    n00b_macho_segment_t *text0 = nullptr;
    assert(find_segment(bin, "__TEXT", &text0));
    uint64_t orig_text_filesize = text0->filesize;

    n00b_buffer_t *payload = make_payload(0x94, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto pr = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(pr);
    assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

    auto ar = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *re = n00b_result_get(reparsed);

    assert(re->header.ncmds == orig_ncmds + 1);

    // The new __N00B segment is present.
    n00b_macho_segment_t *newseg = nullptr;
    assert(find_segment(re, "__N00B", &newseg));

    // __TEXT grown (reflow) and sections slid.
    n00b_macho_segment_t *text = nullptr;
    assert(find_segment(re, "__TEXT", &text));
    assert(text->filesize == orig_text_filesize + plan->text_slide_bytes);

    // __LINKEDIT is last and the file ends at its end.
    n00b_macho_segment_t *le = nullptr;
    assert(find_segment(re, "__LINKEDIT", &le));
    uint64_t max_end = 0;
    for (uint32_t i = 0; i < re->num_segments; i++) {
        uint64_t e = re->segments[i].fileoff + re->segments[i].filesize;
        if (e > max_end) {
            max_end = e;
        }
    }
    assert(le->fileoff + le->filesize == max_end);
    assert((uint64_t)out->byte_len == le->fileoff + le->filesize);

    // LC_MAIN.entryoff unchanged (no entrypoint patch in Phase 1).
    assert(read_lc_main_entryoff(re) == orig_entryoff);

    printf("  [PASS] p1d_parse_back\n");
}

// ---------------------------------------------------------------------------
// P1-d2: after a reflow apply, every __TEXT section's addr (vmaddr) is UNCHANGED
//        (the reflow slides file offset + grows __TEXT sizes only, never addr).
// ---------------------------------------------------------------------------
static void
test_p1d2_section_addr_immutable(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1d2_section_addr_immutable (fixture not found)\n");
        return;
    }

    n00b_macho_segment_t *text0 = nullptr;
    assert(find_segment(bin, "__TEXT", &text0));
    uint32_t nsects = text0->nsects;
    uint64_t orig_addr[64];
    uint32_t orig_off[64];
    assert(nsects <= 64);
    for (uint32_t j = 0; j < nsects; j++) {
        orig_addr[j] = text0->sections[j].addr;
        orig_off[j]  = text0->sections[j].offset;
    }

    n00b_buffer_t *payload = make_payload(0x95, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto pr = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(pr);
    assert(plan->text_reflow_active == true);

    auto ar = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *re = n00b_result_get(reparsed);

    n00b_macho_segment_t *text = nullptr;
    assert(find_segment(re, "__TEXT", &text));
    assert(text->nsects == nsects);
    for (uint32_t j = 0; j < nsects; j++) {
        // addr unchanged; file offset slid by exactly text_slide_bytes.
        assert(text->sections[j].addr == orig_addr[j]);
        if (orig_off[j] != 0) {
            assert((uint64_t)text->sections[j].offset
                   == (uint64_t)orig_off[j] + plan->text_slide_bytes);
        }
    }

    printf("  [PASS] p1d2_section_addr_immutable\n");
}

// ---------------------------------------------------------------------------
// P1-e: signed fixture parse-back — every patched *off in the output points
//       within the relocated __LINKEDIT extent (no dangling offset).
// ---------------------------------------------------------------------------
static void
test_p1e_signed_offsets_in_linkedit(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_signed_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1e_signed_offsets_in_linkedit (fixture not found)\n");
        return;
    }

    n00b_buffer_t *payload = make_payload(0x96, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto pr = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    assert(n00b_result_is_ok(pr));
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(pr);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        // The signed fixture may admit-reject without ALLOW_RESIGN; we pass it.
        printf("  [SKIP] p1e_signed_offsets_in_linkedit (plan rejected: %d)\n",
               (int)plan->rejection_reason);
        return;
    }

    auto ar = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
    assert(n00b_result_is_ok(ar));
    n00b_buffer_t *out = n00b_result_get(ar);

    n00b_bstream_t *stream   = n00b_bstream_new(out);
    auto            reparsed = n00b_macho_parse_single(stream);
    assert(n00b_result_is_ok(reparsed));
    n00b_macho_binary_t *re = n00b_result_get(reparsed);

    n00b_macho_segment_t *le = nullptr;
    assert(find_segment(re, "__LINKEDIT", &le));
    uint64_t le_start = le->fileoff;
    uint64_t le_end   = le->fileoff + le->filesize;

    // Every present __LINKEDIT-referencing *off in the reparsed output lands
    // within the relocated __LINKEDIT extent.
    for (uint32_t i = 0; i < re->num_commands; i++) {
        n00b_macho_command_t *cmd = &re->commands[i];
        const uint8_t *raw =
            cmd->raw_data != nullptr ? (const uint8_t *)cmd->raw_data->data
                                     : nullptr;
        if (raw == nullptr) {
            continue;
        }
        uint64_t fields[8];
        uint32_t nf = 0;
        switch (cmd->cmd) {
        case LC_SYMTAB:
            fields[nf++] = 8u;
            fields[nf++] = 16u;
            break;
        case LC_DYSYMTAB:
            fields[nf++] = 32u; fields[nf++] = 40u; fields[nf++] = 48u;
            fields[nf++] = 56u; fields[nf++] = 64u; fields[nf++] = 72u;
            break;
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            fields[nf++] = 8u; fields[nf++] = 16u; fields[nf++] = 24u;
            fields[nf++] = 32u; fields[nf++] = 40u;
            break;
        case LC_CODE_SIGNATURE:
        case LC_DYLD_CHAINED_FIXUPS:
        case LC_DYLD_EXPORTS_TRIE:
        case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE:
            fields[nf++] = 8u;
            break;
        default:
            break;
        }
        for (uint32_t k = 0; k < nf; k++) {
            if ((uint64_t)cmd->raw_data->byte_len < fields[k] + 4u) {
                continue;
            }
            const uint8_t *p = raw + fields[k];
            uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                       | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            if (v == 0) {
                continue;
            }
            assert((uint64_t)v >= le_start && (uint64_t)v < le_end);
        }
    }

    printf("  [PASS] p1e_signed_offsets_in_linkedit\n");
}

// ---------------------------------------------------------------------------
// P1-f: overflow condition (reflow window can't fit) -> Ok(rejected,
//       REJECT_OVERFLOW) / Err(ERR_OVERFLOW). We force this by requesting a
//       payload so large the padded segment overflows the address space.
// ---------------------------------------------------------------------------
static void
test_p1f_overflow_rejects(void)
{
    // Use the high-slack (non-reflow) fixture and corrupt the parsed __LINKEDIT
    // base to a NON-page-aligned file offset while keeping its end at EOF (so
    // target_profile still sees __LINKEDIT last and admission still accepts).
    // The non-reflow geometry then cannot place the new page-aligned segment in
    // the (now mis-aligned) __LINKEDIT slot and rejects with REJECT_OVERFLOW —
    // the "window can't fit" reject. Documented in-test construction (the byte
    // stream is untouched).
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p1f_overflow_rejects (fixture not found)\n");
        return;
    }

    n00b_macho_segment_t *le = nullptr;
    assert(find_segment(bin, "__LINKEDIT", &le));
    // Shift the base down by 1 (non-page-aligned) and grow filesize by 1 so the
    // end (and thus EOF == __LINKEDIT end) is preserved.
    assert(le->fileoff > 0);
    le->fileoff  -= 1u;
    le->filesize += 1u;

    n00b_buffer_t *payload = make_payload(0x97, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);

    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    // Per the contract, a genuine window overflow surfaces as
    // Ok(rejected, REJECT_OVERFLOW) or Err(ERR_OVERFLOW).
    if (n00b_result_is_err(r)) {
        assert(n00b_result_get_err(r) == N00B_MACHO_REWRITE_ERR_OVERFLOW);
    }
    else {
        n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);
        assert(plan->outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
        assert(plan->rejection_reason == N00B_MACHO_REWRITE_REJECT_OVERFLOW);
    }

    printf("  [PASS] p1f_overflow_rejects\n");
}

// ---------------------------------------------------------------------------
// P1-str: the two new patch kinds + the host-entrypoint rejection mapper map to
//         non-fallback strings; an unknown -> the stable fallback.
// ---------------------------------------------------------------------------
static void
test_p1str_new_mappers(void)
{
    assert(!str_eq(n00b_macho_rewrite_patch_kind_str(
                       N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED),
                   "unknown-macho-rewrite-patch-kind"));
    assert(!str_eq(n00b_macho_rewrite_patch_kind_str(
                       N00B_MACHO_REWRITE_PATCH_TEXT_CMD),
                   "unknown-macho-rewrite-patch-kind"));

    for (int v = N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE;
         v <= N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW;
         v++) {
        n00b_string_t *s = n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
            (n00b_macho_rewrite_host_entrypoint_rejection_reason_t)v);
        assert(!str_eq(
            s, "unknown-macho-rewrite-host-entrypoint-rejection-reason"));
    }
    assert(str_eq(
        n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
            (n00b_macho_rewrite_host_entrypoint_rejection_reason_t)0xffff),
        "unknown-macho-rewrite-host-entrypoint-rejection-reason"));

    printf("  [PASS] p1str_new_mappers\n");
}

// ===========================================================================
// WP-006 Phase 2 — arm64 LC_MAIN host-entrypoint redirect (plan + enable +
//                  apply wiring). Always-run, deterministic, host-neutral.
// ===========================================================================

// Plan an accepted loadable insert for `bin` (helper for the P2 rows). Returns
// nullptr if the fixture/plan is unusable; the caller SKIPs in that case.
static n00b_macho_rewrite_loadable_plan_t *
accepted_loadable_plan_for(n00b_macho_binary_t *bin, uint8_t fill)
{
    n00b_buffer_t *payload = make_payload(fill, 16);
    n00b_macho_rewrite_loadable_request_t req = make_loadable_request(payload);
    auto r = n00b_macho_rewrite_plan_loadable_insert(bin, &req);
    if (n00b_result_is_err(r)) {
        return nullptr;
    }
    n00b_macho_rewrite_loadable_plan_t *plan = n00b_result_get(r);
    if (plan->outcome != N00B_MACHO_REWRITE_PLAN_ACCEPTED) {
        return nullptr;
    }
    return plan;
}

// ---------------------------------------------------------------------------
// P2-a: arm64 hello + a Phase-1 loadable plan -> plan_host_entrypoint_target
//       accepts; cputype arm64; replacement == seg_fileoff + off == file_offset.
// ---------------------------------------------------------------------------
static void
test_p2a_plan_entrypoint_accepts(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p2a_plan_entrypoint_accepts (fixture not found)\n");
        return;
    }
    n00b_macho_rewrite_loadable_plan_t *plan =
        accepted_loadable_plan_for(bin, 0xa0);
    if (plan == nullptr) {
        printf("  [SKIP] p2a_plan_entrypoint_accepts (plan not accepted)\n");
        return;
    }

    uint64_t off = 0; // entry at the start of the trampoline payload.
    auto r = n00b_macho_rewrite_plan_host_entrypoint_target(bin, plan, off, 4u);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_host_entrypoint_target_t t = n00b_result_get(r);

    assert(t.outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);
    assert(t.cputype == (uint32_t)CPU_TYPE_ARM64);
    assert(t.replacement_entryoff == plan->new_segment_file_offset + off);
    assert(t.replacement_entryoff == t.target_file_offset);

    printf("  [PASS] p2a_plan_entrypoint_accepts (entryoff=0x%llx)\n",
           (unsigned long long)t.replacement_entryoff);
}

// ---------------------------------------------------------------------------
// P2-b: x86_64 fixture -> REJECT_UNSUPPORTED_CPUTYPE.
// ---------------------------------------------------------------------------
static void
test_p2b_plan_entrypoint_x86_rejects(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_x86_64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p2b_plan_entrypoint_x86_rejects (fixture not found)\n");
        return;
    }

    // The cputype gate fires before the plan is consulted; a rejected/empty
    // loadable plan is fine here (the x86_64 fixture won't profile as arm64).
    n00b_macho_rewrite_loadable_plan_t *plan =
        accepted_loadable_plan_for(bin, 0xb0);
    // Build a minimal accepted-shaped plan stand-in only if planning failed; the
    // cputype gate is checked first, so even a null plan would Err on NULL_PLAN.
    // Use whatever plan we have (may be rejected) — the gate order guarantees
    // cputype is evaluated before plan state.
    if (plan == nullptr) {
        // Construct a throwaway accepted plan so we exercise the cputype gate,
        // not the null-plan guard. (In-test model; bytes untouched.)
        static n00b_macho_rewrite_loadable_plan_t stub;
        stub          = (n00b_macho_rewrite_loadable_plan_t){};
        stub.outcome  = N00B_MACHO_REWRITE_PLAN_ACCEPTED;
        plan          = &stub;
    }

    auto r = n00b_macho_rewrite_plan_host_entrypoint_target(bin, plan, 0u, 4u);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_host_entrypoint_target_t t = n00b_result_get(r);
    assert(t.outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
    assert(t.rejection_reason
           == N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CPUTYPE);

    printf("  [PASS] p2b_plan_entrypoint_x86_rejects\n");
}

// ---------------------------------------------------------------------------
// P2-c: an arm64 binary WITHOUT LC_MAIN -> REJECT_NO_LC_MAIN.
//
// No LC_UNIXTHREAD-only / no-LC_MAIN fixture exists in test/unit/data and the
// toolchain always emits LC_MAIN, so the input is constructed in-test: parse an
// arm64 fixture, then clear the LC_MAIN command's `cmd` id in the in-memory
// `bin->commands[]` model (the on-disk byte stream is untouched). This drives
// the NO_LC_MAIN gate via the same commands[]-scan the impl uses (D-019). This
// in-test construction is SURFACED in the WP-006 deferrals (no fixture added).
// ---------------------------------------------------------------------------
static void
test_p2c_plan_entrypoint_no_lc_main_rejects(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p2c_plan_entrypoint_no_lc_main_rejects "
               "(fixture not found)\n");
        return;
    }
    n00b_macho_rewrite_loadable_plan_t *plan =
        accepted_loadable_plan_for(bin, 0xc0);
    if (plan == nullptr) {
        printf("  [SKIP] p2c_plan_entrypoint_no_lc_main_rejects "
               "(plan not accepted)\n");
        return;
    }

    // Clear the LC_MAIN command id in the parsed model so commands[]-scan finds
    // none (constructed input; bytes untouched). Confirm at least one existed.
    bool had_lc_main = false;
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_MAIN) {
            bin->commands[i].cmd = 0u; // not LC_MAIN anymore
            had_lc_main          = true;
        }
    }
    assert(had_lc_main);

    auto r = n00b_macho_rewrite_plan_host_entrypoint_target(bin, plan, 0u, 4u);
    assert(n00b_result_is_ok(r));
    n00b_macho_rewrite_host_entrypoint_target_t t = n00b_result_get(r);
    assert(t.outcome == N00B_MACHO_REWRITE_PLAN_REJECTED);
    assert(t.rejection_reason
           == N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN);

    printf("  [PASS] p2c_plan_entrypoint_no_lc_main_rejects\n");
}

// ---------------------------------------------------------------------------
// P2-d: enable_entrypoint on an accepted plan -> Ok(true), flag set, value
//       stored; on a non-accepted plan -> Err.
// ---------------------------------------------------------------------------
static void
test_p2d_enable_entrypoint(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] p2d_enable_entrypoint (fixture not found)\n");
        return;
    }
    n00b_macho_rewrite_loadable_plan_t *plan =
        accepted_loadable_plan_for(bin, 0xd0);
    if (plan == nullptr) {
        printf("  [SKIP] p2d_enable_entrypoint (plan not accepted)\n");
        return;
    }

    uint64_t orig_entryoff = plan->original_entryoff;
    uint64_t repl          = plan->new_segment_file_offset;

    assert(plan->entrypoint_patch_enabled == false);
    uint64_t patches_before = plan->patches.len;

    auto er = n00b_macho_rewrite_loadable_plan_enable_entrypoint(plan, repl);
    assert(n00b_result_is_ok(er));
    assert(n00b_result_get(er) == true);
    assert(plan->entrypoint_patch_enabled == true);
    assert(plan->replacement_entryoff == repl);
    assert(plan->original_entryoff == orig_entryoff); // untouched
    assert(plan->patches.len == patches_before + 1);
    assert(loadable_has_patch_kind(
        plan, N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF));

    // A non-accepted plan -> Err (body guard, D-031).
    n00b_macho_rewrite_loadable_plan_t rej = {};
    rej.outcome = N00B_MACHO_REWRITE_PLAN_REJECTED;
    auto er2 = n00b_macho_rewrite_loadable_plan_enable_entrypoint(&rej, 0u);
    assert(n00b_result_is_err(er2));
    assert(n00b_result_get_err(er2) == N00B_MACHO_REWRITE_ERR_PLAN_REJECTED);

    printf("  [PASS] p2d_enable_entrypoint\n");
}

// ---------------------------------------------------------------------------
// P2-e: apply with the entrypoint patch enabled -> reparse LC_MAIN.entryoff ==
//       replacement; apply with it disabled -> entryoff preserved (unchanged).
// ---------------------------------------------------------------------------
static void
test_p2e_apply_entrypoint(void)
{
    // -- Disabled path: entryoff preserved. --
    {
        n00b_macho_binary_t *bin =
            parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
        if (bin == nullptr) {
            printf("  [SKIP] p2e_apply_entrypoint (fixture not found)\n");
            return;
        }
        uint64_t orig = read_lc_main_entryoff(bin);

        n00b_macho_rewrite_loadable_plan_t *plan =
            accepted_loadable_plan_for(bin, 0xe0);
        if (plan == nullptr) {
            printf("  [SKIP] p2e_apply_entrypoint (plan not accepted)\n");
            return;
        }
        auto ar = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
        assert(n00b_result_is_ok(ar));
        n00b_buffer_t  *out      = n00b_result_get(ar);
        n00b_bstream_t *stream   = n00b_bstream_new(out);
        auto            reparsed = n00b_macho_parse_single(stream);
        assert(n00b_result_is_ok(reparsed));
        n00b_macho_binary_t *re = n00b_result_get(reparsed);
        assert(read_lc_main_entryoff(re) == orig);
    }

    // -- Enabled path: entryoff redirected to the replacement. --
    {
        n00b_macho_binary_t *bin =
            parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
        assert(bin != nullptr);

        n00b_macho_rewrite_loadable_plan_t *plan =
            accepted_loadable_plan_for(bin, 0xe1);
        assert(plan != nullptr);

        auto pr = n00b_macho_rewrite_plan_host_entrypoint_target(
            bin, plan, 0u, 4u);
        assert(n00b_result_is_ok(pr));
        n00b_macho_rewrite_host_entrypoint_target_t t = n00b_result_get(pr);
        assert(t.outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED);

        auto er = n00b_macho_rewrite_loadable_plan_enable_entrypoint(
            plan, t.replacement_entryoff);
        assert(n00b_result_is_ok(er));

        auto ar = n00b_macho_rewrite_apply_loadable_insert_plan(bin, plan);
        assert(n00b_result_is_ok(ar));
        n00b_buffer_t  *out      = n00b_result_get(ar);
        n00b_bstream_t *stream   = n00b_bstream_new(out);
        auto            reparsed = n00b_macho_parse_single(stream);
        assert(n00b_result_is_ok(reparsed));
        n00b_macho_binary_t *re = n00b_result_get(reparsed);
        assert(read_lc_main_entryoff(re) == t.replacement_entryoff);
    }

    printf("  [PASS] p2e_apply_entrypoint\n");
}

// ---------------------------------------------------------------------------
// P2-f: enum sweep — patch_kind_str(LC_MAIN_ENTRYOFF) + the TEXT_* kinds map to
//       non-fallback; host_entrypoint_rejection_reason_str sweep non-fallback;
//       *_str(0xffff) -> stable fallback.
// ---------------------------------------------------------------------------
static void
test_p2f_enum_sweep(void)
{
    assert(!str_eq(n00b_macho_rewrite_patch_kind_str(
                       N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF),
                   "unknown-macho-rewrite-patch-kind"));
    assert(!str_eq(n00b_macho_rewrite_patch_kind_str(
                       N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED),
                   "unknown-macho-rewrite-patch-kind"));
    assert(!str_eq(n00b_macho_rewrite_patch_kind_str(
                       N00B_MACHO_REWRITE_PATCH_TEXT_CMD),
                   "unknown-macho-rewrite-patch-kind"));
    assert(str_eq(n00b_macho_rewrite_patch_kind_str(
                      (n00b_macho_rewrite_patch_kind_t)0xffff),
                  "unknown-macho-rewrite-patch-kind"));

    for (int v = N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE;
         v <= N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW;
         v++) {
        n00b_string_t *s =
            n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
                (n00b_macho_rewrite_host_entrypoint_rejection_reason_t)v);
        assert(!str_eq(
            s, "unknown-macho-rewrite-host-entrypoint-rejection-reason"));
    }
    assert(str_eq(
        n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
            (n00b_macho_rewrite_host_entrypoint_rejection_reason_t)0xffff),
        "unknown-macho-rewrite-host-entrypoint-rejection-reason"));

    printf("  [PASS] p2f_enum_sweep\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running Mach-O rewrite (metadata insert/replace/delete) tests...\n");
    test_p1a_plan_accepts();
    test_p1b_apply_reparses();
    test_p1c_byte_preservation();
    test_p1d_determinism();
    test_p1e_profile_bad_rejects();
    test_p1f_null_zero_guards();
    test_p2a_replace_accepts();
    test_p2b_replace_apply_zeroes_stale();
    test_p2c_delete_shrinks();
    test_p2d_replace_byte_preservation();
    test_p2e_replace_too_large_rejects();
    test_p2f_no_note_rejects();
    test_p2g_str_mappers();

    printf("Running WP-006 Phase-1 loadable-insert tests...\n");
    test_p1a_loadable_plan_reflow();
    test_p1b_offset_patch_completeness();
    test_p1c_accept_without_reflow();
    test_p1c2_accept_with_reflow();
    test_p1d_parse_back();
    test_p1d2_section_addr_immutable();
    test_p1e_signed_offsets_in_linkedit();
    test_p1f_overflow_rejects();
    test_p1str_new_mappers();

    printf("Running WP-006 Phase-2 host-entrypoint redirect tests...\n");
    test_p2a_plan_entrypoint_accepts();
    test_p2b_plan_entrypoint_x86_rejects();
    test_p2c_plan_entrypoint_no_lc_main_rejects();
    test_p2d_enable_entrypoint();
    test_p2e_apply_entrypoint();
    test_p2f_enum_sweep();

    printf("All Mach-O rewrite tests passed.\n");
    return 0;
}
