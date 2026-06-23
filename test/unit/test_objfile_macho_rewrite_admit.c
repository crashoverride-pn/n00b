#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
#include "internal/chalk/macho_core.h" // CHALK_MACHO_NOTE_OWNER (D-030)
#include "text/strings/string_ops.h"

// WP-004 Phase 1 known-answer admission tests. Deterministic, host-neutral,
// always-run (no Darwin/codesign gate, D-006). Committed fixtures are resolved
// via MESON_SOURCE_ROOT (wired in meson for this target), mirroring
// test_objfile_macho_layout.c; absent fixtures [SKIP] cleanly rather than fail.

// The on-disk LC_NOTE command size; the slack reject fires below this (matches
// the admission impl's N00B_MACHO_LC_NOTE_CMD_SIZE / chalk MACHO_NOTE_CMD_SIZE).
#define LC_NOTE_CMD_SIZE 40u

// ----------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_layout.c:parse_fixture)
// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------
// CR-04 byte-non-mutation snapshot (P1-f)
// ----------------------------------------------------------------------------

typedef struct {
    uint64_t byte_len;
    uint64_t checksum;
    uint32_t ncmds;        // CR-04: parsed header must also be untouched
    uint32_t sizeofcmds;
    uintptr_t code_signature; // CR-04: parsed code-signature pointer untouched
} buf_snapshot_t;

static buf_snapshot_t
snapshot_buffer(n00b_macho_binary_t *bin)
{
    n00b_buffer_t *buf      = bin->stream->buf;
    uint64_t       len      = (uint64_t)buf->byte_len;
    uint64_t       checksum = 1469598103934665603ull; // FNV offset basis
    const uint8_t *bytes    = (const uint8_t *)buf->data;

    for (uint64_t i = 0; i < len; i++) {
        checksum ^= (uint64_t)bytes[i];
        checksum *= 1099511628211ull; // FNV prime
    }

    return (buf_snapshot_t){
        .byte_len       = len,
        .checksum       = checksum,
        .ncmds          = bin->header.ncmds,
        .sizeofcmds     = bin->header.sizeofcmds,
        .code_signature = (uintptr_t)bin->code_signature,
    };
}

// CR-04: admission must not mutate the byte buffer NOR the parsed model it
// reads (header command counts, code-signature region). Any in-test synthesis
// happens before the `before` snapshot, so this asserts the admit call itself
// is read-only over `bin`.
static void
assert_snapshot_unchanged(n00b_macho_binary_t *bin, buf_snapshot_t before)
{
    buf_snapshot_t after = snapshot_buffer(bin);
    assert(after.byte_len == before.byte_len);
    assert(after.checksum == before.checksum);
    assert(after.ncmds == before.ncmds);
    assert(after.sizeofcmds == before.sizeofcmds);
    assert(after.code_signature == before.code_signature);
}

// ----------------------------------------------------------------------------
// Request builders + verdict helpers
// ----------------------------------------------------------------------------

static n00b_macho_rewrite_admit_metadata_request_t
default_request(void)
{
    return (n00b_macho_rewrite_admit_metadata_request_t){
        .note_owner     = r"com.example.note",
        .note_name      = r"example",
        .payload_size   = 64,
        .file_alignment = 8,
        .policy         = {.flags = N00B_MACHO_REWRITE_ADMIT_POLICY_NONE},
    };
}

static n00b_macho_rewrite_admit_result_t
require_accepted(n00b_result_t(n00b_macho_rewrite_admit_result_t) result)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_result_t admit = n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    assert(admit.rejection_reason == N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    assert(n00b_option_is_set(admit.placement));
    return admit;
}

static n00b_macho_rewrite_admit_result_t
require_rejected(n00b_result_t(n00b_macho_rewrite_admit_result_t) result,
                 n00b_macho_rewrite_admit_rejection_reason_t      reason)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_result_t admit = n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED);
    assert(admit.rejection_reason == reason);
    assert(!n00b_option_is_set(admit.placement));
    return admit;
}

static void
assert_err(n00b_result_t(n00b_macho_rewrite_admit_result_t) result,
           n00b_err_t                                       err)
{
    assert(n00b_result_is_err(result));
    assert(n00b_result_get_err(result) == err);
}

// ----------------------------------------------------------------------------
// P1-h: null / zero guards (always-run; no fixture needed)
// ----------------------------------------------------------------------------

static void
test_null_zero_guards(void)
{
    n00b_macho_rewrite_admit_metadata_request_t request = default_request();

    assert_err(n00b_macho_rewrite_admit_metadata_insert(nullptr, &request),
               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY);

    // A zeroed binary is non-null but the request is null -> NULL_REQUEST.
    n00b_macho_binary_t empty = {};
    assert_err(n00b_macho_rewrite_admit_metadata_insert(&empty, nullptr),
               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);

    request            = default_request();
    request.note_owner = nullptr;
    assert_err(n00b_macho_rewrite_admit_metadata_insert(&empty, &request),
               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);

    request              = default_request();
    request.payload_size = 0;
    assert_err(n00b_macho_rewrite_admit_metadata_insert(&empty, &request),
               N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD);

    printf("  [PASS] null_zero_guards\n");
}

// ----------------------------------------------------------------------------
// P1-g: *_str enum sweep + out-of-range fallback (always-run)
// ----------------------------------------------------------------------------

static void
assert_non_empty(n00b_string_t *s)
{
    assert(s != nullptr);
    assert(s->u8_bytes > 0);
}

static void
test_stringifiers(void)
{
    assert_non_empty(n00b_macho_rewrite_admit_err_str(
        N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY));
    assert_non_empty(n00b_macho_rewrite_admit_err_str(
        N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST));
    assert_non_empty(n00b_macho_rewrite_admit_err_str(
        N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD));
    assert_non_empty(n00b_macho_rewrite_admit_err_str(
        N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE));
    assert_non_empty(n00b_macho_rewrite_admit_err_str(
        N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW));
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_err_str((n00b_err_t)1),
        r"Mach-O rewrite admission: unknown error code"));

    n00b_macho_rewrite_admit_policy_flag_t flags[] = {
        N00B_MACHO_REWRITE_ADMIT_POLICY_NONE,
        N00B_MACHO_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION,
        N00B_MACHO_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        N00B_MACHO_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY,
        N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN,
    };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        assert_non_empty(n00b_macho_rewrite_admit_policy_flag_str(flags[i]));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_policy_flag_str(
            (n00b_macho_rewrite_admit_policy_flag_t)UINT32_MAX),
        r"unknown-macho-rewrite-admit-policy-flag"));

    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_outcome_str(
            N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED),
        r"accepted"));
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_outcome_str(
            N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED),
        r"rejected"));
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_outcome_str(
            (n00b_macho_rewrite_admit_outcome_t)UINT32_MAX),
        r"unknown-macho-rewrite-admit-outcome"));

    n00b_macho_rewrite_admit_placement_kind_t kinds[] = {
        N00B_MACHO_REWRITE_ADMIT_PLACEMENT_NONE,
        N00B_MACHO_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
        N00B_MACHO_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
        N00B_MACHO_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
        N00B_MACHO_REWRITE_ADMIT_PLACEMENT_BEFORE_CODESIG,
    };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        assert_non_empty(
            n00b_macho_rewrite_admit_placement_kind_str(kinds[i]));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_placement_kind_str(
            (n00b_macho_rewrite_admit_placement_kind_t)UINT32_MAX),
        r"unknown-macho-rewrite-admit-placement-kind"));

    n00b_macho_rewrite_admit_rejection_reason_t reasons[] = {
        N00B_MACHO_REWRITE_ADMIT_REJECT_NONE,
        N00B_MACHO_REWRITE_ADMIT_REJECT_NOT_YET_CHECKED,
        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME,
        N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT,
        N00B_MACHO_REWRITE_ADMIT_REJECT_FILE_COLLISION,
        N00B_MACHO_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES,
        N00B_MACHO_REWRITE_ADMIT_REJECT_OVERLAY_POLICY,
        N00B_MACHO_REWRITE_ADMIT_REJECT_LC_HEADER_SLACK,
        N00B_MACHO_REWRITE_ADMIT_REJECT_LC_REGION_INCONSISTENT,
        N00B_MACHO_REWRITE_ADMIT_REJECT_LINKEDIT_NOT_LAST,
        N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_NOT_LAST,
        N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN,
        N00B_MACHO_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST,
        N00B_MACHO_REWRITE_ADMIT_REJECT_VMSIZE_TOO_SMALL,
        N00B_MACHO_REWRITE_ADMIT_REJECT_VADDR_COLLISION,
        N00B_MACHO_REWRITE_ADMIT_REJECT_FILEOFF_NOT_PAGE_ALIGNED,
        N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_SEGMENT,
        N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_NOT_EXECUTABLE,
        N00B_MACHO_REWRITE_ADMIT_REJECT_UNSUPPORTED_CPUTYPE,
        N00B_MACHO_REWRITE_ADMIT_REJECT_NO_LC_MAIN,
        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_TARGET,
        N00B_MACHO_REWRITE_ADMIT_REJECT_LOADER_PRESERVATION,
    };
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
        assert_non_empty(
            n00b_macho_rewrite_admit_rejection_reason_str(reasons[i]));
    }
    assert(n00b_unicode_str_eq(
        n00b_macho_rewrite_admit_rejection_reason_str(
            (n00b_macho_rewrite_admit_rejection_reason_t)UINT32_MAX),
        r"unknown-macho-rewrite-admit-rejection-reason"));

    printf("  [PASS] stringifiers\n");
}

// ----------------------------------------------------------------------------
// P1-a: accept. `hello_unsigned_arm64.macho` is an unsigned arm64 MH_EXECUTE
// with 256 B of LC slack (>= the 40 B LC_NOTE command), __LINKEDIT last, and the
// file ending at __LINKEDIT end — a clean known-answer accept, no in-test
// mutation (FIXTURES.md; resolves WP-004 DF-004-01).
// ----------------------------------------------------------------------------

static void
test_accept(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] accept (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_metadata_request_t request = default_request();
    buf_snapshot_t                              before  = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_result_t admit = require_accepted(
        n00b_macho_rewrite_admit_metadata_insert(bin, &request));

    assert(admit.file_size == (uint64_t)bin->stream->buf->byte_len);
    assert(admit.lc_slack_bytes >= LC_NOTE_CMD_SIZE);
    assert(admit.lc_region_offset == N00B_MACHO_HEADER_64_SIZE);
    assert(admit.lc_region_used == (uint64_t)bin->header.sizeofcmds);
    assert(!admit.code_signature_present);

    n00b_macho_rewrite_admit_placement_t placement =
        n00b_option_get(admit.placement);
    assert(placement.payload_size == request.payload_size);
    assert(placement.file_end - placement.file_offset >= request.payload_size);
    assert(placement.file_alignment == 8);

    assert_snapshot_unchanged(bin, before); // P1-f
    printf("  [PASS] accept\n");
}

// ----------------------------------------------------------------------------
// P1-b: LC-slack reject. `hello_lowslack_arm64.macho` is an unsigned arm64
// MH_EXECUTE with only 32 B of LC slack (< the 40 B LC_NOTE command) and is
// otherwise clean, so metadata-insert admission rejects with LC_HEADER_SLACK —
// no in-test mutation (FIXTURES.md; resolves WP-004 DF-004-01).
// ----------------------------------------------------------------------------

static void
test_lc_slack_reject(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] lc_slack_reject (fixture "
               "test/unit/data/hello_lowslack_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_metadata_request_t request = default_request();
    buf_snapshot_t                              before  = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_result_t admit = require_rejected(
        n00b_macho_rewrite_admit_metadata_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_LC_HEADER_SLACK);
    assert(admit.lc_slack_bytes < LC_NOTE_CMD_SIZE);

    assert_snapshot_unchanged(bin, before); // P1-f
    printf("  [PASS] lc_slack_reject\n");
}

// ----------------------------------------------------------------------------
// P1-c / P1-d: signed fixture — codesig-no-resign reject, ALLOW_RESIGN clears
// ----------------------------------------------------------------------------

static void
test_codesig_resign(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_signed_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] codesig_resign (fixture "
               "test/unit/data/hello_signed_arm64.macho not found)\n");
        return;
    }
    if (bin->code_signature == nullptr) {
        printf("  [SKIP] codesig_resign (fixture carries no code "
               "signature)\n");
        return;
    }

    // P1-c: policy NONE -> rejected CODESIG_PRESENT_NO_RESIGN.
    n00b_macho_rewrite_admit_metadata_request_t request = default_request();
    buf_snapshot_t                              before  = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_result_t admit = require_rejected(
        n00b_macho_rewrite_admit_metadata_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN);
    assert(admit.code_signature_present);
    assert_snapshot_unchanged(bin, before); // P1-f

    // P1-d: with ALLOW_RESIGN, not rejected for that reason. (It may still be
    // accepted or rejected for another reason; assert only that this specific
    // codesig-no-resign reject no longer fires.)
    request.policy.flags = N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN;
    before               = snapshot_buffer(bin);

    auto resign_result =
        n00b_macho_rewrite_admit_metadata_insert(bin, &request);
    assert(n00b_result_is_ok(resign_result));
    n00b_macho_rewrite_admit_result_t resign = n00b_result_get(resign_result);
    assert(!(resign.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED
             && resign.rejection_reason
                    == N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN));
    assert(resign.code_signature_present);
    assert_snapshot_unchanged(bin, before); // P1-f

    printf("  [PASS] codesig_resign\n");
}

// ----------------------------------------------------------------------------
// P1-e: trusted reserved-owner path — wrong owner rejects, exact owner accepts
// ----------------------------------------------------------------------------

static void
test_reserved_owner(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] reserved_owner (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    // hello_unsigned_arm64.macho admits cleanly (256 B slack, unsigned), so the
    // exact-owner accept and wrong-owner reject are tested without any in-test
    // mutation.
    // Wrong owner on the trusted bundle path -> RESERVED_NOTE_NAME.
    n00b_macho_rewrite_admit_metadata_request_t request = default_request();
    request.note_owner = r"com.example.note";
    buf_snapshot_t before = snapshot_buffer(bin);
    require_rejected(
        n00b_macho_rewrite_admit_object_bundle_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME);
    assert_snapshot_unchanged(bin, before); // P1-f

    // Exact bundle owner on the trusted bundle path -> accepted.
    request.note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER);
    before             = snapshot_buffer(bin);
    require_accepted(
        n00b_macho_rewrite_admit_object_bundle_insert(bin, &request));
    assert_snapshot_unchanged(bin, before); // P1-f

    // The general metadata path rejects the reserved bundle owner.
    request.note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER);
    before             = snapshot_buffer(bin);
    require_rejected(
        n00b_macho_rewrite_admit_metadata_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME);
    assert_snapshot_unchanged(bin, before); // P1-f

    // The trusted chalk path accepts only the exact chalk owner.
    request.note_owner = n00b_string_from_cstr(CHALK_MACHO_NOTE_OWNER);
    before             = snapshot_buffer(bin);
    require_accepted(
        n00b_macho_rewrite_admit_chalk_mark_insert(bin, &request));
    assert_snapshot_unchanged(bin, before);

    request.note_owner = n00b_string_from_cstr(N00B_MACHO_BUNDLE_NOTE_OWNER);
    before             = snapshot_buffer(bin);
    require_rejected(
        n00b_macho_rewrite_admit_chalk_mark_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME);
    assert_snapshot_unchanged(bin, before); // P1-f

    printf("  [PASS] reserved_owner\n");
}

// ============================================================================
// WP-004 Phase 2: loadable-insert + arm64 host-entrypoint admission tests.
// Same conventions as Phase 1: deterministic, host-neutral, always-run, and
// every Phase-2 admit call is wrapped by the CR-04 snapshot (P2-g).
// ============================================================================

// ----------------------------------------------------------------------------
// Phase-2 request builders + verdict helpers
// ----------------------------------------------------------------------------

static n00b_macho_rewrite_admit_loadable_request_t
default_loadable_request(void)
{
    // r-x loadable segment, 16K (arm64) page alignment for both file and vm.
    return (n00b_macho_rewrite_admit_loadable_request_t){
        .payload_size    = 256,
        .initprot        = 5, // VM_PROT_READ | VM_PROT_EXECUTE
        .maxprot         = 5,
        .file_alignment  = N00B_MACHO_ARM64_PAGE_SIZE,
        .vaddr_alignment = N00B_MACHO_ARM64_PAGE_SIZE,
        .vmsize          = N00B_MACHO_ARM64_PAGE_SIZE,
        .policy          = {.flags = N00B_MACHO_REWRITE_ADMIT_POLICY_NONE},
    };
}

static n00b_macho_rewrite_admit_entrypoint_request_t
default_entrypoint_request(void)
{
    return (n00b_macho_rewrite_admit_entrypoint_request_t){
        .target_segment_file_offset = 0x4000,
        .target_segment_vaddr       = 0x100000000ull,
        .target_payload_offset      = 0,
        .target_size                = 4,
    };
}

static n00b_macho_rewrite_admit_loadable_result_t
require_loadable_accepted(
    n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t) result)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_loadable_result_t admit = n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    assert(admit.rejection_reason == N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    return admit;
}

static n00b_macho_rewrite_admit_loadable_result_t
require_loadable_rejected(
    n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t) result,
    n00b_macho_rewrite_admit_rejection_reason_t               reason)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_loadable_result_t admit = n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED);
    assert(admit.rejection_reason == reason);
    return admit;
}

static n00b_macho_rewrite_admit_entrypoint_result_t
require_entry_accepted(
    n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t) result)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_entrypoint_result_t admit =
        n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED);
    assert(admit.rejection_reason == N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    return admit;
}

static n00b_macho_rewrite_admit_entrypoint_result_t
require_entry_rejected(
    n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t) result,
    n00b_macho_rewrite_admit_rejection_reason_t                 reason)
{
    assert(n00b_result_is_ok(result));
    n00b_macho_rewrite_admit_entrypoint_result_t admit =
        n00b_result_get(result);
    assert(admit.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED);
    assert(admit.rejection_reason == reason);
    return admit;
}

// ----------------------------------------------------------------------------
// P2-a: loadable accept. `hello_unsigned_arm64.macho` (256 B LC slack >= the
// 72 B LC_SEGMENT_64 cmd) admits a new r-x loadable segment cleanly: +1 segment
// count, a wide-enough file extent, a well-ordered vm extent, and (slack >= the
// segment cmd) `entrypoint_policy_deferred == false`. (+ P2-g CR-04)
// ----------------------------------------------------------------------------

static void
test_loadable_accept(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] loadable_accept (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_loadable_request_t request =
        default_loadable_request();
    buf_snapshot_t before = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_loadable_result_t admit = require_loadable_accepted(
        n00b_macho_rewrite_admit_loadable_insert(bin, &request));

    assert(admit.new_segment_count == admit.original_segment_count + 1);
    assert(admit.new_segment_count == (uint64_t)bin->num_segments + 1);
    assert(admit.new_segment_file_end - admit.new_segment_file_offset
           >= request.payload_size);
    assert(admit.new_segment_vaddr_end > admit.new_segment_vaddr);
    assert(admit.required_lc_growth == 72u);
    assert(admit.lc_slack_bytes >= admit.required_lc_growth);
    // Slack covers the new segment command -> no __TEXT-reflow signal.
    assert(!admit.entrypoint_policy_deferred);
    assert(!admit.code_signature_present);
    assert(admit.file_size == (uint64_t)bin->stream->buf->byte_len);

    assert_snapshot_unchanged(bin, before); // P2-g
    printf("  [PASS] loadable_accept\n");
}

// ----------------------------------------------------------------------------
// P2-b: undersized vmsize -> REJECTED VMSIZE_TOO_SMALL (D-031 runtime guard).
// ----------------------------------------------------------------------------

static void
test_loadable_vmsize_too_small(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] loadable_vmsize_too_small (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_loadable_request_t request =
        default_loadable_request();
    request.payload_size = 4096;
    request.vmsize       = 1024; // < payload_size
    buf_snapshot_t before = snapshot_buffer(bin);

    require_loadable_rejected(
        n00b_macho_rewrite_admit_loadable_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_VMSIZE_TOO_SMALL);

    assert_snapshot_unchanged(bin, before); // P2-g
    printf("  [PASS] loadable_vmsize_too_small\n");
}

// ----------------------------------------------------------------------------
// P2-c: insufficient LC slack -> reflow ACCEPT (D-021), NOT a rejection.
// `hello_lowslack_arm64.macho` has 32 B of LC slack (< the 72 B segment cmd),
// so the loadable verdict stays ACCEPTED with lc_slack_bytes < required_lc_growth
// and entrypoint_policy_deferred == true (the __TEXT-reflow signal).
// ----------------------------------------------------------------------------

static void
test_loadable_reflow_accept(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_lowslack_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] loadable_reflow_accept (fixture "
               "test/unit/data/hello_lowslack_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_loadable_request_t request =
        default_loadable_request();
    buf_snapshot_t before = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_loadable_result_t admit = require_loadable_accepted(
        n00b_macho_rewrite_admit_loadable_insert(bin, &request));

    assert(admit.lc_slack_bytes < admit.required_lc_growth);
    assert(admit.entrypoint_policy_deferred); // D-021 reflow signal, not reject
    assert(admit.new_segment_count == admit.original_segment_count + 1);

    assert_snapshot_unchanged(bin, before); // P2-g
    printf("  [PASS] loadable_reflow_accept\n");
}

// ----------------------------------------------------------------------------
// P2-d: signed loadable codesig. policy NONE -> REJECTED
// CODESIG_PRESENT_NO_RESIGN; with ALLOW_RESIGN -> not rejected for that reason,
// and code_signature_present && linkedit_must_move facts populated.
// ----------------------------------------------------------------------------

static void
test_loadable_codesig(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_signed_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] loadable_codesig (fixture "
               "test/unit/data/hello_signed_arm64.macho not found)\n");
        return;
    }
    if (bin->code_signature == nullptr) {
        printf("  [SKIP] loadable_codesig (fixture carries no code "
               "signature)\n");
        return;
    }

    // policy NONE -> rejected CODESIG_PRESENT_NO_RESIGN.
    n00b_macho_rewrite_admit_loadable_request_t request =
        default_loadable_request();
    buf_snapshot_t before = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_loadable_result_t reject = require_loadable_rejected(
        n00b_macho_rewrite_admit_loadable_insert(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN);
    assert(reject.code_signature_present);
    assert_snapshot_unchanged(bin, before); // P2-g

    // ALLOW_RESIGN: no longer rejected for codesig-no-resign; facts populated.
    request.policy.flags = N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN;
    before               = snapshot_buffer(bin);

    auto resign_result =
        n00b_macho_rewrite_admit_loadable_insert(bin, &request);
    assert(n00b_result_is_ok(resign_result));
    n00b_macho_rewrite_admit_loadable_result_t resign =
        n00b_result_get(resign_result);
    assert(!(resign.outcome == N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED
             && resign.rejection_reason
                    == N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN));
    assert(resign.code_signature_present);
    // A signed arm64 hello has __LINKEDIT last, so inserting before it forces
    // __LINKEDIT to move.
    assert(resign.linkedit_must_move);
    assert_snapshot_unchanged(bin, before); // P2-g

    printf("  [PASS] loadable_codesig\n");
}

// ----------------------------------------------------------------------------
// P2-e: entrypoint accept. `hello_unsigned_arm64.macho` is an arm64 MH_EXECUTE
// with LC_MAIN -> ACCEPTED, has_lc_main, cputype == CPU_TYPE_ARM64, derived
// replacement_entryoff.
// ----------------------------------------------------------------------------

static void
test_entrypoint_accept(void)
{
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] entrypoint_accept (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    n00b_macho_rewrite_admit_entrypoint_request_t request =
        default_entrypoint_request();
    buf_snapshot_t before = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_entrypoint_result_t admit = require_entry_accepted(
        n00b_macho_rewrite_admit_host_entrypoint_target(bin, &request));

    assert(admit.has_lc_main);
    assert(admit.cputype == (uint32_t)CPU_TYPE_ARM64);
    // replacement_entryoff = candidate segment file base + in-segment offset.
    assert(admit.replacement_entryoff
           == request.target_segment_file_offset
                  + request.target_payload_offset);
    assert(admit.original_entryoff == bin->entrypoint);

    assert_snapshot_unchanged(bin, before); // P2-g
    printf("  [PASS] entrypoint_accept\n");
}

// ----------------------------------------------------------------------------
// P2-f: entrypoint rejects.
//   (1) x86_64 fixture -> REJECTED UNSUPPORTED_CPUTYPE.
//   (2) NO_LC_MAIN: an arm64 Mach-O without LC_MAIN is NOT producible — modern
//       `ld` always emits LC_MAIN and `n00b_macho_build` emits it whenever
//       entrypoint != 0. We therefore took path (ii) of the WP-004 Phase-2
//       NO_LC_MAIN options: parse the real arm64 fixture and minimally remove
//       the parsed LC_MAIN from commands[] to construct the no-LC_MAIN input.
//       This is permissible ONLY because the input genuinely cannot exist as a
//       real artifact (unlike the Phase-1 cases). Admission remains read-only
//       over the constructed model (the in-test edit happens BEFORE the `before`
//       snapshot, so P2-g still proves the admit call itself is read-only).
// ----------------------------------------------------------------------------

// Remove the first LC_MAIN command from the parsed command list in place,
// shifting the tail down. This mutates only the in-test parsed model (the
// constructed no-LC_MAIN input), never via the admission API.
static void
strip_lc_main_command(n00b_macho_binary_t *bin)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_MAIN) {
            for (uint32_t j = i + 1; j < bin->num_commands; j++) {
                bin->commands[j - 1] = bin->commands[j];
            }
            bin->num_commands--;
            return;
        }
    }
}

static void
test_entrypoint_rejects(void)
{
    // (1) x86_64 -> UNSUPPORTED_CPUTYPE.
    n00b_macho_binary_t *x86 = parse_fixture("test/unit/data/hello_x86_64.macho");
    if (x86 == nullptr) {
        printf("  [SKIP] entrypoint_rejects/x86_64 (fixture "
               "test/unit/data/hello_x86_64.macho not found)\n");
    }
    else {
        n00b_macho_rewrite_admit_entrypoint_request_t request =
            default_entrypoint_request();
        buf_snapshot_t before = snapshot_buffer(x86);

        n00b_macho_rewrite_admit_entrypoint_result_t admit =
            require_entry_rejected(
                n00b_macho_rewrite_admit_host_entrypoint_target(x86, &request),
                N00B_MACHO_REWRITE_ADMIT_REJECT_UNSUPPORTED_CPUTYPE);
        assert(admit.cputype == x86->header.cputype);
        assert(admit.cputype != (uint32_t)CPU_TYPE_ARM64);

        assert_snapshot_unchanged(x86, before); // P2-g
        printf("  [PASS] entrypoint_rejects/x86_64\n");
    }

    // (2) NO_LC_MAIN: constructed in-test (path ii); see comment above.
    n00b_macho_binary_t *bin =
        parse_fixture("test/unit/data/hello_unsigned_arm64.macho");
    if (bin == nullptr) {
        printf("  [SKIP] entrypoint_rejects/no_lc_main (fixture "
               "test/unit/data/hello_unsigned_arm64.macho not found)\n");
        return;
    }

    // Sanity: the real fixture has LC_MAIN before we strip it.
    bool had_lc_main = false;
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_MAIN) {
            had_lc_main = true;
            break;
        }
    }
    if (!had_lc_main) {
        printf("  [SKIP] entrypoint_rejects/no_lc_main (fixture lacks "
               "LC_MAIN to strip)\n");
        return;
    }

    // Construct the (non-real) no-LC_MAIN input, THEN snapshot, THEN admit:
    // P2-g guards that the admit call is read-only over this constructed model.
    strip_lc_main_command(bin);
    buf_snapshot_t before = snapshot_buffer(bin);

    n00b_macho_rewrite_admit_entrypoint_request_t request =
        default_entrypoint_request();
    n00b_macho_rewrite_admit_entrypoint_result_t admit = require_entry_rejected(
        n00b_macho_rewrite_admit_host_entrypoint_target(bin, &request),
        N00B_MACHO_REWRITE_ADMIT_REJECT_NO_LC_MAIN);
    assert(admit.cputype == (uint32_t)CPU_TYPE_ARM64);

    assert_snapshot_unchanged(bin, before); // P2-g
    printf("  [PASS] entrypoint_rejects/no_lc_main\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_null_zero_guards();    // P1-h
    test_stringifiers();        // P1-g
    test_accept();              // P1-a (+ P1-f)
    test_lc_slack_reject();     // P1-b (+ P1-f)
    test_codesig_resign();      // P1-c / P1-d (+ P1-f)
    test_reserved_owner();      // P1-e (+ P1-f)

    test_loadable_accept();         // P2-a (+ P2-g)
    test_loadable_vmsize_too_small(); // P2-b (+ P2-g)
    test_loadable_reflow_accept();  // P2-c (+ P2-g)
    test_loadable_codesig();        // P2-d (+ P2-g)
    test_entrypoint_accept();       // P2-e (+ P2-g)
    test_entrypoint_rejects();      // P2-f (+ P2-g)

    return 0;
}
