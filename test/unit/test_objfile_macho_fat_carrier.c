/**
 * @file test_objfile_macho_fat_carrier.c
 * @brief WP-014 Phase 1 always-run, host-neutral regression test for the
 *        fat/universal Mach-O object-bundle carrier WRITE dispatch.
 *
 * Exercises `n00b_obj_bundle_write` on a fat/universal Mach-O input. The write
 * path (WP-008/009/010 thin carrier engine) rejects code-signed inputs and needs
 * real `__TEXT`/`__LINKEDIT` geometry, so the bare casegen thin macho is NOT a
 * carrier-writable target (WP-012 finding). The committed unsigned arm64 fixture
 * `test/unit/data/hello_unsigned_arm64.macho` IS. The fat fixture is therefore
 * ASSEMBLED here from that committed thin arm64 fixture + a programmatically
 * built x86_64 thin slice, re-fattened via `n00b_macho_refat` (the WP-007
 * re-fat primitive). This keeps the arm64 slice carrier-writable while the
 * x86_64 slice is a byte-identity passthrough witness (D-002/D-035, NFR-01).
 *
 * For each carrier kind (METADATA / LOADABLE / SPLIT):
 *   - write the carrier into the fat via the public neutral
 *     `n00b_obj_bundle_write`;
 *   - re-parse the output via `n00b_macho_parse` and assert it IS fat with the
 *     input slice count preserved;
 *   - assert the arm64 slice carries the bundle (via the thin carrier detect,
 *     `_n00b_obj_bundle_macho_detect_carrier`, on the arm64 slice's thin bytes);
 *   - assert the x86_64 slice is byte-identical to the input slice (NFR-01);
 *   - assert slice offsets honor 2^align (NFR-11).
 * Error case: a fat with no arm64 slice → `Err(UNSUPPORTED_CARRIER)`.
 * Regression case: a thin (non-fat) input → unchanged thin carrier output.
 *
 * The output is referenced via `n00b_macho_parse` + the thin carrier detect,
 * NEVER `n00b_obj_bundle_read(fat)` — the neutral reader is thin-only; reading a
 * fat carrier is the deferred WP-015 read half. NO loader / codesign / spawn; the
 * write+reparse are in-memory, so this test does no disk extraction.
 *
 * Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, this test-local
 * scaffolding may use header-only libc for path assembly (`snprintf`, `getenv`)
 * and raw byte comparison; every code-under-test call uses the n00b surface.
 *
 * Cases P1-a..P1-f per the Phase 1 regression matrix.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/macho_build.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "compiler/objfile/obj_bundle.h"
#include "internal/compiler/objfile/obj_bundle_macho.h"

#define TEST_FIXTURE_UNSIGNED "test/unit/data/hello_unsigned_arm64.macho"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                    \
    do {                                      \
        if (cond) {                           \
            printf("  [PASS] %s\n", (label)); \
            g_pass++;                         \
        }                                     \
        else {                                \
            printf("  [FAIL] %s\n", (label)); \
            g_fail++;                         \
        }                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Fixture loading (mirror test_objfile_macho_e2e.c:load_target_bytes). Resolve
// the committed unsigned arm64 fixture against MESON_SOURCE_ROOT, then load its
// raw object bytes.
// ---------------------------------------------------------------------------
static n00b_buffer_t *
load_unsigned_arm64_bytes(void)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    char        path[1024];
    const char *use = TEST_FIXTURE_UNSIGNED;

    if (root != nullptr && root[0] != '\0') {
        int n = snprintf(path, sizeof(path), "%s/%s", root,
                         TEST_FIXTURE_UNSIGNED);
        if (n > 0 && (size_t)n < sizeof(path)) {
            use = path;
        }
    }

    auto r = n00b_bstream_from_file(use);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r)->buf;
    }

    return nullptr;
}

// Build a minimal programmatic x86_64 thin slice. It need not be carrier-
// writable: it is a PASSTHROUGH witness (D-002/D-035), so the bare casegen-style
// builder output is sufficient.
static n00b_buffer_t *
build_x86_64_thin(void)
{
    n00b_macho_binary_t *bin = n00b_macho_binary_new(CPU_TYPE_X86_64,
                                                     CPU_SUBTYPE_X86_64_ALL,
                                                     MH_EXECUTE);
    n00b_macho_add_segment(bin, "__TEXT", 5, 5);
    n00b_macho_set_entry(bin, 0, 0);

    auto r = n00b_macho_build(bin);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// Assemble a 2-slice fat (arm64 carrier-writable + x86_64 passthrough) by
// re-fattening the committed unsigned arm64 thin fixture with a programmatic
// x86_64 thin slice. *arm64_in / *x86_in receive the per-slice input thin bytes
// for later byte-identity assertions.
static n00b_buffer_t *
build_two_slice_fat(n00b_buffer_t **arm64_in, n00b_buffer_t **x86_in)
{
    n00b_buffer_t *arm64_bytes = load_unsigned_arm64_bytes();

    if (arm64_bytes == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *x86_bytes = build_x86_64_thin();

    if (x86_bytes == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *thin[2]   = {arm64_bytes, x86_bytes};
    uint32_t       cputy[2]  = {CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    uint32_t       subty[2]  = {CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_X86_64_ALL};
    uint32_t       aligns[2] = {14u, 14u}; // 2^14 = 16K page alignment.

    auto r = n00b_macho_refat(thin, cputy, subty, aligns, 2);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    if (arm64_in != nullptr) {
        *arm64_in = arm64_bytes;
    }
    if (x86_in != nullptr) {
        *x86_in = x86_bytes;
    }

    return n00b_result_get(r);
}

// Build a 2-slice fat with NO arm64 slice (two x86_64 slices) for the
// UNSUPPORTED_CARRIER error case.
static n00b_buffer_t *
build_no_arm64_fat(void)
{
    n00b_buffer_t *a = build_x86_64_thin();
    n00b_buffer_t *b = build_x86_64_thin();

    if (a == nullptr || b == nullptr) {
        return nullptr;
    }

    n00b_buffer_t *thin[2]   = {a, b};
    uint32_t       cputy[2]  = {CPU_TYPE_X86_64, CPU_TYPE_X86_64};
    uint32_t       subty[2]  = {CPU_SUBTYPE_X86_64_ALL, CPU_SUBTYPE_X86_64_ALL};
    uint32_t       aligns[2] = {14u, 14u};

    auto r = n00b_macho_refat(thin, cputy, subty, aligns, 2);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// Build a single-artifact bundle with a default executable (mirrors the e2e and
// carrier suite helpers) so SPLIT can enumerate an executable slice.
static n00b_obj_bundle_t *
make_test_bundle(void)
{
    auto created = n00b_obj_bundle_new();

    if (n00b_result_is_err(created)) {
        return nullptr;
    }

    n00b_obj_bundle_t *bundle  = n00b_result_get(created);
    n00b_buffer_t     *payload = n00b_buffer_from_cstr("macho-fat-carrier-payload");

    auto add = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        payload,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
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

// Re-parse fat output bytes; returns the parsed fat or nullptr.
static n00b_macho_fat_t *
reparse_fat(n00b_buffer_t *bytes)
{
    n00b_bstream_t *s = n00b_bstream_new(bytes);
    auto            r = n00b_macho_parse(s);

    if (n00b_result_is_err(r)) {
        return nullptr;
    }

    return n00b_result_get(r);
}

// True when the slice at `index` of the (already-parsed) fat carries an N00b
// bundle carrier in its thin bytes.
static bool
slice_has_carrier(n00b_macho_fat_t *fat, uint32_t index)
{
    n00b_macho_binary_t *bin = fat->binaries[index];

    auto detected = _n00b_obj_bundle_macho_detect_carrier(bin);

    if (n00b_result_is_err(detected)) {
        return false;
    }

    return n00b_result_get(detected) != N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE;
}

// Byte-compare a fat slice (read from the parsed fat's stream buffer at its
// descriptor offset/size) against a reference thin input buffer.
static bool
slice_bytes_equal(n00b_macho_fat_t *fat, uint32_t index, n00b_buffer_t *ref)
{
    n00b_macho_fat_slice_t *slice = &fat->slices[index];
    n00b_buffer_t          *src   = fat->binaries[index]->stream->buf;

    if (src == nullptr || ref == nullptr) {
        return false;
    }

    if ((uint64_t)ref->byte_len != slice->size) {
        return false;
    }

    if (slice->offset > (uint64_t)src->byte_len
        || slice->size > (uint64_t)src->byte_len - slice->offset) {
        return false;
    }

    return memcmp(src->data + slice->offset, ref->data, (size_t)slice->size)
           == 0;
}

// ---------------------------------------------------------------------------
// P1-a/-b/-c: per-carrier fat write → fat output; arm64 carries carrier;
// x86_64 byte-identical. P1-d: alignment honored.
// ---------------------------------------------------------------------------
static void
drive_carrier(n00b_obj_bundle_carrier_t carrier, const char *id)
{
    char label[128];

    n00b_buffer_t *arm64_in = nullptr;
    n00b_buffer_t *x86_in   = nullptr;
    n00b_buffer_t *fat_in   = build_two_slice_fat(&arm64_in, &x86_in);

    snprintf(label, sizeof(label), "%s: fat fixture assembled", id);
    CHECK(label, fat_in != nullptr);
    if (fat_in == nullptr) {
        return;
    }

    n00b_obj_bundle_t *bundle = make_test_bundle();
    snprintf(label, sizeof(label), "%s: bundle built", id);
    CHECK(label, bundle != nullptr);
    if (bundle == nullptr) {
        return;
    }

    auto written = n00b_obj_bundle_write(fat_in, bundle, .carrier = carrier);

    snprintf(label, sizeof(label), "%s: write returns Ok", id);
    CHECK(label, n00b_result_is_ok(written));
    if (n00b_result_is_err(written)) {
        return;
    }

    n00b_buffer_t    *out      = n00b_result_get(written);
    n00b_macho_fat_t *out_fat  = reparse_fat(out);

    snprintf(label, sizeof(label), "%s: output re-parses as fat", id);
    CHECK(label, out_fat != nullptr);
    if (out_fat == nullptr) {
        return;
    }

    snprintf(label, sizeof(label), "%s: slice count preserved (2)", id);
    CHECK(label, out_fat->count == 2 && out_fat->slices != nullptr);
    if (out_fat->count != 2 || out_fat->slices == nullptr) {
        return;
    }

    // Locate the arm64 / x86_64 slices by cputype (order is preserved, but read
    // by cputype to be robust).
    uint32_t arm_idx = UINT32_MAX, x86_idx = UINT32_MAX;
    for (uint32_t i = 0; i < out_fat->count; i++) {
        if (out_fat->slices[i].cputype == (uint32_t)CPU_TYPE_ARM64) {
            arm_idx = i;
        }
        else if (out_fat->slices[i].cputype == (uint32_t)CPU_TYPE_X86_64) {
            x86_idx = i;
        }
    }

    snprintf(label, sizeof(label), "%s: arm64 + x86_64 slices present", id);
    CHECK(label, arm_idx != UINT32_MAX && x86_idx != UINT32_MAX);
    if (arm_idx == UINT32_MAX || x86_idx == UINT32_MAX) {
        return;
    }

    snprintf(label, sizeof(label), "%s: arm64 slice carries the carrier", id);
    CHECK(label, slice_has_carrier(out_fat, arm_idx));

    snprintf(label, sizeof(label), "%s: x86_64 slice byte-identical (NFR-01)",
             id);
    CHECK(label, slice_bytes_equal(out_fat, x86_idx, x86_in));

    // P1-d: every slice offset is 2^align-aligned (NFR-11).
    bool aligned = true;
    for (uint32_t i = 0; i < out_fat->count; i++) {
        uint64_t a = 1ULL << out_fat->slices[i].align;
        if (a != 0 && (out_fat->slices[i].offset % a) != 0) {
            aligned = false;
        }
    }
    snprintf(label, sizeof(label), "%s: slice offsets honor 2^align (NFR-11)",
             id);
    CHECK(label, aligned);
}

// ---------------------------------------------------------------------------
// P1-e: a fat with no arm64 slice → Err(UNSUPPORTED_CARRIER).
// ---------------------------------------------------------------------------
static void
test_no_arm64_slice(void)
{
    n00b_buffer_t *fat_in = build_no_arm64_fat();

    CHECK("P1-e: no-arm64 fat fixture assembled", fat_in != nullptr);
    if (fat_in == nullptr) {
        return;
    }

    n00b_obj_bundle_t *bundle = make_test_bundle();
    CHECK("P1-e: bundle built", bundle != nullptr);
    if (bundle == nullptr) {
        return;
    }

    auto written = n00b_obj_bundle_write(
        fat_in, bundle, .carrier = N00B_OBJ_BUNDLE_CARRIER_METADATA);

    CHECK("P1-e: no-arm64 fat write returns Err", n00b_result_is_err(written));

    if (n00b_result_is_err(written)
        && n00b_result_is_err_payload(n00b_obj_bundle_error_t *, written)) {
        n00b_obj_bundle_error_t *err
            = n00b_result_get_err_payload(n00b_obj_bundle_error_t *, written);
        CHECK("P1-e: error code is UNSUPPORTED_CARRIER",
              err != nullptr
                  && n00b_obj_bundle_error_code(err)
                         == N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER);
    }
}

// ---------------------------------------------------------------------------
// P1-f: a thin (non-fat) input takes the unchanged thin carrier path.
// ---------------------------------------------------------------------------
static void
test_thin_regression(void)
{
    n00b_buffer_t *thin_in = load_unsigned_arm64_bytes();

    CHECK("P1-f: thin fixture loaded", thin_in != nullptr);
    if (thin_in == nullptr) {
        return;
    }

    n00b_obj_bundle_t *bundle = make_test_bundle();
    CHECK("P1-f: bundle built", bundle != nullptr);
    if (bundle == nullptr) {
        return;
    }

    auto written = n00b_obj_bundle_write(
        thin_in, bundle, .carrier = N00B_OBJ_BUNDLE_CARRIER_METADATA);

    CHECK("P1-f: thin write returns Ok", n00b_result_is_ok(written));
    if (n00b_result_is_err(written)) {
        return;
    }

    n00b_buffer_t    *out     = n00b_result_get(written);
    n00b_macho_fat_t *out_fat = reparse_fat(out);

    CHECK("P1-f: thin output re-parses (count == 1)",
          out_fat != nullptr && out_fat->count == 1);
    if (out_fat == nullptr || out_fat->count != 1) {
        return;
    }

    CHECK("P1-f: thin output carries the carrier",
          slice_has_carrier(out_fat, 0));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("== WP-014 fat/universal Mach-O carrier-write dispatch ==\n");

    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_METADATA, "P1-a METADATA");
    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_LOADABLE, "P1-b LOADABLE");
    drive_carrier(N00B_OBJ_BUNDLE_CARRIER_SPLIT, "P1-c SPLIT");
    test_no_arm64_slice();
    test_thin_regression();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
