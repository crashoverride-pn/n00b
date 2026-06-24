// test_transient_zero.c — WP-001 Phase 2: marshal-side transient zeroing.
//
// n00b_transient_zero must blank exactly the byte ranges named by a
// n00b_transient_layout_t (byte-granular — sub-word ranges included), leave
// surrounding bytes intact, skip out-of-bounds ranges, and no-op on a null
// layout. n00b_transient_map_lookup must safely miss an unknown type (the
// pinned ncc emits no n00b_trmap entries, so the table is empty here).

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/gc_map.h"
#include "core/runtime.h"
#include "util/assert.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static void
test_zero_ranges(void)
{
    // Zero a 4-byte field at offset 0 and a 1-byte (sub-word) field at 8.
    static const uint64_t                offs[]  = {0, 8};
    static const uint64_t                sizes[] = {4, 1};
    static const n00b_transient_layout_t layout  = {
         .field_count  = 2,
         .byte_offsets = offs,
         .byte_sizes   = sizes,
    };

    uint8_t buf[16];
    memset(buf, 0xAB, sizeof(buf));

    n00b_transient_zero(buf, sizeof(buf), &layout);

    for (int i = 0; i < 4; i++) {
        CHECK(buf[i] == 0x00); // [0,4) zeroed
    }
    for (int i = 4; i < 8; i++) {
        CHECK(buf[i] == 0xAB); // [4,8) intact
    }
    CHECK(buf[8] == 0x00); // [8,9) zeroed
    for (int i = 9; i < 16; i++) {
        CHECK(buf[i] == 0xAB); // [9,16) intact
    }
}

static void
test_out_of_bounds_skipped(void)
{
    // First range [12,20) overruns the 16-byte buffer and must be skipped;
    // the second, in-bounds range [4,8) must still be zeroed.
    static const uint64_t                offs[]  = {12, 4};
    static const uint64_t                sizes[] = {8, 4};
    static const n00b_transient_layout_t layout  = {
         .field_count  = 2,
         .byte_offsets = offs,
         .byte_sizes   = sizes,
    };

    uint8_t buf[16];
    memset(buf, 0xAB, sizeof(buf));

    n00b_transient_zero(buf, sizeof(buf), &layout);

    for (int i = 0; i < 4; i++) {
        CHECK(buf[i] == 0xAB);
    }
    for (int i = 4; i < 8; i++) {
        CHECK(buf[i] == 0x00); // in-bounds range zeroed
    }
    for (int i = 8; i < 16; i++) {
        CHECK(buf[i] == 0xAB); // OOB range skipped -> tail intact
    }
}

static void
test_null_layout_noop(void)
{
    uint8_t buf[8];
    memset(buf, 0xAB, sizeof(buf));
    n00b_transient_zero(buf, sizeof(buf), nullptr);
    for (int i = 0; i < 8; i++) {
        CHECK(buf[i] == 0xAB);
    }
}

static void
test_lookup_unknown_misses(void)
{
    // No n00b_trmap entry for this synthetic hash -> safe miss (degrade path).
    CHECK(n00b_transient_map_lookup(UINT64_C(0x7E57000000000C03)) == nullptr);
    CHECK(n00b_transient_map_lookup(0) == nullptr);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_zero_ranges();
    test_out_of_bounds_skipped();
    test_null_layout_noop();
    test_lookup_unknown_misses();

    n00b_shutdown();
    return 0;
}
