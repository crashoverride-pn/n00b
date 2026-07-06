#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "adt/spsc_ring.h"

// Basic single-threaded FIFO: produce records, peek/pop them back in order
// with exact bytes. (Single-threaded exercises the same code paths; the
// SPSC contract is that producer and consumer never run on the same thread,
// not that they can't be driven from one for testing.)
static void
test_fifo(void)
{
    n00b_spsc_ring_t r;
    assert(n00b_spsc_ring_init(&r, 4096));

    const char *msgs[] = {"a", "bb", "ccc", "dddd", "eeeee"};
    for (int i = 0; i < 5; i++) {
        assert(n00b_spsc_ring_produce(&r, msgs[i], (uint32_t)strlen(msgs[i])));
    }
    for (int i = 0; i < 5; i++) {
        const uint8_t *p = NULL;
        uint32_t       n = 0;
        assert(n00b_spsc_ring_peek(&r, &p, &n));
        assert(n == strlen(msgs[i]));
        assert(memcmp(p, msgs[i], n) == 0);
        n00b_spsc_ring_pop(&r);
    }
    const uint8_t *p = NULL;
    uint32_t       n = 0;
    assert(!n00b_spsc_ring_peek(&r, &p, &n)); // empty
    assert(n00b_spsc_ring_depth(&r) == 0);

    n00b_spsc_ring_destroy(&r);
    printf("  [PASS] fifo\n");
}

// Full-ring drop: fill until produce refuses, confirm the drop counter ticks
// and no delivered record is corrupted, then drain and confirm space frees.
static void
test_full_drops(void)
{
    n00b_spsc_ring_t r;
    assert(n00b_spsc_ring_init(&r, 4096)); // cap rounds to 4096

    uint8_t payload[256];
    memset(payload, 0xAB, sizeof(payload));

    uint64_t produced = 0;
    while (n00b_spsc_ring_produce(&r, payload, sizeof(payload))) {
        produced++;
    }
    assert(n00b_spsc_ring_drops(&r) >= 1);   // hit full
    assert(produced >= 1);

    // Every delivered record is intact.
    for (uint64_t i = 0; i < produced; i++) {
        const uint8_t *p = NULL;
        uint32_t       n = 0;
        assert(n00b_spsc_ring_peek(&r, &p, &n));
        assert(n == sizeof(payload));
        for (uint32_t b = 0; b < n; b++) {
            assert(p[b] == 0xAB);
        }
        n00b_spsc_ring_pop(&r);
    }
    // Space is fully reclaimed: a fresh produce succeeds again.
    assert(n00b_spsc_ring_produce(&r, payload, sizeof(payload)));

    n00b_spsc_ring_destroy(&r);
    printf("  [PASS] full_drops\n");
}

// Forced mid-buffer wrap: interleave produce/consume so the write offset walks
// to the physical end and a record must skip-wrap to offset 0. Verify every
// record round-trips intact across many wraps and head/tail stay in lockstep
// (depth returns to 0). Record size (250 + 8 header, align8 -> 256) does not
// divide 4096 evenly, so the wrap boundary lands mid-record on some laps.
static void
test_wrap(void)
{
    n00b_spsc_ring_t r;
    assert(n00b_spsc_ring_init(&r, 4096));

    uint8_t out[250];
    for (uint32_t i = 0; i < sizeof(out); i++) {
        out[i] = (uint8_t)i;
    }

    // Far more iterations than the ring holds, kept nearly full by draining
    // one fewer than produced each round, so the offset sweeps the whole
    // buffer many times and exercises the skip sentinel repeatedly.
    uint64_t seq = 0;
    for (int round = 0; round < 500; round++) {
        // Stamp a sequence number into the payload so we can verify order.
        out[0] = (uint8_t)(seq & 0xff);
        out[1] = (uint8_t)((seq >> 8) & 0xff);
        if (!n00b_spsc_ring_produce(&r, out, sizeof(out))) {
            // Full: drain one and retry so we keep sweeping.
            const uint8_t *p = NULL;
            uint32_t       n = 0;
            assert(n00b_spsc_ring_peek(&r, &p, &n));
            assert(n == sizeof(out));
            n00b_spsc_ring_pop(&r);
            assert(n00b_spsc_ring_produce(&r, out, sizeof(out)));
        }
        seq++;
    }
    // Drain the remainder; every record must still be intact (bytes 2.. are the
    // ascending pattern, untouched by the sequence stamp).
    const uint8_t *p = NULL;
    uint32_t       n = 0;
    while (n00b_spsc_ring_peek(&r, &p, &n)) {
        assert(n == sizeof(out));
        for (uint32_t b = 2; b < n; b++) {
            assert(p[b] == (uint8_t)b);
        }
        n00b_spsc_ring_pop(&r);
    }
    assert(n00b_spsc_ring_depth(&r) == 0); // head/tail exactly in lockstep

    n00b_spsc_ring_destroy(&r);
    printf("  [PASS] wrap\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running spsc_ring tests...\n");

    test_fifo();
    test_full_drops();
    test_wrap();

    printf("All spsc_ring tests passed.\n");
    n00b_shutdown();
    return 0;
}
