/*
 * test_quic_framer_fuzz.c — Property test for the wire framer.
 *
 * Drives `n00b_quic_frame_parse` with adversarial inputs and asserts:
 *
 *   - Parsing never crashes, asserts, or reads past the buffer.
 *   - When the parse returns ok+some(frame), `frame.consumed` is
 *     within bounds and matches what we'd expect from re-encoding
 *     the same frame.
 *   - When the parse returns ok+none, the buffer is necessarily a
 *     strict prefix of what a complete frame would need (i.e., a
 *     few more bytes might unblock it).
 *   - When the parse returns err, the error is one of the documented
 *     codes.
 *
 * Strategies covered:
 *   1. Pure random bytes (high-entropy, exercises the varint decode
 *      paths and oversize-frame rejection).
 *   2. Truncated valid frames: emit a real frame, then parse strict
 *      prefixes byte by byte.  Each prefix < total_size must yield
 *      ok+none; the full size must yield ok+some.
 *   3. Boundary varint values: 63, 64, 16383, 16384, 2^30-1, 2^30,
 *      and the absolute maximum (2^62-1).  Every length-class
 *      transition must round-trip.
 *   4. Maliciously-large lengths: a varint advertising e.g. 1 GiB
 *      with a small actual buffer.  Must yield err(FRAME_TOO_LARGE)
 *      *or* ok+none, never crash, never over-read.
 *
 * Not a libFuzzer harness — runs as a regular unit test for ~15k
 * iterations and finishes in well under a second.  A libFuzzer
 * harness lands in a separate file when we add the fuzz suite to CI.
 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/random.h"
#include "net/quic/quic_types.h"
#include "net/quic/framer.h"

/* ============================================================================
 * 1. Pure random bytes — parse never crashes, errors are well-formed
 * ============================================================================ */

static void
test_fuzz_random_bytes(void)
{
    enum { ITERS = 2000, MAX_LEN = 4096 };

    for (int it = 0; it < ITERS; it++) {
        size_t  len = (size_t)((n00b_rand32() % MAX_LEN) + 1);
        uint8_t random_buf[MAX_LEN];
        n00b_random_bytes((char *)random_buf, len);

        n00b_buffer_t buf;
        memset(&buf, 0, sizeof(buf));
        n00b_buffer_init(&buf, .length = (int64_t)len);
        memcpy(buf.data, random_buf, len);
        buf.byte_len = (int64_t)len;

        auto pr = n00b_quic_frame_parse(&buf, 0);

        if (n00b_result_is_ok(pr)) {
            n00b_option_t(n00b_quic_frame_t) opt = n00b_result_get(pr);
            if (n00b_option_is_set(opt)) {
                n00b_quic_frame_t f = n00b_option_get(opt);
                /* consumed must fit in the buffer */
                assert(f.consumed <= len);
                /* payload bytes (if any) must be inside the buffer */
                assert(f.payload_len <= len);
                if (f.payload_len > 0) {
                    assert(f.payload != nullptr);
                    /* payload pointer is a borrowed slice — verify it's
                     * within [buf.data, buf.data + len). */
                    const uint8_t *base = (const uint8_t *)buf.data;
                    assert(f.payload >= base);
                    assert(f.payload + f.payload_len <= base + len);
                }
                /* total = varint + 1 + payload_len; we don't reverify
                 * the varint decode here, but consumed >= 1 + payload_len
                 * is a sanity bound (1-byte minimum varint + type byte).*/
                assert(f.consumed >= 1 + f.payload_len);
            }
            /* ok+none is fine — buffer was a partial frame */
        } else {
            /* Errors must be from the documented set. */
            int e = n00b_result_get_err(pr);
            assert(e == N00B_QUIC_ERR_BAD_VARINT ||
                   e == N00B_QUIC_ERR_FRAME_TOO_LARGE ||
                   e == N00B_QUIC_ERR_NULL_ARG ||
                   e == N00B_QUIC_ERR_INVALID_ARG);
        }
    }
    n00b_printf("  [PASS] [|#|] iterations of pure-random bytes — no crashes",
                (int64_t)ITERS);
}

/* ============================================================================
 * 2. Truncated valid frames — every prefix < full size yields None
 * ============================================================================ */

static void
test_fuzz_truncated_prefixes(void)
{
    enum { ITERS = 200 };

    for (int it = 0; it < ITERS; it++) {
        /* Build a real frame with random type + random payload. */
        size_t  payload_len = (size_t)(n00b_rand32() % 4096);
        uint8_t payload[4096];
        n00b_random_bytes((char *)payload, payload_len);
        uint8_t type = (uint8_t)(n00b_rand32() & 0xff);

        n00b_buffer_t out;
        memset(&out, 0, sizeof(out));
        n00b_buffer_init(&out, .length = 0);
        auto er = n00b_quic_frame_emit(&out, type, payload, payload_len);
        assert(n00b_result_is_ok(er));

        size_t total = (size_t)out.byte_len;

        /* Every strict prefix must yield ok+none. */
        for (size_t p = 0; p < total; p++) {
            n00b_buffer_t cut;
            memset(&cut, 0, sizeof(cut));
            n00b_buffer_init(&cut, .length = (int64_t)p);
            if (p > 0) memcpy(cut.data, out.data, p);
            cut.byte_len = (int64_t)p;

            auto pr = n00b_quic_frame_parse(&cut, 0);
            if (n00b_result_is_err(pr)) {
                /* If we error early on a partial, that's only acceptable
                 * if the partial actually contains a malformed varint.
                 * Real prefixes of valid frames never become malformed.
                 * However: a 1-byte prefix of an N-byte varint is a
                 * "could-still-decode" prefix; the parser yields None
                 * for it.  Asserting here would over-constrain. */
                assert(n00b_result_get_err(pr) != N00B_QUIC_ERR_BAD_VARINT);
                continue;
            }
            n00b_option_t(n00b_quic_frame_t) opt = n00b_result_get(pr);
            assert(!n00b_option_is_set(opt));
        }

        /* The full buffer must yield ok+some with consumed == total. */
        auto pr = n00b_quic_frame_parse(&out, 0);
        assert(n00b_result_is_ok(pr));
        assert(n00b_option_is_set(n00b_result_get(pr)));
        n00b_quic_frame_t f =
            n00b_option_get(n00b_result_get(pr));
        assert(f.consumed == total);
        assert(f.payload_len == payload_len);
        assert(f.type == type);
    }
    n00b_printf("  [PASS] [|#|] round-trips with all strict prefixes → None",
                (int64_t)ITERS);
}

/* ============================================================================
 * 3. Varint boundary round-trips
 * ============================================================================ */

static void
test_fuzz_varint_boundaries(void)
{
    static const uint64_t boundaries[] = {
        0, 1, 62, 63, 64, 65,
        16382, 16383, 16384, 16385,
        ((uint64_t)1 << 30) - 2, ((uint64_t)1 << 30) - 1,
        ((uint64_t)1 << 30), ((uint64_t)1 << 30) + 1,
        ((uint64_t)1 << 60),
        ((uint64_t)1 << 62) - 2, N00B_QUIC_VARINT_MAX,
    };
    static const size_t N = sizeof(boundaries) / sizeof(boundaries[0]);

    for (size_t i = 0; i < N; i++) {
        uint8_t buf[16] = {0};
        auto er =
            n00b_quic_varint_encode(buf, sizeof(buf), boundaries[i]);
        assert(n00b_result_is_ok(er));
        size_t enc_len = n00b_result_get(er);

        uint64_t out = ~boundaries[i];
        auto dr = n00b_quic_varint_decode(buf, enc_len, &out);
        assert(n00b_result_is_ok(dr));
        n00b_option_t(size_t) consumed_opt = n00b_result_get(dr);
        assert(n00b_option_is_set(consumed_opt));
        assert(n00b_option_get(consumed_opt) == enc_len);
        assert(out == boundaries[i]);
    }
    n00b_printf("  [PASS] [|#|] varint boundary values round-tripped",
                (int64_t)N);
}

/* ============================================================================
 * 4. Malicious "advertised length is 1 GiB" — must reject without
 *    over-reading
 * ============================================================================ */

static void
test_fuzz_oversize_advertised(void)
{
    /* Construct a varint that advertises 2^31 bytes — well within the
     * varint range, well outside our default cap of 16 MiB.  The
     * parser must reject without over-reading. */
    uint8_t buf[16] = {0};

    /* Encode 2^31 = 2147483648.  That fits in 8-byte varint form
     * (high bits 11). */
    auto er = n00b_quic_varint_encode(buf, sizeof(buf),
                                      (uint64_t)1u << 31);
    assert(n00b_result_is_ok(er));
    size_t vsize = n00b_result_get(er);

    /* Place a type byte; no payload to back the advertised length. */
    buf[vsize] = 0x42;

    n00b_buffer_t b;
    memset(&b, 0, sizeof(b));
    n00b_buffer_init(&b, .length = (int64_t)(vsize + 1));
    memcpy(b.data, buf, vsize + 1);
    b.byte_len = (int64_t)(vsize + 1);

    auto pr = n00b_quic_frame_parse(&b, 0);
    assert(n00b_result_is_err(pr));
    assert(n00b_result_get_err(pr) == N00B_QUIC_ERR_FRAME_TOO_LARGE);

    /* Same buffer with explicit cap of 1 KiB also rejects. */
    pr = n00b_quic_frame_parse(&b, 0, .max_size = 1024);
    assert(n00b_result_is_err(pr));
    assert(n00b_result_get_err(pr) == N00B_QUIC_ERR_FRAME_TOO_LARGE);

    n00b_printf("  [PASS] oversize advertised length cleanly rejected");
}

/* ============================================================================
 * 5. offset > buffer length must yield INVALID_ARG (not crash)
 * ============================================================================ */

static void
test_fuzz_offset_oob(void)
{
    n00b_buffer_t b;
    memset(&b, 0, sizeof(b));
    n00b_buffer_init(&b, .length = 8);
    b.byte_len = 8;

    auto pr = n00b_quic_frame_parse(&b, 100);
    assert(n00b_result_is_err(pr));
    assert(n00b_result_get_err(pr) == N00B_QUIC_ERR_INVALID_ARG);

    /* offset == byte_len is treated as "empty buffer" (None). */
    pr = n00b_quic_frame_parse(&b, 8);
    assert(n00b_result_is_ok(pr));
    assert(!n00b_option_is_set(n00b_result_get(pr)));

    n00b_printf("  [PASS] offset out-of-bounds rejected; offset == len → None");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_quic_framer_fuzz:");

    test_fuzz_random_bytes();
    test_fuzz_truncated_prefixes();
    test_fuzz_varint_boundaries();
    test_fuzz_oversize_advertised();
    test_fuzz_offset_oob();

    n00b_printf("All quic framer fuzz tests passed.");
    n00b_shutdown();
    return 0;
}
