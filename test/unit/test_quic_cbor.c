/*
 * test_quic_cbor.c — Phase 4 § 4.1: CBOR encoder + decoder.
 *
 * What's exercised:
 *   1. RFC 8949 Appendix A test vectors: encode-then-compare against
 *      the documented hex bytes; decode-and-extract for each.
 *   2. n00b round-trips for each supported primitive
 *      (int64, bool, double, string, buffer).
 *   3. Container round-trips: heterogeneous arrays + maps.
 *   4. Nested-container shapes (the JSON-ish object idiom: outer
 *      map with array-of-objects values).
 *   5. Decoder hardening: depth cap, length cap, indefinite-length
 *      refusal, malformed inputs, trailing bytes.
 *   6. The `n00b_cbor_decode_to(T, buf)` macro for each supported T.
 *
 * Mirrors the shape of `test_quic_jwt.c` / `test_quic_jws.c`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "net/quic/quic_types.h"
#include "net/quic/cbor.h"

/* ===========================================================================
 * Helpers
 * =========================================================================== */

/* Compare a buffer's bytes to an expected hex string (no separators). */
static int
buffer_matches_hex(n00b_buffer_t *buf, const char *hex)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;
    size_t expected = hex_len / 2;
    if ((size_t)buf->byte_len != expected) return 0;
    for (size_t i = 0; i < expected; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        if ((unsigned char)buf->data[i] != (unsigned char)v) return 0;
    }
    return 1;
}

/* Build a buffer from a hex string. */
static n00b_buffer_t *
buffer_from_hex(const char *hex)
{
    size_t hex_len = strlen(hex);
    assert(hex_len % 2 == 0);
    size_t bytes = hex_len / 2;
    char  *raw   = malloc(bytes);
    for (size_t i = 0; i < bytes; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%2x", &v);
        raw[i] = (char)v;
    }
    n00b_buffer_t *b = n00b_buffer_from_bytes(raw, (int64_t)bytes);
    free(raw);
    return b;
}

/* ===========================================================================
 * 1. RFC 8949 Appendix A — encode side
 *
 * The vectors enumerate diagnostic notation → CBOR hex.  We sample
 * the integer / float / string / array / map families.
 * =========================================================================== */

static void
test_rfc_appendix_a_encode(void)
{
    struct {
        const char *label;
        int64_t     value;
        const char *hex;
    } int_vecs[] = {
        { "0",            0,                  "00" },
        { "1",            1,                  "01" },
        { "10",           10,                 "0a" },
        { "23",           23,                 "17" },
        { "24",           24,                 "1818" },
        { "25",           25,                 "1819" },
        { "100",          100,                "1864" },
        { "1000",         1000,               "1903e8" },
        { "1000000",      1000000,            "1a000f4240" },
        { "1000000000000", 1000000000000LL,    "1b000000e8d4a51000" },
        { "-1",           -1,                 "20" },
        { "-10",          -10,                "29" },
        { "-100",         -100,               "3863" },
        { "-1000",        -1000,              "3903e7" },
    };
    int n_int_vecs = sizeof(int_vecs) / sizeof(int_vecs[0]);
    for (int i = 0; i < n_int_vecs; i++) {
        n00b_buffer_t *b = n00b_cbor_encode_int64(int_vecs[i].value);
        if (!buffer_matches_hex(b, int_vecs[i].hex)) {
            printf("    FAIL: int %s expected %s got",
                   int_vecs[i].label, int_vecs[i].hex);
            for (size_t j = 0; j < b->byte_len; j++) {
                printf(" %02x", (unsigned char)b->data[j]);
            }
            printf("\n");
            assert(0);
        }
    }
    printf("  [PASS] RFC 8949 App A integer vectors (%d)\n", n_int_vecs);

    /* Booleans + null. */
    {
        n00b_buffer_t *b;
        b = n00b_cbor_encode_bool_(false);
        assert(buffer_matches_hex(b, "f4"));
        b = n00b_cbor_encode_bool_(true);
        assert(buffer_matches_hex(b, "f5"));
        b = n00b_cbor_encode_null_();
        assert(buffer_matches_hex(b, "f6"));
        printf("  [PASS] RFC 8949 App A simple values (false/true/null)\n");
    }

    /* Doubles.  RFC 8949 § A: 1.1 → 0xfb3ff199999999999a (binary64). */
    {
        n00b_buffer_t *b = n00b_cbor_encode_double_(1.1);
        assert(buffer_matches_hex(b, "fb3ff199999999999a"));

        b = n00b_cbor_encode_double_(-4.1);
        assert(buffer_matches_hex(b, "fbc010666666666666"));

        b = n00b_cbor_encode_double_(1.0e+300);
        assert(buffer_matches_hex(b, "fb7e37e43c8800759c"));

        printf("  [PASS] RFC 8949 App A double-precision vectors (3)\n");
    }

    /* Text strings. */
    {
        n00b_string_t *s;
        n00b_buffer_t *b;

        /* "" → 0x60 */
        s = n00b_string_from_cstr("");
        b = n00b_cbor_encode_string_(s);
        assert(buffer_matches_hex(b, "60"));

        /* "a" → 0x6161 */
        s = n00b_string_from_cstr("a");
        b = n00b_cbor_encode_string_(s);
        assert(buffer_matches_hex(b, "6161"));

        /* "IETF" → 0x6449455446 */
        s = n00b_string_from_cstr("IETF");
        b = n00b_cbor_encode_string_(s);
        assert(buffer_matches_hex(b, "6449455446"));

        /* "\"\\" → 0x62225c — 2 bytes: " then \ */
        s = n00b_string_from_cstr("\"\\");
        b = n00b_cbor_encode_string_(s);
        assert(buffer_matches_hex(b, "62225c"));

        printf("  [PASS] RFC 8949 App A text-string vectors (4)\n");
    }

    /* Byte strings. */
    {
        n00b_buffer_t *b;

        /* h'' → 0x40 */
        b = n00b_buffer_empty();
        n00b_buffer_t *out = n00b_buffer_empty();
        n00b_cbor_write_buffer(out, b);
        assert(buffer_matches_hex(out, "40"));

        /* h'01020304' → 0x4401020304 */
        b = buffer_from_hex("01020304");
        out = n00b_buffer_empty();
        n00b_cbor_write_buffer(out, b);
        assert(buffer_matches_hex(out, "4401020304"));

        printf("  [PASS] RFC 8949 App A byte-string vectors (2)\n");
    }

    /* Arrays. */
    {
        /* [] → 0x80 */
        n00b_buffer_t *out = n00b_buffer_empty();
        n00b_cbor_write_array_header(out, 0);
        assert(buffer_matches_hex(out, "80"));

        /* [1, 2, 3] → 0x83010203 */
        out = n00b_buffer_empty();
        n00b_cbor_write_array_header(out, 3);
        n00b_cbor_write_int(out, 1);
        n00b_cbor_write_int(out, 2);
        n00b_cbor_write_int(out, 3);
        assert(buffer_matches_hex(out, "83010203"));

        /* [1, [2, 3], [4, 5]] → 0x8301820203820405 */
        out = n00b_buffer_empty();
        n00b_cbor_write_array_header(out, 3);
        n00b_cbor_write_int(out, 1);
        n00b_cbor_write_array_header(out, 2);
        n00b_cbor_write_int(out, 2);
        n00b_cbor_write_int(out, 3);
        n00b_cbor_write_array_header(out, 2);
        n00b_cbor_write_int(out, 4);
        n00b_cbor_write_int(out, 5);
        assert(buffer_matches_hex(out, "8301820203820405"));

        printf("  [PASS] RFC 8949 App A array vectors (3)\n");
    }

    /* Maps. */
    {
        /* {} → 0xa0 */
        n00b_buffer_t *out = n00b_buffer_empty();
        n00b_cbor_write_map_header(out, 0);
        assert(buffer_matches_hex(out, "a0"));

        /* {1: 2, 3: 4} → 0xa201020304 */
        out = n00b_buffer_empty();
        n00b_cbor_write_map_header(out, 2);
        n00b_cbor_write_int(out, 1);
        n00b_cbor_write_int(out, 2);
        n00b_cbor_write_int(out, 3);
        n00b_cbor_write_int(out, 4);
        assert(buffer_matches_hex(out, "a201020304"));

        /* {"a": 1, "b": [2, 3]} → 0xa26161016162820203 */
        out = n00b_buffer_empty();
        n00b_cbor_write_map_header(out, 2);
        n00b_cbor_write_string(out, n00b_string_from_cstr("a"));
        n00b_cbor_write_int(out, 1);
        n00b_cbor_write_string(out, n00b_string_from_cstr("b"));
        n00b_cbor_write_array_header(out, 2);
        n00b_cbor_write_int(out, 2);
        n00b_cbor_write_int(out, 3);
        assert(buffer_matches_hex(out, "a26161016162820203"));

        printf("  [PASS] RFC 8949 App A map vectors (3)\n");
    }
}

/* ===========================================================================
 * 2. RFC 8949 Appendix A — decode side
 *
 * Same vectors, parsed via `n00b_cbor_decode`.  Verifies the
 * `n00b_cbor_value_t` AST shape.
 * =========================================================================== */

static void
test_rfc_appendix_a_decode(void)
{
    /* Integers — both arms of the tagged union. */
    {
        n00b_buffer_t *b = buffer_from_hex("00");
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_ok(r));
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_UINT);
        assert(v->u.uint == 0);

        b = buffer_from_hex("1b000000e8d4a51000");
        r = n00b_cbor_decode(b);
        assert(n00b_result_is_ok(r));
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_UINT);
        assert(v->u.uint == 1000000000000ULL);

        b = buffer_from_hex("20");
        r = n00b_cbor_decode(b);
        assert(n00b_result_is_ok(r));
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_NEGINT);
        auto i = n00b_cbor_value_to_int64(v);
        assert(n00b_result_is_ok(i));
        assert(n00b_result_get(i) == -1);

        b = buffer_from_hex("3903e7");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        i = n00b_cbor_value_to_int64(v);
        assert(n00b_result_get(i) == -1000);

        printf("  [PASS] decode App A integers\n");
    }

    /* Doubles — including round-trip via the float16 path. */
    {
        n00b_buffer_t *b = buffer_from_hex("fb3ff199999999999a");
        auto r = n00b_cbor_decode(b);
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_DOUBLE);
        assert(v->u.f64 == 1.1);

        /* App A: 1.5 → 0xf93e00 (binary16, NOT round-tripped via
         * canonical encode).  We accept on the decode side. */
        b = buffer_from_hex("f93e00");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_FLOAT16);
        auto d = n00b_cbor_value_to_double(v);
        assert(n00b_result_is_ok(d));
        assert(n00b_result_get(d) == 1.5);

        /* App A: 100000.0 → 0xfa47c35000 (binary32). */
        b = buffer_from_hex("fa47c35000");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_FLOAT32);
        d = n00b_cbor_value_to_double(v);
        assert(n00b_result_get(d) == 100000.0);

        printf("  [PASS] decode App A doubles + float16 + float32\n");
    }

    /* Booleans + null. */
    {
        n00b_buffer_t *b = buffer_from_hex("f4");
        auto r = n00b_cbor_decode(b);
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_BOOL && v->u.boolean == false);

        b = buffer_from_hex("f5");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_BOOL && v->u.boolean == true);

        b = buffer_from_hex("f6");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_NULL);

        printf("  [PASS] decode App A simple values\n");
    }

    /* Text. */
    {
        n00b_buffer_t *b = buffer_from_hex("6449455446");
        auto r = n00b_cbor_decode(b);
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_STRING);
        assert(v->u.string->u8_bytes == 4);
        assert(memcmp(v->u.string->data, "IETF", 4) == 0);

        printf("  [PASS] decode App A text strings\n");
    }

    /* Bytes. */
    {
        n00b_buffer_t *b = buffer_from_hex("4401020304");
        auto r = n00b_cbor_decode(b);
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_BYTES);
        assert(v->u.bytes->byte_len == 4);
        const uint8_t expected[4] = {1, 2, 3, 4};
        assert(memcmp(v->u.bytes->data, expected, 4) == 0);

        printf("  [PASS] decode App A byte strings\n");
    }

    /* Arrays + maps. */
    {
        /* [1, [2, 3], [4, 5]] */
        n00b_buffer_t *b = buffer_from_hex("8301820203820405");
        auto r = n00b_cbor_decode(b);
        n00b_cbor_value_t *v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_ARRAY);
        assert(v->u.array.count == 3);
        assert(v->u.array.items[0]->kind == N00B_CBOR_VT_UINT);
        assert(v->u.array.items[0]->u.uint == 1);
        assert(v->u.array.items[1]->kind == N00B_CBOR_VT_ARRAY);
        assert(v->u.array.items[1]->u.array.count == 2);
        assert(v->u.array.items[1]->u.array.items[0]->u.uint == 2);
        assert(v->u.array.items[1]->u.array.items[1]->u.uint == 3);
        assert(v->u.array.items[2]->u.array.count == 2);
        assert(v->u.array.items[2]->u.array.items[0]->u.uint == 4);
        assert(v->u.array.items[2]->u.array.items[1]->u.uint == 5);

        /* {"a": 1, "b": [2, 3]} */
        b = buffer_from_hex("a26161016162820203");
        r = n00b_cbor_decode(b);
        v = n00b_result_get(r);
        assert(v->kind == N00B_CBOR_VT_MAP);
        assert(v->u.map.count == 2);
        assert(v->u.map.pairs[0].key->kind == N00B_CBOR_VT_STRING);
        assert(memcmp(v->u.map.pairs[0].key->u.string->data, "a", 1) == 0);
        assert(v->u.map.pairs[0].val->kind == N00B_CBOR_VT_UINT);
        assert(v->u.map.pairs[0].val->u.uint == 1);
        assert(v->u.map.pairs[1].val->kind == N00B_CBOR_VT_ARRAY);
        assert(v->u.map.pairs[1].val->u.array.items[0]->u.uint == 2);
        assert(v->u.map.pairs[1].val->u.array.items[1]->u.uint == 3);

        printf("  [PASS] decode App A arrays + maps\n");
    }
}

/* ===========================================================================
 * 3. n00b round-trips
 * =========================================================================== */

static void
test_roundtrip_primitives(void)
{
    /* int64 — boundary values. */
    int64_t int_cases[] = {
        0, 1, -1, 23, 24, 100, 1000, 1000000, 0x7fffffff, INT64_MAX, INT64_MIN
    };
    for (size_t i = 0; i < sizeof(int_cases)/sizeof(int_cases[0]); i++) {
        int64_t v = int_cases[i];
        n00b_buffer_t *enc = n00b_cbor_encode_int64(v);
        auto r = n00b_cbor_decode(enc);
        assert(n00b_result_is_ok(r));
        auto i64 = n00b_cbor_value_to_int64(n00b_result_get(r));
        assert(n00b_result_is_ok(i64));
        assert(n00b_result_get(i64) == v);
    }
    printf("  [PASS] int64 round-trip (%zu boundary values)\n",
           sizeof(int_cases)/sizeof(int_cases[0]));

    /* bool. */
    for (int v = 0; v < 2; v++) {
        n00b_buffer_t *enc = n00b_cbor_encode_bool_((bool)v);
        auto r = n00b_cbor_decode(enc);
        auto b = n00b_cbor_value_to_bool(n00b_result_get(r));
        assert(n00b_result_get(b) == (bool)v);
    }
    printf("  [PASS] bool round-trip\n");

    /* double — incl special values. */
    double d_cases[] = { 0.0, 1.0, -1.0, 3.14159265358979, 1e-100, 1e100,
                         INFINITY, -INFINITY };
    for (size_t i = 0; i < sizeof(d_cases)/sizeof(d_cases[0]); i++) {
        double v = d_cases[i];
        n00b_buffer_t *enc = n00b_cbor_encode_double_(v);
        auto r = n00b_cbor_decode(enc);
        auto d = n00b_cbor_value_to_double(n00b_result_get(r));
        assert(n00b_result_is_ok(d));
        if (isnan(v)) assert(isnan(n00b_result_get(d)));
        else          assert(n00b_result_get(d) == v);
    }
    /* NaN separately. */
    {
        double v = NAN;
        n00b_buffer_t *enc = n00b_cbor_encode_double_(v);
        auto r = n00b_cbor_decode(enc);
        auto d = n00b_cbor_value_to_double(n00b_result_get(r));
        assert(isnan(n00b_result_get(d)));
    }
    printf("  [PASS] double round-trip (incl ±inf, NaN)\n");

    /* string — incl Unicode. */
    const char *s_cases[] = {
        "", "a", "hello", "Здравствуй, мир!", "🌀 spiral",
    };
    for (size_t i = 0; i < sizeof(s_cases)/sizeof(s_cases[0]); i++) {
        n00b_string_t *s = n00b_string_from_cstr(s_cases[i]);
        n00b_buffer_t *enc = n00b_cbor_encode_string_(s);
        auto r = n00b_cbor_decode(enc);
        auto s_out = n00b_cbor_value_to_string(n00b_result_get(r));
        assert(n00b_result_is_ok(s_out));
        n00b_string_t *got = n00b_result_get(s_out);
        assert(got->u8_bytes == s->u8_bytes);
        assert(memcmp(got->data, s->data, s->u8_bytes) == 0);
    }
    printf("  [PASS] string round-trip (incl multi-byte UTF-8)\n");

    /* buffer. */
    {
        const uint8_t bytes[] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff };
        n00b_buffer_t *src = n00b_buffer_from_bytes((char *)bytes, sizeof(bytes));
        n00b_buffer_t *enc = n00b_cbor_encode_buffer_(src);
        auto r = n00b_cbor_decode(enc);
        auto bv = n00b_cbor_value_to_buffer(n00b_result_get(r));
        assert(n00b_result_is_ok(bv));
        n00b_buffer_t *got = n00b_result_get(bv);
        assert((size_t)got->byte_len == sizeof(bytes));
        assert(memcmp(got->data, bytes, sizeof(bytes)) == 0);
    }
    printf("  [PASS] buffer round-trip\n");
}

static void
test_roundtrip_containers(void)
{
    /* Build {"name": "n00b", "version": [0, 3, 0], "stable": false}. */
    n00b_buffer_t *out = n00b_buffer_empty();
    n00b_cbor_write_map_header(out, 3);
    n00b_cbor_write_string(out, n00b_string_from_cstr("name"));
    n00b_cbor_write_string(out, n00b_string_from_cstr("n00b"));
    n00b_cbor_write_string(out, n00b_string_from_cstr("version"));
    n00b_cbor_write_array_header(out, 3);
    n00b_cbor_write_int(out, 0);
    n00b_cbor_write_int(out, 3);
    n00b_cbor_write_int(out, 0);
    n00b_cbor_write_string(out, n00b_string_from_cstr("stable"));
    n00b_cbor_write_bool(out, false);

    auto r = n00b_cbor_decode(out);
    assert(n00b_result_is_ok(r));
    n00b_cbor_value_t *v = n00b_result_get(r);
    assert(v->kind == N00B_CBOR_VT_MAP);
    assert(v->u.map.count == 3);

    n00b_cbor_value_t *version = v->u.map.pairs[1].val;
    assert(version->kind == N00B_CBOR_VT_ARRAY);
    assert(version->u.array.count == 3);
    auto i0 = n00b_cbor_value_to_int64(version->u.array.items[0]);
    auto i1 = n00b_cbor_value_to_int64(version->u.array.items[1]);
    auto i2 = n00b_cbor_value_to_int64(version->u.array.items[2]);
    assert(n00b_result_get(i0) == 0);
    assert(n00b_result_get(i1) == 3);
    assert(n00b_result_get(i2) == 0);

    auto stable = n00b_cbor_value_to_bool(v->u.map.pairs[2].val);
    assert(n00b_result_is_ok(stable));
    assert(n00b_result_get(stable) == false);

    printf("  [PASS] heterogeneous map round-trip\n");

    /* Nested array of objects (the JSON idiom). */
    out = n00b_buffer_empty();
    n00b_cbor_write_array_header(out, 2);
    for (int i = 0; i < 2; i++) {
        n00b_cbor_write_map_header(out, 2);
        n00b_cbor_write_string(out, n00b_string_from_cstr("id"));
        n00b_cbor_write_int(out, 1000 + i);
        n00b_cbor_write_string(out, n00b_string_from_cstr("ok"));
        n00b_cbor_write_bool(out, i == 0);
    }
    r = n00b_cbor_decode(out);
    assert(n00b_result_is_ok(r));
    v = n00b_result_get(r);
    assert(v->kind == N00B_CBOR_VT_ARRAY);
    assert(v->u.array.count == 2);
    for (int i = 0; i < 2; i++) {
        n00b_cbor_value_t *m = v->u.array.items[i];
        assert(m->kind == N00B_CBOR_VT_MAP);
        assert(m->u.map.count == 2);
        auto idr = n00b_cbor_value_to_int64(m->u.map.pairs[0].val);
        assert(n00b_result_get(idr) == 1000 + i);
        auto okr = n00b_cbor_value_to_bool(m->u.map.pairs[1].val);
        assert(n00b_result_get(okr) == (i == 0));
    }
    printf("  [PASS] nested array-of-maps round-trip\n");
}

/* ===========================================================================
 * 4. Hardening — error paths
 * =========================================================================== */

static void
test_decoder_hardening(void)
{
    /* Truncated head. */
    {
        n00b_buffer_t *b = buffer_from_hex("19");  /* uint w/ 2-byte arg, but no bytes */
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NEED_MORE_DATA);
    }

    /* Indefinite-length array (we refuse). */
    {
        n00b_buffer_t *b = buffer_from_hex("9f018202039f0405ffff");
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Indefinite-length text (we refuse). */
    {
        n00b_buffer_t *b = buffer_from_hex("7f657374726561646d696e67ff");
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Trailing bytes after a valid item. */
    {
        n00b_buffer_t *b = buffer_from_hex("0001");
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Length-cap. */
    {
        size_t big = N00B_CBOR_MAX_INPUT_BYTES + 1;
        uint8_t *ones = calloc(big, 1);
        auto r = n00b_cbor_decode_bytes(ones, big);
        free(ones);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_FRAME_TOO_LARGE);
    }

    /* Empty input. */
    {
        auto r = n00b_cbor_decode_bytes(nullptr, 0);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_NEED_MORE_DATA);
    }

    /* Depth-cap.  Build N00B_CBOR_MAX_DEPTH + 1 nested 1-element
     * arrays, then a single integer.  Should hit the cap. */
    {
        size_t depth = (size_t)N00B_CBOR_MAX_DEPTH + 1;
        size_t total = depth + 1;
        uint8_t *bytes = malloc(total);
        for (size_t i = 0; i < depth; i++) {
            bytes[i] = (uint8_t)((4u << 5) | 1u);  /* array(1) */
        }
        bytes[depth] = 0x00;  /* uint 0 */
        auto r = n00b_cbor_decode_bytes(bytes, total);
        free(bytes);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Map size lying about its content (claims 100 pairs, only 1 byte left). */
    {
        n00b_buffer_t *b = buffer_from_hex("b864");  /* map(100), no pairs */
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        /* Could be PROTOCOL (pre-flight) or NEED_MORE_DATA — either is fine. */
        n00b_err_t e = n00b_result_get_err(r);
        assert(e == N00B_QUIC_ERR_PROTOCOL || e == N00B_QUIC_ERR_NEED_MORE_DATA);
    }

    /* Bad UTF-8 in a text string. */
    {
        n00b_buffer_t *b = buffer_from_hex("62c328");  /* text(2), 0xc3 0x28 */
        auto r = n00b_cbor_decode(b);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Reserved AI 28 / 29 / 30. */
    for (uint8_t ai = 28; ai <= 30; ai++) {
        uint8_t bytes[1] = { (uint8_t)((0u << 5) | ai) };
        auto r = n00b_cbor_decode_bytes(bytes, 1);
        assert(n00b_result_is_err(r));
        assert(n00b_result_get_err(r) == N00B_QUIC_ERR_PROTOCOL);
    }

    /* Type-mismatch on extractor. */
    {
        n00b_buffer_t *b = buffer_from_hex("00");
        auto r = n00b_cbor_decode(b);
        auto s = n00b_cbor_value_to_string(n00b_result_get(r));
        assert(n00b_result_is_err(s));
        assert(n00b_result_get_err(s) == N00B_QUIC_ERR_BAD_TYPE);
    }

    printf("  [PASS] decoder hardening (truncated, indef, trailing,\n"
           "         length-cap, depth-cap, lying counts, bad UTF-8,\n"
           "         reserved AI, type mismatch)\n");
}

/* ===========================================================================
 * 5. The decode_to(T, buf) macro
 * =========================================================================== */

static void
test_decode_to_macro(void)
{
    n00b_buffer_t *enc;

    enc = n00b_cbor_encode_int64(42);
    auto ri = n00b_cbor_decode_to(int64_t, enc);
    assert(n00b_result_is_ok(ri));
    assert(n00b_result_get(ri) == 42);

    enc = n00b_cbor_encode_bool_(true);
    auto rb = n00b_cbor_decode_to(bool, enc);
    assert(n00b_result_is_ok(rb));
    assert(n00b_result_get(rb) == true);

    enc = n00b_cbor_encode_double_(2.71828);
    auto rd = n00b_cbor_decode_to(double, enc);
    assert(n00b_result_is_ok(rd));
    assert(n00b_result_get(rd) == 2.71828);

    enc = n00b_cbor_encode_string_(n00b_string_from_cstr("hello"));
    auto rs = n00b_cbor_decode_to(n00b_string_t *, enc);
    assert(n00b_result_is_ok(rs));
    n00b_string_t *s = n00b_result_get(rs);
    assert(s->u8_bytes == 5 && memcmp(s->data, "hello", 5) == 0);

    const uint8_t raw[] = { 1, 2, 3 };
    enc = n00b_cbor_encode_buffer_(n00b_buffer_from_bytes((char *)raw, 3));
    auto rbf = n00b_cbor_decode_to(n00b_buffer_t *, enc);
    assert(n00b_result_is_ok(rbf));
    assert(n00b_result_get(rbf)->byte_len == 3);

    /* Type-mismatch through the macro: encode int → decode_to(string). */
    enc = n00b_cbor_encode_int64(7);
    auto rfail = n00b_cbor_decode_to(n00b_string_t *, enc);
    assert(n00b_result_is_err(rfail));
    assert(n00b_result_get_err(rfail) == N00B_QUIC_ERR_BAD_TYPE);

    printf("  [PASS] n00b_cbor_decode_to(T, buf) for all 5 supported T\n");
}

static void
test_encode_generic_macro(void)
{
    int           i   = 42;
    int32_t       i32 = 43;
    n00b_buffer_t *enc;

    enc = n00b_cbor_encode(i);
    auto ri = n00b_cbor_decode_to(int64_t, enc);
    assert(n00b_result_is_ok(ri));
    assert(n00b_result_get(ri) == 42);

    enc = n00b_cbor_encode(i32);
    auto ri32 = n00b_cbor_decode_to(int64_t, enc);
    assert(n00b_result_is_ok(ri32));
    assert(n00b_result_get(ri32) == 43);

    n00b_string_t *generic = n00b_string_from_cstr("generic");
    enc = n00b_cbor_encode(generic);
    auto rs = n00b_cbor_decode_to(n00b_string_t *, enc);
    assert(n00b_result_is_ok(rs));
    n00b_string_t *s = n00b_result_get(rs);
    assert(s->u8_bytes == 7 && memcmp(s->data, "generic", 7) == 0);

}

/* ===========================================================================
 * 6. Tag round-trip — verify the decoder surfaces the tag
 * =========================================================================== */

static void
test_tag_roundtrip(void)
{
    n00b_buffer_t *out = n00b_buffer_empty();
    n00b_cbor_write_tag(out, N00B_CBOR_TAG_RESULT_OK);
    n00b_cbor_write_int(out, 42);

    auto r = n00b_cbor_decode(out);
    assert(n00b_result_is_ok(r));
    n00b_cbor_value_t *v = n00b_result_get(r);
    assert(v->kind == N00B_CBOR_VT_TAG);
    assert(v->u.tag.tag == N00B_CBOR_TAG_RESULT_OK);
    auto inner = n00b_cbor_value_to_int64(v->u.tag.inner);
    assert(n00b_result_get(inner) == 42);

    /* Standard date-time vector from RFC 8949 Appendix A:
     *   0(2013-03-21T20:04:00Z) →
     *   0xc074323031332d30332d32315432303a30343a30305a   */
    n00b_buffer_t *b = buffer_from_hex(
        "c074323031332d30332d32315432303a30343a30305a");
    r = n00b_cbor_decode(b);
    v = n00b_result_get(r);
    assert(v->kind == N00B_CBOR_VT_TAG);
    assert(v->u.tag.tag == N00B_CBOR_TAG_DATETIME_RFC3339);
    assert(v->u.tag.inner->kind == N00B_CBOR_VT_STRING);
    assert(v->u.tag.inner->u.string->u8_bytes == 20);
    assert(memcmp(v->u.tag.inner->u.string->data,
                  "2013-03-21T20:04:00Z", 20) == 0);

    printf("  [PASS] tag round-trip + RFC 8949 datetime vector\n");
}

/* ===========================================================================
 * 7. Light fuzz pass — random bytes never crash
 *
 * Lightweight in-process fuzz; the dedicated libFuzzer harness lives
 * in test/fuzz/.  Here we just hammer the decoder with a few thousand
 * random short inputs to catch regressions during normal CI runs.
 * =========================================================================== */

static void
test_decoder_fuzz_smoke(void)
{
    srand(0xc0bbf001);
    int crashes = 0;
    for (int i = 0; i < 20000; i++) {
        size_t len = (size_t)(rand() % 256);
        uint8_t buf[256];
        for (size_t j = 0; j < len; j++) {
            buf[j] = (uint8_t)(rand() & 0xff);
        }
        auto r = n00b_cbor_decode_bytes(buf, len);
        if (n00b_result_is_ok(r)) {
            /* The AST root must have a valid kind. */
            n00b_cbor_value_t *v = n00b_result_get(r);
            assert(v->kind <= N00B_CBOR_VT_SIMPLE);
        } else {
            n00b_err_t e = n00b_result_get_err(r);
            (void)crashes;
            assert(e == N00B_QUIC_ERR_NEED_MORE_DATA
                || e == N00B_QUIC_ERR_PROTOCOL
                || e == N00B_QUIC_ERR_NULL_ARG
                || e == N00B_QUIC_ERR_FRAME_TOO_LARGE
                || e == N00B_QUIC_ERR_BAD_TYPE);
        }
    }
    printf("  [PASS] decoder fuzz smoke (20000 random inputs)\n");
}

/* ===========================================================================
 * `n00b_cbor_decode_first_bytes` — pull one item from a sliding window.
 *
 * Streaming RPC consumers want to decode the head of a buffer and
 * be told how many bytes that item occupied so they can advance.
 * The trailing bytes are NOT a protocol error in this variant.
 * =========================================================================== */

static void
test_decode_first_bytes(void)
{
    /* 0x18 0x2a = uint(42) — 2 bytes; 0x18 0x07 = uint(7) — 2 bytes;
     * concatenated. */
    const uint8_t bytes[] = { 0x18, 0x2a, 0x18, 0x07 };

    size_t used = 0;
    auto r1 = n00b_cbor_decode_first_bytes(bytes, sizeof(bytes), &used);
    assert(n00b_result_is_ok(r1));
    assert(used == 2);
    n00b_cbor_value_t *v1 = n00b_result_get(r1);
    assert(v1->kind == N00B_CBOR_VT_UINT && v1->u.uint == 42);

    auto r2 = n00b_cbor_decode_first_bytes(bytes + used,
                                           sizeof(bytes) - used, &used);
    assert(n00b_result_is_ok(r2));
    assert(used == 2);
    n00b_cbor_value_t *v2 = n00b_result_get(r2);
    assert(v2->kind == N00B_CBOR_VT_UINT && v2->u.uint == 7);

    /* Truncated input → NEED_MORE_DATA, consumed reset to 0. */
    used = 999;
    auto r3 = n00b_cbor_decode_first_bytes(bytes, 1, &used);  /* 0x18 wants 1 more byte */
    assert(n00b_result_is_err(r3));
    assert(n00b_result_get_err(r3) == N00B_QUIC_ERR_NEED_MORE_DATA);
    assert(used == 0);

    /* NULL consumed → NULL_ARG. */
    auto r4 = n00b_cbor_decode_first_bytes(bytes, sizeof(bytes), nullptr);
    assert(n00b_result_is_err(r4));
    assert(n00b_result_get_err(r4) == N00B_QUIC_ERR_NULL_ARG);

    printf("  [PASS] decode_first_bytes (sliding-window streaming consumer)\n");
}

/* ===========================================================================
 * Strict-mode policy knobs (Phase 4 § 4.7)
 *
 * The default `n00b_cbor_decode` enforces N00B_CBOR_MAX_DEPTH (32);
 * strict mode lets the caller request a tighter sub-cap via
 * `opts.max_depth`.  Verify that opt is honored.
 * =========================================================================== */

static void
test_strict_max_depth_subcap(void)
{
    /* Build a 4-deep nested array: [[[[1]]]]
     * RFC 8949 § 3.2.1: 0x81 = array(1) header. */
    const uint8_t bytes[] = { 0x81, 0x81, 0x81, 0x81, 0x01 };

    /* opts.max_depth = 0 → defaults to N00B_CBOR_MAX_DEPTH; should accept. */
    n00b_cbor_strict_opts_t lax = { .max_depth = 0 };
    auto r1 = n00b_cbor_decode_strict_bytes(bytes, sizeof(bytes), &lax);
    assert(n00b_result_is_ok(r1));

    /* opts.max_depth = 3 → should reject (4 levels of array nesting). */
    n00b_cbor_strict_opts_t tight = { .max_depth = 3 };
    auto r2 = n00b_cbor_decode_strict_bytes(bytes, sizeof(bytes), &tight);
    assert(n00b_result_is_err(r2));
    assert(n00b_result_get_err(r2) == N00B_QUIC_ERR_PROTOCOL);

    /* opts.max_depth = 10 → should accept (well above the actual depth). */
    n00b_cbor_strict_opts_t loose = { .max_depth = 10 };
    auto r3 = n00b_cbor_decode_strict_bytes(bytes, sizeof(bytes), &loose);
    assert(n00b_result_is_ok(r3));

    printf("  [PASS] strict max_depth honored (0→default, tight rejects, loose accepts)\n");
}

/* ===========================================================================
 * Main
 * =========================================================================== */

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_quic_cbor:\n");
    test_rfc_appendix_a_encode();
    test_rfc_appendix_a_decode();
    test_roundtrip_primitives();
    test_roundtrip_containers();
    test_tag_roundtrip();
    test_decode_to_macro();
    test_encode_generic_macro();
    test_decoder_hardening();
    test_decoder_fuzz_smoke();
    test_decode_first_bytes();
    test_strict_max_depth_subcap();
    printf("All quic_cbor tests passed.\n");

    n00b_shutdown();
    return 0;
}
