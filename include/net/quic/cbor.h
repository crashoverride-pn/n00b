/**
 * @file cbor.h
 * @brief CBOR (RFC 8949) encoder + decoder for the n00b QUIC RPC layer.
 *
 * Phase 4 § 4.1.  CBOR is the on-the-wire payload codec for n00b's
 * H3-based RPC: every request and response body is a single CBOR
 * item (typically a map representing the user's struct).  This
 * module implements:
 *
 *   - **Encoder**: append-style writer that emits canonical CBOR
 *     bytes into an `n00b_buffer_t *`.  Typed entry points cover the
 *     primitive set; container helpers emit array/map headers and
 *     let the caller stream nested items.
 *   - **Decoder**: state-machine pull decoder that materializes any
 *     CBOR document into an `n00b_cbor_value_t` tagged-union AST.
 *     The decoder is **hardened against malicious input**: a hard
 *     recursion cap (`N00B_CBOR_MAX_DEPTH`, default 32) and a hard
 *     total-bytes cap (`N00B_CBOR_MAX_INPUT_BYTES`, default 16 MiB)
 *     short-circuit pathological inputs.
 *   - **Type bindings**: typed extractors and the
 *     `n00b_cbor_decode_to()` macro that pulls a specific n00b type
 *     out of the AST in a single call (returning
 *     `n00b_result_t(T)`).
 *
 * ### Type mapping (Phase 4 plan § 6)
 *
 * | n00b type            | CBOR major type / shape                |
 * |----------------------|----------------------------------------|
 * | `int64_t`            | unsigned (0) or negative (1) integer    |
 * | `bool`               | simple value (true=21, false=20)       |
 * | `double`             | float (7, ai=27)                       |
 * | `n00b_string_t *`    | text string (3); UTF-8 enforced        |
 * | `n00b_buffer_t *`    | byte string (2)                        |
 * | `n00b_list_t(T) *`   | array (4) of T                         |
 * | `n00b_dict_t<K,V> *` | map (5) of K → V                       |
 * | `n00b_option_t(T)`   | nullable: null (7,22) or T              |
 * | `n00b_result_t(T)`   | tagged: tag 27 ok | tag 28 err          |
 * | `n00b_bigint_t *`    | tagged bignum (tag 2 / 3)               |
 * | `n00b_time_t`        | tagged date-time (tag 0 / tag 1)        |
 *
 * Bignum and time bindings emit/parse the tag wrappers but do not
 * ship rich n00b-side types in v1 (n00b's bigint and time wrapper
 * have not landed yet); see § decoder helpers below for the raw
 * accessors.
 *
 * ### Determinism / canonical encoding
 *
 * The encoder follows RFC 8949 § 4.2.1 ("Core Deterministic
 * Encoding"): integers are written in the smallest length that fits;
 * floats use 64-bit width (we do not down-convert); definite-length
 * arrays/maps only.  This makes encoder output byte-stable across
 * platforms — important for digest-based content-addressing built on
 * CBOR.
 *
 * **No `--insecure` switch.** The decoder rejects indefinite-length
 * items (RFC 8949 § 3.2) on input bound for the AST: the wire format
 * for our RPC doesn't need them and they multiply the attack surface.
 *
 * @see ~/dd/quic_4.md § 4.1 + § 6
 * @see RFC 8949 — CBOR
 */
#pragma once

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"
#include "net/quic/quic_types.h"

/* ===========================================================================
 * Limits
 * =========================================================================== */

/**
 * @brief Maximum nesting depth the decoder will descend into.
 *
 * Protects against pathological inputs (e.g., 1 MB of array openers
 * with no closes).  RFC 8949 leaves the limit application-defined;
 * we pick 32 to comfortably cover real RPC schemas while staying
 * stack-friendly.
 */
#ifndef N00B_CBOR_MAX_DEPTH
#define N00B_CBOR_MAX_DEPTH 32
#endif

/**
 * @brief Maximum byte length the decoder will consume.
 *
 * Larger inputs produce `N00B_QUIC_ERR_FRAME_TOO_LARGE`.  16 MiB is
 * generous for an RPC body; the H3 transport layer enforces its own
 * SETTINGS-driven frame caps before this one fires.
 */
#ifndef N00B_CBOR_MAX_INPUT_BYTES
#define N00B_CBOR_MAX_INPUT_BYTES (16u * 1024u * 1024u)
#endif

/* ===========================================================================
 * Tag constants (RFC 8949 § 3.4 + Phase 4 plan § 6)
 * =========================================================================== */

#define N00B_CBOR_TAG_DATETIME_RFC3339 0   /**< text-string standard date-time */
#define N00B_CBOR_TAG_EPOCH            1   /**< numeric Unix epoch */
#define N00B_CBOR_TAG_BIGNUM_POS       2   /**< byte-string positive bignum */
#define N00B_CBOR_TAG_BIGNUM_NEG       3   /**< byte-string negative bignum */
#define N00B_CBOR_TAG_RESULT_OK        27  /**< n00b_result_t ok arm */
#define N00B_CBOR_TAG_RESULT_ERR       28  /**< n00b_result_t err arm */

/* ===========================================================================
 * Decoded-value tagged union
 * =========================================================================== */

/** @brief CBOR major-type-derived discriminator for decoded values. */
typedef enum : uint8_t {
    N00B_CBOR_VT_UINT = 0,    /**< unsigned int that fits in uint64_t */
    N00B_CBOR_VT_NEGINT,      /**< negative int — magnitude in u.uint */
    N00B_CBOR_VT_INT64,       /**< both signed arms collapsed to int64_t */
    N00B_CBOR_VT_BYTES,       /**< byte string (n00b_buffer_t *) */
    N00B_CBOR_VT_STRING,      /**< text string (n00b_string_t *) */
    N00B_CBOR_VT_ARRAY,       /**< array of n00b_cbor_value_t * */
    N00B_CBOR_VT_MAP,         /**< pair-list of n00b_cbor_value_t * */
    N00B_CBOR_VT_TAG,         /**< tag wrapping another value */
    N00B_CBOR_VT_BOOL,
    N00B_CBOR_VT_NULL,
    N00B_CBOR_VT_UNDEFINED,
    N00B_CBOR_VT_DOUBLE,
    N00B_CBOR_VT_FLOAT32,
    N00B_CBOR_VT_FLOAT16,     /**< rare; kept for round-trip fidelity */
    N00B_CBOR_VT_SIMPLE,      /**< other simple values (RFC 8949 § 3.3) */
} n00b_cbor_value_kind_t;

typedef struct n00b_cbor_value_t n00b_cbor_value_t;

/**
 * @brief One key/value pair inside a decoded CBOR map.
 *
 * Keys can be any CBOR type; the wire format does not constrain them
 * to strings (unlike JSON).  Callers that expect string-keyed maps
 * should validate `key->kind == N00B_CBOR_VT_STRING` before use.
 */
typedef struct {
    n00b_cbor_value_t *key;
    n00b_cbor_value_t *val;
} n00b_cbor_pair_t;

/**
 * @brief A decoded CBOR value (the decoder's AST node).
 *
 * Allocated from the conduit pool.  Children (`u.array.items`,
 * `u.map.pairs`, `u.tag.inner`) are also conduit-pool-owned and live
 * for the same lifetime as the root — no per-node free is required.
 */
struct n00b_cbor_value_t {
    n00b_cbor_value_kind_t kind;
    union [[n00b::raw_union]] {
        uint64_t       uint;          /**< NEGINT stores magnitude here */
        int64_t        int64;
        bool           boolean;
        double         f64;
        float          f32;
        uint16_t       f16_bits;      /**< raw IEEE-754 binary16 bits */
        uint8_t        simple;
        n00b_buffer_t *bytes;
        n00b_string_t *string;
        struct {
            n00b_cbor_value_t **items;
            size_t              count;
        } array;
        struct {
            n00b_cbor_pair_t  *pairs;
            size_t             count;
        } map;
        struct {
            uint64_t           tag;
            n00b_cbor_value_t *inner;
        } tag;
    } u;
};

/* ===========================================================================
 * Encoder — typed primitive entry points
 *
 * Each entry point appends the CBOR bytes for a single item to a
 * caller-supplied buffer.  The buffer should be empty (or already
 * mid-document; nesting is the caller's responsibility) on entry.
 * Entry points are infallible for valid inputs; they fail (return
 * err) only when the buffer can't grow.
 * =========================================================================== */

/**
 * @brief Append a signed integer as CBOR major-type 0 / 1.
 *
 * Picks the smallest length that fits per RFC 8949 § 4.2.1.
 *
 * @param dst   Destination buffer (appended in place).
 * @param value Signed value.
 */
extern void n00b_cbor_write_int(n00b_buffer_t *dst, int64_t value);

/** @brief Append an unsigned integer.  Convenience wrapper that
 *         picks major type 0 unconditionally. */
extern void n00b_cbor_write_uint(n00b_buffer_t *dst, uint64_t value);

/** @brief Append a boolean (simple value 20 / 21). */
extern void n00b_cbor_write_bool(n00b_buffer_t *dst, bool value);

/** @brief Append the simple value `null` (7, 22). */
extern void n00b_cbor_write_null(n00b_buffer_t *dst);

/** @brief Append a double-precision float (7, ai=27). */
extern void n00b_cbor_write_double(n00b_buffer_t *dst, double value);

/**
 * @brief Append a byte string (major type 2).
 *
 * @param dst   Destination buffer.
 * @param data  Source bytes (may be nullptr iff @p len == 0).
 * @param len   Byte count.
 */
extern void n00b_cbor_write_bytes(n00b_buffer_t *dst,
                                  const uint8_t *data,
                                  size_t         len);

/**
 * @brief Append an `n00b_buffer_t *` as a byte string.
 *
 * @param dst   Destination buffer.
 * @param value Source buffer (may be nullptr — encodes the empty
 *              byte string, equivalent to an empty buffer).
 */
extern void n00b_cbor_write_buffer(n00b_buffer_t *dst, n00b_buffer_t *value);

/**
 * @brief Append a UTF-8 text string (major type 3).
 *
 * The bytes between @p data and @p data + @p len must be valid UTF-8
 * (RFC 8949 § 3.1).  This function does NOT validate; callers that
 * accept untrusted input should pre-validate with the unicode helpers.
 */
extern void n00b_cbor_write_text(n00b_buffer_t *dst,
                                 const char    *data,
                                 size_t         len);

/**
 * @brief Append an `n00b_string_t *` as a text string.
 *
 * @param dst   Destination buffer.
 * @param value Source string (may be nullptr — encodes the empty
 *              text string).
 */
extern void n00b_cbor_write_string(n00b_buffer_t *dst, n00b_string_t *value);

/**
 * @brief Append an array header for @p count items.
 *
 * The caller is responsible for emitting exactly @p count items
 * after the header.
 */
extern void n00b_cbor_write_array_header(n00b_buffer_t *dst, uint64_t count);

/**
 * @brief Append a map header for @p count pairs.
 *
 * The caller is responsible for emitting exactly @p count
 * key/value pairs after the header.
 */
extern void n00b_cbor_write_map_header(n00b_buffer_t *dst, uint64_t count);

/**
 * @brief Append a tag wrapper.  The next item written into @p dst
 *        becomes the tag's content.
 */
extern void n00b_cbor_write_tag(n00b_buffer_t *dst, uint64_t tag);

/**
 * @brief Append a `n00b_list_t(int64_t)` as an array of integers.
 *
 * @param dst   Destination buffer.
 * @param items List to encode (must be lvalue).
 */
#define n00b_cbor_write_int_list(dst, items)                                                  \
    do {                                                                                       \
        auto _bl_w_lp = &(items);                                                              \
        size_t _bl_w_n = _bl_w_lp->len;                                                        \
        n00b_cbor_write_array_header((dst), (uint64_t)_bl_w_n);                                \
        for (size_t _bl_w_i = 0; _bl_w_i < _bl_w_n; _bl_w_i++) {                               \
            n00b_cbor_write_int((dst), (int64_t)_bl_w_lp->data[_bl_w_i]);                      \
        }                                                                                      \
    } while (0)

/**
 * @brief Append a `n00b_list_t(n00b_string_t *)` as an array of text strings.
 */
#define n00b_cbor_write_string_list(dst, items)                                               \
    do {                                                                                       \
        auto _bl_w_lp = &(items);                                                              \
        size_t _bl_w_n = _bl_w_lp->len;                                                        \
        n00b_cbor_write_array_header((dst), (uint64_t)_bl_w_n);                                \
        for (size_t _bl_w_i = 0; _bl_w_i < _bl_w_n; _bl_w_i++) {                               \
            n00b_cbor_write_string((dst), _bl_w_lp->data[_bl_w_i]);                            \
        }                                                                                      \
    } while (0)

/* ===========================================================================
 * High-level encode entry points
 * =========================================================================== */

/**
 * @brief Allocate a fresh buffer and encode a single primitive value
 *        into it.
 *
 * The `_Generic`-driven `n00b_cbor_encode()` macro selects the right
 * entry point based on the static type of @p value:
 *
 *   - `int64_t` / `int32_t` / `int` → unsigned/negative integer
 *   - `bool`                        → simple 20/21
 *   - `double`                      → float64
 *   - `n00b_string_t *`             → text string
 *   - `n00b_buffer_t *`             → byte string
 *
 * For container types (lists, dicts) callers should use the writer
 * API directly: it scales linearly with the document and avoids
 * intermediate AST construction.
 *
 * @return Heap-allocated buffer (conduit-pool) holding the wire bytes.
 */
extern n00b_buffer_t *n00b_cbor_encode_int64(int64_t v);
extern n00b_buffer_t *n00b_cbor_encode_bool_(bool v);
extern n00b_buffer_t *n00b_cbor_encode_double_(double v);
extern n00b_buffer_t *n00b_cbor_encode_string_(n00b_string_t *v);
extern n00b_buffer_t *n00b_cbor_encode_buffer_(n00b_buffer_t *v);
extern n00b_buffer_t *n00b_cbor_encode_null_(void);

#if INT_MIN == INT32_MIN && INT_MAX == INT32_MAX
#define N00B_CBOR_ENCODE_INT32_ASSOC
#else
#define N00B_CBOR_ENCODE_INT32_ASSOC int32_t: n00b_cbor_encode_int64,
#endif

/**
 * @brief Generic single-value encode: returns a fresh buffer.
 *
 * Selects the typed encoder based on the static type of @p v.  Use
 * the writer API for compound documents.
 */
#define n00b_cbor_encode(v)                                                                   \
    _Generic((v),                                                                              \
        bool:             n00b_cbor_encode_bool_,                                              \
        int:              n00b_cbor_encode_int64,                                              \
        N00B_CBOR_ENCODE_INT32_ASSOC                                                           \
        int64_t:          n00b_cbor_encode_int64,                                              \
        unsigned int:     n00b_cbor_encode_int64,                                              \
        unsigned long:    n00b_cbor_encode_int64,                                              \
        double:           n00b_cbor_encode_double_,                                            \
        float:            n00b_cbor_encode_double_,                                            \
        n00b_string_t *:  n00b_cbor_encode_string_,                                            \
        n00b_buffer_t *:  n00b_cbor_encode_buffer_                                             \
    )(v)

/* ===========================================================================
 * Decoder
 * =========================================================================== */

/**
 * @brief Decode a complete CBOR document into a tagged-union AST.
 *
 * Steps (RFC 8949 § 3):
 *   1. Reject inputs > `N00B_CBOR_MAX_INPUT_BYTES`.
 *   2. Parse one top-level item; depth-bounded by
 *      `N00B_CBOR_MAX_DEPTH`.
 *   3. Reject indefinite-length items (string / array / map / break).
 *   4. Reject trailing bytes after the top-level item.
 *
 * @param input  Bytes to decode.  May be nullptr iff the buffer
 *               stores 0 bytes; equivalent to passing an empty doc
 *               (which itself fails — see below).
 *
 * @return  Result: ok with the AST root; err with:
 *          - `N00B_QUIC_ERR_NULL_ARG` if @p input is nullptr.
 *          - `N00B_QUIC_ERR_FRAME_TOO_LARGE` on input-cap overflow.
 *          - `N00B_QUIC_ERR_NEED_MORE_DATA` on truncated input.
 *          - `N00B_QUIC_ERR_PROTOCOL` on malformed bytes,
 *            indefinite-length items, depth-cap overflow, or
 *            trailing bytes.
 */
extern n00b_result_t(n00b_cbor_value_t *)
n00b_cbor_decode(n00b_buffer_t *input);

/**
 * @brief Same as `n00b_cbor_decode` but on raw bytes.
 *
 * @param data Pointer to first byte (may be nullptr iff @p len == 0).
 * @param len  Total byte count.
 */
extern n00b_result_t(n00b_cbor_value_t *)
n00b_cbor_decode_bytes(const uint8_t *data, size_t len);

/**
 * @brief Decode the first CBOR item from a window, return its byte
 *        size; trailing bytes are NOT an error.
 *
 * The streaming consumer wants exactly this: walk a sliding byte
 * window and pull one item at a time.  `n00b_cbor_decode_bytes`
 * insists on no-trailing — this variant lifts that restriction and
 * reports how many bytes the parsed item occupied.
 *
 * @param data      Pointer to first byte.
 * @param len       Bytes available.
 * @param consumed  Out: bytes consumed by the parsed item (only set
 *                  on the OK path).
 *
 * @return ok with the parsed item; err on NEED_MORE_DATA / PROTOCOL /
 *         FRAME_TOO_LARGE / NULL_ARG.  Differs from `_bytes` only in
 *         the trailing-byte policy: trailing bytes are silently kept
 *         in the caller's window for the next pull.
 */
extern n00b_result_t(n00b_cbor_value_t *)
n00b_cbor_decode_first_bytes(const uint8_t *data,
                             size_t         len,
                             size_t        *consumed);

/* ---------------------------------------------------------------------------
 * Strict-mode decoder (Phase 4 § 4.7)
 *
 * The streaming RPC layer requires a tighter decode policy than the
 * default `n00b_cbor_decode` enforces.  Strict mode:
 *
 *   - Hard depth cap (configurable; default `N00B_CBOR_MAX_DEPTH`).
 *   - Rejects indefinite-length items everywhere (not just at root).
 *   - Rejects duplicate map keys (RFC 8949 § 5.6 — canonical encoders
 *     MUST NOT emit duplicates; in strict mode we treat them as a
 *     protocol error rather than last-write-wins).
 *   - Optional tag allowlist.  When `tag_allowlist != nullptr`, only
 *     tags listed there are accepted; any other tag → `INVALID_ARGUMENT`.
 *     A nullptr allowlist accepts the default RPC tag set
 *     (`docs/quic/rpc_design.md` § 4): bignum (2/3), datetime (0/1),
 *     n00b result (27/28).
 * --------------------------------------------------------------------------- */

/** @brief Strict-decode policy options. */
typedef struct {
    /** Optional tag allowlist; null = use the default RPC tag set. */
    const uint64_t *tag_allowlist;
    /** Length of @c tag_allowlist (entries). */
    size_t          tag_allowlist_len;
    /** Hard depth cap; 0 → use `N00B_CBOR_MAX_DEPTH`. */
    int             max_depth;
} n00b_cbor_strict_opts_t;

/**
 * @brief Decode @p input under strict-mode policies.
 *
 * Strict mode:
 *   1. Rejects indefinite-length items at any depth (the default
 *      decoder rejects them at the root).
 *   2. Rejects duplicate map keys.
 *   3. Enforces a hard depth cap (default `N00B_CBOR_MAX_DEPTH`).
 *   4. Restricts permissible tags to @c opts.tag_allowlist (or the
 *      default RPC set when @c opts is nullptr / @c tag_allowlist is null).
 *
 * @param input Source buffer.
 * @param opts  Strict-mode options (may be nullptr → default RPC policy).
 *
 * @return  ok with the AST root; err with the same error codes as
 *          `n00b_cbor_decode`, plus `N00B_QUIC_ERR_PROTOCOL` for
 *          duplicate keys / disallowed tags / nested indefinite-length
 *          items.
 */
extern n00b_result_t(n00b_cbor_value_t *)
n00b_cbor_decode_strict(n00b_buffer_t                 *input,
                        const n00b_cbor_strict_opts_t *opts);

/**
 * @brief Strict decode from raw bytes (mirrors `n00b_cbor_decode_bytes`).
 */
extern n00b_result_t(n00b_cbor_value_t *)
n00b_cbor_decode_strict_bytes(const uint8_t                 *data,
                              size_t                         len,
                              const n00b_cbor_strict_opts_t *opts);

/* ---------------------------------------------------------------------------
 * Typed extractors — pull a specific n00b type out of a decoded AST
 * --------------------------------------------------------------------------- */

/** @brief Extract an int64 from a decoded value.
 *
 *  Accepts `N00B_CBOR_VT_UINT`, `_NEGINT`, and `_INT64`.  Out-of-range
 *  values (uint > INT64_MAX, or negint magnitude > INT64_MAX + 1)
 *  produce `N00B_QUIC_ERR_PROTOCOL`. */
extern n00b_result_t(int64_t) n00b_cbor_value_to_int64(n00b_cbor_value_t *v);

/** @brief Extract a bool. */
extern n00b_result_t(bool) n00b_cbor_value_to_bool(n00b_cbor_value_t *v);

/** @brief Extract a double.  Promotes float32 / float16. */
extern n00b_result_t(double) n00b_cbor_value_to_double(n00b_cbor_value_t *v);

/** @brief Extract an `n00b_string_t *`. */
extern n00b_result_t(n00b_string_t *) n00b_cbor_value_to_string(n00b_cbor_value_t *v);

/** @brief Extract an `n00b_buffer_t *`. */
extern n00b_result_t(n00b_buffer_t *) n00b_cbor_value_to_buffer(n00b_cbor_value_t *v);

/* ---------------------------------------------------------------------------
 * One-shot decode-to-T macro
 *
 * Selects the right extractor based on the *target* type token.
 * Usage:
 *
 *     n00b_result_t(int64_t) r = n00b_cbor_decode_to(int64_t, body);
 *     if (n00b_result_is_ok(r)) { int64_t v = n00b_result_get(r); ... }
 *
 * Supported target types: int64_t, bool, double, n00b_string_t *,
 * n00b_buffer_t *.  For richer AST exposure use `n00b_cbor_decode()`
 * directly.
 * --------------------------------------------------------------------------- */

extern n00b_result_t(int64_t)         _n00b_cbor_decode_to_int64(n00b_buffer_t *buf);
extern n00b_result_t(bool)            _n00b_cbor_decode_to_bool(n00b_buffer_t *buf);
extern n00b_result_t(double)          _n00b_cbor_decode_to_double(n00b_buffer_t *buf);
extern n00b_result_t(n00b_string_t *) _n00b_cbor_decode_to_string(n00b_buffer_t *buf);
extern n00b_result_t(n00b_buffer_t *) _n00b_cbor_decode_to_buffer(n00b_buffer_t *buf);

/**
 * @brief Decode the buffer and project to @p T in one call.
 *
 * @param T   Target n00b type token (`int64_t`, `bool`, `double`,
 *            `n00b_string_t *`, or `n00b_buffer_t *`).
 * @param buf Source buffer.
 *
 * @return `n00b_result_t(T)` — ok with the value, err on decode or
 *         shape mismatch.
 */
#define n00b_cbor_decode_to(T, buf) _Generic(                                                  \
    *(T *)0,                                                                                   \
    int64_t:         _n00b_cbor_decode_to_int64,                                               \
    bool:            _n00b_cbor_decode_to_bool,                                                \
    double:          _n00b_cbor_decode_to_double,                                              \
    n00b_string_t *: _n00b_cbor_decode_to_string,                                              \
    n00b_buffer_t *: _n00b_cbor_decode_to_buffer)(buf)
