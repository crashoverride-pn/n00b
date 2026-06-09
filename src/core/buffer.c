#define N00B_USE_INTERNAL_API
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/arena.h"
#include "core/static_image.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/defer.h"

// ============================================================================
// Hex map for encoding
// ============================================================================

const char n00b_hex_map_lower[16] = {
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
};

// ============================================================================
// Internal helpers
// ============================================================================

/*
 * Create a new buffer with the given byte length, using the specified
 * allocator (or runtime default if nullptr).
 */
static n00b_buffer_t *
_buffer_create(int64_t length, n00b_allocator_t *allocator)
{
    n00b_buffer_t *buf = n00b_alloc_with_opts(n00b_buffer_t, &(n00b_alloc_opts_t){.allocator = allocator});

    n00b_buffer_init(buf, .length = length, .allocator = allocator);
    return buf;
}

static bool
static_arg_is_named(const n00b_static_init_arg_t *arg, const char *name)
{
    return arg->name && strcmp(arg->name, name) == 0;
}

/*
 * Append a comma-separated `0xNN` list for the given byte run onto the
 * builder's `decls` accumulator.  Uses n00b's rich-format engine via
 * `n00b_cformat` for the per-byte hex emission — see WP-018b's
 * static_image.c refactor for the precedent that replaced the original
 * libc `snprintf("0x%02x", ...)` pattern.
 */
static void
static_image_append_bytes(n00b_static_image_builder_t *builder,
                          const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (i != 0) {
            n00b_static_image_builder_append(builder, r",");
        }
        n00b_static_image_builder_append(
            builder,
            n00b_cformat("0x[|#:02x|]", (int64_t)data[i]));
    }
}

static uint64_t
static_image_pow2_capacity(uint64_t len)
{
    if (len == 0) {
        return N00B_EMPTY_BUFFER_ALLOC;
    }

    uint64_t cap = 1;
    while (cap < len) {
        cap <<= 1;
    }
    return cap;
}

static uint64_t
static_image_hash_cstr(const char *s)
{
    uint64_t h = UINT64_C(1469598103934665603);
    while (s && *s) {
        h ^= (unsigned char)*s++;
        h *= UINT64_C(1099511628211);
    }
    return h;
}

/*
 * Build a C source-level double-quoted string literal for @p s.
 *
 * Returns an `n00b_string_t *` (GC-tracked, no manual free).  Each
 * input byte is mapped to either a 1- or 2-byte escape sequence or,
 * for non-printable bytes, to a 4-byte `\NNN` octal escape produced
 * by `n00b_cformat`.  Pieces are concatenated onto an `n00b_string_t *`
 * accumulator via `n00b_unicode_str_cat` so libc `sprintf` / `malloc`
 * stay out of the static-image build path.
 *
 * The single-byte pieces are built via `n00b_string_from_raw` with
 * plain C string literals — these emit exact byte sequences without
 * the rich-format escape interpretation that `r"..."` literals apply,
 * which matters because the output text itself contains backslash and
 * quote characters that we don't want re-escaped.
 */
static n00b_string_t *
static_image_c_string_literal(const char *s)
{
    const unsigned char *src = (const unsigned char *)(s ? s : "");

    n00b_string_t *acc = n00b_string_from_raw("\"", 1);

    const unsigned char *p;
    for (p = src; *p; p++) {
        n00b_string_t *piece;

        switch (*p) {
        case '\\':
            piece = n00b_string_from_raw("\\\\", 2);
            break;
        case '"':
            piece = n00b_string_from_raw("\\\"", 2);
            break;
        case '\n':
            piece = n00b_string_from_raw("\\n", 2);
            break;
        case '\r':
            piece = n00b_string_from_raw("\\r", 2);
            break;
        case '\t':
            piece = n00b_string_from_raw("\\t", 2);
            break;
        default:
            if (*p >= 0x20 && *p < 0x7f) {
                char one[1] = {(char)*p};
                piece = n00b_string_from_raw(one, 1);
            }
            else {
                // Octal escape `\NNN`.  Build via plain raw bytes so
                // the leading backslash isn't reinterpreted by rich
                // formatting.  Format spec `03o` gives zero-padded
                // width-3 octal, which we then prepend a literal `\`
                // onto.
                n00b_string_t *digits = n00b_cformat("[|#:03o|]",
                                                    (int64_t)*p);
                piece = n00b_unicode_str_cat(
                    n00b_string_from_raw("\\", 1), digits);
            }
            break;
        }

        acc = n00b_unicode_str_cat(acc, piece);
    }

    return n00b_unicode_str_cat(acc, n00b_string_from_raw("\"", 1));
}

static int
hex_digit_value(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/*
 * Decode the hex string carried on @p arg into a freshly allocated
 * byte array.  Returns the decoded bytes as a GC-tracked
 * `unsigned char *` (callers must not call libc `free` on it) and
 * writes the byte count to @p out_len.  Failure modes set @p builder
 * status and message via `n00b_static_image_builder_fail`.
 */
static n00b_static_image_status_t
decode_hex_arg(n00b_static_image_builder_t *builder,
               const n00b_static_init_arg_t *arg,
               unsigned char **out,
               uint64_t *out_len)
{
    if (arg->bytes.len % 2 != 0) {
        return n00b_static_image_builder_fail(
            builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
            r"buffer .hex static initializer requires an even number of hex digits");
    }

    uint64_t len = arg->bytes.len / 2;
    // n00b_alloc_array_with_opts gives zero-filled GC-tracked storage;
    // when len == 0 we still allocate a 1-byte placeholder so the
    // returned pointer is never null (matches the original calloc
    // behaviour that callers rely on as a "valid empty payload"
    // sentinel).
    unsigned char *data = n00b_alloc_array_with_opts(
        unsigned char,
        (int64_t)(len ? len : 1),
        &(n00b_alloc_opts_t){});

    const unsigned char *src = arg->bytes.data;
    for (uint64_t i = 0; i < len; i++) {
        int hi = hex_digit_value(src[i * 2]);
        int lo = hex_digit_value(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return n00b_static_image_builder_fail(
                builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
                r"buffer .hex static initializer contains a non-hex digit");
        }
        data[i] = (unsigned char)((hi << 4) | lo);
    }

    *out     = data;
    *out_len = len;
    return N00B_STATIC_IMAGE_OK;
}

n00b_static_image_status_t
n00b_buffer_static_init(n00b_static_image_builder_t *builder)
{
    const n00b_static_image_request_t *request = builder->request;

    if (!request->symbol_prefix || !request->symbol_prefix[0]) {
        return n00b_static_image_builder_fail(
            builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
            r"n00b_buffer_t static initializer requires a symbol prefix");
    }

    if ((request->object_flags & N00B_STATIC_OBJECT_F_READONLY) == 0) {
        return n00b_static_image_builder_fail(
            builder, N00B_STATIC_IMAGE_ERR_UNSUPPORTED_POLICY,
            r"n00b_buffer_t static images are currently readonly only");
    }

    const unsigned char *raw = nullptr;
    uint64_t raw_len = 0;
    unsigned char *hex_decoded = nullptr;
    uint64_t hex_decoded_len = 0;
    bool have_raw = false;
    bool have_hex = false;
    bool have_length = false;
    uint64_t length = 0;
    // WP-011 Phase 3c.iii (D-066 buffer realization): dict-key-position
    // buffer literals carry a precomputed XXH3_128bits of the buffer's
    // payload bytes — the same value `n00b_buffer_hash` would compute
    // at runtime — split into a low/high uint64 pair on the request
    // wire (signed int64 underneath, see ncc's
    // `build_buffer_literal_helper_request` for the bit-pattern
    // reinterpretation contract).  When both halves are zero we leave
    // the obj descriptor's `.cached_hash` slot at zero so non-key
    // buffer literals stay bit-identical to pre-3c.iii behavior.
    uint64_t cached_hash_lo = 0;
    uint64_t cached_hash_hi = 0;

    for (uint64_t i = 0; i < request->arg_count; i++) {
        const n00b_static_init_arg_t *arg = &request->args[i];
        bool positional = arg->name == nullptr;

        if ((positional || static_arg_is_named(arg, "raw"))
            && arg->kind == N00B_STATIC_INIT_ARG_BYTES) {
            if (have_raw || have_hex) {
                return n00b_static_image_builder_fail(
                    builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
                    r"buffer static initializer accepts only one raw or hex payload");
            }
            have_raw = true;
            raw = arg->bytes.data;
            raw_len = arg->bytes.len;
            continue;
        }

        if (static_arg_is_named(arg, "hex")
            && arg->kind == N00B_STATIC_INIT_ARG_BYTES) {
            if (have_raw || have_hex) {
                return n00b_static_image_builder_fail(
                    builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
                    r"buffer static initializer accepts only one raw or hex payload");
            }
            n00b_static_image_status_t status = decode_hex_arg(
                builder, arg, &hex_decoded, &hex_decoded_len);
            if (status != N00B_STATIC_IMAGE_OK) {
                return status;
            }
            have_hex = true;
            raw = hex_decoded;
            raw_len = hex_decoded_len;
            continue;
        }

        if (static_arg_is_named(arg, "length")
            && arg->kind == N00B_STATIC_INIT_ARG_INT) {
            if (arg->integer < 0) {
                return n00b_static_image_builder_fail(
                    builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
                    r"buffer .length static initializer must be non-negative");
            }
            have_length = true;
            length = (uint64_t)arg->integer;
            continue;
        }

        if (static_arg_is_named(arg, "no_lock")
            && arg->kind == N00B_STATIC_INIT_ARG_BOOL) {
            continue;
        }

        // WP-011 Phase 3c.iii: dict-key-position cached_hash inputs.
        // The request wire transmits int64 (signed); we reinterpret
        // the bit pattern as uint64 here.  ncc emits both halves
        // only when the precomputed XXH3_128bits is non-zero.
        if (static_arg_is_named(arg, "cached_hash_lo")
            && arg->kind == N00B_STATIC_INIT_ARG_INT) {
            cached_hash_lo = (uint64_t)arg->integer;
            continue;
        }

        if (static_arg_is_named(arg, "cached_hash_hi")
            && arg->kind == N00B_STATIC_INIT_ARG_INT) {
            cached_hash_hi = (uint64_t)arg->integer;
            continue;
        }

        return n00b_static_image_builder_fail(
            builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
            r"unsupported n00b_buffer_t static initializer argument");
    }

    if (!have_raw && !have_hex) {
        raw_len = have_length ? length : 0;
    }
    else if (have_length && length != raw_len) {
        return n00b_static_image_builder_fail(
            builder, N00B_STATIC_IMAGE_ERR_ARGUMENT,
            r"buffer .length must match the static raw/hex payload length");
    }

    uint64_t byte_len    = raw_len;
    uint64_t alloc_len   = static_image_pow2_capacity(byte_len);
    uint64_t payload_len = alloc_len;
    // GC-tracked scratch payload — zero-filled, never manually freed.
    unsigned char *payload = n00b_alloc_array_with_opts(
        unsigned char,
        (int64_t)(payload_len ? payload_len : 1),
        &(n00b_alloc_opts_t){});
    if (raw && raw_len) {
        memcpy(payload, raw, (size_t)raw_len);
    }
    // Suppress the otherwise-unused hex_decoded warning — its lifetime
    // is owned by the GC now, and we hold a live alias via `raw`.
    (void)hex_decoded;

    // Convert C-shaped request fields into n00b_string_t * once so we
    // can flow them through n00b_cformat substitutions throughout the
    // emission.
    n00b_string_t *prefix_s     = n00b_string_from_cstr(request->symbol_prefix);
    n00b_string_t *entry_attr_s = n00b_string_from_cstr(
        request->entry_attr ? request->entry_attr : "");

    bool have_identity = request->identity_namespace
                      && request->identity_namespace[0]
                      && request->identity_object_key
                      && request->identity_object_key[0]
                      && request->identity_payload_key
                      && request->identity_payload_key[0];

    n00b_string_t *ns_lit_s  = nullptr;
    n00b_string_t *obj_lit_s = nullptr;
    n00b_string_t *pay_lit_s = nullptr;
    n00b_string_t *null_lit_s = n00b_string_from_cstr("nullptr");
    if (have_identity) {
        ns_lit_s  = static_image_c_string_literal(request->identity_namespace);
        obj_lit_s = static_image_c_string_literal(request->identity_object_key);
        pay_lit_s = static_image_c_string_literal(request->identity_payload_key);
    }

    // Identity reference expressions used in the data_desc /
    // obj_desc `.identity` slots — these are addresses of identity
    // structs when identity is configured, or the literal `nullptr`
    // otherwise.
    n00b_string_t *payload_identity_ref = have_identity
        ? n00b_cformat("&[|#|]_data_id", prefix_s)
        : null_lit_s;
    n00b_string_t *object_identity_ref = have_identity
        ? n00b_cformat("&[|#|]_obj_id", prefix_s)
        : null_lit_s;

    n00b_string_t *namespace_field = have_identity ? ns_lit_s  : null_lit_s;
    n00b_string_t *object_field    = have_identity ? obj_lit_s : null_lit_s;
    n00b_string_t *payload_field   = have_identity ? pay_lit_s : null_lit_s;

    uint64_t payload_id = static_image_hash_cstr(request->symbol_prefix)
                        ^ UINT64_C(0x7061796c6f6164);
    uint64_t object_id  = static_image_hash_cstr(request->symbol_prefix)
                        ^ UINT64_C(0x627566666572);
    int64_t  contract_version = (int64_t)N00B_STATIC_IMAGE_CONTRACT_VERSION;
    int64_t  target_endian    = (int64_t)request->target_abi.endian;
    int64_t  borrowed_flags   = (int64_t)N00B_BUF_F_BORROWED;

    n00b_static_image_builder_set_expr(
        builder, n00b_cformat("&[|#|]_obj", prefix_s));

    if (have_identity) {
        n00b_static_image_builder_append(
            builder,
            n00b_cformat(
                "static const n00b_static_identity_t [|#|]_data_id={"
                ".version=1u,"
                ".kind=N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_PAYLOAD,"
                ".namespace_id=[|#|],.object_key=[|#|]};"
                "static const n00b_static_identity_t [|#|]_obj_id={"
                ".version=1u,"
                ".kind=N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_OBJECT,"
                ".namespace_id=[|#|],.object_key=[|#|]};",
                prefix_s, ns_lit_s, pay_lit_s,
                prefix_s, ns_lit_s, obj_lit_s));
    }

    n00b_static_image_builder_append(
        builder,
        n00b_cformat("static const unsigned char [|#|]_data[]={",
                     prefix_s));
    static_image_append_bytes(builder, payload, (size_t)payload_len);

    // Emit the data_desc block, request struct, and shape arrays.  The
    // emission is split into smaller n00b_cformat chunks so each chunk
    // fits within the format engine's natural substitution width and
    // matches the WP-018b static_image.c refactor style.
    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "};"
            "static const n00b_static_object_desc_t [|#|]_data_desc={"
            ".start=(const void*)[|#|]_data,"
            ".len=(uint64_t)sizeof([|#|]_data),"
            ".tinfo=0,.scan_kind=N00B_GC_SCAN_KIND_NONE,"
            ".scan_cb=nullptr,.scan_user=nullptr,"
            ".object_id=[|#|]ULL,.file=__FILE__,"
            ".identity=[|#|],"
            ".flags=N00B_STATIC_OBJECT_F_READONLY};"
            "static const n00b_static_object_desc_t * const "
            "[|#|]_data_entry [|#|]=&[|#|]_data_desc;",
            prefix_s, prefix_s, prefix_s,
            (int64_t)payload_id,
            payload_identity_ref,
            prefix_s, entry_attr_s, prefix_s));

    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "static const n00b_static_image_request_t [|#|]_request={"
            ".version=[|#|],"
            ".type_hash=[|#|]ULL,.type_name=\"n00b_buffer_t\","
            ".symbol_prefix=\"[|#|]\",.entry_attr=\"\","
            ".payload_kind=N00B_STATIC_IMAGE_PAYLOAD_BYTES,"
            ".payload=(const void*)[|#|]_data,"
            ".payload_len=(uint64_t)[|#|]ULL,"
            ".args=nullptr,.arg_count=0,"
            ".target_abi={.version=[|#|],"
            ".pointer_bytes=(uint8_t)sizeof(void*),"
            ".size_t_bytes=(uint8_t)sizeof(size_t),.char_bits=8,"
            ".endian=[|#|]},"
            ".object_flags=N00B_STATIC_OBJECT_F_READONLY,"
            ".required_scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
            ".identity_namespace=[|#|],"
            ".identity_object_key=[|#|],"
            ".identity_payload_key=[|#|]};",
            prefix_s, contract_version,
            (int64_t)request->type_hash, prefix_s,
            prefix_s, (int64_t)byte_len,
            contract_version, target_endian,
            namespace_field, object_field, payload_field));

    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "_Static_assert((__builtin_offsetof(n00b_buffer_t,data)"
            "%sizeof(void*))==0,"
            "\"buffer data pointer must be pointer-aligned\");"
            "_Static_assert((sizeof(n00b_buffer_t)%sizeof(void*))==0,"
            "\"buffer static image object must be word-sized\");"
            "static const uint64_t [|#|]_offsets[]={"
            "__builtin_offsetof(n00b_buffer_t,data)/sizeof(void*)};"
            "static n00b_gc_struct_layout_t [|#|]_shape={"
            ".stride=(sizeof(n00b_buffer_t)/sizeof(void*)),.count=1,"
            ".offset_count=1,.offsets=[|#|]_offsets};",
            prefix_s, prefix_s, prefix_s));

    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "static const n00b_buffer_t [|#|]_obj={"
            ".data=(char*)[|#|]_data,"
            ".byte_len=[|#|]ULL,"
            ".alloc_len=[|#|]ULL,"
            ".lock=nullptr,.allocator=nullptr,.flags=[|#|],"
            ".scan_kind=N00B_GC_SCAN_KIND_NONE,"
            ".scan_cb=nullptr,.scan_user=nullptr};",
            prefix_s, prefix_s,
            (int64_t)byte_len, (int64_t)alloc_len, borrowed_flags));

    // WP-011 Phase 3c.iii: dict-key-position buffers get the
    // XXH3_128bits of their payload threaded through as a 128-bit
    // literal; the runtime probe loop in
    // `n00b_register_static_object` pre-populates the alloc range's
    // cached_hash so the first lookup short-circuits
    // `n00b_buffer_hash`.  Non-dict-key buffer call sites default both
    // halves to 0 and the slot stays zero.
    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "static const n00b_static_object_desc_t [|#|]_obj_desc={"
            ".start=(const void*)&[|#|]_obj,"
            ".len=(uint64_t)sizeof([|#|]_obj),"
            ".tinfo=[|#|]ULL,.scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
            ".scan_cb=n00b_gc_scan_cb_struct_layout,"
            ".scan_user=&[|#|]_shape,"
            ".object_id=[|#|]ULL,.file=__FILE__,"
            ".identity=[|#|],"
            ".flags=N00B_STATIC_OBJECT_F_READONLY,"
            ".cached_hash=(((n00b_uint128_t)0x[|#:016x|]ULL<<64)"
            "|(n00b_uint128_t)0x[|#:016x|]ULL)};",
            prefix_s, prefix_s, prefix_s,
            (int64_t)request->type_hash,
            prefix_s,
            (int64_t)object_id,
            object_identity_ref,
            (int64_t)cached_hash_hi,
            (int64_t)cached_hash_lo));

    n00b_static_image_builder_append(
        builder,
        n00b_cformat(
            "static const n00b_static_object_desc_t * const "
            "[|#|]_obj_entry [|#|]=&[|#|]_obj_desc;"
            "static const n00b_static_image_dependency_t [|#|]_deps[]={"
            "{.desc=&[|#|]_data_desc,"
            ".relocation_offset=__builtin_offsetof(n00b_buffer_t,data),"
            ".role=\"payload\"}};"
            "static const n00b_static_image_response_t [|#|]_response "
            "__attribute__((used))={"
            ".version=[|#|],.request=&[|#|]_request,"
            ".object_start=(const void*)&[|#|]_obj,"
            ".object_len=(uint64_t)sizeof([|#|]_obj),"
            ".scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
            ".scan_cb=n00b_gc_scan_cb_struct_layout,"
            ".scan_user=&[|#|]_shape,.dependencies=[|#|]_deps,"
            ".dependency_count=1};",
            prefix_s, entry_attr_s, prefix_s,
            prefix_s, prefix_s,
            prefix_s, contract_version, prefix_s,
            prefix_s, prefix_s,
            prefix_s, prefix_s));

    return N00B_STATIC_IMAGE_OK;
}

// ============================================================================
// Construction
// ============================================================================

void
n00b_buffer_init(n00b_buffer_t *obj) _kargs
{
    int64_t              length    = -1;
    char                *raw       = nullptr;
    n00b_string_t       *hex       = nullptr;
    char                *ptr       = nullptr;
    n00b_allocator_t    *allocator = nullptr;
    bool                 no_lock   = false;
    n00b_gc_scan_kind_t  scan_kind = N00B_GC_SCAN_KIND_NONE;
    n00b_gc_scan_cb_t    scan_cb   = nullptr;
    void                *scan_user = nullptr;
}
{
    obj->lock      = no_lock ? nullptr : n00b_data_lock_new(.allocator = allocator);
    obj->allocator = allocator;
    obj->flags     = 0;
    obj->scan_kind = scan_kind;
    obj->scan_cb   = scan_cb;
    obj->scan_user = scan_user;

    if (raw == nullptr && hex == nullptr && ptr == nullptr) {
        if (length < 0) {
            return;
        }
    }

    if (length < 0) {
        if (hex == nullptr) {
            return;
        }
        else {
            length = hex->u8_bytes >> 1;
        }
    }

    if (length == 0) {
        obj->alloc_len = N00B_EMPTY_BUFFER_ALLOC;
        obj->data      = n00b_alloc_array_with_opts(char, obj->alloc_len,
                                                    &(n00b_alloc_opts_t){
                                                        .allocator = obj->allocator,
                                                        .scan_kind = obj->scan_kind,
                                                        .scan_cb   = obj->scan_cb,
                                                        .scan_user = obj->scan_user,
                                                    });
        obj->byte_len  = 0;
        return;
    }

    if (length > 0 && ptr == nullptr) {
        int64_t alloc_len = n00b_align_closest_pow2_ceil(length);

        obj->data      = n00b_alloc_array_with_opts(char, alloc_len,
                                                    &(n00b_alloc_opts_t){
                                                        .allocator = obj->allocator,
                                                        .scan_kind = obj->scan_kind,
                                                        .scan_cb   = obj->scan_cb,
                                                        .scan_user = obj->scan_user,
                                                    });
        obj->alloc_len = alloc_len;
    }

    if (raw != nullptr) {
        if (hex != nullptr || ptr != nullptr) {
            return;
        }
        memcpy(obj->data, raw, length);
    }

    if (ptr != nullptr) {
        if (hex != nullptr) {
            return;
        }
        obj->data      = ptr;
        // .ptr transfers ownership: the buffer's free path will
        // n00b_free this pointer. Record alloc_len so resize-in-place
        // up to `length` doesn't pointlessly reallocate. Anything
        // larger than `length` still goes through the grow path. If
        // `length` is wrong (caller passed a smaller allocation),
        // grow-then-free will fault — same risk that existed before,
        // documented in the .ptr kwarg's @post.
        obj->alloc_len = length;
    }

    if (hex != nullptr) {
        uint8_t cur         = 0;
        int     valid_count = 0;

        for (size_t i = 0; i < hex->u8_bytes; i++) {
            uint8_t byte = (uint8_t)hex->data[i];

            if (byte >= '0' && byte <= '9') {
                if ((++valid_count) % 2 == 1) {
                    cur = (byte - '0') << 4;
                }
                else {
                    cur |= (byte - '0');
                    obj->data[obj->byte_len++] = cur;
                }
                continue;
            }
            if (byte >= 'a' && byte <= 'f') {
                if ((++valid_count) % 2 == 1) {
                    cur = ((byte - 'a') + 10) << 4;
                }
                else {
                    cur |= (byte - 'a') + 10;
                    obj->data[obj->byte_len++] = cur;
                }
                continue;
            }
            if (byte >= 'A' && byte <= 'F') {
                if ((++valid_count) % 2 == 1) {
                    cur = ((byte - 'A') + 10) << 4;
                }
                else {
                    cur |= (byte - 'A') + 10;
                    obj->data[obj->byte_len++] = cur;
                }
                continue;
            }
        }
    }
    else {
        obj->byte_len = length;
    }
}

// ============================================================================
// Len
// ============================================================================

n00b_size_t
n00b_buffer_len(n00b_buffer_t *buffer)
{
    return (n00b_size_t)buffer->byte_len;
}

// ============================================================================
// Resize
// ============================================================================

void
n00b_buffer_resize(n00b_buffer_t *buffer, uint64_t new_sz)
{
    defer_on();
    n00b_buffer_acquire_w(buffer);

    if ((int64_t)new_sz <= (int64_t)buffer->alloc_len) {
        buffer->byte_len = new_sz;
        Return;
    }

    uint64_t new_alloc_sz = n00b_align_closest_pow2_ceil(new_sz);
    char    *new_data = n00b_alloc_array_with_opts(char, new_alloc_sz,
                                                   &(n00b_alloc_opts_t){
                                                       .allocator = buffer->allocator,
                                                       .scan_kind = buffer->scan_kind,
                                                       .scan_cb   = buffer->scan_cb,
                                                       .scan_user = buffer->scan_user,
                                                   });

    memcpy(new_data, buffer->data, buffer->byte_len);

    if (buffer->data) {
        n00b_free(buffer->data);
    }

    buffer->data      = new_data;
    buffer->byte_len  = new_sz;
    buffer->alloc_len = new_alloc_sz;

    Return;
    defer_func_end();
}

// ============================================================================
// Add (concatenate)
// ============================================================================

n00b_buffer_t *
n00b_buffer_add(n00b_buffer_t *b1, n00b_buffer_t *b2) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!b1) {
        return b2;
    }
    if (!b2) {
        return b1;
    }

    defer_on();
    n00b_buffer_acquire_r(b1);
    n00b_buffer_acquire_r(b2);

    int64_t        l1     = n00b_max((int64_t)b1->byte_len, (int64_t)0);
    int64_t        l2     = n00b_max((int64_t)b2->byte_len, (int64_t)0);
    int64_t        lnew   = l1 + l2;
    n00b_buffer_t *result = _buffer_create(lnew, allocator);

    if (l1 > 0) {
        memcpy(result->data, b1->data, l1);
    }
    if (l2 > 0) {
        memcpy(result->data + l1, b2->data, l2);
    }

    Return result;
    defer_func_end();
}

// ============================================================================
// Concat (in-place append)
// ============================================================================

void
n00b_buffer_concat(n00b_buffer_t *dst, n00b_buffer_t *src) _kargs
{
    bool to_front = false;
}
{
    if (!dst || !src || src->byte_len == 0) {
        return;
    }

    defer_on();
    n00b_buffer_acquire_w(dst);
    n00b_buffer_acquire_r(src);

    size_t   old_len = dst->byte_len;
    uint64_t needed  = old_len + src->byte_len;

    if (needed > dst->alloc_len) {
        uint64_t new_alloc = n00b_align_closest_pow2_ceil(needed);
        char    *new_data  = n00b_alloc_array_with_opts(
            char, new_alloc,
            &(n00b_alloc_opts_t){.allocator = dst->allocator});

        if (to_front) {
            memcpy(new_data, src->data, src->byte_len);
            memcpy(new_data + src->byte_len, dst->data, old_len);
        }
        else {
            memcpy(new_data, dst->data, old_len);
            memcpy(new_data + old_len, src->data, src->byte_len);
        }

        if (dst->data) {
            n00b_free(dst->data);
        }

        dst->data      = new_data;
        dst->alloc_len = new_alloc;
    }
    else if (to_front) {
        memmove(dst->data + src->byte_len, dst->data, old_len);
        memcpy(dst->data, src->data, src->byte_len);
    }
    else {
        memcpy(dst->data + old_len, src->data, src->byte_len);
    }

    dst->byte_len = needed;

    Return;
    defer_func_end();
}

// ============================================================================
// Find
// ============================================================================

n00b_option_t(int64_t) n00b_buffer_find(n00b_buffer_t *b, n00b_buffer_t *sub) _kargs
{
    n00b_option_t(size_t) start = n00b_option_set(size_t, 0);
    n00b_option_t(size_t) end   = n00b_option_none(size_t);
}
{
    size_t blen   = b->byte_len;
    size_t sublen = sub->byte_len;
    size_t s      = n00b_option_get_or_else(start, 0);
    size_t e      = n00b_option_get_or_else(end, blen);

    if (s > blen) {
        return n00b_option_none(int64_t);
    }
    if (e > blen) {
        e = blen;
    }
    if (e <= s) {
        return n00b_option_none(int64_t);
    }
    if (sublen == 0) {
        return n00b_option_set(int64_t, (int64_t)s);
    }

    char *bp   = b->data + s;
    char *endp = b->data + e - sublen;

    while (bp <= endp) {
        char *p    = bp;
        char *subp = sub->data;
        bool  hit  = true;

        for (size_t i = 0; i < sublen; i++) {
            if (*p++ != *subp++) {
                hit = false;
                break;
            }
        }
        if (hit) {
            return n00b_option_set(int64_t, (int64_t)(bp - b->data));
        }
        bp++;
    }

    return n00b_option_none(int64_t);
}

// ============================================================================
// Index get / set
// ============================================================================

n00b_result_t(uint8_t) n00b_buffer_get_index(n00b_buffer_t *b, int64_t n)
{
    defer_on();
    n00b_buffer_acquire_r(b);

    if (n < 0) {
        n += (int64_t)b->byte_len;
        if (n < 0) {
            Return n00b_result_err(uint8_t, N00B_ERR_BUFFER_INDEX_OOB);
        }
    }
    if ((uint64_t)n >= b->byte_len) {
        Return n00b_result_err(uint8_t, N00B_ERR_BUFFER_INDEX_OOB);
    }

    uint8_t result = (uint8_t)b->data[n];
    Return  n00b_result_ok(uint8_t, result);
    defer_func_end();
}

n00b_result_t(bool) n00b_buffer_set_index(n00b_buffer_t *b, int64_t n, uint8_t c)
{
    defer_on();
    n00b_buffer_acquire_w(b);

    if (n < 0) {
        n += (int64_t)b->byte_len;
        if (n < 0) {
            Return n00b_result_err(bool, N00B_ERR_BUFFER_INDEX_OOB);
        }
    }
    if ((uint64_t)n >= b->byte_len) {
        Return n00b_result_err(bool, N00B_ERR_BUFFER_INDEX_OOB);
    }

    b->data[n] = (char)c;
    Return n00b_result_ok(bool, true);
    defer_func_end();
}

// ============================================================================
// Slice get / set
// ============================================================================

n00b_buffer_t *
n00b_buffer_get_slice(n00b_buffer_t *b, int64_t start, int64_t end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    defer_on();
    n00b_buffer_acquire_r(b);

    int64_t len = (int64_t)b->byte_len;

    if (start < 0) {
        start += len;
    }
    else if (start >= len) {
        Return _buffer_create(0, allocator);
    }
    if (end < 0) {
        end += len + 1;
    }
    else if (end > len) {
        end = len;
    }
    if ((start | end) < 0 || start >= end) {
        Return _buffer_create(0, allocator);
    }

    int64_t        slice_len = end - start;
    n00b_buffer_t *result    = _buffer_create(slice_len, allocator);

    memcpy(result->data, b->data + start, slice_len);

    Return result;
    defer_func_end();
}

n00b_result_t(bool)
    n00b_buffer_set_slice(n00b_buffer_t *b, int64_t start, int64_t end) _kargs
{
    n00b_buffer_t *val = nullptr;
}
{
    defer_on();
    n00b_buffer_acquire_w(b);

    int64_t len = (int64_t)b->byte_len;

    if (start < 0) {
        start += len;
    }
    else if (start >= len) {
        Return n00b_result_err(bool, N00B_ERR_BUFFER_SLICE_OOB);
    }
    if (end < 0) {
        end += len + 1;
    }
    else if (end > len) {
        end = len;
    }
    if ((start | end) < 0 || start >= end) {
        Return n00b_result_err(bool, N00B_ERR_BUFFER_SLICE_OOB);
    }

    int64_t slice_len   = end - start;
    int64_t new_len     = (int64_t)b->byte_len - slice_len;
    int64_t replace_len = 0;

    if (val != nullptr) {
        replace_len = (int64_t)val->byte_len;
        new_len += replace_len;
    }

    if (new_len <= (int64_t)b->byte_len) {
        if (val != nullptr && val->byte_len > 0) {
            memcpy(b->data + start, val->data, replace_len);
        }
        if (end < (int64_t)b->byte_len) {
            memmove(b->data + start + replace_len, b->data + end, b->byte_len - end);
        }
    }
    else {
        char *new_buf = n00b_alloc_array_with_opts(char, new_len, &(n00b_alloc_opts_t){.allocator = b->allocator});
        if (start > 0) {
            memcpy(new_buf, b->data, start);
        }
        if (replace_len != 0) {
            memcpy(new_buf + start, val->data, replace_len);
        }
        if (end < (int64_t)b->byte_len) {
            memcpy(new_buf + start + replace_len, b->data + end, b->byte_len - end);
        }
        if (b->data) {
            n00b_free(b->data);
        }
        b->data      = new_buf;
        b->alloc_len = new_len;
    }

    b->byte_len = new_len;

    Return n00b_result_ok(bool, true);
    defer_func_end();
}

// ============================================================================
// Copy
// ============================================================================

n00b_buffer_t *
n00b_buffer_copy(n00b_buffer_t *inbuf) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    defer_on();
    n00b_buffer_acquire_r(inbuf);

    n00b_buffer_t *outbuf = _buffer_create((int64_t)inbuf->byte_len, allocator);

    memcpy(outbuf->data, inbuf->data, inbuf->byte_len);

    Return outbuf;
    defer_func_end();
}

// ============================================================================
// Raw C access
// ============================================================================

char *
n00b_buffer_to_c(n00b_buffer_t *b, int64_t *len_ptr)
{
    if (len_ptr) {
        *len_ptr = (int64_t)b->byte_len;
    }
    return b->data;
}

// ============================================================================
// To string
// ============================================================================

n00b_string_t *
n00b_buffer_to_string(n00b_buffer_t *buffer)
{
    defer_on();
    n00b_buffer_acquire_r(buffer);

    int64_t        nbytes = (int64_t)buffer->byte_len;
    n00b_string_t *result = n00b_string_from_raw(buffer->data, nbytes);

    Return result;
    defer_func_end();
}

// ============================================================================
// To hex string
// ============================================================================

n00b_string_t *
n00b_buffer_to_hex_str(n00b_buffer_t *buf)
{
    defer_on();
    n00b_buffer_acquire_r(buf);

    int64_t        hex_len = (int64_t)buf->byte_len * 2;
    n00b_string_t *result  = n00b_alloc(n00b_string_t);

    result->data = n00b_alloc_array(char, hex_len + 1);
    char *p      = result->data;

    for (size_t i = 0; i < buf->byte_len; i++) {
        uint8_t c = ((uint8_t *)buf->data)[i];
        *p++      = n00b_hex_map_lower[(c >> 4)];
        *p++      = n00b_hex_map_lower[c & 0x0f];
    }

    *p                 = '\0';
    result->codepoints = hex_len;
    result->u8_bytes   = hex_len;
    result->styling    = nullptr;

    Return result;
    defer_func_end();
}

// ============================================================================
// Join
// ============================================================================

n00b_buffer_t *
n00b_buffer_join(n00b_array_t(n00b_buffer_t *) items,
                 n00b_buffer_t *joiner) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    size_t count = items.len;

    if (count == 0) {
        return _buffer_create(0, allocator);
    }

    int64_t new_len = 0;
    int64_t jlen    = 0;

    for (size_t i = 0; i < count; i++) {
        new_len += (int64_t)items.data[i]->byte_len;
    }

    if (joiner != nullptr) {
        jlen = (int64_t)joiner->byte_len;
        new_len += jlen * ((int64_t)count - 1);
    }

    n00b_buffer_t *result = _buffer_create(new_len, allocator);
    char          *p      = result->data;

    int64_t clen = (int64_t)items.data[0]->byte_len;
    memcpy(p, items.data[0]->data, clen);

    for (size_t i = 1; i < count; i++) {
        p += clen;
        if (jlen > 0) {
            memcpy(p, joiner->data, jlen);
            p += jlen;
        }
        clen = (int64_t)items.data[i]->byte_len;
        memcpy(p, items.data[i]->data, clen);
    }

    return result;
}

// ============================================================================
// From codepoint
// ============================================================================

n00b_buffer_t *
n00b_buffer_from_codepoint(n00b_codepoint_t cp) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    uint8_t tmp[4];
    int     nbytes = n00b_utf8_encode_codepoint(cp, tmp);

    if (nbytes <= 0) {
        return _buffer_create(0, allocator);
    }

    n00b_buffer_t *result = _buffer_create(nbytes, allocator);
    memcpy(result->data, tmp, nbytes);

    return result;
}

// ============================================================================
// Free
// ============================================================================

void
n00b_buffer_free(n00b_buffer_t *buf)
{
    if (!buf) {
        return;
    }

    if (buf->data) {
        if (buf->flags & N00B_BUF_F_MMAP) {
#ifndef _WIN32
            munmap(buf->data, buf->byte_len);
#endif
        }
        else if (buf->flags & N00B_BUF_F_BORROWED) {
            // Borrowed pointer — owner frees, we don't touch it.
        }
        else {
            n00b_free(buf->data);
        }
    }

    buf->data      = nullptr;
    buf->byte_len  = 0;
    buf->alloc_len = 0;
    buf->flags     = 0;
    buf->lock      = nullptr;
}
