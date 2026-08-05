/*
 * http_compression.c — Content-Encoding decompression for the
 * n00b HTTP client (Phase 6 chunk 8).
 *
 * gzip + deflate are statically linked against libz.  brotli + zstd
 * are dlopen'd opportunistically; if their shared libraries aren't
 * present, the corresponding Content-Encoding values aren't
 * advertised in the Accept-Encoding header.
 *
 * Layout:
 *   §1   libz-backed gzip + deflate
 *   §2   dlopen'd brotli
 *   §3   dlopen'd zstd
 *   §4   Capability probe + Accept-Encoding header derivation
 *   §5   Public dispatch (`n00b_http_decompress`)
 */

#define N00B_USE_INTERNAL_API
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef _WIN32
#include "core/platform.h"
#else
#include <dlfcn.h>
#endif
#include <stdatomic.h>

#include <zlib.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "internal/net/http/http_compression.h"
#include "internal/net/http/http_url.h"  /* for N00B_HTTP_ERR_* */

/* ----------------------------------------------------------------- */
/* Helpers                                                           */
/* ----------------------------------------------------------------- */

#ifdef _WIN32
static void *
n00b_http_dlopen(const char *path)
{
    return (void *)LoadLibraryA(path);
}

static void *
n00b_http_dlsym(void *handle, const char *name)
{
    return (void *)GetProcAddress((HMODULE)handle, name);
}

static void
n00b_http_dlclose(void *handle)
{
    (void)FreeLibrary((HMODULE)handle);
}
#else
static void *
n00b_http_dlopen(const char *path)
{
    return dlopen(path, RTLD_LAZY | RTLD_LOCAL);
}

static void *
n00b_http_dlsym(void *handle, const char *name)
{
    return dlsym(handle, name);
}

static void
n00b_http_dlclose(void *handle)
{
    (void)dlclose(handle);
}
#endif

static n00b_allocator_t *
default_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;
}

static n00b_buffer_t *
buffer_with_data(const uint8_t *data, size_t len, n00b_allocator_t *a)
{
    return n00b_buffer_from_bytes((char *)data, (int64_t)len,
                                  .allocator = a);
}

/* ===========================================================================
 * §1   gzip + deflate (libz)
 *
 * `inflate()` driven by zlib's standard "feed input, drain output"
 * loop.  We grow the output buffer geometrically; the @p max_size
 * cap defuses zip-bombs.
 * =========================================================================== */

static n00b_result_t(n00b_buffer_t *)
inflate_buffer(n00b_buffer_t    *src,
               int               window_bits,
               size_t            max_size,
               n00b_allocator_t *a)
{
    if (!src) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_NULL_ARG);
    }
    z_stream zs = {0};
    if (inflateInit2(&zs, window_bits) != Z_OK) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    zs.next_in  = (Bytef *)src->data;
    zs.avail_in = (uInt)src->byte_len;

    size_t   cap = (src->byte_len < 4096 ? 4096 : src->byte_len * 2);
    if (cap > max_size) cap = max_size;
    uint8_t *out = n00b_alloc_array(uint8_t, cap, .allocator = a);
    size_t   off = 0;

    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        if (off >= cap) {
            size_t new_cap = cap * 2;
            if (new_cap > max_size) new_cap = max_size;
            if (new_cap == cap) {
                inflateEnd(&zs);
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_HTTP_ERR_BAD_RESPONSE);
            }
            uint8_t *grow = n00b_alloc_array(uint8_t, new_cap,
                                              .allocator = a);
            memcpy(grow, out, off);
            out = grow;
            cap = new_cap;
        }
        zs.next_out  = out + off;
        zs.avail_out = (uInt)(cap - off);
        rc = inflate(&zs, Z_NO_FLUSH);
        size_t produced = (size_t)((cap - off) - zs.avail_out);
        off += produced;
        if (rc == Z_OK || rc == Z_STREAM_END || rc == Z_BUF_ERROR) {
            /* Z_BUF_ERROR with no progress + no input means truncated
             * input; check the loop guard. */
            if (rc == Z_BUF_ERROR && produced == 0 && zs.avail_in == 0) {
                inflateEnd(&zs);
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_HTTP_ERR_BAD_RESPONSE);
            }
            continue;
        }
        /* Any other return is a hard error. */
        inflateEnd(&zs);
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    inflateEnd(&zs);
    return n00b_result_ok(n00b_buffer_t *,
                          buffer_with_data(out, off, a));
}

static n00b_result_t(n00b_buffer_t *)
decode_gzip(n00b_buffer_t *src, size_t max_size, n00b_allocator_t *a)
{
    /* MAX_WBITS + 16 — gzip wrapper. */
    return inflate_buffer(src, MAX_WBITS + 16, max_size, a);
}

static n00b_result_t(n00b_buffer_t *)
decode_deflate(n00b_buffer_t *src, size_t max_size, n00b_allocator_t *a)
{
    /* RFC 7230 § 4.2.2: "deflate" is zlib-wrapped, but real-world
     * servers occasionally send raw deflate.  Try zlib first; fall
     * back to raw on failure. */
    auto r = inflate_buffer(src, MAX_WBITS, max_size, a);
    if (n00b_result_is_ok(r)) return r;
    return inflate_buffer(src, -MAX_WBITS, max_size, a);
}

/* ===========================================================================
 * §2   Brotli (dlopen'd)
 *
 * libbrotlidec exposes a streaming decoder API.  We carry just the
 * function pointers we need, populated on first use.
 * =========================================================================== */

typedef struct BrotliDecoderStateStruct BrotliDecoderState;
typedef enum {
    BROTLI_DECODER_RESULT_ERROR        = 0,
    BROTLI_DECODER_RESULT_SUCCESS      = 1,
    BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT  = 2,
    BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3,
} BrotliDecoderResult_e;

typedef BrotliDecoderState *(*brotli_create_fn)(void *(*alloc)(void *, size_t),
                                                 void  (*free)(void *, void *),
                                                 void  *opaque);
typedef BrotliDecoderResult_e (*brotli_decompress_fn)(
    BrotliDecoderState *,
    size_t *available_in, const uint8_t **next_in,
    size_t *available_out, uint8_t **next_out,
    size_t *total_out);
typedef void (*brotli_destroy_fn)(BrotliDecoderState *);

typedef struct {
    void                *handle;
    brotli_create_fn     create;
    brotli_decompress_fn decompress;
    brotli_destroy_fn    destroy;
} brotli_api_t;

static atomic_int   g_brotli_state = 0;   /* 0 = unprobed, 1 = ok, 2 = absent */
static brotli_api_t g_brotli;

static bool
brotli_probe(void)
{
    int s = atomic_load(&g_brotli_state);
    if (s != 0) return s == 1;

    static const char *candidates[] = {
#ifdef _WIN32
        "brotlidec.dll",
        "libbrotlidec.dll",
#else
        "libbrotlidec.so.1",
        "libbrotlidec.dylib",
        "libbrotlidec.so",
#endif
    };
    void *h = nullptr;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(*candidates); i++) {
        h = n00b_http_dlopen(candidates[i]);
        if (h) break;
    }
    if (!h) {
        atomic_store(&g_brotli_state, 2);
        return false;
    }
    brotli_api_t a = {
        .handle     = h,
        .create     = (brotli_create_fn)n00b_http_dlsym(
            h, "BrotliDecoderCreateInstance"),
        .decompress = (brotli_decompress_fn)n00b_http_dlsym(
            h, "BrotliDecoderDecompressStream"),
        .destroy    = (brotli_destroy_fn)n00b_http_dlsym(
            h, "BrotliDecoderDestroyInstance"),
    };
    if (!a.create || !a.decompress || !a.destroy) {
        n00b_http_dlclose(h);
        atomic_store(&g_brotli_state, 2);
        return false;
    }
    g_brotli = a;
    atomic_store(&g_brotli_state, 1);
    return true;
}

static n00b_result_t(n00b_buffer_t *)
decode_brotli(n00b_buffer_t *src, size_t max_size, n00b_allocator_t *a)
{
    if (!brotli_probe()) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    BrotliDecoderState *st = g_brotli.create(nullptr, nullptr, nullptr);
    if (!st) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }

    size_t   cap = (src->byte_len < 4096 ? 4096 : src->byte_len * 2);
    if (cap > max_size) cap = max_size;
    uint8_t *out = n00b_alloc_array(uint8_t, cap, .allocator = a);
    size_t   off = 0;

    size_t          avail_in = (size_t)src->byte_len;
    const uint8_t  *next_in  = (const uint8_t *)src->data;
    size_t          total_out;

    while (true) {
        if (off >= cap) {
            size_t new_cap = cap * 2;
            if (new_cap > max_size) new_cap = max_size;
            if (new_cap == cap) {
                g_brotli.destroy(st);
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_HTTP_ERR_BAD_RESPONSE);
            }
            uint8_t *grow = n00b_alloc_array(uint8_t, new_cap,
                                              .allocator = a);
            memcpy(grow, out, off);
            out = grow;
            cap = new_cap;
        }
        size_t   avail_out = cap - off;
        uint8_t *next_out  = out + off;
        BrotliDecoderResult_e rc = g_brotli.decompress(
            st, &avail_in, &next_in, &avail_out, &next_out, &total_out);
        off = (size_t)(next_out - out);
        if (rc == BROTLI_DECODER_RESULT_SUCCESS) break;
        if (rc == BROTLI_DECODER_RESULT_ERROR) {
            g_brotli.destroy(st);
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_HTTP_ERR_BAD_RESPONSE);
        }
        /* NEEDS_MORE_INPUT here means the input is truncated. */
        if (rc == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            g_brotli.destroy(st);
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_HTTP_ERR_BAD_RESPONSE);
        }
        /* NEEDS_MORE_OUTPUT — loop will grow the buffer. */
    }
    g_brotli.destroy(st);
    return n00b_result_ok(n00b_buffer_t *,
                          buffer_with_data(out, off, a));
}

/* ===========================================================================
 * §3   zstd (dlopen'd)
 * =========================================================================== */

typedef size_t (*zstd_decompress_fn)(void *dst, size_t dstCapacity,
                                      const void *src, size_t srcSize);
typedef size_t (*zstd_get_size_fn)(const void *src, size_t srcSize);
typedef unsigned (*zstd_iserror_fn)(size_t code);

typedef struct {
    void              *handle;
    zstd_decompress_fn decompress;
    zstd_get_size_fn   get_frame_size;
    zstd_iserror_fn    is_error;
} zstd_api_t;

#define ZSTD_CONTENTSIZE_UNKNOWN ((unsigned long long)-1)
#define ZSTD_CONTENTSIZE_ERROR   ((unsigned long long)-2)

static atomic_int g_zstd_state = 0;
static zstd_api_t g_zstd;

static bool
zstd_probe(void)
{
    int s = atomic_load(&g_zstd_state);
    if (s != 0) return s == 1;

    static const char *candidates[] = {
#ifdef _WIN32
        "zstd.dll",
        "libzstd.dll",
#else
        "libzstd.so.1",
        "libzstd.dylib",
        "libzstd.so",
#endif
    };
    void *h = nullptr;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(*candidates); i++) {
        h = n00b_http_dlopen(candidates[i]);
        if (h) break;
    }
    if (!h) {
        atomic_store(&g_zstd_state, 2);
        return false;
    }
    zstd_api_t a = {
        .handle         = h,
        .decompress     = (zstd_decompress_fn)n00b_http_dlsym(
            h, "ZSTD_decompress"),
        .get_frame_size = (zstd_get_size_fn)n00b_http_dlsym(
            h, "ZSTD_getFrameContentSize"),
        .is_error       = (zstd_iserror_fn)n00b_http_dlsym(
            h, "ZSTD_isError"),
    };
    if (!a.decompress || !a.get_frame_size || !a.is_error) {
        n00b_http_dlclose(h);
        atomic_store(&g_zstd_state, 2);
        return false;
    }
    g_zstd = a;
    atomic_store(&g_zstd_state, 1);
    return true;
}

static n00b_result_t(n00b_buffer_t *)
decode_zstd(n00b_buffer_t *src, size_t max_size, n00b_allocator_t *a)
{
    if (!zstd_probe()) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    /* zstd advertises frame content size in the header — we trust
     * it but cap by max_size. */
    unsigned long long fs = (unsigned long long)g_zstd.get_frame_size(
        src->data, (size_t)src->byte_len);
    if (fs == ZSTD_CONTENTSIZE_ERROR) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    size_t cap;
    if (fs == ZSTD_CONTENTSIZE_UNKNOWN) {
        cap = (src->byte_len < 4096 ? 4096 : src->byte_len * 4);
    } else {
        cap = (size_t)fs;
    }
    if (cap > max_size) cap = max_size;
    if (cap == 0) cap = 4;

    uint8_t *out = n00b_alloc_array(uint8_t, cap, .allocator = a);
    size_t   produced = g_zstd.decompress(
        out, cap, src->data, (size_t)src->byte_len);
    if (g_zstd.is_error(produced)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    return n00b_result_ok(n00b_buffer_t *,
                          buffer_with_data(out, produced, a));
}

/* ===========================================================================
 * §4   Capability probe + Accept-Encoding header
 * =========================================================================== */

static atomic_int    g_ae_built = 0;
static n00b_string_t *g_accept_encoding;

bool
n00b_http_have_brotli(void)
{
    return brotli_probe();
}

bool
n00b_http_have_zstd(void)
{
    return zstd_probe();
}

n00b_string_t *
n00b_http_accept_encoding_header()
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    }
{
    int built = atomic_load(&g_ae_built);
    if (built == 1 && g_accept_encoding) return g_accept_encoding;

    /* g_accept_encoding is a process-stable memoized singleton, so it MUST be
     * built in the process-lifetime pool, NEVER the caller's allocator.  A
     * caller may pass a transient/reset allocator (e.g. the egress per-batch
     * `.use_gc = false` bump arena, which wax_ingest_run resets every batch);
     * caching the global there leaves it dangling into reused memory after the
     * reset, and the next request's strlen(value) walks freed bytes -> SIGSEGV.
     * The `allocator` kwarg is intentionally ignored for the cached singleton. */
    (void)allocator;
    n00b_allocator_t *a = default_pool();
    char buf[64];
    /* gzip + deflate are always present. */
    size_t off = 0;
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "gzip, deflate");
    if (n00b_http_have_brotli()) {
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, ", br");
    }
    if (n00b_http_have_zstd()) {
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, ", zstd");
    }
    g_accept_encoding = n00b_string_from_raw(buf, (int64_t)off,
                                              .allocator = a);
    atomic_store(&g_ae_built, 1);
    return g_accept_encoding;
}

void
n00b_http_compression_reset_for_test(void)
{
    atomic_store(&g_brotli_state, 0);
    atomic_store(&g_zstd_state, 0);
    atomic_store(&g_ae_built, 0);
    g_accept_encoding = nullptr;
}

/* ===========================================================================
 * §5   Public dispatch
 * =========================================================================== */

/* Body-side compress (gzip + deflate via libz).  Brotli / zstd
 * request-body compression is a follow-up. */
static n00b_result_t(n00b_buffer_t *)
deflate_buffer(n00b_buffer_t    *src,
               int               window_bits,
               int               level,
               n00b_allocator_t *a)
{
    z_stream zs = {0};
    if (deflateInit2(&zs, level, Z_DEFLATED, window_bits, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    zs.next_in  = (Bytef *)src->data;
    zs.avail_in = (uInt)src->byte_len;

    size_t   cap = (src->byte_len < 256 ? 256 : (size_t)src->byte_len);
    uint8_t *out = n00b_alloc_array(uint8_t, cap, .allocator = a);
    size_t   off = 0;
    int      rc;
    do {
        if (off >= cap) {
            size_t   new_cap = cap * 2;
            uint8_t *grow    = n00b_alloc_array(uint8_t, new_cap,
                                                 .allocator = a);
            memcpy(grow, out, off);
            out = grow;
            cap = new_cap;
        }
        zs.next_out  = out + off;
        zs.avail_out = (uInt)(cap - off);
        rc = deflate(&zs, Z_FINISH);
        off += (cap - off) - zs.avail_out;
    } while (rc == Z_OK);
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_HTTP_ERR_BAD_RESPONSE);
    }
    return n00b_result_ok(n00b_buffer_t *,
                          buffer_with_data(out, off, a));
}

n00b_result_t(n00b_buffer_t *)
n00b_http_compress(n00b_buffer_t *src, const char *encoding)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
        int               level     = -1;
    }
{
    if (!src) {
        return n00b_result_err(n00b_buffer_t *, N00B_HTTP_ERR_NULL_ARG);
    }
    n00b_allocator_t *a = allocator ? allocator : default_pool();
    if (!encoding || !*encoding
        || strcasecmp(encoding, "identity") == 0) {
        return n00b_result_ok(n00b_buffer_t *,
                              buffer_with_data(
                                  (const uint8_t *)src->data,
                                  (size_t)src->byte_len, a));
    }
    if (strcasecmp(encoding, "gzip") == 0) {
        return deflate_buffer(src, MAX_WBITS + 16, level, a);
    }
    if (strcasecmp(encoding, "deflate") == 0) {
        return deflate_buffer(src, MAX_WBITS, level, a);
    }
    return n00b_result_err(n00b_buffer_t *,
                            N00B_HTTP_ERR_BAD_RESPONSE);
}

n00b_result_t(n00b_buffer_t *)
n00b_http_decompress(n00b_buffer_t *src, const char *encoding)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
        size_t            max_size  = 64 * 1024 * 1024;
    }
{
    if (!src) {
        return n00b_result_err(n00b_buffer_t *, N00B_HTTP_ERR_NULL_ARG);
    }
    n00b_allocator_t *a = allocator ? allocator : default_pool();

    /* Empty / nullptr / "identity" → pass-through copy. */
    if (!encoding || !*encoding
        || strcasecmp(encoding, "identity") == 0) {
        return n00b_result_ok(n00b_buffer_t *,
                              buffer_with_data(
                                  (const uint8_t *)src->data,
                                  (size_t)src->byte_len, a));
    }

    if (strcasecmp(encoding, "gzip") == 0
        || strcasecmp(encoding, "x-gzip") == 0) {
        return decode_gzip(src, max_size, a);
    }
    if (strcasecmp(encoding, "deflate") == 0) {
        return decode_deflate(src, max_size, a);
    }
    if (strcasecmp(encoding, "br") == 0) {
        return decode_brotli(src, max_size, a);
    }
    if (strcasecmp(encoding, "zstd") == 0) {
        return decode_zstd(src, max_size, a);
    }
    /* Unknown encoding. */
    return n00b_result_err(n00b_buffer_t *,
                            N00B_HTTP_ERR_BAD_RESPONSE);
}
