#include "text/unicode/casemap.h"
#include "text/unicode/encoding.h"
#include "text/unicode/normalization.h"
#include "text/unicode/properties.h"
#include "internal/text/unicode/raw.h"
#include "core/alloc.h"
#include "core/thread.h"
#include "internal/text/unicode/tables.h"
#include <string.h>

// External generated tables
extern const uint32_t n00b_unicode_simple_upper_index[][2];
extern const uint32_t n00b_unicode_simple_upper_index_len;
extern const uint32_t n00b_unicode_simple_upper_data[];

extern const uint32_t n00b_unicode_simple_lower_index[][2];
extern const uint32_t n00b_unicode_simple_lower_index_len;
extern const uint32_t n00b_unicode_simple_lower_data[];

extern const uint32_t n00b_unicode_simple_title_index[][2];
extern const uint32_t n00b_unicode_simple_title_index_len;
extern const uint32_t n00b_unicode_simple_title_data[];

extern const uint32_t n00b_unicode_full_upper_index[][2];
extern const uint32_t n00b_unicode_full_upper_index_len;
extern const uint32_t n00b_unicode_full_upper_data[];

extern const uint32_t n00b_unicode_full_lower_index[][2];
extern const uint32_t n00b_unicode_full_lower_index_len;
extern const uint32_t n00b_unicode_full_lower_data[];

extern const uint32_t n00b_unicode_full_title_index[][2];
extern const uint32_t n00b_unicode_full_title_index_len;
extern const uint32_t n00b_unicode_full_title_data[];

extern const uint32_t n00b_unicode_casefold_simple_index[][2];
extern const uint32_t n00b_unicode_casefold_simple_index_len;
extern const uint32_t n00b_unicode_casefold_simple_data[];

extern const uint32_t n00b_unicode_casefold_full_index[][2];
extern const uint32_t n00b_unicode_casefold_full_index_len;
extern const uint32_t n00b_unicode_casefold_full_data[];

// ---------------------------------------------------------------------------
// Simple per-codepoint case mapping
// ---------------------------------------------------------------------------

static n00b_codepoint_t
simple_map(n00b_codepoint_t cp,
           const uint32_t   index[][2],
           uint32_t         index_len,
           const uint32_t  *data)
{
    const uint32_t *entry = n00b_unicode_sparse_lookup(index, index_len, data, cp);
    if (entry && entry[0] >= 1) {
        return entry[1];
    }
    return cp;
}

n00b_codepoint_t
n00b_unicode_toupper_cp(n00b_codepoint_t cp)
{
    return simple_map(cp,
                      n00b_unicode_simple_upper_index,
                      n00b_unicode_simple_upper_index_len,
                      n00b_unicode_simple_upper_data);
}

n00b_codepoint_t
n00b_unicode_tolower_cp(n00b_codepoint_t cp)
{
    return simple_map(cp,
                      n00b_unicode_simple_lower_index,
                      n00b_unicode_simple_lower_index_len,
                      n00b_unicode_simple_lower_data);
}

n00b_codepoint_t
n00b_unicode_totitle_cp(n00b_codepoint_t cp)
{
    return simple_map(cp,
                      n00b_unicode_simple_title_index,
                      n00b_unicode_simple_title_index_len,
                      n00b_unicode_simple_title_data);
}

n00b_codepoint_t
n00b_unicode_casefold_cp(n00b_codepoint_t cp)
{
    return simple_map(cp,
                      n00b_unicode_casefold_simple_index,
                      n00b_unicode_casefold_simple_index_len,
                      n00b_unicode_casefold_simple_data);
}

// ---------------------------------------------------------------------------
// Full string-level case mapping
// ---------------------------------------------------------------------------

// Helper: apply a full mapping to a single codepoint, writing UTF-8 to buf.
// Returns bytes written.
static uint32_t
full_map_cp(n00b_codepoint_t cp,
            const uint32_t   index[][2],
            uint32_t         index_len,
            const uint32_t  *data,
            const uint32_t   simple_index[][2],
            uint32_t         simple_index_len,
            const uint32_t  *simple_data,
            char            *buf)
{
    // Try full mapping first
    const uint32_t *entry = n00b_unicode_sparse_lookup(index, index_len, data, cp);
    if (entry) {
        uint32_t count = entry[0];
        uint32_t pos   = 0;
        for (uint32_t i = 0; i < count; i++) {
            pos += n00b_unicode_utf8_encode(entry[1 + i], buf + pos);
        }
        return pos;
    }

    // Fall back to simple mapping
    n00b_codepoint_t mapped = simple_map(cp,
                                         simple_index,
                                         simple_index_len,
                                         simple_data);
    return n00b_unicode_utf8_encode(mapped, buf);
}

static n00b_string_t *
full_case_map(n00b_allocator_t *allocator,
              const char       *data,
              int64_t           len,
              const uint32_t    full_index[][2],
              uint32_t          full_index_len,
              const uint32_t   *full_data,
              const uint32_t    simple_index[][2],
              uint32_t          simple_index_len,
              const uint32_t   *simple_data)
{
    // Worst case: each codepoint maps to 3 codepoints of 4 bytes each.
    // `out` is per-call scratch copied into the result by n00b_string_from_raw;
    // allocate from the ambient allocator and let it reclaim (see
    // n00b_unicode_casefold_raw for why we no longer use a per-thread scratch
    // pool + explicit n00b_free -- it cross-pooled and corrupted free lists).
    char    *out      = n00b_alloc_array(char, (size_t)len * 12 + 1);
    uint32_t out_pos  = 0;
    uint32_t pos      = 0;

    while (pos < (uint32_t)len) {
        int32_t cp = n00b_unicode_utf8_decode(data, (uint32_t)len, &pos);
        if (cp < 0)
            break;

        char     tmp[16];
        uint32_t n = full_map_cp((n00b_codepoint_t)cp,
                                 full_index,
                                 full_index_len,
                                 full_data,
                                 simple_index,
                                 simple_index_len,
                                 simple_data,
                                 tmp);
        memcpy(out + out_pos, tmp, n);
        out_pos += n;
    }

    out[out_pos]          = '\0';
    n00b_string_t *result = n00b_string_from_raw(out, out_pos, .allocator = allocator);
    return result;
}

n00b_string_t *
n00b_unicode_toupper_raw(n00b_allocator_t *allocator,
                         const char       *data,
                         int64_t           len,
                         const char       *locale)
{
    (void)locale; // locale-specific not yet implemented
    return full_case_map(allocator,
                         data,
                         len,
                         n00b_unicode_full_upper_index,
                         n00b_unicode_full_upper_index_len,
                         n00b_unicode_full_upper_data,
                         n00b_unicode_simple_upper_index,
                         n00b_unicode_simple_upper_index_len,
                         n00b_unicode_simple_upper_data);
}

n00b_string_t *
n00b_unicode_toupper(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    const char       *locale    = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_toupper_raw(allocator, s->data, s->u8_bytes, locale);
}

n00b_string_t *
n00b_unicode_tolower_raw(n00b_allocator_t *allocator,
                         const char       *data,
                         int64_t           len,
                         const char       *locale)
{
    (void)locale;
    return full_case_map(allocator,
                         data,
                         len,
                         n00b_unicode_full_lower_index,
                         n00b_unicode_full_lower_index_len,
                         n00b_unicode_full_lower_data,
                         n00b_unicode_simple_lower_index,
                         n00b_unicode_simple_lower_index_len,
                         n00b_unicode_simple_lower_data);
}

n00b_string_t *
n00b_unicode_tolower(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    const char       *locale    = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_tolower_raw(allocator, s->data, s->u8_bytes, locale);
}

n00b_string_t *
n00b_unicode_totitle_raw(n00b_allocator_t *allocator,
                         const char       *data,
                         int64_t           len,
                         const char       *locale)
{
    (void)locale;
    // Simple titlecase: uppercase first cased letter of each word,
    // lowercase the rest. Word boundaries at whitespace.
    // `out` is per-call scratch copied into the result; allocate from the
    // ambient allocator and let it reclaim (see n00b_unicode_casefold_raw).
    char    *out      = n00b_alloc_array(char, (size_t)len * 12 + 1);
    uint32_t out_pos  = 0;
    uint32_t pos      = 0;
    bool     at_start = true;

    while (pos < (uint32_t)len) {
        int32_t cp = n00b_unicode_utf8_decode(data, (uint32_t)len, &pos);
        if (cp < 0)
            break;

        n00b_codepoint_t mapped;
        if (at_start) {
            mapped               = n00b_unicode_totitle_cp((n00b_codepoint_t)cp);
            // Check if this is a cased character
            n00b_unicode_gc_t gc = n00b_unicode_general_category((n00b_codepoint_t)cp);
            if (gc == N00B_UNICODE_GC_LU || gc == N00B_UNICODE_GC_LL
                || gc == N00B_UNICODE_GC_LT) {
                at_start = false;
            }
        }
        else {
            mapped = n00b_unicode_tolower_cp((n00b_codepoint_t)cp);
        }

        // Check for word boundary (whitespace resets)
        n00b_unicode_gc_t gc = n00b_unicode_general_category((n00b_codepoint_t)cp);
        if (gc == N00B_UNICODE_GC_ZS || (n00b_codepoint_t)cp == ' '
            || (n00b_codepoint_t)cp == '\t' || (n00b_codepoint_t)cp == '\n'
            || (n00b_codepoint_t)cp == '\r') {
            at_start = true;
            mapped   = (n00b_codepoint_t)cp; // don't case-map whitespace
        }

        out_pos += n00b_unicode_utf8_encode(mapped, out + out_pos);
    }

    out[out_pos]          = '\0';
    n00b_string_t *result = n00b_string_from_raw(out, out_pos, .allocator = allocator);
    return result;
}

n00b_string_t *
n00b_unicode_totitle(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    const char       *locale    = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_totitle_raw(allocator, s->data, s->u8_bytes, locale);
}

// Fold `data` into `out` (full case fold, simple-map fallback) and return the
// folded byte length.  When `out` is nullptr, only measures: encodes into a
// local temp so the length accounting is identical to the writing pass.
static uint32_t
casefold_fold(const char *data, int64_t len, char *out)
{
    uint32_t out_pos = 0;
    uint32_t pos     = 0;
    char     tmp[4];

    while (pos < (uint32_t)len) {
        int32_t cp = n00b_unicode_utf8_decode(data, (uint32_t)len, &pos);
        if (cp < 0)
            break;

        // Try full case fold
        const uint32_t *entry = n00b_unicode_sparse_lookup(n00b_unicode_casefold_full_index,
                                                           n00b_unicode_casefold_full_index_len,
                                                           n00b_unicode_casefold_full_data,
                                                           (n00b_codepoint_t)cp);

        if (entry) {
            uint32_t count = entry[0];
            for (uint32_t i = 0; i < count; i++) {
                out_pos += n00b_unicode_utf8_encode(entry[1 + i],
                                                    out ? out + out_pos : tmp);
            }
        }
        else {
            n00b_codepoint_t mapped = simple_map((n00b_codepoint_t)cp,
                                                 n00b_unicode_casefold_simple_index,
                                                 n00b_unicode_casefold_simple_index_len,
                                                 n00b_unicode_casefold_simple_data);
            out_pos += n00b_unicode_utf8_encode(mapped,
                                                out ? out + out_pos : tmp);
        }
    }

    return out_pos;
}

n00b_string_t *
n00b_unicode_casefold_raw(n00b_allocator_t *allocator, const char *data, int64_t len)
{
    // ASCII fast path: no ASCII codepoint has a multi-codepoint full fold
    // (the only C+F entries below 0x80 are 'A'-'Z' -> 'a'-'z', 1:1), so the
    // folded string is byte-for-byte the input with A-Z lowered.  Build the
    // result string directly and fold in place on its private copy -- no
    // scratch buffer at all.  Search-token workloads (rocs ingest) are
    // overwhelmingly ASCII; the previous always-taken 12x worst-case scratch
    // per call showed up as 17% of samples inside mmap(2) (#214).
    bool ascii     = true;
    bool has_upper = false;

    for (int64_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c >= 0x80) {
            ascii = false;
            break;
        }
        has_upper |= (c >= 'A' && c <= 'Z');
    }

    if (ascii) {
        n00b_string_t *result = n00b_string_from_raw(data, len, .allocator = allocator);
        if (has_upper) {
            for (int64_t i = 0; i < len; i++) {
                char c = result->data[i];
                if (c >= 'A' && c <= 'Z') {
                    result->data[i] = c + ('a' - 'A');
                }
            }
        }
        return result;
    }

    // Non-ASCII: two passes -- measure the exact folded length, then fold
    // into an exact-size buffer.  The second decode pass is cheaper than the
    // page churn of the former 12x worst-case allocation.
    //
    // `out` is a throwaway fold buffer, copied into the result by
    // n00b_string_from_raw.  Allocate it from the ambient (current/default)
    // allocator and let that allocator reclaim it -- the rocs ingest path sets
    // a per-record scratch pool that is torn down wholesale, and other callers
    // get the GC arena which collects.  Do NOT route it through the per-thread
    // n00b_thread_scratch_pool() + explicit n00b_free: that pool's identity is
    // not stable across a thread's lifetime, and the explicit free cross-pooled
    // (freed to a different n00b_thread_scratch pool than it was allocated
    // from), corrupting the target pool's free list -> crayon-gw crash-loop.
    uint32_t out_len = casefold_fold(data, len, nullptr);
    char    *out     = n00b_alloc_array(char, (size_t)out_len + 1);

    casefold_fold(data, len, out);
    out[out_len] = '\0';

    return n00b_string_from_raw(out, out_len, .allocator = allocator);
}

n00b_string_t *
n00b_unicode_casefold(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_casefold_raw(allocator, s->data, s->u8_bytes);
}

int
n00b_unicode_casecmp_raw(const char *a, int64_t a_len, const char *b, int64_t b_len)
{
    n00b_string_t *fa = n00b_unicode_casefold_raw(nullptr, a, a_len);
    n00b_string_t *fb = n00b_unicode_casefold_raw(nullptr, b, b_len);

    // NFD for canonical equivalence
    n00b_string_t *na = n00b_unicode_nfd_raw(nullptr, fa->data, fa->u8_bytes);
    n00b_string_t *nb = n00b_unicode_nfd_raw(nullptr, fb->data, fb->u8_bytes);

    int64_t min_len = na->u8_bytes < nb->u8_bytes ? na->u8_bytes : nb->u8_bytes;
    int     result  = memcmp(na->data, nb->data, (size_t)min_len);
    if (result == 0) {
        if (na->u8_bytes < nb->u8_bytes)
            result = -1;
        else if (na->u8_bytes > nb->u8_bytes)
            result = 1;
    }

    return result;
}

int
n00b_unicode_casecmp(n00b_string_t *a, n00b_string_t *b)
{
    return n00b_unicode_casecmp_raw(a->data, a->u8_bytes, b->data, b->u8_bytes);
}
