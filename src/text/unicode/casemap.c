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
    // Worst case: each codepoint maps to 3 codepoints of 4 bytes each
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
    n00b_free(out);
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
    n00b_free(out);
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

n00b_string_t *
n00b_unicode_casefold_raw(n00b_allocator_t *allocator, const char *data, int64_t len)
{
    // `out` is a throwaway fold buffer: copied into the result by
    // n00b_string_from_raw, then freed below.  Take it from this thread's
    // persistent scratch pool (non-GC) so n00b_free actually reclaims the slot
    // -- a GC-arena scratch buffer is not reclaimed by n00b_free and just
    // churns the heap.  nullptr (pre-registration) falls back to the default.
    n00b_allocator_t *scratch = n00b_thread_scratch_pool();
    char    *out      = n00b_alloc_array(char,
                                    (size_t)len * 12 + 1,
                                    .allocator = scratch);
    uint32_t out_pos  = 0;
    uint32_t pos      = 0;

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
                out_pos += n00b_unicode_utf8_encode(entry[1 + i], out + out_pos);
            }
        }
        else {
            n00b_codepoint_t mapped = simple_map((n00b_codepoint_t)cp,
                                                 n00b_unicode_casefold_simple_index,
                                                 n00b_unicode_casefold_simple_index_len,
                                                 n00b_unicode_casefold_simple_data);
            out_pos += n00b_unicode_utf8_encode(mapped, out + out_pos);
        }
    }

    out[out_pos]          = '\0';
    n00b_string_t *result = n00b_string_from_raw(out, out_pos, .allocator = allocator);
    n00b_free(out);
    return result;
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
