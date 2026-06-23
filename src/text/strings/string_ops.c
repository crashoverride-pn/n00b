#include "text/strings/string_ops.h"
#include "text/unicode/casemap.h"
#include "text/unicode/encoding.h"
#include "text/unicode/linebreak.h"
#include "text/unicode/normalization.h"
#include "text/unicode/properties.h"
#include "text/unicode/segmentation.h"
#include "internal/text/unicode/raw.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include <string.h>
#include <assert.h>

// ---------------------------------------------------------------------------
// Concatenation
// ---------------------------------------------------------------------------

static n00b_allocator_t *
resolve_string_allocator(n00b_allocator_t *allocator)
{
    if (allocator == nullptr) {
        n00b_thread_t *self = n00b_thread_self();
        if (self != nullptr && self->record != nullptr &&
            self->string_scratch_arena != nullptr) {
            allocator = (n00b_allocator_t *)self->string_scratch_arena;
        }
    }

    n00b_ensure_allocator(allocator);
    return allocator;
}

static n00b_string_t *
alloc_string_storage(n00b_allocator_t *allocator,
                     size_t total_bytes,
                     size_t total_codepoints)
{
    allocator = resolve_string_allocator(allocator);

    n00b_string_t *result = n00b_alloc_with_opts(
        n00b_string_t,
        &(n00b_alloc_opts_t){.allocator = allocator});
    char *data = n00b_alloc_array_with_opts(
        char,
        total_bytes + 1,
        &(n00b_alloc_opts_t){.allocator = allocator, .no_scan = true});

    result->data       = data;
    result->u8_bytes   = total_bytes;
    result->codepoints = total_codepoints;
    result->styling    = nullptr;
    return result;
}

static void
add_part_totals(const n00b_unicode_str_part_t *part,
                size_t *total_bytes,
                size_t *total_codepoints)
{
    assert(part != nullptr);
    assert(part->data != nullptr || part->bytes == 0);
    assert(part->bytes <= UINT32_MAX);
    assert(*total_bytes <= UINT32_MAX - part->bytes);

    *total_bytes += part->bytes;
    if (part->codepoints >= 0) {
        *total_codepoints += (size_t)part->codepoints;
    }
    else {
        *total_codepoints +=
            (size_t)n00b_unicode_utf8_count_codepoints_raw(part->data,
                                                           (uint32_t)part->bytes);
    }
}

n00b_string_t *
n00b_unicode_str_cat_parts_raw(n00b_allocator_t *allocator,
                               const n00b_unicode_str_part_t *parts,
                               size_t count)
{
    if (parts == nullptr || count == 0) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    size_t total_bytes = 0;
    size_t total_codepoints = 0;
    for (size_t i = 0; i < count; i++) {
        add_part_totals(&parts[i], &total_bytes, &total_codepoints);
    }

    n00b_string_t *result =
        alloc_string_storage(allocator, total_bytes, total_codepoints);

    size_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        if (parts[i].bytes == 0) {
            continue;
        }
        memcpy(result->data + pos, parts[i].data, parts[i].bytes);
        pos += parts[i].bytes;
    }
    result->data[total_bytes] = '\0';
    return result;
}

n00b_string_t *
n00b_unicode_str_cat_raw(n00b_allocator_t *allocator,
                         const char       *a,
                         int64_t           a_len,
                         const char       *b,
                         int64_t           b_len)
{
    assert(a_len >= 0);
    assert(b_len >= 0);
    n00b_unicode_str_part_t parts[] = {
        {.data = a, .bytes = (size_t)a_len, .codepoints = -1},
        {.data = b, .bytes = (size_t)b_len, .codepoints = -1},
    };
    return n00b_unicode_str_cat_parts_raw(allocator, parts, 2);
}

n00b_string_t *
n00b_unicode_str_cat(n00b_string_t *a, n00b_string_t *b) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_unicode_str_part_t parts[] = {
        {.data = a->data, .bytes = a->u8_bytes, .codepoints = (int64_t)a->codepoints},
        {.data = b->data, .bytes = b->u8_bytes, .codepoints = (int64_t)b->codepoints},
    };
    return n00b_unicode_str_cat_parts_raw(allocator, parts, 2);
}

n00b_string_t *
n00b_unicode_str_cat_many(n00b_array_t(n00b_string_t *) parts) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    size_t total_bytes = 0;
    size_t total_codepoints = 0;
    for (size_t i = 0; i < parts.len; i++) {
        n00b_unicode_str_part_t part = {
            .data = parts.data[i]->data,
            .bytes = parts.data[i]->u8_bytes,
            .codepoints = (int64_t)parts.data[i]->codepoints,
        };
        add_part_totals(&part, &total_bytes, &total_codepoints);
    }

    n00b_string_t *result =
        alloc_string_storage(allocator, total_bytes, total_codepoints);
    size_t pos = 0;
    for (size_t i = 0; i < parts.len; i++) {
        size_t bytes = parts.data[i]->u8_bytes;
        if (bytes == 0) {
            continue;
        }
        memcpy(result->data + pos, parts.data[i]->data, bytes);
        pos += bytes;
    }
    result->data[total_bytes] = '\0';
    return result;
}

n00b_string_t *
n00b_unicode_str_cat_parts(const n00b_unicode_str_part_t *parts, size_t count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_unicode_str_cat_parts_raw(allocator, parts, count);
}

n00b_string_t *
n00b_unicode_str_join(n00b_string_t *sep, n00b_array_t(n00b_string_t *) parts) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    size_t total_bytes = 0;
    size_t total_codepoints = 0;
    for (size_t i = 0; i < parts.len; i++) {
        if (i > 0) {
            n00b_unicode_str_part_t sep_part = {
                .data = sep->data,
                .bytes = sep->u8_bytes,
                .codepoints = (int64_t)sep->codepoints,
            };
            add_part_totals(&sep_part, &total_bytes, &total_codepoints);
        }
        n00b_unicode_str_part_t part = {
            .data = parts.data[i]->data,
            .bytes = parts.data[i]->u8_bytes,
            .codepoints = (int64_t)parts.data[i]->codepoints,
        };
        add_part_totals(&part, &total_bytes, &total_codepoints);
    }

    n00b_string_t *result =
        alloc_string_storage(allocator, total_bytes, total_codepoints);

    size_t pos = 0;
    for (size_t i = 0; i < parts.len; i++) {
        if (i > 0) {
            if (sep->u8_bytes != 0) {
                memcpy(result->data + pos, sep->data, sep->u8_bytes);
                pos += sep->u8_bytes;
            }
        }
        if (parts.data[i]->u8_bytes != 0) {
            memcpy(result->data + pos,
                   parts.data[i]->data,
                   parts.data[i]->u8_bytes);
            pos += parts.data[i]->u8_bytes;
        }
    }
    result->data[total_bytes] = '\0';
    return result;
}

// ---------------------------------------------------------------------------
// Grapheme-aware slicing helpers
// ---------------------------------------------------------------------------

// Build a byte-offset array for grapheme boundaries.
// Returns count of grapheme clusters. offsets[i] = byte start of grapheme i.
// offsets[count] = num_bytes (sentinel).
static uint32_t
get_grapheme_offsets(const char *data, int64_t len, uint32_t **offsets_out)
{
    uint32_t  num_bytes = (uint32_t)len;
    uint32_t  cap       = num_bytes > 0 ? num_bytes + 1 : 16;
    uint32_t *offs      = n00b_alloc_array(char, cap * sizeof(uint32_t));
    uint32_t  count     = 0;

    offs[count++] = 0;

    n00b_unicode_break_iter_t *it = n00b_unicode_grapheme_iter_raw(data, len);
    int32_t                    b;
    while ((b = n00b_unicode_break_next(it)) >= 0) {
        if (count >= cap) {
            cap *= 2;
            {
                uint32_t *new_offs = n00b_alloc_array(char, cap * sizeof(uint32_t));
                memcpy(new_offs, offs, count * sizeof(uint32_t));
                n00b_free(offs);
                offs = new_offs;
            }
        }
        offs[count++] = (uint32_t)b;
    }

    // Ensure sentinel
    if (count == 0 || offs[count - 1] != num_bytes) {
        if (count >= cap) {
            cap++;
            {
                uint32_t *new_offs = n00b_alloc_array(char, cap * sizeof(uint32_t));
                memcpy(new_offs, offs, count * sizeof(uint32_t));
                n00b_free(offs);
                offs = new_offs;
            }
        }
        offs[count++] = num_bytes;
    }

    n00b_unicode_break_iter_free(it);
    *offsets_out = offs;
    return count - 1; // number of grapheme clusters
}

// Resolve negative index (Python-style: -1 = last)
static int32_t
resolve_index(int32_t idx, uint32_t n_graphemes)
{
    if (idx < 0)
        idx += (int32_t)n_graphemes;
    if (idx < 0)
        idx = 0;
    if ((uint32_t)idx > n_graphemes)
        idx = (int32_t)n_graphemes;
    return idx;
}

n00b_string_t *
n00b_unicode_str_slice_raw(n00b_allocator_t *allocator,
                           const char       *data,
                           int64_t           len,
                           int32_t           start,
                           int32_t           end)
{
    if (len == 0) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    uint32_t *offsets;
    uint32_t  n = get_grapheme_offsets(data, len, &offsets);

    start = resolve_index(start, n);
    end   = resolve_index(end, n);

    n00b_string_t *result;
    if (start >= end) {
        result = n00b_string_from_raw("", 0, .allocator = allocator);
    }
    else {
        uint32_t byte_start = offsets[start];
        uint32_t byte_end   = offsets[end];
        uint32_t slice_len  = byte_end - byte_start;
        result       = n00b_string_from_raw(data + byte_start, slice_len, .allocator = allocator);
    }

    n00b_free(offsets);
    return result;
}

n00b_string_t *
n00b_unicode_str_slice(n00b_string_t *s, int32_t start, int32_t end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_str_slice_raw(allocator, s->data, s->u8_bytes, start, end);
}

n00b_string_t *
n00b_unicode_str_grapheme_at(n00b_string_t *s, int32_t index) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    if (len == 0) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    uint32_t *offsets;
    uint32_t  n = get_grapheme_offsets(data, len, &offsets);

    index = resolve_index(index, n);

    n00b_string_t *result;
    if ((uint32_t)index >= n) {
        result = n00b_string_from_raw("", 0, .allocator = allocator);
    }
    else {
        uint32_t byte_start = offsets[index];
        uint32_t byte_end   = offsets[index + 1];
        uint32_t seg_len    = byte_end - byte_start;
        result       = n00b_string_from_raw(data + byte_start, seg_len, .allocator = allocator);
    }

    n00b_free(offsets);
    return result;
}

// ---------------------------------------------------------------------------
// Byte-level slicing
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_slice_bytes(n00b_string_t *s, uint32_t byte_start, uint32_t byte_end) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    if (byte_start > (uint32_t)len)
        byte_start = (uint32_t)len;
    if (byte_end > (uint32_t)len)
        byte_end = (uint32_t)len;
    if (byte_start >= byte_end)
        return n00b_string_from_raw("", 0, .allocator = allocator);

    uint32_t slice_len = byte_end - byte_start;
    return n00b_string_from_raw(data + byte_start, slice_len, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Search (byte-level, using memmem-style)
// ---------------------------------------------------------------------------

static const char *
find_bytes(const char *haystack, uint32_t hlen, const char *needle, uint32_t nlen)
{
    if (nlen == 0)
        return haystack;
    if (nlen > hlen)
        return nullptr;

    for (uint32_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return haystack + i;
        }
    }
    return nullptr;
}

static const char *
rfind_bytes(const char *haystack, uint32_t hlen, const char *needle, uint32_t nlen)
{
    if (nlen == 0)
        return haystack + hlen;
    if (nlen > hlen)
        return nullptr;

    for (uint32_t i = hlen - nlen;; i--) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return haystack + i;
        }
        if (i == 0)
            break;
    }
    return nullptr;
}

int32_t
n00b_unicode_str_find_raw(const char *haystack,
                          int64_t     h_len,
                          const char *needle,
                          int64_t     n_len)
{
    const char *p = find_bytes(haystack, (uint32_t)h_len, needle, (uint32_t)n_len);
    return p ? (int32_t)(p - haystack) : -1;
}

static inline n00b_string_t *
_str_search_prep(n00b_string_t *s, bool normalize, bool case_sensitive, bool strip_marks)
{
    n00b_string_t *r = s;

    if (normalize)
        r = n00b_unicode_nfc(r);
    if (strip_marks)
        r = n00b_unicode_strip_marks(r);
    if (!case_sensitive)
        r = n00b_unicode_casefold(r);

    return r;
}

n00b_option_t(int32_t)
n00b_unicode_str_find(n00b_string_t *haystack, n00b_string_t *needle) _kargs
{
    bool reverse         = false;
    bool normalize       = true;
    bool case_sensitive  = true;
    bool strip_marks     = false;
}
{
    n00b_string_t *h = _str_search_prep(haystack, normalize, case_sensitive, strip_marks);
    n00b_string_t *n = _str_search_prep(needle, normalize, case_sensitive, strip_marks);

    int32_t r;

    if (reverse) {
        r = n00b_unicode_str_rfind_raw(h->data, h->u8_bytes,
                                       n->data, n->u8_bytes);
    }
    else {
        r = n00b_unicode_str_find_raw(h->data, h->u8_bytes,
                                      n->data, n->u8_bytes);
    }

    if (r < 0)
        return n00b_option_none(int32_t);
    return n00b_option_set(int32_t, r);
}

int32_t
n00b_unicode_str_rfind_raw(const char *haystack,
                           int64_t     h_len,
                           const char *needle,
                           int64_t     n_len)
{
    const char *p = rfind_bytes(haystack, (uint32_t)h_len, needle, (uint32_t)n_len);
    return p ? (int32_t)(p - haystack) : -1;
}

bool
n00b_unicode_str_contains_raw(const char *haystack,
                              int64_t     h_len,
                              const char *needle,
                              int64_t     n_len)
{
    return n00b_unicode_str_find_raw(haystack, h_len, needle, n_len) >= 0;
}

bool
n00b_unicode_str_starts_with_raw(const char *data,
                                 int64_t     len,
                                 const char *prefix,
                                 int64_t     prefix_len)
{
    if (prefix_len > len)
        return false;
    return memcmp(data, prefix, (size_t)prefix_len) == 0;
}

bool
n00b_unicode_str_starts_with(n00b_string_t *s, n00b_string_t *prefix)
{
    return n00b_unicode_str_starts_with_raw(s->data, s->u8_bytes, prefix->data, prefix->u8_bytes);
}

bool
n00b_unicode_str_ends_with_raw(const char *data,
                               int64_t     len,
                               const char *suffix,
                               int64_t     suffix_len)
{
    if (suffix_len > len)
        return false;
    return memcmp(data + len - suffix_len, suffix, (size_t)suffix_len) == 0;
}

bool
n00b_unicode_str_ends_with(n00b_string_t *s, n00b_string_t *suffix)
{
    return n00b_unicode_str_ends_with_raw(s->data, s->u8_bytes, suffix->data, suffix->u8_bytes);
}

// ---------------------------------------------------------------------------
// Replace
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_replace_raw(n00b_allocator_t *allocator,
                             const char       *data,
                             int64_t           len,
                             const char       *old_s,
                             int64_t           old_len,
                             const char       *new_s,
                             int64_t           new_len)
{
    int32_t pos = n00b_unicode_str_find_raw(data, len, old_s, old_len);
    if (pos < 0) {
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    uint32_t result_len = (uint32_t)len - (uint32_t)old_len + (uint32_t)new_len;
    char    *buf        = n00b_alloc_array(char, result_len + 1);
    memcpy(buf, data, (uint32_t)pos);
    memcpy(buf + pos, new_s, (size_t)new_len);
    memcpy(buf + pos + new_len, data + pos + old_len, (size_t)(len - pos - old_len));
    buf[result_len] = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, result_len, .allocator = allocator);
    n00b_free(buf);
    return result;
}

n00b_string_t *
n00b_unicode_str_replace(n00b_string_t *s, n00b_string_t *old_s, n00b_string_t *new_s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_str_replace_raw(allocator,
                                        s->data,
                                        s->u8_bytes,
                                        old_s->data,
                                        old_s->u8_bytes,
                                        new_s->data,
                                        new_s->u8_bytes);
}

n00b_string_t *
n00b_unicode_str_replace_all_raw(n00b_allocator_t *allocator,
                                 const char       *data,
                                 int64_t           len,
                                 const char       *old_s,
                                 int64_t           old_len,
                                 const char       *new_s,
                                 int64_t           new_len)
{
    if (old_len == 0) {
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    // Count occurrences
    uint32_t    count     = 0;
    const char *p         = data;
    uint32_t    remaining = (uint32_t)len;
    while (remaining >= (uint32_t)old_len) {
        const char *found = find_bytes(p, remaining, old_s, (uint32_t)old_len);
        if (!found)
            break;
        count++;
        uint32_t skip = (uint32_t)(found - p) + (uint32_t)old_len;
        p += skip;
        remaining -= skip;
    }

    if (count == 0) {
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    uint32_t result_len;
    if ((uint32_t)new_len >= (uint32_t)old_len) {
        assert((uint64_t)count * ((uint64_t)new_len - (uint64_t)old_len)
               <= UINT32_MAX - (uint64_t)len);
        result_len = (uint32_t)len + count * ((uint32_t)new_len - (uint32_t)old_len);
    }
    else {
        result_len = (uint32_t)len - count * ((uint32_t)old_len - (uint32_t)new_len);
    }

    char    *buf     = n00b_alloc_array(char, result_len + 1);
    uint32_t out_pos = 0;

    p         = data;
    remaining = (uint32_t)len;
    while (remaining >= (uint32_t)old_len) {
        const char *found = find_bytes(p, remaining, old_s, (uint32_t)old_len);
        if (!found)
            break;
        uint32_t before = (uint32_t)(found - p);
        memcpy(buf + out_pos, p, before);
        out_pos += before;
        memcpy(buf + out_pos, new_s, (size_t)new_len);
        out_pos += (uint32_t)new_len;
        p         = found + old_len;
        remaining = (uint32_t)len - (uint32_t)(p - data);
    }
    // Copy remainder
    memcpy(buf + out_pos, p, remaining);
    out_pos += remaining;
    buf[out_pos] = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, out_pos, .allocator = allocator);
    n00b_free(buf);
    return result;
}

n00b_string_t *
n00b_unicode_str_replace_all(n00b_string_t *s, n00b_string_t *old_s, n00b_string_t *new_s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;
    return n00b_unicode_str_replace_all_raw(allocator,
                                            s->data,
                                            s->u8_bytes,
                                            old_s->data,
                                            old_s->u8_bytes,
                                            new_s->data,
                                            new_s->u8_bytes);
}

// ---------------------------------------------------------------------------
// Split
// ---------------------------------------------------------------------------

n00b_string_t **
n00b_unicode_str_split_raw(n00b_allocator_t *allocator,
                           const char       *data,
                           int64_t           len,
                           const char       *sep,
                           int64_t           sep_len,
                           uint32_t         *count)
{
    if (sep_len == 0) {
        // Split into individual codepoints
        int64_t num_cps = n00b_unicode_utf8_count_codepoints_raw(data, (uint32_t)len);
        if (num_cps <= 0) {
            *count = 0;
            return n00b_alloc_array(char, sizeof(n00b_string_t *));
        }
        n00b_string_t **arr = n00b_alloc_array(char, (size_t)num_cps * sizeof(n00b_string_t *));
        uint32_t        pos = 0;
        uint32_t        idx = 0;
        while (pos < (uint32_t)len) {
            uint32_t start = pos;
            n00b_unicode_utf8_decode(data, (uint32_t)len, &pos);
            uint32_t cp_len = pos - start;
            arr[idx++]      = n00b_string_from_raw(data + start, cp_len, .allocator = allocator);
        }
        *count = idx;
        return arr;
    }

    // Count splits
    uint32_t    n         = 1;
    const char *p         = data;
    uint32_t    remaining = (uint32_t)len;
    while (remaining >= (uint32_t)sep_len) {
        const char *found = find_bytes(p, remaining, sep, (uint32_t)sep_len);
        if (!found)
            break;
        n++;
        uint32_t skip = (uint32_t)(found - p) + (uint32_t)sep_len;
        p += skip;
        remaining -= skip;
    }

    n00b_string_t **arr = n00b_alloc_array(char, n * sizeof(n00b_string_t *));
    uint32_t        idx = 0;

    p         = data;
    remaining = (uint32_t)len;
    while (remaining >= (uint32_t)sep_len && idx < n - 1) {
        const char *found = find_bytes(p, remaining, sep, (uint32_t)sep_len);
        if (!found)
            break;
        uint32_t seg_len = (uint32_t)(found - p);
        arr[idx++]       = n00b_string_from_raw(p, seg_len, .allocator = allocator);
        p                = found + sep_len;
        remaining        = (uint32_t)len - (uint32_t)(p - data);
    }
    arr[idx++]  = n00b_string_from_raw(p, remaining, .allocator = allocator);
    *count      = idx;
    return arr;
}

n00b_array_t(n00b_string_t *) n00b_unicode_str_split(n00b_string_t *s, n00b_string_t *sep) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    uint32_t        count;
    n00b_string_t **raw                  = n00b_unicode_str_split_raw(allocator,
                                                                      s->data,
                                                                      s->u8_bytes,
                                                                      sep->data,
                                                                      sep->u8_bytes,
                                                                      &count);
    n00b_array_t(n00b_string_t *) result = n00b_array_checked_ptr(n00b_string_t *, count, raw);
    result.len                           = count;
    return result;
}

n00b_array_t(n00b_string_t *) n00b_unicode_str_split_words(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    // First pass: collect into a temporary malloc'd array
    uint32_t cap = 16;
    uint32_t n   = 0;

    // Store byte offset pairs (start, length) in a temp array
    uint32_t *ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));

    n00b_unicode_break_iter_t *it   = n00b_unicode_word_iter_raw(data, len);
    uint32_t                   prev = 0;
    int32_t                    b;

    while ((b = n00b_unicode_break_next(it)) >= 0) {
        if ((uint32_t)b > prev) {
            if (n >= cap) {
                cap *= 2;
                {
                    uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
                    memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
                    n00b_free(ranges);
                    ranges = new_ranges;
                }
            }
            ranges[n * 2]     = prev;
            ranges[n * 2 + 1] = (uint32_t)b - prev;
            n++;
        }
        prev = (uint32_t)b;
    }
    // Last segment
    if (prev < (uint32_t)len) {
        if (n >= cap) {
            cap++;
            {
                uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
                memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
                n00b_free(ranges);
                ranges = new_ranges;
            }
        }
        ranges[n * 2]     = prev;
        ranges[n * 2 + 1] = (uint32_t)len - prev;
        n++;
    }

    n00b_unicode_break_iter_free(it);

    // Now allocate the result array and populate
    n00b_string_t **arr = n00b_alloc_array(char, n * sizeof(n00b_string_t *));
    for (uint32_t i = 0; i < n; i++) {
        uint32_t start   = ranges[i * 2];
        uint32_t seg_len = ranges[i * 2 + 1];
        arr[i]           = n00b_string_from_raw(data + start, seg_len, .allocator = allocator);
    }

    n00b_free(ranges);

    n00b_array_t(n00b_string_t *) result = n00b_array_checked_ptr(n00b_string_t *, n, arr);
    result.len                           = n;
    return result;
}

n00b_array_t(n00b_string_t *) n00b_unicode_str_split_graphemes(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    uint32_t  cap    = 16;
    uint32_t  n      = 0;
    uint32_t *ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));

    n00b_unicode_break_iter_t *it   = n00b_unicode_grapheme_iter_raw(data, len);
    uint32_t                   prev = 0;
    int32_t                    b;

    while ((b = n00b_unicode_break_next(it)) >= 0) {
        if ((uint32_t)b > prev) {
            if (n >= cap) {
                cap *= 2;
                {
                    uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
                    memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
                    n00b_free(ranges);
                    ranges = new_ranges;
                }
            }
            ranges[n * 2]     = prev;
            ranges[n * 2 + 1] = (uint32_t)b - prev;
            n++;
        }
        prev = (uint32_t)b;
    }
    if (prev < (uint32_t)len) {
        if (n >= cap) {
            cap++;
            {
                uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
                memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
                n00b_free(ranges);
                ranges = new_ranges;
            }
        }
        ranges[n * 2]     = prev;
        ranges[n * 2 + 1] = (uint32_t)len - prev;
        n++;
    }

    n00b_unicode_break_iter_free(it);

    n00b_string_t **arr = n00b_alloc_array(char, n * sizeof(n00b_string_t *));
    for (uint32_t i = 0; i < n; i++) {
        uint32_t start   = ranges[i * 2];
        uint32_t seg_len = ranges[i * 2 + 1];
        arr[i]           = n00b_string_from_raw(data + start, seg_len, .allocator = allocator);
    }

    n00b_free(ranges);

    n00b_array_t(n00b_string_t *) result = n00b_array_checked_ptr(n00b_string_t *, n, arr);
    result.len                           = n;
    return result;
}

n00b_array_t(n00b_string_t *) n00b_unicode_str_split_lines(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    uint32_t  cap    = 16;
    uint32_t  n      = 0;
    uint32_t *ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));

    uint32_t start = 0;
    for (uint32_t i = 0; i < (uint32_t)len; i++) {
        if (data[i] == '\n' || data[i] == '\r') {
            if (n >= cap) {
                cap *= 2;
                {
                    uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
                    memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
                    n00b_free(ranges);
                    ranges = new_ranges;
                }
            }
            ranges[n * 2]     = start;
            ranges[n * 2 + 1] = i - start;
            n++;
            // Skip CRLF as one terminator
            if (data[i] == '\r' && i + 1 < (uint32_t)len && data[i + 1] == '\n') {
                i++;
            }
            start = i + 1;
        }
    }
    // Last line
    if (n >= cap) {
        cap++;
        {
            uint32_t *new_ranges = n00b_alloc_array(char, cap * 2 * sizeof(uint32_t));
            memcpy(new_ranges, ranges, n * 2 * sizeof(uint32_t));
            n00b_free(ranges);
            ranges = new_ranges;
        }
    }
    ranges[n * 2]     = start;
    ranges[n * 2 + 1] = (uint32_t)len - start;
    n++;

    n00b_string_t **arr = n00b_alloc_array(char, n * sizeof(n00b_string_t *));
    for (uint32_t i = 0; i < n; i++) {
        uint32_t seg_start = ranges[i * 2];
        uint32_t seg_len   = ranges[i * 2 + 1];
        arr[i]             = n00b_string_from_raw(data + seg_start, seg_len, .allocator = allocator);
    }

    n00b_free(ranges);

    n00b_array_t(n00b_string_t *) result = n00b_array_checked_ptr(n00b_string_t *, n, arr);
    result.len                           = n;
    return result;
}

// ---------------------------------------------------------------------------
// Trim
// ---------------------------------------------------------------------------

static bool
is_whitespace_cp(n00b_codepoint_t cp)
{
    return n00b_unicode_has_property(cp, N00B_UNICODE_PROP_WHITE_SPACE);
}

n00b_string_t *
n00b_unicode_str_trim(n00b_string_t *s) _kargs
{
    bool              left      = true;
    bool              right     = true;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    // Trim left
    uint32_t lpos = 0;
    if (left) {
        while (lpos < (uint32_t)len) {
            uint32_t save = lpos;
            int32_t  cp   = n00b_unicode_utf8_decode(data, (uint32_t)len, &lpos);
            if (cp < 0 || !is_whitespace_cp((n00b_codepoint_t)cp)) {
                lpos = save;
                break;
            }
        }
    }

    // Trim right
    uint32_t end = (uint32_t)len;
    if (right) {
        while (end > lpos) {
            uint32_t prev = end - 1;
            while (prev > lpos && ((uint8_t)data[prev] & 0xC0) == 0x80) {
                prev--;
            }
            uint32_t tmp = prev;
            int32_t  cp  = n00b_unicode_utf8_decode(data, (uint32_t)len, &tmp);
            if (cp < 0 || !is_whitespace_cp((n00b_codepoint_t)cp))
                break;
            end = prev;
        }
    }

    uint32_t result_len = end - lpos;
    return n00b_string_from_raw(data + lpos, result_len, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

int
n00b_unicode_str_cmp_raw(const char *a, int64_t a_len, const char *b, int64_t b_len)
{
    int64_t min_len = a_len < b_len ? a_len : b_len;
    int     c       = memcmp(a, b, (size_t)min_len);
    if (c != 0)
        return c;
    if (a_len < b_len)
        return -1;
    if (a_len > b_len)
        return 1;
    return 0;
}

int
n00b_unicode_str_cmp(n00b_string_t *a, n00b_string_t *b) _kargs
{
    bool normalize      = false;
    bool case_sensitive  = true;
    bool strip_marks     = false;
}
{
    if (a == b) {
        return 0;
    }
    if (!normalize && case_sensitive && !strip_marks) {
        return n00b_unicode_str_cmp_raw(a->data, a->u8_bytes, b->data, b->u8_bytes);
    }

    n00b_string_t *pa = _str_search_prep(a, normalize, case_sensitive, strip_marks);
    n00b_string_t *pb = _str_search_prep(b, normalize, case_sensitive, strip_marks);

    return n00b_unicode_str_cmp_raw(pa->data, pa->u8_bytes, pb->data, pb->u8_bytes);
}

bool
n00b_unicode_str_eq_raw(const char *a, int64_t a_len, const char *b, int64_t b_len)
{
    return a_len == b_len && memcmp(a, b, (size_t)a_len) == 0;
}

bool
n00b_unicode_str_eq(n00b_string_t *a, n00b_string_t *b) _kargs
{
    bool normalize      = false;
    bool case_sensitive  = true;
    bool strip_marks     = false;
}
{
    if (a == b) {
        return true;
    }
    if (!normalize && case_sensitive && !strip_marks) {
        return n00b_unicode_str_eq_raw(a->data, a->u8_bytes, b->data, b->u8_bytes);
    }

    n00b_string_t *pa = _str_search_prep(a, normalize, case_sensitive, strip_marks);
    n00b_string_t *pb = _str_search_prep(b, normalize, case_sensitive, strip_marks);

    return n00b_unicode_str_eq_raw(pa->data, pa->u8_bytes, pb->data, pb->u8_bytes);
}

// ---------------------------------------------------------------------------
// Width-aware padding
// ---------------------------------------------------------------------------

static void
encode_fill(n00b_codepoint_t fill_cp,
            int32_t          n,
            char           **out_buf,
            uint32_t        *out_bytes,
            uint32_t        *out_cps)
{
    if (n <= 0) {
        *out_buf      = n00b_alloc_array(char, 1);
        (*out_buf)[0] = '\0';
        *out_bytes    = 0;
        *out_cps      = 0;
        return;
    }

    char     enc[4];
    uint32_t enc_len = n00b_unicode_utf8_encode(fill_cp, enc);
    uint32_t total   = enc_len * (uint32_t)n;
    char    *buf     = n00b_alloc_array(char, total + 1);

    for (int32_t i = 0; i < n; i++) {
        memcpy(buf + i * enc_len, enc, enc_len);
    }
    buf[total] = '\0';

    *out_buf   = buf;
    *out_bytes = total;
    *out_cps   = (uint32_t)n;
}

n00b_string_t *
n00b_unicode_str_pad(n00b_string_t *s, int32_t width) _kargs
{
    int              align     = N00B_STR_ALIGN_LEFT;
    n00b_allocator_t *allocator = nullptr;
    n00b_codepoint_t  fill      = ' ';
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    int32_t cur = n00b_unicode_display_width_raw(data, len);
    if (cur >= width) {
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    int32_t fill_w = n00b_unicode_char_width(fill);
    if (fill_w <= 0)
        fill_w = 1;
    int32_t total_fill = (width - cur) / fill_w;

    if (align == N00B_STR_ALIGN_CENTER) {
        int32_t left_n  = total_fill / 2;
        int32_t right_n = total_fill - left_n;

        char    *lpad_buf, *rpad_buf;
        uint32_t lpad_bytes, lpad_cps, rpad_bytes, rpad_cps;
        encode_fill(fill, left_n, &lpad_buf, &lpad_bytes, &lpad_cps);
        encode_fill(fill, right_n, &rpad_buf, &rpad_bytes, &rpad_cps);

        n00b_unicode_str_part_t parts[] = {
            {.data = lpad_buf, .bytes = lpad_bytes, .codepoints = lpad_cps},
            {.data = data, .bytes = (size_t)len, .codepoints = (int64_t)s->codepoints},
            {.data = rpad_buf, .bytes = rpad_bytes, .codepoints = rpad_cps},
        };
        n00b_string_t *result = n00b_unicode_str_cat_parts_raw(allocator, parts, 3);

        n00b_free(lpad_buf);
        n00b_free(rpad_buf);
        return result;
    }

    char    *pad_buf;
    uint32_t pad_bytes, pad_cps;
    encode_fill(fill, total_fill, &pad_buf, &pad_bytes, &pad_cps);

    n00b_unicode_str_part_t parts[2];
    if (align == N00B_STR_ALIGN_RIGHT) {
        parts[0] = (n00b_unicode_str_part_t){
            .data = pad_buf, .bytes = pad_bytes, .codepoints = pad_cps};
        parts[1] = (n00b_unicode_str_part_t){
            .data = data, .bytes = (size_t)len, .codepoints = (int64_t)s->codepoints};
    }
    else {
        parts[0] = (n00b_unicode_str_part_t){
            .data = data, .bytes = (size_t)len, .codepoints = (int64_t)s->codepoints};
        parts[1] = (n00b_unicode_str_part_t){
            .data = pad_buf, .bytes = pad_bytes, .codepoints = pad_cps};
    }

    n00b_string_t *result = n00b_unicode_str_cat_parts_raw(allocator, parts, 2);
    n00b_free(pad_buf);
    return result;
}

n00b_string_t *
n00b_unicode_str_truncate(n00b_string_t *s, int32_t max_width) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    const char       *ellipsis  = "...";
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data         = s->data;
    int64_t     len          = s->u8_bytes;
    int64_t     ellipsis_len = (int64_t)strlen(ellipsis);

    int32_t cur = n00b_unicode_display_width_raw(data, len);
    if (cur <= max_width) {
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    int32_t ellip_w = n00b_unicode_display_width_raw(ellipsis, ellipsis_len);
    int32_t target  = max_width - ellip_w;
    if (target < 0)
        target = 0;

    // Walk codepoints, accumulate width until we exceed target
    uint32_t pos      = 0;
    int32_t  w        = 0;
    uint32_t last_pos = 0;

    while (pos < (uint32_t)len) {
        last_pos   = pos;
        int32_t cp = n00b_unicode_utf8_decode(data, (uint32_t)len, &pos);
        if (cp < 0)
            break;
        w += n00b_unicode_char_width((n00b_codepoint_t)cp);
        if (w > target) {
            pos = last_pos;
            break;
        }
    }

    return n00b_unicode_str_cat_raw(allocator, data, (int64_t)pos, ellipsis, ellipsis_len);
}

// ---------------------------------------------------------------------------
// Repeat
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_repeat(n00b_string_t *s, uint32_t count) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    if (count == 0 || len == 0) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    uint32_t total = (uint32_t)len * count;
    char    *buf   = n00b_alloc_array(char, total + 1);

    for (uint32_t i = 0; i < count; i++) {
        memcpy(buf + i * (uint32_t)len, data, (size_t)len);
    }
    buf[total] = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, total, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// ---------------------------------------------------------------------------
// Reverse (grapheme-aware)
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_reverse(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    int64_t     len  = s->u8_bytes;

    if (len == 0) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    // Get grapheme cluster boundaries
    uint32_t *offsets;
    uint32_t  n_graphemes = get_grapheme_offsets(data, len, &offsets);

    char    *buf     = n00b_alloc_array(char, (size_t)len + 1);
    uint32_t out_pos = 0;

    // Write grapheme clusters in reverse order
    for (uint32_t i = n_graphemes; i > 0; i--) {
        uint32_t start = offsets[i - 1];
        uint32_t end   = offsets[i];
        memcpy(buf + out_pos, data + start, end - start);
        out_pos += end - start;
    }
    buf[out_pos] = '\0';

    n00b_free(offsets);

    n00b_string_t *result = n00b_string_from_raw(buf, out_pos, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// ---------------------------------------------------------------------------
// Escape / Unescape
// ---------------------------------------------------------------------------

static const char hex_lower[16] __attribute__((nonstring)) = "0123456789abcdef";

static bool
is_printable_cp(n00b_codepoint_t cp)
{
    n00b_unicode_gc_t gc = n00b_unicode_general_category(cp);
    return gc != N00B_UNICODE_GC_CC && gc != N00B_UNICODE_GC_CS && gc != N00B_UNICODE_GC_CN;
}

static bool
should_escape_cp(n00b_codepoint_t cp)
{
    if (!is_printable_cp(cp)) {
        return true;
    }
    switch (cp) {
    case '"':
    case '\\':
    case '\'':
        return true;
    default:
        return false;
    }
}

n00b_string_t *
n00b_unicode_str_escape(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const char *data = s->data;
    uint32_t    len  = (uint32_t)s->u8_bytes;

    // Pass 1: count extra bytes needed for escapes.
    uint32_t extra      = 0;
    uint32_t num_escape = 0;
    uint32_t pos        = 0;

    while (pos < len) {
        uint32_t save = pos;
        int32_t  cp   = n00b_unicode_utf8_decode(data, len, &pos);
        if (cp < 0)
            break;
        if (should_escape_cp((n00b_codepoint_t)cp)) {
            num_escape++;
            // Worst case: \UHHHHHHHH = 10 bytes, original was (pos-save).
            // Named escapes = 2 bytes, \xHH = 4, \uHHHH = 6, \UHHHHHHHH = 10
            uint32_t orig_bytes = pos - save;
            uint32_t esc_bytes;
            switch (cp) {
            case '\\':
            case '"':
            case '\'':
            case '\a':
            case '\b':
            case '\e':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
            case '\v':
                esc_bytes = 2;
                break;
            default:
                if (cp <= 0x7f)
                    esc_bytes = 4;  // \xHH
                else if (cp < 0x10000)
                    esc_bytes = 6;  // \uHHHH
                else
                    esc_bytes = 10; // \UHHHHHHHH
                break;
            }
            if (esc_bytes > orig_bytes)
                extra += esc_bytes - orig_bytes;
            else
                extra -= orig_bytes - esc_bytes;
        }
    }

    if (num_escape == 0) {
        // No escapes needed; return a copy.
        return n00b_string_from_raw(data, len, .allocator = allocator);
    }

    // Pass 2: build the escaped string.
    uint32_t out_len = len + extra;
    char    *buf     = n00b_alloc_array(char, out_len + 1);
    char    *q       = buf;

    pos = 0;
    while (pos < len) {
        uint32_t save = pos;
        int32_t  cp   = n00b_unicode_utf8_decode(data, len, &pos);
        if (cp < 0)
            break;

        if (!should_escape_cp((n00b_codepoint_t)cp)) {
            memcpy(q, data + save, pos - save);
            q += pos - save;
            continue;
        }

        *q++ = '\\';
        switch (cp) {
        case '\\':
            *q++ = '\\';
            continue;
        case '"':
            *q++ = '"';
            continue;
        case '\'':
            *q++ = '\'';
            continue;
        case '\a':
            *q++ = 'a';
            continue;
        case '\b':
            *q++ = 'b';
            continue;
        case '\e':
            *q++ = 'e';
            continue;
        case '\f':
            *q++ = 'f';
            continue;
        case '\n':
            *q++ = 'n';
            continue;
        case '\r':
            *q++ = 'r';
            continue;
        case '\t':
            *q++ = 't';
            continue;
        case '\v':
            *q++ = 'v';
            continue;
        default:
            if (cp <= 0x7f) {
                *q++ = 'x';
                *q++ = hex_lower[cp >> 4];
                *q++ = hex_lower[cp & 0x0f];
            }
            else if (cp < 0x10000) {
                *q++ = 'u';
                *q++ = hex_lower[(cp >> 12) & 0x0f];
                *q++ = hex_lower[(cp >> 8) & 0x0f];
                *q++ = hex_lower[(cp >> 4) & 0x0f];
                *q++ = hex_lower[cp & 0x0f];
            }
            else {
                *q++ = 'U';
                *q++ = hex_lower[(cp >> 28) & 0x0f];
                *q++ = hex_lower[(cp >> 24) & 0x0f];
                *q++ = hex_lower[(cp >> 20) & 0x0f];
                *q++ = hex_lower[(cp >> 16) & 0x0f];
                *q++ = hex_lower[(cp >> 12) & 0x0f];
                *q++ = hex_lower[(cp >> 8) & 0x0f];
                *q++ = hex_lower[(cp >> 4) & 0x0f];
                *q++ = hex_lower[cp & 0x0f];
            }
            continue;
        }
    }

    uint32_t actual_len = (uint32_t)(q - buf);
    buf[actual_len]     = '\0';

    n00b_string_t *result  = n00b_string_from_raw(buf, actual_len, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// Inverse hex lookup: maps ASCII byte to 0-15, or 0xFF if invalid.
static const uint8_t inv_hex[256] = {
    ['0'] = 0x00, ['1'] = 0x01, ['2'] = 0x02, ['3'] = 0x03, ['4'] = 0x04, ['5'] = 0x05,
    ['6'] = 0x06, ['7'] = 0x07, ['8'] = 0x08, ['9'] = 0x09, ['a'] = 0x0a, ['b'] = 0x0b,
    ['c'] = 0x0c, ['d'] = 0x0d, ['e'] = 0x0e, ['f'] = 0x0f, ['A'] = 0x0a, ['B'] = 0x0b,
    ['C'] = 0x0c, ['D'] = 0x0d, ['E'] = 0x0e, ['F'] = 0x0f,
};
// Sentinel: default-initialized entries are 0, which conflicts with '0'.
// Use a separate validity check.
static bool
is_hex_digit(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static uint8_t
hex_val(uint8_t c)
{
    return inv_hex[c];
}

n00b_result_t(n00b_string_t *) n00b_unicode_str_unescape(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    const uint8_t *p   = (const uint8_t *)s->data;
    const uint8_t *end = p + s->u8_bytes;

    // Quick check: if no backslash, return as-is.
    bool has_backslash = false;
    const uint8_t *scan;
    for (scan = p; scan < end; scan++) {
        if (*scan == '\\') {
            has_backslash = true;
            break;
        }
    }
    if (!has_backslash) {
        return n00b_result_ok(n00b_string_t *, s);
    }

    // Output buffer (never larger than input).
    char *buf = n00b_alloc_array(char, (size_t)s->u8_bytes + 1);
    char *q   = buf;

    while (p < end) {
        if (*p != '\\') {
            *q++ = (char)*p++;
            continue;
        }
        p++; // skip backslash
        if (p >= end) {
            n00b_free(buf);
            return n00b_result_err(n00b_string_t *, N00B_ERR_STR_ESCAPE_EOS);
        }

        n00b_codepoint_t cp;

        switch (*p) {
        case 'a':
            *q++ = '\a';
            p++;
            continue;
        case 'b':
            *q++ = '\b';
            p++;
            continue;
        case 'e':
            *q++ = '\e';
            p++;
            continue;
        case 'f':
            *q++ = '\f';
            p++;
            continue;
        case 'n':
            *q++ = '\n';
            p++;
            continue;
        case 'r':
            *q++ = '\r';
            p++;
            continue;
        case 't':
            *q++ = '\t';
            p++;
            continue;
        case 'v':
            *q++ = '\v';
            p++;
            continue;
        case '\\':
            *q++ = '\\';
            p++;
            continue;
        case '"':
            *q++ = '"';
            p++;
            continue;
        case '\'':
            *q++ = '\'';
            p++;
            continue;

        case 'x':
        case 'X':
            p++;
            if ((uint32_t)(end - p) < 2) {
                n00b_free(buf);
                return n00b_result_err(n00b_string_t *, N00B_ERR_STR_ESCAPE_EOS);
            }
            if (!is_hex_digit(p[0]) || !is_hex_digit(p[1])) {
                n00b_free(buf);
                return n00b_result_err(n00b_string_t *, N00B_ERR_STR_BAD_HEX);
            }
            cp = (hex_val(p[0]) << 4) | hex_val(p[1]);
            p += 2;
            q += n00b_unicode_utf8_encode(cp, q);
            continue;

        case 'u':
            p++;
            if (*p == '+')
                p++; // optional U+ prefix
            if ((uint32_t)(end - p) < 4) {
                n00b_free(buf);
                return n00b_result_err(n00b_string_t *, N00B_ERR_STR_ESCAPE_EOS);
            }
            cp = 0;
            for (int i = 0; i < 4; i++) {
                if (!is_hex_digit(p[i])) {
                    n00b_free(buf);
                    return n00b_result_err(n00b_string_t *, N00B_ERR_STR_BAD_HEX);
                }
                cp = (cp << 4) | hex_val(p[i]);
            }
            p += 4;
            q += n00b_unicode_utf8_encode(cp, q);
            continue;

        case 'U':
            p++;
            if (*p == '+')
                p++;
            if ((uint32_t)(end - p) < 6) {
                n00b_free(buf);
                return n00b_result_err(n00b_string_t *, N00B_ERR_STR_ESCAPE_EOS);
            }
            cp = 0;
            for (int i = 0; i < 6; i++) {
                if (!is_hex_digit(p[i])) {
                    n00b_free(buf);
                    return n00b_result_err(n00b_string_t *, N00B_ERR_STR_BAD_HEX);
                }
                cp = (cp << 4) | hex_val(p[i]);
            }
            p += 6;
            q += n00b_unicode_utf8_encode(cp, q);
            continue;

        default:
            // Unknown escape: keep the character as-is.
            *q++ = (char)*p++;
            continue;
        }
    }

    uint32_t actual_len = (uint32_t)(q - buf);
    buf[actual_len]     = '\0';

    n00b_string_t *result  = n00b_string_from_raw(buf, actual_len, .allocator = allocator);
    n00b_free(buf);
    return n00b_result_ok(n00b_string_t *, result);
}

// ---------------------------------------------------------------------------
// Codepoint access
// ---------------------------------------------------------------------------

n00b_option_t(n00b_codepoint_t) n00b_unicode_str_codepoint_at(n00b_string_t *s, int64_t index)
{
    int64_t num_cps = s->codepoints;

    // Resolve negative index.
    if (index < 0)
        index += num_cps;
    if (index < 0 || index >= num_cps)
        return n00b_option_none(n00b_codepoint_t);

    const char *data = s->data;
    uint32_t    len  = (uint32_t)s->u8_bytes;
    uint32_t    pos  = 0;

    for (int64_t i = 0; i < index; i++) {
        if (pos >= len)
            return n00b_option_none(n00b_codepoint_t);
        n00b_unicode_utf8_decode(data, len, &pos);
    }

    if (pos >= len)
        return n00b_option_none(n00b_codepoint_t);

    int32_t cp = n00b_unicode_utf8_decode(data, len, &pos);
    if (cp < 0)
        return n00b_option_none(n00b_codepoint_t);

    return n00b_option_set(n00b_codepoint_t, (n00b_codepoint_t)cp);
}

// ---------------------------------------------------------------------------
// Deep copy
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_copy(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    return n00b_string_from_raw(s->data, s->u8_bytes, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// Split-and-crop
// ---------------------------------------------------------------------------

n00b_array_t(n00b_string_t *)
    n00b_unicode_str_split_and_crop(n00b_string_t *s, n00b_string_t *sep, int32_t width) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    n00b_array_t(n00b_string_t *) parts = n00b_unicode_str_split(s, sep, .allocator = allocator);
    for (size_t i = 0; i < parts.len; i++) {
        parts.data[i] = n00b_unicode_str_truncate(parts.data[i], width, .allocator = allocator);
    }
    return parts;
}

// ---------------------------------------------------------------------------
// Text wrapping
// ---------------------------------------------------------------------------

n00b_array_t(n00b_string_t *) n00b_unicode_str_wrap(n00b_string_t *s) _kargs
{
    int32_t           width        = 80;
    int32_t           hang         = 0;
    bool              no_hard_wrap = false;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    if (s->u8_bytes == 0) {
        return n00b_array_new(n00b_string_t *, 0, .allocator = allocator);
    }

    n00b_array_t(uint32_t) breaks = n00b_unicode_linebreak_wrap(s,
                                                                .width        = width,
                                                                .hang         = hang,
                                                                .no_hard_wrap = no_hard_wrap,
                                                                .allocator    = allocator);

    if (breaks.len == 0) {
        n00b_array_t(n00b_string_t *) result = n00b_array_new(n00b_string_t *, 1, .allocator = allocator);
        result.data[0]                       = n00b_unicode_str_copy(s, .allocator = allocator);
        result.len                           = 1;
        return result;
    }

    uint32_t n_lines                     = (uint32_t)breaks.len + 1;
    n00b_array_t(n00b_string_t *) result = n00b_array_new(n00b_string_t *, n_lines, .allocator = allocator);
    uint32_t prev                        = 0;

    for (size_t i = 0; i < breaks.len; i++) {
        result.data[i]
            = n00b_unicode_str_slice_bytes(s, prev, breaks.data[i], .allocator = allocator);
        prev = breaks.data[i];
    }

    result.data[breaks.len]
        = n00b_unicode_str_slice_bytes(s, prev, (uint32_t)s->u8_bytes, .allocator = allocator);
    result.len = n_lines;

    return result;
}
