#include "text/strings/rich_desc.h"
#include "text/strings/text_style.h"
#include "adt/dict_untyped.h"
#include "core/gc.h"
#include "core/hash.h"
#include "core/runtime.h"
#include <string.h>
#include <stddef.h>

// ===================================================================
// Cache
// ===================================================================

static n00b_dict_untyped_t *rich_desc_cache = nullptr;

static inline bool
ascii_isdigit(char c)
{
    return c >= '0' && c <= '9';
}

static n00b_allocator_t *
rich_desc_allocator(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
}

void
n00b_rich_desc_cache_init(void)
{
    if (!rich_desc_cache) {
        n00b_allocator_t *allocator = rich_desc_allocator();

        rich_desc_cache = n00b_alloc_with_opts(
            n00b_dict_untyped_t,
            &(n00b_alloc_opts_t){.allocator = allocator});
        n00b_dict_untyped_init(rich_desc_cache,
                                .hash           = n00b_hash_word,
                                .skip_obj_hash  = true,
                                .allocator      = allocator);
    }
}

// ===================================================================
// Inline property table
// ===================================================================

typedef struct {
    const char      *name;
    n00b_tristate_t *(*field_offset)(n00b_text_style_t *);
} prop_entry_t;

// We use a simple linear scan; the table is small.
static const struct {
    const char *name;
    int         field; // offset of the tristate field in n00b_text_style_t
} prop_table[] = {
    {"b",             offsetof(n00b_text_style_t, bold)},
    {"bold",          offsetof(n00b_text_style_t, bold)},
    {"i",             offsetof(n00b_text_style_t, italic)},
    {"italic",        offsetof(n00b_text_style_t, italic)},
    {"u",             offsetof(n00b_text_style_t, underline)},
    {"underline",     offsetof(n00b_text_style_t, underline)},
    {"uu",            offsetof(n00b_text_style_t, double_underline)},
    {"2u",            offsetof(n00b_text_style_t, double_underline)},
    {"st",            offsetof(n00b_text_style_t, strikethrough)},
    {"strike",        offsetof(n00b_text_style_t, strikethrough)},
    {"strikethrough", offsetof(n00b_text_style_t, strikethrough)},
    {"r",             offsetof(n00b_text_style_t, reverse)},
    {"reverse",       offsetof(n00b_text_style_t, reverse)},
    {"dim",           offsetof(n00b_text_style_t, dim)},
    {"faint",         offsetof(n00b_text_style_t, dim)},
    {"blink",         offsetof(n00b_text_style_t, blink)},
    {nullptr,            -1},
};

// Text case tags: not tristate fields, handled separately.
static const struct {
    const char       *name;
    n00b_text_case_t  value;
} case_table[] = {
    {"upper",   N00B_TEXT_CASE_UPPER},
    {"up",      N00B_TEXT_CASE_UPPER},
    {"lower",   N00B_TEXT_CASE_LOWER},
    {"l",       N00B_TEXT_CASE_LOWER},
    {"caps",    N00B_TEXT_CASE_CAPS},
    {"allcaps", N00B_TEXT_CASE_CAPS},
    {"t",       N00B_TEXT_CASE_TITLE},
    {"title",   N00B_TEXT_CASE_TITLE},
    {nullptr,      0},
};

// Return the tristate field offset for a known property name, or -1.
static int
lookup_prop(const char *name, int name_len)
{
    for (int i = 0; prop_table[i].name; i++) {
        if ((int)strlen(prop_table[i].name) == name_len
            && memcmp(prop_table[i].name, name, name_len) == 0) {
            return prop_table[i].field;
        }
    }
    return -1;
}

// Return the text_case value for a known case tag, or -1.
static int
lookup_case(const char *name, int name_len)
{
    for (int i = 0; case_table[i].name; i++) {
        if ((int)strlen(case_table[i].name) == name_len
            && memcmp(case_table[i].name, name, name_len) == 0) {
            return (int)case_table[i].value;
        }
    }
    return -1;
}

// ===================================================================
// Parser
// ===================================================================

// Working segment list (growable during parse).
typedef struct {
    n00b_rich_segment_t *segs;
    int32_t              count;
    int32_t              cap;
    int32_t              auto_index; // next auto-substitution index
    n00b_allocator_t    *allocator;
} seg_list_t;

static void
seg_push(seg_list_t *sl, n00b_rich_segment_t seg)
{
    if (sl->count >= sl->cap) {
        int32_t new_cap          = sl->cap ? sl->cap * 2 : 16;
        n00b_rich_segment_t *new = n00b_alloc_array_with_opts(
            n00b_rich_segment_t,
            new_cap,
            &(n00b_alloc_opts_t){.allocator = sl->allocator});
        if (sl->segs) {
            memcpy(new, sl->segs, sl->count * sizeof(n00b_rich_segment_t));
            n00b_free(sl->segs);
        }
        sl->segs = new;
        sl->cap  = new_cap;
    }
    sl->segs[sl->count++] = seg;
}

// Copy a NUL-terminated tag name from [start, start+len).
static char *
dup_tag(const char *start, int len, n00b_allocator_t *allocator)
{
    char *t = n00b_alloc_array_with_opts(
        char,
        len + 1,
        &(n00b_alloc_opts_t){.allocator = allocator});
    memcpy(t, start, len);
    t[len] = '\0';
    return t;
}

// Classify and emit a tag body (between delimiters).
// tag_body points to the content, tag_len is its length.
static void
emit_tag(seg_list_t *sl, const char *tag_body, int tag_len)
{
    if (tag_len == 0) {
        return;
    }

    // --- Reset: "/" alone ---
    if (tag_len == 1 && tag_body[0] == '/') {
        seg_push(sl,
                 (n00b_rich_segment_t){.kind = N00B_RICH_RESET});
        return;
    }

    // --- Substitution: starts with '#' ---
    if (tag_body[0] == '#') {
        n00b_rich_segment_t seg = {.kind = N00B_RICH_SUBST};

        const char *p   = tag_body + 1;
        int         rem = tag_len - 1;

        if (rem == 0) {
            // [|#|] auto-index
            seg.offset = sl->auto_index++;
            seg.length = -1;
        }
        else if (rem == 1 && p[0] == '!') {
            // [|#!|] auto-index, strip styling
            seg.offset      = sl->auto_index++;
            seg.length      = -1;
            seg.strip_style = true;
        }
        else {
            // Parse optional index
            int idx       = 0;
            int idx_chars = 0;
            while (idx_chars < rem && ascii_isdigit(p[idx_chars])) {
                idx = idx * 10 + (p[idx_chars] - '0');
                idx_chars++;
            }

            if (idx_chars == 0) {
                // No index = auto
                seg.offset = sl->auto_index++;
            }
            else {
                seg.offset = idx;
            }

            // After index: optional '!' or ':spec'
            const char *rest     = p + idx_chars;
            int         rest_len = rem - idx_chars;

            if (rest_len > 0 && rest[0] == '!') {
                seg.strip_style = true;
                rest++;
                rest_len--;
            }

            if (rest_len > 0 && rest[0] == ':') {
                seg.tag = dup_tag(rest + 1, rest_len - 1, sl->allocator);
            }
        }

        seg_push(sl, seg);
        return;
    }

    // --- Close tag: starts with '/' ---
    bool is_close = (tag_body[0] == '/');
    const char *name     = is_close ? tag_body + 1 : tag_body;
    int         name_len = is_close ? tag_len - 1 : tag_len;

    if (name_len == 0) {
        return; // shouldn't happen (handled above)
    }

    // --- Role: starts with '@' ---
    if (name[0] == '@') {
        char *tag_name = dup_tag(name, name_len, sl->allocator);
        seg_push(sl,
                 (n00b_rich_segment_t){
                     .kind = is_close ? N00B_RICH_ROLE_OFF : N00B_RICH_ROLE_ON,
                     .tag  = tag_name,
                 });
        return;
    }

    // --- Inline property? ---
    int prop_off = lookup_prop(name, name_len);
    if (prop_off >= 0) {
        char *tag_name = dup_tag(name, name_len, sl->allocator);
        seg_push(sl,
                 (n00b_rich_segment_t){
                     .kind   = is_close ? N00B_RICH_PROP_OFF : N00B_RICH_PROP_ON,
                     .tag    = tag_name,
                     .offset = prop_off,
                 });
        return;
    }

    // --- Text case tag? ---
    int case_val = lookup_case(name, name_len);
    if (case_val >= 0) {
        char *tag_name = dup_tag(name, name_len, sl->allocator);
        seg_push(sl,
                 (n00b_rich_segment_t){
                     .kind   = is_close ? N00B_RICH_PROP_OFF : N00B_RICH_PROP_ON,
                     .tag    = tag_name,
                     .offset = case_val,
                     .length = -2, // sentinel: means "this is a case tag"
                 });
        return;
    }

    // --- Named style (default) ---
    char *tag_name = dup_tag(name, name_len, sl->allocator);
    seg_push(sl,
             (n00b_rich_segment_t){
                 .kind = is_close ? N00B_RICH_STYLE_OFF : N00B_RICH_STYLE_ON,
                 .tag  = tag_name,
             });
}

// Emit a text segment from the descriptor.
static void
emit_text(seg_list_t *sl, const char *desc, int start, int end)
{
    if (start >= end) {
        return;
    }
    seg_push(sl,
             (n00b_rich_segment_t){
                 .kind   = N00B_RICH_TEXT,
                 .offset = start,
                 .length = end - start,
             });
}

static n00b_rich_desc_t *
do_parse(const char *desc, int32_t desc_len)
{
    seg_list_t sl = {
        .allocator = rich_desc_allocator(),
    };
    int        i  = 0;
    int        text_start = 0;

    while (i < desc_len) {
        // --- Escape: backslash ---
        if (desc[i] == '\\' && i + 1 < desc_len) {
            // Flush text before backslash.
            emit_text(&sl, desc, text_start, i);
            // The escaped character becomes a 1-byte text segment.
            emit_text(&sl, desc, i + 1, i + 2);
            i += 2;
            text_start = i;
            continue;
        }

        // --- Bracket tag: [| ... |] ---
        if (desc[i] == '[' && i + 1 < desc_len && desc[i + 1] == '|') {
            emit_text(&sl, desc, text_start, i);
            int tag_start = i + 2;
            int j         = tag_start;
            // Find closing |]
            while (j + 1 < desc_len && !(desc[j] == '|' && desc[j + 1] == ']')) {
                j++;
            }
            if (j + 1 < desc_len) {
                emit_tag(&sl, desc + tag_start, j - tag_start);
                i          = j + 2;
                text_start = i;
            }
            else {
                // No closing |] -- treat [| as literal text.
                i += 2;
            }
            continue;
        }

        // --- Guillemet tag: « ... » ---
        // « is U+00AB = C2 AB in UTF-8
        // » is U+00BB = C2 BB in UTF-8
        if (i + 1 < desc_len && (uint8_t)desc[i] == 0xC2
            && (uint8_t)desc[i + 1] == 0xAB) {
            emit_text(&sl, desc, text_start, i);
            int tag_start = i + 2;
            int j         = tag_start;
            // Find closing »
            while (j + 1 < desc_len
                   && !((uint8_t)desc[j] == 0xC2
                        && (uint8_t)desc[j + 1] == 0xBB)) {
                j++;
            }
            if (j + 1 < desc_len) {
                emit_tag(&sl, desc + tag_start, j - tag_start);
                i          = j + 2;
                text_start = i;
            }
            else {
                i += 2;
            }
            continue;
        }

        i++;
    }

    // Trailing text.
    emit_text(&sl, desc, text_start, desc_len);

    // Build result.
    n00b_rich_desc_t *result =
        n00b_alloc_flex_with_opts(n00b_rich_desc_t,
                                  n00b_rich_segment_t,
                                  sl.count,
                                  &(n00b_alloc_opts_t){.allocator = sl.allocator});
    result->num_segments = sl.count;
    if (sl.count > 0) {
        memcpy(result->segments, sl.segs,
               sl.count * sizeof(n00b_rich_segment_t));
    }
    if (sl.segs) {
        n00b_free(sl.segs);
    }

    return result;
}

// ===================================================================
// Public API
// ===================================================================

n00b_rich_desc_t *
n00b_rich_desc_parse(const char *desc, int32_t desc_len)
{
    if (!rich_desc_cache) {
        n00b_rich_desc_cache_init();
    }

    // Hash-based cache lookup.
    uint64_t hash = n00b_xxh3_64bits_raw(desc, (size_t)desc_len);

    bool  found;
    void *cached = _n00b_dict_untyped_get(rich_desc_cache,
                                           (void *)hash, &found);
    if (found) {
        return (n00b_rich_desc_t *)cached;
    }

    n00b_rich_desc_t *result = do_parse(desc, desc_len);
    _n00b_dict_untyped_put(rich_desc_cache, (void *)hash, result);

    return result;
}
