/**
 * @file gc_map.c
 * @brief Per-allocation GC scan-bitmap helpers and built-in callbacks.
 *
 * Step 1 of `~/dd/gc-bits.md`.  These routines are pure data
 * manipulation — no GC state, no allocator state.  They are wired
 * into the collector in later steps.
 */
#include "core/gc_map.h"
#include "util/assert.h"
#include <string.h>

/// Mask of the in-range bits of the bitmap's last uint64_t.  When
/// `num_words` is a multiple of 64 the last word is fully in-range.
static inline uint64_t
last_word_mask(uint64_t num_words)
{
    uint64_t rem = num_words & 63;
    return rem ? ((UINT64_C(1) << rem) - 1) : UINT64_MAX;
}

void
n00b_gc_map_mark_all(n00b_gc_map_t *m)
{
    uint64_t nw = n00b_gc_map_word_count(m->num_words);
    if (nw == 0) {
        return;
    }
    memset(m->bitmap, 0xff, (nw - 1) * sizeof(uint64_t));
    m->bitmap[nw - 1] = last_word_mask(m->num_words);
}

void
n00b_gc_map_unmark_all(n00b_gc_map_t *m)
{
    memset(m->bitmap, 0, n00b_gc_map_word_count(m->num_words) * sizeof(uint64_t));
}

void
n00b_gc_map_mark_range(n00b_gc_map_t *m, uint64_t start, uint64_t len)
{
    assert(start + len <= m->num_words);
    if (len == 0) {
        return;
    }

    uint64_t end = start + len; // exclusive

    // Head: bits in the partial leading word, up to the next 64-boundary
    // or `end`, whichever comes first.
    uint64_t head_end = (start + 63) & ~UINT64_C(63);
    if (head_end > end) {
        head_end = end;
    }
    for (uint64_t i = start; i < head_end; ++i) {
        n00b_gc_map_mark(m, i);
    }

    if (head_end == end) {
        return;
    }

    // Middle: whole 64-bit words.
    uint64_t middle_start_word = head_end >> 6;
    uint64_t tail_start        = end & ~UINT64_C(63);
    uint64_t middle_words      = (tail_start - head_end) >> 6;
    if (middle_words) {
        memset(&m->bitmap[middle_start_word], 0xff, middle_words * sizeof(uint64_t));
    }

    // Tail: bits in the partial trailing word.
    for (uint64_t i = tail_start; i < end; ++i) {
        n00b_gc_map_mark(m, i);
    }
}

void
n00b_gc_map_unmark_range(n00b_gc_map_t *m, uint64_t start, uint64_t len)
{
    assert(start + len <= m->num_words);
    if (len == 0) {
        return;
    }

    uint64_t end = start + len;

    uint64_t head_end = (start + 63) & ~UINT64_C(63);
    if (head_end > end) {
        head_end = end;
    }
    for (uint64_t i = start; i < head_end; ++i) {
        n00b_gc_map_unmark(m, i);
    }

    if (head_end == end) {
        return;
    }

    uint64_t middle_start_word = head_end >> 6;
    uint64_t tail_start        = end & ~UINT64_C(63);
    uint64_t middle_words      = (tail_start - head_end) >> 6;
    if (middle_words) {
        memset(&m->bitmap[middle_start_word], 0, middle_words * sizeof(uint64_t));
    }

    for (uint64_t i = tail_start; i < end; ++i) {
        n00b_gc_map_unmark(m, i);
    }
}

void
n00b_gc_map_mark_stride(n00b_gc_map_t *m, uint64_t start, uint64_t stride, uint64_t count)
{
    if (count == 0) {
        return;
    }
    assert(stride > 0);
    assert(start + (count - 1) * stride < m->num_words);

    uint64_t idx = start;
    for (uint64_t i = 0; i < count; ++i) {
        n00b_gc_map_mark(m, idx);
        idx += stride;
    }
}

void
n00b_gc_map_mark_every_other(n00b_gc_map_t *m, uint64_t start_offset)
{
    if (start_offset >= m->num_words) {
        return;
    }
    uint64_t count = (m->num_words - start_offset + 1) >> 1;
    n00b_gc_map_mark_stride(m, start_offset, 2, count);
}

void
n00b_gc_map_mark_struct_field(n00b_gc_map_t *m,
                              uint64_t base,
                              uint64_t stride,
                              uint64_t offset,
                              uint64_t count)
{
    if (count == 0) {
        return;
    }
    n00b_gc_map_mark_stride(m, base + offset, stride, count);
}

static const n00b_gc_variant_arm_t *
n00b_gc_variant_find_arm(const n00b_gc_variant_field_t *variant,
                         uint64_t                       selector)
{
    if (variant == nullptr || variant->arm_count == 0
        || variant->arms == nullptr) {
        return nullptr;
    }

    uint64_t lo = 0;
    uint64_t hi = variant->arm_count;

    while (lo < hi) {
        uint64_t mid = lo + ((hi - lo) / 2);
        uint64_t key = variant->arms[mid].selector;

        if (key < selector) {
            lo = mid + 1;
        }
        else if (key > selector) {
            hi = mid;
        }
        else {
            return &variant->arms[mid];
        }
    }

    return nullptr;
}

static void
n00b_gc_map_mark_struct_layout_count(n00b_gc_map_t                  *m,
                                     const n00b_gc_struct_layout_t  *layout,
                                     uint64_t                        count)
{
    if (layout == nullptr || count == 0 || layout->stride == 0) {
        return;
    }

    if (layout->offset_count != 0) {
        n00b_require(layout->offsets != nullptr,
                     "STRUCT_LAYOUT scan descriptor has no offset table");
    }
    if (layout->variant_count != 0) {
        n00b_require(layout->variants != nullptr,
                     "STRUCT_LAYOUT variant descriptor has no variant table");
        n00b_require(m->user_ptr != nullptr,
                     "STRUCT_LAYOUT variant scan has no allocation base");
    }

    uint64_t *words = (uint64_t *)m->user_ptr;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t base = i * layout->stride;

        for (uint64_t j = 0; j < layout->offset_count; j++) {
            uint64_t offset = layout->offsets[j];

            n00b_require(offset < layout->stride,
                         "STRUCT_LAYOUT scan offset exceeds descriptor stride");
            n00b_require(base + offset < m->num_words,
                         "STRUCT_LAYOUT scan offset exceeds allocation bounds");
            n00b_gc_map_mark(m, base + offset);
        }

        for (uint64_t j = 0; j < layout->variant_count; j++) {
            const n00b_gc_variant_field_t *variant = &layout->variants[j];

            n00b_require(variant->selector_offset < layout->stride,
                         "STRUCT_LAYOUT variant selector offset exceeds descriptor stride");
            n00b_require(base + variant->selector_offset < m->num_words,
                         "STRUCT_LAYOUT variant selector offset exceeds allocation bounds");

            uint64_t selector = words[base + variant->selector_offset];
            if (selector == 0) {
                continue;
            }

            const n00b_gc_variant_arm_t *arm =
                n00b_gc_variant_find_arm(variant, selector);
            if (arm == nullptr) {
                continue;
            }

            for (uint64_t a = 0; a < arm->ptr_offset_count; a++) {
                uint64_t off = arm->ptr_offsets[a];
                n00b_require(off < layout->stride,
                             "STRUCT_LAYOUT variant arm offset exceeds descriptor stride");
                n00b_require(base + off < m->num_words,
                             "STRUCT_LAYOUT variant arm offset exceeds allocation bounds");
                n00b_gc_map_mark(m, base + off);
            }
        }
    }
}

void
n00b_gc_map_mark_struct_layout(n00b_gc_map_t *m, const n00b_gc_struct_layout_t *layout)
{
    if (layout == nullptr || layout->count == 0) {
        return;
    }

    assert(layout->stride > 0);
    n00b_gc_map_mark_struct_layout_count(m, layout, layout->count);
}

// Length-derived variant of mark_struct_layout: the element COUNT is
// computed from the allocation's word count (num_words / stride) rather
// than read from the descriptor. One shared per-type descriptor (stride
// + pointer offsets) thus serves an allocation of any element count — a
// single object (count == 1) or an array of N. This is what the
// link-time type->GC-map dictionary (D-049) needs: it keys one
// descriptor by object type, and the element count is known only at the
// allocation site (num_words). `layout->count` is ignored here.
//
// A type may also carry discriminated-union (n00b_variant_t) fields whose
// pointer-ness is decided per element by a runtime selector word; those are
// resolved against the live object after the unconditional offsets are marked.
void
n00b_gc_map_mark_type_layout(n00b_gc_map_t *m, const n00b_gc_struct_layout_t *layout)
{
    if (layout == nullptr || layout->stride == 0) {
        return;
    }
    if (layout->offset_count == 0 && layout->variant_count == 0) {
        return;
    }

    n00b_require(layout->offset_count == 0 || layout->offsets != nullptr,
                 "TYPE_LAYOUT scan descriptor has no offset table");
    n00b_require(layout->variant_count == 0 || layout->variants != nullptr,
                 "TYPE_LAYOUT scan descriptor has no variant table");
    n00b_require((m->num_words % layout->stride) == 0,
                 "TYPE_LAYOUT scan allocation length is not a whole number of elements");

    uint64_t count = m->num_words / layout->stride;
    n00b_gc_map_mark_struct_layout_count(m, layout, count);
}

// ---------------------------------------------------------------------------
// Built-in callbacks.
// ---------------------------------------------------------------------------

void
n00b_gc_scan_cb_all(n00b_gc_map_t *m, void *user)
{
    (void)user;
    n00b_gc_map_mark_all(m);
}

void
n00b_gc_scan_cb_none(n00b_gc_map_t *m, void *user)
{
    (void)m;
    (void)user;
    // The GC zero-initialises the bitmap before calling us; leaving it
    // alone is exactly "no pointer words".
}

void
n00b_gc_scan_cb_every_other(n00b_gc_map_t *m, void *user)
{
    (void)user;
    n00b_gc_map_mark_every_other(m, 0);
}

void
n00b_gc_scan_cb_struct_field(n00b_gc_map_t *m, void *user)
{
    n00b_gc_struct_array_t *desc = (n00b_gc_struct_array_t *)user;
    n00b_gc_map_mark_struct_field(m, 0, desc->stride, desc->offset, desc->count);
}

void
n00b_gc_scan_cb_struct_layout(n00b_gc_map_t *m, void *user)
{
    n00b_gc_map_mark_struct_layout(m, (const n00b_gc_struct_layout_t *)user);
}

void
n00b_gc_scan_cb_type_layout(n00b_gc_map_t *m, void *user)
{
    n00b_gc_map_mark_type_layout(m, (const n00b_gc_struct_layout_t *)user);
}
