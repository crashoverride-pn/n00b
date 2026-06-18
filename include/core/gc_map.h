/**
 * @file gc_map.h
 * @brief Per-allocation GC scan-bitmap API.
 *
 * The GC's conservative scanner treats every 8-byte-aligned word of an
 * allocation as a candidate heap pointer.  That is wrong for backing
 * stores that mix pointers and scalars (e.g. a `uint32_t[]` whose
 * adjacent pairs happen to form a pointer-shaped 8-byte value): the
 * collector forwards the bogus "pointer" and rewrites the slot,
 * corrupting unrelated scalar data.
 *
 * This header restores a per-allocation precision mechanism.  An
 * allocation declares its scan shape (`n00b_gc_scan_kind_t`); the
 * `CALLBACK` shape invokes a user-supplied function that fills an
 * `n00b_gc_map_t` bitmap — one bit per word — to tell the collector
 * which words are pointers.  The collector forwards only those words.
 *
 * Step 1 of `~/dd/gc-bits.md` introduces just the bitmap data type,
 * its helpers, and a small set of built-in callbacks.  GC integration
 * is wired up in later steps.
 */
#pragma once

#include "n00b.h"

/**
 * @brief How the GC should scan an allocation's contents.
 *
 * `DEFAULT` falls back to the legacy `no_scan` bit.  Any explicit value
 * overrides `no_scan`.  `CALLBACK` invokes the allocation's registered
 * `n00b_gc_scan_cb_t` to fill the bitmap; the other values are fixed
 * patterns that the collector can apply without an indirect call.
 */
enum n00b_gc_scan_kind_t : uint8_t {
    N00B_GC_SCAN_KIND_DEFAULT     = 0, // honour no_scan, else scan every word
    N00B_GC_SCAN_KIND_NONE        = 1, // never scan (overrides no_scan=false)
    N00B_GC_SCAN_KIND_ALL         = 2, // scan every word (overrides no_scan=true)
    N00B_GC_SCAN_KIND_EVERY_OTHER = 3, // scan words 0, 2, 4, ...
    N00B_GC_SCAN_KIND_CALLBACK    = 4, // invoke scan_cb to fill the bitmap
};

/**
 * @brief View the GC hands to a scan callback.
 *
 * The collector zero-initialises @ref bitmap before the call and the
 * callback sets the bits whose corresponding words contain pointers.
 * `num_words` is the user-data length in 8-byte words; the bitmap is
 * `n00b_gc_map_word_count(num_words)` uint64_ts long.
 */
struct n00b_gc_map_t {
    void     *user_ptr;
    uint64_t  num_words;
    uint64_t *bitmap;
};

/**
 * @brief Descriptor for `n00b_gc_scan_cb_struct_field`.
 *
 * Passed via the allocation's `scan_user` slot when the built-in
 * struct-field callback is installed.  Represents an array of `count`
 * elements, each `stride` words wide, where the pointer field sits at
 * word `offset` within the element.
 */
// n00b_gc_struct_array_t is declared in n00b.h because ncc-generated static
// descriptor code may reference it while including only the umbrella header.

/**
 * @brief Descriptor for `n00b_gc_scan_cb_struct_layout`.
 *
 * Represents an array of `count` elements, each `stride` words wide, with
 * `offset_count` pointer words per element. `offsets` is an array of word
 * offsets relative to the start of one element.
 */
// n00b_gc_struct_layout_t is declared in n00b.h because ncc-generated static
// descriptor code may reference it while including only the umbrella header.

/** @brief Number of uint64_t words needed to hold a bitmap for
 *  @p num_words allocation words. */
static inline uint64_t
n00b_gc_map_word_count(uint64_t num_words)
{
    return (num_words + 63) >> 6;
}

// Single-bit ops; macros so they inline cleanly in the GC's hot path.
#define n00b_gc_map_mark(m, i)   ((m)->bitmap[(i) >> 6] |=  (UINT64_C(1) << ((i) & 63)))
#define n00b_gc_map_unmark(m, i) ((m)->bitmap[(i) >> 6] &= ~(UINT64_C(1) << ((i) & 63)))
#define n00b_gc_map_is_set(m, i) (((m)->bitmap[(i) >> 6] >> ((i) & 63)) & UINT64_C(1))

extern void n00b_gc_map_mark_all(n00b_gc_map_t *m);
extern void n00b_gc_map_unmark_all(n00b_gc_map_t *m);
extern void n00b_gc_map_mark_range(n00b_gc_map_t *m, uint64_t start, uint64_t len);
extern void n00b_gc_map_unmark_range(n00b_gc_map_t *m, uint64_t start, uint64_t len);
extern void n00b_gc_map_mark_stride(n00b_gc_map_t *m, uint64_t start, uint64_t stride, uint64_t count);
extern void n00b_gc_map_mark_every_other(n00b_gc_map_t *m, uint64_t start_offset);
extern void n00b_gc_map_mark_struct_field(n00b_gc_map_t *m, uint64_t base, uint64_t stride, uint64_t offset, uint64_t count);
extern void n00b_gc_map_mark_struct_layout(n00b_gc_map_t *m, const n00b_gc_struct_layout_t *layout);
// Length-derived: element count = m->num_words / layout->stride (layout->count ignored).
extern void n00b_gc_map_mark_type_layout(n00b_gc_map_t *m, const n00b_gc_struct_layout_t *layout);

/// Built-in scan callbacks.  Prefer the matching fixed `scan_kind`
/// enum value when it is sufficient — it lets the GC skip the
/// indirect call.  These exist for the cases where a callback slot
/// is already wired and the natural shape happens to match.
extern void n00b_gc_scan_cb_all(n00b_gc_map_t *m, void *user);
extern void n00b_gc_scan_cb_none(n00b_gc_map_t *m, void *user);
extern void n00b_gc_scan_cb_every_other(n00b_gc_map_t *m, void *user);
/// n00b_gc_scan_cb_struct_field is declared in n00b.h because generated
/// static descriptor code may reference it through the umbrella header only.
/// n00b_gc_scan_cb_struct_layout is declared in n00b.h for the same reason.
/// n00b_gc_scan_cb_type_layout (length-derived) is likewise declared in n00b.h.

// D-049 link-time type->GC-map dictionary (STATIC, post-link table). ncc emits
// per-TU pointer-bearing `n00b_gc_type_map_entry_t` records into `n00b_gcmap`
// and no-pointer index records into `n00b_gcidx`; a post-link pass fills/sorts
// only the index. `_n00b_alloc_raw` calls `n00b_gc_type_map_lookup`, which
// BINARY-SEARCHES that self-located index to upgrade DEFAULT-scanned typed
// allocations to a precise CALLBACK scan. No runtime table is built. A
// missing/empty/unindexed table degrades safely to nullptr -> DEFAULT scan.
// The descriptor's `count` is ignored (the scan derives it from alloc length).
extern const n00b_gc_struct_layout_t *n00b_gc_type_map_lookup(uint64_t type_hash);
extern uint64_t n00b_gc_type_map_hash_for_layout(const n00b_gc_struct_layout_t *layout);

// Runtime (dynamic) registration side of the type->GC-map dictionary. MIR-JIT
// class/tuple layouts are computed at C-runtime (when the n00b compiler runs),
// so they cannot live in the link-time `n00b_gcmap` sections; register them
// here keyed by the class typehash. `n00b_gc_type_map_lookup` consults the
// static sections first, then this registry, so a registered n00b object both
// scans precisely (alloc.c DEFAULT->CALLBACK upgrade) and marshals like a C
// struct. The registry is process-lifetime, never freed, and never traced by
// the GC; GC marking does not consult it (the scan callback uses the layout
// pointer resolved at allocation time). `layout` must outlive every instance.
// Registration is idempotent on `type_hash` (first registration wins).
extern void n00b_gc_type_map_register(uint64_t                       type_hash,
                                      const n00b_gc_struct_layout_t *layout);

// Initialize the runtime registry's lock. Called once during runtime startup
// (after the system pool is up), before any registration or instance alloc.
extern void n00b_gc_type_map_init(void);
// N00B_GC_TYPE_MAP_SECTION (the section attribute used to emit entries) is
// defined in the umbrella n00b.h so ncc-generated code can reference it there.
