/**
 * @file core/codegen_abi.h
 * @brief Volatile GC/marshal codegen ABI: the type->GC-map dictionary, variant
 *        scanning, and transient-field structs the GC/marshal runtime reads.
 *
 * This is the CHURN-prone slice of the codegen ABI. Under `--ncc-gcmap-prelink`
 * ncc no longer emits these typed structs into per-TU linker sections; it emits
 * raw `n00b_gcraw` records, and a link-time pass aggregates them into ONE
 * generated translation unit (`#include "core/codegen_abi.h"`) that defines the
 * typed `n00b_gcmap_table[]`. The runtime reads that table.
 *
 * Therefore NO ordinary translation unit references these structs by name, and
 * this header is NOT force-included by the build (cf. `core/codegen_abi_inject.h`,
 * which holds the stable, ncc-injected roots / stack-map / static-object slice
 * that still must be visible everywhere). Only the explicit includers below
 * pull this header, so editing it rebuilds only those — not the whole tree:
 *   - the pre-link-generated dictionary TU (emitted by ncc),
 *   - the GC/marshal runtime readers (gc_type_map.c, gc_map.c/.h, transient_map.c,
 *     alloc.c, marshal.c, slay/codegen.c, slay/symtab.h, json.c, rocs maps).
 *
 * The stable allocator scan API (n00b_gc_map_t, n00b_gc_scan_kind_t,
 * n00b_gc_scan_cb_t) lives in n00b.h — it is pervasive and never churns.
 *
 * See doc/codegen-abi-prelink-plan.md.
 */
#pragma once

#include "n00b.h"

typedef struct {
    uint64_t stride;
    uint64_t offset;
    uint64_t count;
} n00b_gc_struct_array_t;

// One alternative (arm) of a discriminated-union (n00b_variant_t) field. When
// the element's selector word equals `selector` (a typehash(T) of this arm),
// the live alternative's heap pointers are at the element-relative word offsets
// in `ptr_offsets` (sorted ascending). A single-pointer alternative has one
// offset (the value word itself); a by-value aggregate alternative has one
// offset per pointer field. Alternatives with no heap pointers are omitted.
typedef struct {
    uint64_t        selector;
    uint64_t        ptr_offset_count;
    const uint64_t *ptr_offsets;
} n00b_gc_variant_arm_t;

// One discriminated-union (n00b_variant_t) field within an element. The
// element's `selector` word at `selector_offset` (a typehash(T) of the active
// alternative, or 0 if unset) selects the live alternative; `arms` lists the
// pointer-bearing alternatives, sorted by `selector` for a binary search. Arm
// offsets are element-relative, so the scanner marks `base + ptr_offsets[k]`
// directly. `selector_offset` is a word offset from the start of the element.
typedef struct {
    uint64_t                     selector_offset;
    uint64_t                     arm_count;
    const n00b_gc_variant_arm_t *arms;
} n00b_gc_variant_field_t;

// Tagged (not anonymous) so pervasive headers that only pass it by pointer
// (e.g. core/gc_map.h) can forward-declare it without pulling in this header.
typedef struct n00b_gc_struct_layout_t {
    uint64_t                       stride;
    uint64_t                       count;
    uint64_t                       offset_count;
    const uint64_t                *offsets;
    uint64_t                       variant_count;
    const n00b_gc_variant_field_t *variants;
} n00b_gc_struct_layout_t;

// NOTE: the scan-callback externs (n00b_gc_scan_cb_struct_field /
// _struct_layout / _type_layout) live in core/codegen_abi_inject.h — they are
// referenced by name in ncc-emitted static-object descriptors (`.scan_cb=...`)
// in arbitrary TUs, so they must be force-included, not pulled in here.

// D-049 link-time type->GC-map dictionary entry. ncc emits, per TU, a static
// const array of these (one per pointer-bearing aggregate type) into a linker
// section (the static table — laid out by the linker, no runtime assembly).
// The runtime reads the section directly; nothing is built dynamically.
typedef struct n00b_gc_type_map_entry_t {
    uint64_t                       type_hash; // typehash(T *)
    const n00b_gc_struct_layout_t *layout;    // per-element pointer offsets
} n00b_gc_type_map_entry_t;

// Post-link index entry for n00b_gcmap. This section intentionally carries no
// pointers so a post-link pass can sort/fill it without moving chained-fixup
// metadata on Mach-O.
typedef struct n00b_gc_type_map_index_entry_t {
    uint64_t type_hash;   // typehash(T *)
    uint64_t entry_index; // index into n00b_gcmap
} n00b_gc_type_map_index_entry_t;

// Pre-link-aggregated type->GC-map dictionary (ncc --ncc-gcmap-prelink). The
// build's aggregation step emits a single generated TU defining this
// sorted-by-type_hash table + its count; the runtime binary-searches it directly
// (gc_type_map.c). Every target that links libn00b also links this generated
// object, so the symbols are always defined (the object defines an EMPTY table
// with count==0 when no records were aggregated, in which case the runtime falls
// back to conservative scanning, which is GC-safe). `weak` is kept as belt-and-
// suspenders so a duplicate definition would coalesce rather than collide.
extern const n00b_gc_type_map_entry_t n00b_gcmap_table[] __attribute__((weak));
extern const unsigned long            n00b_gcmap_count __attribute__((weak));

// NOTE: the WP-001 transient-field structs (n00b_transient_layout_t,
// n00b_transient_map_entry_t, _index_entry_t) and the N00B_TRANSIENT_MAP_SECTION
// macros live in core/codegen_abi_inject.h. ncc still emits them TYPED (the
// transient path is not raw-ified), into the few TUs that define a
// [[n00b::transient]] field, so they must be force-included like the static-
// object descriptors. They are stable (WP-001 is settled), so this does not
// reintroduce broad churn.

// Section attribute for emitting gc-map entries. Referenced by ncc-generated
// code, which reaches it through this header (the runtime readers). In the typed
// (non-prelink) gcmap path these would be needed by every aggregate-defining TU,
// but the n00b build uses --ncc-gcmap-prelink (raw n00b_gcraw emission), so no
// ordinary TU references these macros — only the runtime readers do.
#if defined(__APPLE__)
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("__DATA,n00b_gcmap"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("__DATA,n00b_gcidx"), gnu::used]]
#elif defined(_WIN32)
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("n00bg$m"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("n00bi$m"), gnu::used]]
#else
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("n00b_gcmap"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("n00b_gcidx"), gnu::used]]
#endif
