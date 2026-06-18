/**
 * @file alloc_mdata.h
 * @brief Allocation metadata structures.
 *
 * Common memory layout for managed memory and descriptor-backed static
 * objects. Includes inline headers, out-of-band headers, and allocation info
 * queries.
 */
#pragma once
#include "n00b.h"
#include "core/align.h"
#include "adt/option.h"

#define N00B_FORCED_ALIGNMENT N00B_ALIGN

typedef uint64_t n00b_alloc_type_info_t;

#define n00b_core_alloc_info_fields                                                            \
    n00b_alloc_type_info_t tinfo;                                                              \
    uint32_t               alloc_len;                                                          \
    uint32_t               ptr_words;                                                          \
    uint32_t               ptr_words_known : 1;                                                \
    uint32_t               is_array        : 1;                                                \
    uint32_t               no_scan         : 1;                                                \
    uint32_t               mem_debug       : 1;                                                \
    uint32_t               mem_debug_taint : 1;                                                \
    uint32_t               moved           : 1;                                                \
    /* Per-allocation GC scan shape; see core/gc_map.h.                                        \
     * 3 bits covers DEFAULT (0) through CALLBACK (4) with room. */                            \
    uint32_t               scan_kind       : 3;                                                \
    n00b_gc_scan_cb_t      scan_cb;                                                            \
    void                  *scan_user;                                                          \
    n00b_uint128_t         cached_hash

// The header is inline with allocations, and is used when we don't
// have a dynamic record, such as when unmarshaling or for static
// data.
struct n00b_inline_hdr_t {
    uint64_t guard;
    n00b_core_alloc_info_fields;
    alignas(N00B_FORCED_ALIGNMENT) uint64_t data[0];
};

// The dynamic record, which is kept out of band for safety, and thus
// is the prefered source of info when available.
struct n00b_oob_hdr_t {
    void *user_ptr;               // Pointer to the user-returned value.
    n00b_core_alloc_info_fields;  // Authoritative data.
    n00b_inline_hdr_t *hcur;      // Pointer to the guard / inline info.
    const char        *file_name; // file and line info.
    // Per-allocation finalizer slot. Lives only in the OOB record
    // — the inline header stays tight because it doubles as the
    // marshal payload and any new field there would break the
    // serialised format. n00b_add_finalizer uses this storage when
    // n00b_find_alloc_info returns an OOB record (i.e. the pool was
    // initialised with external_metadata=true). Pools without OOB
    // records fall back to rt->finalizers list keyed on the user
    // pointer.
    n00b_finalizer_t   finalizer;
    void              *finalizer_user;
    // Per-allocation liveness + GC epoch tracking.
    //
    // `alive` is set by the alloc path and cleared in the free path;
    // it is the source of truth for "this pool slot is currently
    // handed out". The GC mark walks every metadata-bearing pool's
    // metadata dict, treats every alive alloc as a root, and stamps
    // `gc_epoch` to the current runtime epoch on each alloc it
    // reaches. After mark, a second pass over the dict checks
    // `alive && gc_epoch != current` — those are leaks: handed out,
    // never reached. They are returned to the pool (alive cleared,
    // memory released); if the runtime's debug-leak flag is set the
    // file_name + tinfo + alloc_len are printed first.
    //
    // The bitfield reserves room for future per-OOB scratch flags
    // without needing another header edit. A uint64_t storage unit (rather
    // than uint8_t) keeps the fixed portion ending on an 8-byte boundary so
    // the flex tail below is naturally aligned for word-sized atomics — see
    // the static_assert after the struct.
    uint64_t           gc_epoch;
    uint64_t           alive    : 1;
    uint64_t           reserved : 63;
    // Allocator-specific flex tail. Size = owning allocator's oob_extra_size;
    // the per-alloc OOB record is allocated with that many extra bytes here.
    // Holds per-alloc state such as the .alloc_refcount counter, which is
    // accessed as an _Atomic(uint32_t) — so the tail MUST be at least 4-byte
    // aligned. n00b_alloc_ref/unref do atomic RMW here; on AArch64 a misaligned
    // atomic faults (SIGBUS), so the alignment is load-bearing, not cosmetic.
    // sizeof(n00b_oob_hdr_t) excludes this, so seeding the record by value
    // (`*map_item = (n00b_oob_hdr_t){...}`) never touches it.
    uint8_t            alloc_extra[];
};

// The .alloc_refcount counter lives in alloc_extra and is accessed atomically
// as a uint32_t. A misaligned atomic is undefined behavior and faults on
// strict-alignment targets (AArch64), so pin the offset at build time.
static_assert(offsetof(struct n00b_oob_hdr_t, alloc_extra) % alignof(uint32_t) == 0,
              "n00b_oob_hdr_t.alloc_extra must be aligned for atomic refcounts");

// n00b_alloc_err means we couldn't find a record, but did find the allocator.
typedef enum {
    n00b_alloc_none,
    n00b_alloc_inline,
    n00b_alloc_oob,
    n00b_alloc_static_range,
    n00b_alloc_err,
} n00b_alloc_info_kind_t;

typedef struct n00b_alloc_info_t {
    n00b_alloc_info_kind_t kind;
    union {
        n00b_oob_hdr_t    *oob;
        n00b_inline_hdr_t *in_line;
        n00b_alloc_range_t *range;
    } hdr;
} n00b_alloc_info_t;

/**
 * @brief Extract the out-of-band header from an alloc info, if present.
 * @param info Allocation info to query.
 * @return     Optional OOB header pointer.
 */
static inline n00b_option_t(n00b_oob_hdr_t *)
n00b_alloc_info_oob(n00b_alloc_info_t info)
{
    if (info.kind != n00b_alloc_oob) {
        return n00b_option_none(n00b_oob_hdr_t *);
    }
    return n00b_option_set(n00b_oob_hdr_t *, info.hdr.oob);
}

/**
 * @brief Extract the inline header from an alloc info, if present.
 * @param info Allocation info to query.
 * @return     Optional inline header pointer.
 */
static inline n00b_option_t(n00b_inline_hdr_t *)
n00b_alloc_info_inline(n00b_alloc_info_t info)
{
    if (info.kind != n00b_alloc_inline) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }
    return n00b_option_set(n00b_inline_hdr_t *, info.hdr.in_line);
}

static inline bool
n00b_alloc_info_is_oob(n00b_alloc_info_t info)
{
    return info.kind == n00b_alloc_oob;
}

static inline bool
n00b_alloc_info_is_inline(n00b_alloc_info_t info)
{
    return info.kind == n00b_alloc_inline;
}

static inline bool
n00b_alloc_info_is_heap(n00b_alloc_info_t info)
{
    return info.kind == n00b_alloc_oob || info.kind == n00b_alloc_inline;
}

static inline bool
n00b_alloc_info_is_static_range(n00b_alloc_info_t info)
{
    return info.kind == n00b_alloc_static_range;
}

static inline n00b_option_t(n00b_alloc_range_t *)
n00b_alloc_info_static_range(n00b_alloc_info_t info)
{
    if (info.kind != n00b_alloc_static_range) {
        return n00b_option_none(n00b_alloc_range_t *);
    }
    return n00b_option_set(n00b_alloc_range_t *, info.hdr.range);
}

static inline bool
n00b_alloc_info_exists(n00b_alloc_info_t info)
{
    return info.kind != n00b_alloc_none;
}

#define N00B_ALLOC_HDR_SZ ((sizeof(n00b_inline_hdr_t) + N00B_ALIGN - 1) & ~(N00B_ALIGN - 1))
