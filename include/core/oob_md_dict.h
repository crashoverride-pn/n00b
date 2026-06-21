#pragma once
// OOB-metadata dict helpers.
//
// The per-allocator OOB metadata is a typed dict whose key is the allocation
// address (void *) and whose value is its n00b_oob_hdr_t *. The dict handle is
// held as the opaque, forward-declarable _n00b_dict_internal_t * (the foun-
// dational alloc headers cannot pull adt/dict.h — dict.h -> alloc.h -> alloc_base.h
// would cycle), so call sites use the type-erased dict ops with explicit element
// sizes (exactly what the n00b_dict_* macros expand to).
//
// REQUIRES the includer to have already included "adt/dict.h" and the header
// defining n00b_oob_hdr_t ("core/alloc_mdata.h"); this header is a leaf of pure
// static inlines and intentionally does not include them itself (it is pulled
// into TUs like alloc.c / gc.c that already have both).

#define N00B_MD_KSZ ((uint32_t)sizeof(void *))
#define N00B_MD_VSZ ((uint32_t)sizeof(n00b_oob_hdr_t *))

static inline n00b_oob_hdr_t *
n00b_md_get(_n00b_dict_internal_t *md, void *ptr)
{
    // The metadata dict is copy_values: get copies the stored oob pointer into
    // `out` under the bucket lock, so the result survives a concurrent migrate
    // that frees the old store. `slot` points at `out` on success.
    bool            found = false;
    n00b_oob_hdr_t *out   = nullptr;
    void           *slot  = _n00b_dict_internal_get(md, N00B_MD_KSZ, N00B_MD_VSZ, &ptr, &out, &found);
    return (slot != nullptr && found) ? *(n00b_oob_hdr_t **)slot : nullptr;
}

static inline void
n00b_md_put(_n00b_dict_internal_t *md, void *ptr, n00b_oob_hdr_t *oob)
{
    (void)_n00b_dict_internal_put(md, N00B_MD_KSZ, N00B_MD_VSZ, &ptr, &oob);
}

static inline bool
n00b_md_remove(_n00b_dict_internal_t *md, void *ptr)
{
    return _n00b_dict_internal_remove(md, N00B_MD_KSZ, N00B_MD_VSZ, &ptr);
}
