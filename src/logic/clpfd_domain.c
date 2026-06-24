#include "logic/clpfd_domain.h"
#include "n00b.h"
#include "core/alloc.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int
cmp_i64(const void *a, const void *b)
{
    int64_t va = *(const int64_t *)a;
    int64_t vb = *(const int64_t *)b;

    return (va > vb) - (va < vb);
}

static int
popcount64(uint64_t x)
{
    return __builtin_popcountll(x);
}

static int
ctz64(uint64_t x)
{
    return __builtin_ctzll(x);
}

static int
clz64(uint64_t x)
{
    return __builtin_clzll(x);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

n00b_csp_domain_t
n00b_csp_dom_range(int64_t lo, int64_t hi)
{
    if (lo > hi) {
        return n00b_variant_empty(n00b_csp_domain_t);
    }

    return n00b_variant_set(n00b_csp_domain_t,
                            n00b_csp_dom_interval_t,
                            ((n00b_csp_dom_interval_t){
                                .lo = lo,
                                .hi = hi,
                            }));
}

n00b_csp_domain_t
n00b_csp_dom_singleton(int64_t val)
{
    return n00b_csp_dom_range(val, val);
}

n00b_csp_domain_t
n00b_csp_dom_from_values(const int64_t *vals, int32_t count)
{
    if (count <= 0) {
        return n00b_variant_empty(n00b_csp_domain_t);
    }

    // Copy and sort.
    int64_t *sorted = n00b_alloc_array(int64_t, count);
    memcpy(sorted, vals, count * sizeof(int64_t));
    qsort(sorted, count, sizeof(int64_t), cmp_i64);

    // Deduplicate.
    int32_t unique = 1;

    for (int32_t i = 1; i < count; i++) {
        if (sorted[i] != sorted[unique - 1]) {
            sorted[unique++] = sorted[i];
        }
    }

    // Check if it's a contiguous interval.
    if (sorted[unique - 1] - sorted[0] == unique - 1) {
        int64_t lo = sorted[0];
        int64_t hi = sorted[unique - 1];
        n00b_free(sorted);
        return n00b_csp_dom_range(lo, hi);
    }

    // Check if bitset representation works (range <= 64).
    int64_t range = sorted[unique - 1] - sorted[0] + 1;

    if (range <= 64) {
        n00b_csp_dom_bitset_t bs = {
            .base = sorted[0],
            .bits = 0,
        };

        for (int32_t i = 0; i < unique; i++) {
            bs.bits |= (uint64_t)1 << (sorted[i] - sorted[0]);
        }

        n00b_free(sorted);
        return n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_bitset_t, bs);
    }

    // Sparse.
    return n00b_variant_set(n00b_csp_domain_t,
                            n00b_csp_dom_sparse_t,
                            ((n00b_csp_dom_sparse_t){
                                .values = sorted,
                                .count  = unique,
                                .cap    = count,
                            }));
}

n00b_csp_domain_t
n00b_csp_dom_empty(void)
{
    return n00b_variant_empty(n00b_csp_domain_t);
}

n00b_csp_domain_t
n00b_csp_dom_clone(const n00b_csp_domain_t *d)
{
    n00b_csp_domain_t c = *d;

    if (n00b_variant_is_type(*d, n00b_csp_dom_sparse_t)) {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);

        if (sp.values) {
            int64_t *copy = n00b_alloc_array(int64_t, sp.count);
            memcpy(copy, sp.values, sp.count * sizeof(int64_t));
            c = n00b_variant_set(n00b_csp_domain_t,
                                 n00b_csp_dom_sparse_t,
                                 ((n00b_csp_dom_sparse_t){
                                     .values = copy,
                                     .count  = sp.count,
                                     .cap    = sp.count,
                                 }));
        }
    }

    return c;
}

void
n00b_csp_dom_free(n00b_csp_domain_t *d)
{
    if (n00b_variant_is_type(*d, n00b_csp_dom_sparse_t)) {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        n00b_free(sp.values);
    }

    *d = n00b_variant_empty(n00b_csp_domain_t);
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

int64_t
n00b_csp_dom_min(const n00b_csp_domain_t *d)
{
    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t):
        return n00b_variant_get(*d, n00b_csp_dom_interval_t).lo;
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs = n00b_variant_get(*d, n00b_csp_dom_bitset_t);
        return bs.base + ctz64(bs.bits);
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        return sp.count > 0 ? sp.values[0] : 0;
    }
    default: // empty
        return 0;
    }
}

int64_t
n00b_csp_dom_max(const n00b_csp_domain_t *d)
{
    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t):
        return n00b_variant_get(*d, n00b_csp_dom_interval_t).hi;
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs = n00b_variant_get(*d, n00b_csp_dom_bitset_t);
        return bs.base + (63 - clz64(bs.bits));
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        return sp.count > 0 ? sp.values[sp.count - 1] : 0;
    }
    default: // empty
        return 0;
    }
}

int64_t
n00b_csp_dom_size(const n00b_csp_domain_t *d)
{
    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        return iv.hi - iv.lo + 1;
    }
    case typehash(n00b_csp_dom_bitset_t):
        return popcount64(n00b_variant_get(*d, n00b_csp_dom_bitset_t).bits);
    case typehash(n00b_csp_dom_sparse_t):
        return n00b_variant_get(*d, n00b_csp_dom_sparse_t).count;
    default: // empty
        return 0;
    }
}

bool
n00b_csp_dom_is_singleton(const n00b_csp_domain_t *d)
{
    return n00b_csp_dom_size(d) == 1;
}

bool
n00b_csp_dom_is_empty(const n00b_csp_domain_t *d)
{
    return !n00b_variant_is_set(*d)
           || (n00b_variant_is_type(*d, n00b_csp_dom_bitset_t)
               && n00b_variant_get(*d, n00b_csp_dom_bitset_t).bits == 0)
           || (n00b_variant_is_type(*d, n00b_csp_dom_sparse_t)
               && n00b_variant_get(*d, n00b_csp_dom_sparse_t).count == 0);
}

bool
n00b_csp_dom_contains(const n00b_csp_domain_t *d, int64_t val)
{
    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        return val >= iv.lo && val <= iv.hi;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs     = n00b_variant_get(*d,
                                                    n00b_csp_dom_bitset_t);
        int64_t               offset = val - bs.base;

        if (offset < 0 || offset > 63) {
            return false;
        }

        return (bs.bits >> offset) & 1;
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        int32_t               lo = 0, hi = sp.count - 1;

        while (lo <= hi) {
            int32_t mid = lo + (hi - lo) / 2;

            if (sp.values[mid] == val) {
                return true;
            }

            if (sp.values[mid] < val) {
                lo = mid + 1;
            }
            else {
                hi = mid - 1;
            }
        }

        return false;
    }
    default: // empty
        return false;
    }
}

// ---------------------------------------------------------------------------
// Interval -> bitset/sparse promotion
// ---------------------------------------------------------------------------

static n00b_csp_domain_t
interval_to_bitset(int64_t lo, int64_t hi)
{
    n00b_csp_dom_bitset_t bs = {
        .base = lo,
        .bits = 0,
    };

    for (int64_t v = lo; v <= hi; v++) {
        bs.bits |= (uint64_t)1 << (v - lo);
    }

    return n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_bitset_t, bs);
}

static n00b_csp_domain_t
interval_to_sparse(int64_t lo, int64_t hi)
{
    int32_t               count = (int32_t)(hi - lo + 1);
    n00b_csp_dom_sparse_t sp     = {
            .values = n00b_alloc_array(int64_t, count),
            .count  = count,
            .cap    = count,
    };

    for (int32_t i = 0; i < count; i++) {
        sp.values[i] = lo + i;
    }

    return n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_sparse_t, sp);
}

// ---------------------------------------------------------------------------
// Narrowing
// ---------------------------------------------------------------------------

bool
n00b_csp_dom_intersect(n00b_csp_domain_t *d, const n00b_csp_domain_t *other)
{
    if (!n00b_variant_is_set(*d)) {
        return false;
    }

    if (!n00b_variant_is_set(*other)) {
        n00b_csp_dom_free(d);
        *d = n00b_variant_empty(n00b_csp_domain_t);
        return true;
    }

    // Interval ∩ Interval
    if (n00b_variant_is_type(*d, n00b_csp_dom_interval_t)
        && n00b_variant_is_type(*other, n00b_csp_dom_interval_t)) {
        n00b_csp_dom_interval_t di = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        n00b_csp_dom_interval_t oi = n00b_variant_get(*other,
                                                      n00b_csp_dom_interval_t);
        int64_t new_lo = di.lo > oi.lo ? di.lo : oi.lo;
        int64_t new_hi = di.hi < oi.hi ? di.hi : oi.hi;

        if (new_lo > new_hi) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        bool changed = (new_lo != di.lo || new_hi != di.hi);
        *d           = n00b_variant_set(n00b_csp_domain_t,
                              n00b_csp_dom_interval_t,
                              ((n00b_csp_dom_interval_t){
                                            .lo = new_lo,
                                            .hi = new_hi,
                              }));

        return changed;
    }

    // Bitset ∩ Bitset (possibly different bases)
    if (n00b_variant_is_type(*d, n00b_csp_dom_bitset_t)
        && n00b_variant_is_type(*other, n00b_csp_dom_bitset_t)) {
        n00b_csp_dom_bitset_t db = n00b_variant_get(*d, n00b_csp_dom_bitset_t);
        n00b_csp_dom_bitset_t ob = n00b_variant_get(*other,
                                                    n00b_csp_dom_bitset_t);
        int64_t d_max      = db.base + 63;
        int64_t o_max      = ob.base + 63;
        int64_t overlap_lo = db.base > ob.base ? db.base : ob.base;
        int64_t overlap_hi = d_max < o_max ? d_max : o_max;

        if (overlap_lo > overlap_hi) {
            uint64_t old = db.bits;
            *d           = n00b_variant_empty(n00b_csp_domain_t);
            return old != 0;
        }

        uint64_t d_shifted = db.bits >> (overlap_lo - db.base);
        uint64_t o_shifted = ob.bits >> (overlap_lo - ob.base);

        int64_t  range = overlap_hi - overlap_lo + 1;
        uint64_t mask =
            range >= 64 ? ~(uint64_t)0 : ((uint64_t)1 << range) - 1;

        uint64_t new_bits = d_shifted & o_shifted & mask;
        bool changed = (new_bits != db.bits || overlap_lo != db.base);

        if (new_bits == 0) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
        }
        else {
            *d = n00b_variant_set(n00b_csp_domain_t,
                                  n00b_csp_dom_bitset_t,
                                  ((n00b_csp_dom_bitset_t){
                                      .base = overlap_lo,
                                      .bits = new_bits,
                                  }));
        }

        return changed;
    }

    // General case: build result via membership test.
    // Collect values from d that are also in other using a dynamic buffer.
    int64_t *tmp       = nullptr;
    int32_t  tmp_count = 0;
    int32_t  tmp_cap   = 0;

    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        for (int64_t v = iv.lo; v <= iv.hi; v++) {
            if (n00b_csp_dom_contains(other, v)) {
                if (tmp_count >= tmp_cap) {
                    int32_t  new_cap = tmp_cap ? tmp_cap * 2 : 16;
                    int64_t *new_tmp = n00b_alloc_array(int64_t, new_cap);
                    if (tmp_count > 0) {
                        memcpy(new_tmp, tmp, tmp_count * sizeof(int64_t));
                    }
                    n00b_free(tmp);
                    tmp     = new_tmp;
                    tmp_cap = new_cap;
                }
                tmp[tmp_count++] = v;
            }
        }
        break;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs = n00b_variant_get(*d, n00b_csp_dom_bitset_t);
        for (uint64_t bits = bs.bits; bits;) {
            int     bit = ctz64(bits);
            int64_t v   = bs.base + bit;

            if (n00b_csp_dom_contains(other, v)) {
                if (tmp_count >= tmp_cap) {
                    int32_t  new_cap = tmp_cap ? tmp_cap * 2 : 16;
                    int64_t *new_tmp = n00b_alloc_array(int64_t, new_cap);
                    if (tmp_count > 0) {
                        memcpy(new_tmp, tmp, tmp_count * sizeof(int64_t));
                    }
                    n00b_free(tmp);
                    tmp     = new_tmp;
                    tmp_cap = new_cap;
                }
                tmp[tmp_count++] = v;
            }

            bits &= bits - 1;
        }
        break;
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        for (int32_t i = 0; i < sp.count; i++) {
            if (n00b_csp_dom_contains(other, sp.values[i])) {
                if (tmp_count >= tmp_cap) {
                    int32_t  new_cap = tmp_cap ? tmp_cap * 2 : 16;
                    int64_t *new_tmp = n00b_alloc_array(int64_t, new_cap);
                    if (tmp_count > 0) {
                        memcpy(new_tmp, tmp, tmp_count * sizeof(int64_t));
                    }
                    n00b_free(tmp);
                    tmp     = new_tmp;
                    tmp_cap = new_cap;
                }
                tmp[tmp_count++] = sp.values[i];
            }
        }
        break;
    }
    default:
        break;
    }

    int64_t old_size = n00b_csp_dom_size(d);
    n00b_csp_dom_free(d);

    if (tmp_count == 0) {
        n00b_free(tmp);
        *d = n00b_variant_empty(n00b_csp_domain_t);
        return old_size > 0;
    }

    *d = n00b_csp_dom_from_values(tmp, tmp_count);
    n00b_free(tmp);

    return tmp_count != old_size;
}

bool
n00b_csp_dom_remove_value(n00b_csp_domain_t *d, int64_t val)
{
    if (!n00b_csp_dom_contains(d, val)) {
        return false;
    }

    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        if (val == iv.lo && val == iv.hi) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        if (val == iv.lo) {
            iv.lo++;
            *d = n00b_variant_set(n00b_csp_domain_t,
                                  n00b_csp_dom_interval_t,
                                  iv);
            return true;
        }

        if (val == iv.hi) {
            iv.hi--;
            *d = n00b_variant_set(n00b_csp_domain_t,
                                  n00b_csp_dom_interval_t,
                                  iv);
            return true;
        }

        // Hole in the middle — promote to bitset or sparse.
        int64_t range = iv.hi - iv.lo + 1;

        if (range <= 64) {
            *d = interval_to_bitset(iv.lo, iv.hi);
            n00b_csp_dom_bitset_t bs = n00b_variant_get(*d,
                                                        n00b_csp_dom_bitset_t);
            bs.bits &= ~((uint64_t)1 << (val - bs.base));
            *d = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_bitset_t, bs);
            return true;
        }

        *d = interval_to_sparse(iv.lo, iv.hi);
        // Fall through to sparse removal.
    }
        [[fallthrough]];
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp     = n00b_variant_get(*d,
                                                    n00b_csp_dom_sparse_t);
        int32_t               lo_idx = 0, hi_idx = sp.count - 1;

        while (lo_idx <= hi_idx) {
            int32_t mid = lo_idx + (hi_idx - lo_idx) / 2;

            if (sp.values[mid] == val) {
                memmove(&sp.values[mid],
                        &sp.values[mid + 1],
                        (sp.count - mid - 1) * sizeof(int64_t));
                sp.count--;

                if (sp.count == 0) {
                    *d = n00b_variant_empty(n00b_csp_domain_t);
                }
                else {
                    *d = n00b_variant_set(n00b_csp_domain_t,
                                          n00b_csp_dom_sparse_t,
                                          sp);
                }

                return true;
            }

            if (sp.values[mid] < val) {
                lo_idx = mid + 1;
            }
            else {
                hi_idx = mid - 1;
            }
        }

        return false;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs     = n00b_variant_get(*d,
                                                    n00b_csp_dom_bitset_t);
        int64_t               offset = val - bs.base;
        bs.bits &= ~((uint64_t)1 << offset);

        if (bs.bits == 0) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
        }
        else {
            *d = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_bitset_t, bs);
        }

        return true;
    }
    default: // empty
        return false;
    }
}

bool
n00b_csp_dom_restrict_min(n00b_csp_domain_t *d, int64_t new_min)
{
    if (n00b_csp_dom_is_empty(d)) {
        return false;
    }

    int64_t cur_min = n00b_csp_dom_min(d);

    if (new_min <= cur_min) {
        return false;
    }

    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        if (new_min > iv.hi) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        iv.lo = new_min;
        *d    = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_interval_t, iv);
        return true;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs     = n00b_variant_get(*d,
                                                    n00b_csp_dom_bitset_t);
        int64_t               offset = new_min - bs.base;

        if (offset > 63) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        if (offset > 0) {
            uint64_t mask = ~(((uint64_t)1 << offset) - 1);
            uint64_t old  = bs.bits;
            bs.bits &= mask;

            if (bs.bits == 0) {
                *d = n00b_variant_empty(n00b_csp_domain_t);
            }
            else {
                *d = n00b_variant_set(n00b_csp_domain_t,
                                      n00b_csp_dom_bitset_t,
                                      bs);
            }

            return bs.bits != old;
        }

        return false;
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        int32_t               i  = 0;

        while (i < sp.count && sp.values[i] < new_min) {
            i++;
        }

        if (i == sp.count) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        if (i > 0) {
            memmove(sp.values,
                    &sp.values[i],
                    (sp.count - i) * sizeof(int64_t));
            sp.count -= i;
            *d = n00b_variant_set(n00b_csp_domain_t,
                                  n00b_csp_dom_sparse_t,
                                  sp);
            return true;
        }

        return false;
    }
    default:
        return false;
    }
}

bool
n00b_csp_dom_restrict_max(n00b_csp_domain_t *d, int64_t new_max)
{
    if (n00b_csp_dom_is_empty(d)) {
        return false;
    }

    int64_t cur_max = n00b_csp_dom_max(d);

    if (new_max >= cur_max) {
        return false;
    }

    switch (d->selector) {
    case typehash(n00b_csp_dom_interval_t): {
        n00b_csp_dom_interval_t iv = n00b_variant_get(*d,
                                                      n00b_csp_dom_interval_t);
        if (new_max < iv.lo) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        iv.hi = new_max;
        *d    = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_interval_t, iv);
        return true;
    }
    case typehash(n00b_csp_dom_bitset_t): {
        n00b_csp_dom_bitset_t bs     = n00b_variant_get(*d,
                                                    n00b_csp_dom_bitset_t);
        int64_t               offset = new_max - bs.base;

        if (offset < 0) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        uint64_t mask = ((uint64_t)1 << (offset + 1)) - 1;
        uint64_t old  = bs.bits;
        bs.bits &= mask;

        if (bs.bits == 0) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
        }
        else {
            *d = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_bitset_t, bs);
        }

        return bs.bits != old;
    }
    case typehash(n00b_csp_dom_sparse_t): {
        n00b_csp_dom_sparse_t sp = n00b_variant_get(*d, n00b_csp_dom_sparse_t);
        int32_t               i  = sp.count - 1;

        while (i >= 0 && sp.values[i] > new_max) {
            i--;
        }

        int32_t new_count = i + 1;

        if (new_count == 0) {
            *d = n00b_variant_empty(n00b_csp_domain_t);
            return true;
        }

        if (new_count < sp.count) {
            sp.count = new_count;
            *d = n00b_variant_set(n00b_csp_domain_t, n00b_csp_dom_sparse_t, sp);
            return true;
        }

        return false;
    }
    default:
        return false;
    }
}
