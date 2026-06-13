#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/gc_map.h"
#include "core/alloc.h"   // registry table via n00b_alloc_array on system_pool
#include "core/mutex.h"   // dyn_lock (n00b_sys_mutex)
#include "core/runtime.h" // n00b_system_allocator()

#include <stdatomic.h>
#include <stdint.h>

// D-049 link-time type->GC-map dictionary, lookup side.
//
// ncc emits, per TU, pointer-bearing `n00b_gc_type_map_entry_t {type_hash,
// layout}` records into the `n00b_gcmap` linker section and no-pointer
// `n00b_gc_type_map_index_entry_t {type_hash, entry_index}` placeholders into
// `n00b_gcidx`. A post-link pass fills/sorts only `n00b_gcidx`, leaving the
// relocated pointer slots in `n00b_gcmap` untouched. This matters on Mach-O
// with chained fixups: moving pointer words after link can corrupt fixup-chain
// metadata and invalidate the code signature.
//
// Runtime lookup binary-searches the sorted index and then indexes into the
// original relocated map section. Nothing is built at runtime; a missing,
// empty, or unindexed `n00b_gcidx` yields no match and the allocation keeps its
// conservative DEFAULT scan.
//
// NOTE (single-image assumption): libn00b links statically, so all emitted
// entries land in the main executable's `n00b_gcmap` section. If libn00b ever
// ships as a shared object, this must iterate loaded images like
// src/core/static_objects.c rather than reading only the main image.

static const n00b_gc_type_map_entry_t *gcmap_start = nullptr;
static uint64_t                        gcmap_count = 0;
static const n00b_gc_type_map_index_entry_t *gcidx_start = nullptr;
static uint64_t                              gcidx_count = 0;
static bool                            gcmap_inited = false;
static bool                            gcidx_usable = false;

static bool
gcidx_validate(void)
{
    if (gcmap_start == nullptr || gcidx_start == nullptr || gcmap_count == 0
        || gcidx_count != gcmap_count) {
        return false;
    }

    for (uint64_t i = 0; i < gcidx_count; i++) {
        n00b_gc_type_map_index_entry_t cur = gcidx_start[i];

        if (cur.entry_index >= gcmap_count) {
            return false;
        }
        if (cur.type_hash != gcmap_start[cur.entry_index].type_hash) {
            return false;
        }
        if (i == 0) {
            continue;
        }

        n00b_gc_type_map_index_entry_t prev = gcidx_start[i - 1];
        if (prev.type_hash > cur.type_hash) {
            return false;
        }
        if (prev.type_hash == cur.type_hash
            && prev.entry_index > cur.entry_index) {
            return false;
        }
    }

    return true;
}

#if defined(__APPLE__)
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>

static void
gcmap_locate(void)
{
    if (gcmap_inited) {
        return;
    }
    unsigned long size = 0;
    uint8_t      *p    = getsectiondata(&_mh_execute_header,
                                   "__DATA",
                                   "n00b_gcmap",
                                   &size);
    gcmap_start  = (const n00b_gc_type_map_entry_t *)p;
    gcmap_count  = p != nullptr
                     ? (uint64_t)(size / sizeof(n00b_gc_type_map_entry_t))
                     : 0;
    p            = getsectiondata(&_mh_execute_header,
                       "__DATA",
                       "n00b_gcidx",
                       &size);
    gcidx_start  = (const n00b_gc_type_map_index_entry_t *)p;
    gcidx_count  = p != nullptr
                     ? (uint64_t)(size
                                  / sizeof(n00b_gc_type_map_index_entry_t))
                     : 0;
    gcidx_usable = gcidx_validate();
    gcmap_inited = true;
}

#elif defined(_WIN32)
// TODO(D-049): locate the n00bg$/n00bi$ bracketed sections on Windows. Until
// then the table is treated as empty (typed allocs keep DEFAULT scan).
static void
gcmap_locate(void)
{
    gcmap_inited = true;
}

#else
// ELF: the linker synthesizes __start_/__stop_ symbols for a section whose
// name is a valid C identifier.
extern const n00b_gc_type_map_entry_t __start_n00b_gcmap[] __attribute__((weak));
extern const n00b_gc_type_map_entry_t __stop_n00b_gcmap[] __attribute__((weak));
extern const n00b_gc_type_map_index_entry_t __start_n00b_gcidx[] __attribute__((weak));
extern const n00b_gc_type_map_index_entry_t __stop_n00b_gcidx[] __attribute__((weak));

static void
gcmap_locate(void)
{
    if (gcmap_inited) {
        return;
    }
    gcmap_start = __start_n00b_gcmap;
    gcmap_count = (__start_n00b_gcmap != nullptr
                   && __stop_n00b_gcmap != nullptr)
                    ? (uint64_t)(__stop_n00b_gcmap - __start_n00b_gcmap)
                    : 0;
    gcidx_start = __start_n00b_gcidx;
    gcidx_count = (__start_n00b_gcidx != nullptr
                   && __stop_n00b_gcidx != nullptr)
                    ? (uint64_t)(__stop_n00b_gcidx - __start_n00b_gcidx)
                    : 0;
    gcidx_usable = gcidx_validate();
    gcmap_inited = true;
}
#endif

// ── Runtime (dynamic) type->layout registry ──────────────────────────────
//
// MIR-JIT class/tuple layouts are computed when the n00b compiler runs (C
// runtime), so they cannot land in the link-time n00b_gcmap sections above.
// They register here. The table is a sorted-by-type_hash array allocated from
// the runtime system_pool (hidden + non-GC: it must never be traced or moved,
// and it outlives every instance). It grows by doubling; superseded arrays are
// left in the pool (never freed), bounded at ~2x the live size. GC marking does
// NOT consult this table -- the scan callback uses the layout pointer resolved
// at allocation time and stored in OOB metadata -- so lookups happen only on
// the mutator allocation path (alloc.c DEFAULT->CALLBACK upgrade) and the
// marshal path. dyn_count is atomic so the common "registry empty / no match"
// case takes no lock; all table access is otherwise under dyn_lock.
typedef struct {
    uint64_t                       type_hash;
    const n00b_gc_struct_layout_t *layout;
} _n00b_dyn_type_entry_t;

static _n00b_dyn_type_entry_t *dyn_entries = nullptr;
static _Atomic uint64_t        dyn_count   = 0;
static uint64_t                dyn_cap     = 0;
static n00b_mutex_t            dyn_lock;

// Called once during runtime startup (after system_pool is up), before any
// registration or instance allocation.
void
n00b_gc_type_map_init(void)
{
    n00b_sys_mutex_init(&dyn_lock, N00B_LOC_STRING());
}

// Binary search the sorted dynamic table over [0, count). Returns the index of
// type_hash if present, else the insertion point. Caller holds dyn_lock.
static uint64_t
dyn_search_locked(uint64_t type_hash, uint64_t count, bool *found)
{
    uint64_t lo = 0;
    uint64_t hi = count;

    while (lo < hi) {
        uint64_t mid = lo + ((hi - lo) / 2);
        uint64_t key = dyn_entries[mid].type_hash;

        if (key < type_hash) {
            lo = mid + 1;
        }
        else if (key > type_hash) {
            hi = mid;
        }
        else {
            *found = true;
            return mid;
        }
    }

    *found = false;
    return lo;
}

const n00b_gc_struct_layout_t *
n00b_gc_type_map_lookup(uint64_t type_hash)
{
    if (type_hash == 0) {
        return nullptr;
    }

    gcmap_locate();

    // 1. Static link-time table (immutable; lock-free binary search).
    if (gcidx_usable) {
        uint64_t lo = 0;
        uint64_t hi = gcidx_count;

        while (lo < hi) {
            uint64_t mid = lo + ((hi - lo) / 2);
            uint64_t key = gcidx_start[mid].type_hash;

            if (key < type_hash) {
                lo = mid + 1;
            }
            else if (key > type_hash) {
                hi = mid;
            }
            else {
                uint64_t entry_index = gcidx_start[mid].entry_index;
                return gcmap_start[entry_index].layout;
            }
        }
    }

    // 2. Runtime registry (MIR-JIT class layouts). Empty registry = no lock.
    if (atomic_load_explicit(&dyn_count, memory_order_acquire) == 0) {
        return nullptr;
    }

    const n00b_gc_struct_layout_t *result = nullptr;
    n00b_mutex_lock(&dyn_lock);
    uint64_t count = atomic_load_explicit(&dyn_count, memory_order_relaxed);
    bool     found = false;
    uint64_t idx   = dyn_search_locked(type_hash, count, &found);
    if (found) {
        result = dyn_entries[idx].layout;
    }
    n00b_mutex_unlock(&dyn_lock);

    return result;
}

void
n00b_gc_type_map_register(uint64_t                       type_hash,
                          const n00b_gc_struct_layout_t *layout)
{
    if (type_hash == 0 || layout == nullptr) {
        return;
    }

    n00b_mutex_lock(&dyn_lock);

    uint64_t count = atomic_load_explicit(&dyn_count, memory_order_relaxed);
    bool     found = false;
    uint64_t idx   = dyn_search_locked(type_hash, count, &found);
    if (found) {
        // Idempotent: first registration for a type wins.
        n00b_mutex_unlock(&dyn_lock);
        return;
    }

    if (count == dyn_cap) {
        uint64_t newcap = dyn_cap ? dyn_cap * 2 : 16;
        // system_pool: hidden + non-GC, never freed (the superseded array is
        // left behind, bounded at ~2x by the doubling).
        _n00b_dyn_type_entry_t *grown = n00b_alloc_array(
            _n00b_dyn_type_entry_t,
            newcap,
            .allocator = n00b_system_allocator());
        for (uint64_t i = 0; i < count; i++) {
            grown[i] = dyn_entries[i];
        }
        dyn_entries = grown;
        dyn_cap     = newcap;
    }

    for (uint64_t i = count; i > idx; i--) {
        dyn_entries[i] = dyn_entries[i - 1];
    }
    dyn_entries[idx].type_hash = type_hash;
    dyn_entries[idx].layout    = layout;
    atomic_store_explicit(&dyn_count, count + 1, memory_order_release);

    n00b_mutex_unlock(&dyn_lock);
}

uint64_t
n00b_gc_type_map_hash_for_layout(const n00b_gc_struct_layout_t *layout)
{
    if (layout == nullptr) {
        return 0;
    }

    gcmap_locate();

    // Static link-time table.
    if (gcmap_start != nullptr && gcmap_count != 0) {
        for (uint64_t i = 0; i < gcmap_count; i++) {
            if (gcmap_start[i].layout == layout) {
                return gcmap_start[i].type_hash;
            }
        }
    }

    // Runtime registry (MIR-JIT class layouts). Empty registry = no lock.
    if (atomic_load_explicit(&dyn_count, memory_order_acquire) == 0) {
        return 0;
    }

    uint64_t result = 0;
    n00b_mutex_lock(&dyn_lock);
    uint64_t count = atomic_load_explicit(&dyn_count, memory_order_relaxed);
    for (uint64_t i = 0; i < count; i++) {
        if (dyn_entries[i].layout == layout) {
            result = dyn_entries[i].type_hash;
            break;
        }
    }
    n00b_mutex_unlock(&dyn_lock);

    return result;
}
