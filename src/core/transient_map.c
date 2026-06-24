#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/gc_map.h"
#include "core/codegen_abi_inject.h" // full n00b_transient_* / layout struct defs

#include <stdint.h>
#include <string.h>

// WP-001 transient-field table, lookup side. Sibling to gc_type_map.c (D-049).
//
// ncc emits, per TU, `n00b_transient_map_entry_t {type_hash, layout}` records
// into the `n00b_trmap` linker section (the byte offset + byte size of each
// [[n00b::transient]] field) and no-pointer `n00b_transient_map_index_entry_t
// {type_hash, entry_index}` placeholders into `n00b_tridx`. The post-link
// n00b-gcmap-index pass fills/sorts `n00b_tridx`.
//
// Runtime lookup binary-searches the sorted index; if the index is missing or
// not yet filled it falls back to a linear scan of `n00b_trmap` (each map entry
// carries its real type_hash, so the scan is always correct). A missing/empty
// table yields no match -> marshal does no zeroing -> byte-identical output.
//
// Single-image assumption matches gc_type_map.c: libn00b links statically, so
// all entries land in the main executable's sections.

static const n00b_transient_map_entry_t       *trmap_start  = nullptr;
static uint64_t                                 trmap_count  = 0;
static const n00b_transient_map_index_entry_t  *tridx_start  = nullptr;
static uint64_t                                 tridx_count  = 0;
static bool                                     trmap_inited = false;
static bool                                     tridx_usable = false;

static bool
tridx_validate(void)
{
    if (trmap_start == nullptr || tridx_start == nullptr || trmap_count == 0
        || tridx_count != trmap_count) {
        return false;
    }

    for (uint64_t i = 0; i < tridx_count; i++) {
        n00b_transient_map_index_entry_t cur = tridx_start[i];

        if (cur.entry_index >= trmap_count) {
            return false;
        }
        if (cur.type_hash != trmap_start[cur.entry_index].type_hash) {
            return false;
        }
        if (i == 0) {
            continue;
        }
        if (tridx_start[i - 1].type_hash > cur.type_hash) {
            return false;
        }
    }

    return true;
}

#if defined(__APPLE__)
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>

static void
trmap_locate(void)
{
    if (trmap_inited) {
        return;
    }
    unsigned long size = 0;
    uint8_t      *p    = getsectiondata(&_mh_execute_header,
                                   "__DATA",
                                   "n00b_trmap",
                                   &size);
    trmap_start = (const n00b_transient_map_entry_t *)p;
    trmap_count = p != nullptr
                    ? (uint64_t)(size / sizeof(n00b_transient_map_entry_t))
                    : 0;
    p           = getsectiondata(&_mh_execute_header,
                       "__DATA",
                       "n00b_tridx",
                       &size);
    tridx_start = (const n00b_transient_map_index_entry_t *)p;
    tridx_count = p != nullptr
                    ? (uint64_t)(size
                                 / sizeof(n00b_transient_map_index_entry_t))
                    : 0;
    tridx_usable = tridx_validate();
    trmap_inited = true;
}

#elif defined(_WIN32)
// TODO: locate the n00bt$/n00bj$ bracketed sections on Windows. Until then the
// table is treated as empty (marshal does no transient zeroing).
static void
trmap_locate(void)
{
    trmap_inited = true;
}

#else
extern const n00b_transient_map_entry_t __start_n00b_trmap[] __attribute__((weak));
extern const n00b_transient_map_entry_t __stop_n00b_trmap[] __attribute__((weak));
extern const n00b_transient_map_index_entry_t __start_n00b_tridx[] __attribute__((weak));
extern const n00b_transient_map_index_entry_t __stop_n00b_tridx[] __attribute__((weak));

static void
trmap_locate(void)
{
    if (trmap_inited) {
        return;
    }
    trmap_start = __start_n00b_trmap;
    trmap_count = (__start_n00b_trmap != nullptr && __stop_n00b_trmap != nullptr)
                    ? (uint64_t)(__stop_n00b_trmap - __start_n00b_trmap)
                    : 0;
    tridx_start = __start_n00b_tridx;
    tridx_count = (__start_n00b_tridx != nullptr && __stop_n00b_tridx != nullptr)
                    ? (uint64_t)(__stop_n00b_tridx - __start_n00b_tridx)
                    : 0;
    tridx_usable = tridx_validate();
    trmap_inited = true;
}
#endif

const n00b_transient_layout_t *
n00b_transient_map_lookup(uint64_t type_hash)
{
    if (type_hash == 0) {
        return nullptr;
    }

    trmap_locate();

    if (tridx_usable) {
        uint64_t lo = 0;
        uint64_t hi = tridx_count;

        while (lo < hi) {
            uint64_t mid = lo + ((hi - lo) / 2);
            uint64_t key = tridx_start[mid].type_hash;

            if (key < type_hash) {
                lo = mid + 1;
            }
            else if (key > type_hash) {
                hi = mid;
            }
            else {
                return trmap_start[tridx_start[mid].entry_index].layout;
            }
        }
        return nullptr;
    }

    // Index missing or unfilled: linear scan (entries carry their type_hash).
    for (uint64_t i = 0; i < trmap_count; i++) {
        if (trmap_start[i].type_hash == type_hash) {
            return trmap_start[i].layout;
        }
    }

    return nullptr;
}

void
n00b_transient_zero(void                          *payload,
                    size_t                         payload_len,
                    const n00b_transient_layout_t *layout)
{
    if (payload == nullptr || layout == nullptr) {
        return;
    }

    for (uint64_t i = 0; i < layout->field_count; i++) {
        uint64_t off = layout->byte_offsets[i];
        uint64_t sz  = layout->byte_sizes[i];

        // Skip ranges that fall outside the serialized payload.
        if (off > (uint64_t)payload_len || sz > (uint64_t)payload_len - off) {
            continue;
        }
        memset((uint8_t *)payload + off, 0, (size_t)sz);
    }
}
