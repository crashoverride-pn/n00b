#pragma once

#include "core/alloc.h"
#include "core/gc_map.h"

// True when the allocation holding ptr is marked never-scan.
static inline bool
alloc_is_no_scan(void *ptr)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(ptr, .scan_for_header = true);

    if (info.kind == n00b_alloc_inline) {
        return info.hdr.in_line->scan_kind == N00B_GC_SCAN_KIND_NONE
            && info.hdr.in_line->no_scan;
    }
    if (info.kind == n00b_alloc_oob) {
        return info.hdr.oob->scan_kind == N00B_GC_SCAN_KIND_NONE
            && info.hdr.oob->no_scan;
    }

    return false;
}
