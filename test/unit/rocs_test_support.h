/*
 * Fixtures every rocs test needs and none of them owns.
 *
 * One copy of each, because a second that drifts is a test of the wrong thing:
 * a shard allocator configured differently exercises a memory model production
 * does not use.
 */

#pragma once

#include <stdint.h>

#include "core/pool.h"

// Shards built by a store allocate from its hot pool, configured exactly as
// below: hidden, inline headers, no external metadata. Inline headers keep the
// allocations resolvable by n00b_find_alloc_info, and the pool never moves, so
// the rwlocks guarding a shard's lists stay put while a futex wait is keyed on
// their address. A shard built with no allocator would get the default moving
// heap instead. Tests should exercise the memory model production uses.
static n00b_allocator_t *
test_shard_allocator(void)
{
    static n00b_pool_t       pool;
    static n00b_allocator_t *shared = nullptr;

    if (shared == nullptr) {
        shared = n00b_pool_init(&pool,
                                .hidden            = true,
                                .external_metadata = false,
                                .inline_headers    = true,
                                .name              = "rocs_test_shard_pool");
    }
    return shared;
}
