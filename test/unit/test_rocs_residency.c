/* test/unit/test_rocs_residency.c - WP-005 Phase 4 residency contracts. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/hooks.h"
#include "vfs/vfs.h"

#include "internal/rocs/map.h"
#include "internal/rocs/store.h"
#include <rocs/store.h>
#include "test_check.h"

typedef struct {
    uint64_t shard_opens;
} hook_counter_t;

static n00b_store_schema_t *
new_schema(void)
{
    auto r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_vfs_t *
new_memory_vfs(n00b_vfs_mount_t **mount_out)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    if (mount_out != nullptr) {
        *mount_out = n00b_result_get(mount_r);
    }
    return vfs;
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs) _kargs
{
    n00b_store_residency_policy_t *policy = nullptr;
}
{
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       new_schema(),
                                       .residency_policy = policy);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_store_catalog_entry_t *
seal_one(n00b_store_t *store, uint64_t seal_ts)
{
    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static n00b_store_catalog_entry_t *
find_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static uint64_t
entry_len(n00b_store_catalog_entry_t *entry)
{
    auto len_r = n00b_store_catalog_entry_get_byte_len(entry);
    CHECK(n00b_result_is_ok(len_r));
    return n00b_result_get(len_r);
}

static n00b_store_residency_stats_t
residency_stats(n00b_store_t *store)
{
    auto stats_r = n00b_store_residency_stats(store);
    CHECK(n00b_result_is_ok(stats_r));
    return n00b_result_get(stats_r);
}

static void
count_shard_open_hook(n00b_vfs_hook_ctx_t *ctx, void *cookie)
{
    hook_counter_t *counter = cookie;
    if (ctx->path != nullptr
        && n00b_unicode_str_starts_with(ctx->path, r"/rocs/shards/")) {
        counter->shard_opens++;
    }
}

static n00b_store_map_t *
resident_map(n00b_store_resident_shard_t *resident)
{
    auto map_r = n00b_store_resident_shard_map(resident);
    CHECK(n00b_result_is_ok(map_r));
    return n00b_result_get(map_r);
}

static void
check_shard_id(n00b_store_map_t *map, uint64_t expected)
{
    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    auto id_r = n00b_store_map_shard_id(n00b_result_get(root_r));
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_get(id_r) == expected);
}

static void
test_metadata_only_reopen_still_cold(void)
{
    n00b_vfs_mount_t *mount = nullptr;
    n00b_vfs_t       *vfs   = new_memory_vfs(&mount);
    n00b_store_t     *store = open_store(vfs);

    for (uint64_t i = 0; i < 4; i++) {
        seal_one(store, i + 1);
    }
    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    hook_counter_t counter = {};
    auto hook_r = n00b_vfs_hook_add(mount,
                                    N00B_VFS_HOOK_PRE_OPEN,
                                    count_shard_open_hook,
                                    &counter,
                                    0);
    CHECK(n00b_result_is_ok(hook_r));

    n00b_store_t *reopened = open_store(vfs);
    CHECK(counter.shard_opens == 0);

    auto count_r = n00b_store_catalog_get_entry_count(reopened);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 4);
    auto resident_r = n00b_store_get_resident_shard_count(reopened);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_get(resident_r) == 0);

    close_r = n00b_store_close(reopened);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_lazy_load_reuse_and_trim(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *first  = seal_one(store, 10);
    n00b_store_catalog_entry_t *second = seal_one(store, 20);
    uint64_t first_len  = entry_len(first);
    uint64_t second_len = entry_len(second);
    n00b_store_residency_stats_t stats = residency_stats(store);
    CHECK(stats.cache_hits == 0);
    CHECK(stats.cache_misses == 0);
    CHECK(stats.unloads == 0);

    auto is_resident = n00b_store_catalog_entry_is_resident(first);
    CHECK(n00b_result_is_ok(is_resident));
    CHECK(!n00b_result_get(is_resident));

    auto first_r = n00b_store_resident_shard_acquire(store, first);
    CHECK(n00b_result_is_ok(first_r));
    n00b_store_resident_shard_t *first_handle = n00b_result_get(first_r);
    check_shard_id(resident_map(first_handle), 1);

    auto count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);
    auto bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == first_len);
    stats = residency_stats(store);
    CHECK(stats.resident_bytes == first_len);
    CHECK(stats.resident_shards == 1);
    CHECK(stats.active_pins == 1);
    CHECK(stats.cache_hits == 0);
    CHECK(stats.cache_misses == 1);

    auto release_r = n00b_store_resident_shard_release(first_handle);
    CHECK(n00b_result_is_ok(release_r));

    first_r = n00b_store_resident_shard_acquire(store, first);
    CHECK(n00b_result_is_ok(first_r));
    first_handle = n00b_result_get(first_r);
    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);
    stats = residency_stats(store);
    CHECK(stats.cache_hits == 1);
    CHECK(stats.cache_misses == 1);
    release_r = n00b_store_resident_shard_release(first_handle);
    CHECK(n00b_result_is_ok(release_r));

    auto second_r = n00b_store_resident_shard_acquire(store, second);
    CHECK(n00b_result_is_ok(second_r));
    n00b_store_resident_shard_t *second_handle = n00b_result_get(second_r);
    release_r = n00b_store_resident_shard_release(second_handle);
    CHECK(n00b_result_is_ok(release_r));

    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 2);
    bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == first_len + second_len);
    stats = residency_stats(store);
    CHECK(stats.cache_hits == 1);
    CHECK(stats.cache_misses == 2);

    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == first_len + second_len);
    count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 0);
    bytes_r = n00b_store_get_resident_bytes(store);
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_get(bytes_r) == 0);
    stats = residency_stats(store);
    CHECK(stats.unloads == 2);
    CHECK(stats.unload_bytes == first_len + second_len);

    auto stat_r = n00b_store_catalog_entry_verify_object(store, first);
    CHECK(n00b_result_is_ok(stat_r));
    stat_r = n00b_store_catalog_entry_verify_object(store, second);
    CHECK(n00b_result_is_ok(stat_r));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_pin_blocks_trim_and_close(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 30);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == 0);
    auto count_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_err(close_r));
    CHECK(n00b_result_get_err(close_r) == N00B_STORE_ERR_PINNED);

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
    trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == entry_len(entry));
    close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_unload_unregisters_region(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 40);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(resident_r));
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);
    n00b_store_map_t *map = resident_map(resident);

    auto base_r = n00b_store_map_resident_base_for_test(map);
    CHECK(n00b_result_is_ok(base_r));
    auto len_r = n00b_store_map_resident_len_for_test(map);
    CHECK(n00b_result_is_ok(len_r));
    uint8_t *probe = (uint8_t *)(uintptr_t)n00b_result_get(base_r)
                   + n00b_result_get(len_r) / 2;
    CHECK(n00b_option_is_set(n00b_mmap_by_address(probe)));

    auto release_r = n00b_store_resident_shard_release(resident);
    CHECK(n00b_result_is_ok(release_r));
    auto trim_r = n00b_store_residency_trim(store, .target_resident_bytes = 1);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(!n00b_option_is_set(n00b_mmap_by_address(probe)));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

static void
test_explicit_mmap_modes_do_not_fake_vfs_paths(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs(nullptr);
    n00b_store_t *store = open_store(vfs);
    n00b_store_catalog_entry_t *entry = seal_one(store, 50);
    auto path_r = n00b_store_catalog_entry_get_object_path(entry);
    CHECK(n00b_result_is_ok(path_r));
    n00b_string_t *path = n00b_result_get(path_r);

    n00b_store_residency_policy_t policy =
        n00b_store_residency_policy_get_default();
    policy.preferred_backing = N00B_STORE_IMAGE_LOCAL_MMAP;
    auto map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_err(map_r));
    CHECK(n00b_result_get_err(map_r) == N00B_STORE_MAP_ERR_BACKING);

    policy.preferred_backing = N00B_STORE_IMAGE_CACHE_MMAP;
    map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_err(map_r));
    CHECK(n00b_result_get_err(map_r) == N00B_STORE_MAP_ERR_CACHE);

    policy.preferred_backing = N00B_STORE_IMAGE_PINNED_BUFFER;
    map_r = n00b_store_map_open_vfs(vfs, path, .policy = &policy);
    CHECK(n00b_result_is_ok(map_r));
    auto close_r = n00b_store_map_close(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(close_r));

    close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));
}

// SIEVE residency (Zhang et al., NSDI '24). Shards enter a queue at the head
// when mapped and never move. On eviction a hand walks from the tail toward the
// head: a shard hit since the hand last passed has its bit cleared and is
// spared; the first shard without the bit goes. The hand stays where it
// stopped, and the next eviction continues from there. These tests pin that
// behavior down shard by shard.

static n00b_store_residency_policy_t
shard_budget_policy(uint32_t max_shards)
{
    n00b_store_residency_policy_t policy =
        n00b_store_residency_policy_get_default();
    policy.preferred_backing   = N00B_STORE_IMAGE_PINNED_BUFFER;
    policy.max_resident_shards = max_shards;
    return policy;
}

static void
touch(n00b_store_t *store, n00b_store_catalog_entry_t *entry)
{
    auto acquire_r = n00b_store_resident_shard_acquire(store, entry);
    CHECK(n00b_result_is_ok(acquire_r));
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_release(n00b_result_get(acquire_r))));
}

static bool
is_resident(n00b_store_catalog_entry_t *entry)
{
    auto r = n00b_store_catalog_entry_is_resident(entry);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
check_resident_set(n00b_store_catalog_entry_t **entries,
                   int                          n,
                   const char                  *expected)
{
    for (int i = 0; i < n; i++) {
        CHECK(is_resident(entries[i]) == (expected[i] == '1'));
    }
}

static void
test_sieve_spares_a_hit_and_keeps_its_hand(void)
{
    n00b_store_residency_policy_t policy = shard_budget_policy(3);
    n00b_store_t *store = open_store(new_memory_vfs(nullptr),
                                     .policy = &policy);
    n00b_store_catalog_entry_t *e[6];
    for (int i = 0; i < 6; i++) {
        e[i] = seal_one(store, 100 + i);
    }

    // Queue, head first: e2 e1 e0.
    touch(store, e[0]);
    touch(store, e[1]);
    touch(store, e[2]);
    check_resident_set(e, 6, "111000");

    // e0 is the oldest, but it has been hit since it was mapped.
    touch(store, e[0]);

    // Mapping e3 overruns the budget. The hand starts at the tail, clears
    // e0's bit and passes it, then evicts e1. FIFO or LRU-by-insert would
    // have evicted e0.
    touch(store, e[3]);
    check_resident_set(e, 6, "101100");

    // The hand resumes at e2, not at the tail where e0 now sits unmarked.
    touch(store, e[4]);
    check_resident_set(e, 6, "100110");

    // Next it reaches e3, still ahead of e0.
    touch(store, e[5]);
    check_resident_set(e, 6, "100011");

    // And on toward the head: e4 goes while e0 waits at the tail for the
    // hand to wrap round to it.
    touch(store, e[1]);
    check_resident_set(e, 6, "110001");

    n00b_store_residency_stats_t stats = residency_stats(store);
    CHECK(stats.resident_shards == 3);
    CHECK(stats.unloads == 4);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_sieve_keeps_repeatedly_hit_shards_through_a_scan(void)
{
    n00b_store_residency_policy_t policy = shard_budget_policy(4);
    n00b_store_t *store = open_store(new_memory_vfs(nullptr),
                                     .policy = &policy);
    enum { SCAN = 24 };
    n00b_store_catalog_entry_t *hot[2];
    n00b_store_catalog_entry_t *scan[SCAN];
    hot[0] = seal_one(store, 10);
    hot[1] = seal_one(store, 11);
    for (int i = 0; i < SCAN; i++) {
        scan[i] = seal_one(store, 100 + i);
    }

    // Two shards every query hits, interleaved with a one-pass scan over
    // many shards nobody reads twice.
    touch(store, hot[0]);
    touch(store, hot[1]);
    for (int i = 0; i < SCAN; i++) {
        touch(store, hot[0]);
        touch(store, hot[1]);
        touch(store, scan[i]);
        CHECK(is_resident(hot[0]));
        CHECK(is_resident(hot[1]));
    }

    n00b_store_residency_stats_t stats = residency_stats(store);
    // Every scan shard missed once, and the hot pair never missed again.
    CHECK(stats.cache_misses == 2 + SCAN);
    CHECK(stats.resident_shards == 4);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_sieve_never_evicts_a_pinned_or_new_shard(void)
{
    n00b_store_residency_policy_t policy = shard_budget_policy(1);
    n00b_store_t *store = open_store(new_memory_vfs(nullptr),
                                     .policy = &policy);
    n00b_store_catalog_entry_t *e[4];
    for (int i = 0; i < 4; i++) {
        e[i] = seal_one(store, 200 + i);
    }

    // A budget of one: the shard being mapped displaces the only other one.
    touch(store, e[0]);
    touch(store, e[1]);
    check_resident_set(e, 4, "0100");

    // A pinned shard stays put however far over budget the store goes, and
    // an eviction that finds nothing unpinned stops.
    auto held_r = n00b_store_resident_shard_acquire(store, e[1]);
    CHECK(n00b_result_is_ok(held_r));
    auto held2_r = n00b_store_resident_shard_acquire(store, e[2]);
    CHECK(n00b_result_is_ok(held2_r));
    check_resident_set(e, 4, "0110");
    CHECK(residency_stats(store).resident_shards == 2);

#ifdef N00B_DEBUG
    n00b_store_catalog_entries_visited_reset();
#endif
    auto trim_r = n00b_store_residency_trim(store);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == 0);
#ifdef N00B_DEBUG
    // Two full turns of the hand over the two resident shards, at most.
    CHECK(n00b_store_catalog_entries_visited() <= 4);
#endif

    // Once released, the over-budget store sheds down to its one shard.
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_release(n00b_result_get(held_r))));
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_release(n00b_result_get(held2_r))));
    touch(store, e[3]);
    check_resident_set(e, 4, "0001");
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_sieve_idle_eviction_and_in_budget_trim(void)
{
    n00b_store_residency_policy_t policy = shard_budget_policy(8);
    n00b_store_t *store = open_store(new_memory_vfs(nullptr),
                                     .policy = &policy);
    n00b_store_catalog_entry_t *e[3];
    for (int i = 0; i < 3; i++) {
        e[i] = seal_one(store, 300 + i);
        touch(store, e[i]);
    }

    // Within budget and no idle limit: trim looks at nothing.
#ifdef N00B_DEBUG
    n00b_store_catalog_entries_visited_reset();
#endif
    auto trim_r = n00b_store_residency_trim(store);
    CHECK(n00b_result_is_ok(trim_r));
    CHECK(n00b_result_get(trim_r) == 0);
#ifdef N00B_DEBUG
    CHECK(n00b_store_catalog_entries_visited() == 0);
#endif
    check_resident_set(e, 3, "111");
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    // A 1ns idle limit makes every unpinned shard idle by the next eviction
    // check, so this does not depend on how fast the machine is. Only the
    // pinned shard survives.
    policy.idle_ns = 1;
    store = open_store(new_memory_vfs(nullptr), .policy = &policy);
    for (int i = 0; i < 3; i++) {
        e[i] = seal_one(store, 300 + i);
        touch(store, e[i]);
    }
    auto held_r = n00b_store_resident_shard_acquire(store, e[1]);
    CHECK(n00b_result_is_ok(held_r));
    trim_r = n00b_store_residency_trim(store);
    CHECK(n00b_result_is_ok(trim_r));
    check_resident_set(e, 3, "010");
    CHECK(n00b_result_is_ok(
        n00b_store_resident_shard_release(n00b_result_get(held_r))));
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

#ifdef N00B_DEBUG
static void
test_sieve_eviction_cost_does_not_grow_with_the_catalog(void)
{
    enum { SHARDS = 200, BUDGET = 4 };
    n00b_store_residency_policy_t policy = shard_budget_policy(BUDGET);
    n00b_store_t *store = open_store(new_memory_vfs(nullptr),
                                     .policy = &policy);
    n00b_store_catalog_entry_t *e[SHARDS];
    for (int i = 0; i < SHARDS; i++) {
        e[i] = seal_one(store, 400 + i);
    }

    uint64_t staged_before = n00b_store_map_staging_released_bytes();
    uint64_t mapped_bytes  = 0;
    n00b_store_catalog_entries_visited_reset();
    for (int i = 0; i < SHARDS; i++) {
        touch(store, e[i]);
        mapped_bytes += entry_len(e[i]);
    }
    uint64_t visited = n00b_store_catalog_entries_visited();
    printf("  %d misses against a %d-shard budget visited %llu entries\n",
           SHARDS,
           BUDGET,
           (unsigned long long)visited);
    // The hand walks at most twice the resident set per eviction, however
    // large the catalog.
    CHECK(visited <= (uint64_t)SHARDS * 2 * (BUDGET + 1));
    CHECK(residency_stats(store).resident_shards == BUDGET);

    // Every miss read the shard through a VFS buffer, copied it into the
    // mapping, and released the buffer.
    CHECK(n00b_store_map_staging_released_bytes() - staged_before
          == mapped_bytes);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}
#endif

// The service keeps a store on a pool hidden from the GC, so a buffer a shard
// load allocates there and does not free stays mapped. Two shards alternate
// under a one-shard budget, so every touch reads a shard through the VFS and
// unloads the other. Batches of loads are compared within one run, against
// the growth a retained shard-sized buffer per load would cause.
static void
test_shard_loads_release_their_staging_buffer(void)
{
    enum { RECORDS = 64, PAD = 512, BATCH = 64 };
    n00b_pool_t       pool = {};
    n00b_allocator_t *al   = n00b_pool_init(&pool,
                                            .hidden            = true,
                                            .external_metadata = true,
                                            .name = "residency_staging_test");
    auto schema_r = n00b_store_schema_new(.allocator = al);
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_residency_policy_t policy = shard_budget_policy(1);
    auto store_r = n00b_store_open_vfs(new_memory_vfs(nullptr),
                                       r"/rocs",
                                       n00b_result_get(schema_r),
                                       .residency_policy = &policy,
                                       .allocator        = al);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    char pad[PAD];
    memset(pad, 'x', sizeof(pad));
    n00b_store_catalog_entry_t *e[2];
    for (int s = 0; s < 2; s++) {
        for (int i = 0; i < RECORDS; i++) {
            pad[0] = (char)('a' + s);
            pad[1] = (char)('a' + i % 26);
            pad[2] = (char)('a' + i / 26);
            n00b_json_node_t *rec = n00b_json_object_new();
            n00b_json_object_put_n00b(
                rec,
                r"pad",
                n00b_json_string_new_from_n00b(
                    n00b_string_from_raw(pad, (int64_t)sizeof(pad))));
            CHECK(n00b_result_is_ok(n00b_store_ingest(store, rec)));
        }
        e[s] = seal_one(store, 500 + s);
    }
    uint64_t load_bytes = entry_len(e[0]) + entry_len(e[1]);

    uint64_t mapped[4];
    for (int batch = 0; batch < 4; batch++) {
        for (int i = 0; i < BATCH; i++) {
            touch(store, e[0]);
            touch(store, e[1]);
        }
        mapped[batch] = n00b_pool_mapped_bytes(&pool);
    }
    CHECK(residency_stats(store).cache_misses >= 4 * 2 * BATCH);

    uint64_t growth = mapped[3] - mapped[1];
    // Two batches of BATCH loads of each shard.
    uint64_t retained = 2 * (uint64_t)BATCH * load_bytes;
    printf("  store pool growth over %d shard loads: %llu bytes; a retained "
           "staging buffer per load would add about %llu\n",
           4 * BATCH,
           (unsigned long long)growth,
           (unsigned long long)retained);
    CHECK(growth < retained / 2);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    n00b_allocator_destroy(al);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_metadata_only_reopen_still_cold();
    test_lazy_load_reuse_and_trim();
    test_pin_blocks_trim_and_close();
    test_unload_unregisters_region();
    test_explicit_mmap_modes_do_not_fake_vfs_paths();
    test_sieve_spares_a_hit_and_keeps_its_hand();
    test_sieve_keeps_repeatedly_hit_shards_through_a_scan();
    test_sieve_never_evicts_a_pinned_or_new_shard();
    test_sieve_idle_eviction_and_in_budget_trim();
#ifdef N00B_DEBUG
    test_sieve_eviction_cost_does_not_grow_with_the_catalog();
#endif
    test_shard_loads_release_their_staging_buffer();
    n00b_shutdown();
    return 0;
}
