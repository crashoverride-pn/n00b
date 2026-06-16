#include "rocs/store.h"

#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_s3.h"
#include "conduit/conduit.h"
#include "conduit/print.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/env.h"
#include "core/gc.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/thread.h"
#include "core/time.h"
#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/map.h"
#include "internal/rocs/plan.h"
#include "internal/rocs/store.h"
#include "rocs/normalizer.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"
#include "util/worker_pool.h"
#include "vfs/backend_local.h"
#include "vfs/backend_memory.h"
#include "vfs/backend.h"
#include "vfs/cache.h"
#include "vfs/vfs.h"

#include <stddef.h>

typedef n00b_list_t(n00b_store_field_t *) rocs_store_field_list_t;
typedef n00b_list_t(n00b_store_catalog_entry_t *)
    rocs_store_catalog_list_t;
typedef n00b_list_t(n00b_store_posting_list_t *)
    rocs_store_posting_target_list_t;
typedef struct rocs_store_batch_term rocs_store_batch_term_t;
typedef n00b_list_t(rocs_store_batch_term_t)
    rocs_store_batch_term_list_t;
typedef struct rocs_store_retired_hot_allocator
    rocs_store_retired_hot_allocator_t;
typedef n00b_list_t(rocs_store_retired_hot_allocator_t *)
    rocs_store_retired_hot_allocator_list_t;

static bool rocs_store_root_valid(n00b_string_t *root);
static n00b_result_t(bool)
rocs_store_ingest_common(n00b_store_t     *store,
                         n00b_json_node_t *record,
                         n00b_buffer_t    *raw,
                         n00b_allocator_t *allocator);

N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_commit_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_commit_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_ingest_payload_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_ingest_payload_t);


#define ROCS_STORE_CATALOG_MAGIC_LEN 8
#define ROCS_STORE_CATALOG_VERSION   2
#define ROCS_STORE_CATALOG_VERSION_MIN 1

#define ROCS_STORE_CONFIG_DEFAULT_CACHE_BYTES    (256ull * 1024ull * 1024ull)
#define ROCS_STORE_CONFIG_DEFAULT_RESIDENT_BYTES (64ull * 1024ull * 1024ull)
#define ROCS_STORE_CONFIG_DEFAULT_RESIDENT_SHARDS 64ull
#define ROCS_STORE_CGROUP_CACHE_DIVISOR          4ull
#define ROCS_STORE_CGROUP_RESIDENT_DIVISOR       8ull

[[gnu::weak]] n00b_result_t(n00b_aws_config_t *)
n00b_aws_config(n00b_string_t *region) _kargs
{
    n00b_string_t    *endpoint_override = nullptr;
    n00b_allocator_t *allocator         = nullptr;
}
{
    (void)region;
    (void)endpoint_override;
    (void)allocator;
    return n00b_result_err(n00b_aws_config_t *, N00B_AWS_ERR_INTERNAL);
}

[[gnu::weak]] n00b_result_t(n00b_vfs_backend_t *)
n00b_aws_s3_vfs_backend_new(n00b_aws_config_t *cfg,
                            n00b_string_t     *bucket) _kargs
{
    n00b_string_t    *prefix           = nullptr;
    n00b_string_t    *content_type     = nullptr;
    bool              force_path_style = false;
    uint64_t          multipart_threshold = 0;
    uint64_t          multipart_part_size = 0;
    n00b_allocator_t *allocator        = nullptr;
}
{
    (void)cfg;
    (void)bucket;
    (void)prefix;
    (void)content_type;
    (void)force_path_style;
    (void)multipart_threshold;
    (void)multipart_part_size;
    (void)allocator;
    return n00b_result_err(n00b_vfs_backend_t *, N00B_VFS_ERR_NOT_SUPPORTED);
}

struct n00b_store_field_t {
    n00b_string_t          *name;
    bool                    required;
    n00b_store_index_kind_t index_kind;
    bool                    include_in_all;
    n00b_store_postings_kind_t postings;
    uint8_t                 ngram_n;
};

struct n00b_store_schema_t {
    rocs_store_field_list_t *fields;
    n00b_allocator_t        *allocator;
    bool                     frozen;
};

struct n00b_store_partition_policy_t {
    n00b_store_partition_kind_t kind;
    n00b_string_t              *field;
    uint64_t                    bucket_width;
    uint32_t                    buckets;
    n00b_store_time_source_t    time_source;
};

struct n00b_store_retain_policy_t {
    n00b_store_retain_kind_t kind;
};

struct n00b_store_shard_retention_policy_t {
    uint64_t       max_sealed_shards;
    uint64_t       drop_before_seal_ts;
    n00b_string_t *drop_reason;
};

struct n00b_store_seal_policy_t {
    uint64_t max_records;
    uint64_t max_bytes;
    uint64_t max_hot_bytes;
    uint64_t max_open_ns;
};

struct n00b_store_config_t {
    n00b_store_profile_t     profile;
    n00b_store_writer_mode_t writer_mode;
    n00b_string_t           *name;
    n00b_string_t           *root;
    n00b_string_t           *s3_bucket;
    n00b_string_t           *s3_prefix;
    n00b_string_t           *schema_source;
    n00b_string_t           *aws_region;
    n00b_string_t           *s3_endpoint;
    n00b_string_t           *cache_dir;
    uint64_t                 cache_bytes;
    uint64_t                 resident_bytes;
    uint64_t                 resident_shards;
    bool                     read_only;
    bool                     s3_path_style;
    bool                     has_s3_path_style;
    n00b_allocator_t        *allocator;
};

struct n00b_store_catalog_entry_t {
    n00b_store_t  *owner;
    n00b_string_t *object_path;
    n00b_string_t *partition_key;
    n00b_string_t *etag;
    n00b_store_map_t *resident_map;
    uint64_t       shard_id;
    uint64_t       generation;
    uint64_t       byte_len;
    uint64_t       record_count;
    uint64_t       schema_generation;
    uint64_t       seal_ts;
    uint64_t       resident_pins;
    uint64_t       last_access_ns;
};

struct rocs_store_retired_hot_allocator {
    n00b_allocator_t *allocator;
    uint64_t          shard_id;
    uint64_t          generation;
    uint64_t          record_count;
};

typedef struct {
    n00b_arena_t *arena;
    n00b_pool_t   pool;
} rocs_store_hot_allocator_storage_t;

struct n00b_store_t {
    n00b_vfs_t                    *vfs;
    n00b_string_t                 *root;
    n00b_string_t                 *display_name;
    n00b_store_schema_t           *schema;
    n00b_store_partition_policy_t *partition_policy;
    n00b_store_retain_policy_t    *retain_policy;
    n00b_store_seal_policy_t      *seal_policy;
    n00b_store_residency_policy_t  residency_policy;
    n00b_vfs_cache_t              *cache;
    n00b_store_commit_topic_t     *commit_topic;
    n00b_store_lifecycle_topic_t  *lifecycle_topic;
    n00b_store_shard_t            *hot_shard;
    n00b_allocator_t              *hot_allocator;
    n00b_string_t                 *hot_partition_key;
    rocs_store_retired_hot_allocator_list_t *retired_hot_allocators;
    rocs_store_catalog_list_t     *catalog;
    n00b_allocator_t              *allocator;
    n00b_rwlock_t                 *residency_lock;
    n00b_rwlock_t                 *commit_lock;
    n00b_worker_pool_t            *batch_pool;
    int32_t                        batch_pool_workers;
    int32_t                        batch_pool_capacity;
    n00b_store_state_t             state;
    bool                           read_only;
    bool                           recovery_journal;
    bool                           recovering;
    n00b_vfs_fh_t                  journal_fh;
    uint64_t                       journal_shard_id;
    n00b_string_t                 *journal_path;
    uint64_t                       journal_unsynced;
    // Counts seal rotations that irreversibly dropped already-committed records
    // WITHOUT a recovery journal to replay them (i.e. true data loss).  Ingest
    // entry points compare this across an operation so they never report a
    // committed prefix whose backing shard was dropped.  Drops that the journal
    // retains for replay are not counted here.
    uint64_t                       durable_drop_count;
    uint64_t                       durable_drop_records;
    n00b_err_t                     durable_drop_last_err;
    uint64_t                       next_shard_id;
    uint64_t                       generation;
    uint64_t                       schema_generation;
    n00b_store_pos_t               oldest_available;
    bool                           has_oldest_available;
    uint64_t                       active_pins;
    uint64_t                       resident_bytes;
    uint64_t                       resident_shards;
    uint64_t                       resident_cache_hits;
    uint64_t                       resident_cache_misses;
    uint64_t                       resident_unloads;
    uint64_t                       resident_unload_bytes;
    uint64_t                       hot_destroy_count;
    uint64_t                       hot_destroy_records;
    uint64_t                       hot_destroy_last_pool_mapped_bytes;
    uint64_t                       hot_destroy_last_pool_pages;
    uint64_t                       hot_destroy_last_pool_big_maps;
    uint64_t                       hot_destroy_last_pool_big_unmaps;
    uint64_t                       hot_destroy_last_arena_used_bytes;
    uint64_t                       hot_destroy_last_arena_size_bytes;
    uint64_t                       hot_destroy_total_pool_mapped_bytes;
    uint64_t                       hot_destroy_total_pool_pages;
    uint64_t                       hot_destroy_total_arena_size_bytes;
    uint64_t                       hot_destroy_registry_pool_bytes_before;
    uint64_t                       hot_destroy_registry_pool_bytes_after;
    uint64_t                       hot_destroy_registry_pool_unmapped_bytes;
    uint64_t                       hot_destroy_registry_managed_unmapped_bytes;
    bool                           borrowed_catalog_enumeration_disabled;
};

struct n00b_store_pin_t {
    n00b_store_t *store;
    bool          released;
};

struct n00b_store_resident_shard_t {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *entry;
    bool                        released;
};

struct rocs_store_batch_term {
    n00b_string_t                *field;
    n00b_uint128_t                key;
    n00b_store_postings_kind_t    postings;
};

typedef struct {
    n00b_store_t                   *store;
    n00b_json_node_t               *input_record;
    n00b_buffer_t                  *source;
    n00b_allocator_t               *allocator;
    n00b_json_node_t               *record;
    n00b_buffer_t                  *raw;
    n00b_string_t                  *route;
    rocs_store_batch_term_list_t   *terms;
    n00b_err_t                      err;
} rocs_store_batch_job_t;

struct n00b_store_conduit_ingest_t {
    n00b_store_t                       *store;
    n00b_store_ingest_topic_t          *topic;
    n00b_store_ingest_inbox_t          *inbox;
    n00b_conduit_sub_handle_t           sub;
    n00b_worker_pool_t                 *pool;
    n00b_thread_t                      *thread;
    n00b_rwlock_t                      *lock;
    n00b_allocator_t                   *allocator;
    n00b_store_source_decoder_t         source_decoder;
    n00b_store_conduit_ingest_stats_t   stats;
    bool                                stop_requested;
    bool                                closed;
    bool                                joined;
};

typedef struct {
    n00b_store_conduit_ingest_t *adapter;
    n00b_store_ingest_payload_t  payload;
} rocs_store_conduit_job_t;

static rocs_store_field_list_t *
rocs_store_field_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_field_list_t *fields = n00b_alloc_with_opts(
        rocs_store_field_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *fields = n00b_list_new_private(n00b_store_field_t *,
                                    .allocator = allocator,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return fields;
}

static rocs_store_catalog_list_t *
rocs_store_catalog_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_catalog_list_t *entries = n00b_alloc_with_opts(
        rocs_store_catalog_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *entries = n00b_list_new_private(n00b_store_catalog_entry_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return entries;
}

static n00b_store_catalog_snapshot_t *
rocs_store_catalog_snapshot_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_catalog_snapshot_t *entries = n00b_alloc_with_opts(
        n00b_store_catalog_snapshot_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *entries = n00b_list_new_private(n00b_store_catalog_snapshot_entry_t,
                                     .allocator = allocator);
    return entries;
}

static n00b_store_pos_list_t *
rocs_store_pos_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_pos_list_t *positions = n00b_alloc_with_opts(
        n00b_store_pos_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *positions = n00b_list_new_private(n00b_store_pos_t,
                                       .allocator = allocator);
    return positions;
}

static bool
rocs_store_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
rocs_store_string_copy(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static rocs_store_retired_hot_allocator_list_t *
rocs_store_retired_hot_allocator_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_retired_hot_allocator_list_t *list = n00b_alloc_with_opts(
        rocs_store_retired_hot_allocator_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_store_retired_hot_allocator_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

static n00b_result_t(n00b_allocator_t *)
rocs_store_hot_allocator_new(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_allocator_t *, N00B_STORE_ERR_ARG);
    }

    n00b_arena_t *arena = n00b_new_arena(.use_gc = false,
                                         .hidden = true,
                                         .name   = "rocs_hot_allocator_ctl");
    rocs_store_hot_allocator_storage_t *storage = n00b_alloc_with_opts(
        rocs_store_hot_allocator_storage_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)arena,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    *storage       = (rocs_store_hot_allocator_storage_t){};
    storage->arena = arena;

    n00b_allocator_t *allocator = n00b_pool_init(
        &storage->pool,
        .hidden            = true,
        .external_metadata = true,
        .name              = "rocs_hot_shard_pool");
    return n00b_result_ok(n00b_allocator_t *, allocator);
}

static rocs_store_hot_allocator_storage_t *
rocs_store_hot_allocator_storage(n00b_allocator_t *allocator)
{
    return (rocs_store_hot_allocator_storage_t *)((char *)allocator
                                                 - offsetof(rocs_store_hot_allocator_storage_t,
                                                            pool));
}

static uint64_t
rocs_store_hot_allocator_mapped_bytes(n00b_allocator_t *allocator)
{
    if (allocator == nullptr) {
        return 0;
    }

    rocs_store_hot_allocator_storage_t *storage =
        rocs_store_hot_allocator_storage(allocator);
    return n00b_pool_mapped_bytes(&storage->pool);
}

static void
rocs_store_hot_allocator_memory_stats(n00b_allocator_t           *allocator,
                                      n00b_store_memory_stats_t *stats)
{
    if (allocator == nullptr || stats == nullptr) {
        return;
    }

    rocs_store_hot_allocator_storage_t *storage =
        rocs_store_hot_allocator_storage(allocator);
    stats->hot_pool_mapped_bytes = n00b_pool_mapped_bytes(&storage->pool);
    stats->hot_pool_pages        = n00b_pool_page_count(&storage->pool);
    stats->hot_pool_big_maps     = n00b_pool_big_map_count(&storage->pool);
    stats->hot_pool_big_unmaps   = n00b_pool_big_unmap_count(&storage->pool);
    if (storage->arena != nullptr) {
        stats->hot_arena_used_bytes = n00b_arena_used(storage->arena);
        stats->hot_arena_size_bytes = n00b_arena_size(storage->arena);
    }
}

static uint64_t
rocs_store_u64_add_sat(uint64_t a, uint64_t b)
{
    if (a > UINT64_MAX - b) {
        return UINT64_MAX;
    }
    return a + b;
}

static void
rocs_store_hot_allocator_destroy(n00b_store_t      *store,
                                 n00b_allocator_t *allocator,
                                 uint64_t          record_count)
{
    if (allocator == nullptr) {
        return;
    }

    rocs_store_hot_allocator_storage_t *storage =
        rocs_store_hot_allocator_storage(allocator);
    n00b_arena_t *arena = storage->arena;
    uint64_t      pool_mapped = n00b_pool_mapped_bytes(&storage->pool);
    uint64_t      pool_pages  = n00b_pool_page_count(&storage->pool);
    uint64_t      pool_big_maps = n00b_pool_big_map_count(&storage->pool);
    uint64_t      pool_big_unmaps = n00b_pool_big_unmap_count(&storage->pool);
    uint64_t      arena_used = arena == nullptr ? 0 : n00b_arena_used(arena);
    uint64_t      arena_size = arena == nullptr ? 0 : n00b_arena_size(arena);

    n00b_mmap_registry_stats_t registry_before = {};
    if (store != nullptr) {
        registry_before = n00b_mmap_registry_stats();
    }

    n00b_allocator_destroy(allocator);
    if (arena != nullptr) {
        n00b_allocator_destroy((n00b_allocator_t *)arena);
    }

    if (store == nullptr) {
        return;
    }

    n00b_mmap_registry_stats_t registry_after = n00b_mmap_registry_stats();
    store->hot_destroy_count =
        rocs_store_u64_add_sat(store->hot_destroy_count, 1);
    store->hot_destroy_records =
        rocs_store_u64_add_sat(store->hot_destroy_records, record_count);
    store->hot_destroy_last_pool_mapped_bytes = pool_mapped;
    store->hot_destroy_last_pool_pages        = pool_pages;
    store->hot_destroy_last_pool_big_maps     = pool_big_maps;
    store->hot_destroy_last_pool_big_unmaps   = pool_big_unmaps;
    store->hot_destroy_last_arena_used_bytes  = arena_used;
    store->hot_destroy_last_arena_size_bytes  = arena_size;
    store->hot_destroy_total_pool_mapped_bytes =
        rocs_store_u64_add_sat(store->hot_destroy_total_pool_mapped_bytes,
                               pool_mapped);
    store->hot_destroy_total_pool_pages =
        rocs_store_u64_add_sat(store->hot_destroy_total_pool_pages, pool_pages);
    store->hot_destroy_total_arena_size_bytes =
        rocs_store_u64_add_sat(store->hot_destroy_total_arena_size_bytes,
                               arena_size);
    store->hot_destroy_registry_pool_bytes_before =
        registry_before.pool_bytes;
    store->hot_destroy_registry_pool_bytes_after =
        registry_after.pool_bytes;
    if (registry_before.pool_bytes >= registry_after.pool_bytes) {
        store->hot_destroy_registry_pool_unmapped_bytes =
            rocs_store_u64_add_sat(
                store->hot_destroy_registry_pool_unmapped_bytes,
                registry_before.pool_bytes - registry_after.pool_bytes);
    }
    if (registry_before.managed_segment_bytes
        >= registry_after.managed_segment_bytes) {
        store->hot_destroy_registry_managed_unmapped_bytes =
            rocs_store_u64_add_sat(
                store->hot_destroy_registry_managed_unmapped_bytes,
                registry_before.managed_segment_bytes
                    - registry_after.managed_segment_bytes);
    }
}

#if defined(N00B_ROCS_TRACE)
#if !defined(N00B_ROCS_TRACE_EVERY)
#define N00B_ROCS_TRACE_EVERY UINT64_C(256)
#endif

typedef struct {
    uint64_t columns;
    uint64_t posting_lists;
    uint64_t sparse_ordinals;
    uint64_t dense_bits;
    uint64_t dense_count;
} rocs_store_trace_index_stats_t;

typedef struct {
    uint64_t pool_mapped;
    uint64_t pool_pages;
    uint64_t pool_big_maps;
    uint64_t pool_big_unmaps;
    uint64_t arena_used;
    uint64_t arena_size;
} rocs_store_trace_allocator_stats_t;

static uint64_t
rocs_store_trace_string_bytes(n00b_json_node_t *record, n00b_string_t *field)
{
    n00b_json_node_t *value = rocs_json_object_get_field(record, field);
    if (value == nullptr || !n00b_json_is_string(value)) {
        return 0;
    }

    n00b_string_t *s = n00b_json_as_string(value);
    return s == nullptr ? 0 : (uint64_t)s->u8_bytes;
}

static rocs_store_trace_allocator_stats_t
rocs_store_trace_allocator_stats(n00b_allocator_t *allocator)
{
    rocs_store_trace_allocator_stats_t stats = {};
    if (allocator == nullptr) {
        return stats;
    }

    rocs_store_hot_allocator_storage_t *storage =
        rocs_store_hot_allocator_storage(allocator);
    stats.pool_mapped     = n00b_pool_mapped_bytes(&storage->pool);
    stats.pool_pages      = n00b_pool_page_count(&storage->pool);
    stats.pool_big_maps   = n00b_pool_big_map_count(&storage->pool);
    stats.pool_big_unmaps = n00b_pool_big_unmap_count(&storage->pool);
    if (storage->arena != nullptr) {
        stats.arena_used = n00b_arena_used(storage->arena);
        stats.arena_size = n00b_arena_size(storage->arena);
    }
    return stats;
}

static rocs_store_trace_allocator_stats_t
rocs_store_trace_hot_allocator_stats(n00b_store_t *store)
{
    if (store == nullptr || store->hot_allocator == nullptr) {
        return (rocs_store_trace_allocator_stats_t){};
    }
    return rocs_store_trace_allocator_stats(store->hot_allocator);
}

static rocs_store_trace_index_stats_t
rocs_store_trace_index_stats(n00b_store_shard_t *shard)
{
    rocs_store_trace_index_stats_t stats = {};
    if (shard == nullptr || shard->columns == nullptr) {
        return stats;
    }

    n00b_dict_foreach(shard->columns, field, column, {
        (void)field;
        if (column == nullptr) {
            continue;
        }

        stats.columns++;
        n00b_dict_foreach(column, key, postings, {
            (void)key;
            if (postings == nullptr) {
                continue;
            }

            stats.posting_lists++;
            if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
                stats.dense_count += postings->count;
                if (postings->flags != nullptr) {
                    stats.dense_bits += n00b_flagset_len(postings->flags);
                }
            }
            else if (postings->ordinals != nullptr) {
                stats.sparse_ordinals +=
                    (uint64_t)n00b_list_len(*postings->ordinals);
            }
        });
    });

    return stats;
}

static void
rocs_store_trace_ingest(n00b_store_t                    *store,
                        n00b_json_node_t                *record,
                        n00b_buffer_t                   *raw,
                        rocs_store_batch_term_list_t    *terms,
                        rocs_store_posting_target_list_t *targets,
                        uint64_t                         ordinal)
{
    if (store == nullptr || store->hot_shard == nullptr) {
        return;
    }

    uint64_t record_count = store->hot_shard->record_count;
    if (N00B_ROCS_TRACE_EVERY != 0
        && record_count % N00B_ROCS_TRACE_EVERY != 0) {
        return;
    }

    rocs_store_trace_index_stats_t index_stats =
        rocs_store_trace_index_stats(store->hot_shard);
    uint64_t raw_bytes = raw == nullptr ? 0 : (uint64_t)n00b_buffer_len(raw);
    uint64_t term_count = terms == nullptr ? 0 : (uint64_t)n00b_list_len(*terms);
    uint64_t target_count =
        targets == nullptr ? 0 : (uint64_t)n00b_list_len(*targets);
    uint64_t search_text_bytes =
        rocs_store_trace_string_bytes(record, r"search_text");
    rocs_store_trace_allocator_stats_t alloc_stats =
        rocs_store_trace_hot_allocator_stats(store);

    n00b_eprintf("rocs-trace ingest shard=«#» ordinal=«#» records=«#» "
                 "byte_est=«#» raw=«#» search_text=«#» terms=«#» "
                 "targets=«#» columns=«#» posting_lists=«#» "
                 "sparse_ordinals=«#» dense_count=«#» dense_bits=«#» "
                 "hot_pool_mapped=«#» hot_pool_pages=«#» "
                 "hot_pool_big_maps=«#» hot_pool_big_unmaps=«#» "
                 "hot_arena_used=«#» hot_arena_size=«#»",
                 store->hot_shard->shard_id,
                 ordinal,
                 record_count,
                 store->hot_shard->byte_estimate,
                 raw_bytes,
                 search_text_bytes,
                 term_count,
                 target_count,
                 index_stats.columns,
                 index_stats.posting_lists,
                 index_stats.sparse_ordinals,
                 index_stats.dense_count,
                 index_stats.dense_bits,
                 alloc_stats.pool_mapped,
                 alloc_stats.pool_pages,
                 alloc_stats.pool_big_maps,
                 alloc_stats.pool_big_unmaps,
                 alloc_stats.arena_used,
                 alloc_stats.arena_size);
}

static void
rocs_store_trace_seal(n00b_store_t     *store,
                      uint64_t          shard_id,
                      uint64_t          record_count,
                      uint64_t          byte_estimate,
                      uint64_t          image_bytes,
                      n00b_allocator_t *old_hot_allocator)
{
    rocs_store_trace_allocator_stats_t old_stats =
        rocs_store_trace_allocator_stats(old_hot_allocator);
    rocs_store_trace_allocator_stats_t next_stats =
        rocs_store_trace_hot_allocator_stats(store);

    n00b_eprintf("rocs-trace seal shard=«#» records=«#» byte_est=«#» "
                 "image_bytes=«#» old_hot_pool_mapped=«#» "
                 "old_hot_pool_pages=«#» old_hot_pool_big_maps=«#» "
                 "old_hot_pool_big_unmaps=«#» old_hot_arena_used=«#» "
                 "old_hot_arena_size=«#» "
                 "next_hot_pool_mapped=«#» next_hot_arena_used=«#» "
                 "next_hot_arena_size=«#»",
                 shard_id,
                 record_count,
                 byte_estimate,
                 image_bytes,
                 old_stats.pool_mapped,
                 old_stats.pool_pages,
                 old_stats.pool_big_maps,
                 old_stats.pool_big_unmaps,
                 old_stats.arena_used,
                 old_stats.arena_size,
                 next_stats.pool_mapped,
                 next_stats.arena_used,
                 next_stats.arena_size);
}
#endif

static rocs_store_retired_hot_allocator_list_t *
rocs_store_detach_retired_hot_allocators_locked(n00b_store_t *store)
{
    if (store == nullptr || store->retired_hot_allocators == nullptr
        || n00b_list_len(*store->retired_hot_allocators) == 0) {
        return nullptr;
    }

    rocs_store_retired_hot_allocator_list_t *retired =
        store->retired_hot_allocators;
    store->retired_hot_allocators =
        rocs_store_retired_hot_allocator_list_new(.allocator =
                                                      store->allocator);
    return retired;
}

static void
rocs_store_destroy_retired_hot_allocators(
    n00b_store_t                          *store,
    rocs_store_retired_hot_allocator_list_t *retired)
{
    if (retired == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*retired);
    for (size_t i = 0; i < len; i++) {
        rocs_store_retired_hot_allocator_t *item =
            n00b_list_get(*retired, i);
        if (item == nullptr || item->allocator == nullptr) {
            continue;
        }

        n00b_allocator_t *allocator = item->allocator;
        uint64_t          record_count = item->record_count;
        item->allocator = nullptr;
        rocs_store_hot_allocator_destroy(store, allocator, record_count);
    }
}

static void
rocs_store_retire_hot_allocator_locked(n00b_store_t      *store,
                                       n00b_allocator_t *allocator,
                                       uint64_t          shard_id,
                                       uint64_t          generation,
                                       uint64_t          record_count)
{
    if (store == nullptr || allocator == nullptr) {
        return;
    }
    if (store->retired_hot_allocators == nullptr) {
        store->retired_hot_allocators =
            rocs_store_retired_hot_allocator_list_new(.allocator =
                                                          store->allocator);
    }

    rocs_store_retired_hot_allocator_t *item = n00b_alloc_with_opts(
        rocs_store_retired_hot_allocator_t,
        &(n00b_alloc_opts_t){
            .allocator = store->allocator,
        });
    item->allocator    = allocator;
    item->shard_id     = shard_id;
    item->generation   = generation;
    item->record_count = record_count;
    n00b_list_push(*store->retired_hot_allocators, item);
}

static void
rocs_store_retire_hot_allocator(n00b_store_t      *store,
                                n00b_allocator_t *allocator,
                                uint64_t          shard_id,
                                uint64_t          generation,
                                uint64_t          record_count)
{
    if (store == nullptr || allocator == nullptr) {
        return;
    }

    rocs_store_retired_hot_allocator_list_t *retired = nullptr;
    n00b_data_write_lock(store->residency_lock);
    rocs_store_retire_hot_allocator_locked(store,
                                           allocator,
                                           shard_id,
                                           generation,
                                           record_count);
    retired = rocs_store_detach_retired_hot_allocators_locked(store);
    n00b_data_unlock(store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(store, retired);
}

static void
rocs_store_try_reclaim_retired_hot_allocators(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    rocs_store_retired_hot_allocator_list_t *retired = nullptr;
    n00b_data_write_lock(store->residency_lock);
    retired = rocs_store_detach_retired_hot_allocators_locked(store);
    n00b_data_unlock(store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(store, retired);
}

static bool
rocs_store_string_eq_lit(n00b_string_t *s, n00b_string_t *lit)
{
    return s != nullptr && n00b_unicode_str_eq(s,
                                               lit,
                                               .case_sensitive = false);
}

static bool
rocs_store_string_starts_with_lit(n00b_string_t *s, n00b_string_t *prefix)
{
    return s != nullptr && n00b_unicode_str_starts_with(s, prefix);
}

static n00b_store_config_t *
rocs_store_config_alloc(n00b_store_profile_t profile,
                        n00b_allocator_t    *allocator)
{
    n00b_store_config_t *config = n00b_alloc_with_opts(
        n00b_store_config_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    config->profile         = profile;
    config->writer_mode     = N00B_STORE_WRITER_SINGLE;
    config->name            = rocs_store_string_copy(r"rocs", allocator);
    config->root            = rocs_store_string_copy(r"/rocs", allocator);
    n00b_option_t(uint64_t) mem_limit = rocs_store_cgroup_memory_limit();
    if (n00b_option_is_set(mem_limit)) {
        uint64_t limit = n00b_option_get(mem_limit);
        uint64_t cache_budget = limit / ROCS_STORE_CGROUP_CACHE_DIVISOR;
        if (cache_budget == 0) {
            cache_budget = 1;
        }
        config->cache_bytes =
            cache_budget < ROCS_STORE_CONFIG_DEFAULT_CACHE_BYTES
                ? cache_budget
                : ROCS_STORE_CONFIG_DEFAULT_CACHE_BYTES;

        uint64_t resident_budget = limit / ROCS_STORE_CGROUP_RESIDENT_DIVISOR;
        if (resident_budget == 0) {
            resident_budget = 1;
        }
        config->resident_bytes =
            resident_budget < ROCS_STORE_CONFIG_DEFAULT_RESIDENT_BYTES
                ? resident_budget
                : ROCS_STORE_CONFIG_DEFAULT_RESIDENT_BYTES;
    }
    else {
        config->cache_bytes    = ROCS_STORE_CONFIG_DEFAULT_CACHE_BYTES;
        config->resident_bytes = ROCS_STORE_CONFIG_DEFAULT_RESIDENT_BYTES;
    }
    config->resident_shards = ROCS_STORE_CONFIG_DEFAULT_RESIDENT_SHARDS;
    config->allocator       = allocator;

    if (profile == N00B_STORE_PROFILE_SERVICE_LOCAL
        || profile == N00B_STORE_PROFILE_SERVICE_S3) {
        config->name = rocs_store_string_copy(r"rocs-service", allocator);
    }

    return config;
}

static n00b_result_t(n00b_store_profile_t)
rocs_store_parse_profile(n00b_string_t *s)
{
    if (rocs_store_string_empty(s)
        || rocs_store_string_eq_lit(s, r"embedded")
        || rocs_store_string_eq_lit(s, r"embedded_local")) {
        return n00b_result_ok(n00b_store_profile_t,
                              N00B_STORE_PROFILE_EMBEDDED_LOCAL);
    }
    if (rocs_store_string_eq_lit(s, r"local")
        || rocs_store_string_eq_lit(s, r"service_local")) {
        return n00b_result_ok(n00b_store_profile_t,
                              N00B_STORE_PROFILE_SERVICE_LOCAL);
    }
    if (rocs_store_string_eq_lit(s, r"s3")
        || rocs_store_string_eq_lit(s, r"service_s3")) {
        return n00b_result_ok(n00b_store_profile_t,
                              N00B_STORE_PROFILE_SERVICE_S3);
    }
    return n00b_result_err(n00b_store_profile_t, N00B_STORE_ERR_CONFIG);
}

static n00b_result_t(bool)
rocs_store_parse_bool(n00b_string_t *s)
{
    if (rocs_store_string_eq_lit(s, r"true")
        || rocs_store_string_eq_lit(s, r"1")
        || rocs_store_string_eq_lit(s, r"yes")
        || rocs_store_string_eq_lit(s, r"on")) {
        return n00b_result_ok(bool, true);
    }
    if (rocs_store_string_eq_lit(s, r"false")
        || rocs_store_string_eq_lit(s, r"0")
        || rocs_store_string_eq_lit(s, r"no")
        || rocs_store_string_eq_lit(s, r"off")) {
        return n00b_result_ok(bool, false);
    }
    return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
}

static n00b_result_t(uint64_t)
rocs_store_parse_u64(n00b_string_t *s)
{
    auto parsed = n00b_parse_i64(s);
    if (n00b_result_is_err(parsed) || n00b_result_get(parsed) < 0) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_CONFIG);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_result_get(parsed));
}

static n00b_result_t(n00b_store_writer_mode_t)
rocs_store_parse_writer_mode(n00b_string_t *s)
{
    if (rocs_store_string_empty(s)
        || rocs_store_string_eq_lit(s, r"single")
        || rocs_store_string_eq_lit(s, r"writer")
        || rocs_store_string_eq_lit(s, r"single_writer")) {
        return n00b_result_ok(n00b_store_writer_mode_t,
                              N00B_STORE_WRITER_SINGLE);
    }
    if (rocs_store_string_eq_lit(s, r"read_replica")
        || rocs_store_string_eq_lit(s, r"reader")
        || rocs_store_string_eq_lit(s, r"readonly")
        || rocs_store_string_eq_lit(s, r"read_only")) {
        return n00b_result_ok(n00b_store_writer_mode_t,
                              N00B_STORE_WRITER_READ_REPLICA);
    }
    return n00b_result_err(n00b_store_writer_mode_t,
                           N00B_STORE_ERR_CONFIG);
}

static bool
rocs_store_s3_endpoint_valid(n00b_string_t *endpoint)
{
    if (endpoint == nullptr) {
        return true;
    }
    if (rocs_store_string_empty(endpoint)) {
        return false;
    }
    return rocs_store_string_starts_with_lit(endpoint, r"http://")
           || rocs_store_string_starts_with_lit(endpoint, r"https://");
}

static n00b_string_t *
rocs_store_env_key(n00b_string_t    *prefix,
                   n00b_string_t    *key,
                   n00b_allocator_t *allocator)
{
    if (rocs_store_string_empty(prefix)) {
        return key;
    }
    return n00b_unicode_str_cat(prefix, key, .allocator = allocator);
}

static n00b_string_t *
rocs_store_env(n00b_string_t    *prefix,
               n00b_string_t    *key,
               n00b_allocator_t *allocator)
{
    n00b_string_t *full_key = rocs_store_env_key(prefix, key, allocator);
    return n00b_getenv(full_key);
}

static void
rocs_store_config_set_string(n00b_string_t    **slot,
                             n00b_string_t     *value,
                             n00b_allocator_t  *allocator)
{
    *slot = rocs_store_string_copy(value, allocator);
}

static n00b_result_t(bool)
rocs_store_config_validate(n00b_store_config_t *config,
                           n00b_store_schema_t *schema,
                           bool                 for_open)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (config->profile != N00B_STORE_PROFILE_EMBEDDED_LOCAL
        && config->profile != N00B_STORE_PROFILE_SERVICE_LOCAL
        && config->profile != N00B_STORE_PROFILE_SERVICE_S3) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    if (config->writer_mode == N00B_STORE_WRITER_MULTI_UNSUPPORTED) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    if (config->writer_mode != N00B_STORE_WRITER_SINGLE
        && config->writer_mode != N00B_STORE_WRITER_READ_REPLICA) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    if (!rocs_store_s3_endpoint_valid(config->s3_endpoint)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    if (config->profile != N00B_STORE_PROFILE_SERVICE_S3
        && (config->s3_bucket != nullptr || config->s3_prefix != nullptr
            || config->aws_region != nullptr || config->s3_endpoint != nullptr
            || config->has_s3_path_style)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    if (config->profile == N00B_STORE_PROFILE_SERVICE_S3) {
        if (rocs_store_string_empty(config->s3_bucket)
            || rocs_store_string_empty(config->s3_prefix)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
        }
        if (for_open && schema == nullptr) {
            return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
        }
    }
    if (for_open) {
        if (schema == nullptr || rocs_store_string_empty(config->root)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
        }
        if (!rocs_store_root_valid(config->root)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
        }
    }
    return n00b_result_ok(bool, true);
}

static n00b_store_err_t
rocs_store_err_from_plan(n00b_err_t err)
{
    switch ((n00b_plan_err_t)err) {
    case N00B_PLAN_ERR_ARG:
        return N00B_STORE_ERR_ARG;
    case N00B_PLAN_ERR_STATE:
    case N00B_PLAN_ERR_EMPTY:
    case N00B_PLAN_ERR_ANY_UNSUPPORTED:
    case N00B_PLAN_ERR_ORDINAL:
    case N00B_PLAN_ERR_UNIVERSE:
        return N00B_STORE_ERR_INDEX;
    case N00B_PLAN_OK:
        return N00B_STORE_ERR_INTERNAL;
    }

    return N00B_STORE_ERR_INTERNAL;
}

static n00b_store_err_t
rocs_store_err_from_index(n00b_err_t err)
{
    switch ((n00b_store_index_err_t)err) {
    case N00B_STORE_INDEX_ERR_ARG:
        return N00B_STORE_ERR_ARG;
    case N00B_STORE_INDEX_ERR_STATE:
    case N00B_STORE_INDEX_ERR_KIND:
    case N00B_STORE_INDEX_ERR_UNREADY:
    case N00B_STORE_INDEX_ERR_INTERNAL:
        return N00B_STORE_ERR_INDEX;
    case N00B_STORE_INDEX_OK:
        return N00B_STORE_ERR_INTERNAL;
    }

    return N00B_STORE_ERR_INTERNAL;
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_catalog_buffer_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);
    if (buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_buffer_t *, buf);
}

static n00b_result_t(bool)
rocs_store_catalog_append_u8(n00b_buffer_t *buf, uint8_t byte)
{
    if (buf == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    uint64_t pos = (uint64_t)n00b_buffer_len(buf);
    if (pos >= (uint64_t)INT64_MAX) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_buffer_resize(buf, pos + 1);
    auto set_r = n00b_buffer_set_index(buf, (int64_t)pos, byte);
    if (n00b_result_is_err(set_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_append_u64(n00b_buffer_t *buf, uint64_t value)
{
    for (uint8_t i = 0; i < 8; i++) {
        auto append_r = rocs_store_catalog_append_u8(
            buf,
            (uint8_t)((value >> (i * 8)) & 0xff));
        if (n00b_result_is_err(append_r)) {
            return append_r;
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_append_string(n00b_buffer_t *buf, n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    uint64_t len = s == nullptr ? 0 : (uint64_t)s->u8_bytes;
    if (len > (uint64_t)INT64_MAX) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    auto len_r = rocs_store_catalog_append_u64(buf, len);
    if (n00b_result_is_err(len_r)) {
        return len_r;
    }
    if (len == 0) {
        return n00b_result_ok(bool, true);
    }

    n00b_buffer_t *piece = n00b_buffer_from_bytes(s->data,
                                                  (int64_t)len,
                                                  .allocator = allocator);
    if (piece == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }
    n00b_buffer_concat(buf, piece);
    n00b_buffer_free(piece);
    n00b_free(piece);
    return n00b_result_ok(bool, true);
}

typedef struct {
    n00b_buffer_t *buf;
    uint64_t       pos;
    uint64_t       len;
} rocs_store_catalog_reader_t;

static n00b_result_t(uint8_t)
rocs_store_catalog_read_u8(rocs_store_catalog_reader_t *reader)
{
    if (reader == nullptr || reader->buf == nullptr
        || reader->pos >= reader->len || reader->pos > (uint64_t)INT64_MAX) {
        return n00b_result_err(uint8_t, N00B_STORE_ERR_CORRUPT);
    }

    auto byte_r = n00b_buffer_get_index(reader->buf, (int64_t)reader->pos);
    if (n00b_result_is_err(byte_r)) {
        return n00b_result_err(uint8_t, N00B_STORE_ERR_CORRUPT);
    }

    reader->pos++;
    return n00b_result_ok(uint8_t, n00b_result_get(byte_r));
}

static n00b_result_t(uint64_t)
rocs_store_catalog_read_u64(rocs_store_catalog_reader_t *reader)
{
    uint64_t value = 0;

    for (uint8_t i = 0; i < 8; i++) {
        auto byte_r = rocs_store_catalog_read_u8(reader);
        if (n00b_result_is_err(byte_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(byte_r));
        }
        value |= ((uint64_t)n00b_result_get(byte_r)) << (i * 8);
    }

    return n00b_result_ok(uint64_t, value);
}

static n00b_result_t(n00b_string_t *)
rocs_store_catalog_read_string(rocs_store_catalog_reader_t *reader) _kargs
{
    bool              allow_empty = true;
    n00b_allocator_t *allocator   = nullptr;
}
{
    auto len_r = rocs_store_catalog_read_u64(reader);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(len_r));
    }

    uint64_t len = n00b_result_get(len_r);
    if (!allow_empty && len == 0) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_CORRUPT);
    }
    if (reader->pos > reader->len || len > (uint64_t)INT64_MAX
        || reader->len - reader->pos < len) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_CORRUPT);
    }
    if (len == 0) {
        return n00b_result_ok(n00b_string_t *, nullptr);
    }

    n00b_string_t *value =
        n00b_string_from_raw(reader->buf->data + reader->pos,
                             (int64_t)len,
                             .allocator = allocator);
    reader->pos += len;
    return n00b_result_ok(n00b_string_t *, value);
}

static bool
rocs_store_root_valid(n00b_string_t *root)
{
    return !rocs_store_string_empty(root) && root->data != nullptr
        && root->data[0] == '/';
}

static n00b_result_t(n00b_string_t *)
rocs_store_path_join(n00b_string_t *parent, n00b_string_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (parent == nullptr || child == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    if (parent->u8_bytes == 1 && parent->data[0] == '/') {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_unicode_str_cat(r"/", child, .allocator = allocator));
    }
    if (parent->u8_bytes > 0 && parent->data[parent->u8_bytes - 1] == '/') {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_unicode_str_cat(parent, child, .allocator = allocator));
    }

    n00b_string_t *with_slash =
        n00b_unicode_str_cat(parent, r"/", .allocator = allocator);
    return n00b_result_ok(
        n00b_string_t *,
        n00b_unicode_str_cat(with_slash, child, .allocator = allocator));
}

static n00b_result_t(n00b_string_t *)
rocs_store_parent_path(n00b_string_t *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_store_root_valid(path)) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    uint64_t last_slash = 0;
    for (uint64_t i = 1; i < path->u8_bytes; i++) {
        if (path->data[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash == 0) {
        return n00b_result_ok(n00b_string_t *, r"/");
    }

    return n00b_result_ok(
        n00b_string_t *,
        n00b_string_from_raw(path->data,
                             (int64_t)last_slash,
                             .allocator = allocator));
}

static n00b_result_t(n00b_string_t *)
rocs_store_catalog_path(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    auto path_r = rocs_store_path_join(store->root,
                                       r"catalog.rocs",
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static n00b_result_t(n00b_string_t *)
rocs_store_shard_dir_path(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    auto path_r = rocs_store_path_join(store->root,
                                       r"shards",
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static n00b_result_t(n00b_string_t *)
rocs_store_shard_object_path(n00b_store_t *store, uint64_t shard_id)
{
    if (shard_id > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    auto dir_r = rocs_store_shard_dir_path(store);
    if (n00b_result_is_err(dir_r)) {
        return dir_r;
    }

    n00b_string_t *id_s =
        n00b_unicode_str_from_int((int64_t)shard_id,
                                  .allocator = store->allocator);
    n00b_string_t *file =
        n00b_unicode_str_cat(id_s, r".n00b", .allocator = store->allocator);
    auto path_r = rocs_store_path_join(n00b_result_get(dir_r),
                                       file,
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static n00b_result_t(n00b_string_t *)
rocs_store_journal_dir_path(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return rocs_store_path_join(store->root,
                                r"journals",
                                .allocator = store->allocator);
}

static n00b_result_t(n00b_string_t *)
rocs_store_journal_path(n00b_store_t *store, uint64_t shard_id)
{
    if (shard_id == 0 || shard_id > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    auto dir_r = rocs_store_journal_dir_path(store);
    if (n00b_result_is_err(dir_r)) {
        return dir_r;
    }

    n00b_string_t *id_s =
        n00b_unicode_str_from_int((int64_t)shard_id,
                                  .allocator = store->allocator);
    n00b_string_t *file =
        n00b_unicode_str_cat(id_s, r".jrnl", .allocator = store->allocator);
    return rocs_store_path_join(n00b_result_get(dir_r),
                                file,
                                .allocator = store->allocator);
}

static bool
rocs_store_index_kind_valid(n00b_store_index_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_INDEX_NONE:
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return true;
    }
    return false;
}

static bool
rocs_store_ngram_n_valid(uint8_t ngram_n)
{
    return ngram_n >= N00B_STORE_NGRAM_MIN_N
        && ngram_n <= N00B_STORE_NGRAM_MAX_N;
}

static bool
rocs_store_postings_kind_valid(n00b_store_postings_kind_t kind)
{
    return kind == N00B_STORE_POSTINGS_SPARSE
        || kind == N00B_STORE_POSTINGS_DENSE;
}

static n00b_option_t(n00b_store_field_t *)
rocs_store_schema_find_field_raw(n00b_store_schema_t *schema,
                                 n00b_string_t       *name)
{
    if (schema == nullptr || schema->fields == nullptr || name == nullptr) {
        return n00b_option_none(n00b_store_field_t *);
    }

    n00b_list_foreach(*schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field != nullptr && field->name != nullptr
            && n00b_unicode_str_eq(field->name, name)) {
            return n00b_option_set(n00b_store_field_t *, field);
        }
    }

    return n00b_option_none(n00b_store_field_t *);
}

static n00b_store_partition_policy_t *
rocs_store_partition_policy_new(n00b_store_partition_kind_t kind) _kargs
{
    n00b_string_t    *field        = nullptr;
    uint64_t          bucket_width = 0;
    uint32_t          buckets      = 0;
    n00b_store_time_source_t time_source = N00B_STORE_TIME_SOURCE_INGEST_CLOCK;
    n00b_allocator_t *allocator    = nullptr;
}
{
    n00b_store_partition_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_partition_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    policy->kind         = kind;
    policy->field        = field;
    policy->bucket_width = bucket_width;
    policy->buckets      = buckets;
    policy->time_source  = time_source;
    return policy;
}

static n00b_result_t(n00b_string_t *)
rocs_store_route_bucket(n00b_string_t *prefix,
                        uint64_t       bucket) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bucket > (uint64_t)INT64_MAX) {
        return n00b_result_ok(n00b_string_t *, r"default");
    }

    n00b_string_t *bucket_s =
        n00b_unicode_str_from_int((int64_t)bucket, .allocator = allocator);
    n00b_string_t *route =
        n00b_unicode_str_cat(prefix, bucket_s, .allocator = allocator);
    return n00b_result_ok(n00b_string_t *, route);
}

static n00b_option_t(uint64_t)
rocs_store_time_bucket_from_route(n00b_string_t *route)
{
    if (route == nullptr || route->data == nullptr || route->u8_bytes <= 5) {
        return n00b_option_none(uint64_t);
    }
    if (route->data[0] != 't' || route->data[1] != 'i'
        || route->data[2] != 'm' || route->data[3] != 'e'
        || route->data[4] != '/') {
        return n00b_option_none(uint64_t);
    }

    uint64_t bucket = 0;
    for (uint64_t i = 5; i < route->u8_bytes; i++) {
        uint8_t c = (uint8_t)route->data[i];
        if (c < (uint8_t)'0' || c > (uint8_t)'9') {
            return n00b_option_none(uint64_t);
        }
        uint64_t digit = (uint64_t)(c - (uint8_t)'0');
        if (bucket > (UINT64_MAX - digit) / 10) {
            return n00b_option_none(uint64_t);
        }
        bucket = bucket * 10 + digit;
    }

    return n00b_option_set(uint64_t, bucket);
}

static n00b_option_t(n00b_json_node_t *)
rocs_store_partition_value(n00b_store_partition_policy_t *policy,
                           n00b_json_node_t              *record,
                           n00b_allocator_t              *allocator)
{
    if (policy == nullptr || policy->field == nullptr || record == nullptr
        || n00b_json_type(record) != N00B_JSON_OBJECT) {
        return n00b_option_none(n00b_json_node_t *);
    }

    return n00b_option_from_nullable(n00b_json_node_t *,
                                     rocs_json_object_get_field(record,
                                                                policy->field,
                                                                .allocator = allocator));
}

static bool
rocs_store_retain_kind_valid(n00b_store_retain_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_RETAIN_NONE:
    case N00B_STORE_RETAIN_INLINE:
    case N00B_STORE_RETAIN_EXTERNAL:
        return true;
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_ensure_dir(n00b_store_t *store, n00b_string_t *path)
{
    auto stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_ok(stat_r)) {
        if (n00b_result_get(stat_r).kind == N00B_VFS_OBJ_DIR) {
            return n00b_result_ok(bool, true);
        }
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    if (n00b_result_get_err(stat_r) != N00B_VFS_ERR_NOT_FOUND) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto mkdir_r = n00b_vfs_mkdir(store->vfs, path);
    if (n00b_result_is_ok(mkdir_r)) {
        return n00b_result_ok(bool, true);
    }
    if (n00b_result_get_err(mkdir_r) == N00B_VFS_ERR_EXISTS) {
        return n00b_result_ok(bool, true);
    }

    return n00b_result_err(bool, N00B_STORE_ERR_VFS);
}

static n00b_result_t(bool)
rocs_store_ensure_layout(n00b_store_t *store)
{
    auto root_r = rocs_store_ensure_dir(store, store->root);
    if (n00b_result_is_err(root_r)) {
        return root_r;
    }

    auto shard_dir_r = rocs_store_shard_dir_path(store);
    if (n00b_result_is_err(shard_dir_r)) {
        return n00b_result_err(bool, n00b_result_get_err(shard_dir_r));
    }

    auto shards_r = rocs_store_ensure_dir(store, n00b_result_get(shard_dir_r));
    if (n00b_result_is_err(shards_r) || !store->recovery_journal) {
        return shards_r;
    }

    auto journal_dir_r = rocs_store_journal_dir_path(store);
    if (n00b_result_is_err(journal_dir_r)) {
        return n00b_result_err(bool, n00b_result_get_err(journal_dir_r));
    }

    return rocs_store_ensure_dir(store, n00b_result_get(journal_dir_r));
}

static n00b_result_t(bool)
rocs_store_sync_if_supported(n00b_store_t *store, n00b_string_t *path)
{
    auto sync_r = n00b_vfs_sync(store->vfs, path);
    if (n00b_result_is_ok(sync_r)) {
        return n00b_result_ok(bool, true);
    }
    if (n00b_result_get_err(sync_r) == N00B_VFS_ERR_NOT_SUPPORTED) {
        return n00b_result_ok(bool, false);
    }
    return n00b_result_err(bool, N00B_STORE_ERR_VFS);
}

static n00b_result_t(bool)
rocs_store_sync_path_and_parent(n00b_store_t *store, n00b_string_t *path)
{
    auto sync_r = rocs_store_sync_if_supported(store, path);
    if (n00b_result_is_err(sync_r)) {
        return sync_r;
    }

    auto parent_r = rocs_store_parent_path(path, .allocator = store->allocator);
    if (n00b_result_is_err(parent_r)) {
        return n00b_result_err(bool, n00b_result_get_err(parent_r));
    }

    return rocs_store_sync_if_supported(store, n00b_result_get(parent_r));
}

static n00b_result_t(bool)
rocs_store_write_vfs_object(n00b_store_t  *store,
                            n00b_string_t *path,
                            n00b_buffer_t *data) _kargs
{
    bool create_exclusive = false;
}
{
    if (store == nullptr || path == nullptr || data == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    uint32_t flags = N00B_VFS_O_W
                   | (create_exclusive ? N00B_VFS_OPEN_EXCL : 0);
    auto open_r = n00b_vfs_open(store->vfs, path, flags);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_fh_t fh  = n00b_result_get(open_r);
    uint64_t       len = (uint64_t)n00b_buffer_len(data);

    auto write_r = n00b_vfs_write(store->vfs, fh, data);
    if (n00b_result_is_err(write_r) || n00b_result_get(write_r) != len) {
        (void)n00b_vfs_close(store->vfs, fh);
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto close_r = n00b_vfs_close(store->vfs, fh);
    if (n00b_result_is_err(close_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    return rocs_store_sync_path_and_parent(store, path);
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_read_vfs_object(n00b_store_t *store, n00b_string_t *path)
{
    auto stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_err(stat_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }
    if (n00b_result_get(stat_r).kind != N00B_VFS_OBJ_FILE) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t expected_len = n00b_result_get(stat_r).size;
    auto     open_r       = n00b_vfs_open(store->vfs, path, N00B_VFS_O_R);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_fh_t fh     = n00b_result_get(open_r);
    auto          read_r = n00b_vfs_read(store->vfs,
                                         fh,
                                         expected_len,
                                         .allocator = store->allocator);
    auto          close_r = n00b_vfs_close(store->vfs, fh);

    if (n00b_result_is_err(read_r) || n00b_result_is_err(close_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }
    if ((uint64_t)n00b_buffer_len(n00b_result_get(read_r)) != expected_len) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_CORRUPT);
    }

    return read_r;
}

// ============================================================================
// Recovery journal (write-ahead log).
//
// When the store is opened with recovery_journal=true, every record's source
// bytes are appended to the current hot shard's journal under <root>/journals
// before the in-memory commit.  Each journal frame is an 8-byte native-endian
// length prefix followed by that many source bytes.  A torn trailing frame
// (partial write at crash) is detected and ignored during replay.  The journal
// rotates in lock-step with the hot shard and is deleted only after the sealed
// shard is durably committed to the catalog; on seal failure it is retained as
// the re-ingest source for the next open.
//
// NOTE: the VFS commits whole-file images on flush, so per-record flush is
// O(n^2) in journal bytes over a shard's life.  Acceptable for the first cut;
// an incremental-append VFS path is the follow-up.
// ============================================================================

#define N00B_ROCS_JOURNAL_SYNC_INTERVAL 64

static bool
rocs_store_journal_active(n00b_store_t *store)
{
    return store != nullptr && store->recovery_journal && !store->read_only
        && !store->recovering;
}

// Finalize the current journal handle: commit pending writes durably and close
// it, leaving the journal FILE in place.  Clears the in-store handle state.
static void
rocs_store_journal_finalize(n00b_store_t *store)
{
    if (store == nullptr || store->journal_fh == N00B_VFS_FH_INVALID) {
        return;
    }

    n00b_vfs_fh_t  fh   = store->journal_fh;
    n00b_string_t *path = store->journal_path;

    (void)n00b_vfs_flush(store->vfs, fh);
    (void)n00b_vfs_close(store->vfs, fh);
    if (path != nullptr) {
        (void)rocs_store_sync_if_supported(store, path);
    }

    store->journal_fh       = N00B_VFS_FH_INVALID;
    store->journal_path     = nullptr;
    store->journal_shard_id = 0;
    store->journal_unsynced = 0;
}

// Open (creating) a fresh append handle for the given hot shard's journal.
// Best-effort: on failure the store simply has no active journal handle until
// the next rotation, and ingest keeps flowing.
static n00b_result_t(bool)
rocs_store_journal_open(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    auto path_r = rocs_store_journal_path(store, shard_id);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(bool, n00b_result_get_err(path_r));
    }
    n00b_string_t *path = n00b_result_get(path_r);

    auto open_r = n00b_vfs_open(store->vfs, path, N00B_VFS_O_A);
    if (n00b_result_is_err(open_r)) {
        n00b_eprintf("rocs: failed to open recovery journal for shard [|#|] "
                     "(vfs err [|#|]); journaling disabled until next seal\n",
                     shard_id,
                     (int64_t)n00b_result_get_err(open_r));
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    store->journal_fh       = n00b_result_get(open_r);
    store->journal_path     = path;
    store->journal_shard_id = shard_id;
    store->journal_unsynced = 0;
    return n00b_result_ok(bool, true);
}

// Delete a shard's journal file (after its sealed shard is durably committed).
static void
rocs_store_journal_delete(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || shard_id == 0) {
        return;
    }

    auto path_r = rocs_store_journal_path(store, shard_id);
    if (n00b_result_is_err(path_r)) {
        return;
    }
    (void)n00b_vfs_delete(store->vfs, n00b_result_get(path_r));
}

// Append one record's source bytes to the current hot shard's journal, framed
// with an 8-byte native-endian length prefix.  Commits to the backend on every
// append (so an abandoned-without-seal store is still recoverable) and forces a
// durable sync barrier on a fixed cadence.
static n00b_result_t(bool)
rocs_store_journal_append(n00b_store_t *store, n00b_buffer_t *source)
{
    if (!rocs_store_journal_active(store)
        || store->journal_fh == N00B_VFS_FH_INVALID) {
        return n00b_result_ok(bool, true);
    }
    if (source == nullptr) {
        // No source bytes (record-only ingest path): nothing to journal.
        return n00b_result_ok(bool, true);
    }

    uint64_t payload_len = (uint64_t)n00b_buffer_len(source);
    if (payload_len == 0) {
        return n00b_result_ok(bool, true);
    }

    uint64_t       header = payload_len;
    n00b_buffer_t *frame  = n00b_buffer_from_bytes((char *)&header,
                                                   (int64_t)sizeof(header),
                                                   .allocator = store->allocator);
    if (frame == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }
    n00b_buffer_concat(frame, source);

    auto write_r = n00b_vfs_write(store->vfs, store->journal_fh, frame);
    if (n00b_result_is_err(write_r)
        || n00b_result_get(write_r) != (uint64_t)n00b_buffer_len(frame)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto flush_r = n00b_vfs_flush(store->vfs, store->journal_fh);
    if (n00b_result_is_err(flush_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    store->journal_unsynced++;
    if (store->journal_unsynced >= N00B_ROCS_JOURNAL_SYNC_INTERVAL) {
        if (store->journal_path != nullptr) {
            (void)rocs_store_sync_if_supported(store, store->journal_path);
        }
        store->journal_unsynced = 0;
    }

    return n00b_result_ok(bool, true);
}

static n00b_store_catalog_entry_t *
rocs_store_catalog_entry_new(n00b_store_t *store) _kargs
{
    uint64_t       shard_id          = 0;
    uint64_t       generation        = 0;
    n00b_string_t *object_path       = nullptr;
    uint64_t       byte_len          = 0;
    uint64_t       record_count      = 0;
    uint64_t       schema_generation = 0;
    uint64_t       seal_ts           = 0;
    n00b_string_t *partition_key     = nullptr;
    n00b_string_t *etag              = nullptr;
}
{
    n00b_store_catalog_entry_t *entry = n00b_alloc_with_opts(
        n00b_store_catalog_entry_t,
        &(n00b_alloc_opts_t){
            .allocator = store == nullptr ? nullptr : store->allocator,
        });

    entry->object_path       = object_path;
    entry->owner             = store;
    entry->partition_key     = rocs_store_string_copy(
        partition_key == nullptr ? r"default" : partition_key,
        store == nullptr ? nullptr : store->allocator);
    if (entry->partition_key == nullptr) {
        entry->partition_key = r"default";
    }
    entry->etag              = etag;
    entry->shard_id          = shard_id;
    entry->generation        = generation;
    entry->byte_len          = byte_len;
    entry->record_count      = record_count;
    entry->schema_generation = schema_generation;
    entry->seal_ts           = seal_ts;
    return entry;
}

static n00b_option_t(n00b_store_catalog_entry_t *)
rocs_store_catalog_find_raw(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_option_none(n00b_store_catalog_entry_t *);
    }

    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry != nullptr && entry->shard_id == shard_id) {
            return n00b_option_set(n00b_store_catalog_entry_t *, entry);
        }
    }

    return n00b_option_none(n00b_store_catalog_entry_t *);
}

static bool
rocs_store_catalog_find_index(n00b_store_t *store,
                              uint64_t      shard_id,
                              uint64_t     *index_out)
{
    if (store == nullptr || store->catalog == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry != nullptr && entry->shard_id == shard_id) {
            if (index_out != nullptr) {
                *index_out = (uint64_t)i;
            }
            return true;
        }
    }

    return false;
}

static bool
rocs_store_entry_pos_less(n00b_store_catalog_entry_t *a,
                          n00b_store_catalog_entry_t *b)
{
    if (a == nullptr) {
        return false;
    }
    if (b == nullptr) {
        return true;
    }
    if (a->generation != b->generation) {
        return a->generation < b->generation;
    }
    return a->shard_id < b->shard_id;
}

static void
rocs_store_catalog_insert_sorted(n00b_store_t              *store,
                                 n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || store->catalog == nullptr || entry == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *cur =
            n00b_list_get(*store->catalog, i);
        if (cur != nullptr && rocs_store_entry_pos_less(entry, cur)) {
            n00b_list_insert(*store->catalog, i, entry);
            return;
        }
    }

    n00b_list_push(*store->catalog, entry);
}

static n00b_option_t(n00b_store_pos_t)
rocs_store_compute_oldest_available(n00b_store_t               *store,
                                    n00b_store_catalog_entry_t *pending_entry)
{
    if (store == nullptr) {
        return n00b_option_none(n00b_store_pos_t);
    }

    n00b_store_catalog_entry_t *oldest = nullptr;
    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry != nullptr && rocs_store_entry_pos_less(entry, oldest)) {
                oldest = entry;
            }
        }
    }
    if (pending_entry != nullptr
        && rocs_store_entry_pos_less(pending_entry, oldest)) {
        oldest = pending_entry;
    }

    if (oldest == nullptr) {
        return n00b_option_none(n00b_store_pos_t);
    }

    return n00b_option_set(
        n00b_store_pos_t,
        ((n00b_store_pos_t){
            .shard_id   = oldest->shard_id,
            .ordinal    = 0,
            .generation = oldest->generation,
        }));
}

static void
rocs_store_refresh_oldest_available(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    n00b_option_t(n00b_store_pos_t) oldest =
        rocs_store_compute_oldest_available(store, nullptr);
    store->has_oldest_available = n00b_option_is_set(oldest);
    store->oldest_available =
        store->has_oldest_available
            ? n00b_option_get(oldest)
            : (n00b_store_pos_t){};
}

static bool
rocs_store_catalog_owns_entry(n00b_store_t              *store,
                              n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || store->catalog == nullptr || entry == nullptr) {
        return false;
    }

    n00b_list_foreach(*store->catalog, p) {
        if (*p == entry) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_resident_unload_entry(n00b_store_t              *store,
                                 n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (entry->resident_map == nullptr) {
        return n00b_result_ok(bool, false);
    }
    if (entry->resident_pins != 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    auto close_r = n00b_store_map_close(entry->resident_map);
    if (n00b_result_is_err(close_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_RESIDENCY);
    }

    entry->resident_map   = nullptr;
    entry->last_access_ns = 0;
    if (store->resident_bytes >= entry->byte_len) {
        store->resident_bytes -= entry->byte_len;
    }
    else {
        store->resident_bytes = 0;
    }
    if (store->resident_shards != 0) {
        store->resident_shards--;
    }
    store->resident_unloads++;
    if (store->resident_unload_bytes > UINT64_MAX - entry->byte_len) {
        store->resident_unload_bytes = UINT64_MAX;
    }
    else {
        store->resident_unload_bytes += entry->byte_len;
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(uint64_t)
rocs_store_resident_unload_all_unpinned(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t released = 0;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry == nullptr || entry->resident_map == nullptr) {
            continue;
        }
        if (entry->resident_pins != 0) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_PINNED);
        }
        uint64_t len = entry->byte_len;
        auto unload_r = rocs_store_resident_unload_entry(store, entry);
        if (n00b_result_is_err(unload_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(unload_r));
        }
        if (n00b_result_get(unload_r)) {
            released += len;
        }
    }
    return n00b_result_ok(uint64_t, released);
}

static n00b_store_catalog_entry_t *
rocs_store_oldest_unpinned_resident(n00b_store_t *store, uint64_t now_ns)
{
    n00b_store_catalog_entry_t *best = nullptr;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry == nullptr || entry->resident_map == nullptr
            || entry->resident_pins != 0) {
            continue;
        }
        if (store->residency_policy.idle_ns != 0
            && entry->last_access_ns != 0
            && now_ns >= entry->last_access_ns
            && now_ns - entry->last_access_ns >= store->residency_policy.idle_ns) {
            return entry;
        }
        if (best == nullptr || entry->last_access_ns < best->last_access_ns) {
            best = entry;
        }
    }
    return best;
}

static n00b_result_t(n00b_store_map_t *)
rocs_store_resident_load_entry(n00b_store_t              *store,
                               n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    if (entry->resident_map != nullptr) {
        entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
        store->resident_cache_hits++;
        return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
    }
    store->resident_cache_misses++;

    auto verify_r = n00b_store_catalog_entry_verify_object(store, entry);
    if (n00b_result_is_err(verify_r)) {
        return n00b_result_err(n00b_store_map_t *, n00b_result_get_err(verify_r));
    }

    auto map_r = n00b_store_map_open_vfs(store->vfs,
                                         entry->object_path,
                                         .cache     = store->cache,
                                         .policy    = &store->residency_policy,
                                         .allocator = store->allocator);
    if (n00b_result_is_err(map_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_RESIDENCY);
    }

    if (store->resident_bytes > UINT64_MAX - entry->byte_len
        || store->resident_shards == UINT64_MAX) {
        (void)n00b_store_map_close(n00b_result_get(map_r));
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }

    entry->resident_map   = n00b_result_get(map_r);
    entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
    store->resident_bytes += entry->byte_len;
    store->resident_shards++;
    return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
}

static n00b_result_t(bool)
rocs_store_catalog_append_entry(n00b_store_t               *store,
                                n00b_buffer_t              *buf,
                                n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->object_path == nullptr
        || entry->partition_key == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    auto r = rocs_store_catalog_append_u64(buf, entry->shard_id);
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->generation);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->byte_len);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->record_count);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->schema_generation);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->seal_ts);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->object_path,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->partition_key,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->etag,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool, n00b_result_get_err(r));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_catalog_serialize(n00b_store_t *store) _kargs
{
    n00b_store_catalog_entry_t *pending_entry       = nullptr;
    uint64_t                    next_open_shard_id  = 0;
}
{
    auto buf_r = rocs_store_catalog_buffer_new(.allocator = store->allocator);
    if (n00b_result_is_err(buf_r)) {
        return buf_r;
    }
    n00b_buffer_t *buf = n00b_result_get(buf_r);

    uint8_t magic[ROCS_STORE_CATALOG_MAGIC_LEN] = {
        'R', 'O', 'C', 'S', 'C', 'A', 'T', '1',
    };
    for (uint8_t i = 0; i < ROCS_STORE_CATALOG_MAGIC_LEN; i++) {
        auto magic_r = rocs_store_catalog_append_u8(buf, magic[i]);
        if (n00b_result_is_err(magic_r)) {
            return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(magic_r));
        }
    }

    uint64_t serialized_open_shard_id =
        next_open_shard_id != 0
            ? next_open_shard_id
            : (store->hot_shard == nullptr ? store->next_shard_id
                                           : store->hot_shard->shard_id);

    uint64_t entry_count =
        store->catalog == nullptr ? 0 : (uint64_t)n00b_list_len(*store->catalog);
    if (pending_entry != nullptr) {
        entry_count++;
    }

    auto oldest_opt = rocs_store_compute_oldest_available(store, pending_entry);
    n00b_store_pos_t oldest = n00b_option_is_set(oldest_opt)
                                  ? n00b_option_get(oldest_opt)
                                  : (n00b_store_pos_t){};

    auto version_r = rocs_store_catalog_append_u64(buf,
                                                   ROCS_STORE_CATALOG_VERSION);
    auto generation_r = rocs_store_catalog_append_u64(buf, store->generation);
    auto next_r = rocs_store_catalog_append_u64(buf, serialized_open_shard_id);
    auto schema_r = rocs_store_catalog_append_u64(buf, store->schema_generation);
    auto oldest_gen_r = rocs_store_catalog_append_u64(buf, oldest.generation);
    auto oldest_shard_r = rocs_store_catalog_append_u64(buf, oldest.shard_id);
    auto oldest_ordinal_r = rocs_store_catalog_append_u64(buf, oldest.ordinal);
    auto count_r = rocs_store_catalog_append_u64(buf, entry_count);
    if (n00b_result_is_err(version_r) || n00b_result_is_err(generation_r)
        || n00b_result_is_err(next_r) || n00b_result_is_err(schema_r)
        || n00b_result_is_err(oldest_gen_r)
        || n00b_result_is_err(oldest_shard_r)
        || n00b_result_is_err(oldest_ordinal_r)
        || n00b_result_is_err(count_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_INTERNAL);
    }

    n00b_err_t entry_err = N00B_STORE_OK;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry_err == N00B_STORE_OK) {
            auto append_r = rocs_store_catalog_append_entry(store, buf, entry);
            if (n00b_result_is_err(append_r)) {
                entry_err = n00b_result_get_err(append_r);
            }
        }
    }
    if (entry_err != N00B_STORE_OK) {
        return n00b_result_err(n00b_buffer_t *, entry_err);
    }
    if (pending_entry != nullptr) {
        auto append_r =
            rocs_store_catalog_append_entry(store, buf, pending_entry);
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_buffer_t *,
                                   n00b_result_get_err(append_r));
        }
    }

    return n00b_result_ok(n00b_buffer_t *, buf);
}

static n00b_result_t(bool)
rocs_store_catalog_parse(n00b_store_t *store, n00b_buffer_t *buf)
{
    rocs_store_catalog_reader_t reader = {
        .buf = buf,
        .pos = 0,
        .len = (uint64_t)n00b_buffer_len(buf),
    };

    uint8_t magic[ROCS_STORE_CATALOG_MAGIC_LEN] = {
        'R', 'O', 'C', 'S', 'C', 'A', 'T', '1',
    };
    for (uint8_t i = 0; i < ROCS_STORE_CATALOG_MAGIC_LEN; i++) {
        auto byte_r = rocs_store_catalog_read_u8(&reader);
        if (n00b_result_is_err(byte_r)
            || n00b_result_get(byte_r) != magic[i]) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }
    }

    auto version_r = rocs_store_catalog_read_u64(&reader);
    auto gen_r     = rocs_store_catalog_read_u64(&reader);
    auto next_r    = rocs_store_catalog_read_u64(&reader);
    auto schema_r  = rocs_store_catalog_read_u64(&reader);
    if (n00b_result_is_err(version_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(next_r) || n00b_result_is_err(schema_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t version = n00b_result_get(version_r);
    if (version < ROCS_STORE_CATALOG_VERSION_MIN
        || version > ROCS_STORE_CATALOG_VERSION) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    store->generation        = n00b_result_get(gen_r);
    store->schema_generation = n00b_result_get(schema_r);
    store->has_oldest_available = false;
    store->oldest_available     = (n00b_store_pos_t){};

    if (version >= 2) {
        auto oldest_gen_r     = rocs_store_catalog_read_u64(&reader);
        auto oldest_shard_r   = rocs_store_catalog_read_u64(&reader);
        auto oldest_ordinal_r = rocs_store_catalog_read_u64(&reader);
        if (n00b_result_is_err(oldest_gen_r)
            || n00b_result_is_err(oldest_shard_r)
            || n00b_result_is_err(oldest_ordinal_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        uint64_t oldest_shard = n00b_result_get(oldest_shard_r);
        if (oldest_shard != 0) {
            store->oldest_available = (n00b_store_pos_t){
                .generation = n00b_result_get(oldest_gen_r),
                .shard_id   = oldest_shard,
                .ordinal    = n00b_result_get(oldest_ordinal_r),
            };
            store->has_oldest_available = true;
        }
    }

    auto count_r = rocs_store_catalog_read_u64(&reader);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t next_open_shard_id = n00b_result_get(next_r);
    uint64_t entry_count        = n00b_result_get(count_r);
    uint64_t max_shard_id       = 0;

    for (uint64_t i = 0; i < entry_count; i++) {
        auto shard_id_r  = rocs_store_catalog_read_u64(&reader);
        auto entry_gen_r = rocs_store_catalog_read_u64(&reader);
        auto bytes_r     = rocs_store_catalog_read_u64(&reader);
        auto records_r   = rocs_store_catalog_read_u64(&reader);
        auto schema_gen_r = rocs_store_catalog_read_u64(&reader);
        auto seal_ts_r   = rocs_store_catalog_read_u64(&reader);
        if (n00b_result_is_err(shard_id_r) || n00b_result_is_err(entry_gen_r)
            || n00b_result_is_err(bytes_r) || n00b_result_is_err(records_r)
            || n00b_result_is_err(schema_gen_r)
            || n00b_result_is_err(seal_ts_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        auto path_r = rocs_store_catalog_read_string(
            &reader,
            .allow_empty = false,
            .allocator   = store->allocator);
        auto partition_r = rocs_store_catalog_read_string(
            &reader,
            .allow_empty = false,
            .allocator   = store->allocator);
        auto etag_r = rocs_store_catalog_read_string(
            &reader,
            .allocator = store->allocator);
        if (n00b_result_is_err(path_r) || n00b_result_is_err(partition_r)
            || n00b_result_is_err(etag_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        uint64_t shard_id = n00b_result_get(shard_id_r);
        auto     shard_opt = rocs_store_catalog_find_raw(store, shard_id);
        if (shard_id == 0 || n00b_option_is_set(shard_opt)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }
        if (shard_id > max_shard_id) {
            max_shard_id = shard_id;
        }

        n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
            store,
            .shard_id          = shard_id,
            .generation        = n00b_result_get(entry_gen_r),
            .object_path       = n00b_result_get(path_r),
            .byte_len          = n00b_result_get(bytes_r),
            .record_count      = n00b_result_get(records_r),
            .schema_generation = n00b_result_get(schema_gen_r),
            .seal_ts           = n00b_result_get(seal_ts_r),
            .partition_key     = n00b_result_get(partition_r),
            .etag              = n00b_result_get(etag_r));
        n00b_list_push(*store->catalog, entry);
    }

    if (reader.pos != reader.len || next_open_shard_id == 0
        || next_open_shard_id <= max_shard_id) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    store->next_shard_id = next_open_shard_id + 1;
    rocs_store_refresh_oldest_available(store);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_load(n00b_store_t *store)
{
    auto path_r = rocs_store_catalog_path(store);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(bool, n00b_result_get_err(path_r));
    }

    n00b_string_t *path   = n00b_result_get(path_r);
    auto           stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_err(stat_r)) {
        if (n00b_result_get_err(stat_r) == N00B_VFS_ERR_NOT_FOUND) {
            return n00b_result_ok(bool, false);
        }
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto buf_r = rocs_store_read_vfs_object(store, path);
    if (n00b_result_is_err(buf_r)) {
        return n00b_result_err(bool, n00b_result_get_err(buf_r));
    }

    return rocs_store_catalog_parse(store, n00b_result_get(buf_r));
}

static n00b_result_t(uint64_t)
rocs_store_first_free_hot_shard_id(n00b_store_t *store, uint64_t candidate)
{
    if (store == nullptr || candidate == 0) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t shard_id = candidate;
    for (;;) {
        if (shard_id == UINT64_MAX) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
        }

        if (n00b_option_is_set(rocs_store_catalog_find_raw(store, shard_id))) {
            shard_id++;
            continue;
        }

        auto path_r = rocs_store_shard_object_path(store, shard_id);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(path_r));
        }

        auto stat_r = n00b_vfs_stat(store->vfs, n00b_result_get(path_r));
        if (n00b_result_is_err(stat_r)) {
            if (n00b_result_get_err(stat_r) == N00B_VFS_ERR_NOT_FOUND) {
                return n00b_result_ok(uint64_t, shard_id);
            }
            return n00b_result_err(uint64_t, N00B_STORE_ERR_VFS);
        }

        shard_id++;
    }
}

static n00b_result_t(bool)
rocs_store_catalog_write_staged(n00b_store_t               *store,
                                n00b_store_catalog_entry_t *pending_entry,
                                uint64_t                    next_open_shard_id)
{
    auto path_r = rocs_store_catalog_path(store);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(bool, n00b_result_get_err(path_r));
    }

    auto buf_r = rocs_store_catalog_serialize(
        store,
        .pending_entry      = pending_entry,
        .next_open_shard_id = next_open_shard_id);
    if (n00b_result_is_err(buf_r)) {
        return n00b_result_err(bool, n00b_result_get_err(buf_r));
    }

    return rocs_store_write_vfs_object(store,
                                       n00b_result_get(path_r),
                                       n00b_result_get(buf_r));
}

static n00b_result_t(bool)
rocs_store_catalog_write(n00b_store_t *store)
{
    return rocs_store_catalog_write_staged(store, nullptr, 0);
}

static bool
rocs_store_parse_shard_file_name(n00b_string_t  *name,
                                 uint64_t       *shard_id,
                                 n00b_string_t **base_name,
                                 n00b_allocator_t *allocator)
{
    if (name == nullptr || name->data == nullptr || shard_id == nullptr) {
        return false;
    }

    char  *data  = (char *)name->data;
    size_t len   = name->u8_bytes;
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '/') {
            start = i + 1;
        }
    }

    size_t base_len = len - start;
    if (base_len <= 5) {
        return false;
    }
    if (memcmp(data + start + base_len - 5, ".n00b", 5) != 0) {
        return false;
    }

    size_t digits_len = base_len - 5;
    if (digits_len == 0) {
        return false;
    }

    uint64_t id = 0;
    for (size_t i = 0; i < digits_len; i++) {
        char c = data[start + i];
        if (c < '0' || c > '9') {
            return false;
        }

        uint64_t digit = (uint64_t)(c - '0');
        if (id > (UINT64_MAX - digit) / 10) {
            return false;
        }
        id = id * 10 + digit;
    }

    if (id == 0) {
        return false;
    }

    *shard_id = id;
    if (base_name != nullptr) {
        *base_name = start == 0
                         ? name
                         : n00b_string_from_raw(data + start,
                                                (int64_t)base_len,
                                                .allocator = allocator);
    }
    return true;
}

static bool
rocs_store_orphaned_shard_metadata(n00b_store_t      *store,
                                   n00b_string_t     *object_path,
                                   uint64_t           expected_shard_id,
                                   uint64_t          *record_count,
                                   uint64_t          *seal_ts)
{
    auto map_r = n00b_store_map_open_vfs(store->vfs,
                                         object_path,
                                         .cache     = store->cache,
                                         .policy    = &store->residency_policy,
                                         .allocator = store->allocator);
    if (n00b_result_is_err(map_r)) {
        return false;
    }

    n00b_store_map_t *map = n00b_result_get(map_r);
    auto root_r = n00b_store_map_root(map);
    if (n00b_result_is_err(root_r)) {
        (void)n00b_store_map_close(map);
        return false;
    }

    n00b_store_map_shard_t *root = n00b_result_get(root_r);
    auto id_r      = n00b_store_map_shard_id(root);
    auto state_r   = n00b_store_map_shard_state(root);
    auto records_r = n00b_store_map_shard_records_len(root);
    auto seal_ts_r = n00b_store_map_shard_seal_ts(root);
    if (n00b_result_is_err(id_r) || n00b_result_is_err(state_r)
        || n00b_result_is_err(records_r) || n00b_result_is_err(seal_ts_r)) {
        (void)n00b_store_map_close(map);
        return false;
    }

    bool ok = n00b_result_get(id_r) == expected_shard_id
           && n00b_result_get(state_r) == N00B_SHARD_STATE_SEALED;
    if (ok) {
        *record_count = n00b_result_get(records_r);
        *seal_ts      = n00b_result_get(seal_ts_r);
    }

    (void)n00b_store_map_close(map);
    return ok;
}

static n00b_result_t(uint64_t)
rocs_store_recover_orphaned_shards(n00b_store_t *store)
{
    if (store == nullptr || store->vfs == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    auto dir_r = rocs_store_shard_dir_path(store);
    if (n00b_result_is_err(dir_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(dir_r));
    }

    n00b_string_t *dir = n00b_result_get(dir_r);
    auto list_r = n00b_vfs_readdir(store->vfs,
                                   dir,
                                   0,
                                   .allocator = store->allocator);
    if (n00b_result_is_err(list_r)) {
        if (n00b_result_get_err(list_r) == N00B_VFS_ERR_NOT_FOUND) {
            return n00b_result_ok(uint64_t, 0);
        }
        return n00b_result_err(uint64_t, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_list_result_t *list = n00b_result_get(list_r);
    uint64_t                recovered = 0;
    for (uint32_t i = 0; i < list->count; i++) {
        n00b_vfs_list_entry_t *listed = &list->entries[i];
        if (listed->kind != N00B_VFS_OBJ_FILE) {
            continue;
        }

        uint64_t       shard_id = 0;
        n00b_string_t *base     = nullptr;
        if (!rocs_store_parse_shard_file_name(listed->name,
                                              &shard_id,
                                              &base,
                                              store->allocator)) {
            continue;
        }
        if (n00b_option_is_set(rocs_store_catalog_find_raw(store, shard_id))) {
            continue;
        }

        auto path_r = rocs_store_path_join(dir,
                                           base,
                                           .allocator = store->allocator);
        if (n00b_result_is_err(path_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(path_r));
        }

        n00b_string_t *path = n00b_result_get(path_r);
        auto stat_r = n00b_vfs_stat(store->vfs, path);
        if (n00b_result_is_err(stat_r)) {
            continue;
        }

        n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
        if (stat.kind != N00B_VFS_OBJ_FILE) {
            continue;
        }

        uint64_t record_count = 0;
        uint64_t seal_ts      = 0;
        if (!rocs_store_orphaned_shard_metadata(store,
                                                path,
                                                shard_id,
                                                &record_count,
                                                &seal_ts)) {
            continue;
        }

        n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
            store,
            .shard_id          = shard_id,
            .generation        = store->generation,
            .object_path       = path,
            .byte_len          = stat.size,
            .record_count      = record_count,
            .schema_generation = store->schema_generation,
            .seal_ts           = seal_ts,
            .partition_key     = r"default",
            .etag              = stat.etag);

        rocs_store_catalog_insert_sorted(store, entry);
        recovered++;
    }

    if (recovered != 0) {
        rocs_store_refresh_oldest_available(store);
        auto write_r = rocs_store_catalog_write(store);
        if (n00b_result_is_err(write_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(write_r));
        }
    }

    return n00b_result_ok(uint64_t, recovered);
}

static bool
rocs_store_commit_topic_ready(n00b_store_commit_topic_t *topic)
{
    if (topic == nullptr) {
        return false;
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    return n00b_conduit_topic_is_active(base) && base->conduit != nullptr;
}

static bool
rocs_store_emit_commit(n00b_store_t             *store,
                       n00b_store_commit_kind_t  kind,
                       uint64_t                  shard_id,
                       uint64_t                  ordinal,
                       uint64_t                  record_count,
                       uint64_t                  seal_ts,
                       n00b_string_t            *partition_key)
{
    if (store == nullptr || !rocs_store_commit_topic_ready(store->commit_topic)) {
        return false;
    }

    n00b_conduit_topic_base_t *base =
        (n00b_conduit_topic_base_t *)store->commit_topic;
    n00b_result_t(n00b_conduit_publisher_t *) pub_r =
        n00b_conduit_publish_try_claim(base);
    if (n00b_result_is_err(pub_r)) {
        return false;
    }

    n00b_conduit_publisher_t *pub = n00b_result_get(pub_r);
    n00b_store_commit_msg_t  *msg = n00b_alloc_with_opts(
        n00b_store_commit_msg_t,
        &(n00b_alloc_opts_t){
            .allocator = base->conduit->allocator,
        });
    if (msg == nullptr) {
        n00b_conduit_publish_yield(pub);
        return false;
    }

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = base;
    msg->header.generation = n00b_conduit_topic_generation(base);
    msg->header.epoch      = n00b_conduit_topic_epoch(base);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload.kind          = kind;
    msg->payload.generation    = store->generation;
    msg->payload.shard_id      = shard_id;
    msg->payload.ordinal       = ordinal;
    msg->payload.record_count  = record_count;
    msg->payload.seal_ts       = seal_ts;
    msg->payload.partition_key =
        rocs_store_string_copy(partition_key == nullptr ? r"default"
                                                        : partition_key,
                               base->conduit->allocator);
    if (msg->payload.partition_key == nullptr) {
        n00b_conduit_publish_yield(pub);
        return false;
    }

    n00b_conduit_topic_deliver_msg(n00b_store_commit_t,
                                   store->commit_topic,
                                   msg,
                                   N00B_CONDUIT_OP_ALL);
    n00b_conduit_publish_yield(pub);
    return true;
}

static n00b_result_t(n00b_store_catalog_entry_t *)
rocs_store_seal_hot_shard_unlocked(n00b_store_t  *store,
                                   uint64_t       seal_ts,
                                   uint32_t       base_address,
                                   n00b_allocator_t *allocator,
                                   n00b_string_t *partition_key,
                                   bool           residency_locked)
{
    if (store == nullptr || store->hot_shard == nullptr
        || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_STATE);
    }
    if (store->next_shard_id == UINT64_MAX) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_STATE);
    }

    n00b_string_t *entry_partition =
        partition_key != nullptr ? partition_key
        : store->hot_partition_key != nullptr ? store->hot_partition_key
                                              : r"default";

    uint64_t shard_id = store->hot_shard->shard_id;
    auto existing = rocs_store_catalog_find_raw(store, shard_id);
    if (shard_id == 0 || n00b_option_is_set(existing)) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_CORRUPT);
    }

    auto path_r = rocs_store_shard_object_path(store, shard_id);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(path_r));
    }
    n00b_string_t *object_path = n00b_result_get(path_r);

    n00b_shard_state_t old_shard_state   = store->hot_shard->state;
    uint64_t           old_shard_seal_ts = store->hot_shard->seal_ts;
    n00b_allocator_t   *old_hot_allocator = store->hot_allocator;
    uint64_t            old_record_count = store->hot_shard->record_count;
#if defined(N00B_ROCS_TRACE)
    uint64_t            old_byte_estimate = store->hot_shard->byte_estimate;
#endif
    n00b_store_shard_t *old_shard = store->hot_shard;

    // ==================================================================
    // Rotation seal (hot ingest / flush / explicit): under commit_lock,
    // swap in a fresh hot shard so ingest keeps flowing, then marshal the
    // detached, exclusively-owned old shard with the lock RELEASED (no STW,
    // no concurrent dict needed).  Skipped when residency_lock is held
    // (n00b_store_close only): reacquiring commit_lock while holding
    // residency_lock would invert the commit->residency order and deadlock,
    // and shutdown can afford the inline blocking seal below.
    // ==================================================================
    if (!residency_locked) {
        // ---- Phase 1: rotate (commit_lock held) ----------------------
        // Fallible allocations first: a failure here leaves the old shard
        // installed (rollback-safe — nothing has rotated yet).
        uint64_t rot_next_id = store->next_shard_id;
        auto     rot_alloc_r = rocs_store_hot_allocator_new(store);
        if (n00b_result_is_err(rot_alloc_r)) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(rot_alloc_r));
        }
        n00b_allocator_t *rot_next_alloc = n00b_result_get(rot_alloc_r);

        auto rot_shard_r = n00b_store_shard_new(
            .shard_id   = rot_next_id,
            .retain_raw = store->retain_policy != nullptr
                       && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
            .open_ts    = (uint64_t)n00b_ns_timestamp(),
            .allocator  = rot_next_alloc);
        if (n00b_result_is_err(rot_shard_r)) {
            rocs_store_hot_allocator_destroy(store, rot_next_alloc, 0);
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(rot_shard_r));
        }

        // Infallible swap: new ingest immediately flows into the fresh shard;
        // old_shard is now detached and exclusively owned by this worker (the
        // commit_lock-guarded swap is the single-owner claim).
        store->hot_shard         = n00b_result_get(rot_shard_r);
        store->hot_allocator     = rot_next_alloc;
        store->hot_partition_key = r"default";
        store->next_shard_id     = rot_next_id + 1;

        // Rotate the recovery journal in lock-step: finalize (commit + close,
        // keep the file) old_shard's journal and open a fresh one for the new
        // hot shard.  old_shard's journal is retained until Phase 3 confirms the
        // sealed shard is durably committed; on seal failure it stays put as the
        // re-ingest source for the next open.
        if (store->recovery_journal && !store->recovering) {
            rocs_store_journal_finalize(store);
            (void)rocs_store_journal_open(store, rot_next_id);
        }

        n00b_data_unlock(store->commit_lock);

        // ---- Phase 2: marshal the detached old shard (NO lock, NO STW) --
        n00b_pool_t       rot_seal_pool  = {};
        n00b_allocator_t *rot_seal_alloc = allocator;
        bool              rot_seal_owned = false;
        if (rot_seal_alloc == nullptr) {
            rot_seal_alloc = n00b_pool_init(&rot_seal_pool,
                                            .hidden            = true,
                                            .external_metadata = true,
                                            .name = "rocs_seal_image_scratch");
            rot_seal_owned = true;
        }

        n00b_err_t          rot_err  = N00B_STORE_OK;
        uint64_t            rot_len  = 0;
        n00b_vfs_obj_stat_t rot_stat = {};
        auto rot_image_r = n00b_store_shard_seal(old_shard,
                                                 .seal_ts      = seal_ts,
                                                 .base_address = base_address,
                                                 .allocator    = rot_seal_alloc);
        if (n00b_result_is_err(rot_image_r)) {
            rot_err = N00B_STORE_ERR_INTERNAL;
        }
        else {
            n00b_buffer_t *rot_image = n00b_result_get(rot_image_r);
            rot_len                  = (uint64_t)n00b_buffer_len(rot_image);
            auto rot_write_r         = rocs_store_write_vfs_object(
                store, object_path, rot_image, .create_exclusive = true);
            if (n00b_result_is_err(rot_write_r)) {
                rot_err = n00b_result_get_err(rot_write_r);
            }
            else {
                auto rot_stat_r = n00b_vfs_stat(store->vfs, object_path);
                if (n00b_result_is_err(rot_stat_r)) {
                    (void)n00b_vfs_delete(store->vfs, object_path);
                    rot_err = N00B_STORE_ERR_VFS;
                }
                else {
                    rot_stat = n00b_result_get(rot_stat_r);
                    if (rot_stat.kind != N00B_VFS_OBJ_FILE
                        || rot_stat.size != rot_len) {
                        (void)n00b_vfs_delete(store->vfs, object_path);
                        rot_err = N00B_STORE_ERR_CORRUPT;
                    }
                }
            }
        }
        if (rot_seal_owned) {
            n00b_allocator_destroy(rot_seal_alloc);
        }

        // ---- Phase 3: commit (reacquire commit_lock) -------------------
        n00b_data_write_lock(store->commit_lock);

        if (rot_err != N00B_STORE_OK) {
            // Rotation is irreversible (rare: marshal/VFS failure).  With the
            // recovery journal active, old_shard's journal is retained (not
            // deleted) so its records are replayed on the next open; without it,
            // the records are dropped.  Ingest stays available either way.
            n00b_eprintf("rocs: seal of shard [|#|] failed (err [|#|]); "
                         "rotation already committed — records [|#|]\n",
                         shard_id,
                         (int64_t)rot_err,
                         store->recovery_journal ? r"retained in journal"
                                                 : r"dropped");
            if (!store->recovery_journal) {
                store->durable_drop_count   += 1;
                store->durable_drop_records += old_record_count;
                store->durable_drop_last_err = rot_err;
            }
            rocs_store_retire_hot_allocator(store,
                                            old_hot_allocator,
                                            shard_id,
                                            store->generation,
                                            old_record_count);
            return n00b_result_err(n00b_store_catalog_entry_t *, rot_err);
        }

        n00b_store_catalog_entry_t *rot_entry = rocs_store_catalog_entry_new(
            store,
            .shard_id          = shard_id,
            .generation        = store->generation,
            .object_path       = object_path,
            .byte_len          = rot_stat.size,
            .record_count      = old_record_count,
            .schema_generation = store->schema_generation,
            .seal_ts           = old_shard->seal_ts,
            .partition_key     = entry_partition,
            .etag              = rot_stat.etag);

        auto rot_catalog_r = rocs_store_catalog_write_staged(store,
                                                             rot_entry,
                                                             rot_next_id);
        if (n00b_result_is_err(rot_catalog_r)) {
            (void)n00b_vfs_delete(store->vfs, object_path);
            // Catalog never recorded the shard; with the journal active it is
            // retained (we do NOT delete it) and replayed on the next open.
            n00b_eprintf("rocs: catalog write for sealed shard [|#|] failed; "
                         "rotation already committed — records [|#|]\n",
                         shard_id,
                         store->recovery_journal ? r"retained in journal"
                                                 : r"dropped");
            if (!store->recovery_journal) {
                store->durable_drop_count   += 1;
                store->durable_drop_records += old_record_count;
                store->durable_drop_last_err = n00b_result_get_err(rot_catalog_r);
            }
            rocs_store_retire_hot_allocator(store,
                                            old_hot_allocator,
                                            shard_id,
                                            store->generation,
                                            old_record_count);
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(rot_catalog_r));
        }

        n00b_list_push(*store->catalog, rot_entry);
        rocs_store_refresh_oldest_available(store);
        (void)rocs_store_emit_commit(store,
                                     N00B_STORE_COMMIT_SEAL,
                                     rot_entry->shard_id,
                                     UINT64_MAX,
                                     rot_entry->record_count,
                                     rot_entry->seal_ts,
                                     rot_entry->partition_key);
#if defined(N00B_ROCS_TRACE)
        rocs_store_trace_seal(store,
                              shard_id,
                              old_record_count,
                              old_byte_estimate,
                              rot_len,
                              old_hot_allocator);
#endif
        rocs_store_retire_hot_allocator(store,
                                        old_hot_allocator,
                                        shard_id,
                                        store->generation,
                                        old_record_count);

        // The sealed shard is now durably catalog-committed: its journal is
        // redundant and can be reclaimed.
        if (store->recovery_journal && !store->recovering) {
            rocs_store_journal_delete(store, shard_id);
        }
        return n00b_result_ok(n00b_store_catalog_entry_t *, rot_entry);
    }

    n00b_pool_t      seal_pool            = {};
    n00b_allocator_t *seal_allocator      = allocator;
    bool             seal_allocator_owned = false;
    if (seal_allocator == nullptr) {
        seal_allocator = n00b_pool_init(&seal_pool,
                                        .hidden            = true,
                                        .external_metadata = true,
                                        .name = "rocs_seal_image_scratch");
        seal_allocator_owned = true;
    }

    auto image_r = n00b_store_shard_seal(store->hot_shard,
                                         .seal_ts      = seal_ts,
                                         .base_address = base_address,
                                         .allocator    = seal_allocator);
    if (n00b_result_is_err(image_r)) {
        n00b_err_t err = n00b_result_get_err(image_r);
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        if (err == N00B_STORE_SHARD_ERR_ARG) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   N00B_STORE_ERR_ARG);
        }
        if (err == N00B_STORE_SHARD_ERR_STATE) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   N00B_STORE_ERR_STATE);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_buffer_t *image   = n00b_result_get(image_r);
    uint64_t       img_len = (uint64_t)n00b_buffer_len(image);

    auto write_r = rocs_store_write_vfs_object(store,
                                               object_path,
                                               image,
                                               .create_exclusive = true);
    if (n00b_result_is_err(write_r)) {
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(write_r));
    }

    auto stat_r = n00b_vfs_stat(store->vfs, object_path);
    if (n00b_result_is_err(stat_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_VFS);
    }
    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != img_len) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_CORRUPT);
    }

    n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
        store,
        .shard_id          = shard_id,
        .generation        = store->generation,
        .object_path       = object_path,
        .byte_len          = stat.size,
        .record_count      = store->hot_shard->record_count,
        .schema_generation = store->schema_generation,
        .seal_ts           = store->hot_shard->seal_ts,
        .partition_key     = entry_partition,
        .etag              = stat.etag);

    uint64_t next_hot_id = store->next_shard_id;
    auto next_allocator_r = rocs_store_hot_allocator_new(store);
    if (n00b_result_is_err(next_allocator_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(next_allocator_r));
    }
    n00b_allocator_t *next_hot_allocator = n00b_result_get(next_allocator_r);

    auto shard_r = n00b_store_shard_new(
        .shard_id   = next_hot_id,
        .retain_raw = store->retain_policy != nullptr
                   && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = next_hot_allocator);
    if (n00b_result_is_err(shard_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        rocs_store_hot_allocator_destroy(store, next_hot_allocator, 0);
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(shard_r));
    }

    auto catalog_r = rocs_store_catalog_write_staged(store, entry, next_hot_id);
    if (n00b_result_is_err(catalog_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        rocs_store_hot_allocator_destroy(store, next_hot_allocator, 0);
        if (seal_allocator_owned) {
            n00b_allocator_destroy(seal_allocator);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(catalog_r));
    }

    if (seal_allocator_owned) {
        n00b_allocator_destroy(seal_allocator);
    }

    n00b_list_push(*store->catalog, entry);
    store->hot_shard        = n00b_result_get(shard_r);
    store->hot_allocator    = next_hot_allocator;
    store->hot_partition_key = r"default";
    store->next_shard_id    = next_hot_id + 1;
    rocs_store_refresh_oldest_available(store);

    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_SEAL,
                                 entry->shard_id,
                                 UINT64_MAX,
                                 entry->record_count,
                                 entry->seal_ts,
                                 entry->partition_key);

#if defined(N00B_ROCS_TRACE)
    rocs_store_trace_seal(store,
                          shard_id,
                          old_record_count,
                          old_byte_estimate,
                          img_len,
                          old_hot_allocator);
#endif

    if (residency_locked) {
        rocs_store_retire_hot_allocator_locked(store,
                                               old_hot_allocator,
                                               shard_id,
                                               store->generation,
                                               old_record_count);
    }
    else {
        rocs_store_retire_hot_allocator(store,
                                        old_hot_allocator,
                                        shard_id,
                                        store->generation,
                                        old_record_count);
    }

    return n00b_result_ok(n00b_store_catalog_entry_t *, entry);
}

static n00b_err_t
rocs_store_preflight_ingest(n00b_store_t     *store,
                            n00b_json_node_t *record,
                            n00b_buffer_t    *raw,
                            n00b_allocator_t *allocator)
{
    if (store == nullptr || record == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    if (store->state != N00B_STORE_STATE_OPEN || store->hot_shard == nullptr) {
        return N00B_STORE_ERR_STATE;
    }
    if (n00b_json_type(record) != N00B_JSON_OBJECT) {
        return N00B_STORE_ERR_ARG;
    }
    if (store->retain_policy == nullptr || store->partition_policy == nullptr
        || store->seal_policy == nullptr || store->schema == nullptr
        || store->schema->fields == nullptr) {
        return N00B_STORE_ERR_STATE;
    }
    if (store->retain_policy->kind == N00B_STORE_RETAIN_EXTERNAL) {
        return N00B_STORE_ERR_POLICY;
    }
    if (store->retain_policy->kind == N00B_STORE_RETAIN_INLINE
        && raw == nullptr) {
        return N00B_STORE_ERR_ARG;
    }

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field == nullptr || field->name == nullptr) {
            return N00B_STORE_ERR_STATE;
        }
        if (field->required
            && rocs_json_object_get_field(record,
                                          field->name,
                                          .allocator = allocator) == nullptr) {
            return N00B_STORE_ERR_FIELD;
        }
        switch (field->index_kind) {
        case N00B_STORE_INDEX_NONE:
        case N00B_STORE_INDEX_TERM:
        case N00B_STORE_INDEX_FULLTEXT:
        case N00B_STORE_INDEX_NGRAM:
            break;
        case N00B_STORE_INDEX_NUMERIC:
        case N00B_STORE_INDEX_BOOL:
        case N00B_STORE_INDEX_VECTOR:
            return N00B_STORE_ERR_INDEX;
        default:
            return N00B_STORE_ERR_POLICY;
        }
    }

    return N00B_STORE_OK;
}

static rocs_store_posting_target_list_t *
rocs_store_posting_target_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_posting_target_list_t *targets = n00b_alloc_with_opts(
        rocs_store_posting_target_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *targets = n00b_list_new_private(n00b_store_posting_list_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return targets;
}

static n00b_store_posting_list_t *
rocs_store_posting_list_new() _kargs
{
    n00b_store_postings_kind_t kind      = N00B_STORE_POSTINGS_SPARSE;
    n00b_allocator_t          *allocator = nullptr;
}
{
    n00b_store_posting_list_t *postings = n00b_alloc_with_opts(
        n00b_store_posting_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    postings->kind     = rocs_store_postings_kind_valid(kind)
                           ? kind
                           : N00B_STORE_POSTINGS_SPARSE;
    postings->reserved = 0;
    postings->count    = 0;
    postings->ordinals = nullptr;
    postings->flags    = nullptr;

    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        postings->flags = n00b_flagset_new(.length = 64,
                                           .allocator = allocator);
    }
    else {
        postings->ordinals = n00b_alloc_with_opts(
            n00b_store_posting_ordinal_list_t,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
            });
        *postings->ordinals = n00b_list_new_private(
            uint64_t,
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE);
    }
    return postings;
}

static n00b_store_column_t *
rocs_store_column_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_column_t *column = n00b_alloc_with_opts(
        n00b_store_column_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    n00b_dict_init(column,
                   .allocator       = allocator,
                   .skip_obj_hash   = true,
                   .locked          = false,
                   .key_scan_kind   = N00B_GC_SCAN_KIND_NONE,
                   .value_scan_kind = N00B_GC_SCAN_KIND_ALL);
    return column;
}

static n00b_result_t(n00b_store_column_t *)
rocs_store_column_get_or_create(n00b_store_shard_t *shard,
                                n00b_string_t      *field)
{
    if (shard == nullptr || shard->columns == nullptr || field == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_ERR_INDEX);
    }

    bool found = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns, field, &found);
    if (found) {
        if (column == nullptr) {
            return n00b_result_err(n00b_store_column_t *,
                                   N00B_STORE_ERR_INDEX);
        }
        return n00b_result_ok(n00b_store_column_t *, column);
    }

    n00b_allocator_t *allocator = shard->columns->allocator;
    column = rocs_store_column_new(.allocator = allocator);

    n00b_string_t *stored_field =
        n00b_string_from_raw(field->data,
                             (int64_t)field->u8_bytes,
                             .allocator = allocator);
    n00b_dict_put(shard->columns, stored_field, column);
    return n00b_result_ok(n00b_store_column_t *, column);
}

static n00b_result_t(n00b_store_posting_list_t *)
rocs_store_column_postings_get_or_create(n00b_store_column_t *column,
                                         n00b_uint128_t       key,
                                         n00b_store_postings_kind_t kind)
{
    if (column == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_ERR_INDEX);
    }

    bool found = false;
    n00b_store_posting_list_t *postings = n00b_dict_get(column, key, &found);
    if (found) {
        if (postings == nullptr) {
            return n00b_result_err(n00b_store_posting_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }
        return n00b_result_ok(n00b_store_posting_list_t *, postings);
    }

    postings = rocs_store_posting_list_new(.kind      = kind,
                                           .allocator = column->allocator);
    n00b_dict_put(column, key, postings);
    return n00b_result_ok(n00b_store_posting_list_t *, postings);
}

static n00b_result_t(n00b_uint128_t)
rocs_store_term_key(n00b_store_index_kind_t  kind,
                    n00b_store_normalized_t *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto hash_r = n00b_store_normalize_hash(kind,
                                            term,
                                            .allocator = allocator);
    if (n00b_result_is_err(hash_r)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_ERR_INDEX);
    }
    return n00b_result_ok(n00b_uint128_t, n00b_result_get(hash_r));
}

static bool
rocs_store_batch_term_exists(rocs_store_batch_term_list_t *terms,
                             n00b_string_t                *field,
                             n00b_uint128_t                key)
{
    if (terms == nullptr || field == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*terms);
    for (size_t i = 0; i < len; i++) {
        rocs_store_batch_term_t item = n00b_list_get(*terms, i);
        if (item.field != nullptr
            && item.key == key
            && n00b_unicode_str_eq(item.field, field)) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_batch_term_append_unique(rocs_store_batch_term_list_t *terms,
                                    n00b_string_t                *field,
                                    n00b_uint128_t                key,
                                    n00b_store_postings_kind_t    postings) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (terms == nullptr || field == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    if (rocs_store_batch_term_exists(terms, field, key)) {
        return n00b_result_ok(bool, false);
    }

    rocs_store_batch_term_t item = {
        .field    = field,
        .key      = key,
        .postings = postings,
    };
    n00b_list_push(*terms, item);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_store_normalized_list_t *)
rocs_store_normalize_index_terms(n00b_store_field_t *field,
                                 n00b_json_node_t   *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (field == nullptr || value == nullptr) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_ERR_INDEX);
    }

    n00b_result_t(n00b_store_normalized_list_t *) terms_r;
    switch (field->index_kind) {
    case N00B_STORE_INDEX_TERM:
        terms_r = n00b_store_normalize_json(value, .allocator = allocator);
        break;
    case N00B_STORE_INDEX_FULLTEXT:
        terms_r = n00b_store_normalize_text_tokens(value,
                                                   .allocator = allocator);
        break;
    case N00B_STORE_INDEX_NGRAM:
        terms_r = n00b_store_normalize_text_ngrams(
            value,
            .ngram_n   = field->ngram_n,
            .allocator = allocator);
        break;
    default:
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_ERR_INDEX);
    }

    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(n00b_store_normalized_list_t *,
                               N00B_STORE_ERR_INDEX);
    }
    return terms_r;
}

static n00b_result_t(bool)
rocs_store_append_normalized_terms(rocs_store_batch_term_list_t *out,
                                   n00b_string_t                *field,
                                   n00b_store_index_kind_t       kind,
                                   n00b_store_postings_kind_t    postings,
                                   n00b_store_normalized_list_t  *terms,
                                   n00b_allocator_t             *allocator)
{
    if (out == nullptr || field == nullptr || terms == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }

    size_t len = n00b_list_len(*terms);
    for (size_t i = 0; i < len; i++) {
        n00b_store_normalized_t *term = n00b_list_get(*terms, i);
        auto key_r = rocs_store_term_key(kind,
                                         term,
                                         .allocator = allocator);
        if (n00b_result_is_err(key_r)) {
            return n00b_result_err(bool, n00b_result_get_err(key_r));
        }

        auto append_r = rocs_store_batch_term_append_unique(
            out,
            field,
            n00b_result_get(key_r),
            postings,
            .allocator = allocator);
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(bool, n00b_result_get_err(append_r));
        }
    }

    return n00b_result_ok(bool, true);
}

typedef struct {
    rocs_store_batch_term_list_t *out;
    n00b_string_t                *field;
    n00b_store_postings_kind_t    postings;
    n00b_allocator_t             *allocator;
    n00b_err_t                    err;
} rocs_store_key_append_ctx_t;

static bool
rocs_store_append_key_visitor(void *ctx_ptr, n00b_uint128_t key)
{
    rocs_store_key_append_ctx_t *ctx = ctx_ptr;
    if (ctx == nullptr || ctx->out == nullptr || ctx->field == nullptr) {
        return false;
    }

    auto append_r = rocs_store_batch_term_append_unique(
        ctx->out,
        ctx->field,
        key,
        ctx->postings,
        .allocator = ctx->allocator);
    if (n00b_result_is_err(append_r)) {
        ctx->err = n00b_result_get_err(append_r);
        return false;
    }
    return true;
}

static n00b_result_t(bool)
rocs_store_append_text_keys(rocs_store_batch_term_list_t *out,
                            n00b_string_t                *field,
                            n00b_store_index_kind_t       kind,
                            n00b_store_postings_kind_t    postings,
                            n00b_json_node_t             *value,
                            uint8_t                       ngram_n,
                            n00b_allocator_t             *allocator)
{
    if (out == nullptr || field == nullptr || value == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    if (!n00b_json_is_string(value)) {
        return n00b_result_ok(bool, true);
    }

    rocs_store_key_append_ctx_t ctx = {
        .out       = out,
        .field     = field,
        .postings  = postings,
        .allocator = allocator,
        .err       = N00B_STORE_OK,
    };

    n00b_result_t(uint64_t) keys_r;
    switch (kind) {
    case N00B_STORE_INDEX_FULLTEXT:
        keys_r = n00b_store_normalize_text_token_keys(
            value,
            rocs_store_append_key_visitor,
            &ctx,
            .allocator = allocator);
        break;
    case N00B_STORE_INDEX_NGRAM:
        keys_r = n00b_store_normalize_text_ngram_keys(
            value,
            rocs_store_append_key_visitor,
            &ctx,
            .ngram_n   = ngram_n,
            .allocator = allocator);
        break;
    default:
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }

    if (n00b_result_is_err(keys_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    if (ctx.err != N00B_STORE_OK) {
        return n00b_result_err(bool, ctx.err);
    }
    return n00b_result_ok(bool, true);
}

static rocs_store_batch_term_list_t *
rocs_store_batch_term_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_batch_term_list_t *terms = n00b_alloc_with_opts(
        rocs_store_batch_term_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *terms = n00b_list_new_private(rocs_store_batch_term_t,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return terms;
}

static n00b_result_t(rocs_store_batch_term_list_t *)
rocs_store_build_batch_terms(n00b_store_t     *store,
                             n00b_json_node_t *record,
                             n00b_allocator_t *allocator)
{
    if (store == nullptr || record == nullptr || store->schema == nullptr
        || store->schema->fields == nullptr) {
        return n00b_result_err(rocs_store_batch_term_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    rocs_store_batch_term_list_t *out =
        rocs_store_batch_term_list_new(.allocator = allocator);

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field == nullptr || field->name == nullptr) {
            return n00b_result_err(rocs_store_batch_term_list_t *,
                                   N00B_STORE_ERR_STATE);
        }

        n00b_json_node_t *field_value =
            rocs_json_object_get_field(record,
                                       field->name,
                                       .allocator = allocator);
        if (field_value == nullptr) {
            continue;
        }

        if (field->index_kind == N00B_STORE_INDEX_TERM
            || field->index_kind == N00B_STORE_INDEX_FULLTEXT
            || field->index_kind == N00B_STORE_INDEX_NGRAM) {
            n00b_result_t(bool) append_r;
            if (field->index_kind == N00B_STORE_INDEX_TERM) {
                auto terms_r = rocs_store_normalize_index_terms(
                    field,
                    field_value,
                    .allocator = allocator);
                if (n00b_result_is_err(terms_r)) {
                    return n00b_result_err(rocs_store_batch_term_list_t *,
                                           N00B_STORE_ERR_INDEX);
                }

                append_r = rocs_store_append_normalized_terms(
                    out,
                    field->name,
                    field->index_kind,
                    field->postings,
                    n00b_result_get(terms_r),
                    allocator);
            }
            else {
                append_r = rocs_store_append_text_keys(out,
                                                       field->name,
                                                       field->index_kind,
                                                       field->postings,
                                                       field_value,
                                                       field->ngram_n,
                                                       allocator);
            }
            if (n00b_result_is_err(append_r)) {
                return n00b_result_err(rocs_store_batch_term_list_t *,
                                       n00b_result_get_err(append_r));
            }
        }

        if (field->include_in_all && n00b_json_is_string(field_value)) {
            auto append_r = rocs_store_append_text_keys(
                out,
                field->name,
                N00B_STORE_INDEX_FULLTEXT,
                N00B_STORE_POSTINGS_SPARSE,
                field_value,
                field->ngram_n,
                allocator);
            if (n00b_result_is_err(append_r)) {
                return n00b_result_err(rocs_store_batch_term_list_t *,
                                       n00b_result_get_err(append_r));
            }
        }
    }

    return n00b_result_ok(rocs_store_batch_term_list_t *, out);
}

static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets_from_terms(n00b_store_t                 *store,
                                            n00b_store_shard_t           *shard,
                                            rocs_store_batch_term_list_t *terms,
                                            n00b_allocator_t             *allocator)
{
    if (store == nullptr || shard == nullptr || terms == nullptr
        || shard->columns == nullptr) {
        return n00b_result_err(rocs_store_posting_target_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    rocs_store_posting_target_list_t *targets =
        rocs_store_posting_target_list_new(.allocator = allocator);

    size_t len = n00b_list_len(*terms);
    for (size_t i = 0; i < len; i++) {
        rocs_store_batch_term_t term = n00b_list_get(*terms, i);
        if (term.field == nullptr) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        auto column_r = rocs_store_column_get_or_create(shard, term.field);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   n00b_result_get_err(column_r));
        }

        auto postings_r = rocs_store_column_postings_get_or_create(
            n00b_result_get(column_r),
            term.key,
            term.postings);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_list_push(*targets, n00b_result_get(postings_r));
    }

    return n00b_result_ok(rocs_store_posting_target_list_t *, targets);
}

static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets(n00b_store_t     *store,
                                 n00b_store_shard_t *shard,
                                 n00b_json_node_t *record,
                                 n00b_allocator_t *allocator)
{
    if (store == nullptr || shard == nullptr || record == nullptr
        || store->schema == nullptr || store->schema->fields == nullptr
        || shard->columns == nullptr) {
        return n00b_result_err(rocs_store_posting_target_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    auto terms_r = rocs_store_build_batch_terms(store, record, allocator);
    if (n00b_result_is_err(terms_r)) {
        return n00b_result_err(rocs_store_posting_target_list_t *,
                               n00b_result_get_err(terms_r));
    }

    return rocs_store_prepare_index_targets_from_terms(
        store,
        shard,
        n00b_result_get(terms_r),
        allocator);
}

static bool
rocs_store_posting_list_contains_ordinal(n00b_store_posting_list_t *postings,
                                         uint64_t                   ordinal)
{
    if (postings == nullptr) {
        return false;
    }

    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        return n00b_flagset_index(postings->flags, (int64_t)ordinal);
    }
    if (postings->ordinals == nullptr) {
        return false;
    }

    // Append-dedup fast path.  This predicate is reached only from
    // rocs_store_posting_list_push_unique, which is called with the current
    // record's ordinal.  Records append to the hot shard in increasing order,
    // so the ordinals pushed to any one posting list are monotonically
    // non-decreasing — the only possible duplicate is the most-recent one (the
    // same record matching the same term twice).  Checking just the tail keeps
    // posting-list construction O(N) instead of O(N^2); a single
    // high-cardinality term (a common path/exe/value shared across many
    // records) otherwise pins the ingest worker on a per-insert linear rescan.
    size_t len = n00b_list_len(*postings->ordinals);
    return len != 0 && n00b_list_get(*postings->ordinals, len - 1) == ordinal;
}

static bool
rocs_store_posting_list_push_unique(n00b_store_posting_list_t *postings,
                                    uint64_t                   ordinal)
{
    if (postings == nullptr
        || rocs_store_posting_list_contains_ordinal(postings, ordinal)) {
        return false;
    }
    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        n00b_flagset_set_index(postings->flags, (int64_t)ordinal, true);
        postings->count++;
        return true;
    }
    if (postings->ordinals == nullptr) {
        return false;
    }
    n00b_list_push(*postings->ordinals, ordinal);
    postings->count++;
    return true;
}

static void
rocs_store_commit_index_targets(rocs_store_posting_target_list_t *targets,
                                uint64_t                         ordinal)
{
    if (targets == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*targets);
    for (size_t i = 0; i < len; i++) {
        n00b_store_posting_list_t *postings = n00b_list_get(*targets, i);
        if (postings != nullptr) {
            (void)rocs_store_posting_list_push_unique(postings, ordinal);
        }
    }
}

static n00b_err_t
rocs_store_copy_source_raw(n00b_buffer_t     *source,
                           n00b_buffer_t    **raw_out,
                           n00b_allocator_t  *allocator)
{
    if (source == nullptr || raw_out == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    *raw_out = nullptr;

    uint64_t source_len = (uint64_t)n00b_buffer_len(source);
    if (source_len == 0) {
        return N00B_STORE_ERR_PARSE;
    }
    if (source_len > (uint64_t)INT64_MAX || source_len > (uint64_t)SIZE_MAX) {
        return N00B_STORE_ERR_ARG;
    }

    _n00b_buffer_rlock(source);
    n00b_buffer_t *raw = n00b_buffer_from_bytes(source->data,
                                                (int64_t)source_len,
                                                .allocator = allocator);
    _n00b_buffer_unlock(source);
    if (raw == nullptr) {
        return N00B_STORE_ERR_INTERNAL;
    }

    *raw_out = raw;
    return N00B_STORE_OK;
}

static n00b_err_t
rocs_store_parse_source(n00b_buffer_t     *source,
                        n00b_buffer_t    **raw_out,
                        n00b_json_node_t **record_out,
                        n00b_allocator_t  *allocator)
{
    if (source == nullptr || raw_out == nullptr || record_out == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    *raw_out    = nullptr;
    *record_out = nullptr;

    n00b_buffer_t *raw = nullptr;
    n00b_err_t     err = rocs_store_copy_source_raw(source, &raw, allocator);
    if (err != N00B_STORE_OK) {
        return err;
    }

    const char       *parse_err = nullptr;
    n00b_json_node_t *record    = nullptr;
    uint64_t          raw_len   = (uint64_t)n00b_buffer_len(raw);
    _n00b_buffer_rlock(raw);
    record = n00b_json_parse(raw->data,
                             (size_t)raw_len,
                             &parse_err,
                             .allocator = allocator);
    _n00b_buffer_unlock(raw);
    if (record == nullptr) {
        (void)parse_err;
        return N00B_STORE_ERR_PARSE;
    }

    *raw_out    = raw;
    *record_out = record;
    return N00B_STORE_OK;
}

static n00b_result_t(bool)
rocs_store_ingest_buf_decoded(n00b_store_t                 *store,
                              n00b_buffer_t                *source,
                              n00b_store_source_decoder_t   decoder)
{
    if (store == nullptr || source == nullptr || decoder == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = true,
                       .name              = "rocs_ingest_decode_scratch");

    n00b_buffer_t *raw = nullptr;
    n00b_err_t     err = rocs_store_copy_source_raw(source,
                                                    &raw,
                                                    scratch_allocator);
    if (err != N00B_STORE_OK) {
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(bool, err);
    }

    auto record_r = decoder(raw, scratch_allocator);
    if (n00b_result_is_err(record_r)) {
        n00b_err_t decode_err = n00b_result_get_err(record_r);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(bool, decode_err);
    }

    auto ingest_r = rocs_store_ingest_common(store,
                                             n00b_result_get(record_r),
                                             raw,
                                             scratch_allocator);
    n00b_allocator_destroy(scratch_allocator);
    return ingest_r;
}

static void
rocs_store_batch_worker(void *job_ptr, void *user_data)
{
    (void)user_data;

    rocs_store_batch_job_t *job = job_ptr;
    if (job == nullptr || job->store == nullptr) {
        return;
    }

    job->err = N00B_STORE_OK;

    if (job->source != nullptr) {
        job->err = rocs_store_parse_source(job->source,
                                           &job->raw,
                                           &job->record,
                                           job->allocator);
        if (job->err != N00B_STORE_OK) {
            return;
        }
    }
    else {
        job->record = job->input_record;
    }

    job->err = rocs_store_preflight_ingest(job->store,
                                           job->record,
                                           job->raw,
                                           job->allocator);
    if (job->err != N00B_STORE_OK) {
        return;
    }

    auto route_r = n00b_store_partition_route(job->store->partition_policy,
                                              job->record,
                                              .allocator = job->allocator);
    if (n00b_result_is_err(route_r)) {
        job->err = n00b_result_get_err(route_r);
        return;
    }
    job->route = n00b_result_get(route_r);
    if (job->route == nullptr) {
        job->route = r"default";
    }

    auto terms_r = rocs_store_build_batch_terms(job->store,
                                                job->record,
                                                job->allocator);
    if (n00b_result_is_err(terms_r)) {
        job->err = n00b_result_get_err(terms_r);
        return;
    }
    job->terms = n00b_result_get(terms_r);
}

static bool
rocs_store_should_seal_hot(n00b_store_t *store)
{
    if (store == nullptr || store->hot_shard == nullptr
        || store->seal_policy == nullptr) {
        return false;
    }
    if (store->seal_policy->max_records != 0
        && store->hot_shard->record_count >= store->seal_policy->max_records) {
        return true;
    }
    if (store->seal_policy->max_bytes != 0
        && store->hot_shard->byte_estimate >= store->seal_policy->max_bytes) {
        return true;
    }
    if (store->seal_policy->max_hot_bytes != 0
        && rocs_store_hot_allocator_mapped_bytes(store->hot_allocator)
               >= store->seal_policy->max_hot_bytes) {
        return true;
    }
    if (store->seal_policy->max_open_ns != 0
        && store->hot_shard->open_ts != 0) {
        uint64_t now = (uint64_t)n00b_ns_timestamp();
        if (now >= store->hot_shard->open_ts
            && now - store->hot_shard->open_ts
                   >= store->seal_policy->max_open_ns) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(n00b_string_t *)
rocs_store_partition_key_store_copy(n00b_store_t  *store,
                                    n00b_string_t *route)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    if (route == nullptr) {
        route = r"default";
    }

    n00b_string_t *copy = rocs_store_string_copy(route, store->allocator);
    if (copy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_string_t *, copy);
}

static n00b_result_t(bool)
rocs_store_ensure_hot_route_unlocked(n00b_store_t  *store,
                                     n00b_string_t *route,
                                     bool           residency_locked)
{
    if (store == nullptr || store->hot_shard == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (route == nullptr) {
        route = r"default";
    }

    if (store->hot_partition_key == nullptr) {
        store->hot_partition_key = r"default";
    }
    if (store->hot_shard->record_count == 0) {
        auto copy_r = rocs_store_partition_key_store_copy(store, route);
        if (n00b_result_is_err(copy_r)) {
            return n00b_result_err(bool, n00b_result_get_err(copy_r));
        }
        store->hot_partition_key = n00b_result_get(copy_r);
        return n00b_result_ok(bool, true);
    }
    if (n00b_unicode_str_eq(store->hot_partition_key, route)) {
        return n00b_result_ok(bool, true);
    }

    auto seal_r = rocs_store_seal_hot_shard_unlocked(
        store,
        (uint64_t)n00b_ns_timestamp(),
        0,
        nullptr,
        store->hot_partition_key,
        residency_locked);
    if (n00b_result_is_err(seal_r)) {
        return n00b_result_err(bool, n00b_result_get_err(seal_r));
    }

    auto copy_r = rocs_store_partition_key_store_copy(store, route);
    if (n00b_result_is_err(copy_r)) {
        return n00b_result_err(bool, n00b_result_get_err(copy_r));
    }
    store->hot_partition_key = n00b_result_get(copy_r);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_ingest_prepared_unlocked(n00b_store_t                 *store,
                                    n00b_json_node_t             *record,
                                    n00b_buffer_t                *raw,
                                    n00b_string_t                *route,
                                    rocs_store_batch_term_list_t *terms,
                                    n00b_allocator_t             *allocator)
{
    if (store == nullptr || record == nullptr || store->hot_shard == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (route == nullptr) {
        route = r"default";
    }

    auto route_r = rocs_store_ensure_hot_route_unlocked(store,
                                                        route,
                                                        false);
    if (n00b_result_is_err(route_r)) {
        return n00b_result_err(bool, n00b_result_get_err(route_r));
    }

    n00b_result_t(rocs_store_posting_target_list_t *) targets_r =
        terms == nullptr
            ? rocs_store_prepare_index_targets(store,
                                               store->hot_shard,
                                               record,
                                               allocator)
            : rocs_store_prepare_index_targets_from_terms(store,
                                                          store->hot_shard,
                                                          terms,
                                                          allocator);
    if (n00b_result_is_err(targets_r)) {
        return n00b_result_err(bool, n00b_result_get_err(targets_r));
    }
    rocs_store_posting_target_list_t *targets = n00b_result_get(targets_r);

    // Write-ahead: durably append the record's source bytes to the current hot
    // shard's journal before the in-memory commit, so a crash before seal can
    // be recovered.  No-op unless the recovery journal is active.
    auto journal_r = rocs_store_journal_append(store, raw);
    if (n00b_result_is_err(journal_r)) {
        return n00b_result_err(bool, n00b_result_get_err(journal_r));
    }

    auto append_r = n00b_store_shard_append(store->hot_shard,
                                            record,
                                            .raw = raw);
    if (n00b_result_is_err(append_r)) {
        n00b_err_t err = n00b_result_get_err(append_r);
        return n00b_result_err(bool,
                               err == N00B_STORE_SHARD_ERR_STATE
                                   ? N00B_STORE_ERR_STATE
                                   : N00B_STORE_ERR_ARG);
    }
    uint64_t ordinal = n00b_result_get(append_r);

    rocs_store_commit_index_targets(targets, ordinal);

    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_RECORD,
                                 store->hot_shard->shard_id,
                                 ordinal,
                                 store->hot_shard->record_count,
                                 0,
                                 store->hot_partition_key);

#if defined(N00B_ROCS_TRACE)
    rocs_store_trace_ingest(store,
                            record,
                            raw,
                            terms,
                            targets,
                            ordinal);
#endif

    if (!store->recovering && rocs_store_should_seal_hot(store)) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            nullptr,
            store->hot_partition_key,
            false);
        (void)seal_r;
    }

    return n00b_result_ok(bool, true);
}

n00b_string_t *
n00b_store_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_OK:            return r"OK";
    case N00B_STORE_ERR_ARG:       return r"ARG";
    case N00B_STORE_ERR_STATE:     return r"STATE";
    case N00B_STORE_ERR_DUP_FIELD: return r"DUP_FIELD";
    case N00B_STORE_ERR_FIELD:     return r"FIELD";
    case N00B_STORE_ERR_POLICY:    return r"POLICY";
    case N00B_STORE_ERR_PINNED:    return r"PINNED";
    case N00B_STORE_ERR_VFS:       return r"VFS";
    case N00B_STORE_ERR_INTERNAL:  return r"INTERNAL";
    case N00B_STORE_ERR_CORRUPT:   return r"CORRUPT";
    case N00B_STORE_ERR_RESIDENCY: return r"RESIDENCY";
    case N00B_STORE_ERR_PARSE:     return r"PARSE";
    case N00B_STORE_ERR_INDEX:     return r"INDEX";
    case N00B_STORE_ERR_RETENTION: return r"RETENTION";
    case N00B_STORE_ERR_CONFIG:    return r"CONFIG";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_config_t *)
n00b_store_config_default(n00b_store_profile_t profile) _kargs
{
    n00b_string_t    *name      = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (profile != N00B_STORE_PROFILE_EMBEDDED_LOCAL
        && profile != N00B_STORE_PROFILE_SERVICE_LOCAL
        && profile != N00B_STORE_PROFILE_SERVICE_S3) {
        return n00b_result_err(n00b_store_config_t *, N00B_STORE_ERR_CONFIG);
    }

    n00b_store_config_t *config = rocs_store_config_alloc(profile, allocator);
    if (name != nullptr) {
        rocs_store_config_set_string(&config->name, name, allocator);
    }
    return n00b_result_ok(n00b_store_config_t *, config);
}

n00b_result_t(n00b_store_config_t *)
n00b_store_config_from_env() _kargs
{
    n00b_string_t    *prefix    = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_string_t *profile_s = rocs_store_env(prefix,
                                              r"ROCS_PROFILE",
                                              allocator);
    auto profile_r = rocs_store_parse_profile(profile_s);
    if (n00b_result_is_err(profile_r)) {
        return n00b_result_err(n00b_store_config_t *, N00B_STORE_ERR_CONFIG);
    }

    n00b_store_config_t *config = rocs_store_config_alloc(n00b_result_get(profile_r),
                                                          allocator);
    n00b_string_t *value = nullptr;

    value = rocs_store_env(prefix, r"ROCS_NAME", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->name, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_S3_BUCKET", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->s3_bucket, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_S3_PREFIX", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->s3_prefix, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_SCHEMA", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->schema_source, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_AWS_REGION", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->aws_region, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_S3_ENDPOINT", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->s3_endpoint, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_S3_PATH_STYLE", allocator);
    if (value != nullptr) {
        auto bool_r = rocs_store_parse_bool(value);
        if (n00b_result_is_err(bool_r)) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->s3_path_style     = n00b_result_get(bool_r);
        config->has_s3_path_style = true;
    }

    value = rocs_store_env(prefix, r"ROCS_CACHE_DIR", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->cache_dir, value, allocator);
    }

    value = rocs_store_env(prefix, r"ROCS_CACHE_BYTES", allocator);
    if (value != nullptr) {
        auto num_r = rocs_store_parse_u64(value);
        if (n00b_result_is_err(num_r)) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->cache_bytes = n00b_result_get(num_r);
    }

    value = rocs_store_env(prefix, r"ROCS_RESIDENT_BYTES", allocator);
    if (value != nullptr) {
        auto num_r = rocs_store_parse_u64(value);
        if (n00b_result_is_err(num_r)) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->resident_bytes = n00b_result_get(num_r);
    }

    value = rocs_store_env(prefix, r"ROCS_RESIDENT_SHARDS", allocator);
    if (value != nullptr) {
        auto num_r = rocs_store_parse_u64(value);
        if (n00b_result_is_err(num_r)
            || n00b_result_get(num_r) > UINT32_MAX) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->resident_shards = n00b_result_get(num_r);
    }

    value = rocs_store_env(prefix, r"ROCS_READ_ONLY", allocator);
    bool read_only_set = false;
    if (value != nullptr) {
        auto bool_r = rocs_store_parse_bool(value);
        if (n00b_result_is_err(bool_r)) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->read_only = n00b_result_get(bool_r);
        read_only_set     = true;
    }

    value = rocs_store_env(prefix, r"ROCS_WRITER_MODE", allocator);
    bool writer_set = false;
    if (value != nullptr) {
        if (rocs_store_string_eq_lit(value, r"multi")
            || rocs_store_string_eq_lit(value, r"multi_writer")) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        auto mode_r = rocs_store_parse_writer_mode(value);
        if (n00b_result_is_err(mode_r)) {
            return n00b_result_err(n00b_store_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->writer_mode = n00b_result_get(mode_r);
        writer_set          = true;
    }

    if (read_only_set && config->read_only && !writer_set) {
        config->writer_mode = N00B_STORE_WRITER_READ_REPLICA;
    }

    auto valid_r = rocs_store_config_validate(config, nullptr, false);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_store_config_t *,
                               n00b_result_get_err(valid_r));
    }
    return n00b_result_ok(n00b_store_config_t *, config);
}

n00b_result_t(n00b_store_profile_t)
n00b_store_config_get_profile(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(n00b_store_profile_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_profile_t, config->profile);
}

static n00b_result_t(n00b_option_t(n00b_string_t *))
rocs_store_config_get_string(n00b_store_config_t *config,
                             n00b_string_t       *value)
{
    if (config == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_from_nullable(n00b_string_t *, value));
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_name(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->name);
}

n00b_result_t(bool)
n00b_store_config_set_name(n00b_store_config_t *config, n00b_string_t *name)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    rocs_store_config_set_string(&config->name, name, config->allocator);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_root(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->root);
}

n00b_result_t(bool)
n00b_store_config_set_root(n00b_store_config_t *config, n00b_string_t *root)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    rocs_store_config_set_string(&config->root, root, config->allocator);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_bucket(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->s3_bucket);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_prefix(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->s3_prefix);
}

n00b_result_t(bool)
n00b_store_config_set_s3(n00b_store_config_t *config,
                         n00b_string_t       *bucket,
                         n00b_string_t       *prefix)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (config->profile != N00B_STORE_PROFILE_SERVICE_S3) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    rocs_store_config_set_string(&config->s3_bucket,
                                 bucket,
                                 config->allocator);
    rocs_store_config_set_string(&config->s3_prefix,
                                 prefix,
                                 config->allocator);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_schema_source(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr
                                            ? nullptr
                                            : config->schema_source);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_aws_region(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->aws_region);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_endpoint(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr
                                            ? nullptr
                                            : config->s3_endpoint);
}

n00b_result_t(n00b_option_t(bool))
n00b_store_config_get_s3_path_style(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(n00b_option_t(bool), N00B_STORE_ERR_ARG);
    }
    if (!config->has_s3_path_style) {
        return n00b_result_ok(n00b_option_t(bool), n00b_option_none(bool));
    }
    return n00b_result_ok(n00b_option_t(bool),
                          n00b_option_set(bool, config->s3_path_style));
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_cache_dir(n00b_store_config_t *config)
{
    return rocs_store_config_get_string(config,
                                        config == nullptr ? nullptr
                                                          : config->cache_dir);
}

n00b_result_t(uint64_t)
n00b_store_config_get_cache_bytes(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, config->cache_bytes);
}

n00b_result_t(uint64_t)
n00b_store_config_get_resident_bytes(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, config->resident_bytes);
}

n00b_result_t(uint64_t)
n00b_store_config_get_resident_shards(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, config->resident_shards);
}

n00b_result_t(bool)
n00b_store_config_get_read_only(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(bool, config->read_only);
}

n00b_result_t(n00b_store_writer_mode_t)
n00b_store_config_get_writer_mode(n00b_store_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(n00b_store_writer_mode_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_writer_mode_t, config->writer_mode);
}

n00b_result_t(n00b_store_commit_topic_t *)
n00b_store_commit_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri)
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_commit_topic_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_commit_topic_t *topic =
        n00b_conduit_topic_init(n00b_store_commit_t, conduit, uri);
    if (topic == nullptr) {
        return n00b_result_err(n00b_store_commit_topic_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_store_commit_topic_t *, topic);
}

n00b_result_t(n00b_store_commit_inbox_t *)
n00b_store_commit_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
    n00b_allocator_t           *allocator    = nullptr;
}
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (allocator == nullptr) {
        allocator = conduit->allocator;
    }

    n00b_store_commit_inbox_t *inbox = n00b_alloc_with_opts(
        n00b_store_commit_inbox_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    if (inbox == nullptr) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_inbox_init(n00b_store_commit_t,
                            inbox,
                            conduit,
                            backpressure,
                            limit);
    return n00b_result_ok(n00b_store_commit_inbox_t *, inbox);
}

n00b_result_t(n00b_store_commit_inbox_t *)
n00b_store_commit_inbox_for_query(n00b_store_commit_topic_t *topic,
                                  uint32_t                   limit) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (topic == nullptr || limit == 0) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (!rocs_store_commit_topic_ready(topic)) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    return n00b_store_commit_inbox_new(
        base->conduit,
        .backpressure = N00B_CONDUIT_BP_DROP_NEWEST,
        .limit        = limit,
        .allocator    = allocator);
}

n00b_result_t(n00b_conduit_sub_handle_t)
n00b_store_commit_subscribe(n00b_store_commit_topic_t *topic,
                            n00b_store_commit_inbox_t *inbox) _kargs
{
    uint32_t operations = N00B_CONDUIT_OP_ALL;
    uint32_t flags      = 0;
    uint32_t timeout_ms = 0;
}
{
    if (topic == nullptr || inbox == nullptr) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_ARG);
    }
    if (!rocs_store_commit_topic_ready(topic)) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_subscribe(n00b_store_commit_t,
                               topic,
                               inbox,
                               .operations   = operations,
                               .flags        = flags,
                               .timeout_ms   = timeout_ms);
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_conduit_sub_handle_t, handle);
}

n00b_result_t(bool)
n00b_store_commit_unsubscribe_for_query(n00b_store_commit_topic_t *topic,
                                        n00b_conduit_sub_handle_t  sub)
{
    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_ok(bool, false);
    }
    if (topic == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    _n00b_list_write_lock(&topic->subscriptions);
    n00b_conduit_sub_cancel(sub);
    _n00b_list_unlock(&topic->subscriptions);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_set_commit_topic(n00b_store_t              *store,
                            n00b_store_commit_topic_t *topic)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->commit_topic = topic;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_store_commit_topic_t *))
n00b_store_commit_topic_for_query(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_commit_topic_t *),
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_commit_topic_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_commit_topic_t *topic = store->commit_topic;
    n00b_data_unlock(store->commit_lock);
    if (topic == nullptr) {
        return n00b_result_ok(
            n00b_option_t(n00b_store_commit_topic_t *),
            n00b_option_none(n00b_store_commit_topic_t *));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_commit_topic_t *),
        n00b_option_set(n00b_store_commit_topic_t *, topic));
}

static bool
rocs_store_hot_plan_index_kind(n00b_store_index_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
        return true;
    case N00B_STORE_INDEX_NONE:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return false;
    }
    return false;
}

n00b_result_t(n00b_plan_index_list_t *)
n00b_store_plan_indexes_for_query(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || store->schema == nullptr
        || store->schema->fields == nullptr) {
        return n00b_result_err(n00b_plan_index_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    n00b_plan_index_list_t *indexes =
        n00b_plan_index_list_new(.allocator = allocator);
    n00b_store_index_field_list_t *catch_all_fields =
        n00b_alloc_with_opts(n00b_store_index_field_list_t,
                             &(n00b_alloc_opts_t){
                                 .allocator = allocator,
                             });
    *catch_all_fields = n00b_list_new_private(n00b_string_t *,
                                              .allocator = allocator,
                                              .scan_kind = N00B_GC_SCAN_KIND_ALL);

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field == nullptr || field->name == nullptr) {
            return n00b_result_err(n00b_plan_index_list_t *,
                                   N00B_STORE_ERR_STATE);
        }
        if (field->include_in_all) {
            n00b_list_push(*catch_all_fields, field->name);
        }
        if (!rocs_store_hot_plan_index_kind(field->index_kind)) {
            continue;
        }

        auto index_r = n00b_store_index_new(field->name,
                                            field->index_kind,
                                            .ngram_n = field->ngram_n,
                                            .postings = field->postings,
                                            .allocator = allocator);
        if (n00b_result_is_err(index_r)) {
            return n00b_result_err(n00b_plan_index_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        auto append_r =
            n00b_plan_index_list_append(indexes, n00b_result_get(index_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_plan_index_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }
    }

    if (n00b_list_len(*catch_all_fields) != 0) {
        auto catch_all_r = n00b_store_index_new_catch_all(
            catch_all_fields,
            .allocator = allocator);
        if (n00b_result_is_err(catch_all_r)) {
            return n00b_result_err(n00b_plan_index_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        auto append_r =
            n00b_plan_index_list_append(indexes, n00b_result_get(catch_all_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_plan_index_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }
    }

    return n00b_result_ok(n00b_plan_index_list_t *, indexes);
}

n00b_result_t(n00b_store_hot_tail_scan_t)
n00b_store_hot_tail_scan_after(n00b_store_t          *store,
                               n00b_plan_predicate_t *predicate,
                               n00b_store_pos_t      *after) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    n00b_store_pos_t *through   = nullptr;
}
{
    if (store == nullptr || predicate == nullptr) {
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_hot_tail_scan_t scan = {
        .matches = rocs_store_pos_list_new(.allocator = allocator),
    };
    if (scan.matches == nullptr) {
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_shard_t *hot = store->hot_shard;
    if (hot == nullptr || hot->record_count == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_store_hot_tail_scan_t, scan);
    }

    n00b_store_pos_t first = {
        .generation = store->generation,
        .shard_id   = hot->shard_id,
        .ordinal    = 0,
    };
    n00b_store_pos_t last = {
        .generation = store->generation,
        .shard_id   = hot->shard_id,
        .ordinal    = hot->record_count - 1,
    };
    uint64_t record_limit = hot->record_count;
    if (through != nullptr) {
        if (through->generation != store->generation
            || through->shard_id != hot->shard_id) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_ok(n00b_store_hot_tail_scan_t, scan);
        }
        if (through->ordinal >= hot->record_count) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(n00b_store_hot_tail_scan_t,
                                   N00B_STORE_ERR_STATE);
        }

        last         = *through;
        record_limit = through->ordinal + 1;
    }

    uint64_t first_ordinal = 0;
    if (after != nullptr) {
        if (n00b_store_pos_compare(*after, last) >= 0) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_ok(n00b_store_hot_tail_scan_t, scan);
        }
        if (n00b_store_pos_compare(*after, first) >= 0
            && after->generation == first.generation
            && after->shard_id == first.shard_id) {
            first_ordinal = after->ordinal + 1;
        }
    }

    auto indexes_r = n00b_store_plan_indexes_for_query(
        store,
        .allocator = allocator);
    if (n00b_result_is_err(indexes_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               n00b_result_get_err(indexes_r));
    }

    auto dispatch_r = n00b_plan_dispatch_hot(predicate,
                                             n00b_result_get(indexes_r),
                                             hot,
                                             .allocator = allocator);
    if (n00b_result_is_err(dispatch_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(dispatch_r)));
    }

    auto ordinals_r = n00b_plan_dispatch_verify_hot(
        n00b_result_get(dispatch_r),
        hot,
        .allocator = allocator);
    if (n00b_result_is_err(ordinals_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(ordinals_r)));
    }

    n00b_plan_ordset_t *ordinals = n00b_result_get(ordinals_r);
    auto count_r = n00b_plan_ordset_count(ordinals);
    if (n00b_result_is_err(count_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(count_r)));
    }

    uint64_t ordinal_count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < ordinal_count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(ordinals, i);
        if (n00b_result_is_err(ordinal_r)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(
                n00b_store_hot_tail_scan_t,
                rocs_store_err_from_plan(n00b_result_get_err(ordinal_r)));
        }

        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(n00b_store_hot_tail_scan_t,
                                   N00B_STORE_ERR_INDEX);
        }

        uint64_t ordinal = n00b_option_get(ordinal_opt);
        if (ordinal < first_ordinal || ordinal >= record_limit) {
            continue;
        }

        n00b_store_pos_t pos = {
            .generation = store->generation,
            .shard_id   = hot->shard_id,
            .ordinal    = ordinal,
        };
        n00b_list_push(*scan.matches, pos);
    }

    scan.has_last_observed = true;
    scan.last_observed     = last;
    scan.scanned_records   = record_limit - first_ordinal;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_store_hot_tail_scan_t, scan);
}

n00b_result_t(n00b_option_t(n00b_store_record_t *))
n00b_store_hot_record_view_for_pos(n00b_store_t     *store,
                                   n00b_store_pos_t  pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_shard_t *hot = store->hot_shard;
    if (hot == nullptr
        || pos.generation != store->generation
        || pos.shard_id != hot->shard_id
        || pos.ordinal >= hot->record_count) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(
            n00b_option_t(n00b_store_record_t *),
            n00b_option_none(n00b_store_record_t *));
    }

    auto record_r = n00b_store_record_view_hot_pos(hot,
                                                   pos,
                                                   .allocator = allocator);
    n00b_data_unlock(store->commit_lock);
    if (n00b_result_is_err(record_r)) {
        n00b_err_t err = n00b_result_get_err(record_r);
        return n00b_result_err(
            n00b_option_t(n00b_store_record_t *),
            err == N00B_STORE_INDEX_ERR_ARG ? N00B_STORE_ERR_ARG
                                            : N00B_STORE_ERR_INDEX);
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_record_t *),
        n00b_option_set(n00b_store_record_t *, n00b_result_get(record_r)));
}

n00b_result_t(n00b_option_t(n00b_store_record_t *))
n00b_store_hot_record_copy_for_pos(n00b_store_t     *store,
                                   n00b_store_pos_t  pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || pos.shard_id == 0) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_shard_t *hot = store->hot_shard;
    if (hot == nullptr
        || pos.generation != store->generation
        || pos.shard_id != hot->shard_id
        || pos.ordinal >= hot->record_count) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(
            n00b_option_t(n00b_store_record_t *),
            n00b_option_none(n00b_store_record_t *));
    }

    auto record_r = n00b_store_record_view_hot_pos(hot,
                                                   pos,
                                                   .allocator = allocator);
    if (n00b_result_is_err(record_r)) {
        n00b_data_unlock(store->commit_lock);
        n00b_err_t err = n00b_result_get_err(record_r);
        return n00b_result_err(
            n00b_option_t(n00b_store_record_t *),
            err == N00B_STORE_INDEX_ERR_ARG ? N00B_STORE_ERR_ARG
                                            : N00B_STORE_ERR_INDEX);
    }

    auto json_r = n00b_store_record_view_json_copy(
        n00b_result_get(record_r),
        .allocator = allocator);
    if (n00b_result_is_err(json_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_INDEX);
    }

    auto owned_r = n00b_store_record_view_owned_json(
        pos,
        n00b_result_get(json_r),
        .allocator = allocator);
    n00b_data_unlock(store->commit_lock);
    if (n00b_result_is_err(owned_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_INDEX);
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_record_t *),
        n00b_option_set(n00b_store_record_t *, n00b_result_get(owned_r)));
}

n00b_result_t(bool)
n00b_store_set_lifecycle_topic(n00b_store_t                 *store,
                               n00b_store_lifecycle_topic_t *topic)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->lifecycle_topic = topic;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_ingest_topic_t *)
n00b_store_ingest_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri)
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_ingest_topic_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_ingest_topic_t *topic =
        n00b_conduit_topic_init(n00b_store_ingest_payload_t, conduit, uri);
    if (topic == nullptr) {
        return n00b_result_err(n00b_store_ingest_topic_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_store_ingest_topic_t *, topic);
}

n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_record(n00b_json_node_t *record)
{
    if (record == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        n00b_variant_set(n00b_store_ingest_payload_t,
                         n00b_json_node_t *,
                         record));
}

n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_source(n00b_buffer_t *source)
{
    if (source == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        n00b_variant_set(n00b_store_ingest_payload_t,
                         n00b_buffer_t *,
                         source));
}

n00b_result_t(bool)
n00b_store_ingest_topic_publish(n00b_store_ingest_topic_t   *topic,
                                n00b_store_ingest_payload_t  payload)
{
    if (topic == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    if (!n00b_conduit_topic_is_active(base) || base->conduit == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_r =
        n00b_conduit_publish_try_claim(base);
    if (n00b_result_is_err(pub_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_publisher_t *pub = n00b_result_get(pub_r);
    n00b_store_ingest_msg_t  *msg = n00b_alloc_with_opts(
        n00b_store_ingest_msg_t,
        &(n00b_alloc_opts_t){
            .allocator = base->conduit->allocator,
        });
    if (msg == nullptr) {
        n00b_conduit_publish_yield(pub);
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = base;
    msg->header.generation = n00b_conduit_topic_generation(base);
    msg->header.epoch      = n00b_conduit_topic_epoch(base);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = payload;

    n00b_conduit_topic_deliver_msg(n00b_store_ingest_payload_t,
                                   topic,
                                   msg,
                                   N00B_CONDUIT_OP_ALL);
    n00b_conduit_publish_yield(pub);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_schema_t *)
n00b_store_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_schema_t *schema = n00b_alloc_with_opts(
        n00b_store_schema_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    schema->fields    = rocs_store_field_list_new(.allocator = allocator);
    schema->allocator = allocator;
    schema->frozen    = false;
    return n00b_result_ok(n00b_store_schema_t *, schema);
}

n00b_result_t(n00b_store_field_t *)
n00b_store_schema_add_field(n00b_store_schema_t *schema,
                            n00b_string_t       *name) _kargs
{
    bool                         required       = false;
    n00b_store_index_kind_t      index_kind     = N00B_STORE_INDEX_NONE;
    bool                         include_in_all = false;
    uint8_t                      ngram_n        = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_store_postings_kind_t   postings       = N00B_STORE_POSTINGS_SPARSE;
}
{
    if (schema == nullptr || schema->fields == nullptr
        || !rocs_json_field_name_valid(name)) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_ARG);
    }
    if (schema->frozen) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_STATE);
    }
    if (!rocs_store_index_kind_valid(index_kind)) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
    }
    if (!rocs_store_postings_kind_valid(postings)) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
    }
    if ((index_kind == N00B_STORE_INDEX_NONE
         || index_kind == N00B_STORE_INDEX_NUMERIC
         || index_kind == N00B_STORE_INDEX_BOOL
         || index_kind == N00B_STORE_INDEX_VECTOR)
        && postings != N00B_STORE_POSTINGS_SPARSE) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
    }
    if (index_kind == N00B_STORE_INDEX_NGRAM) {
        if (!rocs_store_ngram_n_valid(ngram_n)) {
            return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
        }
    }
    else if (ngram_n != N00B_STORE_NGRAM_DEFAULT_N) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
    }
    auto existing = rocs_store_schema_find_field_raw(schema, name);
    if (n00b_option_is_set(existing)) {
        return n00b_result_err(n00b_store_field_t *,
                               N00B_STORE_ERR_DUP_FIELD);
    }

    n00b_store_field_t *field = n00b_alloc_with_opts(
        n00b_store_field_t,
        &(n00b_alloc_opts_t){
            .allocator = schema->allocator,
        });
    field->name           = name;
    field->required       = required;
    field->index_kind     = index_kind;
    field->include_in_all = include_in_all;
    field->postings       = postings;
    field->ngram_n        = ngram_n;
    n00b_list_push(*schema->fields, field);

    return n00b_result_ok(n00b_store_field_t *, field);
}

n00b_result_t(bool)
n00b_store_schema_freeze(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->fields == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    schema->frozen = true;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_schema_is_frozen(n00b_store_schema_t *schema)
{
    if (schema == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(bool, schema->frozen);
}

n00b_result_t(uint64_t)
n00b_store_schema_get_field_count(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->fields == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*schema->fields));
}

n00b_result_t(n00b_option_t(n00b_store_field_t *))
n00b_store_schema_find_field(n00b_store_schema_t *schema,
                             n00b_string_t       *name)
{
    if (schema == nullptr || schema->fields == nullptr || name == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_field_t *),
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_field_t *),
                          rocs_store_schema_find_field_raw(schema, name));
}

n00b_result_t(n00b_string_t *)
n00b_store_field_get_name(n00b_store_field_t *field)
{
    if (field == nullptr || field->name == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, field->name);
}

n00b_result_t(bool)
n00b_store_field_is_required(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(bool, field->required);
}

n00b_result_t(n00b_store_index_kind_t)
n00b_store_field_get_index_kind(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_store_index_kind_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_index_kind_t, field->index_kind);
}

n00b_result_t(bool)
n00b_store_field_include_in_all(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(bool, field->include_in_all);
}

n00b_result_t(uint8_t)
n00b_store_field_get_ngram_n(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(uint8_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint8_t, field->ngram_n);
}

n00b_result_t(n00b_store_postings_kind_t)
n00b_store_field_get_postings_kind(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_store_postings_kind_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_postings_kind_t, field->postings);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_none() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_NONE,
                                        .allocator = allocator));
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_time(n00b_string_t            *field,
                                     uint64_t                  bucket_width,
                                     n00b_store_time_source_t  time_source)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_json_field_name_valid(field) || bucket_width == 0
        || (time_source != N00B_STORE_TIME_SOURCE_INGEST_CLOCK
            && time_source != N00B_STORE_TIME_SOURCE_RECORD_FIELD)) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_TIME,
                                        .field        = field,
                                        .bucket_width = bucket_width,
                                        .time_source  = time_source,
                                        .allocator    = allocator));
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_hash(n00b_string_t *field,
                                     uint32_t       buckets) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_json_field_name_valid(field) || buckets == 0) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_HASH,
                                        .field     = field,
                                        .buckets   = buckets,
                                        .allocator = allocator));
}

n00b_result_t(n00b_store_partition_kind_t)
n00b_store_partition_policy_get_kind(n00b_store_partition_policy_t *policy)
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_store_partition_kind_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_partition_kind_t, policy->kind);
}

n00b_result_t(n00b_store_time_source_t)
n00b_store_partition_policy_get_time_source(n00b_store_partition_policy_t *policy)
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_store_time_source_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_time_source_t, policy->time_source);
}

static n00b_result_t(n00b_string_t *)
rocs_store_partition_route_value(
    n00b_store_partition_policy_t        *policy,
    n00b_option_t(n00b_json_node_t *)     value_opt) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    switch (policy->kind) {
    case N00B_STORE_PARTITION_NONE:
        return n00b_result_ok(n00b_string_t *, r"default");

    case N00B_STORE_PARTITION_TIME: {
        // Two clean modes (see n00b_store_time_source_t):
        //
        //   INGEST_CLOCK (robust): route purely by ROCS's own wall-clock ingest
        //   time, ignoring the record value entirely.  No producer timestamp —
        //   wrong units, missing, CLOCK_MONOTONIC, or skewed — can flip the
        //   route, so the rollover cadence cannot be broken by upstream data.
        //   Every record gets a time bucket; "default" never occurs.  The
        //   ingest value MUST be wall-clock epoch ns (CLOCK_REALTIME) via
        //   n00b_capture_timestamp, NOT n00b_ns_timestamp() (CLOCK_MONOTONIC).
        //
        //   RECORD_FIELD: event-time bucketing by the record's field, with a
        //   deterministic "default" route for missing / non-integer /
        //   non-positive values so partition pruning stays sound (a query for
        //   such a value routes to the same "default" partition).  Only sound on
        //   a trusted producer; bad data can thrash the cadence — choose
        //   INGEST_CLOCK if that matters.
        if (policy->time_source == N00B_STORE_TIME_SOURCE_INGEST_CLOCK) {
            n00b_duration_t now_d;
            n00b_capture_timestamp(&now_d);
            uint64_t bucket = (uint64_t)n00b_ns_from_duration(&now_d)
                            / policy->bucket_width;
            return rocs_store_route_bucket(r"time/",
                                           bucket,
                                           .allocator = allocator);
        }

        if (n00b_option_is_set(value_opt)) {
            n00b_json_node_t *value = n00b_option_get(value_opt);
            if (n00b_json_type(value) == N00B_JSON_INT) {
                int64_t v = n00b_json_as_i64(value);
                if (v > 0) {
                    uint64_t bucket = (uint64_t)v / policy->bucket_width;
                    return rocs_store_route_bucket(r"time/",
                                                   bucket,
                                                   .allocator = allocator);
                }
            }
        }
        return n00b_result_ok(n00b_string_t *, r"default");
    }

    case N00B_STORE_PARTITION_HASH: {
        if (!n00b_option_is_set(value_opt)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        n00b_json_node_t *value = n00b_option_get(value_opt);
        auto term_r = n00b_store_normalize_scalar(value, .allocator = allocator);
        if (n00b_result_is_err(term_r)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        auto hash_r = n00b_store_normalize_hash(N00B_STORE_INDEX_TERM,
                                                n00b_result_get(term_r),
                                                .allocator = allocator);
        if (n00b_result_is_err(hash_r)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        uint64_t bucket = (uint64_t)n00b_result_get(hash_r) % policy->buckets;
        return rocs_store_route_bucket(r"hash/",
                                       bucket,
                                       .allocator = allocator);
    }
    }

    return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_POLICY);
}

n00b_result_t(n00b_string_t *)
n00b_store_partition_route(n00b_store_partition_policy_t *policy,
                           n00b_json_node_t              *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return rocs_store_partition_route_value(
        policy,
        rocs_store_partition_value(policy, record, allocator),
        .allocator = allocator);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_for_plan(n00b_store_t *store)
{
    if (store == nullptr || store->partition_policy == nullptr) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_STATE);
    }

    return n00b_result_ok(n00b_store_partition_policy_t *,
                          store->partition_policy);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_partition_policy_field_for_plan(
    n00b_store_partition_policy_t *policy)
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }

    switch (policy->kind) {
    case N00B_STORE_PARTITION_NONE:
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    case N00B_STORE_PARTITION_TIME:
    case N00B_STORE_PARTITION_HASH:
        if (policy->field == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_string_t *),
                                   N00B_STORE_ERR_STATE);
        }
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_set(n00b_string_t *,
                                              policy->field));
    }

    return n00b_result_err(n00b_option_t(n00b_string_t *),
                           N00B_STORE_ERR_POLICY);
}

n00b_result_t(n00b_string_t *)
n00b_store_partition_route_value_for_plan(
    n00b_store_partition_policy_t *policy,
    n00b_json_node_t              *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    n00b_option_t(n00b_json_node_t *) value_opt =
        value == nullptr
            ? n00b_option_none(n00b_json_node_t *)
            : n00b_option_set(n00b_json_node_t *, value);
    return rocs_store_partition_route_value(policy,
                                            value_opt,
                                            .allocator = allocator);
}

n00b_result_t(n00b_store_retain_policy_t *)
n00b_store_retain_policy_new(n00b_store_retain_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_store_retain_kind_valid(kind)) {
        return n00b_result_err(n00b_store_retain_policy_t *,
                               N00B_STORE_ERR_POLICY);
    }

    n00b_store_retain_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_retain_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    policy->kind = kind;

    return n00b_result_ok(n00b_store_retain_policy_t *, policy);
}

n00b_result_t(n00b_store_shard_retention_policy_t *)
n00b_store_shard_retention_policy_new() _kargs
{
    uint64_t          max_sealed_shards  = 0;
    uint64_t          drop_before_seal_ts = 0;
    n00b_string_t    *drop_reason        = nullptr;
    n00b_allocator_t *allocator          = nullptr;
}
{
    if (max_sealed_shards == 0 && drop_before_seal_ts == 0) {
        return n00b_result_err(n00b_store_shard_retention_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_shard_retention_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_shard_retention_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    policy->max_sealed_shards  = max_sealed_shards;
    policy->drop_before_seal_ts = drop_before_seal_ts;
    policy->drop_reason        = drop_reason == nullptr ? r"retention"
                                                        : drop_reason;

    return n00b_result_ok(n00b_store_shard_retention_policy_t *, policy);
}

n00b_result_t(n00b_store_seal_policy_t *)
n00b_store_seal_policy_new() _kargs
{
    uint64_t          max_records = 0;
    uint64_t          max_bytes   = 0;
    uint64_t          max_hot_bytes = 0;
    uint64_t          max_open_ns = 0;
    n00b_allocator_t *allocator   = nullptr;
}
{
    n00b_store_seal_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_seal_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
    });
    policy->max_records   = max_records;
    policy->max_bytes     = max_bytes;
    policy->max_hot_bytes = max_hot_bytes;
    policy->max_open_ns   = max_open_ns;

    return n00b_result_ok(n00b_store_seal_policy_t *, policy);
}

n00b_store_residency_policy_t
n00b_store_residency_policy_get_default(void)
{
    return (n00b_store_residency_policy_t){
        .preferred_backing    = N00B_STORE_IMAGE_AUTO,
        .max_resident_bytes   = 0,
        .max_resident_shards  = 0,
        .idle_ns              = 0,
        .prefetch_pruned_shards = false,
        .allow_direct_mmap    = true,
    };
}

// Replay a single orphaned journal into a freshly sealed shard.
//
// The recovered shard is given a deterministic id equal to the journal's id
// (so a re-run is idempotent), all framed records are replayed in order through
// the normal ingest path into a temporary hot shard, the shard is sealed to its
// deterministic object path (overwriting any partial prior-recovery image), the
// catalog is committed, and only then is the journal deleted.  A torn or
// corrupt trailing frame ends replay; the records read up to that point are
// still recovered.
static n00b_result_t(uint64_t)
rocs_store_recover_one_journal(n00b_store_t  *store,
                              n00b_string_t *journal_path,
                              uint64_t       shard_id)
{
    auto buf_r = rocs_store_read_vfs_object(store, journal_path);
    if (n00b_result_is_err(buf_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(buf_r));
    }
    n00b_buffer_t *journal      = n00b_result_get(buf_r);
    int64_t        journal_clen = 0;
    char          *journal_data = n00b_buffer_to_c(journal, &journal_clen);
    uint64_t       journal_len  = (uint64_t)journal_clen;

    n00b_pool_t       scratch_pool = {};
    n00b_allocator_t *scratch      = n00b_pool_init(
        &scratch_pool,
        .hidden            = true,
        .external_metadata = true,
        .name              = "rocs_journal_recover_scratch");

    auto alloc_r = rocs_store_hot_allocator_new(store);
    if (n00b_result_is_err(alloc_r)) {
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, n00b_result_get_err(alloc_r));
    }
    n00b_allocator_t *recovery_alloc = n00b_result_get(alloc_r);

    auto shard_r = n00b_store_shard_new(
        .shard_id   = shard_id,
        .retain_raw = store->retain_policy != nullptr
                   && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = recovery_alloc);
    if (n00b_result_is_err(shard_r)) {
        rocs_store_hot_allocator_destroy(store, recovery_alloc, 0);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, n00b_result_get_err(shard_r));
    }
    n00b_store_shard_t *recovery_shard = n00b_result_get(shard_r);

    // Temporarily install the recovery shard as the hot shard so the normal
    // ingest path appends + indexes into it.  The recovering flag suppresses
    // journaling and size-triggered auto-seal during replay.
    n00b_store_shard_t *saved_hot   = store->hot_shard;
    n00b_allocator_t   *saved_alloc = store->hot_allocator;
    n00b_string_t      *saved_pk    = store->hot_partition_key;
    store->hot_shard         = recovery_shard;
    store->hot_allocator     = recovery_alloc;
    store->hot_partition_key = r"default";
    store->recovering        = true;

    uint64_t replayed = 0;
    uint64_t off      = 0;
    while (off + sizeof(uint64_t) <= journal_len) {
        uint64_t frame_len = 0;
        memcpy(&frame_len, journal_data + off, sizeof(frame_len));
        off += sizeof(frame_len);
        if (frame_len == 0 || off + frame_len > journal_len) {
            break;  // torn / corrupt trailing frame
        }

        n00b_buffer_t *source = n00b_buffer_from_bytes(journal_data + off,
                                                       (int64_t)frame_len,
                                                       .allocator = scratch);
        off += frame_len;
        if (source == nullptr) {
            break;
        }

        n00b_buffer_t    *raw    = nullptr;
        n00b_json_node_t *record = nullptr;
        if (rocs_store_parse_source(source, &raw, &record, scratch)
            != N00B_STORE_OK) {
            break;  // corrupt frame body
        }

        auto route_r = n00b_store_partition_route(store->partition_policy,
                                                  record,
                                                  .allocator = scratch);
        n00b_string_t *route = n00b_result_is_ok(route_r)
                                   ? n00b_result_get(route_r)
                                   : nullptr;

        auto ingest_r = rocs_store_ingest_prepared_unlocked(store,
                                                            record,
                                                            raw,
                                                            route,
                                                            nullptr,
                                                            scratch);
        if (n00b_result_is_err(ingest_r)) {
            break;  // stop on first replay error; recover what we have
        }
        replayed++;
    }

    n00b_string_t *recovered_pk = store->hot_partition_key;

    // Restore the (still-null, pre-hot-shard) store state before sealing.
    store->hot_shard         = saved_hot;
    store->hot_allocator     = saved_alloc;
    store->hot_partition_key = saved_pk;
    store->recovering        = false;

    if (replayed == 0) {
        // Empty or fully-corrupt journal: nothing to recover.  Drop it.
        rocs_store_hot_allocator_destroy(store, recovery_alloc, 0);
        n00b_allocator_destroy(scratch);
        (void)n00b_vfs_delete(store->vfs, journal_path);
        return n00b_result_ok(uint64_t, 0);
    }

    auto path_r = rocs_store_shard_object_path(store, shard_id);
    if (n00b_result_is_err(path_r)) {
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, n00b_result_get_err(path_r));
    }
    n00b_string_t *object_path = n00b_result_get(path_r);

    // Overwrite a partial prior-recovery image if one exists.
    auto exist_r = n00b_vfs_stat(store->vfs, object_path);
    if (n00b_result_is_ok(exist_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
    }

    uint64_t seal_ts = (uint64_t)n00b_ns_timestamp();
    auto image_r = n00b_store_shard_seal(recovery_shard,
                                         .seal_ts      = seal_ts,
                                         .base_address = 0,
                                         .allocator    = scratch);
    if (n00b_result_is_err(image_r)) {
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }
    n00b_buffer_t *image   = n00b_result_get(image_r);
    uint64_t       img_len = (uint64_t)n00b_buffer_len(image);

    auto write_r = rocs_store_write_vfs_object(store,
                                               object_path,
                                               image,
                                               .create_exclusive = true);
    if (n00b_result_is_err(write_r)) {
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, n00b_result_get_err(write_r));
    }

    auto stat_r = n00b_vfs_stat(store->vfs, object_path);
    if (n00b_result_is_err(stat_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_VFS);
    }
    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != img_len) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_CORRUPT);
    }

    n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
        store,
        .shard_id          = shard_id,
        .generation        = store->generation,
        .object_path       = object_path,
        .byte_len          = stat.size,
        .record_count      = recovery_shard->record_count,
        .schema_generation = store->schema_generation,
        .seal_ts           = recovery_shard->seal_ts,
        .partition_key     = recovered_pk,
        .etag              = stat.etag);

    rocs_store_catalog_insert_sorted(store, entry);
    if (shard_id >= store->next_shard_id) {
        store->next_shard_id = shard_id + 1;
    }
    rocs_store_refresh_oldest_available(store);

    auto catalog_r = rocs_store_catalog_write(store);
    if (n00b_result_is_err(catalog_r)) {
        // Leave both the object and the journal in place; the next open re-runs
        // recovery (the orphan-shard scan adopts the object, or replay redoes
        // it) once the catalog write can succeed.
        rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
        n00b_allocator_destroy(scratch);
        return n00b_result_err(uint64_t, n00b_result_get_err(catalog_r));
    }

    rocs_store_hot_allocator_destroy(store, recovery_alloc, replayed);
    n00b_allocator_destroy(scratch);

    // Catalog is durable: the journal is now redundant.
    (void)n00b_vfs_delete(store->vfs, journal_path);
    return n00b_result_ok(uint64_t, replayed);
}

// Replay every orphaned recovery journal at store open, single-threaded, before
// the conduit ingest pool starts and before the live hot shard is created.
static n00b_result_t(uint64_t)
rocs_store_recover_journals(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    if (!store->recovery_journal || store->read_only) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto dir_r = rocs_store_journal_dir_path(store);
    if (n00b_result_is_err(dir_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(dir_r));
    }
    n00b_string_t *dir = n00b_result_get(dir_r);

    auto list_r = n00b_vfs_readdir(store->vfs,
                                   dir,
                                   0,
                                   .allocator = store->allocator);
    if (n00b_result_is_err(list_r)) {
        if (n00b_result_get_err(list_r) == N00B_VFS_ERR_NOT_FOUND) {
            return n00b_result_ok(uint64_t, 0);
        }
        return n00b_result_err(uint64_t, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_list_result_t *list      = n00b_result_get(list_r);
    uint64_t                recovered = 0;
    for (uint32_t i = 0; i < list->count; i++) {
        n00b_vfs_list_entry_t *listed = &list->entries[i];
        if (listed->kind != N00B_VFS_OBJ_FILE || listed->name == nullptr) {
            continue;
        }

        // Parse "<id>.jrnl" -> shard_id.
        n00b_string_t *name  = listed->name;
        const char    *full  = name->data;
        size_t         n     = name->u8_bytes;
        size_t         start = 0;
        for (size_t j = 0; j < n; j++) {
            if (full[j] == '/') {
                start = j + 1;
            }
        }
        const char *data     = full + start;
        size_t      base_len = n - start;
        if (base_len <= 5 || memcmp(data + base_len - 5, ".jrnl", 5) != 0) {
            continue;
        }
        size_t   digits_len = base_len - 5;
        uint64_t shard_id   = 0;
        bool     ok         = digits_len > 0;
        for (size_t j = 0; j < digits_len; j++) {
            char c = data[j];
            if (c < '0' || c > '9') {
                ok = false;
                break;
            }
            uint64_t digit = (uint64_t)(c - '0');
            if (shard_id > (UINT64_MAX - digit) / 10) {
                ok = false;
                break;
            }
            shard_id = shard_id * 10 + digit;
        }
        if (!ok || shard_id == 0) {
            continue;
        }

        auto path_r = rocs_store_journal_path(store, shard_id);
        if (n00b_result_is_err(path_r)) {
            continue;
        }
        n00b_string_t *journal_path = n00b_result_get(path_r);

        // If the shard is already committed (clean close, or a crash after the
        // catalog commit but before journal delete), the journal is redundant.
        if (n00b_option_is_set(rocs_store_catalog_find_raw(store, shard_id))) {
            (void)n00b_vfs_delete(store->vfs, journal_path);
            continue;
        }

        auto rec_r = rocs_store_recover_one_journal(store,
                                                    journal_path,
                                                    shard_id);
        if (n00b_result_is_err(rec_r)) {
            n00b_eprintf("rocs: recovery of journal for shard [|#|] failed "
                         "(err [|#|]); leaving journal in place\n",
                         shard_id,
                         (int64_t)n00b_result_get_err(rec_r));
            continue;
        }
        recovered += n00b_result_get(rec_r);
    }

    return n00b_result_ok(uint64_t, recovered);
}

n00b_result_t(n00b_store_t *)
n00b_store_open_vfs(n00b_vfs_t          *vfs,
                    n00b_string_t       *root,
                    n00b_store_schema_t *schema) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_retain_policy_t    *retain_policy    = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
    n00b_store_residency_policy_t *residency_policy = nullptr;
    n00b_vfs_cache_t              *cache            = nullptr;
    n00b_store_commit_topic_t     *commit_topic     = nullptr;
    n00b_store_lifecycle_topic_t  *lifecycle_topic  = nullptr;
    n00b_string_t                 *display_name     = nullptr;
    bool                           recovery_journal = false;
    n00b_allocator_t              *allocator        = nullptr;
}
{
    if (vfs == nullptr || schema == nullptr || schema->fields == nullptr
        || !rocs_store_root_valid(root)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_ARG);
    }

    auto freeze_r = n00b_store_schema_freeze(schema);
    if (n00b_result_is_err(freeze_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(freeze_r));
    }

    if (partition_policy == nullptr) {
        auto part_r = n00b_store_partition_policy_new_none(
            .allocator = allocator);
        if (n00b_result_is_err(part_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(part_r));
        }
        partition_policy = n00b_result_get(part_r);
    }
    if (retain_policy == nullptr) {
        auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_NONE,
                                                     .allocator = allocator);
        if (n00b_result_is_err(retain_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(retain_r));
        }
        retain_policy = n00b_result_get(retain_r);
    }
    if (seal_policy == nullptr) {
        auto seal_r = n00b_store_seal_policy_new(.allocator = allocator);
        if (n00b_result_is_err(seal_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(seal_r));
        }
        seal_policy = n00b_result_get(seal_r);
    }

    n00b_store_residency_policy_t residency =
        residency_policy == nullptr
            ? n00b_store_residency_policy_get_default()
            : *residency_policy;

    n00b_store_t *store = n00b_alloc_with_opts(
        n00b_store_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    store->vfs              = vfs;
    store->root             = root;
    store->display_name     = display_name;
    store->schema           = schema;
    store->partition_policy = partition_policy;
    store->retain_policy    = retain_policy;
    store->seal_policy      = seal_policy;
    store->residency_policy = residency;
    store->cache            = cache;
    store->commit_topic     = commit_topic;
    store->lifecycle_topic  = lifecycle_topic;
    store->hot_shard        = nullptr;
    store->hot_allocator    = nullptr;
    store->hot_partition_key = r"default";
    store->retired_hot_allocators =
        rocs_store_retired_hot_allocator_list_new(.allocator = allocator);
    store->catalog          = rocs_store_catalog_list_new(.allocator = allocator);
    store->allocator        = allocator;
    store->residency_lock   = n00b_data_lock_new(.allocator = allocator);
    store->commit_lock      = n00b_data_lock_new(.allocator = allocator);
    store->batch_pool       = nullptr;
    store->batch_pool_workers = 0;
    store->batch_pool_capacity = 0;
    store->state            = N00B_STORE_STATE_OPEN;
    store->read_only        = false;
    store->recovery_journal = recovery_journal;
    store->recovering       = false;
    store->journal_fh       = N00B_VFS_FH_INVALID;
    store->journal_shard_id = 0;
    store->journal_path     = nullptr;
    store->journal_unsynced = 0;
    store->durable_drop_count   = 0;
    store->durable_drop_records = 0;
    store->durable_drop_last_err = N00B_STORE_OK;
    store->next_shard_id    = 2;
    store->generation       = 0;
    store->schema_generation = 0;
    store->oldest_available = (n00b_store_pos_t){};
    store->has_oldest_available = false;
    store->active_pins      = 0;
    store->borrowed_catalog_enumeration_disabled = false;

    auto layout_r = rocs_store_ensure_layout(store);
    if (n00b_result_is_err(layout_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(layout_r));
    }

    auto catalog_r = rocs_store_catalog_load(store);
    if (n00b_result_is_err(catalog_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(catalog_r));
    }

    // Replay orphaned recovery journals into sealed shards before choosing the
    // new hot shard id, so the live hot shard never collides with a shard a
    // journal is about to deterministically recover.
    auto journal_recover_r = rocs_store_recover_journals(store);
    if (n00b_result_is_err(journal_recover_r)) {
        return n00b_result_err(n00b_store_t *,
                               n00b_result_get_err(journal_recover_r));
    }

    uint64_t requested_hot_shard_id = store->next_shard_id - 1;
    auto     hot_shard_id_r =
        rocs_store_first_free_hot_shard_id(store, requested_hot_shard_id);
    if (n00b_result_is_err(hot_shard_id_r)) {
        return n00b_result_err(n00b_store_t *,
                               n00b_result_get_err(hot_shard_id_r));
    }
    uint64_t hot_shard_id = n00b_result_get(hot_shard_id_r);
    store->next_shard_id  = hot_shard_id + 1;

    auto hot_allocator_r = rocs_store_hot_allocator_new(store);
    if (n00b_result_is_err(hot_allocator_r)) {
        return n00b_result_err(n00b_store_t *,
                               n00b_result_get_err(hot_allocator_r));
    }
    store->hot_allocator = n00b_result_get(hot_allocator_r);

    auto shard_r = n00b_store_shard_new(
        .shard_id   = hot_shard_id,
        .retain_raw = retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = store->hot_allocator);
    if (n00b_result_is_err(shard_r)) {
        rocs_store_hot_allocator_destroy(store, store->hot_allocator, 0);
        store->hot_allocator = nullptr;
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(shard_r));
    }
    store->hot_shard = n00b_result_get(shard_r);

    auto recover_r = rocs_store_recover_orphaned_shards(store);
    if (n00b_result_is_err(recover_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(recover_r));
    }

    // Open the write-ahead journal for the live hot shard.  Best-effort: if it
    // fails, ingest still proceeds (just without journal-backed recovery for
    // this shard) until the next rotation reopens one.
    if (store->recovery_journal) {
        (void)rocs_store_journal_open(store, hot_shard_id);
    }

    return n00b_result_ok(n00b_store_t *, store);
}

static n00b_result_t(n00b_vfs_backend_t *)
rocs_store_config_backend(n00b_store_config_t *config,
                          n00b_allocator_t    *allocator)
{
    if (config->profile == N00B_STORE_PROFILE_SERVICE_S3) {
        auto cfg_r = n00b_aws_config(config->aws_region,
                                     .endpoint_override = config->s3_endpoint,
                                     .allocator         = allocator);
        if (n00b_result_is_err(cfg_r)) {
            return n00b_result_err(n00b_vfs_backend_t *, N00B_STORE_ERR_VFS);
        }

        auto be_r = n00b_aws_s3_vfs_backend_new(
            n00b_result_get(cfg_r),
            config->s3_bucket,
            .prefix           = config->s3_prefix,
            .force_path_style = config->has_s3_path_style
                                    ? config->s3_path_style
                                    : false,
            .allocator        = allocator);
        if (n00b_result_is_err(be_r)) {
            return n00b_result_err(n00b_vfs_backend_t *, N00B_STORE_ERR_VFS);
        }
        return be_r;
    }

    if (config->profile == N00B_STORE_PROFILE_SERVICE_LOCAL
        && !rocs_store_string_empty(config->cache_dir)) {
        auto local_r = n00b_vfs_backend_local_new(config->cache_dir,
                                                  .allocator = allocator);
        if (n00b_result_is_err(local_r)) {
            return n00b_result_err(n00b_vfs_backend_t *, N00B_STORE_ERR_VFS);
        }
        return local_r;
    }

    auto mem_r = n00b_vfs_backend_memory_new(.allocator = allocator);
    if (n00b_result_is_err(mem_r)) {
        return n00b_result_err(n00b_vfs_backend_t *, N00B_STORE_ERR_VFS);
    }
    return mem_r;
}

n00b_result_t(n00b_store_t *)
n00b_store_open_config(n00b_store_schema_t *schema,
                       n00b_store_config_t *config) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
    n00b_allocator_t              *allocator        = nullptr;
}
{
    auto valid_r = rocs_store_config_validate(config, schema, true);
    if (n00b_result_is_err(valid_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(valid_r));
    }

    auto vfs_r = n00b_vfs_new(.allocator = allocator);
    if (n00b_result_is_err(vfs_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
    }

    auto backend_r = rocs_store_config_backend(config, allocator);
    if (n00b_result_is_err(backend_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(backend_r));
    }
    n00b_vfs_backend_t *backend = n00b_result_get(backend_r);

    n00b_vfs_cache_t *cache = nullptr;
    if (config->profile == N00B_STORE_PROFILE_SERVICE_S3
        && !rocs_store_string_empty(config->cache_dir)) {
        n00b_vfs_cache_policy_t policy = {
            .max_size_bytes   = config->cache_bytes,
            .max_entry_age_ns = 0,
            .max_entries      = 0,
            .write_through    = true,
            .use_hard_links   = false,
        };
        auto cache_r = n00b_vfs_cache_new(config->cache_dir, backend, policy);
        if (n00b_result_is_err(cache_r)) {
            return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
        }
        cache = n00b_result_get(cache_r);
    }

    auto mount_r = n00b_vfs_mount(n00b_result_get(vfs_r),
                                  r"/",
                                  backend,
                                  0);
    if (n00b_result_is_err(mount_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
    }

    n00b_store_residency_policy_t residency = {
        .preferred_backing       =
            config->profile == N00B_STORE_PROFILE_SERVICE_LOCAL
                ? N00B_STORE_IMAGE_LOCAL_MMAP
                : N00B_STORE_IMAGE_PINNED_BUFFER,
        .max_resident_bytes      = config->resident_bytes,
        .max_resident_shards     = (uint32_t)config->resident_shards,
        .idle_ns                 = 0,
        .prefetch_pruned_shards  = false,
        .allow_direct_mmap       =
            config->profile == N00B_STORE_PROFILE_SERVICE_LOCAL,
    };

    auto store_r = n00b_store_open_vfs(n00b_result_get(vfs_r),
                                       config->root,
                                       schema,
                                       .partition_policy = partition_policy,
                                       .seal_policy      = seal_policy,
                                       .cache            = cache,
                                       .residency_policy = &residency,
                                       .display_name     = config->name,
                                       .allocator        = allocator);
    if (n00b_result_is_ok(store_r)) {
        n00b_store_t *store = n00b_result_get(store_r);
        store->read_only = config->read_only
                           || config->writer_mode
                                  == N00B_STORE_WRITER_READ_REPLICA;
    }
    return store_r;
}

n00b_result_t(bool)
n00b_store_flush(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->read_only) {
        n00b_data_unlock(store->commit_lock);
        rocs_store_try_reclaim_retired_hot_allocators(store);
        return n00b_result_ok(bool, true);
    }

    if (store->hot_shard != nullptr && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            nullptr,
            store->hot_partition_key,
            false);
        if (n00b_result_is_err(seal_r)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
        n00b_data_unlock(store->commit_lock);
        rocs_store_try_reclaim_retired_hot_allocators(store);
        return n00b_result_ok(bool, true);
    }

    auto write_r = rocs_store_catalog_write(store);
    n00b_data_unlock(store->commit_lock);
    if (n00b_result_is_ok(write_r)) {
        rocs_store_try_reclaim_retired_hot_allocators(store);
    }
    return write_r;
}

static void
rocs_store_batch_pool_shutdown(n00b_store_t *store)
{
    if (store == nullptr || store->batch_pool == nullptr) {
        return;
    }

    n00b_worker_pool_shutdown(store->batch_pool);
    store->batch_pool          = nullptr;
    store->batch_pool_workers  = 0;
    store->batch_pool_capacity = 0;
}

static n00b_result_t(n00b_worker_pool_t *)
rocs_store_batch_pool_get(n00b_store_t *store, int32_t workers, int32_t cap)
{
    if (store == nullptr || workers <= 0 || cap <= 0) {
        return n00b_result_err(n00b_worker_pool_t *, N00B_STORE_ERR_ARG);
    }

    if (store->batch_pool != nullptr
        && store->batch_pool_workers == workers
        && store->batch_pool_capacity == cap) {
        return n00b_result_ok(n00b_worker_pool_t *, store->batch_pool);
    }

    rocs_store_batch_pool_shutdown(store);

    n00b_worker_pool_t *pool = n00b_worker_pool_new(workers,
                                                    cap,
                                                    rocs_store_batch_worker,
                                                    nullptr,
                                                    .allocator =
                                                        store->allocator);
    if (pool == nullptr) {
        return n00b_result_err(n00b_worker_pool_t *, N00B_STORE_ERR_INTERNAL);
    }

    store->batch_pool          = pool;
    store->batch_pool_workers  = workers;
    store->batch_pool_capacity = cap;

    return n00b_result_ok(n00b_worker_pool_t *, pool);
}

n00b_result_t(bool)
n00b_store_close(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins != 0) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    if (!store->read_only && store->hot_shard != nullptr
        && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            nullptr,
            store->hot_partition_key,
            true);
        if (n00b_result_is_err(seal_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
    }
    else if (!store->read_only) {
        auto catalog_r = rocs_store_catalog_write(store);
        if (n00b_result_is_err(catalog_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return catalog_r;
        }
    }

    auto unload_r = rocs_store_resident_unload_all_unpinned(store);
    if (n00b_result_is_err(unload_r)) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(unload_r));
    }

    // Clean close: the hot shard was sealed (or had no records), so its journal
    // is no longer needed.  Close the handle and remove the file.  (If this is
    // skipped by a crash, the next open's recovery scan deletes it as redundant
    // once it sees the shard already in the catalog.)
    if (store->journal_fh != N00B_VFS_FH_INVALID) {
        uint64_t closing_journal_id = store->journal_shard_id;
        rocs_store_journal_finalize(store);
        if (!store->read_only) {
            rocs_store_journal_delete(store, closing_journal_id);
        }
    }

    rocs_store_batch_pool_shutdown(store);

    rocs_store_retired_hot_allocator_list_t *retired =
        rocs_store_detach_retired_hot_allocators_locked(store);
    n00b_allocator_t *current_hot_allocator = store->hot_allocator;
    uint64_t          current_hot_records =
        store->hot_shard == nullptr ? 0 : store->hot_shard->record_count;
    store->hot_allocator = nullptr;
    store->hot_shard     = nullptr;
    store->state = N00B_STORE_STATE_CLOSED;
    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);

    rocs_store_destroy_retired_hot_allocators(store, retired);
    if (current_hot_allocator != nullptr) {
        rocs_store_hot_allocator_destroy(store,
                                         current_hot_allocator,
                                         current_hot_records);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_state_t)
n00b_store_get_state(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_state_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->residency_lock);
    n00b_store_state_t state = store->state;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(n00b_store_state_t, state);
}

n00b_result_t(n00b_store_schema_t *)
n00b_store_get_schema(n00b_store_t *store)
{
    if (store == nullptr || store->schema == nullptr) {
        return n00b_result_err(n00b_store_schema_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_schema_t *, store->schema);
}

n00b_result_t(n00b_string_t *)
n00b_store_get_root(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, store->root);
}

n00b_result_t(uint64_t)
n00b_store_get_generation(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, store->generation);
}

n00b_result_t(n00b_store_catalog_entry_t *)
n00b_store_seal_hot_shard(n00b_store_t *store) _kargs
{
    uint64_t          seal_ts      = 0;
    uint32_t          base_address = 0;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    auto seal_r = rocs_store_seal_hot_shard_unlocked(store,
                                                     seal_ts,
                                                     base_address,
                                                     allocator,
                                                     store->hot_partition_key,
                                                     false);
    n00b_data_unlock(store->commit_lock);
    return seal_r;
}

n00b_result_t(bool)
n00b_store_apply_event_time_watermark(n00b_store_t *store,
                                      uint64_t      watermark_ts)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN
        || store->hot_shard == nullptr
        || store->partition_policy == nullptr) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->partition_policy->kind != N00B_STORE_PARTITION_TIME
        || store->partition_policy->bucket_width == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_POLICY);
    }
    if (store->hot_shard->record_count == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    n00b_option_t(uint64_t) bucket_opt =
        rocs_store_time_bucket_from_route(store->hot_partition_key);
    if (!n00b_option_is_set(bucket_opt)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    uint64_t bucket = n00b_option_get(bucket_opt);
    if (watermark_ts / store->partition_policy->bucket_width <= bucket) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    auto seal_r = rocs_store_seal_hot_shard_unlocked(
        store,
        (uint64_t)n00b_ns_timestamp(),
        0,
        nullptr,
        store->hot_partition_key,
        false);
    if (n00b_result_is_err(seal_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(seal_r));
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_ingest_common(n00b_store_t     *store,
                         n00b_json_node_t *record,
                         n00b_buffer_t    *raw,
                         n00b_allocator_t *allocator)
{
    if (store == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);

    n00b_err_t preflight = rocs_store_preflight_ingest(store,
                                                       record,
                                                       raw,
                                                       allocator);
    if (preflight != N00B_STORE_OK) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, preflight);
    }

    auto route_r = n00b_store_partition_route(store->partition_policy,
                                              record,
                                              .allocator = allocator);
    if (n00b_result_is_err(route_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(route_r));
    }
    n00b_string_t *route = n00b_result_get(route_r);
    if (route == nullptr) {
        route = r"default";
    }

    uint64_t drops_before = store->durable_drop_count;
    auto     ingest_r     = rocs_store_ingest_prepared_unlocked(store,
                                                        record,
                                                        raw,
                                                        route,
                                                        nullptr,
                                                        allocator);
    // A size-triggered auto-seal inside ingest can irreversibly drop the record
    // we just committed (no journal).  Surface that as a durable failure rather
    // than the misleading Ok the swallowed auto-seal would otherwise return.
    if (store->durable_drop_count != drops_before) {
        n00b_err_t drop_err = store->durable_drop_last_err;
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, drop_err);
    }
    n00b_data_unlock(store->commit_lock);
    return ingest_r;
}

n00b_result_t(bool)
n00b_store_ingest(n00b_store_t *store, n00b_json_node_t *record)
{
    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = true,
                       .name              = "rocs_ingest_scratch");
    auto ingest_r =
        rocs_store_ingest_common(store, record, nullptr, scratch_allocator);
    n00b_allocator_destroy(scratch_allocator);
    return ingest_r;
}

n00b_result_t(bool)
n00b_store_ingest_buf(n00b_store_t *store, n00b_buffer_t *source)
{
    if (store == nullptr || source == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = true,
                       .name              = "rocs_ingest_buf_scratch");

    n00b_buffer_t *raw = nullptr;
    n00b_json_node_t *record = nullptr;
    n00b_err_t err = rocs_store_parse_source(source,
                                             &raw,
                                             &record,
                                             scratch_allocator);
    if (err != N00B_STORE_OK) {
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(bool, err);
    }

    auto ingest_r = rocs_store_ingest_common(store,
                                             record,
                                             raw,
                                             scratch_allocator);
    n00b_allocator_destroy(scratch_allocator);
    return ingest_r;
}

static n00b_result_t(uint64_t)
rocs_store_ingest_batch_common(n00b_store_t             *store,
                               n00b_store_record_list_t *records,
                               n00b_store_source_list_t *sources,
                               int32_t                   worker_count,
                               int32_t                   queue_capacity)
{
    if (store == nullptr || (records == nullptr && sources == nullptr)
        || (records != nullptr && sources != nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    if (worker_count < 0 || queue_capacity < 0) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t count = records != nullptr ? (uint64_t)n00b_list_len(*records)
                                        : (uint64_t)n00b_list_len(*sources);
    if (count > (uint64_t)INT32_MAX) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }
    if (count == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(uint64_t, 0);
    }

    int32_t workers = worker_count == 0 ? 4 : worker_count;
    if (workers <= 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    int32_t cap = queue_capacity == 0 ? workers : queue_capacity;
    if (cap <= 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = true,
                       .name              = "rocs_batch_ingest_scratch");

    rocs_store_batch_job_t **jobs = n00b_alloc_array(
        rocs_store_batch_job_t *,
        (int64_t)count,
        .allocator = scratch_allocator);
    if (jobs == nullptr) {
        n00b_data_unlock(store->commit_lock);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }

    auto pool_r = rocs_store_batch_pool_get(store, workers, cap);
    if (n00b_result_is_err(pool_r)) {
        n00b_data_unlock(store->commit_lock);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(uint64_t, n00b_result_get_err(pool_r));
    }
    n00b_worker_pool_t *pool = n00b_result_get(pool_r);

    for (uint64_t i = 0; i < count; i++) {
        rocs_store_batch_job_t *job = n00b_alloc(
            rocs_store_batch_job_t,
            .allocator = scratch_allocator);
        job->store        = store;
        job->input_record = nullptr;
        job->source       = nullptr;
        job->allocator    = scratch_allocator;
        job->record       = nullptr;
        job->raw          = nullptr;
        job->route        = nullptr;
        job->terms        = nullptr;
        job->err          = N00B_STORE_OK;
        if (records != nullptr) {
            job->input_record = n00b_list_get(*records, (size_t)i);
        }
        else {
            job->source = n00b_list_get(*sources, (size_t)i);
        }
        jobs[i] = job;
        n00b_worker_pool_submit(pool, job);
    }

    n00b_worker_pool_quiesce(pool);

    for (uint64_t i = 0; i < count; i++) {
        if (jobs[i] == nullptr || jobs[i]->err != N00B_STORE_OK) {
            n00b_err_t err = jobs[i] == nullptr ? N00B_STORE_ERR_INTERNAL
                                                : jobs[i]->err;
            n00b_data_unlock(store->commit_lock);
            n00b_allocator_destroy(scratch_allocator);
            return n00b_result_err(uint64_t, err);
        }
    }

    uint64_t drops_before = store->durable_drop_count;
    uint64_t committed     = 0;
    for (uint64_t i = 0; i < count; i++) {
        auto ingest_r = rocs_store_ingest_prepared_unlocked(store,
                                                            jobs[i]->record,
                                                            jobs[i]->raw,
                                                            jobs[i]->route,
                                                            jobs[i]->terms,
                                                            scratch_allocator);
        if (n00b_result_is_err(ingest_r)) {
            n00b_err_t err = n00b_result_get_err(ingest_r);
            /*
             * A route-change seal in this ingest can irreversibly drop the
             * records committed earlier in this batch (no journal).  That is
             * data loss, not a clean prefix: surface it as an error and never
             * report the dropped records as committed.
             */
            if (store->durable_drop_count != drops_before) {
                err = store->durable_drop_last_err;
                n00b_data_unlock(store->commit_lock);
                n00b_allocator_destroy(scratch_allocator);
                return n00b_result_err(uint64_t, err);
            }
            n00b_data_unlock(store->commit_lock);
            n00b_allocator_destroy(scratch_allocator);
            /*
             * result_t cannot carry both an error and a committed prefix.
             * Once any prefix is visible, the batch retry contract is
             * Ok(committed); callers resume from that index.
             */
            if (committed != 0) {
                return n00b_result_ok(uint64_t, committed);
            }
            return n00b_result_err(uint64_t, err);
        }
        committed++;
    }

    // A size-triggered auto-seal can drop records without returning an error
    // from ingest; treat any uncovered drop as a durable failure too.
    if (store->durable_drop_count != drops_before) {
        n00b_err_t drop_err = store->durable_drop_last_err;
        n00b_data_unlock(store->commit_lock);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(uint64_t, drop_err);
    }

    n00b_data_unlock(store->commit_lock);
    n00b_allocator_destroy(scratch_allocator);
    return n00b_result_ok(uint64_t, committed);
}

n00b_result_t(uint64_t)
n00b_store_ingest_batch(n00b_store_t             *store,
                        n00b_store_record_list_t *records) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
}
{
    return rocs_store_ingest_batch_common(store,
                                          records,
                                          nullptr,
                                          worker_count,
                                          queue_capacity);
}

n00b_result_t(uint64_t)
n00b_store_ingest_buf_batch(n00b_store_t             *store,
                            n00b_store_source_list_t *sources) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
}
{
    return rocs_store_ingest_batch_common(store,
                                          nullptr,
                                          sources,
                                          worker_count,
                                          queue_capacity);
}

static void
rocs_store_emit_lifecycle_drop(n00b_store_t               *store,
                               n00b_store_catalog_entry_t *entry,
                               n00b_string_t              *drop_reason)
{
    if (store == nullptr || entry == nullptr
        || store->lifecycle_topic == nullptr) {
        return;
    }

    n00b_store_lifecycle_t event = {
        .kind         = N00B_STORE_LIFECYCLE_DROPPED,
        .shard_id     = entry->shard_id,
        .record_count = entry->record_count,
        .byte_size    = entry->byte_len,
        .open_ts      = 0,
        .seal_ts      = entry->seal_ts,
        .drop_reason  = drop_reason == nullptr ? r"retention" : drop_reason,
    };
    auto event_r = n00b_store_lifecycle_publish(store->lifecycle_topic, event);
    (void)event_r;
}

static n00b_result_t(bool)
rocs_store_drop_sealed_shard_locked(n00b_store_t  *store,
                                    uint64_t       shard_id,
                                    n00b_string_t *drop_reason)
{
    if (store == nullptr || store->catalog == nullptr || shard_id == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    uint64_t index = 0;
    if (!rocs_store_catalog_find_index(store, shard_id, &index)) {
        return n00b_result_err(bool, N00B_STORE_ERR_RETENTION);
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    if (entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    if (entry->resident_pins != 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    n00b_store_pos_t old_oldest = store->oldest_available;
    bool             old_has_oldest = store->has_oldest_available;

    if (entry->resident_map != nullptr) {
        auto unload_r = rocs_store_resident_unload_entry(store, entry);
        if (n00b_result_is_err(unload_r)) {
            return n00b_result_err(bool, n00b_result_get_err(unload_r));
        }
    }

    entry = n00b_list_delete(*store->catalog, (size_t)index);
    rocs_store_refresh_oldest_available(store);

    auto catalog_r = rocs_store_catalog_write(store);
    if (n00b_result_is_err(catalog_r)) {
        n00b_list_insert(*store->catalog, (size_t)index, entry);
        store->oldest_available     = old_oldest;
        store->has_oldest_available = old_has_oldest;
        return n00b_result_err(bool, n00b_result_get_err(catalog_r));
    }

    auto delete_r = n00b_vfs_delete(store->vfs, entry->object_path);
    if (n00b_result_is_err(delete_r)
        && n00b_result_get_err(delete_r) != N00B_VFS_ERR_NOT_FOUND) {
        n00b_list_insert(*store->catalog, (size_t)index, entry);
        store->oldest_available     = old_oldest;
        store->has_oldest_available = old_has_oldest;
        auto rollback_r = rocs_store_catalog_write(store);
        (void)rollback_r;
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    rocs_store_emit_lifecycle_drop(store, entry, drop_reason);
    return n00b_result_ok(bool, true);
}

static n00b_store_catalog_entry_t *
rocs_store_oldest_retention_candidate(n00b_store_t                        *store,
                                      n00b_store_shard_retention_policy_t *policy)
{
    if (store == nullptr || policy == nullptr || store->catalog == nullptr) {
        return nullptr;
    }

    uint64_t count = (uint64_t)n00b_list_len(*store->catalog);
    bool over_count = policy->max_sealed_shards != 0
                   && count > policy->max_sealed_shards;

    n00b_store_catalog_entry_t *candidate = nullptr;
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry == nullptr) {
            continue;
        }
        bool old_by_time = policy->drop_before_seal_ts != 0
                        && entry->seal_ts < policy->drop_before_seal_ts;
        if (!over_count && !old_by_time) {
            continue;
        }
        if (rocs_store_entry_pos_less(entry, candidate)) {
            candidate = entry;
        }
    }

    return candidate;
}

n00b_result_t(uint64_t)
n00b_store_apply_shard_retention(
    n00b_store_t                        *store,
    n00b_store_shard_retention_policy_t *policy)
{
    if (store == nullptr || policy == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t dropped = 0;
    while (true) {
        n00b_store_catalog_entry_t *candidate =
            rocs_store_oldest_retention_candidate(store, policy);
        if (candidate == nullptr) {
            break;
        }

        uint64_t shard_id = candidate->shard_id;
        auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                          shard_id,
                                                          policy->drop_reason);
        if (n00b_result_is_err(drop_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(uint64_t, n00b_result_get_err(drop_r));
        }
        dropped++;
    }

    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(uint64_t, dropped);
}

n00b_result_t(bool)
n00b_store_drop_sealed_shard(n00b_store_t *store,
                             uint64_t      shard_id) _kargs
{
    n00b_string_t *drop_reason = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                      shard_id,
                                                      drop_reason);
    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);
    return drop_r;
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_oldest_available_pos(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    n00b_option_t(n00b_store_pos_t) result =
        store->has_oldest_available
            ? n00b_option_set(n00b_store_pos_t, store->oldest_available)
            : n00b_option_none(n00b_store_pos_t);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_store_resume_check_t)
n00b_store_resume_check(n00b_store_t *store, n00b_store_pos_t pos)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_resume_check_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_resume_check_t,
                               N00B_STORE_ERR_STATE);
    }
    if (pos.generation != store->generation) {
        n00b_store_resume_check_t check = {
            .available        = false,
            .oldest_available = store->has_oldest_available
                                    ? store->oldest_available
                                    : (n00b_store_pos_t){},
        };
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_store_resume_check_t, check);
    }

    n00b_store_resume_check_t check = {
        .available        = false,
        .oldest_available = store->has_oldest_available
                                ? store->oldest_available
                                : (n00b_store_pos_t){},
    };
    if (!store->has_oldest_available
        || n00b_store_pos_compare(pos, store->oldest_available) < 0) {
        n00b_store_shard_t *hot = store->hot_shard;
        if (hot != nullptr
            && pos.shard_id == hot->shard_id
            && pos.ordinal < hot->record_count) {
            check.available = true;
        }
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_store_resume_check_t, check);
    }

    auto entry_opt = rocs_store_catalog_find_raw(store, pos.shard_id);
    if (n00b_option_is_set(entry_opt)) {
        n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
        check.available = entry != nullptr
                       && pos.ordinal < entry->record_count
                       && pos.generation == entry->generation;
    }
    else {
        n00b_store_shard_t *hot = store->hot_shard;
        check.available = hot != nullptr
                       && pos.shard_id == hot->shard_id
                       && pos.ordinal < hot->record_count;
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_store_resume_check_t, check);
}

static void
rocs_store_conduit_stats_record(n00b_store_conduit_ingest_t *adapter,
                                bool                         ok,
                                n00b_err_t                   err)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(adapter->lock);
    if (ok) {
        adapter->stats.committed++;
    }
    else {
        adapter->stats.failed++;
        adapter->stats.last_error = err;
    }
    n00b_data_unlock(adapter->lock);
}

static void
rocs_store_conduit_payload_cleanup(n00b_store_ingest_payload_t payload)
{
    if (n00b_variant_is_type(payload, n00b_buffer_t *)) {
        n00b_buffer_t *source = n00b_variant_get(payload, n00b_buffer_t *);
        if (source != nullptr) {
            n00b_buffer_free(source);
            n00b_free(source);
        }
    }
}

static void
rocs_store_conduit_worker(void *job_ptr, void *user_data)
{
    (void)user_data;

    rocs_store_conduit_job_t *job = job_ptr;
    if (job == nullptr || job->adapter == nullptr
        || job->adapter->store == nullptr) {
        if (job != nullptr) {
            rocs_store_conduit_payload_cleanup(job->payload);
            n00b_free(job);
        }
        return;
    }

    n00b_result_t(bool) ingest_r;
    if (n00b_variant_is_type(job->payload, n00b_json_node_t *)) {
        ingest_r = n00b_store_ingest(
            job->adapter->store,
            n00b_variant_get(job->payload, n00b_json_node_t *));
    }
    else if (n00b_variant_is_type(job->payload, n00b_buffer_t *)) {
        n00b_buffer_t *source = n00b_variant_get(job->payload, n00b_buffer_t *);
        if (job->adapter->source_decoder != nullptr) {
            ingest_r = rocs_store_ingest_buf_decoded(
                job->adapter->store,
                source,
                job->adapter->source_decoder);
        }
        else {
            ingest_r = n00b_store_ingest_buf(job->adapter->store, source);
        }
    }
    else {
        rocs_store_conduit_stats_record(job->adapter,
                                        false,
                                        N00B_STORE_ERR_ARG);
        rocs_store_conduit_payload_cleanup(job->payload);
        n00b_free(job);
        return;
    }

    if (n00b_result_is_ok(ingest_r)) {
        rocs_store_conduit_stats_record(job->adapter, true, N00B_STORE_OK);
    }
    else {
        rocs_store_conduit_stats_record(job->adapter,
                                        false,
                                        n00b_result_get_err(ingest_r));
    }
    rocs_store_conduit_payload_cleanup(job->payload);
    n00b_free(job);
}

static void
rocs_store_conduit_submit(n00b_store_conduit_ingest_t *adapter,
                          n00b_store_ingest_payload_t  payload)
{
    rocs_store_conduit_job_t *job = n00b_alloc(
        rocs_store_conduit_job_t,
        N00B_ALLOC_OPTS(adapter->allocator));
    job->adapter = adapter;
    job->payload = payload;

    n00b_worker_pool_submit(adapter->pool, job);

    n00b_data_write_lock(adapter->lock);
    adapter->stats.submitted++;
    n00b_data_unlock(adapter->lock);
}

static void
rocs_store_conduit_cancel_subscription(n00b_store_conduit_ingest_t *adapter)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(adapter->lock);
    n00b_conduit_sub_handle_t sub = adapter->sub;
    n00b_store_ingest_topic_t *topic = adapter->topic;
    adapter->sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    n00b_data_unlock(adapter->lock);

    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE || topic == nullptr) {
        return;
    }

    _n00b_list_write_lock(&topic->subscriptions);
    n00b_conduit_sub_cancel(sub);
    _n00b_list_unlock(&topic->subscriptions);
}

static void *
rocs_store_conduit_loop(void *arg)
{
    n00b_store_conduit_ingest_t *adapter = arg;
    if (adapter == nullptr || adapter->inbox == nullptr) {
        return nullptr;
    }

    while (true) {
        n00b_store_ingest_msg_t *msg =
            n00b_store_ingest_inbox_pop(adapter->inbox);
        if (msg != nullptr) {
            rocs_store_conduit_submit(adapter, msg->payload);
            n00b_free(msg);
            continue;
        }

        n00b_conduit_sys_msg_t *sys =
            n00b_conduit_inbox_pop_sys(adapter->inbox);
        if (sys != nullptr) {
            bool terminal =
                sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED
                || sys->header.type == N00B_CONDUIT_MSG_PUBLISHER_LOST;
            n00b_free(sys);
            if (terminal) {
                break;
            }
        }

        n00b_data_read_lock(adapter->lock);
        bool stop_requested = adapter->stop_requested;
        n00b_data_unlock(adapter->lock);
        if (stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)) {
            break;
        }

        n00b_condition_lock(&adapter->inbox->cv);
        n00b_data_read_lock(adapter->lock);
        stop_requested = adapter->stop_requested;
        n00b_data_unlock(adapter->lock);
        if (!stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)
            && !n00b_conduit_inbox_has_sys(adapter->inbox)) {
            n00b_condition_wait(&adapter->inbox->cv,
                                .timeout_ms  = 100,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&adapter->inbox->cv);
        }
    }

    rocs_store_conduit_cancel_subscription(adapter);

    n00b_worker_pool_quiesce(adapter->pool);
    n00b_worker_pool_shutdown(adapter->pool);

    n00b_data_write_lock(adapter->lock);
    adapter->closed = true;
    n00b_data_unlock(adapter->lock);
    return nullptr;
}

n00b_result_t(n00b_store_conduit_ingest_t *)
n00b_store_conduit_ingest_start(n00b_store_t               *store,
                                n00b_store_ingest_topic_t  *topic) _kargs
{
    int32_t           worker_count   = 0;
    int32_t           queue_capacity = 0;
    n00b_store_source_decoder_t source_decoder = nullptr;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (store == nullptr || topic == nullptr || worker_count < 0
        || queue_capacity < 0) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_ARG);
    }
    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    if (!n00b_conduit_topic_is_active(base) || base->conduit == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    int32_t workers = worker_count == 0 ? 1 : worker_count;
    int32_t cap     = queue_capacity == 0 ? workers : queue_capacity;
    if (workers <= 0 || cap <= 0) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_conduit_ingest_t *adapter = n00b_alloc_with_opts(
        n00b_store_conduit_ingest_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    adapter->store          = store;
    adapter->topic          = topic;
    adapter->sub            = N00B_CONDUIT_INVALID_SUB_HANDLE;
    adapter->lock           = n00b_data_lock_new(.allocator = allocator);
    adapter->allocator      = allocator;
    adapter->source_decoder = source_decoder;
    adapter->stats          = (n00b_store_conduit_ingest_stats_t){};
    adapter->stop_requested = false;
    adapter->closed         = false;
    adapter->joined         = false;

    adapter->inbox = n00b_alloc_with_opts(
        n00b_store_ingest_inbox_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    n00b_conduit_inbox_init(n00b_store_ingest_payload_t,
                            adapter->inbox,
                            base->conduit,
                            N00B_CONDUIT_BP_UNBOUNDED,
                            0);

    adapter->pool = n00b_worker_pool_new(workers,
                                         cap,
                                         rocs_store_conduit_worker,
                                         nullptr,
                                         .allocator = allocator);
    if (adapter->pool == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    adapter->sub = n00b_conduit_subscribe(n00b_store_ingest_payload_t,
                                          topic,
                                          adapter->inbox,
                                          .operations = N00B_CONDUIT_OP_ALL);
    if (adapter->sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_worker_pool_shutdown(adapter->pool);
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    auto thread_r = n00b_thread_spawn(rocs_store_conduit_loop, adapter);
    if (n00b_result_is_err(thread_r)) {
        n00b_conduit_sub_cancel(adapter->sub);
        n00b_worker_pool_shutdown(adapter->pool);
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }
    adapter->thread = n00b_result_get(thread_r);

    return n00b_result_ok(n00b_store_conduit_ingest_t *, adapter);
}

n00b_result_t(bool)
n00b_store_conduit_ingest_close(n00b_store_conduit_ingest_t *ingest)
{
    if (ingest == nullptr || ingest->lock == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(ingest->lock);
    if (ingest->joined) {
        n00b_data_unlock(ingest->lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    ingest->stop_requested = true;
    n00b_data_unlock(ingest->lock);

    rocs_store_conduit_cancel_subscription(ingest);

    if (ingest->inbox != nullptr) {
        n00b_condition_lock(&ingest->inbox->cv);
        n00b_condition_notify(&ingest->inbox->cv,
                              .all = true,
                              .auto_unlock = true);
    }
    if (ingest->thread != nullptr) {
        n00b_thread_join(ingest->thread);
    }

    n00b_data_write_lock(ingest->lock);
    ingest->closed = true;
    ingest->joined = true;
    n00b_data_unlock(ingest->lock);

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_conduit_ingest_stats(n00b_store_conduit_ingest_t *ingest)
{
    if (ingest == nullptr || ingest->lock == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_stats_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(ingest->lock);
    n00b_store_conduit_ingest_stats_t stats = ingest->stats;
    n00b_data_unlock(ingest->lock);
    stats.inbox_queued =
        ingest->inbox == nullptr
            ? 0
            : (uint64_t)n00b_store_ingest_inbox_msg_count(ingest->inbox);
    stats.worker_queued =
        ingest->pool == nullptr
            ? 0
            : (uint64_t)n00b_worker_pool_pending(ingest->pool);
    stats.worker_in_flight =
        ingest->pool == nullptr
            ? 0
            : (uint64_t)n00b_worker_pool_in_flight(ingest->pool);
    return n00b_result_ok(n00b_store_conduit_ingest_stats_t, stats);
}

static n00b_result_t(n00b_string_t *)
rocs_store_catalog_snapshot_copy_string(n00b_string_t *src) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (src == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    n00b_string_t *copy = n00b_unicode_str_copy(src,
                                                .allocator = allocator);
    if (copy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_string_t *, copy);
}

static n00b_result_t(n00b_store_catalog_snapshot_entry_t)
rocs_store_catalog_snapshot_copy_entry(n00b_store_catalog_entry_t *entry)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (entry == nullptr || entry->object_path == nullptr
        || entry->partition_key == nullptr) {
        return n00b_result_err(n00b_store_catalog_snapshot_entry_t,
                               N00B_STORE_ERR_STATE);
    }

    auto path_r = rocs_store_catalog_snapshot_copy_string(
        entry->object_path,
        .allocator = allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_store_catalog_snapshot_entry_t,
                               n00b_result_get_err(path_r));
    }

    auto part_r = rocs_store_catalog_snapshot_copy_string(
        entry->partition_key,
        .allocator = allocator);
    if (n00b_result_is_err(part_r)) {
        return n00b_result_err(n00b_store_catalog_snapshot_entry_t,
                               n00b_result_get_err(part_r));
    }

    n00b_option_t(n00b_string_t *) etag_copy =
        n00b_option_none(n00b_string_t *);
    if (entry->etag != nullptr) {
        auto etag_r = rocs_store_catalog_snapshot_copy_string(
            entry->etag,
            .allocator = allocator);
        if (n00b_result_is_err(etag_r)) {
            return n00b_result_err(n00b_store_catalog_snapshot_entry_t,
                                   n00b_result_get_err(etag_r));
        }
        etag_copy =
            n00b_option_set(n00b_string_t *, n00b_result_get(etag_r));
    }

    return n00b_result_ok(
        n00b_store_catalog_snapshot_entry_t,
        ((n00b_store_catalog_snapshot_entry_t){
            .shard_id          = entry->shard_id,
            .generation        = entry->generation,
            .schema_generation = entry->schema_generation,
            .record_count      = entry->record_count,
            .seal_ts           = entry->seal_ts,
            .partition_key     = n00b_result_get(part_r),
            .object_path       = n00b_result_get(path_r),
            .byte_len          = entry->byte_len,
            .etag              = etag_copy,
        }));
}

n00b_result_t(n00b_store_catalog_snapshot_t *)
n00b_store_catalog_visible_snapshot(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_catalog_snapshot_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_catalog_snapshot_t *snapshot =
        rocs_store_catalog_snapshot_list_new(.allocator = allocator);
    if (snapshot == nullptr) {
        return n00b_result_err(n00b_store_catalog_snapshot_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_catalog_snapshot_t *,
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        auto copied_r = rocs_store_catalog_snapshot_copy_entry(
            entry,
            .allocator = allocator);
        if (n00b_result_is_err(copied_r)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(n00b_store_catalog_snapshot_t *,
                                   n00b_result_get_err(copied_r));
        }

        n00b_list_push(*snapshot, n00b_result_get(copied_r));
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_store_catalog_snapshot_t *, snapshot);
}

n00b_result_t(n00b_store_tail_snapshot_t)
n00b_store_tail_snapshot(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_tail_snapshot_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_catalog_snapshot_t *sealed =
        rocs_store_catalog_snapshot_list_new(.allocator = allocator);
    if (sealed == nullptr) {
        return n00b_result_err(n00b_store_tail_snapshot_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_store_tail_snapshot_t snapshot = {
        .sealed = sealed,
    };

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_tail_snapshot_t,
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        auto copied_r = rocs_store_catalog_snapshot_copy_entry(
            entry,
            .allocator = allocator);
        if (n00b_result_is_err(copied_r)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(n00b_store_tail_snapshot_t,
                                   n00b_result_get_err(copied_r));
        }

        n00b_list_push(*sealed, n00b_result_get(copied_r));
    }

    if (store->hot_shard != nullptr && store->hot_shard->record_count != 0) {
        snapshot.has_hot_through = true;
        snapshot.hot_through = (n00b_store_pos_t){
            .generation = store->generation,
            .shard_id   = store->hot_shard->shard_id,
            .ordinal    = store->hot_shard->record_count - 1,
        };
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_store_tail_snapshot_t, snapshot);
}

n00b_result_t(uint64_t)
n00b_store_catalog_get_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    uint64_t count = (uint64_t)n00b_list_len(*store->catalog);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(uint64_t)
n00b_store_catalog_visible_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }
    if (store->borrowed_catalog_enumeration_disabled) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t count = (uint64_t)n00b_list_len(*store->catalog);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_visible_entry_at(n00b_store_t *store, uint64_t index)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }
    if (store->borrowed_catalog_enumeration_disabled) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                              n00b_option_none(n00b_store_catalog_entry_t *));
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    if (entry == nullptr) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                          n00b_option_set(n00b_store_catalog_entry_t *,
                                          entry));
}

n00b_result_t(bool)
n00b_store_catalog_test_set_borrowed_enumeration_disabled(
    n00b_store_t *store,
    bool          disabled)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    store->borrowed_catalog_enumeration_disabled = disabled;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_shard(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                          rocs_store_catalog_find_raw(store, shard_id));
}

n00b_result_t(bool)
n00b_store_catalog_entry_verify_object(n00b_store_t              *store,
                                       n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    auto stat_r = n00b_vfs_stat(store->vfs, entry->object_path);
    if (n00b_result_is_err(stat_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != entry->byte_len) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_shard_id(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->shard_id);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_generation(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->generation);
}

n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_object_path(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_string_t *, entry->object_path);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_byte_len(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->byte_len);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_record_count(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->record_count);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_schema_generation(
    n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->schema_generation);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_seal_ts(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->seal_ts);
}

n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_partition_key(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->partition_key == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_string_t *, entry->partition_key);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_catalog_entry_get_etag(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }
    if (entry->etag == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, entry->etag));
}

n00b_result_t(bool)
n00b_store_catalog_entry_is_resident(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_store_t *store = entry->owner;
    if (store != nullptr) {
        n00b_data_read_lock(store->residency_lock);
    }
    bool resident = entry->resident_map != nullptr;
    if (store != nullptr) {
        n00b_data_unlock(store->residency_lock);
    }
    return n00b_result_ok(bool, resident);
}

n00b_result_t(n00b_store_resident_shard_t *)
n00b_store_resident_shard_acquire(n00b_store_t               *store,
                                  n00b_store_catalog_entry_t *entry) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || entry == nullptr) {
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_STATE);
    }
    if (!rocs_store_catalog_owns_entry(store, entry)) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->active_pins == UINT64_MAX
        || entry->resident_pins == UINT64_MAX) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_STATE);
    }

    auto map_r = rocs_store_resident_load_entry(store, entry);
    if (n00b_result_is_err(map_r)) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               n00b_result_get_err(map_r));
    }

    n00b_store_resident_shard_t *resident = n00b_alloc_with_opts(
        n00b_store_resident_shard_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    resident->store    = store;
    resident->entry    = entry;
    resident->released = false;
    entry->resident_pins++;
    store->active_pins++;
    n00b_data_unlock(store->residency_lock);

    return n00b_result_ok(n00b_store_resident_shard_t *, resident);
}

n00b_result_t(n00b_store_map_t *)
n00b_store_resident_shard_map(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr || resident->entry == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    n00b_store_t *store = resident->store;
    if (store == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (resident->released || resident->entry->resident_map == nullptr) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }
    resident->entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
    n00b_store_map_t *map = resident->entry->resident_map;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(n00b_store_map_t *, map);
}

n00b_result_t(bool)
n00b_store_resident_shard_release(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr || resident->store == nullptr
        || resident->entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(resident->store->residency_lock);
    if (resident->released) {
        n00b_data_unlock(resident->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (resident->entry->resident_pins == 0
        || resident->store->active_pins == 0) {
        n00b_data_unlock(resident->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    resident->entry->resident_pins--;
    resident->store->active_pins--;
    resident->released = true;
    rocs_store_retired_hot_allocator_list_t *retired =
        rocs_store_detach_retired_hot_allocators_locked(resident->store);
    n00b_data_unlock(resident->store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(resident->store, retired);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_bytes(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->residency_lock);
    uint64_t resident_bytes = store->resident_bytes;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_bytes);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_shard_count(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->residency_lock);
    uint64_t resident_shards = store->resident_shards;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_shards);
}

n00b_result_t(n00b_store_residency_stats_t)
n00b_store_residency_stats(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_residency_stats_t,
                               N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->residency_lock);
    n00b_store_residency_stats_t stats = {
        .resident_bytes = store->resident_bytes,
        .resident_shards = store->resident_shards,
        .active_pins = store->active_pins,
        .retired_hot_allocators =
            store->retired_hot_allocators == nullptr
                ? 0
                : (uint64_t)n00b_list_len(*store->retired_hot_allocators),
        .cache_hits = store->resident_cache_hits,
        .cache_misses = store->resident_cache_misses,
        .unloads = store->resident_unloads,
        .unload_bytes = store->resident_unload_bytes,
    };
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(n00b_store_residency_stats_t, stats);
}

n00b_result_t(n00b_store_memory_stats_t)
n00b_store_memory_stats(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_memory_stats_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_memory_stats_t stats = {};

    n00b_data_read_lock(store->commit_lock);
    n00b_store_shard_t *hot = store->hot_shard;
    if (hot != nullptr) {
        stats.hot_shard_id      = hot->shard_id;
        stats.hot_record_count  = hot->record_count;
        stats.hot_byte_estimate = hot->byte_estimate;
        if (hot->raw_bytes != nullptr) {
            stats.hot_raw_bytes = hot->raw_bytes->byte_len;
        }
        if (hot->columns != nullptr) {
            stats.hot_column_count = n00b_dict_internal_len(
                (_n00b_dict_internal_t *)hot->columns);
        }
        if (hot->records != nullptr) {
            size_t len = n00b_list_len(*hot->records);
            for (size_t i = 0; i < len; i++) {
                n00b_string_t *text = n00b_list_get(*hot->records, i);
                if (text != nullptr) {
                    stats.hot_record_text_bytes += (uint64_t)text->u8_bytes;
                }
            }
        }
    }
    rocs_store_hot_allocator_memory_stats(store->hot_allocator, &stats);
    stats.hot_destroy_count = store->hot_destroy_count;
    stats.hot_destroy_records = store->hot_destroy_records;
    stats.hot_destroy_last_pool_mapped_bytes =
        store->hot_destroy_last_pool_mapped_bytes;
    stats.hot_destroy_last_pool_pages =
        store->hot_destroy_last_pool_pages;
    stats.hot_destroy_last_pool_big_maps =
        store->hot_destroy_last_pool_big_maps;
    stats.hot_destroy_last_pool_big_unmaps =
        store->hot_destroy_last_pool_big_unmaps;
    stats.hot_destroy_last_arena_used_bytes =
        store->hot_destroy_last_arena_used_bytes;
    stats.hot_destroy_last_arena_size_bytes =
        store->hot_destroy_last_arena_size_bytes;
    stats.hot_destroy_total_pool_mapped_bytes =
        store->hot_destroy_total_pool_mapped_bytes;
    stats.hot_destroy_total_pool_pages =
        store->hot_destroy_total_pool_pages;
    stats.hot_destroy_total_arena_size_bytes =
        store->hot_destroy_total_arena_size_bytes;
    stats.hot_destroy_registry_pool_bytes_before =
        store->hot_destroy_registry_pool_bytes_before;
    stats.hot_destroy_registry_pool_bytes_after =
        store->hot_destroy_registry_pool_bytes_after;
    stats.hot_destroy_registry_pool_unmapped_bytes =
        store->hot_destroy_registry_pool_unmapped_bytes;
    stats.hot_destroy_registry_managed_unmapped_bytes =
        store->hot_destroy_registry_managed_unmapped_bytes;

    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        stats.catalog_entries = (uint64_t)len;
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry == nullptr) {
                continue;
            }
            if (entry->object_path != nullptr) {
                stats.catalog_object_path_bytes +=
                    (uint64_t)entry->object_path->u8_bytes;
            }
            if (entry->partition_key != nullptr) {
                stats.catalog_partition_key_bytes +=
                    (uint64_t)entry->partition_key->u8_bytes;
            }
            if (entry->etag != nullptr) {
                stats.catalog_etag_bytes +=
                    (uint64_t)entry->etag->u8_bytes;
            }
            stats.sealed_shards++;
            stats.sealed_records += entry->record_count;
            stats.sealed_bytes += entry->byte_len;
            if (stats.sealed_min_bytes == 0
                || entry->byte_len < stats.sealed_min_bytes) {
                stats.sealed_min_bytes = entry->byte_len;
            }
            if (entry->byte_len > stats.sealed_max_bytes) {
                stats.sealed_max_bytes = entry->byte_len;
            }
            if (entry->byte_len <= 64ull * 1024ull) {
                stats.sealed_shards_le_64k++;
            }
            if (entry->byte_len <= 256ull * 1024ull) {
                stats.sealed_shards_le_256k++;
            }
            if (entry->byte_len <= 1024ull * 1024ull) {
                stats.sealed_shards_le_1m++;
            }
        }
    }
    stats.catalog_generation = store->generation;
    stats.catalog_string_bytes = stats.catalog_object_path_bytes
                                 + stats.catalog_partition_key_bytes
                                 + stats.catalog_etag_bytes;
    if (stats.sealed_shards != 0) {
        stats.sealed_avg_bytes = stats.sealed_bytes / stats.sealed_shards;
        stats.sealed_avg_records = stats.sealed_records / stats.sealed_shards;
    }

    n00b_data_read_lock(store->residency_lock);
    stats.resident_bytes       = store->resident_bytes;
    stats.resident_shards      = store->resident_shards;
    stats.active_pins          = store->active_pins;
    stats.resident_cache_hits  = store->resident_cache_hits;
    stats.resident_cache_misses = store->resident_cache_misses;
    stats.resident_unloads     = store->resident_unloads;
    stats.resident_unload_bytes = store->resident_unload_bytes;
    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry == nullptr || entry->resident_map == nullptr) {
                continue;
            }
            auto map_stats_r =
                n00b_store_map_memory_stats(entry->resident_map);
            if (n00b_result_is_err(map_stats_r)) {
                stats.resident_unknown_shards++;
                continue;
            }
            n00b_store_map_memory_stats_t map_stats =
                n00b_result_get(map_stats_r);
            stats.resident_mapped_bytes += map_stats.mapped_bytes;
            if (map_stats.local_mmap) {
                stats.resident_local_mmap_shards++;
            } else if (map_stats.copy_mmap) {
                stats.resident_copy_mmap_shards++;
            } else if (map_stats.pinned_buffer) {
                stats.resident_buffer_shards++;
            } else {
                stats.resident_unknown_shards++;
            }
        }
    }

    if (store->retired_hot_allocators != nullptr) {
        size_t len = n00b_list_len(*store->retired_hot_allocators);
        stats.retired_hot_allocators = (uint64_t)len;
        for (size_t i = 0; i < len; i++) {
            rocs_store_retired_hot_allocator_t *retired =
                n00b_list_get(*store->retired_hot_allocators, i);
            if (retired != nullptr) {
                stats.retired_hot_records += retired->record_count;
            }
        }
    }
    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);

    return n00b_result_ok(n00b_store_memory_stats_t, stats);
}

n00b_result_t(uint64_t)
n00b_store_residency_trim(n00b_store_t *store) _kargs
{
    uint64_t target_resident_bytes = 0;
}
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t target_bytes = target_resident_bytes;
    if (target_bytes == 0 && store->residency_policy.max_resident_bytes != 0) {
        target_bytes = store->residency_policy.max_resident_bytes;
    }
    uint64_t target_shards = store->residency_policy.max_resident_shards;
    uint64_t released      = 0;
    uint64_t now_ns        = (uint64_t)n00b_ns_timestamp();

    while (true) {
        bool bytes_over =
            target_bytes != 0 && store->resident_bytes > target_bytes;
        bool shards_over =
            target_shards != 0 && store->resident_shards > target_shards;
        n00b_store_catalog_entry_t *victim =
            rocs_store_oldest_unpinned_resident(store, now_ns);

        bool idle_victim = victim != nullptr
                        && store->residency_policy.idle_ns != 0
                        && victim->last_access_ns != 0
                        && now_ns >= victim->last_access_ns
                        && now_ns - victim->last_access_ns
                               >= store->residency_policy.idle_ns;
        if (!bytes_over && !shards_over && !idle_victim) {
            break;
        }
        if (victim == nullptr) {
            break;
        }

        uint64_t len = victim->byte_len;
        auto unload_r = rocs_store_resident_unload_entry(store, victim);
        if (n00b_result_is_err(unload_r)) {
            n00b_data_unlock(store->residency_lock);
            return n00b_result_err(uint64_t, n00b_result_get_err(unload_r));
        }
        if (n00b_result_get(unload_r)) {
            released += len;
        }
    }

    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, released);
}

n00b_result_t(n00b_string_t *)
n00b_store_pos_encode(n00b_store_pos_t pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    static const char hex_digits[] = "0123456789abcdef";
    char              token_bytes[48];
    uint64_t          words[3] = {
        pos.generation,
        pos.shard_id,
        pos.ordinal,
    };

    uint64_t out = 0;
    for (uint64_t w = 0; w < 3; w++) {
        for (uint8_t i = 0; i < 8; i++) {
            uint8_t byte =
                (uint8_t)((words[w] >> (56 - (i * 8))) & UINT64_C(0xff));
            token_bytes[out++] = hex_digits[byte >> 4];
            token_bytes[out++] = hex_digits[byte & 0x0f];
        }
    }

    n00b_string_t *token = n00b_string_from_raw(token_bytes,
                                                48,
                                                .allocator = allocator);
    if (token == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_string_t *, token);
}

static n00b_result_t(uint8_t)
rocs_store_hex_nibble(uint8_t byte)
{
    if (byte >= '0' && byte <= '9') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - '0'));
    }
    if (byte >= 'a' && byte <= 'f') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - 'a' + 10));
    }
    if (byte >= 'A' && byte <= 'F') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - 'A' + 10));
    }
    return n00b_result_err(uint8_t, N00B_STORE_ERR_ARG);
}

static n00b_result_t(uint64_t)
rocs_store_pos_decode_u64(n00b_string_t *token, uint64_t start)
{
    uint64_t value = 0;
    for (uint64_t i = 0; i < 16; i++) {
        auto nibble_r = rocs_store_hex_nibble(
            (uint8_t)token->data[start + i]);
        if (n00b_result_is_err(nibble_r)) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
        }
        value = (value << 4) | n00b_result_get(nibble_r);
    }
    return n00b_result_ok(uint64_t, value);
}

n00b_result_t(n00b_store_pos_t)
n00b_store_pos_decode(n00b_string_t *token)
{
    if (token == nullptr || token->data == nullptr || token->u8_bytes != 48) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    auto generation_r = rocs_store_pos_decode_u64(token, 0);
    auto shard_r      = rocs_store_pos_decode_u64(token, 16);
    auto ordinal_r    = rocs_store_pos_decode_u64(token, 32);
    if (n00b_result_is_err(generation_r) || n00b_result_is_err(shard_r)
        || n00b_result_is_err(ordinal_r)) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_pos_t,
                          ((n00b_store_pos_t){
                              .shard_id   = n00b_result_get(shard_r),
                              .ordinal    = n00b_result_get(ordinal_r),
                              .generation = n00b_result_get(generation_r),
                          }));
}

int32_t
n00b_store_pos_compare(n00b_store_pos_t a, n00b_store_pos_t b)
{
    if (a.generation != b.generation) {
        return a.generation < b.generation ? -1 : 1;
    }
    if (a.shard_id != b.shard_id) {
        return a.shard_id < b.shard_id ? -1 : 1;
    }
    if (a.ordinal != b.ordinal) {
        return a.ordinal < b.ordinal ? -1 : 1;
    }
    return 0;
}

n00b_result_t(n00b_store_pin_t *)
n00b_store_pin_acquire(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins == UINT64_MAX) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }

    n00b_store_pin_t *pin = n00b_alloc_with_opts(
        n00b_store_pin_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    pin->store    = store;
    pin->released = false;
    store->active_pins++;
    n00b_data_unlock(store->residency_lock);

    return n00b_result_ok(n00b_store_pin_t *, pin);
}

n00b_result_t(bool)
n00b_store_pin_release(n00b_store_pin_t *pin)
{
    if (pin == nullptr || pin->store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    n00b_data_write_lock(pin->store->residency_lock);
    if (pin->released) {
        n00b_data_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (pin->store->active_pins == 0) {
        n00b_data_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    pin->store->active_pins--;
    pin->released = true;
    rocs_store_retired_hot_allocator_list_t *retired =
        rocs_store_detach_retired_hot_allocators_locked(pin->store);
    n00b_data_unlock(pin->store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(pin->store, retired);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_active_pins(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->residency_lock);
    uint64_t active_pins = store->active_pins;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, active_pins);
}
