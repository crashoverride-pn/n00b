#include "rocs/store.h"

#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_s3.h"
#include "conduit/conduit.h"
#include "conduit/print.h"
#include "core/atomic.h"
#include "core/mem/pinref.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/env.h"
#include "core/gc.h"
#include "core/hash.h"
#include "core/mmaps.h"
#include "core/mutex.h"
#include "core/platform.h"
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
#include "text/unicode/casemap.h"
#include "util/parse_num.h"
#include "util/worker_pool.h"
#include "vfs/backend_local.h"
#include "vfs/backend_memory.h"
#include "vfs/backend.h"
#include "vfs/cache.h"
#include "vfs/vfs.h"

#include <stddef.h>
#include <string.h>

typedef n00b_list_t(n00b_store_field_t *) rocs_store_field_list_t;
typedef n00b_list_t(n00b_store_catalog_entry_t *)
    rocs_store_catalog_list_t;
typedef n00b_list_t(n00b_store_pin_t *)
    rocs_store_pin_list_t;
typedef n00b_list_t(n00b_store_record_stream_t *)
    rocs_store_record_stream_list_t;
typedef n00b_list_t(n00b_store_posting_list_t *)
    rocs_store_posting_target_list_t;
typedef struct rocs_store_batch_term rocs_store_batch_term_t;
typedef n00b_list_t(rocs_store_batch_term_t)
    rocs_store_batch_term_list_t;
typedef struct rocs_store_retired_hot_allocator
    rocs_store_retired_hot_allocator_t;
typedef n00b_list_t(rocs_store_retired_hot_allocator_t *)
    rocs_store_retired_hot_allocator_list_t;
typedef struct rocs_store_seal_job rocs_store_seal_job_t;
typedef n00b_list_t(rocs_store_seal_job_t *)
    rocs_store_seal_job_list_t;
typedef struct rocs_store_seal_queue rocs_store_seal_queue_t;

static bool rocs_store_root_valid(n00b_string_t *root);
static void rocs_store_hot_visibility_reset(n00b_store_t *store);
static n00b_result_t(bool)
rocs_store_append_text_literal_to_column(rocs_store_batch_term_list_t *out,
                                         n00b_string_t                *column,
                                         n00b_string_t                *term,
                                         n00b_allocator_t             *allocator);
static n00b_result_t(bool)
rocs_store_ingest_common(n00b_store_t     *store,
                         n00b_json_node_t *record,
                         n00b_buffer_t    *raw,
                         bool              index_enabled,
                         n00b_allocator_t *allocator);

N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_commit_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_commit_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_ingest_payload_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_ingest_payload_t);


#define ROCS_STORE_CATALOG_MAGIC_LEN 8
#define ROCS_STORE_CATALOG_VERSION   3
#define ROCS_STORE_CATALOG_VERSION_MIN 1

#define ROCS_STORE_CONFIG_DEFAULT_CACHE_BYTES    (256ull * 1024ull * 1024ull)
#define ROCS_STORE_CONFIG_DEFAULT_RESIDENT_BYTES (64ull * 1024ull * 1024ull)
#define ROCS_STORE_CONFIG_DEFAULT_RESIDENT_SHARDS 64ull
#define ROCS_STORE_CGROUP_CACHE_DIVISOR          4ull
#define ROCS_STORE_CGROUP_RESIDENT_DIVISOR       8ull

/* No-AWS fallback stubs. These satisfy the n00b_aws_config /
 * n00b_aws_s3_vfs_backend_new references below when libn00b is built WITHOUT
 * the AWS substrate (enable_aws=false), so rocs links standalone.
 *
 * They MUST NOT be compiled when AWS is enabled: ncc emits the real `_kargs`
 * implementations (in libn00b_aws) as weak symbols, and these stubs are weak
 * too, so a weak-vs-weak collision lets the linker bind the symbol to
 * whichever it sees first by archive order -- which silently linked this
 * always-fails stub into AWS-enabled binaries (e.g. test_aws_s3_contract).
 * The meson `enable_aws` path defines N00B_BUILD_AWS precisely to drop these,
 * leaving the symbol undefined in core libn00b so the linker is forced to pull
 * the real impl from libn00b_aws. */
#ifndef N00B_BUILD_AWS
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
#endif /* N00B_BUILD_AWS */

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
    // Reserved full-text catch-all column enabled (N00B_STORE_SEARCH_TEXT_COLUMN):
    // ingest tokenizes every string in the record into it (index-only); an
    // unqualified query resolves to it.
    bool                          search_text;
    n00b_store_search_text_hook_t search_text_hook;
    void                         *search_text_hook_ctx;
    n00b_store_index_options_t   *index_options;
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
    uint64_t       max_total_sealed_bytes;
    uint64_t       drop_before_seal_ts;
    uint64_t       min_seal_ts;
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

typedef enum {
    ROCS_STORE_CATALOG_ENTRY_SEALED = 1,
    ROCS_STORE_CATALOG_ENTRY_RETIRED_HOT = 2,
    ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL = 3,
    ROCS_STORE_CATALOG_ENTRY_QUARANTINED = 4,
} rocs_store_catalog_entry_state_t;

struct n00b_store_catalog_entry_t {
    n00b_store_t  *owner;
    rocs_store_catalog_entry_state_t state;
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
    // Reader pin count on this sealed shard's resident mmap. Atomic so readers
    // pin/unpin lock-free (a pin, not a mutex); the unload path refuses to
    // munmap while this is non-zero, so a held pin keeps the mapping alive.
    _Atomic(uint64_t) resident_pins;
    uint64_t       last_access_ns;
    n00b_allocator_t *retired_hot_allocator;
    uint64_t       retired_hot_generation;
    uint64_t       retired_hot_record_count;
    n00b_store_shard_t *failed_seal_shard;
    n00b_allocator_t   *failed_seal_allocator;
    uint64_t            failed_seal_byte_estimate;
    uint32_t            failed_seal_base_address;
    n00b_err_t          failed_seal_last_error;
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
    // Reader-pin/writer-drain gate for lock-free snapshot hot-shard reads.
    // Placed third on purpose: two 8-byte pointers precede it, so its offset is
    // 16 -- the 128-bit _Atomic pin cell is naturally 16-byte aligned here with
    // zero padding. A reader pins it across its hot-arena access; the
    // seal/retire path locks it (draining readers) before munmapping the arena.
    n00b_pinref_t                  hot_pin;
    n00b_string_t                 *display_name;
    n00b_store_schema_t           *schema;
    n00b_store_partition_policy_t *partition_policy;
    n00b_store_retain_policy_t    *retain_policy;
    n00b_store_seal_policy_t      *seal_policy;
    n00b_store_residency_policy_t  residency_policy;
    // Default whole-shard retention applied by the sealer after each commit
    // (see rocs_store_apply_default_retention). Set at open from the
    // n00b_store_open_vfs kwargs. window 0 disables the age rule; maxshards 0
    // disables the count cap.
    uint64_t                       retention_window_ns;
    uint64_t                       retention_max_sealed_shards;
    uint64_t                       retention_max_total_bytes;
    n00b_vfs_cache_t              *cache;
    n00b_store_commit_topic_t     *commit_topic;
    n00b_store_lifecycle_topic_t  *lifecycle_topic;
    n00b_store_shard_t            *hot_shard;
    n00b_allocator_t              *hot_allocator;
    n00b_string_t                 *hot_partition_key;
    rocs_store_catalog_list_t     *catalog;
    n00b_allocator_t              *allocator;
    n00b_mutex_t                  *residency_lock;
    n00b_mutex_t                  *commit_lock;
    n00b_mutex_t                  *rotation_lock;
    // Async-seal machinery (opt-in via keep_standby at open; off => seal_queue
    // is null and every seal runs inline exactly as before). The single dequeuer
    // / ingest owner rotates the hot shard with a plain pointer swap and appends
    // the detached old shard to a non-lossy seal worklist; seal worker threads
    // marshal it lock-free (they exclusively own the detached shard), then take
    // commit_lock only to commit the catalog entry, retire the old allocator, and
    // replenish the standby. standby_shard/standby_allocator are a pristine,
    // never-written spare shard guarded by commit_lock (consumed at rotate,
    // replenished by the seal worker) so rotation never has to allocate on the
    // hot path.
    rocs_store_seal_queue_t       *seal_queue;
    int32_t                        seal_worker_count;
    bool                           keep_standby;
    n00b_store_shard_t            *standby_shard;
    n00b_allocator_t              *standby_allocator;
    n00b_store_service_profile_t  *service_profile;
    n00b_conduit_t                *service_conduit;
    n00b_store_ingest_topic_t     *service_ingest_topic;
    n00b_store_conduit_ingest_t   *service_ingest;
    n00b_store_state_t             state;
    bool                           read_only;
    bool                           recovery_journal;
    bool                           recovering;
    n00b_vfs_fh_t                  journal_fh;
    uint64_t                       journal_shard_id;
    n00b_string_t                 *journal_path;
    uint64_t                       journal_unsynced;
    uint64_t                       next_shard_id;
    uint64_t                       generation;
    uint64_t                       schema_generation;
    n00b_store_pos_t               oldest_available;
    bool                           has_oldest_available;
    // Process-side hot visibility boundary. Rows below this ordinal are fully
    // appended and indexed; future worker fan-out may reserve beyond it, but
    // search/egress/health must not expose those holes.
    _Atomic(uint64_t)              hot_live_index;
    n00b_flagset_t                 *hot_ready;
    _Atomic(uint64_t)              hot_active_writers;
    _Atomic(uint64_t)              hot_writer_reservations;
    _Atomic(uint64_t)              hot_writer_completions;
    _Atomic(uint64_t)              hot_ready_out_of_order_publications;
    _Atomic(uint64_t)              hot_worker_range_commits;
    _Atomic(uint64_t)              hot_worker_range_tombstones;
    _Atomic(uint64_t)              seal_active_writer_waits;
    // Aggregate reader pin count across the store (sealed-shard acquires, record
    // streams, and store pins). Atomic: readers pin/unpin lock-free. A non-zero
    // value blocks store teardown / retired-hot reclaim that would pull storage.
    _Atomic(uint64_t)              active_pins;
    rocs_store_pin_list_t          *active_pin_handles;
    rocs_store_record_stream_list_t *active_record_streams;
    // Streams that borrowed hot-row string spans; blocks retired-hot arena
    // reclaim until drained. Atomic so stream open/close touch it lock-free.
    _Atomic(uint64_t)              hot_snapshot_pins;
    uint64_t                       resident_bytes;
    uint64_t                       resident_shards;
    // Atomic: cache_hits is incremented on the lock-free acquire fast path
    // (already-resident pin) as well as the residency_lock-held load path, so
    // both counters are read/written without a common lock. misses is a pair.
    _Atomic(uint64_t)              resident_cache_hits;
    _Atomic(uint64_t)              resident_cache_misses;
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
    n00b_allocator_t *allocator;
    n00b_store_shard_id_list_t *shard_ids;
    bool          all_shards;
    bool          released;
};

struct n00b_store_resident_shard_t {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *entry;
    bool                        released;
};

typedef struct {
    n00b_store_catalog_entry_t *entry;
    uint64_t                    generation;
    uint64_t                    shard_id;
    uint64_t                    record_count;
    uint64_t                    start_ordinal;
    uint64_t                    seal_ts;
} rocs_stream_catalog_snapshot_t;

struct n00b_store_record_stream_t {
    n00b_store_t                    *store;
    n00b_allocator_t                *allocator;
    bool                             closed;
    bool                             pinned;
    n00b_store_shard_id_list_t       *sealed_shard_ids;
    rocs_stream_catalog_snapshot_t  *sealed;
    uint64_t                         sealed_count;
    uint64_t                         sealed_index;
    uint64_t                         sealed_ordinal;
    n00b_store_resident_shard_t     *resident;
    n00b_store_map_shard_t          *root;
    uint64_t                         resident_index;
    n00b_store_pos_t                 hot_base;
    n00b_string_t                  **hot_records;
    uint64_t                         hot_count;
    uint64_t                         hot_ordinal;
    bool                             hot_snapshot_pinned;
};

#define ROCS_STORE_CONTRACT_OPEN(_store) \
    ((_store) != nullptr && (_store)->state == N00B_STORE_STATE_OPEN)

#define ROCS_STORE_CONTRACT_CATALOG_OWNED(_store) \
    (ROCS_STORE_CONTRACT_OPEN(_store) && (_store)->catalog != nullptr)

#define ROCS_STORE_CATALOG_ENTRY_CONTRACT_VISIBLE(_entry) \
    ((_entry) != nullptr && (_entry)->owner != nullptr     \
     && (_entry)->state == ROCS_STORE_CATALOG_ENTRY_SEALED \
     && (_entry)->object_path != nullptr                   \
     && (_entry)->partition_key != nullptr)

#define ROCS_STORE_PIN_CONTRACT_LIVE(_pin) \
    ((_pin) != nullptr && !(_pin)->released && (_pin)->store != nullptr)

#define ROCS_STORE_RESIDENT_CONTRACT_PINNED(_resident) \
    ((_resident) != nullptr && !(_resident)->released   \
     && (_resident)->store != nullptr                   \
     && (_resident)->entry != nullptr)

#define ROCS_STORE_RECORD_STREAM_CONTRACT_OPEN(_stream) \
    ((_stream) != nullptr && !(_stream)->closed          \
     && (_stream)->store != nullptr)

#define ROCS_STORE_RECORD_STREAM_CONTRACT_PINNED(_stream) \
    (ROCS_STORE_RECORD_STREAM_CONTRACT_OPEN(_stream)       \
     && (_stream)->pinned)

struct n00b_store_index_emit_t {
    rocs_store_batch_term_list_t *out;
    n00b_allocator_t            *owner_allocator;
    bool                         live;
    bool                         copied_term;
};

#define N00B_STORE_INDEX_EMIT_CONTRACT_LIVE(_emit) \
    ((_emit) != nullptr && (_emit)->live && (_emit)->out != nullptr)

#define N00B_STORE_INDEX_EMIT_CONTRACT_COPIED(_emit) \
    (N00B_STORE_INDEX_EMIT_CONTRACT_LIVE(_emit) && (_emit)->copied_term)

#define ROCS_STORE_RECORD_STREAM_ITEM_CONTRACT_VALID(_item)          \
    ((_item).pos.shard_id != 0                                       \
     && ((_item).bytes.byte_len == 0 || (_item).bytes.data != nullptr))

#define ROCS_STORE_RECORD_STREAM_NEXT_CONTRACT_VALID_OR_EOF(_result) \
    (n00b_result_is_err(_result)                                     \
     || !n00b_option_is_set(n00b_result_value(_result))              \
     || ROCS_STORE_RECORD_STREAM_ITEM_CONTRACT_VALID(                \
         n00b_result_value(_result).value))

struct rocs_store_batch_term {
    n00b_string_t                *field;
    n00b_uint128_t                key;
    n00b_store_postings_kind_t    postings;
};

typedef struct {
    n00b_store_t                   *store;
    n00b_json_node_t               *input_record;
    n00b_buffer_t                  *source;
    n00b_store_source_decoder_t     source_decoder;
    n00b_allocator_t               *allocator;
    bool                            index_enabled;
    n00b_json_node_t               *record;
    n00b_buffer_t                  *raw;
    n00b_string_t                  *route;
    rocs_store_batch_term_list_t   *terms;
    n00b_err_t                      err;
} rocs_store_batch_job_t;

typedef struct {
    n00b_store_t                 *store;
    n00b_store_shard_t           *hot;
    rocs_store_batch_job_t       *batch_job;
    n00b_store_raw_span_t        *raw_span;
    n00b_store_shard_prepared_slot_t *prepared;
    rocs_store_posting_target_list_t *targets;
    uint64_t                      byte_delta;
    bool                          tombstone;
    n00b_err_t                    err;
} rocs_store_range_commit_job_t;

typedef struct {
    n00b_condition_t  cv;
    uint64_t          remaining;
} rocs_store_batch_worker_latch_t;

typedef struct {
    n00b_worker_fn_t                  fn;
    void                             *job;
    void                             *user_data;
    rocs_store_batch_worker_latch_t  *latch;
} rocs_store_service_worker_item_t;

static void rocs_store_batch_prepare_job(rocs_store_batch_job_t *job);

static void
rocs_store_service_pool_worker(void *item_v, void *user_data)
{
    (void)user_data;
    rocs_store_service_worker_item_t *item = item_v;
    if (item == nullptr) {
        return;
    }

    if (item->fn != nullptr) {
        item->fn(item->job, item->user_data);
    }

    rocs_store_batch_worker_latch_t *latch = item->latch;
    if (latch != nullptr) {
        n00b_condition_lock(&latch->cv);
        if (latch->remaining != 0) {
            latch->remaining--;
        }
        if (latch->remaining == 0) {
            n00b_condition_notify(&latch->cv,
                                  .all = true,
                                  .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&latch->cv);
        }
    }
}

static n00b_err_t
rocs_store_run_service_worker_jobs(n00b_worker_pool_t *pool,
                                   n00b_worker_fn_t    fn,
                                   void *const        *jobs,
                                   uint64_t            count,
                                   void               *user_data,
                                   n00b_allocator_t   *allocator)
{
    if (pool == nullptr || fn == nullptr || jobs == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    if (count == 0) {
        return N00B_STORE_OK;
    }

    rocs_store_service_worker_item_t *items = n00b_alloc_array(
        rocs_store_service_worker_item_t,
        (int64_t)count,
        .allocator = allocator,
        .scan_kind = N00B_GC_SCAN_KIND_ALL);
    if (items == nullptr) {
        return N00B_STORE_ERR_INTERNAL;
    }

    rocs_store_batch_worker_latch_t latch = {};
    n00b_condition_init(&latch.cv);
    latch.remaining = count;

    for (uint64_t i = 0; i < count; i++) {
        items[i].fn        = fn;
        items[i].job       = jobs[i];
        items[i].user_data = user_data;
        items[i].latch     = &latch;
        n00b_worker_pool_submit(pool, &items[i]);
    }

    n00b_condition_lock(&latch.cv);
    while (latch.remaining != 0) {
        n00b_condition_wait(&latch.cv);
    }
    n00b_condition_unlock(&latch.cv);
    n00b_condition_destroy(&latch.cv);

    return N00B_STORE_OK;
}

static void
rocs_store_batch_prepare_worker(void *job_v, void *user_data)
{
    (void)user_data;
    rocs_store_batch_job_t *job = job_v;
    if (job == nullptr) {
        return;
    }
    bool prev_ingest = n00b_gc_attrib_enter_ingest();
    if (job->allocator == nullptr) {
        // Per-worker-arena mode: the worker pool has already installed this
        // thread's persistent bump-arena scratch as current_allocator, and the
        // batch owner resets every worker arena at the batch boundary (once all
        // jobs are joined). Allocate straight from the thread's current
        // allocator -- no per-job set/restore, no per-job pool churn.
        rocs_store_batch_prepare_job(job);
    }
    else {
        // Explicit-allocator mode (e.g. the non-parallel scratch path): route
        // this job's allocations into the caller-provided allocator.
        n00b_allocator_t *prev_alloc = n00b_set_current_allocator(job->allocator);
        rocs_store_batch_prepare_job(job);
        n00b_restore_current_allocator(prev_alloc);
    }
    n00b_gc_attrib_exit_ingest(prev_ingest);
}

static n00b_result_t(bool)
rocs_store_ensure_hot_route_unlocked(n00b_store_t  *store,
                                     n00b_string_t *route,
                                     bool           residency_locked);
static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets_from_terms(n00b_store_t                 *store,
                                            n00b_store_shard_t           *shard,
                                            rocs_store_batch_term_list_t *terms,
                                            n00b_allocator_t             *allocator);
static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets(n00b_store_t     *store,
                                 n00b_store_shard_t *shard,
                                 n00b_json_node_t *record,
                                 n00b_allocator_t *allocator);
static void
rocs_store_commit_index_targets(rocs_store_posting_target_list_t *targets,
                                uint64_t                          ordinal);
static n00b_json_node_t *
rocs_store_reserved_slot_tombstone(n00b_err_t err,
                                   n00b_allocator_t *allocator);

static n00b_buffer_t *
rocs_store_buffer_from_record_text(n00b_string_t    *text,
                                   n00b_allocator_t *allocator)
{
    if (text == nullptr || text->data == nullptr || text->u8_bytes < 0) {
        return nullptr;
    }
    return n00b_buffer_from_bytes(text->data,
                                  (int64_t)text->u8_bytes,
                                  .allocator = allocator);
}

static void
rocs_store_range_prepare_worker(void *job_v, void *user_data)
{
    (void)user_data;
    rocs_store_range_commit_job_t *job = job_v;
    if (job == nullptr || job->store == nullptr || job->hot == nullptr
        || job->batch_job == nullptr || job->batch_job->record == nullptr) {
        return;
    }

    bool prev_ingest = n00b_gc_attrib_enter_ingest();
    // Per-worker-arena mode (persistent worker pool) leaves batch_job->allocator
    // null: the worker's current_allocator is already its per-worker bump arena.
    // Fall back to it so the prepared slot + index targets are still built (a
    // null allocator must NOT skip preparation, which would drop the record from
    // the range-commit path -- leaving it unindexed and uncounted).
    n00b_allocator_t *eff = job->batch_job->allocator != nullptr
                                ? job->batch_job->allocator
                                : n00b_current_allocator();
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(eff);

    job->err         = N00B_STORE_OK;
    job->byte_delta  = 0;
    job->prepared    = nullptr;
    job->targets     = nullptr;
    job->tombstone   = false;

    auto prepared_r = n00b_store_shard_prepare_reserved_slot(
        job->hot,
        job->batch_job->record,
        .raw      = job->batch_job->raw,
        .raw_span = job->raw_span,
        .allocator = eff);
    if (n00b_result_is_err(prepared_r)) {
        job->err = n00b_result_get_err(prepared_r);
        n00b_restore_current_allocator(prev_alloc);
        n00b_gc_attrib_exit_ingest(prev_ingest);
        return;
    }
    n00b_store_shard_prepared_slot_t *prepared = n00b_result_get(prepared_r);

    n00b_result_t(rocs_store_posting_target_list_t *) targets_r =
        job->batch_job->terms == nullptr
            ? rocs_store_prepare_index_targets(job->store,
                                               job->hot,
                                               job->batch_job->record,
                                               eff)
            : rocs_store_prepare_index_targets_from_terms(
                  job->store,
                  job->hot,
                  job->batch_job->terms,
                  eff);
    if (n00b_result_is_err(targets_r)) {
        job->err = n00b_result_get_err(targets_r);
        n00b_restore_current_allocator(prev_alloc);
        n00b_gc_attrib_exit_ingest(prev_ingest);
        return;
    }

    job->prepared    = prepared;
    job->targets     = n00b_result_get(targets_r);
    job->byte_delta  = prepared->byte_delta;

    n00b_restore_current_allocator(prev_alloc);
    n00b_gc_attrib_exit_ingest(prev_ingest);
}

struct n00b_store_conduit_ingest_t {
    n00b_store_t                       *store;
    n00b_store_ingest_topic_t          *topic;
    n00b_store_ingest_inbox_t          *inbox;
    n00b_conduit_sub_handle_t           sub;
    n00b_thread_t                      *thread;
    n00b_worker_pool_t                 *worker_pool;
    n00b_mutex_t                       *lock;
    n00b_allocator_t                   *allocator;
    n00b_store_source_decoder_t         source_decoder;
    n00b_store_conduit_ingest_stats_t   stats;
    uint32_t                            batch_capacity;
    int32_t                             worker_count;
    bool                                stop_requested;
    bool                                closed;
    bool                                joined;
};

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

static rocs_store_pin_list_t *
rocs_store_pin_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_pin_list_t *pins = n00b_alloc_with_opts(
        rocs_store_pin_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *pins = n00b_list_new_private(n00b_store_pin_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return pins;
}

static rocs_store_record_stream_list_t *
rocs_store_record_stream_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_record_stream_list_t *streams = n00b_alloc_with_opts(
        rocs_store_record_stream_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *streams = n00b_list_new_private(n00b_store_record_stream_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return streams;
}

static n00b_store_shard_id_list_t *
rocs_store_shard_id_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_shard_id_list_t *ids = n00b_alloc_with_opts(
        n00b_store_shard_id_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *ids = n00b_list_new_private(uint64_t,
                                 .allocator = allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return ids;
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

static bool
rocs_store_catalog_entry_visible_sealed(n00b_store_catalog_entry_t *entry)
{
    return entry != nullptr
        && entry->state == ROCS_STORE_CATALOG_ENTRY_SEALED
        && entry->object_path != nullptr
        && entry->partition_key != nullptr;
}

static bool
rocs_store_catalog_entry_persistable(n00b_store_catalog_entry_t *entry)
{
    return entry != nullptr
        && (entry->state == ROCS_STORE_CATALOG_ENTRY_SEALED
            || entry->state == ROCS_STORE_CATALOG_ENTRY_QUARANTINED)
        && entry->object_path != nullptr
        && entry->partition_key != nullptr;
}

static bool
rocs_store_catalog_entry_droppable(n00b_store_catalog_entry_t *entry)
{
    return rocs_store_catalog_entry_persistable(entry);
}

static bool
rocs_store_catalog_entry_state_persistent(uint64_t state)
{
    return state == ROCS_STORE_CATALOG_ENTRY_SEALED
        || state == ROCS_STORE_CATALOG_ENTRY_QUARANTINED;
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
                                         .no_map = true,
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

    // The hot shard is self-contained: shard_append copies every value
    // (record bytes, column field-name strings, postings, ordinals,
    // flagsets, raw spans) into this pool, and the shard holds no pointers
    // into GC-managed arenas. It is reached only through store->hot_shard /
    // store->hot_allocator and is destroyed wholesale at seal/retire (never
    // freed object-by-object). It is therefore hidden from GC root scanning.
    //
    // But the shard IS marshaled at seal (n00b_marshal walks it), so the
    // marshaler must be able to resolve every shard allocation via
    // n00b_find_alloc_info. We get that with INLINE headers (not an OOB
    // metadata dict): external_metadata=false drops the per-allocation
    // dict_untyped put/get and the critical_execution (STW-gate) read-lock
    // that dominate hot-path ingest; inline_headers=true makes each
    // allocation self-describing; and because the pool carries inline
    // headers, pool_pages_registered() registers its pages in the mmap tree
    // so find_alloc_info resolves them via the inline header (kind=inline)
    // while n00b_mmap_is_gc_scannable stays false (no metadata pool) so the
    // collector never scans the shard as roots.
    n00b_allocator_t *allocator = n00b_pool_init(
        &storage->pool,
        .hidden            = true,
        .external_metadata = false,
        .inline_headers    = true,
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
                if (postings->flags != nullptr) {
                    stats.dense_count += n00b_flagset_count(postings->flags);
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
    // Caller holds the catalog/commit lock and residency_lock. Only streams
    // that borrowed hot row string spans block retired-hot allocator reclaim;
    // generic store pins still protect catalog shape/residency elsewhere.
    if (store == nullptr || store->catalog == nullptr
        || store->hot_snapshot_pins != 0) {
        return nullptr;
    }

    rocs_store_retired_hot_allocator_list_t *retired = nullptr;
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry == nullptr || entry->retired_hot_allocator == nullptr) {
            continue;
        }

        if (retired == nullptr) {
            retired = rocs_store_retired_hot_allocator_list_new(
                .allocator = store->allocator);
        }

        rocs_store_retired_hot_allocator_t *item = n00b_alloc_with_opts(
            rocs_store_retired_hot_allocator_t,
            &(n00b_alloc_opts_t){
                .allocator = store->allocator,
            });
        item->allocator    = entry->retired_hot_allocator;
        item->shard_id     = entry->shard_id;
        item->generation   = entry->retired_hot_generation;
        item->record_count = entry->retired_hot_record_count;
        n00b_list_push(*retired, item);

        entry->retired_hot_allocator    = nullptr;
        entry->retired_hot_generation   = 0;
        entry->retired_hot_record_count = 0;
    }

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

    // No pin lock here: readers of the outgoing hot arena were already drained
    // at the rotation swap (rocs_store_hot_pin lock in the seal/rotate path),
    // and post-rotation nothing reads a retired arena (new readers see the new
    // hot; stale-generation reads return none), so these arenas are reader-free
    // by the time we free them.
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

static rocs_store_catalog_list_t *
rocs_store_detach_failed_seal_jobs_locked(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return nullptr;
    }

    rocs_store_catalog_list_t *failed = nullptr;
    size_t i = 0;
    while (i < n00b_list_len(*store->catalog)) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, i);
        if (entry == nullptr
            || entry->state != ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL) {
            i++;
            continue;
        }

        if (failed == nullptr) {
            failed = rocs_store_catalog_list_new(.allocator = store->allocator);
        }
        entry = n00b_list_delete(*store->catalog, i);
        n00b_list_push(*failed, entry);
    }

    return failed;
}

static void
rocs_store_destroy_failed_seal_jobs(
    n00b_store_t              *store,
    rocs_store_catalog_list_t *failed)
{
    if (failed == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*failed);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*failed, i);
        if (entry == nullptr || entry->failed_seal_allocator == nullptr) {
            continue;
        }

        n00b_allocator_t *allocator = entry->failed_seal_allocator;
        uint64_t          record_count = entry->record_count;
        entry->failed_seal_allocator = nullptr;
        entry->failed_seal_shard     = nullptr;
        rocs_store_hot_allocator_destroy(store, allocator, record_count);
    }
}

static uint64_t
rocs_store_failed_seal_job_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return 0;
    }
    uint64_t count = 0;
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, i);
        if (entry != nullptr
            && entry->state == ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL) {
            count++;
        }
    }
    return count;
}

static n00b_err_t
rocs_store_failed_seal_last_error(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return N00B_STORE_ERR_VFS;
    }
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = len; i > 0; i--) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, i - 1);
        if (entry != nullptr
            && entry->state == ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL
            && entry->failed_seal_last_error != N00B_STORE_OK) {
            return entry->failed_seal_last_error;
        }
    }
    return N00B_STORE_ERR_VFS;
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
    if (store->catalog == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry == nullptr || entry->shard_id != shard_id) {
            continue;
        }
        entry->retired_hot_allocator    = allocator;
        entry->retired_hot_generation   = generation;
        entry->retired_hot_record_count = record_count;
        return;
    }
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
    n00b_mutex_lock(store->residency_lock);
    rocs_store_retire_hot_allocator_locked(store,
                                           allocator,
                                           shard_id,
                                           generation,
                                           record_count);
    retired = rocs_store_detach_retired_hot_allocators_locked(store);
    n00b_mutex_unlock(store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(store, retired);
}

static void
rocs_store_try_reclaim_retired_hot_allocators(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    rocs_store_retired_hot_allocator_list_t *retired = nullptr;
    n00b_mutex_lock(store->residency_lock);
    retired = rocs_store_detach_retired_hot_allocators_locked(store);
    n00b_mutex_unlock(store->residency_lock);

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

n00b_result_t(n00b_store_service_profile_t *)
n00b_store_service_profile_new() _kargs
{
    uint64_t                          ingest_worker_count = 1;
    uint64_t                          seal_worker_count   = 1;
    uint64_t                          ingest_queue_bound  = 0;
    uint64_t                          ingest_batch_bound  = 0;
    n00b_store_ingest_backpressure_t  ingest_backpressure =
        N00B_STORE_INGEST_BACKPRESSURE_BLOCK;
    n00b_store_source_decoder_t       source_decoder      = nullptr;
    n00b_store_index_options_t       *index_options       = nullptr;
    n00b_allocator_t                 *allocator           = nullptr;
}
    requires {
        ingest_worker_count >= 1;
        N00B_STORE_INGEST_BACKPRESSURE_CONTRACT_VALID(ingest_backpressure);
        N00B_STORE_INDEX_OPTIONS_CONTRACT_VALID(index_options);
    }
    ensures {
        n00b_result_is_err(result)
            || (n00b_result_value(result) != nullptr
                && N00B_STORE_SERVICE_PROFILE_CONTRACT_VALID(
                    n00b_result_value(result)));
    }
{
    n00b_store_service_profile_t *profile = n00b_alloc_with_opts(
        n00b_store_service_profile_t,
        &(n00b_alloc_opts_t){ .allocator = allocator });
    if (profile == nullptr) {
        return n00b_result_err(n00b_store_service_profile_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    profile->ingest_worker_count = ingest_worker_count;
    profile->seal_worker_count   = seal_worker_count;
    profile->ingest_queue_bound  = ingest_queue_bound;
    profile->ingest_batch_bound  = ingest_batch_bound;
    profile->ingest_backpressure = ingest_backpressure;
    profile->source_decoder      = source_decoder;
    profile->index_options       = index_options;
    profile->allocator           = allocator;

    return n00b_result_ok(n00b_store_service_profile_t *, profile);
}

n00b_result_t(n00b_store_t *)
n00b_store_open_service(n00b_vfs_t                   *vfs,
                        n00b_string_t                *root,
                        n00b_store_schema_t          *schema,
                        n00b_store_service_profile_t *profile) _kargs
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
    // Retention is opt-in: a raw store (unit tests, tools, ad-hoc opens) does
    // NOT auto-drop sealed shards. Deployments that want it (e.g. wax = 60 days)
    // pass an explicit window/byte budget. See N00B_STORE_DEFAULT_RETENTION_NS.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
}
    requires {
        vfs != nullptr;
        root != nullptr;
        schema != nullptr;
        N00B_STORE_SERVICE_PROFILE_CONTRACT_VALID(profile);
    }
    ensures {
        n00b_result_is_err(result)
            || (n00b_result_value(result) != nullptr
                && ROCS_STORE_CONTRACT_OPEN(n00b_result_value(result)));
    }
{
    if (profile == nullptr
        || !N00B_STORE_SERVICE_PROFILE_CONTRACT_VALID(profile)
        || profile->seal_worker_count > (uint64_t)INT32_MAX
        || profile->ingest_batch_bound > (uint64_t)INT32_MAX) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_CONFIG);
    }

    uint64_t seal_workers = profile->seal_worker_count == 0
                                ? 1
                                : profile->seal_worker_count;

    auto conduit_r = n00b_conduit_new();
    if (n00b_result_is_err(conduit_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_INTERNAL);
    }
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_ingest_topic_get(
        conduit,
        n00b_conduit_int_uri(N00B_CONDUIT_TAG_USER_EVENT, 1));
    if (n00b_result_is_err(topic_r)) {
        n00b_conduit_destroy(conduit);
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(topic_r));
    }

    auto store_r = n00b_store_open_vfs(
        vfs,
        root,
        schema,
        .partition_policy = partition_policy,
        .retain_policy    = retain_policy,
        .seal_policy      = seal_policy,
        .residency_policy = residency_policy,
        .cache            = cache,
        .commit_topic     = commit_topic,
        .lifecycle_topic  = lifecycle_topic,
        .display_name     = display_name,
        .recovery_journal = recovery_journal,
        .keep_standby     = true,
        .seal_worker_count = seal_workers,
        .retention_window_ns = retention_window_ns,
        .retention_max_sealed_shards = retention_max_sealed_shards,
        .retention_max_total_bytes = retention_max_total_bytes,
        .allocator        = profile->allocator);
    if (n00b_result_is_err(store_r)) {
        n00b_conduit_destroy(conduit);
        return store_r;
    }

    n00b_store_t *store = n00b_result_get(store_r);
    uint64_t queue_bound = profile->ingest_queue_bound == 0
                               ? 128
                               : profile->ingest_queue_bound;
    uint64_t batch_bound = profile->ingest_batch_bound == 0
                               ? 128
                               : profile->ingest_batch_bound;
    if (queue_bound > (uint64_t)INT32_MAX) {
        (void)n00b_store_close(store);
        n00b_conduit_destroy(conduit);
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_CONFIG);
    }
    if (batch_bound > queue_bound) {
        batch_bound = queue_bound;
    }

    auto ingest_r = n00b_store_conduit_ingest_start(
        store,
        n00b_result_get(topic_r),
        .worker_count   = (int32_t)profile->ingest_worker_count,
        .queue_capacity = (int32_t)queue_bound,
        .batch_capacity = (int32_t)batch_bound,
        .source_decoder = profile->source_decoder,
        .allocator      = profile->allocator);
    if (n00b_result_is_err(ingest_r)) {
        (void)n00b_store_close(store);
        n00b_conduit_destroy(conduit);
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(ingest_r));
    }

    store->service_profile      = profile;
    store->service_conduit      = conduit;
    store->service_ingest_topic = n00b_result_get(topic_r);
    store->service_ingest       = n00b_result_get(ingest_r);
    return n00b_result_ok(n00b_store_t *, store);
}

n00b_result_t(n00b_store_ingest_receipt_t)
n00b_store_ingest_submit(n00b_store_t               *store,
                         n00b_store_ingest_payload_t payload)
    requires {
        ROCS_STORE_CONTRACT_OPEN(store);
    }
    ensures {
        n00b_result_is_err(result)
            || N00B_STORE_INGEST_RECEIPT_CONTRACT_ACCOUNTED(
                n00b_result_value(result));
    }
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_ingest_receipt_t,
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN
        || store->service_profile == nullptr
        || store->service_ingest_topic == nullptr) {
        return n00b_result_err(n00b_store_ingest_receipt_t,
                               N00B_STORE_ERR_STATE);
    }

    auto publish_r = n00b_store_ingest_topic_publish_ex(
        store->service_ingest_topic,
        payload,
        .backpressure = store->service_profile->ingest_backpressure);
    if (n00b_result_is_err(publish_r)) {
        n00b_err_t err = n00b_result_get_err(publish_r);
        return n00b_result_ok(
            n00b_store_ingest_receipt_t,
            ((n00b_store_ingest_receipt_t){
                .state    = N00B_STORE_INGEST_RECEIPT_REJECTED_PRE_ADMISSION,
                .admitted = 0,
                .rejected = 1,
                .malformed = 0,
                .err      = err,
            }));
    }

    return n00b_result_ok(
        n00b_store_ingest_receipt_t,
        ((n00b_store_ingest_receipt_t){
            .state    = N00B_STORE_INGEST_RECEIPT_ADMITTED_QUEUED,
            .admitted = 1,
            .rejected = 0,
            .malformed = 0,
            .err      = N00B_STORE_OK,
        }));
}

n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_service_ingest_stats(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_stats_t,
                               N00B_STORE_ERR_ARG);
    }
    if (store->service_ingest == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_stats_t,
                               N00B_STORE_ERR_STATE);
    }
    return n00b_store_conduit_ingest_stats(store->service_ingest);
}

n00b_result_t(bool)
n00b_store_index_emit_term(n00b_store_index_emit_t *emit,
                           n00b_string_t           *column,
                           n00b_string_t           *term)
    requires {
        N00B_STORE_INDEX_EMIT_CONTRACT_LIVE(emit);
        column != nullptr;
        term != nullptr;
    }
    ensures {
        n00b_result_is_err(result)
            || (n00b_result_value(result) == true
                && N00B_STORE_INDEX_EMIT_CONTRACT_COPIED(emit));
    }
{
    emit->copied_term = false;
    auto append_r = rocs_store_append_text_literal_to_column(
        emit->out,
        column,
        term,
        emit->owner_allocator);
    if (n00b_result_is_err(append_r)) {
        return append_r;
    }
    emit->copied_term = true;
    return n00b_result_ok(bool, true);
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

    entry->state             = ROCS_STORE_CATALOG_ENTRY_SEALED;
    entry->object_path       = rocs_store_string_copy(
        object_path,
        store == nullptr ? nullptr : store->allocator);
    entry->owner             = store;
    entry->partition_key     = rocs_store_string_copy(
        partition_key == nullptr ? r"default" : partition_key,
        store == nullptr ? nullptr : store->allocator);
    if (entry->partition_key == nullptr) {
        entry->partition_key = r"default";
    }
    entry->etag              = rocs_store_string_copy(
        etag,
        store == nullptr ? nullptr : store->allocator);
    entry->shard_id          = shard_id;
    entry->generation        = generation;
    entry->byte_len          = byte_len;
    entry->record_count      = record_count;
    entry->schema_generation = schema_generation;
    entry->seal_ts           = seal_ts;
    entry->retired_hot_allocator    = nullptr;
    entry->retired_hot_generation   = 0;
    entry->retired_hot_record_count = 0;
    entry->failed_seal_shard         = nullptr;
    entry->failed_seal_allocator     = nullptr;
    entry->failed_seal_byte_estimate = 0;
    entry->failed_seal_base_address  = 0;
    entry->failed_seal_last_error    = N00B_STORE_OK;
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
            if (rocs_store_catalog_entry_visible_sealed(entry)
                && rocs_store_entry_pos_less(entry, oldest)) {
                oldest = entry;
            }
        }
    }
    if (rocs_store_catalog_entry_visible_sealed(pending_entry)
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

// resident_map is a plain (GC-traced) pointer, but the reader fast path pins a
// shard lock-free and races the (write-locked) unload path that clears it. These
// helpers give that one field seq_cst atomic access via cast -- keeping the field
// plain so ncc's typemap still traces it as a GC pointer -- so the pin/clear
// handshake (pin -> fence -> re-check map, vs. clear -> fence -> check pins) is
// well-defined instead of a data race.
static inline n00b_store_map_t *
rocs_entry_map_load(n00b_store_catalog_entry_t *entry)
{
    return atomic_load_explicit(
        (_Atomic(n00b_store_map_t *) *)&entry->resident_map,
        memory_order_seq_cst);
}

static inline void
rocs_entry_map_store(n00b_store_catalog_entry_t *entry, n00b_store_map_t *map)
{
    atomic_store_explicit(
        (_Atomic(n00b_store_map_t *) *)&entry->resident_map,
        map,
        memory_order_seq_cst);
}

static bool
rocs_store_catalog_owns_entry(n00b_store_t              *store,
                              n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || store->catalog == nullptr || entry == nullptr) {
        return false;
    }

    return entry->owner == store
        && entry->shard_id != 0
        && rocs_store_catalog_entry_visible_sealed(entry);
}

static n00b_result_t(bool)
rocs_store_resident_unload_entry(n00b_store_t              *store,
                                 n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_store_map_t *map = rocs_entry_map_load(entry);
    if (map == nullptr) {
        return n00b_result_ok(bool, false);
    }
    if (n00b_atomic_load(&entry->resident_pins) != 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    // Unload handshake vs. lock-free readers: clear the map pointer FIRST so a
    // new fast-path pinner re-checking the map sees it gone, then a seq_cst fence,
    // then re-check pins. If a reader pinned between our pre-check and the clear,
    // we now observe pins != 0 and restore the map without munmapping (the reader
    // holds a valid mapping). Writers are serialized by residency_lock, so only
    // reader pins race us here. Mirror of the reader in resident_shard_acquire.
    rocs_entry_map_store(entry, nullptr);
    atomic_thread_fence(memory_order_seq_cst);
    if (n00b_atomic_load(&entry->resident_pins) != 0) {
        rocs_entry_map_store(entry, map);
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    auto close_r = n00b_store_map_close(map);
    if (n00b_result_is_err(close_r)) {
        rocs_entry_map_store(entry, map);
        return n00b_result_err(bool, N00B_STORE_ERR_RESIDENCY);
    }

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
rocs_store_oldest_unpinned_resident(n00b_store_t               *store,
                                    uint64_t                    now_ns,
                                    n00b_store_catalog_entry_t *protect)
{
    n00b_store_catalog_entry_t *best = nullptr;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        // Skip unmappable/pinned entries and `protect` (the shard just mapped by
        // the in-flight load — evict-on-add must never reclaim it).
        if (entry == nullptr || entry == protect
            || entry->resident_map == nullptr
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

// residency_lock (write) MUST be held by the caller, which keeps the lock
// afterward. Evicts oldest unpinned resident shards (skipping `protect`, the
// entry the caller just mapped) while over the residency budget — count
// (max_resident_shards) and/or bytes (max_resident_bytes) — plus idle eviction.
// Best-effort: stops when no evictable victim remains. This is the shared core
// of evict-on-add (rocs_store_resident_load_entry) and n00b_store_residency_trim
// so the LRU is bounded the moment a shard is added, not only on explicit trim.
static uint64_t
rocs_store_evict_over_budget_locked(n00b_store_t               *store,
                                    uint64_t                    target_bytes,
                                    uint64_t                    target_shards,
                                    n00b_store_catalog_entry_t *protect)
{
    uint64_t released = 0;
    uint64_t now_ns   = (uint64_t)n00b_ns_timestamp();

    while (true) {
        bool bytes_over =
            target_bytes != 0 && store->resident_bytes > target_bytes;
        bool shards_over =
            target_shards != 0 && store->resident_shards > target_shards;
        n00b_store_catalog_entry_t *victim =
            rocs_store_oldest_unpinned_resident(store, now_ns, protect);

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

        uint64_t len      = victim->byte_len;
        auto     unload_r = rocs_store_resident_unload_entry(store, victim);
        if (n00b_result_is_err(unload_r)) {
            break; // best-effort; caller retains the lock
        }
        if (n00b_result_get(unload_r)) {
            released += len;
        }
    }

    return released;
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
        n00b_atomic_add(&store->resident_cache_hits, 1);
        return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
    }
    n00b_atomic_add(&store->resident_cache_misses, 1);

    if (store->residency_policy.validate_on_open) {
        auto verify_r = n00b_store_catalog_entry_verify_object(store, entry);
        if (n00b_result_is_err(verify_r)) {
            return n00b_result_err(n00b_store_map_t *,
                                   n00b_result_get_err(verify_r));
        }
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

    // Evict-on-add: bound the resident LRU the moment a shard is mapped, rather
    // than relying on an external trim. Evicts oldest unpinned shards down to the
    // residency budget, protecting the entry we just mapped (the caller pins it
    // next). The caller (acquire) holds residency_lock across this call.
    (void)rocs_store_evict_over_budget_locked(
        store,
        store->residency_policy.max_resident_bytes,
        store->residency_policy.max_resident_shards,
        entry);

    return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
}

static n00b_result_t(bool)
rocs_store_catalog_append_entry(n00b_store_t               *store,
                                n00b_buffer_t              *buf,
                                n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->object_path == nullptr
        || entry->partition_key == nullptr
        || !rocs_store_catalog_entry_persistable(entry)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    auto r = rocs_store_catalog_append_u64(buf, (uint64_t)entry->state);
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->shard_id);
    }
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

    uint64_t entry_count = 0;
    if (store->catalog != nullptr) {
        n00b_list_foreach(*store->catalog, p) {
            if (rocs_store_catalog_entry_persistable(*p)) {
                entry_count++;
            }
        }
    }
    if (rocs_store_catalog_entry_persistable(pending_entry)) {
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
        if (entry_err == N00B_STORE_OK
            && rocs_store_catalog_entry_persistable(entry)) {
            auto append_r = rocs_store_catalog_append_entry(store, buf, entry);
            if (n00b_result_is_err(append_r)) {
                entry_err = n00b_result_get_err(append_r);
            }
        }
    }
    if (entry_err != N00B_STORE_OK) {
        return n00b_result_err(n00b_buffer_t *, entry_err);
    }
    if (rocs_store_catalog_entry_persistable(pending_entry)) {
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
        uint64_t entry_state = ROCS_STORE_CATALOG_ENTRY_SEALED;
        if (version >= 3) {
            auto state_r = rocs_store_catalog_read_u64(&reader);
            if (n00b_result_is_err(state_r)) {
                return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
            }
            entry_state = n00b_result_get(state_r);
            if (!rocs_store_catalog_entry_state_persistent(entry_state)) {
                return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
            }
        }
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
        entry->state = (rocs_store_catalog_entry_state_t)entry_state;
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

// Release a directory listing returned by n00b_vfs_readdir once recovery has
// finished consuming it. The store passes its own allocator to n00b_vfs_readdir,
// so the result is a deep clone (vfs_clone_list_result) whose name strings,
// entries array, and continuation are all freshly owned in store->allocator and
// therefore safe to free here regardless of the underlying VFS backend.
static void
rocs_store_free_dir_listing(n00b_vfs_list_result_t *list)
{
    if (list == nullptr) {
        return;
    }
    if (list->entries != nullptr) {
        for (uint32_t i = 0; i < list->count; i++) {
            n00b_free(list->entries[i].name);
        }
        n00b_free(list->entries);
    }
    if (list->continuation != nullptr) {
        n00b_free(list->continuation);
    }
    n00b_free(list);
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
            rocs_store_free_dir_listing(list);
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
            rocs_store_free_dir_listing(list);
            return n00b_result_err(uint64_t, n00b_result_get_err(write_r));
        }
    }

    rocs_store_free_dir_listing(list);
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

static n00b_err_t rocs_store_seal_active_writer_guard_unlocked(
    n00b_store_t *store);
static void rocs_store_rotation_lock(n00b_store_t *store);
static void rocs_store_rotation_unlock(n00b_store_t *store);

// ============================================================================
// Async seal: take-next-hot / replenish-standby helpers + the seal worker.
//
// All run with commit_lock held by the caller (the seal worker reacquires it
// for its commit phase).  take/replenish are the ONLY places that create or
// consume hot/standby shards, so shard-id assignment (next_shard_id) stays
// monotonic regardless of which thread runs them: every fresh shard pulls the
// next id and bumps the counter; consuming a pre-built standby does not bump
// (its id was already accounted when the standby was built).
// ============================================================================

// Provide the next hot shard + its allocator (commit_lock held).  Prefers the
// pristine standby (a pure pointer take, no allocation -> fast rotation); falls
// back to allocating a fresh shard when none is available (keep_standby off, or
// the seal worker has not replenished yet -- the latter signals that rotation is
// outrunning sealing).
static n00b_result_t(bool)
rocs_store_take_next_hot_unlocked(n00b_store_t        *store,
                                  n00b_store_shard_t **out_shard,
                                  n00b_allocator_t   **out_alloc)
{
    if (store->keep_standby && store->standby_shard != nullptr) {
        *out_shard               = store->standby_shard;
        *out_alloc               = store->standby_allocator;
        store->standby_shard     = nullptr;
        store->standby_allocator = nullptr;
        return n00b_result_ok(bool, true);
    }

    uint64_t next_id = store->next_shard_id;
    auto     alloc_r = rocs_store_hot_allocator_new(store);
    if (n00b_result_is_err(alloc_r)) {
        return n00b_result_err(bool, n00b_result_get_err(alloc_r));
    }
    n00b_allocator_t *alloc = n00b_result_get(alloc_r);

    auto shard_r = n00b_store_shard_new(
        .shard_id   = next_id,
        .retain_raw = store->retain_policy != nullptr
                   && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = alloc,
        .record_cap = store->seal_policy != nullptr
                          ? store->seal_policy->max_records
                          : 0);
    if (n00b_result_is_err(shard_r)) {
        rocs_store_hot_allocator_destroy(store, alloc, 0);
        return n00b_result_err(bool, n00b_result_get_err(shard_r));
    }

    *out_shard           = n00b_result_get(shard_r);
    *out_alloc           = alloc;
    store->next_shard_id = next_id + 1;
    return n00b_result_ok(bool, true);
}

// Rebuild the standby spare (commit_lock held) when keep_standby is on and the
// slot is empty. This takes the rotation mutex around standby/next-shard state.
// Best-effort: on allocation failure the slot stays empty and the next rotation
// falls back to an inline allocation, so failure is silent and non-fatal.
static void
rocs_store_replenish_standby(n00b_store_t *store)
{
    rocs_store_rotation_lock(store);
    if (!store->keep_standby || store->standby_shard != nullptr) {
        rocs_store_rotation_unlock(store);
        return;
    }
    if (store->state != N00B_STORE_STATE_OPEN
        || store->next_shard_id == UINT64_MAX) {
        rocs_store_rotation_unlock(store);
        return;
    }

    uint64_t next_id = store->next_shard_id;
    auto     alloc_r = rocs_store_hot_allocator_new(store);
    if (n00b_result_is_err(alloc_r)) {
        rocs_store_rotation_unlock(store);
        return;
    }
    n00b_allocator_t *alloc = n00b_result_get(alloc_r);

    auto shard_r = n00b_store_shard_new(
        .shard_id   = next_id,
        .retain_raw = store->retain_policy != nullptr
                   && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = alloc,
        .record_cap = store->seal_policy != nullptr
                          ? store->seal_policy->max_records
                          : 0);
    if (n00b_result_is_err(shard_r)) {
        rocs_store_hot_allocator_destroy(store, alloc, 0);
        rocs_store_rotation_unlock(store);
        return;
    }

    store->standby_shard     = n00b_result_get(shard_r);
    store->standby_allocator = alloc;
    store->next_shard_id     = next_id + 1;
    rocs_store_rotation_unlock(store);
}

    // One enqueued seal job: the detached old shard plus everything the seal worker
    // needs to marshal it, commit its catalog entry, and retire its allocator.  All
    // fields are captured at rotate time (commit_lock held) so the worker touches no
    // live store state except inside its own commit_lock-guarded commit phase.
    struct rocs_store_seal_job {
    n00b_store_t       *store;
    n00b_store_shard_t *old_shard;
    n00b_allocator_t   *old_allocator;
    n00b_string_t      *object_path;
    n00b_string_t      *entry_partition;
    uint64_t            shard_id;
    uint64_t            generation;
    uint64_t            schema_generation;
    uint64_t            record_count;
    uint64_t            seal_ts;
    uint64_t            byte_estimate;
    uint32_t            base_address;
};

#define ROCS_STORE_SEAL_JOB_CONTRACT_WORK(_job) \
    ((_job) != nullptr                           \
     && (_job)->store != nullptr                 \
     && (_job)->old_shard != nullptr             \
     && (_job)->old_allocator != nullptr         \
     && (_job)->object_path != nullptr           \
     && (_job)->entry_partition != nullptr       \
     && (_job)->shard_id != 0                    \
     && (_job)->record_count != 0)

#define ROCS_STORE_SEAL_JOB_CONTRACT_VALID(_job) \
    ROCS_STORE_SEAL_JOB_CONTRACT_WORK(_job)

struct rocs_store_seal_queue {
    n00b_store_t               *store;
    rocs_store_seal_job_list_t *jobs;
    n00b_condition_t            cv;
    n00b_thread_t             **threads;
    int32_t                     thread_count;
    uint64_t                    in_flight;
    bool                        stopping;
};

static rocs_store_seal_job_list_t *
rocs_store_seal_job_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_seal_job_list_t *list = n00b_alloc_with_opts(
        rocs_store_seal_job_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *list = n00b_list_new_private(rocs_store_seal_job_t *,
                                  .allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return list;
}

typedef struct {
    bool old_allocator_released_or_transferred;
    bool catalog_entry_visible;
    bool failure_path;
    bool retained_for_retry;
} rocs_store_seal_job_outcome_t;

#define ROCS_STORE_SEAL_JOB_OUTCOME_CONTRACT_VALID(_outcome)    \
    ((_outcome).old_allocator_released_or_transferred            \
     && ((_outcome).catalog_entry_visible || (_outcome).failure_path))

static void
rocs_store_retain_failed_seal_job_locked(n00b_store_t          *store,
                                         rocs_store_seal_job_t *job,
                                         n00b_err_t             err)
{
    if (store == nullptr || job == nullptr || job->old_allocator == nullptr) {
        return;
    }

    n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
        store,
        .shard_id          = job->shard_id,
        .generation        = job->generation,
        .object_path       = job->object_path,
        .byte_len          = 0,
        .record_count      = job->record_count,
        .schema_generation = job->schema_generation,
        .seal_ts           = job->seal_ts,
        .partition_key     = job->entry_partition,
        .etag              = nullptr);
    if (entry == nullptr) {
        return;
    }

    entry->state                     = ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL;
    entry->failed_seal_shard         = job->old_shard;
    entry->failed_seal_allocator     = job->old_allocator;
    entry->failed_seal_byte_estimate = job->byte_estimate;
    entry->failed_seal_base_address  = job->base_address;
    entry->failed_seal_last_error    = err;
    rocs_store_catalog_insert_sorted(store, entry);
}

// Shared tail of every seal-worker failure path (commit_lock held): retain the
// detached old hot shard for retry/teardown instead of retiring the allocator.
// The old records are not catalog-visible yet, but they are still owned by the
// store and are not counted as durable drops.
static void
rocs_store_seal_job_fail_locked(n00b_store_t          *store,
                                rocs_store_seal_job_t *job,
                                n00b_err_t             err)
{
    n00b_eprintf("rocs: async seal of shard [|#|] failed (err [|#|]); "
                 "rotation already committed — records retained for retry "
                 "[|#|]\n",
                 job->shard_id,
                 (int64_t)err,
                 job->record_count);
    rocs_store_retain_failed_seal_job_locked(store, job, err);
    rocs_store_replenish_standby(store);
}

// Epoch (wall-clock) nanoseconds. seal_ts and retention cutoffs must be on the
// same epoch clock as record ts_ns; n00b_ns_timestamp() is CLOCK_MONOTONIC and
// resets on reboot, so it is wrong for any durable/time-window comparison.
static inline uint64_t
rocs_store_epoch_ns(void)
{
    n00b_duration_t d;
    n00b_capture_timestamp(&d);
    return (uint64_t)n00b_ns_from_duration(&d);
}

// Apply the store's default whole-shard retention (set at open). Called by the
// sealer after a commit, with no store lock held (apply re-takes commit_lock +
// residency_lock internally). Cheap: the drop loop exits immediately when the
// oldest sealed shard is within the window and under the count cap. Without this
// the catalog grows forever — nothing else prunes sealed shards.
static void
rocs_store_apply_default_retention(n00b_store_t *store)
{
    uint64_t window    = store->retention_window_ns;
    uint64_t maxshards = store->retention_max_sealed_shards;
    uint64_t maxbytes  = store->retention_max_total_bytes;
    if (window == 0 && maxshards == 0 && maxbytes == 0) {
        return; // retention disabled for this store
    }
    uint64_t cutoff = 0;
    if (window != 0) {
        uint64_t now = rocs_store_epoch_ns();
        cutoff       = now > window ? (now - window) : 0;
    }
    // drop_before_seal_ts == 0 disables the age rule; if the window produced no
    // usable cutoff and there are no count/byte caps, there is nothing to do.
    if (cutoff == 0 && maxshards == 0 && maxbytes == 0) {
        return;
    }
    auto policy_r = n00b_store_shard_retention_policy_new(
        .max_sealed_shards      = maxshards,
        .max_total_sealed_bytes = maxbytes,
        .drop_before_seal_ts    = cutoff,
        .min_seal_ts            = 0,
        .drop_reason            = r"retention",
        .allocator              = store->allocator);
    if (n00b_result_is_err(policy_r)) {
        return;
    }
    (void)n00b_store_apply_shard_retention(store, n00b_result_get(policy_r));
}

// Seal-pool worker core: marshals the detached old shard with NO lock held (it
// owns the shard exclusively -- the whole point of the handoff), then takes
// commit_lock only to write the catalog entry, retire the old allocator, delete
// the journal, and replenish the standby.
static n00b_result_t(rocs_store_seal_job_outcome_t)
rocs_store_seal_job_run(rocs_store_seal_job_t *job)
    requires {
        ROCS_STORE_SEAL_JOB_CONTRACT_WORK(job);
    }
    ensures {
        n00b_result_is_err(result)
            || ROCS_STORE_SEAL_JOB_OUTCOME_CONTRACT_VALID(
                n00b_result_value(result));
    }
{
    n00b_store_t *store = job->store;
    rocs_store_seal_job_outcome_t outcome = {};

    // ---- Phase 2: marshal the detached old shard (NO lock, exclusive) ------
    n00b_shard_state_t old_shard_state   = job->old_shard->state;
    uint64_t           old_shard_seal_ts = job->old_shard->seal_ts;
    n00b_pool_t       seal_pool  = {};
    n00b_allocator_t *seal_alloc = n00b_pool_init(
        &seal_pool,
        .hidden            = true,
        .external_metadata = true,
        .use_epochs        = false,
        .name              = "rocs_seal_image_scratch");

    n00b_err_t          err  = N00B_STORE_OK;
    uint64_t            len  = 0;
    n00b_vfs_obj_stat_t stat = {};
    auto image_r = n00b_store_shard_seal(job->old_shard,
                                         .seal_ts      = job->seal_ts,
                                         .base_address = job->base_address,
                                         .allocator    = seal_alloc);
    if (n00b_result_is_err(image_r)) {
        n00b_eprintf("rocs: async seal of shard [|#|] failed at shard_seal "
                     "(cause err=[|#|], record_count=[|#|])\n",
                     job->shard_id,
                     (int64_t)n00b_result_get_err(image_r),
                     job->record_count);
        err = N00B_STORE_ERR_INTERNAL;
    }
    else {
        n00b_buffer_t *image = n00b_result_get(image_r);
        len                  = (uint64_t)n00b_buffer_len(image);
        auto write_r         = rocs_store_write_vfs_object(
            store, job->object_path, image, .create_exclusive = true);
        if (n00b_result_is_err(write_r)) {
            err = n00b_result_get_err(write_r);
        }
        else {
            auto stat_r = n00b_vfs_stat(store->vfs, job->object_path);
            if (n00b_result_is_err(stat_r)) {
                (void)n00b_vfs_delete(store->vfs, job->object_path);
                err = N00B_STORE_ERR_VFS;
            }
            else {
                stat = n00b_result_get(stat_r);
                if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != len) {
                    (void)n00b_vfs_delete(store->vfs, job->object_path);
                    err = N00B_STORE_ERR_CORRUPT;
                }
            }
        }
    }
    n00b_allocator_destroy(seal_alloc);
    if (err != N00B_STORE_OK) {
        job->old_shard->state   = old_shard_state;
        job->old_shard->seal_ts = old_shard_seal_ts;
    }

    // ---- Phase 3: commit (commit_lock held) --------------------------------
    n00b_mutex_lock(store->commit_lock);

    if (err != N00B_STORE_OK) {
        rocs_store_seal_job_fail_locked(store, job, err);
        n00b_mutex_unlock(store->commit_lock);
        outcome.old_allocator_released_or_transferred = true;
        outcome.failure_path                          = true;
        outcome.retained_for_retry                    = true;
        return n00b_result_ok(rocs_store_seal_job_outcome_t, outcome);
    }

    n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
        store,
        .shard_id          = job->shard_id,
        .generation        = job->generation,
        .object_path       = job->object_path,
        .byte_len          = stat.size,
        .record_count      = job->record_count,
        .schema_generation = job->schema_generation,
        .seal_ts           = job->seal_ts,
        .partition_key     = job->entry_partition,
        .etag              = stat.etag);

    auto catalog_r = rocs_store_catalog_write_staged(store,
                                                     entry,
                                                     store->next_shard_id);
    if (n00b_result_is_err(catalog_r)) {
        (void)n00b_vfs_delete(store->vfs, job->object_path);
        job->old_shard->state   = old_shard_state;
        job->old_shard->seal_ts = old_shard_seal_ts;
        rocs_store_seal_job_fail_locked(store,
                                        job,
                                        n00b_result_get_err(catalog_r));
        n00b_mutex_unlock(store->commit_lock);
        outcome.old_allocator_released_or_transferred = true;
        outcome.failure_path                          = true;
        outcome.retained_for_retry                    = true;
        return n00b_result_ok(rocs_store_seal_job_outcome_t, outcome);
    }

    rocs_store_rotation_lock(store);
    n00b_list_push(*store->catalog, entry);
    rocs_store_refresh_oldest_available(store);
    rocs_store_rotation_unlock(store);
    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_SEAL,
                                 entry->shard_id,
                                 UINT64_MAX,
                                 entry->record_count,
                                 entry->seal_ts,
                                 entry->partition_key);
#if defined(N00B_ROCS_TRACE)
    rocs_store_trace_seal(store,
                          job->shard_id,
                          job->record_count,
                          job->byte_estimate,
                          len,
                          job->old_allocator);
#endif
    rocs_store_retire_hot_allocator(store,
                                    job->old_allocator,
                                    job->shard_id,
                                    job->generation,
                                    job->record_count);
    if (store->recovery_journal && !store->recovering) {
        rocs_store_journal_delete(store, job->shard_id);
    }
    rocs_store_replenish_standby(store);
    n00b_mutex_unlock(store->commit_lock);
    // Prune sealed shards past the retention window / count cap now that a new
    // shard is committed. Done after releasing commit_lock — apply re-takes it.
    rocs_store_apply_default_retention(store);
    outcome.old_allocator_released_or_transferred = true;
    outcome.catalog_entry_visible                 = true;
    return n00b_result_ok(rocs_store_seal_job_outcome_t, outcome);
}

static n00b_result_t(bool)
rocs_store_retry_failed_seal_jobs_once(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(store->commit_lock);
    rocs_store_catalog_list_t *failed =
        rocs_store_detach_failed_seal_jobs_locked(store);
    n00b_mutex_unlock(store->commit_lock);
    if (failed == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_err_t first_err = N00B_STORE_OK;
    size_t     len       = n00b_list_len(*failed);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*failed, i);
        if (entry == nullptr
            || entry->state != ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL) {
            continue;
        }

        rocs_store_seal_job_t job = {
            .store             = store,
            .old_shard         = entry->failed_seal_shard,
            .old_allocator     = entry->failed_seal_allocator,
            .object_path       = entry->object_path,
            .entry_partition   = entry->partition_key,
            .shard_id          = entry->shard_id,
            .generation        = entry->generation,
            .schema_generation = entry->schema_generation,
            .record_count      = entry->record_count,
            .seal_ts           = rocs_store_epoch_ns(),
            .byte_estimate     = entry->failed_seal_byte_estimate,
            .base_address      = entry->failed_seal_base_address,
        };

        auto retry_r = rocs_store_seal_job_run(&job);
        if (n00b_result_is_err(retry_r)) {
            first_err = n00b_result_get_err(retry_r);
            n00b_mutex_lock(store->commit_lock);
            rocs_store_retain_failed_seal_job_locked(store,
                                                     &job,
                                                     first_err);
            n00b_mutex_unlock(store->commit_lock);
        }
        else {
            rocs_store_seal_job_outcome_t outcome = n00b_result_get(retry_r);
            if (outcome.failure_path && first_err == N00B_STORE_OK) {
                first_err = entry->failed_seal_last_error != N00B_STORE_OK
                                ? entry->failed_seal_last_error
                                : N00B_STORE_ERR_VFS;
            }
        }
        entry->failed_seal_allocator = nullptr;
        entry->failed_seal_shard     = nullptr;
        n00b_free(entry);
    }

    if (first_err != N00B_STORE_OK) {
        return n00b_result_err(bool, first_err);
    }
    return n00b_result_ok(bool, true);
}

static void
rocs_store_seal_worker_fn(void *job_v, void *user_data)
    requires {
        ROCS_STORE_SEAL_JOB_CONTRACT_VALID(
            (rocs_store_seal_job_t *)job_v);
    }
    ensures {
        job_v != nullptr;
    }
{
    (void)user_data;
    rocs_store_seal_job_t *job = job_v;

    auto run_r = rocs_store_seal_job_run(job);
    (void)run_r;
    n00b_free(job);
}

static void *
rocs_store_seal_queue_thread(void *arg)
{
    rocs_store_seal_queue_t *queue = arg;
    if (queue == nullptr) {
        return nullptr;
    }

    while (true) {
        n00b_condition_lock(&queue->cv);
        while (!queue->stopping && n00b_list_len(*queue->jobs) == 0) {
            n00b_condition_wait(&queue->cv);
        }
        if (queue->stopping && n00b_list_len(*queue->jobs) == 0) {
            n00b_condition_unlock(&queue->cv);
            break;
        }

        rocs_store_seal_job_t *job = n00b_list_delete(*queue->jobs, 0);
        queue->in_flight++;
        n00b_condition_unlock(&queue->cv);

        rocs_store_seal_worker_fn(job, queue->store);

        n00b_condition_lock(&queue->cv);
        if (queue->in_flight != 0) {
            queue->in_flight--;
        }
        if (queue->in_flight == 0 && n00b_list_len(*queue->jobs) == 0) {
            n00b_condition_notify(&queue->cv,
                                  .all = true,
                                  .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&queue->cv);
        }
    }

    return nullptr;
}

static n00b_result_t(rocs_store_seal_queue_t *)
rocs_store_seal_queue_new(n00b_store_t *store,
                          int32_t       thread_count,
                          n00b_allocator_t *allocator)
{
    if (store == nullptr || thread_count <= 0) {
        return n00b_result_err(rocs_store_seal_queue_t *, N00B_STORE_ERR_ARG);
    }

    rocs_store_seal_queue_t *queue = n00b_alloc_with_opts(
        rocs_store_seal_queue_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    if (queue == nullptr) {
        return n00b_result_err(rocs_store_seal_queue_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    queue->store        = store;
    queue->jobs         = rocs_store_seal_job_list_new(.allocator = allocator);
    queue->threads      = n00b_alloc_array(n00b_thread_t *,
                                           thread_count,
                                           .allocator = allocator);
    queue->thread_count = thread_count;
    queue->in_flight    = 0;
    queue->stopping     = false;
    n00b_condition_init(&queue->cv);

    if (queue->jobs == nullptr || queue->threads == nullptr) {
        return n00b_result_err(rocs_store_seal_queue_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    for (int32_t i = 0; i < thread_count; i++) {
        auto thread_r = n00b_thread_spawn(rocs_store_seal_queue_thread,
                                          queue);
        if (n00b_result_is_err(thread_r)) {
            n00b_condition_lock(&queue->cv);
            queue->stopping = true;
            n00b_condition_notify(&queue->cv,
                                  .all = true,
                                  .auto_unlock = true);
            for (int32_t j = 0; j < i; j++) {
                n00b_thread_join(queue->threads[j]);
            }
            return n00b_result_err(rocs_store_seal_queue_t *,
                                   N00B_STORE_ERR_INTERNAL);
        }
        queue->threads[i] = n00b_result_get(thread_r);
    }

    return n00b_result_ok(rocs_store_seal_queue_t *, queue);
}

static n00b_result_t(bool)
rocs_store_seal_queue_submit(rocs_store_seal_queue_t *queue,
                             rocs_store_seal_job_t   *job)
{
    if (queue == nullptr || job == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_condition_lock(&queue->cv);
    if (queue->stopping) {
        n00b_condition_unlock(&queue->cv);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    n00b_list_push(*queue->jobs, job);
    n00b_condition_notify(&queue->cv, .auto_unlock = true);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_seal_queue_drain(rocs_store_seal_queue_t *queue)
{
    if (queue == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_condition_lock(&queue->cv);
    while (n00b_list_len(*queue->jobs) != 0 || queue->in_flight != 0) {
        n00b_condition_wait(&queue->cv);
    }
    n00b_condition_unlock(&queue->cv);
    return n00b_result_ok(bool, true);
}

static void
rocs_store_seal_queue_snapshot(rocs_store_seal_queue_t *queue,
                               uint64_t                *pending,
                               uint64_t                *in_flight)
{
    if (pending != nullptr) {
        *pending = 0;
    }
    if (in_flight != nullptr) {
        *in_flight = 0;
    }
    if (queue == nullptr) {
        return;
    }

    n00b_condition_lock(&queue->cv);
    if (pending != nullptr) {
        *pending = (uint64_t)n00b_list_len(*queue->jobs);
    }
    if (in_flight != nullptr) {
        *in_flight = queue->in_flight;
    }
    n00b_condition_unlock(&queue->cv);
}

static void
rocs_store_seal_queue_shutdown(rocs_store_seal_queue_t *queue)
{
    if (queue == nullptr) {
        return;
    }

    n00b_condition_lock(&queue->cv);
    queue->stopping = true;
    n00b_condition_notify(&queue->cv,
                          .all = true,
                          .auto_unlock = true);
    for (int32_t i = 0; i < queue->thread_count; i++) {
        if (queue->threads[i] != nullptr) {
            n00b_thread_join(queue->threads[i]);
            queue->threads[i] = nullptr;
        }
    }
    n00b_condition_destroy(&queue->cv);
}

static uint64_t
rocs_store_hot_visible_count_unlocked(n00b_store_t     *store,
                                      n00b_store_shard_t *hot);

static n00b_result_t(n00b_store_catalog_entry_t *)
rocs_store_seal_hot_shard_unlocked(n00b_store_t  *store,
                                   uint64_t       seal_ts,
                                   uint32_t       base_address,
                                   n00b_allocator_t *allocator,
                                   n00b_string_t *partition_key,
                                   bool           residency_locked,
                                   bool           defer)
    requires {
        ROCS_STORE_CONTRACT_CATALOG_OWNED(store);
        store->hot_shard != nullptr;
        store->next_shard_id != UINT64_MAX;
    }
    ensures {
        n00b_result_is_err(result)
            || n00b_result_value(result) == nullptr
            || ROCS_STORE_CATALOG_ENTRY_CONTRACT_VISIBLE(
                n00b_result_value(result));
    }
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
    n00b_err_t writer_guard = rocs_store_seal_active_writer_guard_unlocked(
        store);
    if (writer_guard != N00B_STORE_OK) {
        return n00b_result_err(n00b_store_catalog_entry_t *, writer_guard);
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
    if (rocs_store_hot_visible_count_unlocked(store, store->hot_shard)
        != old_record_count) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_STATE);
    }
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
    if (!residency_locked && defer && store->seal_queue != nullptr) {
        // ============================================================
        // Async rotate (ingest hot path): the single ingest worker swaps
        // in the next hot shard with no marshal and no per-shard locking,
        // then hands the detached old shard to the seal pool.  A dedicated
        // seal worker marshals it lock-free (it owns the detached shard
        // exclusively) and commits the catalog entry under commit_lock.
        // This is what keeps queue processing from stalling on the marshal.
        // ============================================================
        n00b_store_shard_t *new_hot   = nullptr;
        n00b_allocator_t   *new_alloc = nullptr;
        // Fallible take first (only the no-standby fallback can fail): on
        // failure the old shard stays installed (rollback-safe).
        rocs_store_rotation_lock(store);
        auto take_r = rocs_store_take_next_hot_unlocked(store,
                                                        &new_hot,
                                                        &new_alloc);
        if (n00b_result_is_err(take_r)) {
            rocs_store_rotation_unlock(store);
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(take_r));
        }

        n00b_string_t *entry_partition_copy =
            rocs_store_string_copy(entry_partition, store->allocator);
        if (entry_partition_copy == nullptr) {
            rocs_store_rotation_unlock(store);
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   N00B_STORE_ERR_INTERNAL);
        }

        // Build the seal job from the soon-to-be-detached old shard before
        // the swap, so it captures the old shard's identity, not the new one.
        rocs_store_seal_job_t *job = n00b_alloc(rocs_store_seal_job_t,
                                                .allocator = store->allocator);
        job->store             = store;
        job->old_shard         = old_shard;
        job->old_allocator     = old_hot_allocator;
        job->object_path       = object_path;
        job->entry_partition   = entry_partition_copy;
        job->shard_id          = shard_id;
        job->generation        = store->generation;
        job->schema_generation = store->schema_generation;
        job->record_count      = old_record_count;
        job->seal_ts           = seal_ts;
        job->base_address      = base_address;
#if defined(N00B_ROCS_TRACE)
        job->byte_estimate     = old_byte_estimate;
#else
        job->byte_estimate     = 0;
#endif

        // Drain in-flight readers of the outgoing hot arena before it becomes
        // detached/retired. Locking the pin (a reference change) blocks new pins
        // and spins until current hot_tail_scan_after / hot_record_copy_for_pos
        // readers unpin, so none is mid-read when the seal worker later frees
        // this arena. After the swap, new readers see new_hot and stale-gen reads
        // return none, so the retired arena is reader-free and frees with no lock.
        while (n00b_pinref_lock(&store->hot_pin) == nullptr) {
            ;
        }
        // Infallible swap: new ingest immediately flows into new_hot; old_shard
        // is now detached and owned solely by the seal worker.
        store->hot_shard         = new_hot;
        store->hot_allocator     = new_alloc;
        store->hot_partition_key = r"default";
        rocs_store_hot_visibility_reset(store);
        n00b_pinref_unlock(&store->hot_pin);
        rocs_store_rotation_unlock(store);

        // Rotate the recovery journal in lock-step (finalize old, open new).
        if (store->recovery_journal && !store->recovering) {
            rocs_store_journal_finalize(store);
            (void)rocs_store_journal_open(store, new_hot->shard_id);
        }

        // Submit with commit_lock RELEASED: the pool's submit blocks when the
        // ring is full, and the seal worker needs commit_lock for its commit
        // phase, so holding it here could deadlock against a full ring.  The
        // caller held commit_lock on entry and expects it held on return, so
        // reacquire after the handoff.
        n00b_mutex_unlock(store->commit_lock);
        auto submit_r = rocs_store_seal_queue_submit(store->seal_queue, job);
        n00b_mutex_lock(store->commit_lock);
        if (n00b_result_is_err(submit_r)) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(submit_r));
        }

        // The catalog entry does not exist yet (the seal worker creates it);
        // the only async caller is ingest, which ignores the entry.
        return n00b_result_ok(n00b_store_catalog_entry_t *, nullptr);
    }

    if (!residency_locked) {
        // ---- Phase 1: rotate (commit_lock held) ----------------------
        // Fallible allocations first: a failure here leaves the old shard
        // installed (rollback-safe — nothing has rotated yet).
        // Take the next hot shard: consumes the pristine standby when one is
        // present, else allocates fresh.  Fallible only in the fallback branch;
        // a failure leaves the old shard installed (rollback-safe).
        n00b_store_shard_t *rot_new_hot   = nullptr;
        n00b_allocator_t   *rot_next_alloc = nullptr;
        rocs_store_rotation_lock(store);
        auto rot_take_r = rocs_store_take_next_hot_unlocked(store,
                                                            &rot_new_hot,
                                                            &rot_next_alloc);
        if (n00b_result_is_err(rot_take_r)) {
            rocs_store_rotation_unlock(store);
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   n00b_result_get_err(rot_take_r));
        }

        // Drain in-flight readers of the outgoing hot arena before it detaches
        // (see the async-seal rotation above for the full rationale): the pin
        // lock blocks new pins and waits for current hot readers to unpin.
        while (n00b_pinref_lock(&store->hot_pin) == nullptr) {
            ;
        }
        // Infallible swap: new ingest immediately flows into the fresh shard;
        // old_shard is now detached and exclusively owned by this worker (the
        // commit_lock-guarded swap is the single-owner claim).
        store->hot_shard         = rot_new_hot;
        store->hot_allocator     = rot_next_alloc;
        store->hot_partition_key = r"default";
        rocs_store_hot_visibility_reset(store);
        n00b_pinref_unlock(&store->hot_pin);
        rocs_store_rotation_unlock(store);

        // Rotate the recovery journal in lock-step: finalize (commit + close,
        // keep the file) old_shard's journal and open a fresh one for the new
        // hot shard.  old_shard's journal is retained until Phase 3 confirms the
        // sealed shard is durably committed; on seal failure it stays put as the
        // re-ingest source for the next open.
        if (store->recovery_journal && !store->recovering) {
            rocs_store_journal_finalize(store);
            (void)rocs_store_journal_open(store, rot_new_hot->shard_id);
        }

        n00b_mutex_unlock(store->commit_lock);

        // ---- Phase 2: marshal the detached old shard (NO lock, NO STW) --
        n00b_pool_t       rot_seal_pool  = {};
        n00b_allocator_t *rot_seal_alloc = allocator;
        bool              rot_seal_owned = false;
        if (rot_seal_alloc == nullptr) {
            rot_seal_alloc = n00b_pool_init(&rot_seal_pool,
                                            .hidden            = true,
                                            .external_metadata = true,
                                            .use_epochs        = false,
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
            // Preserve the real shard_seal cause for the failure log below;
            // rot_err stays INTERNAL for the existing control flow / last_err.
            n00b_err_t rot_seal_err = n00b_result_get_err(rot_image_r);
            n00b_eprintf("rocs: rotation seal of shard [|#|] failed at "
                         "shard_seal (cause err=[|#|], record_count=[|#|])\n",
                         old_shard->shard_id,
                         (int64_t)rot_seal_err,
                         old_shard->record_count);
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
        n00b_mutex_lock(store->commit_lock);

        if (rot_err != N00B_STORE_OK) {
            old_shard->state   = old_shard_state;
            old_shard->seal_ts = old_shard_seal_ts;
            rocs_store_seal_job_t failed_job = {
                .store             = store,
                .old_shard         = old_shard,
                .old_allocator     = old_hot_allocator,
                .object_path       = object_path,
                .entry_partition   = entry_partition,
                .shard_id          = shard_id,
                .generation        = store->generation,
                .schema_generation = store->schema_generation,
                .record_count      = old_record_count,
                .seal_ts           = seal_ts,
                .byte_estimate     = old_shard->byte_estimate,
                .base_address      = base_address,
            };
            rocs_store_seal_job_fail_locked(store, &failed_job, rot_err);
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
                                                             store->next_shard_id);
        if (n00b_result_is_err(rot_catalog_r)) {
            (void)n00b_vfs_delete(store->vfs, object_path);
            old_shard->state   = old_shard_state;
            old_shard->seal_ts = old_shard_seal_ts;
            rocs_store_seal_job_t failed_job = {
                .store             = store,
                .old_shard         = old_shard,
                .old_allocator     = old_hot_allocator,
                .object_path       = object_path,
                .entry_partition   = entry_partition,
                .shard_id          = shard_id,
                .generation        = store->generation,
                .schema_generation = store->schema_generation,
                .record_count      = old_record_count,
                .seal_ts           = seal_ts,
                .byte_estimate     = old_shard->byte_estimate,
                .base_address      = base_address,
            };
            rocs_store_seal_job_fail_locked(store,
                                            &failed_job,
                                            n00b_result_get_err(rot_catalog_r));
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
        // Rebuild the standby spare (no-op unless keep_standby) so the next
        // async rotation stays a pure pointer swap.
        rocs_store_replenish_standby(store);
        return n00b_result_ok(n00b_store_catalog_entry_t *, rot_entry);
    }

    n00b_pool_t      seal_pool            = {};
    n00b_allocator_t *seal_allocator      = allocator;
    bool             seal_allocator_owned = false;
    if (seal_allocator == nullptr) {
        seal_allocator = n00b_pool_init(&seal_pool,
                                        .hidden            = true,
                                        .external_metadata = true,
                                        .use_epochs        = false,
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
        .record_count      = old_record_count,
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
        .allocator  = next_hot_allocator,
        .record_cap = store->seal_policy != nullptr
                          ? store->seal_policy->max_records
                          : 0);
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

    rocs_store_rotation_lock(store);
    n00b_list_push(*store->catalog, entry);
    store->hot_shard         = n00b_result_get(shard_r);
    store->hot_allocator     = next_hot_allocator;
    store->hot_partition_key = r"default";
    rocs_store_hot_visibility_reset(store);
    store->next_shard_id     = next_hot_id + 1;
    rocs_store_refresh_oldest_available(store);
    rocs_store_rotation_unlock(store);

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
        *postings->ordinals = n00b_list_new(
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
                   .locked          = true,
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
    if (stored_field == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_ERR_INTERNAL);
    }
    if (n00b_dict_add(shard->columns, stored_field, column)) {
        return n00b_result_ok(n00b_store_column_t *, column);
    }

    column = n00b_dict_get(shard->columns, field, &found);
    if (!found || column == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_ERR_INDEX);
    }
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
    if (postings == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_ERR_INTERNAL);
    }
    if (n00b_dict_add(column, key, postings)) {
        return n00b_result_ok(n00b_store_posting_list_t *, postings);
    }

    postings = n00b_dict_get(column, key, &found);
    if (!found || postings == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_ERR_INDEX);
    }
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

// Append a (field, key) term to the per-record batch list. Despite the name,
// this no longer pre-dedupes the batch list: the prior O(N^2) implementation
// linear-scanned the whole accumulated list (plus a full string compare on the
// field) for every insert, which pinned the ingest worker on records whose
// fulltext/ngram fields expand into thousands of tokens. Uniqueness is enforced
// downstream for free and idempotently — rocs_store_prepare_index_targets_from_terms
// resolves every term through column_get_or_create + column_postings_get_or_create
// (dict lookups keyed by the 128-bit term key), and the ordinal is added via
// rocs_store_posting_list_push_unique, so a duplicate (field, key) lands on the
// same postings entry and the duplicate ordinal is dropped. Carrying a few
// duplicate terms through the batch costs O(1) redundant dict gets each; the
// pre-dedup cost O(N^2). This mirrors the tail-only fix already applied to
// rocs_store_posting_list_contains_ordinal.
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
                            n00b_allocator_t             *allocator) _kargs
{
    bool include_full_value = true;
}
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
            .include_full_value = include_full_value,
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

// The reserved catch-all column name as an n00b string. A direct r"..." literal
// (an r-string macro does not survive preprocessor expansion); its content must
// match N00B_STORE_SEARCH_TEXT_COLUMN.
static inline n00b_string_t *
rocs_store_search_text_column(void)
{
    return r"__n00b_search_text";
}

// Recursively tokenize every string value in a record into the reserved
// full-text catch-all column (N00B_STORE_SEARCH_TEXT_COLUMN). This is what makes
// arbitrary blob content searchable via an unqualified query, without indexing
// each field. Index-only: the column is never materialized in the record body.
static n00b_string_t *
rocs_store_search_child_path(n00b_string_t    *parent,
                             n00b_string_t    *key,
                             n00b_allocator_t *allocator)
{
    if (key == nullptr) {
        return parent;
    }
    if (parent == nullptr || parent->u8_bytes == 0) {
        return key;
    }

    uint64_t plen = (uint64_t)parent->u8_bytes;
    uint64_t klen = (uint64_t)key->u8_bytes;
    if (plen > (uint64_t)INT64_MAX || klen > (uint64_t)INT64_MAX
        || UINT64_MAX - plen < klen + 1
        || plen + klen + 1 > (uint64_t)INT64_MAX) {
        return nullptr;
    }

    char *data = n00b_alloc_array_with_opts(char,
                                            plen + klen + 1,
                                            &(n00b_alloc_opts_t){
                                                .allocator = allocator,
                                                .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                            });
    memcpy(data, parent->data, (size_t)plen);
    data[plen] = '.';
    memcpy(data + plen + 1, key->data, (size_t)klen);
    return n00b_string_from_raw(data,
                                (int64_t)(plen + klen + 1),
                                .allocator = allocator);
}

static n00b_result_t(bool)
rocs_store_append_text_literal_to_column(rocs_store_batch_term_list_t *out,
                                         n00b_string_t                *column,
                                         n00b_string_t                *term,
                                         n00b_allocator_t             *allocator)
{
    if (out == nullptr || column == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    if (term == nullptr || term->data == nullptr || term->u8_bytes == 0) {
        return n00b_result_ok(bool, true);
    }

    n00b_string_t *folded = n00b_unicode_casefold(term, .allocator = allocator);
    if (folded == nullptr || folded->data == nullptr || folded->u8_bytes == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }

    auto key_r = n00b_store_normalize_string_key(N00B_STORE_INDEX_FULLTEXT,
                                                 folded->data,
                                                 (uint64_t)folded->u8_bytes,
                                                 .allocator = allocator);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }

    return rocs_store_batch_term_append_unique(out,
                                               column,
                                               n00b_result_get(key_r),
                                               N00B_STORE_POSTINGS_SPARSE,
                                               .allocator = allocator);
}

static n00b_result_t(bool)
rocs_store_append_search_text_literal(rocs_store_batch_term_list_t *out,
                                      n00b_string_t                *term,
                                      n00b_allocator_t             *allocator)
{
    return rocs_store_append_text_literal_to_column(
        out,
        rocs_store_search_text_column(),
        term,
        allocator);
}

static n00b_result_t(bool)
rocs_store_append_search_text_literals(rocs_store_batch_term_list_t       *out,
                                       n00b_store_search_text_term_list_t *terms,
                                       n00b_allocator_t                   *allocator)
{
    if (terms == nullptr) {
        return n00b_result_ok(bool, true);
    }

    size_t n = n00b_list_len(*terms);
    for (size_t i = 0; i < n; i++) {
        auto append_r = rocs_store_append_search_text_literal(
            out,
            n00b_list_get(*terms, i),
            allocator);
        if (n00b_result_is_err(append_r)) {
            return append_r;
        }
    }
    return n00b_result_ok(bool, true);
}

static bool
rocs_store_schema_index_exact_full_string(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->index_options == nullptr) {
        return true;
    }
    return schema->index_options->exact_full_string;
}

static bool
rocs_store_schema_index_split_terms(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->index_options == nullptr) {
        return true;
    }
    return schema->index_options->split_terms;
}

// Default cap for the exact-full-string search-text term. Comfortably covers
// session IDs / event IDs / refs (tens of bytes) while excluding large content
// blobs (full transcript messages, tool output) from being casefolded/hashed as
// a single whole-value term on the ingest thread. Tokenization still indexes the
// full content, so history stays searchable.
#define N00B_STORE_EXACT_FULL_STRING_MAX_DEFAULT 256u

static uint64_t
rocs_store_schema_exact_full_string_max(n00b_store_schema_t *schema)
{
    if (schema != nullptr && schema->index_options != nullptr
        && schema->index_options->exact_full_string_max_bytes != 0) {
        return schema->index_options->exact_full_string_max_bytes;
    }
    return N00B_STORE_EXACT_FULL_STRING_MAX_DEFAULT;
}

static n00b_result_t(bool)
rocs_store_emit_index_hook_terms(rocs_store_batch_term_list_t *out,
                                 n00b_store_schema_t          *schema,
                                 n00b_string_t                *path,
                                 n00b_json_node_t             *node,
                                 n00b_allocator_t             *allocator)
{
    if (schema == nullptr || schema->index_options == nullptr
        || schema->index_options->term_hook == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_store_index_emit_t emit = {
        .out             = out,
        .owner_allocator = allocator,
        .live            = true,
        .copied_term     = false,
    };

    auto hook_r = schema->index_options->term_hook(
        &emit,
        path,
        node,
        schema->index_options->term_hook_ctx,
        allocator);
    emit.live = false;
    return hook_r;
}

static n00b_result_t(bool)
rocs_store_append_default_search_text(rocs_store_batch_term_list_t *out,
                                      n00b_store_schema_t          *schema,
                                      n00b_json_node_t             *node,
                                      n00b_allocator_t             *allocator)
{
    if (!n00b_json_is_string(node)) {
        return n00b_result_ok(bool, true);
    }

    if (rocs_store_schema_index_exact_full_string(schema)) {
        n00b_string_t *sval = n00b_json_as_string(node);
        uint64_t       cap  = rocs_store_schema_exact_full_string_max(schema);
        // Only index the whole value as one exact term when it is small enough
        // to plausibly be an exact-match target (IDs/refs). Large content is left
        // to tokenization, so we don't casefold/hash a multi-KB blob per record.
        if (sval != nullptr && (uint64_t)sval->u8_bytes <= cap) {
            auto exact_r = rocs_store_append_search_text_literal(out,
                                                                 sval,
                                                                 allocator);
            if (n00b_result_is_err(exact_r)) {
                return exact_r;
            }
        }
    }

    if (!rocs_store_schema_index_split_terms(schema)) {
        return n00b_result_ok(bool, true);
    }

    return rocs_store_append_text_keys(out,
                                       rocs_store_search_text_column(),
                                       N00B_STORE_INDEX_FULLTEXT,
                                       N00B_STORE_POSTINGS_SPARSE,
                                       node,
                                       N00B_STORE_NGRAM_DEFAULT_N,
                                       allocator,
                                       .include_full_value = false);
}

static n00b_result_t(bool)
rocs_store_collect_search_text(rocs_store_batch_term_list_t *out,
                               n00b_store_schema_t          *schema,
                               n00b_json_node_t             *node,
                               n00b_string_t                *path,
                               n00b_allocator_t             *allocator)
{
    if (node == nullptr) {
        return n00b_result_ok(bool, true);
    }
    if (n00b_json_is_string(node)) {
        n00b_store_search_text_action_t action = N00B_STORE_SEARCH_TEXT_DEFAULT;
        n00b_store_search_text_term_list_t *terms = nullptr;
        if (schema != nullptr && schema->search_text_hook != nullptr) {
            action = schema->search_text_hook(path,
                                              n00b_json_as_string(node),
                                              &terms,
                                              schema->search_text_hook_ctx,
                                              allocator);
        }

        switch (action) {
        case N00B_STORE_SEARCH_TEXT_DEFAULT: {
            auto custom_r = rocs_store_append_search_text_literals(out,
                                                                   terms,
                                                                   allocator);
            if (n00b_result_is_err(custom_r)) {
                return custom_r;
            }
            auto hook_r = rocs_store_emit_index_hook_terms(out,
                                                           schema,
                                                           path,
                                                           node,
                                                           allocator);
            if (n00b_result_is_err(hook_r)) {
                return hook_r;
            }
            return rocs_store_append_default_search_text(out,
                                                         schema,
                                                         node,
                                                         allocator);
        }
        case N00B_STORE_SEARCH_TEXT_REPLACE:
        {
            auto custom_r = rocs_store_append_search_text_literals(out,
                                                                   terms,
                                                                   allocator);
            if (n00b_result_is_err(custom_r)) {
                return custom_r;
            }
            return rocs_store_emit_index_hook_terms(out,
                                                   schema,
                                                   path,
                                                   node,
                                                   allocator);
        }
        case N00B_STORE_SEARCH_TEXT_SKIP:
            return n00b_result_ok(bool, true);
        }
        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
    }
    if (n00b_json_is_array(node)) {
        size_t n = n00b_json_array_len(node);
        for (size_t i = 0; i < n; i++) {
            auto r = rocs_store_collect_search_text(out,
                                                    schema,
                                                    n00b_json_array_get(node,
                                                                        i),
                                                    path,
                                                    allocator);
            if (n00b_result_is_err(r)) {
                return r;
            }
        }
        return n00b_result_ok(bool, true);
    }
    if (n00b_json_is_object(node)) {
        auto entries_r = n00b_json_object_entries(node, .allocator = allocator);
        if (n00b_result_is_err(entries_r)) {
            return n00b_result_err(bool, n00b_result_get_err(entries_r));
        }
        n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
        if (entries != nullptr) {
            size_t n = n00b_list_len(*entries);
            for (size_t i = 0; i < n; i++) {
                n00b_json_object_entry_t *e = n00b_list_get(*entries, i);
                if (e == nullptr) {
                    continue;
                }
                n00b_string_t *child_path = path;
                if (schema != nullptr
                    && (schema->search_text_hook != nullptr
                        || (schema->index_options != nullptr
                            && schema->index_options->term_hook != nullptr))) {
                    child_path = rocs_store_search_child_path(path,
                                                             e->key,
                                                             allocator);
                    if (child_path == nullptr) {
                        return n00b_result_err(bool, N00B_STORE_ERR_INDEX);
                    }
                }
                auto r = rocs_store_collect_search_text(out,
                                                        schema,
                                                        e->value,
                                                        child_path,
                                                        allocator);
                if (n00b_result_is_err(r)) {
                    return r;
                }
            }
        }
        return n00b_result_ok(bool, true);
    }
    return n00b_result_ok(bool, true); // number / bool / null: not text
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

    // All term-normalization allocations go through the caller's batch-lifetime
    // allocator. (A prior attempt routed them through a per-batch non-GC scratch
    // arena destroyed before return, to spare the ingest thread GC churn -- but
    // destroying that arena crashed in n00b_epoch_drain_allocator_nodes, so it is
    // reverted to the stable behavior. `ta` is retained as an alias to keep the
    // diff small.)
    n00b_allocator_t *ta  = allocator;
    n00b_err_t        err = (n00b_err_t)N00B_STORE_OK;

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field == nullptr || field->name == nullptr) {
            err = (n00b_err_t)N00B_STORE_ERR_STATE;
            goto done;
        }

        n00b_json_node_t *field_value =
            rocs_json_object_get_field(record,
                                       field->name,
                                       .allocator = ta);
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
                    .allocator = ta);
                if (n00b_result_is_err(terms_r)) {
                    err = (n00b_err_t)N00B_STORE_ERR_INDEX;
                    goto done;
                }

                append_r = rocs_store_append_normalized_terms(
                    out,
                    field->name,
                    field->index_kind,
                    field->postings,
                    n00b_result_get(terms_r),
                    ta);
            }
            else {
                append_r = rocs_store_append_text_keys(out,
                                                       field->name,
                                                       field->index_kind,
                                                       field->postings,
                                                       field_value,
                                                       field->ngram_n,
                                                       ta);
            }
            if (n00b_result_is_err(append_r)) {
                err = n00b_result_get_err(append_r);
                goto done;
            }
        }

        // Schema-derived catch-all: a field opted into include_in_all
        // contributes its string value's full-text tokens under its own field
        // name, so the catch-all index (which lists include_in_all field names
        // as members) can resolve an unqualified n00b_filter_any() contains.
        // This coexists with the reserved whole-record search_text column below.
        if (field->include_in_all && n00b_json_is_string(field_value)) {
            auto append_r = rocs_store_append_text_keys(
                out,
                field->name,
                N00B_STORE_INDEX_FULLTEXT,
                N00B_STORE_POSTINGS_SPARSE,
                field_value,
                field->ngram_n,
                ta,
                .include_full_value = false);
            if (n00b_result_is_err(append_r)) {
                err = n00b_result_get_err(append_r);
                goto done;
            }
        }
    }

    // Reserved full-text catch-all: tokenize every string in the whole record
    // (including non-schema paths like body.*) into the single search_text
    // column. Replaces the old per-field include_in_all fan-out and the wax
    // adapter's injected "search_text" JSON field. Index-only.
    if (store->schema->search_text) {
        auto catch_r = rocs_store_collect_search_text(out,
                                                      store->schema,
                                                      record,
                                                      r"",
                                                      ta);
        if (n00b_result_is_err(catch_r)) {
            err = n00b_result_get_err(catch_r);
            goto done;
        }
    }

done:
    if (err != (n00b_err_t)N00B_STORE_OK) {
        return n00b_result_err(rocs_store_batch_term_list_t *, err);
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
    if (postings == nullptr) {
        return false;
    }
    if (postings->kind == N00B_STORE_POSTINGS_DENSE) {
        if (postings->flags == nullptr) {
            return false;
        }
        bool old = n00b_flagset_test_and_set_index(postings->flags,
                                                   (int64_t)ordinal,
                                                   true);
        return !old;
    }
    if (postings->ordinals == nullptr) {
        return false;
    }

    _n00b_list_write_lock(postings->ordinals);
    size_t len = postings->ordinals->len;
    if (len != 0 && postings->ordinals->data[len - 1] == ordinal) {
        _n00b_list_unlock(postings->ordinals);
        return false;
    }
    _n00b_list_ensure_cap(postings->ordinals, len + 1);
    postings->ordinals->data[postings->ordinals->len++] = ordinal;
    postings->count++;
    _n00b_list_unlock(postings->ordinals);
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

static n00b_string_t *
rocs_store_buffer_hex_string(n00b_buffer_t    *raw,
                             n00b_allocator_t *allocator)
{
    if (raw == nullptr) {
        return nullptr;
    }

    uint64_t raw_len = (uint64_t)n00b_buffer_len(raw);
    if (raw_len > (uint64_t)INT64_MAX / 2
        || raw_len > ((uint64_t)SIZE_MAX - 1) / 2) {
        return nullptr;
    }

    uint64_t hex_len = raw_len * 2;
    char    *hex     = n00b_alloc_array(char,
                                     (int64_t)hex_len + 1,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_NONE);
    if (hex == nullptr) {
        return nullptr;
    }

    _n00b_buffer_rlock(raw);
    for (uint64_t i = 0; i < raw_len; i++) {
        uint8_t c      = ((uint8_t *)raw->data)[i];
        hex[i * 2]     = n00b_hex_map_lower[c >> 4];
        hex[i * 2 + 1] = n00b_hex_map_lower[c & 0x0f];
    }
    _n00b_buffer_unlock(raw);
    hex[hex_len] = 0;

    return n00b_string_from_raw(hex,
                                (int64_t)hex_len,
                                .allocator = allocator);
}

static n00b_result_t(bool)
rocs_store_ingest_source_tombstone(n00b_store_t     *store,
                                   n00b_buffer_t    *source,
                                   n00b_buffer_t    *raw,
                                   n00b_err_t        err,
                                   n00b_allocator_t *allocator)
{
    if (store == nullptr || source == nullptr || allocator == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    if (raw == nullptr) {
        n00b_err_t copy_err = rocs_store_copy_source_raw(source,
                                                        &raw,
                                                        allocator);
        if (copy_err != N00B_STORE_OK) {
            return n00b_result_err(bool, copy_err);
        }
    }

    n00b_json_node_t *record = n00b_json_object_new(.allocator = allocator);
    if (record == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_json_object_put_n00b(
        record,
        r"kind",
        n00b_json_string_new("rocs.ingest_error", .allocator = allocator));
    n00b_json_object_put_n00b(record,
                              r"rocs_tombstone",
                              n00b_json_bool_new(true,
                                                 .allocator = allocator));
    n00b_json_object_put_n00b(record,
                              r"error_code",
                              n00b_json_int_new((int64_t)err,
                                                .allocator = allocator));

    n00b_string_t *source_hex = rocs_store_buffer_hex_string(raw, allocator);
    if (source_hex != nullptr) {
        n00b_json_object_put_n00b(
            record,
            r"source_hex",
            n00b_json_string_new_from_n00b(source_hex,
                                           .allocator = allocator));
    }

    return rocs_store_ingest_common(store, record, raw, true, allocator);
}

static n00b_json_node_t *
rocs_store_reserved_slot_tombstone(n00b_err_t err,
                                   n00b_allocator_t *allocator)
{
    if (allocator == nullptr) {
        return nullptr;
    }

    n00b_json_node_t *record = n00b_json_object_new(.allocator = allocator);
    if (record == nullptr) {
        return nullptr;
    }

    n00b_json_object_put_n00b(
        record,
        r"kind",
        n00b_json_string_new("rocs.ingest_error", .allocator = allocator));
    n00b_json_object_put_n00b(record,
                              r"rocs_tombstone",
                              n00b_json_bool_new(true,
                                                 .allocator = allocator));
    n00b_json_object_put_n00b(record,
                              r"error_code",
                              n00b_json_int_new((int64_t)err,
                                                .allocator = allocator));
    n00b_json_object_put_n00b(
        record,
        r"error_stage",
        n00b_json_string_new("reserved_slot_worker",
                             .allocator = allocator));

    return record;
}

static n00b_result_t(bool)
rocs_store_ingest_buf_decoded(n00b_store_t                 *store,
                              n00b_buffer_t                *source,
                              n00b_store_source_decoder_t   decoder,
                              bool                          index_enabled)
{
    if (store == nullptr || source == nullptr || decoder == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    // Per-record working memory: a transient scratch pool (slab-backed, so
    // resize-heavy JSON building reuses freed slabs rather than thrashing).
    // copy_source_raw, the JSON decode, normalize, and route allocate here
    // via explicit .allocator; the only data that outlives the record is
    // copied OUT by shard_append into the store's hot shard. The pool is
    // destroyed wholesale below. external_metadata=false eliminates the
    // per-allocation dict_untyped put/get; the pool is unregistered. Epoch
    // retirement stays off for this stack-owned pool: retired dict stores can
    // otherwise outlive the pool's stack storage in the thread retire list.
    n00b_pool_t       scratch_pool      = {};
    n00b_allocator_t *scratch_allocator = n00b_pool_init(
        &scratch_pool,
        .hidden            = true,
        .external_metadata = false,
        .use_epochs        = false,
        .name              = "rocs_ingest_decode_scratch");

    // MEASUREMENT (observational, no redirection): mark this thread as inside
    // rocs ingest so the GC-arena allocation counter attributes implicit
    // default-arena bytes to "consumer" vs "other". This does NOT change where
    // anything allocates (no current_allocator override) -- it only tags the
    // allocations for accounting, so it cannot wedge ingest.
    bool prev_ingest = n00b_gc_attrib_enter_ingest();

    // REDIRECTION (the active fix for default-arena transient churn): route the
    // CURRENT allocator to the per-record scratch pool so libn00b intermediates
    // that take no explicit .allocator -- unicode casefold/normalize
    // (casemap.c/normalization.c), JSON parse nodes (json.c), transient strings
    // (string.c) -- land in the scratch pool (freed wholesale below) instead of
    // the default GC arena, where a per-site census showed ~1.5GB of pure churn.
    // SAFE because every PERSISTENT write overrides the current allocator with an
    // explicit shard/store-derived one: shard_append (shard->records/retain_raw
    // allocators), index columns (shard->columns->allocator) + postings
    // (column->allocator), and the seal-triggered hot-shard rotation
    // (standby_allocator / hot_allocator_new).  Restored before the scratch pool
    // is destroyed on every return path below.
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(scratch_allocator);

    n00b_buffer_t *raw = nullptr;
    n00b_err_t     err = rocs_store_copy_source_raw(source,
                                                &raw,
                                                scratch_allocator);
    if (err != N00B_STORE_OK) {
        n00b_gc_attrib_exit_ingest(prev_ingest);
        n00b_restore_current_allocator(prev_alloc);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(bool, err);
    }

    auto record_r = decoder(raw, scratch_allocator);
    if (n00b_result_is_err(record_r)) {
        n00b_err_t decode_err = n00b_result_get_err(record_r);
        n00b_gc_attrib_exit_ingest(prev_ingest);
        n00b_restore_current_allocator(prev_alloc);
        n00b_allocator_destroy(scratch_allocator);
        return n00b_result_err(bool, decode_err);
    }

    auto ingest_r = rocs_store_ingest_common(store,
                                             n00b_result_get(record_r),
                                             raw,
                                             index_enabled,
                                             scratch_allocator);
    n00b_gc_attrib_exit_ingest(prev_ingest);
    n00b_restore_current_allocator(prev_alloc);
    n00b_allocator_destroy(scratch_allocator);
    return ingest_r;
}

static void
rocs_store_batch_prepare_job(rocs_store_batch_job_t *job)
{
    if (job == nullptr || job->store == nullptr) {
        return;
    }

    job->err = N00B_STORE_OK;

    if (job->source != nullptr && job->source_decoder != nullptr) {
        job->err = rocs_store_copy_source_raw(job->source,
                                              &job->raw,
                                              job->allocator);
        if (job->err != N00B_STORE_OK) {
            return;
        }

        auto record_r = job->source_decoder(job->raw, job->allocator);
        if (n00b_result_is_err(record_r)) {
            job->err = n00b_result_get_err(record_r);
            return;
        }
        job->record = n00b_result_get(record_r);
    }
    else if (job->source != nullptr) {
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

    if (job->index_enabled) {
        auto terms_r = rocs_store_build_batch_terms(job->store,
                                                    job->record,
                                                    job->allocator);
        if (n00b_result_is_err(terms_r)) {
            job->err = n00b_result_get_err(terms_r);
            return;
        }
        job->terms = n00b_result_get(terms_r);
    }
    else {
        job->terms = rocs_store_batch_term_list_new(
            .allocator = job->allocator);
    }
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

static uint64_t
rocs_store_hot_visible_count_unlocked(n00b_store_t *store,
                                      n00b_store_shard_t *hot)
{
    if (store == nullptr || hot == nullptr) {
        return 0;
    }
    uint64_t live = n00b_atomic_load(&store->hot_live_index);
    return live < hot->record_count ? live : hot->record_count;
}

static void
rocs_store_hot_visibility_reset(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }
    n00b_atomic_store(&store->hot_live_index, 0);
    if (store->hot_ready == nullptr) {
        store->hot_ready = n00b_flagset_new(.length    = 64,
                                            .allocator = store->allocator);
        return;
    }
    if (store->hot_ready->contents != nullptr
        && store->hot_ready->alloc_wordlen != 0) {
        memset(store->hot_ready->contents,
               0,
               store->hot_ready->alloc_wordlen * sizeof(uint64_t));
    }
    store->hot_ready->num_flags = 64;
}

static n00b_err_t
rocs_store_hot_publish_ordinal_unlocked(n00b_store_t     *store,
                                        n00b_store_shard_t *hot,
                                        uint64_t           ordinal)
{
    if (store == nullptr || hot == nullptr || hot != store->hot_shard) {
        return N00B_STORE_ERR_STATE;
    }
    if (ordinal >= hot->record_count) {
        return N00B_STORE_ERR_STATE;
    }
    uint64_t live = n00b_atomic_load(&store->hot_live_index);
    if (ordinal < live) {
        return N00B_STORE_ERR_STATE;
    }
    if (ordinal > live) {
        n00b_atomic_add(&store->hot_ready_out_of_order_publications, 1);
    }
    if (store->hot_ready == nullptr) {
        store->hot_ready = n00b_flagset_new(.length    = ordinal + 1,
                                            .allocator = store->allocator);
        if (store->hot_ready == nullptr) {
            return N00B_STORE_ERR_INTERNAL;
        }
    }

    n00b_flagset_set_index(store->hot_ready, (int64_t)ordinal, true);

    for (;;) {
        live          = n00b_atomic_load(&store->hot_live_index);
        uint64_t next = live;
        while (next < hot->record_count
               && n00b_flagset_index(store->hot_ready, (int64_t)next)) {
            next++;
        }
        if (next == live) {
            return N00B_STORE_OK;
        }
        uint64_t expected = live;
        if (n00b_atomic_cas(&store->hot_live_index, &expected, next)) {
            return N00B_STORE_OK;
        }
    }
}

static n00b_err_t
rocs_store_hot_writer_begin_unlocked(n00b_store_t *store)
{
    if (store == nullptr || store->hot_shard == nullptr) {
        return N00B_STORE_ERR_STATE;
    }
    n00b_atomic_add(&store->hot_active_writers, 1);
    n00b_atomic_add(&store->hot_writer_reservations, 1);
    return N00B_STORE_OK;
}

static void
rocs_store_hot_writer_end_unlocked(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }
    uint64_t current = n00b_atomic_load(&store->hot_active_writers);
    if (current == 0) {
        return;
    }
    (void)atomic_fetch_sub_explicit(&store->hot_active_writers,
                                    1,
                                    memory_order_acq_rel);
    n00b_atomic_add(&store->hot_writer_completions, 1);
}

static n00b_err_t
rocs_store_seal_active_writer_guard_unlocked(n00b_store_t *store)
{
    if (store == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    if (n00b_atomic_load(&store->hot_active_writers) != 0) {
        n00b_atomic_add(&store->seal_active_writer_waits, 1);
        return N00B_STORE_ERR_STATE;
    }
    return N00B_STORE_OK;
}

static bool
rocs_store_batch_range_candidate_unlocked(n00b_store_t             *store,
                                          rocs_store_batch_job_t  **jobs,
                                          uint64_t                  count)
{
    if (store == nullptr || jobs == nullptr || count == 0
        || store->hot_shard == nullptr) {
        return false;
    }
    if (store->hot_shard->record_count
        != n00b_atomic_load(&store->hot_live_index)) {
        return false;
    }
    if (UINT64_MAX - store->hot_shard->record_count < count) {
        return false;
    }
    if (store->seal_policy != nullptr
        && store->seal_policy->max_records != 0
        && store->hot_shard->record_count + count
               > store->seal_policy->max_records) {
        return false;
    }

    n00b_string_t *route = jobs[0]->route == nullptr ? r"default"
                                                     : jobs[0]->route;
    for (uint64_t i = 1; i < count; i++) {
        n00b_string_t *next = jobs[i]->route == nullptr ? r"default"
                                                        : jobs[i]->route;
        if (!n00b_unicode_str_eq(route, next)) {
            return false;
        }
    }
    if (store->hot_shard->retain_raw != nullptr) {
        for (uint64_t i = 0; i < count; i++) {
            if (jobs[i]->raw == nullptr) {
                return false;
            }
        }
    }

    return true;
}

static n00b_result_t(uint64_t)
rocs_store_ingest_prepared_range_unlocked(
    n00b_store_t                 *store,
    rocs_store_batch_job_t      **jobs,
    uint64_t                      count,
    n00b_allocator_t             *allocator,
    n00b_worker_pool_t           *worker_pool,
    int32_t                       worker_count,
    int32_t                       queue_capacity,
    bool                          reverse_publish)
{
    if (store == nullptr || jobs == nullptr || count == 0
        || store->hot_shard == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_string_t *route = jobs[0]->route == nullptr ? r"default"
                                                     : jobs[0]->route;
    auto route_r = rocs_store_ensure_hot_route_unlocked(store,
                                                        route,
                                                        false);
    if (n00b_result_is_err(route_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(route_r));
    }

    uint64_t begun = 0;
    for (; begun < count; begun++) {
        n00b_err_t writer_err = rocs_store_hot_writer_begin_unlocked(store);
        if (writer_err != N00B_STORE_OK) {
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, writer_err);
        }
    }

    auto reserve_r = n00b_store_shard_reserve(store->hot_shard, count);
    if (n00b_result_is_err(reserve_r)) {
        while (begun != 0) {
            rocs_store_hot_writer_end_unlocked(store);
            begun--;
        }
        n00b_err_t err = n00b_result_get_err(reserve_r);
        return n00b_result_err(uint64_t,
                               err == N00B_STORE_SHARD_ERR_STATE
                                   ? N00B_STORE_ERR_STATE
                                   : N00B_STORE_ERR_ARG);
    }
    uint64_t start = n00b_result_get(reserve_r);

    rocs_store_range_commit_job_t **commit_jobs = n00b_alloc_array(
        rocs_store_range_commit_job_t *,
        (int64_t)count,
        .allocator = allocator);
    if (commit_jobs == nullptr) {
        (void)n00b_store_shard_cancel_tail_reservation(store->hot_shard,
                                                       start,
                                                       count);
        while (begun != 0) {
            rocs_store_hot_writer_end_unlocked(store);
            begun--;
        }
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }

    for (uint64_t i = 0; i < count; i++) {
        rocs_store_range_commit_job_t *job = n00b_alloc(
            rocs_store_range_commit_job_t,
            .allocator = allocator);
        if (job == nullptr) {
            (void)n00b_store_shard_cancel_tail_reservation(store->hot_shard,
                                                           start,
                                                           count);
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
        }
        job->store       = store;
        job->hot         = store->hot_shard;
        job->batch_job   = jobs[i];
        job->raw_span    = nullptr;
        job->prepared    = nullptr;
        job->targets     = nullptr;
        job->byte_delta  = 0;
        job->tombstone   = false;
        job->err         = N00B_STORE_OK;
        if (store->hot_shard->retain_raw != nullptr) {
            auto span_r = n00b_store_shard_reserve_raw_span(store->hot_shard,
                                                            jobs[i]->raw);
            if (n00b_result_is_err(span_r)) {
                (void)n00b_store_shard_cancel_tail_reservation(
                    store->hot_shard,
                    start,
                    count);
                while (begun != 0) {
                    rocs_store_hot_writer_end_unlocked(store);
                    begun--;
                }
                return n00b_result_err(uint64_t, n00b_result_get_err(span_r));
            }
            job->raw_span = n00b_result_get(span_r);
        }
        commit_jobs[i]   = job;
    }

    int32_t workers = worker_count <= 1 ? 1 : worker_count;
    if ((uint64_t)workers > count) {
        workers = (int32_t)count;
    }
    int32_t cap = queue_capacity <= 0 ? workers : queue_capacity;
    if (worker_pool != nullptr) {
        n00b_err_t worker_err = rocs_store_run_service_worker_jobs(
            worker_pool,
            rocs_store_range_prepare_worker,
            (void *const *)commit_jobs,
            count,
            nullptr,
            allocator);
        if (worker_err != N00B_STORE_OK) {
            (void)n00b_store_shard_cancel_tail_reservation(store->hot_shard,
                                                           start,
                                                           count);
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, worker_err);
        }
    }
    else {
        n00b_worker_pool_t *commit_pool = n00b_worker_pool_new(
            workers,
            cap,
            rocs_store_range_prepare_worker,
            nullptr,
            .allocator = allocator);
        if (commit_pool == nullptr) {
            (void)n00b_store_shard_cancel_tail_reservation(store->hot_shard,
                                                           start,
                                                           count);
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
        }
        for (uint64_t i = 0; i < count; i++) {
            n00b_worker_pool_submit(commit_pool, commit_jobs[i]);
        }
        n00b_worker_pool_shutdown(commit_pool);
    }

    uint64_t total_byte_delta = 0;
    for (uint64_t i = 0; i < count; i++) {
        rocs_store_range_commit_job_t *job = commit_jobs[i];
        if (job == nullptr) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
        }
        if (job->prepared == nullptr || job->targets == nullptr
            || job->err != N00B_STORE_OK) {
            n00b_json_node_t *tombstone =
                rocs_store_reserved_slot_tombstone(job->err == N00B_STORE_OK
                                                       ? N00B_STORE_ERR_INTERNAL
                                                       : job->err,
                                                   allocator);
            if (tombstone == nullptr) {
                while (begun != 0) {
                    rocs_store_hot_writer_end_unlocked(store);
                    begun--;
                }
                return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
            }
            auto prepared_r = n00b_store_shard_prepare_reserved_slot(
                store->hot_shard,
                tombstone,
                .raw_span = job->raw_span,
                .allocator = allocator);
            if (n00b_result_is_err(prepared_r)) {
                while (begun != 0) {
                    rocs_store_hot_writer_end_unlocked(store);
                    begun--;
                }
                return n00b_result_err(uint64_t,
                                       n00b_result_get_err(prepared_r));
            }
            job->prepared   = n00b_result_get(prepared_r);
            job->targets    = nullptr;
            job->byte_delta = job->prepared->byte_delta;
            job->tombstone  = true;
            n00b_atomic_add(&store->hot_worker_range_tombstones, 1);
        }
        if (job->prepared == nullptr || job->prepared->record_text == nullptr) {
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
        }
        if (rocs_store_journal_active(store)) {
            n00b_buffer_t *journal_raw = nullptr;
            if (!job->tombstone && job->batch_job != nullptr
                && job->batch_job->raw != nullptr) {
                journal_raw = job->batch_job->raw;
            }
            else {
                journal_raw = rocs_store_buffer_from_record_text(
                    job->prepared->record_text,
                    allocator);
                if (journal_raw == nullptr) {
                    while (begun != 0) {
                        rocs_store_hot_writer_end_unlocked(store);
                        begun--;
                    }
                    return n00b_result_err(uint64_t,
                                           N00B_STORE_ERR_INTERNAL);
                }
            }
            auto journal_r = rocs_store_journal_append(store, journal_raw);
            if (n00b_result_is_err(journal_r)) {
                while (begun != 0) {
                    rocs_store_hot_writer_end_unlocked(store);
                    begun--;
                }
                return n00b_result_err(uint64_t,
                                       n00b_result_get_err(journal_r));
            }
        }
        if (UINT64_MAX - total_byte_delta < job->byte_delta) {
            total_byte_delta = UINT64_MAX;
        }
        else {
            total_byte_delta += job->byte_delta;
        }
    }

    for (uint64_t i = 0; i < count; i++) {
        rocs_store_range_commit_job_t *job = commit_jobs[i];
        auto fill_r = n00b_store_shard_fill_prepared_reserved(
            store->hot_shard,
            start + i,
            job->prepared,
            .account_byte_estimate = false);
        if (n00b_result_is_err(fill_r)) {
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, n00b_result_get_err(fill_r));
        }
        if (job->targets != nullptr) {
            rocs_store_commit_index_targets(job->targets, start + i);
            n00b_atomic_add(&store->hot_worker_range_commits, 1);
        }
    }

    if (UINT64_MAX - store->hot_shard->byte_estimate < total_byte_delta) {
        store->hot_shard->byte_estimate = UINT64_MAX;
    }
    else {
        store->hot_shard->byte_estimate += total_byte_delta;
    }

    for (uint64_t step = 0; step < count; step++) {
        uint64_t i = reverse_publish ? count - 1 - step : step;
        n00b_err_t publish_err = rocs_store_hot_publish_ordinal_unlocked(
            store,
            store->hot_shard,
            start + i);
        if (publish_err != N00B_STORE_OK) {
            while (begun != 0) {
                rocs_store_hot_writer_end_unlocked(store);
                begun--;
            }
            return n00b_result_err(uint64_t, publish_err);
        }
    }

    uint64_t visible = rocs_store_hot_visible_count_unlocked(store,
                                                            store->hot_shard);
    for (uint64_t i = 0; i < count; i++) {
        (void)rocs_store_emit_commit(store,
                                     N00B_STORE_COMMIT_RECORD,
                                     store->hot_shard->shard_id,
                                     start + i,
                                     visible,
                                     0,
                                     store->hot_partition_key);
    }

    while (begun != 0) {
        rocs_store_hot_writer_end_unlocked(store);
        begun--;
    }

    if (!store->recovering && rocs_store_should_seal_hot(store)) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            rocs_store_epoch_ns(),
            0,
            nullptr,
            store->hot_partition_key,
            false,
            true);
        (void)seal_r;
    }

    return n00b_result_ok(uint64_t, count);
}

static void
rocs_store_rotation_lock(n00b_store_t *store)
{
    if (store != nullptr && store->rotation_lock != nullptr) {
        (void)n00b_mutex_lock(store->rotation_lock);
    }
}

static void
rocs_store_rotation_unlock(n00b_store_t *store)
{
    if (store != nullptr && store->rotation_lock != nullptr) {
        (void)n00b_mutex_unlock(store->rotation_lock);
    }
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
        rocs_store_epoch_ns(),
        0,
        nullptr,
        store->hot_partition_key,
        residency_locked,
        // Defer to the seal pool on the ingest hot path (route change); the
        // async branch's own !residency_locked guard makes this a no-op when
        // sealing for close.
        true);
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

    n00b_err_t writer_err = rocs_store_hot_writer_begin_unlocked(store);
    if (writer_err != N00B_STORE_OK) {
        return n00b_result_err(bool, writer_err);
    }

    auto reserve_r = n00b_store_shard_reserve(store->hot_shard, 1);
    if (n00b_result_is_err(reserve_r)) {
        n00b_err_t err = n00b_result_get_err(reserve_r);
        rocs_store_hot_writer_end_unlocked(store);
        return n00b_result_err(bool,
                               err == N00B_STORE_SHARD_ERR_STATE
                                   ? N00B_STORE_ERR_STATE
                                   : N00B_STORE_ERR_ARG);
    }
    uint64_t ordinal = n00b_result_get(reserve_r);

    auto fill_r = n00b_store_shard_fill_reserved(store->hot_shard,
                                                 ordinal,
                                                 record,
                                                 .raw = raw);
    if (n00b_result_is_err(fill_r)) {
        n00b_err_t err = n00b_result_get_err(fill_r);
        (void)n00b_store_shard_cancel_tail_reservation(store->hot_shard,
                                                       ordinal,
                                                       1);
        rocs_store_hot_writer_end_unlocked(store);
        return n00b_result_err(bool,
                               err == N00B_STORE_SHARD_ERR_STATE
                                   ? N00B_STORE_ERR_STATE
                                   : N00B_STORE_ERR_ARG);
    }

    rocs_store_commit_index_targets(targets, ordinal);
    n00b_err_t publish_err =
        rocs_store_hot_publish_ordinal_unlocked(store,
                                                store->hot_shard,
                                                ordinal);
    if (publish_err != N00B_STORE_OK) {
        rocs_store_hot_writer_end_unlocked(store);
        return n00b_result_err(bool, publish_err);
    }
    rocs_store_hot_writer_end_unlocked(store);

    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_RECORD,
                                 store->hot_shard->shard_id,
                                 ordinal,
                                 rocs_store_hot_visible_count_unlocked(
                                     store,
                                     store->hot_shard),
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
        // Ingest hot path: defer the marshal to the seal pool so queue
        // processing never stalls on it.
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            rocs_store_epoch_ns(),
            0,
            nullptr,
            store->hot_partition_key,
            false,
            true);
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

    value = rocs_store_env(prefix, r"ROCS_ROOT", allocator);
    if (value != nullptr) {
        rocs_store_config_set_string(&config->root, value, allocator);
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

n00b_result_t(bool)
n00b_store_config_set_cache_dir(n00b_store_config_t *config,
                                n00b_string_t       *cache_dir)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    rocs_store_config_set_string(&config->cache_dir, cache_dir,
                                 config->allocator);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_config_set_writer_mode(n00b_store_config_t      *config,
                                  n00b_store_writer_mode_t  mode)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (mode != N00B_STORE_WRITER_SINGLE
        && mode != N00B_STORE_WRITER_READ_REPLICA
        && mode != N00B_STORE_WRITER_MULTI_UNSUPPORTED) {
        return n00b_result_err(bool, N00B_STORE_ERR_CONFIG);
    }
    config->writer_mode = mode;
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
    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->commit_topic = topic;
    n00b_mutex_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_store_commit_topic_t *))
n00b_store_commit_topic_for_query(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_commit_topic_t *),
                               N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_commit_topic_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_commit_topic_t *topic = store->commit_topic;
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

    // Reserved full-text catch-all column: an unqualified (n00b_filter_any)
    // query resolves to the catch-all index, which fans out over this one
    // physical column populated at ingest from every record string.
    if (store->schema->search_text) {
        n00b_list_push(*catch_all_fields, rocs_store_search_text_column());
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

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               N00B_STORE_ERR_STATE);
    }

    // Pin the hot arena across the whole hot-index scan; every return unpins.
    // Matches are copied durable positions, so they need no pin once built.
    n00b_pinref_pin(&store->hot_pin);
    n00b_store_shard_t *hot = store->hot_shard;
    uint64_t record_limit = rocs_store_hot_visible_count_unlocked(store, hot);
    if (hot == nullptr || record_limit == 0) {
        n00b_pinref_unpin(&store->hot_pin);
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
        .ordinal    = record_limit - 1,
    };
    if (through != nullptr) {
        if (through->generation != store->generation
            || through->shard_id != hot->shard_id) {
            n00b_pinref_unpin(&store->hot_pin);
            return n00b_result_ok(n00b_store_hot_tail_scan_t, scan);
        }
        if (through->ordinal >= record_limit) {
            n00b_pinref_unpin(&store->hot_pin);
            return n00b_result_err(n00b_store_hot_tail_scan_t,
                                   N00B_STORE_ERR_STATE);
        }

        last         = *through;
        record_limit = through->ordinal + 1;
    }

    uint64_t first_ordinal = 0;
    if (after != nullptr) {
        if (n00b_store_pos_compare(*after, last) >= 0) {
            n00b_pinref_unpin(&store->hot_pin);
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
        n00b_pinref_unpin(&store->hot_pin);
        return n00b_result_err(n00b_store_hot_tail_scan_t,
                               n00b_result_get_err(indexes_r));
    }

    // Pass the schema so the plan can treat a declared-indexed-but-unpopulated
    // field's equality as an empty exact match instead of a full-shard scan.
    auto schema_r = n00b_store_get_schema(store);
    n00b_store_schema_t *schema = n00b_result_is_ok(schema_r)
                                      ? n00b_result_get(schema_r)
                                      : nullptr;
    auto dispatch_r = n00b_plan_dispatch_hot(predicate,
                                             n00b_result_get(indexes_r),
                                             hot,
                                             .allocator = allocator,
                                             .schema    = schema);
    if (n00b_result_is_err(dispatch_r)) {
        n00b_pinref_unpin(&store->hot_pin);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(dispatch_r)));
    }

    auto ordinals_r = n00b_plan_dispatch_verify_hot(
        n00b_result_get(dispatch_r),
        hot,
        .allocator = allocator);
    if (n00b_result_is_err(ordinals_r)) {
        n00b_pinref_unpin(&store->hot_pin);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(ordinals_r)));
    }

    n00b_plan_ordset_t *ordinals = n00b_result_get(ordinals_r);
    auto count_r = n00b_plan_ordset_count(ordinals);
    if (n00b_result_is_err(count_r)) {
        n00b_pinref_unpin(&store->hot_pin);
        return n00b_result_err(
            n00b_store_hot_tail_scan_t,
            rocs_store_err_from_plan(n00b_result_get_err(count_r)));
    }

    uint64_t ordinal_count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < ordinal_count; i++) {
        auto ordinal_r = n00b_plan_ordset_at(ordinals, i);
        if (n00b_result_is_err(ordinal_r)) {
            n00b_pinref_unpin(&store->hot_pin);
            return n00b_result_err(
                n00b_store_hot_tail_scan_t,
                rocs_store_err_from_plan(n00b_result_get_err(ordinal_r)));
        }

        n00b_option_t(uint64_t) ordinal_opt = n00b_result_get(ordinal_r);
        if (!n00b_option_is_set(ordinal_opt)) {
            n00b_pinref_unpin(&store->hot_pin);
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

    n00b_pinref_unpin(&store->hot_pin);
    scan.has_last_observed = true;
    scan.last_observed     = last;
    scan.scanned_records   = record_limit - first_ordinal;
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

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_STATE);
    }

    n00b_store_shard_t *hot = store->hot_shard;
    if (hot == nullptr
        || pos.generation != store->generation
        || pos.shard_id != hot->shard_id
        || pos.ordinal >= rocs_store_hot_visible_count_unlocked(store, hot)) {
        return n00b_result_ok(
            n00b_option_t(n00b_store_record_t *),
            n00b_option_none(n00b_store_record_t *));
    }

    auto record_r = n00b_store_record_view_hot_pos(hot,
                                                   pos,
                                                   .allocator = allocator);
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

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_STATE);
    }

    // Pin the hot arena so the seal/retire path drains this reader before
    // munmapping it; unpin on every exit and once the JSON is copied out.
    n00b_pinref_pin(&store->hot_pin);
    n00b_store_shard_t *hot = store->hot_shard;
    if (hot == nullptr
        || pos.generation != store->generation
        || pos.shard_id != hot->shard_id
        || pos.ordinal >= rocs_store_hot_visible_count_unlocked(store, hot)) {
        n00b_pinref_unpin(&store->hot_pin);
        return n00b_result_ok(
            n00b_option_t(n00b_store_record_t *),
            n00b_option_none(n00b_store_record_t *));
    }

    auto record_r = n00b_store_record_view_hot_pos(hot,
                                                   pos,
                                                   .allocator = allocator);
    if (n00b_result_is_err(record_r)) {
        n00b_pinref_unpin(&store->hot_pin);
        n00b_err_t err = n00b_result_get_err(record_r);
        return n00b_result_err(
            n00b_option_t(n00b_store_record_t *),
            err == N00B_STORE_INDEX_ERR_ARG ? N00B_STORE_ERR_ARG
                                            : N00B_STORE_ERR_INDEX);
    }

    auto json_r = n00b_store_record_view_json_copy(
        n00b_result_get(record_r),
        .allocator = allocator);
    // Arena access done -- JSON graph is copied out independently now.
    n00b_pinref_unpin(&store->hot_pin);
    if (n00b_result_is_err(json_r)) {
        return n00b_result_err(n00b_option_t(n00b_store_record_t *),
                               N00B_STORE_ERR_INDEX);
    }

    auto owned_r = n00b_store_record_view_owned_json(
        pos,
        n00b_result_get(json_r),
        .allocator = allocator);
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
    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->lifecycle_topic = topic;
    n00b_mutex_unlock(store->commit_lock);
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
n00b_store_ingest_payload_record(n00b_json_node_t *record) _kargs
{
    bool index = true;
}
{
    if (record == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        ((n00b_store_ingest_payload_t){
            .value = n00b_variant_set(n00b_store_ingest_payload_value_t,
                                      n00b_json_node_t *,
                                      record),
            .index_enabled = index,
        }));
}

n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_source(n00b_buffer_t *source) _kargs
{
    bool index = true;
}
{
    if (source == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        ((n00b_store_ingest_payload_t){
            .value = n00b_variant_set(n00b_store_ingest_payload_value_t,
                                      n00b_buffer_t *,
                                      source),
            .index_enabled = index,
        }));
}

static void
rocs_store_ingest_topic_admission_state(n00b_store_ingest_topic_t *topic,
                                        bool                      *has_active,
                                        bool                      *full)
{
    if (has_active != nullptr) {
        *has_active = false;
    }
    if (full != nullptr) {
        *full = false;
    }
    if (topic == nullptr) {
        return;
    }

    _n00b_list_read_lock(&topic->subscriptions);
    for (size_t i = 0; i < topic->subscriptions.len; i++) {
        n00b_conduit_subscription_t(n00b_store_ingest_payload_t) *sub =
            topic->subscriptions.data[i];
        if (sub == nullptr
            || n00b_atomic_load(&sub->state) != N00B_CONDUIT_SUB_ACTIVE) {
            continue;
        }
        if (has_active != nullptr) {
            *has_active = true;
        }
        if (sub->inbox != nullptr
            && n00b_conduit_inbox_full(n00b_store_ingest_payload_t,
                                       sub->inbox)) {
            if (full != nullptr) {
                *full = true;
            }
            break;
        }
    }
    _n00b_list_unlock(&topic->subscriptions);
}

n00b_result_t(bool)
n00b_store_ingest_topic_publish_ex(n00b_store_ingest_topic_t   *topic,
                                   n00b_store_ingest_payload_t  payload) _kargs
{
    n00b_store_ingest_backpressure_t backpressure =
        N00B_STORE_INGEST_BACKPRESSURE_BLOCK;
}
{
    if (topic == nullptr
        || !N00B_STORE_INGEST_BACKPRESSURE_CONTRACT_VALID(backpressure)) {
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

    while (true) {
        if (!n00b_conduit_topic_is_active(base)) {
            n00b_conduit_publish_yield(pub);
            return n00b_result_err(bool, N00B_STORE_ERR_STATE);
        }

        bool has_active = false;
        bool full       = false;
        rocs_store_ingest_topic_admission_state(topic, &has_active, &full);
        if (!has_active) {
            n00b_conduit_publish_yield(pub);
            return n00b_result_err(bool, N00B_STORE_ERR_STATE);
        }
        if (!full) {
            break;
        }
        if (backpressure == N00B_STORE_INGEST_BACKPRESSURE_REJECT) {
            n00b_conduit_publish_yield(pub);
            return n00b_result_err(bool, N00B_STORE_ERR_STATE);
        }

        base_nanosleep_ns(1ULL * N00B_NS_PER_MS);
    }

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

n00b_result_t(bool)
n00b_store_ingest_topic_publish(n00b_store_ingest_topic_t   *topic,
                                n00b_store_ingest_payload_t  payload)
{
    return n00b_store_ingest_topic_publish_ex(
        topic,
        payload,
        .backpressure = N00B_STORE_INGEST_BACKPRESSURE_BLOCK);
}

n00b_result_t(n00b_store_schema_t *)
n00b_store_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
    bool                          search_text = false;
    n00b_store_search_text_hook_t search_text_hook = nullptr;
    void                         *search_text_hook_ctx = nullptr;
    n00b_store_index_options_t   *index_options = nullptr;
}
{
    n00b_store_schema_t *schema = n00b_alloc_with_opts(
        n00b_store_schema_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    schema->fields               = rocs_store_field_list_new(.allocator = allocator);
    schema->allocator            = allocator;
    schema->frozen               = false;
    schema->search_text          = search_text;
    schema->search_text_hook     = search_text_hook;
    schema->search_text_hook_ctx = search_text_hook_ctx;
    schema->index_options        = index_options;
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
    // The full-text catch-all column name is reserved; it is not a user field.
    if (n00b_unicode_str_eq(name, rocs_store_search_text_column())) {
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
    uint64_t          max_sealed_shards     = 0;
    uint64_t          max_total_sealed_bytes = 0;
    uint64_t          drop_before_seal_ts   = 0;
    uint64_t          min_seal_ts           = 0;
    n00b_string_t    *drop_reason           = nullptr;
    n00b_allocator_t *allocator             = nullptr;
}
{
    if (max_sealed_shards == 0 && max_total_sealed_bytes == 0
        && drop_before_seal_ts == 0) {
        return n00b_result_err(n00b_store_shard_retention_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_shard_retention_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_shard_retention_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    policy->max_sealed_shards      = max_sealed_shards;
    policy->max_total_sealed_bytes = max_total_sealed_bytes;
    policy->drop_before_seal_ts    = drop_before_seal_ts;
    policy->min_seal_ts            = min_seal_ts;
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
        .validate_on_open     = true,
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
        .use_epochs        = false,
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
        .allocator  = recovery_alloc,
        .record_cap = store->seal_policy != nullptr
                          ? store->seal_policy->max_records
                          : 0);
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
    uint64_t            saved_live_index =
        n00b_atomic_load(&store->hot_live_index);
    n00b_flagset_t     *saved_ready = store->hot_ready;
    store->hot_shard         = recovery_shard;
    store->hot_allocator     = recovery_alloc;
    store->hot_partition_key = r"default";
    store->hot_ready         = nullptr;
    rocs_store_hot_visibility_reset(store);
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

    n00b_string_t  *recovered_pk    = store->hot_partition_key;
    n00b_flagset_t *recovery_ready  = store->hot_ready;

    // Restore the (still-null, pre-hot-shard) store state before sealing.
    store->hot_shard         = saved_hot;
    store->hot_allocator     = saved_alloc;
    store->hot_partition_key = saved_pk;
    n00b_atomic_store(&store->hot_live_index, saved_live_index);
    store->hot_ready         = saved_ready;
    store->recovering        = false;
    if (recovery_ready != nullptr && recovery_ready != saved_ready) {
        n00b_free(recovery_ready->contents);
        n00b_free(recovery_ready);
    }

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

    uint64_t seal_ts = rocs_store_epoch_ns();
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

    rocs_store_free_dir_listing(list);
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
    bool                           keep_standby     = false;
    uint64_t                       seal_worker_count = 1;
    // Retention is opt-in: a raw store (unit tests, tools, ad-hoc opens) does
    // NOT auto-drop sealed shards. Deployments that want it (e.g. wax = 60 days)
    // pass an explicit window/byte budget. See N00B_STORE_DEFAULT_RETENTION_NS.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
    n00b_allocator_t              *allocator        = nullptr;
}
{
    if (vfs == nullptr || schema == nullptr || schema->fields == nullptr
        || !rocs_store_root_valid(root)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_ARG);
    }
    if (keep_standby && seal_worker_count > (uint64_t)INT32_MAX) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_CONFIG);
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
    n00b_atomic_store(&store->hot_live_index, 0);
    store->hot_ready         = nullptr;
    store->catalog          = rocs_store_catalog_list_new(.allocator = allocator);
    store->allocator        = allocator;
    // Locks must live in the non-moving system pool, never the (movable) store
    // allocator: a relocated mutex leaves any thread parked on its futex waiting
    // on a stale address, and the GC's thread-lock-chain scan then dereferences
    // the moved-out slot -> SIGSEGV in n00b_visit_possible_pointer.
    n00b_allocator_t *lock_pool = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
    store->residency_lock   = n00b_alloc_with_opts(
        n00b_mutex_t,
        &(n00b_alloc_opts_t){
            .allocator = lock_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    if (store->residency_lock != nullptr) {
        n00b_mutex_init(store->residency_lock);
    }
    store->commit_lock      = n00b_alloc_with_opts(
        n00b_mutex_t,
        &(n00b_alloc_opts_t){
            .allocator = lock_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    if (store->commit_lock != nullptr) {
        n00b_mutex_init(store->commit_lock);
    }
    n00b_pinref_init(&store->hot_pin, store);
    store->rotation_lock    = n00b_alloc_with_opts(
        n00b_mutex_t,
        &(n00b_alloc_opts_t){
            .allocator = lock_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    if (store->rotation_lock != nullptr) {
        n00b_mutex_init(store->rotation_lock);
    }
    store->seal_queue         = nullptr;
    store->seal_worker_count  = 0;
    store->keep_standby       = keep_standby;
    store->retention_window_ns         = retention_window_ns;
    store->retention_max_sealed_shards = retention_max_sealed_shards;
    store->retention_max_total_bytes   = retention_max_total_bytes;
    store->standby_shard      = nullptr;
    store->standby_allocator  = nullptr;
    store->service_profile    = nullptr;
    store->service_conduit    = nullptr;
    store->service_ingest_topic = nullptr;
    store->service_ingest     = nullptr;
    store->state            = N00B_STORE_STATE_OPEN;
    store->read_only        = false;
    store->recovery_journal = recovery_journal;
    store->recovering       = false;
    store->journal_fh       = N00B_VFS_FH_INVALID;
    store->journal_shard_id = 0;
    store->journal_path     = nullptr;
    store->journal_unsynced = 0;
    store->next_shard_id    = 2;
    store->generation       = 0;
    store->schema_generation = 0;
    store->oldest_available = (n00b_store_pos_t){};
    store->has_oldest_available = false;
    n00b_atomic_store(&store->hot_live_index, 0);
    rocs_store_hot_visibility_reset(store);
    n00b_atomic_store(&store->hot_active_writers, 0);
    n00b_atomic_store(&store->hot_writer_reservations, 0);
    n00b_atomic_store(&store->hot_writer_completions, 0);
    n00b_atomic_store(&store->hot_ready_out_of_order_publications, 0);
    n00b_atomic_store(&store->hot_worker_range_commits, 0);
    n00b_atomic_store(&store->hot_worker_range_tombstones, 0);
    n00b_atomic_store(&store->seal_active_writer_waits, 0);
    store->active_pins       = 0;
    store->active_pin_handles =
        rocs_store_pin_list_new(.allocator = allocator);
    store->active_record_streams =
        rocs_store_record_stream_list_new(.allocator = allocator);
    store->hot_snapshot_pins = 0;
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
        .allocator  = store->hot_allocator,
        .record_cap = store->seal_policy != nullptr
                          ? store->seal_policy->max_records
                          : 0);
    if (n00b_result_is_err(shard_r)) {
        rocs_store_hot_allocator_destroy(store, store->hot_allocator, 0);
        store->hot_allocator = nullptr;
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(shard_r));
    }
    store->hot_shard = n00b_result_get(shard_r);
    rocs_store_hot_visibility_reset(store);

    auto recover_r = rocs_store_recover_orphaned_shards(store);
    if (n00b_result_is_err(recover_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(recover_r));
    }

    // Retention is a catalog/store invariant, not only a post-seal cleanup.
    // Applying it on open catches old stores, bad legacy seal_ts values, and
    // orphaned shard objects recovered above even if the daemon stays mostly idle.
    rocs_store_apply_default_retention(store);

    // Open the write-ahead journal for the live hot shard.  Best-effort: if it
    // fails, ingest still proceeds (just without journal-backed recovery for
    // this shard) until the next rotation reopens one.
    if (store->recovery_journal) {
        (void)rocs_store_journal_open(store, hot_shard_id);
    }

    // Async-seal machinery (opt-in): a dedicated seal-worker queue plus a
    // pre-built standby shard, so the ingest worker rotates with a pure pointer
    // swap and hands the marshal off the hot path. Off => every seal stays
    // inline (unchanged for all other stores). Safe to build without commit_lock
    // here: the store is not published yet and no seal worker has any work to
    // run.
    if (store->keep_standby) {
        uint64_t configured_seal_workers = seal_worker_count == 0
                                               ? 1
                                               : seal_worker_count;
        store->seal_worker_count = (int32_t)configured_seal_workers;
        auto seal_queue_r = rocs_store_seal_queue_new(store,
                                                      store->seal_worker_count,
                                                      store->allocator);
        if (n00b_result_is_err(seal_queue_r)) {
            return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_INTERNAL);
        }
        store->seal_queue = n00b_result_get(seal_queue_r);
        rocs_store_replenish_standby(store);
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
    // Retention is opt-in (default 0 = disabled). Callers that want automatic
    // shard retention (e.g. wax = 60 days) pass an explicit window/byte budget.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
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
                ? N00B_STORE_IMAGE_AUTO
                : N00B_STORE_IMAGE_PINNED_BUFFER,
        .max_resident_bytes      = config->resident_bytes,
        .max_resident_shards     = (uint32_t)config->resident_shards,
        .idle_ns                 = 0,
        .prefetch_pruned_shards  = false,
        .allow_direct_mmap       =
            config->profile == N00B_STORE_PROFILE_SERVICE_LOCAL,
        .validate_on_open        =
            config->profile != N00B_STORE_PROFILE_SERVICE_LOCAL,
    };

    auto store_r = n00b_store_open_vfs(n00b_result_get(vfs_r),
                                       config->root,
                                       schema,
                                       .partition_policy = partition_policy,
                                       .seal_policy      = seal_policy,
                                       .cache            = cache,
                                       .residency_policy = &residency,
                                       .display_name     = config->name,
                                       .retention_window_ns = retention_window_ns,
                                       .retention_max_sealed_shards =
                                           retention_max_sealed_shards,
                                       .retention_max_total_bytes =
                                           retention_max_total_bytes,
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
    // Flush is a durability barrier: any detached shard handed to the async
    // sealer before this call must have its catalog entry committed before
    // flush returns. Drain the explicit ROCS seal queue rather than injecting a
    // control job or asking the worker pool to prove every worker is idle.
    auto drain_r = rocs_store_seal_queue_drain(store->seal_queue);
    if (n00b_result_is_err(drain_r)) {
        return n00b_result_err(bool, n00b_result_get_err(drain_r));
    }
    auto retry_failed_r = rocs_store_retry_failed_seal_jobs_once(store);
    if (n00b_result_is_err(retry_failed_r)) {
        return n00b_result_err(bool, n00b_result_get_err(retry_failed_r));
    }
    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->read_only) {
        n00b_mutex_unlock(store->commit_lock);
        rocs_store_try_reclaim_retired_hot_allocators(store);
        return n00b_result_ok(bool, true);
    }

    if (store->hot_shard != nullptr && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            rocs_store_epoch_ns(),
            0,
            nullptr,
            store->hot_partition_key,
            false,
            false);
        if (n00b_result_is_err(seal_r)) {
            n00b_mutex_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
        n00b_mutex_unlock(store->commit_lock);
        rocs_store_try_reclaim_retired_hot_allocators(store);
        return n00b_result_ok(bool, true);
    }

    auto write_r = rocs_store_catalog_write(store);
    n00b_mutex_unlock(store->commit_lock);
    if (n00b_result_is_ok(write_r)) {
        rocs_store_try_reclaim_retired_hot_allocators(store);
    }
    return write_r;
}

n00b_result_t(bool)
n00b_store_close(n00b_store_t *store)
    requires {
        store != nullptr;
    }
    ensures {
        n00b_result_is_err(result)
            || n00b_result_value(result) == true;
        n00b_result_is_err(result)
            || store->state == N00B_STORE_STATE_CLOSED;
    }
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (store->service_ingest != nullptr) {
        auto service_close_r =
            n00b_store_conduit_ingest_close(store->service_ingest);
        if (n00b_result_is_err(service_close_r)) {
            return n00b_result_err(bool, n00b_result_get_err(service_close_r));
        }
        store->service_ingest       = nullptr;
        store->service_ingest_topic = nullptr;
    }
    // Close is teardown, so joining the seal workers is appropriate.  Do it
    // before taking commit_lock because an in-flight seal worker needs that
    // lock for its catalog commit phase.
    if (store->seal_queue != nullptr) {
        rocs_store_seal_queue_shutdown(store->seal_queue);
        store->seal_queue        = nullptr;
        store->seal_worker_count = 0;
    }
    if (!store->read_only) {
        auto retry_failed_r = rocs_store_retry_failed_seal_jobs_once(store);
        if (n00b_result_is_err(retry_failed_r)) {
            return n00b_result_err(bool, n00b_result_get_err(retry_failed_r));
        }
    }
    n00b_mutex_lock(store->commit_lock);
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins != 0) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    if (!store->read_only && store->hot_shard != nullptr
        && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            rocs_store_epoch_ns(),
            0,
            nullptr,
            store->hot_partition_key,
            true,
            false);
        if (n00b_result_is_err(seal_r)) {
            n00b_mutex_unlock(store->residency_lock);
            n00b_mutex_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
    }
    else if (!store->read_only) {
        auto catalog_r = rocs_store_catalog_write(store);
        if (n00b_result_is_err(catalog_r)) {
            n00b_mutex_unlock(store->residency_lock);
            n00b_mutex_unlock(store->commit_lock);
            return catalog_r;
        }
    }

    auto unload_r = rocs_store_resident_unload_all_unpinned(store);
    if (n00b_result_is_err(unload_r)) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
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

    // The seal queue was joined before taking commit_lock.
    n00b_allocator_t *standby_allocator = store->standby_allocator;
    store->standby_shard     = nullptr;
    store->standby_allocator = nullptr;

    rocs_store_retired_hot_allocator_list_t *retired =
        rocs_store_detach_retired_hot_allocators_locked(store);
    rocs_store_catalog_list_t *failed_seals =
        rocs_store_detach_failed_seal_jobs_locked(store);
    n00b_allocator_t *current_hot_allocator = store->hot_allocator;
    uint64_t          current_hot_records =
        store->hot_shard == nullptr ? 0 : store->hot_shard->record_count;
    store->hot_allocator = nullptr;
    store->hot_shard     = nullptr;
    rocs_store_hot_visibility_reset(store);
    n00b_atomic_store(&store->hot_active_writers, 0);
    store->state = N00B_STORE_STATE_CLOSED;
    n00b_mutex_unlock(store->residency_lock);
    n00b_mutex_unlock(store->commit_lock);

    rocs_store_destroy_retired_hot_allocators(store, retired);
    rocs_store_destroy_failed_seal_jobs(store, failed_seals);
    if (current_hot_allocator != nullptr) {
        rocs_store_hot_allocator_destroy(store,
                                         current_hot_allocator,
                                         current_hot_records);
    }
    // The standby is a pristine, never-written empty shard, so it has no records
    // to drop.
    if (standby_allocator != nullptr) {
        rocs_store_hot_allocator_destroy(store, standby_allocator, 0);
    }
    if (store->service_conduit != nullptr) {
        n00b_conduit_destroy(store->service_conduit);
        store->service_conduit = nullptr;
    }
    store->service_profile = nullptr;
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_state_t)
n00b_store_get_state(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_state_t, N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(store->residency_lock);
    n00b_store_state_t state = store->state;
    n00b_mutex_unlock(store->residency_lock);
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
    // Default seal_ts to epoch wall-clock so retention/as_of compare on the same
    // clock as record ts_ns (a caller may still pass an explicit value).
    if (seal_ts == 0) {
        seal_ts = rocs_store_epoch_ns();
    }

    n00b_mutex_lock(store->commit_lock);
    auto seal_r = rocs_store_seal_hot_shard_unlocked(store,
                                                     seal_ts,
                                                     base_address,
                                                     allocator,
                                                     store->hot_partition_key,
                                                     false,
                                                     false);
    n00b_mutex_unlock(store->commit_lock);
    if (n00b_result_is_ok(seal_r)) {
        rocs_store_apply_default_retention(store);
    }
    return seal_r;
}

n00b_result_t(bool)
n00b_store_apply_event_time_watermark(n00b_store_t *store,
                                      uint64_t      watermark_ts)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN
        || store->hot_shard == nullptr
        || store->partition_policy == nullptr) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->partition_policy->kind != N00B_STORE_PARTITION_TIME
        || store->partition_policy->bucket_width == 0) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_POLICY);
    }
    if (store->hot_shard->record_count == 0) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    n00b_option_t(uint64_t) bucket_opt =
        rocs_store_time_bucket_from_route(store->hot_partition_key);
    if (!n00b_option_is_set(bucket_opt)) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    uint64_t bucket = n00b_option_get(bucket_opt);
    if (watermark_ts / store->partition_policy->bucket_width <= bucket) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    auto seal_r = rocs_store_seal_hot_shard_unlocked(
        store,
        rocs_store_epoch_ns(),
        0,
        nullptr,
        store->hot_partition_key,
        false,
        false);
    if (n00b_result_is_err(seal_r)) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(seal_r));
    }

    n00b_mutex_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_ingest_common(n00b_store_t     *store,
                         n00b_json_node_t *record,
                         n00b_buffer_t    *raw,
                         bool              index_enabled,
                         n00b_allocator_t *allocator)
{
    if (store == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_err_t preflight = rocs_store_preflight_ingest(store,
                                                       record,
                                                       raw,
                                                       allocator);
    if (preflight != N00B_STORE_OK) {
        return n00b_result_err(bool, preflight);
    }

    auto route_r = n00b_store_partition_route(store->partition_policy,
                                              record,
                                              .allocator = allocator);
    if (n00b_result_is_err(route_r)) {
        return n00b_result_err(bool, n00b_result_get_err(route_r));
    }
    n00b_string_t *route = n00b_result_get(route_r);
    if (route == nullptr) {
        route = r"default";
    }

    rocs_store_batch_term_list_t *terms = nullptr;
    if (index_enabled) {
        auto terms_r = rocs_store_build_batch_terms(store, record, allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(bool, n00b_result_get_err(terms_r));
        }
        terms = n00b_result_get(terms_r);
    }
    else {
        terms = rocs_store_batch_term_list_new(.allocator = allocator);
    }

    n00b_mutex_lock(store->commit_lock);

    // Recheck cheap state/required-field predicates after taking the commit
    // lock.  Expensive index term construction above reads immutable schema and
    // stays out of the lock so status/query readers are not blocked behind
    // Unicode normalization.
    preflight = rocs_store_preflight_ingest(store,
                                           record,
                                           raw,
                                           allocator);
    if (preflight != N00B_STORE_OK) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, preflight);
    }

    uint64_t failed_seals_before = rocs_store_failed_seal_job_count(store);
    auto     ingest_r            = rocs_store_ingest_prepared_unlocked(store,
                                                        record,
                                                        raw,
                                                        route,
                                                        terms,
                                                        allocator);
    // A size-triggered auto-seal inside ingest can fail after the record is
    // accepted into the old hot shard. Surface that as a durability failure
    // instead of reporting an Ok while the shard is only retained for retry.
    if (rocs_store_failed_seal_job_count(store) != failed_seals_before) {
        n00b_err_t seal_err = rocs_store_failed_seal_last_error(store);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, seal_err);
    }
    n00b_mutex_unlock(store->commit_lock);
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
                       .use_epochs        = false,
                       .name              = "rocs_ingest_scratch");
    auto ingest_r =
        rocs_store_ingest_common(store,
                                 record,
                                 nullptr,
                                 true,
                                 scratch_allocator);
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
                       .use_epochs        = false,
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
                                             true,
                                             scratch_allocator);
    n00b_allocator_destroy(scratch_allocator);
    return ingest_r;
}

static n00b_result_t(uint64_t)
rocs_store_ingest_batch_common(n00b_store_t             *store,
                               n00b_store_record_list_t *records,
                               n00b_store_source_list_t *sources,
                               n00b_store_source_decoder_t source_decoder,
                               n00b_worker_pool_t       *worker_pool,
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
    if (count == 0) {
        return n00b_result_ok(uint64_t, 0);
    }
    int32_t workers = worker_count <= 1 ? 1 : worker_count;
    if ((uint64_t)workers > count) {
        workers = (int32_t)count;
    }
    int32_t prep_queue_capacity = queue_capacity <= 0 ? workers
                                                      : queue_capacity;
    bool parallel_prepare = workers > 1;

    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = false,
                       .use_epochs        = false,
                       .name              = "rocs_batch_ingest_scratch");
    // Parallel prepare runs each record's prep on a worker whose OWN per-worker
    // bump arena is its current_allocator (job->allocator == nullptr); those
    // arenas hold the prepared data through the append loop and are reset/torn
    // down at the batch boundary -- bounded to `workers`, NEVER a pool-per-record
    // (which would blow the arena audit ring + churn the global mmap registry).
    // A caller may pass a persistent worker_pool; otherwise we spin up a
    // transient one (owned here, shut down at ROCS_BATCH_RETURN). The serial
    // path (workers == 1) prepares straight into scratch_allocator above.
    n00b_worker_pool_t *prep_pool       = worker_pool;
    bool                owned_prep_pool = false;
    if (parallel_prepare && prep_pool == nullptr) {
        // Transient prepare pool: workers allocate each record's prepared data
        // from the shared scratch pool (job->allocator == scratch_allocator),
        // so no worker_scratch_arena and NO pool-per-record.
        prep_pool = n00b_worker_pool_new(workers,
                                         prep_queue_capacity,
                                         rocs_store_service_pool_worker,
                                         nullptr,
                                         .allocator = scratch_allocator);
        if (prep_pool == nullptr) {
            n00b_allocator_destroy(scratch_allocator);
            return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
        }
        owned_prep_pool = true;
    }

#define ROCS_BATCH_RETURN(_expr)                                      \
    do {                                                              \
        n00b_result_t(uint64_t) _rocs_batch_ret = (_expr);            \
        /* A transient pool we created is shut down (frees its per-worker       \
         * arenas); a caller-owned persistent pool just has its arenas reset for \
         * the next batch (no-op for a null pool). Safe here: every              \
         * ROCS_BATCH_RETURN site is pre-dispatch or post-latch, and the single  \
         * conduit loop thread means no concurrent batch is in flight. */        \
        if (owned_prep_pool) {                                        \
            n00b_worker_pool_shutdown(prep_pool);                     \
        }                                                             \
        else {                                                        \
            n00b_worker_pool_reset_scratch(prep_pool);                \
        }                                                             \
        n00b_gc_attrib_exit_ingest(prev_ingest);                      \
        if (alloc_redirected) {                                       \
            n00b_restore_current_allocator(prev_alloc);               \
            alloc_redirected = false;                                 \
        }                                                             \
        n00b_allocator_destroy(scratch_allocator);                    \
        return _rocs_batch_ret;                                       \
    } while (0)

    bool prev_ingest = n00b_gc_attrib_enter_ingest();
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(
        scratch_allocator);
    bool alloc_redirected = true;

    rocs_store_batch_job_t **jobs = n00b_alloc_array(
        rocs_store_batch_job_t *,
        (int64_t)count,
        .allocator = scratch_allocator);
    if (jobs == nullptr) {
        ROCS_BATCH_RETURN(
            n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL));
    }

    for (uint64_t i = 0; i < count; i++) {
        rocs_store_batch_job_t *job = n00b_alloc(
            rocs_store_batch_job_t,
            .allocator = scratch_allocator);
        job->store        = store;
        job->input_record = nullptr;
        job->source       = nullptr;
        job->source_decoder = source_decoder;
        if (parallel_prepare && worker_pool != nullptr) {
            // Persistent worker-pool path: allocate from the worker's own
            // per-worker bump arena (its current_allocator). nullptr signals
            // rocs_store_batch_prepare_worker to use the current allocator
            // without per-job set/restore; the batch owner resets the arenas
            // at the batch boundary.
            job->allocator = nullptr;
        }
        else {
            // Transient parallel prepare (workers > 1, no caller pool) or the
            // serial path: prepare into the single shared batch scratch pool
            // (a locked, MT-safe pool). A concrete per-job allocator here is
            // what the range-commit re-prep (rocs_store_range_prepare_worker)
            // needs -- it is bypassed when batch_job->allocator is null.
            job->allocator = scratch_allocator;
        }
        job->index_enabled = true;
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
    }

    n00b_restore_current_allocator(prev_alloc);
    alloc_redirected = false;

    if (parallel_prepare) {
        // prep_pool is the caller's persistent pool or our transient one; both
        // give each worker a per-worker arena. run_service_worker_jobs drains
        // (waits for every job) without shutting the pool down, so the prepared
        // data in those arenas stays live for the append loop below.
        n00b_err_t worker_err = rocs_store_run_service_worker_jobs(
            prep_pool,
            rocs_store_batch_prepare_worker,
            (void *const *)jobs,
            count,
            nullptr,
            scratch_allocator);
        if (worker_err != N00B_STORE_OK) {
            ROCS_BATCH_RETURN(n00b_result_err(uint64_t, worker_err));
        }
    }
    else {
        for (uint64_t i = 0; i < count; i++) {
            rocs_store_batch_prepare_worker(jobs[i], nullptr);
        }
    }

    for (uint64_t i = 0; i < count; i++) {
        if (jobs[i]->err != N00B_STORE_OK) {
            ROCS_BATCH_RETURN(n00b_result_err(uint64_t, jobs[i]->err));
        }
    }

    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->commit_lock);
        ROCS_BATCH_RETURN(n00b_result_err(uint64_t, N00B_STORE_ERR_STATE));
    }

    for (uint64_t i = 0; i < count; i++) {
        n00b_err_t preflight = rocs_store_preflight_ingest(store,
                                                           jobs[i]->record,
                                                           jobs[i]->raw,
                                                           scratch_allocator);
        if (preflight != N00B_STORE_OK) {
            n00b_mutex_unlock(store->commit_lock);
            ROCS_BATCH_RETURN(n00b_result_err(uint64_t, preflight));
        }
    }

    uint64_t failed_seals_before = rocs_store_failed_seal_job_count(store);
    uint64_t committed           = 0;
    for (uint64_t i = 0; i < count;) {
        if (parallel_prepare) {
            n00b_string_t *route = jobs[i]->route == nullptr ? r"default"
                                                             : jobs[i]->route;
            uint64_t run = 1;
            while (i + run < count) {
                n00b_string_t *next = jobs[i + run]->route == nullptr
                                          ? r"default"
                                          : jobs[i + run]->route;
                if (!n00b_unicode_str_eq(route, next)) {
                    break;
                }
                run++;
            }

            while (run != 0
                   && !rocs_store_batch_range_candidate_unlocked(
                       store,
                       &jobs[i],
                       run)) {
                run--;
            }

            if (run != 0) {
                auto range_r = rocs_store_ingest_prepared_range_unlocked(
                    store,
                    &jobs[i],
                    run,
                    scratch_allocator,
                    // Commit uses the caller's persistent pool (or serial for a
                    // null one) -- NOT the transient prepare pool, whose only
                    // job was the prepare phase above.
                    worker_pool,
                    workers,
                    prep_queue_capacity,
                    true);
                if (n00b_result_is_err(range_r)) {
                    n00b_err_t err = n00b_result_get_err(range_r);
                    bool failed_seals_changed =
                        rocs_store_failed_seal_job_count(store)
                        != failed_seals_before;
                    if (failed_seals_changed) {
                        err = rocs_store_failed_seal_last_error(store);
                    }
                    n00b_mutex_unlock(store->commit_lock);
                    if (committed != 0 && !failed_seals_changed) {
                        ROCS_BATCH_RETURN(n00b_result_ok(uint64_t,
                                                         committed));
                    }
                    ROCS_BATCH_RETURN(n00b_result_err(uint64_t, err));
                }
                uint64_t range_committed = n00b_result_get(range_r);
                committed += range_committed;
                i += range_committed;
                if (rocs_store_failed_seal_job_count(store)
                    != failed_seals_before) {
                    n00b_err_t seal_err = rocs_store_failed_seal_last_error(
                        store);
                    n00b_mutex_unlock(store->commit_lock);
                    ROCS_BATCH_RETURN(n00b_result_err(uint64_t, seal_err));
                }
                continue;
            }
        }

        auto ingest_r = rocs_store_ingest_prepared_unlocked(store,
                                                            jobs[i]->record,
                                                            jobs[i]->raw,
                                                            jobs[i]->route,
                                                            jobs[i]->terms,
                                                            scratch_allocator);
        if (n00b_result_is_err(ingest_r)) {
            n00b_err_t err = n00b_result_get_err(ingest_r);
            /*
             * A route-change seal in this ingest can leave records committed
             * earlier in this batch retained for retry but not durable/catalog
             * visible yet. That is not a clean committed prefix.
             */
            if (rocs_store_failed_seal_job_count(store)
                != failed_seals_before) {
                err = rocs_store_failed_seal_last_error(store);
                n00b_mutex_unlock(store->commit_lock);
                ROCS_BATCH_RETURN(n00b_result_err(uint64_t, err));
            }
            n00b_mutex_unlock(store->commit_lock);
            /*
             * result_t cannot carry both an error and a committed prefix.
             * Once any prefix is visible, the batch retry contract is
             * Ok(committed); callers resume from that index.
             */
            if (committed != 0) {
                ROCS_BATCH_RETURN(n00b_result_ok(uint64_t, committed));
            }
            ROCS_BATCH_RETURN(n00b_result_err(uint64_t, err));
        }
        committed++;
        i++;
    }

    // A size-triggered auto-seal can retain a failed shard without returning an
    // error from ingest; treat that as a durability failure too.
    if (rocs_store_failed_seal_job_count(store) != failed_seals_before) {
        n00b_err_t seal_err = rocs_store_failed_seal_last_error(store);
        n00b_mutex_unlock(store->commit_lock);
        ROCS_BATCH_RETURN(n00b_result_err(uint64_t, seal_err));
    }

    n00b_mutex_unlock(store->commit_lock);
    ROCS_BATCH_RETURN(n00b_result_ok(uint64_t, committed));
#undef ROCS_BATCH_RETURN
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
                                          nullptr,
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
                                          nullptr,
                                          nullptr,
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

static bool
rocs_store_shard_id_list_contains(n00b_store_shard_id_list_t *ids,
                                  uint64_t                    shard_id)
{
    if (ids == nullptr || shard_id == 0) {
        return false;
    }
    size_t len = n00b_list_len(*ids);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*ids, i) == shard_id) {
            return true;
        }
    }
    return false;
}

static bool
rocs_store_pin_handles_block_shard_locked(n00b_store_t *store,
                                          uint64_t      shard_id)
{
    if (store == nullptr || store->active_pin_handles == nullptr) {
        return false;
    }
    size_t len = n00b_list_len(*store->active_pin_handles);
    for (size_t i = 0; i < len; i++) {
        n00b_store_pin_t *pin =
            n00b_list_get(*store->active_pin_handles, i);
        if (pin == nullptr || pin->released) {
            continue;
        }
        if (pin->all_shards
            || rocs_store_shard_id_list_contains(pin->shard_ids,
                                                 shard_id)) {
            return true;
        }
    }
    return false;
}

static bool
rocs_store_record_streams_block_shard_locked(n00b_store_t *store,
                                             uint64_t      shard_id)
{
    if (store == nullptr || store->active_record_streams == nullptr) {
        return false;
    }
    size_t len = n00b_list_len(*store->active_record_streams);
    for (size_t i = 0; i < len; i++) {
        n00b_store_record_stream_t *stream =
            n00b_list_get(*store->active_record_streams, i);
        if (stream == nullptr || !stream->pinned || stream->closed) {
            continue;
        }
        if (stream->hot_snapshot_pinned) {
            return true;
        }
        if (rocs_store_shard_id_list_contains(stream->sealed_shard_ids,
                                              shard_id)) {
            return true;
        }
    }
    return false;
}

static bool
rocs_store_drop_blocked_by_active_pin_locked(n00b_store_t *store,
                                             uint64_t      shard_id)
{
    if (store == nullptr) {
        return false;
    }
    if (rocs_store_pin_handles_block_shard_locked(store, shard_id)) {
        return true;
    }
    if (rocs_store_record_streams_block_shard_locked(store, shard_id)) {
        return true;
    }
    return false;
}

static bool
rocs_store_drop_entry_blocked_locked(n00b_store_t               *store,
                                     n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr) {
        return false;
    }
    if (entry->resident_pins != 0) {
        return true;
    }
    return rocs_store_drop_blocked_by_active_pin_locked(store,
                                                        entry->shard_id);
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
    if (!rocs_store_catalog_entry_droppable(entry)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    // Store/query pins and record streams are target-aware by class. Resident
    // pins are target-entry state and block only this entry.
    if (rocs_store_drop_entry_blocked_locked(store, entry)) {
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
                                      n00b_store_shard_retention_policy_t *policy,
                                      n00b_store_shard_id_list_t          *blocked)
{
    if (store == nullptr || policy == nullptr || store->catalog == nullptr) {
        return nullptr;
    }
    // Total on-disk bytes rule: when the summed sealed byte_len exceeds the
    // budget, the oldest shard is droppable; apply() loops + recomputes, so it
    // drops oldest-first until the total fits.
    uint64_t total_bytes = 0;
    uint64_t count       = 0;
    size_t   len         = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (rocs_store_catalog_entry_visible_sealed(entry)) {
            count++;
            total_bytes += entry->byte_len;
        }
    }
    bool over_count = policy->max_sealed_shards != 0
                   && count > policy->max_sealed_shards;
    bool over_bytes = policy->max_total_sealed_bytes != 0
                   && total_bytes > policy->max_total_sealed_bytes;

    n00b_store_catalog_entry_t *candidate = nullptr;
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)) {
            continue;
        }
        if (rocs_store_shard_id_list_contains(blocked, entry->shard_id)) {
            continue;
        }
        bool old_by_time = policy->drop_before_seal_ts != 0
                        && entry->seal_ts >= policy->min_seal_ts
                        && entry->seal_ts < policy->drop_before_seal_ts;
        if (!over_count && !over_bytes && !old_by_time) {
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

    n00b_mutex_lock(store->commit_lock);
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t dropped = 0;
    bool     saw_pinned_candidate = false;
    n00b_store_shard_id_list_t *blocked =
        rocs_store_shard_id_list_new(.allocator = store->allocator);
    if (blocked == nullptr) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }
    while (true) {
        n00b_store_catalog_entry_t *candidate =
            rocs_store_oldest_retention_candidate(store, policy, blocked);
        if (candidate == nullptr) {
            break;
        }

        if (rocs_store_drop_entry_blocked_locked(store, candidate)) {
            n00b_list_push(*blocked, candidate->shard_id);
            saw_pinned_candidate = true;
            continue;
        }

        uint64_t shard_id = candidate->shard_id;
        auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                          shard_id,
                                                          policy->drop_reason);
        if (n00b_result_is_err(drop_r)) {
            n00b_mutex_unlock(store->residency_lock);
            n00b_mutex_unlock(store->commit_lock);
            return n00b_result_err(uint64_t, n00b_result_get_err(drop_r));
        }
        dropped++;
    }

    n00b_mutex_unlock(store->residency_lock);
    n00b_mutex_unlock(store->commit_lock);
    if (saw_pinned_candidate) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_PINNED);
    }
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

    n00b_mutex_lock(store->commit_lock);
    n00b_mutex_lock(store->residency_lock);
    auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                      shard_id,
                                                      drop_reason);
    n00b_mutex_unlock(store->residency_lock);
    n00b_mutex_unlock(store->commit_lock);
    return drop_r;
}

n00b_result_t(bool)
n00b_store_quarantine_shard(n00b_store_t *store,
                            uint64_t      shard_id) _kargs
{
    n00b_string_t *reason = nullptr;
}
{
    if (store == nullptr || store->catalog == nullptr || shard_id == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(store->commit_lock);
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    uint64_t index = 0;
    if (!rocs_store_catalog_find_index(store, shard_id, &index)) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    if (entry == nullptr
        || entry->state == ROCS_STORE_CATALOG_ENTRY_QUARANTINED) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_ok(bool, entry != nullptr);
    }
    if (!rocs_store_catalog_entry_visible_sealed(entry)) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    if (rocs_store_drop_entry_blocked_locked(store, entry)) {
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    n00b_store_pos_t old_oldest = store->oldest_available;
    bool             old_has_oldest = store->has_oldest_available;

    if (entry->resident_map != nullptr) {
        auto unload_r = rocs_store_resident_unload_entry(store, entry);
        if (n00b_result_is_err(unload_r)) {
            n00b_mutex_unlock(store->residency_lock);
            n00b_mutex_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(unload_r));
        }
    }

    (void)reason;
    entry->state = ROCS_STORE_CATALOG_ENTRY_QUARANTINED;
    rocs_store_refresh_oldest_available(store);

    auto catalog_r = rocs_store_catalog_write(store);
    if (n00b_result_is_err(catalog_r)) {
        entry->state = ROCS_STORE_CATALOG_ENTRY_SEALED;
        store->oldest_available     = old_oldest;
        store->has_oldest_available = old_has_oldest;
        n00b_mutex_unlock(store->residency_lock);
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(catalog_r));
    }

    n00b_mutex_unlock(store->residency_lock);
    n00b_mutex_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_oldest_available_pos(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_STORE_ERR_ARG);
    }

    n00b_option_t(n00b_store_pos_t) result =
        store->has_oldest_available
            ? n00b_option_set(n00b_store_pos_t, store->oldest_available)
            : n00b_option_none(n00b_store_pos_t);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_option_t(uint64_t))
n00b_store_oldest_available_expires_at_ns(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(uint64_t), N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(uint64_t), N00B_STORE_ERR_STATE);
    }
    if (!store->has_oldest_available || store->retention_window_ns == 0) {
        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_none(uint64_t));
    }

    n00b_option_t(uint64_t) result = n00b_option_none(uint64_t);
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)) {
            continue;
        }
        if (entry->generation == store->oldest_available.generation
            && entry->shard_id == store->oldest_available.shard_id) {
            uint64_t expires_at = entry->seal_ts + store->retention_window_ns;
            if (expires_at < entry->seal_ts) {
                expires_at = UINT64_MAX;
            }
            result = n00b_option_set(uint64_t, expires_at);
            break;
        }
    }

    return n00b_result_ok(n00b_option_t(uint64_t), result);
}

n00b_result_t(uint64_t)
n00b_store_retention_window_ns(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }
    uint64_t window = store->retention_window_ns;
    return n00b_result_ok(uint64_t, window);
}

n00b_result_t(n00b_store_resume_check_t)
n00b_store_resume_check(n00b_store_t *store, n00b_store_pos_t pos)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_resume_check_t,
                               N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
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
            && pos.ordinal < rocs_store_hot_visible_count_unlocked(store, hot)) {
            check.available = true;
        }
        return n00b_result_ok(n00b_store_resume_check_t, check);
    }

    auto entry_opt = rocs_store_catalog_find_raw(store, pos.shard_id);
    if (n00b_option_is_set(entry_opt)) {
        n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
        check.available = rocs_store_catalog_entry_visible_sealed(entry)
                       && pos.ordinal < entry->record_count
                       && pos.generation == entry->generation;
    }
    else {
        n00b_store_shard_t *hot = store->hot_shard;
        check.available = hot != nullptr
                       && pos.shard_id == hot->shard_id
                       && pos.ordinal
                              < rocs_store_hot_visible_count_unlocked(store,
                                                                      hot);
    }

    return n00b_result_ok(n00b_store_resume_check_t, check);
}

static void
rocs_store_conduit_stats_record(n00b_store_conduit_ingest_t *adapter,
                                uint64_t                     committed,
                                uint64_t                     failed,
                                uint64_t                     malformed,
                                n00b_err_t                   err)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_mutex_lock(adapter->lock);
    adapter->stats.committed += committed;
    adapter->stats.failed += failed;
    adapter->stats.malformed += malformed;
    if (err != N00B_STORE_OK && (failed != 0 || malformed != 0)) {
        adapter->stats.last_error = err;
    }
    n00b_mutex_unlock(adapter->lock);
}

static void
rocs_store_conduit_stats_submitted(n00b_store_conduit_ingest_t *adapter,
                                   uint64_t                     submitted)
{
    if (adapter == nullptr || adapter->lock == nullptr || submitted == 0) {
        return;
    }

    n00b_mutex_lock(adapter->lock);
    adapter->stats.submitted += submitted;
    n00b_mutex_unlock(adapter->lock);
}

static void
rocs_store_conduit_payload_cleanup(n00b_store_ingest_payload_t payload)
{
    if (n00b_variant_is_type(payload.value, n00b_buffer_t *)) {
        n00b_buffer_t *source = n00b_variant_get(payload.value, n00b_buffer_t *);
        if (source != nullptr) {
            n00b_buffer_free(source);
            n00b_free(source);
        }
    }
}

static n00b_store_record_list_t *
rocs_store_conduit_record_list_new(uint64_t count, n00b_allocator_t *allocator)
{
    n00b_store_record_list_t *records =
        n00b_alloc(n00b_store_record_list_t, .allocator = allocator);
    *records = n00b_list_new_cap_private(n00b_json_node_t *,
                                         count,
                                         .allocator = allocator,
                                         .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static n00b_store_source_list_t *
rocs_store_conduit_source_list_new(uint64_t count, n00b_allocator_t *allocator)
{
    n00b_store_source_list_t *sources =
        n00b_alloc(n00b_store_source_list_t, .allocator = allocator);
    *sources = n00b_list_new_cap_private(n00b_buffer_t *,
                                         count,
                                         .allocator = allocator,
                                         .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return sources;
}

static void
rocs_store_conduit_process_batch(n00b_store_conduit_ingest_t *adapter,
                                 n00b_store_ingest_msg_t     *first)
{
    if (adapter == nullptr || adapter->store == nullptr || first == nullptr) {
        if (first != nullptr) {
            rocs_store_conduit_payload_cleanup(first->payload);
            n00b_free(first);
        }
        return;
    }

    uint32_t cap = adapter->batch_capacity == 0 ? 1 : adapter->batch_capacity;
    if (cap == 0) {
        cap = 1;
    }

    n00b_pool_t      scratch_pool = {};
    n00b_allocator_t *scratch_allocator =
        n00b_pool_init(&scratch_pool,
                       .hidden            = true,
                       .external_metadata = false,
                       .use_epochs        = false,
                       .name              = "rocs_conduit_batch_scratch");

    n00b_store_ingest_payload_t *payloads = n00b_alloc_array(
        n00b_store_ingest_payload_t,
        cap,
        .allocator = scratch_allocator,
        .scan_kind = N00B_GC_SCAN_KIND_ALL);
    if (payloads == nullptr) {
        rocs_store_conduit_payload_cleanup(first->payload);
        n00b_free(first);
        n00b_allocator_destroy(scratch_allocator);
        rocs_store_conduit_stats_record(adapter,
                                        0,
                                        1,
                                        0,
                                        N00B_STORE_ERR_INTERNAL);
        return;
    }

    uint32_t count = 0;
    payloads[count++] = first->payload;
    n00b_free(first);

    while (count < cap) {
        n00b_store_ingest_msg_t *msg =
            n00b_store_ingest_inbox_pop(adapter->inbox);
        if (msg == nullptr) {
            break;
        }
        payloads[count++] = msg->payload;
        n00b_free(msg);
    }

    bool all_records = true;
    bool all_sources = true;
    bool all_indexed = true;
    for (uint32_t i = 0; i < count; i++) {
        all_records = all_records
                   && n00b_variant_is_type(payloads[i].value, n00b_json_node_t *);
        all_sources = all_sources
                   && n00b_variant_is_type(payloads[i].value, n00b_buffer_t *);
        all_indexed = all_indexed && payloads[i].index_enabled;
    }

    uint64_t   malformed     = 0;
    n00b_err_t malformed_err = N00B_STORE_OK;

    n00b_result_t(uint64_t) batch_r;
    if (all_records && all_indexed) {
        n00b_store_record_list_t *records =
            rocs_store_conduit_record_list_new(count, scratch_allocator);
        for (uint32_t i = 0; i < count; i++) {
            n00b_list_push(*records,
                           n00b_variant_get(payloads[i].value, n00b_json_node_t *));
        }
        batch_r = rocs_store_ingest_batch_common(adapter->store,
                                                 records,
                                                 nullptr,
                                                 nullptr,
                                                 adapter->worker_pool,
                                                 adapter->worker_count,
                                                 (int32_t)adapter->batch_capacity);
    }
    else if (all_sources && all_indexed) {
        n00b_store_source_list_t *sources =
            rocs_store_conduit_source_list_new(count, scratch_allocator);
        for (uint32_t i = 0; i < count; i++) {
            n00b_list_push(*sources,
                           n00b_variant_get(payloads[i].value, n00b_buffer_t *));
        }
        batch_r = rocs_store_ingest_batch_common(adapter->store,
                                                 nullptr,
                                                 sources,
                                                 adapter->source_decoder,
                                                 adapter->worker_pool,
                                                 adapter->worker_count,
                                                 (int32_t)adapter->batch_capacity);
        if (n00b_result_is_err(batch_r)
            && n00b_result_get_err(batch_r) == N00B_STORE_ERR_PARSE) {
            uint64_t committed = 0;
            n00b_err_t last_err = N00B_STORE_OK;
            for (uint32_t i = 0; i < count; i++) {
                n00b_buffer_t *source =
                    n00b_variant_get(payloads[i].value, n00b_buffer_t *);
                n00b_pool_t       item_pool = {};
                n00b_allocator_t *item_alloc =
                    n00b_pool_init(&item_pool,
                                   .hidden            = true,
                                   .external_metadata = false,
                                   .use_epochs        = false,
                                   .name              = "rocs_conduit_item");
                n00b_buffer_t    *raw    = nullptr;
                n00b_json_node_t *record = nullptr;
                n00b_result_t(bool) ingest_r;
                if (adapter->source_decoder == nullptr) {
                    n00b_err_t parse_err = rocs_store_parse_source(source,
                                                                  &raw,
                                                                  &record,
                                                                  item_alloc);
                    ingest_r = parse_err == N00B_STORE_OK
                             ? rocs_store_ingest_common(adapter->store,
                                                        record,
                                                        raw,
                                                        true,
                                                        item_alloc)
                             : rocs_store_ingest_source_tombstone(adapter->store,
                                                                  source,
                                                                  raw,
                                                                  parse_err,
                                                                  item_alloc);
                    if (parse_err != N00B_STORE_OK) {
                        malformed++;
                        malformed_err = parse_err;
                        last_err = parse_err;
                    }
                }
                else {
                    n00b_err_t copy_err = rocs_store_copy_source_raw(source,
                                                                     &raw,
                                                                     item_alloc);
                    if (copy_err != N00B_STORE_OK) {
                        ingest_r = n00b_result_err(bool, copy_err);
                    }
                    else {
                        auto record_r = adapter->source_decoder(raw,
                                                                item_alloc);
                        if (n00b_result_is_ok(record_r)) {
                            ingest_r = rocs_store_ingest_common(
                                adapter->store,
                                n00b_result_get(record_r),
                                raw,
                                true,
                                item_alloc);
                        }
                        else {
                            n00b_err_t decode_err = n00b_result_get_err(record_r);
                            ingest_r = rocs_store_ingest_source_tombstone(
                                adapter->store,
                                source,
                                raw,
                                decode_err,
                                item_alloc);
                            malformed++;
                            malformed_err = decode_err;
                            last_err = decode_err;
                        }
                    }
                }
                if (n00b_result_is_ok(ingest_r)) {
                    committed++;
                }
                else {
                    last_err = n00b_result_get_err(ingest_r);
                }
                n00b_allocator_destroy(item_alloc);
            }
            batch_r = committed == count
                    ? n00b_result_ok(uint64_t, committed)
                    : n00b_result_err(uint64_t,
                                      last_err == N00B_STORE_OK
                                          ? N00B_STORE_ERR_ARG
                                          : last_err);
        }
    }
    else {
        uint64_t committed = 0;
        n00b_err_t last_err = N00B_STORE_OK;
        for (uint32_t i = 0; i < count; i++) {
            n00b_result_t(bool) ingest_r;
            if (n00b_variant_is_type(payloads[i].value, n00b_json_node_t *)) {
                n00b_pool_t       item_pool = {};
                n00b_allocator_t *item_alloc =
                    n00b_pool_init(&item_pool,
                                   .hidden            = true,
                                   .external_metadata = false,
                                   .use_epochs        = false,
                                   .name              = "rocs_conduit_item");
                ingest_r = rocs_store_ingest_common(
                    adapter->store,
                    n00b_variant_get(payloads[i].value, n00b_json_node_t *),
                    nullptr,
                    payloads[i].index_enabled,
                    item_alloc);
                n00b_allocator_destroy(item_alloc);
            }
            else if (n00b_variant_is_type(payloads[i].value, n00b_buffer_t *)) {
                n00b_buffer_t *source =
                    n00b_variant_get(payloads[i].value, n00b_buffer_t *);
                if (adapter->source_decoder == nullptr) {
                    n00b_pool_t       item_pool = {};
                    n00b_allocator_t *item_alloc =
                        n00b_pool_init(&item_pool,
                                       .hidden            = true,
                                       .external_metadata = false,
                                       .use_epochs        = false,
                                       .name              = "rocs_conduit_item");
                    n00b_buffer_t    *raw    = nullptr;
                    n00b_json_node_t *record = nullptr;
                    n00b_err_t parse_err = rocs_store_parse_source(source,
                                                                  &raw,
                                                                  &record,
                                                                  item_alloc);
                    ingest_r = parse_err == N00B_STORE_OK
                             ? rocs_store_ingest_common(adapter->store,
                                                        record,
                                                        raw,
                                                        payloads[i].index_enabled,
                                                        item_alloc)
                             : rocs_store_ingest_source_tombstone(adapter->store,
                                                                  source,
                                                                  raw,
                                                                  parse_err,
                                                                  item_alloc);
                    if (parse_err != N00B_STORE_OK) {
                        malformed++;
                        malformed_err = parse_err;
                        last_err = parse_err;
                    }
                    n00b_allocator_destroy(item_alloc);
                }
                else {
                    n00b_pool_t       item_pool = {};
                    n00b_allocator_t *item_alloc =
                        n00b_pool_init(&item_pool,
                                       .hidden            = true,
                                       .external_metadata = false,
                                       .use_epochs        = false,
                                       .name              = "rocs_conduit_item");
                    n00b_buffer_t *raw = nullptr;
                    n00b_err_t copy_err = rocs_store_copy_source_raw(source,
                                                                     &raw,
                                                                     item_alloc);
                    if (copy_err != N00B_STORE_OK) {
                        ingest_r = n00b_result_err(bool, copy_err);
                    }
                    else {
                        auto record_r = adapter->source_decoder(raw,
                                                                item_alloc);
                        if (n00b_result_is_ok(record_r)) {
                            ingest_r = rocs_store_ingest_common(
                                adapter->store,
                                n00b_result_get(record_r),
                                raw,
                                payloads[i].index_enabled,
                                item_alloc);
                        }
                        else {
                            n00b_err_t decode_err = n00b_result_get_err(record_r);
                            ingest_r = rocs_store_ingest_source_tombstone(
                                adapter->store,
                                source,
                                raw,
                                decode_err,
                                item_alloc);
                            malformed++;
                            malformed_err = decode_err;
                            last_err = decode_err;
                        }
                    }
                    n00b_allocator_destroy(item_alloc);
                }
            }
            else {
                ingest_r = n00b_result_err(bool, N00B_STORE_ERR_ARG);
            }
            if (n00b_result_is_ok(ingest_r)) {
                committed++;
            }
            else {
                last_err = n00b_result_get_err(ingest_r);
            }
        }
        batch_r = committed == count
                ? n00b_result_ok(uint64_t, committed)
                : n00b_result_err(uint64_t,
                                  last_err == N00B_STORE_OK
                                      ? N00B_STORE_ERR_ARG
                                      : last_err);
    }

    uint64_t committed = 0;
    uint64_t failed    = 0;
    n00b_err_t err     = N00B_STORE_OK;
    if (n00b_result_is_ok(batch_r)) {
        committed = n00b_result_get(batch_r);
        failed    = committed <= count ? (uint64_t)count - committed
                                       : 0;
        if (failed != 0) {
            err = N00B_STORE_ERR_INTERNAL;
        }
    }
    else {
        failed = count;
        err    = n00b_result_get_err(batch_r);
    }
    if (err == N00B_STORE_OK && malformed_err != N00B_STORE_OK) {
        err = malformed_err;
    }

    rocs_store_conduit_stats_submitted(adapter, count);
    rocs_store_conduit_stats_record(adapter,
                                    committed,
                                    failed,
                                    malformed,
                                    err);

    for (uint32_t i = 0; i < count; i++) {
        rocs_store_conduit_payload_cleanup(payloads[i]);
    }
    n00b_allocator_destroy(scratch_allocator);
}

static void
rocs_store_conduit_cancel_subscription(n00b_store_conduit_ingest_t *adapter)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_mutex_lock(adapter->lock);
    n00b_conduit_sub_handle_t sub = adapter->sub;
    n00b_store_ingest_topic_t *topic = adapter->topic;
    adapter->sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    n00b_mutex_unlock(adapter->lock);

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
            rocs_store_conduit_process_batch(adapter, msg);
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

        n00b_mutex_lock(adapter->lock);
        bool stop_requested = adapter->stop_requested;
        n00b_mutex_unlock(adapter->lock);
        if (stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)) {
            break;
        }

        n00b_mutex_lock(adapter->lock);
        stop_requested = adapter->stop_requested;
        n00b_mutex_unlock(adapter->lock);
        if (!stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)
            && !n00b_conduit_inbox_has_sys(adapter->inbox)) {
            base_nanosleep_ns(1ULL * N00B_NS_PER_MS);
        }
    }

    rocs_store_conduit_cancel_subscription(adapter);

    n00b_mutex_lock(adapter->lock);
    adapter->closed = true;
    n00b_mutex_unlock(adapter->lock);
    return nullptr;
}

n00b_result_t(n00b_store_conduit_ingest_t *)
n00b_store_conduit_ingest_start(n00b_store_t               *store,
                                n00b_store_ingest_topic_t  *topic) _kargs
{
    int32_t           worker_count   = 0;
    int32_t           queue_capacity = 0;
    int32_t           batch_capacity = 0;
    n00b_store_source_decoder_t source_decoder = nullptr;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (store == nullptr || topic == nullptr || worker_count < 0
        || queue_capacity < 0 || batch_capacity < 0) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_ARG);
    }
    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    if (!n00b_conduit_topic_is_active(base) || base->conduit == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    int32_t workers = worker_count == 0 ? 1 : worker_count;
    int32_t queue_cap = queue_capacity == 0 ? 128 : queue_capacity;
    int32_t batch_cap = batch_capacity == 0 ? 128 : batch_capacity;
    if (batch_cap > queue_cap) {
        batch_cap = queue_cap;
    }
    if (workers <= 0 || queue_cap <= 0 || batch_cap <= 0) {
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
    adapter->worker_pool    = nullptr;
    // Lock in the non-moving system pool (see store->commit_lock rationale):
    // a relocated futex strands parked threads and faults the GC lock scan.
    adapter->lock           = n00b_alloc_with_opts(
        n00b_mutex_t,
        &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)&n00b_get_runtime()->system_pool,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    if (adapter->lock != nullptr) {
        n00b_mutex_init(adapter->lock);
    }
    adapter->allocator      = allocator;
    adapter->source_decoder = source_decoder;
    adapter->stats          = (n00b_store_conduit_ingest_stats_t){};
    adapter->batch_capacity = (uint32_t)batch_cap;
    adapter->worker_count   = workers;
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
                            N00B_CONDUIT_BP_DROP_NEWEST,
                            (uint32_t)queue_cap);
    n00b_conduit_inbox_set_no_notify(adapter->inbox, true);

    if (workers > 1) {
        adapter->worker_pool = n00b_worker_pool_new(
            workers,
            batch_cap,
            rocs_store_service_pool_worker,
            nullptr,
            .allocator            = allocator,
            // Each worker owns a persistent bump-arena scratch (installed as its
            // current_allocator for the worker's lifetime). Batch prepare jobs
            // (job->allocator == nullptr) allocate transient prepared data from
            // it; the batch owner resets every worker arena at the batch
            // boundary (rocs_store_ingest_batch_common's ROCS_BATCH_RETURN),
            // where the single conduit loop thread guarantees no concurrent
            // batch is in flight. Replaces the former per-record pool churn
            // (N pool_init/destroy per batch under the global mmap-tree lock).
            .worker_scratch_arena = true);
        if (adapter->worker_pool == nullptr) {
            return n00b_result_err(n00b_store_conduit_ingest_t *,
                                   N00B_STORE_ERR_INTERNAL);
        }
    }

    adapter->sub = n00b_conduit_subscribe(n00b_store_ingest_payload_t,
                                          topic,
                                          adapter->inbox,
                                          .operations = N00B_CONDUIT_OP_ALL);
    if (adapter->sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        if (adapter->worker_pool != nullptr) {
            n00b_worker_pool_shutdown(adapter->worker_pool);
            adapter->worker_pool = nullptr;
        }
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    auto thread_r = n00b_thread_spawn(rocs_store_conduit_loop, adapter);
    if (n00b_result_is_err(thread_r)) {
        n00b_conduit_sub_cancel(adapter->sub);
        if (adapter->worker_pool != nullptr) {
            n00b_worker_pool_shutdown(adapter->worker_pool);
            adapter->worker_pool = nullptr;
        }
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

    n00b_mutex_lock(ingest->lock);
    if (ingest->joined) {
        n00b_mutex_unlock(ingest->lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    ingest->stop_requested = true;
    n00b_mutex_unlock(ingest->lock);

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
    if (ingest->worker_pool != nullptr) {
        n00b_worker_pool_shutdown(ingest->worker_pool);
        ingest->worker_pool = nullptr;
    }

    n00b_mutex_lock(ingest->lock);
    ingest->closed = true;
    ingest->joined = true;
    n00b_mutex_unlock(ingest->lock);

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_conduit_ingest_stats(n00b_store_conduit_ingest_t *ingest)
{
    if (ingest == nullptr || ingest->lock == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_stats_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(ingest->lock);
    n00b_store_conduit_ingest_stats_t stats = ingest->stats;
    n00b_mutex_unlock(ingest->lock);
    stats.inbox_queued =
        ingest->inbox == nullptr
            ? 0
            : (uint64_t)n00b_store_ingest_inbox_msg_count(ingest->inbox);
    stats.worker_queued =
        ingest->worker_pool == nullptr
            ? 0
            : (uint64_t)n00b_worker_pool_pending(ingest->worker_pool);
    stats.worker_in_flight =
        ingest->worker_pool == nullptr
            ? 0
            : (uint64_t)n00b_worker_pool_in_flight(ingest->worker_pool);
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

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_catalog_snapshot_t *,
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)) {
            continue;
        }
        auto copied_r = rocs_store_catalog_snapshot_copy_entry(
            entry,
            .allocator = allocator);
        if (n00b_result_is_err(copied_r)) {
            return n00b_result_err(n00b_store_catalog_snapshot_t *,
                                   n00b_result_get_err(copied_r));
        }

        n00b_list_push(*snapshot, n00b_result_get(copied_r));
    }

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

    // No commit-lock here: a SNAPSHOT query captures its boundary lock-free and
    // relies on its store pin for safety. Holding the commit read lock would
    // serialize every query behind the ingest/seal commit WRITE lock, so the
    // query read path would block for the whole duration of a batch commit or a
    // shard seal/marshal -- the "instant when idle, hangs under load" symptom.
    // Sealed catalog entries are immutable once visible, and hot_through is a
    // point-in-time boundary; a commit racing this read simply lands outside the
    // snapshot, which is exactly the correct "as of now" semantics.
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_tail_snapshot_t,
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)) {
            continue;
        }
        auto copied_r = rocs_store_catalog_snapshot_copy_entry(
            entry,
            .allocator = allocator);
        if (n00b_result_is_err(copied_r)) {
            return n00b_result_err(n00b_store_tail_snapshot_t,
                                   n00b_result_get_err(copied_r));
        }

        n00b_list_push(*sealed, n00b_result_get(copied_r));
    }

    n00b_store_shard_t *hot = store->hot_shard;
    uint64_t hot_visible =
        rocs_store_hot_visible_count_unlocked(store, hot);
    if (hot != nullptr && hot_visible != 0) {
        snapshot.has_hot_through = true;
        snapshot.hot_through = (n00b_store_pos_t){
            .generation = store->generation,
            .shard_id   = hot->shard_id,
            .ordinal    = hot_visible - 1,
        };
    }

    return n00b_result_ok(n00b_store_tail_snapshot_t, snapshot);
}

n00b_result_t(uint64_t)
n00b_store_catalog_get_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t count = 0;
    n00b_list_foreach(*store->catalog, p) {
        if (rocs_store_catalog_entry_visible_sealed(*p)) {
            count++;
        }
    }
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(uint64_t)
n00b_store_catalog_all_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t count = (uint64_t)n00b_list_len(*store->catalog);
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_all_entry_at(n00b_store_t *store, uint64_t index)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    if (index > (uint64_t)SIZE_MAX
        || index >= (uint64_t)n00b_list_len(*store->catalog)) {
        return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                              n00b_option_none(n00b_store_catalog_entry_t *));
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    return n00b_result_ok(
        n00b_option_t(n00b_store_catalog_entry_t *),
        n00b_option_set(n00b_store_catalog_entry_t *, entry));
}

n00b_result_t(n00b_store_backlog_t)
n00b_store_catalog_backlog(n00b_store_t *store, n00b_store_pos_t *after)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_backlog_t, N00B_STORE_ERR_ARG);
    }

    n00b_store_backlog_t out = {0};

    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *e = *p;
        if (!rocs_store_catalog_entry_visible_sealed(e)) {
            continue;
        }
        if (after != nullptr) {
            // Entry strictly before the resume position's shard: delivered.
            if (e->generation < after->generation
                || (e->generation == after->generation
                    && e->shard_id < after->shard_id)) {
                continue;
            }
            // The resume position's own shard: records strictly after the
            // ordinal are pending (delivered records are 0..ordinal).
            if (e->generation == after->generation
                && e->shard_id == after->shard_id) {
                uint64_t left = e->record_count > after->ordinal + 1
                                    ? e->record_count - after->ordinal - 1
                                    : 0;
                out.current_shard_records_left = left;
                out.records_remaining += left;
                if (left > 0) {
                    out.shards_remaining += 1;
                }
                continue;
            }
        }
        // No resume position (from the beginning), or entry fully after it:
        // the whole shard is pending.
        out.records_remaining += e->record_count;
        out.shards_remaining += 1;
    }

    // Time-anchored fallback for a stranded watermark. Position-based counting
    // above found nothing, but the resume position carries a seal timestamp and
    // there are sealed shards sealed strictly after it: this happens when the
    // local store was rebuilt and its shard-id counter rewound below the
    // persisted watermark, so every current shard sorts *before* a position
    // that can never be reached again. Fall back to wall-clock time, which
    // never rewinds. Only engaged when position semantics are exhausted, so
    // normal monotonic operation is unaffected.
    if (out.shards_remaining == 0 && out.records_remaining == 0
        && after != nullptr && after->seal_ts != 0) {
        n00b_list_foreach(*store->catalog, p) {
            n00b_store_catalog_entry_t *e = *p;
            if (!rocs_store_catalog_entry_visible_sealed(e)) {
                continue;
            }
            if (e->seal_ts <= after->seal_ts) {
                continue;
            }
            out.records_remaining += e->record_count;
            out.shards_remaining += 1;
        }
    }

    return n00b_result_ok(n00b_store_backlog_t, out);
}

n00b_result_t(uint64_t)
n00b_store_catalog_visible_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }
    if (store->borrowed_catalog_enumeration_disabled) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t count = 0;
    n00b_list_foreach(*store->catalog, p) {
        if (rocs_store_catalog_entry_visible_sealed(*p)) {
            count++;
        }
    }
    return n00b_result_ok(uint64_t, count);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_visible_entry_at(n00b_store_t *store, uint64_t index)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }
    if (store->borrowed_catalog_enumeration_disabled) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    if (index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                              n00b_option_none(n00b_store_catalog_entry_t *));
    }

    uint64_t visible_index = 0;
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)) {
            continue;
        }
        if (visible_index == index) {
            return n00b_result_ok(
                n00b_option_t(n00b_store_catalog_entry_t *),
                n00b_option_set(n00b_store_catalog_entry_t *, entry));
        }
        visible_index++;
    }

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                          n00b_option_none(n00b_store_catalog_entry_t *));
}

n00b_result_t(n00b_option_t(n00b_store_catalog_resume_entry_t))
n00b_store_catalog_visible_entry_after(n00b_store_t     *store,
                                       n00b_store_pos_t *after)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_resume_entry_t),
                               N00B_STORE_ERR_ARG);
    }

    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_resume_entry_t),
                               N00B_STORE_ERR_STATE);
    }
    if (store->borrowed_catalog_enumeration_disabled) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_resume_entry_t),
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        if (!rocs_store_catalog_entry_visible_sealed(entry)
            || entry->record_count == 0) {
            continue;
        }

        uint64_t start_ordinal = 0;
        if (after != nullptr) {
            if (entry->generation < after->generation
                || (entry->generation == after->generation
                    && entry->shard_id < after->shard_id)) {
                continue;
            }
            if (entry->generation == after->generation
                && entry->shard_id == after->shard_id) {
                start_ordinal = after->ordinal == UINT64_MAX
                                    ? UINT64_MAX
                                    : after->ordinal + 1;
            }
        }
        if (start_ordinal >= entry->record_count) {
            continue;
        }

        n00b_store_catalog_resume_entry_t out = {
            .entry         = entry,
            .index         = i,
            .generation    = entry->generation,
            .shard_id      = entry->shard_id,
            .record_count  = entry->record_count,
            .start_ordinal = start_ordinal,
        };
        return n00b_result_ok(
            n00b_option_t(n00b_store_catalog_resume_entry_t),
            n00b_option_set(n00b_store_catalog_resume_entry_t, out));
    }

    // Time-anchored fallback: no shard sorts after the resume position, but the
    // position carries a seal timestamp and a shard was sealed strictly after
    // it. This is the store-rebuild / shard-id-rewind case (see
    // n00b_store_catalog_backlog). Resume at the oldest such shard, from its
    // start, using wall-clock time as the anchor position can no longer trust.
    if (after != nullptr && after->seal_ts != 0) {
        n00b_store_catalog_resume_entry_t best = {};
        bool                              have_best = false;
        for (uint64_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, (size_t)i);
            if (!rocs_store_catalog_entry_visible_sealed(entry)
                || entry->record_count == 0) {
                continue;
            }
            if (entry->seal_ts <= after->seal_ts) {
                continue;
            }
            if (!have_best || entry->seal_ts < best.entry->seal_ts) {
                best = (n00b_store_catalog_resume_entry_t){
                    .entry         = entry,
                    .index         = i,
                    .generation    = entry->generation,
                    .shard_id      = entry->shard_id,
                    .record_count  = entry->record_count,
                    .start_ordinal = 0,
                };
                have_best = true;
            }
        }
        if (have_best) {
            return n00b_result_ok(
                n00b_option_t(n00b_store_catalog_resume_entry_t),
                n00b_option_set(n00b_store_catalog_resume_entry_t, best));
        }
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_catalog_resume_entry_t),
        n00b_option_none(n00b_store_catalog_resume_entry_t));
}

n00b_result_t(bool)
n00b_store_catalog_test_set_borrowed_enumeration_disabled(
    n00b_store_t *store,
    bool          disabled)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_mutex_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    store->borrowed_catalog_enumeration_disabled = disabled;
    n00b_mutex_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_shard(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }

    // The public find takes commit_lock(read) so it is safe to call from a
    // query running concurrently with the seal worker / prune, which mutate
    // store->catalog (list_push / list_delete) under commit_lock(write). The
    // raw, UNLOCKED rocs_store_catalog_find_raw stays for callers that already
    // hold commit_lock (seal/rotate/recovery) -- locking here would self-deadlock
    // those. The returned entry stays valid after unlock: it is reachable from
    // the caller's stack (the pinning GC keeps it alive even if prune unlinks it
    // from the list) and its fields are immutable once sealed. Only the live
    // callers (query.c, the wax cache-output tool) use this wrapper; no
    // commit_lock(write) holder does. Reads are re-entrant, so a caller already
    // under commit_lock(read) nests safely.
    n00b_option_t(n00b_store_catalog_entry_t *) found =
        rocs_store_catalog_find_raw(store, shard_id);
    if (n00b_option_is_set(found)
        && !rocs_store_catalog_entry_visible_sealed(n00b_option_get(found))) {
        found = n00b_option_none(n00b_store_catalog_entry_t *);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *), found);
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_any_shard(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }

    n00b_option_t(n00b_store_catalog_entry_t *) found =
        rocs_store_catalog_find_raw(store, shard_id);

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *), found);
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

n00b_result_t(n00b_store_catalog_entry_state_t)
n00b_store_catalog_entry_get_state(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(n00b_store_catalog_entry_state_t,
                               N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_catalog_entry_state_t,
                          (n00b_store_catalog_entry_state_t)entry->state);
}

n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_state_name(n00b_store_catalog_entry_state_t state)
{
    switch (state) {
    case N00B_STORE_CATALOG_ENTRY_STATE_SEALED:
        return n00b_result_ok(n00b_string_t *, r"sealed");
    case N00B_STORE_CATALOG_ENTRY_STATE_RETIRED_HOT:
        return n00b_result_ok(n00b_string_t *, r"retired_hot");
    case N00B_STORE_CATALOG_ENTRY_STATE_FAILED_SEAL:
        return n00b_result_ok(n00b_string_t *, r"failed_seal");
    case N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED:
        return n00b_result_ok(n00b_string_t *, r"quarantined");
    case N00B_STORE_CATALOG_ENTRY_STATE_UNKNOWN:
    default:
        return n00b_result_ok(n00b_string_t *, r"unknown");
    }
}

n00b_result_t(bool)
n00b_store_catalog_entry_is_resident(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    // Lock-free read: residency is a snapshot the moment we look.
    return n00b_result_ok(bool, rocs_entry_map_load(entry) != nullptr);
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

    // ---- Fast path: already resident -> pin lock-free ---------------------
    // No lock: publish a pin (atomic), then re-check the mapping with a seq_cst
    // fence. This is the reader half of the unload handshake -- if a concurrent
    // (write-locked) unload cleared the map, it will observe our pin and abort
    // the munmap, and if it cleared before our pin was visible we re-read null
    // here and back off. A held pin then keeps the mapping alive: unload refuses
    // while resident_pins != 0. Pins are not a mutex, so this survives the store
    // pool relocating (unlike a futex-backed lock).
    if (rocs_entry_map_load(entry) != nullptr) {
        n00b_atomic_add(&entry->resident_pins, 1);
        n00b_atomic_add(&store->active_pins, 1);
        atomic_thread_fence(memory_order_seq_cst);
        if (rocs_entry_map_load(entry) != nullptr) {
            // Reusing an already-mapped shard is a resident cache hit. The slow
            // path counts hits in load_entry, but this lock-free fast path
            // returns before ever calling it, so count the hit here too.
            n00b_atomic_add(&store->resident_cache_hits, 1);
            n00b_store_resident_shard_t *resident = n00b_alloc_with_opts(
                n00b_store_resident_shard_t,
                &(n00b_alloc_opts_t){
                    .allocator = allocator,
                });
            resident->store    = store;
            resident->entry    = entry;
            resident->released = false;
            return n00b_result_ok(n00b_store_resident_shard_t *, resident);
        }
        // Raced with an unload; drop the speculative pin, fall to the map path.
        n00b_atomic_add(&entry->resident_pins, -1);
        n00b_atomic_add(&store->active_pins, -1);
    }

    // ---- Slow path: map the shard (a write) under residency_lock ----------
    // Only the mmap/install is serialized -- readers never take this lock. The
    // lock also guards the catalog walk against concurrent seal append / prune
    // delete and keeps `entry` alive through the pin below. We pin before
    // releasing the lock, so no unload can reclaim what we just mapped.
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_STATE);
    }
    if (!rocs_store_catalog_owns_entry(store, entry)) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_ARG);
    }

    auto map_r = rocs_store_resident_load_entry(store, entry);
    if (n00b_result_is_err(map_r)) {
        n00b_mutex_unlock(store->residency_lock);
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
    n00b_atomic_add(&entry->resident_pins, 1);
    n00b_atomic_add(&store->active_pins, 1);
    n00b_mutex_unlock(store->residency_lock);

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
    // Lock-free: the caller holds a pin from acquire, so unload cannot munmap
    // this mapping (it refuses while resident_pins != 0). last_access_ns is an
    // LRU hint; a racy write is benign.
    if (resident->released) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }
    n00b_store_map_t *map = rocs_entry_map_load(resident->entry);
    if (map == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }
    resident->entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
    return n00b_result_ok(n00b_store_map_t *, map);
}

n00b_result_t(bool)
n00b_store_resident_shard_release(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr || resident->store == nullptr
        || resident->entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    // Lock-free unpin. Sealed-shard release does NOT touch retired-hot arena
    // reclaim: that is hot-arena domain (gated by hot_snapshot_pins, drained at
    // rotation) and lives on the hot stream/pin release paths -- coupling it here
    // was what left the store's hot_pin double-unlocked.
    if (resident->released) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (n00b_atomic_load(&resident->entry->resident_pins) == 0
        || n00b_atomic_load(&resident->store->active_pins) == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    resident->released = true;
    n00b_atomic_add(&resident->entry->resident_pins, -1);
    n00b_atomic_add(&resident->store->active_pins, -1);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_bytes(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_mutex_lock(store->residency_lock);
    uint64_t resident_bytes = store->resident_bytes;
    n00b_mutex_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_bytes);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_shard_count(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_mutex_lock(store->residency_lock);
    uint64_t resident_shards = store->resident_shards;
    n00b_mutex_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_shards);
}

n00b_result_t(n00b_store_residency_stats_t)
n00b_store_residency_stats(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_residency_stats_t,
                               N00B_STORE_ERR_ARG);
    }
    uint64_t retired_hot_allocators = 0;
    n00b_mutex_lock(store->residency_lock);
    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry != nullptr && entry->retired_hot_allocator != nullptr) {
                retired_hot_allocators++;
            }
        }
    }
    n00b_store_residency_stats_t stats = {
        .resident_bytes = store->resident_bytes,
        .resident_shards = store->resident_shards,
        .active_pins = store->active_pins,
        .retired_hot_allocators = retired_hot_allocators,
        .cache_hits = store->resident_cache_hits,
        .cache_misses = store->resident_cache_misses,
        .unloads = store->resident_unloads,
        .unload_bytes = store->resident_unload_bytes,
    };
    n00b_mutex_unlock(store->residency_lock);
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

    n00b_store_shard_t *hot = store->hot_shard;
    if (hot != nullptr) {
        stats.hot_shard_id      = hot->shard_id;
        stats.hot_record_count  = hot->record_count;
        stats.hot_live_index    =
            rocs_store_hot_visible_count_unlocked(store, hot);
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
    stats.hot_active_writers      =
        n00b_atomic_load(&store->hot_active_writers);
    stats.hot_writer_reservations =
        n00b_atomic_load(&store->hot_writer_reservations);
    stats.hot_writer_completions =
        n00b_atomic_load(&store->hot_writer_completions);
    stats.hot_ready_out_of_order_publications =
        n00b_atomic_load(&store->hot_ready_out_of_order_publications);
    stats.hot_worker_range_commits =
        n00b_atomic_load(&store->hot_worker_range_commits);
    stats.hot_worker_range_tombstones =
        n00b_atomic_load(&store->hot_worker_range_tombstones);
    stats.seal_active_writer_waits =
        n00b_atomic_load(&store->seal_active_writer_waits);
    stats.seal_worker_count = (uint64_t)store->seal_worker_count;
    rocs_store_seal_queue_snapshot(store->seal_queue,
                                   &stats.seal_queue_pending,
                                   &stats.seal_queue_in_flight);
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
            if (entry->state == ROCS_STORE_CATALOG_ENTRY_QUARANTINED) {
                stats.quarantined_shards++;
                stats.quarantined_records += entry->record_count;
                stats.quarantined_bytes += entry->byte_len;
                continue;
            }
            if (!rocs_store_catalog_entry_visible_sealed(entry)) {
                continue;
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

    n00b_mutex_lock(store->residency_lock);
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

    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry != nullptr && entry->retired_hot_allocator != nullptr) {
                stats.retired_hot_allocators++;
                stats.retired_hot_records +=
                    entry->retired_hot_record_count;
            }
        }
    }
    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry != nullptr
                && entry->state == ROCS_STORE_CATALOG_ENTRY_FAILED_SEAL) {
                stats.failed_seal_jobs++;
                stats.failed_seal_records += entry->record_count;
            }
        }
    }
    n00b_mutex_unlock(store->residency_lock);

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
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t target_bytes = target_resident_bytes;
    if (target_bytes == 0 && store->residency_policy.max_resident_bytes != 0) {
        target_bytes = store->residency_policy.max_resident_bytes;
    }
    uint64_t target_shards = store->residency_policy.max_resident_shards;

    uint64_t released = rocs_store_evict_over_budget_locked(store,
                                                            target_bytes,
                                                            target_shards,
                                                            nullptr);

    n00b_mutex_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, released);
}

n00b_result_t(n00b_string_t *)
n00b_store_pos_encode(n00b_store_pos_t pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    static const char hex_digits[] = "0123456789abcdef";
    // Up to 4 x 8-byte words, 2 hex chars per byte. A position with no seal_ts
    // encodes to the legacy 48-char form (generation, shard_id, ordinal) so
    // tokens that carry no wall-clock anchor stay byte-identical to pre-seal_ts
    // tokens; only a non-zero seal_ts appends the 4th word (64 chars). Decode
    // accepts both widths.
    char              token_bytes[64];
    uint64_t          words[4] = {
        pos.generation,
        pos.shard_id,
        pos.ordinal,
        pos.seal_ts,
    };
    uint64_t nwords = pos.seal_ts != 0 ? 4 : 3;

    uint64_t out = 0;
    for (uint64_t w = 0; w < nwords; w++) {
        for (uint8_t i = 0; i < 8; i++) {
            uint8_t byte =
                (uint8_t)((words[w] >> (56 - (i * 8))) & UINT64_C(0xff));
            token_bytes[out++] = hex_digits[byte >> 4];
            token_bytes[out++] = hex_digits[byte & 0x0f];
        }
    }

    n00b_string_t *token = n00b_string_from_raw(token_bytes,
                                                (int64_t)(nwords * 16),
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
    // 48 chars = legacy token (no seal_ts); 64 chars = current token with the
    // appended seal_ts word. Any other width is malformed.
    if (token == nullptr || token->data == nullptr
        || (token->u8_bytes != 48 && token->u8_bytes != 64)) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    auto generation_r = rocs_store_pos_decode_u64(token, 0);
    auto shard_r      = rocs_store_pos_decode_u64(token, 16);
    auto ordinal_r    = rocs_store_pos_decode_u64(token, 32);
    if (n00b_result_is_err(generation_r) || n00b_result_is_err(shard_r)
        || n00b_result_is_err(ordinal_r)) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    uint64_t seal_ts = 0;
    if (token->u8_bytes == 64) {
        auto seal_ts_r = rocs_store_pos_decode_u64(token, 48);
        if (n00b_result_is_err(seal_ts_r)) {
            return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
        }
        seal_ts = n00b_result_get(seal_ts_r);
    }

    return n00b_result_ok(n00b_store_pos_t,
                          ((n00b_store_pos_t){
                              .shard_id   = n00b_result_get(shard_r),
                              .ordinal    = n00b_result_get(ordinal_r),
                              .generation = n00b_result_get(generation_r),
                              .seal_ts    = seal_ts,
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

static bool
rocs_stream_entry_after(n00b_store_catalog_entry_t *entry,
                        n00b_store_pos_t          *after,
                        uint64_t                  *start_ordinal)
{
    if (!rocs_store_catalog_entry_visible_sealed(entry)
        || entry->record_count == 0) {
        return false;
    }

    uint64_t start = 0;
    if (after != nullptr) {
        if (entry->generation < after->generation
            || (entry->generation == after->generation
                && entry->shard_id < after->shard_id)) {
            return false;
        }
        if (entry->generation == after->generation
            && entry->shard_id == after->shard_id) {
            start = after->ordinal == UINT64_MAX ? UINT64_MAX
                                                 : after->ordinal + 1;
        }
    }

    if (start >= entry->record_count) {
        return false;
    }
    if (start_ordinal != nullptr) {
        *start_ordinal = start;
    }
    return true;
}

// Time-anchored resume predicate: a visible sealed shard qualifies if it was
// sealed strictly after `after_seal_ts` (start from its first record). This is
// the fallback used when position-based resume is stranded — the local store
// was rebuilt and its shard-id counter rewound below the persisted watermark,
// so no shard sorts after the position, yet newer-by-wall-clock data exists.
// Time never rewinds, so it is the durable anchor. Callers engage this only
// after the position pass finds nothing, leaving normal operation untouched.
static bool
rocs_stream_entry_after_time(n00b_store_catalog_entry_t *entry,
                             uint64_t                    after_seal_ts,
                             uint64_t                   *start_ordinal)
{
    if (!rocs_store_catalog_entry_visible_sealed(entry)
        || entry->record_count == 0) {
        return false;
    }
    if (entry->seal_ts <= after_seal_ts) {
        return false;
    }
    if (start_ordinal != nullptr) {
        *start_ordinal = 0;
    }
    return true;
}

static n00b_result_t(bool)
rocs_stream_release_resident(n00b_store_record_stream_t *stream)
{
    if (stream == nullptr || stream->resident == nullptr) {
        return n00b_result_ok(bool, true);
    }

    n00b_store_resident_shard_t *resident = stream->resident;
    stream->resident       = nullptr;
    stream->root           = nullptr;
    stream->resident_index = UINT64_MAX;
    return n00b_store_resident_shard_release(resident);
}

n00b_result_t(n00b_store_record_stream_t *)
n00b_store_record_stream_open(n00b_store_t     *store,
                              n00b_store_pos_t *after) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        ROCS_STORE_CONTRACT_CATALOG_OWNED(store);
    }
    ensures {
        n00b_result_is_err(result)
            || (n00b_result_value(result) != nullptr
                && ROCS_STORE_RECORD_STREAM_CONTRACT_PINNED(
                    n00b_result_value(result)));
    }
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_record_stream_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_record_stream_t *stream = n00b_alloc_with_opts(
        n00b_store_record_stream_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    stream->store          = store;
    stream->allocator      = allocator;
    stream->closed         = false;
    stream->pinned         = false;
    stream->sealed_shard_ids =
        rocs_store_shard_id_list_new(.allocator = allocator);
    stream->sealed         = nullptr;
    stream->sealed_count   = 0;
    stream->sealed_index   = 0;
    stream->sealed_ordinal = 0;
    stream->resident       = nullptr;
    stream->root           = nullptr;
    stream->resident_index = UINT64_MAX;
    stream->hot_records    = nullptr;
    stream->hot_count      = 0;
    stream->hot_ordinal    = 0;
    stream->hot_snapshot_pinned = false;

    // Lock-free pin: publish the pin first, then validate the store is still
    // open (pin-before-check pairs with teardown, which drains active_pins after
    // marking the store closed). active_record_streams is a self-locking list.
    if (store->active_record_streams == nullptr
        || stream->sealed_shard_ids == nullptr) {
        return n00b_result_err(n00b_store_record_stream_t *,
                               N00B_STORE_ERR_STATE);
    }
    n00b_atomic_add(&store->active_pins, 1);
    atomic_thread_fence(memory_order_seq_cst);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_atomic_add(&store->active_pins, -1);
        return n00b_result_err(n00b_store_record_stream_t *,
                               N00B_STORE_ERR_STATE);
    }
    stream->pinned = true;
    n00b_list_push(*store->active_record_streams, stream);

    uint64_t sealed_count = 0;
    uint64_t catalog_len  = (uint64_t)n00b_list_len(*store->catalog);
    for (uint64_t i = 0; i < catalog_len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        if (entry == nullptr) {
            (void)n00b_store_record_stream_close(stream);
            return n00b_result_err(n00b_store_record_stream_t *,
                                   N00B_STORE_ERR_STATE);
        }
        if (rocs_stream_entry_after(entry, after, nullptr)) {
            sealed_count++;
        }
    }

    // Position-based resume found no sealed shards, but the watermark carries a
    // seal timestamp: fall back to time-anchored resume (see
    // rocs_stream_entry_after_time). Recount under the time predicate; if it
    // finds shards, the fill pass below uses the same predicate.
    bool time_fallback = false;
    if (sealed_count == 0 && after != nullptr && after->seal_ts != 0) {
        for (uint64_t i = 0; i < catalog_len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, (size_t)i);
            if (rocs_stream_entry_after_time(entry, after->seal_ts, nullptr)) {
                sealed_count++;
            }
        }
        time_fallback = sealed_count != 0;
    }

    if (sealed_count != 0) {
        stream->sealed = n00b_alloc_array(
            rocs_stream_catalog_snapshot_t,
            (int64_t)sealed_count,
            .allocator = allocator);
    }

    uint64_t sealed_index = 0;
    for (uint64_t i = 0; i < catalog_len; i++) {
        n00b_store_catalog_entry_t *entry =
            n00b_list_get(*store->catalog, (size_t)i);
        uint64_t start_ordinal = 0;
        bool     include       = time_fallback
                    ? rocs_stream_entry_after_time(entry,
                                                   after->seal_ts,
                                                   &start_ordinal)
                    : rocs_stream_entry_after(entry, after, &start_ordinal);
        if (!include) {
            continue;
        }
        stream->sealed[sealed_index++] = (rocs_stream_catalog_snapshot_t){
            .entry         = entry,
            .generation    = entry->generation,
            .shard_id      = entry->shard_id,
            .record_count  = entry->record_count,
            .start_ordinal = start_ordinal,
            .seal_ts       = entry->seal_ts,
        };
        if (!rocs_store_shard_id_list_contains(stream->sealed_shard_ids,
                                               entry->shard_id)) {
            n00b_list_push(*stream->sealed_shard_ids, entry->shard_id);
        }
    }
    stream->sealed_count = sealed_index;

    n00b_store_shard_t *hot = store->hot_shard;
    uint64_t hot_visible =
        rocs_store_hot_visible_count_unlocked(store, hot);
    if (hot != nullptr && hot->records != nullptr && hot_visible != 0) {
        n00b_store_pos_t hot_last = {
            .generation = store->generation,
            .shard_id   = hot->shard_id,
            .ordinal    = hot_visible - 1,
        };
        // When resuming by seal_ts (a rewound/stranded watermark), the hot tail
        // is newer than every sealed shard, so include all of it. Position
        // comparison against a stranded watermark would wrongly exclude it,
        // leaving live records unreachable until the shard-id counter climbed
        // back above the stale watermark.
        if (after == nullptr || time_fallback
            || n00b_store_pos_compare(*after, hot_last) < 0) {
            uint64_t start_ordinal = 0;
            if (!time_fallback && after != nullptr
                && after->generation == store->generation
                && after->shard_id == hot->shard_id) {
                start_ordinal = after->ordinal == UINT64_MAX
                                    ? UINT64_MAX
                                    : after->ordinal + 1;
            }
            if (start_ordinal < hot_visible) {
                uint64_t count = hot_visible - start_ordinal;
                stream->hot_records = n00b_alloc_array(
                    n00b_string_t *,
                    (int64_t)count,
                    .allocator = allocator);
                for (uint64_t i = 0; i < count; i++) {
                    stream->hot_records[i] =
                        n00b_list_get(*hot->records,
                                      (size_t)(start_ordinal + i));
                }
                stream->hot_base = (n00b_store_pos_t){
                    .generation = store->generation,
                    .shard_id   = hot->shard_id,
                    .ordinal    = start_ordinal,
                };
                stream->hot_count = count;
                stream->hot_snapshot_pinned = true;
                store->hot_snapshot_pins++;
            }
        }
    }

    return n00b_result_ok(n00b_store_record_stream_t *, stream);
}

n00b_result_t(n00b_option_t(n00b_store_record_stream_item_t))
n00b_store_record_stream_next(n00b_store_record_stream_t *stream)
    requires {
        ROCS_STORE_RECORD_STREAM_CONTRACT_OPEN(stream);
    }
    ensures {
        ROCS_STORE_RECORD_STREAM_NEXT_CONTRACT_VALID_OR_EOF(result);
    }
{
    if (stream == nullptr || stream->store == nullptr) {
        return n00b_result_err(
            n00b_option_t(n00b_store_record_stream_item_t),
            N00B_STORE_ERR_ARG);
    }
    if (stream->closed) {
        return n00b_result_err(
            n00b_option_t(n00b_store_record_stream_item_t),
            N00B_STORE_ERR_STATE);
    }

    while (stream->sealed_index < stream->sealed_count) {
        rocs_stream_catalog_snapshot_t *entry =
            &stream->sealed[stream->sealed_index];
        if (stream->resident == nullptr
            || stream->resident_index != stream->sealed_index) {
            auto release_r = rocs_stream_release_resident(stream);
            if (n00b_result_is_err(release_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_record_stream_item_t),
                    n00b_result_get_err(release_r));
            }

            auto resident_r = n00b_store_resident_shard_acquire(
                stream->store,
                entry->entry,
                .allocator = stream->allocator);
            if (n00b_result_is_err(resident_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_record_stream_item_t),
                    n00b_result_get_err(resident_r));
            }
            stream->resident       = n00b_result_get(resident_r);
            stream->resident_index = stream->sealed_index;
            stream->sealed_ordinal = entry->start_ordinal;

            auto map_r = n00b_store_resident_shard_map(stream->resident);
            if (n00b_result_is_err(map_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_record_stream_item_t),
                    n00b_result_get_err(map_r));
            }
            auto root_r = n00b_store_map_root(n00b_result_get(map_r),
                                              .view_allocator =
                                                  stream->allocator);
            if (n00b_result_is_err(root_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_record_stream_item_t),
                    n00b_result_get_err(root_r));
            }
            stream->root = n00b_result_get(root_r);
        }

        if (stream->sealed_ordinal < entry->record_count) {
            uint64_t ordinal = stream->sealed_ordinal++;
            auto span_r = n00b_store_map_shard_record_span(stream->root,
                                                           ordinal);
            if (n00b_result_is_err(span_r)) {
                return n00b_result_err(
                    n00b_option_t(n00b_store_record_stream_item_t),
                    n00b_result_get_err(span_r));
            }

            n00b_store_record_stream_item_t item = {
                .pos = {
                    .generation = entry->generation,
                    .shard_id   = entry->shard_id,
                    .ordinal    = ordinal,
                    // Stamp the position with the shard's seal timestamp so a
                    // watermark built from it can resume by wall-clock time
                    // after a store rebuild rewinds shard ids (see the
                    // seal_ts fallback in the catalog/backlog readers).
                    .seal_ts    = entry->seal_ts,
                },
                .bytes = n00b_result_get(span_r),
                .hot   = false,
            };
            return n00b_result_ok(
                n00b_option_t(n00b_store_record_stream_item_t),
                n00b_option_set(n00b_store_record_stream_item_t, item));
        }

        auto release_r = rocs_stream_release_resident(stream);
        if (n00b_result_is_err(release_r)) {
            return n00b_result_err(
                n00b_option_t(n00b_store_record_stream_item_t),
                n00b_result_get_err(release_r));
        }
        stream->sealed_index++;
    }

    while (stream->hot_ordinal < stream->hot_count) {
        uint64_t       index = stream->hot_ordinal++;
        n00b_string_t *text  = stream->hot_records[index];
        if (text == nullptr || (text->u8_bytes != 0 && text->data == nullptr)) {
            return n00b_result_err(
                n00b_option_t(n00b_store_record_stream_item_t),
                N00B_STORE_ERR_STATE);
        }

        n00b_store_record_stream_item_t item = {
            .pos = {
                .generation = stream->hot_base.generation,
                .shard_id   = stream->hot_base.shard_id,
                .ordinal    = stream->hot_base.ordinal + index,
            },
            .bytes = {
                .data     = (uint8_t *)text->data,
                .byte_len = (uint64_t)text->u8_bytes,
            },
            .hot = true,
        };
        return n00b_result_ok(
            n00b_option_t(n00b_store_record_stream_item_t),
            n00b_option_set(n00b_store_record_stream_item_t, item));
    }

    return n00b_result_ok(
        n00b_option_t(n00b_store_record_stream_item_t),
        n00b_option_none(n00b_store_record_stream_item_t));
}

static bool
rocs_store_remove_record_stream_locked(n00b_store_t               *store,
                                       n00b_store_record_stream_t *stream)
{
    if (store == nullptr || store->active_record_streams == nullptr
        || stream == nullptr) {
        return false;
    }
    size_t len = n00b_list_len(*store->active_record_streams);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*store->active_record_streams, i) == stream) {
            (void)n00b_list_delete(*store->active_record_streams, i);
            return true;
        }
    }
    return false;
}

n00b_result_t(bool)
n00b_store_record_stream_close(n00b_store_record_stream_t *stream)
    requires {
        ROCS_STORE_RECORD_STREAM_CONTRACT_OPEN(stream);
    }
    ensures {
        n00b_result_is_err(result)
            || !ROCS_STORE_RECORD_STREAM_CONTRACT_OPEN(stream);
    }
{
    if (stream == nullptr || stream->store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (stream->closed) {
        return n00b_result_ok(bool, true);
    }

    auto release_r = rocs_stream_release_resident(stream);
    if (n00b_result_is_err(release_r)) {
        return n00b_result_err(bool, n00b_result_get_err(release_r));
    }

    rocs_store_retired_hot_allocator_list_t *retired = nullptr;
    if (stream->pinned) {
        n00b_mutex_lock(stream->store->residency_lock);
        if (stream->store->active_pins == 0) {
            n00b_mutex_unlock(stream->store->residency_lock);
            return n00b_result_err(bool, N00B_STORE_ERR_STATE);
        }
        if (!rocs_store_remove_record_stream_locked(stream->store, stream)) {
            n00b_mutex_unlock(stream->store->residency_lock);
            return n00b_result_err(bool, N00B_STORE_ERR_STATE);
        }
        stream->store->active_pins--;
        stream->pinned = false;
        if (stream->hot_snapshot_pinned) {
            if (stream->store->hot_snapshot_pins == 0) {
                n00b_mutex_unlock(stream->store->residency_lock);
                return n00b_result_err(bool, N00B_STORE_ERR_STATE);
            }
            stream->store->hot_snapshot_pins--;
            stream->hot_snapshot_pinned = false;
        }
        retired = rocs_store_detach_retired_hot_allocators_locked(stream->store);
        n00b_mutex_unlock(stream->store->residency_lock);
    }

    stream->closed = true;
    rocs_store_destroy_retired_hot_allocators(stream->store, retired);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_pin_t *)
n00b_store_pin_acquire(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    requires {
        ROCS_STORE_CONTRACT_OPEN(store);
    }
    ensures {
        n00b_result_is_err(result)
            || ROCS_STORE_PIN_CONTRACT_LIVE(n00b_result_value(result));
    }
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_ARG);
    }
    n00b_mutex_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins == UINT64_MAX) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }

    n00b_store_pin_t *pin = n00b_alloc_with_opts(
        n00b_store_pin_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    pin->store    = store;
    pin->allocator = allocator;
    pin->shard_ids = nullptr;
    pin->all_shards = true;
    pin->released = false;
    if (store->active_pin_handles == nullptr) {
        n00b_mutex_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }
    n00b_list_push(*store->active_pin_handles, pin);
    store->active_pins++;
    n00b_mutex_unlock(store->residency_lock);

    return n00b_result_ok(n00b_store_pin_t *, pin);
}

static bool
rocs_store_remove_pin_handle_locked(n00b_store_t     *store,
                                    n00b_store_pin_t *pin)
{
    if (store == nullptr || store->active_pin_handles == nullptr
        || pin == nullptr) {
        return false;
    }
    size_t len = n00b_list_len(*store->active_pin_handles);
    for (size_t i = 0; i < len; i++) {
        if (n00b_list_get(*store->active_pin_handles, i) == pin) {
            (void)n00b_list_delete(*store->active_pin_handles, i);
            return true;
        }
    }
    return false;
}

n00b_result_t(bool)
n00b_store_pin_narrow_to_shards(n00b_store_pin_t           *pin,
                                n00b_store_shard_id_list_t *shard_ids)
{
    if (pin == nullptr || pin->store == nullptr || shard_ids == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_store_shard_id_list_t *copy =
        rocs_store_shard_id_list_new(.allocator = pin->allocator);
    if (copy == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    size_t len = n00b_list_len(*shard_ids);
    for (size_t i = 0; i < len; i++) {
        uint64_t shard_id = n00b_list_get(*shard_ids, i);
        if (shard_id == 0
            || rocs_store_shard_id_list_contains(copy, shard_id)) {
            continue;
        }
        n00b_list_push(*copy, shard_id);
    }

    n00b_mutex_lock(pin->store->residency_lock);
    if (pin->released) {
        n00b_mutex_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    pin->shard_ids  = copy;
    pin->all_shards = false;
    n00b_mutex_unlock(pin->store->residency_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_pin_release(n00b_store_pin_t *pin)
    requires {
        ROCS_STORE_PIN_CONTRACT_LIVE(pin);
    }
    ensures {
        n00b_result_is_err(result) || n00b_result_value(result) == true;
        n00b_result_is_err(result) || !ROCS_STORE_PIN_CONTRACT_LIVE(pin);
    }
{
    if (pin == nullptr || pin->store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    n00b_mutex_lock(pin->store->residency_lock);
    if (pin->released) {
        n00b_mutex_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (pin->store->active_pins == 0) {
        n00b_mutex_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    if (!rocs_store_remove_pin_handle_locked(pin->store, pin)) {
        n00b_mutex_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    pin->store->active_pins--;
    pin->released = true;
    rocs_store_retired_hot_allocator_list_t *retired =
        rocs_store_detach_retired_hot_allocators_locked(pin->store);
    n00b_mutex_unlock(pin->store->residency_lock);

    rocs_store_destroy_retired_hot_allocators(pin->store, retired);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_active_pins(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, n00b_atomic_load(&store->active_pins));
}
