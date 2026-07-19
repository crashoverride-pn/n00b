/**
 * @file rocs/store.h
 * @brief Durable store, schema, partition, and policy declarations for rocs.
 *
 * The store layer is process-side state over VFS-backed durable shard objects.
 * It owns schemas, partition routing, residency/seal/retain policies, hot
 * shard state, catalog state, and active resource pins. These objects are not
 * marshalable shard roots and must not be embedded in sealed shard images.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/variant.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "conduit/topic.h"
#include "parsers/json.h"
#include "rocs/index.h"
#include "rocs/map.h"

typedef struct n00b_store_t                  n00b_store_t;
typedef struct n00b_store_schema_t           n00b_store_schema_t;
typedef struct n00b_store_field_t            n00b_store_field_t;
typedef struct n00b_store_partition_policy_t n00b_store_partition_policy_t;
typedef struct n00b_store_seal_policy_t      n00b_store_seal_policy_t;
typedef struct n00b_store_retain_policy_t    n00b_store_retain_policy_t;
typedef struct n00b_store_shard_retention_policy_t
    n00b_store_shard_retention_policy_t;

// Default automatic retention window: drop sealed shards older than 60 days
// (by epoch seal_ts). The sealer applies this after each commit unless a store
// is opened with retention_window_ns = 0.
#define N00B_STORE_DEFAULT_RETENTION_NS \
    (UINT64_C(60) * UINT64_C(24) * UINT64_C(60) * UINT64_C(60) \
     * UINT64_C(1000000000))

// Default total on-disk budget for sealed shards: 64 GiB. The sealer drops the
// oldest sealed shards until the total sealed byte_len is within this budget.
#define N00B_STORE_DEFAULT_RETENTION_BYTES (UINT64_C(64) << 30)

// Reserved full-text catch-all column name. Enabled per-schema via
// n00b_store_schema_new(.search_text=true). Index-only (never a record field);
// the leading "__n00b_" marks it reserved and n00b_store_schema_add_field
// rejects this name for user fields. (Plain C string: an r-string macro would
// not survive preprocessor expansion; the rocs internals use a matching
// r"..." literal.)
#define N00B_STORE_SEARCH_TEXT_COLUMN "__n00b_search_text"
typedef struct n00b_store_pin_t              n00b_store_pin_t;
typedef struct n00b_store_catalog_entry_t    n00b_store_catalog_entry_t;
typedef struct n00b_store_resident_shard_t   n00b_store_resident_shard_t;
typedef struct n00b_store_conduit_ingest_t    n00b_store_conduit_ingest_t;
typedef struct n00b_store_config_t            n00b_store_config_t;
typedef struct n00b_store_record_stream_t     n00b_store_record_stream_t;
typedef struct n00b_store_index_emit_t        n00b_store_index_emit_t;
typedef struct n00b_store_index_options_t     n00b_store_index_options_t;
typedef struct n00b_store_service_profile_t   n00b_store_service_profile_t;

typedef enum : int32_t {
    N00B_STORE_CATALOG_ENTRY_STATE_UNKNOWN = 0,
    N00B_STORE_CATALOG_ENTRY_STATE_SEALED = 1,
    N00B_STORE_CATALOG_ENTRY_STATE_RETIRED_HOT = 2,
    N00B_STORE_CATALOG_ENTRY_STATE_FAILED_SEAL = 3,
    N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED = 4,
} n00b_store_catalog_entry_state_t;

/** @brief List of source JSON buffers for batch ingest. */
typedef n00b_list_t(n00b_buffer_t *) n00b_store_source_list_t;

/** @brief Optional conduit-ingest source decoder callback. */
typedef n00b_result_t(n00b_json_node_t *) (*n00b_store_source_decoder_t)(
    n00b_buffer_t    *source,
    n00b_allocator_t *allocator);

/** @brief String terms returned by a schema search-text hook. */
typedef n00b_list_t(n00b_string_t *) n00b_store_search_text_term_list_t;

/**
 * @brief Search-text hook disposition for one string value.
 *
 * DEFAULT appends hook-provided terms, then applies ROCS's default full-text
 * tokenizer. REPLACE appends only hook-provided terms. SKIP appends neither.
 */
typedef enum : int32_t {
    N00B_STORE_SEARCH_TEXT_DEFAULT = 0,
    N00B_STORE_SEARCH_TEXT_REPLACE = 1,
    N00B_STORE_SEARCH_TEXT_SKIP    = 2,
} n00b_store_search_text_action_t;

/**
 * @brief Optional schema hook for adding/replacing catch-all terms per string.
 *
 * @param path      Dotted record path for the string when available. Array
 *                  elements inherit their parent path.
 * @param value     String value being considered for the reserved catch-all
 *                  full-text column.
 * @param out_terms Optional list of exact full-text terms to add. Terms are
 *                  case-folded and hashed as single full-text terms by ROCS;
 *                  they are not passed through the default tokenizer again.
 * @param ctx       Caller-owned context pointer from schema construction.
 * @param allocator Scratch allocator for any returned list/strings.
 */
typedef n00b_store_search_text_action_t (*n00b_store_search_text_hook_t)(
    n00b_string_t                    *path,
    n00b_string_t                    *value,
    n00b_store_search_text_term_list_t **out_terms,
    void                             *ctx,
    n00b_allocator_t                 *allocator);

/**
 * @brief Store-service admission policy for bounded ingest pressure.
 *
 * ROCS is a database: accepted rows must not be silently dropped. BLOCK waits
 * before admission until capacity exists. REJECT returns a typed pre-admission
 * failure that the caller can route to backpressure handling. There is no DROP
 * mode.
 */
typedef enum : int32_t {
    N00B_STORE_INGEST_BACKPRESSURE_BLOCK,
    N00B_STORE_INGEST_BACKPRESSURE_REJECT,
} n00b_store_ingest_backpressure_t;

/**
 * @brief Visibility/lifetime state for a submitted ingest unit.
 *
 * The service API accounts for records explicitly from pre-admission through
 * visible storage. Malformed JSON is represented by an error/tombstone record;
 * it is not accepted and then lost.
 */
typedef enum : int32_t {
    N00B_STORE_INGEST_RECEIPT_REJECTED_PRE_ADMISSION,
    N00B_STORE_INGEST_RECEIPT_ADMITTED_QUEUED,
    N00B_STORE_INGEST_RECEIPT_RANGE_RESERVED,
    N00B_STORE_INGEST_RECEIPT_ROW_POPULATING,
    N00B_STORE_INGEST_RECEIPT_READY_NOT_LIVE,
    N00B_STORE_INGEST_RECEIPT_LIVE_HOT,
    N00B_STORE_INGEST_RECEIPT_RETIRED_HOT,
    N00B_STORE_INGEST_RECEIPT_SEALED_VISIBLE,
    N00B_STORE_INGEST_RECEIPT_MALFORMED_TOMBSTONE,
} n00b_store_ingest_receipt_state_t;

/**
 * @brief Optional per-field generic index term emitter.
 *
 * Default ROCS indexing emits exact full-string terms plus split terms for
 * opted-in columns. Split terms use the ROCS text tokenizer, whose default
 * boundaries include whitespace and punctuation. A hook may add terms for
 * application-specific reference fields without baking Wax semantics into ROCS.
 * The hook receives an opaque emitter; it must use ROCS emitter helpers rather
 * than retaining internal index structures.
 */
typedef n00b_result_t(bool) (*n00b_store_index_term_hook_t)(
    n00b_store_index_emit_t *emit,
    n00b_string_t           *field_path,
    n00b_json_node_t        *field_value,
    void                    *ctx,
    n00b_allocator_t        *scratch);

/**
 * @brief Default and hook-driven index policy for service profiles.
 *
 * This is process-side policy only. It is not marshaled into shard images; any
 * durable schema identity needed to interpret sealed shards must be represented
 * by schema/catalog metadata.
 */
struct n00b_store_index_options_t {
    bool                          exact_full_string;
    bool                          split_terms;
    // Cap for the exact-full-string search-text term: strings longer than this
    // (in bytes) are only tokenized, not indexed as one whole-value term.
    // 0 selects the built-in default. Keeps IDs/refs exact-matchable while
    // avoiding casefolding/hashing large content blobs on the ingest thread.
    uint32_t                      exact_full_string_max_bytes;
    uint64_t                      schema_index_identity;
    n00b_store_index_term_hook_t  term_hook;
    void                         *term_hook_ctx;
};

/**
 * @brief Process-side service profile for the future ROCS ingest service API.
 *
 * The profile describes queueing, worker topology, seal concurrency, allocator
 * ownership, and index defaults. It is not part of the marshalable shard root.
 */
struct n00b_store_service_profile_t {
    uint64_t                            ingest_worker_count;
    uint64_t                            seal_worker_count;
    uint64_t                            ingest_queue_bound;
    uint64_t                            ingest_batch_bound;
    n00b_store_ingest_backpressure_t    ingest_backpressure;
    n00b_store_source_decoder_t         source_decoder;
    n00b_store_index_options_t         *index_options;
    n00b_allocator_t                   *allocator;
};

/**
 * @brief Accounting receipt for the future service ingest submission API.
 */
typedef struct {
    n00b_store_ingest_receipt_state_t state;
    uint64_t                          admitted;
    uint64_t                          rejected;
    uint64_t                          malformed;
    n00b_store_pos_t                  first_pos;
    n00b_store_pos_t                  last_pos;
    n00b_err_t                        err;
} n00b_store_ingest_receipt_t;

#define N00B_STORE_INGEST_BACKPRESSURE_CONTRACT_VALID(_bp) \
    ((_bp) == N00B_STORE_INGEST_BACKPRESSURE_BLOCK          \
     || (_bp) == N00B_STORE_INGEST_BACKPRESSURE_REJECT)

#define N00B_STORE_INGEST_RECEIPT_STATE_CONTRACT_VALID(_state)       \
    ((_state) >= N00B_STORE_INGEST_RECEIPT_REJECTED_PRE_ADMISSION    \
     && (_state) <= N00B_STORE_INGEST_RECEIPT_MALFORMED_TOMBSTONE)

#define N00B_STORE_INDEX_OPTIONS_CONTRACT_VALID(_opts)       \
    ((_opts) == nullptr                                      \
     || ((_opts)->exact_full_string || (_opts)->split_terms  \
         || (_opts)->term_hook != nullptr))

#define N00B_STORE_SERVICE_PROFILE_CONTRACT_VALID(_profile)          \
    ((_profile) != nullptr                                           \
     && (_profile)->ingest_worker_count > 0                          \
     && N00B_STORE_INGEST_BACKPRESSURE_CONTRACT_VALID(               \
         (_profile)->ingest_backpressure)                            \
     && N00B_STORE_INDEX_OPTIONS_CONTRACT_VALID((_profile)->index_options))

#define N00B_STORE_INGEST_RECEIPT_CONTRACT_ACCOUNTED(_receipt)       \
    (N00B_STORE_INGEST_RECEIPT_STATE_CONTRACT_VALID((_receipt).state) \
     && ((_receipt).admitted + (_receipt).rejected + (_receipt).malformed) > 0)

typedef n00b_variant_t(n00b_json_node_t *, n00b_buffer_t *)
    n00b_store_ingest_payload_value_t;

/**
 * @brief Conduit ingest payload plus per-record ingest options.
 *
 * @field value         Variant discriminator and value: record payloads contain
 *                      a parsed JSON node and source payloads contain a
 *                      byte-exact JSON buffer.
 * @field index_enabled Whether this record should populate configured indexes.
 *                      False still stores the row/source, but emits no index
 *                      terms for the record.
 */
typedef struct {
    n00b_store_ingest_payload_value_t value;
    bool                              index_enabled;
} n00b_store_ingest_payload_t;

/**
 * @brief Error domain for store/schema/policy operations.
 */
typedef enum : int32_t {
    N00B_STORE_OK            = 0,
    N00B_STORE_ERR_ARG       = -1,
    N00B_STORE_ERR_STATE     = -2,
    N00B_STORE_ERR_DUP_FIELD = -3,
    N00B_STORE_ERR_FIELD     = -4,
    N00B_STORE_ERR_POLICY    = -5,
    N00B_STORE_ERR_PINNED    = -6,
    N00B_STORE_ERR_VFS       = -7,
    N00B_STORE_ERR_INTERNAL  = -8,
    N00B_STORE_ERR_CORRUPT   = -9,
    N00B_STORE_ERR_RESIDENCY = -10,
    N00B_STORE_ERR_PARSE     = -11,
    N00B_STORE_ERR_INDEX     = -12,
    N00B_STORE_ERR_RETENTION = -13,
    N00B_STORE_ERR_CONFIG    = -14,
} n00b_store_err_t;

/**
 * @brief Store deployment profile for config-driven opening.
 *
 * Embedded local uses an in-memory VFS by default for no-network tests and
 * process-local tools. Service local represents a single-writer local/PVC-style
 * deployment profile; when a cache/root directory is supplied it opens a local
 * VFS backend, otherwise it keeps the same no-network memory backend shape as
 * embedded local. Service S3 validates bucket/prefix/schema inputs and opens
 * through the optional libn00b AWS S3 VFS adapter when that substrate is linked.
 */
typedef enum : int32_t {
    N00B_STORE_PROFILE_EMBEDDED_LOCAL,
    N00B_STORE_PROFILE_SERVICE_LOCAL,
    N00B_STORE_PROFILE_SERVICE_S3,
} n00b_store_profile_t;

/**
 * @brief Service topology role represented by store configuration.
 *
 * Phase 1 supports a single writer and read-replica/read-only process role.
 * Multi-writer is intentionally unsupported until catalog compare-and-swap
 * generation commits exist; env/config requests for that mode return typed
 * config errors.
 */
typedef enum : int32_t {
    N00B_STORE_WRITER_SINGLE,
    N00B_STORE_WRITER_READ_REPLICA,
    N00B_STORE_WRITER_MULTI_UNSUPPORTED,
} n00b_store_writer_mode_t;

/**
 * @brief Process-side store lifecycle state.
 */
typedef enum : int32_t {
    N00B_STORE_STATE_OPEN,
    N00B_STORE_STATE_CLOSED,
} n00b_store_state_t;

/**
 * @brief Partition strategy for future durable shard object layout.
 */
typedef enum : int32_t {
    N00B_STORE_PARTITION_NONE,
    N00B_STORE_PARTITION_TIME,
    N00B_STORE_PARTITION_HASH,
} n00b_store_partition_kind_t;

/**
 * @brief Which clock drives a time partition's shard-rollover cadence.
 *
 * This is a REQUIRED choice when constructing a time partition: the routing
 * clock determines whether ROCS's sharding can be broken by upstream data, so
 * the caller must decide explicitly rather than silently trusting a field.
 */
typedef enum : int32_t {
    /** Route by ROCS's own wall-clock ingest time. The rollover cadence is
     *  immune to producer timestamp quality (wrong units, missing values,
     *  monotonic-vs-realtime mixups, clock skew): the route only advances and
     *  never thrashes. The record's timestamp field is still stored and indexed
     *  for queries, and tracked as a per-shard event-time range for pruning. */
    N00B_STORE_TIME_SOURCE_INGEST_CLOCK,
    /** Route by the record's timestamp field (event-time bucketing). Fragile to
     *  producer data quality; choose only when event-time shard layout is
     *  required and the producer is trusted to stamp consistent epoch values. */
    N00B_STORE_TIME_SOURCE_RECORD_FIELD,
} n00b_store_time_source_t;

/**
 * @brief Raw-source retention placement.
 */
typedef enum : int32_t {
    N00B_STORE_RETAIN_NONE,
    N00B_STORE_RETAIN_INLINE,
    N00B_STORE_RETAIN_EXTERNAL,
} n00b_store_retain_kind_t;

/**
 * @brief Process-side commit event kind.
 */
typedef enum : int32_t {
    N00B_STORE_COMMIT_RECORD,
    N00B_STORE_COMMIT_SEAL,
} n00b_store_commit_kind_t;

/**
 * @brief Process-side commit notification payload.
 *
 * Commit events are best-effort notifications only. They are never marshaled
 * into shard images and are not the durable visibility boundary.
 *
 * @field ordinal Record events carry the zero-based hot-shard ordinal. Seal
 *        events use @c UINT64_MAX because they describe a whole sealed shard,
 *        not one appended record.
 */
typedef struct {
    n00b_store_commit_kind_t kind;
    uint64_t                 generation;
    uint64_t                 shard_id;
    uint64_t                 ordinal;
    uint64_t                 record_count;
    uint64_t                 seal_ts;
    n00b_string_t           *partition_key;
} n00b_store_commit_t;

N00B_CONDUIT_INBOX_IMPL(n00b_store_commit_t);

typedef n00b_conduit_message_t(n00b_store_commit_t) n00b_store_commit_msg_t;
typedef n00b_conduit_inbox_t(n00b_store_commit_t)   n00b_store_commit_inbox_t;
typedef n00b_conduit_topic_t(n00b_store_commit_t)   n00b_store_commit_topic_t;

N00B_CONDUIT_INBOX_IMPL(n00b_store_ingest_payload_t);

typedef n00b_conduit_message_t(n00b_store_ingest_payload_t)
    n00b_store_ingest_msg_t;
typedef n00b_conduit_inbox_t(n00b_store_ingest_payload_t)
    n00b_store_ingest_inbox_t;
typedef n00b_conduit_topic_t(n00b_store_ingest_payload_t)
    n00b_store_ingest_topic_t;

/** @brief Pop one store commit message from an inbox. */
#define n00b_store_commit_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_store_commit_t, inbox)

/** @brief Check whether a store commit inbox has queued messages. */
#define n00b_store_commit_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_store_commit_t, inbox)

/** @brief Return the queued user-message count for a store commit inbox. */
#define n00b_store_commit_inbox_msg_count(inbox) \
    n00b_conduit_inbox_msg_count(n00b_store_commit_t, inbox)

/** @brief Pop one store-ingest input message from an inbox. */
#define n00b_store_ingest_inbox_pop(inbox) \
    n00b_conduit_inbox_pop_msg(n00b_store_ingest_payload_t, inbox)

/** @brief Check whether a store-ingest inbox has queued messages. */
#define n00b_store_ingest_inbox_has_messages(inbox) \
    n00b_conduit_inbox_has_msg(n00b_store_ingest_payload_t, inbox)

/** @brief Return queued store-ingest user-message count. */
#define n00b_store_ingest_inbox_msg_count(inbox) \
    n00b_conduit_inbox_msg_count(n00b_store_ingest_payload_t, inbox)

/**
 * @brief Availability check for a durable resume position.
 *
 * `available == false` means the requested position is before the oldest
 * retained boundary, names a dropped or missing shard, is out of range for
 * its shard, or has a generation that does not match the open store.
 * `oldest_available` carries the first still-retained sealed position when
 * one is known, or zeros when the store currently has no sealed shard
 * boundary. Generation mismatches and other unavailable resume positions are
 * successful unavailable checks, not typed store errors.
 */
typedef struct {
    bool             available;
    n00b_store_pos_t oldest_available;
} n00b_store_resume_check_t;

/** @brief Counters for an asynchronous conduit ingest adapter. */
typedef struct {
    uint64_t   submitted;
    uint64_t   committed;
    uint64_t   failed;
    uint64_t   malformed;
    uint64_t   inbox_queued;
    uint64_t   worker_queued;
    uint64_t   worker_in_flight;
    n00b_err_t last_error;
} n00b_store_conduit_ingest_stats_t;

/**
 * @brief Process-side sealed-shard residency counters.
 *
 * Resident cache hits count sealed-shard acquisitions that reuse an already
 * loaded resident map. Misses count acquisitions that must load the shard
 * through VFS before pinning it. Unload counters cover resident-map unload
 * operations from trim, retention, or close paths; they do not count durable
 * object deletion or VFS cache eviction. Retired hot allocators are sealed
 * hot-shard arenas waiting for destruction; under normal operation this should
 * be zero immediately after seal cleanup.
 */
typedef struct {
    uint64_t resident_bytes;
    uint64_t resident_shards;
    uint64_t active_pins;
    uint64_t retired_hot_allocators;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t unloads;
    uint64_t unload_bytes;
} n00b_store_residency_stats_t;

/**
 * @brief Process-side rocs memory/accounting snapshot.
 *
 * This is intended for health endpoints and live diagnostics. It reports
 * counters already maintained by the store and its hot-shard allocator; it does
 * not walk arbitrary GC roots or perform expensive object graph inspection.
 */
typedef struct {
    uint64_t hot_shard_id;
    uint64_t hot_record_count;
    uint64_t hot_live_index;
    uint64_t hot_active_writers;
    uint64_t hot_writer_reservations;
    uint64_t hot_writer_completions;
    uint64_t hot_ready_out_of_order_publications;
    uint64_t hot_worker_range_commits;
    uint64_t hot_worker_range_tombstones;
    uint64_t seal_active_writer_waits;
    uint64_t seal_worker_count;
    uint64_t seal_queue_pending;
    uint64_t seal_queue_in_flight;
    uint64_t hot_byte_estimate;
    uint64_t hot_record_text_bytes;
    uint64_t hot_raw_bytes;
    uint64_t hot_column_count;
    uint64_t hot_pool_mapped_bytes;
    uint64_t hot_pool_pages;
    uint64_t hot_pool_big_maps;
    uint64_t hot_pool_big_unmaps;
    uint64_t hot_arena_used_bytes;
    uint64_t hot_arena_size_bytes;
    uint64_t hot_destroy_count;
    uint64_t hot_destroy_records;
    uint64_t hot_destroy_last_pool_mapped_bytes;
    uint64_t hot_destroy_last_pool_pages;
    uint64_t hot_destroy_last_pool_big_maps;
    uint64_t hot_destroy_last_pool_big_unmaps;
    uint64_t hot_destroy_last_arena_used_bytes;
    uint64_t hot_destroy_last_arena_size_bytes;
    uint64_t hot_destroy_total_pool_mapped_bytes;
    uint64_t hot_destroy_total_pool_pages;
    uint64_t hot_destroy_total_arena_size_bytes;
    uint64_t hot_destroy_registry_pool_bytes_before;
    uint64_t hot_destroy_registry_pool_bytes_after;
    uint64_t hot_destroy_registry_pool_unmapped_bytes;
    uint64_t hot_destroy_registry_managed_unmapped_bytes;
    uint64_t catalog_entries;
    uint64_t catalog_generation;
    uint64_t catalog_object_path_bytes;
    uint64_t catalog_partition_key_bytes;
    uint64_t catalog_etag_bytes;
    uint64_t catalog_string_bytes;
    uint64_t sealed_shards;
    uint64_t sealed_records;
    uint64_t sealed_bytes;
    uint64_t quarantined_shards;
    uint64_t quarantined_records;
    uint64_t quarantined_bytes;
    uint64_t sealed_min_bytes;
    uint64_t sealed_max_bytes;
    uint64_t sealed_avg_bytes;
    uint64_t sealed_avg_records;
    uint64_t sealed_shards_le_64k;
    uint64_t sealed_shards_le_256k;
    uint64_t sealed_shards_le_1m;
    uint64_t resident_bytes;
    uint64_t resident_shards;
    uint64_t resident_mapped_bytes;
    uint64_t resident_local_mmap_shards;
    uint64_t resident_copy_mmap_shards;
    uint64_t resident_buffer_shards;
    uint64_t resident_unknown_shards;
    uint64_t active_pins;
    uint64_t retired_hot_allocators;
    uint64_t retired_hot_records;
    uint64_t failed_seal_jobs;
    uint64_t failed_seal_records;
    uint64_t resident_cache_hits;
    uint64_t resident_cache_misses;
    uint64_t resident_unloads;
    uint64_t resident_unload_bytes;
} n00b_store_memory_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a store error code.
 *
 * @param err A @c N00B_STORE_* code, usually from a result error branch.
 * @return A n00b string naming the code, or @c UNKNOWN for an unrecognized
 *         value.
 */
extern n00b_string_t *n00b_store_err_str(n00b_err_t err);

/**
 * @brief Construct profile defaults for config-driven store opening.
 *
 * @param profile Deployment profile to initialize.
 * @kw name      Optional store display name. The string is copied into the
 *               returned config.
 * @kw allocator Allocator for config-owned strings and process-side state.
 *
 * @return Ok(config) on success, or @c N00B_STORE_ERR_CONFIG for an unknown
 *         profile.
 *
 * @post The returned opaque config owns copies of public string inputs. It
 *       contains process-side defaults only; no service runtime is started and
 *       no store/query/index/live/aggregation/ranking semantics change.
 *
 * The bounded Phase 1 defaults derive resident/cache byte budgets from the
 * Linux cgroup memory limit when available, capped at 64 MiB resident bytes
 * and 256 MiB cache bytes; otherwise those caps are used directly. The default
 * resident shard budget is 64. Service S3 additionally requires bucket,
 * prefix, and schema input before @ref n00b_store_open_config can open a real
 * store. AWS credentials are not config fields; the optional S3 path delegates
 * credential resolution to libn00b AWS runtime configuration.
 */
extern n00b_result_t(n00b_store_config_t *)
n00b_store_config_default(n00b_store_profile_t profile) _kargs
{
    n00b_string_t    *name      = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct store config from environment variables.
 *
 * @kw prefix    Optional prefix prepended verbatim to every supported key.
 *               For example prefix @c r"TEST_" reads @c TEST_ROCS_PROFILE.
 * @kw allocator Allocator for config-owned strings.
 *
 * @return Ok(config) on success. Invalid profiles, booleans, numeric values,
 *         S3 endpoint/path-style values, missing SERVICE_S3 fields requested
 *         by env, or unsupported writer modes return @c N00B_STORE_ERR_CONFIG.
 *
 * Supported keys are @c ROCS_PROFILE, @c ROCS_NAME, @c ROCS_S3_BUCKET,
 * @c ROCS_S3_PREFIX, @c ROCS_SCHEMA, @c ROCS_AWS_REGION,
 * @c ROCS_S3_ENDPOINT, @c ROCS_S3_PATH_STYLE, @c ROCS_CACHE_DIR,
 * @c ROCS_ROOT,
 * @c ROCS_CACHE_BYTES, @c ROCS_RESIDENT_BYTES, @c ROCS_RESIDENT_SHARDS,
 * @c ROCS_HTTP_ADDR, @c ROCS_READ_ONLY, and @c ROCS_WRITER_MODE.
 * Static AWS access key/secret variables are intentionally not rocs config
 * fields and are left to the AWS runtime credential chain.
 */
extern n00b_result_t(n00b_store_config_t *)
n00b_store_config_from_env() _kargs
{
    n00b_string_t    *prefix    = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/** @brief Return a config's profile. */
extern n00b_result_t(n00b_store_profile_t)
n00b_store_config_get_profile(n00b_store_config_t *config);

/** @brief Return the copied display name, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_name(n00b_store_config_t *config);

/** @brief Set or clear the copied display name. */
extern n00b_result_t(bool)
n00b_store_config_set_name(n00b_store_config_t *config,
                           n00b_string_t       *name);

/** @brief Return the VFS store root path configured for local profiles. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_root(n00b_store_config_t *config);

/** @brief Set or clear the copied VFS store root path. */
extern n00b_result_t(bool)
n00b_store_config_set_root(n00b_store_config_t *config,
                           n00b_string_t       *root);

/** @brief Set or clear the copied cache directory (for local read replicas).
 *  Direct alternative to the @c ROCS_CACHE_DIR env var. */
extern n00b_result_t(bool)
n00b_store_config_set_cache_dir(n00b_store_config_t *config,
                                n00b_string_t       *cache_dir);

/** @brief Set the writer topology mode. Direct alternative to the
 *  @c ROCS_WRITER_MODE env var. */
extern n00b_result_t(bool)
n00b_store_config_set_writer_mode(n00b_store_config_t      *config,
                                  n00b_store_writer_mode_t  mode);

/** @brief Return the copied SERVICE_S3 bucket, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_bucket(n00b_store_config_t *config);

/** @brief Return the copied SERVICE_S3 prefix, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_prefix(n00b_store_config_t *config);

/**
 * @brief Set SERVICE_S3 bucket and prefix.
 *
 * Both strings are copied. SERVICE_S3 open validation rejects missing or empty
 * values; other profiles reject S3-only settings as incompatible config.
 */
extern n00b_result_t(bool)
n00b_store_config_set_s3(n00b_store_config_t *config,
                         n00b_string_t       *bucket,
                         n00b_string_t       *prefix);

/** @brief Return copied ROCS_SCHEMA text/path input, when supplied by env. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_schema_source(n00b_store_config_t *config);

/** @brief Return copied AWS region override, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_aws_region(n00b_store_config_t *config);

/** @brief Return copied S3 endpoint override, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_s3_endpoint(n00b_store_config_t *config);

/** @brief Return configured S3 path-style behavior, when set. */
extern n00b_result_t(n00b_option_t(bool))
n00b_store_config_get_s3_path_style(n00b_store_config_t *config);

/** @brief Return copied cache directory input, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_config_get_cache_dir(n00b_store_config_t *config);

/** @brief Return the configured cache byte budget. */
extern n00b_result_t(uint64_t)
n00b_store_config_get_cache_bytes(n00b_store_config_t *config);

/** @brief Return the configured resident byte budget. */
extern n00b_result_t(uint64_t)
n00b_store_config_get_resident_bytes(n00b_store_config_t *config);

/** @brief Return the configured resident shard count budget. */
extern n00b_result_t(uint64_t)
n00b_store_config_get_resident_shards(n00b_store_config_t *config);

/** @brief Return whether the config represents a read-only process role. */
extern n00b_result_t(bool)
n00b_store_config_get_read_only(n00b_store_config_t *config);

/** @brief Return the supported writer topology mode. */
extern n00b_result_t(n00b_store_writer_mode_t)
n00b_store_config_get_writer_mode(n00b_store_config_t *config);

/**
 * @brief Open a store from a profile config.
 *
 * @param schema Store schema supplied by the application. Env @c ROCS_SCHEMA is
 *               retained as config metadata for later service parsing, but
 *               Phase 1 does not parse schemas from strings during open.
 * @param config Opaque config returned by @ref n00b_store_config_default or
 *               @ref n00b_store_config_from_env.
 * @kw partition_policy Optional partition policy. Defaults to no partition.
 * @kw seal_policy      Optional seal policy. Defaults to manual seal.
 * @kw allocator Allocator for process-side store state.
 *
 * @return Ok(store) on success. Invalid config returns
 *         @c N00B_STORE_ERR_CONFIG; backend setup failures return
 *         @c N00B_STORE_ERR_VFS.
 *
 * @post This is store construction only. It does not start service request
 *       threads, add HTTP endpoints, mutate query semantics, or unmarshal
 *       sealed shards. Local profiles open a finite VFS-backed store. SERVICE_S3
 *       opens through libn00b AWS S3 VFS when that optional substrate is linked;
 *       otherwise validation succeeds but open returns a typed VFS error.
 */
extern n00b_result_t(n00b_store_t *)
n00b_store_open_config(n00b_store_schema_t *schema,
                       n00b_store_config_t *config) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
    // Retention is opt-in (0 = disabled); wax passes 60 days explicitly.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
    n00b_allocator_t              *allocator        = nullptr;
};

/**
 * @brief Construct a service profile for the future ROCS service API.
 *
 * @kw ingest_worker_count Number of scratch-isolated ingest workers behind the
 *                         single service dequeuer. Values greater than one fan
 *                         out parse/route/index-term preparation and eligible
 *                         reserved-slot fill/index commit work. The dequeuer
 *                         still reserves row order and visibility is published
 *                         only by contiguous reserved ordinal.
 * @kw seal_worker_count   Number of concurrent seal workers. Zero uses the
 *                         service default.
 * @kw ingest_queue_bound  Bounded admission queue size. Zero means use ROCS's
 *                         service default, not an unbounded queue.
 * @kw ingest_batch_bound  Maximum records drained from the admission queue into
 *                         one transient preparation batch. Zero uses ROCS's
 *                         service default and is intentionally independent of
 *                         the admission queue bound.
 * @kw ingest_backpressure Admission behavior when the bounded queue is full.
 * @kw index_options       Optional caller-owned process-side index policy.
 * @kw allocator           Allocator for process-side profile state.
 *
 * Contract macro: @ref N00B_STORE_SERVICE_PROFILE_CONTRACT_VALID.
 */
extern n00b_result_t(n00b_store_service_profile_t *)
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
};

/**
 * @brief Open the future bounded/asynchronous ROCS service profile.
 *
 * This declaration is the Phase 1 contract target. The implementation must own
 * conduit subscription, row-range reservation, hot-shard publication, seal
 * work, and catalog lifetime management behind the store API.
 */
extern n00b_result_t(n00b_store_t *)
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
    // Retention is opt-in (0 = disabled). See n00b_store_open_vfs.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
};

/**
 * @brief Submit one service-ingest payload through the future admission API.
 *
 * Implementations must return a pre-admission reject receipt or an admitted
 * receipt. They must not drop accepted records. Malformed JSON produces an
 * error/tombstone accounting path.
 *
 * Contract macro: @ref N00B_STORE_INGEST_RECEIPT_CONTRACT_ACCOUNTED.
 */
extern n00b_result_t(n00b_store_ingest_receipt_t)
n00b_store_ingest_submit(n00b_store_t                  *store,
                         n00b_store_ingest_payload_t    payload);

/** @brief Return service-owned ingest counters for a service-opened store. */
extern n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_service_ingest_stats(n00b_store_t *store);

/**
 * @brief Add one normalized term through the generic index emitter.
 *
 * Application hooks must use this API rather than retaining ROCS reverse-index
 * internals. The emitter owns ordering, duplicate policy, and allocator choice.
 */
extern n00b_result_t(bool)
n00b_store_index_emit_term(n00b_store_index_emit_t *emit,
                           n00b_string_t           *column,
                           n00b_string_t           *term);

/**
 * @brief Construct an empty mutable schema.
 *
 * @kw allocator Allocator for the schema and later field descriptors.
 * @return Ok(schema) on success.
 * @post The schema is mutable until @ref n00b_store_schema_freeze succeeds or
 *       the schema is passed to @ref n00b_store_open_vfs.
 */
extern n00b_result_t(n00b_store_schema_t *)
n00b_store_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
    // Enable the reserved full-text catch-all column (N00B_STORE_SEARCH_TEXT_COLUMN).
    // When set, ingest tokenizes every string value in the record into that one
    // column (index-only — never stored in the record body), and an unqualified
    // query (n00b_filter_any) resolves to it. The reserved name is not a usable
    // user field. DB-level switch; default off.
    bool                           search_text = false;
    n00b_store_search_text_hook_t  search_text_hook = nullptr;
    void                          *search_text_hook_ctx = nullptr;
    // Optional generic indexing policy for the reserved catch-all path.
    // When null, ROCS uses its default exact-full-string plus split-token
    // behavior. Hooks are additive unless the legacy search_text hook returns
    // REPLACE or SKIP for a value.
    n00b_store_index_options_t    *index_options = nullptr;
};

/**
 * @brief Add one field descriptor to a mutable schema.
 *
 * @param schema Mutable schema returned by @ref n00b_store_schema_new.
 * @param name   Field name. The pointer is retained, not copied. Dotted names
 *               resolve through nested JSON objects after an exact top-level
 *               key lookup misses.
 * @kw required   Whether ingest must require this field once ingest lands.
 * @kw index_kind Process-side index kind planned for this field, or
 *                @c N00B_STORE_INDEX_NONE.
 * @kw include_in_all Whether this real field is opted into schema-derived
 *                    tokens-only catch-all search for
 *                    @ref n00b_filter_any whole-word @c contains predicates.
 *                    The default is false; opting in does not create a schema
 *                    field named "all" or any other sentinel.
 * @kw ngram_n N-gram byte width for @c N00B_STORE_INDEX_NGRAM fields.
 *             Defaults to @c N00B_STORE_NGRAM_DEFAULT_N. Non-NGRAM fields
 *             must use the default value.
 * @kw postings Physical posting representation for this field's index.
 *              Defaults to sparse ordinal lists. Dense postings are intended
 *              for low-cardinality fields where most terms are non-sparse.
 *
 * @pre @p schema is mutable and @p name is non-null, non-empty, and has no
 *      empty dotted-path segment.
 * @return Ok(field) on success. Duplicate names return
 *         @c N00B_STORE_ERR_DUP_FIELD; mutation after freeze/open returns
 *         @c N00B_STORE_ERR_STATE. Invalid index kinds or n-gram sizes return
 *         @c N00B_STORE_ERR_POLICY.
 * @post The field descriptor contains schema metadata only. It does not store
 *       JSON kind/type metadata; record values remain variant-driven.
 */
extern n00b_result_t(n00b_store_field_t *)
n00b_store_schema_add_field(n00b_store_schema_t *schema,
                            n00b_string_t       *name) _kargs
{
    bool                         required       = false;
    n00b_store_index_kind_t      index_kind     = N00B_STORE_INDEX_NONE;
    bool                         include_in_all = false;
    uint8_t                      ngram_n        = N00B_STORE_NGRAM_DEFAULT_N;
    n00b_store_postings_kind_t   postings       = N00B_STORE_POSTINGS_SPARSE;
};

/**
 * @brief Freeze a schema and reject future field registration.
 *
 * @param schema Schema returned by @ref n00b_store_schema_new.
 * @return Ok(true) when @p schema is frozen. The operation is idempotent.
 * @post All later calls to @ref n00b_store_schema_add_field return
 *       @c N00B_STORE_ERR_STATE.
 */
extern n00b_result_t(bool)
n00b_store_schema_freeze(n00b_store_schema_t *schema);

/**
 * @brief Report whether a schema is frozen.
 *
 * @param schema Schema returned by @ref n00b_store_schema_new.
 * @return Ok(boolean), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(bool)
n00b_store_schema_is_frozen(n00b_store_schema_t *schema);

/**
 * @brief Return the number of field descriptors in a schema.
 *
 * @param schema Schema returned by @ref n00b_store_schema_new.
 * @return Ok(count), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_schema_get_field_count(n00b_store_schema_t *schema);

/**
 * @brief Look up a field descriptor by name.
 *
 * @param schema Schema returned by @ref n00b_store_schema_new.
 * @param name   Field name to find.
 * @return Ok(some(field)) when present, Ok(none) when absent, or
 *         @c N00B_STORE_ERR_ARG for invalid arguments.
 */
extern n00b_result_t(n00b_option_t(n00b_store_field_t *))
n00b_store_schema_find_field(n00b_store_schema_t *schema,
                             n00b_string_t       *name);

/**
 * @brief Borrow a field descriptor's name.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(name), or @c N00B_STORE_ERR_ARG for null/malformed descriptors.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_field_get_name(n00b_store_field_t *field);

/**
 * @brief Return whether a field is marked required.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(required), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(bool)
n00b_store_field_is_required(n00b_store_field_t *field);

/**
 * @brief Return the process-side index kind configured for a field.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(index kind), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(n00b_store_index_kind_t)
n00b_store_field_get_index_kind(n00b_store_field_t *field);

/**
 * @brief Return whether a field is opted into schema-derived catch-all search.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(include flag), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(bool)
n00b_store_field_include_in_all(n00b_store_field_t *field);

/**
 * @brief Return the n-gram byte width configured for a field.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(width) for all fields. Non-NGRAM fields report
 *         @c N00B_STORE_NGRAM_DEFAULT_N because schema mutation rejects
 *         non-default n-gram widths for those fields. Returns
 *         @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint8_t)
n00b_store_field_get_ngram_n(n00b_store_field_t *field);

/**
 * @brief Return the posting representation configured for a field.
 *
 * @param field Field descriptor returned by a schema lookup/add call.
 * @return Ok(representation), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(n00b_store_postings_kind_t)
n00b_store_field_get_postings_kind(n00b_store_field_t *field);

/**
 * @brief Construct a no-partition policy.
 *
 * @kw allocator Allocator for the policy.
 * @return Ok(policy). All records route to @c default.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_none() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a time-bucket partition policy.
 *
 * @param field        JSON object field naming the record's event timestamp.
 *                     Stored/indexed and tracked as a per-shard event-time
 *                     range; used for routing only under
 *                     @c N00B_STORE_TIME_SOURCE_RECORD_FIELD.
 * @param bucket_width Positive timestamp units per bucket.
 * @param time_source  REQUIRED. Which clock drives shard rollover. Use
 *                     @c N00B_STORE_TIME_SOURCE_INGEST_CLOCK for a cadence that
 *                     cannot be broken by upstream timestamp data;
 *                     @c N00B_STORE_TIME_SOURCE_RECORD_FIELD for event-time
 *                     bucketing on a trusted producer.
 * @kw allocator Allocator for the policy.
 *
 * @return Ok(policy) on success. Null/empty fields and zero bucket width return
 *         @c N00B_STORE_ERR_ARG.
 * @post Under @c RECORD_FIELD, missing/non-integer/non-positive record values
 *       route to the current ingest-time bucket (no thrash). Under
 *       @c INGEST_CLOCK, the record value never affects routing.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_time(n00b_string_t            *field,
                                     uint64_t                  bucket_width,
                                     n00b_store_time_source_t  time_source)
    _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a hash-bucket partition policy.
 *
 * @param field   JSON object field containing a scalar JSON value.
 * @param buckets Number of hash buckets.
 * @kw allocator Allocator for the policy.
 *
 * @return Ok(policy) on success. Null/empty fields and zero buckets return
 *         @c N00B_STORE_ERR_ARG.
 * @post Missing, non-object, or non-scalar record values route to @c default.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_hash(n00b_string_t *field,
                                     uint32_t       buckets) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return a partition policy's kind.
 *
 * @param policy Policy returned by a partition constructor.
 * @return Ok(kind), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(n00b_store_partition_kind_t)
n00b_store_partition_policy_get_kind(n00b_store_partition_policy_t *policy);

/**
 * @brief Return a time partition policy's routing clock source.
 *
 * @param policy Policy returned by a partition constructor.
 * @return Ok(time_source), or @c N00B_STORE_ERR_ARG for null. Only meaningful
 *         for @c N00B_STORE_PARTITION_TIME policies.
 */
extern n00b_result_t(n00b_store_time_source_t)
n00b_store_partition_policy_get_time_source(n00b_store_partition_policy_t *policy);

/**
 * @brief Compute the deterministic partition route key for a record.
 *
 * @param policy Partition policy returned by a constructor.
 * @param record JSON record object.
 * @kw allocator Allocator for non-default route key strings.
 *
 * @return Ok(route key). Missing/invalid partition fields are successful and
 *         route to @c default.
 * @post The route key is deterministic for the same policy and JSON variant
 *       value. The function uses JSON accessors and normalizer APIs, never JSON
 *       object storage internals.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_partition_route(n00b_store_partition_policy_t *policy,
                           n00b_json_node_t              *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a raw-source retention policy.
 *
 * @param kind Retention placement.
 * @kw allocator Allocator for the policy.
 * @return Ok(policy), or @c N00B_STORE_ERR_POLICY for an unknown kind.
 */
extern n00b_result_t(n00b_store_retain_policy_t *)
n00b_store_retain_policy_new(n00b_store_retain_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a whole-shard retention policy.
 *
 * This is separate from raw-source retention. It applies only to sealed shard
 * catalog entries and never rewrites or unmarshals sealed shard images.
 *
 * @kw max_sealed_shards  Keep at most this many newest sealed shards. Zero
 *                        disables the count rule.
 * @kw max_total_sealed_bytes Drop oldest sealed shards until the summed sealed
 *                        byte_len is within this budget. Zero disables the rule.
 * @kw drop_before_seal_ts Drop shards whose seal timestamp is strictly less
 *                         than this value. Zero disables the age rule.
 * @kw min_seal_ts        Floor for the age rule: shards with seal_ts below this
 *                        are exempt from drop_before_seal_ts (used to skip
 *                        non-epoch synthetic timestamps). Zero applies the age
 *                        rule to all shards.
 * @kw drop_reason        Optional process-side lifecycle reason.
 * @kw allocator          Allocator for the policy.
 *
 * @return Ok(policy) when at least one rule is enabled, or
 *         @c N00B_STORE_ERR_ARG when all rules are zero.
 */
extern n00b_result_t(n00b_store_shard_retention_policy_t *)
n00b_store_shard_retention_policy_new() _kargs
{
    uint64_t          max_sealed_shards     = 0;
    uint64_t          max_total_sealed_bytes = 0;
    uint64_t          drop_before_seal_ts   = 0;
    uint64_t          min_seal_ts           = 0;
    n00b_string_t    *drop_reason           = nullptr;
    n00b_allocator_t *allocator             = nullptr;
};

/**
 * @brief Construct a shard seal policy.
 *
 * @kw max_records Seal after this many records; zero disables this trigger.
 * @kw max_bytes   Seal after this byte estimate; zero disables this trigger.
 * @kw max_hot_bytes Seal after this many hot allocator mapped bytes; zero
 *                   disables this trigger.
 * @kw max_open_ns Seal after this open duration; zero disables this trigger.
 * @kw allocator   Allocator for the policy.
 *
 * @return Ok(policy) on success. A policy with all thresholds zero is manual.
 */
extern n00b_result_t(n00b_store_seal_policy_t *)
n00b_store_seal_policy_new() _kargs
{
    uint64_t          max_records = 0;
    uint64_t          max_bytes   = 0;
    uint64_t          max_hot_bytes = 0;
    uint64_t          max_open_ns = 0;
    n00b_allocator_t *allocator   = nullptr;
};

/**
 * @brief Return the default sealed-image residency policy.
 *
 * @return A value policy suitable for passing to @ref n00b_store_open_vfs.
 */
extern n00b_store_residency_policy_t
n00b_store_residency_policy_get_default(void);

/**
 * @brief Open a process-side store over a VFS root.
 *
 * @param vfs    VFS instance that owns the durable namespace.
 * @param root   Absolute VFS path that is the durable store root.
 * @param schema Schema for ingested records. Mutable schemas are frozen by
 *               this call.
 * @kw partition_policy Optional partition policy. Defaults to no partition.
 * @kw retain_policy    Optional raw-retention policy. Defaults to none.
 * @kw seal_policy      Optional seal policy. Defaults to manual seal.
 * @kw residency_policy Optional sealed-image residency policy. Defaults to
 *                      @ref n00b_store_residency_policy_get_default.
 * @kw cache            Optional VFS cache used for pinned-buffer residency
 *                      reads.
 * @kw commit_topic     Optional process-side best-effort commit topic.
 * @kw lifecycle_topic  Optional process-side shard lifecycle topic.
 * @kw display_name     Optional borrowed human-readable name.
 * @kw recovery_journal When true, the store maintains a per-hot-shard
 *                      write-ahead recovery journal under @c <root>/journals
 *                      and replays any orphaned journals at open. Defaults to
 *                      false.
 * @kw keep_standby     When true, the store runs hot-shard sealing on a
 *                      dedicated seal-worker pool and keeps a pre-built standby
 *                      shard, so the ingest worker rotates with a pure pointer
 *                      swap and never marshals on the hot path. Defaults to
 *                      false (every seal runs inline, as before). Intended for
 *                      high-throughput single-writer ingest (the gateway).
 * @kw seal_worker_count Number of concurrent seal workers when
 *                      @c keep_standby is true. Zero uses the default of one.
 * @kw allocator        Allocator for process-side store state.
 *
 * @pre @p vfs, @p root, and @p schema are non-null; @p root is non-empty and
 *      absolute in the VFS namespace.
 * @return Ok(store) on success. Invalid arguments return
 *         @c N00B_STORE_ERR_ARG.
 * @post @p schema is frozen. The returned store owns only process-side state
 *       and reads only catalog metadata during open; it never unmarshals
 *       sealed shard images.
 */
extern n00b_result_t(n00b_store_t *)
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
    // Whole-shard retention, applied automatically by the sealer after each
    // commit. Retention is OPT-IN: all three default to 0 (disabled), so a raw
    // store never auto-drops sealed shards. Deployments that want it pass an
    // explicit budget (e.g. wax = N00B_STORE_DEFAULT_RETENTION_NS / 60 days).
    // retention_window_ns drops sealed shards older than the window by seal_ts
    // (epoch ns). retention_max_sealed_shards caps the number of newest sealed
    // shards. retention_max_total_bytes caps summed on-disk byte_len.
    uint64_t                       retention_window_ns         = 0;
    uint64_t                       retention_max_sealed_shards = 0;
    uint64_t                       retention_max_total_bytes   = 0;
    n00b_allocator_t              *allocator        = nullptr;
};

/**
 * @brief Create or retrieve a typed process-side store commit topic.
 *
 * @param conduit Conduit instance that owns the topic.
 * @param uri     Conduit URI selected by the caller or store/service layer.
 *
 * @return Ok(topic) on success. Returns @c N00B_STORE_ERR_ARG for null
 *         conduit or @c N00B_STORE_ERR_INTERNAL when topic creation fails.
 * @post The returned topic is process-side only and must not be embedded in
 *       marshalable shard state.
 */
extern n00b_result_t(n00b_store_commit_topic_t *)
n00b_store_commit_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri);

/**
 * @brief Allocate and initialize a typed commit inbox.
 *
 * @param conduit Conduit instance whose allocator and notification domain own
 *                the inbox.
 * @kw backpressure Inbox backpressure policy. Defaults to drop-newest with a
 *                  small bounded queue so slow subscribers cannot grow ingest
 *                  memory without bound.
 * @kw limit        Maximum queued commit messages. Zero keeps the selected
 *                  policy unbounded; the default is 1024.
 * @kw allocator    Optional inbox allocator. Defaults to the conduit allocator.
 */
extern n00b_result_t(n00b_store_commit_inbox_t *)
n00b_store_commit_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
    n00b_allocator_t           *allocator    = nullptr;
};

/**
 * @brief Subscribe an inbox to a store commit topic.
 *
 * Inbox queue bounds and backpressure are configured by
 * @ref n00b_store_commit_inbox_new. This call only binds an already-configured
 * inbox to a topic.
 *
 * @kw operations Conduit operation mask. Defaults to all operations.
 * @kw flags      Conduit subscription flags.
 * @kw timeout_ms Optional conduit timeout in milliseconds.
 */
extern n00b_result_t(n00b_conduit_sub_handle_t)
n00b_store_commit_subscribe(n00b_store_commit_topic_t *topic,
                            n00b_store_commit_inbox_t *inbox) _kargs
{
    uint32_t operations = N00B_CONDUIT_OP_ALL;
    uint32_t flags      = 0;
    uint32_t timeout_ms = 0;
};

/**
 * @brief Set or replace the optional process-side commit topic on a store.
 *
 * @return Ok(true) for an open store, or a typed store error.
 * @post Commit events are best-effort. Ingest does not wait for subscribers
 *       and does not fail solely because a commit topic is inactive or full.
 */
extern n00b_result_t(bool)
n00b_store_set_commit_topic(n00b_store_t              *store,
                            n00b_store_commit_topic_t *topic);

/**
 * @brief Set or replace the optional process-side lifecycle topic on a store.
 *
 * @return Ok(true) for an open store, or a typed store error.
 * @post Lifecycle events remain process-side only and are never stored in
 *       marshalable shard roots.
 */
extern n00b_result_t(bool)
n00b_store_set_lifecycle_topic(n00b_store_t                 *store,
                               n00b_store_lifecycle_topic_t *topic);

/**
 * @brief Create or retrieve a typed process-side ingest topic.
 *
 * The topic carries @ref n00b_store_ingest_payload_t values. The payload
 * variant selector distinguishes parsed-record and raw-source inputs.
 */
extern n00b_result_t(n00b_store_ingest_topic_t *)
n00b_store_ingest_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri);

/** @brief Build a parsed-record ingest payload. */
extern n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_record(n00b_json_node_t *record) _kargs
{
    bool index = true;
};

/**
 * @brief Build a raw-source ingest payload.
 *
 * The source buffer is transferred to the store-ingest adapter that consumes
 * the payload. Callers must not reuse it after successful publish.
 */
extern n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_source(n00b_buffer_t *source) _kargs
{
    bool index = true;
};

/**
 * @brief Publish one ingest payload to a store-ingest topic.
 *
 * This helper claims the process-side publisher role briefly and emits one
 * user-message. It uses BLOCK backpressure: if the bounded ROCS ingest inbox is
 * full, it waits before admission. If there is no active ingest subscriber, the
 * payload is rejected before admission and the caller retains responsibility for
 * cleanup/retry.
 */
extern n00b_result_t(bool)
n00b_store_ingest_topic_publish(n00b_store_ingest_topic_t   *topic,
                                n00b_store_ingest_payload_t  payload);

/**
 * @brief Publish one ingest payload with explicit ROCS admission policy.
 *
 * BLOCK waits while at least one active ingest subscriber exists but its bounded
 * inbox is full. REJECT returns @c N00B_STORE_ERR_STATE before admission when
 * no active subscriber exists or any active subscriber inbox is full. Neither
 * mode permits accepted records to be dropped by conduit backpressure.
 */
extern n00b_result_t(bool)
n00b_store_ingest_topic_publish_ex(n00b_store_ingest_topic_t   *topic,
                                   n00b_store_ingest_payload_t  payload) _kargs
{
    n00b_store_ingest_backpressure_t backpressure =
        N00B_STORE_INGEST_BACKPRESSURE_BLOCK;
};

/**
 * @brief Ingest one parsed JSON object into the store.
 *
 * @param store  Open store returned by @ref n00b_store_open_vfs.
 * @param record Parsed JSON object. The hot shard retains this pointer.
 *
 * @return Ok(true) after the record is appended, configured hot indexes are
 *         updated, and the commit is visible to later flush/seal operations.
 *         Missing required fields return @c N00B_STORE_ERR_FIELD. Non-object
 *         records and unsupported policies return typed store errors.
 *
 * @post This ack-only API does not return positions. It cannot retain
 *       byte-exact source under inline raw-retention policy because no source
 *       buffer is available; use @ref n00b_store_ingest_buf for that case.
 */
extern n00b_result_t(bool)
n00b_store_ingest(n00b_store_t *store, n00b_json_node_t *record);

/**
 * @brief Parse and ingest one JSON source buffer.
 *
 * @param store  Open store returned by @ref n00b_store_open_vfs.
 * @param source Byte-exact JSON source buffer.
 *
 * @return Ok(true) after one successful parse and ingest. Parse failures
 *         return @c N00B_STORE_ERR_PARSE.
 * @post The buffer is parsed once. When inline raw retention is enabled, the
 *       byte-exact source is also copied into the hot shard's linear raw-byte
 *       store before seal.
 */
extern n00b_result_t(bool)
n00b_store_ingest_buf(n00b_store_t *store, n00b_buffer_t *source);

/**
 * @brief Ingest a batch of parsed JSON objects in input order.
 *
 * @param store   Open store returned by @ref n00b_store_open_vfs.
 * @param records List of parsed JSON object pointers.
 * @kw worker_count    Number of scratch-isolated preparation workers. Values
 *                     greater than one parse/route/build index terms in
 *                     parallel; commit remains ordered by input position.
 * @kw queue_capacity  Bounded preparation queue capacity. Zero selects the
 *                     worker count.
 *
 * @return Ok(committed_count). On full success this equals the list length.
 *         Worker/preflight failures return typed store errors before any batch
 *         record is appended. If any commit-stage failure occurs after a
 *         prefix has already been appended, this returns the committed prefix
 *         count rather than a retry-unsafe error; callers resume from that
 *         index.
 * @post Record order and per-shard ordinal order follow input order. Hot-shard
 *       mutation is single-writer; per-record parse/preflight/index-key state
 *       is built before the commit lock is taken.
 */
extern n00b_result_t(uint64_t)
n00b_store_ingest_batch(n00b_store_t             *store,
                        n00b_store_record_list_t *records) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
};

/**
 * @brief Parse and ingest a batch of JSON source buffers in input order.
 *
 * @param store   Open store returned by @ref n00b_store_open_vfs.
 * @param sources List of byte-exact JSON source buffers.
 * @kw worker_count    Number of scratch-isolated preparation workers. Values
 *                     greater than one parse/route/build index terms in
 *                     parallel; commit remains ordered by input position.
 * @kw queue_capacity  Bounded preparation queue capacity. Zero selects the
 *                     worker count.
 *
 * @return Ok(committed_count). Parse/preflight failures return typed store
 *         errors before any batch record is appended. Commit-stage failures
 *         after a prefix commit return the committed prefix count; callers
 *         resume from that index.
 * @post Each source is parsed once. Inline raw retention copies byte-exact
 *       source bytes into the shard raw-byte store during the single-writer
 *       commit step.
 */
extern n00b_result_t(uint64_t)
n00b_store_ingest_buf_batch(n00b_store_t             *store,
                            n00b_store_source_list_t *sources) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
};

/**
 * @brief Start asynchronously ingesting from a variant-backed conduit topic.
 *
 * The adapter subscribes with an internal bounded inbox. Its single adapter
 * thread drains bounded batches from that inbox. When `worker_count > 1`, the
 * adapter owns one bounded persistent worker pool for service-local
 * preparation and eligible reserved-slot fill/index work; each batch waits on
 * an explicit completion token, not a pool-wide quiesce.
 *
 * @kw worker_count   Number of scratch-isolated service workers used behind
 *                    the single dequeuer. Reserved slot assignment remains
 *                    ordered by dequeue position.
 * @kw queue_capacity Maximum queued records. Zero selects the implementation
 *                    default.
 * @kw batch_capacity Maximum records drained into one adapter batch. Zero
 *                    selects the implementation default and is capped
 *                    separately from queue_capacity to bound transient
 *                    scratch allocation.
 * @kw source_decoder Optional raw-source decoder. Null parses source buffers
 *                    as ordinary JSON store records. Non-null decoders run in
 *                    worker scratch storage before the store copies accepted
 *                    records into the hot shard.
 * @kw allocator      Allocator for the adapter handle.
 *
 * @return Ok(handle) on success. Close the handle with
 *         @ref n00b_store_conduit_ingest_close.
 */
extern n00b_result_t(n00b_store_conduit_ingest_t *)
n00b_store_conduit_ingest_start(n00b_store_t               *store,
                                n00b_store_ingest_topic_t  *topic) _kargs
{
    int32_t           worker_count   = 0;
    int32_t           queue_capacity = 0;
    int32_t           batch_capacity = 0;
    n00b_store_source_decoder_t source_decoder = nullptr;
    n00b_allocator_t *allocator      = nullptr;
};

/**
 * @brief Stop a conduit ingest adapter, unsubscribe, and join workers.
 *
 * @post Queued accepted input is drained before the adapter thread exits.
 */
extern n00b_result_t(bool)
n00b_store_conduit_ingest_close(n00b_store_conduit_ingest_t *ingest);

/** @brief Return current counters for a conduit ingest adapter. */
extern n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_conduit_ingest_stats(n00b_store_conduit_ingest_t *ingest);

/**
 * @brief Flush process-side store state.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(true) for an open store. Closed stores return
 *         @c N00B_STORE_ERR_STATE.
 *
 * Flush seals any non-empty hot shard through the durable VFS/catalog path.
 * Empty stores still rewrite catalog metadata through VFS.
 */
extern n00b_result_t(bool)
n00b_store_flush(n00b_store_t *store);

/**
 * @brief Close a store.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(true) on close. Active resource pins return
 *         @c N00B_STORE_ERR_PINNED; already-closed stores return
 *         @c N00B_STORE_ERR_STATE.
 * @post On success, future flush/close/pin-acquire calls fail with
 *       @c N00B_STORE_ERR_STATE.
 */
extern n00b_result_t(bool)
n00b_store_close(n00b_store_t *store);

/**
 * @brief Return a store's lifecycle state.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(state), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(n00b_store_state_t)
n00b_store_get_state(n00b_store_t *store);

/**
 * @brief Borrow the schema associated with a store.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(schema), or a typed store error.
 */
extern n00b_result_t(n00b_store_schema_t *)
n00b_store_get_schema(n00b_store_t *store);

/**
 * @brief Borrow the durable VFS root path associated with a store.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(root), or a typed store error.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_get_root(n00b_store_t *store);

/**
 * @brief Return the store generation used in durable position tokens.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(generation), or a typed store error.
 */
extern n00b_result_t(uint64_t)
n00b_store_get_generation(n00b_store_t *store);

/**
 * @brief Seal the current hot shard as an immutable VFS object.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @kw seal_ts      Timestamp recorded in the shard root and catalog entry.
 * @kw base_address Marshal base address for the sealed image.
 * @kw allocator    Allocator for transient seal/copy state.
 *
 * @return Ok(catalog_entry) for the newly visible sealed shard. The entry is
 *         process-side catalog metadata owned by the store.
 * @post The shard image bytes are written before the catalog is updated. The
 *       catalog update is the visibility boundary. The sealed image is not
 *       unmarshaled.
 */
extern n00b_result_t(n00b_store_catalog_entry_t *)
n00b_store_seal_hot_shard(n00b_store_t *store) _kargs
{
    uint64_t          seal_ts      = 0;
    uint32_t          base_address = 0;
    n00b_allocator_t *allocator    = nullptr;
};

/**
 * @brief Apply an event-time watermark to a time-partitioned store.
 *
 * @param store        Store returned by @ref n00b_store_open_vfs.
 * @param watermark_ts Event-time watermark in the same units as the store's
 *                     time partition policy.
 *
 * @return Ok(true) when a non-empty hot time-window shard was sealed, Ok(false)
 *         when no hot time window is closed by the watermark, or a typed store
 *         error. Non-time partition policies return @c N00B_STORE_ERR_POLICY.
 * @post The seal path is the ordinary VFS/catalog path and never unmarshals
 *       sealed shards. Late records for an already-sealed window are handled by
 *       normal ingest routing: rocs opens a new hot shard for that partition
 *       and never mutates the prior sealed shard.
 */
extern n00b_result_t(bool)
n00b_store_apply_event_time_watermark(n00b_store_t *store,
                                      uint64_t      watermark_ts);

/**
 * @brief Return the number of sealed shard catalog entries.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(count), or a typed store error.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_get_entry_count(n00b_store_t *store);

/**
 * @brief Return the number of catalog entries, including quarantined entries.
 *
 * Visible query/upload paths should use the visible-entry APIs below. This API
 * is for operator tooling that needs to inspect non-visible catalog state.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_all_entry_count(n00b_store_t *store);

/**
 * @brief Borrow one catalog entry by raw catalog index.
 *
 * Returned entries may be sealed, quarantined, or process-side diagnostic
 * entries. Callers must not retain returned entries across catalog mutation.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_all_entry_at(n00b_store_t *store, uint64_t index);

/**
 * @brief Return the number of currently visible sealed catalog entries.
 *
 * This borrowed enumeration path avoids copying catalog strings. Callers must
 * not retain returned entries across catalog mutation.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_visible_entry_count(n00b_store_t *store);

/**
 * @brief Borrow one currently visible sealed catalog entry by index.
 *
 * @return Ok(some(entry)) when present, Ok(none) when @p index is out of
 *         bounds, or a typed store error. The returned entry is borrowed from
 *         @p store and must not be retained across catalog mutation.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_visible_entry_at(n00b_store_t *store, uint64_t index);

/**
 * @brief Find a catalog entry by shard id, including quarantined entries.
 *
 * Query and upload paths should use @ref n00b_store_catalog_find_shard, which
 * hides quarantined entries.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_any_shard(n00b_store_t *store, uint64_t shard_id);

/**
 * @brief Borrowed catalog entry selected for a strict-after resume position.
 *
 * `entry` is borrowed from the store catalog and must not be retained across
 * catalog mutation. `start_ordinal` is the first not-yet-delivered record in
 * that shard for the supplied resume position.
 */
typedef struct {
    n00b_store_catalog_entry_t *entry;
    uint64_t                    index;
    uint64_t                    generation;
    uint64_t                    shard_id;
    uint64_t                    record_count;
    uint64_t                    start_ordinal;
} n00b_store_catalog_resume_entry_t;

/**
 * @brief Borrow the first visible sealed shard with records after @p after.
 *
 * This is the cursor form of visible catalog enumeration: it scans the catalog
 * while holding the store commit lock once, then returns the first shard with
 * remaining records. Passing NULL starts at the first non-empty sealed shard.
 *
 * Time-anchored fallback (see @ref n00b_store_catalog_backlog): if no shard
 * sorts after @p after by position but @p after has a non-zero `seal_ts`,
 * resume at the oldest sealed shard sealed strictly after that timestamp. This
 * recovers a watermark stranded by a shard-id rewind after a store rebuild.
 *
 * @return Ok(some(entry)) when a shard has undelivered records, Ok(none) when
 *         sealed state is drained, or a typed store error.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_resume_entry_t))
n00b_store_catalog_visible_entry_after(n00b_store_t     *store,
                                       n00b_store_pos_t *after);

/**
 * @brief Borrowed record payload returned by a store stream cursor.
 *
 * The byte span is valid until the next call to
 * @ref n00b_store_record_stream_next on the same cursor or until
 * @ref n00b_store_record_stream_close. Callers that need longer retention must
 * copy the bytes.
 */
typedef struct {
    n00b_store_pos_t       pos;
    n00b_store_byte_span_t bytes;
    bool                   hot;
} n00b_store_record_stream_item_t;

/**
 * @brief Open a durable-position scan cursor across sealed shards and hot tail.
 *
 * The cursor snapshots visible sealed catalog entries and the current hot
 * record pointers under the store commit lock, then pins backing lifetime until
 * closed. It does not evaluate predicates or materialize records.
 *
 * Time-anchored fallback (see @ref n00b_store_catalog_backlog): if @p after
 * sorts past every sealed shard by position but carries a non-zero `seal_ts`
 * (a watermark stranded by a store-rebuild shard-id rewind), the cursor resumes
 * at shards sealed strictly after that timestamp and includes the full hot tail
 * (which is newer than any sealed shard). Emitted sealed positions carry their
 * shard's `seal_ts`, so a watermark built from this cursor self-anchors for the
 * next resume.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @param after Optional strict resume position; NULL starts at the first
 *              visible record.
 * @kw allocator Optional allocator for cursor metadata.
 */
extern n00b_result_t(n00b_store_record_stream_t *)
n00b_store_record_stream_open(n00b_store_t     *store,
                              n00b_store_pos_t *after) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the next record span from a stream cursor.
 *
 * @return Ok(some(item)) for a record, Ok(none) when drained, or a typed store
 *         / mapped-image error.
 */
extern n00b_result_t(n00b_option_t(n00b_store_record_stream_item_t))
n00b_store_record_stream_next(n00b_store_record_stream_t *stream);

/**
 * @brief Close a stream cursor and release its backing lifetime pin.
 */
extern n00b_result_t(bool)
n00b_store_record_stream_close(n00b_store_record_stream_t *stream);

/**
 * @brief Sealed-shard backlog ahead of a durable position.
 *
 * @field shards_remaining           Sealed shards holding undelivered records
 *                                   (includes a partially-consumed current shard).
 * @field records_remaining          Total undelivered records across those shards.
 * @field current_shard_records_left Undelivered records in @p after's own shard.
 */
typedef struct {
    uint64_t shards_remaining;
    uint64_t records_remaining;
    uint64_t current_shard_records_left;
} n00b_store_backlog_t;

/**
 * @brief Count the sealed-shard backlog strictly after a durable position.
 *
 * Walks the catalog (sealed shards only — the unsealed hot shard is excluded)
 * and sums record counts for shards at/after @p after. Cheap: O(catalog
 * entries), no shard images are mapped.
 *
 * Time-anchored fallback: if position-based counting finds nothing but @p after
 * carries a non-zero `seal_ts` and sealed shards exist that were sealed strictly
 * after it, those shards are counted instead. This recovers a watermark
 * stranded past every shard by a store rebuild that rewound shard ids (position
 * can lie across a rebuild; seal_ts does not). It never engages during normal
 * monotonic operation, so it cannot double-count already-delivered records.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @param after Resume position; records strictly after it are pending. Pass
 *              NULL for "from the beginning" (everything is pending).
 * @return Ok(backlog), or a typed store error.
 */
extern n00b_result_t(n00b_store_backlog_t)
n00b_store_catalog_backlog(n00b_store_t *store, n00b_store_pos_t *after);

/**
 * @brief Apply a whole-shard retention policy to sealed catalog entries.
 *
 * Drops are whole-shard only. Pinned resident images return
 * @c N00B_STORE_ERR_PINNED. The catalog update is the visibility boundary; VFS
 * object deletion happens after the catalog no longer advertises the shard.
 *
 * @return Ok(number of shards dropped).
 */
extern n00b_result_t(uint64_t)
n00b_store_apply_shard_retention(
    n00b_store_t                        *store,
    n00b_store_shard_retention_policy_t *policy);

/**
 * @brief Drop one sealed shard by id.
 *
 * @kw drop_reason Optional lifecycle reason. If omitted, the policy/default
 *                 reason is used.
 */
extern n00b_result_t(bool)
n00b_store_drop_sealed_shard(n00b_store_t *store,
                             uint64_t      shard_id) _kargs
{
    n00b_string_t *drop_reason = nullptr;
};

/**
 * @brief Mark one sealed shard as quarantined.
 *
 * Quarantine persists in the catalog and removes the shard from normal query,
 * stream, retention, and upload visibility. The shard object is not deleted.
 */
extern n00b_result_t(bool)
n00b_store_quarantine_shard(n00b_store_t *store,
                            uint64_t      shard_id) _kargs
{
    n00b_string_t *reason = nullptr;
};

/** @brief Return the oldest retained sealed position, if known. */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_oldest_available_pos(n00b_store_t *store);

/** @brief Return the age-retention expiry for the oldest retained sealed shard. */
extern n00b_result_t(n00b_option_t(uint64_t))
n00b_store_oldest_available_expires_at_ns(n00b_store_t *store);

/**
 * @brief Return the configured age-retention window in epoch nanoseconds.
 *
 * A zero value means age-based retention is disabled for this store. Callers
 * can add this value to a catalog entry's seal timestamp to display that
 * entry's age-retention expiry.
 */
extern n00b_result_t(uint64_t)
n00b_store_retention_window_ns(n00b_store_t *store);

/**
 * @brief Check whether a durable position is still retained.
 *
 * Retained sealed positions and generation-compatible current hot-shard
 * positions return Ok with `available == true`. Positions older than the
 * retained boundary, dropped or missing shard ids, out-of-range ordinals, and
 * generation mismatches return Ok with `available == false` and the current
 * oldest sealed boundary populated when known. Store argument/state failures
 * still return typed store errors.
 */
extern n00b_result_t(n00b_store_resume_check_t)
n00b_store_resume_check(n00b_store_t *store, n00b_store_pos_t pos);

/**
 * @brief Look up a sealed shard catalog entry by shard id.
 *
 * @param store    Store returned by @ref n00b_store_open_vfs.
 * @param shard_id Durable shard identifier.
 * @return Ok(some(entry)) when present, Ok(none) when absent, or a typed
 *         store error.
 */
extern n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_shard(n00b_store_t *store, uint64_t shard_id);

/**
 * @brief Verify that a catalog entry's durable shard object exists.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @param entry Catalog entry borrowed from @p store.
 * @return Ok(true) when the VFS object exists with the catalog byte length.
 *         Missing objects return @c N00B_STORE_ERR_VFS; mismatched metadata
 *         returns @c N00B_STORE_ERR_CORRUPT.
 */
extern n00b_result_t(bool)
n00b_store_catalog_entry_verify_object(n00b_store_t              *store,
                                       n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's shard id.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(shard id), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_shard_id(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's store generation.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(generation), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_generation(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's durable VFS object path.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(path), or @c N00B_STORE_ERR_ARG for null/malformed entry.
 * @post The returned path is borrowed from the store catalog.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_object_path(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's sealed object byte length.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(byte length), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_byte_len(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's shard record count.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(record count), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_record_count(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's schema generation.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(schema generation), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_schema_generation(
    n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's seal timestamp.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(seal timestamp), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_seal_ts(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a catalog entry's partition route key.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(partition key), or @c N00B_STORE_ERR_ARG for null/malformed entry.
 * @post The returned key is borrowed from the store catalog.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_partition_key(n00b_store_catalog_entry_t *entry);

/**
 * @brief Return a backend ETag/checksum when cataloged.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(some(etag)) when present, Ok(none) when the backend did not
 *         provide one, or @c N00B_STORE_ERR_ARG for null.
 * @post Any returned string is borrowed from the store catalog.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_catalog_entry_get_etag(n00b_store_catalog_entry_t *entry);

extern n00b_result_t(n00b_store_catalog_entry_state_t)
n00b_store_catalog_entry_get_state(n00b_store_catalog_entry_t *entry);

extern n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_state_name(n00b_store_catalog_entry_state_t state);

/**
 * @brief Report whether a sealed shard catalog entry is resident in process.
 *
 * @param entry Catalog entry borrowed from a store catalog lookup.
 * @return Ok(true) when the shard image is currently loaded as a resident
 *         map, Ok(false) when it is cold, or @c N00B_STORE_ERR_ARG.
 */
extern n00b_result_t(bool)
n00b_store_catalog_entry_is_resident(n00b_store_catalog_entry_t *entry);

/**
 * @brief Acquire a resident mapped image for one sealed shard.
 *
 * @param store Store that owns @p entry.
 * @param entry Catalog entry borrowed from @p store.
 * @kw allocator Allocator for the returned handle.
 *
 * @return Ok(handle) on success. The shard body is loaded lazily from VFS when
 *         it is not already resident. The handle pins the resident image until
 *         released, so trim/unload cannot close the map underneath the caller.
 * @post The returned handle must be released with
 *       @ref n00b_store_resident_shard_release.
 */
extern n00b_result_t(n00b_store_resident_shard_t *)
n00b_store_resident_shard_acquire(n00b_store_t               *store,
                                  n00b_store_catalog_entry_t *entry) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Borrow the mapped-image handle pinned by a resident shard handle.
 *
 * @param resident Handle returned by @ref n00b_store_resident_shard_acquire.
 * @return Ok(map) while @p resident is live; released/null handles return
 *         @c N00B_STORE_ERR_STATE / @c N00B_STORE_ERR_ARG.
 */
extern n00b_result_t(n00b_store_map_t *)
n00b_store_resident_shard_map(n00b_store_resident_shard_t *resident);

/**
 * @brief Release a resident shard handle.
 *
 * @param resident Handle returned by @ref n00b_store_resident_shard_acquire.
 * @return Ok(true) on first release. The image may remain resident until a
 *         later trim; releasing only removes this handle's pin.
 */
extern n00b_result_t(bool)
n00b_store_resident_shard_release(n00b_store_resident_shard_t *resident);

/**
 * @brief Return current process-resident sealed shard bytes.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(byte count), or a typed store error.
 */
extern n00b_result_t(uint64_t)
n00b_store_get_resident_bytes(n00b_store_t *store);

/**
 * @brief Return current process-resident sealed shard count.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(shard count), or a typed store error.
 */
extern n00b_result_t(uint64_t)
n00b_store_get_resident_shard_count(n00b_store_t *store);

/**
 * @brief Return current process-side sealed-shard residency counters.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(copied stats), or a typed store error.
 */
extern n00b_result_t(n00b_store_residency_stats_t)
n00b_store_residency_stats(n00b_store_t *store);

/**
 * @brief Return current rocs store memory/accounting counters.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(copied stats), or a typed store error.
 */
extern n00b_result_t(n00b_store_memory_stats_t)
n00b_store_memory_stats(n00b_store_t *store);

/**
 * @brief Unload unpinned resident sealed shard images.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @kw target_resident_bytes Target resident bytes. Zero means use the store's
 *                           configured residency policy.
 *
 * @return Ok(bytes released). Trim never deletes durable VFS shard objects and
 *         never unloads images with live resident-shard handles.
 */
extern n00b_result_t(uint64_t)
n00b_store_residency_trim(n00b_store_t *store) _kargs
{
    uint64_t target_resident_bytes = 0;
};

/**
 * @brief Encode a durable store position into a stable resume token.
 *
 * Fixed-width hexadecimal encoding of `(generation, shard_id, ordinal)`,
 * optionally followed by `seal_ts` when it is non-zero. A position with no
 * seal_ts encodes to the legacy 48-char form (three 16-char words); a non-zero
 * seal_ts appends a fourth word (64 chars). @ref n00b_store_pos_decode accepts
 * both widths and reports seal_ts 0 for a legacy token.
 *
 * @param pos Position tuple to encode.
 * @kw allocator Allocator for the returned token string.
 * @return Ok(token) on success.
 */
extern n00b_result_t(n00b_string_t *)
n00b_store_pos_encode(n00b_store_pos_t pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Decode a resume token created by @ref n00b_store_pos_encode.
 *
 * @param token Fixed-width hexadecimal token.
 * @return Ok(position) on success, or @c N00B_STORE_ERR_ARG when the token is
 *         null, the wrong length, or contains non-hex data.
 */
extern n00b_result_t(n00b_store_pos_t)
n00b_store_pos_decode(n00b_string_t *token);

/**
 * @brief Compare two durable positions by generation, shard id, then ordinal.
 *
 * @param a First position.
 * @param b Second position.
 * @return -1 when @p a sorts before @p b, 1 when after, and 0 when equal.
 */
extern int32_t
n00b_store_pos_compare(n00b_store_pos_t a, n00b_store_pos_t b);

/**
 * @brief Acquire a process-side active-resource pin.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @kw allocator Allocator for the pin handle.
 *
 * @return Ok(pin) while the store is open. Pins model query/view/resource
 *         lifetimes that make close unsafe.
 * @post Each successful pin must be released with @ref n00b_store_pin_release.
 */
extern n00b_result_t(n00b_store_pin_t *)
n00b_store_pin_acquire(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Release an active-resource pin.
 *
 * @param pin Pin returned by @ref n00b_store_pin_acquire.
 * @return Ok(true) on first release. Null or already-released pins return
 *         @c N00B_STORE_ERR_STATE.
 */
extern n00b_result_t(bool)
n00b_store_pin_release(n00b_store_pin_t *pin);

/**
 * @brief Return the number of active resource pins on a store.
 *
 * @param store Store returned by @ref n00b_store_open_vfs.
 * @return Ok(pin count), or @c N00B_STORE_ERR_ARG for null.
 */
extern n00b_result_t(uint64_t)
n00b_store_get_active_pins(n00b_store_t *store);

#ifdef __cplusplus
}
#endif
