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
typedef struct n00b_store_pin_t              n00b_store_pin_t;
typedef struct n00b_store_catalog_entry_t    n00b_store_catalog_entry_t;
typedef struct n00b_store_resident_shard_t   n00b_store_resident_shard_t;
typedef struct n00b_store_conduit_ingest_t    n00b_store_conduit_ingest_t;
typedef struct n00b_store_config_t            n00b_store_config_t;

/** @brief List of source JSON buffers for batch ingest. */
typedef n00b_list_t(n00b_buffer_t *) n00b_store_source_list_t;

/**
 * @brief Variant-backed conduit ingest payload.
 *
 * The variant selector is the only discriminator: record payloads contain a
 * parsed JSON node and source payloads contain a byte-exact JSON buffer. No
 * parallel type field is stored in the payload.
 */
typedef n00b_variant_t(n00b_json_node_t *, n00b_buffer_t *)
    n00b_store_ingest_payload_t;

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
    n00b_allocator_t              *allocator        = nullptr;
};

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
    bool                    required       = false;
    n00b_store_index_kind_t index_kind     = N00B_STORE_INDEX_NONE;
    bool                    include_in_all = false;
    uint8_t                 ngram_n        = N00B_STORE_NGRAM_DEFAULT_N;
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
 * @param field        JSON object field containing a non-negative integer
 *                     event timestamp.
 * @param bucket_width Positive timestamp units per bucket.
 * @kw allocator Allocator for the policy.
 *
 * @return Ok(policy) on success. Null/empty fields and zero bucket width return
 *         @c N00B_STORE_ERR_ARG.
 * @post Missing, non-object, non-integer, or negative record values route to
 *       @c default.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_time(n00b_string_t *field,
                                     uint64_t       bucket_width) _kargs
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
 * @kw drop_before_seal_ts Drop shards whose seal timestamp is strictly less
 *                         than this value. Zero disables the age rule.
 * @kw drop_reason        Optional process-side lifecycle reason.
 * @kw allocator          Allocator for the policy.
 *
 * @return Ok(policy) when at least one rule is enabled, or
 *         @c N00B_STORE_ERR_ARG when both rules are zero.
 */
extern n00b_result_t(n00b_store_shard_retention_policy_t *)
n00b_store_shard_retention_policy_new() _kargs
{
    uint64_t          max_sealed_shards  = 0;
    uint64_t          drop_before_seal_ts = 0;
    n00b_string_t    *drop_reason        = nullptr;
    n00b_allocator_t *allocator          = nullptr;
};

/**
 * @brief Construct a shard seal policy.
 *
 * @kw max_records Seal after this many records; zero disables this trigger.
 * @kw max_bytes   Seal after this byte estimate; zero disables this trigger.
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
n00b_store_ingest_payload_record(n00b_json_node_t *record);

/** @brief Build a raw-source ingest payload. */
extern n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_source(n00b_buffer_t *source);

/**
 * @brief Publish one ingest payload to a store-ingest topic.
 *
 * This helper claims the process-side publisher role briefly and emits one
 * user-message. It reports publisher/topic errors, not subscriber counts.
 */
extern n00b_result_t(bool)
n00b_store_ingest_topic_publish(n00b_store_ingest_topic_t   *topic,
                                n00b_store_ingest_payload_t  payload);

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
 * @kw worker_count    Worker-pool size for parse/preflight/index-key build.
 *                     Zero chooses a small implementation default capped by
 *                     the batch length.
 * @kw queue_capacity  Pending worker-pool job bound. Zero chooses the worker
 *                     count.
 *
 * @return Ok(committed_count). On full success this equals the list length.
 *         Worker/preflight failures return typed store errors before any batch
 *         record is appended. If any commit-stage failure occurs after a
 *         prefix has already been appended, this returns the committed prefix
 *         count rather than a retry-unsafe error; callers resume from that
 *         index.
 * @post Record order and per-shard ordinal order follow input order. Hot-shard
 *       mutation is single-writer; workers only build private per-record
 *       parse/preflight/index-key state.
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
 * @kw worker_count    Worker-pool size for parse/preflight/index-key build.
 * @kw queue_capacity  Pending worker-pool job bound. Zero chooses the worker
 *                     count.
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
 * The adapter subscribes with an internal unbounded inbox and uses a bounded
 * worker pool for ingest work. The adapter thread blocks in
 * @c n00b_worker_pool_submit when @p queue_capacity is full; it does not use a
 * drop-newest/drop-oldest conduit policy for accepted input.
 *
 * @kw worker_count   Worker count for store ingest calls. Zero selects one.
 * @kw queue_capacity Pending worker-pool job bound. Zero selects the worker
 *                    count.
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
    n00b_allocator_t *allocator      = nullptr;
};

/**
 * @brief Stop a conduit ingest adapter, unsubscribe, and join workers.
 *
 * @post Queued accepted input is drained before the worker pool shuts down.
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

/** @brief Return the oldest retained sealed position, if known. */
extern n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_oldest_available_pos(n00b_store_t *store);

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
 * The token is a fixed-width hexadecimal encoding of
 * `(generation, shard_id, ordinal)`.
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
