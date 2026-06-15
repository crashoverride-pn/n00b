/**
 * @file rocs/wax.h
 * @brief Wax normalized-event schema and record adapter for rocs.
 *
 * This header exposes the Phase 1 wax normalized-event adapter and the
 * Phase 2 fixture/replay cache daemon surface. It does not declare the later
 * search/filter command API, live mode, query DSL behavior, or deployment
 * surface.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/string.h"
#include "parsers/json.h"
#include "rocs/store.h"

typedef struct n00b_rocs_wax_daemon_config_t n00b_rocs_wax_daemon_config_t;
typedef struct n00b_rocs_wax_daemon_t        n00b_rocs_wax_daemon_t;

/**
 * @brief Return the supported wax normalized event schema id.
 *
 * @return A static rich string for @c wax.normalized.v1.
 */
extern n00b_string_t *n00b_rocs_wax_normalized_schema(void);

/** @brief Supported wax normalized event schema id expression. */
#define N00B_ROCS_WAX_NORMALIZED_SCHEMA n00b_rocs_wax_normalized_schema()

/** @brief One day expressed in the nanosecond timestamp units used by wax. */
#define N00B_ROCS_WAX_DAY_NS UINT64_C(86400000000000)

/** @brief Default record threshold for sealing wax shards inside one day. */
#define N00B_ROCS_WAX_SHARD_MAX_RECORDS UINT64_C(262144)

/** @brief Default byte-estimate threshold for sealing wax shards inside one day. */
#define N00B_ROCS_WAX_SHARD_MAX_BYTES UINT64_C(268435456)

/** @brief Default hot-resident threshold for sealing wax shards. */
#define N00B_ROCS_WAX_SHARD_MAX_HOT_BYTES UINT64_C(268435456)

/**
 * @brief Error domain for rocs-side wax event adapter helpers.
 */
typedef enum : int32_t {
    N00B_ROCS_WAX_OK                     = 0,
    N00B_ROCS_WAX_ERR_ARG                = -1,
    N00B_ROCS_WAX_ERR_MALFORMED_JSON     = -2,
    N00B_ROCS_WAX_ERR_NON_OBJECT         = -3,
    N00B_ROCS_WAX_ERR_UNSUPPORTED_SCHEMA = -4,
    N00B_ROCS_WAX_ERR_MISSING_KIND       = -5,
    N00B_ROCS_WAX_ERR_MISSING_EVENT_ID   = -6,
    N00B_ROCS_WAX_ERR_INTERNAL           = -7,
    N00B_ROCS_WAX_ERR_CONFIG             = -8,
    N00B_ROCS_WAX_ERR_SOURCE             = -9,
    N00B_ROCS_WAX_ERR_CHECKPOINT         = -10,
    N00B_ROCS_WAX_ERR_STORE              = -11,
    N00B_ROCS_WAX_ERR_CLOSED             = -12,
    N00B_ROCS_WAX_ERR_STATE              = -13,
} n00b_rocs_wax_err_t;

/**
 * @brief Snapshot counters for the wax cache daemon.
 *
 * @field lines_read         Source lines consumed during this daemon process.
 * @field events_ingested    Valid normalized events accepted by rocs ingest.
 * @field events_rejected    Malformed, unsupported, or incomplete source lines.
 * @field store_errors       Store-open, ingest, flush, or close errors.
 * @field source_disconnects Fixture EOF or subscription disconnect events.
 * @field checkpoint_writes  Successful durable checkpoint updates.
 * @field checkpoint_errors  Checkpoint write errors observed after start.
 * @field checkpoint_line    Last consumed one-based source line checkpoint.
 * @field last_error         Last typed wax/store/source/checkpoint error.
 */
typedef struct {
    uint64_t   lines_read;
    uint64_t   events_ingested;
    uint64_t   events_rejected;
    uint64_t   store_errors;
    uint64_t   source_disconnects;
    uint64_t   checkpoint_writes;
    uint64_t   checkpoint_errors;
    uint64_t   checkpoint_line;
    n00b_err_t last_error;
} n00b_rocs_wax_daemon_stats_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a wax adapter error.
 *
 * @param err A @c N00B_ROCS_WAX_* code.
 * @return A static rich string naming the code, or @c UNKNOWN for an
 *         unrecognized value.
 */
extern n00b_string_t *n00b_rocs_wax_err_str(n00b_err_t err);

/**
 * @brief Construct the public rocs schema used for wax normalized events.
 *
 * @kw allocator Allocator for the schema and its field descriptors.
 *
 * @return Ok(schema) on success. Any schema-construction failure is converted
 *         to @ref N00B_ROCS_WAX_ERR_INTERNAL.
 *
 * @post The returned schema is mutable until passed to a store opener. It
 *       registers wax normalized-event fields directly, including dotted
 *       fields such as @c source.family, @c lineage.event_id,
 *       @c policy.revision, and @c quality.state. Top-level @c event_id and
 *       @c class remain indexed for producers that emit them. @c search_text
 *       is a derived full-text field and is opted into catch-all search.
 */
extern n00b_result_t(n00b_store_schema_t *)
n00b_rocs_wax_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct the wax store partition policy.
 *
 * Wax events are routed by normalized @c ts_ns into day buckets. Invalid or
 * missing timestamps still route to the store default partition.
 */
extern n00b_result_t(n00b_store_partition_policy_t *)
n00b_rocs_wax_partition_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct the wax store seal policy.
 *
 * The seal policy is a size guard inside a day partition. It is not the
 * partitioning mechanism.
 */
extern n00b_result_t(n00b_store_seal_policy_t *)
n00b_rocs_wax_seal_policy_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Parse one wax NDJSON line into a rocs-owned JSON record.
 *
 * @param line One line containing a JSON object. A trailing newline is allowed.
 * @kw allocator Allocator for the materialized record and copied strings.
 *
 * @return Ok(record) when @p line is a supported @c wax.normalized.v1 event.
 *         Malformed JSON, non-object roots, unsupported schema ids,
 *         missing/empty @c kind, or missing/empty event identity return typed
 *         @ref n00b_rocs_wax_err_t codes.
 *
 * @post The returned record is the parsed normalized event object, preserving
 *       all original fields. The adapter adds @c search_text as a derived
 *       full-text sink, but does not flatten structured event fields into
 *       parallel top-level query fields. The serialized source line is not
 *       retained in the marshalable record graph. The adapter never exposes
 *       mapped store pointers and never mutates a store on error.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_rocs_wax_record_from_line(n00b_string_t *line) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Parse one wax NDJSON source buffer into a rocs-owned JSON record.
 *
 * This callback-shaped variant avoids constructing an intermediate n00b string
 * when conduit ingest workers already have a byte buffer.
 */
extern n00b_result_t(n00b_json_node_t *)
n00b_rocs_wax_record_from_source(n00b_buffer_t    *source,
                                 n00b_allocator_t *allocator);

/**
 * @brief Construct fixture/replay cache daemon configuration.
 *
 * @param store_config Store profile config used by daemon start. The pointer
 *                     is borrowed and must remain reachable until start.
 * @kw allocator Allocator for config-owned paths and process-side state.
 *
 * @return Ok(config) on success, or @ref N00B_ROCS_WAX_ERR_CONFIG for a null
 *         store config.
 *
 * @post This only constructs daemon configuration. It does not open a store,
 *       start a thread, connect a socket, ingest events, or change query/store
 *       semantics.
 */
extern n00b_result_t(n00b_rocs_wax_daemon_config_t *)
n00b_rocs_wax_daemon_config_new(n00b_store_config_t *store_config) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Set the fixture/replay NDJSON source path.
 *
 * @param config Daemon config returned by
 *               @ref n00b_rocs_wax_daemon_config_new.
 * @param path Host filesystem path to a line-oriented wax NDJSON source. The
 *             string is copied into the config.
 *
 * @return Ok(true) on success, or a typed wax config error.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_fixture_source(
    n00b_rocs_wax_daemon_config_t *config,
    n00b_string_t                 *path);

/**
 * @brief Set or clear the durable source-line checkpoint path.
 *
 * The checkpoint file records the one-based number of the last consumed source
 * line after both accepted and rejected lines. A null path disables durable
 * checkpoint writes while stats still report in-process progress.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_checkpoint_path(
    n00b_rocs_wax_daemon_config_t *config,
    n00b_string_t                 *path);

/**
 * @brief Limit source lines consumed by one run call.
 *
 * @param max_lines Zero means no limit. Non-zero values stop after at most
 *                  that many non-skipped source lines in one
 *                  @ref n00b_rocs_wax_daemon_run call.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_config_set_max_lines(
    n00b_rocs_wax_daemon_config_t *config,
    uint64_t                       max_lines);

/**
 * @brief Start a wax cache daemon over a configured rocs store.
 *
 * @param config Daemon config with a borrowed store config and fixture source.
 * @kw allocator Allocator for runtime-owned state.
 *
 * @return Ok(daemon) after the wax schema store is opened and any checkpoint
 *         file is read. Null or incomplete config returns
 *         @ref N00B_ROCS_WAX_ERR_CONFIG. Store-open failures return
 *         @ref N00B_ROCS_WAX_ERR_STORE.
 *
 * @post Start does not ingest events. Call @ref n00b_rocs_wax_daemon_run to
 *       consume the fixture/replay source, then
 *       @ref n00b_rocs_wax_daemon_stop to flush and close the cache.
 */
extern n00b_result_t(n00b_rocs_wax_daemon_t *)
n00b_rocs_wax_daemon_start(n00b_rocs_wax_daemon_config_t *config) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Consume the configured fixture/replay source once.
 *
 * The daemon skips lines already covered by the durable checkpoint, parses
 * later lines through @ref n00b_rocs_wax_record_from_line, ingests accepted
 * records through @ref n00b_store_ingest, advances checkpoints after accepted
 * and rejected consumed lines, and continues past malformed poison lines.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_run(n00b_rocs_wax_daemon_t *daemon);

/**
 * @brief Stop a daemon, flush committed events, and close its store.
 *
 * @return Ok(true) on first stop, Ok(false) on later calls, or typed wax/store
 *         errors. Store close returning pinned/resource errors is surfaced as
 *         @ref N00B_ROCS_WAX_ERR_STORE.
 *
 * @post On success, the borrowed store accessor reports closed and all accepted
 *       records have crossed the public store flush/catalog visibility path.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_stop(n00b_rocs_wax_daemon_t *daemon);

/**
 * @brief Return current daemon counters.
 *
 * Stats are value-copied and remain valid independently of the daemon object.
 */
extern n00b_result_t(n00b_rocs_wax_daemon_stats_t)
n00b_rocs_wax_daemon_stats(n00b_rocs_wax_daemon_t *daemon);

/**
 * @brief Report whether the daemon currently has an open store.
 *
 * Healthy is true after start and before stop when no fatal source/store/
 * checkpoint error has closed the runtime.
 */
extern n00b_result_t(bool)
n00b_rocs_wax_daemon_healthy(n00b_rocs_wax_daemon_t *daemon);

/**
 * @brief Borrow the open rocs store for tests and local supervision.
 *
 * The store is owned by the daemon and remains valid only until
 * @ref n00b_rocs_wax_daemon_stop. Callers must not close it directly.
 */
extern n00b_result_t(n00b_store_t *)
n00b_rocs_wax_daemon_store(n00b_rocs_wax_daemon_t *daemon);

#ifdef __cplusplus
}
#endif
