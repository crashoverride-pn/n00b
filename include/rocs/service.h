/**
 * @file rocs/service.h
 * @brief Reference service configuration and runtime declarations for rocs.
 *
 * The reference service is a thin composition layer over the public rocs
 * store, query, HTTP, and conduit APIs. Service configuration composes a store
 * config profile plus service-local process options. Runtime startup requires
 * an application-supplied schema; the runtime keeps @c ROCS_SCHEMA as config
 * metadata while the reference CLI may use recognized schema ids to choose
 * that application schema before startup.
 *
 * Minimal reference HTTP protocol:
 *
 * - @c POST @c /v1/query accepts JSON:
 *   @code
 *   {
 *     "filter": { "exists": "id" },
 *     "limit": 10,
 *     "ranked": false,
 *     "include_records": false,
 *     "resume": "optional-durable-position-token"
 *   }
 *   @endcode
 *   The @c filter object supports @c {"exists":"field"} and
 *   @c {"contains":{"field":"message","term":"word"}},
 *   @c {"eq":{"field":"quality","value":"degraded"}},
 *   @c {"range":{"field":"timestamp","lower":1,"upper":2}}, and
 *   @c {"and":[...]} composition. The route constructs public filter/query
 *   specs. Unranked requests execute a bounded snapshot cursor page and return
 *   @c hits, @c count, @c more, and @c next_resume so callers can stream pages
 *   by sending the previous @c next_resume as @c resume. Ranked requests execute
 *   @ref n00b_query_run as a finite ranked query and do not accept @c resume.
 *   When @c include_records is true, each hit also includes a newly
 *   materialized JSON copy of the record.
 * - @c POST @c /v1/records accepts one JSON record body. Read-only services
 *   return a deterministic @c 403 response. Read-write services ingest the
 *   body through @ref n00b_store_ingest_buf without sealing the current hot
 *   shard.
 * - @c POST @c /v1/records/batch accepts newline-delimited JSON records.
 *   Read-write services ingest the batch through
 *   @ref n00b_store_ingest_buf_batch without sealing the current hot shard.
 * - @c POST @c /v1/flush seals pending writes through the public store API so
 *   later snapshot queries observe the write.
 * - @c GET @c /healthz/startup succeeds after config/schema/store open,
 *   route registration, and listener startup have completed.
 * - @c GET @c /healthz/live succeeds while the runtime is alive, including
 *   dependency outage or draining states.
 * - @c GET @c /healthz/ready succeeds only when the service is started,
 *   dependency-ready, not draining, and the underlying store is open.
 * - @c GET @c /metrics returns Prometheus text with stable rocs metric names
 *   for store residency/catalog state, resident-cache activity, live-pressure
 *   gauges, and request/error/latency counters.
 *
 * Responses never expose mapped JSON containers, mapped buffers,
 * catalog-entry pointers, resident handles, or query-cache internals.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/string.h"
#include "rocs/store.h"

typedef struct n00b_rocs_service_config_t n00b_rocs_service_config_t;
typedef struct n00b_rocs_service_t        n00b_rocs_service_t;

/** @brief Error domain for the reference rocs service lifecycle. */
typedef enum : int32_t {
    N00B_ROCS_SERVICE_OK            = 0,
    N00B_ROCS_SERVICE_ERR_ARG       = -1,
    N00B_ROCS_SERVICE_ERR_CONFIG    = -2,
    N00B_ROCS_SERVICE_ERR_STORE     = -3,
    N00B_ROCS_SERVICE_ERR_HTTP      = -4,
    N00B_ROCS_SERVICE_ERR_STATE     = -5,
    N00B_ROCS_SERVICE_ERR_CLOSED    = -6,
    N00B_ROCS_SERVICE_ERR_READ_ONLY = -7,
    N00B_ROCS_SERVICE_ERR_REQUEST   = -8,
    N00B_ROCS_SERVICE_ERR_QUERY     = -9,
} n00b_rocs_service_err_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Construct reference service config from environment variables.
 *
 * @kw prefix    Optional prefix prepended verbatim to every supported
 *               @c ROCS_* key.
 * @kw allocator Allocator for config-owned strings and nested store config.
 *
 * @return Ok(config) on success. Invalid profile, store config, HTTP address,
 *         boolean, numeric, S3 endpoint/path-style, or writer mode inputs
 *         return typed store config errors.
 *
 * @post This function only builds process-side configuration. It does not open
 *       stores, start service threads, bind sockets, initialize Kubernetes
 *       probes, or change store/query/index/live/aggregation/ranking behavior.
 */
extern n00b_result_t(n00b_rocs_service_config_t *)
n00b_rocs_service_config_from_env() _kargs
{
    n00b_string_t    *prefix    = nullptr;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Borrow the nested store config.
 *
 * The returned pointer is owned by the service config and remains valid while
 * the service config is reachable.
 */
extern n00b_result_t(n00b_store_config_t *)
n00b_rocs_service_config_get_store_config(
    n00b_rocs_service_config_t *config);

/** @brief Return the copied HTTP bind address, when configured. */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_rocs_service_config_get_http_addr(
    n00b_rocs_service_config_t *config);

/** @brief Return whether the service is configured read-only. */
extern n00b_result_t(bool)
n00b_rocs_service_config_get_read_only(
    n00b_rocs_service_config_t *config);

/** @brief Static diagnostic string for a reference-service error code. */
extern n00b_string_t *
n00b_rocs_service_err_str(n00b_err_t err);

/**
 * @brief Start the reference HTTP service runtime.
 *
 * @param config Service config returned by
 *               @ref n00b_rocs_service_config_from_env.
 * @param schema Application-supplied store schema. The service passes this
 *               schema to @ref n00b_store_open_config; it does not parse
 *               @c ROCS_SCHEMA.
 * @kw allocator Allocator for runtime-owned state.
 *
 * @return Ok(runtime) after the store is open, routes are registered, and the
 *         HTTP listener has bound successfully. Null inputs return
 *         @ref N00B_ROCS_SERVICE_ERR_ARG. Invalid HTTP bind config returns
 *         @ref N00B_ROCS_SERVICE_ERR_CONFIG. Store-open failures return
 *         @ref N00B_ROCS_SERVICE_ERR_STORE. Route/listener failures return
 *         @ref N00B_ROCS_SERVICE_ERR_HTTP.
 *
 * @post The runtime does not change store/query/index/live/aggregation/ranking
 *       semantics. Snapshot query requests use @ref n00b_query_new and
 *       @ref n00b_query_run; no live HTTP streaming protocol is added in this
 *       phase.
 */
extern n00b_result_t(n00b_rocs_service_t *)
n00b_rocs_service_start(n00b_rocs_service_config_t *config,
                        n00b_store_schema_t        *schema) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Stop the reference service and close its store.
 *
 * @param service Runtime returned by @ref n00b_rocs_service_start.
 * @return Ok(true) on the first stop, Ok(false) on later calls,
 *         @ref N00B_ROCS_SERVICE_ERR_ARG for null, or
 *         @ref N00B_ROCS_SERVICE_ERR_STORE if store close reports leaked pins
 *         or another store-domain failure.
 *
 * @post Stop first stops accepting HTTP requests and joins the listener, then
 *       closes the store. Phase 2 does not use an HTTP worker pool, so an
 *       in-flight handler is joined before store close. Finite query handlers
 *       close their result before sending a response; read-write record
 *       handlers append to the hot shard and explicit flush requests seal
 *       pending writes.
 */
extern n00b_result_t(bool)
n00b_rocs_service_stop(n00b_rocs_service_t *service);

/**
 * @brief Mark the running service as draining or serving.
 *
 * Draining services keep liveness green but readiness red. This is the
 * Kubernetes pre-stop/shutdown hook: callers can mark a service draining,
 * let traffic drain, then call @ref n00b_rocs_service_stop.
 *
 * @return Ok(true) when the state was recorded, @ref N00B_ROCS_SERVICE_ERR_ARG
 *         for null, or @ref N00B_ROCS_SERVICE_ERR_CLOSED after stop.
 */
extern n00b_result_t(bool)
n00b_rocs_service_set_draining(n00b_rocs_service_t *service, bool draining);

/**
 * @brief Mark external runtime dependencies ready or unavailable.
 *
 * This hook lets service supervisors or tests reflect VFS/S3/catalog
 * reachability into readiness without changing liveness or closing the store.
 * A false value makes @c /healthz/ready return a deterministic not-ready
 * response while @c /healthz/live remains green.
 *
 * @return Ok(true) when the state was recorded, @ref N00B_ROCS_SERVICE_ERR_ARG
 *         for null, or @ref N00B_ROCS_SERVICE_ERR_CLOSED after stop.
 */
extern n00b_result_t(bool)
n00b_rocs_service_set_dependency_ready(n00b_rocs_service_t *service,
                                       bool                 ready);

/**
 * @brief Record current service-owned live queue pressure.
 *
 * Reference-service live adapters use this hook to project WP-009 live queue
 * pressure into the service metric surface without exposing queue internals.
 * Liveness and readiness are unchanged by this value.
 *
 * @return Ok(true) when the value was recorded,
 *         @ref N00B_ROCS_SERVICE_ERR_ARG for null, or
 *         @ref N00B_ROCS_SERVICE_ERR_CLOSED after stop.
 */
extern n00b_result_t(bool)
n00b_rocs_service_set_live_queue_pressure(n00b_rocs_service_t *service,
                                          uint64_t             pressure);

/**
 * @brief Return the bound HTTP port for a running service.
 *
 * This is primarily useful when config used an ephemeral @c :0 port.
 */
extern n00b_result_t(uint16_t)
n00b_rocs_service_bound_port(n00b_rocs_service_t *service);

#ifdef __cplusplus
}
#endif
