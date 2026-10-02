#include "rocs/service.h"

#include <stdint.h>

#include "conduit/conduit.h"
#include "conduit/service.h"
#include "core/atomic.h"
#include "core/buffer.h"
#include "core/mutex.h"
#include "core/platform.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "internal/rocs/index.h"
#include "net/http/http_service.h"
#include "parsers/json.h"
#include "rocs/filter.h"
#include "rocs/query.h"
#include "rocs/wax.h"
#include "text/strings/fmt_numbers.h"
#include "text/strings/string_ops.h"

struct n00b_rocs_service_t {
    n00b_rocs_service_config_t *config;
    n00b_store_t               *store;
    n00b_http_service_t        *http;
    n00b_conduit_t             *worker_conduit;
    n00b_conduit_service_t     *worker_service;
    n00b_mutex_t                store_mutex;
    bool                        read_only;
    _Atomic(bool)               stopped;
    _Atomic(bool)               startup_ready;
    _Atomic(bool)               draining;
    _Atomic(bool)               dependency_ready;
    uint16_t                    bound_port;
    n00b_allocator_t           *allocator;
    n00b_pool_t                 owned_pool;
    bool                        owns_allocator;
    _Atomic(uint64_t)           query_requests;
    _Atomic(uint64_t)           query_errors;
    _Atomic(uint64_t)           query_latency_ns;
    _Atomic(uint64_t)           ingest_requests;
    _Atomic(uint64_t)           ingest_errors;
    _Atomic(uint64_t)           ingest_latency_ns;
    _Atomic(uint64_t)           store_errors;
    _Atomic(uint64_t)           vfs_s3_errors;
    _Atomic(uint64_t)           live_queue_pressure;
};

#define N00B_ROCS_SERVICE_WORKER_THREADS 4

typedef struct {
    n00b_string_t *host;
    uint16_t       port;
} rocs_service_bind_t;

static n00b_allocator_t *
rocs_service_control_allocator(n00b_allocator_t *allocator)
{
    if (allocator != nullptr) {
        return allocator;
    }
    return (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
}

static n00b_allocator_t *
rocs_service_runtime_allocator(n00b_rocs_service_t *service,
                               n00b_allocator_t    *allocator)
{
    if (allocator != nullptr) {
        service->owns_allocator = false;
        return allocator;
    }

    service->owns_allocator = true;
    return n00b_pool_init(&service->owned_pool,
                          .hidden            = true,
                          .external_metadata = true,
                          .name              = "rocs_service_pool");
}

static void
rocs_service_destroy_owned_allocator(n00b_rocs_service_t *service)
{
    if (service == nullptr || !service->owns_allocator
        || service->allocator == nullptr) {
        return;
    }

    n00b_allocator_destroy(service->allocator);
    service->allocator      = nullptr;
    service->owns_allocator = false;
}

static void
rocs_service_destroy_workers(n00b_rocs_service_t *service)
{
    if (service == nullptr) {
        return;
    }
    if (service->worker_service != nullptr) {
        n00b_conduit_service_stop(service->worker_service);
        n00b_conduit_service_destroy(service->worker_service);
        service->worker_service = nullptr;
    }
    if (service->worker_conduit != nullptr) {
        n00b_conduit_destroy(service->worker_conduit);
        service->worker_conduit = nullptr;
    }
}

static bool
rocs_service_start_workers(n00b_rocs_service_t *service)
{
    if (service == nullptr) {
        return false;
    }

    auto conduit_r = n00b_conduit_new();
    if (n00b_result_is_err(conduit_r)) {
        return false;
    }
    service->worker_conduit = n00b_result_get(conduit_r);

    auto service_r = n00b_conduit_service_new(service->worker_conduit);
    if (n00b_result_is_err(service_r)) {
        rocs_service_destroy_workers(service);
        return false;
    }
    service->worker_service = n00b_result_get(service_r);

    auto start_r = n00b_conduit_service_start(service->worker_service);
    if (n00b_result_is_err(start_r)) {
        rocs_service_destroy_workers(service);
        return false;
    }

    for (uint64_t i = 0; i < N00B_ROCS_SERVICE_WORKER_THREADS; i++) {
        auto worker_r = n00b_conduit_service_add_worker(service->worker_service);
        if (n00b_result_is_err(worker_r)) {
            rocs_service_destroy_workers(service);
            return false;
        }
    }

    return true;
}

static bool
rocs_service_runtime_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static void
rocs_service_append(n00b_buffer_t *buf, n00b_string_t *s)
{
    if (buf == nullptr || s == nullptr || s->u8_bytes == 0) {
        return;
    }
    n00b_buffer_append_bytes(buf, s->data, (uint64_t)s->u8_bytes);
}

static void
rocs_service_append_u64(n00b_buffer_t *buf, uint64_t value)
{
    if (buf == nullptr) {
        return;
    }
    n00b_buffer_append_uint(buf, value);
}

static void
rocs_service_append_f64(n00b_buffer_t *buf, double value)
{
    if (buf == nullptr) {
        return;
    }
    rocs_service_append(buf,
                        n00b_fmt_float(value, .allocator = buf->allocator));
}

static n00b_store_source_list_t *
rocs_service_source_list_new(n00b_allocator_t *allocator)
{
    n00b_store_source_list_t *sources =
        n00b_alloc_with_opts(n00b_store_source_list_t,
                             &(n00b_alloc_opts_t){
                                 .allocator = allocator,
                             });

    *sources = n00b_list_new_private(n00b_buffer_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return sources;
}

static n00b_result_t(n00b_store_source_list_t *)
rocs_service_ndjson_sources(n00b_buffer_t *body, n00b_allocator_t *allocator)
{
    if (body == nullptr || body->data == nullptr) {
        return n00b_result_err(n00b_store_source_list_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_source_list_t *sources =
        rocs_service_source_list_new(allocator);
    size_t len   = (size_t)n00b_buffer_len(body);
    size_t start = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i < len && body->data[i] != '\n') {
            continue;
        }
        if (i == len && start == i) {
            break;
        }

        size_t end = i;
        if (end > start && body->data[end - 1] == '\r') {
            end--;
        }
        if (end > start) {
            n00b_buffer_t *line =
                n00b_buffer_from_bytes((char *)body->data + start,
                                       (int64_t)(end - start),
                                       .allocator = allocator);
            n00b_list_push(*sources, line);
        }
        start = i + 1;
    }

    return n00b_result_ok(n00b_store_source_list_t *, sources);
}

static void
rocs_service_append_bool(n00b_buffer_t *buf, bool value)
{
    rocs_service_append(buf, value ? r"true" : r"false");
}

static void
rocs_service_append_memory_field(n00b_buffer_t *buf,
                                 n00b_string_t *name,
                                 uint64_t       value,
                                 bool           comma)
{
    if (comma) {
        rocs_service_append(buf, r",");
    }
    rocs_service_append(buf, r"\"");
    rocs_service_append(buf, name);
    rocs_service_append(buf, r"\":");
    rocs_service_append_u64(buf, value);
}

static void
rocs_service_append_memory_body(n00b_buffer_t              *buf,
                                n00b_store_memory_stats_t  stats)
{
    rocs_service_append(buf, r",\"memory\":{");
    rocs_service_append_memory_field(buf,
                                     r"hot_shard_id",
                                     stats.hot_shard_id,
                                     false);
    rocs_service_append_memory_field(buf,
                                     r"hot_record_count",
                                     stats.hot_record_count,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_byte_estimate",
                                     stats.hot_byte_estimate,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_record_text_bytes",
                                     stats.hot_record_text_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_raw_bytes",
                                     stats.hot_raw_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_column_count",
                                     stats.hot_column_count,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_pool_mapped_bytes",
                                     stats.hot_pool_mapped_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_pool_pages",
                                     stats.hot_pool_pages,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_pool_big_maps",
                                     stats.hot_pool_big_maps,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_pool_big_unmaps",
                                     stats.hot_pool_big_unmaps,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_arena_used_bytes",
                                     stats.hot_arena_used_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"hot_arena_size_bytes",
                                     stats.hot_arena_size_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_entries",
                                     stats.catalog_entries,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_generation",
                                     stats.catalog_generation,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_object_path_bytes",
                                     stats.catalog_object_path_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_partition_key_bytes",
                                     stats.catalog_partition_key_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_etag_bytes",
                                     stats.catalog_etag_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"catalog_string_bytes",
                                     stats.catalog_string_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_shards",
                                     stats.sealed_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_records",
                                     stats.sealed_records,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_bytes",
                                     stats.sealed_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_min_bytes",
                                     stats.sealed_min_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_max_bytes",
                                     stats.sealed_max_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_avg_bytes",
                                     stats.sealed_avg_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_avg_records",
                                     stats.sealed_avg_records,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_shards_le_64k",
                                     stats.sealed_shards_le_64k,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_shards_le_256k",
                                     stats.sealed_shards_le_256k,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"sealed_shards_le_1m",
                                     stats.sealed_shards_le_1m,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_bytes",
                                     stats.resident_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_shards",
                                     stats.resident_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_mapped_bytes",
                                     stats.resident_mapped_bytes,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_local_mmap_shards",
                                     stats.resident_local_mmap_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_copy_mmap_shards",
                                     stats.resident_copy_mmap_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_buffer_shards",
                                     stats.resident_buffer_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_unknown_shards",
                                     stats.resident_unknown_shards,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"active_pins",
                                     stats.active_pins,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"retired_hot_allocators",
                                     stats.retired_hot_allocators,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"retired_hot_records",
                                     stats.retired_hot_records,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"failed_seal_jobs",
                                     stats.failed_seal_jobs,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"failed_seal_records",
                                     stats.failed_seal_records,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"seal_worker_count",
                                     stats.seal_worker_count,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"seal_queue_pending",
                                     stats.seal_queue_pending,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"seal_queue_in_flight",
                                     stats.seal_queue_in_flight,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_cache_hits",
                                     stats.resident_cache_hits,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_cache_misses",
                                     stats.resident_cache_misses,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_unloads",
                                     stats.resident_unloads,
                                     true);
    rocs_service_append_memory_field(buf,
                                     r"resident_unload_bytes",
                                     stats.resident_unload_bytes,
                                     true);
    rocs_service_append(buf, r"}");
}

// Per-request scratch. Everything a handler builds for one request, from the
// parsed body to the query view and the serialized reply, is cut from this pool
// and released by a single destroy once the reply has been handed over.
typedef struct {
    n00b_pool_t       pool;
    n00b_allocator_t *allocator;
} rocs_service_scratch_t;

// Query code frees some temporaries without naming their allocator, which only
// finds the pool when its pages are registered through external metadata. That
// metadata pool's teardown waits for the next stop-the-world, and a full queue
// of them forces one, so handlers that build only buffers leave it off.
static n00b_allocator_t *
rocs_service_scratch_begin(rocs_service_scratch_t *scratch,
                           bool                    external_metadata)
{
    scratch->allocator = n00b_pool_init(&scratch->pool,
                                        .hidden            = true,
                                        .external_metadata = external_metadata,
                                        .name = "rocs_service_request");
    return scratch->allocator;
}

// The response writer borrows its body until after the handler returns, so
// the body is copied onto the HTTP layer's heap before the pool is destroyed.
static void
rocs_service_scratch_reply(rocs_service_scratch_t      *scratch,
                           n00b_http_response_writer_t *resp,
                           uint16_t                     status,
                           n00b_buffer_t               *body,
                           n00b_string_t               *content_type)
{
    n00b_buffer_t *out = n00b_buffer_from_bytes(body->data,
                                                n00b_buffer_len(body));
    n00b_allocator_destroy(scratch->allocator);
    scratch->allocator = nullptr;

    n00b_http_response_writer_status(resp, status);
    n00b_http_response_writer_header(resp, r"content-type", content_type);
    n00b_http_response_writer_body(resp, out);
}

static n00b_buffer_t *
rocs_service_json_error(n00b_string_t *code,
                        n00b_allocator_t *allocator)
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);
    rocs_service_append(buf, r"{\"ok\":false,\"error\":\"");
    rocs_service_append(buf, code);
    rocs_service_append(buf, r"\"}");
    return buf;
}

static void
rocs_service_reply_json(rocs_service_scratch_t      *scratch,
                        n00b_http_response_writer_t *resp,
                        uint16_t                     status,
                        n00b_buffer_t               *body)
{
    rocs_service_scratch_reply(scratch,
                               resp,
                               status,
                               body,
                               r"application/json");
}

static void
rocs_service_reply_error(rocs_service_scratch_t      *scratch,
                         n00b_http_response_writer_t *resp,
                         uint16_t                     status,
                         n00b_string_t               *code)
{
    rocs_service_reply_json(scratch,
                            resp,
                            status,
                            rocs_service_json_error(code,
                                                    scratch->allocator));
}

static void
rocs_service_record_store_error(n00b_rocs_service_t *service, n00b_err_t err)
{
    if (service == nullptr) {
        return;
    }
    n00b_atomic_add(&service->store_errors, 1);
    if (err == N00B_STORE_ERR_VFS) {
        n00b_atomic_add(&service->vfs_s3_errors, 1);
    }
}

static bool
rocs_service_store_open(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return false;
    }
    auto state_r = n00b_store_get_state(service->store);
    if (n00b_result_is_err(state_r)) {
        return false;
    }
    return n00b_result_get(state_r) == N00B_STORE_STATE_OPEN;
}

static bool
rocs_service_is_started(n00b_rocs_service_t *service)
{
    return service != nullptr && !n00b_atomic_load(&service->stopped)
        && n00b_atomic_load(&service->startup_ready)
        && service->bound_port != 0 && rocs_service_store_open(service);
}

static bool
rocs_service_is_ready(n00b_rocs_service_t *service)
{
    return rocs_service_is_started(service)
        && !n00b_atomic_load(&service->draining)
        && n00b_atomic_load(&service->dependency_ready);
}

static n00b_buffer_t *
rocs_service_health_body(n00b_rocs_service_t *service,
                         n00b_string_t       *status,
                         bool                 ok,
                         n00b_allocator_t    *allocator)
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);
    rocs_service_append(buf, r"{\"ok\":");
    rocs_service_append_bool(buf, ok);
    rocs_service_append(buf, r",\"status\":\"");
    rocs_service_append(buf, status);
    rocs_service_append(buf, r"\",\"startup\":");
    rocs_service_append_bool(
        buf,
        service != nullptr && n00b_atomic_load(&service->startup_ready));
    rocs_service_append(buf, r",\"draining\":");
    rocs_service_append_bool(
        buf,
        service != nullptr && n00b_atomic_load(&service->draining));
    rocs_service_append(buf, r",\"dependency_ready\":");
    rocs_service_append_bool(
        buf,
        service != nullptr && n00b_atomic_load(&service->dependency_ready));
    n00b_store_memory_stats_t memory = {};
    if (service != nullptr && service->store != nullptr) {
        auto memory_r = n00b_store_memory_stats(service->store);
        if (n00b_result_is_ok(memory_r)) {
            memory = n00b_result_get(memory_r);
        }
    }
    rocs_service_append_memory_body(buf, memory);
    rocs_service_append(buf, r"}");
    return buf;
}

static void
rocs_service_health_reply(n00b_rocs_service_t         *service,
                          n00b_http_response_writer_t *resp,
                          bool                         ok,
                          n00b_string_t               *status)
{
    rocs_service_scratch_t scratch;
    n00b_allocator_t      *allocator =
        rocs_service_scratch_begin(&scratch, false);
    rocs_service_reply_json(&scratch,
                            resp,
                            ok ? 200 : 503,
                            rocs_service_health_body(service,
                                                     status,
                                                     ok,
                                                     allocator));
}

static void
rocs_service_startup_handler(n00b_http_request_t         *req,
                             n00b_http_response_writer_t *resp,
                             void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool                 ok      = rocs_service_is_started(service);
    rocs_service_health_reply(service,
                              resp,
                              ok,
                              ok ? r"started" : r"starting");
}

static void
rocs_service_liveness_handler(n00b_http_request_t         *req,
                              n00b_http_response_writer_t *resp,
                              void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool ok = service != nullptr && !n00b_atomic_load(&service->stopped);
    rocs_service_health_reply(service, resp, ok, ok ? r"alive" : r"closed");
}

static void
rocs_service_readiness_handler(n00b_http_request_t         *req,
                               n00b_http_response_writer_t *resp,
                               void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool                 ok      = rocs_service_is_ready(service);
    rocs_service_health_reply(service,
                              resp,
                              ok,
                              ok ? r"ready" : r"not_ready");
}

static void
rocs_service_metric_type(n00b_buffer_t *buf,
                         n00b_string_t *name,
                         n00b_string_t *kind,
                         n00b_string_t *help)
{
    rocs_service_append(buf, r"# HELP ");
    rocs_service_append(buf, name);
    rocs_service_append(buf, r" ");
    rocs_service_append(buf, help);
    rocs_service_append(buf, r"\n# TYPE ");
    rocs_service_append(buf, name);
    rocs_service_append(buf, r" ");
    rocs_service_append(buf, kind);
    rocs_service_append(buf, r"\n");
}

static void
rocs_service_metric_u64(n00b_buffer_t *buf,
                        n00b_string_t *name,
                        n00b_string_t *kind,
                        n00b_string_t *help,
                        uint64_t       value)
{
    rocs_service_metric_type(buf, name, kind, help);
    rocs_service_append(buf, name);
    rocs_service_append(buf, r" ");
    rocs_service_append_u64(buf, value);
    rocs_service_append(buf, r"\n");
}

static uint64_t
rocs_service_store_generation_metric(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return 0;
    }
    auto r = n00b_store_get_generation(service->store);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : 0;
}

static uint64_t
rocs_service_store_catalog_metric(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return 0;
    }
    auto r = n00b_store_catalog_get_entry_count(service->store);
    return n00b_result_is_ok(r) ? n00b_result_get(r) : 0;
}

static n00b_store_residency_stats_t
rocs_service_store_residency_stats_metric(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return (n00b_store_residency_stats_t){};
    }
    auto r = n00b_store_residency_stats(service->store);
    return n00b_result_is_ok(r) ? n00b_result_get(r)
                                : (n00b_store_residency_stats_t){};
}

static n00b_store_memory_stats_t
rocs_service_store_memory_stats_metric(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return (n00b_store_memory_stats_t){};
    }
    auto r = n00b_store_memory_stats(service->store);
    return n00b_result_is_ok(r) ? n00b_result_get(r)
                                : (n00b_store_memory_stats_t){};
}

static void
rocs_service_trim_residency(n00b_rocs_service_t *service)
{
    if (service == nullptr || service->store == nullptr) {
        return;
    }
    auto trim_r = n00b_store_residency_trim(service->store);
    if (n00b_result_is_err(trim_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(trim_r));
    }
}

static n00b_buffer_t *
rocs_service_metrics_body(n00b_rocs_service_t *service,
                          n00b_allocator_t    *allocator)
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);
    uint64_t          up        = service != nullptr
                               && !n00b_atomic_load(&service->stopped);
    uint64_t store_errors = service == nullptr ? 0
                                               : n00b_atomic_load(
                                                     &service->store_errors);
    uint64_t vfs_s3_errors = service == nullptr ? 0
                                                : n00b_atomic_load(
                                                      &service->vfs_s3_errors);
    n00b_store_residency_stats_t residency =
        rocs_service_store_residency_stats_metric(service);
    n00b_store_memory_stats_t memory =
        rocs_service_store_memory_stats_metric(service);
    uint64_t query_requests = service == nullptr ? 0
                                                 : n00b_atomic_load(
                                                       &service->query_requests);
    uint64_t query_errors = service == nullptr ? 0
                                               : n00b_atomic_load(
                                                     &service->query_errors);
    uint64_t query_latency = service == nullptr ? 0
                                                : n00b_atomic_load(
                                                      &service->query_latency_ns);
    uint64_t ingest_requests = service == nullptr
                                   ? 0
                                   : n00b_atomic_load(
                                         &service->ingest_requests);
    uint64_t ingest_errors = service == nullptr ? 0
                                                : n00b_atomic_load(
                                                      &service->ingest_errors);
    uint64_t ingest_latency = service == nullptr
                                  ? 0
                                  : n00b_atomic_load(
                                        &service->ingest_latency_ns);
    uint64_t live_queue_pressure =
        service == nullptr ? 0
                           : n00b_atomic_load(&service->live_queue_pressure);

    rocs_service_metric_u64(buf,
                            r"rocs_service_up",
                            r"gauge",
                            r"service runtime is alive",
                            up);
    rocs_service_metric_u64(buf,
                            r"rocs_service_ready",
                            r"gauge",
                            r"service runtime is ready for traffic",
                            rocs_service_is_ready(service));
    rocs_service_metric_u64(buf,
                            r"rocs_store_resident_bytes",
                            r"gauge",
                            r"resident sealed shard bytes",
                            residency.resident_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_resident_shards",
                            r"gauge",
                            r"resident sealed shard count",
                            residency.resident_shards);
    rocs_service_metric_u64(buf,
                            r"rocs_store_catalog_generation",
                            r"gauge",
                            r"store catalog generation",
                            rocs_service_store_generation_metric(service));
    rocs_service_metric_u64(buf,
                            r"rocs_store_catalog_entries",
                            r"gauge",
                            r"sealed shard catalog entry count",
                            rocs_service_store_catalog_metric(service));
    rocs_service_metric_u64(buf,
                            r"rocs_store_active_pins",
                            r"gauge",
                            r"active store resource pins",
                            residency.active_pins);
    rocs_service_metric_u64(buf,
                            r"rocs_store_retired_hot_allocators",
                            r"gauge",
                            r"sealed hot-shard allocators pending destruction",
                            residency.retired_hot_allocators);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_record_count",
                            r"gauge",
                            r"records in the current hot shard",
                            memory.hot_record_count);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_byte_estimate",
                            r"gauge",
                            r"estimated bytes retained by current hot shard",
                            memory.hot_byte_estimate);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_record_text_bytes",
                            r"gauge",
                            r"compact JSON text bytes in current hot shard",
                            memory.hot_record_text_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_pool_mapped_bytes",
                            r"gauge",
                            r"bytes mapped by current hot shard pool",
                            memory.hot_pool_mapped_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_pool_pages",
                            r"gauge",
                            r"mmap regions owned by current hot shard pool",
                            memory.hot_pool_pages);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_arena_used_bytes",
                            r"gauge",
                            r"bytes used by current hot shard control arena",
                            memory.hot_arena_used_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_hot_arena_size_bytes",
                            r"gauge",
                            r"bytes available in current hot shard control arena",
                            memory.hot_arena_size_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_sealed_shards",
                            r"gauge",
                            r"sealed shard catalog entries",
                            memory.sealed_shards);
    rocs_service_metric_u64(buf,
                            r"rocs_store_sealed_records",
                            r"gauge",
                            r"records in sealed shard catalog entries",
                            memory.sealed_records);
    rocs_service_metric_u64(buf,
                            r"rocs_store_sealed_bytes",
                            r"gauge",
                            r"bytes in sealed shard catalog entries",
                            memory.sealed_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_sealed_avg_bytes",
                            r"gauge",
                            r"average sealed shard image bytes",
                            memory.sealed_avg_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_sealed_shards_le_256k",
                            r"gauge",
                            r"sealed shard catalog entries at or below 256KiB",
                            memory.sealed_shards_le_256k);
    rocs_service_metric_u64(buf,
                            r"rocs_store_resident_mapped_bytes",
                            r"gauge",
                            r"page-aligned bytes mapped by resident shard images",
                            memory.resident_mapped_bytes);
    rocs_service_metric_u64(buf,
                            r"rocs_store_resident_local_mmap_shards",
                            r"gauge",
                            r"resident shard images backed by direct local mmap",
                            memory.resident_local_mmap_shards);
    rocs_service_metric_u64(buf,
                            r"rocs_store_retired_hot_records",
                            r"gauge",
                            r"records held by retired hot-shard allocators",
                            memory.retired_hot_records);
    rocs_service_metric_u64(buf,
                            r"rocs_store_failed_seal_jobs",
                            r"gauge",
                            r"failed async seal jobs retained for retry",
                            memory.failed_seal_jobs);
    rocs_service_metric_u64(buf,
                            r"rocs_store_failed_seal_records",
                            r"gauge",
                            r"records held by failed async seal jobs",
                            memory.failed_seal_records);
    rocs_service_metric_u64(buf,
                            r"rocs_store_seal_worker_count",
                            r"gauge",
                            r"configured async seal worker threads",
                            memory.seal_worker_count);
    rocs_service_metric_u64(buf,
                            r"rocs_store_seal_queue_pending",
                            r"gauge",
                            r"async seal jobs waiting in the store worklist",
                            memory.seal_queue_pending);
    rocs_service_metric_u64(buf,
                            r"rocs_store_seal_queue_in_flight",
                            r"gauge",
                            r"async seal jobs currently running",
                            memory.seal_queue_in_flight);
    rocs_service_metric_u64(buf,
                            r"rocs_service_store_errors_total",
                            r"counter",
                            r"store-domain errors observed by the service",
                            store_errors);
    rocs_service_metric_u64(buf,
                            r"rocs_service_vfs_s3_errors_total",
                            r"counter",
                            r"VFS or S3 store errors observed by the service",
                            vfs_s3_errors);
    rocs_service_metric_u64(buf,
                            r"rocs_service_cache_hits_total",
                            r"counter",
                            r"resident shard cache hits observed by service",
                            residency.cache_hits);
    rocs_service_metric_u64(buf,
                            r"rocs_service_cache_misses_total",
                            r"counter",
                            r"resident shard cache misses observed by service",
                            residency.cache_misses);
    rocs_service_metric_u64(buf,
                            r"rocs_service_query_requests_total",
                            r"counter",
                            r"snapshot query HTTP requests",
                            query_requests);
    rocs_service_metric_u64(buf,
                            r"rocs_service_query_errors_total",
                            r"counter",
                            r"snapshot query HTTP request errors",
                            query_errors);
    rocs_service_metric_u64(buf,
                            r"rocs_service_query_latency_ns_total",
                            r"counter",
                            r"total snapshot query request latency in ns",
                            query_latency);
    rocs_service_metric_u64(buf,
                            r"rocs_service_ingest_requests_total",
                            r"counter",
                            r"record ingest HTTP requests",
                            ingest_requests);
    rocs_service_metric_u64(buf,
                            r"rocs_service_ingest_errors_total",
                            r"counter",
                            r"record ingest HTTP request errors",
                            ingest_errors);
    rocs_service_metric_u64(buf,
                            r"rocs_service_ingest_latency_ns_total",
                            r"counter",
                            r"total record ingest request latency in ns",
                            ingest_latency);
    rocs_service_metric_u64(buf,
                            r"rocs_service_trim_unloads_total",
                            r"counter",
                            r"resident shard unload operations visible to service",
                            residency.unloads);
    rocs_service_metric_u64(buf,
                            r"rocs_service_live_queue_pressure",
                            r"gauge",
                            r"service-owned live queue pressure",
                            live_queue_pressure);
    return buf;
}

static void
rocs_service_metrics_handler(n00b_http_request_t         *req,
                             n00b_http_response_writer_t *resp,
                             void                        *user_data)
{
    n00b_rocs_service_t   *service = user_data;
    rocs_service_scratch_t scratch;
    n00b_allocator_t      *allocator =
        rocs_service_scratch_begin(&scratch, false);
    n00b_mutex_lock(&service->store_mutex);
    n00b_buffer_t *body = rocs_service_metrics_body(service, allocator);
    n00b_mutex_unlock(&service->store_mutex);
    rocs_service_scratch_reply(&scratch,
                               resp,
                               200,
                               body,
                               r"text/plain; version=0.0.4");
}

static n00b_result_t(rocs_service_bind_t)
rocs_service_parse_bind(n00b_string_t    *addr,
                        n00b_allocator_t *allocator)
{
    if (rocs_service_runtime_string_empty(addr)) {
        return n00b_result_err(rocs_service_bind_t,
                               N00B_ROCS_SERVICE_ERR_CONFIG);
    }

    int64_t colon = -1;
    for (int64_t i = 0; i < (int64_t)addr->u8_bytes; i++) {
        if (addr->data[i] == ':') {
            colon = i;
        }
    }
    if (colon <= 0 || colon + 1 >= (int64_t)addr->u8_bytes) {
        return n00b_result_err(rocs_service_bind_t,
                               N00B_ROCS_SERVICE_ERR_CONFIG);
    }

    uint64_t port = 0;
    for (int64_t i = colon + 1; i < (int64_t)addr->u8_bytes; i++) {
        char ch = addr->data[i];
        if (ch < '0' || ch > '9') {
            return n00b_result_err(rocs_service_bind_t,
                                   N00B_ROCS_SERVICE_ERR_CONFIG);
        }
        port = port * 10u + (uint64_t)(ch - '0');
        if (port > UINT16_MAX) {
            return n00b_result_err(rocs_service_bind_t,
                                   N00B_ROCS_SERVICE_ERR_CONFIG);
        }
    }

    rocs_service_bind_t bind = {
        .host = n00b_string_from_raw(addr->data,
                                     colon,
                                     .allocator = allocator),
        .port = (uint16_t)port,
    };
    return n00b_result_ok(rocs_service_bind_t, bind);
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_field(n00b_json_node_t *node)
{
    n00b_string_t *field_name = n00b_json_as_string(node);
    if (rocs_service_runtime_string_empty(field_name)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto field_r = n00b_filter_field(field_name);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto exists_r = n00b_filter_exists(n00b_result_get(field_r));
    if (n00b_result_is_err(exists_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return exists_r;
}

static bool
rocs_service_filter_value_from_json(n00b_json_node_t     *node,
                                    n00b_filter_value_t  *out)
{
    if (node == nullptr || out == nullptr) {
        return false;
    }

    switch (n00b_json_type(node)) {
    case N00B_JSON_NULL:
        *out = n00b_fv_null();
        return true;
    case N00B_JSON_BOOL:
        *out = n00b_fv_bool(n00b_json_as_bool(node));
        return true;
    case N00B_JSON_INT:
        *out = n00b_fv_i64(n00b_json_as_i64(node));
        return true;
    case N00B_JSON_DOUBLE:
        *out = n00b_fv_f64(n00b_json_as_f64(node));
        return true;
    case N00B_JSON_STRING:
        if (rocs_service_runtime_string_empty(n00b_json_as_string(node))) {
            return false;
        }
        *out = n00b_fv_utf8(n00b_json_as_string(node));
        return true;
    case N00B_JSON_ARRAY:
    case N00B_JSON_OBJECT:
    default:
        return false;
    }
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_leaf_eq(n00b_json_node_t *eq)
{
    if (eq == nullptr || !n00b_json_is_object(eq)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_string_t *field_name =
        n00b_json_as_string(n00b_json_object_get(eq, r"field"));
    n00b_json_node_t *value = n00b_json_object_get(eq, r"value");
    n00b_filter_value_t filter_value = {};
    if (rocs_service_runtime_string_empty(field_name)
        || !rocs_service_filter_value_from_json(value, &filter_value)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto field_r = n00b_filter_field(field_name);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto eq_r = n00b_filter_eq(n00b_result_get(field_r), filter_value);
    if (n00b_result_is_err(eq_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return eq_r;
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_leaf_range(n00b_json_node_t *range)
{
    if (range == nullptr || !n00b_json_is_object(range)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_string_t *field_name =
        n00b_json_as_string(n00b_json_object_get(range, r"field"));
    n00b_filter_value_t lower = {};
    n00b_filter_value_t upper = {};
    if (rocs_service_runtime_string_empty(field_name)
        || !rocs_service_filter_value_from_json(
            n00b_json_object_get(range, r"lower"), &lower)
        || !rocs_service_filter_value_from_json(
            n00b_json_object_get(range, r"upper"), &upper)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto field_r = n00b_filter_field(field_name);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto range_r = n00b_filter_between(n00b_result_get(field_r),
                                       lower,
                                       upper);
    if (n00b_result_is_err(range_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return range_r;
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_leaf_prefix(n00b_json_node_t *prefix)
{
    if (prefix == nullptr || !n00b_json_is_object(prefix)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_string_t *field_name =
        n00b_json_as_string(n00b_json_object_get(prefix, r"field"));
    n00b_string_t *prefix_text =
        n00b_json_as_string(n00b_json_object_get(prefix, r"prefix"));
    if (rocs_service_runtime_string_empty(field_name)
        || rocs_service_runtime_string_empty(prefix_text)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto field_r = n00b_filter_field(field_name);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto prefix_r = n00b_filter_prefix(n00b_result_get(field_r), prefix_text);
    if (n00b_result_is_err(prefix_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return prefix_r;
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_leaf_regex(n00b_json_node_t *regex)
{
    if (regex == nullptr || !n00b_json_is_object(regex)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_string_t *field_name =
        n00b_json_as_string(n00b_json_object_get(regex, r"field"));
    n00b_string_t *pattern =
        n00b_json_as_string(n00b_json_object_get(regex, r"pattern"));
    if (rocs_service_runtime_string_empty(field_name)
        || rocs_service_runtime_string_empty(pattern)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto field_r = n00b_filter_field(field_name);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto regex_r = n00b_regex_new(pattern);
    if (n00b_result_is_err(regex_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto filter_r = n00b_filter_regex(n00b_result_get(field_r),
                                      n00b_result_get(regex_r));
    if (n00b_result_is_err(filter_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return filter_r;
}

// Leaf predicates only. Returns N00B_ROCS_SERVICE_ERR_STATE when the object
// names no leaf operator, so the caller can try the boolean operators next.
static n00b_result_t(n00b_filter_t *)
rocs_service_filter_leaf_json(n00b_json_node_t *filter)
{
    n00b_json_node_t *exists = n00b_json_object_get(filter, r"exists");
    if (exists != nullptr) {
        return rocs_service_filter_field(exists);
    }

    n00b_json_node_t *contains = n00b_json_object_get(filter, r"contains");
    if (contains != nullptr && n00b_json_is_object(contains)) {
        n00b_string_t *field_name =
            n00b_json_as_string(n00b_json_object_get(contains, r"field"));
        n00b_json_node_t *any_node = n00b_json_object_get(contains, r"any");
        n00b_string_t *term =
            n00b_json_as_string(n00b_json_object_get(contains, r"term"));
        bool any_field = any_node != nullptr && n00b_json_is_bool(any_node)
                         && n00b_json_as_bool(any_node);
        if ((!any_field && rocs_service_runtime_string_empty(field_name))
            || rocs_service_runtime_string_empty(term)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        n00b_filter_field_t *field = any_field ? n00b_filter_any() : nullptr;
        if (!any_field) {
            auto field_r = n00b_filter_field(field_name);
            if (n00b_result_is_err(field_r)) {
                return n00b_result_err(n00b_filter_t *,
                                       N00B_ROCS_SERVICE_ERR_REQUEST);
            }
            field = n00b_result_get(field_r);
        }

        auto filter_r = n00b_filter_contains(field, term);
        if (n00b_result_is_err(filter_r)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        return filter_r;
    }

    n00b_json_node_t *eq = n00b_json_object_get(filter, r"eq");
    if (eq != nullptr) {
        return rocs_service_filter_leaf_eq(eq);
    }

    n00b_json_node_t *range = n00b_json_object_get(filter, r"range");
    if (range != nullptr) {
        return rocs_service_filter_leaf_range(range);
    }

    n00b_json_node_t *prefix = n00b_json_object_get(filter, r"prefix");
    if (prefix != nullptr) {
        return rocs_service_filter_leaf_prefix(prefix);
    }

    n00b_json_node_t *regex = n00b_json_object_get(filter, r"regex");
    if (regex != nullptr) {
        return rocs_service_filter_leaf_regex(regex);
    }

    return n00b_result_err(n00b_filter_t *, N00B_ROCS_SERVICE_ERR_STATE);
}

static n00b_result_t(n00b_filter_ir_t *)
rocs_service_filter_ir_json(n00b_json_node_t *filter);

// An "and"/"or" array becomes one n-ary node, so its width does not count
// toward N00B_FILTER_MAX_DEPTH. A single-element array is its element.
static n00b_result_t(n00b_filter_ir_t *)
rocs_service_filter_combine_json(n00b_json_node_t *items_node, bool is_or)
{
    if (items_node == nullptr || !n00b_json_is_array(items_node)) {
        return n00b_result_err(n00b_filter_ir_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_json_array_t *items = n00b_json_as_array(items_node);
    size_t             len   = items == nullptr ? 0 : n00b_list_len(*items);
    if (len == 0) {
        return n00b_result_err(n00b_filter_ir_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    if (len == 1) {
        return rocs_service_filter_ir_json(n00b_list_get(*items, 0));
    }

    n00b_filter_ir_child_list_t *children = n00b_filter_ir_child_list_new();
    for (size_t i = 0; i < len; i++) {
        auto child_r = rocs_service_filter_ir_json(n00b_list_get(*items, i));
        if (n00b_result_is_err(child_r)) {
            return child_r;
        }
        auto append_r = n00b_filter_ir_child_list_append(
            children,
            n00b_result_get(child_r));
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_filter_ir_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
    }

    n00b_filter_ir_t *node = is_or ? n00b_filter_ir_or(children)
                                   : n00b_filter_ir_and(children);
    if (node == nullptr) {
        return n00b_result_err(n00b_filter_ir_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return n00b_result_ok(n00b_filter_ir_t *, node);
}

static n00b_result_t(n00b_filter_ir_t *)
rocs_service_filter_ir_json(n00b_json_node_t *filter)
{
    if (filter == nullptr || !n00b_json_is_object(filter)) {
        return n00b_result_err(n00b_filter_ir_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto leaf_r = rocs_service_filter_leaf_json(filter);
    if (n00b_result_is_ok(leaf_r)) {
        auto ir_r = n00b_filter_to_ir(n00b_result_get(leaf_r));
        if (n00b_result_is_err(ir_r)) {
            return n00b_result_err(n00b_filter_ir_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        return ir_r;
    }
    if (n00b_result_get_err(leaf_r) != N00B_ROCS_SERVICE_ERR_STATE) {
        return n00b_result_err(n00b_filter_ir_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_json_node_t *and_node = n00b_json_object_get(filter, r"and");
    if (and_node != nullptr) {
        return rocs_service_filter_combine_json(and_node, false);
    }

    n00b_json_node_t *or_node = n00b_json_object_get(filter, r"or");
    if (or_node != nullptr) {
        return rocs_service_filter_combine_json(or_node, true);
    }

    return n00b_result_err(n00b_filter_ir_t *,
                           N00B_ROCS_SERVICE_ERR_REQUEST);
}

static n00b_result_t(n00b_filter_t *)
rocs_service_filter_from_json(n00b_json_node_t *root)
{
    auto ir_r = rocs_service_filter_ir_json(
        n00b_json_object_get(root, r"filter"));
    if (n00b_result_is_err(ir_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto filter_r = n00b_filter_from_ir(n00b_result_get(ir_r));
    if (n00b_result_is_err(filter_r)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return filter_r;
}

static n00b_result_t(uint64_t)
rocs_service_query_limit(n00b_json_node_t *root)
{
    n00b_json_node_t *limit = n00b_json_object_get(root, r"limit");
    if (limit == nullptr) {
        return n00b_result_ok(uint64_t, N00B_ROCS_SERVICE_DEFAULT_QUERY_LIMIT);
    }
    if (!n00b_json_is_int(limit) || n00b_json_as_i64(limit) < 0) {
        return n00b_result_err(uint64_t, N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_json_as_i64(limit));
}

static n00b_result_t(bool)
rocs_service_query_ranked(n00b_json_node_t *root)
{
    n00b_json_node_t *ranked = n00b_json_object_get(root, r"ranked");
    if (ranked == nullptr) {
        return n00b_result_ok(bool, false);
    }
    if (!n00b_json_is_bool(ranked)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return n00b_result_ok(bool, n00b_json_as_bool(ranked));
}

static n00b_result_t(bool)
rocs_service_query_include_records(n00b_json_node_t *root)
{
    n00b_json_node_t *include = n00b_json_object_get(root, r"include_records");
    if (include == nullptr) {
        return n00b_result_ok(bool, false);
    }
    if (!n00b_json_is_bool(include)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    return n00b_result_ok(bool, n00b_json_as_bool(include));
}

typedef struct {
    bool             has_resume;
    n00b_store_pos_t resume;
} rocs_service_resume_t;

static n00b_result_t(rocs_service_resume_t)
rocs_service_query_resume(n00b_json_node_t *root)
{
    rocs_service_resume_t out = {};
    n00b_json_node_t     *resume = n00b_json_object_get(root, r"resume");
    if (resume == nullptr) {
        return n00b_result_ok(rocs_service_resume_t, out);
    }
    if (!n00b_json_is_string(resume)) {
        return n00b_result_err(rocs_service_resume_t,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_string_t *token = n00b_json_as_string(resume);
    if (rocs_service_runtime_string_empty(token)) {
        return n00b_result_err(rocs_service_resume_t,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    auto pos_r = n00b_store_pos_decode(token);
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(rocs_service_resume_t,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    out.has_resume = true;
    out.resume     = n00b_result_get(pos_r);
    return n00b_result_ok(rocs_service_resume_t, out);
}

static bool
rocs_service_append_query_hit(n00b_buffer_t      *buf,
                              n00b_query_hit_t   *hit,
                              bool                include_records,
                              n00b_allocator_t   *allocator,
                              n00b_store_pos_t   *pos_out)
{
    auto pos_r = n00b_query_hit_pos(hit);
    auto score_r = n00b_query_hit_score(hit);
    if (n00b_result_is_err(pos_r) || n00b_result_is_err(score_r)) {
        return false;
    }
    n00b_store_pos_t pos   = n00b_result_get(pos_r);
    double           score = n00b_result_get(score_r);
    if (pos_out != nullptr) {
        *pos_out = pos;
    }

    rocs_service_append(buf, r"{\"generation\":");
    rocs_service_append_u64(buf, pos.generation);
    rocs_service_append(buf, r",\"shard_id\":");
    rocs_service_append_u64(buf, pos.shard_id);
    rocs_service_append(buf, r",\"ordinal\":");
    rocs_service_append_u64(buf, pos.ordinal);
    rocs_service_append(buf, r",\"score\":");
    rocs_service_append_f64(buf, score);
    if (include_records) {
        // Sealed records come back as their stored compact JSON bytes, with
        // no parse, node graph, or re-encode.
        auto json_r = n00b_query_hit_json_string(hit, .allocator = allocator);
        if (n00b_result_is_err(json_r)) {
            return false;
        }
        rocs_service_append(buf, r",\"record\":");
        rocs_service_append(buf, n00b_result_get(json_r));
    }
    rocs_service_append(buf, r"}");
    return true;
}

static bool
rocs_service_query_expired(void *ctx)
{
    if (ctx == nullptr) {
        return false;
    }
    return base_monotonic_ns() >= *(uint64_t *)ctx;
}

#ifdef N00B_DEBUG
// Set by a test before it sends the request and cleared after the response.
static bool (*rocs_service_serialize_cancel_cb)(void *) = nullptr;
static void  *rocs_service_serialize_cancel_ctx        = nullptr;

void
n00b_rocs_service_serialize_cancel_for_test(bool (*cancel_cb)(void *),
                                            void  *cancel_ctx)
{
    rocs_service_serialize_cancel_cb  = cancel_cb;
    rocs_service_serialize_cancel_ctx = cancel_ctx;
}
#endif

static bool
rocs_service_serialize_expired(uint64_t *deadline_ns)
{
#ifdef N00B_DEBUG
    if (rocs_service_serialize_cancel_cb != nullptr
        && rocs_service_serialize_cancel_cb(
            rocs_service_serialize_cancel_ctx)) {
        return true;
    }
#endif
    return rocs_service_query_expired(deadline_ns);
}

// Serializes a ranked result. Each hit may copy and encode a whole record
// under store_mutex, so the query budget is checked before every one.
static n00b_result_t(n00b_buffer_t *)
rocs_service_query_response(n00b_query_result_t   *result,
                            n00b_query_hit_list_t *records,
                            bool                   include_records,
                            uint64_t              *deadline_ns,
                            n00b_allocator_t      *allocator)
{
    n00b_buffer_t *buf   = n00b_buffer_new(0, .allocator = allocator);
    uint64_t       count = n00b_query_count(result);

    rocs_service_append(buf, r"{\"ok\":true,\"count\":");
    rocs_service_append_u64(buf, count);
    rocs_service_append(buf, r",\"hits\":[");

    uint64_t len = (uint64_t)n00b_list_len(*records);
    for (uint64_t i = 0; i < len; i++) {
        if (rocs_service_serialize_expired(deadline_ns)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ROCS_SERVICE_ERR_TIMEOUT);
        }
        n00b_query_hit_t *hit = n00b_list_get(*records, (size_t)i);
        if (i != 0) {
            rocs_service_append(buf, r",");
        }
        if (!rocs_service_append_query_hit(buf,
                                           hit,
                                           include_records,
                                           allocator,
                                           nullptr)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ROCS_SERVICE_ERR_QUERY);
        }
    }

    rocs_service_append(buf, r"]}");
    return n00b_result_ok(n00b_buffer_t *, buf);
}

static n00b_result_t(n00b_buffer_t *)
rocs_service_query_page_response(n00b_store_t     *store,
                                 n00b_filter_t    *filter,
                                 uint64_t          limit,
                                 rocs_service_resume_t resume,
                                 bool              include_records,
                                 uint64_t         *deadline_ns,
                                 n00b_allocator_t *allocator)
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);

    uint64_t         view_limit = limit + 1;
    n00b_store_pos_t *resume_ptr =
        resume.has_resume ? &resume.resume : nullptr;
    auto view_r = n00b_query_view(store,
                                  filter,
                                  .resume = resume_ptr,
                                  .limit = view_limit,
                                  .allocator = allocator);
    if (n00b_result_is_err(view_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }
    n00b_query_view_t *view = n00b_result_get(view_r);

    /* The cancel hook has to be threaded HERE too, not only on the ranked
     * path: this is the DEFAULT branch (a body without "ranked": true), it
     * holds store_mutex for its whole scan, and building the cursor with
     * .allocator alone leaves every poll site inside the boundary scan a
     * no-op. Same defect the ranked path had, and the same blast radius --
     * an unbounded query here blocks every other query, both ingest
     * handlers, /v1/flush and /v1/status. */
    auto cursor_r = n00b_query_cursor(view,
                                      .cancel_cb  = rocs_service_query_expired,
                                      .cancel_ctx = deadline_ns,
                                      .allocator  = allocator);
    if (n00b_result_is_err(cursor_r)) {
        (void)n00b_query_view_close(view);
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ROCS_SERVICE_ERR_QUERY);
    }
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    rocs_service_append(buf, r"{\"ok\":true,\"hits\":[");
    uint64_t         emitted  = 0;
    bool             more     = false;
    bool             has_last = false;
    n00b_store_pos_t last     = {};

    while (emitted < limit) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            /* Keep a budget expiry distinct from a query fault all the way
             * out to the handler: collapsing both into _QUERY is what makes a
             * 30s timeout indistinguishable from a corrupt shard. */
            bool timed_out = n00b_result_get_err(next_r)
                             == N00B_QUERY_ERR_CANCELED;
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            return n00b_result_err(n00b_buffer_t *,
                                   timed_out
                                       ? N00B_ROCS_SERVICE_ERR_TIMEOUT
                                       : N00B_ROCS_SERVICE_ERR_QUERY);
        }
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }

        if (emitted != 0) {
            rocs_service_append(buf, r",");
        }
        n00b_store_pos_t pos = {};
        if (!rocs_service_append_query_hit(buf,
                                           n00b_option_get(hit_opt),
                                           include_records,
                                           allocator,
                                           &pos)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ROCS_SERVICE_ERR_QUERY);
        }
        last     = pos;
        has_last = true;
        emitted++;
    }

    if (emitted == limit) {
        auto probe_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(probe_r)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ROCS_SERVICE_ERR_QUERY);
        }
        more = n00b_option_is_set(n00b_result_get(probe_r));
    }

    auto cursor_close_r = n00b_query_cursor_close(cursor);
    auto view_close_r   = n00b_query_view_close(view);
    if (n00b_result_is_err(cursor_close_r)
        || n00b_result_is_err(view_close_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_ROCS_SERVICE_ERR_QUERY);
    }

    n00b_string_t *next_resume = r"";
    if (has_last) {
        auto token_r = n00b_store_pos_encode(last, .allocator = allocator);
        if (n00b_result_is_err(token_r)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_ROCS_SERVICE_ERR_QUERY);
        }
        next_resume = n00b_result_get(token_r);
    }

    rocs_service_append(buf, r"],\"count\":");
    rocs_service_append_u64(buf, emitted);
    rocs_service_append(buf, r",\"more\":");
    rocs_service_append(buf, more ? r"true" : r"false");
    rocs_service_append(buf, r",\"next_resume\":\"");
    rocs_service_append(buf, next_resume);
    rocs_service_append(buf, r"\"}");
    return n00b_result_ok(n00b_buffer_t *, buf);
}

static bool
rocs_service_config_is_wax(n00b_store_config_t *config)
{
    auto schema_source_r = n00b_store_config_get_schema_source(config);
    if (n00b_result_is_err(schema_source_r)) {
        return false;
    }
    n00b_option_t(n00b_string_t *) schema_source_opt =
        n00b_result_get(schema_source_r);
    return n00b_option_is_set(schema_source_opt)
        && n00b_unicode_str_eq(n00b_option_get(schema_source_opt),
                               N00B_ROCS_WAX_NORMALIZED_SCHEMA);
}

static n00b_result_t(n00b_store_t *)
rocs_service_open_store(n00b_store_schema_t  *schema,
                        n00b_store_config_t  *store_config,
                        n00b_allocator_t     *allocator)
{
    if (rocs_service_config_is_wax(store_config)) {
        auto partition_r =
            n00b_rocs_wax_partition_policy_new(.allocator = allocator);
        auto seal_r = n00b_rocs_wax_seal_policy_new(.allocator = allocator);
        if (n00b_result_is_err(partition_r) || n00b_result_is_err(seal_r)) {
            return n00b_result_err(n00b_store_t *,
                                   N00B_STORE_ERR_POLICY);
        }
        return n00b_store_open_config(schema,
                                      store_config,
                                      .partition_policy =
                                          n00b_result_get(partition_r),
                                      .seal_policy = n00b_result_get(seal_r),
                                      .allocator   = allocator);
    }

    return n00b_store_open_config(schema,
                                  store_config,
                                  .allocator = allocator);
}

static void
rocs_service_finish_query(n00b_rocs_service_t *service,
                          uint64_t             start_ns,
                          bool                 failed)
{
    uint64_t elapsed = base_monotonic_ns() - start_ns;
    n00b_atomic_add(&service->query_latency_ns, elapsed);
    if (failed) {
        n00b_atomic_add(&service->query_errors, 1);
    }
}

static void
rocs_service_finish_ingest(n00b_rocs_service_t *service,
                           uint64_t             start_ns,
                           bool                 failed)
{
    uint64_t elapsed = base_monotonic_ns() - start_ns;
    n00b_atomic_add(&service->ingest_latency_ns, elapsed);
    if (failed) {
        n00b_atomic_add(&service->ingest_errors, 1);
    }
}

// Upper bound on how long one query may hold store_mutex.
//
// Deliberately generous: a legitimate ranked query over a large store can take
// seconds, and this must not turn a slow-but-progressing query into a spurious
// error. It exists to make an UNBOUNDED one representable -- the same reasoning
// as ROCS_SEAL_DRAIN_DEADLINE_MS in store.c. A consumer that cannot be told
// "this query did not finish" has no option but to hang, and with a global
// mutex it takes the whole service down with it (n00b#255).
#define ROCS_SERVICE_QUERY_BUDGET_NS (UINT64_C(30) * UINT64_C(1000000000))

// Polled by the cursor during boundary scans. ctx is a borrowed pointer to the
// caller's monotonic deadline; see the comment at the call site for why a stack
// address is safe here.

static void
rocs_service_query_handler(n00b_http_request_t        *req,
                           n00b_http_response_writer_t *resp,
                           void                       *user_data)
{
    n00b_rocs_service_t   *service = user_data;
    rocs_service_scratch_t scratch;
    n00b_allocator_t      *allocator =
        rocs_service_scratch_begin(&scratch, true);
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_reply_error(&scratch, resp, 503, r"service_closed");
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->query_requests, 1);

    n00b_buffer_t *body = n00b_http_request_body(req);
    if (body == nullptr || n00b_buffer_len(body) == 0) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             n00b_buffer_len(body),
                                             nullptr,
                                             .allocator = allocator);
    if (root == nullptr || !n00b_json_is_object(root)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    auto filter_r = rocs_service_filter_from_json(root);
    auto limit_r  = rocs_service_query_limit(root);
    auto ranked_r = rocs_service_query_ranked(root);
    auto include_records_r = rocs_service_query_include_records(root);
    auto resume_r = rocs_service_query_resume(root);
    if (n00b_result_is_err(filter_r) || n00b_result_is_err(limit_r)
        || n00b_result_is_err(ranked_r)
        || n00b_result_is_err(include_records_r)
        || n00b_result_is_err(resume_r)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    uint64_t limit = n00b_result_get(limit_r);
    if (limit > N00B_ROCS_SERVICE_MAX_QUERY_LIMIT) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"limit_too_large");
        return;
    }

    bool ranked = n00b_result_get(ranked_r);
    rocs_service_resume_t resume = n00b_result_get(resume_r);
    if (ranked && resume.has_resume) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }
    if (limit == 0) {
        n00b_buffer_t *empty = n00b_buffer_new(0, .allocator = allocator);
        rocs_service_append(
            empty,
            ranked ? r"{\"ok\":true,\"count\":0,\"hits\":[]}"
                   : r"{\"ok\":true,\"hits\":[],\"count\":0,\"more\":false,\"next_resume\":\"\"}");
        rocs_service_finish_query(service, start_ns, false);
        rocs_service_reply_json(&scratch, resp, 200, empty);
        return;
    }

    if (!ranked) {
        n00b_mutex_lock(&service->store_mutex);
        /* Started AFTER the lock: the budget is a bound on how long one query
         * may HOLD store_mutex, not on how long it waited for it. Timing it
         * from before the acquire means a query that queued behind another
         * gets whatever is left, and under contention -- the only condition
         * this exists for -- it can fail having scanned nothing. */
        uint64_t page_deadline_ns = base_monotonic_ns()
                                    + ROCS_SERVICE_QUERY_BUDGET_NS;
        auto page_r =
            rocs_service_query_page_response(service->store,
                                             n00b_result_get(filter_r),
                                             limit,
                                             resume,
                                             n00b_result_get(include_records_r),
                                             &page_deadline_ns,
                                             allocator);
        if (n00b_result_is_err(page_r)) {
            n00b_mutex_unlock(&service->store_mutex);
            n00b_rocs_service_err_t page_err = n00b_result_get_err(page_r);
            bool bad_request = page_err == N00B_ROCS_SERVICE_ERR_REQUEST;
            bool timed_out   = page_err == N00B_ROCS_SERVICE_ERR_TIMEOUT;
            rocs_service_finish_query(service, start_ns, true);
            rocs_service_reply_error(&scratch,
                                     resp,
                                     bad_request  ? 400
                                     : timed_out  ? 504
                                                  : 500,
                                     bad_request  ? r"bad_request"
                                     : timed_out  ? r"query_timeout"
                                                  : r"query_error");
            return;
        }

        rocs_service_trim_residency(service);
        n00b_mutex_unlock(&service->store_mutex);
        rocs_service_finish_query(service, start_ns, false);
        rocs_service_reply_json(&scratch, resp, 200, n00b_result_get(page_r));
        return;
    }

    // Bound the query (n00b#255). This handler holds store_mutex across the
    // WHOLE of n00b_query_run -- scan, materialization, serialization and the
    // residency trim -- so an unbounded query does not merely run long, it
    // blocks every other query, both ingest handlers and /v1/status. The
    // measured field signature was exactly that: GET /v1/query 200 in 0.21s
    // (never reaches the locked section), POST /v1/query hanging, /v1/sessions
    // fast (takes the mutex zero times).
    //
    // The deadline lives on this stack frame and is only read by the cursor
    // while n00b_query_run is on the stack below us, so the borrow is valid
    // for exactly as long as it is used. It is NOT captured anywhere that
    // outlives the call.
    /* Assigned AFTER the lock is taken (below), for the same reason as the
     * unranked branch: the budget bounds mutex-HOLD time, not lock-wait.
     * UINT64_MAX until then, so a poll that somehow ran during setup cannot
     * see an already-expired deadline. The query borrows the address, so
     * assigning the value later is safe -- the slot is what it captured. */
    uint64_t query_deadline_ns = UINT64_MAX;

    auto query_r = n00b_query_new(n00b_result_get(filter_r),
                                  .limit      = limit,
                                  .ranked     = ranked,
                                  .cancel_cb  = rocs_service_query_expired,
                                  .cancel_ctx = &query_deadline_ns);
    if (n00b_result_is_err(query_r)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    n00b_mutex_lock(&service->store_mutex);
    query_deadline_ns = base_monotonic_ns() + ROCS_SERVICE_QUERY_BUDGET_NS;
    // Passing the request pool also routes the map view handles each hit
    // derives there; without it they default to the store's allocator.
    auto result_r = n00b_query_run(service->store,
                                   n00b_result_get(query_r),
                                   .allocator = allocator);
    if (n00b_result_is_err(result_r)) {
        bool timed_out = n00b_result_get_err(result_r)
                         == N00B_QUERY_ERR_CANCELED;
        n00b_mutex_unlock(&service->store_mutex);
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch,
                                 resp,
                                 timed_out ? 504 : 500,
                                 timed_out ? r"query_timeout"
                                           : r"query_error");
        return;
    }

    n00b_query_result_t *result = n00b_result_get(result_r);
    auto records_r = n00b_query_records(result, .allocator = allocator);
    if (n00b_result_is_err(records_r)) {
        (void)n00b_query_result_close(result);
        n00b_mutex_unlock(&service->store_mutex);
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 500, r"query_error");
        return;
    }

    auto out_r =
        rocs_service_query_response(result,
                                    n00b_result_get(records_r),
                                    n00b_result_get(include_records_r),
                                    &query_deadline_ns,
                                    // Per-request scratch, not the service
                                    // allocator: that is this PR's point. The
                                    // deadline arg is n00b#472's and is kept.
                                    allocator);
    (void)n00b_query_result_close(result);
    if (n00b_result_is_err(out_r)) {
        bool timed_out = n00b_result_get_err(out_r)
                         == N00B_ROCS_SERVICE_ERR_TIMEOUT;
        n00b_mutex_unlock(&service->store_mutex);
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_reply_error(&scratch,
                                 resp,
                                 timed_out ? 504 : 500,
                                 timed_out ? r"query_timeout"
                                           : r"query_error");
        return;
    }
    rocs_service_trim_residency(service);
    n00b_mutex_unlock(&service->store_mutex);
    rocs_service_finish_query(service, start_ns, false);
    rocs_service_reply_json(&scratch, resp, 200, n00b_result_get(out_r));
}

static void
rocs_service_records_handler(n00b_http_request_t        *req,
                             n00b_http_response_writer_t *resp,
                             void                       *user_data)
{
    n00b_rocs_service_t   *service = user_data;
    rocs_service_scratch_t scratch;
    (void)rocs_service_scratch_begin(&scratch, false);
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_reply_error(&scratch, resp, 503, r"service_closed");
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->ingest_requests, 1);

    if (service->read_only) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 403, r"read_only");
        return;
    }

    n00b_buffer_t *body = n00b_http_request_body(req);
    if (body == nullptr || n00b_buffer_len(body) == 0) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    n00b_mutex_lock(&service->store_mutex);
    auto ingest_r = n00b_store_ingest_buf(service->store, body);
    n00b_mutex_unlock(&service->store_mutex);
    if (n00b_result_is_err(ingest_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(ingest_r));
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }
    n00b_buffer_t *out = n00b_buffer_new(0,
                                         .allocator = scratch.allocator);
    rocs_service_append(out, r"{\"ok\":true}");
    rocs_service_finish_ingest(service, start_ns, false);
    rocs_service_reply_json(&scratch, resp, 200, out);
}

static void
rocs_service_records_batch_handler(n00b_http_request_t        *req,
                                   n00b_http_response_writer_t *resp,
                                   void                       *user_data)
{
    n00b_rocs_service_t   *service = user_data;
    rocs_service_scratch_t scratch;
    n00b_allocator_t      *allocator =
        rocs_service_scratch_begin(&scratch, false);
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_reply_error(&scratch, resp, 503, r"service_closed");
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->ingest_requests, 1);

    if (service->read_only) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 403, r"read_only");
        return;
    }

    n00b_buffer_t *body = n00b_http_request_body(req);
    if (body == nullptr || n00b_buffer_len(body) == 0) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    auto sources_r = rocs_service_ndjson_sources(body, allocator);
    if (n00b_result_is_err(sources_r)) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    n00b_store_source_list_t *sources = n00b_result_get(sources_r);
    uint64_t                 count   = (uint64_t)n00b_list_len(*sources);
    if (count == 0) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    n00b_mutex_lock(&service->store_mutex);
    auto ingest_r = n00b_store_ingest_buf_batch(service->store, sources);
    n00b_mutex_unlock(&service->store_mutex);
    if (n00b_result_is_err(ingest_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(ingest_r));
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 400, r"bad_request");
        return;
    }

    uint64_t committed = n00b_result_get(ingest_r);
    if (committed != count) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 500, r"partial_ingest");
        return;
    }

    n00b_buffer_t *out = n00b_buffer_new(0, .allocator = allocator);
    rocs_service_append(out, r"{\"ok\":true,\"ingested\":");
    rocs_service_append_u64(out, committed);
    rocs_service_append(out, r"}");
    rocs_service_finish_ingest(service, start_ns, false);
    rocs_service_reply_json(&scratch, resp, 200, out);
}

static void
rocs_service_flush_handler(n00b_http_request_t        *req,
                           n00b_http_response_writer_t *resp,
                           void                       *user_data)
{
    (void)req;
    n00b_rocs_service_t   *service = user_data;
    rocs_service_scratch_t scratch;
    (void)rocs_service_scratch_begin(&scratch, false);
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_reply_error(&scratch, resp, 503, r"service_closed");
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->ingest_requests, 1);

    if (service->read_only) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 403, r"read_only");
        return;
    }

    n00b_mutex_lock(&service->store_mutex);
    auto flush_r = n00b_store_flush(service->store);
    n00b_mutex_unlock(&service->store_mutex);
    if (n00b_result_is_err(flush_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(flush_r));
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_reply_error(&scratch, resp, 500, r"store_error");
        return;
    }

    n00b_buffer_t *out = n00b_buffer_new(0,
                                         .allocator = scratch.allocator);
    rocs_service_append(out, r"{\"ok\":true}");
    rocs_service_finish_ingest(service, start_ns, false);
    rocs_service_reply_json(&scratch, resp, 200, out);
}

static n00b_result_t(bool)
rocs_service_register_routes(n00b_rocs_service_t *service)
{
    auto startup_r = n00b_http_service_route(service->http,
                                             r"GET",
                                             r"/healthz/startup",
                                             rocs_service_startup_handler,
                                             service);
    if (n00b_result_is_err(startup_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto live_r = n00b_http_service_route(service->http,
                                          r"GET",
                                          r"/healthz/live",
                                          rocs_service_liveness_handler,
                                          service);
    if (n00b_result_is_err(live_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto ready_r = n00b_http_service_route(service->http,
                                           r"GET",
                                           r"/healthz/ready",
                                           rocs_service_readiness_handler,
                                           service);
    if (n00b_result_is_err(ready_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto metrics_r = n00b_http_service_route(service->http,
                                             r"GET",
                                             r"/metrics",
                                             rocs_service_metrics_handler,
                                             service);
    if (n00b_result_is_err(metrics_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto query_r = n00b_http_service_route(service->http,
                                           r"POST",
                                           r"/v1/query",
                                           rocs_service_query_handler,
                                           service);
    if (n00b_result_is_err(query_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto records_r = n00b_http_service_route(service->http,
                                             r"POST",
                                             r"/v1/records",
                                             rocs_service_records_handler,
                                             service);
    if (n00b_result_is_err(records_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto records_batch_r =
        n00b_http_service_route(service->http,
                                r"POST",
                                r"/v1/records/batch",
                                rocs_service_records_batch_handler,
                                service);
    if (n00b_result_is_err(records_batch_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    auto flush_r = n00b_http_service_route(service->http,
                                           r"POST",
                                           r"/v1/flush",
                                           rocs_service_flush_handler,
                                           service);
    if (n00b_result_is_err(flush_r)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_HTTP);
    }
    return n00b_result_ok(bool, true);
}

n00b_string_t *
n00b_rocs_service_err_str(n00b_err_t err)
{
    switch ((n00b_rocs_service_err_t)err) {
    case N00B_ROCS_SERVICE_OK:            return r"OK";
    case N00B_ROCS_SERVICE_ERR_ARG:       return r"ARG";
    case N00B_ROCS_SERVICE_ERR_CONFIG:    return r"CONFIG";
    case N00B_ROCS_SERVICE_ERR_STORE:     return r"STORE";
    case N00B_ROCS_SERVICE_ERR_HTTP:      return r"HTTP";
    case N00B_ROCS_SERVICE_ERR_STATE:     return r"STATE";
    case N00B_ROCS_SERVICE_ERR_CLOSED:    return r"CLOSED";
    case N00B_ROCS_SERVICE_ERR_READ_ONLY: return r"READ_ONLY";
    case N00B_ROCS_SERVICE_ERR_REQUEST:   return r"REQUEST";
    case N00B_ROCS_SERVICE_ERR_QUERY:     return r"QUERY";
    case N00B_ROCS_SERVICE_ERR_TIMEOUT:   return r"TIMEOUT";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_rocs_service_t *)
n00b_rocs_service_start(n00b_rocs_service_config_t *config,
                        n00b_store_schema_t        *schema) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (config == nullptr || schema == nullptr) {
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_ARG);
    }

    auto http_addr_r = n00b_rocs_service_config_get_http_addr(config);
    auto read_only_r = n00b_rocs_service_config_get_read_only(config);
    auto store_cfg_r = n00b_rocs_service_config_get_store_config(config);
    if (n00b_result_is_err(http_addr_r) || n00b_result_is_err(read_only_r)
        || n00b_result_is_err(store_cfg_r)) {
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_CONFIG);
    }

    n00b_rocs_service_t *service = n00b_alloc_with_opts(
        n00b_rocs_service_t,
        &(n00b_alloc_opts_t){
            .allocator = rocs_service_control_allocator(allocator),
        });
    n00b_allocator_t *runtime_allocator =
        rocs_service_runtime_allocator(service, allocator);
    service->allocator = runtime_allocator;

    n00b_option_t(n00b_string_t *) http_addr_opt =
        n00b_result_get(http_addr_r);
    n00b_string_t *http_addr = n00b_option_is_set(http_addr_opt)
                                   ? n00b_option_get(http_addr_opt)
                                   : r"127.0.0.1:8080";
    auto bind_r = rocs_service_parse_bind(http_addr, runtime_allocator);
    if (n00b_result_is_err(bind_r)) {
        rocs_service_destroy_owned_allocator(service);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_CONFIG);
    }
    rocs_service_bind_t bind = n00b_result_get(bind_r);

    auto store_r = rocs_service_open_store(schema,
                                           n00b_result_get(store_cfg_r),
                                           runtime_allocator);
    if (n00b_result_is_err(store_r)) {
        rocs_service_destroy_owned_allocator(service);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_STORE);
    }

    service->config    = config;
    service->store     = n00b_result_get(store_r);
    service->read_only = n00b_result_get(read_only_r);
    n00b_atomic_store(&service->stopped, false);
    n00b_atomic_store(&service->startup_ready, false);
    n00b_atomic_store(&service->draining, false);
    n00b_atomic_store(&service->dependency_ready, true);
    n00b_mutex_init(&service->store_mutex);

    if (!rocs_service_start_workers(service)) {
        (void)n00b_store_close(service->store);
        n00b_atomic_store(&service->stopped, true);
        rocs_service_destroy_owned_allocator(service);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_HTTP);
    }

    service->http = n00b_http_service_new(.bind_host = bind.host,
                                          .bind_port = bind.port,
                                          .worker_service =
                                              service->worker_service,
                                          .allocator = runtime_allocator);
    auto routes_r = rocs_service_register_routes(service);
    if (n00b_result_is_err(routes_r)) {
        (void)n00b_store_close(service->store);
        rocs_service_destroy_workers(service);
        n00b_atomic_store(&service->stopped, true);
        rocs_service_destroy_owned_allocator(service);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_HTTP);
    }

    auto start_r = n00b_http_service_start(service->http);
    if (n00b_result_is_err(start_r)) {
        (void)n00b_store_close(service->store);
        rocs_service_destroy_workers(service);
        n00b_atomic_store(&service->stopped, true);
        rocs_service_destroy_owned_allocator(service);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_HTTP);
    }

    service->bound_port = n00b_http_service_port(service->http);
    n00b_atomic_store(&service->startup_ready, true);
    return n00b_result_ok(n00b_rocs_service_t *, service);
}

n00b_result_t(bool)
n00b_rocs_service_stop(n00b_rocs_service_t *service)
{
    if (service == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_ARG);
    }
    if (n00b_atomic_load(&service->stopped)) {
        return n00b_result_ok(bool, false);
    }

    n00b_atomic_store(&service->draining, true);
    n00b_atomic_store(&service->startup_ready, false);
    n00b_http_service_stop(service->http);
    rocs_service_destroy_workers(service);
    n00b_atomic_store(&service->stopped, true);

    if (service->store != nullptr) {
        auto close_r = n00b_store_close(service->store);
        if (n00b_result_is_err(close_r)) {
            return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_STORE);
        }
    }
    rocs_service_destroy_owned_allocator(service);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_rocs_service_set_draining(n00b_rocs_service_t *service, bool draining)
{
    if (service == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_ARG);
    }
    if (n00b_atomic_load(&service->stopped)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_CLOSED);
    }
    n00b_atomic_store(&service->draining, draining);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_rocs_service_set_dependency_ready(n00b_rocs_service_t *service,
                                       bool                 ready)
{
    if (service == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_ARG);
    }
    if (n00b_atomic_load(&service->stopped)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_CLOSED);
    }
    bool was_ready = n00b_atomic_load(&service->dependency_ready);
    n00b_atomic_store(&service->dependency_ready, ready);
    if (was_ready && !ready) {
        n00b_atomic_add(&service->vfs_s3_errors, 1);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_rocs_service_set_live_queue_pressure(n00b_rocs_service_t *service,
                                          uint64_t             pressure)
{
    if (service == nullptr) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_ARG);
    }
    if (n00b_atomic_load(&service->stopped)) {
        return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_CLOSED);
    }
    n00b_atomic_store(&service->live_queue_pressure, pressure);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint16_t)
n00b_rocs_service_bound_port(n00b_rocs_service_t *service)
{
    if (service == nullptr) {
        return n00b_result_err(uint16_t, N00B_ROCS_SERVICE_ERR_ARG);
    }
    if (n00b_atomic_load(&service->stopped)) {
        return n00b_result_err(uint16_t, N00B_ROCS_SERVICE_ERR_CLOSED);
    }
    return n00b_result_ok(uint16_t, service->bound_port);
}
