#include "rocs/service.h"

#include <stdint.h>

#include "core/atomic.h"
#include "core/buffer.h"
#include "core/platform.h"
#include "net/http/http_service.h"
#include "parsers/json.h"
#include "rocs/filter.h"
#include "rocs/query.h"
#include "text/strings/fmt_numbers.h"
#include "text/strings/string_ops.h"

struct n00b_rocs_service_t {
    n00b_rocs_service_config_t *config;
    n00b_store_t               *store;
    n00b_http_service_t        *http;
    bool                        read_only;
    _Atomic(bool)               stopped;
    _Atomic(bool)               startup_ready;
    _Atomic(bool)               draining;
    _Atomic(bool)               dependency_ready;
    uint16_t                    bound_port;
    n00b_allocator_t           *allocator;
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

typedef struct {
    n00b_string_t *host;
    uint16_t       port;
} rocs_service_bind_t;

static bool
rocs_service_runtime_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static void
rocs_service_append(n00b_buffer_t *buf, n00b_string_t *s)
{
    if (buf == nullptr || s == nullptr) {
        return;
    }
    n00b_buffer_t *part = n00b_buffer_from_bytes(s->data,
                                                 (int64_t)s->u8_bytes,
                                                 .allocator =
                                                     buf->allocator);
    n00b_buffer_concat(buf, part);
}

static void
rocs_service_append_u64(n00b_buffer_t *buf, uint64_t value)
{
    if (buf == nullptr) {
        return;
    }
    rocs_service_append(buf,
                        n00b_fmt_uint(value, .allocator = buf->allocator));
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

static void
rocs_service_append_bool(n00b_buffer_t *buf, bool value)
{
    rocs_service_append(buf, value ? r"true" : r"false");
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
rocs_service_write_json(n00b_http_response_writer_t *resp,
                        uint16_t                    status,
                        n00b_buffer_t              *body)
{
    n00b_http_response_writer_status(resp, status);
    n00b_http_response_writer_header(resp,
                                     r"content-type",
                                     r"application/json");
    n00b_http_response_writer_body(resp, body);
}

static void
rocs_service_write_error(n00b_http_response_writer_t *resp,
                         uint16_t                    status,
                         n00b_string_t              *code,
                         n00b_allocator_t           *allocator)
{
    rocs_service_write_json(resp,
                            status,
                            rocs_service_json_error(code, allocator));
}

static void
rocs_service_write_text(n00b_http_response_writer_t *resp,
                        uint16_t                    status,
                        n00b_buffer_t              *body,
                        n00b_string_t              *content_type)
{
    n00b_http_response_writer_status(resp, status);
    n00b_http_response_writer_header(resp, r"content-type", content_type);
    n00b_http_response_writer_body(resp, body);
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
                         bool                 ok)
{
    n00b_allocator_t *allocator = service == nullptr ? nullptr
                                                     : service->allocator;
    n00b_buffer_t    *buf       = n00b_buffer_new(0, .allocator = allocator);
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
    rocs_service_append(buf, r"}");
    return buf;
}

static void
rocs_service_startup_handler(n00b_http_request_t         *req,
                             n00b_http_response_writer_t *resp,
                             void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool                 ok      = rocs_service_is_started(service);
    rocs_service_write_json(resp,
                            ok ? 200 : 503,
                            rocs_service_health_body(service,
                                                     ok ? r"started"
                                                        : r"starting",
                                                     ok));
}

static void
rocs_service_liveness_handler(n00b_http_request_t         *req,
                              n00b_http_response_writer_t *resp,
                              void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool ok = service != nullptr && !n00b_atomic_load(&service->stopped);
    rocs_service_write_json(resp,
                            ok ? 200 : 503,
                            rocs_service_health_body(service,
                                                     ok ? r"alive" : r"closed",
                                                     ok));
}

static void
rocs_service_readiness_handler(n00b_http_request_t         *req,
                               n00b_http_response_writer_t *resp,
                               void                        *user_data)
{
    n00b_rocs_service_t *service = user_data;
    bool                 ok      = rocs_service_is_ready(service);
    rocs_service_write_json(resp,
                            ok ? 200 : 503,
                            rocs_service_health_body(service,
                                                     ok ? r"ready"
                                                        : r"not_ready",
                                                     ok));
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
rocs_service_metrics_body(n00b_rocs_service_t *service)
{
    n00b_allocator_t *allocator = service == nullptr ? nullptr
                                                     : service->allocator;
    n00b_buffer_t    *buf       = n00b_buffer_new(0, .allocator = allocator);
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
    n00b_rocs_service_t *service = user_data;
    rocs_service_write_text(resp,
                            200,
                            rocs_service_metrics_body(service),
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
rocs_service_filter_from_json(n00b_json_node_t *root)
{
    n00b_json_node_t *filter = n00b_json_object_get(root, r"filter");
    if (filter == nullptr || !n00b_json_is_object(filter)) {
        return n00b_result_err(n00b_filter_t *,
                               N00B_ROCS_SERVICE_ERR_REQUEST);
    }

    n00b_json_node_t *exists = n00b_json_object_get(filter, r"exists");
    if (exists != nullptr) {
        n00b_string_t *field_name = n00b_json_as_string(exists);
        if (rocs_service_runtime_string_empty(field_name)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        auto field_r = n00b_filter_field(field_name);
        if (n00b_result_is_err(field_r)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        auto filter_r = n00b_filter_exists(n00b_result_get(field_r));
        if (n00b_result_is_err(filter_r)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        return filter_r;
    }

    n00b_json_node_t *contains = n00b_json_object_get(filter, r"contains");
    if (contains != nullptr && n00b_json_is_object(contains)) {
        n00b_string_t *field_name =
            n00b_json_as_string(n00b_json_object_get(contains, r"field"));
        n00b_string_t *term =
            n00b_json_as_string(n00b_json_object_get(contains, r"term"));
        if (rocs_service_runtime_string_empty(field_name)
            || rocs_service_runtime_string_empty(term)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        auto field_r = n00b_filter_field(field_name);
        if (n00b_result_is_err(field_r)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        auto filter_r = n00b_filter_contains(n00b_result_get(field_r), term);
        if (n00b_result_is_err(filter_r)) {
            return n00b_result_err(n00b_filter_t *,
                                   N00B_ROCS_SERVICE_ERR_REQUEST);
        }
        return filter_r;
    }

    return n00b_result_err(n00b_filter_t *,
                           N00B_ROCS_SERVICE_ERR_REQUEST);
}

static n00b_result_t(uint64_t)
rocs_service_query_limit(n00b_json_node_t *root)
{
    n00b_json_node_t *limit = n00b_json_object_get(root, r"limit");
    if (limit == nullptr) {
        return n00b_result_ok(uint64_t, 100);
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

static n00b_buffer_t *
rocs_service_query_response(n00b_query_result_t *result,
                            n00b_query_hit_list_t *records,
                            n00b_allocator_t      *allocator)
{
    n00b_buffer_t *buf   = n00b_buffer_new(0, .allocator = allocator);
    uint64_t       count = n00b_query_count(result);

    rocs_service_append(buf, r"{\"ok\":true,\"count\":");
    rocs_service_append_u64(buf, count);
    rocs_service_append(buf, r",\"hits\":[");

    uint64_t len = (uint64_t)n00b_list_len(*records);
    for (uint64_t i = 0; i < len; i++) {
        n00b_query_hit_t *hit = n00b_list_get(*records, (size_t)i);
        auto             pos_r = n00b_query_hit_pos(hit);
        auto             score_r = n00b_query_hit_score(hit);
        if (n00b_result_is_err(pos_r) || n00b_result_is_err(score_r)) {
            return rocs_service_json_error(r"query_error", allocator);
        }
        n00b_store_pos_t pos = n00b_result_get(pos_r);
        double           score = n00b_result_get(score_r);

        if (i != 0) {
            rocs_service_append(buf, r",");
        }
        rocs_service_append(buf, r"{\"generation\":");
        rocs_service_append_u64(buf, pos.generation);
        rocs_service_append(buf, r",\"shard_id\":");
        rocs_service_append_u64(buf, pos.shard_id);
        rocs_service_append(buf, r",\"ordinal\":");
        rocs_service_append_u64(buf, pos.ordinal);
        rocs_service_append(buf, r",\"score\":");
        rocs_service_append_f64(buf, score);
        rocs_service_append(buf, r"}");
    }

    rocs_service_append(buf, r"]}");
    return buf;
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

static void
rocs_service_query_handler(n00b_http_request_t        *req,
                           n00b_http_response_writer_t *resp,
                           void                       *user_data)
{
    n00b_rocs_service_t *service = user_data;
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_write_error(resp, 503, r"service_closed", nullptr);
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->query_requests, 1);

    n00b_buffer_t *body = n00b_http_request_body(req);
    if (body == nullptr || n00b_buffer_len(body) == 0) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }

    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             n00b_buffer_len(body),
                                             nullptr);
    if (root == nullptr || !n00b_json_is_object(root)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }

    auto filter_r = rocs_service_filter_from_json(root);
    auto limit_r  = rocs_service_query_limit(root);
    auto ranked_r = rocs_service_query_ranked(root);
    if (n00b_result_is_err(filter_r) || n00b_result_is_err(limit_r)
        || n00b_result_is_err(ranked_r)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }

    auto query_r = n00b_query_new(n00b_result_get(filter_r),
                                  .limit  = n00b_result_get(limit_r),
                                  .ranked = n00b_result_get(ranked_r));
    if (n00b_result_is_err(query_r)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }

    auto result_r = n00b_query_run(service->store, n00b_result_get(query_r));
    if (n00b_result_is_err(result_r)) {
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 500,
                                 r"query_error",
                                 service->allocator);
        return;
    }

    n00b_query_result_t *result = n00b_result_get(result_r);
    auto records_r = n00b_query_records(result);
    if (n00b_result_is_err(records_r)) {
        (void)n00b_query_result_close(result);
        rocs_service_finish_query(service, start_ns, true);
        rocs_service_write_error(resp,
                                 500,
                                 r"query_error",
                                 service->allocator);
        return;
    }

    n00b_buffer_t *out =
        rocs_service_query_response(result,
                                    n00b_result_get(records_r),
                                    service->allocator);
    (void)n00b_query_result_close(result);
    rocs_service_trim_residency(service);
    rocs_service_finish_query(service, start_ns, false);
    rocs_service_write_json(resp, 200, out);
}

static void
rocs_service_records_handler(n00b_http_request_t        *req,
                             n00b_http_response_writer_t *resp,
                             void                       *user_data)
{
    n00b_rocs_service_t *service = user_data;
    if (service == nullptr || n00b_atomic_load(&service->stopped)
        || service->store == nullptr) {
        rocs_service_write_error(resp, 503, r"service_closed", nullptr);
        return;
    }

    uint64_t start_ns = base_monotonic_ns();
    n00b_atomic_add(&service->ingest_requests, 1);

    if (service->read_only) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_write_error(resp, 403, r"read_only", service->allocator);
        return;
    }

    n00b_buffer_t *body = n00b_http_request_body(req);
    if (body == nullptr || n00b_buffer_len(body) == 0) {
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }

    auto ingest_r = n00b_store_ingest_buf(service->store, body);
    if (n00b_result_is_err(ingest_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(ingest_r));
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_write_error(resp,
                                 400,
                                 r"bad_request",
                                 service->allocator);
        return;
    }
    auto flush_r = n00b_store_flush(service->store);
    if (n00b_result_is_err(flush_r)) {
        rocs_service_record_store_error(service, n00b_result_get_err(flush_r));
        rocs_service_finish_ingest(service, start_ns, true);
        rocs_service_write_error(resp,
                                 500,
                                 r"store_error",
                                 service->allocator);
        return;
    }
    n00b_buffer_t *out = n00b_buffer_new(0,
                                         .allocator = service->allocator);
    rocs_service_append(out, r"{\"ok\":true}");
    rocs_service_finish_ingest(service, start_ns, false);
    rocs_service_write_json(resp, 200, out);
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

    n00b_option_t(n00b_string_t *) http_addr_opt =
        n00b_result_get(http_addr_r);
    n00b_string_t *http_addr = n00b_option_is_set(http_addr_opt)
                                   ? n00b_option_get(http_addr_opt)
                                   : r"127.0.0.1:8080";
    auto bind_r = rocs_service_parse_bind(http_addr, allocator);
    if (n00b_result_is_err(bind_r)) {
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_CONFIG);
    }
    rocs_service_bind_t bind = n00b_result_get(bind_r);

    auto store_r = n00b_store_open_config(schema,
                                          n00b_result_get(store_cfg_r),
                                          .allocator = allocator);
    if (n00b_result_is_err(store_r)) {
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_STORE);
    }

    n00b_rocs_service_t *service = n00b_alloc_with_opts(
        n00b_rocs_service_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    service->config    = config;
    service->store     = n00b_result_get(store_r);
    service->read_only = n00b_result_get(read_only_r);
    service->allocator = allocator;
    n00b_atomic_store(&service->stopped, false);
    n00b_atomic_store(&service->startup_ready, false);
    n00b_atomic_store(&service->draining, false);
    n00b_atomic_store(&service->dependency_ready, true);

    service->http = n00b_http_service_new(.bind_host = bind.host,
                                          .bind_port = bind.port,
                                          .allocator = allocator);
    auto routes_r = rocs_service_register_routes(service);
    if (n00b_result_is_err(routes_r)) {
        (void)n00b_store_close(service->store);
        n00b_atomic_store(&service->stopped, true);
        return n00b_result_err(n00b_rocs_service_t *,
                               N00B_ROCS_SERVICE_ERR_HTTP);
    }

    auto start_r = n00b_http_service_start(service->http);
    if (n00b_result_is_err(start_r)) {
        (void)n00b_store_close(service->store);
        n00b_atomic_store(&service->stopped, true);
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
    n00b_atomic_store(&service->stopped, true);

    if (service->store != nullptr) {
        auto close_r = n00b_store_close(service->store);
        if (n00b_result_is_err(close_r)) {
            return n00b_result_err(bool, N00B_ROCS_SERVICE_ERR_STORE);
        }
    }
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
