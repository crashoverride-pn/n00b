/**
 * @file http_service.h
 * @brief Small local HTTP/1 service/router.
 *
 * This API is intentionally narrow: it is for local tools, endpoint
 * harnesses, and small service slices that need deterministic HTTP/1
 * request handling without production ingress machinery.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "conduit/service.h"

typedef struct n00b_http_service          n00b_http_service_t;
typedef struct n00b_http_request          n00b_http_request_t;
typedef struct n00b_http_response_writer  n00b_http_response_writer_t;

typedef void (*n00b_http_handler_fn)(n00b_http_request_t         *req,
                                     n00b_http_response_writer_t *resp,
                                     void                        *user_data);

typedef struct {
    n00b_string_t *name;
    n00b_string_t *location;
    bool           required;
    n00b_string_t *schema_json;
    n00b_string_t *description;
} n00b_http_param_spec_t;

typedef struct {
    n00b_string_t *content_type;
    n00b_string_t *schema_json;
    bool           required;
} n00b_http_body_spec_t;

typedef struct {
    uint16_t       status;
    n00b_string_t *description;
    n00b_string_t *content_type;
    n00b_string_t *schema_json;
} n00b_http_response_spec_t;

typedef struct {
    n00b_string_t        *method;
    n00b_string_t        *path;
    n00b_http_handler_fn  handler;
    void                 *user_data;

    n00b_string_t        *operation_id;
    n00b_string_t        *summary;
    n00b_string_t       **tags;
    size_t                tag_count;

    n00b_http_param_spec_t    *query_params;
    size_t                     query_param_count;
    n00b_http_body_spec_t      request_body;
    n00b_http_response_spec_t *responses;
    size_t                     response_count;
} n00b_http_route_spec_t;

typedef struct {
    n00b_string_t  *service_id;
    n00b_string_t  *service_name;
    n00b_string_t  *service_version;
    n00b_string_t  *api_version;
    n00b_string_t  *openapi_path;
    n00b_string_t  *health_path;
    n00b_string_t **schema_paths;
    size_t          schema_path_count;
    n00b_string_t **capabilities;
    size_t          capability_count;
} n00b_http_discovery_info_t;

typedef struct {
    n00b_string_t **items;
    size_t          count;
} n00b_http_string_list_t;

typedef struct {
    n00b_http_param_spec_t *items;
    size_t                  count;
} n00b_http_param_list_t;

typedef struct {
    n00b_http_response_spec_t *items;
    size_t                     count;
} n00b_http_response_list_t;

typedef struct {
    n00b_string_t             *method;
    n00b_string_t             *path;
    n00b_http_handler_fn       handler;
    void                      *user_data;

    n00b_string_t             *id;
    n00b_string_t             *summary;
    n00b_http_string_list_t    tags;
    n00b_http_param_list_t     query;
    n00b_http_body_spec_t      body;
    n00b_http_response_list_t  responses;
} n00b_http_endpoint_t;

typedef struct {
    n00b_string_t            *service_id;
    n00b_string_t            *name;
    n00b_string_t            *version;
    n00b_string_t            *api_version;
    n00b_string_t            *openapi_path;
    n00b_string_t            *health_path;
    n00b_http_string_list_t   schemas;
    n00b_http_string_list_t   capabilities;
} n00b_http_discovery_doc_t;

#define n00b_http_strings(...)                                               \
    ((n00b_http_string_list_t){                                              \
        .items = (n00b_string_t *[]){__VA_ARGS__},                           \
        .count = sizeof((n00b_string_t *[]){__VA_ARGS__}) /                  \
                 sizeof(n00b_string_t *)})

#define n00b_http_tags(...) n00b_http_strings(__VA_ARGS__)
#define n00b_http_schemas(...) n00b_http_strings(__VA_ARGS__)
#define n00b_http_capabilities(...) n00b_http_strings(__VA_ARGS__)

#define n00b_http_params(...)                                                \
    ((n00b_http_param_list_t){                                               \
        .items = (n00b_http_param_spec_t []){__VA_ARGS__},                   \
        .count = sizeof((n00b_http_param_spec_t []){__VA_ARGS__}) /          \
                 sizeof(n00b_http_param_spec_t)})

#define n00b_http_responses(...)                                             \
    ((n00b_http_response_list_t){                                            \
        .items = (n00b_http_response_spec_t []){__VA_ARGS__},                \
        .count = sizeof((n00b_http_response_spec_t []){__VA_ARGS__}) /       \
                 sizeof(n00b_http_response_spec_t)})

/**
 * @brief Create a local HTTP service.
 *
 * The service runs over the conduit layer (`n00b_conduit_listen_tcp` /
 * `n00b_conduit_listen_unix` + the accept-event model). It uses the
 * runtime's default conduit and IO service for readiness; no raw socket
 * loop is owned by the service.
 *
 * @kw bind_host        Address to bind for TCP. Default `127.0.0.1`.
 * @kw bind_port        Port to bind for TCP. Use 0 for an ephemeral port.
 * @kw socket_path      AF_UNIX socket path. When non-null the service
 *                      listens on a unix-domain socket instead of TCP;
 *                      `bind_host`/`bind_port` are ignored and
 *                      `n00b_http_service_port` returns 0.
 * @kw socket_mode      chmod applied to the unix socket after bind
 *                      (0 leaves the umask default). Unix mode only.
 * @kw max_header_bytes Maximum request header bytes. Default 16 KiB.
 * @kw max_body_bytes   Maximum request body bytes. Default 1 MiB.
 * @kw backlog          Listen backlog. Default 128.
 * @kw worker_service   Optional conduit service for handler dispatch.
 * @kw allocator        Allocator for service-owned state.
 */
extern n00b_http_service_t *
n00b_http_service_new()
    _kargs {
        n00b_string_t          *bind_host        = nullptr;
        uint16_t                bind_port        = 0;
        n00b_string_t          *socket_path      = nullptr;
        int                     socket_mode      = 0;
        size_t                  max_header_bytes = 16384;
        size_t                  max_body_bytes   = 1048576;
        int                     backlog          = 128;
        n00b_conduit_service_t *worker_service   = nullptr;
        n00b_allocator_t       *allocator        = nullptr;
    };

/**
 * @brief Return the unix-domain socket path the service is listening on.
 *
 * `n00b_option_none` for a TCP service (the absence is a normal state, not
 * an error).
 */
extern n00b_option_t(n00b_string_t *)
    n00b_http_service_socket_path(n00b_http_service_t *svc);

/**
 * @brief Build a query parameter doc entry.
 */
extern n00b_http_param_spec_t
n00b_http_query_param(n00b_string_t *name)
    _kargs {
        bool           required    = false;
        n00b_string_t *schema_json = nullptr;
        n00b_string_t *description = nullptr;
    };

/**
 * @brief Build a JSON request body doc entry.
 */
extern n00b_http_body_spec_t
n00b_http_json_body(n00b_string_t *schema_json)
    _kargs {
        bool required = true;
    };

/**
 * @brief Build a JSON response doc entry.
 */
extern n00b_http_response_spec_t
n00b_http_json_response(uint16_t status)
    _kargs {
        n00b_string_t *description = nullptr;
        n00b_string_t *schema_json = nullptr;
    };

/**
 * @brief Register an exact method/path route with documentation metadata.
 *
 * This is the main route registration API. It keeps the service code compact
 * while still giving n00b enough metadata to generate OpenAPI.
 */
extern n00b_result_t(bool)
n00b_http_route(n00b_http_service_t *svc,
                n00b_http_endpoint_t endpoint);

extern n00b_result_t(bool)
n00b_http_get(n00b_http_service_t *svc,
              n00b_http_endpoint_t endpoint);

extern n00b_result_t(bool)
n00b_http_post(n00b_http_service_t *svc,
               n00b_http_endpoint_t endpoint);

/**
 * @brief Mount local service discovery endpoints.
 *
 * Registers `GET /openapi.json`, `GET /.well-known/openapi.json`, and
 * `GET /.well-known/<service-id>` unless custom paths are provided in @p doc.
 * Must be called before `n00b_http_service_start`.
 */
extern n00b_result_t(bool)
n00b_http_discover(n00b_http_service_t       *svc,
                   n00b_http_discovery_doc_t  doc);

/**
 * @brief Register an exact method/path route without documentation metadata.
 *
 * Routes must be registered before `n00b_http_service_start`.
 */
extern n00b_result_t(bool)
n00b_http_service_route(n00b_http_service_t *svc,
                        n00b_string_t       *method,
                        n00b_string_t       *path,
                        n00b_http_handler_fn handler,
                        void                *user_data);

/**
 * @brief Low-level route descriptor API.
 *
 * n00b copies the route spec structure and array fields, but string values are
 * retained by pointer. Most callers should prefer `n00b_http_get`,
 * `n00b_http_post`, or `n00b_http_route`.
 */
extern n00b_result_t(bool)
n00b_http_service_route_spec(n00b_http_service_t           *svc,
                             const n00b_http_route_spec_t *spec);

/**
 * @brief Low-level service discovery descriptor API.
 *
 * Registers `GET /openapi.json`, `GET /.well-known/openapi.json`, and
 * `GET /.well-known/<service-id>` unless custom paths are provided in @p info.
 * Most callers should prefer `n00b_http_discover`.
 */
extern n00b_result_t(bool)
n00b_http_service_enable_discovery(n00b_http_service_t                 *svc,
                                   const n00b_http_discovery_info_t   *info);

extern n00b_result_t(bool)
n00b_http_service_start(n00b_http_service_t *svc);

extern void
n00b_http_service_stop(n00b_http_service_t *svc);

extern uint16_t
n00b_http_service_port(n00b_http_service_t *svc);

extern n00b_string_t *
n00b_http_request_method(n00b_http_request_t *req);

extern n00b_string_t *
n00b_http_request_path(n00b_http_request_t *req);

extern n00b_string_t *
n00b_http_request_query(n00b_http_request_t *req);

extern n00b_buffer_t *
n00b_http_request_body(n00b_http_request_t *req);

extern n00b_string_t *
n00b_http_request_header(n00b_http_request_t *req, n00b_string_t *name);

extern void
n00b_http_response_writer_status(n00b_http_response_writer_t *resp,
                                 uint16_t                    status);

extern void
n00b_http_response_writer_header(n00b_http_response_writer_t *resp,
                                 n00b_string_t               *name,
                                 n00b_string_t               *value);

extern void
n00b_http_response_writer_body(n00b_http_response_writer_t *resp,
                               n00b_buffer_t               *body);

extern void
n00b_http_response_writer_text(n00b_http_response_writer_t *resp,
                               n00b_string_t               *body)
    _kargs {
        n00b_string_t *content_type = nullptr;
    };

// Streaming response: begin (writes status + headers, body delimited by
// Connection: close), then emit body bytes/lines incrementally. After
// _stream_begin the dispatcher will not send a buffered body.
extern void
n00b_http_response_writer_stream_begin(n00b_http_response_writer_t *resp,
                                       uint16_t                     status,
                                       n00b_string_t               *content_type);

// Return false if the write failed (e.g. client disconnected); the caller
// should stop producing.
extern bool
n00b_http_response_writer_stream_write(n00b_http_response_writer_t *resp,
                                       const void                  *data,
                                       size_t                       len);

extern bool
n00b_http_response_writer_stream_line(n00b_http_response_writer_t *resp,
                                      n00b_string_t               *line);
