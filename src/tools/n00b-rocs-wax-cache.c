/* Thin WP-013 wax cache replay/search binary.
 *
 * This tool validates env-derived store config, ingests a fixture/replay
 * NDJSON source through the public wax daemon API, or runs finite snapshot
 * searches over an existing wax cache, including a fixture-backed live mode.
 * It intentionally does not implement a query DSL, real gateway requirements,
 * or deployment behavior.
 */

#include "n00b.h"
#include "conduit/print.h"
#include "core/env.h"
#include "core/file.h"
#include "core/runtime.h"
#include "core/string.h"
#include "net/http/http_client.h"
#include "parsers/json.h"
#include "rocs/n00b_rocs.h"
#include "rocs/wax.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"
#include "util/path.h"

typedef enum : int32_t {
    ROCS_WAX_CACHE_FORMAT_TEXT,
    ROCS_WAX_CACHE_FORMAT_TABLE,
    ROCS_WAX_CACHE_FORMAT_JSONL,
} rocs_wax_cache_output_format_t;

typedef enum : int32_t {
    ROCS_WAX_CACHE_ORDER_DURABLE,
    ROCS_WAX_CACHE_ORDER_RANKED,
} rocs_wax_cache_order_t;

extern n00b_result_t(bool)
rocs_wax_cache_print_result(n00b_store_t        *store,
                            n00b_query_result_t *result,
                            int32_t              format);

extern n00b_result_t(bool)
rocs_wax_cache_print_header(int32_t format);

extern n00b_result_t(bool)
rocs_wax_cache_run_live(n00b_store_t  *store,
                        n00b_filter_t *filter,
                        n00b_string_t *fixture,
                        n00b_string_t *resume_token,
                        uint64_t       limit,
                        int32_t        format);

typedef struct {
    n00b_string_t                   *kind;
    n00b_string_t                   *class_name;
    n00b_string_t                   *family;
    n00b_string_t                   *event_id;
    n00b_string_t                   *contains;
    n00b_string_t                   *field_eq_name;
    n00b_string_t                   *field_eq_value;
    bool                             has_time_from;
    bool                             has_time_to;
    bool                             live;
    int64_t                          time_from;
    int64_t                          time_to;
    uint64_t                         limit;
    rocs_wax_cache_order_t           order;
    rocs_wax_cache_output_format_t   format;
    n00b_string_t                   *live_fixture;
    n00b_string_t                   *resume_token;
    n00b_string_t                   *server_url;
} rocs_wax_cache_search_args_t;

static bool
rocs_wax_cache_str_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static bool
rocs_wax_cache_arg_eq(const char *arg, n00b_string_t *expected)
{
    return n00b_unicode_str_eq(n00b_string_from_cstr(arg), expected);
}

static void
rocs_wax_cache_tool_usage(void)
{
    n00b_eprintf("usage: n00b-rocs-wax-cache [--server [URL]|--server-url URL] --check-config|--run-fixture <source> [checkpoint]|--search [filters]");
    n00b_eprintf("search filters: --kind K --class C --family F --event-id ID --contains TERM --field-eq FIELD=VALUE --time-from NS --time-to NS --limit N --order durable|ranked --format text|table|jsonl");
    n00b_eprintf("server mode: --server defaults to ROCS_SERVICE_URL or http://127.0.0.1:8080 and talks to /healthz/ready, /v1/records, and /v1/query");
    n00b_eprintf("live search: --search --live [--live-fixture PATH] [--resume TOKEN]; live output is durable ordered and reports the next resume token on stderr");
}

static bool
rocs_wax_cache_need_value(int           argc,
                          char        **argv,
                          int          *index,
                          n00b_string_t **out)
{
    if (*index + 1 >= argc) {
        n00b_eprintf("n00b-rocs-wax-cache: missing value for «#»",
                     n00b_string_from_cstr(argv[*index]));
        return false;
    }

    *index += 1;
    *out = n00b_string_from_cstr(argv[*index]);
    if (rocs_wax_cache_str_empty(*out)) {
        n00b_eprintf("n00b-rocs-wax-cache: empty value for option");
        return false;
    }
    return true;
}

static bool
rocs_wax_cache_parse_i64(n00b_string_t *value, int64_t *out)
{
    auto parsed_r = n00b_parse_i64(value);
    if (n00b_result_is_err(parsed_r)) {
        return false;
    }
    *out = n00b_result_get(parsed_r);
    return true;
}

static bool
rocs_wax_cache_parse_u64(n00b_string_t *value, uint64_t *out)
{
    int64_t parsed = 0;
    if (!rocs_wax_cache_parse_i64(value, &parsed) || parsed < 0) {
        return false;
    }
    *out = (uint64_t)parsed;
    return true;
}

static bool
rocs_wax_cache_split_field_eq(n00b_string_t  *spec,
                              n00b_string_t **field,
                              n00b_string_t **value)
{
    if (rocs_wax_cache_str_empty(spec)) {
        return false;
    }

    for (size_t i = 0; i < spec->u8_bytes; i++) {
        if (spec->data[i] != '=') {
            continue;
        }
        if (i == 0 || i + 1 >= spec->u8_bytes) {
            return false;
        }

        *field = n00b_string_from_raw(spec->data, (int64_t)i);
        *value = n00b_string_from_raw(spec->data + i + 1,
                                      (int64_t)(spec->u8_bytes - i - 1));
        return !rocs_wax_cache_str_empty(*field)
               && !rocs_wax_cache_str_empty(*value);
    }

    return false;
}

static bool
rocs_wax_cache_parse_format(n00b_string_t *value,
                            rocs_wax_cache_output_format_t *out)
{
    if (n00b_unicode_str_eq(value, r"text")) {
        *out = ROCS_WAX_CACHE_FORMAT_TEXT;
        return true;
    }
    if (n00b_unicode_str_eq(value, r"table")) {
        *out = ROCS_WAX_CACHE_FORMAT_TABLE;
        return true;
    }
    if (n00b_unicode_str_eq(value, r"jsonl")) {
        *out = ROCS_WAX_CACHE_FORMAT_JSONL;
        return true;
    }
    return false;
}

static bool
rocs_wax_cache_parse_order(n00b_string_t         *value,
                           rocs_wax_cache_order_t *out)
{
    if (n00b_unicode_str_eq(value, r"durable")) {
        *out = ROCS_WAX_CACHE_ORDER_DURABLE;
        return true;
    }
    if (n00b_unicode_str_eq(value, r"ranked")) {
        *out = ROCS_WAX_CACHE_ORDER_RANKED;
        return true;
    }
    return false;
}

static bool
rocs_wax_cache_parse_search_args(int                            argc,
                                 char                         **argv,
                                 int                            start_index,
                                 rocs_wax_cache_search_args_t  *args)
{
    n00b_string_t *server_url = args->server_url;
    *args = (rocs_wax_cache_search_args_t){
        .limit      = 100,
        .order      = ROCS_WAX_CACHE_ORDER_DURABLE,
        .format     = ROCS_WAX_CACHE_FORMAT_TEXT,
        .server_url = server_url,
    };

    for (int i = start_index; i < argc; i++) {
        n00b_string_t *value = nullptr;
        if (rocs_wax_cache_arg_eq(argv[i], r"--kind")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &args->kind)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--class")) {
            if (!rocs_wax_cache_need_value(argc,
                                           argv,
                                           &i,
                                           &args->class_name)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--family")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &args->family)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--event-id")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &args->event_id)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--contains")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &args->contains)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--field-eq")) {
            if (args->field_eq_name != nullptr
                || !rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_split_field_eq(value,
                                                  &args->field_eq_name,
                                                  &args->field_eq_value)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --field-eq FIELD=VALUE");
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--time-from")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_parse_i64(value, &args->time_from)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --time-from");
                return false;
            }
            args->has_time_from = true;
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--time-to")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_parse_i64(value, &args->time_to)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --time-to");
                return false;
            }
            args->has_time_to = true;
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--limit")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_parse_u64(value, &args->limit)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --limit");
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--order")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_parse_order(value, &args->order)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --order");
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--format")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_parse_format(value, &args->format)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --format");
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--live")) {
            args->live = true;
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--live-fixture")) {
            if (!rocs_wax_cache_need_value(argc,
                                           argv,
                                           &i,
                                           &args->live_fixture)) {
                return false;
            }
            continue;
        }
        if (rocs_wax_cache_arg_eq(argv[i], r"--resume")) {
            if (!rocs_wax_cache_need_value(argc,
                                           argv,
                                           &i,
                                           &args->resume_token)) {
                return false;
            }
            continue;
        }

        n00b_eprintf("n00b-rocs-wax-cache: unknown search option «#»",
                     n00b_string_from_cstr(argv[i]));
        return false;
    }

    if (args->has_time_from && args->has_time_to
        && args->time_from > args->time_to) {
        n00b_eprintf("n00b-rocs-wax-cache: invalid timestamp range");
        return false;
    }
    if (!args->live && (!rocs_wax_cache_str_empty(args->live_fixture)
                        || !rocs_wax_cache_str_empty(args->resume_token))) {
        n00b_eprintf("n00b-rocs-wax-cache: --live-fixture and --resume require --live");
        return false;
    }
    if (args->live && args->order == ROCS_WAX_CACHE_ORDER_RANKED) {
        n00b_eprintf("n00b-rocs-wax-cache: --live does not support ranked ordering");
        return false;
    }
    if (args->live && !rocs_wax_cache_str_empty(args->server_url)) {
        n00b_eprintf("n00b-rocs-wax-cache: --server does not support --live");
        return false;
    }
    return true;
}

static n00b_result_t(n00b_store_config_t *)
rocs_wax_cache_tool_config() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_store_config_from_env(.allocator = allocator);
}

static n00b_result_t(n00b_filter_field_t *)
rocs_wax_cache_field(n00b_string_t *name)
{
    return n00b_filter_field(name);
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_eq(n00b_string_t *field, n00b_string_t *value)
{
    auto field_r = rocs_wax_cache_field(field);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *, n00b_result_get_err(field_r));
    }
    return n00b_filter_eq(n00b_result_get(field_r), n00b_fv_utf8(value));
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_exists(n00b_string_t *field)
{
    auto field_r = rocs_wax_cache_field(field);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *, n00b_result_get_err(field_r));
    }
    return n00b_filter_exists(n00b_result_get(field_r));
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_contains(n00b_string_t *field, n00b_string_t *term)
{
    auto field_r = rocs_wax_cache_field(field);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *, n00b_result_get_err(field_r));
    }
    return n00b_filter_contains(n00b_result_get(field_r), term);
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_time_range(rocs_wax_cache_search_args_t *args)
{
    auto field_r = rocs_wax_cache_field(r"timestamp");
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *, n00b_result_get_err(field_r));
    }

    int64_t lower = args->has_time_from ? args->time_from : INT64_MIN;
    int64_t upper = args->has_time_to ? args->time_to : INT64_MAX;
    return n00b_filter_between(n00b_result_get(field_r),
                               n00b_fv_i64(lower),
                               n00b_fv_i64(upper));
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_and(n00b_filter_t *left, n00b_filter_t *right)
{
    if (left == nullptr) {
        return n00b_result_ok(n00b_filter_t *, right);
    }
    return n00b_filter_and(left, right, kw_func(n00b_filter_and));
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_add_filter(n00b_filter_t               *acc,
                          n00b_result_t(n00b_filter_t *) next_r)
{
    if (n00b_result_is_err(next_r)) {
        return next_r;
    }
    return rocs_wax_cache_and(acc, n00b_result_get(next_r));
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_build_filter(rocs_wax_cache_search_args_t *args)
{
    n00b_filter_t *filter = nullptr;
    if (!rocs_wax_cache_str_empty(args->kind)) {
        auto add_r = rocs_wax_cache_add_filter(filter,
                                               rocs_wax_cache_eq(r"kind",
                                                                 args->kind));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }

    if (!rocs_wax_cache_str_empty(args->class_name)) {
        auto add_r =
            rocs_wax_cache_add_filter(filter,
                                      rocs_wax_cache_eq(r"class",
                                                        args->class_name));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (!rocs_wax_cache_str_empty(args->family)) {
        auto add_r =
            rocs_wax_cache_add_filter(filter,
                                      rocs_wax_cache_eq(r"family",
                                                        args->family));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (!rocs_wax_cache_str_empty(args->event_id)) {
        auto add_r =
            rocs_wax_cache_add_filter(filter,
                                      rocs_wax_cache_eq(r"event_id",
                                                        args->event_id));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (!rocs_wax_cache_str_empty(args->contains)) {
        auto add_r = rocs_wax_cache_add_filter(
            filter,
            rocs_wax_cache_contains(r"search_text", args->contains));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (!rocs_wax_cache_str_empty(args->field_eq_name)) {
        auto add_r = rocs_wax_cache_add_filter(
            filter,
            rocs_wax_cache_eq(args->field_eq_name, args->field_eq_value));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (args->has_time_from || args->has_time_to) {
        auto add_r =
            rocs_wax_cache_add_filter(filter, rocs_wax_cache_time_range(args));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }

    if (filter == nullptr) {
        return rocs_wax_cache_exists(r"event_id");
    }
    return n00b_result_ok(n00b_filter_t *, filter);
}

static n00b_string_t *
rocs_wax_cache_default_server_url(void)
{
    n00b_string_t *env = n00b_getenv(r"ROCS_SERVICE_URL");
    if (!rocs_wax_cache_str_empty(env)) {
        return env;
    }
    return r"http://127.0.0.1:8080";
}

static n00b_string_t *
rocs_wax_cache_service_url(n00b_string_t *server_url, n00b_string_t *path)
{
    if (rocs_wax_cache_str_empty(server_url)) {
        server_url = rocs_wax_cache_default_server_url();
    }
    if (rocs_wax_cache_str_empty(path)) {
        return server_url;
    }

    bool server_slash = server_url->u8_bytes > 0
                        && server_url->data[server_url->u8_bytes - 1] == '/';
    bool path_slash = path->u8_bytes > 0 && path->data[0] == '/';
    if (server_slash && path_slash) {
        n00b_string_t *trimmed =
            n00b_string_from_raw(path->data + 1,
                                 (int64_t)(path->u8_bytes - 1));
        return n00b_unicode_str_cat(server_url, trimmed);
    }
    if (!server_slash && !path_slash) {
        return n00b_cformat("[|#|]/[|#|]", server_url, path);
    }
    return n00b_unicode_str_cat(server_url, path);
}

static n00b_result_t(n00b_http_response_t *)
rocs_wax_cache_server_post(n00b_string_t *server_url,
                           n00b_string_t *path,
                           n00b_string_t *body)
{
    if (rocs_wax_cache_str_empty(body)) {
        return n00b_result_err(n00b_http_response_t *, N00B_ROCS_WAX_ERR_ARG);
    }
    return n00b_http_request_sync(
        rocs_wax_cache_service_url(server_url, path),
        .method           = r"POST",
        .body             = n00b_buffer_from_bytes(body->data,
                                                   (int64_t)body->u8_bytes),
        .content_type     = r"application/json",
        .allow_plain_http = true);
}

static n00b_result_t(n00b_http_response_t *)
rocs_wax_cache_server_get(n00b_string_t *server_url, n00b_string_t *path)
{
    return n00b_http_request_sync(
        rocs_wax_cache_service_url(server_url, path),
        .allow_plain_http = true);
}

static bool
rocs_wax_cache_server_response_ok(n00b_result_t(n00b_http_response_t *) r,
                                  int                                  *status,
                                  n00b_string_t                       **body)
{
    if (status != nullptr) {
        *status = 0;
    }
    if (body != nullptr) {
        *body = r"";
    }
    if (n00b_result_is_err(r)) {
        return false;
    }

    n00b_http_response_t *resp = n00b_result_get(r);
    int                  code = n00b_http_response_status(resp);
    if (status != nullptr) {
        *status = code;
    }
    n00b_buffer_t *resp_body = n00b_http_response_body(resp);
    if (body != nullptr && resp_body != nullptr) {
        *body = n00b_buffer_to_string(n00b_buffer_copy(resp_body));
    }
    return code >= 200 && code < 300;
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_read_text_file(n00b_string_t *path)
{
    if (rocs_wax_cache_str_empty(path)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_file_t *file  = n00b_result_get(open_r);
    auto         buf_r = n00b_file_as_buffer(file);
    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(file);
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_buffer_t *copy = n00b_buffer_copy(n00b_result_get(buf_r));
    n00b_file_close(file);
    return n00b_result_ok(n00b_string_t *, n00b_buffer_to_string(copy));
}

static n00b_result_t(uint64_t)
rocs_wax_cache_checkpoint_read(n00b_string_t *path)
{
    if (rocs_wax_cache_str_empty(path) || !n00b_file_exists(path)) {
        return n00b_result_ok(uint64_t, 0);
    }

    auto text_r = rocs_wax_cache_read_text_file(path);
    if (n00b_result_is_err(text_r)) {
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    auto parsed_r = n00b_parse_i64(n00b_result_get(text_r));
    if (n00b_result_is_err(parsed_r) || n00b_result_get(parsed_r) < 0) {
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }
    return n00b_result_ok(uint64_t, (uint64_t)n00b_result_get(parsed_r));
}

static n00b_result_t(bool)
rocs_wax_cache_checkpoint_write(n00b_string_t *path, uint64_t line_no)
{
    if (rocs_wax_cache_str_empty(path)) {
        return n00b_result_ok(bool, true);
    }

    n00b_string_t *text = n00b_cformat("[|#|]\n", (int64_t)line_no);
    n00b_buffer_t *buf  = n00b_buffer_from_bytes(text->data,
                                                 (int64_t)text->u8_bytes);
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }
    n00b_file_t *file = n00b_result_get(open_r);
    auto         wr_r = n00b_file_write_all(file, buf);
    auto         cl_r = n00b_file_close_result(file);
    if (n00b_result_is_err(wr_r) || n00b_result_is_err(cl_r)) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }
    return n00b_result_ok(bool, true);
}

static n00b_json_node_t *
rocs_wax_cache_json_eq(n00b_string_t *field, n00b_json_node_t *value)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_object_put_n00b(payload,
                              r"field",
                              n00b_json_string_new_from_n00b(field));
    n00b_json_object_put_n00b(payload, r"value", value);

    n00b_json_node_t *leaf = n00b_json_object_new();
    n00b_json_object_put_n00b(leaf, r"eq", payload);
    return leaf;
}

static n00b_json_node_t *
rocs_wax_cache_json_eq_string(n00b_string_t *field, n00b_string_t *value)
{
    return rocs_wax_cache_json_eq(field, n00b_json_string_new_from_n00b(value));
}

static n00b_json_node_t *
rocs_wax_cache_json_contains(n00b_string_t *field, n00b_string_t *term)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_object_put_n00b(payload,
                              r"field",
                              n00b_json_string_new_from_n00b(field));
    n00b_json_object_put_n00b(payload,
                              r"term",
                              n00b_json_string_new_from_n00b(term));

    n00b_json_node_t *leaf = n00b_json_object_new();
    n00b_json_object_put_n00b(leaf, r"contains", payload);
    return leaf;
}

static n00b_json_node_t *
rocs_wax_cache_json_range(n00b_string_t *field, int64_t lower, int64_t upper)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_object_put_n00b(payload,
                              r"field",
                              n00b_json_string_new_from_n00b(field));
    n00b_json_object_put_n00b(payload, r"lower", n00b_json_int_new(lower));
    n00b_json_object_put_n00b(payload, r"upper", n00b_json_int_new(upper));

    n00b_json_node_t *leaf = n00b_json_object_new();
    n00b_json_object_put_n00b(leaf, r"range", payload);
    return leaf;
}

static void
rocs_wax_cache_server_add_leaf(n00b_json_node_t **only,
                               n00b_json_node_t **array,
                               uint64_t          *count,
                               n00b_json_node_t  *leaf)
{
    if (*count == 0) {
        *only = leaf;
    } else {
        if (*count == 1) {
            *array = n00b_json_array_new();
            n00b_json_array_push(*array, *only);
        }
        n00b_json_array_push(*array, leaf);
    }
    *count += 1;
}

static n00b_json_node_t *
rocs_wax_cache_server_filter_json(rocs_wax_cache_search_args_t *args)
{
    n00b_json_node_t *only = nullptr;
    n00b_json_node_t *array = nullptr;
    uint64_t          count = 0;

    if (!rocs_wax_cache_str_empty(args->kind)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           r"kind",
                                           args->kind));
    }
    if (!rocs_wax_cache_str_empty(args->class_name)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           r"class",
                                           args->class_name));
    }
    if (!rocs_wax_cache_str_empty(args->family)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           r"family",
                                           args->family));
    }
    if (!rocs_wax_cache_str_empty(args->event_id)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           r"event_id",
                                           args->event_id));
    }
    if (!rocs_wax_cache_str_empty(args->contains)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_contains(
                                           r"search_text",
                                           args->contains));
    }
    if (!rocs_wax_cache_str_empty(args->field_eq_name)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           args->field_eq_name,
                                           args->field_eq_value));
    }
    if (args->has_time_from || args->has_time_to) {
        rocs_wax_cache_server_add_leaf(
            &only,
            &array,
            &count,
            rocs_wax_cache_json_range(r"timestamp",
                                      args->has_time_from ? args->time_from
                                                          : INT64_MIN,
                                      args->has_time_to ? args->time_to
                                                        : INT64_MAX));
    }

    if (count == 0) {
        n00b_json_node_t *filter = n00b_json_object_new();
        n00b_json_object_put_n00b(filter,
                                  r"exists",
                                  n00b_json_string_new_from_n00b(r"event_id"));
        return filter;
    }
    if (count == 1) {
        return only;
    }

    n00b_json_node_t *filter = n00b_json_object_new();
    n00b_json_object_put_n00b(filter, r"and", array);
    return filter;
}

static n00b_string_t *
rocs_wax_cache_json_string(n00b_json_node_t *json, n00b_string_t *field)
{
    n00b_json_node_t *node = n00b_json_object_get(json, field);
    if (n00b_json_is_string(node)) {
        return n00b_json_as_string(node);
    }
    if (n00b_json_is_int(node)) {
        return n00b_cformat("[|#|]", n00b_json_as_i64(node));
    }
    if (n00b_json_is_bool(node)) {
        return n00b_json_as_bool(node) ? r"true" : r"false";
    }
    if (n00b_json_is_double(node)) {
        double value = n00b_json_as_f64(node);
        return n00b_cformat("[|#:.6f|]", &value);
    }
    return r"";
}

static n00b_string_t *
rocs_wax_cache_server_hit_pos(n00b_json_node_t *hit)
{
    n00b_store_pos_t pos = {
        .generation = (uint64_t)n00b_json_as_i64(n00b_json_object_get(hit,
                                                                      r"generation")),
        .shard_id   = (uint64_t)n00b_json_as_i64(n00b_json_object_get(hit,
                                                                      r"shard_id")),
        .ordinal    = (uint64_t)n00b_json_as_i64(n00b_json_object_get(hit,
                                                                      r"ordinal")),
    };
    auto encoded_r = n00b_store_pos_encode(pos);
    return n00b_result_is_ok(encoded_r) ? n00b_result_get(encoded_r) : r"";
}

static double
rocs_wax_cache_server_hit_score(n00b_json_node_t *hit)
{
    n00b_json_node_t *score = n00b_json_object_get(hit, r"score");
    if (n00b_json_is_double(score)) {
        return n00b_json_as_f64(score);
    }
    if (n00b_json_is_int(score)) {
        return (double)n00b_json_as_i64(score);
    }
    return 0.0;
}

static n00b_result_t(bool)
rocs_wax_cache_server_print_hit(n00b_json_node_t *hit, int32_t format)
{
    n00b_json_node_t *record = n00b_json_object_get(hit, r"record");
    if (record == nullptr || !n00b_json_is_object(record)) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_SOURCE);
    }

    if (format == ROCS_WAX_CACHE_FORMAT_JSONL) {
        n00b_string_t *raw = rocs_wax_cache_json_string(record, r"raw_json");
        if (rocs_wax_cache_str_empty(raw)) {
            char *encoded = n00b_json_encode(record);
            raw = encoded == nullptr ? r"{}" : n00b_string_from_cstr(encoded);
        }
        n00b_printf("«#»", raw);
        return n00b_result_ok(bool, true);
    }

    n00b_string_t *pos = rocs_wax_cache_server_hit_pos(hit);
    double         score = rocs_wax_cache_server_hit_score(hit);
    if (format == ROCS_WAX_CACHE_FORMAT_TABLE) {
        n00b_printf("«#»\t«#»\t«#»\t«#»\t«#»\t«#»",
                    pos,
                    n00b_cformat("[|#:.6f|]", &score),
                    rocs_wax_cache_json_string(record, r"event_id"),
                    rocs_wax_cache_json_string(record, r"kind"),
                    rocs_wax_cache_json_string(record, r"class"),
                    rocs_wax_cache_json_string(record, r"family"));
        return n00b_result_ok(bool, true);
    }

    n00b_printf("pos=«#» score=«#» event_id=«#» kind=«#» class=«#» family=«#»",
                pos,
                n00b_cformat("[|#:.6f|]", &score),
                rocs_wax_cache_json_string(record, r"event_id"),
                rocs_wax_cache_json_string(record, r"kind"),
                rocs_wax_cache_json_string(record, r"class"),
                rocs_wax_cache_json_string(record, r"family"));
    return n00b_result_ok(bool, true);
}

static int
rocs_wax_cache_tool_check_server(n00b_string_t *server_url)
{
    int            status = 0;
    n00b_string_t *body   = nullptr;
    if (!rocs_wax_cache_server_response_ok(
            rocs_wax_cache_server_get(server_url, r"/healthz/ready"),
            &status,
            &body)) {
        n00b_eprintf("n00b-rocs-wax-cache: server not ready status=«#» body=«#»",
                     (int64_t)status,
                     body == nullptr ? r"" : body);
        return 2;
    }
    n00b_printf("n00b-rocs-wax-cache: server ok");
    return 0;
}

static int
rocs_wax_cache_tool_check_config(void)
{
    auto config_r = rocs_wax_cache_tool_config();
    if (n00b_result_is_err(config_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(config_r)));
        return 2;
    }
    n00b_printf("n00b-rocs-wax-cache: config ok");
    return 0;
}

static int
rocs_wax_cache_tool_search(rocs_wax_cache_search_args_t *args)
{
    if (!rocs_wax_cache_str_empty(args->server_url)) {
        n00b_json_node_t *request = n00b_json_object_new();
        n00b_json_object_put_n00b(request,
                                  r"filter",
                                  rocs_wax_cache_server_filter_json(args));
        n00b_json_object_put_n00b(request,
                                  r"limit",
                                  n00b_json_int_new((int64_t)args->limit));
        n00b_json_object_put_n00b(
            request,
            r"ranked",
            n00b_json_bool_new(args->order == ROCS_WAX_CACHE_ORDER_RANKED));
        n00b_json_object_put_n00b(request,
                                  r"include_records",
                                  n00b_json_bool_new(true));

        char *encoded = n00b_json_encode(request);
        if (encoded == nullptr) {
            n00b_eprintf("n00b-rocs-wax-cache: server query encode error");
            return 2;
        }

        int            status = 0;
        n00b_string_t *body   = nullptr;
        if (!rocs_wax_cache_server_response_ok(
                rocs_wax_cache_server_post(args->server_url,
                                           r"/v1/query",
                                           n00b_string_from_cstr(encoded)),
                &status,
                &body)) {
            n00b_eprintf("n00b-rocs-wax-cache: server query failed status=«#» body=«#»",
                         (int64_t)status,
                         body == nullptr ? r"" : body);
            return 2;
        }

        n00b_json_node_t *root = n00b_json_parse(body->data,
                                                 body->u8_bytes,
                                                 nullptr);
        if (root == nullptr || !n00b_json_is_object(root)) {
            n00b_eprintf("n00b-rocs-wax-cache: server query response parse error");
            return 2;
        }
        n00b_json_node_t *hits = n00b_json_object_get(root, r"hits");
        if (hits == nullptr || !n00b_json_is_array(hits)) {
            n00b_eprintf("n00b-rocs-wax-cache: server query response missing hits");
            return 2;
        }

        auto header_r = rocs_wax_cache_print_header(args->format);
        if (n00b_result_is_err(header_r)) {
            return 2;
        }
        n00b_json_array_t *items = n00b_json_as_array(hits);
        for (size_t i = 0; i < n00b_list_len(*items); i++) {
            auto print_r =
                rocs_wax_cache_server_print_hit(n00b_list_get(*items, i),
                                                args->format);
            if (n00b_result_is_err(print_r)) {
                n00b_eprintf("n00b-rocs-wax-cache: server output error");
                return 2;
            }
        }
        return 0;
    }

    auto config_r = rocs_wax_cache_tool_config();
    if (n00b_result_is_err(config_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(config_r)));
        return 2;
    }

    auto schema_r = n00b_rocs_wax_schema_new();
    if (n00b_result_is_err(schema_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: schema error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(schema_r)));
        return 2;
    }

    auto store_r = n00b_store_open_config(n00b_result_get(schema_r),
                                          n00b_result_get(config_r));
    if (n00b_result_is_err(store_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: store error «#»",
                     n00b_store_err_str(n00b_result_get_err(store_r)));
        return 2;
    }
    n00b_store_t *store = n00b_result_get(store_r);

    auto filter_r = rocs_wax_cache_build_filter(args);
    if (n00b_result_is_err(filter_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: filter error");
        (void)n00b_store_close(store);
        return 2;
    }

    if (args->live) {
        auto live_r = rocs_wax_cache_run_live(store,
                                              n00b_result_get(filter_r),
                                              args->live_fixture,
                                              args->resume_token,
                                              args->limit,
                                              args->format);
        auto close_store_r = n00b_store_close(store);
        if (n00b_result_is_err(live_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: live search error «#»",
                         (int64_t)n00b_result_get_err(live_r));
            return 2;
        }
        if (n00b_result_is_err(close_store_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: store close error «#»",
                         n00b_store_err_str(n00b_result_get_err(
                             close_store_r)));
            return 2;
        }
        return 0;
    }

    auto query_r = n00b_query_new(n00b_result_get(filter_r),
                                  .ranked = args->order
                                            == ROCS_WAX_CACHE_ORDER_RANKED,
                                  .limit  = args->limit);
    if (n00b_result_is_err(query_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: query spec error");
        (void)n00b_store_close(store);
        return 2;
    }

    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    if (n00b_result_is_err(result_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: query run error");
        (void)n00b_store_close(store);
        return 2;
    }

    n00b_query_result_t *result = n00b_result_get(result_r);
    auto print_r = rocs_wax_cache_print_result(store, result, args->format);
    auto close_result_r = n00b_query_result_close(result);
    auto close_store_r  = n00b_store_close(store);
    if (n00b_result_is_err(print_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: output error «#»",
                     (int64_t)n00b_result_get_err(print_r));
        return 2;
    }
    if (n00b_result_is_err(close_result_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: result close error");
        return 2;
    }
    if (n00b_result_is_err(close_store_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: store close error «#»",
                     n00b_store_err_str(n00b_result_get_err(close_store_r)));
        return 2;
    }
    return 0;
}

static int
rocs_wax_cache_tool_run_fixture(n00b_string_t *source,
                                n00b_string_t *checkpoint,
                                n00b_string_t *server_url)
{
    if (!rocs_wax_cache_str_empty(server_url)) {
        auto checkpoint_r = rocs_wax_cache_checkpoint_read(checkpoint);
        if (n00b_result_is_err(checkpoint_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: checkpoint config error CHECKPOINT");
            return 2;
        }
        uint64_t checkpoint_line = n00b_result_get(checkpoint_r);

        auto source_r = rocs_wax_cache_read_text_file(source);
        if (n00b_result_is_err(source_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: source error SOURCE");
            return 2;
        }

        n00b_string_t *text = n00b_result_get(source_r);
        uint64_t       line_no = 0;
        uint64_t       lines = 0;
        uint64_t       ingested = 0;
        uint64_t       rejected = 0;
        size_t         start = 0;

        for (size_t i = 0; i <= text->u8_bytes; i++) {
            if (i < text->u8_bytes && text->data[i] != '\n') {
                continue;
            }
            if (i == text->u8_bytes && start == i) {
                break;
            }

            line_no++;
            size_t end = i;
            if (end > start && text->data[end - 1] == '\r') {
                end--;
            }
            if (line_no <= checkpoint_line) {
                start = i + 1;
                continue;
            }

            n00b_string_t *line = n00b_string_from_raw(
                text->data + start,
                (int64_t)(end - start));
            lines++;

            auto record_r = n00b_rocs_wax_record_from_line(line);
            if (n00b_result_is_err(record_r)) {
                rejected++;
                auto checkpoint_write_r =
                    rocs_wax_cache_checkpoint_write(checkpoint, line_no);
                if (n00b_result_is_err(checkpoint_write_r)) {
                    n00b_eprintf("n00b-rocs-wax-cache: checkpoint write error CHECKPOINT");
                    return 2;
                }
                start = i + 1;
                continue;
            }

            char *encoded = n00b_json_encode(n00b_result_get(record_r));
            if (encoded == nullptr) {
                n00b_eprintf("n00b-rocs-wax-cache: record encode error");
                return 2;
            }

            int            status = 0;
            n00b_string_t *body   = nullptr;
            if (!rocs_wax_cache_server_response_ok(
                    rocs_wax_cache_server_post(server_url,
                                               r"/v1/records",
                                               n00b_string_from_cstr(encoded)),
                    &status,
                    &body)) {
                n00b_eprintf("n00b-rocs-wax-cache: server ingest failed status=«#» body=«#»",
                             (int64_t)status,
                             body == nullptr ? r"" : body);
                return 2;
            }
            ingested++;

            auto checkpoint_write_r =
                rocs_wax_cache_checkpoint_write(checkpoint, line_no);
            if (n00b_result_is_err(checkpoint_write_r)) {
                n00b_eprintf("n00b-rocs-wax-cache: checkpoint write error CHECKPOINT");
                return 2;
            }
            start = i + 1;
        }

        n00b_printf("n00b-rocs-wax-cache: server=«#» lines=«#» ingested=«#» rejected=«#» checkpoint=«#»",
                    server_url,
                    (int64_t)lines,
                    (int64_t)ingested,
                    (int64_t)rejected,
                    (int64_t)line_no);
        return 0;
    }

    auto store_config_r = rocs_wax_cache_tool_config();
    if (n00b_result_is_err(store_config_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(store_config_r)));
        return 2;
    }

    auto daemon_config_r =
        n00b_rocs_wax_daemon_config_new(n00b_result_get(store_config_r));
    if (n00b_result_is_err(daemon_config_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: daemon config error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(
                         daemon_config_r)));
        return 2;
    }

    n00b_rocs_wax_daemon_config_t *daemon_config =
        n00b_result_get(daemon_config_r);
    auto set_r =
        n00b_rocs_wax_daemon_config_set_fixture_source(daemon_config, source);
    if (n00b_result_is_err(set_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: source config error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(set_r)));
        return 2;
    }

    set_r = n00b_rocs_wax_daemon_config_set_checkpoint_path(daemon_config,
                                                            checkpoint);
    if (n00b_result_is_err(set_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: checkpoint config error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(set_r)));
        return 2;
    }

    auto start_r = n00b_rocs_wax_daemon_start(daemon_config);
    if (n00b_result_is_err(start_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: start error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(start_r)));
        return 2;
    }

    n00b_rocs_wax_daemon_t *daemon = n00b_result_get(start_r);
    auto                    run_r  = n00b_rocs_wax_daemon_run(daemon);
    auto                    stop_r = n00b_rocs_wax_daemon_stop(daemon);
    if (n00b_result_is_err(run_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: run error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(run_r)));
        return 2;
    }
    if (n00b_result_is_err(stop_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: stop error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(stop_r)));
        return 2;
    }

    auto stats_r = n00b_rocs_wax_daemon_stats(daemon);
    if (n00b_result_is_err(stats_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: stats error «#»",
                     n00b_rocs_wax_err_str(n00b_result_get_err(stats_r)));
        return 2;
    }

    n00b_rocs_wax_daemon_stats_t stats = n00b_result_get(stats_r);
    n00b_printf("n00b-rocs-wax-cache: lines=«#» ingested=«#» rejected=«#» checkpoint=«#»",
                (int64_t)stats.lines_read,
                (int64_t)stats.events_ingested,
                (int64_t)stats.events_rejected,
                (int64_t)stats.checkpoint_line);
    return 0;
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    int            rc         = 1;
    int            mode_index = 1;
    n00b_string_t *server_url = nullptr;

    if (argc >= 2) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[1]);
        if (n00b_unicode_str_eq(arg, r"--server")) {
            if (argc >= 3 && argv[2][0] != '-') {
                server_url = n00b_string_from_cstr(argv[2]);
                mode_index = 3;
            } else {
                server_url = rocs_wax_cache_default_server_url();
                mode_index = 2;
            }
        } else if (n00b_unicode_str_eq(arg, r"--server-url")) {
            if (argc < 3 || argv[2][0] == '-') {
                n00b_eprintf("n00b-rocs-wax-cache: --server-url requires URL");
                rocs_wax_cache_tool_usage();
                rc = 1;
                goto done;
            }
            server_url = n00b_string_from_cstr(argv[2]);
            mode_index = 3;
        }
    }

    if (argc == mode_index + 1) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[mode_index]);
        if (n00b_unicode_str_eq(arg, r"--help")) {
            rocs_wax_cache_tool_usage();
            rc = 0;
            goto done;
        }
        if (n00b_unicode_str_eq(arg, r"--check-config")) {
            rc = rocs_wax_cache_str_empty(server_url)
                     ? rocs_wax_cache_tool_check_config()
                     : rocs_wax_cache_tool_check_server(server_url);
            goto done;
        }
    }
    if (argc > mode_index) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[mode_index]);
        if (n00b_unicode_str_eq(arg, r"--search")) {
            rocs_wax_cache_search_args_t args = {
                .server_url = server_url,
            };
            if (!rocs_wax_cache_parse_search_args(argc,
                                                  argv,
                                                  mode_index + 1,
                                                  &args)) {
                rocs_wax_cache_tool_usage();
                rc = 1;
                goto done;
            }
            rc = rocs_wax_cache_tool_search(&args);
            goto done;
        }
    }
    if (argc == mode_index + 2 || argc == mode_index + 3) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[mode_index]);
        if (n00b_unicode_str_eq(arg, r"--run-fixture")) {
            n00b_string_t *checkpoint = argc == mode_index + 3
                                            ? n00b_string_from_cstr(
                                                argv[mode_index + 2])
                                            : nullptr;
            rc = rocs_wax_cache_tool_run_fixture(
                n00b_string_from_cstr(argv[mode_index + 1]),
                checkpoint,
                server_url);
            goto done;
        }
    }

    rocs_wax_cache_tool_usage();

done:
    n00b_shutdown();
    return rc;
}
