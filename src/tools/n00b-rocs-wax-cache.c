/* Thin WP-013 wax cache replay/search binary.
 *
 * This tool validates env-derived store config, ingests a fixture/replay
 * NDJSON source through the public wax daemon API, subscribes directly to the
 * installed wax gateway AF_UNIX event socket, or runs finite snapshot searches
 * over an existing wax cache, including a fixture-backed live mode.
 */

#include "n00b.h"
#include "conduit/fd_managed.h"
#include "conduit/print.h"
#include "conduit/service.h"
#include "conduit/socket.h"
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

#include <unistd.h>

#define ROCS_WAX_CACHE_GATEWAY_SOCKET \
    r"/Library/Application Support/Crayon/subscription.sock"
#define ROCS_WAX_CACHE_GATEWAY_READ_CAP (1024 * 1024)
#define ROCS_WAX_CACHE_GATEWAY_RETRY_MS 1000
#define ROCS_WAX_CACHE_GATEWAY_POST_BATCH_SIZE 64
#define ROCS_WAX_CACHE_SERVER_BATCH_SIZE 512
#define ROCS_WAX_CACHE_SERVER_QUERY_PAGE_SIZE 64
#define ROCS_WAX_CACHE_SERVER_TIMEOUT_MS 300000
#define ROCS_WAX_CACHE_QUERY_ARENA_SIZE (1ULL << 25)

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
rocs_wax_cache_print_hit(n00b_store_t      *store,
                         n00b_query_hit_t  *hit,
                         int32_t            format);

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
    n00b_string_t                   *regex;
    n00b_string_t                   *field_eq_name;
    n00b_string_t                   *field_eq_value;
    n00b_string_t                   *field_regex_name;
    n00b_string_t                   *field_regex_value;
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

static n00b_result_t(bool)
rocs_wax_cache_checkpoint_write(n00b_string_t *path, uint64_t line_no);

static void
rocs_wax_cache_tool_usage(void)
{
    n00b_eprintf("usage: n00b-rocs-wax-cache [--server [URL]|--server-url URL] --check-config|--run-fixture <source> [checkpoint]|--subscribe-gateway [socket]|--search [TERM] [filters]");
    n00b_eprintf("search filters: --kind K --class C --family F --event-id ID --regex REGEX --field-eq FIELD=VALUE --field-regex FIELD=REGEX --time-from NS --time-to NS --limit N --order durable|ranked --format text|table|jsonl");
    n00b_eprintf("server mode: --server defaults to ROCS_SERVICE_URL or http://127.0.0.1:8080 and talks to /healthz/ready, /v1/records/batch, /v1/flush, and /v1/query");
    n00b_eprintf("gateway mode: --subscribe-gateway connects directly to the wax gateway AF_UNIX socket and caches live normalized events");
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
rocs_wax_cache_validate_regex_arg(n00b_string_t *pattern)
{
    auto regex_r = n00b_regex_new(pattern);
    if (n00b_result_is_ok(regex_r)) {
        return true;
    }

    n00b_string_t *detail = n00b_regex_err_detail();
    n00b_eprintf("n00b-rocs-wax-cache: invalid regex «#»: «#»",
                 pattern,
                 detail == nullptr
                     ? n00b_regex_err_str((int)n00b_result_get_err(regex_r))
                     : detail);
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
        if (rocs_wax_cache_arg_eq(argv[i], r"--regex")) {
            if (!rocs_wax_cache_need_value(argc, argv, &i, &args->regex)
                || !rocs_wax_cache_validate_regex_arg(args->regex)) {
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
        if (rocs_wax_cache_arg_eq(argv[i], r"--field-regex")) {
            if (args->field_regex_name != nullptr
                || !rocs_wax_cache_need_value(argc, argv, &i, &value)
                || !rocs_wax_cache_split_field_eq(value,
                                                  &args->field_regex_name,
                                                  &args->field_regex_value)
                || !rocs_wax_cache_validate_regex_arg(
                    args->field_regex_value)) {
                n00b_eprintf("n00b-rocs-wax-cache: invalid --field-regex FIELD=REGEX");
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

        if (argv[i][0] != '-' && args->contains == nullptr) {
            args->contains = n00b_string_from_cstr(argv[i]);
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
rocs_wax_cache_contains_any(n00b_string_t *term)
{
    return n00b_filter_contains(n00b_filter_any(), term);
}

static n00b_result_t(n00b_filter_t *)
rocs_wax_cache_regex(n00b_string_t *field, n00b_string_t *pattern)
{
    auto field_r = rocs_wax_cache_field(field);
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_filter_t *, n00b_result_get_err(field_r));
    }

    auto regex_r = n00b_regex_new(pattern);
    if (n00b_result_is_err(regex_r)) {
        n00b_string_t *detail = n00b_regex_err_detail();
        n00b_eprintf("n00b-rocs-wax-cache: invalid regex «#»: «#»",
                     pattern,
                     detail == nullptr
                         ? n00b_regex_err_str((int)n00b_result_get_err(regex_r))
                         : detail);
        return n00b_result_err(n00b_filter_t *, N00B_FILTER_ERR_ARG);
    }

    return n00b_filter_regex(n00b_result_get(field_r),
                             n00b_result_get(regex_r));
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
            rocs_wax_cache_contains_any(args->contains));
        if (n00b_result_is_err(add_r)) {
            return add_r;
        }
        filter = n00b_result_get(add_r);
    }
    if (!rocs_wax_cache_str_empty(args->regex)) {
        auto add_r = rocs_wax_cache_add_filter(
            filter,
            rocs_wax_cache_regex(r"search_text", args->regex));
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
    if (!rocs_wax_cache_str_empty(args->field_regex_name)) {
        auto add_r = rocs_wax_cache_add_filter(
            filter,
            rocs_wax_cache_regex(args->field_regex_name,
                                 args->field_regex_value));
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
        .timeout_ms       = ROCS_WAX_CACHE_SERVER_TIMEOUT_MS,
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

static void
rocs_wax_cache_buffer_append_bytes(n00b_buffer_t *buf, char *data, size_t len)
{
    if (buf == nullptr || data == nullptr || len == 0) {
        return;
    }
    n00b_buffer_t *part = n00b_buffer_from_bytes(data,
                                                 (int64_t)len,
                                                 .allocator = buf->allocator);
    n00b_buffer_concat(buf, part);
}

static bool
rocs_wax_cache_server_ingest_batch(n00b_string_t  *server_url,
                                   n00b_buffer_t  *batch,
                                   uint64_t        batch_count,
                                   int            *status,
                                   n00b_string_t **body)
{
    if (batch_count == 0) {
        return true;
    }
    if (batch == nullptr || n00b_buffer_len(batch) == 0) {
        return false;
    }

    return rocs_wax_cache_server_response_ok(
        rocs_wax_cache_server_post(server_url,
                                   r"/v1/records/batch",
                                   n00b_buffer_to_string(batch)),
        status,
        body);
}

static bool
rocs_wax_cache_server_flush(n00b_string_t  *server_url,
                            int            *status,
                            n00b_string_t **body)
{
    return rocs_wax_cache_server_response_ok(
        rocs_wax_cache_server_post(server_url, r"/v1/flush", r"{}"),
        status,
        body);
}

static bool
rocs_wax_cache_flush_server_batch(n00b_string_t  *server_url,
                                  n00b_buffer_t **batch,
                                  uint64_t       *batch_count,
                                  uint64_t       *batch_last_line,
                                  uint64_t       *ingested)
{
    if (batch_count == nullptr || *batch_count == 0) {
        return true;
    }

    int            status = 0;
    n00b_string_t *body   = nullptr;
    uint64_t       sent   = *batch_count;
    if (!rocs_wax_cache_server_ingest_batch(server_url,
                                           *batch,
                                           *batch_count,
                                           &status,
                                           &body)) {
        n00b_eprintf("n00b-rocs-wax-cache: server batch ingest failed status=«#» body=«#»",
                     (int64_t)status,
                     body == nullptr ? r"" : body);
        return false;
    }

    if (ingested != nullptr) {
        *ingested += sent;
        n00b_printf("n00b-rocs-wax-cache: progress batch=[|#|] ingested=[|#|]",
                    (int64_t)sent,
                    (int64_t)*ingested);
    }

    *batch           = n00b_buffer_new(0);
    *batch_count     = 0;
    *batch_last_line = 0;
    return true;
}

static n00b_string_t *
rocs_wax_cache_gateway_request_json(void)
{
    return n00b_cformat(
        "{\"schema\":\"wax.subscription.request.v1\","
        "\"request_id\":\"rocs:[|#|]\","
        "\"root_ref\":\"\","
        "\"access_path_prefix\":\"\","
        "\"root_pid\":0,"
        "\"detail\":\"event\","
        "\"raw\":false,"
        "\"include_file_access\":true,"
        "\"include_content_hash\":false,"
        "\"settle_ms\":0,"
        "\"max_buffered_events\":0,"
        "\"families\":[\"all\"]}\n",
        (int64_t)getpid());
}

static bool
rocs_wax_cache_gateway_response_ok(n00b_string_t  *line,
                                   n00b_string_t **error)
{
    if (error != nullptr) {
        *error = r"";
    }
    if (rocs_wax_cache_str_empty(line)) {
        return false;
    }

    const char       *parse_error = nullptr;
    n00b_json_node_t *root =
        n00b_json_parse((char *)line->data, line->u8_bytes, &parse_error);
    (void)parse_error;
    if (root == nullptr || !n00b_json_is_object(root)) {
        return false;
    }

    n00b_json_node_t *schema = n00b_json_object_get_cstr(root, "schema");
    if (schema == nullptr ||
        !n00b_json_is_string(schema) ||
        !n00b_unicode_str_eq(n00b_json_as_string(schema),
                             r"wax.subscription.response.v1")) {
        return false;
    }

    n00b_json_node_t *ok = n00b_json_object_get_cstr(root, "ok");
    if (ok == nullptr || !n00b_json_is_bool(ok)) {
        return false;
    }

    n00b_json_node_t *err_node = n00b_json_object_get_cstr(root, "error");
    if (error != nullptr &&
        err_node != nullptr &&
        n00b_json_is_string(err_node)) {
        *error = n00b_json_as_string(err_node);
    }

    return n00b_json_as_bool(ok);
}

static bool
rocs_wax_cache_stream_push(void *inbox, void *msg)
{
    return n00b_conduit_inbox_push_msg(
        n00b_conduit_fd_stream_payload_t,
        (n00b_conduit_fd_stream_inbox_t *)inbox,
        (n00b_conduit_fd_stream_msg_t *)msg);
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_stream_read_line(n00b_conduit_stream_reader_t    *reader,
                                n00b_conduit_fd_stream_inbox_t *inbox,
                                size_t                          cap)
{
    if (reader == nullptr || inbox == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_conduit_stream_read_until(reader,
                                   '\n',
                                   cap,
                                   inbox,
                                   rocs_wax_cache_stream_push);

    for (;;) {
        n00b_conduit_stream_reader_process(reader);

        n00b_conduit_fd_stream_msg_t *msg =
            n00b_conduit_inbox_pop_msg(n00b_conduit_fd_stream_payload_t,
                                       inbox);
        if (msg != nullptr) {
            n00b_conduit_fd_stream_payload_t payload = msg->payload;
            if (payload.error ||
                (payload.len == 0 && payload.eof) ||
                (payload.len >= cap &&
                 ((char *)payload.data)[payload.len - 1] != '\n')) {
                return n00b_result_err(n00b_string_t *,
                                       N00B_ROCS_WAX_ERR_SOURCE);
            }

            size_t len  = payload.len;
            char  *data = payload.data;
            if (len > 0 && data[len - 1] == '\n') {
                len--;
            }
            if (len > 0 && data[len - 1] == '\r') {
                len--;
            }
            return n00b_result_ok(n00b_string_t *,
                                  n00b_string_from_raw(data, (int64_t)len));
        }

        if (reader->eof || reader->error) {
            return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
        }

        n00b_condition_lock(&reader->internal_inbox->cv);
        if (!n00b_conduit_inbox_has_msg(n00b_buffer_t *,
                                        reader->internal_inbox) &&
            !n00b_conduit_inbox_has_sys(reader->internal_inbox)) {
            n00b_condition_wait(&reader->internal_inbox->cv,
                                .timeout_ms = 100,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&reader->internal_inbox->cv);
        }
    }
}

static n00b_result_t(n00b_conduit_io_backend_t *)
rocs_wax_cache_default_io(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr ||
        rt->default_conduit == nullptr ||
        rt->default_service == nullptr) {
        return n00b_result_err(n00b_conduit_io_backend_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_option_t(n00b_conduit_svc_thread_t *) svc_thread_opt =
        n00b_conduit_service_default_io(rt->default_service);
    if (!n00b_option_is_set(svc_thread_opt)) {
        return n00b_result_err(n00b_conduit_io_backend_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_option_t(n00b_conduit_io_backend_t *) io_opt =
        n00b_conduit_svc_thread_io(n00b_option_get(svc_thread_opt));
    if (!n00b_option_is_set(io_opt)) {
        return n00b_result_err(n00b_conduit_io_backend_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }
    return n00b_result_ok(n00b_conduit_io_backend_t *, n00b_option_get(io_opt));
}

static int
rocs_wax_cache_gateway_run_connection(n00b_string_t *server_url,
                                      n00b_string_t *socket_path,
                                      uint64_t      *ingested,
                                      uint64_t      *rejected)
{
    n00b_runtime_t *rt   = n00b_get_runtime();
    auto            io_r = rocs_wax_cache_default_io();
    if (rt == nullptr || n00b_result_is_err(io_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: conduit runtime unavailable");
        return 2;
    }

    auto conn_r = n00b_conduit_conn_unix(rt->default_conduit,
                                         n00b_result_get(io_r),
                                         socket_path);
    if (n00b_result_is_err(conn_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway connect failed socket=«#» err=«#»",
                     socket_path,
                     (int64_t)n00b_result_get_err(conn_r));
        return 1;
    }

    n00b_conduit_conn_t *conn = n00b_result_get(conn_r);
    for (int i = 0; i < 50; ++i) {
        int state = n00b_atomic_load(&conn->conn_state);
        if (state == N00B_CONDUIT_CONN_ST_CONNECTED) {
            break;
        }
        if (state == N00B_CONDUIT_CONN_ST_ERROR ||
            state == N00B_CONDUIT_CONN_ST_CLOSED) {
            n00b_conduit_conn_close(conn);
            return 1;
        }
        usleep(20000);
    }

    if (n00b_atomic_load(&conn->conn_state) != N00B_CONDUIT_CONN_ST_CONNECTED) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway connect timed out socket=«#»",
                     socket_path);
        n00b_conduit_conn_close(conn);
        return 1;
    }

    n00b_option_t(n00b_conduit_fd_owner_t *) owner_opt =
        n00b_conduit_conn_fd_owner(conn);
    if (!n00b_option_is_set(owner_opt)) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway connection has no fd owner");
        n00b_conduit_conn_close(conn);
        return 1;
    }

    n00b_conduit_fd_owner_t *owner   = n00b_option_get(owner_opt);
    n00b_string_t           *request = rocs_wax_cache_gateway_request_json();
    auto write_r = n00b_fd_owner_write(owner, request->data, request->u8_bytes);
    if (n00b_result_is_err(write_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway subscription write failed err=«#»",
                     (int64_t)n00b_result_get_err(write_r));
        n00b_conduit_conn_close(conn);
        return 1;
    }

    auto reader_r = n00b_conduit_stream_reader_new(rt->default_conduit, owner);
    if (n00b_result_is_err(reader_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway stream reader failed err=«#»",
                     (int64_t)n00b_result_get_err(reader_r));
        n00b_conduit_conn_close(conn);
        return 1;
    }

    n00b_conduit_stream_reader_t *reader = n00b_result_get(reader_r);
    n00b_conduit_fd_stream_inbox_t *inbox =
        n00b_conduit_fd_stream_inbox_new(rt->default_conduit);

    auto response_line_r =
        rocs_wax_cache_stream_read_line(reader,
                                        inbox,
                                        ROCS_WAX_CACHE_GATEWAY_READ_CAP);
    n00b_string_t *response_error = r"";
    if (n00b_result_is_err(response_line_r) ||
        !rocs_wax_cache_gateway_response_ok(n00b_result_get(response_line_r),
                                            &response_error)) {
        n00b_eprintf("n00b-rocs-wax-cache: gateway subscription refused «#»",
                     response_error);
        n00b_conduit_stream_reader_destroy(reader);
        n00b_conduit_conn_close(conn);
        return 1;
    }

    n00b_eprintf("n00b-rocs-wax-cache: subscribed socket=«#» server=«#»",
                 socket_path,
                 server_url);

    n00b_buffer_t *batch = n00b_buffer_new(0);
    uint64_t       batch_count = 0;
    uint64_t       batch_last_line = 0;

    for (;;) {
        auto line_r =
            rocs_wax_cache_stream_read_line(reader,
                                            inbox,
                                            ROCS_WAX_CACHE_GATEWAY_READ_CAP);
        if (n00b_result_is_err(line_r)) {
            (void)rocs_wax_cache_flush_server_batch(server_url,
                                                    &batch,
                                                    &batch_count,
                                                    &batch_last_line,
                                                    ingested);
            n00b_eprintf("n00b-rocs-wax-cache: gateway stream closed socket=«#» ingested=«#» rejected=«#»",
                         socket_path,
                         (int64_t)*ingested,
                         (int64_t)*rejected);
            n00b_conduit_stream_reader_destroy(reader);
            n00b_conduit_conn_close(conn);
            return 1;
        }

        n00b_string_t *line = n00b_result_get(line_r);
        if (rocs_wax_cache_str_empty(line)) {
            continue;
        }

        auto record_r = n00b_rocs_wax_record_from_line(line);
        if (n00b_result_is_err(record_r)) {
            *rejected += 1;
            continue;
        }
        char *encoded = n00b_json_encode(n00b_result_get(record_r));
        if (encoded == nullptr) {
            *rejected += 1;
            continue;
        }

        rocs_wax_cache_buffer_append_bytes(batch, encoded, strlen(encoded));
        rocs_wax_cache_buffer_append_bytes(batch, (char *)"\n", 1);
        batch_count++;

        if (batch_count >= ROCS_WAX_CACHE_GATEWAY_POST_BATCH_SIZE) {
            for (;;) {
                if (rocs_wax_cache_flush_server_batch(server_url,
                                                      &batch,
                                                      &batch_count,
                                                      &batch_last_line,
                                                      ingested)) {
                    break;
                }
                n00b_eprintf("n00b-rocs-wax-cache: server batch ingest retry");
                usleep(ROCS_WAX_CACHE_GATEWAY_RETRY_MS * 1000);
            }
        }
    }
}

static int
rocs_wax_cache_tool_subscribe_gateway(n00b_string_t *socket_path,
                                      n00b_string_t *server_url)
{
    if (rocs_wax_cache_str_empty(server_url)) {
        n00b_eprintf("n00b-rocs-wax-cache: --subscribe-gateway requires --server-url");
        return 2;
    }
    if (rocs_wax_cache_str_empty(socket_path)) {
        socket_path = ROCS_WAX_CACHE_GATEWAY_SOCKET;
    }

    uint64_t ingested = 0;
    uint64_t rejected = 0;
    for (;;) {
        (void)rocs_wax_cache_gateway_run_connection(server_url,
                                                    socket_path,
                                                    &ingested,
                                                    &rejected);
        usleep(ROCS_WAX_CACHE_GATEWAY_RETRY_MS * 1000);
    }
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
rocs_wax_cache_json_contains_any(n00b_string_t *term)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_object_put_n00b(payload,
                              r"field",
                              n00b_json_string_new_from_n00b(r"search_text"));
    n00b_json_object_put_n00b(payload,
                              r"any",
                              n00b_json_bool_new(true));
    n00b_json_object_put_n00b(payload,
                              r"term",
                              n00b_json_string_new_from_n00b(term));

    n00b_json_node_t *leaf = n00b_json_object_new();
    n00b_json_object_put_n00b(leaf, r"contains", payload);
    return leaf;
}

static n00b_json_node_t *
rocs_wax_cache_json_regex(n00b_string_t *field, n00b_string_t *pattern)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_object_put_n00b(payload,
                              r"field",
                              n00b_json_string_new_from_n00b(field));
    n00b_json_object_put_n00b(payload,
                              r"pattern",
                              n00b_json_string_new_from_n00b(pattern));

    n00b_json_node_t *leaf = n00b_json_object_new();
    n00b_json_object_put_n00b(leaf, r"regex", payload);
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
                                       rocs_wax_cache_json_contains_any(
                                           args->contains));
    }
    if (!rocs_wax_cache_str_empty(args->regex)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_regex(r"search_text",
                                                                 args->regex));
    }
    if (!rocs_wax_cache_str_empty(args->field_eq_name)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_eq_string(
                                           args->field_eq_name,
                                           args->field_eq_value));
    }
    if (!rocs_wax_cache_str_empty(args->field_regex_name)) {
        rocs_wax_cache_server_add_leaf(&only,
                                       &array,
                                       &count,
                                       rocs_wax_cache_json_regex(
                                           args->field_regex_name,
                                           args->field_regex_value));
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
rocs_wax_cache_event_tail(n00b_string_t *event_id)
{
    if (rocs_wax_cache_str_empty(event_id)) {
        return r"";
    }

    size_t tail = 0;
    for (size_t i = 0; i < event_id->u8_bytes; i++) {
        if (event_id->data[i] == ':') {
            tail = i + 1;
        }
    }

    return n00b_string_from_raw(event_id->data + tail,
                                (int64_t)(event_id->u8_bytes - tail));
}

static n00b_string_t *
rocs_wax_cache_payload_json(n00b_json_node_t *record)
{
    n00b_string_t *raw = rocs_wax_cache_json_string(record, r"raw_json");
    if (!rocs_wax_cache_str_empty(raw)) {
        return raw;
    }

    char *encoded = n00b_json_encode(record);
    return encoded == nullptr ? r"{}" : n00b_string_from_cstr(encoded);
}

static n00b_string_t *
rocs_wax_cache_short_pos(n00b_store_pos_t pos)
{
    if (pos.generation == 0) {
        return n00b_cformat("[|#|]:[|#|]",
                            (int64_t)pos.shard_id,
                            (int64_t)pos.ordinal);
    }

    return n00b_cformat("[|#|]:[|#|]:[|#|]",
                        (int64_t)pos.generation,
                        (int64_t)pos.shard_id,
                        (int64_t)pos.ordinal);
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
    return rocs_wax_cache_short_pos(pos);
}

static n00b_result_t(bool)
rocs_wax_cache_server_print_hit(n00b_json_node_t *hit, int32_t format)
{
    n00b_json_node_t *record = n00b_json_object_get(hit, r"record");
    if (record == nullptr || !n00b_json_is_object(record)) {
        return n00b_result_err(bool, N00B_ROCS_WAX_ERR_SOURCE);
    }

    if (format == ROCS_WAX_CACHE_FORMAT_JSONL) {
        n00b_printf("«#»", rocs_wax_cache_payload_json(record));
        return n00b_result_ok(bool, true);
    }

    n00b_string_t *pos = rocs_wax_cache_server_hit_pos(hit);
    if (format == ROCS_WAX_CACHE_FORMAT_TABLE) {
        n00b_printf("«#»\t«#»\t«#»\t«#»",
                    pos,
                    rocs_wax_cache_event_tail(
                        rocs_wax_cache_json_string(record, r"event_id")),
                    rocs_wax_cache_json_string(record, r"kind"),
                    rocs_wax_cache_payload_json(record));
        return n00b_result_ok(bool, true);
    }

    n00b_printf("pos=«#» id=«#» kind=«#» json=«#»",
                pos,
                rocs_wax_cache_event_tail(
                    rocs_wax_cache_json_string(record, r"event_id")),
                rocs_wax_cache_json_string(record, r"kind"),
                rocs_wax_cache_payload_json(record));
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_json_node_t *)
rocs_wax_cache_server_query(rocs_wax_cache_search_args_t *args,
                            uint64_t                      limit,
                            n00b_string_t                *resume)
{
    n00b_json_node_t *request = n00b_json_object_new();
    n00b_json_object_put_n00b(request,
                              r"filter",
                              rocs_wax_cache_server_filter_json(args));
    n00b_json_object_put_n00b(request,
                              r"limit",
                              n00b_json_int_new((int64_t)limit));
    n00b_json_object_put_n00b(
        request,
        r"ranked",
        n00b_json_bool_new(args->order == ROCS_WAX_CACHE_ORDER_RANKED));
    n00b_json_object_put_n00b(request,
                              r"include_records",
                              n00b_json_bool_new(true));
    if (!rocs_wax_cache_str_empty(resume)) {
        n00b_json_object_put_n00b(
            request,
            r"resume",
            n00b_json_string_new_from_n00b(resume));
    }

    char *encoded = n00b_json_encode(request);
    if (encoded == nullptr) {
        n00b_eprintf("n00b-rocs-wax-cache: server query encode error");
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
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
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_json_node_t *root = n00b_json_parse(body->data,
                                             body->u8_bytes,
                                             nullptr);
    if (root == nullptr || !n00b_json_is_object(root)) {
        n00b_eprintf("n00b-rocs-wax-cache: server query response parse error");
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }
    n00b_json_node_t *hits = n00b_json_object_get(root, r"hits");
    if (hits == nullptr || !n00b_json_is_array(hits)) {
        n00b_eprintf("n00b-rocs-wax-cache: server query response missing hits");
        return n00b_result_err(n00b_json_node_t *,
                               N00B_ROCS_WAX_ERR_SOURCE);
    }
    return n00b_result_ok(n00b_json_node_t *, root);
}

static n00b_result_t(uint64_t)
rocs_wax_cache_server_print_hits(n00b_json_node_t *root, int32_t format)
{
    n00b_json_node_t *hits = n00b_json_object_get(root, r"hits");
    if (hits == nullptr || !n00b_json_is_array(hits)) {
        n00b_eprintf("n00b-rocs-wax-cache: server query response missing hits");
        return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_json_array_t *items = n00b_json_as_array(hits);
    uint64_t           len   = (uint64_t)n00b_list_len(*items);
    for (uint64_t i = 0; i < len; i++) {
        auto print_r =
            rocs_wax_cache_server_print_hit(n00b_list_get(*items, (size_t)i),
                                            format);
        if (n00b_result_is_err(print_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: server output error");
            return n00b_result_err(uint64_t, N00B_ROCS_WAX_ERR_SOURCE);
        }
    }
    return n00b_result_ok(uint64_t, len);
}

static bool
rocs_wax_cache_server_response_more(n00b_json_node_t *root)
{
    n00b_json_node_t *more = n00b_json_object_get(root, r"more");
    return more != nullptr && n00b_json_is_bool(more)
        && n00b_json_as_bool(more);
}

static n00b_string_t *
rocs_wax_cache_server_response_resume(n00b_json_node_t *root)
{
    n00b_json_node_t *resume = n00b_json_object_get(root, r"next_resume");
    if (resume == nullptr || !n00b_json_is_string(resume)) {
        return r"";
    }
    return n00b_json_as_string(resume);
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

static n00b_result_t(uint64_t)
rocs_wax_cache_tool_search_stream(n00b_store_t                *store,
                                  n00b_filter_t               *filter,
                                  rocs_wax_cache_search_args_t *args)
{
    n00b_arena_t     *query_arena = n00b_new_arena(
        .size   = ROCS_WAX_CACHE_QUERY_ARENA_SIZE,
        .use_gc = false,
        .name   = "wax-cache-query");
    n00b_allocator_t *query_alloc = (n00b_allocator_t *)query_arena;
    n00b_query_view_t   *view     = nullptr;
    n00b_query_cursor_t *cursor   = nullptr;
    n00b_err_t           err      = 0;
    uint64_t             printed  = 0;

    auto view_r = n00b_query_view(store,
                                  filter,
                                  .limit     = args->limit,
                                  .allocator = query_alloc);
    if (n00b_result_is_err(view_r)) {
        err = n00b_result_get_err(view_r);
        goto done;
    }
    view = n00b_result_get(view_r);

    auto cursor_r = n00b_query_cursor(view, .allocator = query_alloc);
    if (n00b_result_is_err(cursor_r)) {
        err = n00b_result_get_err(cursor_r);
        goto done;
    }
    cursor = n00b_result_get(cursor_r);

    auto header_r = rocs_wax_cache_print_header(args->format);
    if (n00b_result_is_err(header_r)) {
        err = n00b_result_get_err(header_r);
        goto done;
    }

    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            err = n00b_result_get_err(next_r);
            goto done;
        }

        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            break;
        }

        auto print_r = rocs_wax_cache_print_hit(store,
                                                n00b_option_get(hit_opt),
                                                args->format);
        if (n00b_result_is_err(print_r)) {
            err = n00b_result_get_err(print_r);
            goto done;
        }
        printed++;
        if (args->limit != 0 && printed >= args->limit) {
            break;
        }
    }

done:
    if (cursor != nullptr) {
        auto cursor_close_r = n00b_query_cursor_close(cursor);
        if (err == 0 && n00b_result_is_err(cursor_close_r)) {
            err = n00b_result_get_err(cursor_close_r);
        }
    }
    if (view != nullptr) {
        auto view_close_r = n00b_query_view_close(view);
        if (err == 0 && n00b_result_is_err(view_close_r)) {
            err = n00b_result_get_err(view_close_r);
        }
    }
    n00b_allocator_destroy(query_alloc);

    if (err != 0) {
        return n00b_result_err(uint64_t, err);
    }

    if (printed == 0 && args->format != ROCS_WAX_CACHE_FORMAT_JSONL) {
        n00b_printf("(No records)");
    }

    return n00b_result_ok(uint64_t, printed);
}

static n00b_result_t(n00b_store_t *)
rocs_wax_cache_open_store(n00b_store_schema_t *schema,
                          n00b_store_config_t *config)
{
    auto partition_r = n00b_rocs_wax_partition_policy_new();
    auto seal_r      = n00b_rocs_wax_seal_policy_new();
    if (n00b_result_is_err(partition_r) || n00b_result_is_err(seal_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_POLICY);
    }

    return n00b_store_open_config(schema,
                                  config,
                                  .partition_policy =
                                      n00b_result_get(partition_r),
                                  .seal_policy = n00b_result_get(seal_r));
}

typedef struct {
    n00b_string_t *checkpoint;
    uint64_t       line_no;
} rocs_wax_cache_checkpoint_update_t;

typedef struct {
    uint64_t                                    lines;
    uint64_t                                    ingested;
    uint64_t                                    rejected;
    n00b_buffer_t                              *batch;
    uint64_t                                    batch_count;
    uint64_t                                    batch_last_line;
    n00b_list_t(rocs_wax_cache_checkpoint_update_t) checkpoint_updates;
} rocs_wax_cache_server_import_t;

static n00b_string_t *
rocs_wax_cache_basename(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return r"";
    }

    size_t start = 0;
    for (size_t i = 0; i < path->u8_bytes; i++) {
        if (path->data[i] == '/') {
            start = i + 1;
        }
    }

    return n00b_string_from_raw(path->data + start,
                                (int64_t)(path->u8_bytes - start));
}

static bool
rocs_wax_cache_is_stream_artifact(n00b_string_t *path)
{
    n00b_string_t *base = rocs_wax_cache_basename(path);

    return n00b_unicode_str_eq(base, r"live-stream.json")
        || (n00b_unicode_str_starts_with(base, r"live-stream.")
            && n00b_unicode_str_ends_with(base, r".json"));
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_child_checkpoint_path(n00b_string_t *checkpoint,
                                     n00b_string_t *source)
{
    if (rocs_wax_cache_str_empty(checkpoint)) {
        return n00b_result_ok(n00b_string_t *, nullptr);
    }

    n00b_string_t *dir = n00b_cformat("[|#|].d", checkpoint);
    auto           mkdir_r = n00b_path_mkdir_p(dir);
    if (n00b_result_is_err(mkdir_r)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_CHECKPOINT);
    }

    n00b_string_t *base = rocs_wax_cache_basename(source);
    n00b_string_t *name = n00b_cformat("[|#|].checkpoint", base);

    return n00b_result_ok(n00b_string_t *, n00b_path_join_v(dir, name));
}

static void
rocs_wax_cache_note_checkpoint(rocs_wax_cache_server_import_t *state,
                               n00b_string_t                 *checkpoint,
                               uint64_t                       line_no)
{
    rocs_wax_cache_checkpoint_update_t update = {
        .checkpoint = checkpoint,
        .line_no    = line_no,
    };
    n00b_list_push(state->checkpoint_updates, update);
}

static bool
rocs_wax_cache_write_checkpoint_updates(
    rocs_wax_cache_server_import_t *state)
{
    size_t len = n00b_list_len(state->checkpoint_updates);
    for (size_t i = 0; i < len; i++) {
        rocs_wax_cache_checkpoint_update_t update =
            n00b_list_get(state->checkpoint_updates, i);
        auto checkpoint_write_r =
            rocs_wax_cache_checkpoint_write(update.checkpoint,
                                            update.line_no);
        if (n00b_result_is_err(checkpoint_write_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: checkpoint write error CHECKPOINT");
            return false;
        }
    }
    return true;
}

static int
rocs_wax_cache_path_ptr_cmp(const void *a, const void *b)
{
    n00b_string_t *left  = *(n00b_string_t **)a;
    n00b_string_t *right = *(n00b_string_t **)b;

    return n00b_unicode_str_cmp(left, right);
}

static bool
rocs_wax_cache_server_import_line(n00b_string_t                 *server_url,
                                  n00b_string_t                 *line,
                                  rocs_wax_cache_server_import_t *state,
                                  uint64_t                       checkpoint_line,
                                  uint64_t                      *line_no)
{
    *line_no += 1;
    if (*line_no <= checkpoint_line) {
        return true;
    }
    state->lines++;

    auto record_r = n00b_rocs_wax_record_from_line(line);
    if (n00b_result_is_err(record_r)) {
        state->rejected++;
        return true;
    }

    char *encoded = n00b_json_encode(n00b_result_get(record_r));
    if (encoded == nullptr) {
        n00b_eprintf("n00b-rocs-wax-cache: record encode error");
        return false;
    }

    rocs_wax_cache_buffer_append_bytes(state->batch, encoded, strlen(encoded));
    rocs_wax_cache_buffer_append_bytes(state->batch, (char *)"\n", 1);
    state->batch_count++;
    state->batch_last_line = *line_no;

    if (state->batch_count >= ROCS_WAX_CACHE_SERVER_BATCH_SIZE
        && !rocs_wax_cache_flush_server_batch(server_url,
                                              &state->batch,
                                              &state->batch_count,
                                              &state->batch_last_line,
                                              &state->ingested)) {
        return false;
    }
    return true;
}

static bool
rocs_wax_cache_server_import_file(n00b_string_t                 *server_url,
                                  n00b_string_t                 *checkpoint,
                                  n00b_string_t                 *source,
                                  rocs_wax_cache_server_import_t *state)
{
    auto checkpoint_r = rocs_wax_cache_checkpoint_read(checkpoint);
    if (n00b_result_is_err(checkpoint_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: checkpoint config error CHECKPOINT");
        return false;
    }

    auto source_r = rocs_wax_cache_read_text_file(source);
    if (n00b_result_is_err(source_r)) {
        n00b_eprintf("n00b-rocs-wax-cache: source error SOURCE");
        return false;
    }

    n00b_string_t *text = n00b_result_get(source_r);
    size_t         start = 0;
    uint64_t       checkpoint_line = n00b_result_get(checkpoint_r);
    uint64_t       line_no         = 0;
    for (size_t i = 0; i <= text->u8_bytes; i++) {
        if (i < text->u8_bytes && text->data[i] != '\n') {
            continue;
        }
        if (i == text->u8_bytes && start == i) {
            break;
        }

        size_t end = i;
        if (end > start && text->data[end - 1] == '\r') {
            end--;
        }
        n00b_string_t *line = n00b_string_from_raw(
            text->data + start,
            (int64_t)(end - start));
        if (!rocs_wax_cache_server_import_line(server_url,
                                               line,
                                               state,
                                               checkpoint_line,
                                               &line_no)) {
            return false;
        }
        start = i + 1;
    }
    rocs_wax_cache_note_checkpoint(state, checkpoint, line_no);
    return true;
}

static bool
rocs_wax_cache_server_import_source(n00b_string_t                 *server_url,
                                    n00b_string_t                 *checkpoint,
                                    n00b_string_t                 *source,
                                    rocs_wax_cache_server_import_t *state,
                                    uint64_t                      *files)
{
    if (n00b_path_is_file(source)) {
        *files += 1;
        return rocs_wax_cache_server_import_file(server_url,
                                                 checkpoint,
                                                 source,
                                                 state);
    }
    if (!n00b_path_is_directory(source)) {
        n00b_eprintf("n00b-rocs-wax-cache: source is not a regular file or directory: «#»",
                     source);
        return false;
    }

    n00b_list_t(n00b_string_t *) *entries =
        n00b_list_directory(source,
                            .files       = true,
                            .directories = false,
                            .links       = true,
                            .specials    = false,
                            .full_path   = true,
                            .dot_files   = false);
    if (entries == nullptr) {
        n00b_eprintf("n00b-rocs-wax-cache: could not list source dir «#»",
                     source);
        return false;
    }
    n00b_list_sort(*entries, rocs_wax_cache_path_ptr_cmp);

    uint64_t len = (uint64_t)n00b_list_len(*entries);
    for (uint64_t i = 0; i < len; i++) {
        n00b_string_t *path = n00b_list_get(*entries, (size_t)i);
        if (!rocs_wax_cache_is_stream_artifact(path)) {
            continue;
        }
        *files += 1;
        auto checkpoint_r =
            rocs_wax_cache_child_checkpoint_path(checkpoint, path);
        if (n00b_result_is_err(checkpoint_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: checkpoint config error CHECKPOINT");
            return false;
        }
        if (!rocs_wax_cache_server_import_file(server_url,
                                               n00b_result_get(checkpoint_r),
                                               path,
                                               state)) {
            return false;
        }
        n00b_printf("n00b-rocs-wax-cache: progress file=[|#|] files=[|#|] lines=[|#|] ingested=[|#|] queued=[|#|] rejected=[|#|]",
                    rocs_wax_cache_basename(path),
                    (int64_t)*files,
                    (int64_t)state->lines,
                    (int64_t)state->ingested,
                    (int64_t)state->batch_count,
                    (int64_t)state->rejected);
    }
    return true;
}

static int
rocs_wax_cache_tool_search(rocs_wax_cache_search_args_t *args)
{
    if (!rocs_wax_cache_str_empty(args->server_url)) {
        auto header_r = rocs_wax_cache_print_header(args->format);
        if (n00b_result_is_err(header_r)) {
            return 2;
        }
        uint64_t       printed = 0;
        n00b_string_t *resume  = nullptr;
        uint64_t       remaining = args->limit;
        while (true) {
            uint64_t page_limit = args->order == ROCS_WAX_CACHE_ORDER_RANKED
                                    ? args->limit
                                    : remaining < ROCS_WAX_CACHE_SERVER_QUERY_PAGE_SIZE
                                          ? remaining
                                          : ROCS_WAX_CACHE_SERVER_QUERY_PAGE_SIZE;
            auto root_r = rocs_wax_cache_server_query(args,
                                                      page_limit,
                                                      resume);
            if (n00b_result_is_err(root_r)) {
                return 2;
            }

            n00b_json_node_t *root = n00b_result_get(root_r);
            auto print_r = rocs_wax_cache_server_print_hits(root,
                                                            args->format);
            if (n00b_result_is_err(print_r)) {
                return 2;
            }
            uint64_t count = n00b_result_get(print_r);
            printed += count;
            if (remaining >= count) {
                remaining -= count;
            }
            else {
                remaining = 0;
            }

            if (args->order == ROCS_WAX_CACHE_ORDER_RANKED
                || remaining == 0 || count == 0
                || !rocs_wax_cache_server_response_more(root)) {
                break;
            }

            resume = rocs_wax_cache_server_response_resume(root);
            if (rocs_wax_cache_str_empty(resume)) {
                n00b_eprintf("n00b-rocs-wax-cache: server query response missing resume");
                return 2;
            }
        }

        if (printed == 0 && args->format != ROCS_WAX_CACHE_FORMAT_JSONL) {
            n00b_printf("(No records)");
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

    auto store_r = rocs_wax_cache_open_store(n00b_result_get(schema_r),
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

    if (args->order != ROCS_WAX_CACHE_ORDER_RANKED) {
        auto stream_r = rocs_wax_cache_tool_search_stream(
            store,
            n00b_result_get(filter_r),
            args);
        auto close_store_r = n00b_store_close(store);
        if (n00b_result_is_err(stream_r)) {
            n00b_eprintf("n00b-rocs-wax-cache: query stream error «#»",
                         (int64_t)n00b_result_get_err(stream_r));
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
        rocs_wax_cache_server_import_t state = {
            .batch = n00b_buffer_new(0),
            .checkpoint_updates =
                n00b_list_new_private(rocs_wax_cache_checkpoint_update_t),
        };
        uint64_t files = 0;

        if (!rocs_wax_cache_server_import_source(server_url,
                                                checkpoint,
                                                source,
                                                &state,
                                                &files)) {
            return 2;
        }
        if (!rocs_wax_cache_flush_server_batch(server_url,
                                              &state.batch,
                                              &state.batch_count,
                                              &state.batch_last_line,
                                              &state.ingested)) {
            return 2;
        }
        int            flush_status = 0;
        n00b_string_t *flush_body   = nullptr;
        if (!rocs_wax_cache_server_flush(server_url,
                                         &flush_status,
                                         &flush_body)) {
            n00b_eprintf("n00b-rocs-wax-cache: server flush failed status=«#» body=«#»",
                         (int64_t)flush_status,
                         flush_body == nullptr ? r"" : flush_body);
            return 2;
        }
        if (!rocs_wax_cache_write_checkpoint_updates(&state)) {
            return 2;
        }
        n00b_printf("n00b-rocs-wax-cache: server=«#» files=«#» lines=«#» ingested=«#» rejected=«#» checkpoints=«#»",
                    server_url,
                    (int64_t)files,
                    (int64_t)state.lines,
                    (int64_t)state.ingested,
                    (int64_t)state.rejected,
                    (int64_t)n00b_list_len(state.checkpoint_updates));
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
    if (argc == mode_index + 1 || argc == mode_index + 2) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[mode_index]);
        if (n00b_unicode_str_eq(arg, r"--subscribe-gateway")) {
            n00b_string_t *socket_path =
                argc == mode_index + 2
                    ? n00b_string_from_cstr(argv[mode_index + 1])
                    : ROCS_WAX_CACHE_GATEWAY_SOCKET;
            rc = rocs_wax_cache_tool_subscribe_gateway(socket_path,
                                                       server_url);
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
