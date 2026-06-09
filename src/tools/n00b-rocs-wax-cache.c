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
#include "core/runtime.h"
#include "core/string.h"
#include "rocs/n00b_rocs.h"
#include "rocs/wax.h"
#include "text/strings/string_ops.h"
#include "util/parse_num.h"

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
    n00b_eprintf("usage: n00b-rocs-wax-cache --check-config|--run-fixture <source> [checkpoint]|--search [filters]");
    n00b_eprintf("search filters: --kind K --class C --family F --event-id ID --contains TERM --field-eq FIELD=VALUE --time-from NS --time-to NS --limit N --order durable|ranked --format text|table|jsonl");
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
                                 rocs_wax_cache_search_args_t  *args)
{
    *args = (rocs_wax_cache_search_args_t){
        .limit  = 100,
        .order  = ROCS_WAX_CACHE_ORDER_DURABLE,
        .format = ROCS_WAX_CACHE_FORMAT_TEXT,
    };

    for (int i = 2; i < argc; i++) {
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
                                n00b_string_t *checkpoint)
{
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

    int rc = 1;
    if (argc == 2) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[1]);
        if (n00b_unicode_str_eq(arg, r"--help")) {
            rocs_wax_cache_tool_usage();
            rc = 0;
            goto done;
        }
        if (n00b_unicode_str_eq(arg, r"--check-config")) {
            rc = rocs_wax_cache_tool_check_config();
            goto done;
        }
    }
    if (argc >= 2) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[1]);
        if (n00b_unicode_str_eq(arg, r"--search")) {
            rocs_wax_cache_search_args_t args = {};
            if (!rocs_wax_cache_parse_search_args(argc, argv, &args)) {
                rocs_wax_cache_tool_usage();
                rc = 1;
                goto done;
            }
            rc = rocs_wax_cache_tool_search(&args);
            goto done;
        }
    }
    if (argc == 3 || argc == 4) {
        n00b_string_t *arg = n00b_string_from_cstr(argv[1]);
        if (n00b_unicode_str_eq(arg, r"--run-fixture")) {
            n00b_string_t *checkpoint = argc == 4
                                            ? n00b_string_from_cstr(argv[3])
                                            : nullptr;
            rc = rocs_wax_cache_tool_run_fixture(
                n00b_string_from_cstr(argv[2]),
                checkpoint);
            goto done;
        }
    }

    rocs_wax_cache_tool_usage();

done:
    n00b_shutdown();
    return rc;
}
