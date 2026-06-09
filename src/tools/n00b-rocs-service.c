/* Thin WP-012 reference-service binary.
 *
 * This tool intentionally keeps schema handling out of scope. It validates
 * env-derived service config, and in smoke mode starts/stops the runtime with
 * a minimal caller-supplied schema so packaging has a concrete binary target.
 */

#include "n00b.h"
#include "conduit/print.h"
#include "core/platform.h"
#include "core/runtime.h"
#include "core/string.h"
#include "rocs/n00b_rocs.h"
#include "text/strings/string_ops.h"

static volatile sig_atomic_t rocs_service_tool_stop_requested = 0;

static void
rocs_service_tool_signal(int signum)
{
    (void)signum;
    rocs_service_tool_stop_requested = 1;
}

static void
rocs_service_tool_install_stop_signals(void)
{
    signal(SIGINT, rocs_service_tool_signal);
    signal(SIGTERM, rocs_service_tool_signal);
}

static n00b_result_t(n00b_store_schema_t *)
rocs_service_tool_schema() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto schema_r = n00b_store_schema_new(.allocator = allocator);
    if (n00b_result_is_err(schema_r)) {
        return schema_r;
    }

    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    auto field_r = n00b_store_schema_add_field(schema, r"id");
    if (n00b_result_is_err(field_r)) {
        return n00b_result_err(n00b_store_schema_t *,
                               n00b_result_get_err(field_r));
    }
    return n00b_result_ok(n00b_store_schema_t *, schema);
}

static n00b_result_t(n00b_rocs_service_config_t *)
rocs_service_tool_config() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_rocs_service_config_from_env(.allocator = allocator);
}

static int
rocs_service_tool_check_config(void)
{
    auto config_r = rocs_service_tool_config();
    if (n00b_result_is_err(config_r)) {
        n00b_eprintf("n00b-rocs-service: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(config_r)));
        return 2;
    }
    n00b_printf("n00b-rocs-service: config ok");
    return 0;
}

static int
rocs_service_tool_smoke(void)
{
    auto config_r = rocs_service_tool_config();
    if (n00b_result_is_err(config_r)) {
        n00b_eprintf("n00b-rocs-service: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(config_r)));
        return 2;
    }

    auto schema_r = rocs_service_tool_schema();
    if (n00b_result_is_err(schema_r)) {
        n00b_eprintf("n00b-rocs-service: schema error «#»",
                     n00b_store_err_str(n00b_result_get_err(schema_r)));
        return 2;
    }

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           n00b_result_get(schema_r));
    if (n00b_result_is_err(start_r)) {
        n00b_eprintf("n00b-rocs-service: start error «#»",
                     n00b_rocs_service_err_str(n00b_result_get_err(start_r)));
        return 2;
    }

    n00b_rocs_service_t *service = n00b_result_get(start_r);
    auto                 port_r  = n00b_rocs_service_bound_port(service);
    if (n00b_result_is_ok(port_r)) {
        n00b_printf("n00b-rocs-service: started on port «#»",
                    (int64_t)n00b_result_get(port_r));
    }

    auto stop_r = n00b_rocs_service_stop(service);
    if (n00b_result_is_err(stop_r)) {
        n00b_eprintf("n00b-rocs-service: stop error «#»",
                     n00b_rocs_service_err_str(n00b_result_get_err(stop_r)));
        return 2;
    }
    return 0;
}

static int
rocs_service_tool_serve(void)
{
    auto config_r = rocs_service_tool_config();
    if (n00b_result_is_err(config_r)) {
        n00b_eprintf("n00b-rocs-service: config error «#»",
                     n00b_store_err_str(n00b_result_get_err(config_r)));
        return 2;
    }

    auto schema_r = rocs_service_tool_schema();
    if (n00b_result_is_err(schema_r)) {
        n00b_eprintf("n00b-rocs-service: schema error «#»",
                     n00b_store_err_str(n00b_result_get_err(schema_r)));
        return 2;
    }

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           n00b_result_get(schema_r));
    if (n00b_result_is_err(start_r)) {
        n00b_eprintf("n00b-rocs-service: start error «#»",
                     n00b_rocs_service_err_str(n00b_result_get_err(start_r)));
        return 2;
    }

    n00b_rocs_service_t *service = n00b_result_get(start_r);
    auto                 port_r  = n00b_rocs_service_bound_port(service);
    if (n00b_result_is_ok(port_r)) {
        n00b_printf("n00b-rocs-service: serving on port «#»",
                    (int64_t)n00b_result_get(port_r));
    }

    rocs_service_tool_stop_requested = 0;
    rocs_service_tool_install_stop_signals();
    while (!rocs_service_tool_stop_requested) {
        base_nanosleep_ns(250000000ull);
    }

    (void)n00b_rocs_service_set_draining(service, true);
    auto stop_r = n00b_rocs_service_stop(service);
    if (n00b_result_is_err(stop_r)) {
        n00b_eprintf("n00b-rocs-service: stop error «#»",
                     n00b_rocs_service_err_str(n00b_result_get_err(stop_r)));
        return 2;
    }
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
        if (n00b_unicode_str_eq(arg, r"--check-config")) {
            rc = rocs_service_tool_check_config();
            goto done;
        }
        if (n00b_unicode_str_eq(arg, r"--smoke-start-stop")) {
            rc = rocs_service_tool_smoke();
            goto done;
        }
        if (n00b_unicode_str_eq(arg, r"--serve")) {
            rc = rocs_service_tool_serve();
            goto done;
        }
    }

    n00b_eprintf("usage: n00b-rocs-service --check-config|--smoke-start-stop|--serve");

done:
    n00b_shutdown();
    return rc;
}
