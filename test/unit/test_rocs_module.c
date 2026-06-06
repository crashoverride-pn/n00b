/** @file test/unit/test_rocs_module.c — rocs module skeleton smoke test. */

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/map.h>

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    static_assert(N00B_ROCS_API_VERSION == 1,
                  "N00B_ROCS_API_VERSION must remain 1 in WP-001 Phase 1");
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_MODULE_LIFECYCLE) != 0,
                  "rocs lifecycle capability must be exposed");
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_STORE_MAP_DECLS) != 0,
                  "rocs store-map declaration capability must be exposed");

    n00b_rocs_module_init();
    n00b_rocs_module_init();
    n00b_rocs_module_shutdown();
    n00b_rocs_module_shutdown();

    n00b_require(n00b_store_map_err_str(N00B_STORE_MAP_OK) != nullptr,
                 "rocs OK error string must be linked");
    n00b_require(n00b_store_map_err_str(N00B_STORE_MAP_ERR_BAD_LAYOUT) != nullptr,
                 "rocs BAD_LAYOUT error string must be linked");

    return 0;
}
