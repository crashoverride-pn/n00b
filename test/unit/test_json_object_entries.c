/* test/unit/test_json_object_entries.c - JSON object entry accessor contracts. */

#include "n00b.h"
#include "adt/list.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static void
test_object_entries(void)
{
    n00b_json_node_t *obj = n00b_json_object_new();
    n00b_json_object_put_n00b(obj, r"a", n00b_json_int_new(1));
    n00b_json_object_put_n00b(obj, r"b", n00b_json_bool_new(true));

    auto entries_r = n00b_json_object_entries(obj);
    CHECK(n00b_result_is_ok(entries_r));

    n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
    CHECK(entries != nullptr);
    CHECK(n00b_list_len(*entries) == 2);

    bool found_a = false;
    bool found_b = false;
    for (size_t i = 0; i < n00b_list_len(*entries); i++) {
        n00b_json_object_entry_t *entry = n00b_list_get(*entries, i);
        CHECK(entry != nullptr);
        CHECK(entry->key != nullptr);
        CHECK(entry->value != nullptr);

        if (n00b_unicode_str_eq(entry->key, r"a")) {
            found_a = true;
            CHECK(n00b_json_is_int(entry->value));
            CHECK(n00b_json_as_i64(entry->value) == 1);
        }
        if (n00b_unicode_str_eq(entry->key, r"b")) {
            found_b = true;
            CHECK(n00b_json_is_bool(entry->value));
            CHECK(n00b_json_as_bool(entry->value) == true);
        }
    }
    CHECK(found_a);
    CHECK(found_b);
}

static void
test_object_entries_errors(void)
{
    auto null_r = n00b_json_object_entries(nullptr);
    CHECK(n00b_result_is_err(null_r));
    CHECK(n00b_result_get_err(null_r) == N00B_JSON_ERR_ARG);

    auto type_r = n00b_json_object_entries(n00b_json_array_new());
    CHECK(n00b_result_is_err(type_r));
    CHECK(n00b_result_get_err(type_r) == N00B_JSON_ERR_TYPE);

    n00b_json_node_t *malformed = n00b_alloc(n00b_json_node_t);
    malformed->value = n00b_variant_set(n00b_json_value_t,
                                        n00b_json_object_t *,
                                        nullptr);
    auto state_r = n00b_json_object_entries(malformed);
    CHECK(n00b_result_is_err(state_r));
    CHECK(n00b_result_get_err(state_r) == N00B_JSON_ERR_STATE);

    CHECK(n00b_json_err_str(N00B_JSON_ERR_TYPE) != nullptr);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_object_entries();
    test_object_entries_errors();
    n00b_shutdown();
    return 0;
}
