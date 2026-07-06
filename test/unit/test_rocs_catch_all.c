/* test/unit/test_rocs_catch_all.c - WP-010 Phase 4 catch-all search. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/filter.h"
#include "internal/rocs/store.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

static n00b_store_schema_t *
schema_ok(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_vfs_t *
mounted_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_t *
open_store(n00b_store_schema_t *schema)
{
    auto store_r = n00b_store_open_vfs(mounted_vfs(), r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_store_t *
open_search_text_store(n00b_store_index_options_t *options)
{
    auto schema_r = n00b_store_schema_new(.search_text = true,
                                          .index_options = options);
    CHECK(n00b_result_is_ok(schema_r));
    return open_store(n00b_result_get(schema_r));
}

static n00b_filter_field_t *
field_ok(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) regex_r)
{
    CHECK(n00b_result_is_ok(regex_r));
    n00b_regex_t *regex = n00b_result_get(regex_r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_plan_predicate_t *
lower_ok(n00b_result_t(n00b_filter_t *) filter_r)
{
    CHECK(n00b_result_is_ok(filter_r));
    auto plan_r = n00b_filter_lower_to_plan(n00b_result_get(filter_r));
    CHECK(n00b_result_is_ok(plan_r));
    return n00b_result_get(plan_r);
}

static n00b_plan_predicate_t *
any_contains(n00b_string_t *term)
{
    return lower_ok(n00b_filter_contains(n00b_filter_any(), term));
}

static n00b_plan_predicate_t *
field_contains(n00b_string_t *field, n00b_string_t *term)
{
    return lower_ok(n00b_filter_contains(field_ok(field), term));
}

static n00b_plan_predicate_t *
or_any_contains_with_field_contains(n00b_string_t *any_term,
                                    n00b_string_t *field,
                                    n00b_string_t *field_term)
{
    auto any_r = n00b_filter_contains(n00b_filter_any(), any_term);
    CHECK(n00b_result_is_ok(any_r));
    auto field_r = n00b_filter_contains(field_ok(field), field_term);
    CHECK(n00b_result_is_ok(field_r));
    return lower_ok(n00b_filter_or(n00b_result_get(any_r),
                                   n00b_result_get(field_r),
                                   kw_func(n00b_filter_or)));
}

static n00b_plan_predicate_t *
not_or_any_contains_with_field_contains(n00b_string_t *any_term,
                                        n00b_string_t *field,
                                        n00b_string_t *field_term)
{
    auto any_r = n00b_filter_contains(n00b_filter_any(), any_term);
    CHECK(n00b_result_is_ok(any_r));
    auto field_r = n00b_filter_contains(field_ok(field), field_term);
    CHECK(n00b_result_is_ok(field_r));
    auto or_r = n00b_filter_or(n00b_result_get(any_r),
                               n00b_result_get(field_r),
                               kw_func(n00b_filter_or));
    CHECK(n00b_result_is_ok(or_r));
    return lower_ok(n00b_filter_not(n00b_result_get(or_r)));
}

static void
put_string(n00b_json_node_t *record,
           n00b_string_t    *field,
           n00b_string_t    *value)
{
    n00b_json_object_put_n00b(record,
                              field,
                              n00b_json_string_new_from_n00b(value));
}

static void
put_int(n00b_json_node_t *record, n00b_string_t *field, int64_t value)
{
    n00b_json_object_put_n00b(record, field, n00b_json_int_new(value));
}

static void
ingest(n00b_store_t *store, n00b_json_node_t *record)
{
    auto ingest_r = n00b_store_ingest(store, record);
    CHECK(n00b_result_is_ok(ingest_r));
}

static void
check_scan_impl(const char             *label,
                n00b_store_t          *store,
                n00b_plan_predicate_t *predicate,
                const uint64_t        *expected,
                uint64_t               expected_len,
                uint64_t               last_ordinal)
{
    auto scan_r = n00b_store_hot_tail_scan_after(store, predicate, nullptr);
    CHECK(n00b_result_is_ok(scan_r));
    n00b_store_hot_tail_scan_t scan = n00b_result_get(scan_r);
    CHECK(scan.matches != nullptr);
    if (n00b_list_len(*scan.matches) != expected_len) {
        n00b_printf("scan length mismatch ([|#|]): expected=[|#|] actual=[|#|] last=[|#|]",
                     n00b_string_from_cstr(label),
                     expected_len,
                     n00b_list_len(*scan.matches),
                     last_ordinal);
    }
    CHECK(n00b_list_len(*scan.matches) == expected_len);
    for (uint64_t i = 0; i < expected_len; i++) {
        n00b_store_pos_t pos = n00b_list_get(*scan.matches, i);
        CHECK(pos.ordinal == expected[i]);
    }
    CHECK(scan.has_last_observed);
    CHECK(scan.last_observed.ordinal == last_ordinal);
}

#define check_scan(store, predicate, expected, expected_len, last_ordinal)      \
    check_scan_impl(__func__,                                                  \
                    store,                                                     \
                    predicate,                                                 \
                    expected,                                                  \
                    expected_len,                                              \
                    last_ordinal)

static n00b_store_t *
sample_store(void)
{
    n00b_store_schema_t *schema = schema_ok();
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"message",
        .include_in_all = true)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"title",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"hidden",
        .index_kind = N00B_STORE_INDEX_FULLTEXT)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"plain")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"all",
        .index_kind = N00B_STORE_INDEX_FULLTEXT)));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"count",
        .include_in_all = true)));

    n00b_store_t *store = open_store(schema);

    n00b_json_node_t *r0 = n00b_json_object_new();
    put_string(r0, r"message", r"Alpha launch");
    put_string(r0, r"title", r"Beta signal");
    put_string(r0, r"hidden", r"Secret");
    put_string(r0, r"plain", r"DefaultOnly");
    put_string(r0, r"all", r"Collision");
    put_int(r0, r"count", 100);
    ingest(store, r0);

    n00b_json_node_t *r1 = n00b_json_object_new();
    put_string(r1, r"title", r"Gamma ALPHA");
    put_string(r1, r"hidden", r"Beta");
    put_string(r1, r"plain", r"Alpha");
    put_string(r1, r"all", r"Alpha");
    put_int(r1, r"count", 200);
    ingest(store, r1);

    n00b_json_node_t *r2 = n00b_json_object_new();
    put_string(r2, r"message", r"Prefixology");
    put_string(r2, r"title", r"Delta");
    put_string(r2, r"hidden", r"Alpha");
    put_string(r2, r"plain", r"Beta");
    put_string(r2, r"all", r"Collision");
    put_int(r2, r"count", 300);
    ingest(store, r2);

    n00b_json_node_t *r3 = n00b_json_object_new();
    put_string(r3, r"hidden", r"Secret");
    put_string(r3, r"plain", r"Alpha");
    put_string(r3, r"all", r"Alpha");
    put_int(r3, r"count", 400);
    ingest(store, r3);

    return store;
}

static void
test_any_identity_and_filter_validation(void)
{
    n00b_filter_field_t *any = n00b_filter_any();
    n00b_filter_field_t *all = field_ok(r"all");
    CHECK(any != nullptr);
    CHECK(all != nullptr);
    CHECK(any != all);

    auto any_name_r = n00b_filter_field_name(any);
    CHECK(n00b_result_is_ok(any_name_r));
    CHECK(!n00b_option_is_set(n00b_result_get(any_name_r)));

    auto all_name_r = n00b_filter_field_name(all);
    CHECK(n00b_result_is_ok(all_name_r));
    CHECK(n00b_option_is_set(n00b_result_get(all_name_r)));
    CHECK(n00b_unicode_str_eq(n00b_option_get(n00b_result_get(all_name_r)),
                              r"all"));

    CHECK_ERR(n00b_filter_contains(any, r""), N00B_FILTER_ERR_ARG);
    CHECK_ERR(n00b_filter_prefix(any, r"al"),
              N00B_FILTER_ERR_UNSUPPORTED);
    CHECK_ERR(n00b_filter_regex(any, regex_ok(n00b_regex_new(r"a.*"))),
              N00B_FILTER_ERR_UNSUPPORTED);
}

static void
test_catch_all_hot_scan_respects_schema_opt_in(void)
{
    n00b_store_t *store = sample_store();

    uint64_t alpha[] = {0, 1};
    check_scan(store, any_contains(r"ALPHA"), alpha, 2, 3);

    uint64_t beta[] = {0};
    check_scan(store, any_contains(r"beta"), beta, 1, 3);

    uint64_t prefixology[] = {2};
    check_scan(store, any_contains(r"prefixology"), prefixology, 1, 3);

    check_scan(store, any_contains(r"secret"), nullptr, 0, 3);
    check_scan(store, any_contains(r"defaultonly"), nullptr, 0, 3);
    check_scan(store, any_contains(r"collision"), nullptr, 0, 3);
    check_scan(store, any_contains(r"fix"), nullptr, 0, 3);
    check_scan(store, any_contains(r"alpha launch"), nullptr, 0, 3);
}

static void
test_named_all_field_is_not_catch_all(void)
{
    n00b_store_t *store = sample_store();

    uint64_t named_all[] = {0, 2};
    check_scan(store, field_contains(r"all", r"collision"), named_all, 2, 3);

    check_scan(store, any_contains(r"collision"), nullptr, 0, 3);
}

static void
test_or_residual_preserves_exact_catch_all_matches(void)
{
    n00b_store_t *store = sample_store();

    uint64_t expected[] = {0, 1};
    check_scan(store,
               or_any_contains_with_field_contains(r"alpha",
                                                   r"plain",
                                                   r"defaultonly"),
               expected,
               2,
               3);

    uint64_t not_expected[] = {2, 3};
    check_scan(store,
               not_or_any_contains_with_field_contains(r"alpha",
                                                       r"plain",
                                                       r"defaultonly"),
               not_expected,
               2,
               3);
}

static void
test_no_opt_in_schema_does_not_broad_scan_strings(void)
{
    n00b_store_schema_t *schema = schema_ok();
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"message")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"all",
        .index_kind = N00B_STORE_INDEX_FULLTEXT)));

    n00b_store_t      *store  = open_store(schema);
    n00b_json_node_t  *record = n00b_json_object_new();
    put_string(record, r"message", r"Alpha");
    put_string(record, r"all", r"Collision");
    ingest(store, record);

    check_scan(store, any_contains(r"alpha"), nullptr, 0, 0);
    check_scan(store, any_contains(r"collision"), nullptr, 0, 0);
}

static void
test_reserved_search_text_defaults_exact_and_split_terms(void)
{
    n00b_store_t *store = open_search_text_store(nullptr);

    n00b_json_node_t *record = n00b_json_object_new();
    put_string(record, r"message", r"hello.world/test");
    ingest(store, record);

    uint64_t hit[] = {0};
    check_scan(store, any_contains(r"hello.world/test"), hit, 1, 0);
    check_scan(store, any_contains(r"hello"), hit, 1, 0);
    check_scan(store, any_contains(r"world"), hit, 1, 0);
    check_scan(store, any_contains(r"test"), hit, 1, 0);
}

static void
test_reserved_search_text_options_gate_exact_and_split_terms(void)
{
    n00b_store_index_options_t split_only = {
        .exact_full_string = false,
        .split_terms       = true,
    };
    n00b_store_t *split_store = open_search_text_store(&split_only);
    n00b_json_node_t *split_record = n00b_json_object_new();
    put_string(split_record, r"message", r"split.only");
    ingest(split_store, split_record);

    uint64_t hit[] = {0};
    check_scan(split_store, any_contains(r"split.only"), nullptr, 0, 0);
    check_scan(split_store, any_contains(r"split"), hit, 1, 0);
    check_scan(split_store, any_contains(r"only"), hit, 1, 0);

    n00b_store_index_options_t exact_only = {
        .exact_full_string = true,
        .split_terms       = false,
    };
    n00b_store_t *exact_store = open_search_text_store(&exact_only);
    n00b_json_node_t *exact_record = n00b_json_object_new();
    put_string(exact_record, r"message", r"exact.only");
    ingest(exact_store, exact_record);

    check_scan(exact_store, any_contains(r"exact.only"), hit, 1, 0);
    check_scan(exact_store, any_contains(r"exact"), nullptr, 0, 0);
    check_scan(exact_store, any_contains(r"only"), nullptr, 0, 0);
}

static n00b_result_t(bool)
custom_term_hook(n00b_store_index_emit_t *emit,
                 n00b_string_t           *field_path,
                 n00b_json_node_t        *field_value,
                 void                    *ctx,
                 n00b_allocator_t        *scratch)
{
    (void)field_value;
    (void)ctx;
    if (n00b_unicode_str_eq(field_path, r"message")) {
        n00b_string_t *scratch_term =
            n00b_unicode_str_cat(r"hook-", r"alias", .allocator = scratch);
        return n00b_store_index_emit_term(emit,
                                          r"__n00b_search_text",
                                          scratch_term);
    }
    return n00b_result_ok(bool, true);
}

static void
test_reserved_search_text_generic_hook_terms_are_searchable(void)
{
    n00b_store_index_options_t hook_only = {
        .exact_full_string = false,
        .split_terms       = false,
        .term_hook         = custom_term_hook,
    };
    n00b_store_t *store = open_search_text_store(&hook_only);
    n00b_json_node_t *record = n00b_json_object_new();
    put_string(record, r"message", r"not-indexed-by-default");
    ingest(store, record);

    uint64_t hit[] = {0};
    check_scan(store, any_contains(r"hook-alias"), hit, 1, 0);
    check_scan(store, any_contains(r"not-indexed-by-default"), nullptr, 0, 0);
    check_scan(store, any_contains(r"indexed"), nullptr, 0, 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_any_identity_and_filter_validation();
    test_catch_all_hot_scan_respects_schema_opt_in();
    test_named_all_field_is_not_catch_all();
    test_or_residual_preserves_exact_catch_all_matches();
    test_no_opt_in_schema_does_not_broad_scan_strings();
    test_reserved_search_text_defaults_exact_and_split_terms();
    test_reserved_search_text_options_gate_exact_and_split_terms();
    test_reserved_search_text_generic_hook_terms_are_searchable();

    n00b_shutdown();
    return 0;
}
