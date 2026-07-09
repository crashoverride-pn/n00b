/*
 * test_json.c — Tests for JSON value types, parser, and encoder.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "parsers/json.h"
#include "core/runtime.h"

// ============================================================================
// Helpers
// ============================================================================

static n00b_json_node_t *
json_obj_get(n00b_json_node_t *obj, const char *key)
{
    return n00b_json_object_get_cstr(obj, key);
}

static n00b_allocator_t *
owner_of(void *ptr)
{
    auto owner_opt = n00b_mem_get_allocator(ptr);
    assert(n00b_option_is_set(owner_opt));
    return n00b_option_get(owner_opt);
}

static void
assert_owner(void *ptr, n00b_allocator_t *allocator)
{
    assert(owner_of(ptr) == allocator);
}

// ============================================================================
// Tests
// ============================================================================

static void
test_json_parse_object(void)
{
    const char *json = "{\"name\":\"test\",\"value\":42}";
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);

    assert(root != nullptr);
    assert(err == nullptr);
    assert(n00b_json_is_object(root));
    assert(n00b_json_length(root) == 2);

    // Check "name" key.
    n00b_json_node_t *name_val = json_obj_get(root, "name");
    assert(name_val != nullptr);
    assert(n00b_json_is_string(name_val));
    assert(strcmp(n00b_json_as_cstr(name_val), "test") == 0);

    // Check "value" key.
    n00b_json_node_t *value_val = json_obj_get(root, "value");
    assert(value_val != nullptr);
    assert(n00b_json_is_int(value_val));
    assert(n00b_json_as_i64(value_val) == 42);

    printf("  [PASS] json parse object\n");
}

static void
test_json_parse_array(void)
{
    const char *json = "[1, \"two\", true, null, 3.14]";
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);

    assert(root != nullptr);
    assert(err == nullptr);
    assert(n00b_json_is_array(root));
    assert(n00b_json_length(root) == 5);

    // Element 0: integer 1
    n00b_json_node_t *e0 = n00b_json_array_get(root, 0);
    assert(n00b_json_is_int(e0));
    assert(n00b_json_as_i64(e0) == 1);

    // Element 1: string "two"
    n00b_json_node_t *e1 = n00b_json_array_get(root, 1);
    assert(n00b_json_is_string(e1));
    assert(strcmp(n00b_json_as_cstr(e1), "two") == 0);

    // Element 2: true
    n00b_json_node_t *e2 = n00b_json_array_get(root, 2);
    assert(n00b_json_is_bool(e2));
    assert(n00b_json_as_bool(e2) == true);

    // Element 3: null
    n00b_json_node_t *e3 = n00b_json_array_get(root, 3);
    assert(n00b_json_is_null(e3));

    // Element 4: double 3.14
    n00b_json_node_t *e4 = n00b_json_array_get(root, 4);
    assert(n00b_json_is_double(e4));
    assert(fabs(n00b_json_as_f64(e4) - 3.14) < 0.001);

    printf("  [PASS] json parse array\n");
}

static void
test_json_parse_nested(void)
{
    const char *json = "{\"a\":{\"b\":[1,2,3]}}";
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);

    assert(root != nullptr);
    assert(n00b_json_is_object(root));

    n00b_json_node_t *a = json_obj_get(root, "a");
    assert(a != nullptr);
    assert(n00b_json_is_object(a));

    n00b_json_node_t *b = json_obj_get(a, "b");
    assert(b != nullptr);
    assert(n00b_json_is_array(b));
    assert(n00b_json_length(b) == 3);

    n00b_json_node_t *b0 = n00b_json_array_get(b, 0);
    assert(n00b_json_is_int(b0));
    assert(n00b_json_as_i64(b0) == 1);

    n00b_json_node_t *b2 = n00b_json_array_get(b, 2);
    assert(n00b_json_is_int(b2));
    assert(n00b_json_as_i64(b2) == 3);

    printf("  [PASS] json parse nested\n");
}

static void
test_json_parse_unicode(void)
{
    // \u0048\u0065 = "He"
    const char *json = "{\"s\":\"\\u0048\\u0065\"}";
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);

    assert(root != nullptr);
    assert(n00b_json_is_object(root));

    n00b_json_node_t *s = json_obj_get(root, "s");
    assert(s != nullptr);
    assert(n00b_json_is_string(s));
    assert(strcmp(n00b_json_as_cstr(s), "He") == 0);

    printf("  [PASS] json parse unicode escapes\n");
}

static void
test_json_parse_errors(void)
{
    const char *err = nullptr;

    // Empty input.
    assert(n00b_json_parse("", 0, &err) == nullptr);

    // Truncated object.
    assert(n00b_json_parse("{\"key\":", 7, &err) == nullptr);

    // Trailing content.
    assert(n00b_json_parse("123 456", 7, &err) == nullptr);

    // Leading zeros.
    assert(n00b_json_parse("01", 2, &err) == nullptr);

    // Invalid literal.
    assert(n00b_json_parse("tru", 3, &err) == nullptr);

    printf("  [PASS] json parse errors\n");
}

static void
test_json_encode_roundtrip(void)
{
    const char *json = "{\"key\":\"value\",\"num\":42,\"arr\":[1,true,null]}";
    const char *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);
    assert(root != nullptr);

    // Encode back.
    char *encoded = n00b_json_encode(root);
    assert(encoded != nullptr);

    // Re-parse the encoded output.
    n00b_json_node_t *root2 = n00b_json_parse(encoded, strlen(encoded), &err);
    assert(root2 != nullptr);
    assert(n00b_json_is_object(root2));

    // Verify a key from the roundtrip.
    n00b_json_node_t *key_val = json_obj_get(root2, "key");
    assert(key_val != nullptr);
    assert(n00b_json_is_string(key_val));
    assert(strcmp(n00b_json_as_cstr(key_val), "value") == 0);

    n00b_json_node_t *num_val = json_obj_get(root2, "num");
    assert(num_val != nullptr);
    assert(n00b_json_is_int(num_val));
    assert(n00b_json_as_i64(num_val) == 42);

    printf("  [PASS] json encode roundtrip\n");
}

static void
test_json_encode_pretty(void)
{
    n00b_json_node_t *obj = n00b_json_object_new();
    n00b_json_object_put(obj, "a", n00b_json_int_new(1));
    n00b_json_object_put(obj, "b", n00b_json_bool_new(true));

    char *compact = n00b_json_encode(obj);
    assert(compact != nullptr);
    // Compact should not contain newlines.
    assert(strchr(compact, '\n') == nullptr);

    char *pretty = n00b_json_encode(obj, .pretty = true, .indent = 2);
    assert(pretty != nullptr);
    // Pretty should contain newlines.
    assert(strchr(pretty, '\n') != nullptr);

    // Both should be valid JSON.
    const char *err = nullptr;
    assert(n00b_json_parse(compact, strlen(compact), &err) != nullptr);
    assert(n00b_json_parse(pretty, strlen(pretty), &err) != nullptr);

    printf("  [PASS] json encode pretty\n");
}

static void
test_json_string_new_from_n00b(void)
{
    // [1] Non-empty source string round-trips through encode/parse.
    n00b_string_t    *s = n00b_string_from_cstr("hello-from-n00b");
    n00b_json_node_t *n = n00b_json_string_new_from_n00b(s);
    assert(n != nullptr);
    assert(n00b_json_is_string(n));
    assert(n00b_json_as_string(n) != nullptr);
    assert(strcmp(n00b_json_as_cstr(n), "hello-from-n00b") == 0);

    // The copy must be independent of the source `n00b_string_t`.
    assert(n00b_json_as_cstr(n) != s->data);

    // [2] Empty source string yields a JSON empty string.
    n00b_string_t    *e = n00b_string_from_cstr("");
    n00b_json_node_t *en = n00b_json_string_new_from_n00b(e);
    assert(en != nullptr);
    assert(n00b_json_is_string(en));
    assert(n00b_json_as_string(en) != nullptr);
    assert(n00b_json_as_cstr(en)[0] == '\0');

    // [3] nullptr source — mirror n00b_json_string_new(nullptr) shape.
    n00b_json_node_t *nn = n00b_json_string_new_from_n00b(nullptr);
    assert(nn != nullptr);
    assert(n00b_json_is_string(nn));
    assert(n00b_json_as_string(nn) == nullptr);

    printf("  [PASS] json string_new_from_n00b\n");
}

static void
test_json_constructor_allocator(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size   = 32768,
                                         .use_gc = true,
                                         .name   = "test_json_ctor_alloc");
    n00b_allocator_t *allocator = (n00b_allocator_t *)arena;

    n00b_json_node_t *null_node =
        n00b_json_null_new(.allocator = allocator);
    assert_owner(null_node, allocator);

    n00b_json_node_t *int_node =
        n00b_json_int_new(42, .allocator = allocator);
    assert_owner(int_node, allocator);

    n00b_json_node_t *string_node =
        n00b_json_string_new_from_n00b(r"allocator",
                                       .allocator = allocator);
    assert_owner(string_node, allocator);
    assert_owner(n00b_json_as_string(string_node), allocator);

    n00b_json_node_t *array_node =
        n00b_json_array_new(.allocator = allocator);
    assert_owner(array_node, allocator);
    n00b_json_array_t *array = n00b_json_as_array(array_node);
    assert(array != nullptr);
    assert_owner(array->data, allocator);

    n00b_json_node_t *object_node =
        n00b_json_object_new(.allocator = allocator);
    assert_owner(object_node, allocator);
    n00b_json_object_t *object = n00b_json_as_object(object_node);
    assert(object != nullptr);
    assert_owner(object, allocator);

    n00b_json_object_put(object_node,
                         "key",
                         n00b_json_bool_new(true, .allocator = allocator));
    auto entries_r = n00b_json_object_entries(object_node,
                                             .allocator = allocator);
    assert(n00b_result_is_ok(entries_r));
    n00b_json_object_entry_list_t *entries = n00b_result_get(entries_r);
    assert(n00b_list_len(*entries) == 1);
    n00b_json_object_entry_t *entry = n00b_list_get(*entries, 0);
    assert_owner(entry, allocator);
    assert_owner(entry->key, allocator);
    assert_owner(entry->value, allocator);

    n00b_allocator_destroy(allocator);

    printf("  [PASS] json constructor allocator\n");
}

// Regression (WP-005): json parse/encode now free their scratch — parser
// `out`/`key`/`s` and encoder `e->buf` — through the allocator they were
// allocated from (the .allocator hint) instead of the global mmap-lookup path,
// and n00b_free's .allocator short-circuit was moved ahead of the baked-region
// check. Drive every one of those hinted-free sites through a dedicated
// allocator so a wrong-allocator / double free surfaces as a crash or wrong
// result here rather than silently in production. In N00B_DEBUG builds this
// also arms n00b_free's baked-region assertion on the hinted path.
static void
test_json_hinted_free_paths(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size   = 65536,
                                         .use_gc = true,
                                         .name   = "test_json_hinted_free");
    n00b_allocator_t *a   = (n00b_allocator_t *)arena;
    const char       *err = nullptr;

    // Parser error paths: each aborts mid-string and frees `out` via
    // .allocator = p->allocator (= a).
    const char *bad[] = {
        "{\"k\":\"\\x\"}",            // invalid escape character
        "{\"k\":\"\\u12\"}",          // invalid hex digit in unicode escape
        "{\"k\":\"abc",               // unterminated string
        "{\"k\":\"\\uD800x\"}",       // missing low surrogate
        "{\"k\":\"\\uD800\\uABCD\"}", // invalid low surrogate
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err = nullptr;
        assert(n00b_json_parse(bad[i], strlen(bad[i]), &err, .allocator = a)
               == nullptr);
    }

    // Success path with an escaped key and escaped value: frees `key` (after
    // building the key string) and `s` (after building the value string), both
    // via .allocator = a.
    const char *ok  = "{\"a\\tb\":\"c\\nd\",\"o\":{\"x\":[1,2,3]}}";
    err             = nullptr;
    n00b_json_node_t *root =
        n00b_json_parse(ok, strlen(ok), &err, .allocator = a);
    assert(root != nullptr);
    assert(err == nullptr);
    assert(n00b_json_is_object(root));
    n00b_json_node_t *o = json_obj_get(root, "o");
    assert(o != nullptr && n00b_json_is_object(o));

    // Encoder path: enc_ensure's doubling frees each superseded e->buf and
    // n00b_json_encode frees the final one, both via
    // .allocator = n00b_thread_scratch_pool() (a real reclaiming pool). Encode
    // a payload > 256 bytes to force a grow-free on top of the final free.
    char big[600];
    int  n = 0;
    n += snprintf(big + n, sizeof(big) - n, "[");
    for (int i = 0; i < 100; i++) {
        n += snprintf(big + n, sizeof(big) - n, "%s%d", i ? "," : "", i);
    }
    n += snprintf(big + n, sizeof(big) - n, "]");
    err = nullptr;
    n00b_json_node_t *arr =
        n00b_json_parse(big, (size_t)n, &err, .allocator = a);
    assert(arr != nullptr);
    assert(n00b_json_is_array(arr));
    assert(n00b_json_length(arr) == 100);
    char *enc = n00b_json_encode(arr);
    assert(enc != nullptr);
    assert(strlen(enc) > 256);

    // Re-use the allocator after all those frees; a mis-routed free would
    // corrupt it and surface as a crash or wrong result on this reparse.
    err = nullptr;
    n00b_json_node_t *again =
        n00b_json_parse(ok, strlen(ok), &err, .allocator = a);
    assert(again != nullptr);
    assert(n00b_json_is_object(again));

    n00b_allocator_destroy(a);

    printf("  [PASS] json hinted-free paths\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_json:\n");
    fflush(stdout);

    test_json_parse_object();    fflush(stdout);
    test_json_parse_array();     fflush(stdout);
    test_json_parse_nested();    fflush(stdout);
    test_json_parse_unicode();   fflush(stdout);
    test_json_parse_errors();    fflush(stdout);
    test_json_encode_roundtrip(); fflush(stdout);
    test_json_encode_pretty();   fflush(stdout);
    test_json_string_new_from_n00b(); fflush(stdout);
    test_json_constructor_allocator(); fflush(stdout);
    test_json_hinted_free_paths(); fflush(stdout);

    printf("All json tests passed.\n");
    n00b_shutdown();
    return 0;
}
