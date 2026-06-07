/*
 * test_json.c — Tests for JSON value types, parser, and encoder.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include "n00b.h"
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

    printf("All json tests passed.\n");
    n00b_shutdown();
    return 0;
}
