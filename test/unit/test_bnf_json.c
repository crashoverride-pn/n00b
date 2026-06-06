// test_bnf_json.c — End-to-end test: load JSON BNF, parse JSON strings,
//                   walk parse trees, verify results.

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "slay/pwz.h"
#include "slay/parse_tree.h"
#include "slay/parse_forest.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "internal/slay/grammar_internal.h"

// ============================================================================
// Simple JSON value representation for testing
// ============================================================================

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

typedef struct json_value_t json_value_t;

typedef struct {
    char         *key;
    json_value_t *value;
} json_pair_t;

struct json_value_t {
    json_type_t type;
    union {
        bool          boolean;
        double        number;
        char         *string;
        struct {
            json_value_t **data;
            size_t         len;
            size_t         cap;
        } array;
        struct {
            json_pair_t *data;
            size_t       len;
            size_t       cap;
        } object;
    };
};

// ============================================================================
// JSON value constructors and helpers
// ============================================================================

static json_value_t *
json_new(json_type_t type)
{
    json_value_t *v = n00b_alloc(json_value_t);

    *v    = (json_value_t){0};
    v->type = type;
    return v;
}

static json_value_t *
json_null(void)
{
    return json_new(JSON_NULL);
}

static json_value_t *
json_bool(bool b)
{
    json_value_t *v = json_new(JSON_BOOL);
    v->boolean      = b;
    return v;
}

static json_value_t *
json_string(const char *s)
{
    json_value_t *v = json_new(JSON_STRING);
    v->string       = strdup(s);
    return v;
}

static json_value_t *
json_array_new(void)
{
    return json_new(JSON_ARRAY);
}

static void
json_array_push(json_value_t *arr, json_value_t *item)
{
    if (arr->array.len >= arr->array.cap) {
        size_t new_cap = arr->array.cap ? arr->array.cap * 2 : 4;
        json_value_t **new_data = realloc(arr->array.data,
                                          new_cap * sizeof(json_value_t *));
        arr->array.data = new_data;
        arr->array.cap  = new_cap;
    }
    arr->array.data[arr->array.len++] = item;
}

static json_value_t *
json_object_new(void)
{
    return json_new(JSON_OBJECT);
}

static void
json_object_put(json_value_t *obj, const char *key, json_value_t *value)
{
    if (obj->object.len >= obj->object.cap) {
        size_t new_cap = obj->object.cap ? obj->object.cap * 2 : 4;
        json_pair_t *new_data = realloc(obj->object.data,
                                        new_cap * sizeof(json_pair_t));
        obj->object.data = new_data;
        obj->object.cap  = new_cap;
    }
    obj->object.data[obj->object.len++] = (json_pair_t){
        .key   = strdup(key),
        .value = value,
    };
}

static json_value_t *
json_object_get(json_value_t *obj, const char *key)
{
    for (size_t i = 0; i < obj->object.len; i++) {
        if (strcmp(obj->object.data[i].key, key) == 0) {
            return obj->object.data[i].value;
        }
    }
    return NULL;
}

static void
json_free(json_value_t *v)
{
    if (!v) {
        return;
    }

    switch (v->type) {
    case JSON_STRING:
        free(v->string);
        break;
    case JSON_ARRAY:
        for (size_t i = 0; i < v->array.len; i++) {
            json_free(v->array.data[i]);
        }
        free(v->array.data);
        break;
    case JSON_OBJECT:
        for (size_t i = 0; i < v->object.len; i++) {
            free(v->object.data[i].key);
            json_free(v->object.data[i].value);
        }
        free(v->object.data);
        break;
    default:
        break;
    }

    n00b_free(v);
}

// ============================================================================
// Walk actions to build json_value_t from parse trees
// ============================================================================

// chars -> "" | __JSON_STR chars | "\\" __PRINTABLE chars
static void *
chars_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_string("");
    }

    if (pn->rule_index == 0) {
        // chars -> "" (empty)
        n00b_free(kids);
        return json_string("");
    }

    if (pn->rule_index == 1) {
        // chars -> __JSON_STR chars
        n00b_token_info_t *tok  = (n00b_token_info_t *)kids[0];
        json_value_t      *rest = (json_value_t *)kids[1];
        char               c    = (tok && n00b_option_is_set(tok->value))
                                      ? n00b_option_get(tok->value)->data[0]
                                      : '?';

        const char *rest_str = (rest && rest->type == JSON_STRING)
                                   ? rest->string
                                   : "";
        size_t      rlen = strlen(rest_str);
        char       *buf  = malloc(rlen + 2);

        buf[0] = c;
        memcpy(buf + 1, rest_str, rlen + 1);

        json_value_t *result = json_string(buf);
        free(buf);
        json_free(rest);
        n00b_free(kids);
        return result;
    }

    // chars -> "\\" __PRINTABLE chars
    n00b_token_info_t *escaped = (n00b_token_info_t *)kids[1];
    json_value_t      *rest    = (json_value_t *)kids[2];
    char               c       = (escaped && n00b_option_is_set(escaped->value))
                                      ? n00b_option_get(escaped->value)->data[0]
                                      : '?';

    char actual;
    switch (c) {
    case 'n':  actual = '\n'; break;
    case 't':  actual = '\t'; break;
    case 'r':  actual = '\r'; break;
    case '\\': actual = '\\'; break;
    case '"':  actual = '"';  break;
    case '/':  actual = '/';  break;
    default:   actual = c;    break;
    }

    const char *rest_str = (rest && rest->type == JSON_STRING)
                               ? rest->string
                               : "";
    size_t      rlen = strlen(rest_str);
    char       *buf  = malloc(rlen + 2);

    buf[0] = actual;
    memcpy(buf + 1, rest_str, rlen + 1);

    json_value_t *result = json_string(buf);
    free(buf);
    json_free(rest);
    n00b_free(kids);
    return result;
}

// string -> '"' chars '"'
static void *
string_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)pn;
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_string("");
    }

    // kids[0] = '"', kids[1] = chars result, kids[2] = '"'
    json_value_t *chars_val = (json_value_t *)kids[1];
    json_value_t *result;

    if (chars_val && chars_val->type == JSON_STRING) {
        result = json_string(chars_val->string);
    }
    else {
        result = json_string("");
    }

    json_free(chars_val);
    n00b_free(kids);
    return result;
}

// value -> object | array | string | number | "true" | "false" | "null"
static void *
value_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_null();
    }

    json_value_t *result;

    switch (pn->rule_index) {
    case 0: // object
    case 1: // array
    case 2: // string
        result = (json_value_t *)kids[0];
        break;
    case 3: // number
        result = (json_value_t *)kids[0];
        if (!result || result->type != JSON_NUMBER) {
            result = json_null(); // Numbers not fully implemented.
        }
        break;
    case 4: // "true"
        result = json_bool(true);
        break;
    case 5: // "false"
        result = json_bool(false);
        break;
    case 6: // "null"
        result = json_null();
        break;
    default:
        result = json_null();
        break;
    }

    n00b_free(kids);
    return result;
}

// object -> "{" ws "}" | "{" members "}"
static void *
object_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_object_new();
    }

    json_value_t *result;

    if (pn->rule_index == 0) {
        result = json_object_new();
    }
    else {
        result = (json_value_t *)kids[1];
        if (!result) {
            result = json_object_new();
        }
    }

    n00b_free(kids);
    return result;
}

// members -> member | member "," members
static void *
members_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_object_new();
    }

    json_value_t *result;

    if (pn->rule_index == 0) {
        // members -> member
        result               = json_object_new();
        json_value_t *member = (json_value_t *)kids[0];
        if (member && member->type == JSON_OBJECT && member->object.len == 1) {
            json_object_put(result,
                            member->object.data[0].key,
                            member->object.data[0].value);
            member->object.data[0].value = NULL;
        }
        json_free(member);
    }
    else {
        // members -> member "," members
        result = (json_value_t *)kids[2];
        if (!result) {
            result = json_object_new();
        }
        json_value_t *member = (json_value_t *)kids[0];
        if (member && member->type == JSON_OBJECT && member->object.len == 1) {
            json_object_put(result,
                            member->object.data[0].key,
                            member->object.data[0].value);
            member->object.data[0].value = NULL;
        }
        json_free(member);
    }

    n00b_free(kids);
    return result;
}

// member -> ws string ws ":" ws value ws
static void *
member_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)pn;
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_object_new();
    }

    // kids: [0]=ws, [1]=string, [2]=ws, [3]=':', [4]=ws, [5]=value, [6]=ws
    json_value_t *key_val = (json_value_t *)kids[1];
    json_value_t *val     = (json_value_t *)kids[5];

    json_value_t *result = json_object_new();
    const char   *key    = (key_val && key_val->type == JSON_STRING)
                               ? key_val->string
                               : "";
    json_object_put(result, key, val ? val : json_null());

    kids[5] = NULL; // Ownership transferred.
    json_free(key_val);
    n00b_free(kids);
    return result;
}

// array -> "[" ws "]" | "[" elements "]"
static void *
array_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_array_new();
    }

    json_value_t *result;

    if (pn->rule_index == 0) {
        result = json_array_new();
    }
    else {
        result = (json_value_t *)kids[1];
        if (!result) {
            result = json_array_new();
        }
    }

    n00b_free(kids);
    return result;
}

// elements -> ws value ws | ws value ws "," elements
static void *
elements_action(n00b_nt_node_t *pn, void *children, void *thunk)
{
    (void)thunk;
    void **kids = (void **)children;

    if (!kids) {
        return json_array_new();
    }

    json_value_t *result;

    if (pn->rule_index == 0) {
        // elements -> ws value ws
        result = json_array_new();
        json_array_push(result, kids[1] ? kids[1] : (void *)json_null());
    }
    else {
        // elements -> ws value ws "," elements
        result = (json_value_t *)kids[4];
        if (!result) {
            result = json_array_new();
        }
        // Prepend: shift existing, insert at front.
        json_value_t *item = kids[1] ? kids[1] : (void *)json_null();
        json_array_push(result, item);
        size_t n = result->array.len;
        if (n > 1) {
            memmove(result->array.data + 1,
                    result->array.data,
                    (n - 1) * sizeof(json_value_t *));
            result->array.data[0] = item;
        }
    }

    kids[1] = NULL; // Ownership transferred.
    n00b_free(kids);
    return result;
}

// ============================================================================
// Character-level scanner for JSON parsing
// ============================================================================

static bool
char_scan(n00b_scanner_t *s)
{
    if (n00b_scan_at_eof(s)) {
        return false;
    }

    n00b_scan_mark(s);
    n00b_scan_advance(s);
    n00b_scan_emit(s);
    return true;
}

// ============================================================================
// Grammar setup
// ============================================================================

static n00b_grammar_t *
make_json_grammar(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    // Read the JSON BNF file.
    // Look relative to the source root — meson runs tests from the build dir.
    const char *paths[] = {
        "grammars/json.bnf",
        "../grammars/json.bnf",
        "../../grammars/json.bnf",
    };

    FILE *f = NULL;
    for (int i = 0; i < 3; i++) {
        f = fopen(paths[i], "r");
        if (f) break;
    }

    if (!f) {
        // Try from MESON_SOURCE_ROOT environment variable.
        const char *srcroot = getenv("MESON_SOURCE_ROOT");
        if (srcroot) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/grammars/json.bnf", srcroot);
            f = fopen(path, "r");
        }
    }

    if (!f) {
        printf("    Could not find grammars/json.bnf\n");
        n00b_grammar_free(g);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    fread(buf, 1, (size_t)len, f);
    buf[len] = '\0';
    fclose(f);

    n00b_string_t *bnf_text = n00b_string_from_cstr(buf);
    free(buf);

    bool ok = n00b_bnf_load(bnf_text, n00b_string_from_cstr("value"), g);
    if (!ok) {
        printf("    n00b_bnf_load failed\n");
        n00b_grammar_free(g);
        return NULL;
    }

    // Set walk actions on the NTs we care about.
    n00b_nonterm_t *nt_value    = n00b_nonterm(g, n00b_string_from_cstr("value"));
    n00b_nonterm_t *nt_object   = n00b_nonterm(g, n00b_string_from_cstr("object"));
    n00b_nonterm_t *nt_members  = n00b_nonterm(g, n00b_string_from_cstr("members"));
    n00b_nonterm_t *nt_member   = n00b_nonterm(g, n00b_string_from_cstr("member"));
    n00b_nonterm_t *nt_array    = n00b_nonterm(g, n00b_string_from_cstr("array"));
    n00b_nonterm_t *nt_elements = n00b_nonterm(g, n00b_string_from_cstr("elements"));
    n00b_nonterm_t *nt_string   = n00b_nonterm(g, n00b_string_from_cstr("string"));
    n00b_nonterm_t *nt_chars    = n00b_nonterm(g, n00b_string_from_cstr("chars"));

    n00b_nonterm_set_action(nt_value, value_action);
    n00b_nonterm_set_action(nt_object, object_action);
    n00b_nonterm_set_action(nt_members, members_action);
    n00b_nonterm_set_action(nt_member, member_action);
    n00b_nonterm_set_action(nt_array, array_action);
    n00b_nonterm_set_action(nt_elements, elements_action);
    n00b_nonterm_set_action(nt_string, string_action);
    n00b_nonterm_set_action(nt_chars, chars_action);

    return g;
}

// ============================================================================
// Parse helper: JSON string → json_value_t
// ============================================================================

static json_value_t *
parse_json(n00b_grammar_t *g, const char *input)
{
    n00b_buffer_t *buf = n00b_buffer_from_cstr(input);
    n00b_scanner_t *sc = n00b_scanner_new(buf, char_scan, NULL);
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);

    n00b_parse_forest_t forest = n00b_pwz_parse_grammar(g, ts);

    if (n00b_parse_forest_count(&forest) < 1) {
        n00b_parse_forest_free(&forest);
        n00b_token_stream_free(ts);
        n00b_scanner_free(sc);
        return NULL;
    }

    json_value_t *result = n00b_parse_forest_walk_best(&forest, NULL);

    n00b_parse_forest_free(&forest);
    n00b_token_stream_free(ts);
    n00b_scanner_free(sc);
    return result;
}

// ============================================================================
// Tests
// ============================================================================

// 1. Grammar loads
static void
test_json_grammar_loads(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);
    n00b_grammar_free(g);
    printf("  [PASS] grammar_loads\n");
}

// 2. Parse simple literals: null, true, false
static void
test_json_literals(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v;

    v = parse_json(g, "null");
    assert(v != NULL);
    assert(v->type == JSON_NULL);
    json_free(v);

    v = parse_json(g, "true");
    assert(v != NULL);
    assert(v->type == JSON_BOOL);
    assert(v->boolean == true);
    json_free(v);

    v = parse_json(g, "false");
    assert(v != NULL);
    assert(v->type == JSON_BOOL);
    assert(v->boolean == false);
    json_free(v);

    n00b_grammar_free(g);
    printf("  [PASS] literals\n");
}

// 3. Parse strings
static void
test_json_strings(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v;

    v = parse_json(g, "\"hello\"");
    assert(v != NULL);
    assert(v->type == JSON_STRING);
    assert(strcmp(v->string, "hello") == 0);
    json_free(v);

    v = parse_json(g, "\"\"");
    assert(v != NULL);
    assert(v->type == JSON_STRING);
    assert(strcmp(v->string, "") == 0);
    json_free(v);

    v = parse_json(g, "\"a b c\"");
    assert(v != NULL);
    assert(v->type == JSON_STRING);
    assert(strcmp(v->string, "a b c") == 0);
    json_free(v);

    n00b_grammar_free(g);
    printf("  [PASS] strings\n");
}

// 4. Parse empty array
static void
test_json_empty_array(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "[]");
    assert(v != NULL);
    assert(v->type == JSON_ARRAY);
    assert(v->array.len == 0);
    json_free(v);

    n00b_grammar_free(g);
    printf("  [PASS] empty_array\n");
}

// 5. Parse array with elements
static void
test_json_array(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "[true, false, null]");
    assert(v != NULL);
    assert(v->type == JSON_ARRAY);
    assert(v->array.len == 3);
    assert(v->array.data[0]->type == JSON_BOOL);
    assert(v->array.data[0]->boolean == true);
    assert(v->array.data[1]->type == JSON_BOOL);
    assert(v->array.data[1]->boolean == false);
    assert(v->array.data[2]->type == JSON_NULL);
    json_free(v);

    n00b_grammar_free(g);
    printf("  [PASS] array\n");
}

// 6. Parse empty object
static void
test_json_empty_object(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "{}");
    assert(v != NULL);
    assert(v->type == JSON_OBJECT);
    assert(v->object.len == 0);
    json_free(v);

    n00b_grammar_free(g);
    printf("  [PASS] empty_object\n");
}

// 7. Parse object with members
static void
test_json_object(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "{\"name\": \"n00b\", \"ok\": true}");
    assert(v != NULL);
    assert(v->type == JSON_OBJECT);
    assert(v->object.len == 2);

    json_value_t *name = json_object_get(v, "name");
    assert(name != NULL);
    assert(name->type == JSON_STRING);
    assert(strcmp(name->string, "n00b") == 0);

    json_value_t *ok = json_object_get(v, "ok");
    assert(ok != NULL);
    assert(ok->type == JSON_BOOL);
    assert(ok->boolean == true);

    json_free(v);
    n00b_grammar_free(g);
    printf("  [PASS] object\n");
}

// 8. Parse nested structure
static void
test_json_nested(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "{\"a\": [true, null]}");
    assert(v != NULL);
    assert(v->type == JSON_OBJECT);

    json_value_t *a = json_object_get(v, "a");
    assert(a != NULL);
    assert(a->type == JSON_ARRAY);
    assert(a->array.len == 2);
    assert(a->array.data[0]->type == JSON_BOOL);
    assert(a->array.data[1]->type == JSON_NULL);

    json_free(v);
    n00b_grammar_free(g);
    printf("  [PASS] nested\n");
}

// 9. Reject invalid JSON
static void
test_json_invalid(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v;

    v = parse_json(g, "");
    assert(v == NULL);

    v = parse_json(g, "{");
    assert(v == NULL);

    v = parse_json(g, "[,]");
    assert(v == NULL);

    n00b_grammar_free(g);
    printf("  [PASS] invalid\n");
}

// 10. Parse string array
static void
test_json_string_array(void)
{
    n00b_grammar_t *g = make_json_grammar();
    assert(g != NULL);

    json_value_t *v = parse_json(g, "[\"hello\", \"world\"]");
    assert(v != NULL);
    assert(v->type == JSON_ARRAY);
    assert(v->array.len == 2);
    assert(v->array.data[0]->type == JSON_STRING);
    assert(strcmp(v->array.data[0]->string, "hello") == 0);
    assert(v->array.data[1]->type == JSON_STRING);
    assert(strcmp(v->array.data[1]->string, "world") == 0);

    json_free(v);
    n00b_grammar_free(g);
    printf("  [PASS] string_array\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("BNF JSON end-to-end tests:\n");

    test_json_grammar_loads();
    test_json_literals();
    test_json_strings();
    test_json_empty_array();
    test_json_array();
    test_json_empty_object();
    test_json_object();
    test_json_nested();
    test_json_invalid();
    test_json_string_array();

    printf("All BNF JSON tests passed.\n");
    n00b_shutdown();
    return 0;
}
