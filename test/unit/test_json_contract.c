/*
 * test_json_contract.c — JSON request contract helper tests.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "adt/list.h"
#include "core/runtime.h"
#include "parsers/json_contract.h"

static n00b_json_node_t *
parse_json(const char *text)
{
    const char *err = nullptr;
    n00b_json_node_t *root = n00b_json_parse(text, strlen(text), &err);
    assert(root != nullptr);
    assert(err == nullptr);
    return root;
}

static bool
s_contains(n00b_string_t *s, const char *needle)
{
    return s != nullptr && strstr(s->data, needle) != nullptr;
}

static void
test_missing_required_field(void)
{
    n00b_json_contract_t *c = n00b_json_contract_new();
    n00b_json_node_t *root = parse_json("{\"kind\":\"test\"}");

    n00b_json_node_t *id = n00b_json_contract_required(
        c,
        root,
        r"id",
        N00B_JSON_CONTRACT_STRING);
    assert(id == nullptr);
    assert(!n00b_json_contract_ok(c));
    assert(n00b_json_contract_error_count(c) == 1);
    assert(s_contains(n00b_json_contract_error(c, 0), "id"));
    assert(s_contains(n00b_json_contract_error(c, 0), "missing required field"));
    printf("  [PASS] missing required field\n");
}

static void
test_wrong_type(void)
{
    n00b_json_contract_t *c = n00b_json_contract_new();
    n00b_json_node_t *root = parse_json("{\"id\":7}");

    n00b_json_node_t *id = n00b_json_contract_required(
        c,
        root,
        r"id",
        N00B_JSON_CONTRACT_STRING);
    assert(id == nullptr);
    assert(n00b_json_contract_error_count(c) == 1);
    assert(s_contains(n00b_json_contract_error(c, 0), "expected string"));
    assert(s_contains(n00b_json_contract_error(c, 0), "got int"));
    printf("  [PASS] wrong type diagnostic\n");
}

static void
test_null_handling(void)
{
    n00b_json_node_t *root = parse_json("{\"note\":null}");
    n00b_json_contract_t *c = n00b_json_contract_new();

    n00b_json_node_t *note = n00b_json_contract_required(
        c,
        root,
        r"note",
        N00B_JSON_CONTRACT_STRING,
        .nullable = true);
    assert(note != nullptr);
    assert(n00b_json_is_null(note));
    assert(n00b_json_contract_ok(c));

    c = n00b_json_contract_new();
    note = n00b_json_contract_required(c,
                                       root,
                                       r"note",
                                       N00B_JSON_CONTRACT_STRING);
    assert(note == nullptr);
    assert(!n00b_json_contract_ok(c));
    assert(s_contains(n00b_json_contract_error(c, 0), "got null"));
    printf("  [PASS] nullable and non-nullable handling\n");
}

static void
test_optional_default(void)
{
    n00b_json_contract_t *c = n00b_json_contract_new();
    n00b_json_node_t *root = parse_json("{\"kind\":\"test\"}");
    n00b_json_node_t *def  = n00b_json_int_new(3);

    n00b_json_node_t *retries = n00b_json_contract_optional(
        c,
        root,
        r"retries",
        N00B_JSON_CONTRACT_INT,
        def);
    assert(retries == def);
    assert(n00b_json_as_i64(retries) == 3);
    assert(n00b_json_contract_ok(c));
    printf("  [PASS] optional default\n");
}

static void
test_enum_validation(void)
{
    n00b_list_t(n00b_string_t *) allowed = n00b_list_new(n00b_string_t *);
    n00b_list_push(allowed, r"testing");
    n00b_list_push(allowed, r"static-analysis");

    n00b_json_contract_t *c = n00b_json_contract_new();
    n00b_json_node_t *root = parse_json("{\"kind\":\"testing\"}");
    n00b_json_node_t *kind = n00b_json_contract_required_enum(
        c,
        root,
        r"kind",
        &allowed);
    assert(kind != nullptr);
    assert(n00b_json_contract_ok(c));

    c = n00b_json_contract_new();
    root = parse_json("{\"kind\":\"unknown\"}");
    kind = n00b_json_contract_required_enum(c, root, r"kind", &allowed);
    assert(kind == nullptr);
    assert(!n00b_json_contract_ok(c));
    assert(s_contains(n00b_json_contract_error(c, 0), "allowed set"));
    printf("  [PASS] enum accept/reject\n");
}

static void
test_nested_diagnostic_path(void)
{
    n00b_json_contract_t *c = n00b_json_contract_new();
    n00b_json_node_t *root = parse_json("{\"tool\":{\"version\":7}}");
    n00b_json_node_t *tool = n00b_json_contract_required(
        c,
        root,
        r"tool",
        N00B_JSON_CONTRACT_OBJECT);
    assert(tool != nullptr);

    n00b_json_node_t *version = n00b_json_contract_required(
        c,
        tool,
        r"version",
        N00B_JSON_CONTRACT_STRING,
        .path = r"tool.version");
    assert(version == nullptr);
    assert(!n00b_json_contract_ok(c));
    assert(s_contains(n00b_json_contract_error(c, 0), "tool.version"));
    printf("  [PASS] nested diagnostic path\n");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_json_contract:\n");
    test_missing_required_field();
    test_wrong_type();
    test_null_handling();
    test_optional_default();
    test_enum_validation();
    test_nested_diagnostic_path();
    return 0;
}
