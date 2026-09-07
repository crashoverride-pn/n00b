/* test/unit/test_rocs_json_field_scan.c - the byte scan agrees with the parser.
 *
 * Indexing reads one field per index, and rocs_json_scan_field_span finds that
 * field without building the record's node graph. Two readers of the same
 * bytes is a correctness risk, so what is pinned here is agreement: where the
 * scan answers, it answers what a parse would have, and where it cannot, it
 * says so rather than guessing.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/json_field.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                      \
    } while (0)

// What a parse of the whole record says the field is, re-encoded, or nullptr
// when the record has no such field or does not parse. The comparison is on
// encoded output because that is what makes two node graphs the same answer.
static char *
by_parse(const char *json, const char *field)
{
    const char       *err  = nullptr;
    n00b_json_node_t *root = n00b_json_parse(json, strlen(json), &err);

    if (root == nullptr || err != nullptr) {
        return nullptr;
    }

    n00b_json_node_t *value
        = rocs_json_object_get_field(root, n00b_string_from_cstr(field));

    if (value == nullptr) {
        return nullptr;
    }

    return n00b_json_encode(value);
}

// What the scan says, or nullptr when it declined or found nothing.
static char *
by_scan(const char *json, const char *field, rocs_json_scan_t *outcome)
{
    size_t start = 0;
    size_t span  = 0;

    *outcome = rocs_json_scan_field_span(json,
                                         strlen(json),
                                         n00b_string_from_cstr(field),
                                         &start,
                                         &span);

    if (*outcome != ROCS_JSON_SCAN_FOUND) {
        return nullptr;
    }

    const char       *err   = nullptr;
    n00b_json_node_t *value = n00b_json_parse(json + start, span, &err);

    CHECK(value != nullptr && err == nullptr);

    return n00b_json_encode(value);
}

// A record the scan is expected to answer for: it must agree with the parse,
// both on the value and on the field being absent.
static void
agrees(const char *json, const char *field)
{
    rocs_json_scan_t outcome = ROCS_JSON_SCAN_UNSURE;
    char            *scanned = by_scan(json, field, &outcome);
    char            *parsed  = by_parse(json, field);

    CHECK(outcome != ROCS_JSON_SCAN_UNSURE);

    if (parsed == nullptr) {
        CHECK(outcome == ROCS_JSON_SCAN_ABSENT);
        return;
    }

    CHECK(outcome == ROCS_JSON_SCAN_FOUND);
    CHECK(scanned != nullptr);
    CHECK(strcmp(scanned, parsed) == 0);
}

// A record the scan is expected to hand back rather than answer for. The
// fallback is a full parse, so declining costs nothing but a slower path.
static void
declines(const char *json, const char *field)
{
    rocs_json_scan_t outcome = ROCS_JSON_SCAN_UNSURE;

    (void)by_scan(json, field, &outcome);
    CHECK(outcome == ROCS_JSON_SCAN_UNSURE);
}

static void
test_flat_records_agree(void)
{
    const char *rec = "{\"level\":\"info\",\"kind\":\"log\",\"n\":42,"
                      "\"ok\":true,\"z\":null}";

    agrees(rec, "level");
    agrees(rec, "kind");
    agrees(rec, "n");
    agrees(rec, "ok");
    agrees(rec, "z");
    agrees(rec, "absent");

    n00b_printf("  [PASS] every field of a flat record scans to what it parses");
}

static void
test_value_shapes_agree(void)
{
    // A field's value is skipped as often as it is taken, so each shape has to
    // be walked correctly whether or not it is the one being looked for.
    agrees("{\"a\":{\"nested\":{\"deep\":1}},\"b\":2}", "b");
    agrees("{\"a\":{\"nested\":{\"deep\":1}},\"b\":2}", "a");
    agrees("{\"a\":[1,[2,3],{\"k\":4}],\"b\":\"x\"}", "b");
    agrees("{\"a\":[1,[2,3],{\"k\":4}],\"b\":\"x\"}", "a");
    agrees("{\"a\":-1.5e10,\"b\":\"x\"}", "b");

    // A brace or a comma inside a string is text, not structure.
    agrees("{\"a\":\"}\",\"b\":\"x\"}", "b");
    agrees("{\"a\":\"a,b\",\"b\":\"x\"}", "b");

    // A string does not end at an escaped quote.
    agrees("{\"a\":\"say \\\"hi\\\"\",\"b\":\"x\"}", "b");
    agrees("{\"a\":\"trailing backslash \\\\\",\"b\":\"x\"}", "b");

    // Whitespace everywhere it is legal.
    agrees("{ \"a\" : 1 , \"b\" : 2 }", "b");
    agrees("\n{\n\"a\"\t:\r1\n}\n", "a");

    // An empty object has every field absent.
    agrees("{}", "a");
    agrees("  {  }  ", "a");

    n00b_printf("  [PASS] each value shape is walked the way the parser walks "
                "it");
}

static void
test_scan_declines_what_it_cannot_settle(void)
{
    // A dotted path descends, which the scan does not do.
    declines("{\"a\":{\"b\":1}}", "a.b");

    // An escaped key does not compare byte-for-byte against a field name.
    declines("{\"a\\u0062\":1,\"c\":2}", "c");

    // Which of two same-named keys wins is the parser's convention.
    declines("{\"a\":1,\"a\":2}", "a");

    // Trailing bytes make the record a parse error, not a lookup.
    declines("{\"a\":1} tail", "a");

    // Not an object at all.
    declines("[1,2,3]", "a");
    declines("\"bare\"", "a");
    declines("", "a");

    n00b_printf("  [PASS] the scan declines a dotted path, an escaped or "
                "repeated key, and trailing bytes");
}

static void
test_damage_after_the_field_is_not_answered(void)
{
    // The wanted field is intact and sits before the damage. Answering from
    // the prefix would index a record a parse rejects, and would do so only
    // when the field happened to sit early enough.
    declines("{\"a\":1,\"b\":}", "a");
    declines("{\"a\":1,\"b\"}", "a");
    declines("{\"a\":1,,\"b\":2}", "a");
    declines("{\"a\":1,\"b\":[1,2}", "a");
    declines("{\"a\":1,\"b\":\"unterminated}", "a");
    declines("{\"a\":1", "a");

    // The same damage before the field is refused for the same reason.
    declines("{\"b\":,\"a\":1}", "a");

    n00b_printf("  [PASS] damage anywhere in the record is declined, not "
                "answered from a clean prefix");
}

// Damage one level in is still damage. Bracket balance alone accepts all of
// these, and accepting them means an index on `a` succeeds while an index on
// `b` errors on the very same record, which is the divergence the whole scan
// is built to avoid.
static void
test_damage_inside_another_value_is_not_answered(void)
{
    declines("{\"a\":1,\"b\":[1 2]}", "a");
    declines("{\"a\":1,\"b\":{\"x\" 1}}", "a");
    declines("{\"a\":1,\"b\":[,]}", "a");
    declines("{\"a\":1,\"b\":{1:2}}", "a");
    declines("{\"a\":1,\"b\":{\"x\":}}", "a");
    declines("{\"a\":1,\"b\":[1,]}", "a");
    declines("{\"a\":1,\"b\":{\"x\":1,}}", "a");
    declines("{\"a\":1,\"b\":[[1 2]]}", "a");
    declines("{\"a\":1,\"b\":{\"x\":{\"y\" 1}}}", "a");

    // The well-formed shapes those are mangled from still answer, so the
    // check above is rejecting the damage and not the shape.
    agrees("{\"a\":1,\"b\":[1,2]}", "a");
    agrees("{\"a\":1,\"b\":{\"x\":1}}", "a");
    agrees("{\"a\":1,\"b\":[]}", "a");
    agrees("{\"a\":1,\"b\":{}}", "a");
    agrees("{\"a\":1,\"b\":[[1,2]]}", "a");
    agrees("{\"a\":1,\"b\":{\"x\":{\"y\":1}}}", "a");

    n00b_printf("  [PASS] damage inside another field's value is declined too");
}

// Both readers spend one nesting level on the record's own object, so the
// seam between accepted and refused has to fall in the same place for both.
// Probing either side of it is the only way to catch an off-by-one.
static void
test_the_depth_seam_falls_where_the_parser_puts_it(void)
{
    for (size_t nest = 253; nest <= 258; nest++) {
        char   buf[600];
        size_t at = 0;

        memcpy(buf + at, "{\"a\":", 5);
        at += 5;

        for (size_t i = 0; i < nest; i++) {
            buf[at++] = '[';
        }
        for (size_t i = 0; i < nest; i++) {
            buf[at++] = ']';
        }

        memcpy(buf + at, ",\"b\":1}", 7);
        at += 7;
        buf[at] = '\0';

        rocs_json_scan_t outcome = ROCS_JSON_SCAN_UNSURE;
        char            *scanned = by_scan(buf, "b", &outcome);
        char            *parsed  = by_parse(buf, "b");

        // Where the parser has no answer, neither may the scan.
        if (parsed == nullptr) {
            CHECK(outcome == ROCS_JSON_SCAN_UNSURE);
            continue;
        }

        CHECK(outcome == ROCS_JSON_SCAN_FOUND);
        CHECK(scanned != nullptr);
        CHECK(strcmp(scanned, parsed) == 0);
    }

    n00b_printf("  [PASS] the depth both readers refuse is the same depth");
}

static void
test_nesting_past_the_parser_stops_both(void)
{
    // Past the parser's own depth limit, so the record has no parse and the
    // scan must not offer an answer where there is none.
    enum { DEPTH = 300 };

    char   buf[DEPTH * 2 + 32];
    size_t at = 0;

    memcpy(buf + at, "{\"a\":", 5);
    at += 5;

    for (size_t i = 0; i < DEPTH; i++) {
        buf[at++] = '[';
    }
    for (size_t i = 0; i < DEPTH; i++) {
        buf[at++] = ']';
    }

    memcpy(buf + at, ",\"b\":1}", 7);
    at += 7;
    buf[at] = '\0';

    CHECK(by_parse(buf, "b") == nullptr);
    declines(buf, "b");

    n00b_printf("  [PASS] a record too deep to parse is too deep to scan");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_flat_records_agree();
    test_value_shapes_agree();
    test_scan_declines_what_it_cannot_settle();
    test_damage_after_the_field_is_not_answered();
    test_damage_inside_another_value_is_not_answered();
    test_the_depth_seam_falls_where_the_parser_puts_it();
    test_nesting_past_the_parser_stops_both();

    n00b_shutdown();
    return 0;
}
