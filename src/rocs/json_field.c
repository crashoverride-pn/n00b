#include "internal/rocs/json_field.h"

static bool
rocs_json_field_has_dot(n00b_string_t *field)
{
    if (field == nullptr || field->data == nullptr) {
        return false;
    }

    for (size_t i = 0; i < field->u8_bytes; i++) {
        if (field->data[i] == '.') {
            return true;
        }
    }
    return false;
}

bool
rocs_json_field_name_valid(n00b_string_t *field)
{
    if (field == nullptr || field->data == nullptr || field->u8_bytes == 0) {
        return false;
    }

    bool previous_was_dot = true;
    for (size_t i = 0; i < field->u8_bytes; i++) {
        if (field->data[i] == '.') {
            if (previous_was_dot) {
                return false;
            }
            previous_was_dot = true;
            continue;
        }
        previous_was_dot = false;
    }

    return !previous_was_dot;
}

n00b_json_node_t *
rocs_json_object_get_field(n00b_json_node_t *record, n00b_string_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (record == nullptr || field == nullptr || !n00b_json_is_object(record)) {
        return nullptr;
    }

    n00b_json_node_t *exact = n00b_json_object_get(record, field);
    if (exact != nullptr || !rocs_json_field_has_dot(field)
        || !rocs_json_field_name_valid(field)) {
        return exact;
    }

    n00b_json_node_t *current = record;
    size_t            start   = 0;
    for (size_t i = 0; i <= field->u8_bytes; i++) {
        if (i != field->u8_bytes && field->data[i] != '.') {
            continue;
        }

        size_t segment_len = i - start;
        if (segment_len == 0 || !n00b_json_is_object(current)) {
            return nullptr;
        }

        n00b_string_t *segment =
            n00b_string_from_raw(field->data + start,
                                 (int64_t)segment_len,
                                 .allocator = allocator);
        current = n00b_json_object_get(current, segment);
        if (current == nullptr) {
            return nullptr;
        }
        start = i + 1;
    }

    return current;
}

// ---------------------------------------------------------------------------
// Scanning for one field, without building the record's node graph.
//
// Indexing reads exactly one field per index, so parsing the record builds
// every other field's value to throw it away, once per index. These walk the
// stored bytes to the wanted value and stop, leaving the parse to that value
// alone.
//
// Deliberately not a second JSON reader: anything it is not certain of, it
// declines, and the caller parses the record as before.

static bool
json_scan_skip_ws(const char *d, size_t len, size_t *i)
{
    while (*i < len) {
        char c = d[*i];

        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            return true;
        }
        (*i)++;
    }

    return false;
}

// Advances past a string that starts at d[*i] == '"', reporting whether it
// held a backslash. An escaped key does not compare byte-for-byte against a
// field name, so callers treat one as a case to decline.
static bool
json_scan_string(const char *d, size_t len, size_t *i, bool *escaped)
{
    if (*i >= len || d[*i] != '"') {
        return false;
    }

    *escaped = false;
    (*i)++;

    while (*i < len) {
        char c = d[*i];

        if (c == '\\') {
            *escaped = true;
            *i += 2;
            continue;
        }
        if (c == '"') {
            (*i)++;
            return true;
        }
        (*i)++;
    }

    return false;
}

// The parser's nesting budget, counting the record's own object as the first
// level (src/parsers/json.c, checked before the increment in parse_object and
// parse_array). The scan spends from the same budget so a record cannot scan
// clean and parse as an error.
#define ROCS_JSON_SCAN_MAX_DEPTH 256

static bool json_scan_value(const char *d, size_t len, size_t *i, size_t depth);

// The opening brace is already consumed. Keys must be strings, pairs must be
// separated the way the grammar says, and every value is validated in turn:
// bracket balance alone would accept `{"x" 1}` and `[1 2]`, which the parser
// rejects, and a record indexed off one field while another field's index
// errored on the same bytes is the divergence this exists to prevent.
static bool
json_scan_object(const char *d, size_t len, size_t *i, size_t depth)
{
    bool escaped;

    if (!json_scan_skip_ws(d, len, i)) {
        return false;
    }
    if (d[*i] == '}') {
        (*i)++;
        return true;
    }

    for (;;) {
        if (!json_scan_skip_ws(d, len, i)) {
            return false;
        }
        if (!json_scan_string(d, len, i, &escaped)) {
            return false;
        }
        if (!json_scan_skip_ws(d, len, i) || d[*i] != ':') {
            return false;
        }
        (*i)++;

        if (!json_scan_value(d, len, i, depth)) {
            return false;
        }
        if (!json_scan_skip_ws(d, len, i)) {
            return false;
        }
        if (d[*i] == ',') {
            (*i)++;
            continue;
        }
        if (d[*i] == '}') {
            (*i)++;
            return true;
        }

        return false;
    }
}

// The opening bracket is already consumed.
static bool
json_scan_array(const char *d, size_t len, size_t *i, size_t depth)
{
    if (!json_scan_skip_ws(d, len, i)) {
        return false;
    }
    if (d[*i] == ']') {
        (*i)++;
        return true;
    }

    for (;;) {
        if (!json_scan_value(d, len, i, depth)) {
            return false;
        }
        if (!json_scan_skip_ws(d, len, i)) {
            return false;
        }
        if (d[*i] == ',') {
            (*i)++;
            continue;
        }
        if (d[*i] == ']') {
            (*i)++;
            return true;
        }

        return false;
    }
}

// Advances past one value, rejecting anything the parser would reject.
//
// @p depth is the level of the container this value sits in, so a value at the
// top of a record is at depth 1. Recursion rather than a bracket counter,
// because validating a nested value is the same problem as validating this
// one, and the parser bounds the depth for both of us.
static bool
json_scan_value(const char *d, size_t len, size_t *i, size_t depth)
{
    bool escaped;

    if (!json_scan_skip_ws(d, len, i)) {
        return false;
    }

    char c = d[*i];

    if (c == '"') {
        return json_scan_string(d, len, i, &escaped);
    }

    if (c == '{' || c == '[') {
        if (depth + 1 > ROCS_JSON_SCAN_MAX_DEPTH) {
            return false;
        }
        (*i)++;

        return (c == '{') ? json_scan_object(d, len, i, depth + 1)
                          : json_scan_array(d, len, i, depth + 1);
    }

    // A number or one of the three literals: it ends where its container does.
    size_t literal_open = *i;

    while (*i < len) {
        char k = d[*i];

        if (k == ',' || k == '}' || k == ']' || k == ' ' || k == '\t'
            || k == '\n' || k == '\r') {
            break;
        }
        (*i)++;
    }

    // A value has to be made of something. Reaching here having consumed
    // nothing means punctuation stood where a value belongs, as in
    // `{"a":1,"b":}`, and that is a parse error rather than an empty value.
    return *i > literal_open;
}

rocs_json_scan_t
rocs_json_scan_field_span(const char    *data,
                          size_t         len,
                          n00b_string_t *field,
                          size_t        *out_start,
                          size_t        *out_len)
{
    if (data == nullptr || field == nullptr || field->data == nullptr
        || field->u8_bytes == 0 || rocs_json_field_has_dot(field)) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    size_t i = 0;

    if (!json_scan_skip_ws(data, len, &i) || data[i] != '{') {
        return ROCS_JSON_SCAN_UNSURE;
    }
    i++;

    bool   found       = false;
    size_t found_start = 0;
    size_t found_len   = 0;

    if (!json_scan_skip_ws(data, len, &i)) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    if (data[i] == '}') {
        i++;
    }
    else {
        // Runs to the closing brace even once the field is in hand. Stopping
        // at the match would answer from a prefix, so a record that is
        // well-formed up to the wanted field and broken after it would index
        // here and fail a parse, and which of the two a caller got would
        // depend on where in the record its field happened to sit.
        for (;;) {
            if (!json_scan_skip_ws(data, len, &i)) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            size_t key_open = i;
            bool   escaped  = false;

            if (!json_scan_string(data, len, &i, &escaped) || escaped) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            size_t key_len = (i - 1) - (key_open + 1);
            bool   match   = key_len == field->u8_bytes
                         && memcmp(data + key_open + 1, field->data, key_len)
                                == 0;

            if (match && found) {
                // Which of two same-named keys survives is the parser's
                // convention, not something to restate here.
                return ROCS_JSON_SCAN_UNSURE;
            }

            if (!json_scan_skip_ws(data, len, &i) || data[i] != ':') {
                return ROCS_JSON_SCAN_UNSURE;
            }
            i++;

            if (!json_scan_skip_ws(data, len, &i)) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            size_t value_open = i;

            // The record's own object is the first level of the parser's
            // nesting budget, so a value at the top of it sits at depth 1.
            if (!json_scan_value(data, len, &i, 1)) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            if (match) {
                found       = true;
                found_start = value_open;
                found_len   = i - value_open;
            }

            if (!json_scan_skip_ws(data, len, &i)) {
                return ROCS_JSON_SCAN_UNSURE;
            }
            if (data[i] == ',') {
                i++;
                continue;
            }
            if (data[i] == '}') {
                i++;
                break;
            }

            return ROCS_JSON_SCAN_UNSURE;
        }
    }

    // n00b_json_parse rejects anything after the value, so a record with
    // trailing bytes is an error there and must not be an answer here.
    if (json_scan_skip_ws(data, len, &i)) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    if (!found) {
        return ROCS_JSON_SCAN_ABSENT;
    }

    *out_start = found_start;
    *out_len   = found_len;

    return ROCS_JSON_SCAN_FOUND;
}
