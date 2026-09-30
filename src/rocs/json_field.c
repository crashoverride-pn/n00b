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

static int
json_hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
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
            (*i)++;

            if (*i >= len) {
                return false;
            }

            char esc = d[*i];

            // The parser's set, and nothing else: skipping two bytes per
            // backslash would walk through `\}` and `\x`, which it rejects.
            if (esc == '"' || esc == '\\' || esc == '/' || esc == 'b'
                || esc == 'f' || esc == 'n' || esc == 'r' || esc == 't') {
                (*i)++;
                continue;
            }

            if (esc == 'u') {
                (*i)++;

                uint32_t cp = 0;

                for (int k = 0; k < 4; k++) {
                    if (*i >= len) {
                        return false;
                    }

                    int digit = json_hex_digit(d[*i]);

                    if (digit < 0) {
                        return false;
                    }
                    cp = (cp << 4) | (uint32_t)digit;
                    (*i)++;
                }

                // A surrogate half brings pairing rules with it. Declining is
                // cheaper than a second copy of them that could disagree.
                if (cp >= 0xD800 && cp <= 0xDFFF) {
                    return false;
                }
                continue;
            }

            return false;
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

// Exactly the word, and nothing about what follows: whether a value may end
// where it ends is the containing object's or array's rule to enforce.
static bool
json_scan_word(const char *d, size_t len, size_t *i, const char *word)
{
    size_t n = strlen(word);

    if (*i + n > len || memcmp(d + *i, word, n) != 0) {
        return false;
    }
    *i += n;

    return true;
}

// JSON's number grammar, spelled out. Taking any run of bytes that is not a
// delimiter would accept `12x3` and `tru`, which the parser rejects, and a
// record that scans clean and parses as an error is the whole thing this is
// built to avoid. Reading it stricter than the parser only costs a fallback.
static bool
json_scan_number(const char *d, size_t len, size_t *i)
{
    if (*i < len && d[*i] == '-') {
        (*i)++;
    }

    if (*i >= len) {
        return false;
    }

    if (d[*i] == '0') {
        (*i)++;
    }
    else if (d[*i] >= '1' && d[*i] <= '9') {
        while (*i < len && d[*i] >= '0' && d[*i] <= '9') {
            (*i)++;
        }
    }
    else {
        return false;
    }

    if (*i < len && d[*i] == '.') {
        (*i)++;

        if (*i >= len || d[*i] < '0' || d[*i] > '9') {
            return false;
        }
        while (*i < len && d[*i] >= '0' && d[*i] <= '9') {
            (*i)++;
        }
    }

    if (*i < len && (d[*i] == 'e' || d[*i] == 'E')) {
        (*i)++;

        if (*i < len && (d[*i] == '+' || d[*i] == '-')) {
            (*i)++;
        }
        if (*i >= len || d[*i] < '0' || d[*i] > '9') {
            return false;
        }
        while (*i < len && d[*i] >= '0' && d[*i] <= '9') {
            (*i)++;
        }
    }

    return true;
}

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

    if (c == 't') {
        return json_scan_word(d, len, i, "true");
    }
    if (c == 'f') {
        return json_scan_word(d, len, i, "false");
    }
    if (c == 'n') {
        return json_scan_word(d, len, i, "null");
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return json_scan_number(d, len, i);
    }

    // Punctuation where a value belongs, as in `{"a":1,"b":}`.
    return false;
}

// One pass over a flat object, looking for several keys at once. The object's
// bytes are data[0..len). Each key found fills its span; each key is looked for
// at the top of this object only.
//
// Runs to the closing brace even once every key is in hand. Stopping at a
// match would answer from a prefix, so a record that is well-formed up to the
// wanted field and broken after it would read here and fail a parse, and which
// of the two a caller got would depend on where in the record its field sat.
static rocs_json_scan_t
json_scan_object_keys(const char       *data,
                      size_t            len,
                      size_t            count,
                      const char      **keys,
                      const size_t     *key_lens,
                      rocs_json_span_t *out)
{
    for (size_t k = 0; k < count; k++) {
        out[k] = (rocs_json_span_t){};
    }

    size_t i = 0;

    if (!json_scan_skip_ws(data, len, &i) || data[i] != '{') {
        return ROCS_JSON_SCAN_UNSURE;
    }
    i++;

    if (!json_scan_skip_ws(data, len, &i)) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    if (data[i] == '}') {
        i++;
    }
    else {
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
            size_t match   = count;

            for (size_t k = 0; k < count; k++) {
                if (key_len == key_lens[k]
                    && memcmp(data + key_open + 1, keys[k], key_len) == 0) {
                    // Which of two same-named keys survives is the parser's
                    // convention, not something to restate here.
                    if (out[k].found) {
                        return ROCS_JSON_SCAN_UNSURE;
                    }
                    match = k;
                    break;
                }
            }

            if (!json_scan_skip_ws(data, len, &i) || data[i] != ':') {
                return ROCS_JSON_SCAN_UNSURE;
            }
            i++;

            if (!json_scan_skip_ws(data, len, &i)) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            size_t value_open = i;

            // The object is the first level of the parser's nesting budget,
            // so a value at the top of it sits at depth 1.
            if (!json_scan_value(data, len, &i, 1)) {
                return ROCS_JSON_SCAN_UNSURE;
            }

            if (match != count) {
                out[match] = (rocs_json_span_t){
                    .start = value_open,
                    .len   = i - value_open,
                    .found = true,
                };
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

    return ROCS_JSON_SCAN_FOUND;
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

    const char      *key     = field->data;
    size_t           key_len = field->u8_bytes;
    rocs_json_span_t span;

    if (json_scan_object_keys(data, len, 1, &key, &key_len, &span)
        != ROCS_JSON_SCAN_FOUND) {
        return ROCS_JSON_SCAN_UNSURE;
    }
    if (!span.found) {
        return ROCS_JSON_SCAN_ABSENT;
    }

    *out_start = span.start;
    *out_len   = span.len;

    return ROCS_JSON_SCAN_FOUND;
}

// Follow a dotted field's segments down from the span of its first one, the
// way rocs_json_object_get_field walks a parsed record: every segment but the
// last must name an object.
static rocs_json_scan_t
json_scan_descend(const char       *data,
                  n00b_string_t    *field,
                  size_t            first_end,
                  rocs_json_span_t *span)
{
    size_t start = first_end + 1;

    while (start <= field->u8_bytes) {
        size_t end = start;
        while (end < field->u8_bytes && field->data[end] != '.') {
            end++;
        }

        const char *value = data + span->start;
        if (span->len == 0 || value[0] != '{') {
            span->found = false;
            return ROCS_JSON_SCAN_ABSENT;
        }

        const char      *key     = field->data + start;
        size_t           key_len = end - start;
        rocs_json_span_t inner;

        if (json_scan_object_keys(value, span->len, 1, &key, &key_len, &inner)
            != ROCS_JSON_SCAN_FOUND) {
            return ROCS_JSON_SCAN_UNSURE;
        }
        if (!inner.found) {
            span->found = false;
            return ROCS_JSON_SCAN_ABSENT;
        }

        span->start += inner.start;
        span->len    = inner.len;
        start        = end + 1;
    }

    return ROCS_JSON_SCAN_FOUND;
}

// A field wants at most two top-level keys: its own name and, when dotted, its
// first segment. A literal, because ncc sizes stack roots only from one.
#define ROCS_JSON_SCAN_KEYS_MAX 16
static_assert(ROCS_JSON_SCAN_KEYS_MAX == 2 * ROCS_JSON_SCAN_FIELDS_MAX);

static size_t
json_scan_key_slot(const char **keys,
                   size_t      *key_lens,
                   size_t      *nkeys,
                   const char  *key,
                   size_t       key_len)
{
    for (size_t k = 0; k < *nkeys; k++) {
        if (key_lens[k] == key_len && memcmp(keys[k], key, key_len) == 0) {
            return k;
        }
    }
    keys[*nkeys]     = key;
    key_lens[*nkeys] = key_len;
    return (*nkeys)++;
}

rocs_json_scan_t
rocs_json_scan_fields(const char       *data,
                      size_t            len,
                      size_t            count,
                      n00b_string_t   **fields,
                      rocs_json_span_t *out)
{
    if (data == nullptr || fields == nullptr || out == nullptr
        || count > ROCS_JSON_SCAN_FIELDS_MAX) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    // Each field is wanted under its own name, and a dotted one also under its
    // first segment, which is where the walk starts when no key spells the
    // whole path. Two fields wanting the same key share its slot, so the pass
    // never sees one name twice and mistakes it for a repeated key.
    const char      *keys[ROCS_JSON_SCAN_KEYS_MAX];
    size_t           key_lens[ROCS_JSON_SCAN_KEYS_MAX];
    size_t           exact_slot[ROCS_JSON_SCAN_FIELDS_MAX];
    size_t           first_slot[ROCS_JSON_SCAN_FIELDS_MAX];
    size_t           first_end[ROCS_JSON_SCAN_FIELDS_MAX];
    rocs_json_span_t spans[ROCS_JSON_SCAN_KEYS_MAX];
    size_t           nkeys = 0;

    for (size_t f = 0; f < count; f++) {
        n00b_string_t *field = fields[f];

        if (field == nullptr || field->data == nullptr
            || field->u8_bytes == 0) {
            return ROCS_JSON_SCAN_UNSURE;
        }

        exact_slot[f] = json_scan_key_slot(keys, key_lens, &nkeys,
                                           field->data, field->u8_bytes);
        first_slot[f] = SIZE_MAX;
        if (!rocs_json_field_has_dot(field)
            || !rocs_json_field_name_valid(field)) {
            continue;
        }

        size_t dot = 0;
        while (field->data[dot] != '.') {
            dot++;
        }
        first_end[f]  = dot;
        first_slot[f] = json_scan_key_slot(keys, key_lens, &nkeys,
                                           field->data, dot);
    }

    if (json_scan_object_keys(data, len, nkeys, keys, key_lens, spans)
        != ROCS_JSON_SCAN_FOUND) {
        return ROCS_JSON_SCAN_UNSURE;
    }

    for (size_t f = 0; f < count; f++) {
        out[f] = spans[exact_slot[f]];
        if (out[f].found || first_slot[f] == SIZE_MAX) {
            continue;
        }

        rocs_json_span_t walk = spans[first_slot[f]];
        if (!walk.found) {
            continue;
        }
        if (json_scan_descend(data, fields[f], first_end[f], &walk)
            == ROCS_JSON_SCAN_UNSURE) {
            return ROCS_JSON_SCAN_UNSURE;
        }
        out[f] = walk;
    }

    return ROCS_JSON_SCAN_FOUND;
}
