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
