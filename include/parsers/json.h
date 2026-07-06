/**
 * @file json.h
 * @brief JSON value types, recursive descent parser, and encoder.
 *
 * Provides:
 * - Variant-backed `n00b_json_node_t` value type
 * - Recursive descent parser (`n00b_json_parse`)
 * - JSON encoder (`n00b_json_encode`)
 * - Constructors and accessors for building/querying value trees
 *
 * ### Usage
 *
 * ```c
 * const char       *err  = nullptr;
 * n00b_json_node_t *root = n00b_json_parse("{\"key\": 42}", 11, &err);
 * if (root != nullptr) {
 *     // ...
 * }
 * ```
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "adt/result.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "adt/variant.h"

// ============================================================================
// JSON value type
// ============================================================================

/**
 * @brief JSON value type tags.
 */
typedef enum {
    N00B_JSON_NULL,    /**< JSON null. */
    N00B_JSON_BOOL,    /**< JSON boolean. */
    N00B_JSON_INT,     /**< JSON integer (int64_t). */
    N00B_JSON_DOUBLE,  /**< JSON floating-point (double). */
    N00B_JSON_STRING,  /**< JSON string. */
    N00B_JSON_ARRAY,   /**< JSON array. */
    N00B_JSON_OBJECT,  /**< JSON object. */
} n00b_json_type_t;

/**
 * @brief Error domain for fallible JSON helper APIs.
 *
 * @post Codes are stable public result errors for JSON helper functions.
 */
typedef enum : int32_t {
    N00B_JSON_OK        = 0,
    N00B_JSON_ERR_ARG   = -1,
    N00B_JSON_ERR_TYPE  = -2,
    N00B_JSON_ERR_STATE = -3,
} n00b_json_err_t;

typedef struct n00b_json_node n00b_json_node_t;

/**
 * @brief Distinct variant payload used to represent JSON null.
 */
typedef struct {
    uint8_t reserved;
} n00b_json_null_t;

/**
 * @brief Typed JSON array payload.
 *
 * Arrays contain recursive JSON node handles.
 */
typedef n00b_list_t(n00b_json_node_t *) n00b_json_array_t;

/**
 * @brief Typed JSON object payload.
 *
 * Object keys are n00b strings; values are recursive JSON node handles.
 */
typedef n00b_dict_t(n00b_string_t *, n00b_json_node_t *) n00b_json_object_t;

/**
 * @brief One borrowed JSON object entry.
 *
 * Entries returned by `n00b_json_object_entries` borrow the key and value from
 * the object. The entry objects and list are newly allocated; the JSON tree
 * owns the pointed-to key/value payloads.
 *
 * @post `key` and `value` point into the source object and must not be treated
 *       as separately owned by the entry wrapper.
 */
typedef struct {
    n00b_string_t    *key;
    n00b_json_node_t *value;
} n00b_json_object_entry_t;

/** @brief List of borrowed JSON object entries. */
typedef n00b_list_t(n00b_json_object_entry_t *) n00b_json_object_entry_list_t;

/**
 * @brief JSON node variant payload.
 */
typedef n00b_variant_t(n00b_json_null_t,
                       bool,
                       int64_t,
                       double,
                       n00b_string_t *,
                       n00b_json_array_t,
                       n00b_json_object_t *) n00b_json_value_t;

/**
 * @brief JSON value — tagged variant of all JSON types.
 *
 * All nodes are GC-allocated. The variant selector is the JSON kind; there is
 * no parallel type field.
 * Strings are stored as n00b strings, arrays are typed lists of recursive node
 * handles, and objects are typed dictionaries keyed by n00b strings.
 */
struct n00b_json_node {
    n00b_json_value_t value; /**< Variant payload; selector carries the kind. */
};

// ============================================================================
// Constructors
// ============================================================================

/**
 * @brief Construct a JSON null node.
 *
 * @kw allocator Allocator for the node.
 */
extern n00b_json_node_t *
n00b_json_null_new() _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Construct a JSON boolean node.
 *
 * @param val Boolean payload.
 * @kw allocator Allocator for the node.
 */
extern n00b_json_node_t *
n00b_json_bool_new(bool val) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a JSON signed-integer node.
 *
 * @param val Integer payload.
 * @kw allocator Allocator for the node.
 */
extern n00b_json_node_t *
n00b_json_int_new(int64_t val) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a JSON double node.
 *
 * @param val Floating-point payload.
 * @kw allocator Allocator for the node.
 */
extern n00b_json_node_t *
n00b_json_double_new(double val) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a JSON string node from a C string.
 *
 * @param val Source C string. Passing `nullptr` stores a null string payload.
 * @kw allocator Allocator for the node and copied string payload.
 */
extern n00b_json_node_t *
n00b_json_string_new(const char *val) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an empty JSON array node.
 *
 * @kw allocator Allocator for the node and array backing storage.
 */
extern n00b_json_node_t *
n00b_json_array_new() _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Construct an empty JSON object node.
 *
 * @kw allocator Allocator for the node, object dictionary, and dictionary
 *               backing storage.
 */
extern n00b_json_node_t *
n00b_json_object_new() _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Construct a JSON string node directly from an `n00b_string_t *`.
 *
 * Copies the source bytes into a fresh `n00b_string_t` payload. This keeps
 * JSON strings in the same representation as parsed JSON and avoids leaking
 * the caller's string lifetime into the JSON tree.
 *
 * @param s  Source string. Passing `nullptr` returns a JSON string node with
 *           a null string payload (mirrors `n00b_json_string_new(nullptr)`).
 *
 * @kw allocator Allocator for the node and copied string payload.
 *
 * @return A newly-allocated JSON string node.
 */
extern n00b_json_node_t *
n00b_json_string_new_from_n00b(n00b_string_t *s) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Mutation
// ============================================================================

void   n00b_json_array_push(n00b_json_node_t *arr, n00b_json_node_t *val);
void   n00b_json_object_put(n00b_json_node_t *obj, const char *key,
                             n00b_json_node_t *val);
void   n00b_json_object_put_n00b(n00b_json_node_t *obj, n00b_string_t *key,
                                 n00b_json_node_t *val);
size_t n00b_json_length(const n00b_json_node_t *val);

// ============================================================================
// Accessors
// ============================================================================

/**
 * @brief Return the JSON type tag derived from the variant selector.
 */
static inline n00b_json_type_t
n00b_json_type(const n00b_json_node_t *n)
{
    if (n == nullptr || n00b_variant_is_type(n->value, n00b_json_null_t)) {
        return N00B_JSON_NULL;
    }
    if (n00b_variant_is_type(n->value, bool)) {
        return N00B_JSON_BOOL;
    }
    if (n00b_variant_is_type(n->value, int64_t)) {
        return N00B_JSON_INT;
    }
    if (n00b_variant_is_type(n->value, double)) {
        return N00B_JSON_DOUBLE;
    }
    if (n00b_variant_is_type(n->value, n00b_string_t *)) {
        return N00B_JSON_STRING;
    }
    if (n00b_variant_is_type(n->value, n00b_json_array_t)) {
        return N00B_JSON_ARRAY;
    }
    if (n00b_variant_is_type(n->value, n00b_json_object_t *)) {
        return N00B_JSON_OBJECT;
    }
    return N00B_JSON_NULL;
}

/** @brief Return the boolean payload. */
static inline bool
n00b_json_as_bool(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, bool)
               ? n00b_variant_get(n->value, bool)
               : false;
}

/** @brief Return the signed integer payload. */
static inline int64_t
n00b_json_as_i64(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, int64_t)
               ? n00b_variant_get(n->value, int64_t)
               : 0;
}

/** @brief Return the floating-point payload. */
static inline double
n00b_json_as_f64(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, double)
               ? n00b_variant_get(n->value, double)
               : 0.0;
}

/** @brief Return the string payload, or @c nullptr if @p n is not a string. */
static inline n00b_string_t *
n00b_json_as_string(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_string_t *)
               ? n00b_variant_get(n->value, n00b_string_t *)
               : nullptr;
}

/**
 * @brief Return a borrowed NUL-terminated string pointer for legacy callers.
 */
static inline const char *
n00b_json_as_cstr(const n00b_json_node_t *n)
{
    n00b_string_t *s = n00b_json_as_string(n);
    return s == nullptr ? nullptr : s->data;
}

/** @brief Return the typed array payload, or @c nullptr for non-arrays. */
static inline n00b_json_array_t *
n00b_json_as_array(n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_array_t)
               ? &n->value.value.N00B_VARIANT_FIELD(n00b_json_array_t)
               : nullptr;
}

/** @brief Return the typed array payload, or @c nullptr for non-arrays. */
static inline const n00b_json_array_t *
n00b_json_as_array_const(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_array_t)
               ? &n->value.value.N00B_VARIANT_FIELD(n00b_json_array_t)
               : nullptr;
}

/** @brief Return the typed object payload, or @c nullptr for non-objects. */
static inline n00b_json_object_t *
n00b_json_as_object(n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_object_t *)
               ? n00b_variant_get(n->value, n00b_json_object_t *)
               : nullptr;
}

/** @brief Return the typed object payload, or @c nullptr for non-objects. */
static inline const n00b_json_object_t *
n00b_json_as_object_const(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_object_t *)
               ? n00b_variant_get(n->value, n00b_json_object_t *)
               : nullptr;
}

/**
 * @brief Look up a field in a JSON object.
 *
 * @return The borrowed parse-tree node for @p key, or @c nullptr when @p obj is
 *         not an object or the key is absent.
 */
extern n00b_json_node_t *
n00b_json_object_get(n00b_json_node_t *obj, n00b_string_t *key);

/**
 * @brief Look up a field in a JSON object using a NUL-terminated key.
 */
extern n00b_json_node_t *
n00b_json_object_get_cstr(n00b_json_node_t *obj, const char *key);

/**
 * @brief Static diagnostic string for a JSON helper error code.
 *
 * @param err A @c N00B_JSON_* code.
 * @pre `err` is expected to come from a JSON helper result.
 * @return A n00b string naming the code, or @c UNKNOWN for an unrecognized
 *         value.
 * @post The returned string is static and remains owned by the runtime.
 */
extern n00b_string_t *n00b_json_err_str(n00b_err_t err);

/**
 * @brief Return borrowed entries for a JSON object.
 *
 * @param obj JSON object node.
 * @kw allocator Allocator for the returned list and entry wrappers.
 *
 * @pre `obj` must be a non-null JSON object for success.
 * @return Ok(list) containing one borrowed entry per object field. Non-object
 *         nodes return @c N00B_JSON_ERR_TYPE; malformed object state returns
 *         @c N00B_JSON_ERR_STATE.
 * @post The returned list and wrappers are newly allocated. Entry keys and
 *       values are borrowed from `obj`, so callers must keep the JSON tree live
 *       while using them.
 */
extern n00b_result_t(n00b_json_object_entry_list_t *)
n00b_json_object_entries(n00b_json_node_t *obj) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the number of elements in a JSON array.
 */
static inline size_t
n00b_json_array_len(const n00b_json_node_t *n)
{
    const n00b_json_array_t *arr = n00b_json_as_array_const(n);
    return arr == nullptr ? 0 : n00b_list_len(*arr);
}

/**
 * @brief Return an array element, or @c nullptr for non-arrays/OOB indexes.
 */
static inline n00b_json_node_t *
n00b_json_array_get(n00b_json_node_t *n, size_t i)
{
    n00b_json_array_t *arr = n00b_json_as_array(n);
    if (arr == nullptr || i >= n00b_list_len(*arr)) {
        return nullptr;
    }
    return n00b_list_get(*arr, i);
}

// ============================================================================
// Type query
// ============================================================================

static inline bool n00b_json_is_null(const n00b_json_node_t *n)
{
    return n00b_json_type(n) == N00B_JSON_NULL;
}

static inline bool n00b_json_is_bool(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, bool);
}

static inline bool n00b_json_is_int(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, int64_t);
}

static inline bool n00b_json_is_double(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, double);
}

static inline bool n00b_json_is_string(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_string_t *);
}

static inline bool n00b_json_is_array(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_array_t);
}

static inline bool n00b_json_is_object(const n00b_json_node_t *n)
{
    return n != nullptr && n00b_variant_is_type(n->value, n00b_json_object_t *);
}

// ============================================================================
// Standalone parse/encode API
// ============================================================================

/**
 * @brief Parse a JSON string into a value tree.
 *
 * @param input     JSON text.
 * @param input_len Length in bytes.
 * @param err_out   If non-null, stores an error message on failure.
 * @kw allocator    Allocator for the parsed value tree.
 *
 * @return Parsed value, or nullptr on error.
 */
extern n00b_json_node_t *n00b_json_parse(const char *input,
                                         size_t      input_len,
                                         const char **err_out) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Encode a JSON value tree to text.
 *
 * @param val The root value to encode.
 * @kw pretty     Enable indented output (default false).
 * @kw indent     Indent width in spaces (default 2).
 * @kw canonical  Emit object keys in lexicographic (codepoint-sort)
 *                order so the output is byte-stable across runs and
 *                independent of dictionary insertion order (default
 *                false; current behavior preserved). Required by
 *                downstream consumers that compute hashes / signatures
 *                over the JSON wire form — e.g. libchalk's
 *                ATTESTATION subtree round-trip through extract.
 *
 * @return NUL-terminated JSON text, or nullptr on error.
 */
extern char *n00b_json_encode(const n00b_json_node_t *val) _kargs {
    bool pretty    = false;
    int  indent    = 2;
    bool canonical = false;
    n00b_allocator_t *allocator = nullptr;
};
