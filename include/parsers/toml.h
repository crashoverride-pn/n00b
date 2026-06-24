/**
 * @file parsers/toml.h
 * @brief Minimal TOML parser.
 *
 * Tagged-union `n00b_toml_node_t` value type, recursive-descent
 * `n00b_toml_parse` / `n00b_toml_parse_file`, and a small accessor
 * surface for test-fixture consumption.
 *
 * Scope (a strict subset of the TOML spec — only what the regex-engine
 * test fixtures use):
 *
 *  - `# ...` line comments
 *  - `key = value` top-level assignments
 *  - `[name]` single-named tables
 *  - `[[name]]` array-of-tables (multiple entries per name)
 *  - basic strings  `"..."`  with `\n \r \t \\ \" \xNN \uXXXX` escapes
 *  - literal strings `'...'` (no escape processing)
 *  - multi-line basic strings  `""" ... """`
 *  - multi-line literal strings `''' ... '''`
 *  - decimal ints `[+-]?[0-9_]+` (underscores allowed for grouping)
 *  - booleans `true` / `false`
 *  - arrays `[ value, value, ... ]` (homogeneity not enforced)
 *
 * Not supported (deliberately): floats, dates/times, inline tables,
 * dotted keys, hex/octal/binary integer literals.
 *
 * Failure model: every parse error returns `n00b_result_err(..)` with
 * `N00B_TOML_ERR_PARSE` (and a diagnostic string in the node-tree's
 * `error` field — see below).  Callers should `n00b_result_is_ok()`
 * the return and only deref on success.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "adt/variant.h"
#include "util/assert.h"

// ============================================================================
// TOML value type
// ============================================================================

/** @brief TOML value-type tags. */
typedef enum {
    N00B_TOML_INT,    /**< 64-bit signed integer. */
    N00B_TOML_BOOL,   /**< Boolean. */
    N00B_TOML_STRING, /**< UTF-8 string. */
    N00B_TOML_ARRAY,  /**< Array of TOML values. */
    N00B_TOML_TABLE,  /**< Table — `n00b_string_t *` key to `n00b_toml_node_t *` value. */
} n00b_toml_type_t;

typedef struct n00b_toml_node n00b_toml_node_t;

/** @brief Array arm of a TOML node — list of child nodes. */
typedef n00b_list_t(n00b_toml_node_t *) n00b_toml_array_t;

/** @brief Table arm of a TOML node — string-keyed map of child nodes. */
typedef n00b_dict_t(n00b_string_t *, n00b_toml_node_t *) n00b_toml_table_t;

/**
 * @brief A parsed TOML value — tagged variant of all supported kinds.
 *
 * The selector (`typehash(arm)`) is the discriminator; there is no
 * parallel `type` field.  GC-precise and marshalable.  The public
 * `n00b_toml_type()` accessor maps the selector back to the
 * `n00b_toml_type_t` enum that external (regex-fixture) consumers use.
 *
 * Strings are stored as `n00b_string_t *` (Unicode-aware, length-
 * carrying).  Arrays and tables are heap pointers to the inner
 * `n00b_list_t` / `n00b_dict_t` containers, which transitively own
 * their children; the GC handles the rest.
 */
typedef n00b_variant_t(int64_t,
                       bool,
                       n00b_string_t *,
                       n00b_toml_array_t *,
                       n00b_toml_table_t *) n00b_toml_value_t;

/**
 * @brief A parsed TOML node.
 *
 * Allocated from n00b's heap (`n00b_alloc(n00b_toml_node_t)`).
 */
struct n00b_toml_node {
    n00b_toml_value_t v; /**< Variant payload; selector carries the kind. */
};

// ============================================================================
// Errors
// ============================================================================

/** @brief Parse error tags for `n00b_result_t(n00b_toml_node_t *)`. */
typedef enum {
    N00B_TOML_ERR_NONE  = 0,
    N00B_TOML_ERR_PARSE = 1,  /**< Document is malformed. */
    N00B_TOML_ERR_IO    = 2,  /**< File-open / read failed. */
} n00b_toml_err_t;

/**
 * @brief Get the diagnostic string from the most recent parse failure
 *        on the calling thread.  Cleared on every `n00b_toml_parse*`
 *        call.  Format: `"toml: parse error at line L column C: <msg>"`.
 */
extern n00b_string_t *n00b_toml_last_error(void);

// ============================================================================
// Parsing
// ============================================================================

/**
 * @brief Parse a TOML document held in @p src.
 *
 * Returns an `n00b_result_t(n00b_toml_node_t *)`.  On success, the
 * payload is always a `N00B_TOML_TABLE` node — the document root.
 * On failure, `n00b_toml_last_error()` carries the diagnostic.
 */
extern n00b_result_t(n00b_toml_node_t *)
n00b_toml_parse(n00b_string_t *src);

/**
 * @brief Read @p path via the conduit subsystem and parse the result.
 *
 * On file-IO failure returns `n00b_result_err(N00B_TOML_ERR_IO)`; on
 * a parse error returns `n00b_result_err(N00B_TOML_ERR_PARSE)`.
 */
extern n00b_result_t(n00b_toml_node_t *)
n00b_toml_parse_file(n00b_string_t *path);

// ============================================================================
// Accessors
// ============================================================================

/** @brief Get the value-type tag of @p v.  Panics on NULL. */
static inline n00b_toml_type_t
n00b_toml_type(const n00b_toml_node_t *v)
{
    n00b_require(v != nullptr, "n00b_toml_type: NULL value");
    switch (v->v.selector) {
    case typehash(int64_t):
        return N00B_TOML_INT;
    case typehash(bool):
        return N00B_TOML_BOOL;
    case typehash(n00b_string_t *):
        return N00B_TOML_STRING;
    case typehash(n00b_toml_array_t *):
        return N00B_TOML_ARRAY;
    case typehash(n00b_toml_table_t *):
        return N00B_TOML_TABLE;
    default:
        n00b_require(false, "n00b_toml_type: unset/invalid variant");
        return N00B_TOML_INT;
    }
}

/** @brief Get the integer payload.  Panics on type mismatch. */
extern int64_t n00b_toml_as_int(const n00b_toml_node_t *v);

/** @brief Get the boolean payload.  Panics on type mismatch. */
extern bool n00b_toml_as_bool(const n00b_toml_node_t *v);

/** @brief Get the string payload (borrowed).  Panics on type mismatch. */
extern n00b_string_t *n00b_toml_as_string(const n00b_toml_node_t *v);

/** @brief Array element count.  Panics on type mismatch. */
extern size_t n00b_toml_array_len(const n00b_toml_node_t *v);

/** @brief Array element at index @p i.  Panics on type / bounds error. */
extern n00b_toml_node_t *
n00b_toml_array_get(const n00b_toml_node_t *v, size_t i);

/**
 * @brief Table lookup by key.
 *
 * @param v   Table node (must be `N00B_TOML_TABLE`).
 * @param key Key to look up.
 *
 * @return The bound value wrapped in @c n00b_option_t. Returns
 *         @c n00b_option_none(n00b_toml_node_t *) if @p key is not
 *         present in @p v.
 *
 * @pre @p v has type `N00B_TOML_TABLE`. Panics on type mismatch.
 *
 * @post Once unwrapped via @ref n00b_option_get, the returned node is
 *       borrowed (owned by @p v's transitive child graph).
 */
extern n00b_option_t(n00b_toml_node_t *)
n00b_toml_table_get(const n00b_toml_node_t *v, n00b_string_t *key);

/**
 * @brief As @ref n00b_toml_table_get but with a C-string key.
 *
 * @return The bound value wrapped in @c n00b_option_t, or
 *         @c n00b_option_none(n00b_toml_node_t *) if @p key is not
 *         present in @p v.
 */
extern n00b_option_t(n00b_toml_node_t *)
n00b_toml_table_get_cstr(const n00b_toml_node_t *v, const char *key);

/**
 * @brief Look up `[[name]]` array-of-tables in the root table.
 *
 * @param v    Root table node (must be `N00B_TOML_TABLE`).
 * @param name `[[name]]` header to look up.
 *
 * @return The implicit `N00B_TOML_ARRAY` whose elements are the
 *         individual table entries, wrapped in @c n00b_option_t.
 *         Returns @c n00b_option_none(n00b_toml_node_t *) if no
 *         `[[name]]` headers with this name were seen.
 *
 * @pre The looked-up value (if present) has type `N00B_TOML_ARRAY`.
 *      Panics on type mismatch.
 */
extern n00b_option_t(n00b_toml_node_t *)
n00b_toml_table_array_of(const n00b_toml_node_t *v, const char *name);
