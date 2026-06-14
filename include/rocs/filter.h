/**
 * @file rocs/filter.h
 * @brief Store-independent public filter value, field, path, and predicate
 *        builder declarations.
 *
 * Filters are first-class process-side values. This header is intentionally
 * independent of stores, query execution, and the internal planner tree: callers
 * may construct values, named fields, the catch-all field identity, typed
 * paths, and immutable predicate nodes without opening a rocs store.
 *
 * `n00b_filter_value_t` is a n00b variant. The variant selector is the only
 * filter-value payload discriminator. This header does not define a public
 * filter-value type enum, cached payload type, node type, or manual value union.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/variant.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "text/regex/regex.h"

typedef struct n00b_filter_t                n00b_filter_t;
typedef struct n00b_filter_field_t          n00b_filter_field_t;
typedef struct n00b_filter_ir_t             n00b_filter_ir_t;
typedef struct n00b_filter_path_t           n00b_filter_path_t;
typedef struct n00b_filter_path_component_t n00b_filter_path_component_t;
typedef struct n00b_filter_value_list_t     n00b_filter_value_list_t;

/**
 * @brief Distinct variant payload used to represent a filter null value.
 */
typedef struct {
    uint8_t reserved;
} n00b_filter_null_t;

/**
 * @brief Store-independent filter value payload.
 *
 * The selector in this variant is authoritative. Consumers inspect with
 * `n00b_variant_is_type` / `n00b_variant_get`; no parallel filter-value kind is
 * exposed by rocs.
 */
typedef n00b_variant_t(n00b_filter_null_t,
                       bool,
                       int64_t,
                       uint64_t,
                       double,
                       n00b_string_t *,
                       n00b_buffer_t *,
                       n00b_regex_t *,
                       n00b_filter_value_list_t *) n00b_filter_value_t;

/**
 * @brief Ordered path-component list used to build immutable filter paths.
 *
 * Callers may mutate this list until passing it to @ref n00b_filter_path. A
 * successful path construction copies the component handles into private path
 * storage; later mutations to the builder list do not affect the path.
 */
typedef n00b_list_t(n00b_filter_path_component_t *)
    n00b_filter_path_component_list_t;

/**
 * @brief Ordered IR child-list builder used for immutable boolean IR nodes.
 *
 * Callers may mutate this list until passing it to a boolean IR constructor.
 * Successful boolean IR construction copies the child handles into private IR
 * node storage; later mutations to the builder list do not affect the node.
 * The list is intentionally permissive so tests and importers can represent
 * malformed exchange trees and let @ref n00b_filter_from_ir validate them.
 */
typedef n00b_list_t(n00b_filter_ir_t *) n00b_filter_ir_child_list_t;

/**
 * @brief Error domain for public filter builders.
 */
typedef enum : int32_t {
    N00B_FILTER_OK              = 0,
    N00B_FILTER_ERR_ARG         = -1,
    N00B_FILTER_ERR_PATH        = -2,
    N00B_FILTER_ERR_IR          = -3,
    N00B_FILTER_ERR_UNSUPPORTED = -4,
    N00B_FILTER_ERR_STATE       = -5,
} n00b_filter_err_t;

/**
 * @brief Public path component syntax tag.
 *
 * This classifies path syntax only: object key versus array ordinal. It is not
 * a predicate or value payload discriminator.
 */
typedef enum : int32_t {
    N00B_FILTER_PATH_KEY   = 1,
    N00B_FILTER_PATH_INDEX = 2,
} n00b_filter_path_component_kind_t;

/**
 * @brief Public predicate shape tag.
 *
 * This classifies immutable predicate-node structure only. It is not a
 * filter-value payload discriminator; @ref n00b_filter_value_t remains
 * discriminated solely by its n00b variant selector.
 */
typedef enum : int32_t {
    N00B_FILTER_PREDICATE_AND  = 1,
    N00B_FILTER_PREDICATE_OR   = 2,
    N00B_FILTER_PREDICATE_NOT  = 3,
    N00B_FILTER_PREDICATE_LEAF = 4,
} n00b_filter_predicate_kind_t;

/**
 * @brief Public leaf predicate operator tag.
 *
 * This classifies leaf predicate structure only. It must not be used to infer
 * or duplicate the active member of any @ref n00b_filter_value_t payload.
 */
typedef enum : int32_t {
    N00B_FILTER_LEAF_EQ       = 1,
    N00B_FILTER_LEAF_IN       = 2,
    N00B_FILTER_LEAF_RANGE    = 3,
    N00B_FILTER_LEAF_EXISTS   = 4,
    N00B_FILTER_LEAF_CONTAINS = 5,
    N00B_FILTER_LEAF_PREFIX   = 6,
    N00B_FILTER_LEAF_REGEX    = 7,
    N00B_FILTER_LEAF_UNDER    = 8,
} n00b_filter_leaf_op_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Static diagnostic string for a public filter error.
 *
 * @param err Error code in the public filter domain.
 * @return Static rich string naming the error, or an unknown-error string for
 *         codes outside @ref n00b_filter_err_t.
 */
extern n00b_string_t *n00b_filter_err_str(n00b_err_t err);

/**
 * @brief Construct a null filter value.
 *
 * @return A set variant whose active member is @ref n00b_filter_null_t.
 */
extern n00b_filter_value_t n00b_fv_null(void);

/**
 * @brief Construct a boolean filter value.
 *
 * @param value Boolean payload copied into the variant.
 * @return A set variant whose active member is @c bool.
 */
extern n00b_filter_value_t n00b_fv_bool(bool value);

/**
 * @brief Construct a signed 64-bit integer filter value.
 *
 * @param value Integer payload copied into the variant.
 * @return A set variant whose active member is @c int64_t.
 */
extern n00b_filter_value_t n00b_fv_i64(int64_t value);

/**
 * @brief Construct an unsigned 64-bit integer filter value.
 *
 * @param value Integer payload copied into the variant.
 * @return A set variant whose active member is @c uint64_t.
 */
extern n00b_filter_value_t n00b_fv_u64(uint64_t value);

/**
 * @brief Construct a floating-point filter value.
 *
 * @param value Double payload copied into the variant.
 * @return A set variant whose active member is @c double.
 */
extern n00b_filter_value_t n00b_fv_f64(double value);

/**
 * @brief Construct a UTF-8 string filter value.
 *
 * @param value Borrowed n00b string handle retained by pointer. The caller
 *              keeps ownership and the string must outlive consumers of the
 *              filter value through the allocator/GC lifetime.
 * @pre @p value should be non-null for later predicate construction.
 * @return A set variant whose active member is @c n00b_string_t *.
 */
extern n00b_filter_value_t n00b_fv_utf8(n00b_string_t *value);

/**
 * @brief Construct a byte-buffer filter value.
 *
 * @param value Borrowed n00b buffer handle retained by pointer. The caller
 *              keeps ownership and the buffer must outlive consumers of the
 *              filter value through the allocator/GC lifetime.
 * @pre @p value should be non-null for later predicate construction.
 * @return A set variant whose active member is @c n00b_buffer_t *.
 */
extern n00b_filter_value_t n00b_fv_bytes(n00b_buffer_t *value);

/**
 * @brief Construct a compiled-regex filter value.
 *
 * @param value Borrowed compiled regex handle retained by pointer. Regex syntax
 *              errors occur when constructing the regex, not here.
 * @pre @p value should be non-null for later predicate construction.
 * @return A set variant whose active member is @c n00b_regex_t *.
 */
extern n00b_filter_value_t n00b_fv_regex(n00b_regex_t *value);

/**
 * @brief Construct a list-valued filter value.
 *
 * @param values Borrowed value-list handle retained by pointer. The list and
 *               its values are not copied; callers should treat a list as
 *               immutable after wrapping it in a value for predicate use.
 * @pre @p values should be non-null for later predicate construction.
 * @return A set variant whose active member is
 *         @c n00b_filter_value_list_t *.
 */
extern n00b_filter_value_t n00b_fv_list(n00b_filter_value_list_t *values);

/**
 * @brief Allocate an empty filter-value list.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned mutable list builder.
 */
extern n00b_filter_value_list_t *
n00b_filter_value_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one set filter value to a value-list builder.
 *
 * @param list Mutable borrowed value-list builder.
 * @param value Variant-only filter value. Must be set.
 * @return Ok(true) on append, or @c N00B_FILTER_ERR_ARG for a null list or
 *         unset variant.
 */
extern n00b_result_t(bool)
n00b_filter_value_list_append(n00b_filter_value_list_t *list,
                              n00b_filter_value_t      value);

/**
 * @brief Return the number of values in a filter-value list.
 *
 * @param list Borrowed value-list handle.
 * @return Ok(count) on success, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_filter_value_list_count(n00b_filter_value_list_t *list);

/**
 * @brief Borrow a value-list member by ordinal.
 *
 * @param list Borrowed value-list handle.
 * @param ordinal Zero-based member ordinal.
 * @return Ok(some(value)) when present, Ok(none) when @p ordinal is out of
 *         range, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_value_list_at(n00b_filter_value_list_t *list, uint64_t ordinal);

/**
 * @brief Construct a named schema-field handle.
 *
 * @param name Borrowed real schema field name. The pointer is retained, not
 *             copied. Dotted names resolve through nested JSON objects after
 *             an exact top-level key lookup misses. The named field handle
 *             does not validate against a store schema; schema resolution
 *             happens later during query planning.
 * @kw allocator Allocator for the returned field handle.
 * @return Ok(field) on success, or @c N00B_FILTER_ERR_ARG for a null, empty,
 *         or malformed dotted name.
 */
extern n00b_result_t(n00b_filter_field_t *)
n00b_filter_field(n00b_string_t *name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the reserved catch-all field identity.
 *
 * @return Borrowed process-static any-field handle. Callers must not free or
 *         mutate it. The handle is distinguishable by pointer identity and has
 *         no schema field-name string.
 */
extern n00b_filter_field_t *n00b_filter_any(void);

/**
 * @brief Test whether a field handle is the reserved any-field identity.
 *
 * @param field Borrowed field handle.
 * @return Ok(true) for the singleton returned by @ref n00b_filter_any,
 *         Ok(false) for named field handles, or @c N00B_FILTER_ERR_ARG for
 *         null input.
 */
extern n00b_result_t(bool)
n00b_filter_field_is_any(n00b_filter_field_t *field);

/**
 * @brief Borrow a named field handle's field name.
 *
 * @param field Borrowed field handle.
 * @return Ok(some(name)) for named fields, Ok(none) for the any-field identity,
 *         or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_field_name(n00b_filter_field_t *field);

/**
 * @brief Allocate an empty path-component list builder.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned mutable component-list builder.
 */
extern n00b_filter_path_component_list_t *
n00b_filter_path_component_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an object-key path component.
 *
 * @param key Borrowed object key string. The key pointer is retained, not
 *            copied, and must outlive paths that include the component through
 *            the allocator/GC lifetime.
 * @kw allocator Allocator for the component handle.
 * @return Ok(component) on success, or @c N00B_FILTER_ERR_ARG for null key.
 */
extern n00b_result_t(n00b_filter_path_component_t *)
n00b_filter_path_key(n00b_string_t *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an array-ordinal path component.
 *
 * @param ordinal Array ordinal to record in the component.
 * @kw allocator Allocator for the component handle.
 * @return Ok(component) on success.
 */
extern n00b_result_t(n00b_filter_path_component_t *)
n00b_filter_path_index(uint64_t ordinal) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one component to a path-component list builder.
 *
 * @param list Mutable borrowed component-list builder.
 * @param component Borrowed component handle.
 * @return Ok(true) on append, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(bool)
n00b_filter_path_component_list_append(
    n00b_filter_path_component_list_t *list,
    n00b_filter_path_component_t      *component);

/**
 * @brief Construct an immutable typed filter path.
 *
 * @param components Borrowed ordered component-list builder. Components are
 *                   validated and copied into private path storage; the
 *                   builder remains caller-owned and may be mutated afterwards.
 * @kw allocator Allocator for the path handle and copied component list.
 * @return Ok(path) on success, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_PATH for invalid component state.
 *
 * Paths are typed values over object keys and array ordinals. rocs does not
 * parse path syntax strings into filter paths in this API.
 */
extern n00b_result_t(n00b_filter_path_t *)
n00b_filter_path(n00b_filter_path_component_list_t *components) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return the number of components in an immutable filter path.
 *
 * @param path Borrowed path handle.
 * @return Ok(count) on success, or @c N00B_FILTER_ERR_ARG for null/malformed
 *         path state.
 */
extern n00b_result_t(uint64_t)
n00b_filter_path_component_count(n00b_filter_path_t *path);

/**
 * @brief Borrow one immutable path component by ordinal.
 *
 * @param path Borrowed path handle.
 * @param ordinal Zero-based component ordinal.
 * @return Ok(some(component)) when present, Ok(none) when @p ordinal is out of
 *         range, or @c N00B_FILTER_ERR_ARG for null path.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_path_component_t *))
n00b_filter_path_component_at(n00b_filter_path_t *path, uint64_t ordinal);

/**
 * @brief Inspect a path component's syntax kind.
 *
 * @param component Borrowed component handle.
 * @return Ok(kind) on success, or @c N00B_FILTER_ERR_ARG for null/invalid
 *         component state.
 */
extern n00b_result_t(n00b_filter_path_component_kind_t)
n00b_filter_path_component_kind(n00b_filter_path_component_t *component);

/**
 * @brief Borrow an object-key component's key.
 *
 * @param component Borrowed component handle.
 * @return Ok(some(key)) for object-key components, Ok(none) for array-ordinal
 *         components, or @c N00B_FILTER_ERR_ARG for null/invalid input.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_path_component_key(n00b_filter_path_component_t *component);

/**
 * @brief Inspect an array-ordinal component's ordinal.
 *
 * @param component Borrowed component handle.
 * @return Ok(some(ordinal)) for array-ordinal components, Ok(none) for
 *         object-key components, or @c N00B_FILTER_ERR_ARG for null/invalid
 *         input.
 */
extern n00b_result_t(n00b_option_t(uint64_t))
n00b_filter_path_component_index(n00b_filter_path_component_t *component);

/**
 * @brief Construct an equality predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param value Set variant-only filter value. Pointer payloads must be
 *              non-null; a set @ref n00b_filter_null_t value is valid.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null/unset
 *         input, or @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_eq(n00b_filter_field_t *field,
               n00b_filter_value_t  value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an IN predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param values Set variant whose active member must be a non-null
 *               @ref n00b_filter_value_list_t pointer. Empty lists are valid
 *               public predicates and are not simplified in the builder.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null/unset or
 *         non-list input, or @c N00B_FILTER_ERR_UNSUPPORTED for any-field
 *         input.
 *
 * A successful predicate records the list handle by pointer. Callers should
 * treat the value list as immutable after construction.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_in(n00b_filter_field_t *field,
               n00b_filter_value_t  values) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a scalar range predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param lower Set lower-bound value. Must be numeric or a non-null UTF-8
 *              string value.
 * @param upper Set upper-bound value. Must be from the same scalar family as
 *              @p lower: numeric with numeric, or UTF-8 string with UTF-8
 *              string.
 * @kw include_lower Whether the lower bound is inclusive. Defaults to true.
 * @kw include_upper Whether the upper bound is inclusive. Defaults to true.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for unset,
 *         non-scalar, null, or mixed-family bounds, or
 *         @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 *
 * Null, bool, bytes, regex, list, unset, and mixed scalar-family bounds are
 * rejected by the public builder.
 *
 * This constructor is named @c n00b_filter_between because libn00b already
 * exports @c n00b_filter_range for Unicode codepoint filters.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_between(n00b_filter_field_t *field,
                    n00b_filter_value_t  lower,
                    n00b_filter_value_t  upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
};

/**
 * @brief Construct a whole-word contains/search predicate.
 *
 * @param field Borrowed named field handle or the any-field identity returned
 *              by @ref n00b_filter_any. This is the only Phase 2 leaf that
 *              accepts the any-field identity.
 * @param term Borrowed non-empty search term.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, or @c N00B_FILTER_ERR_ARG for null/empty
 *         input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_contains(n00b_filter_field_t *field,
                     n00b_string_t       *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a prefix predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param prefix Borrowed non-empty prefix string.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null/empty
 *         input, or @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_prefix(n00b_filter_field_t *field,
                   n00b_string_t       *prefix) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a regex predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param regex Borrowed non-null compiled regex handle. Regex syntax errors
 *              happen before this call, when the regex is constructed.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_regex(n00b_filter_field_t *field,
                  n00b_regex_t        *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an existence predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null/malformed
 *         field input, or @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_exists(n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an under/path predicate over a named field.
 *
 * @param field Borrowed field handle. Must be a named field; the any-field
 *              identity is rejected with @c N00B_FILTER_ERR_UNSUPPORTED.
 * @param path Borrowed immutable typed filter path.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, @c N00B_FILTER_ERR_ARG for null/malformed
 *         input, or @c N00B_FILTER_ERR_UNSUPPORTED for any-field input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_under(n00b_filter_field_t *field,
                  n00b_filter_path_t  *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an AND predicate from ordered child arguments.
 *
 * @param first First borrowed child predicate. At least one additional
 *              non-null variadic child is required.
 * @kw allocator Allocator for the returned immutable predicate node and its
 *               private child-list wrapper.
 * @return Ok(predicate) on success, or @c N00B_FILTER_ERR_ARG when fewer than
 *         two non-null children are supplied.
 *
 * The returned node preserves child order exactly and does not simplify,
 * flatten, or drop children.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_and(n00b_filter_t *first, n00b_filter_t *+) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an OR predicate from ordered child arguments.
 *
 * @param first First borrowed child predicate. At least one additional
 *              non-null variadic child is required.
 * @kw allocator Allocator for the returned immutable predicate node and its
 *               private child-list wrapper.
 * @return Ok(predicate) on success, or @c N00B_FILTER_ERR_ARG when fewer than
 *         two non-null children are supplied.
 *
 * The returned node preserves child order exactly and does not simplify,
 * flatten, or drop children.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_or(n00b_filter_t *first, n00b_filter_t *+) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a NOT predicate from one child predicate.
 *
 * @param filter Borrowed non-null child predicate. The returned node preserves
 *               this exact child relationship and does not simplify.
 * @kw allocator Allocator for the returned immutable predicate node.
 * @return Ok(predicate) on success, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_not(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Allocate an empty filter-IR child-list builder.
 *
 * @kw allocator Allocator for the list wrapper and backing storage.
 * @return Owned mutable IR child-list builder.
 *
 * The builder is process-side construction state only. It is not a persisted
 * representation and is copied by successful boolean IR constructors.
 */
extern n00b_filter_ir_child_list_t *
n00b_filter_ir_child_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Append one child handle to an IR child-list builder.
 *
 * @param list Mutable borrowed IR child-list builder.
 * @param child Borrowed child IR handle. May be null to intentionally build a
 *              malformed child list for import validation.
 * @return Ok(true) on append, or @c N00B_FILTER_ERR_ARG for a null list.
 */
extern n00b_result_t(bool)
n00b_filter_ir_child_list_append(n00b_filter_ir_child_list_t *list,
                                 n00b_filter_ir_t            *child);

/**
 * @brief Construct a permissive value-bearing IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @param op Structural leaf operator. Equality and IN imports use this helper;
 *           other or invalid operators are preserved for validation.
 * @param value Variant-only filter value copied into the IR leaf. It may be
 *              unset or have the wrong variant shape; @ref n00b_filter_from_ir
 *              is the validation boundary.
 * @kw allocator Allocator for the immutable IR node and copied value slot.
 * @return Owned immutable in-memory IR leaf.
 *
 * IR leaf/operator tags classify predicate structure only. They do not
 * duplicate or replace the selector of @ref n00b_filter_value_t.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_value_leaf(n00b_filter_field_t *field,
                          n00b_filter_leaf_op_t op,
                          n00b_filter_value_t   value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a permissive range IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @param lower Variant-only lower bound copied into the IR leaf.
 * @param upper Variant-only upper bound copied into the IR leaf.
 * @kw include_lower Whether the lower bound is inclusive. Defaults to true.
 * @kw include_upper Whether the upper bound is inclusive. Defaults to true.
 * @kw allocator Allocator for the immutable IR node and copied bound slots.
 * @return Owned immutable in-memory range IR leaf.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_range_leaf(n00b_filter_field_t *field,
                          n00b_filter_value_t  lower,
                          n00b_filter_value_t  upper) _kargs
{
    bool              include_lower = true;
    bool              include_upper = true;
    n00b_allocator_t *allocator     = nullptr;
};

/**
 * @brief Construct a permissive text IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @param op Structural leaf operator. Contains and prefix imports use this
 *           helper; invalid operators are preserved for validation.
 * @param text Borrowed text handle recorded by pointer. May be null or empty;
 *             @ref n00b_filter_from_ir validates imported shape.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory text IR leaf.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_text_leaf(n00b_filter_field_t *field,
                         n00b_filter_leaf_op_t op,
                         n00b_string_t        *text) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a permissive regex IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @param regex Borrowed compiled-regex handle recorded by pointer. May be null;
 *              @ref n00b_filter_from_ir validates imported shape.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory regex IR leaf.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_regex_leaf(n00b_filter_field_t *field,
                          n00b_regex_t        *regex) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a permissive under/path IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @param path Borrowed typed path handle recorded by pointer. May be null;
 *             @ref n00b_filter_from_ir validates imported shape.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory under/path IR leaf.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_under_leaf(n00b_filter_field_t *field,
                          n00b_filter_path_t  *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a permissive existence IR leaf.
 *
 * @param field Borrowed field handle recorded by pointer. May be null for
 *              malformed import-validation cases.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory exists IR leaf.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_exists_leaf(n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an AND IR node from an ordered child-list builder.
 *
 * @param children Borrowed IR child-list builder. The child handles are copied
 *                 into private immutable node storage. Null or undersized lists
 *                 are allowed here and rejected by @ref n00b_filter_from_ir.
 * @kw allocator Allocator for the immutable IR node and copied child list.
 * @return Owned immutable in-memory AND IR node.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_and(n00b_filter_ir_child_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct an OR IR node from an ordered child-list builder.
 *
 * @param children Borrowed IR child-list builder. The child handles are copied
 *                 into private immutable node storage. Null or undersized lists
 *                 are allowed here and rejected by @ref n00b_filter_from_ir.
 * @kw allocator Allocator for the immutable IR node and copied child list.
 * @return Owned immutable in-memory OR IR node.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_or(n00b_filter_ir_child_list_t *children) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a NOT IR node from one child handle.
 *
 * @param child Borrowed child IR handle. May be null for malformed
 *              import-validation cases.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory NOT IR node.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_not(n00b_filter_ir_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a raw IR node with an arbitrary structural tag.
 *
 * @param kind Raw structural node tag. Invalid tags are preserved so
 *             @ref n00b_filter_from_ir can reject them with
 *             @c N00B_FILTER_ERR_IR.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory raw IR node.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_raw_node(int32_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Construct a raw leaf IR node with no payload.
 *
 * @param leaf_op Raw structural leaf operator. Invalid operators and missing
 *                payloads are preserved so @ref n00b_filter_from_ir can reject
 *                them with @c N00B_FILTER_ERR_IR.
 * @param field Borrowed field handle recorded by pointer. May be null.
 * @kw allocator Allocator for the immutable IR node.
 * @return Owned immutable in-memory raw leaf IR node.
 */
extern n00b_filter_ir_t *
n00b_filter_ir_raw_leaf(int32_t leaf_op,
                        n00b_filter_field_t *field) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convert a checked public filter predicate to an in-memory IR tree.
 *
 * @param filter Borrowed public checked filter predicate.
 * @kw allocator Allocator for the returned immutable IR tree.
 * @return Ok(IR) on success, or @c N00B_FILTER_ERR_ARG for null input.
 *
 * The returned @ref n00b_filter_ir_t is an immutable process-side exchange
 * tree. It preserves predicate structure, child order, field handle identity,
 * path handles, regex/text handles, range inclusivity, empty IN lists, and
 * variant-only filter values. It is not a persisted DSL, not shard marshal
 * state, and not a query executor.
 */
extern n00b_result_t(n00b_filter_ir_t *)
n00b_filter_to_ir(n00b_filter_t *filter) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Validate and import an in-memory IR tree as a checked public filter.
 *
 * @param ir Borrowed in-memory IR exchange tree.
 * @kw allocator Allocator for the returned immutable public filter tree.
 * @return Ok(filter) on valid import, @c N00B_FILTER_ERR_ARG for null top-level
 *         input, or @c N00B_FILTER_ERR_IR for structurally malformed IR.
 *
 * This function is the IR validation boundary. It rejects malformed node kinds,
 * invalid leaf operators, bad boolean arity, missing fields or payloads,
 * invalid any-field use, non-list IN values, invalid range bounds, missing
 * regex/text/path handles, empty text, and malformed child lists.
 */
extern n00b_result_t(n00b_filter_t *)
n00b_filter_from_ir(n00b_filter_ir_t *ir) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Inspect an IR node's structural predicate kind.
 *
 * @param ir Borrowed IR node.
 * @return Ok(kind) on success, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_filter_predicate_kind_t)
n00b_filter_ir_kind(n00b_filter_ir_t *ir);

/**
 * @brief Inspect an IR leaf node's structural operator.
 *
 * @param ir Borrowed IR node.
 * @return Ok(op) for leaf IR nodes, @c N00B_FILTER_ERR_STATE for non-leaf IR
 *         nodes, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_filter_leaf_op_t)
n00b_filter_ir_leaf_op(n00b_filter_ir_t *ir);

/**
 * @brief Borrow an IR leaf node's field handle.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(field)) for leaf IR nodes with a field, Ok(none) for
 *         non-leaf or missing-field nodes, or @c N00B_FILTER_ERR_ARG for null
 *         input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_filter_ir_field(n00b_filter_ir_t *ir);

/**
 * @brief Return child count for boolean IR nodes, or zero for leaves.
 *
 * @param ir Borrowed IR node.
 * @return Ok(count) on success, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(uint64_t)
n00b_filter_ir_child_count(n00b_filter_ir_t *ir);

/**
 * @brief Borrow one child IR node by ordinal.
 *
 * @param ir Borrowed IR node.
 * @param ordinal Zero-based child ordinal.
 * @return Ok(some(child)) when present, Ok(none) for leaves, missing children,
 *         or out-of-range ordinals, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_ir_t *))
n00b_filter_ir_child_at(n00b_filter_ir_t *ir, uint64_t ordinal);

/**
 * @brief Borrow a value-bearing IR leaf's variant-only value.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(value)) for value-bearing leaves, Ok(none) otherwise, or
 *         @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_value(n00b_filter_ir_t *ir);

/**
 * @brief Borrow a range IR leaf's lower bound.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(value)) for range leaves with a lower slot, Ok(none)
 *         otherwise, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_range_lower(n00b_filter_ir_t *ir);

/**
 * @brief Borrow a range IR leaf's upper bound.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(value)) for range leaves with an upper slot, Ok(none)
 *         otherwise, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_ir_range_upper(n00b_filter_ir_t *ir);

/**
 * @brief Return whether a range IR leaf includes its lower bound.
 *
 * @param ir Borrowed IR node.
 * @return Ok(flag) for range leaves, @c N00B_FILTER_ERR_STATE for non-range
 *         nodes, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(bool)
n00b_filter_ir_range_include_lower(n00b_filter_ir_t *ir);

/**
 * @brief Return whether a range IR leaf includes its upper bound.
 *
 * @param ir Borrowed IR node.
 * @return Ok(flag) for range leaves, @c N00B_FILTER_ERR_STATE for non-range
 *         nodes, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(bool)
n00b_filter_ir_range_include_upper(n00b_filter_ir_t *ir);

/**
 * @brief Borrow a text IR leaf's text handle.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(text)) for text leaves with a handle, Ok(none) otherwise, or
 *         @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_ir_text(n00b_filter_ir_t *ir);

/**
 * @brief Borrow a regex IR leaf's compiled regex handle.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(regex)) for regex leaves with a handle, Ok(none) otherwise,
 *         or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_filter_ir_regex_handle(n00b_filter_ir_t *ir);

/**
 * @brief Borrow an under/path IR leaf's typed path handle.
 *
 * @param ir Borrowed IR node.
 * @return Ok(some(path)) for under/path leaves with a handle, Ok(none)
 *         otherwise, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_path_t *))
n00b_filter_ir_path(n00b_filter_ir_t *ir);

/**
 * @brief Inspect a predicate's structural kind.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(kind) on success, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_filter_predicate_kind_t)
n00b_filter_predicate_kind(n00b_filter_t *filter);

/**
 * @brief Inspect a leaf predicate's operator.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(op) for leaf predicates, @c N00B_FILTER_ERR_STATE for boolean
 *         predicates, or @c N00B_FILTER_ERR_ARG for null input.
 */
extern n00b_result_t(n00b_filter_leaf_op_t)
n00b_filter_predicate_leaf_op(n00b_filter_t *filter);

/**
 * @brief Borrow a leaf predicate's field handle.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(field)) for leaf predicates, Ok(none) for boolean
 *         predicates, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for malformed leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_field_t *))
n00b_filter_predicate_field(n00b_filter_t *filter);

/**
 * @brief Return child count for boolean predicates, or zero for leaves.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(count) on success, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for malformed boolean state.
 */
extern n00b_result_t(uint64_t)
n00b_filter_predicate_child_count(n00b_filter_t *filter);

/**
 * @brief Borrow a child predicate by ordinal.
 *
 * NOT exposes its single child at ordinal zero. Leaves and out-of-range
 * ordinals return Ok(none).
 *
 * @param filter Borrowed predicate handle.
 * @param ordinal Zero-based child ordinal.
 * @return Ok(some(child)) when present, Ok(none) for leaves or out-of-range
 *         ordinals, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for malformed boolean state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_t *))
n00b_filter_predicate_child_at(n00b_filter_t *filter, uint64_t ordinal);

/**
 * @brief Borrow an equality leaf's variant-only value.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(value)) for equality leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed equality leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_value(n00b_filter_t *filter);

/**
 * @brief Borrow an IN leaf's value-list handle.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(values)) for IN leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed IN leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_list_t *))
n00b_filter_predicate_values(n00b_filter_t *filter);

/**
 * @brief Borrow a range leaf's lower bound.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(value)) for range leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed range leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_range_lower(n00b_filter_t *filter);

/**
 * @brief Borrow a range leaf's upper bound.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(value)) for range leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed range leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_value_t))
n00b_filter_predicate_range_upper(n00b_filter_t *filter);

/**
 * @brief Return whether a range leaf includes its lower bound.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(flag) for range leaves, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for non-range predicates.
 */
extern n00b_result_t(bool)
n00b_filter_predicate_range_include_lower(n00b_filter_t *filter);

/**
 * @brief Return whether a range leaf includes its upper bound.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(flag) for range leaves, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for non-range predicates.
 */
extern n00b_result_t(bool)
n00b_filter_predicate_range_include_upper(n00b_filter_t *filter);

/**
 * @brief Borrow a contains or prefix leaf's text handle.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(text)) for contains/prefix leaves, Ok(none) for other
 *         predicates, @c N00B_FILTER_ERR_ARG for null input, or
 *         @c N00B_FILTER_ERR_STATE for malformed text leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_filter_predicate_text(n00b_filter_t *filter);

/**
 * @brief Borrow a regex leaf's compiled regex handle.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(regex)) for regex leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed regex leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_regex_t *))
n00b_filter_predicate_regex_handle(n00b_filter_t *filter);

/**
 * @brief Borrow an under/path leaf's immutable path handle.
 *
 * @param filter Borrowed predicate handle.
 * @return Ok(some(path)) for under/path leaves, Ok(none) for other predicates,
 *         @c N00B_FILTER_ERR_ARG for null input, or @c N00B_FILTER_ERR_STATE
 *         for malformed under/path leaf state.
 */
extern n00b_result_t(n00b_option_t(n00b_filter_path_t *))
n00b_filter_predicate_path(n00b_filter_t *filter);

#ifdef __cplusplus
}
#endif
