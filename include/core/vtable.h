/**
 * @file vtable.h
 * @brief Core vtable enumeration and extension method types.
 *
 * Defines the builtin function slots for the core vtable (bare function
 * pointers with known, fixed signatures) and the `n00b_method_t` /
 * `n00b_method_param_t` types used for extension methods that carry full
 * runtime signature metadata.
 */
#pragma once

#include "n00b.h"
#include "adt/array.h"

/**
 * @brief Indices into the core vtable's bare function pointer array.
 *
 * Core operations with known, fixed signatures.
 */
enum n00b_builtin_type_fn {
    N00B_BI_CONSTRUCTOR = 0,
    N00B_BI_ALLOC_SZ,
    N00B_BI_TO_STRING,
    N00B_BI_TO_LITERAL,
    N00B_BI_FORMAT,
    N00B_BI_FINALIZER,
    N00B_BI_COERCIBLE,
    N00B_BI_COERCE,
    N00B_BI_FROM_LITERAL,
    N00B_BI_COPY,
    N00B_BI_SHALLOW_COPY,
    N00B_BI_RESTORE,
    N00B_BI_ADD,
    N00B_BI_SUB,
    N00B_BI_MUL,
    N00B_BI_DIV,
    N00B_BI_MOD,
    N00B_BI_EQ,
    N00B_BI_LT,
    N00B_BI_GT,
    N00B_BI_LEN,
    N00B_BI_INDEX_GET,
    N00B_BI_INDEX_SET,
    N00B_BI_SLICE_GET,
    N00B_BI_SLICE_SET,
    N00B_BI_ITEM_TYPE,
    N00B_BI_VIEW,
    N00B_BI_CONTAINER_LIT,
    N00B_BI_GC_MAP,
    N00B_BI_RENDER,
    N00B_BI_HASH,
    N00B_BI_NUM_FUNCS,
};

/**
 * @brief Parameter/return type descriptor for extension method signatures.
 */
typedef struct n00b_method_param_t {
    uint64_t    type_hash; ///< typehash(T) of the parameter type.
    const char *type_name; ///< Human-readable C type name.
} n00b_method_param_t;

/**
 * @brief An extension method: function pointer + full signature metadata.
 *
 * Used only in the extension vtable, not the core vtable (which uses
 * bare n00b_vtable_entry pointers with known, fixed signatures).
 */
typedef struct n00b_method_t {
    n00b_vtable_entry                  fn;          ///< The function pointer.
    const char                        *name;        ///< Method name.
    n00b_method_param_t                return_type; ///< Return type info.
    n00b_array_t(n00b_method_param_t)  params;      ///< Parameter type info.
} n00b_method_t;
