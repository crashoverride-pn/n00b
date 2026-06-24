/**
 * @file types.h
 * @brief Type representation for slay's type inference engine.
 *
 * @defgroup typecheck Type Checker
 * @{
 *
 * Slay's type system provides a general-purpose inference engine for grammar
 * authors building language tooling.  It supports seven type kinds (Var,
 * Primitive, Param, Fn, Sum, Record, Tuple), union-find-based inference,
 * constraint checking, and rich diagnostics.
 *
 * The `typecheck/` module is **standalone** — it has no dependency on slay's
 * parser or grammar system.  The bridge lives in `slay/infer.h`.
 *
 * ## Type kinds
 *
 * | Kind       | Struct              | Examples                         |
 * |------------|---------------------|----------------------------------|
 * | Var        | `n00b_tc_var_t`     | `` `T ``, `` `K ``               |
 * | Primitive  | `n00b_tc_prim_t`    | `int`, `bool`, `nil`             |
 * | Param      | `n00b_tc_param_t`   | `list[int]`, `dict[K,V]`         |
 * | Fn         | `n00b_tc_fn_t`      | `(int, string) -> bool`          |
 * | Sum        | `n00b_tc_sum_t`     | `int \| string \| nil`           |
 * | Record     | `n00b_tc_record_t`  | `Point{x: int, y: int}`         |
 * | Tuple      | `n00b_tc_tuple_t`   | `(int, string)`                  |
 *
 * Every type node sits in a union-find graph: the `forward` pointer chains to
 * the canonical representative, and path compression keeps lookups fast.
 *
 * @}
 */
#pragma once

#include "n00b.h"
#include "adt/variant.h"
#include "adt/option.h"
#include "adt/list.h"

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_tc_type_s       n00b_tc_type_t;
typedef struct n00b_tc_ctx_s        n00b_tc_ctx_t;

// n00b_option_t(n00b_string_t) is declared in core/string.h (one canonical site).
// Just include string.h to get it.
#include "core/string.h"

// ============================================================================
// Constraints on type variables
// ============================================================================
//
// A constraint is a tagged union over the seven constraint shapes below,
// expressed as an `n00b_variant_t`. The variant's `selector` is the
// discriminator: dispatch with `n00b_variant_is_type` / `n00b_variant_get`, or
// `switch (con->selector) { case typehash(n00b_tc_con_unifies_t): ... }` since
// `typehash(T)` is a compile-time integer constant. There is no separate
// `kind` enum.
//
// Defined here (ahead of `n00b_tc_var_t`) because the type-variable payload
// holds an `n00b_list_t(n00b_tc_constraint_t)`.

/** @brief Must unify with a specific type. */
typedef struct {
    n00b_tc_type_t *target;
} n00b_tc_con_unifies_t;

/** @brief Must unify with one of a set. */
typedef struct {
    n00b_list_t(n00b_tc_type_t *) *types;
} n00b_tc_con_one_of_t;

/** @brief Must implement a named interface. */
typedef struct {
    n00b_string_t *iface_name;
} n00b_tc_con_implements_t;

/** @brief Must be a record with a named field. */
typedef struct {
    n00b_string_t  *field_name;
    n00b_tc_type_t *field_type;
} n00b_tc_con_has_field_t;

/** @brief Parameterized type whose Nth param unifies. */
typedef struct {
    int32_t         index;
    n00b_tc_type_t *param_type;
} n00b_tc_con_has_param_t;

/** @brief Must be promotable to a target type. */
typedef struct {
    n00b_tc_type_t *target;
} n00b_tc_con_promotes_t;

/** @brief Must NOT unify with a type. */
typedef struct {
    n00b_tc_type_t *excluded;
} n00b_tc_con_not_t;

/**
 * @brief A constraint on a type variable.
 *
 * Constraints are checked at binding time — when a variable's `forward`
 * pointer is set during unification.
 */
typedef n00b_variant_t(
    n00b_tc_con_unifies_t,
    n00b_tc_con_one_of_t,
    n00b_tc_con_implements_t,
    n00b_tc_con_has_field_t,
    n00b_tc_con_has_param_t,
    n00b_tc_con_promotes_t,
    n00b_tc_con_not_t
) n00b_tc_constraint_t;

// ============================================================================
// Kind payloads
// ============================================================================

/**
 * @brief Type variable — the core of inference.
 *
 * A fresh variable can unify with any type, subject to its constraints.
 * Unification sets a `forward` pointer from the variable to the resolved type.
 */
typedef struct {
    uint32_t                              id;           /**< Unique within context. */
    n00b_option_t(n00b_string_t *)         given_name;   /**< User's name (if any). */
    n00b_string_t                        *display_name; /**< Shown in errors. */
    n00b_list_t(n00b_tc_constraint_t)    *constraints;  /**< Constraints on this var. */
} n00b_tc_var_t;

/**
 * @brief Primitive type — interned by name.
 *
 * Built-in primitives (int, bool, string, nil, ...) are pre-registered
 * on the type context.
 */
typedef struct {
    n00b_string_t *name; /**< Interned: "int", "f64", "bool", "nil", ... */
} n00b_tc_prim_t;

/**
 * @brief Parameterized type — constructor name + type parameters.
 *
 * Covers `list[T]`, `dict[K,V]`, `ref[T]`, `maybe[T]`, and any
 * grammar-author-defined parameterized type.
 */
typedef struct {
    n00b_string_t                *name;   /**< Constructor: "list", "dict", "ref", ... */
    n00b_list_t(n00b_tc_type_t *) *params; /**< Type parameters. */
} n00b_tc_param_t;

/**
 * @brief Function type — positional params, optional vargs/kargs, return type.
 *
 * Keywords are represented as an unordered Record (see `kargs_type`).
 */
typedef struct {
    n00b_list_t(n00b_tc_type_t *) *positional;   /**< Positional parameter types. */
    n00b_tc_type_t                *vargs_type;   /**< nullptr if not variadic. */
    n00b_tc_type_t                *kargs_type;   /**< nullptr, or Record (ordered=false). */
    n00b_tc_type_t                *return_type;  /**< Return type. */
} n00b_tc_fn_t;

/**
 * @brief Sum type — a flat, sorted list of variant types.
 *
 * `a | (b | c)` normalizes to `a | b | c`.
 */
typedef struct {
    n00b_list_t(n00b_tc_type_t *) *variants; /**< Sorted, flat. */
} n00b_tc_sum_t;

/**
 * @brief Field descriptor for records.
 *
 * Small struct, returned by value from `n00b_tc_field()`.
 */
typedef struct {
    n00b_string_t   *name;        /**< Field name. */
    n00b_tc_type_t  *type;        /**< Field type. */
    bool             has_default;  /**< true = caller may omit (keyword args). */
} n00b_tc_field_t;

/**
 * @brief Record type — named fields, optional type parameters, ordered flag.
 *
 * Records serve as struct bodies, enum variant payloads, and keyword
 * argument bundles.
 *
 * - **ordered=true**: field position matters (struct layout).
 * - **ordered=false**: only field names matter (keyword bag).
 * - **open=true**: row-polymorphic (duck typing / call site).
 * - **open=false**: exactly these fields (definition site).
 */
typedef struct {
    n00b_string_t                  *name;              /**< Record name (empty for anonymous). */
    n00b_list_t(n00b_tc_type_t *)  *type_params;       /**< May be nullptr. */
    n00b_list_t(n00b_string_t *)   *field_names;       /**< Field name per index. */
    n00b_list_t(n00b_tc_type_t *)  *field_types;       /**< Field type per index. */
    n00b_list_t(bool)              *field_has_default;  /**< Per-field; nullptr = none have defaults. */
    bool                            open;              /**< Open row (duck typing). */
    bool                            ordered;           /**< true = struct layout; false = keyword bag. */
} n00b_tc_record_t;

/**
 * @brief Tuple type — ordered, positional product type.
 *
 * Open tuples support row polymorphism on positional elements.
 */
typedef struct {
    n00b_list_t(n00b_tc_type_t *) *elements; /**< Known element types. */
    uint16_t                       min_len;  /**< Minimum tuple length. */
    bool                           open;     /**< true = open (may have more). */
} n00b_tc_tuple_t;

// ============================================================================
// Type node — union-find link + variant payload
// ============================================================================

/**
 * @brief Variant discriminator for the seven type kinds.
 */
typedef n00b_variant_t(
    n00b_tc_var_t,
    n00b_tc_prim_t,
    n00b_tc_param_t,
    n00b_tc_fn_t,
    n00b_tc_sum_t,
    n00b_tc_record_t,
    n00b_tc_tuple_t
) n00b_tc_kind_t;

/**
 * @brief Core type node.
 *
 * Every type is a node in a union-find graph.  `forward` chains to the
 * canonical representative (nullptr = this node is the root).  `kind`
 * holds the type-kind-specific payload via an `n00b_variant_t`.
 *
 * @par Usage
 * @code
 * // Check kind:
 * n00b_variant_is_type(t->kind, n00b_tc_var_t)
 *
 * // Extract payload:
 * auto var = n00b_variant_get(t->kind, n00b_tc_var_t);
 * @endcode
 */
struct n00b_tc_type_s {
    n00b_tc_type_t  *forward;  /**< Union-find link (nullptr = root). */
    n00b_tc_kind_t   kind;     /**< Which kind + kind-specific data. */
    void            *user_data; /**< Language-specific metadata (e.g., sym entry for classes/tuples). */
};

// ============================================================================
// Source spans (for diagnostics)
// ============================================================================

/**
 * @brief Source location span for type error diagnostics.
 */
typedef struct {
    n00b_option_t(n00b_string_t *) file;       /**< Source file (none = stdin). */
    uint32_t                     start_line;
    uint32_t                     start_col;
    uint32_t                     end_line;
    uint32_t                     end_col;
} n00b_tc_span_t;

// ============================================================================
// Errors
// ============================================================================

/**
 * @brief Type error kinds.
 */
typedef enum {
    N00B_TC_ERR_UNIFY_FAIL,         /**< Cannot unify two types. */
    N00B_TC_ERR_CONSTRAINT_FAIL,    /**< Constraint violation. */
    N00B_TC_ERR_OCCURS_CHECK,       /**< Infinite type (Var occurs in its own binding). */
    N00B_TC_ERR_NON_EXHAUSTIVE,     /**< Non-exhaustive match on sum type. */
    N00B_TC_ERR_UNREACHABLE_PATTERN,/**< Pattern already covered. */
    N00B_TC_ERR_DUPLICATE_VARIANT,  /**< Variant appears twice in sum. */
    N00B_TC_ERR_NO_SUCH_FIELD,      /**< Record has no such field. */
    N00B_TC_ERR_PARAM_MISMATCH,     /**< Wrong number of type parameters. */
    N00B_TC_ERR_ARITY_MISMATCH,     /**< Wrong number of function arguments. */
    N00B_TC_ERR_MISSING_KEYWORD,    /**< Missing required keyword argument. */
    N00B_TC_ERR_UNKNOWN_KEYWORD,    /**< Unknown keyword argument. */
    N00B_TC_ERR_NO_MATCHING_RULE,   /**< No type rule matched for production. */
} n00b_tc_err_kind_t;

/**
 * @brief Structured type error with source location and context.
 *
 * Two spans allow errors that reference two source locations (e.g.,
 * conflicting uses of the same variable).
 */
typedef struct {
    n00b_tc_err_kind_t  kind;
    n00b_string_t      *message;       /**< Human-readable error. */
    n00b_tc_type_t     *expected;      /**< What was expected (may be nullptr). */
    n00b_tc_type_t     *got;           /**< What was found (may be nullptr). */
    n00b_string_t      *constraint;    /**< Which constraint failed (may be empty). */
    n00b_tc_span_t      span;          /**< Primary source location. */
    n00b_tc_span_t      related_span;  /**< Secondary location (e.g., conflicting decl). */
} n00b_tc_error_t;

// ============================================================================
// Coercion tracking
// ============================================================================

/**
 * @brief Coercion kinds.
 */
typedef enum {
    N00B_TC_COERCE_PROMOTE,     /**< Numeric widening (i32 -> i64, f32 -> f64). */
    N00B_TC_COERCE_OPTION_WRAP, /**< T -> maybe[T] (implicit option injection). */
    N00B_TC_COERCE_DEREF,       /**< ref[T] -> T (auto-dereference at call sites). */
    N00B_TC_COERCE_CUSTOM,      /**< Grammar-author-registered coercion. */
} n00b_tc_coerce_kind_t;

/**
 * @brief A coercion record emitted when unification succeeds via promotion.
 */
typedef struct {
    n00b_tc_coerce_kind_t  kind;
    n00b_tc_type_t        *from;
    n00b_tc_type_t        *to;
    n00b_tc_span_t         span; /**< Where the coercion occurs. */
} n00b_tc_coercion_t;

// ============================================================================
// Interface types (for registration/querying)
// ============================================================================

/**
 * @brief A named parameter of an interface.
 */
typedef struct {
    n00b_string_t   *name; /**< "key", "value", "element", ... */
    n00b_tc_type_t  *type; /**< Type variable for this param. */
} n00b_tc_iface_param_t;

/**
 * @brief An interface definition.
 */
typedef struct {
    n00b_string_t                       *name;   /**< "Indexable", "Numeric", ... */
    n00b_list_t(n00b_tc_iface_param_t)  *params; /**< Named type parameters. */
} n00b_tc_iface_t;

/**
 * @brief An implementation binding: "dict implements Indexable with [...]".
 */
typedef struct {
    n00b_string_t                 *type_name;  /**< "dict", "list", ... */
    n00b_string_t                 *iface_name; /**< "Indexable", ... */
    n00b_list_t(n00b_tc_type_t *) *bindings;   /**< Concrete types for each iface param. */
} n00b_tc_impl_t;
