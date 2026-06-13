#pragma once

/**
 * @file rewrite.h
 * @brief Slay-level rewrite mechanism: inline captures + rewrite-block
 *        templates attached to BNF productions.
 *
 * A consumer-facing layer on top of the slay grammar API. Captures are
 * declared on a production's RHS via `$name:<nt>` syntax; a rewrite
 * block immediately following the production carries a template
 * (with `$name` / `${name}` substitution points) plus arbitrary
 * `key: value` metadata fields.
 *
 * ## Syntax (within `n00b_bnf_load`)
 *
 * ```
 * <prod> ::= %"NULL"
 * rewrite {
 *     template: nullptr
 *     description:
 *     Replaces NULL with the C23 standard nullptr keyword.
 * }
 *
 * <malloc_call> ::= %"malloc" %"(" $sz:<expression> %")"
 * rewrite {
 *     template: n00b_alloc_array(char, $sz)
 *     description: Replace malloc(N) with the n00b allocator.
 * }
 * ```
 *
 * `{=* ... =*}` blocks (with N `=` characters on each side) supply
 * leveled delimiters for blocks whose body might contain a bare `}`.
 * Block contents may use `[==[ ... ]==]` (any number of `=`) as
 * exact-byte heredoc values within fields.
 *
 * ## API surface
 *
 * - `n00b_production_has_rewrite()` — does this production carry a
 *   rewrite block?
 * - `n00b_production_rewrite_text()` — apply the rewrite, substituting
 *   captures with the matched source bytes verbatim (preserves
 *   whitespace + comments from the original input).
 * - `n00b_production_rewrite_subtree()` — apply the rewrite, substituting
 *   captures with re-rendered subtrees via @ref n00b_pretty_print
 *   (canonical formatting).
 * - `n00b_production_rewrite_field()` — read a named metadata field
 *   (e.g., "description", "references").
 * - `n00b_production_capture_names()` — enumerate the capture names
 *   declared on the production's RHS.
 *
 * A "production" in this API is an `n00b_parse_rule_t` — the same
 * type the slay grammar core uses for a single rule body of an NT.
 */

#include "slay/grammar.h"
#include "slay/parse_tree.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"

// ============================================================================
// Production type alias
// ============================================================================

/**
 * @brief A production: a single rule body for some NT.
 *
 * Synonymous with @ref n00b_parse_rule_t. The rewrite API treats
 * each rule as one "production" (BNF terminology).
 */
typedef n00b_parse_rule_t n00b_production_t;

// ============================================================================
// Error codes
// ============================================================================

/** @brief Null production or null parse-tree node. */
#define N00B_ERR_REWRITE_NULL_INPUT       (-1)

/** @brief Production has no rewrite block attached. */
#define N00B_ERR_REWRITE_NO_BLOCK         (-2)

/** @brief Required `template:` field missing from rewrite block. */
#define N00B_ERR_REWRITE_NO_TEMPLATE      (-3)

/** @brief `$name` reference in template names a capture that wasn't
 *         declared on the production's RHS. */
#define N00B_ERR_REWRITE_UNDEFINED_CAPTURE (-4)

/** @brief Capture's child index is out of range on the parse-tree node. */
#define N00B_ERR_REWRITE_NO_CHILD          (-5)

/** @brief Internal pretty-printer failure during subtree-mode apply. */
#define N00B_ERR_REWRITE_PPRINT_FAILED     (-6)

/**
 * @brief Return a short, static description for a rewrite error code.
 *
 * @param err  Error code from @ref n00b_production_rewrite_text or
 *             @ref n00b_production_rewrite_subtree.
 * @return     Static description, or a generic "(unknown)" string.
 */
extern n00b_string_t *n00b_rewrite_err_str(n00b_err_t err);

// ============================================================================
// Predicates
// ============================================================================

/**
 * @brief Does this production carry a rewrite block?
 *
 * @param p  Production to inspect (or nullptr).
 * @return   True iff @p p has an attached rewrite block with a
 *           `template:` field.
 */
extern bool n00b_production_has_rewrite(n00b_production_t *p);

// ============================================================================
// Apply API
// ============================================================================

/**
 * @brief Apply the production's rewrite template, substituting captures
 *        with the matched bytes from the input verbatim.
 *
 * The default substitution mode. Captures preserve whitespace +
 * comments from the source. Cheap; no pretty-printer dependency.
 *
 * @param p     Production carrying the rewrite block.
 * @param node  Parse-tree node matching @p p.
 *
 * @return On success, `n00b_result_ok(n00b_string_t *, formatted)`.
 *         On failure, an err result with one of `N00B_ERR_REWRITE_*`.
 *
 * @kw allocator  Allocator for the returned string and all internal
 *                scratch. nullptr = runtime default. (default: nullptr)
 *
 * @pre  @p p has a rewrite block (see @ref n00b_production_has_rewrite).
 * @pre  @p node was produced by parsing @p p.
 * @post On `ok`, the returned string is independently allocated under
 *       `.allocator`.
 */
extern n00b_result_t(n00b_string_t *)
n00b_production_rewrite_text(n00b_production_t *p,
                             n00b_parse_tree_t *node) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply the production's rewrite template, substituting captures
 *        with subtrees re-rendered via the slay pretty-printer.
 *
 * The subtree path: each capture's matched node is canonicalized via
 * @ref n00b_pretty_print before substitution. Useful when the caller
 * wants canonical formatting in the rewrite output. Slower than the
 * text path; pulls in the pretty-printer dependency.
 *
 * @param p     Production carrying the rewrite block.
 * @param node  Parse-tree node matching @p p.
 *
 * @return On success, `n00b_result_ok(n00b_string_t *, formatted)`.
 *         On failure, an err result with one of `N00B_ERR_REWRITE_*`.
 *
 * @kw allocator  Allocator for the returned string and all internal
 *                scratch. nullptr = runtime default. (default: nullptr)
 *
 * @pre  @p p has a rewrite block (see @ref n00b_production_has_rewrite).
 * @pre  @p node was produced by parsing @p p.
 * @post On `ok`, the returned string is independently allocated under
 *       `.allocator`.
 */
extern n00b_result_t(n00b_string_t *)
n00b_production_rewrite_subtree(n00b_production_t *p,
                                n00b_parse_tree_t *node) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Metadata accessors
// ============================================================================

/**
 * @brief Read a named rewrite-metadata field.
 *
 * Returns the raw value as it appears in the rewrite block, with
 * per-field leading/trailing whitespace stripped (heredoc values
 * preserve all interior bytes).
 *
 * @param p           Production to inspect.
 * @param field_name  Field name string, e.g. `r"description"`,
 *                    `r"references"`, `r"severity"`.
 *
 * @return Some(value) if the field is present; none() otherwise.
 *         The `template:` field is also accessible via this API.
 */
extern n00b_option_t(n00b_string_t *)
n00b_production_rewrite_field(n00b_production_t *p,
                              n00b_string_t     *field_name);

/**
 * @brief Enumerate the capture names declared on a production's RHS.
 *
 * Names appear in source order. The returned list is freshly allocated
 * (the caller may free it without affecting the production).
 *
 * @param p  Production to inspect (nullptr returns an empty list).
 * @return   List of capture-name strings, in declaration order.
 *           Never nullptr; may be empty.
 *
 * @kw allocator  Allocator for the returned list. nullptr = runtime
 *                default. (default: nullptr)
 */
extern n00b_list_t(n00b_string_t *) *
n00b_production_capture_names(n00b_production_t *p) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Set the grammar used by @ref n00b_production_rewrite_subtree.
 *
 * Subtree-mode rewrites need a grammar to drive the pretty-printer;
 * the public rewrite-subtree API takes only (production, parse-tree-node)
 * plus kwargs to keep the surface aligned with the rewrite-syntax spec.
 * Callers of subtree mode must set the active grammar with this function
 * before invoking @ref n00b_production_rewrite_subtree. Text-mode
 * rewrites do not require this.
 *
 * @warning Module-level mutable state. Concurrent callers from different
 *          threads using different grammars MUST serialize externally;
 *          this back-channel does NOT take a lock.
 *
 * @param g  Grammar to make active (may be nullptr to clear).
 */
extern void n00b_rewrite_set_grammar(n00b_grammar_t *g);

// ============================================================================
// Internal builder API (used by the BNF loader)
// ============================================================================

/**
 * @internal
 * @brief Attach a freshly-parsed rewrite block to a production.
 *
 * Called by `n00b_bnf_load` after a `rewrite { ... }` block follows
 * a production. The block body is parsed once into a field map; the
 * production retains a sidecar reference to the parsed result.
 *
 * @param p       Production to receive the rewrite block.
 * @param body    Raw block contents (between the leveled braces,
 *                exclusive of the delimiters themselves).
 * @return        True iff the block parsed successfully and contained
 *                a `template:` field; false otherwise.
 *
 * @kw allocator  Allocator for the rewrite info + field map. nullptr =
 *                runtime default. (default: nullptr)
 */
extern bool _n00b_production_attach_rewrite(n00b_production_t *p,
                                            n00b_string_t     *body) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @internal
 * @brief Attach a capture-name → child-index entry to a production.
 *
 * Called by `n00b_bnf_load` for each `$name:<nt>` capture encountered
 * in the production's RHS. The order of calls determines the order in
 * which @ref n00b_production_capture_names returns names.
 *
 * @param p         Production to receive the capture entry.
 * @param name      Capture name (without the leading `$`).
 * @param child_ix  Child index in the produced parse-tree node.
 *
 * @kw allocator  Allocator for the capture table + entry. nullptr =
 *                runtime default. (default: nullptr)
 */
extern void _n00b_production_add_capture(n00b_production_t *p,
                                         n00b_string_t     *name,
                                         int32_t            child_ix) _kargs {
    n00b_allocator_t *allocator = nullptr;
};
