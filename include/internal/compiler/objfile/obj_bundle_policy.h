#pragma once

/**
 * @file obj_bundle_policy.h
 * @brief Internal object-bundle embedded policy evaluation hooks.
 *
 * This header is a private test seam for WP-014. It is not part of the public
 * object-bundle API.
 */

#include "compiler/objfile/obj_bundle.h"

typedef struct n00b_obj_bundle_policy_context
    n00b_obj_bundle_policy_context_t;
typedef struct n00b_eval_session n00b_eval_session_t;

/**
 * @post The internal policy-context type and accessor methods are available
 *       to embedded policy predicate compilation.
 */
extern void n00b_obj_bundle_policy_context_type_register(void);

/**
 * @post On success, returns an eval session ready for object-bundle policy
 *       predicates.
 * @kw allocator Optional allocator for the returned session; default
 *     `nullptr`.
 */
extern n00b_result_t(n00b_eval_session_t *)
n00b_obj_bundle_policy_eval_session_new(
    n00b_obj_bundle_policy_scope_t scope) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @post Returns a read-only extraction policy context for synthetic predicate
 *       evaluation.
 * @kw overwrite Whether extraction may replace an existing path; default
 *     `false`.
 * @kw create_dirs Whether extraction may create parent directories; default
 *     `true`.
 * @kw policy_mode Policy enforcement mode; default
 *     `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allocator Optional allocator for the returned context; default
 *     `nullptr`.
 */
extern n00b_obj_bundle_policy_context_t *
n00b_obj_bundle_policy_context_for_extraction(
    n00b_string_t                    *logical_path,
    n00b_obj_bundle_artifact_kind_t   artifact_kind) _kargs {
    bool                         overwrite   = false;
    bool                         create_dirs = true;
    n00b_obj_bundle_policy_mode_t policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @post Returns a read-only execution policy context for synthetic predicate
 *       evaluation.
 * @kw selection_source Source that selected the executable artifact; default
 *     `N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT`.
 * @kw inherit_env Whether execution may inherit the process environment;
 *     default `true`.
 * @kw strict_selector Whether selector matching is strict; default `false`.
 * @kw requested_mode Requested execution mode; default
 *     `N00B_OBJ_BUNDLE_EXEC_AUTO`.
 * @kw policy_mode Policy enforcement mode; default
 *     `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allocator Optional allocator for the returned context; default
 *     `nullptr`.
 */
extern n00b_obj_bundle_policy_context_t *
n00b_obj_bundle_policy_context_for_execution(
    n00b_string_t                           *logical_path,
    n00b_obj_bundle_artifact_kind_t          artifact_kind) _kargs {
    n00b_obj_bundle_exec_selection_source_t selection_source =
        N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT;
    bool                         inherit_env     = true;
    bool                         strict_selector = false;
    n00b_obj_bundle_exec_mode_t  requested_mode  = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t *allocator = nullptr;
};

/** @post Returns the context policy scope, or `0` for `nullptr`. */
extern int64_t n00b_obj_bundle_policy_context_scope(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns the context logical path, or an empty string when absent. */
extern n00b_string_t *n00b_obj_bundle_policy_context_logical_path(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns the context artifact kind, or `0` for `nullptr`. */
extern int64_t n00b_obj_bundle_policy_context_artifact_kind(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns the execution selection source, or `0` when absent. */
extern int64_t n00b_obj_bundle_policy_context_selection_source(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns whether extraction may overwrite an existing path. */
extern bool n00b_obj_bundle_policy_context_overwrite(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns whether extraction may create parent directories. */
extern bool n00b_obj_bundle_policy_context_create_dirs(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns whether execution may inherit the process environment. */
extern bool n00b_obj_bundle_policy_context_inherit_env(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns whether execution uses strict selector matching. */
extern bool n00b_obj_bundle_policy_context_strict_selector(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns the requested execution mode, or `0` when absent. */
extern int64_t n00b_obj_bundle_policy_context_requested_mode(
    n00b_obj_bundle_policy_context_t *context);

/** @post Returns the policy enforcement mode, or `0` for `nullptr`. */
extern int64_t n00b_obj_bundle_policy_context_policy_mode(
    n00b_obj_bundle_policy_context_t *context);

/**
 * @post On success, returns whether the embedded policy predicate allowed the
 *       synthetic operation represented by @p context.
 * @kw allocator Optional allocator for transient evaluation objects; default
 *     `nullptr`.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_policy_evaluate_embedded(
    n00b_eval_session_t                  *session,
    const n00b_buffer_t                  *payload,
    uint64_t                              fallback_policy_id,
    n00b_obj_bundle_policy_scope_t        scope,
    n00b_obj_bundle_policy_context_t     *context) _kargs {
    n00b_allocator_t *allocator = nullptr;
};
