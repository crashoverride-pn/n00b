#pragma once

/**
 * @file n00b_module_loader.h
 * @brief Module loading for `use` statements: file discovery, parsing,
 *        compilation, and cross-module symbol merging.
 *
 * ## Path resolution
 *
 * Module search order:
 * 1. `N00B_ROOT/sys/` (if `N00B_ROOT` is set)
 * 2. Directories from `N00B_PATH` (colon-separated)
 * 3. Current working directory
 *
 * ## Cycle detection
 *
 * A per-session loading stack tracks modules currently being compiled.
 * Self-imports are errors; indirect cycles produce a warning and return
 * the cached (partially loaded) module.
 */

#include "slay/codegen.h"
#include "slay/grammar.h"
#include "slay/parse_tree.h"
#include "slay/cf_label.h"
#include "adt/result.h"

/** @brief Failure reasons for @ref n00b_module_load. */
typedef enum {
    N00B_MODULE_LOAD_OK            = 0,
    N00B_MODULE_LOAD_ERR_ARG       = -1, // null session / grammar / module name
    N00B_MODULE_LOAD_ERR_NOT_FOUND = -2, // no matching module file on the path
    N00B_MODULE_LOAD_ERR_CACHE_KEY = -3, // resolved-path identity unavailable
    N00B_MODULE_LOAD_ERR_CIRCULAR  = -4, // circular import detected
    N00B_MODULE_LOAD_ERR_READ      = -5, // module file could not be read
    N00B_MODULE_LOAD_ERR_PARSE     = -6, // parse failed
    N00B_MODULE_LOAD_ERR_ANNOTATE  = -7, // annotation walk failed
    N00B_MODULE_LOAD_ERR_CODEGEN   = -8, // codegen / compile failed
    N00B_MODULE_LOAD_ERR_NO_STATE  = -9, // codegen produced no module state
    N00B_MODULE_LOAD_ERR_DEPENDENCY = -10, // a nested `use` import failed
} n00b_module_load_err_t;

/** @brief Human-readable description of a @ref n00b_module_load error code. */
extern n00b_string_t *n00b_module_load_err_str(n00b_err_t err);

/**
 * @brief Get the module search path.
 *
 * Builds a search path from `N00B_ROOT`, `N00B_PATH`, and CWD.
 *
 * @return List of directory paths, in search order.
 */
n00b_list_t(n00b_string_t *) *n00b_get_module_search_path(void);

/**
 * @brief Load a module by name.
 *
 * Full pipeline: cache check, filesystem search, read, tokenize,
 * parse, annotate, recursive use-stmt resolution, codegen, compile,
 * and symbol merge.
 *
 * @param session      Codegen session (owns module cache and global scope).
 * @param grammar      Grammar for parsing.
 * @param module_name  Module name (last component of dotted path).
 * @param package      Package prefix (everything before last dot), or nullptr.
 * @param from_path    Explicit path from `use X from "path"`, or nullptr.
 * @param caller_path  Directory of the importing file (for relative lookup).
 * @return Ok(module) on success, Err(@ref n00b_module_load_err_t) on failure.
 */
n00b_result_t(n00b_cg_module_t *)
    n00b_module_load(n00b_cg_session_t *session,
                                   n00b_grammar_t    *grammar,
                                   n00b_string_t     *module_name,
                                   n00b_string_t     *package,
                                   n00b_string_t     *from_path,
                                   n00b_string_t     *caller_path);

/**
 * @brief Walk a parse tree for `use-stmt` nodes and resolve each.
 *
 * Called after the annotation walk, before codegen. For each `use-stmt`
 * found, extracts the module path, calls `n00b_module_load`, and links
 * the resulting module's symbols into the session's global scope.
 *
 * @param session  Codegen session.
 * @param grammar  Grammar used for parsing.
 * @param tree     Root of the parse tree to scan.
 * @param annot    Annotation result from the walk.
 * @param caller_path  Directory of the importing file (for relative lookup).
 */
bool n00b_resolve_use_stmts(n00b_cg_session_t   *session,
                            n00b_grammar_t      *grammar,
                            n00b_parse_tree_t   *tree,
                            n00b_annot_result_t *annot,
                            n00b_string_t       *caller_path);
