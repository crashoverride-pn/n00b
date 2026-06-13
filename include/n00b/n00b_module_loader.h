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
 * @param package      Package prefix (everything before last dot), or NULL.
 * @param from_path    Explicit path from `use X from "path"`, or NULL.
 * @param caller_path  Directory of the importing file (for relative lookup).
 * @return Loaded module, or NULL on error.
 */
n00b_cg_module_t *n00b_module_load(n00b_cg_session_t *session,
                                    n00b_grammar_t     *grammar,
                                    const char          *module_name,
                                    const char          *package,
                                    const char          *from_path,
                                    const char          *caller_path);

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
                             n00b_grammar_t       *grammar,
                             n00b_parse_tree_t    *tree,
                             n00b_annot_result_t  *annot,
                             const char           *caller_path);
