#pragma once

/**
 * @file naudit/languages.h
 * @brief Built-in language registry for naudit (WP-009 Phase 1).
 *
 * Naudit's per-file dispatch needs to know, for any audited source
 * file, which grammar to load and which tokenizer to invoke. That
 * mapping is owned by **naudit itself** — a hardcoded table of
 * supported languages plus their default file extensions. Project
 * rule files may override the extension set per language (via the
 * `@extensions` top-level directive parsed by `guidance.c`), but
 * they cannot redefine a language's grammar or tokenizer. Adding a
 * new language is a naudit-side commit, not a per-project concern.
 *
 * The Phase 1 registry has exactly one entry — `c` — pointing at
 * the vendored `c_ncc.bnf` (configure-time-baked
 * `N00B_AUDIT_GRAMMAR_PATH`) and at the `"c"` tokenizer in
 * `tokenizer_registry.h`. Future language additions (n00b, Python,
 * etc.) land here as new const-data rows.
 *
 * Per project DECISIONS.md D-006, the header filename is unprefixed
 * (`naudit/languages.h`); symbol-level prefix discipline (the
 * `n00b_naudit_` prefix matching WP-008's
 * `n00b_naudit_register_rule_file_tokenizer` precedent) is in
 * force. See `_kargs` discipline note on the lookup APIs below.
 *
 * Headers under `include/naudit/` may be #included standalone, so
 * this file pulls `<n00b.h>` defensively for the `n00b_string_t` /
 * `n00b_list_t` / `n00b_dict_t` declarations.
 */

#include <n00b.h>
#include "adt/list.h"
#include "adt/dict.h"

/**
 * @brief One row in the naudit built-in language registry.
 *
 * Populated lazily on the first registry lookup (see
 * `n00b_naudit_lookup_language_by_name`); the resulting list is
 * read-only after init.
 *
 * Field meanings:
 *  - `name`                short language name (e.g. `r"c"`).
 *  - `grammar_path`        absolute path to the language's BNF
 *                          grammar file (configure-time baked by
 *                          the meson build, e.g.
 *                          `N00B_AUDIT_GRAMMAR_PATH` for C).
 *  - `tokenizer_name`      key into the tokenizer registry (see
 *                          `naudit/tokenizer_registry.h`); same
 *                          string as `name` when the language and
 *                          tokenizer share a name.
 *  - `static_grammar_name` lookup name of the pre-compiled
 *                          (build-time-baked) grammar image for this
 *                          language. When non-null the engine resolves
 *                          the grammar with `n00b_static_grammar_lookup`
 *                          and skips the runtime BNF parse. `nullptr`
 *                          for languages without a baked image (the
 *                          engine falls back to parsing `grammar_path`).
 *                          For C this is `r"c_ncc"`, matching the name
 *                          passed to the `c_grammar_image` object bake
 *                          step in the meson build.
 *  - `default_extensions`  file extensions associated with this
 *                          language out of the box, each carrying
 *                          the leading `.` (e.g. `r".c"`, `r".h"`
 *                          for C). Always non-null and non-empty
 *                          on a registered language.
 */
typedef struct {
    n00b_string_t                *name;
    n00b_string_t                *grammar_path;
    n00b_string_t                *tokenizer_name;
    n00b_string_t                *static_grammar_name;
    n00b_list_t(n00b_string_t *) *default_extensions;
    /*
     * WP-017: when true, the engine runs `cc -E` over the source
     * before tokenizing. Real n00b C code uses type-as-macro-
     * argument patterns that the grammar can't parse without
     * preprocessor expansion. Per-language flag so other
     * tokenizer/grammar pairs that don't need preprocessing don't
     * pay the subprocess cost.
     */
    bool                          preprocess;
} n00b_naudit_language_info_t;

/**
 * @brief Look up a language descriptor by name.
 *
 * Returns the const-data row whose `name` field matches `name`, or
 * `nullptr` if no language by that name is registered. Names are
 * case-sensitive bytewise compares (`c` and `C` are distinct).
 *
 * Per project DECISIONS.md D-005 / D-017, this function carries no
 * `_kargs` block — naudit's surface does not expose `.allocator`
 * keyword arguments. New WP-009 APIs that allocate carry `_kargs
 * { allocator = nullptr }` per the compromise; pure lookups (no
 * allocation on the happy path) do not.
 *
 * @param name  Language name to look up.
 *
 * @return Pointer to the registered descriptor, or `nullptr` if not
 *         found. The returned pointer has process lifetime — never
 *         freed.
 */
extern n00b_naudit_language_info_t *
n00b_naudit_lookup_language_by_name(n00b_string_t *name);

/**
 * @brief Look up a language descriptor by file extension.
 *
 * First consults `project_overrides` (a dict mapping extension
 * strings → language names) if non-null; falls back to the
 * built-in default extensions of each registered language.
 * Extensions carry the leading `.` (e.g. `r".c"`).
 *
 * Per project DECISIONS.md D-005 / D-017, this function carries no
 * `_kargs` block.
 *
 * @param ext               File extension (with leading `.`).
 * @param project_overrides Optional dict: ext-string → language-name.
 *                          May be `nullptr` (no project overrides).
 *
 * @return Pointer to the registered descriptor, or `nullptr` if no
 *         language matches. The returned pointer has process
 *         lifetime.
 */
extern n00b_naudit_language_info_t *
n00b_naudit_lookup_language_by_extension(
    n00b_string_t                                  *ext,
    n00b_dict_t(n00b_string_t *, n00b_string_t *) *project_overrides);

/**
 * @brief Return the list of all registered languages.
 *
 * Used by the engine to validate project-supplied `@language`
 * annotations at guidance-load time. The returned list is the
 * registry's own private/unlocked backing list and must not be
 * mutated. It is read-only after registry initialization and is not
 * safe for concurrent caller mutation.
 *
 * Per project DECISIONS.md D-005 / D-017, this function carries no
 * `_kargs` block.
 *
 * @return Non-null list of `n00b_naudit_language_info_t *` rows.
 */
extern n00b_list_t(n00b_naudit_language_info_t *) *
n00b_naudit_all_languages(void);
