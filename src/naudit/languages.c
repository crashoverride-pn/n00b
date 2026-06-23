/*
 * WP-009 Phase 1 — built-in language registry.
 *
 * The naudit engine dispatches per-file by extension: an audited
 * `.c` file picks up the C grammar + the C tokenizer; an audited
 * `.h` file uses the same triple; future languages add rows here.
 * The mapping is owned by naudit (not by the project's rule file)
 * because adding a new language is a code change — a new grammar
 * path, a new tokenizer registration — not a per-project knob.
 * Projects may, however, override which file extensions map to a
 * given language; see `n00b_naudit_lookup_language_by_extension`
 * and the `@extensions` directive parsed by `guidance.c`.
 *
 * Initialization is lazy. `init_registry` runs on the first call
 * to any public lookup; we use a one-shot guard rather than a
 * static initializer so libn00b's allocator / string machinery is
 * fully online before the registry constructs its strings.
 *
 * Per project DECISIONS.md D-005 / D-017 (the standing
 * compromise), the public lookups carry no `_kargs` block — they
 * don't allocate after the one-shot init.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "text/strings/string_ops.h"

#include "naudit/languages.h"

#include "audit_paths.h"

/* ---------------------------------------------------------------- */
/* Registry state                                                   */
/* ---------------------------------------------------------------- */

/*
 * The registry's lazy-init guard. Static-initialized to false; set
 * to true exactly once by `init_registry`. The registry is
 * conceptually read-only after init, so reads do not need a fence
 * beyond the natural happens-before from the init store.
 *
 * naudit is single-threaded at the CLI surface today (one
 * invocation = one engine = one guidance load); a future multi-
 * threaded harness will need a real once-init guard, but that is
 * out of WP-009 Phase 1 scope.
 */
static bool registry_initialized = false;

/* The languages list itself (locked dict not needed — read-only). */
static n00b_list_t(n00b_naudit_language_info_t *) *all_languages = nullptr;

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/*
 * Append a single-entry default-extensions list to `dst`. Each
 * call adds one extension string (with the leading `.`) to the
 * list. Returns the same list pointer so the call chain reads
 * naturally at the call site.
 */
static n00b_list_t(n00b_string_t *) *
push_ext(n00b_list_t(n00b_string_t *) *dst, n00b_string_t *ext)
{
    n00b_list_push(*dst, ext);
    return dst;
}

/*
 * Build the registry's single row for C. The grammar path is the
 * existing `N00B_AUDIT_GRAMMAR_PATH` macro from `audit_paths.h`;
 * the tokenizer name is `"c"` (matches the tokenizer registered by
 * `tokenizer_registry.c`). Default extensions are `.c` and `.h`.
 */
static n00b_naudit_language_info_t *
build_c_row(void)
{
    n00b_naudit_language_info_t *row =
        n00b_alloc(n00b_naudit_language_info_t);
    row->name                = r"c";
    row->grammar_path        = n00b_string_from_cstr(N00B_AUDIT_GRAMMAR_PATH);
    row->tokenizer_name      = r"c";
    /*
     * WP-008 Phase 3: the C grammar is baked into the naudit binary as a
     * linked `n00b_gimage` object record named `c_ncc`. The engine resolves it
     * via `n00b_static_grammar_lookup(r"c_ncc")` and skips the runtime BNF
     * parse. `grammar_path` is retained as the fallback source and for the
     * probe-load path on unknown-language fragment builds.
     */
    row->static_grammar_name = r"c_ncc";
    row->preprocess          = true;  /* WP-017: run cc -E before parse. */

    n00b_list_t(n00b_string_t *) *exts = n00b_alloc(
        n00b_list_t(n00b_string_t *));
    *exts = n00b_list_new_private(n00b_string_t *);
    push_ext(exts, r".c");
    push_ext(exts, r".h");
    row->default_extensions = exts;

    return row;
}

/*
 * Build the registry. Called once on first lookup. New languages
 * land here as additional `n00b_list_push` calls — the registry
 * is small enough (1 row at Phase 1) that a linear-scan lookup
 * is fine, and the natural growth pattern is < 10 languages.
 */
static void
init_registry(void)
{
    if (registry_initialized) {
        return;
    }

    n00b_gc_register_root(all_languages);
    all_languages = n00b_alloc(
        n00b_list_t(n00b_naudit_language_info_t *));
    *all_languages = n00b_list_new_private(n00b_naudit_language_info_t *);

    n00b_list_push(*all_languages, build_c_row());

    registry_initialized = true;
}

/* ---------------------------------------------------------------- */
/* Public surface                                                   */
/* ---------------------------------------------------------------- */

n00b_naudit_language_info_t *
n00b_naudit_lookup_language_by_name(n00b_string_t *name)
{
    if (!name) {
        return nullptr;
    }
    init_registry();
    int64_t n = n00b_list_len(*all_languages);
    for (int64_t i = 0; i < n; i++) {
        n00b_naudit_language_info_t *row = n00b_list_get(*all_languages,
                                                         i);
        if (row && row->name && n00b_unicode_str_eq(row->name, name)) {
            return row;
        }
    }
    return nullptr;
}

n00b_naudit_language_info_t *
n00b_naudit_lookup_language_by_extension(
    n00b_string_t                                  *ext,
    n00b_dict_t(n00b_string_t *, n00b_string_t *) *project_overrides)
{
    if (!ext) {
        return nullptr;
    }
    init_registry();

    /*
     * Step 1: project overrides win. If `ext` is in the project's
     * override dict, look up the named language by name and
     * return. Unknown language names in the override dict surface
     * as nullptr here — the canonical caller
     * (`n00b_audit_load_guidance`) validates language names at
     * load time so a runtime dangling-override is a logic error
     * upstream.
     */
    if (project_overrides) {
        bool           found = false;
        n00b_string_t *lang  = n00b_dict_get(project_overrides, ext,
                                             &found);
        if (found && lang) {
            return n00b_naudit_lookup_language_by_name(lang);
        }
    }

    /*
     * Step 2: built-in defaults. Scan every registered language's
     * default-extensions list looking for a bytewise match.
     */
    int64_t n = n00b_list_len(*all_languages);
    for (int64_t i = 0; i < n; i++) {
        n00b_naudit_language_info_t *row = n00b_list_get(*all_languages,
                                                         i);
        if (!row || !row->default_extensions) {
            continue;
        }
        int64_t m = n00b_list_len(*row->default_extensions);
        for (int64_t j = 0; j < m; j++) {
            n00b_string_t *candidate =
                n00b_list_get(*row->default_extensions, j);
            if (candidate && n00b_unicode_str_eq(candidate, ext)) {
                return row;
            }
        }
    }
    return nullptr;
}

n00b_list_t(n00b_naudit_language_info_t *) *
n00b_naudit_all_languages(void)
{
    init_registry();
    return all_languages;
}
