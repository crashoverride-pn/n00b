/*
 * WP-009 Phase 1 — language-aware audit engine.
 *
 * Replaces the WP-001 Phase 3 hard-coded c_ncc.bnf load with
 * per-file dispatch via naudit's built-in language registry. For
 * each audited file:
 *
 *   1. Resolve the file's language via
 *      `n00b_naudit_lookup_language_by_extension`, consulting the
 *      project's `@extensions` overrides first and the built-in
 *      defaults second.
 *   2. Get-or-load the corresponding merged grammar from a
 *      per-engine cache keyed by language name. A multi-file
 *      invocation against a single language re-uses the same
 *      grammar object — the base grammar + fragments parse +
 *      `n00b_bnf_load` chain runs once per (engine, language)
 *      pair. (DF-V resolution: cache lives on the engine struct
 *      in a single `grammars` dict — string-keyed and populated
 *      on first miss; cache insertion only happens on the full
 *      load-AND-validate success path, so a cache hit implies
 *      D-017 validation already passed.)
 *   3. Construct the language's tokenizer via
 *      `n00b_naudit_lookup_tokenizer` (slay scan-cb + state-new
 *      factory + reset hook), parse, walk the parse tree, emit
 *      one violation per match.
 *
 * The D-017 dangling-`@violation_nt` validation moved from
 * `engine_new` to the per-(language, ruleset) grammar-load path
 * inside `check_file`: each merged grammar is validated against
 * every applicable rule's `violation_nt` exactly once. The
 * cached grammar is only inserted into `engine->grammars` after
 * validation passes, so a cache hit on `grammars` implies the
 * validation already succeeded. A dangling NT name aborts
 * `check_file` with `N00B_AUDIT_ERR_GUIDANCE_SCHEMA`, mirroring
 * the original WP-001 Phase 3 contract.
 *
 * D-018 (WP-007 Phase 2 rewrite blocks + violation `rewrite`
 * field) is preserved verbatim — the per-match rewrite-text
 * lookup loop in `check_file` is unchanged from its post-WP-007
 * shape.
 *
 * Per project DECISIONS.md D-005 / D-017 (the standing
 * compromise), this implementation's public functions carry no
 * `_kargs` block — naudit's existing surface does not thread
 * allocators.
 */

#include "n00b.h"
#include "core/file.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/static_image.h"
#include "adt/result.h"
#include "adt/list.h"
#include "adt/dict.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "internal/slay/grammar_internal.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "slay/rewrite.h"
#include "slay/token.h"
#include "adt/tree.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "conduit/print.h"
#include "util/path.h"

#include "naudit/engine.h"
#include "naudit/guidance.h"
#include "naudit/rule.h"
#include "naudit/violation.h"
#include "naudit/errors.h"
#include "naudit/exemption.h"
#include "naudit/languages.h"
#include "naudit/tokenizer_registry.h"
#include "naudit/filter.h"
#include "naudit/trust_root.h"
#include "naudit/preprocess.h"
#include "n00b/eval.h"

/* ---------------------------------------------------------------- */
/* Engine struct                                                    */
/* ---------------------------------------------------------------- */

/*
 * Engine handle. Per-language merged grammars live in `grammars`,
 * keyed by language name; cache-hit on `grammars` skips both the
 * grammar load and the D-017 dangling-violation_nt validation
 * (the validation runs as part of the same cache-miss path and
 * only succeeds-and-caches together).
 *
 *   - `guidance`  back-pointer to the loaded guidance. The
 *                 engine borrows; the caller owns.
 *   - `grammars`  language-name → merged grammar pointer cache.
 *                 Each entry is a fully composed
 *                 `n00b_grammar_t *` (base grammar + applicable
 *                 rule fragments, post-D-017-validated) loaded
 *                 on first audit of that language. The dict is
 *                 locked (the WP-009 Phase 1 contract is
 *                 single-threaded, but the locked-by-default
 *                 `n00b_dict_new` precedent is the natural
 *                 primitive).
 */
struct n00b_audit_engine {
    n00b_audit_guidance_t                          *guidance;
    n00b_dict_t(n00b_string_t *, n00b_grammar_t *) *grammars;
    /*
     * WP-009 Phase 4 — per-engine embedded-eval session, lazily
     * allocated on the first audit invocation that touches a rule
     * with a filter. The compiled-filter cache maps filter name →
     * JIT'd predicate; populated on first reference so re-runs
     * of the same engine skip recompilation.
     *
     * `filter_compile_failed` short-circuits future audit calls
     * after a previously-failed compile so each subsequent file
     * gets the same propagation rather than a silent retry.
     */
    n00b_eval_session_t                                       *eval_session;
    n00b_dict_t(n00b_string_t *, n00b_eval_predicate_fn_t)    *compiled_filters;
    int                                                        filter_compile_err;
    /*
     * WP-011: when set, `n00b_audit_engine_check_file` skips the
     * baseline-suppression check (still applies the exemption list).
     * Tracks the `--ignore-baseline` CLI flag. Defaults to false.
     */
    bool                                                       ignore_baseline;
    /*
     * WP-012: when set, the exemption + baseline verification gate
     * accepts unsigned / bad-signature / unknown-signer records with
     * a stderr warning instead of dropping them. Tracks the
     * `--allow-unsigned` CLI flag. Defaults to false.
     */
    bool                                                       allow_unsigned;
    /*
     * WP-012: idempotency flag for the signature verification gate.
     * The gate walks `guidance->exemptions` + `guidance->baseline`
     * once on first `check_file` invocation, drops records that
     * don't verify (unless `allow_unsigned`), and sets this flag so
     * subsequent `check_file` calls skip the (expensive) subprocess
     * sweep. Per-engine caching, not per-process — a fresh engine
     * re-verifies.
     */
    bool                                                       signatures_applied;
    /*
     * WP-015: `--repo-protected` policy flag. When set, the
     * REPO-source-roster warning and the unsigned-rule-file warning
     * downgrade from prominent to informational (per white paper
     * § 9.2 + § 6.3 — the running environment has asserted that
     * agent-write access is mediated by CI / pre-commit).
     */
    bool                                                       repo_protected;
    /*
     * WP-015: track whether the trust-root binding fingerprint
     * mismatched. Set by `apply_signature_gate` when the on-disk
     * SYSTEM-slot roster's SHA-256 doesn't match the directive
     * in `audit-rules.bnf`. When set, `check_file` short-circuits
     * with `N00B_AUDIT_ERR_ENGINE_BAD_ARGS` — the audit refuses
     * to proceed.
     */
    bool                                                       trust_root_failed;
    /*
     * WP-017: extra args passed through to `cc -E` when the
     * language's `preprocess` flag is set. Currently driven by the
     * `--cpp-args` CLI flag. Pass e.g. `-I /path -DFOO` to bring
     * project headers into scope. nullptr or empty string is fine.
     */
    n00b_string_t                                             *cpp_args;
};

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/*
 * Read a BNF grammar file (mmap'd) into a fresh n00b_buffer_t *.
 * Returns nullptr on any I/O failure. The buffer is a copy of the
 * mmap'd file content (so we can mutate it via
 * `n00b_buffer_concat` to append rule fragments).
 */
static n00b_buffer_t *
read_grammar_file(n00b_string_t *path)
{
    if (!path) {
        return nullptr;
    }
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return nullptr;
    }
    n00b_buffer_t *mmap_buf = n00b_result_get(br);
    return n00b_buffer_copy(mmap_buf);
}

/*
 * Append `\n<fragment>\n` to `dst` so each merged rule's BNF text
 * is separated from the previous block. A leading newline is
 * safer than relying on the base grammar ending with one; the BNF
 * loader also tolerates extra blank lines.
 */
static void
append_fragment(n00b_buffer_t *dst, n00b_string_t *fragment)
{
    n00b_buffer_t *sep = n00b_buffer_from_bytes((char *)"\n", 1);
    n00b_buffer_concat(dst, sep);
    n00b_buffer_t *body = n00b_buffer_from_bytes(fragment->data,
                                                 (int64_t)fragment->u8_bytes);
    n00b_buffer_concat(dst, body);
    n00b_buffer_concat(dst, sep);
}

/*
 * Decide whether `rule` applies to language `lang_name`.
 *
 * Per WP-009 Phase 1 spec: empty / null `rule->language` means
 * "apply to every supported language whose grammar defines the
 * rule's violation_nt" — so this function returns true. A
 * non-empty list filters by exact-name match.
 */
static bool
rule_applies_to_language(n00b_audit_rule_t *rule,
                         n00b_string_t     *lang_name)
{
    if (!rule || !lang_name) {
        return false;
    }
    if (!rule->language || n00b_list_len(*rule->language) == 0) {
        return true;
    }
    int64_t n = n00b_list_len(*rule->language);
    for (int64_t i = 0; i < n; i++) {
        n00b_string_t *l = n00b_list_get(*rule->language, i);
        if (l && n00b_unicode_str_eq(l, lang_name)) {
            return true;
        }
    }
    return false;
}

/*
 * Build (or fetch from cache) the merged grammar for a language.
 *
 * On a cache miss:
 *   1. Read the language's base grammar file.
 *   2. Sanity-check the base grammar loads on its own — separates
 *      GRAMMAR_LOAD failures from RULE_MERGE failures.
 *   3. Append each applicable rule's `bnf_fragment` to the
 *      combined text.
 *   4. Load the merged text into a fresh grammar object.
 *   5. Validate every applicable rule's `violation_nt` resolves
 *      to an NT in the merged grammar (D-017 dangling-NT check).
 *   6. Cache the grammar by language name.
 *
 * Returns the grammar pointer on success; sets `*err_out` to an
 * `N00B_AUDIT_ERR_*` code and returns nullptr on failure.
 */
/*
 * D-017 dangling-`@violation_nt` validation. For every rule applicable
 * to `lang`, confirm its `@violation_nt` resolves to an NT in `grammar`.
 * A dangling `@violation_nt` sends the parser into pathological
 * behavior on every input, so this fails fast with the canonical
 * schema-error code. Returns true on success; on failure sets
 * `*err_out` to N00B_AUDIT_ERR_GUIDANCE_SCHEMA and returns false.
 *
 * Shared by both the static-image short-circuit and the runtime BNF
 * parse path so the contract is identical regardless of how the
 * grammar was obtained.
 */
static bool
validate_violation_nts(n00b_audit_engine_t         *engine,
                       n00b_naudit_language_info_t *lang,
                       n00b_grammar_t              *grammar,
                       int                         *err_out)
{
    size_t nrules = n00b_list_len(*engine->guidance->rules);
    for (size_t i = 0; i < nrules; i++) {
        n00b_audit_rule_t *rule = n00b_list_get(*engine->guidance->rules,
                                                i);
        if (!rule || !rule->violation_nt
            || rule->violation_nt->u8_bytes == 0) {
            continue;
        }
        if (!rule_applies_to_language(rule, lang->name)) {
            continue;
        }
        if (!n00b_dict_contains(grammar->nt_map, rule->violation_nt)) {
            n00b_eprintf(
                "n00b-audit: rule '«#»': @violation_nt '«#»' does "
                "not resolve to an NT in the «#» base grammar. "
                "For known languages, @violation_nt must name an "
                "existing base-grammar NT; use @filter to narrow.",
                rule->id ? rule->id : n00b_string_empty(),
                rule->violation_nt,
                lang->name);
            *err_out = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
            return false;
        }
    }
    return true;
}

static n00b_grammar_t *
get_or_load_grammar(n00b_audit_engine_t *engine,
                    n00b_naudit_language_info_t *lang,
                    int                 *err_out)
{
    *err_out = 0;

    bool            found     = false;
    n00b_grammar_t *cached    = n00b_dict_get(engine->grammars,
                                              lang->name, &found);
    if (found && cached) {
        return cached;
    }

    /*
     * WP-018 static-image short-circuit. For a KNOWN language (one with
     * a `grammar_path`, so the rule-fragment append path below is never
     * taken) that also has a pre-compiled grammar image baked into the
     * binary, resolve the grammar via `n00b_static_grammar_lookup` and
     * skip the ~1.5s runtime BNF parse + finalize entirely. The lookup
     * materializes the grammar lazily on first call (post-runtime-init)
     * and caches it. We still run the D-017 `@violation_nt` validation
     * and the per-engine cache insert so a cache hit means the same
     * thing on both paths.
     *
     * If the lookup returns nullptr (image not linked into this binary,
     * or an unexpected name), fall through to the runtime parse path —
     * the static image is a fast path, not a hard dependency.
     */
    if (lang->static_grammar_name && lang->grammar_path) {
        auto baked_opt = n00b_static_grammar_lookup(lang->static_grammar_name);
        if (n00b_option_is_set(baked_opt)) {
            n00b_grammar_t *baked = n00b_option_get(baked_opt);
            if (!validate_violation_nts(engine, lang, baked, err_out)) {
                return nullptr;
            }
            /*
             * The materialized grammar is immutable once
             * `n00b_static_grammar_lookup` has finalized it (the
             * static-image registry memoizes a single instance and only
             * ever hands back that pointer; nothing mutates it after
             * finalize). It is therefore safe to cache the same pointer
             * in this per-engine dict and to share it across engines —
             * unlike the runtime-parse path below, which owns a freshly
             * parsed grammar per engine and must free it on validation
             * failure.
             */
            n00b_dict_put(engine->grammars, lang->name, baked);
            return baked;
        }
    }

    /* Step 1: read the language's base grammar. */
    n00b_buffer_t *combined = read_grammar_file(lang->grammar_path);
    if (!combined) {
        *err_out = N00B_AUDIT_ERR_ENGINE_GRAMMAR_LOAD;
        return nullptr;
    }

    /* Step 2: probe-load the base grammar in isolation. */
    {
        n00b_string_t *base_text = n00b_string_from_raw(combined->data,
                                                        (int64_t)combined->byte_len);
        // naudit parses PWZ-only; instantiating PWZ_ONLY forces the
        // Earley-only error-recovery rules off (matches the baked image).
        n00b_grammar_t *probe = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
        bool ok = n00b_bnf_load(base_text, r"translation_unit", probe);
        n00b_grammar_free(probe);
        if (!ok) {
            *err_out = N00B_AUDIT_ERR_ENGINE_GRAMMAR_LOAD;
            return nullptr;
        }
    }

    /*
     * Step 3: append each applicable rule's fragment to the
     * combined text — ONLY for unknown languages.
     *
     * WP-016: for KNOWN languages (those with a registered
     * grammar_path, e.g. c → c_ncc.bnf), the base grammar is
     * used as-is and rules query the resulting parse tree.
     * Appending each rule's fragment onto a complete C grammar
     * extended existing NTs with alternative productions and
     * exploded parse-time ambiguity (Rule 1's
     * `<provided_identifier> ::= <n00b_audit_v_null>` made every
     * identifier 2-way ambiguous, etc.). For known languages
     * rules must instead point `@violation_nt` at an existing
     * base-grammar NT and narrow via `@filter`.
     *
     * For UNKNOWN languages (`grammar_path == nullptr`) — none
     * currently registered — the fragment-build path remains
     * available so a tiny grammar can be assembled from rule
     * fragments alone.
     */
    size_t nrules = n00b_list_len(*engine->guidance->rules);
    if (!lang->grammar_path) {
        for (size_t i = 0; i < nrules; i++) {
            n00b_audit_rule_t *rule = n00b_list_get(*engine->guidance->rules,
                                                    i);
            if (!rule || !rule->bnf_fragment
                || rule->bnf_fragment->u8_bytes == 0) {
                continue;
            }
            if (!rule_applies_to_language(rule, lang->name)) {
                continue;
            }
            append_fragment(combined, rule->bnf_fragment);
        }
    }

    /* Step 4: load the merged grammar. */
    n00b_string_t  *merged_text = n00b_string_from_raw(
        combined->data, (int64_t)combined->byte_len);
    // PWZ-only audit path: instantiate PWZ_ONLY so the runtime-built grammar
    // matches the baked static image (no Earley-only error-recovery rules).
    n00b_grammar_t *grammar = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    bool ok = n00b_bnf_load(merged_text, r"translation_unit", grammar);
    if (!ok) {
        n00b_grammar_free(grammar);
        *err_out = N00B_AUDIT_ERR_ENGINE_RULE_MERGE;
        return nullptr;
    }

    /*
     * Step 5: validate each applicable rule's `violation_nt`
     * resolves to an NT in the merged grammar. A dangling
     * `@violation_nt` sends the parser into pathological
     * behavior on every input — fail fast with the canonical
     * schema-error code (D-017 contract). On failure the
     * just-parsed grammar is freed (unlike the static-image path,
     * which shares a cached image and must not free it).
     */
    if (!validate_violation_nts(engine, lang, grammar, err_out)) {
        n00b_grammar_free(grammar);
        return nullptr;
    }

    /*
     * Step 6: cache. The dict put is keyed by the language's own
     * name pointer (process-lifetime, from the registry). Cache
     * insertion happens only on the success path, so a
     * cache-hit on `grammars` is equivalent to "load AND
     * D-017 validation passed."
     */
    n00b_dict_put(engine->grammars, lang->name, grammar);
    return grammar;
}

/* ---------------------------------------------------------------- */
/* Public entries                                                   */
/* ---------------------------------------------------------------- */

n00b_result_t(n00b_audit_engine_t *)
n00b_audit_engine_new(n00b_audit_guidance_t *guidance)
{
    if (!guidance || !guidance->rules) {
        return n00b_result_err(n00b_audit_engine_t *,
                               N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }

    /*
     * The grammar load no longer happens here. Per WP-009 Phase
     * 1, the engine learns the audited file's language inside
     * `check_file` and loads (or fetches the cached) merged
     * grammar there. `engine_new` only stashes the guidance
     * pointer and initializes the per-language caches.
     */
    struct n00b_audit_engine *e = n00b_alloc_with_opts(
        struct n00b_audit_engine,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    e->guidance = guidance;

    e->grammars = n00b_alloc_with_opts(
        n00b_dict_t(n00b_string_t *, n00b_grammar_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    n00b_dict_init(e->grammars,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true,
                   .scan_kind     = N00B_GC_SCAN_KIND_ALL);

    e->eval_session       = nullptr;
    e->compiled_filters   = nullptr;
    e->filter_compile_err = 0;
    e->ignore_baseline    = false;
    e->allow_unsigned     = false;
    e->signatures_applied = false;
    e->repo_protected     = false;
    e->trust_root_failed  = false;

    return n00b_result_ok(n00b_audit_engine_t *, e);
}

/*
 * WP-011: setter for the engine's per-invocation `ignore_baseline`
 * flag. The CLI calls this when `--ignore-baseline` was passed; the
 * default (false) leaves the baseline as a bulk suppression source.
 */
void
n00b_audit_engine_set_ignore_baseline(n00b_audit_engine_t *engine,
                                       bool                 ignore)
{
    if (!engine) {
        return;
    }
    engine->ignore_baseline = ignore;
}

/*
 * WP-012: setter for the engine's `allow_unsigned` policy flag.
 * Default false; the CLI calls this when `--allow-unsigned` was
 * passed. When set, the exemption / baseline signature gate
 * downgrades verification failure from "drop the record" to
 * "warn + keep the record" — matching the WP-012 prompt's
 * policy contract.
 */
void
n00b_audit_engine_set_allow_unsigned(n00b_audit_engine_t *engine,
                                      bool                 allow)
{
    if (!engine) {
        return;
    }
    engine->allow_unsigned = allow;
}

/*
 * WP-015: setter for the engine's `repo_protected` policy. When
 * set, the REPO-source-roster + unsigned-rule-file warnings
 * downgrade from prominent to informational. Default false (the
 * agent-writable working tree is the conservative assumption per
 * white paper § 9.2 + § 6.3).
 */
void
n00b_audit_engine_set_repo_protected(n00b_audit_engine_t *engine,
                                      bool                 protected_)
{
    if (!engine) {
        return;
    }
    engine->repo_protected = protected_;
}

/*
 * WP-017: setter for the engine's preprocessor extra-args. Driven
 * by the CLI's `--cpp-args` flag. Empty/null means: invoke `cc -E`
 * with only its default flags; expect failures on any source that
 * includes project-specific headers.
 */
void
n00b_audit_engine_set_cpp_args(n00b_audit_engine_t *engine,
                                n00b_string_t       *cpp_args)
{
    if (!engine) {
        return;
    }
    engine->cpp_args = cpp_args;
}

/* ---------------------------------------------------------------- */
/* Filter compilation (WP-009 Phase 4)                              */
/* ---------------------------------------------------------------- */

/*
 * Lazily allocate the per-engine eval session + compiled-filter
 * cache. Returns 0 on success or an N00B_AUDIT_ERR_* code that the
 * caller propagates back to check_file's caller.
 *
 * Per the WP-009 Phase 4 design decision documented in
 * `key_findings`, filter compilation happens lazily on the first
 * audit invocation that touches a filter-bearing rule (rather than
 * eagerly in `n00b_audit_engine_new`). Rationale: rule files
 * without filters pay zero startup cost; rule files with filters
 * front-load the JIT setup once, then per-match invocation is a
 * native call.
 */
static int
ensure_eval_session(n00b_audit_engine_t *engine)
{
    if (engine->eval_session) {
        return 0;
    }
    if (engine->filter_compile_err) {
        return engine->filter_compile_err;
    }

    auto sr = n00b_naudit_filter_session_new();
    if (n00b_result_is_err(sr)) {
        engine->filter_compile_err = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
        return engine->filter_compile_err;
    }
    engine->eval_session = n00b_result_get(sr);

    engine->compiled_filters = n00b_alloc(
        n00b_dict_t(n00b_string_t *, n00b_eval_predicate_fn_t));
    n00b_dict_init(engine->compiled_filters,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true);
    return 0;
}

/*
 * Look up (or compile + cache) a filter's JIT'd predicate by name.
 * Returns nullptr + sets `*err` on failure; the caller treats a
 * failed-compile as N00B_AUDIT_ERR_GUIDANCE_SCHEMA so the diagnostic
 * surface stays consistent with the dangling-name path.
 */
static n00b_eval_predicate_fn_t
get_or_compile_filter(n00b_audit_engine_t *engine,
                      n00b_string_t       *filter_name,
                      int                 *err)
{
    *err = 0;
    if (!filter_name || filter_name->u8_bytes == 0) {
        return nullptr;
    }
    if (engine->filter_compile_err) {
        *err = engine->filter_compile_err;
        return nullptr;
    }
    int session_err = ensure_eval_session(engine);
    if (session_err) {
        *err = session_err;
        return nullptr;
    }

    bool found = false;
    n00b_eval_predicate_fn_t cached =
        n00b_dict_get(engine->compiled_filters, filter_name, &found);
    if (found && cached) {
        return cached;
    }

    if (!engine->guidance->filters) {
        engine->filter_compile_err = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
        *err = engine->filter_compile_err;
        return nullptr;
    }
    bool filter_present = false;
    n00b_audit_filter_t *filter = n00b_dict_get(engine->guidance->filters,
                                                 filter_name,
                                                 &filter_present);
    if (!filter_present || !filter || !filter->expr) {
        engine->filter_compile_err = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
        *err = engine->filter_compile_err;
        return nullptr;
    }

    auto cr = n00b_naudit_filter_compile(engine->eval_session,
                                         filter_name, filter->expr);
    if (n00b_result_is_err(cr)) {
        engine->filter_compile_err = N00B_AUDIT_ERR_GUIDANCE_SCHEMA;
        *err = engine->filter_compile_err;
        return nullptr;
    }
    n00b_eval_predicate_fn_t fn = n00b_result_get(cr);
    n00b_dict_put(engine->compiled_filters, filter_name, fn);
    return fn;
}

/* ---------------------------------------------------------------- */
/* Capture binding (WP-009 Phase 4)                                 */
/* ---------------------------------------------------------------- */

/*
 * Bind each `$name:<NT>` capture declared on the rule to the
 * appropriate descendant of @p match in document order (pre-order
 * DFS — `n00b_pt_search_by_nt`'s documented contract; see
 * `include/slay/parse_tree.h` line 261).
 *
 * Per the WP-009 Phase 4 DF-U resolution: the Nth `$name<I>:<NT>`
 * declaration (in the rule's source-order capture list) binds to
 * the Nth descendant of @p match whose NT matches `<NT>`.
 * Declarations sharing a `<NT>` name resolve positionally; declarations with distinct NT names bind independently (each
 * uses its own zero-th descendant of that NT).
 *
 * Captures whose declared NT has fewer than the requested ordinal
 * of matches in the subtree are left unbound — the filter
 * expression's `arg.capture(name)` then returns nullptr, which
 * the JIT exposes as a falsy value the predicate can detect.
 *
 * The 4096 cap on per-NT match lookups matches
 * `n00b_audit_engine_check_file`'s per-rule cap so the budgets
 * stay aligned.
 */
static void
bind_captures(n00b_audit_rule_t   *rule,
              n00b_parse_tree_t   *match,
              n00b_naudit_match_t *handle)
{
    if (!rule || !rule->captures || !match || !handle) {
        return;
    }
    /*
     * Per-NT counter for declaration-order binding. We rebuild
     * this for every match (matches are independent); within a
     * single match's capture list, the Nth declaration of an NT
     * binds to the Nth descendant.
     */
    int64_t ndecls = n00b_list_len(*rule->captures);
    for (int64_t i = 0; i < ndecls; i++) {
        n00b_audit_capture_decl_t *decl = n00b_list_get(*rule->captures,
                                                         i);
        if (!decl || !decl->name || !decl->nt
            || decl->nt->u8_bytes == 0) {
            continue;
        }
        /*
         * Count how many prior declarations share this NT — that
         * gives us the ordinal of the descendant we want for the
         * current declaration.
         */
        int64_t ordinal = 0;
        for (int64_t j = 0; j < i; j++) {
            n00b_audit_capture_decl_t *prev = n00b_list_get(*rule->captures,
                                                             j);
            if (prev && prev->nt
                && n00b_unicode_str_eq(prev->nt, decl->nt)) {
                ordinal++;
            }
        }

        enum { N00B_AUDIT_ENGINE_MAX_CAPTURE_MATCHES = 4096 };
        n00b_parse_tree_t *cands[N00B_AUDIT_ENGINE_MAX_CAPTURE_MATCHES];
        int n_cands = n00b_pt_search_by_nt(match, decl->nt->data, cands,
                                           N00B_AUDIT_ENGINE_MAX_CAPTURE_MATCHES);
        if (ordinal < n_cands) {
            n00b_naudit_match_bind_capture(handle, decl->name,
                                           cands[ordinal]);
        }
    }
}

/*
 * WP-012 — apply the signature verification gate to the loaded
 * exemption + baseline lists. Walks each record, calls
 * `n00b_audit_exemption_verify` against the roster, and either
 * drops or keeps the record per the engine's `allow_unsigned`
 * policy. Idempotent via `engine->signatures_applied`.
 *
 * Rebuilds the suppression lists in place: records that fail
 * verification are filtered out (unless allow_unsigned), records
 * that pass are kept. The list-of-void-pointer cast pattern is the
 * same one used by the existing suppression loop below.
 *
 * Behavior in the corner cases:
 *   - guidance->allowed_signers_path is null  → no roster on disk:
 *       * allow_unsigned: keep all records + emit ONE roster-
 *         missing warning to stderr (not per-record).
 *       * else: drop all records + emit ONE roster-missing
 *         refusal to stderr.
 *   - roster present, individual record fails verify:
 *       * allow_unsigned: keep record + per-record warning.
 *       * else: drop record + per-record warning.
 *
 * All warnings go to stderr via `n00b_eprintf`; no return code
 * (the gate is advisory — the affected records simply disappear
 * from the suppression list in the strict path).
 */
/*
 * WP-015 — Trust-root checks (run once per engine, ahead of the
 * per-record signature gate).
 *
 *   1. Roster-source kind:
 *        - REPO: warn (prominent without --repo-protected;
 *                informational with).
 *        - SYSTEM / ENV / NONE: no warning.
 *   2. Fingerprint binding (§ 9.1): when the SYSTEM slot is the
 *      source AND `guidance->expected_roster_sha256` is set:
 *        - Hash the on-disk roster.
 *        - Compare to the directive value.
 *        - Mismatch → set `engine->trust_root_failed`; the
 *          subsequent `check_file` short-circuits with
 *          `N00B_AUDIT_ERR_ENGINE_BAD_ARGS`.
 *      (ENV-source rosters skip binding by design — the user/CI
 *      override is taken as an intentional bypass of the system
 *      trust-root mechanism for one-off audits.)
 *   3. Rule-file signature (§ 6.3): when the roster is available:
 *        - Look for `<audit-rules.bnf>.sig`.
 *        - 0: silent accept.
 *        - 1 (unsigned): warn (prominent without --repo-protected;
 *               informational with).
 *        - 2 (bad signature / non-roster signer): refuse — sets
 *               `engine->trust_root_failed`.
 */
static void
apply_trust_root_checks(n00b_audit_engine_t *engine)
{
    n00b_audit_guidance_t *g = engine->guidance;
    if (!g) {
        return;
    }

    n00b_string_t *project_root = g->project_root;
    /*
     * Read the source kind from the guidance struct rather than
     * re-walking the chain via `n00b_audit_roster_source_kind`.
     * The loader cached both `allowed_signers_path` and
     * `allowed_signers_source` from a single chain walk; doing a
     * second walk here could observe different env-var state and
     * desynchronize the path/kind pair (e.g., path came from ENV
     * but the second walk would now return SYSTEM, triggering
     * fingerprint binding against the wrong path). See WP-015
     * code audit W1.
     */
    n00b_audit_roster_source_t kind = g->allowed_signers_source;

    /* (1) repo-source warning. */
    if (kind == N00B_AUDIT_ROSTER_SOURCE_REPO) {
        if (engine->repo_protected) {
            n00b_eprintf(
                "n00b-audit: info: trust roster is at repo path "
                "<project_root>/audit/allowed_signers — --repo-protected "
                "asserted; verifier proceeding");
        }
        else {
            n00b_eprintf(
                "n00b-audit: warning: trust roster lives in the repo "
                "(audit/allowed_signers); commits modifying it must be "
                "commit-signed by a previously-trusted signer for this "
                "audit to be trustworthy (white paper § 9.2). Use "
                "--repo-protected to acknowledge a protected CI / "
                "pre-commit context");
        }
    }

    /* (2) fingerprint binding — SYSTEM slot only. */
    if (kind == N00B_AUDIT_ROSTER_SOURCE_SYSTEM
        && g->allowed_signers_path
        && g->expected_roster_sha256
        && g->expected_roster_sha256->u8_bytes > 0) {
        auto vr = n00b_audit_verify_roster_fingerprint(
            g->allowed_signers_path, g->expected_roster_sha256);
        if (n00b_result_is_err(vr)) {
            n00b_eprintf(
                "n00b-audit: error: could not hash trust roster at «#»: «#»",
                g->allowed_signers_path,
                n00b_audit_err_str(n00b_result_get_err(vr)));
            engine->trust_root_failed = true;
            return;
        }
        int matched = n00b_result_get(vr);
        if (matched != 0) {
            auto hr = n00b_audit_roster_sha256(g->allowed_signers_path);
            n00b_string_t *actual = n00b_result_is_ok(hr)
                                        ? n00b_result_get(hr)
                                        : r"(unknown)";
            n00b_eprintf(
                "n00b-audit: error: trust-root fingerprint mismatch — "
                "@expected_roster_sha256 says «#» but on-disk roster «#» "
                "hashes to «#»; refusing audit (white paper § 9.1). "
                "Update the directive after auditing the trust roster, "
                "or point NAUDIT_ROSTER at a different roster",
                g->expected_roster_sha256,
                g->allowed_signers_path,
                actual);
            engine->trust_root_failed = true;
            return;
        }
    }

    /* (3) Rule-file signature (§ 6.3). */
    if (g->allowed_signers_path && project_root) {
        n00b_string_t *rules_path = n00b_path_simple_join(
            project_root, r"audit-rules.bnf");
        rules_path = n00b_path_canonical(rules_path);
        if (n00b_path_is_file(rules_path)) {
            /*
             * Without an explicit signer-id hint the engine cannot
             * call `ssh-keygen -Y verify -I <id>`; we walk the
             * roster's principals and try each one until one
             * succeeds. That keeps the rule-file-signature flow
             * compatible with multi-signer rosters without
             * requiring a separate `@rules_signer_id` directive.
             * For a single-signer roster (the common case) this
             * loop runs once.
             *
             * The roster file is small (a few entries at most);
             * reading + parsing the principal column inline keeps
             * the diff focused.
             */
            auto fr = n00b_file_open(g->allowed_signers_path,
                                     .kind = N00B_FILE_KIND_MMAP);
            if (n00b_result_is_err(fr)) {
                /*
                 * The chain walk above confirmed the roster path
                 * exists (n00b_path_is_file true at resolution
                 * time), so an open failure here is a TOCTOU /
                 * permission anomaly. Treat as a trust-root
                 * failure rather than silently skipping the
                 * rule-file signature gate — a silent skip would
                 * let a hostile process race the roster and bypass
                 * the § 6.3 check.
                 */
                n00b_eprintf(
                    "n00b-audit: error: could not open trust roster "
                    "at «#» for rule-file signature verification: «#»; "
                    "refusing audit (white paper § 6.3)",
                    g->allowed_signers_path,
                    n00b_audit_err_str(n00b_result_get_err(fr)));
                engine->trust_root_failed = true;
            }
            else {
                n00b_file_t *f  = n00b_result_get(fr);
                auto         br = n00b_file_as_buffer(f);
                n00b_file_close(f);
                if (n00b_result_is_err(br)) {
                    /* Same rationale as the open-failure branch
                     * above: a buffered-read failure on a roster
                     * that just opened is anomalous; surface it. */
                    n00b_eprintf(
                        "n00b-audit: error: could not read trust roster "
                        "at «#» for rule-file signature verification: «#»; "
                        "refusing audit (white paper § 6.3)",
                        g->allowed_signers_path,
                        n00b_audit_err_str(n00b_result_get_err(br)));
                    engine->trust_root_failed = true;
                }
                else {
                    n00b_buffer_t *buf = n00b_result_get(br);
                    const char *d   = buf->data;
                    int64_t     n   = buf->byte_len;
                    int64_t     i   = 0;
                    int         verdict = 1; /* default: unsigned */
                    bool        any_signer_tried = false;
                    while (i < n && verdict != 0) {
                        /* Read one line. */
                        int64_t ls = i;
                        while (i < n && d[i] != '\n') {
                            i++;
                        }
                        int64_t le = i;
                        if (i < n) {
                            i++;
                        }
                        /* Skip leading whitespace + comments. */
                        int64_t s = ls;
                        while (s < le && (d[s] == ' ' || d[s] == '\t')) {
                            s++;
                        }
                        if (s >= le || d[s] == '#') {
                            continue;
                        }
                        /*
                         * First whitespace-bounded field is the
                         * principal id.
                         */
                        int64_t pe = s;
                        while (pe < le && d[pe] != ' ' && d[pe] != '\t') {
                            pe++;
                        }
                        if (pe == s) {
                            continue;
                        }
                        n00b_string_t *principal = n00b_string_from_raw(
                            d + s, (int64_t)(pe - s));
                        any_signer_tried = true;
                        auto sv = n00b_audit_rules_verify_signature(
                            rules_path, g->allowed_signers_path,
                            principal);
                        if (n00b_result_is_ok(sv)) {
                            int v = n00b_result_get(sv);
                            /* Once any principal accepts, we're done. */
                            if (v == 0) {
                                verdict = 0;
                                break;
                            }
                            /*
                             * If at least one principal returns 2
                             * (bad sig / non-roster) and none has
                             * returned 0, keep trying — another
                             * principal in the roster might
                             * succeed. If all signers fail, the
                             * final verdict is 2.
                             */
                            if (v == 2) {
                                verdict = 2;
                            }
                            /* v == 1 (unsigned) sticks. */
                        }
                    }
                    if (!any_signer_tried) {
                        /* Roster has no principals — treat as
                         * "no signer to verify against"; the rule
                         * file is effectively unverifiable. */
                        verdict = 1;
                    }
                    if (verdict == 0) {
                        /* Silent accept. */
                    }
                    else if (verdict == 1) {
                        if (engine->repo_protected) {
                            n00b_eprintf(
                                "n00b-audit: info: audit-rules.bnf is "
                                "unsigned; --repo-protected asserted");
                        }
                        else {
                            n00b_eprintf(
                                "n00b-audit: warning: audit-rules.bnf "
                                "is unsigned — agent or attacker writes "
                                "to it are not detectable by this audit "
                                "(white paper § 6.3). Sign with "
                                "`naudit --sign-rules <path> --key ... "
                                "--signer ...` or pass --repo-protected "
                                "to acknowledge a protected context");
                        }
                    }
                    else { /* verdict == 2 */
                        n00b_eprintf(
                            "n00b-audit: error: audit-rules.bnf signature "
                            "did not verify against any roster principal; "
                            "refusing audit (white paper § 6.3)");
                        engine->trust_root_failed = true;
                    }
                }
            }
        }
    }
}


static void
apply_signature_gate(n00b_audit_engine_t *engine)
{
    if (!engine || engine->signatures_applied) {
        return;
    }
    engine->signatures_applied = true;

    /*
     * WP-015: run the trust-root checks ahead of the per-record
     * signature gate. The two are sequenced (trust root must be
     * verified before we trust any signature against the roster);
     * a trust-root failure short-circuits the per-record gate.
     */
    apply_trust_root_checks(engine);
    if (engine->trust_root_failed) {
        return;
    }

    n00b_audit_guidance_t *g = engine->guidance;
    if (!g) {
        return;
    }

    /* Combined view of "do we have anything to verify?" */
    bool have_exemptions = (g->exemptions
                            && n00b_list_len(*g->exemptions) > 0);
    bool have_baseline   = (g->baseline
                            && n00b_list_len(*g->baseline) > 0);
    if (!have_exemptions && !have_baseline) {
        return;
    }

    /*
     * Roster discovery behavior (WP-012 documented contract):
     *   - roster absent + --allow-unsigned: warn once, accept-all.
     *   - roster absent + strict mode: warn once, refuse-all (clear
     *     the suppression lists).
     *   - roster present: verify per-record below.
     */
    if (!g->allowed_signers_path
        || g->allowed_signers_path->u8_bytes == 0) {
        if (engine->allow_unsigned) {
            n00b_eprintf(
                "n00b-audit: no audit/allowed_signers roster found; --allow-unsigned: accepting all exemption + baseline records");
            return;
        }
        n00b_eprintf(
            "n00b-audit: no audit/allowed_signers roster found; refusing all exemption + baseline records (pass --allow-unsigned to accept)");
        if (have_exemptions) {
            *g->exemptions = n00b_list_new(void *);
        }
        if (have_baseline) {
            *g->baseline = n00b_list_new(void *);
        }
        return;
    }

    /*
     * Per-list verification. We walk each loaded record, attempt
     * to verify its source file against the roster, and either
     * keep the record (verify ok OR allow_unsigned warn-and-keep)
     * or drop it (verify failed under strict mode).
     *
     * Two list shapes — exemptions and baseline — but identical
     * structure. The helper lambda-ish pattern in C: a small
     * walker writing to a fresh list of the same type.
     */
    n00b_list_t(void *) *both[2];
    both[0] = have_exemptions ? g->exemptions : nullptr;
    both[1] = have_baseline ? g->baseline : nullptr;
    const char *labels[2] = {"exemption", "baseline"};

    for (int side = 0; side < 2; side++) {
        n00b_list_t(void *) *src = both[side];
        if (!src) {
            continue;
        }
        n00b_list_t(void *) *keep = n00b_alloc(n00b_list_t(void *));
        *keep = n00b_list_new(void *);
        int64_t n = n00b_list_len(*src);
        for (int64_t i = 0; i < n; i++) {
            n00b_audit_exemption_t *ex =
                (n00b_audit_exemption_t *)n00b_list_get(*src, i);
            if (!ex || !ex->source_file) {
                continue;
            }
            n00b_string_t *signer = ex->signer_id;
            /*
             * Records baselined under WP-011 carry an empty
             * `signer_id`. The verify helper would treat an empty
             * principal as "no name supplied" — ssh-keygen rejects
             * that. Treat empty as missing-signature so the policy
             * decision is the same: drop in strict mode, warn-and-
             * keep in allow_unsigned mode.
             */
            int err = 0;
            if (!signer || signer->u8_bytes == 0) {
                err = N00B_AUDIT_ERR_EXEMPTION_NO_SIGNATURE;
            }
            else {
                auto vr = n00b_audit_exemption_verify(
                    ex->source_file, g->allowed_signers_path, signer);
                if (n00b_result_is_err(vr)) {
                    err = n00b_result_get_err(vr);
                }
            }

            if (err == 0) {
                n00b_list_push(*keep, (void *)ex);
                continue;
            }

            /* Failure path — differentiate diagnostic on err. */
            n00b_string_t *reason = n00b_audit_err_str(err);
            if (engine->allow_unsigned) {
                n00b_eprintf(
                    "n00b-audit: --allow-unsigned: keeping «#» «#» despite signature failure: «#»",
                    n00b_string_from_cstr(labels[side]),
                    ex->source_file,
                    reason);
                n00b_list_push(*keep, (void *)ex);
            }
            else {
                n00b_eprintf(
                    "n00b-audit: refusing «#» «#»: «#»",
                    n00b_string_from_cstr(labels[side]),
                    ex->source_file,
                    reason);
            }
        }
        *src = *keep;
    }
}

n00b_result_t(n00b_list_t(n00b_audit_violation_t *) *)
n00b_audit_engine_check_file(n00b_audit_engine_t *engine,
                             n00b_string_t       *path)
{
    if (!engine || !path) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }

    /*
     * WP-012: apply the signature verification gate before the per-
     * file audit pass. Idempotent — runs once per engine lifetime.
     * Records that fail verification under strict mode are dropped
     * from `guidance->exemptions` / `guidance->baseline` before the
     * suppression loop below ever sees them; records that pass (or
     * that --allow-unsigned re-admits with a warning) survive.
     *
     * WP-015: the gate now also runs the trust-root checks
     * (roster-source warning, fingerprint binding, rule-file
     * signature). A trust-root failure refuses the audit
     * unconditionally — `--allow-unsigned` does not bypass it
     * (the trust-root failure means we can't trust ANY signature
     * against the roster, including a putative bypass).
     */
    apply_signature_gate(engine);
    if (engine->trust_root_failed) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_BAD_ARGS);
    }

    /* Canonicalize the source-file path: cwd-independent
     * diagnostics + downstream I/O regardless of caller cwd. */
    path = n00b_path_canonical(path);

    /*
     * Step 0 (WP-009 Phase 1): resolve the audited file's
     * language via the built-in registry plus any project-level
     * extension overrides on the guidance struct.
     */
    /*
     * `n00b_path_get_extension` returns the extension WITH the
     * leading `.` (see `src/util/path.c::n00b_path_get_extension`,
     * which slices from the `rfind_period` index); the registry's
     * default-extensions list stores entries with the leading `.`
     * too, so the lookup compares apples to apples. The defensive
     * fallback below catches the (unlikely) case where the
     * accessor changes shape in a future libn00b sweep.
     */
    n00b_string_t *ext = n00b_path_get_extension(path);
    if (ext && ext->u8_bytes > 0 && ext->data[0] != '.') {
        n00b_buffer_t *acc = n00b_buffer_from_bytes((char *)".", 1);
        n00b_buffer_t *eb  = n00b_buffer_from_bytes(ext->data,
                                                    (int64_t)ext->u8_bytes);
        n00b_buffer_concat(acc, eb);
        ext = n00b_string_from_raw(acc->data, (int64_t)acc->byte_len);
    }
    n00b_naudit_language_info_t *lang =
        n00b_naudit_lookup_language_by_extension(
            ext, engine->guidance->extension_overrides);
    if (!lang) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_UNKNOWN_LANGUAGE);
    }

    /* Get-or-load the merged grammar for this language. */
    int             err     = 0;
    n00b_grammar_t *grammar = get_or_load_grammar(engine, lang, &err);
    if (!grammar) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               err);
    }

    /* Look up the tokenizer triple by name. */
    n00b_naudit_tokenizer_info_t *tok =
        n00b_naudit_lookup_tokenizer(lang->tokenizer_name);
    if (!tok || !tok->scan_cb || !tok->state_new) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_UNKNOWN_LANGUAGE);
    }

    /* Step 1: open the file. */
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_TARGET_NOT_FOUND);
    }
    n00b_buffer_t *src_buf = n00b_result_get(br);

    /*
     * WP-017: C preprocessor pre-pass. Real n00b C code uses
     * type-as-macro-argument patterns (`n00b_alloc(T)`,
     * `n00b_alloc_array_with_opts(T, n, opts)`, `typehash(T)`,
     * etc.) that the grammar can't parse as raw C — the type name
     * is a keyword or identifier in a position the grammar wants
     * an expression. Shell out to `cc -E` for languages whose
     * registry entry sets the preprocess flag (currently: C only).
     * The output replaces the raw source for tokenization +
     * parse purposes.
     */
    /* WP-017: N00B_NAUDIT_SKIP_PREPROCESS=1 disables the ncc -E
     * pre-pass, useful for testing already-preprocessed input. */
    const char *skip_pp = getenv("N00B_NAUDIT_SKIP_PREPROCESS");
    bool        skip    = skip_pp && skip_pp[0] == '1';
    if (lang->preprocess && !skip) {
        auto pr_buf = n00b_audit_preprocess_c(path, engine->cpp_args);
        if (n00b_result_is_err(pr_buf)) {
            return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                                   N00B_AUDIT_ERR_ENGINE_PARSE);
        }
        src_buf = n00b_result_get(pr_buf);
    }

    /*
     * WP-021: `src_text` MUST be derived from the SAME buffer that is
     * tokenized + parsed below (the post-preprocess `src_buf`), not
     * the raw on-disk source. Filter match handles resolve a match's
     * `.text` by walking `src_text` using the parse tree's token
     * line/column coordinates (see `n00b_naudit_match_text` in
     * filter.c). The preprocessor reflows whitespace (e.g. `int *p`
     * → `int * p`), so a match's column in the preprocessed parse
     * tree does NOT index the same byte in the raw source. Building
     * `src_text` from the raw source while parsing the preprocessed
     * buffer made `.text` resolve to the wrong (or empty) slice, so
     * text-predicate filters (e.g. the NULL rule's `text_contains
     * "NULL"`) silently dropped real violations whenever
     * preprocessing was on — a false-negative for a standards tool.
     */
    n00b_string_t *src_text = n00b_string_from_raw(
        src_buf->data, (int64_t)src_buf->byte_len);

    /* Step 2: set up the tokenizer + token stream via the
     * registry's per-language triple. */
    void *st = tok->state_new();
    n00b_scanner_t *sc = n00b_scanner_new(
        src_buf, tok->scan_cb, grammar,
        .state    = st,
        .reset_cb = tok->reset_cb);
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);

    /* Step 3: parse. The grammar is instantiated PWZ_ONLY — Earley fallback
     * is never useful for this use case (c_ncc.bnf is unambiguous in
     * practice); falling back grinds for hours on real input. If PWZ fails,
     * it's a real parse error to report, not a signal to keep trying. */
    n00b_parse_result_t *pr = n00b_grammar_parse(grammar, ts);
    if (!n00b_parse_result_ok(pr)) {
        n00b_parse_result_free(pr);
        return n00b_result_err(n00b_list_t(n00b_audit_violation_t *) *,
                               N00B_AUDIT_ERR_ENGINE_PARSE);
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    /* Step 4: allocate the result list. */
    n00b_list_t(n00b_audit_violation_t *) *violations =
        n00b_alloc(n00b_list_t(n00b_audit_violation_t *));
    *violations = n00b_list_new(n00b_audit_violation_t *);

    /*
     * Step 5: for every rule applicable to this language, DFS
     * the tree for nodes matching the rule's violation_nt and
     * emit one violation per match.
     *
     * Rules NOT applicable to this language are skipped silently
     * — they don't apply to this file.
     */
    size_t nrules = n00b_list_len(*engine->guidance->rules);
    for (size_t i = 0; i < nrules; i++) {
        n00b_audit_rule_t *rule = n00b_list_get(*engine->guidance->rules,
                                                i);
        if (!rule || !rule->violation_nt
            || rule->violation_nt->u8_bytes == 0) {
            continue;
        }
        if (!rule_applies_to_language(rule, lang->name)) {
            continue;
        }

        const char *nt_cstr = rule->violation_nt->data;

        enum { N00B_AUDIT_ENGINE_MAX_MATCHES_PER_RULE = 4096 };
        n00b_parse_tree_t *matches[N00B_AUDIT_ENGINE_MAX_MATCHES_PER_RULE];
        int n_matches = n00b_pt_search_by_nt(tree, nt_cstr, matches,
                                             N00B_AUDIT_ENGINE_MAX_MATCHES_PER_RULE);

        /*
         * WP-009 Phase 4: resolve the filter predicate once per
         * (rule, file). The predicate is engine-cached so subsequent
         * files audited by the same engine reuse the JIT'd
         * function pointer.
         */
        n00b_eval_predicate_fn_t filter_fn = nullptr;
        if (rule->filter_name && rule->filter_name->u8_bytes > 0) {
            int ferr = 0;
            filter_fn = get_or_compile_filter(engine, rule->filter_name,
                                              &ferr);
            if (ferr) {
                return n00b_result_err(
                    n00b_list_t(n00b_audit_violation_t *) *, ferr);
            }
        }

        for (int m = 0; m < n_matches; m++) {
            n00b_parse_tree_t *match = matches[m];
            if (!match) {
                continue;
            }

            /*
             * WP-009 Phase 4: bind captures + apply the filter
             * BEFORE computing the rest of the violation record.
             * Suppressed matches contribute no list entries.
             */
            if (filter_fn) {
                n00b_naudit_match_t *handle = n00b_naudit_match_new(
                    match, src_text);
                bind_captures(rule, match, handle);
                bool keep = n00b_naudit_filter_apply_handle(filter_fn,
                                                            handle);
                if (!keep) {
                    continue;
                }
            }

            n00b_parse_tree_t *first_leaf = n00b_pt_first_token(match);
            n00b_parse_tree_t *last_leaf  = n00b_pt_last_token(match);
            int64_t line     = 0;
            int64_t col      = 0;
            int64_t end_line = 0;
            int64_t end_col  = 0;
            if (first_leaf) {
                n00b_token_info_t *tk = n00b_parse_node_token(first_leaf);
                if (tk) {
                    line = (int64_t)tk->line;
                    col  = (int64_t)tk->column;
                }
            }
            if (last_leaf) {
                n00b_token_info_t *tk = n00b_parse_node_token(last_leaf);
                if (tk) {
                    end_line = (int64_t)tk->line;
                    end_col  = (int64_t)tk->endcol;
                }
            }

            /*
             * D-018 / WP-007 Phase 2: preserve the rewrite-text
             * lookup for the matched production. Unchanged from
             * the prior shape.
             */
            n00b_string_t *rewrite_text = nullptr;
            if (!n00b_tree_is_leaf(match)) {
                n00b_nt_node_t *pn = &n00b_tree_node_value(match);
                n00b_parse_rule_t *production =
                    n00b_get_node_rule(grammar, pn);
                if (production
                    && n00b_production_has_rewrite(production)) {
                    n00b_result_t(n00b_string_t *) rr =
                        n00b_production_rewrite_text(production, match);
                    if (n00b_result_is_ok(rr)) {
                        rewrite_text = n00b_result_get(rr);
                    }
                }
            }

            n00b_audit_violation_t *v = n00b_alloc(n00b_audit_violation_t);
            v->file       = path;
            v->line       = line;
            v->column     = col;
            v->end_line   = end_line;
            v->end_column = end_col;
            v->rule       = rule;
            v->rewrite    = rewrite_text;
            /*
             * WP-011: compute the region fingerprint from the
             * matched span's source bytes (the locator is already
             * resolved above). The fingerprint becomes part of the
             * violation record and is the matching primitive for
             * exemption + baseline suppression below.
             */
            /*
             * WP-021 / task #14: slice the region bytes from the SAME
             * parsed buffer (`src_text`) the token coordinates index,
             * NOT the raw on-disk file. With preprocessing on, the
             * preprocessor reflows whitespace (`int *p` → `int * p`),
             * so re-reading `path` with preprocessed coordinates sliced
             * the wrong span and gave two identical NULL tokens
             * distinct fingerprints — breaking exemption/baseline
             * suppression.
             */
            n00b_string_t *region_bytes
                = n00b_audit_extract_region_bytes_from_text(
                    src_text, line, col, end_line, end_col);
            v->region_fingerprint = n00b_audit_compute_region_fingerprint(
                region_bytes ? region_bytes : n00b_string_empty());

            /*
             * WP-011 + WP-013: apply the suppression engine. The
             * matcher takes a `repo_root` argument so blame can
             * derive the signing commit from VCS history per the
             * white paper § 5.2 rule (the signing commit is NEVER
             * stored in the exemption record). We pass
             * `guidance->project_root` — `git_repository_discover`
             * inside `n00b_audit_blame_signing_commit` walks up
             * from there to find `.git/`, so subdirectory
             * project_roots are handled correctly. If naudit is
             * invoked outside a git repo, the signing-commit
             * lookup returns a "none" option and the matcher
             * takes the pre-commit fingerprint-only fallback
             * (degradation documented in `naudit/exemption.h`).
             */
            n00b_string_t *repo_root = engine->guidance->project_root;
            int            sim       =
                engine->guidance->blame_similarity_threshold;
            bool suppressed = false;
            if (!engine->ignore_baseline && engine->guidance->baseline) {
                int64_t nb = n00b_list_len(*engine->guidance->baseline);
                for (int64_t k = 0; k < nb && !suppressed; k++) {
                    n00b_audit_exemption_t *ex =
                        (n00b_audit_exemption_t *)
                            n00b_list_get(*engine->guidance->baseline, k);
                    if (n00b_audit_exemption_match(ex, v, repo_root,
                                                    sim)) {
                        suppressed = true;
                    }
                }
            }
            if (!suppressed && engine->guidance->exemptions) {
                int64_t ne =
                    n00b_list_len(*engine->guidance->exemptions);
                for (int64_t k = 0; k < ne && !suppressed; k++) {
                    n00b_audit_exemption_t *ex =
                        (n00b_audit_exemption_t *)
                            n00b_list_get(*engine->guidance->exemptions, k);
                    if (n00b_audit_exemption_match(ex, v, repo_root,
                                                    sim)) {
                        suppressed = true;
                    }
                }
            }
            if (suppressed) {
                continue;
            }

            n00b_list_push(*violations, v);
        }
    }

    n00b_parse_result_free(pr);
    return n00b_result_ok(n00b_list_t(n00b_audit_violation_t *) *, violations);
}
