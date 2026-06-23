/*
 * WP-001 Phase 4 — terminal-format output renderer.
 *
 * Implements `n00b_audit_print_terminal`, which emits one block per
 * violation to stdout via libn00b's conduit / print substrate:
 *
 *   <file>:<line>:<col>: <rule_id>: <title> (<source_doc> <section>)
 *     | <good_example line 1>
 *     | <good_example line 2>
 *     ...
 *
 * The `  | ` prefix on the good-example block is grep-stable
 * (preflight Q7 settlement).
 *
 * Capture-mechanism note (Phase 4 W-4 settlement). The terminal
 * renderer writes to libn00b's runtime stdout topic via
 * `n00b_print` / `n00b_printf` (fd 1). The Phase 4 regression test
 * captures output via POSIX `pipe()` + `dup2()` in the test harness
 * (where libc is allowed per the relaxed test-file convention),
 * which redirects the kernel's fd 1 / fd 2 onto pipe write ends
 * before invoking `n00b_audit_run_cli`. libn00b's fd-writer holds
 * the integer fd number, so post-dup2 writes flow to the pipe
 * read-end. This avoids any API-surface refactor: the production
 * code path is untouched and remains test-observable. Approach (b)
 * — an explicit output-target parameter — was considered but
 * rejected as more invasive for the same result.
 *
 * Per project DECISIONS.md D-005, this implementation's public
 * functions carry no `_kargs` block — n00b-audit's own surface does
 * not expose `.allocator` keyword arguments. Per D-005 there is also
 * no `severity` field in the rendered output.
 *
 * NCC.md "Rich string literals" gotcha: `r"..."` literals cannot
 * carry `«#»` substitution markers or use C-style adjacent-literal
 * concatenation. The format templates with substitutions in this
 * file are plain C strings (`"..."`) passed to `n00b_cformat` /
 * `n00b_printf`.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/result.h"
#include "adt/list.h"
#include "adt/array.h"
#include "conduit/print.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"

#include "naudit/output.h"
#include "naudit/violation.h"
#include "naudit/rule.h"
#include "naudit/guidance.h"
#include "naudit/errors.h"

/* ---------------------------------------------------------------- */
/* Helpers                                                          */
/* ---------------------------------------------------------------- */

/*
 * Render one violation's header line:
 *   <file>:<line>:<col>: <rule_id>: <title> (<source_doc> <section>)
 *
 * The format template is a plain C string (passed to `n00b_cformat`)
 * because `r"..."` cannot carry `«#»` markers (NCC.md).
 *
 * Returns nullptr on any rule-field-missing problem; the caller
 * surfaces that as `N00B_AUDIT_ERR_CLI_RENDER`.
 */
static n00b_string_t *
render_header(n00b_audit_violation_t *v, n00b_audit_guidance_t *guidance)
{
    if (!v || !v->rule) {
        return nullptr;
    }
    n00b_audit_rule_t *rule = v->rule;
    if (!v->file || !rule->id || !rule->title || !rule->section) {
        return nullptr;
    }

    /*
     * `<source_doc>` is read from the guidance struct (project-wide
     * field, not per-rule — every rule in a single guidance file
     * cites the same source document by current v1 contract). If
     * guidance is null or the field is null, render an empty string
     * in that slot rather than failing outright.
     */
    n00b_string_t *source_doc = (guidance && guidance->source_doc)
                                    ? guidance->source_doc
                                    : r"";

    /*
     * WP-011 (D-X3): include the rule's content hash + the region
     * fingerprint in the violation header so audit consumers can
     * craft exemption records by copy-paste. The hash is the value
     * exemptions key off (per D-X3); the fingerprint is the WP-011
     * substitute for the WP-013 blame anchor.
     */
    n00b_string_t *content_hash = rule->content_hash
                                      ? rule->content_hash
                                      : r"";
    n00b_string_t *region_fp = v->region_fingerprint
                                   ? v->region_fingerprint
                                   : r"";

    return n00b_cformat(
        "«#»:«#»:«#»: «#» [hash=«#»]: «#» («#» «#») [region=«#»]",
        v->file,
        (int64_t)v->line,
        (int64_t)v->column,
        rule->id,
        content_hash,
        rule->title,
        source_doc,
        rule->section,
        region_fp);
}

/*
 * Emit the rule's good-example block, each line prefixed with
 * `  | ` (two spaces, pipe, space — grep-stable per the WP-001
 * preflight Q7 settlement). Splits the example on `\n` boundaries
 * via libn00b's `n00b_unicode_str_split_lines`.
 *
 * Returns true on success; false if the rule is missing a required
 * field for the format contract.
 */
static bool
emit_good_example_block(n00b_audit_rule_t *rule)
{
    if (!rule || !rule->good_example) {
        return false;
    }

    /*
     * `n00b_unicode_str_split_lines` returns a typed array; iterate
     * via array_get / array_len (the standard libn00b shape).
     * Empty good-example renders as one empty-block line per the
     * format contract — emit the prefix even if the example is the
     * empty string so the block is visually marked.
     */
    n00b_array_t(n00b_string_t *) lines =
        n00b_unicode_str_split_lines(rule->good_example);

    size_t n = n00b_array_len(lines);
    if (n == 0) {
        n00b_print(r"  | ");
        return true;
    }
    for (size_t i = 0; i < n; i++) {
        n00b_string_t *ln = n00b_array_get(lines, i);
        if (!ln) {
            ln = r"";
        }
        n00b_printf("  | «#»", ln);
    }
    return true;
}

/* ---------------------------------------------------------------- */
/* Public entry                                                     */
/* ---------------------------------------------------------------- */

n00b_result_t(int)
n00b_audit_print_terminal(n00b_list_t(n00b_audit_violation_t *) *violations,
                          n00b_audit_guidance_t                  *guidance)
{
    if (!violations) {
        return n00b_result_err(int, N00B_AUDIT_ERR_CLI_RENDER);
    }

    size_t n = n00b_list_len(*violations);
    for (size_t i = 0; i < n; i++) {
        n00b_audit_violation_t *v = n00b_list_get(*violations, i);
        if (!v) {
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_RENDER);
        }
        n00b_string_t *header = render_header(v, guidance);
        if (!header) {
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_RENDER);
        }
        n00b_print(header);
        if (!emit_good_example_block(v->rule)) {
            return n00b_result_err(int, N00B_AUDIT_ERR_CLI_RENDER);
        }
        /*
         * WP-007 Phase 2: when the violation carries a suggested
         * rewrite (only rules with a `rewrite { template: ... }`
         * block in the guidance file populate this — rules 1, 4,
         * and 7 of the canonical guidance), emit a single
         * "suggested fix: <text>" line indented to match the
         * `  | ` block above. The text is the bytes slay's
         * `n00b_production_rewrite_text` produced, verbatim.
         */
        if (v->rewrite && v->rewrite->u8_bytes > 0) {
            n00b_printf("  suggested fix: «#»", v->rewrite);
        }
    }

    return n00b_result_ok(int, (int)n);
}
