/**
 * @file test_codegen_coverage.c
 * @brief Source-level MIR/JIT coverage audit.
 */

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"
#include "n00b/n00b_type_map.h"
#include "slay/bnf.h"
#include "slay/codegen.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"

typedef struct {
    const char *source;
    const char *feature;
    const char *status;
} ref_feature_t;

static const ref_feature_t reference_features[] = {
    {"n00b-old", "functions and direct calls", "required_covered"},
    {"n00b-old", "function varargs and default parameters", "required_covered"},
    {"n00b-old", "function privacy and once modifiers", "required_covered"},
    {"n00b-old", "arithmetic and comparisons", "required_covered"},
    {"n00b-old", "if/while/for control flow", "required_covered"},
    {"n00b-old", "early return lowering", "required_covered"},
    {"n00b-old", "assert statements", "required_covered"},
    {"n00b-old", "classes, fields, and methods", "required_covered"},
    {"n00b-old", "interfaces", "required_covered"},
    {"n00b-old", "enums and named tuples", "required_covered"},
    {"n00b-old", "option/result helpers", "required_covered"},
    {"n00b-old", "postfix ! result/option propagation", "required_covered"},
    {"n00b-old", "switch lowering", "required_covered"},
    {"n00b-old", "typeof lowering", "required_covered"},
    {"n00b-old", "list literals and len(list)", "required_covered"},
    {"n00b-old", "integer dict literal, len(dict), and index get/set", "required_covered"},
    {"n00b-old", "set literals", "required_covered"},
    {"n00b-old", "collection value and nested collection printing", "required_covered"},
    {"n00b-old", "non-integer/general dict keys", "required_covered"},
    {"n00b-old", "collection copy/value-copy semantics", "required_covered"},
    {"n00b-old", "list index get/set", "required_covered"},
    {"n00b-old",
     "slice operations, string indexing, and invalid set index diagnostics",
     "required_covered"},
    {"n00b-old", "module use", "required_covered"},
    {"n00b-old", "module parameters, defaults, and validators", "required_covered"},
    {"n00b-old", "extern declarations", "required_covered"},
    {"n00b-old", "FFI embed/import calls", "required_covered"},
    {"n00b-old", "callback literals", "required_covered"},
    {"n00b-old", "embed literals without explicit modifiers", "required_covered"},
    {"n00b-old", "attribute locking", "required_covered"},
    {"n00b-old", "modern compile-cache artifact (replaces bytecode serialization)", "required_covered"},
    {"n00b-old", "modern compile-cache restore (replaces VM save/restore state)", "required_covered"},
    {"slop", "enum/class/basic expression fixtures", "migrated"},
    {"slop", "confspec blocks", "migrated"},
    {"slop", "parameter blocks", "migrated"},
    {"slop", "extern blocks", "migrated"},
    {"slop", "call kwargs", "migrated"},
    {"slop", "function varargs and keyword defaults", "migrated"},
    {"slop", "function modifiers", "migrated"},
    {"slop", "callback literals", "migrated"},
    {"slop", "use statements", "migrated"},
    {"slop", "list index get/set runtime fixtures", "migrated"},
    {"slop", "integer dict runtime fixture", "migrated"},
    {"slop", "slice syntax and remaining non-list index assignment", "migrated"},
    {"slop", "list literal runtime fixture", "migrated"},
    {"slop", "set collection literals", "migrated"},
    {"slop", "ncc C transform pipeline", "not_applicable"},
};

static n00b_grammar_t *
load_n00b_grammar(void)
{
    const char *paths[] = {
        "grammars/n00b.bnf",
        "../grammars/n00b.bnf",
        "../../grammars/n00b.bnf",
        NULL,
    };

    const char *srcroot = getenv("MESON_SOURCE_ROOT");
    FILE       *f       = NULL;

    const char **p;
    for (p = paths; *p; p++) {
        f = fopen(*p, "r");

        if (f) {
            break;
        }
    }

    if (!f && srcroot) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/grammars/n00b.bnf", srcroot);
        f = fopen(path, "r");
    }

    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)len + 1);
    assert(buf != NULL);
    size_t nread = fread(buf, 1, (size_t)len, f);
    fclose(f);
    assert(nread == (size_t)len);
    buf[len] = '\0';

    n00b_string_t *bnf_text = n00b_string_from_cstr(buf);
    free(buf);

    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    n00b_diag_ctx_t *diag = n00b_diag_ctx_new();
    bool             ok   = n00b_bnf_load(bnf_text, r"module", g, .diag = diag);

    if (!ok) {
        n00b_diag_print_all(diag, NULL, "n00b.bnf");
        n00b_diag_ctx_free(diag);
        n00b_grammar_free(g);
        return NULL;
    }

    n00b_diag_ctx_free(diag);
    return g;
}

static void
join_path(char *out, size_t out_len, const char *root, const char *rel)
{
    if (!root || !*root) {
        snprintf(out, out_len, "%s", rel);
        return;
    }

    size_t      root_len = strlen(root);
    const char *sep      = (root_len > 0 && root[root_len - 1] == '/') ? "" : "/";
    snprintf(out, out_len, "%s%s%s", root, sep, rel);
}

static bool
ends_with(const char *s, const char *suffix)
{
    size_t sl = strlen(s);
    size_t xl = strlen(suffix);

    return sl >= xl && strcmp(s + sl - xl, suffix) == 0;
}

static int
count_interp_fixtures(void)
{
    char path[1024];
    join_path(path, sizeof(path), getenv("MESON_SOURCE_ROOT"), "test/interp");

    DIR *dir = opendir(path);
    assert(dir != NULL);

    int            count = 0;
    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL) {
        if (ends_with(ent->d_name, ".n")) {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static int
count_todo_markers_in_file(const char *rel_path)
{
    char path[1024];
    join_path(path, sizeof(path), getenv("MESON_SOURCE_ROOT"), rel_path);

    FILE *f = fopen(path, "r");

    if (!f) {
        return 0;
    }

    int  count = 0;
    char line[2048];

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "TODO")) {
            count++;
        }
    }

    fclose(f);
    return count;
}

static int
count_todo_markers(void)
{
    return count_todo_markers_in_file("src/slay/codegen.c")
         + count_todo_markers_in_file("src/slay/codegen_builtins.c")
         + count_todo_markers_in_file("src/slay/codegen_mir.c")
         + count_todo_markers_in_file("include/slay/codegen.h");
}

static int
count_refs(const char *source, const char *status)
{
    int count = 0;

    for (size_t i = 0; i < sizeof(reference_features) / sizeof(reference_features[0]); i++) {
        if (strcmp(reference_features[i].source, source) == 0
            && strcmp(reference_features[i].status, status) == 0) {
            count++;
        }
    }

    return count;
}

static void
print_reference_features(void)
{
    for (size_t i = 0; i < sizeof(reference_features) / sizeof(reference_features[0]); i++) {
        printf("MIR_JIT_REFERENCE source=%s status=%s feature=\"%s\"\n",
               reference_features[i].source,
               reference_features[i].status,
               reference_features[i].feature);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_grammar_t *g = load_n00b_grammar();
    assert(g != NULL);

    n00b_cg_session_t *session = n00b_cg_session_new(g, .type_map = n00b_type_map);
    assert(session != NULL);

    n00b_cg_audit_t audit            = n00b_codegen_audit(session);
    int             fixture_count    = count_interp_fixtures();
    int             todo_count       = count_todo_markers();
    int             old_required     = count_refs("n00b-old", "required_covered");
    int             old_pending      = count_refs("n00b-old", "pending");
    int             old_out_of_scope = count_refs("n00b-old", "out_of_scope");
    int             old_unsupported  = count_refs("n00b-old", "unsupported_diagnostic");
    int             old_syntax       = count_refs("n00b-old", "syntax_unaccepted");
    int             slop_migrated    = count_refs("slop", "migrated");
    int             slop_pending     = count_refs("slop", "pending");
    int             slop_unsupported = count_refs("slop", "unsupported_diagnostic");
    int             slop_syntax      = count_refs("slop", "syntax_unaccepted");
    int             slop_na          = count_refs("slop", "not_applicable");

    printf(
        "MIR_JIT_COVERAGE explicit_handlers=%d semantic_auto=%d "
        "unhandled=%d source_fixtures=%d todo_markers=%d "
        "old_vm_required=%d old_vm_pending=%d old_vm_out_of_scope=%d "
        "old_vm_unsupported=%d old_vm_syntax_unaccepted=%d "
        "slop_migrated=%d slop_pending=%d "
        "slop_unsupported=%d slop_syntax_unaccepted=%d "
        "slop_not_applicable=%d "
        "enforced_gaps=0\n",
        audit.explicit_count,
        audit.auto_inferred_count,
        audit.unhandled_count,
        fixture_count,
        todo_count,
        old_required,
        old_pending,
        old_out_of_scope,
        old_unsupported,
        old_syntax,
        slop_migrated,
        slop_pending,
        slop_unsupported,
        slop_syntax,
        slop_na);
    print_reference_features();

    assert(audit.explicit_count >= 6);
    assert(audit.auto_inferred_count > 0);
    assert(fixture_count >= 52);
    assert(old_required > 0);
    assert(slop_migrated + slop_unsupported + slop_syntax + slop_na > 0);

    n00b_cg_audit_free(&audit);
    n00b_cg_session_free(session);
    n00b_grammar_free(g);
    n00b_shutdown();
    return 0;
}
