/**
 * @file test_n00b_extension_methods.c
 * @brief End-to-end test for WP-010 JIT extension-method dispatch.
 *
 * Verifies that the JIT codegen pipeline:
 *   1. Records the typehash of a function parameter whose declared type
 *      is a registered user-defined opaque (via the per-session side
 *      table introduced for D-021).
 *   2. Resolves `arg.method` (postfix-`.` property form) through the
 *      type registry's `ext_vtable` and emits an indirect call to the
 *      registered function pointer.
 *   3. Propagates the method's declared return type through the type
 *      checker (`method_return($0)` inference operator) and the
 *      codegen-side `method_ret_type_to_tag` helper.
 *
 * The test deliberately stays in the libn00b core: it registers a
 * synthetic widget type, attaches an extension method, JITs a tiny
 * `fn run(arg: wp010_widget) -> int { return arg.value }` predicate,
 * and invokes the JIT'd function pointer against two widget instances.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/type_info.h"
#include "core/vtable.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"
#include "n00b/n00b_type_map.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/annot_walk.h"
#include "slay/bnf.h"
#include "slay/codegen.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "text/strings/string_ops.h"
#include "internal/slay/codegen_internal.h"

// ============================================================================
// Synthetic widget type
// ============================================================================

typedef struct wp010_widget_s {
    int64_t value;
} wp010_widget_t;

// The extension method called by the JIT'd predicate. The signature
// has to match the calling convention emitted by
// `n00b_codegen_method_dispatch` (one pointer arg, i64 return), which
// is the MIR_T_I64 ABI used throughout the codegen.
static int64_t
wp010_widget_value(wp010_widget_t *self)
{
    return self ? self->value : 0;
}

// ============================================================================
// Grammar helpers (lifted from test_n00b_programs.c)
// ============================================================================

static n00b_grammar_t *shared_grammar = NULL;

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
        fprintf(stderr, "  [FAIL] n00b_bnf_load failed for n00b.bnf\n");
        n00b_diag_print_all(diag, NULL, "n00b.bnf");
        n00b_diag_ctx_free(diag);
        n00b_grammar_free(g);
        return NULL;
    }

    n00b_diag_ctx_free(diag);
    return g;
}

// ============================================================================
// Test
// ============================================================================

static void
test_jit_extension_method(void)
{
    // (a) Register the synthetic widget type with the type registry.
    //     The registered name (`wp010_widget_t`) is what the type
    //     checker's prim-name lookup matches against and what the
    //     codegen side-table uses to derive the receiver's typehash
    //     in `codegen_func_meta_new`.
    bool reg_ok = N00B_TYPE_REGISTER(wp010_widget_t,
                                     N00B_TYPE_STATIC_TRANSIENT(r"unit test only"));
    assert(reg_ok);

    // (b) Attach the extension method. The C type name string is
    //     `"i64"`; the new return-type bridge maps that to N00B_CG_I64
    //     for the JIT and to the cached `t_i64` for the type checker.
    bool method_ok = n00b_type_add_method(typehash(wp010_widget_t *),
                                          &(n00b_method_t){
                                              .fn          = (n00b_vtable_entry)wp010_widget_value,
                                              .name        = "value",
                                              .return_type = {
                                                  .type_hash = typehash(int64_t),
                                                  .type_name = "i64",
                                              },
                                          });
    assert(method_ok);

    // (c) Parse the predicate function. The receiver type name is the
    //     C name of the registered type so the codegen's reverse name
    //     → typehash lookup hits.
    const char    *src = "func run(arg: wp010_widget_t) -> int { return arg.value }\n";
    n00b_buffer_t *buf = n00b_buffer_from_bytes((char *)src, (int64_t)strlen(src));
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, n00b_lang_tokenize, shared_grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *pr = n00b_grammar_parse(shared_grammar, ts);
    if (!n00b_parse_result_ok(pr)) {
        n00b_string_t *err = n00b_parse_result_error_string(pr);
        fprintf(stderr, "  [FAIL] parse: %.*s\n",
                err ? (int)err->u8_bytes : 0,
                err && err->data ? err->data : "");
    }
    assert(n00b_parse_result_ok(pr));

    n00b_parse_tree_t   *tree = n00b_parse_result_tree(pr);
    n00b_annot_result_t *ar   = n00b_compile_walk(shared_grammar, tree);
    assert(ar != NULL);

    // (d) Create a codegen session and emit the function. The
    //     `n00b_type_map` callback knows about the built-in primitives;
    //     unknown prim names (like `wp010_widget_t`) fall through to
    //     `N00B_CG_I64`, which shares the MIR_T_I64 ABI used by every
    //     pointer-like value.
    n00b_codegen_t *cg = n00b_codegen_new(shared_grammar,
                                          .annot    = ar,
                                          .type_map = n00b_type_map);
    assert(cg != NULL);

    bool emit_ok = n00b_codegen_emit(cg, tree);
    assert(emit_ok);

    n00b_cg_module_t *m = cg->active_module;
    assert(m != NULL);

    typedef int64_t (*run_fn_t)(wp010_widget_t *);
    run_fn_t fn = (run_fn_t)n00b_cg_module_compile(m, "run");
    assert(fn != NULL);

    // (e) Invoke against two distinct widgets to confirm the
    //     receiver flows through to the extension method.
    wp010_widget_t w1   = {.value = 15};
    int64_t        got1 = fn(&w1);
    assert(got1 == 15);

    wp010_widget_t w2   = {.value = 5};
    int64_t        got2 = fn(&w2);
    assert(got2 == 5);

    printf("  [PASS] jit_extension_method (got %lld, %lld)\n",
           (long long)got1,
           (long long)got2);

    n00b_codegen_free(cg);
    n00b_parse_result_free(pr);
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    shared_grammar = load_n00b_grammar();
    assert(shared_grammar != NULL);

    test_jit_extension_method();

    n00b_grammar_free(shared_grammar);
    n00b_shutdown();
    return 0;
}
