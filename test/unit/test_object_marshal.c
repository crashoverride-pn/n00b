// test_object_marshal.c — WP-C: a JIT-allocated n00b object (a class instance)
// is GC-precise and marshalable.
//
// JITs a class with a value field (int) and a pointer field (string),
// constructs an instance, then marshals and unmarshals it and verifies BOTH
// fields survive. This only round-trips correctly if the per-type GC layout
// (the gc_descriptor that codegen builds and registers via
// n00b_gc_type_map_register, keyed by the type hash passed to
// n00b_builtin_obj_alloc) classified the pointer vs. non-pointer fields
// correctly: marshal follows the registered pointer offsets, so a
// mis-classified field either corrupts (value treated as pointer) or drops the
// reference (pointer treated as value).
//
// We drive compilation through the embedded-eval session (the only
// library-level entry point that loads the stdlib builtins). The session leaves
// its `_n00b_eval_install` MIR module open for FFI installs; we finish it
// before running our own module so MIR will accept a fresh module.

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/marshal.h"
#include "slay/codegen.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "internal/slay/codegen_internal.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "n00b/eval.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

// Pt { x: int; label: string }  —  x is a value (word 0), label is a pointer
// (word 1). The trailing bare `p` is the final top-level expression, so the
// synthesized `_main` returns the instance pointer as its i64 result.
static const char *PROGRAM =
    "class Pt {\n"
    "  x: int\n"
    "  label: string\n"
    "}\n"
    "var p = Pt(7, \"origin\")\n"
    "p\n";

static void
test_jit_object_marshal_round_trip(void)
{
    auto sr = n00b_eval_session_new();
    CHECK(n00b_result_is_ok(sr));
    n00b_eval_session_t *s  = n00b_result_get(sr);
    n00b_cg_session_t   *cg = n00b_eval_session_cg(s);
    n00b_grammar_t      *g  = n00b_eval_session_grammar(s);

    // The session leaves `_n00b_eval_install` open for FFI installs. Finish it
    // (compile with no entry just finalizes/links the empty module) so
    // run_module's MIR_new_module is not rejected with "previous module not
    // finished".
    if (cg->active_module && cg->active_module->state == N00B_CG_MOD_BUILDING) {
        n00b_cg_module_compile(cg->active_module, nullptr);
    }

    // Parse the program against the session grammar.
    n00b_buffer_t       *buf = n00b_buffer_from_bytes((char *)PROGRAM,
                                                (int64_t)strlen(PROGRAM));
    n00b_scanner_t      *sc  = n00b_scanner_new(buf, n00b_lang_tokenize, g);
    n00b_token_stream_t *ts  = n00b_token_stream_new(sc);
    n00b_parse_result_t *pr  = n00b_grammar_parse(g, ts);
    CHECK(pr != nullptr && n00b_parse_result_ok(pr));

    n00b_parse_tree_t   *tree = n00b_parse_result_tree(pr);
    n00b_annot_result_t *ar   = n00b_compile_walk(g, tree);
    CHECK(ar != nullptr);

    // Compile + run the module; `_main` returns the instance pointer as i64.
    bool    ok = false;
    int64_t r  = n00b_cg_session_run_module(cg,
                                           tree,
                                           .annot = ar,
                                           .ok    = &ok);
    CHECK(ok);

    void *obj = (void *)(uintptr_t)r;
    CHECK(obj != nullptr);

    // Field layout (WP-B): x at word 0 (int value), label at word 1
    // (n00b_string_t *).
    int64_t        x_before     = ((int64_t *)obj)[0];
    n00b_string_t *label_before = ((n00b_string_t **)obj)[1];
    CHECK(x_before == 7);
    CHECK(label_before != nullptr);
    CHECK(n00b_unicode_str_eq(label_before, n00b_string_from_cstr("origin")));

    // Marshal round-trip: precise scanning must follow `label` (a pointer) and
    // treat `x` (a value) inline.
    n00b_buffer_t *mbuf = n00b_marshal(obj);
    CHECK(mbuf != nullptr);

    void *obj2 = n00b_unmarshal_one(mbuf);
    CHECK(obj2 != nullptr);

    int64_t        x_after     = ((int64_t *)obj2)[0];
    n00b_string_t *label_after = ((n00b_string_t **)obj2)[1];

    // x is a value: had it been mis-classified as a pointer, marshal would have
    // tried to follow `7` as an object and corrupted/crashed. label is a
    // pointer: had it been mis-classified as a value, marshal would have copied
    // the raw pointer bits inline and never followed the reference, so its
    // content could not be recovered into the rebuilt graph. Both surviving a
    // round-trip is the precision proof.
    //
    // The pointer identity is intentionally NOT asserted: `"origin"` is an
    // interned static string literal, so marshal serializes it by identity and
    // unmarshal legitimately restores the same interned object — equal content
    // is the invariant, equal-or-distinct pointer is an implementation detail.
    CHECK(x_after == 7);                                    // value survived inline
    CHECK(label_after != nullptr);                          // pointer was followed
    CHECK(n00b_unicode_str_eq(label_after, label_before));  // content intact

    n00b_eval_session_free(s);
    printf("  [PASS] jit_object_marshal_round_trip\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running object marshal tests...\n");
    test_jit_object_marshal_round_trip();
    printf("All object marshal tests passed.\n");

    n00b_shutdown();
    return 0;
}
