// naudit-grammar-bake.c — build-time grammar baking tool (WP-018).
//
// Usage:
//     naudit-grammar-bake <bnf_path> <start_nt> <output.c>
//                         [<symbol_prefix> [<grammar_name>]]
//
// Parses <bnf_path> with the BNF metagrammar, finalizes the resulting grammar,
// then emits C source to <output.c> that unmarshals an identical grammar at
// program startup WITHOUT re-parsing — see `slay/grammar_image.h`.
//
// This tool is the Phase-1 stand-in for an ncc literal form (e.g.
// `bnf"path"`): the ncc xform piece is deferred to a follow-up ncc-repo
// PR (WP-018 DF-EA), so the bake step is wired explicitly via a meson
// `custom_target` rather than triggered by a source-level literal.
//
// Like `n00b-static-init-helper`, this is a build-time HOST tool: it
// links libn00b for the grammar machinery but uses libc for argv/file
// I/O. It is NOT compiled into the shipping binary, so its libc use does
// not fall under the runtime n00b-api-guidelines bans.

#include <stdio.h>
#include <stdlib.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/file_map.h"
#include "slay/grammar.h"
#include "slay/bnf.h"
#include "slay/grammar_image.h"

extern void n00b_init_simple(int argc, char *argv[]);
extern void n00b_shutdown_simple(void);

int
main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <bnf_path> <start_nt> <output.c> "
                "[<symbol_prefix> [<grammar_name>]]\n",
                argv[0]);
        return 2;
    }

    const char *bnf_path      = argv[1];
    const char *start_nt      = argv[2];
    const char *output_path   = argv[3];
    const char *symbol_prefix = (argc > 4) ? argv[4]
                                           : "__naudit_static_grammar";
    const char *grammar_name  = (argc > 5) ? argv[5] : start_nt;

    // The baked grammar is for PWZ-only consumers (naudit). finalize no
    // longer computes the heavy (multi-minute on c_ncc.bnf) first-set /
    // left-corner / LR0 analysis at all — that is Earley-only and now runs
    // lazily in n00b_earley_new — so load + finalize here are already
    // cheap with no flag. The reconstructed runtime grammar finalizes the
    // same way, keeping build-time and runtime structures identical
    // (WP-018 DF-EB / DF-EC).
    // Bring the n00b runtime up FIRST, then read the input with n00b's own
    // file IO (n00b_file_mmap) — no libc malloc/fopen.  (Previously this
    // slurped the file with fopen/fread/malloc BEFORE init, because n00b_alloc
    // is unusable before n00b_init_simple; reordering removes the libc dep.)
    n00b_init_simple(argc, argv);

    n00b_result_t(n00b_buffer_t *) bnf_r
        = n00b_file_mmap(n00b_string_from_cstr(bnf_path));
    if (n00b_result_is_err(bnf_r)) {
        fprintf(stderr, "naudit-grammar-bake: cannot read '%s'\n", bnf_path);
        n00b_shutdown_simple();
        return 3;
    }

    n00b_buffer_t  *bnf_buf  = n00b_result_get(bnf_r);
    n00b_string_t  *bnf_text = n00b_string_from_raw(bnf_buf->data,
                                                    (int64_t)bnf_buf->byte_len);
    n00b_string_t  *start_s  = n00b_string_from_cstr(start_nt);
    n00b_grammar_t *g        = n00b_grammar_new();

    if (!n00b_bnf_load(bnf_text, start_s, g)) {
        fprintf(stderr, "naudit-grammar-bake: failed to parse '%s'\n",
                bnf_path);
        n00b_shutdown_simple();
        return 4;
    }

    // Finalize so the baked image captures the canonical post-finalize
    // structure (including error-recovery rules) that PWZ sees on the
    // first parse.
    n00b_grammar_finalize(g);

    n00b_result_t(n00b_string_t *) emit_r = n00b_grammar_image_emit(
        g,
        n00b_string_from_cstr(symbol_prefix),
        n00b_string_from_cstr(grammar_name));

    if (n00b_result_is_err(emit_r)) {
        n00b_string_t *why = n00b_grammar_image_emit_err_str(
            n00b_result_get_err(emit_r));
        fprintf(stderr, "naudit-grammar-bake: emit failed for '%s': %s\n",
                bnf_path, why->data);
        n00b_shutdown_simple();
        return 5;
    }

    n00b_string_t *emitted = n00b_result_get(emit_r);

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        fprintf(stderr, "naudit-grammar-bake: cannot write '%s'\n",
                output_path);
        n00b_shutdown_simple();
        return 6;
    }
    fwrite(emitted->data, 1, (size_t)emitted->u8_bytes, out);
    fclose(out);

    n00b_shutdown_simple();
    return 0;
}
