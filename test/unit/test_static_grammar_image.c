/*
 * WP-018 Phase 1 — static-image grammar caching acceptance tests.
 *
 * Validates that a parsed `n00b_grammar_t` can be baked into a linked object
 * record at build time and looked up as a direct relocated baked root at
 * runtime, producing a grammar structurally identical to a fresh
 * `n00b_bnf_load` parse without the BNF-metagrammar parse on every program
 * start.
 *
 *   Test 1 — bake-tool round-trip: spawn `naudit-grammar-bake` on a
 *            small fixture .bnf and confirm it emits a host object with the
 *            grammar-image section and no legacy generated-C materializer text.
 *   Test 2 — grammar-structure equivalence: the build-time-baked
 *            c_ncc image (linked in) returns a baked grammar whose NT /
 *            rule / match structure matches a fresh runtime parse.
 *   Test 3 — c_ncc round-trip on real C: parse fixture_null.c with both
 *            the static-image grammar and the same fresh runtime grammar;
 *            both succeed and yield structurally-identical parse trees.
 *
 * The c_ncc fresh parse is intentionally shared between Test 2 and Test 3:
 * the build already bakes c_ncc.bnf once as the `c_grammar_image`
 * custom_target, and Test 1 already exercises the bake-tool subprocess
 * contract. Re-baking/re-parsing the full C grammar inside this correctness
 * test added tens of seconds without covering a distinct behavior.
 *
 * The subprocess helper below is a narrow POSIX test harness boundary for
 * build tools whose contract is argv/stdout. File contents are still read and
 * written through n00b_file_*.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "n00b.h"
#include "core/file.h"
#include "core/gc_baked.h"
#include "core/runtime.h"
#include "core/static_image.h"
#include "slay/grammar.h"
#include "slay/bnf.h"
#include "slay/grammar_image.h"
#include "internal/slay/grammar_internal.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "naudit/tokenizer_registry.h"

#ifndef NAUDIT_GRAMMAR_BAKE_PATH
#error "NAUDIT_GRAMMAR_BAKE_PATH must be defined by the build"
#endif
#ifndef NAUDIT_C_NCC_BNF_PATH
#error "NAUDIT_C_NCC_BNF_PATH must be defined by the build"
#endif
#ifndef NAUDIT_C_FIXTURE_PATH
#error "NAUDIT_C_FIXTURE_PATH must be defined by the build"
#endif

// The build-time-baked c_ncc grammar is linked as an object containing a
// n00b_gimage section record under this name (see the meson
// `c_grammar_image` custom_target).
#define C_NCC_IMAGE_NAME r"c_ncc"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

// Test convenience: unwrap the `n00b_option_t(n00b_grammar_t *)` returned
// by `n00b_static_grammar_lookup` to a bare pointer (nullptr when the
// name is unregistered).
static n00b_grammar_t *
lookup_static_grammar(n00b_string_t *name)
{
    auto opt = n00b_static_grammar_lookup(name);
    return n00b_option_is_set(opt) ? n00b_option_get(opt) : nullptr;
}

static bool
buffer_contains_cstr(n00b_buffer_t *buf, const char *needle)
{
    if (buf == nullptr || buf->data == nullptr || needle == nullptr) {
        return false;
    }

    size_t needle_len = strlen(needle);
    if (needle_len == 0 || buf->byte_len < needle_len) {
        return false;
    }

    for (size_t i = 0; i <= buf->byte_len - needle_len; i++) {
        if (memcmp(buf->data + i, needle, needle_len) == 0) {
            return true;
        }
    }

    return false;
}

// A tiny self-contained grammar used by Test 1. Char-level (default
// tokenizer) so the bake tool needs no language tokenizer.
static const char *k_tiny_bnf =
    "<expr> ::= <term> %\"+\" <expr>\n"
    "<expr> ::= <term>\n"
    "<term> ::= %\"a\"\n"
    "<term> ::= %\"b\"\n";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// D-056 C-ABI test harness boundary. The bake program is an external
// executable whose contract is POSIX argv/stdout and NUL-terminated file
// paths. Keep char* construction, snprintf, fork/execv/waitpid confined to
// this helper block; the test assertions and file contents stay on n00b APIs.
static char *
write_temp(const char *suffix, n00b_string_t *contents)
{
    char *path = n00b_alloc_array(char, 256);
    snprintf(path, 256, "/tmp/naudit_wp018_%d_%s", (int)getpid(), suffix);
    auto fr = n00b_file_open(n00b_string_from_cstr(path),
                             .mode = N00B_FILE_W,
                             .kind = N00B_FILE_KIND_STREAM);
    CHECK(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);
    if (contents != nullptr) {
        auto wr = n00b_file_write(f, contents->data, (size_t)contents->u8_bytes);
        CHECK(n00b_result_is_ok(wr));
        CHECK(n00b_result_get(wr) == (size_t)contents->u8_bytes);
    }
    n00b_file_close(f);
    return path;
}

static n00b_buffer_t *
read_whole_buffer(const char *path)
{
    auto fr = n00b_file_open(n00b_string_from_cstr(path),
                             .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    if (n00b_result_is_err(br)) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *buf = n00b_buffer_copy(n00b_result_get(br));
    n00b_file_close(f);
    return buf;
}

static n00b_string_t *
read_whole_text(const char *path, long *len_out)
{
    n00b_buffer_t *buf = read_whole_buffer(path);
    if (buf == nullptr) {
        return nullptr;
    }
    if (len_out != nullptr) {
        *len_out = (long)n00b_buffer_len(buf);
    }
    return n00b_buffer_to_string(buf);
}

static int
run_argv(char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// End D-056 C-ABI test harness boundary.

// Canonicalize an NT node name for structural comparison. Synthetic
// EBNF group / anonymous NTs are named `$$group_<N>` / `$$bnf_anon_<N>`
// where <N> is a *global* counter that advances across every grammar
// built in the process — so the same production gets a different suffix
// in the image grammar vs a later fresh parse. The names are pure
// internal artifacts (PWZ matches groups by structure, not name), so
// strip the trailing `_<digits>` to compare shape, not counter state.
static n00b_string_t *
canon_name(n00b_string_t *name)
{
    if (name == nullptr || name->data == nullptr) {
        return n00b_string_from_cstr("?");
    }
    if (n00b_unicode_str_starts_with(name, r"$$group_")) {
        return n00b_string_from_cstr("$$group");
    }
    if (n00b_unicode_str_starts_with(name, r"$$bnf_anon_")) {
        return n00b_string_from_cstr("$$bnf_anon");
    }
    return name;
}

// Render a parse tree to a canonical structural signature: each interior
// node contributes its (canonicalized) NT name and the bracketed
// signatures of its children; leaves contribute a marker. Two trees with
// the same signature are structurally identical for our purposes.
static void
tree_sig(n00b_parse_tree_t *t, n00b_list_t(n00b_string_t *) *out)
{
    if (t == nullptr) {
        n00b_list_push(*out, n00b_string_from_cstr("<nil>"));
        return;
    }
    if (t->is_leaf) {
        n00b_list_push(*out, n00b_string_from_cstr("L"));
        return;
    }

    n00b_option_t(n00b_string_t *) nm = n00b_parse_node_name(t);
    n00b_string_t *name = n00b_option_is_set(nm)
                              ? canon_name(n00b_option_get(nm))
                              : n00b_string_from_cstr("?");
    n00b_list_push(*out, name);
    n00b_list_push(*out, n00b_string_from_cstr("("));
    for (size_t i = 0; i < t->node.num_children; i++) {
        tree_sig(t->node.children[i], out);
    }
    n00b_list_push(*out, n00b_string_from_cstr(")"));
}

static n00b_string_t *
tree_signature(n00b_parse_tree_t *t)
{
    n00b_list_t(n00b_string_t *) parts
        = n00b_list_new_private(n00b_string_t *);
    tree_sig(t, &parts);
    return n00b_unicode_str_join(n00b_string_empty(),
                                 n00b_list_to_array(n00b_string_t *, parts));
}

// Fresh runtime parse of c_ncc.bnf → finalized grammar.
static n00b_grammar_t *
fresh_c_grammar(void)
{
    n00b_string_t  *text = read_whole_text(NAUDIT_C_NCC_BNF_PATH, nullptr);
    CHECK(text != nullptr);
    // Match the baked image + naudit's PWZ-only load path: instantiating
    // PWZ_ONLY forces the C grammar's error-recovery rules off (see
    // naudit-grammar-bake.c and naudit/engine.c).
    n00b_grammar_t *g  = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    bool            ok = n00b_bnf_load(text, n00b_string_from_cstr("translation_unit"), g);
    CHECK(ok);
    n00b_grammar_finalize(g);
    return g;
}

// Parse a C source file with the given (already-finalized) grammar using
// the registered "c" tokenizer. Returns the parse tree, or nullptr if
// the parse failed.
static n00b_parse_tree_t *
parse_c_file(n00b_grammar_t *g, const char *path)
{
    n00b_buffer_t *buf = read_whole_buffer(path);
    CHECK(buf != nullptr);

    n00b_naudit_tokenizer_info_t *tok =
        n00b_naudit_lookup_tokenizer(n00b_string_from_cstr("c"));
    CHECK(tok != nullptr && tok->scan_cb != nullptr && tok->state_new != nullptr);

    void *st = tok->state_new();
    n00b_scanner_t *sc = n00b_scanner_new(buf, tok->scan_cb, g,
                                          .state    = st,
                                          .reset_cb = tok->reset_cb);
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);

    n00b_parse_result_t *pr = n00b_grammar_parse(g, ts);
    if (n00b_parse_result_ok(pr) == false) {
        return nullptr;
    }
    return n00b_parse_result_tree(pr);
}

// ---------------------------------------------------------------------------
// Test 1 — bake-tool round-trip + standalone compile
// ---------------------------------------------------------------------------

static void
test_bake_roundtrip(void)
{
    char *bnf_path = write_temp("tiny.bnf", n00b_string_from_cstr(k_tiny_bnf));
    char *out_path = write_temp("tiny_image.o", nullptr);

    char *const argv[] = {
        (char *)NAUDIT_GRAMMAR_BAKE_PATH,
        bnf_path,
        (char *)"expr",
        out_path,
        (char *)"__naudit_tiny_grammar",
        (char *)"tiny",
        nullptr,
    };
    int rc = run_argv(argv);
    CHECK(rc == 0);

    n00b_buffer_t *obj = read_whole_buffer(out_path);
    CHECK(obj != nullptr && obj->byte_len > 16);
#if defined(__APPLE__)
    CHECK((uint8_t)obj->data[0] == 0xcf);
    CHECK((uint8_t)obj->data[1] == 0xfa);
    CHECK((uint8_t)obj->data[2] == 0xed);
    CHECK((uint8_t)obj->data[3] == 0xfe);
#elif defined(__ELF__)
    CHECK((uint8_t)obj->data[0] == 0x7f);
    CHECK(obj->data[1] == 'E');
    CHECK(obj->data[2] == 'L');
    CHECK(obj->data[3] == 'F');
#endif
    CHECK(buffer_contains_cstr(obj, "n00b_gimage"));
    CHECK(!buffer_contains_cstr(obj, "__naudit_tiny_grammar_build"));
    CHECK(!buffer_contains_cstr(obj, "n00b_static_grammar_register"));
    CHECK(!buffer_contains_cstr(obj, "n00b_base64_decode"));
    CHECK(!buffer_contains_cstr(obj, "n00b_unmarshal_one"));
    CHECK(!buffer_contains_cstr(obj, "n00b_grammar_image_repair"));
    CHECK(!buffer_contains_cstr(obj, "n00b_grammar_image_begin"));
    CHECK(!buffer_contains_cstr(obj, "n00b_grammar_image_add_rule"));
    CHECK(!buffer_contains_cstr(obj, "n00b_grammar_image_group"));
    CHECK(!buffer_contains_cstr(obj, "n00b_grammar_image_finish"));
}

// ---------------------------------------------------------------------------
// Test 2 — grammar-structure equivalence (image vs fresh runtime parse)
// ---------------------------------------------------------------------------

static n00b_grammar_t *
test_linked_static_lookup(void)
{
    CHECK(lookup_static_grammar(r"__missing_static_grammar") == nullptr);

    n00b_grammar_t *first  = lookup_static_grammar(C_NCC_IMAGE_NAME);
    n00b_grammar_t *second = lookup_static_grammar(C_NCC_IMAGE_NAME);
    CHECK(first != nullptr);
    CHECK(second == first);
    CHECK(n00b_gc_addr_in_baked_region(first));
    return first;
}

static void
test_grammar_structure_equivalence(n00b_grammar_t *img, n00b_grammar_t *fresh)
{
    CHECK(img != nullptr);
    CHECK(fresh != nullptr);

    CHECK(img->nt_list.len == fresh->nt_list.len);
    CHECK(img->rules.len == fresh->rules.len);
    CHECK(img->default_start == fresh->default_start);
    CHECK(img->next_literal_type_id == fresh->next_literal_type_id);

    // Per-rule contents shape must match id-for-id.
    for (size_t i = 0; i < fresh->rules.len; i++) {
        n00b_parse_rule_t *ri = &img->rules.data[i];
        n00b_parse_rule_t *rf = &fresh->rules.data[i];
        CHECK(ri->nt_id == rf->nt_id);
        CHECK(ri->contents.len == rf->contents.len);
        for (size_t j = 0; j < rf->contents.len; j++) {
            CHECK(ri->contents.data[j].kind == rf->contents.data[j].kind);
        }
    }

    // NT names + group flags must match id-for-id.
    for (size_t i = 0; i < fresh->nt_list.len; i++) {
        n00b_nonterm_t *ni = &img->nt_list.data[i];
        n00b_nonterm_t *nf = &fresh->nt_list.data[i];
        CHECK(ni->group_nt == nf->group_nt);
        if (nf->name != nullptr && ni->name != nullptr) {
            CHECK(n00b_unicode_str_eq(nf->name, ni->name));
        }
    }

}

// ---------------------------------------------------------------------------
// Test 3 — c_ncc round-trip on real C source
// ---------------------------------------------------------------------------

static void
test_c_ncc_real_parse(n00b_grammar_t *img, n00b_grammar_t *fresh)
{
    CHECK(img != nullptr);
    CHECK(fresh != nullptr);

    n00b_parse_tree_t *t_img = parse_c_file(img, NAUDIT_C_FIXTURE_PATH);
    CHECK(t_img != nullptr);

    n00b_parse_tree_t *t_fresh = parse_c_file(fresh, NAUDIT_C_FIXTURE_PATH);
    CHECK(t_fresh != nullptr);

    n00b_string_t *sig_img   = tree_signature(t_img);
    n00b_string_t *sig_fresh = tree_signature(t_fresh);

    if (!n00b_unicode_str_eq(sig_img, sig_fresh)) {
        CHECK(false);
    }

    CHECK(sig_img->u8_bytes > 0);
    CHECK(n00b_unicode_str_eq(sig_img, sig_fresh));

}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    test_bake_roundtrip();

    n00b_grammar_t *img   = test_linked_static_lookup();
    n00b_grammar_t *fresh = fresh_c_grammar();

    test_grammar_structure_equivalence(img, fresh);
    test_c_ncc_real_parse(img, fresh);

    return 0;
}
