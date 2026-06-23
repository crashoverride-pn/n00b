#include "n00b.h"
#include "core/file.h"
#include "core/gc_baked.h"
#include "core/runtime.h"
#include "core/static_image.h"
#include "internal/slay/grammar_internal.h"
#include "naudit/engine.h"
#include "naudit/languages.h"
#include "naudit/tokenizer_registry.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "slay/grammar_image.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/marshal.h"

#ifndef NAUDIT_C_NCC_BNF_PATH
#error "NAUDIT_C_NCC_BNF_PATH must be defined by the build"
#endif
#ifndef NAUDIT_C_FIXTURE_PATH
#error "NAUDIT_C_FIXTURE_PATH must be defined by the build"
#endif

#define C_NCC_IMAGE_NAME r"c_ncc"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static n00b_grammar_t *
lookup_static_grammar(n00b_string_t *name)
{
    auto opt = n00b_static_grammar_lookup(name);
    return n00b_option_is_set(opt) ? n00b_option_get(opt) : nullptr;
}

static n00b_buffer_t *
read_whole_buffer(n00b_string_t *path)
{
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(fr));

    n00b_file_t *f = n00b_result_get(fr);
    auto br = n00b_file_as_buffer(f);
    CHECK(n00b_result_is_ok(br));

    n00b_buffer_t *buf = n00b_buffer_copy(n00b_result_get(br));
    n00b_file_close(f);
    return buf;
}

static n00b_string_t *
read_whole_text(n00b_string_t *path)
{
    n00b_buffer_t *buf = read_whole_buffer(path);
    return n00b_buffer_to_string(buf);
}

static n00b_string_t *
canon_name(n00b_string_t *name)
{
    if (name == nullptr || name->data == nullptr) {
        return r"?";
    }
    if (n00b_unicode_str_starts_with(name, r"$$group_")) {
        return r"$$group";
    }
    if (n00b_unicode_str_starts_with(name, r"$$bnf_anon_")) {
        return r"$$bnf_anon";
    }
    return name;
}

static void
tree_sig(n00b_parse_tree_t *t, n00b_list_t(n00b_string_t *) *out)
{
    if (t == nullptr) {
        n00b_list_push(*out, r"<nil>");
        return;
    }
    if (t->is_leaf) {
        n00b_list_push(*out, r"L");
        return;
    }

    n00b_option_t(n00b_string_t *) nm = n00b_parse_node_name(t);
    n00b_string_t *name = n00b_option_is_set(nm)
                              ? canon_name(n00b_option_get(nm))
                              : r"?";
    n00b_list_push(*out, name);
    n00b_list_push(*out, r"(");
    for (size_t i = 0; i < t->node.num_children; i++) {
        tree_sig(t->node.children[i], out);
    }
    n00b_list_push(*out, r")");
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

static n00b_grammar_t *
fresh_c_grammar(void)
{
    n00b_string_t *text = read_whole_text(
        n00b_string_from_cstr(NAUDIT_C_NCC_BNF_PATH));
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    CHECK(n00b_bnf_load(text, r"translation_unit", g));
    n00b_grammar_finalize(g);
    return g;
}

static n00b_grammar_t *
legacy_heap_materialize(n00b_grammar_t *src)
{
    n00b_marshal_ctx_t *mctx = n00b_marshal_ctx_new();
    n00b_buffer_t *blob = n00b_marshal_incremental(mctx, src);
    n00b_marshal_ctx_destroy(mctx);
    CHECK(blob != nullptr);

    n00b_grammar_t *g = (n00b_grammar_t *)n00b_unmarshal_one(blob);
    CHECK(g != nullptr);
    n00b_grammar_image_repair(g);
    return g;
}

static void
assert_repaired_grammar_state(n00b_grammar_t *g)
{
    CHECK(g != nullptr);
    CHECK(g->tokenizer_name != nullptr);
    CHECK(n00b_unicode_str_eq(g->tokenizer_name, r"c"));

    n00b_string_t *translation_unit = r"translation_unit";
    n00b_string_t *return_kw        = r"return";
    n00b_string_t *identifier       = r"IDENTIFIER";

    bool found = false;
    (void)n00b_dict_get(g->nt_map, translation_unit, &found);
    CHECK(found);

    found = false;
    int64_t return_id = n00b_dict_get(g->terminal_map, return_kw, &found);
    CHECK(found);
    CHECK(n00b_dict_contains(g->valid_tokens, return_id));

    found = false;
    (void)n00b_dict_get(g->literal_type_map, identifier, &found);
    CHECK(found);
}

static void
assert_tokenizer_cached(n00b_grammar_t *g)
{
    CHECK(g != nullptr);
    CHECK(g->tokenize_cb != nullptr);
}

static n00b_parse_tree_t *
parse_c_file(n00b_grammar_t *g, n00b_string_t *path)
{
    n00b_buffer_t *buf = read_whole_buffer(path);
    n00b_naudit_tokenizer_info_t *tok =
        n00b_naudit_lookup_tokenizer(r"c");
    CHECK(tok != nullptr && tok->scan_cb != nullptr && tok->state_new != nullptr);

    void *st = tok->state_new();
    n00b_scanner_t *sc = n00b_scanner_new(buf, tok->scan_cb, g,
                                          .state = st,
                                          .reset_cb = tok->reset_cb);
    n00b_token_stream_t *ts = n00b_token_stream_new(sc);
    n00b_parse_result_t *pr = n00b_grammar_parse(g, ts);
    CHECK(n00b_parse_result_ok(pr));
    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);
    CHECK(tree != nullptr);
    return tree;
}

static n00b_string_t *
parse_signature(n00b_grammar_t *g)
{
    return tree_signature(parse_c_file(
        g, n00b_string_from_cstr(NAUDIT_C_FIXTURE_PATH)));
}

static n00b_audit_guidance_t *
empty_guidance(void)
{
    n00b_audit_guidance_t *g = n00b_alloc_with_opts(
        n00b_audit_guidance_t,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});

    g->schema_version = 1;
    g->project        = r"wp008-phase4";
    g->description    = r"grammar baked equivalence fallback probe";
    g->source_doc     = r"WP-008 Phase 4";
    g->dependencies   = n00b_alloc_with_opts(
        n00b_list_t(n00b_string_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    *g->dependencies  = n00b_list_new(n00b_string_t *,
                                      .scan_kind = N00B_GC_SCAN_KIND_ALL);
    g->rules          = n00b_alloc_with_opts(
        n00b_list_t(n00b_audit_rule_t *),
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_ALL});
    *g->rules         = n00b_list_new(n00b_audit_rule_t *,
                                      .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return g;
}

static void
assert_engine_runtime_fallback(void)
{
    n00b_naudit_language_info_t *lang =
        n00b_naudit_lookup_language_by_name(r"c");
    CHECK(lang != nullptr);

    n00b_string_t *saved_static_name = lang->static_grammar_name;
    lang->static_grammar_name        = r"__phase4_absent_image";

    auto er = n00b_audit_engine_new(empty_guidance());
    CHECK(n00b_result_is_ok(er));
    n00b_audit_engine_t *engine = n00b_result_get(er);

    auto cr = n00b_audit_engine_check_file(
        engine, n00b_string_from_cstr(NAUDIT_C_FIXTURE_PATH));
    lang->static_grammar_name = saved_static_name;

    CHECK(n00b_result_is_ok(cr));
    n00b_list_t(n00b_audit_violation_t *) *violations = n00b_result_get(cr);
    CHECK(violations != nullptr);
    CHECK(n00b_list_len(*violations) == 0);
}

int
main(void)
{
    n00b_init_simple(0, nullptr);

    CHECK(lookup_static_grammar(r"__phase4_absent_image") == nullptr);

    n00b_grammar_t *linked = lookup_static_grammar(C_NCC_IMAGE_NAME);
    CHECK(linked != nullptr);
    CHECK(n00b_gc_addr_in_baked_region(linked));
    assert_repaired_grammar_state(linked);

    n00b_grammar_t *fresh = fresh_c_grammar();
    CHECK(fresh != nullptr);
    CHECK(!n00b_gc_addr_in_baked_region(fresh));
    assert_repaired_grammar_state(fresh);

    n00b_grammar_t *legacy = legacy_heap_materialize(fresh);
    CHECK(legacy != nullptr);
    CHECK(!n00b_gc_addr_in_baked_region(legacy));
    assert_repaired_grammar_state(legacy);

    n00b_string_t *sig_linked = parse_signature(linked);
    n00b_string_t *sig_legacy = parse_signature(legacy);
    n00b_string_t *sig_fresh  = parse_signature(fresh);

    CHECK(sig_linked->u8_bytes > 0);
    CHECK(n00b_unicode_str_eq(sig_linked, sig_legacy));
    CHECK(n00b_unicode_str_eq(sig_linked, sig_fresh));
    assert_engine_runtime_fallback();
    assert_tokenizer_cached(linked);
    assert_tokenizer_cached(legacy);
    assert_tokenizer_cached(fresh);

    return 0;
}
