#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "adt/dict.h"
#include "core/runtime.h"
#include "internal/slay/grammar_internal.h"
#include "parsers/tokenizer_registry.h"
#include "slay/grammar_image.h"
#include "util/assert.h"
#include "util/comptime_image.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

static n00b_uint128_t
bad_hash(void *value)
{
    (void)value;
    return (n00b_uint128_t)0xdeadbeefU;
}

static void *
dummy_action(n00b_nt_node_t *node, void *children, void *thunk)
{
    (void)node;
    (void)children;
    return thunk;
}

static int
dummy_disambiguator(n00b_parse_tree_t *a, n00b_parse_tree_t *b)
{
    (void)a;
    (void)b;
    return 0;
}

static bool
dummy_tokenizer(n00b_scanner_t *scanner)
{
    (void)scanner;
    return false;
}

static void
poison_hash(_n00b_dict_internal_t *d)
{
    CHECK(d != nullptr);
    d->fn = bad_hash;
    d->skip_obj_hash = false;
}

static void
check_hash(_n00b_dict_internal_t *d, n00b_hash_fn expected)
{
    CHECK(d != nullptr);
    CHECK(d->fn == expected);
    CHECK(d->skip_obj_hash == true);
}

static n00b_grammar_t *
new_repair_fixture(n00b_string_t *tokenizer_name)
{
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    n00b_nonterm_t *nt = n00b_nonterm(g, r"expr");
    int64_t terminal_id = n00b_register_terminal(g, r"TOKEN");
    n00b_register_literal_type(g, r"IDENTIFIER");
    n00b_grammar_set_terminal_category(g, terminal_id, r"name");
    n00b_add_rule(g, nt, N00B_TERMINAL(terminal_id));
    n00b_grammar_set_start(g, nt);
    n00b_grammar_finalize(g);

    if (tokenizer_name != nullptr) {
        g->tokenizer_name = tokenizer_name;
    }
    return g;
}

static void
poison_repair_targets(n00b_grammar_t *g)
{
    poison_hash((_n00b_dict_internal_t *)g->nt_map);
    poison_hash((_n00b_dict_internal_t *)g->terminal_map);
    poison_hash((_n00b_dict_internal_t *)g->literal_type_map);
    poison_hash((_n00b_dict_internal_t *)g->valid_tokens);
    poison_hash((_n00b_dict_internal_t *)g->terminal_by_id);
    poison_hash((_n00b_dict_internal_t *)g->terminal_categories);

    for (size_t i = 0; i < g->nt_list.len; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];
        poison_hash((_n00b_dict_internal_t *)nt->first_set);
        nt->action = dummy_action;
        nt->user_data = g;
    }

    for (size_t i = 0; i < g->rules.len; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];
        poison_hash((_n00b_dict_internal_t *)rule->first_set);
        rule->thunk = g;
    }

    g->default_action = dummy_action;
    g->disambiguator = dummy_disambiguator;
    g->tokenize_cb = dummy_tokenizer;
}

static void
check_repaired_hashes(n00b_grammar_t *g)
{
    check_hash((_n00b_dict_internal_t *)g->nt_map, n00b_string_hash);
    check_hash((_n00b_dict_internal_t *)g->terminal_map, n00b_string_hash);
    check_hash((_n00b_dict_internal_t *)g->literal_type_map, n00b_string_hash);
    check_hash((_n00b_dict_internal_t *)g->valid_tokens, n00b_hash_word);
    check_hash((_n00b_dict_internal_t *)g->terminal_by_id, n00b_hash_word);
    check_hash((_n00b_dict_internal_t *)g->terminal_categories, n00b_hash_word);

    for (size_t i = 0; i < g->nt_list.len; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];
        check_hash((_n00b_dict_internal_t *)nt->first_set, n00b_hash_word);
        CHECK(nt->action == nullptr);
        CHECK(nt->user_data == nullptr);
    }

    for (size_t i = 0; i < g->rules.len; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];
        check_hash((_n00b_dict_internal_t *)rule->first_set, n00b_hash_word);
        CHECK(rule->thunk == nullptr);
    }

    CHECK(g->default_action == nullptr);
    CHECK(g->disambiguator == nullptr);
}

static void
test_repair_hook_rebinds_hashes_and_callbacks(void)
{
    n00b_grammar_t *g = new_repair_fixture(r"text");
    poison_repair_targets(g);

    n00b_ct_image_repair_hook_t hook = {
        .fn = n00b_grammar_image_repair_hook,
    };
    auto repair_r = hook.fn(g, 4096, g, nullptr);
    CHECK(n00b_result_is_ok(repair_r));
    CHECK(n00b_result_get(repair_r) == true);

    check_repaired_hashes(g);

    bool found = false;
    n00b_scan_cb_t expected = n00b_tokenizer_lookup("text", &found);
    CHECK(found == true);
    CHECK(g->tokenize_cb == expected);
}

static void
test_repair_hook_clears_missing_tokenizer(void)
{
    n00b_grammar_t *g = new_repair_fixture(r"missing_tokenizer_for_repair_test");
    poison_repair_targets(g);

    auto repair_r = n00b_grammar_image_repair_hook(nullptr, 0, g, nullptr);
    CHECK(n00b_result_is_ok(repair_r));
    CHECK(n00b_result_get(repair_r) == true);

    check_repaired_hashes(g);
    CHECK(g->tokenize_cb == nullptr);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_repair_hook_rebinds_hashes_and_callbacks();
    test_repair_hook_clears_missing_tokenizer();

    n00b_shutdown();
    return 0;
}
