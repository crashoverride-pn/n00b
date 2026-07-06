/* test/unit/test_rocs_normalizer.c - WP-004 Phase 2 normalizer contracts. */

#include <stddef.h>
#include <stdint.h>

#include "n00b.h"
#include "adt/list.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/normalizer.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static void
check_bytes(n00b_buffer_t *buf, const uint8_t *expected, uint64_t len)
{
    CHECK(buf != nullptr);
    CHECK((uint64_t)n00b_buffer_len(buf) == len);

    for (uint64_t i = 0; i < len; i++) {
        auto actual = n00b_buffer_get_index(buf, (int64_t)i);
        CHECK(n00b_result_is_ok(actual));
        CHECK(n00b_result_get(actual) == expected[i]);
    }
}

static n00b_store_normalized_t *
normalize_scalar_ok(n00b_json_node_t *node)
{
    auto r = n00b_store_normalize_scalar(node);
    CHECK(n00b_result_is_ok(r));

    n00b_store_normalized_t *term = n00b_result_get(r);
    CHECK(term != nullptr);
    CHECK(term->path != nullptr);
    CHECK(term->value != nullptr);
    CHECK(term->bytes != nullptr);
    return term;
}

static void
check_path(n00b_store_normalized_t *term, n00b_string_t *expected)
{
    CHECK(term != nullptr);
    CHECK(n00b_unicode_str_eq(term->path, expected));
}

static void
test_public_contracts(void)
{
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_STORE_NORMALIZER_DECLS)
                  != 0);
    static_assert(N00B_STORE_NORM_OK == 0);
    static_assert(offsetof(n00b_store_normalized_t, path) == 0);
    static_assert(offsetof(n00b_store_normalized_t, value) == sizeof(void *));

    CHECK(n00b_store_normalize_err_str(N00B_STORE_NORM_OK) != nullptr);
    CHECK(n00b_store_normalize_err_str(N00B_STORE_NORM_ERR_NUMERIC) != nullptr);
    CHECK(n00b_store_normalize_err_str(9999) != nullptr);
}

static void
test_scalar_payloads(void)
{
    n00b_store_normalized_t *null_term = normalize_scalar_ok(n00b_json_null_new());
    CHECK(n00b_json_type(null_term->value) == N00B_JSON_NULL);
    check_path(null_term, r"");
    check_bytes(null_term->bytes, nullptr, 0);

    n00b_store_normalized_t *bool_term = normalize_scalar_ok(n00b_json_bool_new(true));
    uint8_t bool_bytes[] = {1};
    CHECK(n00b_json_type(bool_term->value) == N00B_JSON_BOOL);
    check_bytes(bool_term->bytes, bool_bytes, sizeof(bool_bytes));

    n00b_store_normalized_t *int_term = normalize_scalar_ok(n00b_json_int_new(42));
    uint8_t int_bytes[] = {0, 0, 0, 0, 0, 0, 0, 42};
    CHECK(n00b_json_type(int_term->value) == N00B_JSON_INT);
    check_bytes(int_term->bytes, int_bytes, sizeof(int_bytes));

    n00b_store_normalized_t *neg_term = normalize_scalar_ok(n00b_json_int_new(-1));
    uint8_t neg_bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    check_bytes(neg_term->bytes, neg_bytes, sizeof(neg_bytes));

    n00b_store_normalized_t *dbl_term = normalize_scalar_ok(n00b_json_double_new(1.5));
    uint8_t dbl_bytes[] = {0x3f, 0xf8, 0, 0, 0, 0, 0, 0};
    CHECK(n00b_json_type(dbl_term->value) == N00B_JSON_DOUBLE);
    check_bytes(dbl_term->bytes, dbl_bytes, sizeof(dbl_bytes));

    n00b_store_normalized_t *zero_term = normalize_scalar_ok(n00b_json_double_new(-0.0));
    uint8_t zero_bytes[] = {0, 0, 0, 0, 0, 0, 0, 0};
    check_bytes(zero_term->bytes, zero_bytes, sizeof(zero_bytes));

    n00b_store_normalized_t *str_term =
        normalize_scalar_ok(n00b_json_string_new_from_n00b(r"Error"));
    uint8_t str_bytes[] = {'E', 'r', 'r', 'o', 'r'};
    CHECK(n00b_json_type(str_term->value) == N00B_JSON_STRING);
    check_bytes(str_term->bytes, str_bytes, sizeof(str_bytes));
}

static void
test_scalar_errors(void)
{
    auto null_arg = n00b_store_normalize_scalar(nullptr);
    CHECK(n00b_result_is_err(null_arg));
    CHECK(n00b_result_get_err(null_arg) == N00B_STORE_NORM_ERR_ARG);

    auto object_r = n00b_store_normalize_scalar(n00b_json_object_new());
    CHECK(n00b_result_is_err(object_r));
    CHECK(n00b_result_get_err(object_r) == N00B_STORE_NORM_ERR_TYPE);

    union [[n00b::raw_union]] {
        uint64_t u;
        double   f;
    } inf = {
        .u = UINT64_C(0x7ff0000000000000),
    };
    auto inf_r = n00b_store_normalize_scalar(n00b_json_double_new(inf.f));
    CHECK(n00b_result_is_err(inf_r));
    CHECK(n00b_result_get_err(inf_r) == N00B_STORE_NORM_ERR_NUMERIC);
}

static n00b_uint128_t
hash_ok(n00b_store_index_kind_t kind, n00b_store_normalized_t *term)
{
    auto r = n00b_store_normalize_hash(kind, term);
    CHECK(n00b_result_is_ok(r));
    n00b_uint128_t hv = n00b_result_get(r);
    CHECK(hv != (n00b_uint128_t)0);
    return hv;
}

static n00b_store_normalized_t *
token_at(n00b_store_normalized_list_t *tokens, int64_t ordinal)
{
    CHECK(tokens != nullptr);
    CHECK(ordinal >= 0);
    CHECK(ordinal < (int64_t)n00b_list_len(*tokens));

    n00b_store_normalized_t *term = n00b_list_get(*tokens, ordinal);
    CHECK(term != nullptr);
    CHECK(term->path != nullptr);
    CHECK(term->value != nullptr);
    CHECK(term->bytes != nullptr);
    CHECK(n00b_json_is_string(term->value));
    return term;
}

static void
check_token(n00b_store_normalized_list_t *tokens,
            int64_t                       ordinal,
            n00b_string_t                *expected)
{
    n00b_store_normalized_t *term = token_at(tokens, ordinal);
    n00b_string_t           *text = n00b_json_as_string(term->value);
    CHECK(n00b_unicode_str_eq(text, expected));
    check_bytes(term->bytes,
                (const uint8_t *)expected->data,
                (uint64_t)expected->u8_bytes);
}

static bool
count_key_visitor(void *ctx, n00b_uint128_t key)
{
    CHECK(ctx != nullptr);
    CHECK(key != (n00b_uint128_t)0);
    uint64_t *count = ctx;
    (*count)++;
    return true;
}

static void
test_text_token_normalization(void)
{
    n00b_json_node_t *node =
        n00b_json_string_new_from_n00b(r"Error, DISK_full! terror's");

    auto tokens_r = n00b_store_normalize_text_tokens(node, .path = r"/message");
    CHECK(n00b_result_is_ok(tokens_r));

    n00b_store_normalized_list_t *tokens = n00b_result_get(tokens_r);
    CHECK(tokens != nullptr);
    CHECK(n00b_list_len(*tokens) == 5);

    check_token(tokens, 0, r"error, disk_full! terror's");
    check_token(tokens, 1, r"error");
    check_token(tokens, 2, r"disk_full");
    check_token(tokens, 3, r"terror");
    check_token(tokens, 4, r"s");

    for (int64_t i = 0; i < (int64_t)n00b_list_len(*tokens); i++) {
        check_path(token_at(tokens, i), r"/message");
    }

    auto query_r =
        n00b_store_normalize_text_tokens(n00b_json_string_new_from_n00b(r"ERROR"));
    CHECK(n00b_result_is_ok(query_r));
    n00b_store_normalized_list_t *query_tokens = n00b_result_get(query_r);
    CHECK(n00b_list_len(*query_tokens) == 1);
    check_token(query_tokens, 0, r"error");
    CHECK(hash_ok(N00B_STORE_INDEX_FULLTEXT, token_at(tokens, 1))
          != hash_ok(N00B_STORE_INDEX_FULLTEXT, token_at(query_tokens, 0)));

    auto query_path_r =
        n00b_store_normalize_text_tokens(n00b_json_string_new_from_n00b(r"ERROR"),
                                         .path = r"/message");
    CHECK(n00b_result_is_ok(query_path_r));
    CHECK(hash_ok(N00B_STORE_INDEX_FULLTEXT, token_at(tokens, 1))
          == hash_ok(N00B_STORE_INDEX_FULLTEXT,
                     token_at(n00b_result_get(query_path_r), 0)));

    n00b_store_normalized_t *exact =
        normalize_scalar_ok(n00b_json_string_new_from_n00b(r"Error"));
    uint8_t exact_bytes[] = {'E', 'r', 'r', 'o', 'r'};
    check_bytes(exact->bytes, exact_bytes, sizeof(exact_bytes));
    CHECK(hash_ok(N00B_STORE_INDEX_TERM, exact)
          != hash_ok(N00B_STORE_INDEX_FULLTEXT, token_at(tokens, 1)));

    auto id_r = n00b_store_normalize_text_tokens(
        n00b_json_string_new_from_n00b(r"AI-Session:55545:2"));
    CHECK(n00b_result_is_ok(id_r));
    n00b_store_normalized_list_t *id_tokens = n00b_result_get(id_r);
    CHECK(n00b_list_len(*id_tokens) == 5);
    check_token(id_tokens, 0, r"ai-session:55545:2");
    check_token(id_tokens, 1, r"ai");
    check_token(id_tokens, 2, r"session");
    check_token(id_tokens, 3, r"55545");
    check_token(id_tokens, 4, r"2");

    auto dotted_r = n00b_store_normalize_text_tokens(
        n00b_json_string_new_from_n00b(r"dns.prefetch"));
    CHECK(n00b_result_is_ok(dotted_r));
    n00b_store_normalized_list_t *dotted_tokens = n00b_result_get(dotted_r);
    CHECK(n00b_list_len(*dotted_tokens) == 3);
    check_token(dotted_tokens, 0, r"dns.prefetch");
    check_token(dotted_tokens, 1, r"dns");
    check_token(dotted_tokens, 2, r"prefetch");

    auto dotted_token_only_r = n00b_store_normalize_text_tokens(
        n00b_json_string_new_from_n00b(r"dns.prefetch"),
        .include_full_value = false);
    CHECK(n00b_result_is_ok(dotted_token_only_r));
    n00b_store_normalized_list_t *dotted_token_only =
        n00b_result_get(dotted_token_only_r);
    CHECK(n00b_list_len(*dotted_token_only) == 2);
    check_token(dotted_token_only, 0, r"dns");
    check_token(dotted_token_only, 1, r"prefetch");

    uint64_t key_count = 0;
    auto     keys_r    = n00b_store_normalize_text_token_keys(
        n00b_json_string_new_from_n00b(r"dns.prefetch"),
        count_key_visitor,
        &key_count);
    CHECK(n00b_result_is_ok(keys_r));
    CHECK(n00b_result_get(keys_r) == 3);
    CHECK(key_count == 3);


    auto empty_r =
        n00b_store_normalize_text_tokens(n00b_json_string_new_from_n00b(r" !-- "));
    CHECK(n00b_result_is_ok(empty_r));
    CHECK(n00b_list_len(*(n00b_store_normalized_list_t *)n00b_result_get(empty_r))
          == 0);

    auto non_string_r = n00b_store_normalize_text_tokens(n00b_json_int_new(7));
    CHECK(n00b_result_is_err(non_string_r));
    CHECK(n00b_result_get_err(non_string_r) == N00B_STORE_NORM_ERR_TYPE);

    auto null_r = n00b_store_normalize_text_tokens(nullptr);
    CHECK(n00b_result_is_err(null_r));
    CHECK(n00b_result_get_err(null_r) == N00B_STORE_NORM_ERR_ARG);
}

static void
test_text_ngram_normalization(void)
{
    n00b_json_node_t *node = n00b_json_string_new_from_n00b(r"AbCd");

    auto grams_r = n00b_store_normalize_text_ngrams(node, .path = r"/message");
    CHECK(n00b_result_is_ok(grams_r));

    n00b_store_normalized_list_t *grams = n00b_result_get(grams_r);
    CHECK(grams != nullptr);
    CHECK(n00b_list_len(*grams) == 2);

    check_token(grams, 0, r"abc");
    check_token(grams, 1, r"bcd");
    check_path(token_at(grams, 0), r"/message");
    check_path(token_at(grams, 1), r"/message");

    auto bigram_r =
        n00b_store_normalize_text_ngrams(node, .ngram_n = 2);
    CHECK(n00b_result_is_ok(bigram_r));
    n00b_store_normalized_list_t *bigrams = n00b_result_get(bigram_r);
    CHECK(n00b_list_len(*bigrams) == 3);
    check_token(bigrams, 0, r"ab");
    check_token(bigrams, 1, r"bc");
    check_token(bigrams, 2, r"cd");

    auto short_r =
        n00b_store_normalize_text_ngrams(n00b_json_string_new_from_n00b(r"ab"));
    CHECK(n00b_result_is_ok(short_r));
    CHECK(n00b_list_len(*(n00b_store_normalized_list_t *)n00b_result_get(short_r))
          == 0);

    auto lower_bound_r =
        n00b_store_normalize_text_ngrams(node, .ngram_n = 1);
    CHECK(n00b_result_is_err(lower_bound_r));
    CHECK(n00b_result_get_err(lower_bound_r) == N00B_STORE_NORM_ERR_ARG);

    auto upper_bound_r =
        n00b_store_normalize_text_ngrams(node, .ngram_n = 17);
    CHECK(n00b_result_is_err(upper_bound_r));
    CHECK(n00b_result_get_err(upper_bound_r) == N00B_STORE_NORM_ERR_ARG);

    auto non_string_r = n00b_store_normalize_text_ngrams(n00b_json_int_new(7));
    CHECK(n00b_result_is_err(non_string_r));
    CHECK(n00b_result_get_err(non_string_r) == N00B_STORE_NORM_ERR_TYPE);

    CHECK(hash_ok(N00B_STORE_INDEX_NGRAM, token_at(grams, 0))
          != hash_ok(N00B_STORE_INDEX_FULLTEXT, token_at(grams, 0)));

    auto query_r =
        n00b_store_normalize_text_ngrams(n00b_json_string_new_from_n00b(r"ABC"),
                                         .path = r"/message");
    CHECK(n00b_result_is_ok(query_r));
    CHECK(hash_ok(N00B_STORE_INDEX_NGRAM, token_at(grams, 0))
          == hash_ok(N00B_STORE_INDEX_NGRAM,
                     token_at(n00b_result_get(query_r), 0)));

    char upper_bytes[] = {(char)0xc3, (char)0x85, 'B', 'C'};
    char lower_bytes[] = {(char)0xc3, (char)0xa5, 'b', 'c'};
    n00b_string_t *upper =
        n00b_string_from_raw(upper_bytes, sizeof(upper_bytes));
    n00b_string_t *lower =
        n00b_string_from_raw(lower_bytes, sizeof(lower_bytes));
    auto upper_r =
        n00b_store_normalize_text_ngrams(n00b_json_string_new_from_n00b(upper),
                                         .path = r"/message");
    auto lower_r =
        n00b_store_normalize_text_ngrams(n00b_json_string_new_from_n00b(lower),
                                         .path = r"/message");
    CHECK(n00b_result_is_ok(upper_r));
    CHECK(n00b_result_is_ok(lower_r));
    n00b_store_normalized_list_t *upper_grams = n00b_result_get(upper_r);
    n00b_store_normalized_list_t *lower_grams = n00b_result_get(lower_r);
    CHECK(n00b_list_len(*upper_grams) == 2);
    CHECK(n00b_list_len(*lower_grams) == 2);

    uint8_t folded_gram0[] = {0xc3, 0xa5, 'b'};
    uint8_t folded_gram1[] = {0xa5, 'b', 'c'};
    check_bytes(token_at(upper_grams, 0)->bytes,
                folded_gram0,
                sizeof(folded_gram0));
    check_bytes(token_at(upper_grams, 1)->bytes,
                folded_gram1,
                sizeof(folded_gram1));
    CHECK(hash_ok(N00B_STORE_INDEX_NGRAM, token_at(upper_grams, 0))
          == hash_ok(N00B_STORE_INDEX_NGRAM, token_at(lower_grams, 0)));
    CHECK(hash_ok(N00B_STORE_INDEX_NGRAM, token_at(upper_grams, 1))
          == hash_ok(N00B_STORE_INDEX_NGRAM, token_at(lower_grams, 1)));

    auto root_query_r =
        n00b_store_normalize_text_ngrams(n00b_json_string_new_from_n00b(r"ABC"));
    CHECK(n00b_result_is_ok(root_query_r));
    CHECK(hash_ok(N00B_STORE_INDEX_NGRAM, token_at(grams, 0))
          != hash_ok(N00B_STORE_INDEX_NGRAM,
                     token_at(n00b_result_get(root_query_r), 0)));
}

static void
test_hash_contracts(void)
{
    n00b_store_normalized_t *int_a = normalize_scalar_ok(n00b_json_int_new(1));
    n00b_store_normalized_t *int_b = normalize_scalar_ok(n00b_json_int_new(1));
    n00b_store_normalized_t *dbl   = normalize_scalar_ok(n00b_json_double_new(1.0));
    n00b_store_normalized_t *str =
        normalize_scalar_ok(n00b_json_string_new_from_n00b(r"1"));
    n00b_store_normalized_t *case_a =
        normalize_scalar_ok(n00b_json_string_new_from_n00b(r"Error"));
    n00b_store_normalized_t *case_b =
        normalize_scalar_ok(n00b_json_string_new_from_n00b(r"error"));
    auto path_a_r = n00b_store_normalize_scalar(n00b_json_int_new(1),
                                                .path = r"/a");
    auto path_a2_r = n00b_store_normalize_scalar(n00b_json_int_new(1),
                                                 .path = r"/a");
    auto path_b_r = n00b_store_normalize_scalar(n00b_json_int_new(1),
                                                .path = r"/b");
    CHECK(n00b_result_is_ok(path_a_r));
    CHECK(n00b_result_is_ok(path_a2_r));
    CHECK(n00b_result_is_ok(path_b_r));
    n00b_store_normalized_t *path_a  = n00b_result_get(path_a_r);
    n00b_store_normalized_t *path_a2 = n00b_result_get(path_a2_r);
    n00b_store_normalized_t *path_b  = n00b_result_get(path_b_r);

    n00b_uint128_t int_term_h = hash_ok(N00B_STORE_INDEX_TERM, int_a);
    CHECK(int_term_h == hash_ok(N00B_STORE_INDEX_TERM, int_b));
    CHECK(int_term_h != hash_ok(N00B_STORE_INDEX_FULLTEXT, int_a));
    CHECK(int_term_h != hash_ok(N00B_STORE_INDEX_TERM, dbl));
    CHECK(int_term_h != hash_ok(N00B_STORE_INDEX_TERM, str));
    CHECK(hash_ok(N00B_STORE_INDEX_TERM, case_a)
          != hash_ok(N00B_STORE_INDEX_TERM, case_b));
    CHECK(hash_ok(N00B_STORE_INDEX_TERM, path_a)
          == hash_ok(N00B_STORE_INDEX_TERM, path_a2));
    CHECK(hash_ok(N00B_STORE_INDEX_TERM, path_a)
          != hash_ok(N00B_STORE_INDEX_TERM, path_b));

    auto bad_kind = n00b_store_normalize_hash(N00B_STORE_INDEX_NONE, int_a);
    CHECK(n00b_result_is_err(bad_kind));
    CHECK(n00b_result_get_err(bad_kind) == N00B_STORE_NORM_ERR_ARG);

    auto bad_term = n00b_store_normalize_hash(N00B_STORE_INDEX_TERM, nullptr);
    CHECK(n00b_result_is_err(bad_term));
    CHECK(n00b_result_get_err(bad_term) == N00B_STORE_NORM_ERR_ARG);

    n00b_buffer_t bad_buf = {
        .data     = nullptr,
        .byte_len = 1,
    };
    n00b_store_normalized_t bad_bytes = {
        .path  = r"",
        .value = int_a->value,
        .bytes = &bad_buf,
    };
    auto bad_bytes_r =
        n00b_store_normalize_hash(N00B_STORE_INDEX_TERM, &bad_bytes);
    CHECK(n00b_result_is_err(bad_bytes_r));
    CHECK(n00b_result_get_err(bad_bytes_r) == N00B_STORE_NORM_ERR_STATE);
}

static void
test_json_flattening(void)
{
    n00b_json_node_t *root = n00b_json_object_new();
    n00b_json_node_t *b    = n00b_json_array_new();
    n00b_json_array_push(b, n00b_json_bool_new(true));
    n00b_json_array_push(b, n00b_json_int_new(2));
    n00b_json_object_put_n00b(root, r"b", b);

    n00b_json_node_t *a_slash_b = n00b_json_object_new();
    n00b_json_object_put_n00b(a_slash_b,
                              r"~c",
                              n00b_json_string_new_from_n00b(r"x"));
    n00b_json_object_put_n00b(root, r"a/b", a_slash_b);
    n00b_json_object_put_n00b(root, r"n", n00b_json_null_new());

    auto flat_r = n00b_store_normalize_json(root);
    CHECK(n00b_result_is_ok(flat_r));

    n00b_store_normalized_list_t *items = n00b_result_get(flat_r);
    CHECK(items != nullptr);
    CHECK(n00b_list_len(*items) == 4);

    n00b_store_normalized_t *t0 = n00b_list_get(*items, 0);
    n00b_store_normalized_t *t1 = n00b_list_get(*items, 1);
    n00b_store_normalized_t *t2 = n00b_list_get(*items, 2);
    n00b_store_normalized_t *t3 = n00b_list_get(*items, 3);

    check_path(t0, r"/a~1b/~0c");
    CHECK(n00b_json_type(t0->value) == N00B_JSON_STRING);
    uint8_t x_bytes[] = {'x'};
    check_bytes(t0->bytes, x_bytes, sizeof(x_bytes));

    check_path(t1, r"/b/0");
    CHECK(n00b_json_type(t1->value) == N00B_JSON_BOOL);
    uint8_t true_bytes[] = {1};
    check_bytes(t1->bytes, true_bytes, sizeof(true_bytes));

    check_path(t2, r"/b/1");
    CHECK(n00b_json_type(t2->value) == N00B_JSON_INT);
    uint8_t two_bytes[] = {0, 0, 0, 0, 0, 0, 0, 2};
    check_bytes(t2->bytes, two_bytes, sizeof(two_bytes));

    check_path(t3, r"/n");
    CHECK(n00b_json_type(t3->value) == N00B_JSON_NULL);
    check_bytes(t3->bytes, nullptr, 0);
}

static void
test_root_path_prefix(void)
{
    n00b_json_node_t *root = n00b_json_array_new();
    n00b_json_node_t *item = n00b_json_object_new();
    n00b_json_object_put_n00b(item, r"x", n00b_json_bool_new(false));
    n00b_json_array_push(root, item);

    auto flat_r = n00b_store_normalize_json(root, .root_path = r"/root");
    CHECK(n00b_result_is_ok(flat_r));

    n00b_store_normalized_list_t *items = n00b_result_get(flat_r);
    CHECK(n00b_list_len(*items) == 1);

    n00b_store_normalized_t *term = n00b_list_get(*items, 0);
    check_path(term, r"/root/0/x");
    CHECK(n00b_json_type(term->value) == N00B_JSON_BOOL);
    uint8_t false_bytes[] = {0};
    check_bytes(term->bytes, false_bytes, sizeof(false_bytes));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);
    test_public_contracts();
    test_scalar_payloads();
    test_scalar_errors();
    test_text_token_normalization();
    test_text_ngram_normalization();
    test_hash_contracts();
    test_json_flattening();
    test_root_path_prefix();
    n00b_shutdown();
    return 0;
}
