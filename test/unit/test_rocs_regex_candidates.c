/* test/unit/test_rocs_regex_candidates.c - WP-010 Phase 3 regex candidates. */

#include <stdint.h>

#include "n00b.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "public rocs headers must not include internal planner declarations"
#endif

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#include "plan_oracle.h"
#include "rocs_test_support.h"

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_store_index_t *index = n00b_result_get(r);
    CHECK(index != nullptr);
    return index;
}

static n00b_store_index_t *
ngram_index(n00b_string_t *field)
{
    return index_ok(n00b_store_index_new(field, N00B_STORE_INDEX_NGRAM));
}

static n00b_plan_target_t *
target_ok(n00b_result_t(n00b_plan_target_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_target_t *target = n00b_result_get(r);
    CHECK(target != nullptr);
    return target;
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_plan_ordset_t *
ordset_ok(n00b_result_t(n00b_plan_ordset_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_regex_t *regex = n00b_result_get(r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_predicate_t *
message_regex(n00b_regex_t *regex)
{
    return predicate_ok(n00b_plan_predicate_regex(field_target(r"message"),
                                                 regex));
}

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(indexes != nullptr);
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index)));
    return indexes;
}

static n00b_json_node_t *
record_with_message_node(n00b_json_node_t *message)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"message", message);
    return record;
}

static n00b_json_node_t *
record_with_message(n00b_string_t *message)
{
    return record_with_message_node(n00b_json_string_new_from_n00b(message));
}

static n00b_json_node_t *
record_without_message(void)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"level",
                              n00b_json_string_new_from_n00b(r"info"));
    return record;
}

static n00b_store_shard_t *
shard_ok(uint64_t shard_id)
{
    auto shard_r = n00b_store_shard_new(.shard_id = shard_id, .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);
    CHECK(shard != nullptr);
    return shard;
}

static uint64_t
append_record(n00b_store_shard_t *shard, n00b_json_node_t *record)
{
    auto append_r = n00b_store_shard_append(shard, record);
    CHECK(n00b_result_is_ok(append_r));
    return n00b_result_get(append_r);
}

static uint64_t
append_and_index_at_least(n00b_store_index_t *index,
                          n00b_store_shard_t *shard,
                          n00b_json_node_t   *record,
                          uint64_t            minimum_terms)
{
    uint64_t ordinal = append_record(shard, record);
    auto     add_r   = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
    CHECK(n00b_result_get(add_r) >= minimum_terms);
    return ordinal;
}

static uint64_t
append_and_index_exact(n00b_store_index_t *index,
                       n00b_store_shard_t *shard,
                       n00b_json_node_t   *record,
                       uint64_t            expected_terms)
{
    uint64_t ordinal = append_record(shard, record);
    auto     add_r   = n00b_store_index_add(index, shard, ordinal);
    CHECK(n00b_result_is_ok(add_r));
    CHECK(n00b_result_get(add_r) == expected_terms);
    return ordinal;
}

static n00b_store_shard_t *
sample_regex_shard(n00b_store_index_t *index)
{
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7300));
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qzj42 open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"prefix qzj900 close"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qzj open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"xqzjY open"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"QZJ77 uppercase"),
                              1);
    append_and_index_at_least(index,
                              shard,
                              record_with_message(r"qz7 short"),
                              1);
    append_and_index_exact(index, shard, record_without_message(), 0);
    append_and_index_exact(index,
                           shard,
                           record_with_message_node(n00b_json_int_new(123)),
                           0);
    return shard;
}

static bool
expected_has(const uint64_t *expected, uint64_t len, uint64_t ordinal)
{
    for (uint64_t i = 0; i < len; i++) {
        if (expected[i] == ordinal) {
            return true;
        }
    }
    return false;
}

static void
check_set(n00b_plan_ordset_t *set,
          uint64_t            record_count,
          const uint64_t     *expected,
          uint64_t            expected_len)
{
    auto record_count_r = n00b_plan_ordset_record_count(set);
    CHECK(n00b_result_is_ok(record_count_r));
    CHECK(n00b_result_get(record_count_r) == record_count);

    auto count_r = n00b_plan_ordset_count(set);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == expected_len);

    for (uint64_t i = 0; i < expected_len; i++) {
        auto at_r = n00b_plan_ordset_at(set, i);
        CHECK(n00b_result_is_ok(at_r));
        CHECK(n00b_option_is_set(n00b_result_get(at_r)));
        CHECK(n00b_option_get(n00b_result_get(at_r)) == expected[i]);
    }

    auto none_r = n00b_plan_ordset_at(set, expected_len);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    for (uint64_t ordinal = 0; ordinal < record_count; ordinal++) {
        auto contains_r = n00b_plan_ordset_contains(set, ordinal);
        CHECK(n00b_result_is_ok(contains_r));
        CHECK(n00b_result_get(contains_r)
              == expected_has(expected, expected_len, ordinal));
    }
}

static void
check_plan_flags(n00b_plan_node_t      *plan,
                 n00b_plan_predicate_t *expected_record_scan,
                 bool                   expected_uses_index)
{
    auto sole_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(sole_r));
    n00b_option_t(n00b_plan_predicate_t *) residual = n00b_result_get(sole_r);

    auto exact_r = n00b_plan_reads_no_records(plan);
    auto used_r  = n00b_plan_uses_index(plan);
    CHECK(n00b_result_is_ok(exact_r));
    CHECK(n00b_result_is_ok(used_r));
    CHECK(n00b_result_get(used_r) == expected_uses_index);

    if (expected_record_scan == nullptr) {
        CHECK(!n00b_option_is_set(residual));
        CHECK(n00b_result_get(exact_r));
    }
    else {
        CHECK(n00b_option_is_set(residual));
        CHECK(n00b_option_get(residual) == expected_record_scan);
        CHECK(!n00b_result_get(exact_r));
    }
}

// Both accessors collect bytes, and both hand back an n00b_string_t. A run cut
// part way through a character gets the -1 the decoder returns stored into a
// size_t field, so every length taken from it afterwards is SIZE_MAX, and
// n00b_string_from_raw hands that back rather than refusing it.
//
// Checked against the byte count rather than against SIZE_MAX, because one
// byte per character is the floor for well-formed UTF-8 and nothing valid can
// be over it. Asserted apart from the value because the unreadable string is
// the symptom worth naming.
static void
check_literal_is_readable(n00b_string_t *literal)
{
    CHECK(literal != nullptr);
    CHECK(literal->codepoints <= literal->u8_bytes);
}

static void
check_prefix_opt(n00b_regex_t *regex,
                 n00b_string_t *expected,
                 bool expected_set)
{
    n00b_option_t(n00b_string_t *) opt =
        n00b_regex_required_literal_prefix(regex);
    CHECK(n00b_option_is_set(opt) == expected_set);
    if (expected_set) {
        check_literal_is_readable(n00b_option_get(opt));
        CHECK(n00b_unicode_str_eq(n00b_option_get(opt), expected));
    }
}

static void
test_regex_prefix_accessor_shape(void)
{
    check_prefix_opt(regex_ok(n00b_regex_new(r"qzj[0-9]+")), r"qzj", true);
    check_prefix_opt(regex_ok(n00b_regex_new(r"qz[0-9]+")), r"qz", true);
    check_prefix_opt(regex_ok(n00b_regex_new(r"[qQ]zj[0-9]+")),
                     nullptr,
                     false);
    check_prefix_opt(regex_ok(n00b_regex_new(r"[0-9]+")), nullptr, false);

    // A class over a range of multi-byte characters shares their leading
    // bytes, and those bytes are single-byte predicates like any other:
    // `[\u4e00-\u4e05]` is `e4` then `b8` then `[80-85]`. The walk collects
    // the first two and stops, so the run ends half way through a character
    // and what is left after the trim is the part in front of it.
    check_prefix_opt(regex_ok(n00b_regex_new(r"abc[\u4e00-\u4e05]")),
                     r"abc",
                     true);

    // Nothing in front of it, so nothing survives at all.
    check_prefix_opt(regex_ok(n00b_regex_new(r"[\u4e00-\u4e05]y")),
                     nullptr,
                     false);

    // A whole character is kept, multi-byte or not.
    check_prefix_opt(regex_ok(n00b_regex_new(r"\u00e9\u00e9mn[0-9]")),
                     r"éémn",
                     true);
}

static void
check_anywhere_opt(n00b_regex_t  *regex,
                   n00b_string_t *expected,
                   bool           expected_set)
{
    n00b_option_t(n00b_string_t *) opt =
        n00b_regex_required_literal_anywhere(regex);
    CHECK(n00b_option_is_set(opt) == expected_set);
    if (expected_set) {
        check_literal_is_readable(n00b_option_get(opt));
        CHECK(n00b_unicode_str_eq(n00b_option_get(opt), expected));
    }
}

static void
test_regex_anywhere_accessor_shape(void)
{
    // Everything the prefix accessor finds, the wider one finds too.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"qzj[0-9]+")), r"qzj", true);
    check_anywhere_opt(regex_ok(n00b_regex_new(r"qzj(42|99)")), r"qzj", true);

    // A literal the prefix accessor cannot reach, because something that is
    // not a single byte comes first.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"(bar|baz)qzj")), r"qzj", true);
    check_anywhere_opt(regex_ok(n00b_regex_new(r"[0-9]+qzj")), r"qzj", true);
    check_anywhere_opt(regex_ok(n00b_regex_new(r"a?qzj")), r"qzj", true);

    // Several runs qualify, so the longest one wins: it generates the most
    // n-grams and so rules out the most records.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"ab[0-9]qzjmn")),
                       r"qzjmn",
                       true);

    // A top-level alternation requires nothing, so neither accessor may claim
    // a literal. Reporting one here would drop every record matching the other
    // branch.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"qzj|mnp")), nullptr, false);
    check_prefix_opt(regex_ok(n00b_regex_new(r"qzj|mnp")), nullptr, false);

    // An optional group is not required either, so its bytes must not be
    // reported. A concat spine cannot express an optional head, which is what
    // keeps the walk from picking one up by accident.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"(qzj)?mnp")), r"mnp", true);

    // Nothing literal at all.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"[0-9]+")), nullptr, false);

    // Ties go to the earliest run. Two literals that rule out the same amount
    // leave nothing to choose between them, and an answer that depended on
    // which one the walk saw last would be one nobody could predict.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"qz.mn")), r"qz", true);

    // A class over a range of multi-byte characters lends its leading bytes to
    // the run in front of it, so that run ends half way through a character.
    // The trim takes those bytes back, which is also why the run behind the
    // class is the one that wins here: comparing the runs before trimming
    // would pick a five-byte answer that is worth three.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"qzj[\u4e00-\u4e05]mnpqr")),
                       r"mnpqr",
                       true);

    // Trimmed down to the one character in front of it.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"x[\u4e00-\u4e05]y")),
                       r"x",
                       true);

    // And with nothing in front of it, the run behind is all there is.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"[\u00e0-\u00ef]xyz")),
                       r"xyz",
                       true);

    // Whole characters are kept, however many bytes they take.
    check_anywhere_opt(regex_ok(n00b_regex_new(r"(a|b)\u00e9\u00e9mn")),
                       r"éémn",
                       true);
}

// A run longer than the walk will read stops at REQUIRED_LITERAL_MAX_BYTES.
// Giving up the tail only shortens the answer, so what comes back is still a
// literal every match contains.
//
// The cap counts bytes and this pattern spends three of them per character, so
// the cut lands inside one: 4096 bytes is 1365 characters and a stray lead
// byte, which the trim gives back. That pairing is the point of the case. A
// cap alone would hand out half a character every time it fired on a pattern
// that was not ASCII.
static void
test_regex_anywhere_accessor_caps_a_long_literal(void)
{
    n00b_string_t *capped = n00b_unicode_str_repeat(r"一", 2000);
    check_anywhere_opt(regex_ok(n00b_regex_new(capped)),
                       n00b_unicode_str_repeat(r"一", 1365),
                       true);

    // Under the cap the whole run comes back.
    n00b_string_t *whole = n00b_unicode_str_repeat(r"一", 1000);
    check_anywhere_opt(regex_ok(n00b_regex_new(whole)), whole, true);
}

static void
test_literal_regex_uses_ngram_candidates_with_residual(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex =
        message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));

    n00b_plan_node_t *plan = test_plan_hot(regex, indexes, shard);

    check_plan_flags(plan, regex, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {0, 1};
    check_set(verified, 8, verified_expected, 2);
}

static void
test_regex_without_usable_prefix_scans_and_verifies(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_regex_shard(index);

    n00b_plan_predicate_t *broad =
        message_regex(regex_ok(n00b_regex_new(r"[qQ]zj[0-9]+")));
    n00b_plan_node_t *broad_dispatch = test_plan_hot(broad, index_list_with(index), shard);
    check_plan_flags(broad_dispatch, broad, false);
    n00b_plan_ordset_t *broad_verified =
        ordset_ok(n00b_plan_exec_hot(broad_dispatch, shard));
    uint64_t broad_expected[] = {0, 1};
    check_set(broad_verified, 8, broad_expected, 2);

    n00b_plan_predicate_t *digits =
        message_regex(regex_ok(n00b_regex_new(r"[0-9]+")));
    n00b_plan_node_t *digits_dispatch = test_plan_hot(digits, index_list_with(index), shard);
    check_plan_flags(digits_dispatch, digits, false);
    n00b_plan_ordset_t *digits_verified =
        ordset_ok(n00b_plan_exec_hot(digits_dispatch, shard));
    uint64_t digits_expected[] = {0, 1, 4, 5};
    check_set(digits_verified, 8, digits_expected, 4);
}


// The literal sits behind an alternation, so the prefix extraction finds
// nothing. The n-gram index takes an interior literal as a candidate
// generator, which is what substring hands it, so this rides the same lossy
// pair instead of reading every record.
static void
test_regex_literal_behind_an_alternation_uses_candidates(void)
{
    n00b_store_index_t     *index   = ngram_index(r"message");
    n00b_store_shard_t     *shard   = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex   =
        message_regex(regex_ok(n00b_regex_new(r"(x|y)qzj")));

    n00b_plan_node_t *plan = test_plan_hot(regex, indexes, shard);

    check_plan_flags(plan, regex, true);

    n00b_plan_ordset_t *verified = ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {3};
    check_set(verified, 8, verified_expected, 1);
}

// The run the walk collects ends inside a multi-byte character, and what
// survives the trim is still long enough to make the n-gram cut. An untrimmed
// literal is not a string the normalizer can gram, so this planned a full read
// of every record and answered the same way, slower.
static void
test_regex_multibyte_class_uses_candidates(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = shard_ok(UINT64_C(0x7311));

    // Matches: the class covers U+4E00..U+4E05.
    append_and_index_at_least(index, shard,
                              record_with_message(r"aaa qzj一mnp bbb"), 1);
    // Carries the literal, so the index offers it, and the residual turns it
    // down: a digit is not in the class.
    append_and_index_at_least(index, shard,
                              record_with_message(r"aaa qzj7mnp bbb"), 1);
    append_and_index_at_least(index, shard,
                              record_with_message(r"nothing of interest"), 1);

    n00b_plan_predicate_t *regex = message_regex(
        regex_ok(n00b_regex_new(r"qzj[\u4e00-\u4e05]mnp")));
    n00b_plan_node_t *plan = test_plan_hot(regex,
                                           index_list_with(index),
                                           shard);

    check_plan_flags(plan, regex, true);

    uint64_t expected[] = {0};
    check_set(ordset_ok(n00b_plan_exec_hot(plan, shard)), 3, expected, 1);
}

static void
test_short_literal_regex_falls_back_to_scan_verify(void)
{
    n00b_store_index_t     *index = ngram_index(r"message");
    n00b_store_shard_t     *shard = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex =
        message_regex(regex_ok(n00b_regex_new(r"qz[0-9]+")));

    n00b_plan_node_t *plan = test_plan_hot(regex, indexes, shard);

    check_plan_flags(plan, regex, false);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t verified_expected[] = {5};
    check_set(verified, 8, verified_expected, 1);
}

// Counts steer the plan; they never change what it answers. This is why a plan
// built for one shard and run against another degrades silently instead of
// failing, and so why plan.h rule 4 is a rule rather than an assertion.
static void
test_counts_change_speed_not_answer(void)
{
    n00b_store_index_t     *index   = ngram_index(r"message");
    n00b_store_shard_t     *shard   = sample_regex_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);
    n00b_plan_predicate_t  *regex
        = message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));

    n00b_store_shard_t *other = shard_ok(UINT64_C(0x7301));
    append_record(other, record_with_message(r"qzj42 only"));

    // Each shard plans from its own counts, which is what a fan-out does.
    n00b_plan_node_t *own_first  = test_plan_hot(regex, indexes, shard);
    n00b_plan_node_t *own_second = test_plan_hot(regex, indexes, other);

    n00b_plan_ordset_t *first = ordset_ok(n00b_plan_exec_hot(own_first, shard));
    auto                first_rc = n00b_plan_ordset_record_count(first);
    CHECK(n00b_result_is_ok(first_rc));
    CHECK(n00b_result_get(first_rc) == 8);

    n00b_plan_ordset_t *second
        = ordset_ok(n00b_plan_exec_hot(own_second, other));
    auto second_rc = n00b_plan_ordset_record_count(second);
    CHECK(n00b_result_is_ok(second_rc));
    CHECK(n00b_result_get(second_rc) == 1);

    // The same query planned from the wrong shard's counts. It is the wrong
    // plan to run, and it still answers exactly the same, which is the point.
    n00b_plan_ordset_t *borrowed
        = ordset_ok(n00b_plan_exec_hot(own_first, other));
    auto borrowed_rc = n00b_plan_ordset_record_count(borrowed);
    CHECK(n00b_result_is_ok(borrowed_rc));
    CHECK(n00b_result_get(borrowed_rc) == 1);
}

static void
test_mapped_regex_uses_ngram_candidates_with_residual(void)
{
    n00b_store_index_t *index = ngram_index(r"message");
    n00b_store_shard_t *shard = sample_regex_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 93,
                                        .base_address = 0x730000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));

    n00b_plan_predicate_t *regex =
        message_regex(regex_ok(n00b_regex_new(r"qzj[0-9]+")));
    n00b_plan_node_t *plan = test_plan_hot(regex, index_list_with(index), shard);

    check_plan_flags(plan, regex, true);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_mapped(plan, n00b_result_get(root_r)));
    uint64_t verified_expected[] = {0, 1};
    check_set(verified, 8, verified_expected, 2);

    CHECK(n00b_result_is_ok(n00b_store_map_close(map)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_regex_prefix_accessor_shape();
    test_regex_anywhere_accessor_shape();
    test_regex_anywhere_accessor_caps_a_long_literal();
    test_literal_regex_uses_ngram_candidates_with_residual();
    test_regex_without_usable_prefix_scans_and_verifies();
    test_regex_literal_behind_an_alternation_uses_candidates();
    test_regex_multibyte_class_uses_candidates();
    test_short_literal_regex_falls_back_to_scan_verify();
    test_counts_change_speed_not_answer();
    test_mapped_regex_uses_ngram_candidates_with_residual();

    n00b_shutdown();
    return 0;
}
