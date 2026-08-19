/* test/unit/plan_oracle.h - a built plan checked against an unoptimized scan
 * of the same predicate.
 *
 * Rows come from the predicate. Every field it names gets a pool of values
 * built from that field's own literals, and the rows are the cross product of
 * those pools, which covers the boolean structure without having to ask which
 * truth assignments are satisfiable. Both plans run over the same rows and
 * must return the same ordinals.
 *
 * The including file must define CHECK.
 */

#pragma once

#include <stdio.h>
#include "conduit/print.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"

#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"
#include "rocs/normalizer.h"
#include "internal/rocs/plan_ir.h"

#define ORACLE_MAX_FIELDS   4
#define ORACLE_MAX_LITERALS 8
#define ORACLE_MAX_VALUES   20
#define ORACLE_MAX_ROWS     48

typedef struct {
    n00b_string_t *name;
    n00b_string_t *literals[ORACLE_MAX_LITERALS];
    uint64_t       literal_count;
} oracle_field_t;

typedef struct {
    oracle_field_t fields[ORACLE_MAX_FIELDS];
    uint64_t       field_count;
    n00b_string_t *any_literals[ORACLE_MAX_LITERALS];
    uint64_t       any_count;
    bool           too_wide;
} oracle_shape_t;

static n00b_string_t *
oracle_leaf_text(n00b_plan_predicate_t *predicate)
{
    auto text_r = n00b_plan_predicate_text(predicate);
    if (n00b_result_is_err(text_r)) {
        return nullptr;
    }
    n00b_option_t(n00b_string_t *) text = n00b_result_get(text_r);
    if (n00b_option_is_set(text)) {
        return n00b_option_get(text);
    }

    auto value_r = n00b_plan_predicate_value(predicate);
    if (n00b_result_is_err(value_r)) {
        return nullptr;
    }
    n00b_option_t(n00b_plan_value_t) value = n00b_result_get(value_r);
    if (!n00b_option_is_set(value)) {
        return nullptr;
    }
    n00b_plan_value_t held = n00b_option_get(value);
    if (!n00b_variant_is_type(held, n00b_json_node_t *)) {
        return nullptr;
    }
    n00b_json_node_t *node = n00b_variant_get(held, n00b_json_node_t *);
    if (node == nullptr || !n00b_json_is_string(node)) {
        return nullptr;
    }
    return n00b_json_as_string(node);
}

static void
oracle_note(n00b_string_t **slots,
            uint64_t       *count,
            n00b_string_t  *literal,
            bool           *too_wide)
{
    if (literal == nullptr) {
        return;
    }
    for (uint64_t i = 0; i < *count; i++) {
        if (n00b_unicode_str_eq(slots[i], literal)) {
            return;
        }
    }
    if (*count == ORACLE_MAX_LITERALS) {
        *too_wide = true;
        return;
    }
    slots[(*count)++] = literal;
}

static oracle_field_t *
oracle_slot(oracle_shape_t *shape, n00b_string_t *name)
{
    for (uint64_t i = 0; i < shape->field_count; i++) {
        if (n00b_unicode_str_eq(shape->fields[i].name, name)) {
            return &shape->fields[i];
        }
    }
    if (shape->field_count == ORACLE_MAX_FIELDS) {
        shape->too_wide = true;
        return nullptr;
    }
    oracle_field_t *slot = &shape->fields[shape->field_count++];
    slot->name           = name;
    slot->literal_count  = 0;
    return slot;
}

static void
oracle_collect(n00b_plan_predicate_t *predicate, oracle_shape_t *shape)
{
    auto kind_r = n00b_plan_predicate_kind(predicate);
    if (n00b_result_is_err(kind_r)) {
        return;
    }

    if (n00b_result_get(kind_r) == N00B_PLAN_PREDICATE_LEAF) {
        auto target_r = n00b_plan_predicate_target(predicate);
        if (n00b_result_is_err(target_r)) {
            return;
        }
        n00b_option_t(n00b_plan_target_t *) target = n00b_result_get(target_r);
        if (!n00b_option_is_set(target)) {
            return;
        }
        auto name_r = n00b_plan_target_field_name(n00b_option_get(target));
        if (n00b_result_is_err(name_r)) {
            return;
        }
        n00b_option_t(n00b_string_t *) name = n00b_result_get(name_r);
        n00b_string_t *literal              = oracle_leaf_text(predicate);

        if (!n00b_option_is_set(name)) {
            oracle_note(shape->any_literals,
                        &shape->any_count,
                        literal,
                        &shape->too_wide);
            return;
        }
        oracle_field_t *slot = oracle_slot(shape, n00b_option_get(name));
        if (slot != nullptr) {
            oracle_note(slot->literals,
                        &slot->literal_count,
                        literal,
                        &shape->too_wide);
        }
        return;
    }

    auto count_r = n00b_plan_predicate_child_count(predicate);
    if (n00b_result_is_err(count_r)) {
        return;
    }
    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto child_r = n00b_plan_predicate_child_at(predicate, i);
        if (n00b_result_is_err(child_r)) {
            continue;
        }
        n00b_option_t(n00b_plan_predicate_t *) child = n00b_result_get(child_r);
        if (n00b_option_is_set(child)) {
            oracle_collect(n00b_option_get(child), shape);
        }
    }
}

static bool
oracle_mentions_any(n00b_plan_predicate_t *predicate)
{
    auto kind_r = n00b_plan_predicate_kind(predicate);
    if (n00b_result_is_err(kind_r)) {
        return false;
    }
    if (n00b_result_get(kind_r) == N00B_PLAN_PREDICATE_LEAF) {
        auto target_r = n00b_plan_predicate_target(predicate);
        if (n00b_result_is_err(target_r)) {
            return false;
        }
        n00b_option_t(n00b_plan_target_t *) target = n00b_result_get(target_r);
        if (!n00b_option_is_set(target)) {
            return false;
        }
        auto name_r = n00b_plan_target_field_name(n00b_option_get(target));
        return n00b_result_is_ok(name_r)
            && !n00b_option_is_set(n00b_result_get(name_r));
    }

    auto count_r = n00b_plan_predicate_child_count(predicate);
    if (n00b_result_is_err(count_r)) {
        return false;
    }
    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto child_r = n00b_plan_predicate_child_at(predicate, i);
        if (n00b_result_is_err(child_r)) {
            continue;
        }
        n00b_option_t(n00b_plan_predicate_t *) child = n00b_result_get(child_r);
        if (n00b_option_is_set(child)
            && oracle_mentions_any(n00b_option_get(child))) {
            return true;
        }
    }
    return false;
}

// Subtrees with no any-field leaf are shared rather than copied, so only the
// spine down to a rewritten leaf is rebuilt.
static n00b_plan_predicate_t *
oracle_expand_any(n00b_plan_predicate_t         *predicate,
                  n00b_store_index_field_list_t *covered)
{
    if (!oracle_mentions_any(predicate)) {
        return predicate;
    }

    auto kind_r = n00b_plan_predicate_kind(predicate);
    CHECK(n00b_result_is_ok(kind_r));
    n00b_plan_predicate_kind_t kind = n00b_result_get(kind_r);

    if (kind == N00B_PLAN_PREDICATE_LEAF) {
        n00b_string_t *literal = oracle_leaf_text(predicate);
        CHECK(literal != nullptr);
        CHECK(covered != nullptr);

        n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
        size_t                      n    = n00b_list_len(*covered);
        CHECK(n > 0);
        for (size_t i = 0; i < n; i++) {
            auto target_r = n00b_plan_target_field(n00b_list_get(*covered, i));
            CHECK(n00b_result_is_ok(target_r));
            auto leaf_r = n00b_plan_predicate_contains(n00b_result_get(target_r),
                                                       literal);
            CHECK(n00b_result_is_ok(leaf_r));
            CHECK(n00b_result_is_ok(
                n00b_plan_predicate_list_append(kids, n00b_result_get(leaf_r))));
        }
        if (n == 1) {
            return n00b_list_get(*kids, 0);
        }
        auto or_r = n00b_plan_predicate_or(kids);
        CHECK(n00b_result_is_ok(or_r));
        return n00b_result_get(or_r);
    }

    auto count_r = n00b_plan_predicate_child_count(predicate);
    CHECK(n00b_result_is_ok(count_r));
    uint64_t count = n00b_result_get(count_r);

    if (kind == N00B_PLAN_PREDICATE_NOT) {
        CHECK(count == 1);
        auto child_r = n00b_plan_predicate_child_at(predicate, 0);
        CHECK(n00b_result_is_ok(child_r));
        n00b_option_t(n00b_plan_predicate_t *) child = n00b_result_get(child_r);
        CHECK(n00b_option_is_set(child));
        auto not_r = n00b_plan_predicate_not(
            oracle_expand_any(n00b_option_get(child), covered));
        CHECK(n00b_result_is_ok(not_r));
        return n00b_result_get(not_r);
    }

    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    for (uint64_t i = 0; i < count; i++) {
        auto child_r = n00b_plan_predicate_child_at(predicate, i);
        CHECK(n00b_result_is_ok(child_r));
        n00b_option_t(n00b_plan_predicate_t *) child = n00b_result_get(child_r);
        CHECK(n00b_option_is_set(child));
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            kids,
            oracle_expand_any(n00b_option_get(child), covered))));
    }
    auto rebuilt_r = kind == N00B_PLAN_PREDICATE_AND
                       ? n00b_plan_predicate_and(kids)
                       : n00b_plan_predicate_or(kids);
    CHECK(n00b_result_is_ok(rebuilt_r));
    return n00b_result_get(rebuilt_r);
}

static n00b_store_index_field_list_t *
oracle_covered_fields(n00b_plan_index_list_t *indexes)
{
    if (indexes == nullptr) {
        return nullptr;
    }
    size_t count = n00b_list_len(*indexes);
    for (size_t i = 0; i < count; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, i);
        auto                is_r  = n00b_store_index_is_catch_all(index);
        if (n00b_result_is_ok(is_r) && n00b_result_get(is_r)) {
            auto fields_r = n00b_store_index_catch_all_fields(index);
            CHECK(n00b_result_is_ok(fields_r));
            return n00b_result_get(fields_r);
        }
    }
    return nullptr;
}

// Fresh descriptors of the same shape, because the caller's own indexes are
// already populated against the caller's records.
static n00b_plan_index_list_t *
oracle_clone_indexes(n00b_plan_index_list_t *indexes)
{
    n00b_plan_index_list_t *clones = n00b_plan_index_list_new();
    if (indexes == nullptr) {
        return clones;
    }
    size_t count = n00b_list_len(*indexes);
    for (size_t i = 0; i < count; i++) {
        n00b_store_index_t *index = n00b_list_get(*indexes, i);
        n00b_store_index_t *clone = nullptr;

        auto is_r = n00b_store_index_is_catch_all(index);
        if (n00b_result_is_ok(is_r) && n00b_result_get(is_r)) {
            auto fields_r = n00b_store_index_catch_all_fields(index);
            CHECK(n00b_result_is_ok(fields_r));
            auto clone_r = n00b_store_index_new_catch_all(
                n00b_result_get(fields_r));
            CHECK(n00b_result_is_ok(clone_r));
            clone = n00b_result_get(clone_r);
        }
        else {
            auto field_r = n00b_store_index_field(index);
            auto kind_r  = n00b_store_index_kind(index);
            CHECK(n00b_result_is_ok(field_r));
            CHECK(n00b_result_is_ok(kind_r));
            auto clone_r = n00b_store_index_new(n00b_result_get(field_r),
                                                n00b_result_get(kind_r));
            CHECK(n00b_result_is_ok(clone_r));
            clone = n00b_result_get(clone_r);
        }
        CHECK(n00b_result_is_ok(n00b_plan_index_list_append(clones, clone)));
    }
    return clones;
}

// Values for one field: each literal verbatim, each literal buried mid-string
// so that contains and prefix separate, one token matching nothing, and the
// field left out entirely.
static uint64_t
oracle_values(oracle_field_t *field, n00b_string_t **out)
{
    uint64_t n = 0;
    for (uint64_t i = 0; i < field->literal_count; i++) {
        out[n++] = field->literals[i];
        out[n++] = n00b_cformat("zq [|#|] qz", field->literals[i]);
    }
    out[n++] = r"zzqq";
    out[n++] = nullptr;
    return n;
}

typedef struct {
    n00b_store_shard_t            *shard;
    n00b_store_map_shard_t        *mapped;
    n00b_plan_index_list_t        *indexes;
    n00b_store_index_field_list_t *covered;
    uint64_t                       rows;
} oracle_fixture_t;

// One shard and one set of indexes covering every literal the given predicates
// mention, so a sweep of many shapes shares a single fixture.
static oracle_fixture_t
n00b_plan_oracle_fixture(n00b_plan_predicate_t **predicates,
                         uint64_t                predicate_count,
                         n00b_plan_index_list_t *indexes)
{
    oracle_shape_t shape = {};
    for (uint64_t i = 0; i < predicate_count; i++) {
        oracle_collect(predicates[i], &shape);
    }
    CHECK(!shape.too_wide);

    n00b_store_index_field_list_t *covered = oracle_covered_fields(indexes);

    // An any-field literal has to be reachable through a field the catch-all
    // covers, and present in one it does not, or the opt-in list goes untested.
    if (shape.any_count > 0) {
        CHECK(covered != nullptr);
        size_t covered_n = n00b_list_len(*covered);
        for (size_t i = 0; i < covered_n; i++) {
            oracle_field_t *slot = oracle_slot(&shape,
                                               n00b_list_get(*covered, i));
            CHECK(slot != nullptr);
            for (uint64_t j = 0; j < shape.any_count; j++) {
                oracle_note(slot->literals,
                            &slot->literal_count,
                            shape.any_literals[j],
                            &shape.too_wide);
            }
        }
        oracle_field_t *hidden = oracle_slot(&shape, r"oracle_uncovered");
        CHECK(hidden != nullptr);
        for (uint64_t j = 0; j < shape.any_count; j++) {
            oracle_note(hidden->literals,
                        &hidden->literal_count,
                        shape.any_literals[j],
                        &shape.too_wide);
        }
        CHECK(!shape.too_wide);
    }

    CHECK(shape.field_count > 0);

    n00b_string_t *pools[ORACLE_MAX_FIELDS][ORACLE_MAX_VALUES];
    uint64_t       widths[ORACLE_MAX_FIELDS];
    uint64_t       total = 1;
    for (uint64_t f = 0; f < shape.field_count; f++) {
        widths[f] = oracle_values(&shape.fields[f], pools[f]);
        total *= widths[f];
    }

    // Two shards holding the same rows. Sealing closes a shard, so the hot
    // path needs one that stays open.
    static uint64_t oracle_shard_seq = 0;
    auto            hot_r            = n00b_store_shard_new(
        .shard_id = UINT64_C(0x04ac1e0000) + oracle_shard_seq++);
    auto seal_src_r = n00b_store_shard_new(
        .shard_id = UINT64_C(0x04ac1e0000) + oracle_shard_seq++);
    CHECK(n00b_result_is_ok(hot_r));
    CHECK(n00b_result_is_ok(seal_src_r));
    n00b_store_shard_t     *shard   = n00b_result_get(hot_r);
    n00b_store_shard_t     *to_seal = n00b_result_get(seal_src_r);
    n00b_plan_index_list_t *clones  = oracle_clone_indexes(indexes);
    size_t                  clone_n = n00b_list_len(*clones);

    // The cross product grows with the number of literals, so beyond a cap the
    // rows are sampled evenly across it rather than truncated at the front,
    // which would leave whole fields pinned to their first value.
    uint64_t rows = total > ORACLE_MAX_ROWS ? ORACLE_MAX_ROWS : total;

    for (uint64_t row = 0; row < rows; row++) {
        n00b_json_node_t *record = n00b_json_object_new();
        uint64_t          rest   = rows == total
                                     ? row
                                     : (uint64_t)((row * total) / rows);
        for (uint64_t f = 0; f < shape.field_count; f++) {
            n00b_string_t *value = pools[f][rest % widths[f]];
            rest /= widths[f];
            if (value != nullptr) {
                n00b_json_object_put_n00b(record,
                                          shape.fields[f].name,
                                          n00b_json_string_new_from_n00b(value));
            }
        }
        CHECK(n00b_result_is_ok(n00b_store_shard_append(shard, record)));
        CHECK(n00b_result_is_ok(n00b_store_shard_append(to_seal, record)));
        for (size_t i = 0; i < clone_n; i++) {
            // A catch-all descriptor resolves from the shard's columns, so it
            // has no postings to feed and rejects being added to.
            n00b_store_index_t *index = n00b_list_get(*clones, i);
            auto                is_r  = n00b_store_index_is_catch_all(index);
            if (n00b_result_is_ok(is_r) && n00b_result_get(is_r)) {
                continue;
            }
            CHECK(n00b_result_is_ok(
                n00b_store_index_add(index, shard, row)));
            CHECK(n00b_result_is_ok(
                n00b_store_index_add(index, to_seal, row)));
        }
    }

    // The same rows read the other way. Hot and mapped differ in record fetch
    // and index lookup, so a shape that agrees on one can still disagree here.
    n00b_store_map_shard_t *mapped  = nullptr;
    auto                    seal_r  = n00b_store_shard_seal(
        to_seal,
        .seal_ts      = 91 + oracle_shard_seq,
        .base_address = 0x9100u + (oracle_shard_seq * 0x100u));
    if (n00b_result_is_ok(seal_r)) {
        auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
        if (n00b_result_is_ok(map_r)) {
            auto root_r = n00b_store_map_root(n00b_result_get(map_r));
            if (n00b_result_is_ok(root_r)) {
                mapped = n00b_result_get(root_r);
            }
        }
    }
    CHECK(mapped != nullptr);

    return (oracle_fixture_t){.shard   = shard,
                             .mapped  = mapped,
                             .indexes = clones,
                             .covered = covered,
                             .rows    = rows};
}

// Check one predicate against a fixture: the plan must answer exactly what an
// unoptimized scan of the same predicate answers.
static void
n00b_plan_oracle_check_in(oracle_fixture_t       fixture,
                          n00b_plan_predicate_t *predicate)
{
    n00b_store_shard_t            *shard   = fixture.shard;
    n00b_plan_index_list_t        *clones  = fixture.indexes;
    n00b_store_index_field_list_t *covered = fixture.covered;
    uint64_t                       rows    = fixture.rows;

    n00b_plan_node_t *planned = nullptr;
    auto              plan_r  = n00b_plan_build(predicate, clones);
    CHECK(n00b_result_is_ok(plan_r));
    planned = n00b_result_get(plan_r);

    n00b_plan_index_list_t *none     = n00b_plan_index_list_new();
    auto                    naive_r  = n00b_plan_build(
        oracle_expand_any(predicate, covered), none);
    CHECK(n00b_result_is_ok(naive_r));
    n00b_plan_node_t *naive = n00b_result_get(naive_r);

    // With nothing to look up, the reference must be one flat pass. If it is
    // not, the reference is doing optimization of its own and proves nothing.
    auto sole_r = n00b_plan_sole_record_scan(naive);
    CHECK(n00b_result_is_ok(sole_r));
    CHECK(n00b_option_is_set(n00b_result_get(sole_r)));

    n00b_plan_records_scanned_reset();
    auto planned_set_r = n00b_plan_exec_hot(planned, shard);
    CHECK(n00b_result_is_ok(planned_set_r));
    uint64_t scanned = n00b_plan_records_scanned();

    auto naive_set_r = n00b_plan_exec_hot(naive, shard);
    CHECK(n00b_result_is_ok(naive_set_r));

    auto mapped_set_r = n00b_plan_exec_mapped(planned, fixture.mapped);
    CHECK(n00b_result_is_ok(mapped_set_r));

    n00b_plan_ordset_t *got      = n00b_result_get(planned_set_r);
    n00b_plan_ordset_t *expected = n00b_result_get(naive_set_r);
    n00b_plan_ordset_t *mapped   = n00b_result_get(mapped_set_r);
    for (uint64_t row = 0; row < rows; row++) {
        auto map_r = n00b_plan_ordset_contains(mapped, row);
        auto exp2  = n00b_plan_ordset_contains(expected, row);
        CHECK(n00b_result_is_ok(map_r));
        CHECK(n00b_result_is_ok(exp2));
        if (n00b_result_get(map_r) != n00b_result_get(exp2)) {
            n00b_eprintf("mapped mismatch row [|#|] mapped=[|#|] naive=[|#|]",
                         (int64_t)row,
                         (int64_t)n00b_result_get(map_r),
                         (int64_t)n00b_result_get(exp2));
        }
        CHECK(n00b_result_get(map_r) == n00b_result_get(exp2));

        auto got_r = n00b_plan_ordset_contains(got, row);
        auto exp_r = n00b_plan_ordset_contains(expected, row);
        CHECK(n00b_result_is_ok(got_r));
        CHECK(n00b_result_is_ok(exp_r));
        if (n00b_result_get(got_r) != n00b_result_get(exp_r)) {
            n00b_eprintf("oracle mismatch row [|#|] planned=[|#|] naive=[|#|]",
                         (int64_t)row,
                         (int64_t)n00b_result_get(got_r),
                         (int64_t)n00b_result_get(exp_r));
        }
        CHECK(n00b_result_get(got_r) == n00b_result_get(exp_r));
    }

    // Record scans that are not siblings cannot merge, so a nested predicate
    // may read the rows more than once. How many passes a shape is allowed is
    // the planner's own invariant; what is checked here is the answer.
    (void)scanned;
}

// One predicate, its own fixture.
static void
n00b_plan_oracle_check(n00b_plan_predicate_t  *predicate,
                       n00b_plan_index_list_t *indexes)
{
    n00b_plan_predicate_t *one[] = {predicate};
    n00b_plan_oracle_check_in(n00b_plan_oracle_fixture(one, 1, indexes),
                              predicate);
}

// Rows are built from the fields a predicate names, so one that names none
// (a constant, or a target the walker does not model) has nothing to vary.
// An any-field leaf additionally needs the catch-all's opt-in list, without
// which the reference has no way to say what the leaf means.
static bool
oracle_can_check(n00b_plan_predicate_t  *predicate,
                 n00b_plan_index_list_t *indexes)
{
    oracle_shape_t shape = {};

    oracle_collect(predicate, &shape);
    if (shape.too_wide || shape.field_count == 0) {
        return false;
    }
    if (shape.any_count > 0 && oracle_covered_fields(indexes) == nullptr) {
        return false;
    }
    return true;
}

// The real entry point, for the checker's own use and for a call site that
// deliberately wants an unchecked build.
static n00b_result_t(n00b_plan_node_t *)
n00b_plan_build_raw(n00b_plan_predicate_t  *predicate,
                    n00b_plan_index_list_t *indexes)
{
    return n00b_plan_build(predicate, indexes);
}

// Every plan a test builds gets compared against an unoptimized scan of the
// same predicate, over rows derived from that predicate. A build that fails is
// passed through, since a test may be asserting the failure.
static n00b_result_t(n00b_plan_node_t *)
n00b_plan_build_checked(n00b_plan_predicate_t  *predicate,
                        n00b_plan_index_list_t *indexes)
{
    auto result = n00b_plan_build_raw(predicate, indexes);

    if (n00b_result_is_ok(result) && oracle_can_check(predicate, indexes)) {
        // Checking reads records of its own, which would otherwise show up in
        // a caller's work count.
        uint64_t scanned = n00b_plan_records_scanned();
        n00b_plan_oracle_check(predicate, indexes);
        n00b_plan_records_scanned_set(scanned);
    }
    return result;
}

// Shadowed so a call site cannot be added without the check. Defined after the
// functions above so they still reach the real one.
#define n00b_plan_build(predicate, indexes)                                    \
    n00b_plan_build_checked((predicate), (indexes))
