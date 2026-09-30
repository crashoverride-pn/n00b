/*
 * What an index lookup, a probe, and a record read cost, counted.
 *
 * Each test builds a shard where the answer is small or cheap and the thing
 * around it is large, then asserts on the work the debug counters saw: posting
 * entries and bitmap words read, map view handles cut, record views built,
 * whole records parsed, and normalized terms built. None of it is timed. A
 * regression shows up as a count proportional to the large thing instead of
 * the small one, on any machine.
 */

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/json_field.h"
#include "internal/rocs/map.h"
#include "internal/rocs/normalizer.h"
#include "rocs_test_support.h"
#include "test_check.h"

#ifndef N00B_DEBUG
#error "test_rocs_index_scaling asserts on debug-only work counters"
#endif

#define SEAL_TS UINT64_C(4242)

typedef struct {
    n00b_store_map_t       *map;
    n00b_store_map_shard_t *root;
} mapped_t;

static n00b_store_shard_t *
new_shard(uint64_t id)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = id,
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));
    return n00b_result_get(shard_r);
}

static n00b_store_index_t *
term_index(n00b_string_t *field, n00b_store_postings_kind_t postings)
{
    auto index_r = n00b_store_index_new(field,
                                        N00B_STORE_INDEX_TERM,
                                        .postings = postings);
    CHECK(n00b_result_is_ok(index_r));
    return n00b_result_get(index_r);
}

static uint64_t
append(n00b_store_shard_t *shard, n00b_json_node_t *record)
{
    auto append_r = n00b_store_shard_append(shard, record);
    CHECK(n00b_result_is_ok(append_r));
    return n00b_result_get(append_r);
}

static void
add(n00b_store_index_t *index, n00b_store_shard_t *shard, uint64_t ordinal)
{
    CHECK(n00b_result_is_ok(n00b_store_index_add(index, shard, ordinal)));
}

static mapped_t
seal_and_map(n00b_store_shard_t *shard)
{
    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = SEAL_TS,
                                        .base_address = 0xE10000u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    CHECK(n00b_result_is_ok(root_r));

    return (mapped_t){
        .map  = n00b_result_get(map_r),
        .root = n00b_result_get(root_r),
    };
}

static n00b_json_node_t *
str(n00b_string_t *s)
{
    return n00b_json_string_new_from_n00b(s);
}

// Two values are the same when they encode the same. Both sides come from the
// same stored bytes, so key order agrees.
static bool
same_json(n00b_json_node_t *a, n00b_json_node_t *b)
{
    char *ea = n00b_json_encode(a, .pretty = false);
    char *eb = n00b_json_encode(b, .pretty = false);
    return ea != nullptr && eb != nullptr && strcmp(ea, eb) == 0;
}

static const uint64_t *
ordinals_of(n00b_result_t(n00b_store_postings_t *) postings_r, uint64_t *len)
{
    CHECK(n00b_result_is_ok(postings_r));
    return n00b_store_postings_ordinals(n00b_result_get(postings_r), len);
}

// ---------------------------------------------------------------------------
// 1. Dense postings enumerate in one pass over the bitmap.

#define DENSE_ROWS UINT64_C(16384)

static void
check_every_other(const uint64_t *ordinals, uint64_t len)
{
    CHECK(len == DENSE_ROWS / 2);
    for (uint64_t i = 0; i < len; i++) {
        CHECK(ordinals[i] == 2 * i);
    }
}

static void
test_dense_enumeration_is_linear(void)
{
    n00b_store_shard_t *shard = new_shard(UINT64_C(0x5CA1));
    n00b_store_index_t *kind  = term_index(r"kind", N00B_STORE_POSTINGS_DENSE);

    for (uint64_t i = 0; i < DENSE_ROWS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(rec, r"kind", str(i % 2 == 0 ? r"x" : r"y"));
        add(kind, shard, append(shard, rec));
    }

    // A few steps per word plus one per posting, allowing the bitmap twice the
    // words it needs. Finding each posting by rank from word 0 would cost
    // p * p / 2.
    uint64_t bound = 4 * (DENSE_ROWS / 64) + DENSE_ROWS / 2;

    n00b_store_posting_steps_reset();
    uint64_t        len      = 0;
    const uint64_t *ordinals = ordinals_of(
        n00b_store_index_lookup(kind, shard, str(r"x")),
        &len);
    uint64_t hot_steps = n00b_store_posting_steps();
    check_every_other(ordinals, len);
    CHECK(hot_steps <= bound);

    // The answer comes from the bitmap, whatever the list's count says.
    CHECK(n00b_store_index_hot_skew_count(kind, shard, str(r"x"), -1000) == 1);
    ordinals = ordinals_of(n00b_store_index_lookup(kind, shard, str(r"x")),
                           &len);
    check_every_other(ordinals, len);
    CHECK(n00b_store_index_hot_skew_count(kind, shard, str(r"x"), 1000) == 1);

    mapped_t mapped = seal_and_map(shard);
    n00b_store_posting_steps_reset();
    ordinals = ordinals_of(n00b_store_index_lookup_mapped(kind,
                                                          mapped.root,
                                                          str(r"x")),
                           &len);
    uint64_t sealed_steps = n00b_store_posting_steps();
    check_every_other(ordinals, len);
    CHECK(sealed_steps <= bound);
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    n00b_printf("  dense «#» of «#»: hot «#» steps, sealed «#» steps, bound «#»",
                (int64_t)(DENSE_ROWS / 2),
                (int64_t)DENSE_ROWS,
                (int64_t)hot_steps,
                (int64_t)sealed_steps,
                (int64_t)bound);
    n00b_printf("  [PASS] dense postings enumerate in O(words + postings)");
}

// ---------------------------------------------------------------------------
// 2 and 3. A sealed sparse lookup and its probes cut no view handle per
// posting, and a lookup copies its postings once and builds no record views.

#define SPARSE_ROWS UINT64_C(4096)
#define SPARSE_HITS UINT64_C(2000)

static void
test_sparse_reads_allocate_nothing_per_posting(void)
{
    n00b_store_shard_t *shard = new_shard(UINT64_C(0x5CA2));
    n00b_store_index_t *trace = term_index(r"trace", N00B_STORE_POSTINGS_SPARSE);

    for (uint64_t i = 0; i < SPARSE_ROWS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(rec,
                                  r"trace",
                                  str(i < SPARSE_HITS ? r"t" : r"u"));
        add(trace, shard, append(shard, rec));
    }

    n00b_store_record_counters_reset();
    n00b_store_posting_steps_reset();
    uint64_t len = 0;
    (void)ordinals_of(n00b_store_index_lookup(trace, shard, str(r"t")), &len);
    CHECK(len == SPARSE_HITS);
    CHECK(n00b_store_record_views_built() == 0);
    CHECK(n00b_store_posting_steps() == SPARSE_HITS);

    mapped_t mapped = seal_and_map(shard);

    n00b_store_map_view_allocs_reset();
    n00b_store_posting_steps_reset();
    const uint64_t *ordinals = ordinals_of(
        n00b_store_index_lookup_mapped(trace, mapped.root, str(r"t")),
        &len);
    uint64_t lookup_views = n00b_store_map_view_allocs();
    CHECK(len == SPARSE_HITS);
    for (uint64_t i = 0; i < len; i++) {
        CHECK(ordinals[i] == i);
    }
    CHECK(lookup_views < 16);
    CHECK(n00b_store_posting_steps() == SPARSE_HITS);

    auto probe_r = n00b_store_index_probe_mapped(trace, mapped.root, str(r"t"));
    CHECK(n00b_result_is_ok(probe_r));
    n00b_store_index_probe_t *probe = n00b_result_get(probe_r);

    n00b_store_map_view_allocs_reset();
    for (uint64_t ord = 0; ord < SPARSE_ROWS; ord++) {
        auto has_r = n00b_store_index_probe_contains(probe, ord);
        CHECK(n00b_result_is_ok(has_r));
        CHECK(n00b_result_get(has_r) == (ord < SPARSE_HITS));
    }
    CHECK(n00b_store_map_view_allocs() == 0);
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    n00b_printf("  sealed lookup of «#» postings cut «#» view handles",
                (int64_t)SPARSE_HITS,
                (int64_t)lookup_views);
    n00b_printf("  [PASS] posting reads cost no allocation per posting");
}

// ---------------------------------------------------------------------------
// 4. A multi-term lookup starts from its rarest term.

#define WIDE_ROWS UINT64_C(4096)

static void
check_rare(const uint64_t *ordinals, uint64_t len)
{
    CHECK(len == 3);
    CHECK(ordinals[0] == 10 && ordinals[1] == 2000 && ordinals[2] == 4000);
}

static void
test_intersection_starts_from_the_rarest_term(void)
{
    n00b_store_shard_t *shard   = new_shard(UINT64_C(0x5CA3));
    n00b_store_index_t *message = index_of(r"message", N00B_STORE_INDEX_FULLTEXT);

    for (uint64_t i = 0; i < WIDE_ROWS; i++) {
        n00b_json_node_t *rec  = n00b_json_object_new();
        bool              rare = i == 10 || i == 2000 || i == 4000;
        n00b_json_object_put_n00b(rec,
                                  r"message",
                                  str(rare ? r"common yzq" : r"common text"));
        add(message, shard, append(shard, rec));
    }

    // Written common-first and rare-first; both must start from the rare one.
    n00b_json_node_t *queries[] = {str(r"common yzq"), str(r"yzq common")};
    uint64_t          worst     = 0;

    for (size_t q = 0; q < 2; q++) {
        n00b_store_posting_steps_reset();
        uint64_t        len      = 0;
        const uint64_t *ordinals = ordinals_of(
            n00b_store_index_lookup(message, shard, queries[q]),
            &len);
        check_rare(ordinals, len);
        uint64_t steps = n00b_store_posting_steps();
        CHECK(steps < 16);
        worst = steps > worst ? steps : worst;
    }

    mapped_t mapped = seal_and_map(shard);
    for (size_t q = 0; q < 2; q++) {
        n00b_store_posting_steps_reset();
        uint64_t        len      = 0;
        const uint64_t *ordinals = ordinals_of(
            n00b_store_index_lookup_mapped(message, mapped.root, queries[q]),
            &len);
        check_rare(ordinals, len);
        // Three copied, then three binary searches of the wide list.
        uint64_t steps = n00b_store_posting_steps();
        CHECK(steps <= 3 + 3 * 13);
        worst = steps > worst ? steps : worst;
    }
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    n00b_printf("  3 of «#» rows, worst «#» posting steps",
                (int64_t)WIDE_ROWS,
                (int64_t)worst);
    n00b_printf("  [PASS] multi-term lookups start from the smallest list");
}

// ---------------------------------------------------------------------------
// 5 and 6. The catch-all has a df and a probe, and index stats read headers.

#define CA_ROWS UINT64_C(2048)

typedef struct {
    n00b_store_shard_t     *shard;
    n00b_store_index_t     *message;
    n00b_store_index_t     *title;
    n00b_store_index_t     *event;
    n00b_store_index_t     *catch_all;
    n00b_plan_index_list_t *indexes;
    uint64_t                error_rows;
} catch_all_sample_t;

static catch_all_sample_t
catch_all_sample(uint64_t id)
{
    catch_all_sample_t s = {
        .shard   = new_shard(id),
        .message = index_of(r"message", N00B_STORE_INDEX_FULLTEXT),
        .title   = index_of(r"title", N00B_STORE_INDEX_FULLTEXT),
        .event   = term_index(r"event_id", N00B_STORE_POSTINGS_SPARSE),
    };

    n00b_store_index_field_list_t *fields =
        n00b_alloc(n00b_store_index_field_list_t);
    *fields = n00b_list_new_private(n00b_string_t *,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    n00b_list_push(*fields, r"message");
    n00b_list_push(*fields, r"title");
    auto catch_all_r = n00b_store_index_new_catch_all(fields);
    CHECK(n00b_result_is_ok(catch_all_r));
    s.catch_all = n00b_result_get(catch_all_r);

    // "error" in every message but the last quarter, and in every eighth
    // title, so some records match in both covered fields.
    for (uint64_t i = 0; i < CA_ROWS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        bool              msg = i < CA_ROWS * 3 / 4;
        bool              ttl = i % 8 == 0;
        n00b_json_object_put_n00b(rec,
                                  r"message",
                                  str(msg ? r"error opening file" : r"ok"));
        n00b_json_object_put_n00b(rec,
                                  r"title",
                                  str(ttl ? r"error" : r"fine"));
        n00b_json_object_put_n00b(rec,
                                  r"event_id",
                                  str(i == 77 ? r"abc" : r"zzz"));
        uint64_t ord = append(s.shard, rec);
        add(s.message, s.shard, ord);
        add(s.title, s.shard, ord);
        add(s.event, s.shard, ord);
        if (msg || ttl) {
            s.error_rows++;
        }
    }

    s.indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(s.indexes, s.catch_all)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(s.indexes, s.event)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(s.indexes, s.message)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(s.indexes, s.title)));
    return s;
}

static uint64_t
error_sum(void)
{
    uint64_t in_message = CA_ROWS * 3 / 4;
    uint64_t in_title   = CA_ROWS / 8;
    return in_message + in_title;
}

static n00b_plan_predicate_t *
error_and_event(void)
{
    auto any_r = n00b_plan_target_any();
    CHECK(n00b_result_is_ok(any_r));
    auto contains_r = n00b_plan_predicate_contains(n00b_result_get(any_r),
                                                   r"error");
    CHECK(n00b_result_is_ok(contains_r));
    return group(n00b_result_get(contains_r), eq(r"event_id", r"abc"), true);
}

static void
check_probe_matches_lookup(n00b_result_t(n00b_store_index_probe_t *) probe_r,
                           n00b_result_t(n00b_store_postings_t *)    postings_r)
{
    CHECK(n00b_result_is_ok(probe_r));
    n00b_store_index_probe_t *probe = n00b_result_get(probe_r);

    uint64_t        len      = 0;
    const uint64_t *ordinals = ordinals_of(postings_r, &len);
    uint64_t        at       = 0;
    for (uint64_t ord = 0; ord < CA_ROWS; ord++) {
        bool expected = at < len && ordinals[at] == ord;
        if (expected) {
            at++;
        }
        auto has_r = n00b_store_index_probe_contains(probe, ord);
        CHECK(n00b_result_is_ok(has_r));
        CHECK(n00b_result_get(has_r) == expected);
    }
    CHECK(at == len);
}

static void
test_catch_all_df_probe_and_plan(void)
{
    catch_all_sample_t s     = catch_all_sample(UINT64_C(0x5CA4));
    n00b_json_node_t  *error = str(r"error");

    auto df_r = n00b_store_index_df_hot(s.catch_all, s.shard, error);
    CHECK(n00b_result_is_ok(df_r));
    CHECK(n00b_result_get(df_r) == error_sum());
    CHECK(error_sum() > s.error_rows);

    check_probe_matches_lookup(
        n00b_store_index_probe_hot(s.catch_all, s.shard, error),
        n00b_store_index_lookup(s.catch_all, s.shard, error));

    // Stats come from headers: no posting is read to produce them.
    n00b_store_posting_steps_reset();
    auto stats_r = n00b_store_index_stats_hot(s.catch_all, s.shard, error);
    CHECK(n00b_result_is_ok(stats_r));
    CHECK(n00b_result_get(stats_r).document_frequency == error_sum());
    CHECK(n00b_store_posting_steps() == 0);

    // One record carries event_id=abc, so the conjunction has one candidate
    // to test against the catch-all rather than every "error" posting to walk.
    n00b_plan_predicate_t *predicate = error_and_event();
    n00b_plan_node_t      *hot_plan  = test_plan_hot(predicate,
                                                     s.indexes,
                                                     s.shard);
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
    auto hot_r = n00b_plan_exec_hot(hot_plan, s.shard);
    CHECK(n00b_result_is_ok(hot_r));
    CHECK(n00b_result_get(n00b_plan_ordset_count(n00b_result_get(hot_r))) == 1);
    CHECK(n00b_result_get(n00b_plan_ordset_contains(n00b_result_get(hot_r), 77)));
    uint64_t hot_walked = n00b_plan_postings_walked();
    uint64_t hot_probes = n00b_plan_index_probes();
    CHECK(hot_walked < 8);
    CHECK(hot_probes >= 1);

    mapped_t mapped = seal_and_map(s.shard);

    df_r = n00b_store_index_df_mapped(s.catch_all, mapped.root, error);
    CHECK(n00b_result_is_ok(df_r));
    CHECK(n00b_result_get(df_r) == error_sum());

    check_probe_matches_lookup(
        n00b_store_index_probe_mapped(s.catch_all, mapped.root, error),
        n00b_store_index_lookup_mapped(s.catch_all, mapped.root, error));

    n00b_store_posting_steps_reset();
    auto sealed_stats_r = n00b_store_index_stats_mapped(s.message,
                                                        mapped.root,
                                                        error);
    CHECK(n00b_result_is_ok(sealed_stats_r));
    CHECK(n00b_result_get(sealed_stats_r).document_frequency
          == CA_ROWS * 3 / 4);
    CHECK(n00b_result_get(sealed_stats_r).record_count == CA_ROWS);
    CHECK(n00b_store_posting_steps() == 0);

    n00b_plan_node_t *cold_plan = test_plan_mapped(predicate,
                                                   s.indexes,
                                                   mapped.root);
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
    auto cold_r = n00b_plan_exec_mapped(cold_plan, mapped.root);
    CHECK(n00b_result_is_ok(cold_r));
    CHECK(n00b_result_get(n00b_plan_ordset_count(n00b_result_get(cold_r))) == 1);
    uint64_t cold_walked = n00b_plan_postings_walked();
    CHECK(cold_walked < 8);
    CHECK(n00b_plan_index_probes() >= 1);
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    n00b_printf("  error AND event_id: «#» error rows, walked «#» hot, «#» sealed",
                (int64_t)s.error_rows,
                (int64_t)hot_walked,
                (int64_t)cold_walked);
    n00b_printf("  [PASS] catch-all has a df and a probe; stats read headers");
}

// ---------------------------------------------------------------------------
// 7 and 9. Field reads scan the stored bytes; returning a record does not
// copy or re-encode what it already has.

static n00b_json_node_t *
field_record(uint64_t i)
{
    n00b_json_node_t *inner = n00b_json_object_new();
    n00b_json_object_put_n00b(inner, r"name", str(r"leaf"));
    n00b_json_object_put_n00b(inner, r"depth", n00b_json_int_new((int64_t)i));

    n00b_json_node_t *rec = n00b_json_object_new();
    n00b_json_object_put_n00b(rec, r"level", str(i % 3 == 0 ? r"error" : r"info"));
    n00b_json_object_put_n00b(rec, r"inner", inner);
    n00b_json_object_put_n00b(rec, r"a.b", str(r"dotted key"));
    n00b_json_object_put_n00b(rec, r"flat", n00b_json_int_new(7));
    n00b_json_object_put_n00b(rec,
                              r"message",
                              str(i % 5 == 0 ? r"alpha beta gamma"
                                             : r"alpha delta"));
    return rec;
}

#define PROBE_FIELDS 7

static void
check_fields_match_parse(n00b_store_record_t *view)
{
    n00b_string_t *probe_fields[PROBE_FIELDS] = {
        r"level",
        r"inner.name",
        r"inner.depth",
        r"a.b",
        r"flat.x",
        r"missing",
        r"inner",
    };

    auto json_r = n00b_store_record_view_json(view);
    CHECK(n00b_result_is_ok(json_r));
    n00b_json_node_t *whole = n00b_result_get(json_r);

    n00b_store_record_counters_reset();
    for (size_t f = 0; f < PROBE_FIELDS; f++) {
        auto one_r = n00b_store_record_view_field(view, probe_fields[f]);
        CHECK(n00b_result_is_ok(one_r));
        n00b_json_node_t *expected = rocs_json_object_get_field(whole,
                                                                probe_fields[f]);
        n00b_option_t(n00b_json_node_t *) got = n00b_result_get(one_r);
        CHECK(n00b_option_is_set(got) == (expected != nullptr));
        if (expected != nullptr) {
            CHECK(same_json(n00b_option_get(got), expected));
        }
    }
    CHECK(n00b_store_record_parses() == 0);
    CHECK(n00b_store_record_field_scans() == PROBE_FIELDS);

    n00b_json_node_t *values[PROBE_FIELDS];
    n00b_store_record_counters_reset();
    CHECK(n00b_result_is_ok(
        n00b_store_record_view_fields(view, PROBE_FIELDS, probe_fields, values)));
    CHECK(n00b_store_record_field_scans() == 1);
    CHECK(n00b_store_record_parses() == 0);
    for (size_t f = 0; f < PROBE_FIELDS; f++) {
        n00b_json_node_t *expected = rocs_json_object_get_field(whole,
                                                                probe_fields[f]);
        CHECK((values[f] != nullptr) == (expected != nullptr));
        if (expected != nullptr) {
            CHECK(same_json(values[f], expected));
        }
    }
}

static void
test_field_reads_scan_stored_bytes(void)
{
    n00b_store_shard_t *shard = new_shard(UINT64_C(0x5CA5));
    for (uint64_t i = 0; i < 4; i++) {
        (void)append(shard, field_record(i));
    }

    auto hot_r = n00b_store_record_view_hot_at(shard, 1);
    CHECK(n00b_result_is_ok(hot_r));
    check_fields_match_parse(n00b_result_get(hot_r));

    // Returning a hot record's text copies its bytes and parses nothing, and
    // a copy of its graph is the one parse, not a parse and then a copy.
    n00b_store_record_counters_reset();
    auto text_r = n00b_store_record_view_json_string(n00b_result_get(hot_r));
    CHECK(n00b_result_is_ok(text_r));
    CHECK(n00b_store_record_parses() == 0);
    auto copy_r = n00b_store_record_view_json_copy(n00b_result_get(hot_r));
    CHECK(n00b_result_is_ok(copy_r));
    CHECK(n00b_store_record_parses() == 1);
    auto whole_r = n00b_store_record_view_json(n00b_result_get(hot_r));
    CHECK(n00b_result_is_ok(whole_r));
    CHECK(same_json(n00b_result_get(copy_r), n00b_result_get(whole_r)));

    auto owned_r = n00b_store_record_view_owned_text(
        (n00b_store_pos_t){.shard_id = 1, .ordinal = 0},
        n00b_result_get(text_r));
    CHECK(n00b_result_is_ok(owned_r));
    check_fields_match_parse(n00b_result_get(owned_r));

    mapped_t mapped = seal_and_map(shard);
    auto     cold_r = n00b_store_record_view_mapped_at(mapped.root, 2);
    CHECK(n00b_result_is_ok(cold_r));
    check_fields_match_parse(n00b_result_get(cold_r));
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    // An escaped key is one the scan declines; the record is parsed once.
    n00b_string_t *escaped = n00b_string_from_cstr("{\"le\\u0076el\":\"error\"}");
    auto           esc_r   = n00b_store_record_view_owned_text(
        (n00b_store_pos_t){.shard_id = 1, .ordinal = 0},
        escaped);
    CHECK(n00b_result_is_ok(esc_r));
    n00b_store_record_counters_reset();
    auto level_r = n00b_store_record_view_field(n00b_result_get(esc_r), r"level");
    CHECK(n00b_result_is_ok(level_r));
    CHECK(n00b_option_is_set(n00b_result_get(level_r)));
    CHECK(n00b_store_record_parses() == 1);

    n00b_printf("  [PASS] field reads scan stored bytes; returns copy nothing twice");
}

// ---------------------------------------------------------------------------
// 7 and 8. Residual verification reads fields, not records, and CONTAINS
// hashes its needle once.

#define VERIFY_ROWS UINT64_C(600)

static n00b_plan_predicate_t *
contains(n00b_string_t *field, n00b_string_t *text)
{
    auto r = n00b_plan_predicate_contains(target(field), text);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
test_residual_verify_reads_fields(void)
{
    n00b_store_shard_t *shard = new_shard(UINT64_C(0x5CA6));
    for (uint64_t i = 0; i < VERIFY_ROWS; i++) {
        (void)append(shard, field_record(i));
    }

    // level=error (every third) OR message contains "beta gamma" (every
    // fifth), and inner.name=leaf on every record.
    n00b_plan_predicate_t *residual = group(
        group(eq(r"level", r"error"),
              contains(r"message", r"beta gamma"),
              false),
        eq(r"inner.name", r"leaf"),
        true);

    uint64_t expected = 0;
    for (uint64_t i = 0; i < VERIFY_ROWS; i++) {
        expected += (i % 3 == 0 || i % 5 == 0) ? 1 : 0;
    }

    n00b_store_record_counters_reset();
    n00b_store_normalize_counters_reset();
    auto hot_r = n00b_plan_record_scan_hot(shard, nullptr, residual);
    CHECK(n00b_result_is_ok(hot_r));
    CHECK(n00b_result_get(n00b_plan_ordset_count(n00b_result_get(hot_r)))
          == expected);
    CHECK(n00b_store_record_parses() == 0);
    CHECK(n00b_store_record_field_scans() == VERIFY_ROWS);
    // No term is built for a haystack or the needle, and the needle is
    // tokenized once for the scan. Haystacks stream only for records the
    // equality leaf did not already accept.
    CHECK(n00b_store_normalize_terms_built() == 0);
    uint64_t streams = n00b_store_normalize_key_streams();
    CHECK(streams <= VERIFY_ROWS + 2);

    mapped_t mapped = seal_and_map(shard);
    n00b_store_record_counters_reset();
    auto cold_r = n00b_plan_record_scan_mapped(mapped.root, nullptr, residual);
    CHECK(n00b_result_is_ok(cold_r));
    CHECK(n00b_result_get(n00b_plan_ordset_count(n00b_result_get(cold_r)))
          == expected);
    CHECK(n00b_store_record_parses() == 0);
    CHECK(n00b_store_record_field_scans() == VERIFY_ROWS);
    CHECK(n00b_result_is_ok(n00b_store_map_close(mapped.map)));

    // Past the scan's field limit, each record is parsed whole, once.
    n00b_plan_predicate_t *wide = eq(r"f0", r"x");
    for (int i = 1; i <= (int)ROCS_JSON_SCAN_FIELDS_MAX; i++) {
        wide = group(wide,
                     eq(n00b_cformat("f«#»", (int64_t)i), r"x"),
                     false);
    }
    n00b_store_shard_t *wide_shard = new_shard(UINT64_C(0x5CA7));
    for (uint64_t i = 0; i < 8; i++) {
        (void)append(wide_shard, field_record(i));
    }
    n00b_store_record_counters_reset();
    auto wide_r = n00b_plan_record_scan_hot(wide_shard, nullptr, wide);
    CHECK(n00b_result_is_ok(wide_r));
    CHECK(n00b_result_get(n00b_plan_ordset_count(n00b_result_get(wide_r))) == 0);
    CHECK(n00b_store_record_parses() == 8);
    CHECK(n00b_store_record_field_scans() == 0);

    n00b_printf("  residual over «#» records: 0 parses, «#» key streams",
                (int64_t)VERIFY_ROWS,
                (int64_t)streams);
    n00b_printf("  [PASS] residual verify reads fields; CONTAINS builds no terms");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_dense_enumeration_is_linear();
    test_sparse_reads_allocate_nothing_per_posting();
    test_intersection_starts_from_the_rarest_term();
    test_catch_all_df_probe_and_plan();
    test_field_reads_scan_stored_bytes();
    test_residual_verify_reads_fields();

    n00b_shutdown();
    return 0;
}
