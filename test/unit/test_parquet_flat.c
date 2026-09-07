#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "core/string.h"
#include "data/parquet.h"

static n00b_string_t *
test_path(const char *suffix)
{
    static int counter = 0;
    const char *tmp = getenv("TMPDIR");
    char path[512];

    if (!tmp || tmp[0] == '\0') {
        tmp = "/tmp";
    }

    snprintf(path,
             sizeof(path),
             "%s/n00b_parquet_flat_%d_%s.parquet",
             tmp,
             counter++,
             suffix);
    remove(path);
    return n00b_string_from_cstr(path);
}

static void
test_roundtrip_all_supported_types(void)
{
    n00b_parquet_column_t columns[] = {
        {.name = "passed", .type = N00B_PARQUET_BOOL, .nullable = true},
        {.name = "duration_us", .type = N00B_PARQUET_I64, .nullable = false},
        {.name = "ordinal", .type = N00B_PARQUET_U64, .nullable = true},
        {.name = "case_name", .type = N00B_PARQUET_UTF8, .nullable = false},
        {.name = "digest", .type = N00B_PARQUET_BINARY, .nullable = true},
        {.name = "observed_at", .type = N00B_PARQUET_TIMESTAMP_MICROS, .nullable = true},
    };
    n00b_parquet_writer_t *writer = n00b_parquet_writer_new(columns, 6);

    n00b_parquet_value_t row1[] = {
        n00b_parquet_bool(true),
        n00b_parquet_i64(1200),
        n00b_parquet_u64(7),
        n00b_parquet_cstr("unit:json_contract"),
        n00b_parquet_binary(n00b_buffer_from_bytes("abcd", 4)),
        n00b_parquet_timestamp_micros(1700000000123456LL),
    };
    n00b_parquet_value_t row2[] = {
        n00b_parquet_null(),
        n00b_parquet_i64(33),
        n00b_parquet_null(),
        n00b_parquet_cstr("unit:http_service"),
        n00b_parquet_null(),
        n00b_parquet_null(),
    };

    auto ar1 = n00b_parquet_writer_add_row(writer, row1);
    assert(n00b_result_is_ok(ar1));
    auto ar2 = n00b_parquet_writer_add_row(writer, row2);
    assert(n00b_result_is_ok(ar2));
    assert(n00b_parquet_writer_row_count(writer) == 2);

    n00b_string_t *path = test_path("roundtrip");
    auto wr = n00b_parquet_writer_write_file(writer, path);
    assert(n00b_result_is_ok(wr));

    FILE *f = fopen((const char *)path->data, "rb");
    assert(f != nullptr);
    char magic[4];
    assert(fread(magic, 1, 4, f) == 4);
    assert(memcmp(magic, "PAR1", 4) == 0);
    fclose(f);

    auto rr = n00b_parquet_read_file(path, columns, 6);
    assert(n00b_result_is_ok(rr));
    n00b_parquet_table_t *table = n00b_result_get(rr);
    assert(n00b_parquet_table_row_count(table) == 2);
    assert(n00b_parquet_table_column_count(table) == 6);

    const n00b_parquet_value_t *v = n00b_parquet_table_value(table, 0, 0);
    assert(v && !v->is_null && v->as.boolean);
    v = n00b_parquet_table_value(table, 0, 1);
    assert(v && !v->is_null && v->as.i64 == 1200);
    v = n00b_parquet_table_value(table, 0, 2);
    assert(v && !v->is_null && v->as.u64 == 7);
    v = n00b_parquet_table_value(table, 0, 3);
    assert(v && !v->is_null);
    assert(v->as.bytes->byte_len == strlen("unit:json_contract"));
    assert(memcmp(v->as.bytes->data, "unit:json_contract", v->as.bytes->byte_len) == 0);
    v = n00b_parquet_table_value(table, 0, 4);
    assert(v && !v->is_null && v->as.bytes->byte_len == 4);
    assert(memcmp(v->as.bytes->data, "abcd", 4) == 0);
    v = n00b_parquet_table_value(table, 0, 5);
    assert(v && !v->is_null && v->as.i64 == 1700000000123456LL);

    assert(n00b_parquet_table_value(table, 1, 0)->is_null);
    assert(n00b_parquet_table_value(table, 1, 2)->is_null);
    assert(n00b_parquet_table_value(table, 1, 4)->is_null);
    assert(n00b_parquet_table_value(table, 1, 5)->is_null);

    remove((const char *)path->data);
    printf("  [PASS] roundtrip_all_supported_types\n");
}

static void
test_required_null_rejected(void)
{
    n00b_parquet_column_t columns[] = {
        {.name = "case_name", .type = N00B_PARQUET_UTF8, .nullable = false},
    };
    n00b_parquet_writer_t *writer = n00b_parquet_writer_new(columns, 1);
    n00b_parquet_value_t row[] = {n00b_parquet_null()};
    auto r = n00b_parquet_writer_add_row(writer, row);

    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_PARQUET_SCHEMA);
    printf("  [PASS] required_null_rejected\n");
}

static void
test_schema_mismatch_rejected(void)
{
    n00b_parquet_column_t columns[] = {
        {.name = "case_name", .type = N00B_PARQUET_UTF8, .nullable = false},
    };
    n00b_parquet_column_t wrong[] = {
        {.name = "case_id", .type = N00B_PARQUET_UTF8, .nullable = false},
    };
    n00b_parquet_writer_t *writer = n00b_parquet_writer_new(columns, 1);
    n00b_parquet_value_t row[] = {n00b_parquet_cstr("test_one")};
    n00b_string_t *path = test_path("mismatch");

    assert(n00b_result_is_ok(n00b_parquet_writer_add_row(writer, row)));
    assert(n00b_result_is_ok(n00b_parquet_writer_write_file(writer, path)));

    auto rr = n00b_parquet_read_file(path, wrong, 1);
    assert(n00b_result_is_err(rr));
    assert(n00b_result_get_err(rr) == N00B_ERR_PARQUET_SCHEMA);

    remove((const char *)path->data);
    printf("  [PASS] schema_mismatch_rejected\n");
}

static void
test_empty_table_roundtrip(void)
{
    n00b_parquet_column_t columns[] = {
        {.name = "finding_count", .type = N00B_PARQUET_I64, .nullable = true},
    };
    n00b_parquet_writer_t *writer = n00b_parquet_writer_new(columns, 1);
    n00b_string_t *path = test_path("empty");

    assert(n00b_result_is_ok(n00b_parquet_writer_write_file(writer, path)));
    auto rr = n00b_parquet_read_file(path, columns, 1);
    assert(n00b_result_is_ok(rr));
    assert(n00b_parquet_table_row_count(n00b_result_get(rr)) == 0);

    remove((const char *)path->data);
    printf("  [PASS] empty_table_roundtrip\n");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    test_roundtrip_all_supported_types();
    test_required_null_rejected();
    test_schema_mismatch_rejected();
    test_empty_table_roundtrip();

    printf("test_parquet_flat: ok\n");
    n00b_shutdown();
    return 0;
}
