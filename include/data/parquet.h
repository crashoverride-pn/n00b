/**
 * @file parquet.h
 * @brief Minimal flat Parquet row sink for local service data landing.
 *
 * This module intentionally supports a small Parquet subset: one flat schema,
 * one row group, one plain-encoded data page per column, no compression, and
 * nullable primitive columns. It is meant to produce durable part files for
 * service prototypes before ClickHouse/S3/object-store plumbing exists.
 */
#pragma once

#include "n00b.h"
#include "adt/result.h"
#include "core/buffer.h"
#include "core/string.h"

#define N00B_ERR_PARQUET_SCHEMA      (-220)
#define N00B_ERR_PARQUET_IO          (-221)
#define N00B_ERR_PARQUET_FORMAT      (-222)
#define N00B_ERR_PARQUET_UNSUPPORTED (-223)

typedef enum {
    N00B_PARQUET_BOOL,
    N00B_PARQUET_I64,
    N00B_PARQUET_U64,
    N00B_PARQUET_UTF8,
    N00B_PARQUET_BINARY,
    N00B_PARQUET_TIMESTAMP_MICROS,
} n00b_parquet_column_type_t;

typedef struct {
    const char                 *name;
    n00b_parquet_column_type_t  type;
    bool                        nullable;
} n00b_parquet_column_t;

typedef struct {
    bool is_null;
    union [[n00b::raw_union]] {
        bool           boolean;
        int64_t        i64;
        uint64_t       u64;
        n00b_buffer_t *bytes;
    } as;
} n00b_parquet_value_t;

typedef struct n00b_parquet_writer n00b_parquet_writer_t;
typedef struct n00b_parquet_table  n00b_parquet_table_t;

extern n00b_parquet_value_t n00b_parquet_null(void);
extern n00b_parquet_value_t n00b_parquet_bool(bool v);
extern n00b_parquet_value_t n00b_parquet_i64(int64_t v);
extern n00b_parquet_value_t n00b_parquet_u64(uint64_t v);
extern n00b_parquet_value_t n00b_parquet_timestamp_micros(int64_t v);
extern n00b_parquet_value_t n00b_parquet_utf8(n00b_string_t *v);
extern n00b_parquet_value_t n00b_parquet_binary(n00b_buffer_t *v);
extern n00b_parquet_value_t n00b_parquet_cstr(const char *v);

extern n00b_parquet_writer_t *
n00b_parquet_writer_new(const n00b_parquet_column_t *columns,
                        size_t                       column_count);

extern n00b_result_t(bool)
n00b_parquet_writer_add_row(n00b_parquet_writer_t      *writer,
                            const n00b_parquet_value_t *values);

extern n00b_result_t(bool)
n00b_parquet_writer_write_file(n00b_parquet_writer_t *writer,
                               n00b_string_t         *path);

extern n00b_result_t(n00b_parquet_table_t *)
n00b_parquet_read_file(n00b_string_t                *path,
                       const n00b_parquet_column_t  *expected_columns,
                       size_t                        expected_column_count);

extern size_t n00b_parquet_writer_row_count(n00b_parquet_writer_t *writer);
extern int    n00b_parquet_writer_error(n00b_parquet_writer_t *writer);

extern size_t n00b_parquet_table_row_count(n00b_parquet_table_t *table);
extern size_t n00b_parquet_table_column_count(n00b_parquet_table_t *table);

extern const n00b_parquet_value_t *
n00b_parquet_table_value(n00b_parquet_table_t *table, size_t row, size_t column);

