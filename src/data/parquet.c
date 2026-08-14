#include "data/parquet.h"

#include "compiler/objfile/endian.h"
#include "compiler/objfile/writer.h"
#if defined(__linux__)
#include "core/syscall.h"
#endif

#include <errno.h>
#if defined(__linux__)
#include <fcntl.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>

enum {
    PQ_TYPE_BOOLEAN          = 0,
    PQ_TYPE_INT32            = 1,
    PQ_TYPE_INT64            = 2,
    PQ_TYPE_DOUBLE           = 5,
    PQ_TYPE_BYTE_ARRAY       = 6,
    PQ_REP_REQUIRED          = 0,
    PQ_REP_OPTIONAL          = 1,
    PQ_CONVERTED_UTF8        = 0,
    PQ_CONVERTED_TIMESTAMP_US = 10,
    PQ_CONVERTED_UINT_64     = 14,
    PQ_CONVERTED_INT_64      = 18,
    PQ_ENCODING_PLAIN        = 0,
    PQ_ENCODING_RLE          = 3,
    PQ_CODEC_UNCOMPRESSED    = 0,
    PQ_PAGE_DATA             = 0,
};

enum {
    TC_STOP        = 0,
    TC_BOOL_TRUE   = 1,
    TC_BOOL_FALSE  = 2,
    TC_BYTE        = 3,
    TC_I16         = 4,
    TC_I32         = 5,
    TC_I64         = 6,
    TC_DOUBLE      = 7,
    TC_BINARY      = 8,
    TC_LIST        = 9,
    TC_SET         = 10,
    TC_MAP         = 11,
    TC_STRUCT      = 12,
};

typedef struct {
    n00b_parquet_column_t spec;
    size_t                len;
    size_t                cap;
    bool                 *is_null;
    bool                 *bools;
    int64_t              *i64s;
    uint64_t             *u64s;
    n00b_buffer_t       **bytes;
} pq_column_data_t;

struct n00b_parquet_writer {
    pq_column_data_t *columns;
    size_t            column_count;
    size_t            row_count;
    int               error;
};

struct n00b_parquet_table {
    n00b_parquet_column_t *columns;
    size_t                 column_count;
    size_t                 row_count;
    n00b_parquet_value_t  *values;
};

typedef struct {
    int64_t data_page_offset;
    int64_t total_uncompressed_size;
    int64_t total_compressed_size;
    int64_t num_values;
    int64_t null_count;
} pq_column_chunk_info_t;

typedef struct {
    n00b_writer_t *w;
    int16_t        last_field;
    int16_t        stack[32];
    int            depth;
} pq_tc_writer_t;

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    int16_t        last_field;
    int16_t        stack[32];
    int            depth;
    bool           error;
} pq_tc_reader_t;

typedef struct {
    uint8_t type;
    int16_t id;
} pq_tc_field_t;

typedef struct {
    int                  physical_type;
    int                  repetition_type;
    int                  converted_type;
    n00b_string_t       *name;
} pq_schema_meta_t;

typedef struct {
    int64_t data_page_offset;
    int64_t total_compressed_size;
    int64_t num_values;
    int64_t null_count;
    int     physical_type;
} pq_file_column_meta_t;

typedef struct {
    pq_schema_meta_t      *schema;
    size_t                 schema_count;
    pq_file_column_meta_t *columns;
    size_t                 column_count;
    int64_t                num_rows;
} pq_file_meta_t;

typedef struct {
    int     page_type;
    int32_t compressed_page_size;
    int32_t uncompressed_page_size;
    int32_t num_values;
    size_t  header_size;
} pq_page_meta_t;

static uint32_t
pq_u32_from_le(const uint8_t *p)
{
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint64_t
pq_u64_from_le(const uint8_t *p)
{
    uint64_t lo = pq_u32_from_le(p);
    uint64_t hi = pq_u32_from_le(p + 4);
    return lo | (hi << 32);
}

static uint64_t
pq_zigzag_encode_i64(int64_t v)
{
    return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
}

static int64_t
pq_zigzag_decode_i64(uint64_t v)
{
    return (int64_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
}

static int
pq_physical_type(n00b_parquet_column_type_t type)
{
    switch (type) {
    case N00B_PARQUET_BOOL:
        return PQ_TYPE_BOOLEAN;
    case N00B_PARQUET_I64:
    case N00B_PARQUET_U64:
    case N00B_PARQUET_TIMESTAMP_MICROS:
        return PQ_TYPE_INT64;
    case N00B_PARQUET_UTF8:
    case N00B_PARQUET_BINARY:
        return PQ_TYPE_BYTE_ARRAY;
    }

    return -1;
}

static int
pq_converted_type(n00b_parquet_column_type_t type)
{
    switch (type) {
    case N00B_PARQUET_I64:
        return PQ_CONVERTED_INT_64;
    case N00B_PARQUET_U64:
        return PQ_CONVERTED_UINT_64;
    case N00B_PARQUET_UTF8:
        return PQ_CONVERTED_UTF8;
    case N00B_PARQUET_TIMESTAMP_MICROS:
        return PQ_CONVERTED_TIMESTAMP_US;
    default:
        return -1;
    }
}

static void
pq_tc_init(pq_tc_writer_t *tc, n00b_writer_t *w)
{
    tc->w          = w;
    tc->last_field = 0;
    tc->depth      = 0;
}

static void
pq_tc_write_varint(pq_tc_writer_t *tc, uint64_t v)
{
    while (v >= 0x80) {
        n00b_writer_write_u8(tc->w, (uint8_t)(v | 0x80));
        v >>= 7;
    }

    n00b_writer_write_u8(tc->w, (uint8_t)v);
}

static void
pq_tc_struct_begin(pq_tc_writer_t *tc)
{
    tc->stack[tc->depth++] = tc->last_field;
    tc->last_field         = 0;
}

static void
pq_tc_struct_end(pq_tc_writer_t *tc)
{
    n00b_writer_write_u8(tc->w, TC_STOP);
    tc->last_field = tc->stack[--tc->depth];
}

static void
pq_tc_field_begin_raw(pq_tc_writer_t *tc, uint8_t type, int16_t field_id)
{
    int16_t delta = field_id - tc->last_field;

    if (delta > 0 && delta <= 15) {
        n00b_writer_write_u8(tc->w, (uint8_t)((delta << 4) | type));
    }
    else {
        n00b_writer_write_u8(tc->w, type);
        pq_tc_write_varint(tc, pq_zigzag_encode_i64(field_id));
    }

    tc->last_field = field_id;
}

static void
pq_tc_i32(pq_tc_writer_t *tc, int16_t field_id, int32_t value)
{
    pq_tc_field_begin_raw(tc, TC_I32, field_id);
    pq_tc_write_varint(tc, pq_zigzag_encode_i64(value));
}

static void
pq_tc_i64(pq_tc_writer_t *tc, int16_t field_id, int64_t value)
{
    pq_tc_field_begin_raw(tc, TC_I64, field_id);
    pq_tc_write_varint(tc, pq_zigzag_encode_i64(value));
}

static void
pq_tc_i16(pq_tc_writer_t *tc, int16_t field_id, int16_t value)
{
    pq_tc_field_begin_raw(tc, TC_I16, field_id);
    pq_tc_write_varint(tc, pq_zigzag_encode_i64(value));
}

static void
pq_tc_i8(pq_tc_writer_t *tc, int16_t field_id, int8_t value)
{
    pq_tc_field_begin_raw(tc, TC_BYTE, field_id);
    n00b_writer_write_i8(tc->w, value);
}

static void
pq_tc_bool(pq_tc_writer_t *tc, int16_t field_id, bool value)
{
    pq_tc_field_begin_raw(tc, value ? TC_BOOL_TRUE : TC_BOOL_FALSE, field_id);
}

static void
pq_tc_binary_bytes(pq_tc_writer_t *tc, const char *data, size_t len)
{
    pq_tc_write_varint(tc, len);
    n00b_writer_write_bytes(tc->w, data, len);
}

static void
pq_tc_string(pq_tc_writer_t *tc, int16_t field_id, const char *value)
{
    pq_tc_field_begin_raw(tc, TC_BINARY, field_id);
    pq_tc_binary_bytes(tc, value, strlen(value));
}

static void
pq_tc_string_n00b(pq_tc_writer_t *tc, int16_t field_id, n00b_string_t *value)
{
    pq_tc_field_begin_raw(tc, TC_BINARY, field_id);
    pq_tc_binary_bytes(tc, value->data, value->u8_bytes);
}

static void
pq_tc_list_header(pq_tc_writer_t *tc, uint8_t elem_type, size_t count)
{
    if (count < 15) {
        n00b_writer_write_u8(tc->w, (uint8_t)((count << 4) | elem_type));
    }
    else {
        n00b_writer_write_u8(tc->w, (uint8_t)(0xf0 | elem_type));
        pq_tc_write_varint(tc, count);
    }
}

static void
pq_write_empty_struct(pq_tc_writer_t *tc)
{
    pq_tc_struct_begin(tc);
    pq_tc_struct_end(tc);
}

static void
pq_write_string_logical_type(pq_tc_writer_t *tc)
{
    pq_tc_field_begin_raw(tc, TC_STRUCT, 10);
    pq_tc_struct_begin(tc);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 1);
    pq_write_empty_struct(tc);
    pq_tc_struct_end(tc);
}

static void
pq_write_int_logical_type(pq_tc_writer_t *tc, bool is_signed)
{
    pq_tc_field_begin_raw(tc, TC_STRUCT, 10);
    pq_tc_struct_begin(tc);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 10);
    pq_tc_struct_begin(tc);
    pq_tc_i8(tc, 1, 64);
    pq_tc_bool(tc, 2, is_signed);
    pq_tc_struct_end(tc);
    pq_tc_struct_end(tc);
}

static void
pq_write_timestamp_logical_type(pq_tc_writer_t *tc)
{
    pq_tc_field_begin_raw(tc, TC_STRUCT, 10);
    pq_tc_struct_begin(tc);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 8);
    pq_tc_struct_begin(tc);
    pq_tc_bool(tc, 1, true);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 2);
    pq_tc_struct_begin(tc);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 2);
    pq_write_empty_struct(tc);
    pq_tc_struct_end(tc);
    pq_tc_struct_end(tc);
    pq_tc_struct_end(tc);
}

static void
pq_write_schema_element(pq_tc_writer_t                  *tc,
                        const n00b_parquet_column_t    *column,
                        bool                            root,
                        size_t                          column_count)
{
    pq_tc_struct_begin(tc);

    if (root) {
        pq_tc_string(tc, 4, "schema");
        pq_tc_i32(tc, 5, (int32_t)column_count);
        pq_tc_struct_end(tc);
        return;
    }

    pq_tc_i32(tc, 1, pq_physical_type(column->type));
    pq_tc_i32(tc, 3, column->nullable ? PQ_REP_OPTIONAL : PQ_REP_REQUIRED);
    pq_tc_string(tc, 4, column->name);

    int converted = pq_converted_type(column->type);
    if (converted >= 0) {
        pq_tc_i32(tc, 6, converted);
    }

    switch (column->type) {
    case N00B_PARQUET_I64:
        pq_write_int_logical_type(tc, true);
        break;
    case N00B_PARQUET_U64:
        pq_write_int_logical_type(tc, false);
        break;
    case N00B_PARQUET_UTF8:
        pq_write_string_logical_type(tc);
        break;
    case N00B_PARQUET_TIMESTAMP_MICROS:
        pq_write_timestamp_logical_type(tc);
        break;
    default:
        break;
    }

    pq_tc_struct_end(tc);
}

static void
pq_write_statistics(pq_tc_writer_t *tc, int64_t null_count)
{
    pq_tc_field_begin_raw(tc, TC_STRUCT, 12);
    pq_tc_struct_begin(tc);
    pq_tc_i64(tc, 3, null_count);
    pq_tc_struct_end(tc);
}

static n00b_buffer_t *
pq_write_page_header(int32_t num_values, int32_t page_size, int64_t null_count)
{
    n00b_writer_t *w = n00b_writer_new(128);
    pq_tc_writer_t tc;

    pq_tc_init(&tc, w);
    pq_tc_struct_begin(&tc);
    pq_tc_i32(&tc, 1, PQ_PAGE_DATA);
    pq_tc_i32(&tc, 2, page_size);
    pq_tc_i32(&tc, 3, page_size);

    pq_tc_field_begin_raw(&tc, TC_STRUCT, 5);
    pq_tc_struct_begin(&tc);
    pq_tc_i32(&tc, 1, num_values);
    pq_tc_i32(&tc, 2, PQ_ENCODING_PLAIN);
    pq_tc_i32(&tc, 3, PQ_ENCODING_RLE);
    pq_tc_i32(&tc, 4, PQ_ENCODING_RLE);
    pq_tc_field_begin_raw(&tc, TC_STRUCT, 5);
    pq_tc_struct_begin(&tc);
    pq_tc_i64(&tc, 3, null_count);
    pq_tc_struct_end(&tc);
    pq_tc_struct_end(&tc);
    pq_tc_struct_end(&tc);

    return n00b_writer_finalize(w);
}

static void
pq_write_column_metadata(pq_tc_writer_t               *tc,
                         const n00b_parquet_column_t *column,
                         pq_column_chunk_info_t      *chunk)
{
    pq_tc_struct_begin(tc);
    pq_tc_i32(tc, 1, pq_physical_type(column->type));

    pq_tc_field_begin_raw(tc, TC_LIST, 2);
    pq_tc_list_header(tc, TC_I32, 2);
    pq_tc_write_varint(tc, pq_zigzag_encode_i64(PQ_ENCODING_PLAIN));
    pq_tc_write_varint(tc, pq_zigzag_encode_i64(PQ_ENCODING_RLE));

    pq_tc_field_begin_raw(tc, TC_LIST, 3);
    pq_tc_list_header(tc, TC_BINARY, 1);
    pq_tc_binary_bytes(tc, column->name, strlen(column->name));

    pq_tc_i32(tc, 4, PQ_CODEC_UNCOMPRESSED);
    pq_tc_i64(tc, 5, chunk->num_values);
    pq_tc_i64(tc, 6, chunk->total_uncompressed_size);
    pq_tc_i64(tc, 7, chunk->total_compressed_size);
    pq_tc_i64(tc, 9, chunk->data_page_offset);
    pq_write_statistics(tc, chunk->null_count);
    pq_tc_struct_end(tc);
}

static void
pq_write_column_chunk(pq_tc_writer_t               *tc,
                      const n00b_parquet_column_t *column,
                      pq_column_chunk_info_t      *chunk)
{
    pq_tc_struct_begin(tc);
    pq_tc_i64(tc, 2, 0);
    pq_tc_field_begin_raw(tc, TC_STRUCT, 3);
    pq_write_column_metadata(tc, column, chunk);
    pq_tc_struct_end(tc);
}

static n00b_buffer_t *
pq_write_footer(n00b_parquet_writer_t   *writer,
                pq_column_chunk_info_t  *chunks,
                int64_t                  row_group_size)
{
    n00b_writer_t *w = n00b_writer_new(512);
    pq_tc_writer_t tc;

    pq_tc_init(&tc, w);
    pq_tc_struct_begin(&tc);
    pq_tc_i32(&tc, 1, 1);

    pq_tc_field_begin_raw(&tc, TC_LIST, 2);
    pq_tc_list_header(&tc, TC_STRUCT, writer->column_count + 1);
    pq_write_schema_element(&tc, nullptr, true, writer->column_count);
    for (size_t i = 0; i < writer->column_count; i++) {
        pq_write_schema_element(&tc, &writer->columns[i].spec, false, 0);
    }

    pq_tc_i64(&tc, 3, (int64_t)writer->row_count);

    pq_tc_field_begin_raw(&tc, TC_LIST, 4);
    pq_tc_list_header(&tc, TC_STRUCT, 1);
    pq_tc_struct_begin(&tc);
    pq_tc_field_begin_raw(&tc, TC_LIST, 1);
    pq_tc_list_header(&tc, TC_STRUCT, writer->column_count);
    for (size_t i = 0; i < writer->column_count; i++) {
        pq_write_column_chunk(&tc, &writer->columns[i].spec, &chunks[i]);
    }
    pq_tc_i64(&tc, 2, row_group_size);
    pq_tc_i64(&tc, 3, (int64_t)writer->row_count);
    pq_tc_i64(&tc, 6, row_group_size);
    pq_tc_i16(&tc, 7, 0);
    pq_tc_struct_end(&tc);

    pq_tc_field_begin_raw(&tc, TC_LIST, 5);
    pq_tc_list_header(&tc, TC_STRUCT, 2);
    pq_tc_struct_begin(&tc);
    pq_tc_string(&tc, 1, "n00b.parquet.subset");
    pq_tc_string(&tc, 2, "flat-v1");
    pq_tc_struct_end(&tc);
    pq_tc_struct_begin(&tc);
    pq_tc_string(&tc, 1, "n00b.parquet.row_groups");
    pq_tc_string(&tc, 2, "1");
    pq_tc_struct_end(&tc);

    pq_tc_string(&tc, 6, "n00b flat parquet writer 0.1");
    pq_tc_struct_end(&tc);

    return n00b_writer_finalize(w);
}

static n00b_buffer_t *
pq_copy_bytes(n00b_buffer_t *src)
{
    if (src == nullptr) {
        return n00b_buffer_from_bytes("", 0);
    }

    return n00b_buffer_from_bytes(src->data, (int64_t)src->byte_len);
}

static void
pq_column_grow(pq_column_data_t *column, size_t need)
{
    if (need <= column->cap) {
        return;
    }

    size_t new_cap = column->cap ? column->cap * 2 : 16;
    while (new_cap < need) {
        new_cap *= 2;
    }

    bool *new_null = n00b_alloc_array(bool, new_cap);
    if (column->is_null) {
        memcpy(new_null, column->is_null, column->len * sizeof(bool));
    }
    column->is_null = new_null;

    switch (column->spec.type) {
    case N00B_PARQUET_BOOL: {
        bool *new_vals = n00b_alloc_array(bool, new_cap);
        if (column->bools) {
            memcpy(new_vals, column->bools, column->len * sizeof(bool));
        }
        column->bools = new_vals;
        break;
    }
    case N00B_PARQUET_I64:
    case N00B_PARQUET_TIMESTAMP_MICROS: {
        int64_t *new_vals = n00b_alloc_array(int64_t, new_cap);
        if (column->i64s) {
            memcpy(new_vals, column->i64s, column->len * sizeof(int64_t));
        }
        column->i64s = new_vals;
        break;
    }
    case N00B_PARQUET_U64: {
        uint64_t *new_vals = n00b_alloc_array(uint64_t, new_cap);
        if (column->u64s) {
            memcpy(new_vals, column->u64s, column->len * sizeof(uint64_t));
        }
        column->u64s = new_vals;
        break;
    }
    case N00B_PARQUET_UTF8:
    case N00B_PARQUET_BINARY: {
        n00b_buffer_t **new_vals = n00b_alloc_array(n00b_buffer_t *, new_cap);
        if (column->bytes) {
            memcpy(new_vals,
                   column->bytes,
                   column->len * sizeof(n00b_buffer_t *));
        }
        column->bytes = new_vals;
        break;
    }
    }

    column->cap = new_cap;
}

static int64_t
pq_column_null_count(pq_column_data_t *column)
{
    int64_t result = 0;

    for (size_t i = 0; i < column->len; i++) {
        if (column->is_null[i]) {
            result++;
        }
    }

    return result;
}

static void
pq_write_definition_levels(n00b_writer_t *body, pq_column_data_t *column)
{
    if (!column->spec.nullable) {
        return;
    }

    n00b_writer_t *levels = n00b_writer_new(64);
    size_t i = 0;

    while (i < column->len) {
        uint8_t level = column->is_null[i] ? 0 : 1;
        size_t  run   = 1;

        while (i + run < column->len) {
            uint8_t next = column->is_null[i + run] ? 0 : 1;
            if (next != level) {
                break;
            }
            run++;
        }

        n00b_writer_write_uleb128(levels, run << 1);
        n00b_writer_write_u8(levels, level);
        i += run;
    }

    n00b_buffer_t *encoded = n00b_writer_finalize(levels);
    n00b_writer_write_u32(body, (uint32_t)encoded->byte_len);
    n00b_writer_write_buffer(body, encoded);
}

static void
pq_write_plain_values(n00b_writer_t *body, pq_column_data_t *column)
{
    switch (column->spec.type) {
    case N00B_PARQUET_BOOL: {
        uint8_t cur = 0;
        int bit = 0;

        for (size_t i = 0; i < column->len; i++) {
            if (column->is_null[i]) {
                continue;
            }

            if (column->bools[i]) {
                cur |= (uint8_t)(1u << bit);
            }

            bit++;
            if (bit == 8) {
                n00b_writer_write_u8(body, cur);
                cur = 0;
                bit = 0;
            }
        }

        if (bit != 0) {
            n00b_writer_write_u8(body, cur);
        }
        break;
    }
    case N00B_PARQUET_I64:
    case N00B_PARQUET_TIMESTAMP_MICROS:
        for (size_t i = 0; i < column->len; i++) {
            if (!column->is_null[i]) {
                n00b_writer_write_i64(body, column->i64s[i]);
            }
        }
        break;
    case N00B_PARQUET_U64:
        for (size_t i = 0; i < column->len; i++) {
            if (!column->is_null[i]) {
                n00b_writer_write_u64(body, column->u64s[i]);
            }
        }
        break;
    case N00B_PARQUET_UTF8:
    case N00B_PARQUET_BINARY:
        for (size_t i = 0; i < column->len; i++) {
            if (!column->is_null[i]) {
                n00b_buffer_t *b = column->bytes[i];
                n00b_writer_write_u32(body, (uint32_t)b->byte_len);
                n00b_writer_write_buffer(body, b);
            }
        }
        break;
    }
}

static n00b_result_t(bool)
pq_write_buffer_to_path(n00b_string_t *path, n00b_buffer_t *buf)
{
#if defined(__linux__)
    long fd = _n00b_raw_linux_syscall4(SYS_openat,
                                       AT_FDCWD,
                                       (long)(uintptr_t)path->data,
                                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                       0666);

    if (fd < 0) {
        return n00b_result_err(bool, (int)-fd);
    }

    size_t off = 0;
    int    err = 0;

    while (off < buf->byte_len) {
        size_t remaining = buf->byte_len - off;
        size_t chunk     = remaining > (size_t)LONG_MAX
                               ? (size_t)LONG_MAX
                               : remaining;
        long   rc        = _n00b_raw_linux_syscall3(
            SYS_write,
            fd,
            (long)(uintptr_t)(buf->data + off),
            (long)chunk);

        if (rc < 0) {
            if (rc == -EINTR) {
                continue;
            }
            err = (int)-rc;
            break;
        }
        if (rc == 0) {
            err = N00B_ERR_PARQUET_IO;
            break;
        }
        off += (size_t)rc;
    }

    long close_rc = _n00b_raw_linux_syscall1(SYS_close, fd);

    if (err != 0) {
        return n00b_result_err(bool, err);
    }
    if (close_rc < 0) {
        return n00b_result_err(bool, (int)-close_rc);
    }

    return n00b_result_ok(bool, true);
#else
    FILE *f = fopen((const char *)path->data, "wb");

    if (!f) {
        return n00b_result_err(bool, errno ? errno : N00B_ERR_PARQUET_IO);
    }

    size_t written = fwrite(buf->data, 1, buf->byte_len, f);
    int close_rc = fclose(f);

    if (written != buf->byte_len || close_rc != 0) {
        return n00b_result_err(bool, errno ? errno : N00B_ERR_PARQUET_IO);
    }

    return n00b_result_ok(bool, true);
#endif
}

n00b_parquet_value_t
n00b_parquet_null(void)
{
    return (n00b_parquet_value_t){.is_null = true};
}

n00b_parquet_value_t
n00b_parquet_bool(bool v)
{
    return (n00b_parquet_value_t){.as.boolean = v};
}

n00b_parquet_value_t
n00b_parquet_i64(int64_t v)
{
    return (n00b_parquet_value_t){.as.i64 = v};
}

n00b_parquet_value_t
n00b_parquet_u64(uint64_t v)
{
    return (n00b_parquet_value_t){.as.u64 = v};
}

n00b_parquet_value_t
n00b_parquet_timestamp_micros(int64_t v)
{
    return (n00b_parquet_value_t){.as.i64 = v};
}

n00b_parquet_value_t
n00b_parquet_utf8(n00b_string_t *v)
{
    if (!v) {
        return n00b_parquet_null();
    }

    return (n00b_parquet_value_t){
        .as.bytes = n00b_buffer_from_bytes(v->data, (int64_t)v->u8_bytes),
    };
}

n00b_parquet_value_t
n00b_parquet_binary(n00b_buffer_t *v)
{
    if (!v) {
        return n00b_parquet_null();
    }

    return (n00b_parquet_value_t){.as.bytes = pq_copy_bytes(v)};
}

n00b_parquet_value_t
n00b_parquet_cstr(const char *v)
{
    if (!v) {
        return n00b_parquet_null();
    }

    return (n00b_parquet_value_t){
        .as.bytes = n00b_buffer_from_bytes((char *)v, (int64_t)strlen(v)),
    };
}

n00b_parquet_writer_t *
n00b_parquet_writer_new(const n00b_parquet_column_t *columns, size_t column_count)
{
    n00b_parquet_writer_t *writer = n00b_alloc(n00b_parquet_writer_t);

    writer->column_count = column_count;
    writer->columns      = n00b_alloc_array(pq_column_data_t, column_count);
    writer->row_count    = 0;
    writer->error        = 0;

    if (column_count == 0 || column_count > INT32_MAX || columns == nullptr) {
        writer->error = N00B_ERR_PARQUET_SCHEMA;
        return writer;
    }

    for (size_t i = 0; i < column_count; i++) {
        if (columns[i].name == nullptr || columns[i].name[0] == '\0'
            || pq_physical_type(columns[i].type) < 0) {
            writer->error = N00B_ERR_PARQUET_SCHEMA;
        }
        writer->columns[i].spec = columns[i];
    }

    return writer;
}

n00b_result_t(bool)
n00b_parquet_writer_add_row(n00b_parquet_writer_t      *writer,
                            const n00b_parquet_value_t *values)
{
    if (!writer || !values) {
        return n00b_result_err(bool, EINVAL);
    }
    if (writer->error) {
        return n00b_result_err(bool, writer->error);
    }
    if (writer->row_count >= INT32_MAX) {
        writer->error = N00B_ERR_PARQUET_UNSUPPORTED;
        return n00b_result_err(bool, writer->error);
    }

    size_t row = writer->row_count;

    for (size_t i = 0; i < writer->column_count; i++) {
        pq_column_data_t *column = &writer->columns[i];
        const n00b_parquet_value_t *value = &values[i];

        if (value->is_null && !column->spec.nullable) {
            writer->error = N00B_ERR_PARQUET_SCHEMA;
            return n00b_result_err(bool, writer->error);
        }

        pq_column_grow(column, row + 1);
        column->is_null[row] = value->is_null;

        if (!value->is_null) {
            switch (column->spec.type) {
            case N00B_PARQUET_BOOL:
                column->bools[row] = value->as.boolean;
                break;
            case N00B_PARQUET_I64:
            case N00B_PARQUET_TIMESTAMP_MICROS:
                column->i64s[row] = value->as.i64;
                break;
            case N00B_PARQUET_U64:
                column->u64s[row] = value->as.u64;
                break;
            case N00B_PARQUET_UTF8:
            case N00B_PARQUET_BINARY:
                column->bytes[row] = pq_copy_bytes(value->as.bytes);
                break;
            }
        }

        column->len = row + 1;
    }

    writer->row_count++;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_parquet_writer_write_file(n00b_parquet_writer_t *writer, n00b_string_t *path)
{
    if (!writer || !path) {
        return n00b_result_err(bool, EINVAL);
    }
    if (writer->error) {
        return n00b_result_err(bool, writer->error);
    }

    n00b_writer_t *file = n00b_writer_new(4096);
    n00b_writer_set_endian(file, N00B_ENDIAN_LITTLE);
    n00b_writer_write_bytes(file, "PAR1", 4);

    pq_column_chunk_info_t *chunks =
        n00b_alloc_array(pq_column_chunk_info_t, writer->column_count);
    int64_t row_group_size = 0;

    for (size_t i = 0; i < writer->column_count; i++) {
        pq_column_data_t *column = &writer->columns[i];
        n00b_writer_t *body = n00b_writer_new(512);
        n00b_writer_set_endian(body, N00B_ENDIAN_LITTLE);

        pq_write_definition_levels(body, column);
        pq_write_plain_values(body, column);

        n00b_buffer_t *body_buf = n00b_writer_finalize(body);
        int64_t null_count = pq_column_null_count(column);
        n00b_buffer_t *header_buf =
            pq_write_page_header((int32_t)writer->row_count,
                                 (int32_t)body_buf->byte_len,
                                 null_count);

        chunks[i].data_page_offset = (int64_t)n00b_writer_pos(file);
        chunks[i].total_uncompressed_size =
            (int64_t)(header_buf->byte_len + body_buf->byte_len);
        chunks[i].total_compressed_size = chunks[i].total_uncompressed_size;
        chunks[i].num_values = (int64_t)writer->row_count;
        chunks[i].null_count = null_count;

        n00b_writer_write_buffer(file, header_buf);
        n00b_writer_write_buffer(file, body_buf);
        row_group_size += chunks[i].total_uncompressed_size;
    }

    n00b_buffer_t *footer = pq_write_footer(writer, chunks, row_group_size);
    n00b_writer_write_buffer(file, footer);
    n00b_writer_write_u32(file, (uint32_t)footer->byte_len);
    n00b_writer_write_bytes(file, "PAR1", 4);

    if (n00b_writer_has_error(file)) {
        return n00b_result_err(bool, N00B_ERR_PARQUET_IO);
    }

    n00b_buffer_t *buf = n00b_writer_finalize(file);
    return pq_write_buffer_to_path(path, buf);
}

static bool
pq_tc_read_varint(pq_tc_reader_t *tc, uint64_t *out)
{
    uint64_t result = 0;
    int shift = 0;

    while (tc->p < tc->end && shift <= 63) {
        uint8_t byte = *tc->p++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) {
            *out = result;
            return true;
        }
        shift += 7;
    }

    tc->error = true;
    return false;
}

static int64_t
pq_tc_read_i64_value(pq_tc_reader_t *tc)
{
    uint64_t raw = 0;

    if (!pq_tc_read_varint(tc, &raw)) {
        return 0;
    }

    return pq_zigzag_decode_i64(raw);
}

static bool
pq_tc_read_binary(pq_tc_reader_t *tc, const uint8_t **data, size_t *len)
{
    uint64_t n = 0;

    if (!pq_tc_read_varint(tc, &n) || (uint64_t)(tc->end - tc->p) < n) {
        tc->error = true;
        return false;
    }

    *data = tc->p;
    *len  = (size_t)n;
    tc->p += n;
    return true;
}

static void
pq_tc_reader_struct_begin(pq_tc_reader_t *tc)
{
    tc->stack[tc->depth++] = tc->last_field;
    tc->last_field         = 0;
}

static void
pq_tc_reader_struct_end(pq_tc_reader_t *tc)
{
    tc->last_field = tc->stack[--tc->depth];
}

static pq_tc_field_t
pq_tc_next_field(pq_tc_reader_t *tc)
{
    pq_tc_field_t result = {.type = TC_STOP, .id = 0};

    if (tc->p >= tc->end) {
        tc->error = true;
        return result;
    }

    uint8_t header = *tc->p++;
    result.type = header & 0x0f;

    if (result.type == TC_STOP) {
        return result;
    }

    int16_t delta = (int16_t)(header >> 4);
    if (delta != 0) {
        result.id = tc->last_field + delta;
    }
    else {
        result.id = (int16_t)pq_tc_read_i64_value(tc);
    }

    tc->last_field = result.id;
    return result;
}

static bool
pq_tc_read_list_header(pq_tc_reader_t *tc, uint8_t *elem_type, size_t *count)
{
    if (tc->p >= tc->end) {
        tc->error = true;
        return false;
    }

    uint8_t header = *tc->p++;
    *elem_type = header & 0x0f;
    *count = header >> 4;

    if (*count == 15) {
        uint64_t n = 0;
        if (!pq_tc_read_varint(tc, &n)) {
            return false;
        }
        *count = (size_t)n;
    }

    return true;
}

static void pq_tc_skip_value(pq_tc_reader_t *tc, uint8_t type);

static void
pq_tc_skip_struct(pq_tc_reader_t *tc)
{
    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }
        pq_tc_skip_value(tc, field.type);
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_tc_skip_value(pq_tc_reader_t *tc, uint8_t type)
{
    switch (type) {
    case TC_BOOL_TRUE:
    case TC_BOOL_FALSE:
        return;
    case TC_BYTE:
        if (tc->p >= tc->end) {
            tc->error = true;
        }
        else {
            tc->p++;
        }
        return;
    case TC_I16:
    case TC_I32:
    case TC_I64:
        (void)pq_tc_read_i64_value(tc);
        return;
    case TC_DOUBLE:
        if ((size_t)(tc->end - tc->p) < 8) {
            tc->error = true;
        }
        else {
            tc->p += 8;
        }
        return;
    case TC_BINARY: {
        const uint8_t *data = nullptr;
        size_t len = 0;
        (void)pq_tc_read_binary(tc, &data, &len);
        return;
    }
    case TC_STRUCT:
        pq_tc_skip_struct(tc);
        return;
    case TC_LIST:
    case TC_SET: {
        uint8_t elem_type = 0;
        size_t count = 0;
        if (!pq_tc_read_list_header(tc, &elem_type, &count)) {
            return;
        }
        for (size_t i = 0; i < count && !tc->error; i++) {
            pq_tc_skip_value(tc, elem_type);
        }
        return;
    }
    default:
        tc->error = true;
        return;
    }
}

static n00b_string_t *
pq_tc_read_string_value(pq_tc_reader_t *tc)
{
    const uint8_t *data = nullptr;
    size_t len = 0;

    if (!pq_tc_read_binary(tc, &data, &len)) {
        return nullptr;
    }

    return n00b_string_from_raw((const char *)data, (int64_t)len);
}

static void
pq_parse_statistics(pq_tc_reader_t *tc, int64_t *null_count)
{
    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        if (field.id == 3 && field.type == TC_I64) {
            *null_count = pq_tc_read_i64_value(tc);
        }
        else {
            pq_tc_skip_value(tc, field.type);
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_schema_element(pq_tc_reader_t *tc, pq_schema_meta_t *schema)
{
    schema->physical_type   = -1;
    schema->repetition_type = -1;
    schema->converted_type  = -1;
    schema->name            = nullptr;

    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        switch (field.id) {
        case 1:
            schema->physical_type = (int)pq_tc_read_i64_value(tc);
            break;
        case 3:
            schema->repetition_type = (int)pq_tc_read_i64_value(tc);
            break;
        case 4:
            schema->name = pq_tc_read_string_value(tc);
            break;
        case 6:
            schema->converted_type = (int)pq_tc_read_i64_value(tc);
            break;
        default:
            pq_tc_skip_value(tc, field.type);
            break;
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_column_metadata(pq_tc_reader_t *tc, pq_file_column_meta_t *column)
{
    column->physical_type          = -1;
    column->data_page_offset       = -1;
    column->total_compressed_size  = -1;
    column->num_values             = -1;
    column->null_count             = -1;

    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        switch (field.id) {
        case 1:
            column->physical_type = (int)pq_tc_read_i64_value(tc);
            break;
        case 5:
            column->num_values = pq_tc_read_i64_value(tc);
            break;
        case 7:
            column->total_compressed_size = pq_tc_read_i64_value(tc);
            break;
        case 9:
            column->data_page_offset = pq_tc_read_i64_value(tc);
            break;
        case 12:
            pq_parse_statistics(tc, &column->null_count);
            break;
        default:
            pq_tc_skip_value(tc, field.type);
            break;
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_column_chunk(pq_tc_reader_t *tc, pq_file_column_meta_t *column)
{
    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        if (field.id == 3 && field.type == TC_STRUCT) {
            pq_parse_column_metadata(tc, column);
        }
        else {
            pq_tc_skip_value(tc, field.type);
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_row_group(pq_tc_reader_t *tc, pq_file_meta_t *meta)
{
    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        if (field.id == 1 && field.type == TC_LIST) {
            uint8_t elem_type = 0;
            size_t count = 0;
            if (!pq_tc_read_list_header(tc, &elem_type, &count)
                || elem_type != TC_STRUCT) {
                tc->error = true;
                break;
            }
            meta->column_count = count;
            meta->columns = n00b_alloc_array(pq_file_column_meta_t, count);
            for (size_t i = 0; i < count; i++) {
                pq_parse_column_chunk(tc, &meta->columns[i]);
            }
        }
        else if (field.id == 3 && field.type == TC_I64) {
            meta->num_rows = pq_tc_read_i64_value(tc);
        }
        else {
            pq_tc_skip_value(tc, field.type);
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_file_metadata(pq_tc_reader_t *tc, pq_file_meta_t *meta)
{
    meta->schema       = nullptr;
    meta->schema_count = 0;
    meta->columns      = nullptr;
    meta->column_count = 0;
    meta->num_rows     = -1;

    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        if (field.id == 2 && field.type == TC_LIST) {
            uint8_t elem_type = 0;
            size_t count = 0;
            if (!pq_tc_read_list_header(tc, &elem_type, &count)
                || elem_type != TC_STRUCT) {
                tc->error = true;
                break;
            }
            meta->schema_count = count;
            meta->schema = n00b_alloc_array(pq_schema_meta_t, count);
            for (size_t i = 0; i < count; i++) {
                pq_parse_schema_element(tc, &meta->schema[i]);
            }
        }
        else if (field.id == 3 && field.type == TC_I64) {
            meta->num_rows = pq_tc_read_i64_value(tc);
        }
        else if (field.id == 4 && field.type == TC_LIST) {
            uint8_t elem_type = 0;
            size_t count = 0;
            if (!pq_tc_read_list_header(tc, &elem_type, &count)
                || elem_type != TC_STRUCT || count != 1) {
                tc->error = true;
                break;
            }
            pq_parse_row_group(tc, meta);
        }
        else {
            pq_tc_skip_value(tc, field.type);
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_data_page_header(pq_tc_reader_t *tc, int32_t *num_values)
{
    pq_tc_reader_struct_begin(tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(tc);
        if (tc->error || field.type == TC_STOP) {
            break;
        }

        if (field.id == 1 && field.type == TC_I32) {
            *num_values = (int32_t)pq_tc_read_i64_value(tc);
        }
        else {
            pq_tc_skip_value(tc, field.type);
        }
    }

    pq_tc_reader_struct_end(tc);
}

static void
pq_parse_page_header(const uint8_t *start,
                     const uint8_t *end,
                     pq_page_meta_t *page)
{
    pq_tc_reader_t tc = {
        .p          = start,
        .end        = end,
        .last_field = 0,
    };

    page->page_type              = -1;
    page->compressed_page_size   = -1;
    page->uncompressed_page_size = -1;
    page->num_values             = -1;
    page->header_size            = 0;

    pq_tc_reader_struct_begin(&tc);

    for (;;) {
        pq_tc_field_t field = pq_tc_next_field(&tc);
        if (tc.error || field.type == TC_STOP) {
            break;
        }

        switch (field.id) {
        case 1:
            page->page_type = (int)pq_tc_read_i64_value(&tc);
            break;
        case 2:
            page->uncompressed_page_size = (int32_t)pq_tc_read_i64_value(&tc);
            break;
        case 3:
            page->compressed_page_size = (int32_t)pq_tc_read_i64_value(&tc);
            break;
        case 5:
            pq_parse_data_page_header(&tc, &page->num_values);
            break;
        default:
            pq_tc_skip_value(&tc, field.type);
            break;
        }
    }

    pq_tc_reader_struct_end(&tc);
    if (tc.error) {
        page->page_type = -1;
    }
    else {
        page->header_size = (size_t)(tc.p - start);
    }
}

static n00b_result_t(n00b_buffer_t *)
pq_read_path(n00b_string_t *path)
{
    FILE *f = fopen((const char *)path->data, "rb");

    if (!f) {
        return n00b_result_err(n00b_buffer_t *, errno ? errno : N00B_ERR_PARQUET_IO);
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        int e = errno ? errno : N00B_ERR_PARQUET_IO;
        fclose(f);
        return n00b_result_err(n00b_buffer_t *, e);
    }

    long file_size = ftell(f);
    if (file_size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        int e = errno ? errno : N00B_ERR_PARQUET_IO;
        fclose(f);
        return n00b_result_err(n00b_buffer_t *, e);
    }

    n00b_buffer_t *buf = n00b_buffer_new(file_size);
    size_t n = fread(buf->data, 1, (size_t)file_size, f);
    int close_rc = fclose(f);

    if (n != (size_t)file_size || close_rc != 0) {
        return n00b_result_err(n00b_buffer_t *,
                               errno ? errno : N00B_ERR_PARQUET_IO);
    }

    buf->byte_len = (size_t)file_size;
    return n00b_result_ok(n00b_buffer_t *, buf);
}

static bool
pq_name_eq(n00b_string_t *actual, const char *expected)
{
    size_t len = strlen(expected);

    return actual != nullptr
        && actual->u8_bytes == len
        && memcmp(actual->data, expected, len) == 0;
}

static bool
pq_schema_matches(pq_file_meta_t                 *meta,
                  const n00b_parquet_column_t   *expected,
                  size_t                         expected_count)
{
    if (meta->schema_count != expected_count + 1
        || meta->column_count != expected_count) {
        return false;
    }

    for (size_t i = 0; i < expected_count; i++) {
        pq_schema_meta_t *actual = &meta->schema[i + 1];
        int expected_rep = expected[i].nullable ? PQ_REP_OPTIONAL : PQ_REP_REQUIRED;

        if (!pq_name_eq(actual->name, expected[i].name)
            || actual->physical_type != pq_physical_type(expected[i].type)
            || actual->repetition_type != expected_rep
            || actual->converted_type != pq_converted_type(expected[i].type)) {
            return false;
        }
    }

    return true;
}

static bool
pq_decode_uleb(const uint8_t **p, const uint8_t *end, uint64_t *out)
{
    uint64_t result = 0;
    int shift = 0;

    while (*p < end && shift <= 63) {
        uint8_t byte = *(*p)++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) {
            *out = result;
            return true;
        }
        shift += 7;
    }

    return false;
}

static bool
pq_decode_definition_levels(const uint8_t **p,
                            const uint8_t  *end,
                            bool            nullable,
                            bool           *is_null,
                            size_t          row_count)
{
    if (!nullable) {
        for (size_t i = 0; i < row_count; i++) {
            is_null[i] = false;
        }
        return true;
    }

    if ((size_t)(end - *p) < 4) {
        return false;
    }

    uint32_t len = pq_u32_from_le(*p);
    *p += 4;
    if ((size_t)(end - *p) < len) {
        return false;
    }

    const uint8_t *levels = *p;
    const uint8_t *levels_end = levels + len;
    size_t out_i = 0;

    while (levels < levels_end && out_i < row_count) {
        uint64_t header = 0;
        if (!pq_decode_uleb(&levels, levels_end, &header)) {
            return false;
        }
        if (header & 1) {
            return false;
        }

        size_t run = (size_t)(header >> 1);
        if (levels >= levels_end || out_i + run > row_count) {
            return false;
        }
        uint8_t level = *levels++;
        for (size_t i = 0; i < run; i++) {
            is_null[out_i++] = (level == 0);
        }
    }

    *p = levels_end;
    return out_i == row_count;
}

static bool
pq_decode_column_values(const uint8_t                  *p,
                        const uint8_t                  *end,
                        n00b_parquet_table_t           *table,
                        size_t                          column_index,
                        bool                           *is_null)
{
    size_t row_count = table->row_count;
    size_t col_count = table->column_count;
    n00b_parquet_column_type_t type = table->columns[column_index].type;
    size_t bool_index = 0;

    for (size_t row = 0; row < row_count; row++) {
        n00b_parquet_value_t *value =
            &table->values[row * col_count + column_index];

        value->is_null = is_null[row];
        if (is_null[row]) {
            continue;
        }

        switch (type) {
        case N00B_PARQUET_BOOL:
            if ((size_t)(end - p) < (bool_index / 8) + 1) {
                return false;
            }
            value->as.boolean = (p[bool_index / 8] & (1u << (bool_index % 8))) != 0;
            bool_index++;
            break;
        case N00B_PARQUET_I64:
        case N00B_PARQUET_TIMESTAMP_MICROS:
            if ((size_t)(end - p) < 8) {
                return false;
            }
            value->as.i64 = (int64_t)pq_u64_from_le(p);
            p += 8;
            break;
        case N00B_PARQUET_U64:
            if ((size_t)(end - p) < 8) {
                return false;
            }
            value->as.u64 = pq_u64_from_le(p);
            p += 8;
            break;
        case N00B_PARQUET_UTF8:
        case N00B_PARQUET_BINARY: {
            if ((size_t)(end - p) < 4) {
                return false;
            }
            uint32_t len = pq_u32_from_le(p);
            p += 4;
            if ((size_t)(end - p) < len) {
                return false;
            }
            value->as.bytes = n00b_buffer_from_bytes((char *)p, (int64_t)len);
            p += len;
            break;
        }
        }
    }

    return true;
}

static bool
pq_decode_column(n00b_buffer_t                 *file,
                 pq_file_column_meta_t        *column_meta,
                 n00b_parquet_table_t         *table,
                 size_t                        column_index)
{
    if (column_meta->data_page_offset < 4
        || column_meta->data_page_offset >= (int64_t)file->byte_len) {
        return false;
    }

    const uint8_t *start = (const uint8_t *)file->data + column_meta->data_page_offset;
    const uint8_t *end = (const uint8_t *)file->data + file->byte_len;
    pq_page_meta_t page;

    pq_parse_page_header(start, end, &page);
    if (page.page_type != PQ_PAGE_DATA
        || page.compressed_page_size < 0
        || page.num_values != (int32_t)table->row_count) {
        return false;
    }

    const uint8_t *body = start + page.header_size;
    if ((size_t)(end - body) < (size_t)page.compressed_page_size) {
        return false;
    }

    const uint8_t *body_end = body + page.compressed_page_size;
    bool *is_null = n00b_alloc_array(bool, table->row_count);

    if (!pq_decode_definition_levels(&body,
                                     body_end,
                                     table->columns[column_index].nullable,
                                     is_null,
                                     table->row_count)) {
        return false;
    }

    return pq_decode_column_values(body, body_end, table, column_index, is_null);
}

n00b_result_t(n00b_parquet_table_t *)
n00b_parquet_read_file(n00b_string_t               *path,
                       const n00b_parquet_column_t *expected_columns,
                       size_t                       expected_column_count)
{
    auto rr = pq_read_path(path);
    if (n00b_result_is_err(rr)) {
        return n00b_result_err(n00b_parquet_table_t *, n00b_result_get_err(rr));
    }

    n00b_buffer_t *file = n00b_result_get(rr);
    if (file->byte_len < 12
        || memcmp(file->data, "PAR1", 4) != 0
        || memcmp(file->data + file->byte_len - 4, "PAR1", 4) != 0) {
        return n00b_result_err(n00b_parquet_table_t *, N00B_ERR_PARQUET_FORMAT);
    }

    uint32_t footer_len =
        pq_u32_from_le((const uint8_t *)file->data + file->byte_len - 8);
    if (footer_len > file->byte_len - 12) {
        return n00b_result_err(n00b_parquet_table_t *, N00B_ERR_PARQUET_FORMAT);
    }

    const uint8_t *footer =
        (const uint8_t *)file->data + file->byte_len - 8 - footer_len;
    pq_tc_reader_t tc = {
        .p          = footer,
        .end        = footer + footer_len,
        .last_field = 0,
    };
    pq_file_meta_t meta;

    pq_parse_file_metadata(&tc, &meta);
    if (tc.error || !pq_schema_matches(&meta,
                                       expected_columns,
                                       expected_column_count)
        || meta.num_rows < 0) {
        return n00b_result_err(n00b_parquet_table_t *, N00B_ERR_PARQUET_SCHEMA);
    }

    n00b_parquet_table_t *table = n00b_alloc(n00b_parquet_table_t);
    table->column_count = expected_column_count;
    table->row_count    = (size_t)meta.num_rows;
    table->columns      = n00b_alloc_array(n00b_parquet_column_t,
                                           expected_column_count);
    table->values       = n00b_alloc_array(n00b_parquet_value_t,
                                           table->row_count * table->column_count);

    memcpy(table->columns,
           expected_columns,
           expected_column_count * sizeof(n00b_parquet_column_t));

    for (size_t i = 0; i < table->column_count; i++) {
        if (!pq_decode_column(file, &meta.columns[i], table, i)) {
            return n00b_result_err(n00b_parquet_table_t *,
                                   N00B_ERR_PARQUET_FORMAT);
        }
    }

    return n00b_result_ok(n00b_parquet_table_t *, table);
}

size_t
n00b_parquet_writer_row_count(n00b_parquet_writer_t *writer)
{
    return writer ? writer->row_count : 0;
}

int
n00b_parquet_writer_error(n00b_parquet_writer_t *writer)
{
    return writer ? writer->error : EINVAL;
}

size_t
n00b_parquet_table_row_count(n00b_parquet_table_t *table)
{
    return table ? table->row_count : 0;
}

size_t
n00b_parquet_table_column_count(n00b_parquet_table_t *table)
{
    return table ? table->column_count : 0;
}

const n00b_parquet_value_t *
n00b_parquet_table_value(n00b_parquet_table_t *table, size_t row, size_t column)
{
    if (!table || row >= table->row_count || column >= table->column_count) {
        return nullptr;
    }

    return &table->values[row * table->column_count + column];
}
