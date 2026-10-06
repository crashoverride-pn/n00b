// Every buffer mutator over every kind of buffer storage, checked against a
// byte model and the ownership invariants: a mutation leaves the buffer owning
// heap data that is never scanned, and whatever it aliased is left alone.
//
// Pass "<kind>/<op>" to run one cell.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/file_map.h"
#include "util/path.h"
#include "test_scan_kind.h"

#define ORIG     "0123456789ab"
#define ORIG_LEN 12
#define TAIL     "PARENT"

typedef enum {
    K_HEAP,            // spare capacity, owned
    K_HEAP_EXACT,      // .ptr ownership transfer, alloc_len == byte_len
    K_NO_LOCK,         // .no_lock
    K_MAP_RO,          // n00b_file_mmap, read-only
    K_MAP_RW,          // n00b_file_mmap(.writable)
    K_BORROWED_SLICE,  // n00b_file_read on an MMAP file, alloc_len 0
    K_BORROWED_SPARE,  // borrowed with spare capacity, the baked-image shape
    K_COUNT,
} kind_t;

static const char *kind_names[K_COUNT] = {
    "heap", "heap_exact", "no_lock", "map_ro", "map_rw", "borrowed_slice",
    "borrowed_spare",
};

typedef enum {
    OP_RESIZE_GROW,
    OP_RESIZE_SAME,
    OP_RESIZE_SHRINK,
    OP_RESIZE_ZERO,
    OP_APPEND,
    OP_APPEND_UINT,
    OP_CONCAT,
    OP_CONCAT_FRONT,
    OP_SET_SLICE_GROW,
    OP_SET_SLICE_SAME,
    OP_SET_SLICE_SHRINK,
    OP_SET_SLICE_DELETE,
    OP_SET_INDEX,
    OP_SET_INDEX_NEG,
    OP_APPEND_NOTHING,
    OP_CONCAT_EMPTY,
    OP_COUNT,
} op_t;

static const char *op_names[OP_COUNT] = {
    "resize_grow", "resize_same", "resize_shrink", "resize_zero", "append",
    "append_uint", "concat", "concat_front", "set_slice_grow", "set_slice_same",
    "set_slice_shrink", "set_slice_delete", "set_index", "set_index_neg",
    "append_nothing", "concat_empty",
};

static kind_t cur_kind;
static op_t   cur_op;

#define CELL_CHECK(expr)                                                       \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr,                                                    \
                    "cell %s/%s: check failed at line %d: %s\n",               \
                    kind_names[cur_kind],                                      \
                    op_names[cur_op],                                          \
                    __LINE__,                                                  \
                    #expr);                                                    \
            abort();                                                           \
        }                                                                      \
    } while (0)

typedef struct {
    n00b_buffer_t *buf;
    n00b_string_t *path;      // backing file, if any
    n00b_file_t   *file;      // open file a slice borrows from
    const char    *source;    // bytes the aliased storage must still hold
    size_t         source_len;
    char          *aliased;   // storage the buffer aliases, if it is not the file
} cell_t;

static n00b_string_t *
temp_file(const char *contents, size_t n)
{
    n00b_string_t *p = nullptr;
    for (int i = 0; i < 64 && p == nullptr; i++) {
        p = n00b_new_temp_path(n00b_string_from_cstr("n00b_buffer_mutators_"),
                               n00b_string_from_cstr(".tmp"));
        if (n00b_path_exists(p)) {
            p = nullptr;
        }
    }
    CELL_CHECK(p != nullptr);

    auto open_r = n00b_file_open(p, .mode = N00B_FILE_W);
    CELL_CHECK(n00b_result_is_ok(open_r));
    n00b_file_t *f = n00b_result_get(open_r);
    CELL_CHECK(n00b_result_is_ok(
        n00b_file_write_all(f, n00b_buffer_from_bytes((char *)contents, (int64_t)n))));
    CELL_CHECK(n00b_result_is_ok(n00b_file_close_result(f)));
    return p;
}

static bool
file_holds(n00b_string_t *p, const char *bytes, size_t n)
{
    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_STREAM);
    CELL_CHECK(n00b_result_is_ok(fr));
    n00b_file_t *f  = n00b_result_get(fr);
    auto         rr = n00b_file_read(f, 4096);
    CELL_CHECK(n00b_result_is_ok(rr));
    n00b_buffer_t *got = n00b_result_get(rr);
    bool           ok  = n00b_buffer_len(got) == (int64_t)n && memcmp(got->data, bytes, n) == 0;
    CELL_CHECK(n00b_result_is_ok(n00b_file_close_result(f)));
    return ok;
}

static cell_t
make_cell(kind_t kind)
{
    cell_t c = {0};

    switch (kind) {
    case K_HEAP:
        c.buf = n00b_buffer_from_bytes(ORIG, ORIG_LEN);
        break;
    case K_HEAP_EXACT: {
        char *owned = n00b_alloc_array_with_opts(char,
                                                 ORIG_LEN,
                                                 &(n00b_alloc_opts_t){
                                                     .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                                 });
        memcpy(owned, ORIG, ORIG_LEN);
        c.buf = n00b_alloc(n00b_buffer_t);
        n00b_buffer_init(c.buf, .ptr = owned, .length = ORIG_LEN);
        break;
    }
    case K_NO_LOCK:
        c.buf = n00b_alloc(n00b_buffer_t);
        n00b_buffer_init(c.buf, .raw = ORIG, .length = ORIG_LEN, .no_lock = true);
        break;
    case K_MAP_RO:
    case K_MAP_RW: {
        c.path       = temp_file(ORIG, ORIG_LEN);
        c.source     = ORIG;
        c.source_len = ORIG_LEN;
        auto br      = n00b_file_mmap(c.path, .writable = kind == K_MAP_RW);
        CELL_CHECK(n00b_result_is_ok(br));
        c.buf = n00b_result_get(br);
        CELL_CHECK(c.buf->flags & N00B_BUF_F_MMAP);
        break;
    }
    case K_BORROWED_SLICE: {
        c.path       = temp_file(ORIG TAIL, ORIG_LEN + strlen(TAIL));
        c.source     = ORIG TAIL;
        c.source_len = ORIG_LEN + strlen(TAIL);
        auto fr      = n00b_file_open(c.path, .kind = N00B_FILE_KIND_MMAP);
        CELL_CHECK(n00b_result_is_ok(fr));
        c.file  = n00b_result_get(fr);
        auto rr = n00b_file_read(c.file, ORIG_LEN);
        CELL_CHECK(n00b_result_is_ok(rr));
        c.buf = n00b_result_get(rr);
        CELL_CHECK(c.buf->flags & N00B_BUF_F_BORROWED);
        c.aliased = n00b_result_get(n00b_file_as_buffer(c.file))->data;
        break;
    }
    case K_BORROWED_SPARE:
        // n00b_buffer_init(.raw) allocates 16 zeroed bytes for 12.
        c.buf = n00b_alloc(n00b_buffer_t);
        n00b_buffer_init(c.buf, .raw = ORIG, .length = ORIG_LEN);
        c.buf->flags = N00B_BUF_F_BORROWED;
        CELL_CHECK(c.buf->alloc_len > (int64_t)ORIG_LEN);
        c.aliased    = c.buf->data;
        c.source     = ORIG "\0\0\0\0";
        c.source_len = 16;
        break;
    default:
        CELL_CHECK(false);
    }

    CELL_CHECK(n00b_buffer_len(c.buf) == ORIG_LEN);
    CELL_CHECK(memcmp(c.buf->data, ORIG, ORIG_LEN) == 0);
    CELL_CHECK(c.buf->scan_kind == N00B_GC_SCAN_KIND_NONE);
    return c;
}

// Apply op and write the bytes it must leave into expect. Returns the
// expected length; *cmp_len is how many leading bytes are defined.
static size_t
apply_op(n00b_buffer_t *buf, op_t op, char *expect, size_t *cmp_len)
{
    size_t len = ORIG_LEN;
    memcpy(expect, ORIG, ORIG_LEN);

    switch (op) {
    case OP_RESIZE_GROW:
        n00b_buffer_resize(buf, ORIG_LEN + 3);
        *cmp_len = ORIG_LEN;
        return ORIG_LEN + 3;
    case OP_RESIZE_SAME:
        n00b_buffer_resize(buf, ORIG_LEN);
        break;
    case OP_RESIZE_SHRINK:
        n00b_buffer_resize(buf, 5);
        len = 5;
        break;
    case OP_RESIZE_ZERO:
        n00b_buffer_resize(buf, 0);
        len = 0;
        break;
    case OP_APPEND:
        n00b_buffer_append_bytes(buf, "xyz", 3);
        memcpy(expect + len, "xyz", 3);
        len += 3;
        break;
    case OP_APPEND_UINT:
        n00b_buffer_append_uint(buf, 42);
        memcpy(expect + len, "42", 2);
        len += 2;
        break;
    case OP_CONCAT:
        n00b_buffer_concat(buf, n00b_buffer_from_cstr("xyz"));
        memcpy(expect + len, "xyz", 3);
        len += 3;
        break;
    case OP_CONCAT_FRONT:
        n00b_buffer_concat(buf, n00b_buffer_from_cstr("xyz"), .to_front = true);
        memcpy(expect, "xyz" ORIG, ORIG_LEN + 3);
        len += 3;
        break;
    case OP_SET_SLICE_GROW:
        CELL_CHECK(n00b_result_is_ok(
            n00b_buffer_set_slice(buf, 1, 2, .val = n00b_buffer_from_cstr("xyz"))));
        memcpy(expect, "0xyz23456789ab", 14);
        len = 14;
        break;
    case OP_SET_SLICE_SAME:
        CELL_CHECK(n00b_result_is_ok(
            n00b_buffer_set_slice(buf, 1, 2, .val = n00b_buffer_from_cstr("x"))));
        expect[1] = 'x';
        break;
    case OP_SET_SLICE_SHRINK:
        CELL_CHECK(n00b_result_is_ok(
            n00b_buffer_set_slice(buf, 1, 4, .val = n00b_buffer_from_cstr("x"))));
        memcpy(expect, "0x456789ab", 10);
        len = 10;
        break;
    case OP_SET_SLICE_DELETE:
        CELL_CHECK(n00b_result_is_ok(n00b_buffer_set_slice(buf, 0, ORIG_LEN)));
        len = 0;
        break;
    case OP_SET_INDEX:
        CELL_CHECK(n00b_result_is_ok(n00b_buffer_set_index(buf, 1, 'x')));
        expect[1] = 'x';
        break;
    case OP_SET_INDEX_NEG:
        CELL_CHECK(n00b_result_is_ok(n00b_buffer_set_index(buf, -1, 'x')));
        expect[ORIG_LEN - 1] = 'x';
        break;
    case OP_APPEND_NOTHING:
        n00b_buffer_append_bytes(buf, "", 0);
        break;
    case OP_CONCAT_EMPTY:
        n00b_buffer_concat(buf, n00b_buffer_from_bytes("", 0));
        break;
    default:
        CELL_CHECK(false);
    }

    *cmp_len = len;
    return len;
}

static bool
op_is_noop(op_t op)
{
    return op == OP_APPEND_NOTHING || op == OP_CONCAT_EMPTY;
}

static void
run_cell(kind_t kind, op_t op)
{
    cur_kind = kind;
    cur_op   = op;

    cell_t   c         = make_cell(kind);
    char    *old_data  = c.buf->data;
    uint32_t old_flags = c.buf->flags;

    char   expect[32];
    size_t cmp_len = 0;
    size_t len     = apply_op(c.buf, op, expect, &cmp_len);

    CELL_CHECK(n00b_buffer_len(c.buf) == (int64_t)len);
    CELL_CHECK(memcmp(c.buf->data, expect, cmp_len) == 0);
    CELL_CHECK(c.buf->scan_kind == N00B_GC_SCAN_KIND_NONE);

    if (op_is_noop(op)) {
        CELL_CHECK(c.buf->data == old_data);
        CELL_CHECK(c.buf->flags == old_flags);
    }
    else {
        CELL_CHECK(!(c.buf->flags & (N00B_BUF_F_MMAP | N00B_BUF_F_BORROWED)));
        CELL_CHECK(c.buf->alloc_len >= (int64_t)c.buf->byte_len);
        CELL_CHECK(alloc_is_no_scan(c.buf->data));
        if (c.aliased != nullptr || (old_flags & N00B_BUF_F_MMAP)) {
            CELL_CHECK(c.buf->data != old_data);
        }
#ifndef _WIN32
        if (old_flags & N00B_BUF_F_MMAP) {
            errno = 0;
            CELL_CHECK(msync(old_data, ORIG_LEN, MS_ASYNC) == -1 && errno == ENOMEM);
        }
#endif
    }

    if (c.aliased != nullptr) {
        CELL_CHECK(memcmp(c.aliased, c.source, c.source_len) == 0);
    }

    n00b_buffer_free(c.buf);
    if (c.file != nullptr) {
        n00b_file_close(c.file);
    }
    if (c.path != nullptr) {
        CELL_CHECK(file_holds(c.path, c.source, c.source_len));
        (void)n00b_file_unlink(c.path, .ignore_missing = true);
    }
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    const char *only  = argc > 1 ? argv[1] : nullptr;
    int         cells = 0;

    for (int k = 0; k < K_COUNT; k++) {
        for (int o = 0; o < OP_COUNT; o++) {
            char name[64];
            snprintf(name, sizeof(name), "%s/%s", kind_names[k], op_names[o]);
            if (only != nullptr && strcmp(only, name) != 0) {
                continue;
            }
            run_cell((kind_t)k, (op_t)o);
            cells++;
        }
    }

    if (cells == 0) {
        fprintf(stderr, "no cell named %s\n", only);
        return 1;
    }
    printf("  [PASS] %d buffer mutator cells\n", cells);
    n00b_shutdown();
    return 0;
}
