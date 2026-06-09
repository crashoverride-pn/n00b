
#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/parse_num.h"
#include "vfs/backend_s3.h"

#define FAKE_S3_MAX_OBJECTS 32

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

typedef struct {
    n00b_string_t *bucket;
    n00b_string_t *key;
    n00b_buffer_t *data;
    n00b_string_t *etag;
    n00b_string_t *content_type;
    uint64_t       mtime_ns;
} fake_s3_object_t;

typedef struct {
    fake_s3_object_t *objects[FAKE_S3_MAX_OBJECTS];
    uint32_t          count;
    uint64_t          clock;
    uint32_t          multipart_puts;
    uint64_t          last_part_size;
    n00b_string_t    *last_key;
    n00b_allocator_t *allocator;
} fake_s3_t;

static bool
str_eq(n00b_string_t *a, n00b_string_t *b)
{
    return n00b_unicode_str_eq(a, b);
}

static bool
str_eq_c(n00b_string_t *s, const char *c)
{
    if (c == nullptr) {
        return false;
    }
    return n00b_unicode_str_eq(s, n00b_string_from_cstr(c));
}

static bool
prefix_matches(n00b_string_t *s, n00b_string_t *prefix)
{
    if (s == nullptr || s->data == nullptr) {
        return false;
    }
    if (prefix == nullptr || prefix->data == nullptr || prefix->u8_bytes == 0) {
        return true;
    }
    if (s->u8_bytes < prefix->u8_bytes) {
        return false;
    }
    for (size_t i = 0; i < prefix->u8_bytes; i++) {
        if (s->data[i] != prefix->data[i]) {
            return false;
        }
    }
    return true;
}

static n00b_string_t *
clone_string(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s == nullptr || s->data == nullptr) {
        return n00b_string_from_cstr("", .allocator = allocator);
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static fake_s3_object_t *
find_object(fake_s3_t *fake, n00b_string_t *bucket, n00b_string_t *key)
{
    for (uint32_t i = 0; i < fake->count; i++) {
        fake_s3_object_t *obj = fake->objects[i];
        if (obj != nullptr && str_eq(obj->bucket, bucket)
            && str_eq(obj->key, key)) {
            return obj;
        }
    }
    return nullptr;
}

static n00b_result_t(bool)
fake_store(fake_s3_t *fake, n00b_string_t *bucket, n00b_string_t *key,
           n00b_buffer_t *data, n00b_string_t *content_type)
{
    fake_s3_object_t *obj = find_object(fake, bucket, key);
    if (obj == nullptr) {
        if (fake->count == FAKE_S3_MAX_OBJECTS) {
            return n00b_result_err(bool, N00B_VFS_ERR_NO_SPACE);
        }
        obj = n00b_alloc(fake_s3_object_t, .allocator = fake->allocator);
        obj->bucket = clone_string(bucket, fake->allocator);
        obj->key    = clone_string(key, fake->allocator);
        fake->objects[fake->count++] = obj;
    }

    obj->data         = n00b_buffer_copy(data, .allocator = fake->allocator);
    obj->etag         = r"fake-etag";
    obj->content_type = clone_string(content_type, fake->allocator);
    obj->mtime_ns     = ++fake->clock;
    fake->last_key    = clone_string(key, fake->allocator);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_buffer_t *)
fake_get(void *ctx, n00b_string_t *bucket, n00b_string_t *key,
         n00b_allocator_t *allocator)
{
    fake_s3_object_t *obj = find_object(ctx, bucket, key);
    if (obj == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_VFS_ERR_NOT_FOUND);
    }
    return n00b_result_ok(n00b_buffer_t *,
                          n00b_buffer_copy(obj->data,
                                           .allocator = allocator));
}

static n00b_result_t(n00b_buffer_t *)
fake_get_range(void *ctx, n00b_string_t *bucket, n00b_string_t *key,
               uint64_t offset, uint64_t length,
               n00b_allocator_t *allocator)
{
    fake_s3_object_t *obj = find_object(ctx, bucket, key);
    if (obj == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_VFS_ERR_NOT_FOUND);
    }

    uint64_t size = n00b_buffer_len(obj->data);
    if (offset >= size || length == 0) {
        return n00b_result_ok(n00b_buffer_t *,
                              n00b_buffer_new(0, .allocator = allocator));
    }

    uint64_t end = offset + length;
    if (end < offset || end > size) {
        end = size;
    }

    return n00b_result_ok(n00b_buffer_t *,
                          n00b_buffer_get_slice(obj->data,
                                                (int64_t)offset,
                                                (int64_t)end,
                                                .allocator = allocator));
}

static n00b_result_t(bool)
fake_put(void *ctx, n00b_string_t *bucket, n00b_string_t *key,
         n00b_buffer_t *data, n00b_string_t *content_type)
{
    return fake_store(ctx, bucket, key, data, content_type);
}

static n00b_result_t(bool)
fake_put_if_absent(void *ctx, n00b_string_t *bucket, n00b_string_t *key,
                   n00b_buffer_t *data, n00b_string_t *content_type)
{
    if (find_object(ctx, bucket, key) != nullptr) {
        return n00b_result_err(bool, N00B_VFS_ERR_EXISTS);
    }
    return fake_store(ctx, bucket, key, data, content_type);
}

static n00b_result_t(bool)
fake_put_multipart(void *ctx, n00b_string_t *bucket, n00b_string_t *key,
                   n00b_buffer_t *data, n00b_string_t *content_type,
                   uint64_t part_size)
{
    fake_s3_t *fake = ctx;
    fake->multipart_puts++;
    fake->last_part_size = part_size;
    return fake_store(fake, bucket, key, data, content_type);
}

static n00b_result_t(bool)
fake_del(void *ctx, n00b_string_t *bucket, n00b_string_t *key)
{
    fake_s3_t *fake = ctx;
    for (uint32_t i = 0; i < fake->count; i++) {
        fake_s3_object_t *obj = fake->objects[i];
        if (obj != nullptr && str_eq(obj->bucket, bucket)
            && str_eq(obj->key, key)) {
            for (uint32_t j = i + 1; j < fake->count; j++) {
                fake->objects[j - 1] = fake->objects[j];
            }
            fake->count--;
            return n00b_result_ok(bool, true);
        }
    }
    return n00b_result_err(bool, N00B_VFS_ERR_NOT_FOUND);
}

static n00b_result_t(n00b_vfs_obj_stat_t)
fake_stat(void *ctx, n00b_string_t *bucket, n00b_string_t *key)
{
    fake_s3_object_t *obj = find_object(ctx, bucket, key);
    if (obj == nullptr) {
        return n00b_result_err(n00b_vfs_obj_stat_t,
                               N00B_VFS_ERR_NOT_FOUND);
    }

    return n00b_result_ok(n00b_vfs_obj_stat_t, ((n00b_vfs_obj_stat_t){
        .kind         = N00B_VFS_OBJ_FILE,
        .size         = n00b_buffer_len(obj->data),
        .mtime_ns     = obj->mtime_ns,
        .etag         = obj->etag,
        .content_type = obj->content_type,
        .mode         = 0,
    }));
}

static n00b_result_t(n00b_vfs_list_result_t *)
fake_list(void *ctx, n00b_string_t *bucket, n00b_string_t *prefix,
          n00b_string_t *continuation, uint32_t max_keys,
          n00b_allocator_t *allocator)
{
    fake_s3_t *fake = ctx;
    uint32_t   start = 0;
    if (continuation != nullptr && continuation->data != nullptr
        && continuation->u8_bytes > 0) {
        auto parsed = n00b_parse_i64_string(continuation);
        CHECK(n00b_result_is_ok(parsed));
        CHECK(n00b_result_get(parsed) >= 0);
        start = (uint32_t)n00b_result_get(parsed);
    }

    uint32_t cap = max_keys == 0 ? FAKE_S3_MAX_OBJECTS : max_keys;
    n00b_vfs_list_result_t *out =
        n00b_alloc(n00b_vfs_list_result_t, .allocator = allocator);
    out->entries = cap == 0 ? nullptr
                            : n00b_alloc_array(n00b_vfs_list_entry_t,
                                               cap,
                                               .allocator = allocator);
    out->count        = 0;
    out->truncated    = false;
    out->continuation = nullptr;

    for (uint32_t i = start; i < fake->count; i++) {
        fake_s3_object_t *obj = fake->objects[i];
        if (obj == nullptr || !str_eq(obj->bucket, bucket)
            || !prefix_matches(obj->key, prefix)) {
            continue;
        }
        if (out->count == cap) {
            out->truncated = true;
            out->continuation =
                n00b_unicode_str_from_int((int64_t)i,
                                          .allocator = allocator);
            return n00b_result_ok(n00b_vfs_list_result_t *, out);
        }
        out->entries[out->count++] = (n00b_vfs_list_entry_t){
            .name     = clone_string(obj->key, allocator),
            .kind     = N00B_VFS_OBJ_FILE,
            .size     = n00b_buffer_len(obj->data),
            .mtime_ns = obj->mtime_ns,
        };
    }

    if (out->count == 0) {
        out->entries = nullptr;
    }
    return n00b_result_ok(n00b_vfs_list_result_t *, out);
}

static const n00b_vfs_s3_client_ops_t fake_ops = {
    .name          = nullptr,
    .get           = fake_get,
    .get_range     = fake_get_range,
    .put           = fake_put,
    .put_if_absent = fake_put_if_absent,
    .put_multipart = fake_put_multipart,
    .del           = fake_del,
    .stat          = fake_stat,
    .list          = fake_list,
};

static n00b_vfs_backend_t *
setup(fake_s3_t **fake_out)
{
    fake_s3_t *fake = n00b_alloc(fake_s3_t);
    fake->allocator = nullptr;

    auto client_r = n00b_vfs_s3_client_new(&fake_ops, fake);
    CHECK(n00b_result_is_ok(client_r));

    auto be_r = n00b_vfs_backend_s3_new(
        n00b_result_get(client_r),
        r"bucket",
        .prefix       = r"tenant/root/",
        .content_type = r"application/x-n00b-shard");
    CHECK(n00b_result_is_ok(be_r));

    *fake_out = fake;
    return n00b_result_get(be_r);
}

static n00b_vfs_backend_t *
setup_multipart(fake_s3_t **fake_out)
{
    fake_s3_t *fake = n00b_alloc(fake_s3_t);
    fake->allocator = nullptr;

    auto client_r = n00b_vfs_s3_client_new(&fake_ops, fake);
    CHECK(n00b_result_is_ok(client_r));

    auto be_r = n00b_vfs_backend_s3_new(
        n00b_result_get(client_r),
        r"bucket",
        .prefix              = r"tenant/root/",
        .content_type        = r"application/x-n00b-shard",
        .multipart_threshold = 4,
        .multipart_part_size = 3);
    CHECK(n00b_result_is_ok(be_r));

    *fake_out = fake;
    return n00b_result_get(be_r);
}

static void
assert_buffer_eq(n00b_buffer_t *buf, n00b_buffer_t *expected)
{
    CHECK(buf != nullptr);
    CHECK(expected != nullptr);
    CHECK(n00b_buffer_len(buf) == n00b_buffer_len(expected));

    size_t len = n00b_buffer_len(buf);
    for (size_t i = 0; i < len; i++) {
        auto actual = n00b_buffer_get_index(buf, (int64_t)i);
        auto want   = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(actual));
        CHECK(n00b_result_is_ok(want));
        CHECK(n00b_result_get(actual) == n00b_result_get(want));
    }
}

static void
test_put_get_range_stat_list_delete(void)
{
    fake_s3_t         *fake;
    n00b_vfs_backend_t *be = setup(&fake);

    auto put_r = be->ops->put(be->ctx,
                              r"dir/a.bin",
                              n00b_buffer_from_cstr("abcdef"));
    CHECK(n00b_result_is_ok(put_r));
    CHECK(str_eq_c(fake->last_key, "tenant/root/dir/a.bin"));

    auto get_r = be->ops->get(be->ctx, r"dir/a.bin");
    CHECK(n00b_result_is_ok(get_r));
    assert_buffer_eq(n00b_result_get(get_r), n00b_buffer_from_cstr("abcdef"));

    auto range_r = be->ops->get_range(be->ctx, r"dir/a.bin", 2, 3);
    CHECK(n00b_result_is_ok(range_r));
    assert_buffer_eq(n00b_result_get(range_r), n00b_buffer_from_cstr("cde"));

    auto stat_r = be->ops->stat(be->ctx, r"dir/a.bin");
    CHECK(n00b_result_is_ok(stat_r));
    n00b_vfs_obj_stat_t st = n00b_result_get(stat_r);
    CHECK(st.kind == N00B_VFS_OBJ_FILE);
    CHECK(st.size == 6);
    CHECK(str_eq_c(st.etag, "fake-etag"));
    CHECK(str_eq_c(st.content_type, "application/x-n00b-shard"));

    auto list_r = be->ops->list(be->ctx, r"dir/", nullptr, 10);
    CHECK(n00b_result_is_ok(list_r));
    n00b_vfs_list_result_t *list = n00b_result_get(list_r);
    CHECK(list->count == 1);
    CHECK(!list->truncated);
    CHECK(str_eq_c(list->entries[0].name, "dir/a.bin"));
    CHECK(list->entries[0].size == 6);

    auto del_r = be->ops->del(be->ctx, r"dir/a.bin");
    CHECK(n00b_result_is_ok(del_r));
    get_r = be->ops->get(be->ctx, r"dir/a.bin");
    CHECK(n00b_result_is_err(get_r));
    CHECK(n00b_result_get_err(get_r) == N00B_VFS_ERR_NOT_FOUND);

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] put_get_range_stat_list_delete");
}

static void
test_put_if_absent_and_prefix_normalization(void)
{
    fake_s3_t         *fake;
    n00b_vfs_backend_t *be = setup(&fake);

    auto put_r = be->ops->put_if_absent(be->ctx,
                                        r"/unique.bin",
                                        n00b_buffer_from_cstr("first"));
    CHECK(n00b_result_is_ok(put_r));
    CHECK(str_eq_c(fake->last_key, "tenant/root/unique.bin"));

    put_r = be->ops->put_if_absent(be->ctx,
                                   r"unique.bin",
                                   n00b_buffer_from_cstr("second"));
    CHECK(n00b_result_is_err(put_r));
    CHECK(n00b_result_get_err(put_r) == N00B_VFS_ERR_EXISTS);

    auto get_r = be->ops->get(be->ctx, r"unique.bin");
    CHECK(n00b_result_is_ok(get_r));
    assert_buffer_eq(n00b_result_get(get_r), n00b_buffer_from_cstr("first"));

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] put_if_absent_and_prefix_normalization");
}

static void
test_list_continuation(void)
{
    fake_s3_t         *fake;
    n00b_vfs_backend_t *be = setup(&fake);

    auto put_r = be->ops->put(be->ctx, r"items/1", n00b_buffer_from_cstr("1"));
    CHECK(n00b_result_is_ok(put_r));
    put_r = be->ops->put(be->ctx, r"items/2", n00b_buffer_from_cstr("22"));
    CHECK(n00b_result_is_ok(put_r));
    put_r = be->ops->put(be->ctx, r"items/3", n00b_buffer_from_cstr("333"));
    CHECK(n00b_result_is_ok(put_r));

    auto list_r = be->ops->list(be->ctx, r"items/", nullptr, 2);
    CHECK(n00b_result_is_ok(list_r));
    n00b_vfs_list_result_t *first = n00b_result_get(list_r);
    CHECK(first->count == 2);
    CHECK(first->truncated);
    CHECK(first->continuation != nullptr);
    CHECK(str_eq_c(first->entries[0].name, "items/1"));
    CHECK(str_eq_c(first->entries[1].name, "items/2"));

    list_r = be->ops->list(be->ctx, r"items/", first->continuation, 2);
    CHECK(n00b_result_is_ok(list_r));
    n00b_vfs_list_result_t *second = n00b_result_get(list_r);
    CHECK(second->count == 1);
    CHECK(!second->truncated);
    CHECK(str_eq_c(second->entries[0].name, "items/3"));

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] list_continuation");
}

static void
test_list_prefix_boundary(void)
{
    fake_s3_t         *fake;
    n00b_vfs_backend_t *be = setup(&fake);

    auto put_r = be->ops->put(be->ctx,
                              r"visible.bin",
                              n00b_buffer_from_cstr("ok"));
    CHECK(n00b_result_is_ok(put_r));

    put_r = fake_store(fake,
                       r"bucket",
                       r"tenant/rooted/leak.bin",
                       n00b_buffer_from_cstr("leak"),
                       r"application/octet-stream");
    CHECK(n00b_result_is_ok(put_r));

    auto list_r = be->ops->list(be->ctx, r"", nullptr, 10);
    CHECK(n00b_result_is_ok(list_r));
    n00b_vfs_list_result_t *list = n00b_result_get(list_r);
    CHECK(list->count == 1);
    CHECK(str_eq_c(list->entries[0].name, "visible.bin"));

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] list_prefix_boundary");
}

static void
test_multipart_threshold_path(void)
{
    fake_s3_t           *fake;
    n00b_vfs_backend_t *be = setup_multipart(&fake);

    auto put_r = be->ops->put(be->ctx,
                              r"large.bin",
                              n00b_buffer_from_cstr("abcdef"));
    CHECK(n00b_result_is_ok(put_r));
    CHECK(fake->multipart_puts == 1);
    CHECK(fake->last_part_size == 3);
    CHECK(str_eq_c(fake->last_key, "tenant/root/large.bin"));

    auto get_r = be->ops->get(be->ctx, r"large.bin");
    CHECK(n00b_result_is_ok(get_r));
    assert_buffer_eq(n00b_result_get(get_r), n00b_buffer_from_cstr("abcdef"));

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] multipart_threshold_path");
}

static void
test_capabilities(void)
{
    fake_s3_t         *fake;
    n00b_vfs_backend_t *be = setup(&fake);

    CHECK(be->ops->supports_range_read(be->ctx));
    CHECK(!be->ops->supports_rename(be->ctx));
    CHECK(!be->ops->supports_link(be->ctx));
    CHECK(!be->ops->supports_durable_sync(be->ctx));

    auto r = be->ops->rename(be->ctx, r"a", r"b");
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == N00B_VFS_ERR_NOT_SUPPORTED);

    r = be->ops->mkdir(be->ctx, r"prefix");
    CHECK(n00b_result_is_ok(r));

    r = be->ops->sync(be->ctx, r"a");
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == N00B_VFS_ERR_NOT_SUPPORTED);

    r = be->ops->link(be->ctx, r"a", r"b");
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == N00B_VFS_ERR_NOT_SUPPORTED);

    n00b_vfs_backend_cleanup(be);
    n00b_print(r"  [PASS] capabilities");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_print(r"Running VFS S3 contract tests...");
    test_put_get_range_stat_list_delete();
    test_put_if_absent_and_prefix_normalization();
    test_list_continuation();
    test_list_prefix_boundary();
    test_multipart_threshold_path();
    test_capabilities();
    n00b_print(r"All VFS S3 contract tests passed.");

    n00b_shutdown();
    return 0;
}
