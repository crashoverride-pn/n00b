#include "vfs/backend_s3.h"
#include "core/alloc.h"

#include <string.h>

#define S3_DEFAULT_MULTIPART_THRESHOLD (UINT64_C(64) * 1024 * 1024)
#define S3_DEFAULT_MULTIPART_PART_SIZE (UINT64_C(16) * 1024 * 1024)

typedef struct {
    n00b_vfs_s3_client_t *client;
    n00b_string_t        *bucket;
    n00b_string_t        *prefix;
    n00b_string_t        *content_type;
    uint64_t              multipart_threshold;
    uint64_t              multipart_part_size;
    n00b_allocator_t     *allocator;
} s3_ctx_t;

static bool
s3_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
s3_string_clone(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s3_string_empty(s)) {
        return r"";
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static n00b_result_t(n00b_string_t *)
s3_key_for(s3_ctx_t *ctx, n00b_string_t *path)
{
    if (ctx == nullptr || path == nullptr || path->data == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_VFS_ERR_NULL_ARG);
    }

    n00b_string_t    *prefix    = ctx->prefix;
    n00b_allocator_t *allocator = ctx->allocator;
    const char       *path_data  = path->data;
    size_t            path_len   = path->u8_bytes;

    while (path_len > 0 && path_data[0] == '/') {
        path_data++;
        path_len--;
    }

    if (s3_string_empty(prefix)) {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_string_from_raw(path_data,
                                 (int64_t)path_len,
                                 .allocator = allocator));
    }

    size_t prefix_len = prefix->u8_bytes;
    while (prefix_len > 0 && prefix->data[prefix_len - 1] == '/') {
        prefix_len--;
    }

    if (path_len == 0) {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_string_from_raw(prefix->data,
                                 (int64_t)prefix_len,
                                 .allocator = allocator));
    }

    size_t total = prefix_len + 1 + path_len;
    char  *buf   = n00b_alloc_array(char,
                                    total + 1,
                                    .allocator = allocator);
    memcpy(buf, prefix->data, prefix_len);
    buf[prefix_len] = '/';
    memcpy(buf + prefix_len + 1, path_data, path_len);
    buf[total] = '\0';

    return n00b_result_ok(n00b_string_t *,
                          n00b_string_from_raw(buf,
                                               (int64_t)total,
                                               .allocator = allocator));
}

static n00b_string_t *
s3_name_from_key(s3_ctx_t *ctx, n00b_string_t *key)
{
    if (key == nullptr || key->data == nullptr) {
        return r"";
    }

    n00b_string_t *prefix = ctx->prefix;
    if (s3_string_empty(prefix)) {
        return s3_string_clone(key, ctx->allocator);
    }

    size_t prefix_len = prefix->u8_bytes;
    while (prefix_len > 0 && prefix->data[prefix_len - 1] == '/') {
        prefix_len--;
    }

    if (key->u8_bytes < prefix_len
        || memcmp(key->data, prefix->data, prefix_len) != 0) {
        return nullptr;
    }

    size_t skip = prefix_len;
    if (skip < key->u8_bytes) {
        if (key->data[skip] != '/') {
            return nullptr;
        }
        skip++;
    }

    return n00b_string_from_raw(key->data + skip,
                                (int64_t)(key->u8_bytes - skip),
                                .allocator = ctx->allocator);
}

static n00b_string_t *
s3_list_prefix_for(s3_ctx_t *ctx, n00b_string_t *path)
{
    auto key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return nullptr;
    }

    n00b_string_t *key = n00b_result_get(key_r);
    if (s3_string_empty(key) || key->data[key->u8_bytes - 1] == '/') {
        return key;
    }

    char *buf = n00b_alloc_array(char,
                                 key->u8_bytes + 2,
                                 .allocator = ctx->allocator);
    memcpy(buf, key->data, key->u8_bytes);
    buf[key->u8_bytes]     = '/';
    buf[key->u8_bytes + 1] = '\0';
    return n00b_string_from_raw(buf,
                                (int64_t)(key->u8_bytes + 1),
                                .allocator = ctx->allocator);
}

static n00b_vfs_s3_client_ops_t const *
s3_client_ops(s3_ctx_t *ctx)
{
    return ctx->client->ops;
}

static n00b_string_t *
s3_name(void)
{
    return r"s3";
}

static void
s3_cleanup(void *ctx)
{
    (void)ctx;
}

static n00b_result_t(n00b_buffer_t *)
s3_get(void *vctx, n00b_string_t *path)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(key_r));
    }

    return s3_client_ops(ctx)->get(ctx->client->ctx,
                                   ctx->bucket,
                                   n00b_result_get(key_r),
                                   ctx->allocator);
}

static n00b_result_t(n00b_buffer_t *)
s3_get_range(void *vctx, n00b_string_t *path, uint64_t offset,
             uint64_t length)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(key_r));
    }

    return s3_client_ops(ctx)->get_range(ctx->client->ctx,
                                         ctx->bucket,
                                         n00b_result_get(key_r),
                                         offset,
                                         length,
                                         ctx->allocator);
}

static n00b_result_t(bool)
s3_put(void *vctx, n00b_string_t *path, n00b_buffer_t *data)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }

    const n00b_vfs_s3_client_ops_t *ops = s3_client_ops(ctx);
    if (data != nullptr && ops->put_multipart != nullptr
        && ctx->multipart_threshold != 0
        && (uint64_t)n00b_buffer_len(data) >= ctx->multipart_threshold) {
        return ops->put_multipart(ctx->client->ctx,
                                  ctx->bucket,
                                  n00b_result_get(key_r),
                                  data,
                                  ctx->content_type,
                                  ctx->multipart_part_size);
    }

    return ops->put(ctx->client->ctx,
                    ctx->bucket,
                    n00b_result_get(key_r),
                    data,
                    ctx->content_type);
}

static n00b_result_t(bool)
s3_put_if_absent(void *vctx, n00b_string_t *path, n00b_buffer_t *data)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }

    return s3_client_ops(ctx)->put_if_absent(ctx->client->ctx,
                                             ctx->bucket,
                                             n00b_result_get(key_r),
                                             data,
                                             ctx->content_type);
}

static n00b_result_t(bool)
s3_del(void *vctx, n00b_string_t *path)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(bool, n00b_result_get_err(key_r));
    }

    return s3_client_ops(ctx)->del(ctx->client->ctx,
                                   ctx->bucket,
                                   n00b_result_get(key_r));
}

static n00b_result_t(n00b_vfs_obj_stat_t)
s3_stat(void *vctx, n00b_string_t *path)
{
    s3_ctx_t *ctx   = vctx;
    auto      key_r = s3_key_for(ctx, path);
    if (n00b_result_is_err(key_r)) {
        return n00b_result_err(n00b_vfs_obj_stat_t,
                               n00b_result_get_err(key_r));
    }

    return s3_client_ops(ctx)->stat(ctx->client->ctx,
                                    ctx->bucket,
                                    n00b_result_get(key_r));
}

static n00b_result_t(n00b_vfs_list_result_t *)
s3_list(void *vctx, n00b_string_t *prefix, n00b_string_t *continuation,
        uint32_t max_keys)
{
    s3_ctx_t      *ctx = vctx;
    n00b_string_t *key = s3_list_prefix_for(ctx, prefix);
    if (key == nullptr) {
        return n00b_result_err(n00b_vfs_list_result_t *,
                               N00B_VFS_ERR_NULL_ARG);
    }

    auto raw_r = s3_client_ops(ctx)->list(ctx->client->ctx,
                                          ctx->bucket,
                                          key,
                                          continuation,
                                          max_keys,
                                          ctx->allocator);
    if (n00b_result_is_err(raw_r)) {
        return raw_r;
    }

    n00b_vfs_list_result_t *raw = n00b_result_get(raw_r);
    n00b_vfs_list_result_t *out =
        n00b_alloc(n00b_vfs_list_result_t, .allocator = ctx->allocator);
    out->count     = raw == nullptr ? 0 : raw->count;
    out->truncated = raw != nullptr && raw->truncated;
    out->continuation =
        raw == nullptr || raw->continuation == nullptr
            ? nullptr
            : s3_string_clone(raw->continuation, ctx->allocator);
    out->entries = nullptr;

    if (raw == nullptr || raw->count == 0 || raw->entries == nullptr) {
        return n00b_result_ok(n00b_vfs_list_result_t *, out);
    }

    out->entries = n00b_alloc_array(n00b_vfs_list_entry_t,
                                    raw->count,
                                    .allocator = ctx->allocator);
    uint32_t count = 0;
    for (uint32_t i = 0; i < raw->count; i++) {
        n00b_string_t *name = s3_name_from_key(ctx, raw->entries[i].name);
        if (name == nullptr) {
            continue;
        }
        out->entries[count]      = raw->entries[i];
        out->entries[count].name = name;
        count++;
    }
    out->count = count;
    if (count == 0) {
        out->entries = nullptr;
    }

    return n00b_result_ok(n00b_vfs_list_result_t *, out);
}

static n00b_result_t(bool)
s3_rename(void *ctx, n00b_string_t *old_path, n00b_string_t *new_path)
{
    (void)ctx;
    (void)old_path;
    (void)new_path;
    return n00b_result_err(bool, N00B_VFS_ERR_NOT_SUPPORTED);
}

static n00b_result_t(bool)
s3_mkdir(void *ctx, n00b_string_t *path)
{
    (void)ctx;
    (void)path;
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
s3_sync(void *ctx, n00b_string_t *path)
{
    (void)ctx;
    (void)path;
    return n00b_result_err(bool, N00B_VFS_ERR_NOT_SUPPORTED);
}

static bool
s3_supports_range_read(void *ctx)
{
    (void)ctx;
    return true;
}

static bool
s3_supports_rename(void *ctx)
{
    (void)ctx;
    return false;
}

static bool
s3_supports_link(void *ctx)
{
    (void)ctx;
    return false;
}

static bool
s3_supports_durable_sync(void *ctx)
{
    (void)ctx;
    return false;
}

static n00b_result_t(bool)
s3_link(void *ctx, n00b_string_t *target, n00b_string_t *link_path)
{
    (void)ctx;
    (void)target;
    (void)link_path;
    return n00b_result_err(bool, N00B_VFS_ERR_NOT_SUPPORTED);
}

const n00b_vfs_backend_ops_t n00b_vfs_backend_s3_ops = {
    .name                  = s3_name,
    .init                  = nullptr,
    .cleanup               = s3_cleanup,
    .get                   = s3_get,
    .get_range             = s3_get_range,
    .put                   = s3_put,
    .put_if_absent         = s3_put_if_absent,
    .del                   = s3_del,
    .stat                  = s3_stat,
    .list                  = s3_list,
    .rename                = s3_rename,
    .mkdir                 = s3_mkdir,
    .sync                  = s3_sync,
    .supports_range_read   = s3_supports_range_read,
    .supports_rename       = s3_supports_rename,
    .supports_link         = s3_supports_link,
    .supports_durable_sync = s3_supports_durable_sync,
    .link                  = s3_link,
    // s3_list builds fresh name strings via s3_name_from_key; the readdir clone
    // may free the originals.
    .list_result_owns_strings = true,
};

n00b_result_t(n00b_vfs_s3_client_t *)
n00b_vfs_s3_client_new(const n00b_vfs_s3_client_ops_t *ops,
                       void                           *ctx) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (ops == nullptr || ops->get == nullptr || ops->get_range == nullptr
        || ops->put == nullptr || ops->put_if_absent == nullptr
        || ops->del == nullptr || ops->stat == nullptr
        || ops->list == nullptr) {
        return n00b_result_err(n00b_vfs_s3_client_t *,
                               N00B_VFS_ERR_NULL_ARG);
    }

    n00b_vfs_s3_client_t *client =
        n00b_alloc(n00b_vfs_s3_client_t, .allocator = allocator);
    client->ops       = ops;
    client->ctx       = ctx;
    client->allocator = allocator;
    return n00b_result_ok(n00b_vfs_s3_client_t *, client);
}

n00b_result_t(n00b_vfs_backend_t *)
n00b_vfs_backend_s3_new(n00b_vfs_s3_client_t *client,
                        n00b_string_t        *bucket) _kargs
{
    n00b_string_t    *prefix       = nullptr;
    n00b_string_t    *content_type = nullptr;
    uint64_t          multipart_threshold = 0;
    uint64_t          multipart_part_size = 0;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (client == nullptr || client->ops == nullptr || s3_string_empty(bucket)) {
        return n00b_result_err(n00b_vfs_backend_t *,
                               N00B_VFS_ERR_NULL_ARG);
    }

    s3_ctx_t *ctx = n00b_alloc(s3_ctx_t, .allocator = allocator);
    ctx->client       = client;
    ctx->bucket       = bucket;
    ctx->prefix       = s3_string_empty(prefix) ? r"" : prefix;
    ctx->content_type = s3_string_empty(content_type)
                            ? r"application/octet-stream"
                            : content_type;
    ctx->multipart_threshold =
        multipart_threshold == 0 ? S3_DEFAULT_MULTIPART_THRESHOLD
                                 : multipart_threshold;
    ctx->multipart_part_size =
        multipart_part_size == 0 ? S3_DEFAULT_MULTIPART_PART_SIZE
                                 : multipart_part_size;
    ctx->allocator    = allocator;

    n00b_vfs_backend_t *be =
        n00b_alloc(n00b_vfs_backend_t, .allocator = allocator);
    be->ops       = &n00b_vfs_backend_s3_ops;
    be->ctx       = ctx;
    be->root      = ctx->prefix;
    be->allocator = allocator;

    auto init_r = n00b_vfs_backend_init(be);
    if (n00b_result_is_err(init_r)) {
        return n00b_result_err(n00b_vfs_backend_t *,
                               n00b_result_get_err(init_r));
    }

    return n00b_result_ok(n00b_vfs_backend_t *, be);
}
