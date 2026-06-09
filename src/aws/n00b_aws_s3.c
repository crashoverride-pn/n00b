/* src/aws/n00b_aws_s3.c — libn00b_aws S3 wrap + VFS adapter. */

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"

#include "aws/n00b_aws.h"
#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_s3.h"
#include "vfs/backend_s3.h"

#include "n00b_aws_shim_generated.h"
#include "internal/aws/config.h"
#include "internal/aws/s3_test.h"

#include <stdint.h>

#define AWS_S3_MIN_MULTIPART_PART_SIZE     (UINT64_C(5) * 1024 * 1024)
#define AWS_S3_DEFAULT_MULTIPART_PART_SIZE (UINT64_C(16) * 1024 * 1024)

struct n00b_aws_s3_client_t {
    n00b_aws_config_t          *cfg;
    n00b_aws_shim_s3_client_t  *shim;
    n00b_allocator_t           *allocator;
};

static void
finalize_s3_client(void *p)
{
    n00b_aws_s3_client_t *client = p;
    if (client != nullptr && client->shim != nullptr) {
        n00b_aws_shim_s3_client_free(client->shim);
        client->shim = nullptr;
    }
}

static bool
string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
cstr_to_string(char *p, n00b_allocator_t *allocator)
{
    return n00b_string_from_cstr(p == nullptr ? "" : p,
                                 .allocator = allocator);
}

static n00b_buffer_t *
raw_to_buffer(uint8_t *data, size_t len, n00b_allocator_t *allocator)
{
    if (len == 0) {
        return n00b_buffer_new(0, .allocator = allocator);
    }
    return n00b_buffer_from_bytes((char *)data,
                                  (int64_t)len,
                                  .allocator = allocator);
}

static n00b_err_t
aws_to_vfs_err(n00b_aws_status_t status)
{
    switch (status) {
    case N00B_AWS_OK:                  return N00B_VFS_ERR_NONE;
    case N00B_AWS_ERR_INVALID_ARG:     return N00B_VFS_ERR_NULL_ARG;
    case N00B_AWS_ERR_NO_CREDENTIALS:  return N00B_VFS_ERR_PERMISSION;
    case N00B_AWS_ERR_AUTHZ:           return N00B_VFS_ERR_PERMISSION;
    case N00B_AWS_ERR_NOT_FOUND:       return N00B_VFS_ERR_NOT_FOUND;
    case N00B_AWS_ERR_EXISTS:          return N00B_VFS_ERR_EXISTS;
    case N00B_AWS_ERR_TIMEOUT:         return N00B_VFS_ERR_IO;
    case N00B_AWS_ERR_NETWORK:         return N00B_VFS_ERR_IO;
    case N00B_AWS_ERR_THROTTLED:       return N00B_VFS_ERR_IO;
    case N00B_AWS_ERR_SERVICE:         return N00B_VFS_ERR_IO;
    case N00B_AWS_ERR_NOT_INITIALIZED: return N00B_VFS_ERR_BACKEND;
    case N00B_AWS_ERR_CLIENT:          return N00B_VFS_ERR_BACKEND;
    case N00B_AWS_ERR_INTERNAL:        return N00B_VFS_ERR_BACKEND;
    default:                           return N00B_VFS_ERR_BACKEND;
    }
}

static n00b_aws_s3_object_t *
object_to_n00b(n00b_aws_shim_s3_object_t *raw, n00b_allocator_t *allocator)
{
    n00b_aws_s3_object_t *out =
        n00b_alloc(n00b_aws_s3_object_t, .allocator = allocator);
    out->body             = raw_to_buffer(raw->data, raw->data_len, allocator);
    out->size             = raw->content_length;
    out->last_modified_ms = raw->last_modified_ms < 0
                                ? 0
                                : (uint64_t)raw->last_modified_ms;
    out->etag             = cstr_to_string(raw->etag, allocator);
    out->content_type     = cstr_to_string(raw->content_type, allocator);
    return out;
}

static n00b_aws_s3_stat_t *
stat_to_n00b(n00b_aws_shim_s3_stat_t *raw, n00b_allocator_t *allocator)
{
    n00b_aws_s3_stat_t *out =
        n00b_alloc(n00b_aws_s3_stat_t, .allocator = allocator);
    out->size             = raw->content_length;
    out->last_modified_ms = raw->last_modified_ms < 0
                                ? 0
                                : (uint64_t)raw->last_modified_ms;
    out->etag             = cstr_to_string(raw->etag, allocator);
    out->content_type     = cstr_to_string(raw->content_type, allocator);
    return out;
}

static n00b_aws_s3_completed_part_t *
completed_part_to_n00b(n00b_aws_shim_s3_completed_part_t *raw,
                       n00b_allocator_t                  *allocator)
{
    n00b_aws_s3_completed_part_t *out =
        n00b_alloc(n00b_aws_s3_completed_part_t, .allocator = allocator);
    out->part_number = raw->part_number;
    out->etag        = cstr_to_string(raw->etag, allocator);
    return out;
}

static n00b_aws_s3_list_result_t *
list_to_n00b(n00b_aws_shim_s3_list_output_t *raw,
             n00b_allocator_t               *allocator)
{
    n00b_aws_s3_list_result_t *out =
        n00b_alloc(n00b_aws_s3_list_result_t, .allocator = allocator);
    out->count        = raw->entries_count > UINT32_MAX
                            ? UINT32_MAX
                            : (uint32_t)raw->entries_count;
    out->truncated    = raw->truncated;
    out->continuation = raw->continuation == nullptr
                            ? nullptr
                            : cstr_to_string(raw->continuation, allocator);
    out->entries      = nullptr;

    if (out->count != 0) {
        out->entries = n00b_alloc_array(n00b_aws_s3_list_entry_t,
                                        out->count,
                                        .allocator = allocator);
        for (uint32_t i = 0; i < out->count; i++) {
            n00b_aws_shim_s3_list_entry_t *src = &raw->entries[i];
            out->entries[i] = (n00b_aws_s3_list_entry_t){
                .key              = cstr_to_string(src->key, allocator),
                .size             = src->size,
                .last_modified_ms = src->last_modified_ms < 0
                                        ? 0
                                        : (uint64_t)src->last_modified_ms,
                .etag             = cstr_to_string(src->etag, allocator),
            };
        }
    }

    return out;
}

n00b_result_t(n00b_aws_s3_client_t *)
n00b_aws_s3_client_new(n00b_aws_config_t *cfg) _kargs
{
    bool              force_path_style = false;
    n00b_allocator_t *allocator        = nullptr;
}
{
    if (cfg == nullptr || cfg->shim == nullptr) {
        return n00b_result_err(n00b_aws_s3_client_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_s3_client_t *shim =
        n00b_aws_shim_s3_client_new(cfg->shim, force_path_style);
    if (shim == nullptr) {
        return n00b_result_err(n00b_aws_s3_client_t *,
                               N00B_AWS_ERR_INTERNAL);
    }

    n00b_aws_s3_client_t *client =
        n00b_alloc(n00b_aws_s3_client_t, .allocator = allocator);
    client->cfg       = cfg;
    client->shim      = shim;
    client->allocator = allocator;
    n00b_add_finalizer(client, finalize_s3_client, client);
    return n00b_result_ok(n00b_aws_s3_client_t *, client);
}

n00b_result_t(n00b_aws_s3_object_t *)
n00b_aws_s3_get_object(n00b_aws_s3_client_t *client,
                       n00b_string_t        *bucket,
                       n00b_string_t        *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)) {
        return n00b_result_err(n00b_aws_s3_object_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_s3_object_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_get_object(client->shim,
                                         bucket->data,
                                         key->data,
                                         &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_aws_s3_object_t *, rc);
    }

    n00b_aws_s3_object_t *out = object_to_n00b(raw, allocator);
    n00b_aws_shim_s3_object_free(raw);
    return n00b_result_ok(n00b_aws_s3_object_t *, out);
}

n00b_result_t(n00b_aws_s3_object_t *)
n00b_aws_s3_get_object_range(n00b_aws_s3_client_t *client,
                             n00b_string_t        *bucket,
                             n00b_string_t        *key,
                             uint64_t              offset,
                             uint64_t              length) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)) {
        return n00b_result_err(n00b_aws_s3_object_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }
    if (length == 0) {
        n00b_aws_s3_object_t *out =
            n00b_alloc(n00b_aws_s3_object_t, .allocator = allocator);
        out->body             = n00b_buffer_new(0, .allocator = allocator);
        out->size             = 0;
        out->last_modified_ms = 0;
        out->etag             = n00b_string_from_cstr("",
                                                      .allocator = allocator);
        out->content_type     = n00b_string_from_cstr("",
                                                      .allocator = allocator);
        return n00b_result_ok(n00b_aws_s3_object_t *, out);
    }

    n00b_aws_shim_s3_object_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_get_object_range(client->shim,
                                               bucket->data,
                                               key->data,
                                               offset,
                                               length,
                                               &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_aws_s3_object_t *, rc);
    }

    n00b_aws_s3_object_t *out = object_to_n00b(raw, allocator);
    n00b_aws_shim_s3_object_free(raw);
    return n00b_result_ok(n00b_aws_s3_object_t *, out);
}

static n00b_result_t(bool)
put_common(n00b_aws_s3_client_t *client,
           n00b_string_t        *bucket,
           n00b_string_t        *key,
           n00b_buffer_t        *body,
           n00b_string_t        *content_type,
           bool                  if_absent)
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key) || body == nullptr) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }

    const char *ct = content_type == nullptr ? nullptr : content_type->data;
    int rc = if_absent
                 ? n00b_aws_shim_s3_put_object_if_absent(client->shim,
                                                         bucket->data,
                                                         key->data,
                                                         (uint8_t *)body->data,
                                                         body->byte_len,
                                                         ct)
                 : n00b_aws_shim_s3_put_object(client->shim,
                                               bucket->data,
                                               key->data,
                                               (uint8_t *)body->data,
                                               body->byte_len,
                                               ct);
    if (rc != N00B_AWS_OK) {
        return n00b_result_err(bool, rc);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_aws_s3_put_object(n00b_aws_s3_client_t *client,
                       n00b_string_t        *bucket,
                       n00b_string_t        *key,
                       n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
}
{
    return put_common(client, bucket, key, body, content_type, false);
}

n00b_result_t(bool)
n00b_aws_s3_put_object_if_absent(n00b_aws_s3_client_t *client,
                                 n00b_string_t        *bucket,
                                 n00b_string_t        *key,
                                 n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
}
{
    return put_common(client, bucket, key, body, content_type, true);
}

n00b_result_t(bool)
n00b_aws_s3_put_object_multipart(n00b_aws_s3_client_t *client,
                                 n00b_string_t        *bucket,
                                 n00b_string_t        *key,
                                 n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
    uint64_t       part_size    = 0;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key) || body == nullptr) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }
    if (n00b_buffer_len(body) == 0) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }
    if (part_size == 0) {
        part_size = AWS_S3_DEFAULT_MULTIPART_PART_SIZE;
    }
    else if (part_size < AWS_S3_MIN_MULTIPART_PART_SIZE) {
        part_size = AWS_S3_MIN_MULTIPART_PART_SIZE;
    }
    if (part_size > (uint64_t)SIZE_MAX) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }

    const char *ct = content_type == nullptr ? nullptr : content_type->data;
    int rc = n00b_aws_shim_s3_put_object_multipart(client->shim,
                                                   bucket->data,
                                                   key->data,
                                                   (uint8_t *)body->data,
                                                   body->byte_len,
                                                   ct,
                                                   (size_t)part_size);
    if (rc != N00B_AWS_OK) {
        return n00b_result_err(bool, rc);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_string_t *)
n00b_aws_s3_multipart_create(n00b_aws_s3_client_t *client,
                              n00b_string_t        *bucket,
                              n00b_string_t        *key) _kargs
{
    n00b_string_t    *content_type = nullptr;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)) {
        return n00b_result_err(n00b_string_t *, N00B_AWS_ERR_INVALID_ARG);
    }

    const char *ct = content_type == nullptr ? nullptr : content_type->data;
    n00b_aws_shim_s3_multipart_create_output_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_multipart_create(client->shim,
                                               bucket->data,
                                               key->data,
                                               ct,
                                               &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_string_t *, rc);
    }

    n00b_string_t *upload_id = cstr_to_string(raw->upload_id, allocator);
    n00b_aws_shim_s3_multipart_create_output_free(raw);
    return n00b_result_ok(n00b_string_t *, upload_id);
}

n00b_result_t(n00b_aws_s3_completed_part_t *)
n00b_aws_s3_multipart_upload_part(n00b_aws_s3_client_t *client,
                                  n00b_string_t        *bucket,
                                  n00b_string_t        *key,
                                  n00b_string_t        *upload_id,
                                  int32_t               part_number,
                                  n00b_buffer_t        *body) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)
        || string_empty(upload_id) || body == nullptr || part_number < 1) {
        return n00b_result_err(n00b_aws_s3_completed_part_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_s3_completed_part_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_multipart_upload_part(client->shim,
                                                    bucket->data,
                                                    key->data,
                                                    upload_id->data,
                                                    part_number,
                                                    (uint8_t *)body->data,
                                                    body->byte_len,
                                                    &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_aws_s3_completed_part_t *, rc);
    }

    n00b_aws_s3_completed_part_t *out =
        completed_part_to_n00b(raw, allocator);
    n00b_aws_shim_s3_completed_part_free(raw);
    return n00b_result_ok(n00b_aws_s3_completed_part_t *, out);
}

n00b_result_t(bool)
n00b_aws_s3_multipart_complete(n00b_aws_s3_client_t          *client,
                               n00b_string_t                 *bucket,
                               n00b_string_t                 *key,
                               n00b_string_t                 *upload_id,
                               n00b_aws_s3_completed_part_t  *parts,
                               uint32_t                       part_count)
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)
        || string_empty(upload_id) || parts == nullptr || part_count == 0) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_s3_completed_part_t *raw_parts =
        n00b_alloc_array(n00b_aws_shim_s3_completed_part_t, part_count);
    for (uint32_t i = 0; i < part_count; i++) {
        if (parts[i].part_number < 1 || string_empty(parts[i].etag)) {
            return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
        }
        raw_parts[i] = (n00b_aws_shim_s3_completed_part_t){
            .part_number = parts[i].part_number,
            .etag        = parts[i].etag->data,
        };
    }

    int rc = n00b_aws_shim_s3_multipart_complete(client->shim,
                                                 bucket->data,
                                                 key->data,
                                                 upload_id->data,
                                                 raw_parts,
                                                 part_count);
    if (rc != N00B_AWS_OK) {
        return n00b_result_err(bool, rc);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_aws_s3_multipart_abort(n00b_aws_s3_client_t *client,
                            n00b_string_t        *bucket,
                            n00b_string_t        *key,
                            n00b_string_t        *upload_id)
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)
        || string_empty(upload_id)) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }

    int rc = n00b_aws_shim_s3_multipart_abort(client->shim,
                                              bucket->data,
                                              key->data,
                                              upload_id->data);
    if (rc != N00B_AWS_OK) {
        return n00b_result_err(bool, rc);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_aws_s3_delete_object(n00b_aws_s3_client_t *client,
                          n00b_string_t        *bucket,
                          n00b_string_t        *key)
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)) {
        return n00b_result_err(bool, N00B_AWS_ERR_INVALID_ARG);
    }

    int rc = n00b_aws_shim_s3_delete_object(client->shim,
                                            bucket->data,
                                            key->data);
    if (rc != N00B_AWS_OK) {
        return n00b_result_err(bool, rc);
    }
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_aws_s3_stat_t *)
n00b_aws_s3_head_object(n00b_aws_s3_client_t *client,
                        n00b_string_t        *bucket,
                        n00b_string_t        *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr
        || string_empty(bucket) || string_empty(key)) {
        return n00b_result_err(n00b_aws_s3_stat_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    n00b_aws_shim_s3_stat_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_head_object(client->shim,
                                          bucket->data,
                                          key->data,
                                          &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_aws_s3_stat_t *, rc);
    }

    n00b_aws_s3_stat_t *out = stat_to_n00b(raw, allocator);
    n00b_aws_shim_s3_stat_free(raw);
    return n00b_result_ok(n00b_aws_s3_stat_t *, out);
}

n00b_result_t(n00b_aws_s3_list_result_t *)
n00b_aws_s3_list_objects(n00b_aws_s3_client_t *client,
                         n00b_string_t        *bucket,
                         n00b_string_t        *prefix) _kargs
{
    n00b_string_t    *continuation = nullptr;
    uint32_t          max_keys     = 0;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr || string_empty(bucket)) {
        return n00b_result_err(n00b_aws_s3_list_result_t *,
                               N00B_AWS_ERR_INVALID_ARG);
    }

    const char *prefix_c = prefix == nullptr ? nullptr : prefix->data;
    const char *cont_c   = continuation == nullptr ? nullptr : continuation->data;
    n00b_aws_shim_s3_list_output_t *raw = nullptr;
    int rc = n00b_aws_shim_s3_list_objects(client->shim,
                                           bucket->data,
                                           prefix_c,
                                           cont_c,
                                           max_keys,
                                           &raw);
    if (rc != N00B_AWS_OK || raw == nullptr) {
        return n00b_result_err(n00b_aws_s3_list_result_t *, rc);
    }

    n00b_aws_s3_list_result_t *out = list_to_n00b(raw, allocator);
    n00b_aws_shim_s3_list_output_free(raw);
    return n00b_result_ok(n00b_aws_s3_list_result_t *, out);
}

static n00b_result_t(n00b_buffer_t *)
s3_vfs_get(void             *ctx,
           n00b_string_t    *bucket,
           n00b_string_t    *key,
           n00b_allocator_t *allocator)
{
    auto r = n00b_aws_s3_get_object(ctx, bucket, key, .allocator = allocator);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(n00b_buffer_t *,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(r)->body);
}

static n00b_result_t(n00b_buffer_t *)
s3_vfs_get_range(void             *ctx,
                 n00b_string_t    *bucket,
                 n00b_string_t    *key,
                 uint64_t          offset,
                 uint64_t          length,
                 n00b_allocator_t *allocator)
{
    auto r = n00b_aws_s3_get_object_range(ctx,
                                          bucket,
                                          key,
                                          offset,
                                          length,
                                          .allocator = allocator);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(n00b_buffer_t *,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(r)->body);
}

static n00b_result_t(bool)
s3_vfs_put(void          *ctx,
           n00b_string_t *bucket,
           n00b_string_t *key,
           n00b_buffer_t *data,
           n00b_string_t *content_type)
{
    auto r = n00b_aws_s3_put_object(ctx,
                                    bucket,
                                    key,
                                    data,
                                    .content_type = content_type);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
s3_vfs_put_if_absent(void          *ctx,
                     n00b_string_t *bucket,
                     n00b_string_t *key,
                     n00b_buffer_t *data,
                     n00b_string_t *content_type)
{
    auto r = n00b_aws_s3_put_object_if_absent(ctx,
                                              bucket,
                                              key,
                                              data,
                                              .content_type = content_type);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
s3_vfs_put_multipart(void          *ctx,
                     n00b_string_t *bucket,
                     n00b_string_t *key,
                     n00b_buffer_t *data,
                     n00b_string_t *content_type,
                     uint64_t       part_size)
{
    auto r = n00b_aws_s3_put_object_multipart(ctx,
                                              bucket,
                                              key,
                                              data,
                                              .content_type = content_type,
                                              .part_size    = part_size);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
s3_vfs_del(void *ctx, n00b_string_t *bucket, n00b_string_t *key)
{
    auto r = n00b_aws_s3_delete_object(ctx, bucket, key);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_vfs_obj_stat_t)
s3_vfs_stat(void *ctx, n00b_string_t *bucket, n00b_string_t *key)
{
    auto r = n00b_aws_s3_head_object(ctx, bucket, key);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(n00b_vfs_obj_stat_t,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }
    n00b_aws_s3_stat_t *st = n00b_result_get(r);
    uint64_t            ms = st->last_modified_ms;
    return n00b_result_ok(n00b_vfs_obj_stat_t, ((n00b_vfs_obj_stat_t){
        .kind         = N00B_VFS_OBJ_FILE,
        .size         = st->size,
        .mtime_ns     = ms > UINT64_MAX / 1000000 ? UINT64_MAX
                                                   : ms * 1000000,
        .etag         = st->etag,
        .content_type = st->content_type,
        .mode         = 0,
    }));
}

static n00b_result_t(n00b_vfs_list_result_t *)
s3_vfs_list(void             *ctx,
            n00b_string_t    *bucket,
            n00b_string_t    *prefix,
            n00b_string_t    *continuation,
            uint32_t          max_keys,
            n00b_allocator_t *allocator)
{
    auto r = n00b_aws_s3_list_objects(ctx,
                                      bucket,
                                      prefix,
                                      .continuation = continuation,
                                      .max_keys     = max_keys,
                                      .allocator    = allocator);
    if (n00b_result_is_err(r)) {
        return n00b_result_err(n00b_vfs_list_result_t *,
                               aws_to_vfs_err(n00b_result_get_err(r)));
    }

    n00b_aws_s3_list_result_t *src = n00b_result_get(r);
    n00b_vfs_list_result_t    *out =
        n00b_alloc(n00b_vfs_list_result_t, .allocator = allocator);
    out->count        = src->count;
    out->truncated    = src->truncated;
    out->continuation = src->continuation;
    out->entries      = nullptr;

    if (src->count != 0) {
        out->entries = n00b_alloc_array(n00b_vfs_list_entry_t,
                                        src->count,
                                        .allocator = allocator);
        for (uint32_t i = 0; i < src->count; i++) {
            uint64_t ms = src->entries[i].last_modified_ms;
            out->entries[i] = (n00b_vfs_list_entry_t){
                .name     = src->entries[i].key,
                .kind     = N00B_VFS_OBJ_FILE,
                .size     = src->entries[i].size,
                .mtime_ns = ms > UINT64_MAX / 1000000 ? UINT64_MAX
                                                       : ms * 1000000,
            };
        }
    }
    return n00b_result_ok(n00b_vfs_list_result_t *, out);
}

static const n00b_vfs_s3_client_ops_t aws_s3_vfs_ops = {
    .name          = nullptr,
    .get           = s3_vfs_get,
    .get_range     = s3_vfs_get_range,
    .put           = s3_vfs_put,
    .put_if_absent = s3_vfs_put_if_absent,
    .put_multipart = s3_vfs_put_multipart,
    .del           = s3_vfs_del,
    .stat          = s3_vfs_stat,
    .list          = s3_vfs_list,
};

n00b_result_t(n00b_vfs_s3_client_t *)
n00b_aws_s3_vfs_client_new(n00b_aws_s3_client_t *client) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (client == nullptr || client->shim == nullptr) {
        return n00b_result_err(n00b_vfs_s3_client_t *,
                               N00B_VFS_ERR_NULL_ARG);
    }
    return n00b_vfs_s3_client_new(&aws_s3_vfs_ops,
                                  client,
                                  .allocator = allocator);
}

n00b_result_t(n00b_vfs_backend_t *)
n00b_aws_s3_vfs_backend_new(n00b_aws_config_t *cfg,
                            n00b_string_t     *bucket) _kargs
{
    n00b_string_t    *prefix           = nullptr;
    n00b_string_t    *content_type     = nullptr;
    bool              force_path_style = false;
    uint64_t          multipart_threshold = 0;
    uint64_t          multipart_part_size = 0;
    n00b_allocator_t *allocator        = nullptr;
}
{
    auto client_r = n00b_aws_s3_client_new(cfg,
                                           .force_path_style = force_path_style,
                                           .allocator        = allocator);
    if (n00b_result_is_err(client_r)) {
        return n00b_result_err(n00b_vfs_backend_t *,
                               aws_to_vfs_err(n00b_result_get_err(client_r)));
    }

    auto vfs_client_r = n00b_aws_s3_vfs_client_new(n00b_result_get(client_r),
                                                   .allocator = allocator);
    if (n00b_result_is_err(vfs_client_r)) {
        return n00b_result_err(n00b_vfs_backend_t *,
                               n00b_result_get_err(vfs_client_r));
    }

    return n00b_vfs_backend_s3_new(n00b_result_get(vfs_client_r),
                                   bucket,
                                   .prefix              = prefix,
                                   .content_type        = content_type,
                                   .multipart_threshold = multipart_threshold,
                                   .multipart_part_size = multipart_part_size,
                                   .allocator           = allocator);
}

n00b_aws_s3_object_t *
n00b_aws_s3_test_object_from_raw(uint8_t          *data,
                                 size_t            data_len,
                                 uint64_t          content_length,
                                 int64_t           last_modified_ms,
                                 char             *etag,
                                 char             *content_type,
                                 n00b_allocator_t *allocator)
{
    n00b_aws_shim_s3_object_t raw = {
        .data             = data,
        .data_len         = data_len,
        .content_length   = content_length,
        .last_modified_ms = last_modified_ms,
        .etag             = etag,
        .content_type     = content_type,
    };
    return object_to_n00b(&raw, allocator);
}

n00b_aws_s3_stat_t *
n00b_aws_s3_test_stat_from_raw(uint64_t          content_length,
                               int64_t           last_modified_ms,
                               char             *etag,
                               char             *content_type,
                               n00b_allocator_t *allocator)
{
    n00b_aws_shim_s3_stat_t raw = {
        .content_length   = content_length,
        .last_modified_ms = last_modified_ms,
        .etag             = etag,
        .content_type     = content_type,
    };
    return stat_to_n00b(&raw, allocator);
}

n00b_aws_s3_list_result_t *
n00b_aws_s3_test_list_from_raw(n00b_allocator_t *allocator)
{
    n00b_aws_shim_s3_list_entry_t entries[2] = {
        {
            .key              = "alpha.bin",
            .size             = 5,
            .last_modified_ms = 17,
            .etag             = "etag-a",
        },
        {
            .key              = "nested/beta.bin",
            .size             = 9,
            .last_modified_ms = -1,
            .etag             = nullptr,
        },
    };
    n00b_aws_shim_s3_list_output_t raw = {
        .entries       = entries,
        .entries_count = 2,
        .continuation  = "next-token",
        .truncated     = true,
    };
    return list_to_n00b(&raw, allocator);
}

n00b_err_t
n00b_aws_s3_test_vfs_error(n00b_aws_status_t status)
{
    return aws_to_vfs_err(status);
}
