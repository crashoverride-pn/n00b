/**
 * @file aws/n00b_aws_s3.h
 * @brief S3 object operations and VFS backend adapter.
 *
 * The public S3 surface has two layers:
 *
 * - Direct object operations for callers that want AWS/S3 concepts.
 * - A VFS adapter that turns an S3 client into `n00b_vfs_backend_t`.
 *
 * The VFS adapter keeps the core VFS free of AWS dependencies: core owns the
 * generic S3-compatible backend over an injected operation table, while
 * libn00b_aws supplies the real AWS-backed client implementation.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/result.h"
#include "aws/n00b_aws.h"
#include "vfs/backend.h"
#include "vfs/backend_s3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct n00b_aws_s3_client_t n00b_aws_s3_client_t;

/**
 * @brief S3 object body plus metadata returned by get operations.
 *
 * All fields are copied into n00b-owned GC allocations before the Rust shim
 * response is freed. Empty or absent string metadata is represented as an
 * allocated empty n00b string.
 */
typedef struct {
    n00b_buffer_t *body;
    uint64_t       size;
    uint64_t       last_modified_ms;
    n00b_string_t *etag;
    n00b_string_t *content_type;
} n00b_aws_s3_object_t;

/**
 * @brief S3 object metadata returned by head/stat operations.
 *
 * String fields are n00b-owned copies. `last_modified_ms` is Unix epoch
 * milliseconds, or zero when the service omits the timestamp.
 */
typedef struct {
    uint64_t       size;
    uint64_t       last_modified_ms;
    n00b_string_t *etag;
    n00b_string_t *content_type;
} n00b_aws_s3_stat_t;

/**
 * @brief One S3 list entry.
 *
 * `key` and `etag` are n00b-owned copies. `last_modified_ms` is Unix epoch
 * milliseconds, or zero when absent.
 */
typedef struct {
    n00b_string_t *key;
    uint64_t       size;
    uint64_t       last_modified_ms;
    n00b_string_t *etag;
} n00b_aws_s3_list_entry_t;

/**
 * @brief Paged S3 list result.
 *
 * `entries` is a n00b-owned array with `count` elements. `continuation` is
 * nullptr when no next page exists; otherwise pass it to the next list call.
 */
typedef struct {
    n00b_aws_s3_list_entry_t *entries;
    uint32_t                  count;
    n00b_string_t            *continuation;
    bool                      truncated;
} n00b_aws_s3_list_result_t;

/**
 * @brief Completed multipart part descriptor.
 *
 * `etag` is a n00b-owned copy returned by upload-part or supplied by the
 * caller to complete-multipart.
 */
typedef struct {
    int32_t        part_number;
    n00b_string_t *etag;
} n00b_aws_s3_completed_part_t;

/**
 * @brief Build an S3 client from a libn00b_aws config.
 *
 * @kw force_path_style Use path-style addressing. Defaults false for AWS S3;
 *                      set true for LocalStack or S3-compatible services that
 *                      do not support virtual-hosted bucket names.
 * @kw allocator        Allocator for the wrapper.
 */
extern n00b_result_t(n00b_aws_s3_client_t *)
n00b_aws_s3_client_new(n00b_aws_config_t *cfg) _kargs
{
    bool              force_path_style = false;
    n00b_allocator_t *allocator        = nullptr;
};

/**
 * @brief Get a complete S3 object.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @kw allocator Allocator for the returned object wrapper, body, and strings.
 * @return Ok(object) with copied body/metadata, or an AWS-domain error.
 */
extern n00b_result_t(n00b_aws_s3_object_t *)
n00b_aws_s3_get_object(n00b_aws_s3_client_t *client,
                       n00b_string_t        *bucket,
                       n00b_string_t        *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Get a byte range from an S3 object.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @param offset First byte offset.
 * @param length Number of bytes to request; zero returns an empty object
 *               result without calling the shim.
 * @kw allocator Allocator for the returned object wrapper, body, and strings.
 * @return Ok(object) with copied body/metadata, or an AWS-domain error.
 */
extern n00b_result_t(n00b_aws_s3_object_t *)
n00b_aws_s3_get_object_range(n00b_aws_s3_client_t *client,
                             n00b_string_t        *bucket,
                             n00b_string_t        *key,
                             uint64_t              offset,
                             uint64_t              length) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Put/replace an S3 object.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @param body Object bytes. Empty buffers are allowed for ordinary put.
 * @kw content_type Optional object content type.
 * @return Ok(true), or an AWS-domain error.
 */
extern n00b_result_t(bool)
n00b_aws_s3_put_object(n00b_aws_s3_client_t *client,
                       n00b_string_t        *bucket,
                       n00b_string_t        *key,
                       n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
};

/**
 * @brief Atomic create-only put when the S3-compatible service supports it.
 *
 * Existing objects return `N00B_AWS_ERR_EXISTS`, which the VFS adapter maps to
 * `N00B_VFS_ERR_EXISTS`.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @param body Object bytes. Empty buffers are allowed.
 * @kw content_type Optional object content type.
 * @return Ok(true), or an AWS-domain error.
 */
extern n00b_result_t(bool)
n00b_aws_s3_put_object_if_absent(n00b_aws_s3_client_t *client,
                                 n00b_string_t        *bucket,
                                 n00b_string_t        *key,
                                 n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
};

/**
 * @brief Multipart put with abort-on-failure semantics.
 *
 * @kw content_type Object content type. Optional.
 * @kw part_size    Multipart part size in bytes. Defaults in the C wrapper to
 *                  the S3 VFS part-size default when zero.
 *
 * @post If the upload is created and any part upload or completion fails, the
 *       wrapper attempts `AbortMultipartUpload` before returning the error.
 */
extern n00b_result_t(bool)
n00b_aws_s3_put_object_multipart(n00b_aws_s3_client_t *client,
                                 n00b_string_t        *bucket,
                                 n00b_string_t        *key,
                                 n00b_buffer_t        *body) _kargs
{
    n00b_string_t *content_type = nullptr;
    uint64_t       part_size    = 0;
};

/**
 * @brief Create a multipart upload and return its upload id.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @kw content_type Optional object content type.
 * @kw allocator Allocator for the returned upload-id string.
 * @return Ok(upload id), or an AWS-domain error.
 */
extern n00b_result_t(n00b_string_t *)
n00b_aws_s3_multipart_create(n00b_aws_s3_client_t *client,
                              n00b_string_t        *bucket,
                              n00b_string_t        *key) _kargs
{
    n00b_string_t    *content_type = nullptr;
    n00b_allocator_t *allocator    = nullptr;
};

/**
 * @brief Upload one multipart part.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @param upload_id Upload id from `n00b_aws_s3_multipart_create`.
 * @param part_number 1-based S3 part number.
 * @param body Part bytes.
 * @kw allocator Allocator for the returned part descriptor.
 * @return Ok(completed part descriptor), or an AWS-domain error.
 */
extern n00b_result_t(n00b_aws_s3_completed_part_t *)
n00b_aws_s3_multipart_upload_part(n00b_aws_s3_client_t *client,
                                  n00b_string_t        *bucket,
                                  n00b_string_t        *key,
                                  n00b_string_t        *upload_id,
                                  int32_t               part_number,
                                  n00b_buffer_t        *body) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Complete a multipart upload.
 *
 * @param client Initialized S3 client.
 * @param bucket Bucket name.
 * @param key Object key.
 * @param upload_id Upload id to complete.
 * @param parts Completed parts in ascending S3 part order.
 * @param part_count Number of entries in @p parts.
 * @return Ok(true), or an AWS-domain error.
 */
extern n00b_result_t(bool)
n00b_aws_s3_multipart_complete(n00b_aws_s3_client_t          *client,
                               n00b_string_t                 *bucket,
                               n00b_string_t                 *key,
                               n00b_string_t                 *upload_id,
                               n00b_aws_s3_completed_part_t  *parts,
                               uint32_t                       part_count);

/**
 * @brief Abort a multipart upload.
 *
 * @return Ok(true), or an AWS-domain error.
 */
extern n00b_result_t(bool)
n00b_aws_s3_multipart_abort(n00b_aws_s3_client_t *client,
                            n00b_string_t        *bucket,
                            n00b_string_t        *key,
                            n00b_string_t        *upload_id);

/**
 * @brief Delete one S3 object.
 *
 * @return Ok(true), or an AWS-domain error. Missing objects return
 *         `N00B_AWS_ERR_NOT_FOUND` because the shim heads before deleting.
 */
extern n00b_result_t(bool)
n00b_aws_s3_delete_object(n00b_aws_s3_client_t *client,
                          n00b_string_t        *bucket,
                          n00b_string_t        *key);

/**
 * @brief Retrieve S3 object metadata without the body.
 *
 * @kw allocator Allocator for the returned stat wrapper and strings.
 * @return Ok(stat), or an AWS-domain error.
 */
extern n00b_result_t(n00b_aws_s3_stat_t *)
n00b_aws_s3_head_object(n00b_aws_s3_client_t *client,
                        n00b_string_t        *bucket,
                        n00b_string_t        *key) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief List S3 objects by prefix.
 *
 * @kw continuation Opaque token from a previous truncated result.
 * @kw max_keys Service page size hint; zero lets the SDK choose.
 * @kw allocator Allocator for the returned list, entries, and strings.
 * @return Ok(list result), or an AWS-domain error.
 */
extern n00b_result_t(n00b_aws_s3_list_result_t *)
n00b_aws_s3_list_objects(n00b_aws_s3_client_t *client,
                         n00b_string_t        *bucket,
                         n00b_string_t        *prefix) _kargs
{
    n00b_string_t    *continuation = nullptr;
    uint32_t          max_keys     = 0;
    n00b_allocator_t *allocator    = nullptr;
};

/**
 * @brief Wrap @p client as a generic S3-compatible VFS client.
 *
 * The returned wrapper borrows @p client; keep the AWS client alive at least as
 * long as any backend using the wrapper.
 */
extern n00b_result_t(n00b_vfs_s3_client_t *)
n00b_aws_s3_vfs_client_new(n00b_aws_s3_client_t *client) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief One-call S3 VFS backend constructor with production defaults.
 *
 * Uses the SDK credential/region chain from @p cfg, virtual-hosted addressing
 * by default, `application/octet-stream` content type by default, and the
 * generic S3 VFS backend for path normalization/range/list contracts.
 */
extern n00b_result_t(n00b_vfs_backend_t *)
n00b_aws_s3_vfs_backend_new(n00b_aws_config_t *cfg,
                            n00b_string_t     *bucket) _kargs
{
    n00b_string_t    *prefix           = nullptr;
    n00b_string_t    *content_type     = nullptr;
    bool              force_path_style = false;
    uint64_t          multipart_threshold = 0;
    uint64_t          multipart_part_size = 0;
    n00b_allocator_t *allocator        = nullptr;
};

#ifdef __cplusplus
}
#endif
