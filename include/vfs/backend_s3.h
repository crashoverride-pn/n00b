/**
 * @file backend_s3.h
 * @brief S3-compatible object-store backend for VFS.
 *
 * The backend is implemented over a small client operation table rather than
 * directly over the AWS shim. This keeps the VFS object-store semantics
 * testable without network access while letting libn00b_aws provide the real
 * S3 client in AWS-enabled builds.
 */
#pragma once

#include "vfs/backend.h"

typedef struct n00b_vfs_s3_client     n00b_vfs_s3_client_t;
typedef struct n00b_vfs_s3_client_ops n00b_vfs_s3_client_ops_t;

/**
 * @brief Client operation table consumed by the S3 VFS backend.
 *
 * All paths are bucket keys after the backend prefix has been applied. Client
 * implementations return VFS-domain errors so the backend does not need to
 * understand AWS- or test-client-specific status codes.
 */
struct n00b_vfs_s3_client_ops {
    n00b_string_t *(*name)(void *ctx);

    n00b_result_t(n00b_buffer_t *) (*get)(void             *ctx,
                                           n00b_string_t    *bucket,
                                           n00b_string_t    *key,
                                           n00b_allocator_t *allocator);

    n00b_result_t(n00b_buffer_t *) (*get_range)(void             *ctx,
                                                 n00b_string_t    *bucket,
                                                 n00b_string_t    *key,
                                                 uint64_t          offset,
                                                 uint64_t          length,
                                                 n00b_allocator_t *allocator);

    n00b_result_t(bool) (*put)(void          *ctx,
                                n00b_string_t *bucket,
                                n00b_string_t *key,
                                n00b_buffer_t *data,
                                n00b_string_t *content_type);

    n00b_result_t(bool) (*put_if_absent)(void          *ctx,
                                          n00b_string_t *bucket,
                                          n00b_string_t *key,
                                          n00b_buffer_t *data,
                                          n00b_string_t *content_type);

    /**
     * Optional multipart put path for large objects.
     *
     * Implementations that start a multipart upload must abort it before
     * returning an error from this call. When null, the backend falls back to
     * ordinary `put` for every object size.
     */
    n00b_result_t(bool) (*put_multipart)(void          *ctx,
                                          n00b_string_t *bucket,
                                          n00b_string_t *key,
                                          n00b_buffer_t *data,
                                          n00b_string_t *content_type,
                                          uint64_t       part_size);

    n00b_result_t(bool) (*del)(void          *ctx,
                                n00b_string_t *bucket,
                                n00b_string_t *key);

    n00b_result_t(n00b_vfs_obj_stat_t) (*stat)(void          *ctx,
                                                n00b_string_t *bucket,
                                                n00b_string_t *key);

    n00b_result_t(n00b_vfs_list_result_t *) (*list)(
        void             *ctx,
        n00b_string_t    *bucket,
        n00b_string_t    *prefix,
        n00b_string_t    *continuation,
        uint32_t          max_keys,
        n00b_allocator_t *allocator);
};

/**
 * @brief Configured S3-compatible object client.
 *
 * The backend borrows this handle. The caller owns @c ctx and any teardown
 * policy associated with it.
 */
struct n00b_vfs_s3_client {
    const n00b_vfs_s3_client_ops_t *ops;
    void                           *ctx;
    n00b_allocator_t               *allocator;
};

/**
 * @brief Construct an S3-compatible client wrapper over @p ops and @p ctx.
 *
 * @kw allocator Allocator for the wrapper object.
 * @return Ok(client) when @p ops has the required core object methods.
 */
extern n00b_result_t(n00b_vfs_s3_client_t *)
n00b_vfs_s3_client_new(const n00b_vfs_s3_client_ops_t *ops,
                       void                           *ctx) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Create an S3-compatible VFS backend.
 *
 * @param client Client operation table wrapper. Borrowed by the backend.
 * @param bucket Bucket name for all backend operations.
 *
 * @kw prefix       Optional key prefix for this backend root.
 * @kw content_type Content type for newly-written objects. Defaults to
 *                  @c application/octet-stream.
 * @kw multipart_threshold Object size at or above which the backend uses
 *                         @c put_multipart when the client supplies it.
 *                         Defaults to a production-safe S3 threshold.
 * @kw multipart_part_size Size for each multipart upload part. Defaults to a
 *                         production-safe S3 part size.
 * @kw allocator    Allocator for backend state.
 *
 * @return Initialized backend, or a VFS-domain error.
 */
extern n00b_result_t(n00b_vfs_backend_t *)
n00b_vfs_backend_s3_new(n00b_vfs_s3_client_t *client,
                        n00b_string_t        *bucket) _kargs
{
    n00b_string_t    *prefix       = nullptr;
    n00b_string_t    *content_type = nullptr;
    uint64_t          multipart_threshold = 0;
    uint64_t          multipart_part_size = 0;
    n00b_allocator_t *allocator    = nullptr;
};

/** @brief The vtable for the S3-compatible backend. */
extern const n00b_vfs_backend_ops_t n00b_vfs_backend_s3_ops;
