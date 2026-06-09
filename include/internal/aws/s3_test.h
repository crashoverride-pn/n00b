/**
 * @file internal/aws/s3_test.h
 * @brief Internal no-network test hooks for the libn00b_aws S3 adapter.
 *
 * These hooks exercise C-side conversion and error-mapping logic without
 * calling the Rust AWS SDK or requiring a live S3 endpoint. They are not a
 * public libn00b_aws API.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "aws/n00b_aws.h"
#include "vfs/types.h"

extern n00b_aws_s3_object_t *
n00b_aws_s3_test_object_from_raw(uint8_t          *data,
                                 size_t            data_len,
                                 uint64_t          content_length,
                                 int64_t           last_modified_ms,
                                 char             *etag,
                                 char             *content_type,
                                 n00b_allocator_t *allocator);

extern n00b_aws_s3_stat_t *
n00b_aws_s3_test_stat_from_raw(uint64_t          content_length,
                               int64_t           last_modified_ms,
                               char             *etag,
                               char             *content_type,
                               n00b_allocator_t *allocator);

extern n00b_aws_s3_list_result_t *
n00b_aws_s3_test_list_from_raw(n00b_allocator_t *allocator);

extern n00b_err_t
n00b_aws_s3_test_vfs_error(n00b_aws_status_t status);
