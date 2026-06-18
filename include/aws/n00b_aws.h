/**
 * @file aws/n00b_aws.h
 * @brief Public umbrella for libn00b_aws.
 *
 * libn00b_aws is the n00b-idiomatic wrap over `n00b-aws-shim`, a
 * Rust cdylib that re-exports aws-sdk-rust operations as
 * `extern "C"`. See [[project_n00b_aws_via_rust_shim]] in the SKP
 * auto-memory for why we use aws-sdk-rust instead of aws-sdk-cpp.
 *
 * Build it with `-Denable_aws=true` (or `N00B_BUILD_AWS=1` to
 * `build.sh`). Programs that don't use AWS pay zero build cost.
 *
 * Coverage rule: every public Operation in each service's Smithy
 * model has a wrapper here, including the long tail. The first
 * service in is STS — see `<aws/n00b_aws_sts.h>` for the surface.
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "adt/result.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes mirrored from the Rust shim's `N00bAwsShimStatus`.
 * The integer values MUST stay in lock-step with
 * `subprojects/n00b-aws-shim/src/lib.rs::N00bAwsShimStatus`. */
typedef enum {
    N00B_AWS_OK                 = 0,
    N00B_AWS_ERR_INVALID_ARG    = -1,
    N00B_AWS_ERR_NOT_INITIALIZED = -2,
    N00B_AWS_ERR_NO_CREDENTIALS = -3,
    N00B_AWS_ERR_AUTHZ          = -4,
    N00B_AWS_ERR_NOT_FOUND      = -5,
    N00B_AWS_ERR_THROTTLED      = -6,
    N00B_AWS_ERR_TIMEOUT        = -7,
    N00B_AWS_ERR_NETWORK        = -8,
    N00B_AWS_ERR_SERVICE        = -9,
    N00B_AWS_ERR_CLIENT         = -10,
    N00B_AWS_ERR_INTERNAL       = -11,
    N00B_AWS_ERR_EXISTS         = -12,
} n00b_aws_status_t;

/** @brief Static debug string for an `n00b_aws_status_t` code. */
extern const char *n00b_aws_status_str(n00b_aws_status_t status);

/* Forward declaration; the full type lives in <aws/n00b_aws_config.h>. */
typedef struct n00b_aws_config_t n00b_aws_config_t;

#ifdef __cplusplus
}
#endif

#include "aws/n00b_aws_config.h"
#include "aws/n00b_aws_dynamodb.h"
#include "aws/n00b_aws_s3.h"
#include "aws/n00b_aws_sns.h"
#include "aws/n00b_aws_sqs.h"
#include "aws/n00b_aws_sts.h"
