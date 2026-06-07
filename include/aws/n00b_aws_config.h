/**
 * @file aws/n00b_aws_config.h
 * @brief libn00b_aws configuration: region, endpoint, credentials.
 *
 * `n00b_aws_config_t` is an opaque GC-managed wrapper around the
 * aws-sdk-rust `SdkConfig` constructed inside the shim. The Rust
 * handle is freed when the n00b GC reclaims the wrapper via the
 * finalizer wired in `n00b_aws_config(...)`.
 *
 * Default resolution chain (inherited from aws-sdk-rust):
 *   1. Env vars (`AWS_REGION`, `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/
 *      `AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`).
 *   2. AWS profile file (`~/.aws/config`).
 *   3. EKS / IRSA web-identity token + STS AssumeRoleWithWebIdentity.
 *   4. EC2 IMDS / ECS task role.
 *
 * Override region and endpoint via the `_kargs` keyword arguments.
 * Credentials are not exposed as a kwarg — every consumer should use
 * the chain. Manual credential injection arrives when an explicit
 * use case lands.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct n00b_aws_config_t n00b_aws_config_t;

/**
 * @brief Build a libn00b_aws configuration.
 *
 * `region` is the only required argument. Pass nullptr to inherit
 * the SDK's region resolution chain (env / profile / IMDS). ncc
 * does not support `_kargs` on zero-positional-arg signatures, so
 * region travels positional.
 *
 * @param region               Region name (e.g. r"us-east-1") or
 *                             nullptr to inherit the SDK chain.
 * @kw endpoint_override       Optional URL override (LocalStack /
 *                             VPC endpoint). nullptr = SDK default.
 * @kw allocator               Override n00b's default allocator.
 *                             nullptr keeps the default arena.
 * @return Ok(configured handle), or `N00B_AWS_ERR_INTERNAL` when the
 *         Rust shim cannot build the SDK config.
 * @post On success, the returned config owns the Rust shim handle and
 *       releases it from a GC finalizer.
 */
extern n00b_result_t(n00b_aws_config_t *)
n00b_aws_config(n00b_string_t *region) _kargs {
    n00b_string_t    *endpoint_override = nullptr;
    n00b_allocator_t *allocator         = nullptr;
};

#ifdef __cplusplus
}
#endif
