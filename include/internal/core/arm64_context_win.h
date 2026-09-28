#pragma once

/**
 * @file arm64_context_win.h
 * @brief Read x0..x30 out of a Windows arm64 CONTEXT (internal).
 *
 * Shared by the crash capture path and the stop-the-world suspend path, which
 * both get a CONTEXT from GetThreadContext() or an exception record.
 */

#include "core/platform.h"

#if defined(_WIN32) && (defined(_M_ARM64) || defined(__aarch64__))

// CONTEXT.X[] covers x0..x28; x29 and x30 are the named Fp and Lr members.
static inline void
n00b_arm64_context_gprs(const CONTEXT *ctx, uint64_t x[31])
{
    for (int i = 0; i < 29; i++) {
        x[i] = (uint64_t)ctx->X[i];
    }
    x[29] = (uint64_t)ctx->Fp;
    x[30] = (uint64_t)ctx->Lr;
}

#endif
