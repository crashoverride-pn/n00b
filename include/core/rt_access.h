/**
 * @file rt_access.h
 * @brief Runtime accessor for keyword-argument defaults.
 *
 * Provides the `n00b_get_runtime()` accessor and the global
 * `n00b_default_runtime` option, extracted from `runtime.h` so that
 * headers needing only the accessor (for `_kargs` defaults) avoid
 * pulling in the full runtime definition.
 */
#pragma once

#include "n00b.h"
#include "adt/option.h"

/**
 * @brief Raw control word holding the default runtime pointer.
 *
 * Kept as an integer rather than an `n00b_runtime_t *` option so the compiler's
 * static-root/marshal machinery never treats the runtime control pointer as a
 * heap root to rewrite.
 */
extern uintptr_t n00b_default_runtime_bits;

[[n00b::nogc]] static inline bool
n00b_default_runtime_is_set(void)
{
    return n00b_default_runtime_bits != 0;
}

[[n00b::nogc]] static inline n00b_runtime_t *
n00b_default_runtime_or_null(void)
{
    return (n00b_runtime_t *)(uintptr_t)n00b_default_runtime_bits;
}

[[n00b::nogc]] static inline void
n00b_set_default_runtime(n00b_runtime_t *rt)
{
    n00b_default_runtime_bits = (uintptr_t)rt;
}

[[n00b::nogc]] static inline void
n00b_clear_default_runtime(void)
{
    n00b_default_runtime_bits = 0;
}

/**
 * @brief Get the current runtime (asserts if uninitialized).
 * @return Pointer to the active n00b_runtime_t.
 * @pre `n00b_init()` has been called.
 */
[[n00b::nogc]] static inline n00b_runtime_t *
n00b_get_runtime(void)
{
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    assert(rt);
    return rt;
}
