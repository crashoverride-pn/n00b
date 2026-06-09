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

/** @brief Global optional holding the default runtime instance. */
extern n00b_option_t(n00b_runtime_t *) n00b_default_runtime;

/**
 * @brief Get the current runtime (asserts if uninitialized).
 * @return Pointer to the active n00b_runtime_t.
 * @pre `n00b_init()` has been called.
 */
[[n00b::nogc]] static inline n00b_runtime_t *
n00b_get_runtime(void)
{
    return n00b_option_get(n00b_default_runtime);
}
