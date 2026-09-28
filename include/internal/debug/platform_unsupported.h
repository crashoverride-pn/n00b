#pragma once

/**
 * @file platform_unsupported.h
 * @brief Debug backend for an OS/arch pair with no hardware debug support.
 *
 * Defines every platform.h entry point except n00b_debug_plat_is_attached()
 * so that each one reports N00B_DEBUG_ERR_UNSUPPORTED. A platform file
 * includes this, once, under its own arch gate.
 */

#include "internal/debug/platform.h"

n00b_debug_err_t
n00b_debug_plat_init(void)
{
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_watch_set(int32_t slot, void *addr, int32_t size,
                          n00b_debug_watch_kind_t kind)
{
    (void)slot; (void)addr; (void)size; (void)kind;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_watch_clear(int32_t slot)
{
    (void)slot;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_break_set(int32_t slot, void *addr)
{
    (void)slot; (void)addr;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

n00b_debug_err_t
n00b_debug_plat_break_clear(int32_t slot)
{
    (void)slot;
    return N00B_DEBUG_ERR_UNSUPPORTED;
}

void
n00b_debug_plat_enroll_self(void)
{
}
