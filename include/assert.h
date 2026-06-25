#pragma once

/*
 * glibc's C23 assert macro copies the expression into an unevaluated sizeof
 * check. ncc lowers _kargs calls in the evaluated expression but leaves that
 * sizeof copy untouched, so calls such as r"x" can fail
 * to compile inside assert(). Keep the standard failure path while evaluating
 * the expression only once.
 */
#include_next <assert.h>

#if !defined(NDEBUG) && defined(N00B_NCC_GLIBC_ASSERT_SHIM) && defined(__GLIBC__)
#undef assert
#define assert(expr)                                                           \
    ((expr) ? (void)0                                                          \
            : __assert_fail(#expr, __FILE__, __LINE__,                         \
                            __extension__ __PRETTY_FUNCTION__))
#endif
