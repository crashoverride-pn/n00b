#pragma once

// CHECK(expr) aborts the test with the failing expression, file, and line
// when expr is false. It stays active in release builds, unlike assert().

#include "util/assert.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)
