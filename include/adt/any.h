#pragma once

#include <stdint.h>

/**
 * @file any.h
 * @brief Boxed `any` type for dynamically-typed values.
 *
 * `n00b_any_t` pairs a `typehash()` tag with a value union.
 * Scalar types (integers, floats, bools) use `int_contents`;
 * heap types (strings, containers) use `ref_contents`.
 */

typedef struct {
    uint64_t type_hash;
    union [[n00b::raw_union]] {
        int64_t int_contents;
        void   *ref_contents;
    } contents;
} n00b_any_t;

/**
 * @brief Box a scalar (word-sized) value.
 */
static inline n00b_any_t
n00b_any_box_int(uint64_t type_hash, int64_t value)
{
    return (n00b_any_t){
        .type_hash = type_hash,
        .contents  = {.int_contents = value},
    };
}

/**
 * @brief Box a pointer (heap object) value.
 */
static inline n00b_any_t
n00b_any_box_ref(uint64_t type_hash, void *value)
{
    return (n00b_any_t){
        .type_hash = type_hash,
        .contents  = {.ref_contents = value},
    };
}

/**
 * @brief Unbox to scalar.  Caller must verify type_hash first.
 */
static inline int64_t
n00b_any_unbox_int(n00b_any_t any)
{
    return any.contents.int_contents;
}

/**
 * @brief Unbox to pointer.  Caller must verify type_hash first.
 */
static inline void *
n00b_any_unbox_ref(n00b_any_t any)
{
    return any.contents.ref_contents;
}
