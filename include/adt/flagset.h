/**
 * @file flagset.h
 * @brief Dynamic bit-backed flag set.
 */
#pragma once

#include "n00b.h"
#include "core/alloc.h"

#include <stdint.h>

typedef struct n00b_flagset_t {
    uint64_t         *contents;
    uint64_t          num_flags;
    uint64_t          alloc_wordlen;
    n00b_allocator_t *allocator;
} n00b_flagset_t;

extern n00b_flagset_t *
n00b_flagset_new() _kargs
{
    uint64_t          length    = 64;
    n00b_allocator_t *allocator = nullptr;
};

extern void
n00b_flagset_init(n00b_flagset_t *self) _kargs
{
    uint64_t          length    = 64;
    n00b_allocator_t *allocator = nullptr;
};

extern n00b_flagset_t *n00b_flagset_copy(const n00b_flagset_t *self);
extern n00b_flagset_t *n00b_flagset_invert(const n00b_flagset_t *self);
extern n00b_flagset_t *n00b_flagset_add(const n00b_flagset_t *self,
                                        const n00b_flagset_t *with);
extern n00b_flagset_t *n00b_flagset_sub(const n00b_flagset_t *self,
                                        const n00b_flagset_t *with);
extern n00b_flagset_t *n00b_flagset_test(const n00b_flagset_t *self,
                                         const n00b_flagset_t *with);
extern n00b_flagset_t *n00b_flagset_xor(const n00b_flagset_t *self,
                                        const n00b_flagset_t *with);
extern bool            n00b_flagset_eq(const n00b_flagset_t *self,
                                       const n00b_flagset_t *other);
extern uint64_t        n00b_flagset_len(const n00b_flagset_t *self);
extern bool            n00b_flagset_index(n00b_flagset_t *self, int64_t index);
extern void            n00b_flagset_set_index(n00b_flagset_t *self,
                                              int64_t          index,
                                              bool             value);
extern uint64_t        n00b_flagset_count(const n00b_flagset_t *self);

extern bool
n00b_flagset_next_set(const n00b_flagset_t *self,
                      uint64_t              after,
                      uint64_t             *out_index);
