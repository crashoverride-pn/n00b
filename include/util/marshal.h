/**
 * @file marshal.h
 * @brief Incremental object graph marshal/unmarshal support.
 */
#pragma once

#include "n00b.h"
#include "adt/list.h"
#include "core/arena.h"
#include "core/buffer.h"

#define N00B_MARSHAL_MAGIC   UINT64_C(0xee1cbab01ac0cac0)
#define N00B_MARSHAL_VERSION 4u

typedef enum {
    N00B_MARSHAL_OK = 0,
    N00B_MARSHAL_ERR_NULL_ARG,
    N00B_MARSHAL_ERR_UNSUPPORTED_ALLOCATION,
    N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_POLICY,
    N00B_MARSHAL_ERR_UNSUPPORTED_SCAN_CALLBACK,
    N00B_MARSHAL_ERR_UNSUPPORTED_STATIC_POINTER,
    N00B_MARSHAL_ERR_BAD_STREAM,
    N00B_MARSHAL_ERR_INCOMPLETE_STREAM,
    N00B_MARSHAL_ERR_CONTEXT_CLOSED,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_MISSING,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_DUPLICATE,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_MUTABILITY,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_TYPE,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_SCAN,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_LENGTH,
    N00B_MARSHAL_ERR_STATIC_IDENTITY_CHECK_BYTES,
    N00B_MARSHAL_ERR_LIMIT,
} n00b_marshal_status_t;

enum n00b_marshal_flags_t : uint32_t {
    N00B_MARSHAL_F_NONE = 0,
    N00B_MARSHAL_F_STW  = 1u << 0,
};

typedef enum n00b_marshal_flags_t n00b_marshal_flags_t;

typedef struct n00b_marshal_ctx_t   n00b_marshal_ctx_t;
typedef struct n00b_unmarshal_ctx_t n00b_unmarshal_ctx_t;

// Standalone accessor: human-readable name for a marshal status code,
// independent of any live context.  Returns an n00b r-string literal so
// callers can pass it straight to n00b_print / n00b_eprintf.  Use this
// when you have a status code but no context (e.g., after the context
// has been destroyed, or for logging enum values directly).
extern n00b_string_t *n00b_marshal_status_name(n00b_marshal_status_t code);

extern n00b_marshal_ctx_t *n00b_marshal_ctx_new() _kargs
{
    uint32_t flags        = N00B_MARSHAL_F_NONE;
    uint32_t base_address = 0;
};
extern void n00b_marshal_ctx_destroy(n00b_marshal_ctx_t *ctx);
extern n00b_marshal_status_t n00b_marshal_ctx_status(n00b_marshal_ctx_t *ctx);
extern n00b_string_t *n00b_marshal_ctx_error(n00b_marshal_ctx_t *ctx);

extern n00b_buffer_t *n00b_marshal_incremental(n00b_marshal_ctx_t *ctx,
                                               void               *addr) _kargs
{
    bool close = true;
};
extern n00b_buffer_t *n00b_marshal(void *addr) _kargs
{
    uint32_t          flags        = N00B_MARSHAL_F_NONE;
    uint32_t          base_address = 0;
};

extern n00b_unmarshal_ctx_t *n00b_unmarshal_ctx_new() _kargs
{
    n00b_arena_t *target_arena = nullptr;
};
extern void n00b_unmarshal_ctx_destroy(n00b_unmarshal_ctx_t *ctx);
extern n00b_marshal_status_t n00b_unmarshal_ctx_status(n00b_unmarshal_ctx_t *ctx);
extern n00b_string_t *n00b_unmarshal_ctx_error(n00b_unmarshal_ctx_t *ctx);

extern n00b_list_t(void *) n00b_unmarshal_incremental(n00b_unmarshal_ctx_t *ctx,
                                                      n00b_buffer_t        *chunk);
extern n00b_list_t(void *) n00b_unmarshal(n00b_buffer_t *buf) _kargs
{
    n00b_arena_t *target_arena = nullptr;
};
extern void *n00b_unmarshal_one(n00b_buffer_t *buf) _kargs
{
    n00b_arena_t *target_arena = nullptr;
};
