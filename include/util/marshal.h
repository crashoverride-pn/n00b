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
// Single, unshipped wire format: there is no version history to stay compatible
// with, so this is 1 and the reader accepts only this exact version.
#define N00B_MARSHAL_VERSION 1u

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

/**
 * @brief Allocation metadata decoded from a relocated marshal stream.
 *
 * @field start                 Absolute start address of the allocation.
 * @field len                   Allocation length in bytes.
 * @field tinfo                 Type metadata emitted for the allocation.
 * @field ptr_words             Pointer-word count from the allocation record.
 * @field ptr_words_known       Whether @p ptr_words was explicitly recorded.
 * @field scan_kind             GC scan policy recorded for the allocation.
 * @field no_scan               Legacy no-scan bit from the allocation record.
 * @field cached_hash           Pointer-key hash carried from allocation metadata.
 * @field callback_bitmap       Scratch bitmap for built-in callback scans.
 * @field callback_bitmap_words Number of words in @p callback_bitmap.
 */
typedef struct {
    void                  *start;
    size_t                 len;
    n00b_alloc_type_info_t tinfo;
    uint32_t               ptr_words;
    bool                   ptr_words_known;
    n00b_gc_scan_kind_t    scan_kind;
    bool                   no_scan;
    n00b_uint128_t         cached_hash;
    const uint64_t        *callback_bitmap;
    uint64_t               callback_bitmap_words;
} n00b_marshal_relocated_alloc_t;

/**
 * @brief Visitor for relocated marshal allocation metadata.
 *
 * @param alloc Decoded allocation metadata for one relocated object.
 * @param user  Caller-supplied visitor context.
 * @return      Ok(true) to continue, Ok(false) to stop, or Err.
 */
typedef n00b_result_t(bool) (*n00b_marshal_relocated_alloc_visit_fn)(
    const n00b_marshal_relocated_alloc_t *alloc,
    void                                *user);

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
 
/**
 * @brief Relocate a payload-front marshal stream in place.
  *
  * @param ctx         Unmarshal context used for diagnostics and scratch state.
  * @param stream_base Start of the writable marshal stream bytes.
  * @param stream_len  Length of the marshal stream.
 * @return            Ok(root pointer inside @p stream_base), or Err.
  *
  * @pre @p stream_base is a complete marshal stream using payload-front layout
  *      (marshal version 4 or newer).
  * @post Virtual intra-stream pointers have been rewritten to absolute addresses
  *       inside @p stream_base. Static and function pointer patch records have
  *       been applied using the normal unmarshal rebinding rules.
 */
extern n00b_result_t(void *)
n00b_unmarshal_relocate_inplace(n00b_unmarshal_ctx_t *ctx,
                                void                 *stream_base,
                                size_t                stream_len);

/**
 * @brief Resolve all currently pending portable static patch fixups.
 *
 * @return Ok(true) if every pending patch resolved, Ok(false) if at least one
 *         target identity is still missing, or Err when a now-present target
 *         fails validation.
 *
 * Pending patches are created by in-place relocation when a PSPATCH target has
 * not been registered yet. This supports order-independent cross-image baked
 * references: registering the later image should make its identity visible, then
 * this pass updates earlier image slots in place.
 *
 * @pre The n00b runtime is initialized.
 * @post Every resolvable pending patch slot has been updated in place and
 *       removed from the runtime pending-patch registry.
 */
extern n00b_result_t(bool) n00b_marshal_apply_deferred_static_patches(void);

/**
 * @brief Count currently unresolved portable static patch fixups.
 *
 * @return Number of unresolved portable static patch fixups in the runtime
 *         pending-patch registry.
 *
 * @pre The n00b runtime is initialized.
 * @post The pending-patch registry is unchanged.
 */
extern size_t n00b_marshal_deferred_static_patch_count(void);
 
/**
 * @brief Visit allocation records in a relocated payload-front marshal stream.
 *
 * @param stream_base Start of the relocated marshal stream.
 * @param stream_len  Length of the marshal stream.
 * @param visit       Callback invoked once per allocation record.
 * @param user        Opaque callback context.
 * @return            Ok(true) after all allocation records are visited, or Err.
 *
 * @pre @p stream_base is a complete payload-front marshal stream that has
 *      already been relocated in place.
 * @post The visitor receives absolute object addresses inside @p stream_base
 *       and the scan metadata required to register those objects with the GC.
 */
extern n00b_result_t(bool)
n00b_marshal_visit_relocated_allocs(void *stream_base,
                                    size_t stream_len,
                                    n00b_marshal_relocated_alloc_visit_fn visit,
                                    void *user);

/**
 * @brief Validate that a marshal stream uses only comptime-image portable
 *        relocation forms.
  *
  * @return Ok(true) for a stream that can be embedded in a cross-process
  *         comptime image, Ok(false) for a well-formed stream that contains
  *         absolute static patches, or Err(N00B_MARSHAL_ERR_*) for malformed
  *         streams.
 */
extern n00b_result_t(bool)
n00b_marshal_stream_is_comptime_portable(n00b_buffer_t *stream);
