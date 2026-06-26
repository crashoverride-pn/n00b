/**
 * @file gc_baked.h
 * @brief GC registration for baked object images.
 */
#pragma once

#include "n00b.h"
// Full codegen-ABI descriptor definitions: uses the N00B_STATIC_OBJECT_F_BAKED
// enum constant and the n00b_static_identity_t layout.
#include "core/codegen_abi_inject.h"
#include "adt/result.h"

typedef enum : n00b_err_t {
    /** Invalid region descriptor, image bounds, or allocation record. */
    N00B_GC_BAKED_ERR_ARG = -300,
    /** The relocated marshal stream could not be decoded for GC metadata. */
    N00B_GC_BAKED_ERR_MARSHAL,
    /** A baked-image mmap or allocation range could not be registered. */
    N00B_GC_BAKED_ERR_RANGE,
    /** A baked allocation contains a pointer to mutable runtime memory. */
    N00B_GC_BAKED_ERR_EXTERNAL_POINTER,
} n00b_gc_baked_err_t;

/**
 * @brief Descriptor for a comptime image that has been relocated.
 *
 * @field base           Start address of the mapped image.
 * @field len            Total mapped image length.
 * @field marshal_stream Start address of the relocated payload-front marshal
 *                       stream inside @p base.
 * @field marshal_len    Length of the marshal stream.
 * @field root           Root object pointer returned by image relocation.
 * @field root_identity  Optional static identity to attach to the root
 *                       allocation's baked range.
 * @field writable       True for a mutable baked region whose pointer slots are
 *                       scanned and updated as GC roots.
 */
typedef struct {
    void                         *base;
    size_t                        len;
    void                         *marshal_stream;
    size_t                        marshal_len;
    void                         *root;
    const n00b_static_identity_t *root_identity;
    bool                          writable;
} n00b_gc_baked_region_t;

/**
 * @brief Return a human-readable description for a baked-GC error.
 *
 * @param err Error code returned by the baked-GC registration API.
 * @return    Static n00b string describing @p err.
 */
extern n00b_string_t *n00b_gc_baked_err_str(n00b_err_t err);

/**
 * @brief Register every allocation in a relocated comptime image as baked.
 *
 * Baked allocations are treated as read-only static objects: the collector may
 * scan them, but it never moves them or writes forwarded pointers into them.
 *
 * @param region Relocated image and marshal-stream descriptor.
 * @return       Ok(true) when the image is registered, or Err.
 *
 * @pre @p region describes a complete comptime image after in-place
 *      relocation.
 * @post All allocation records in the image have static range descriptors with
 *       @ref N00B_STATIC_OBJECT_F_BAKED.
 */
extern n00b_result_t(bool)
n00b_gc_register_baked_region(const n00b_gc_baked_region_t *region);

/**
 * @brief Register every allocation in a relocated writable comptime image.
 *
 * @param region Relocated image and marshal-stream descriptor.
 * @return       Ok(true) when the image is registered, or Err.
 *
 * @pre @p region describes a complete writable comptime image after in-place
 *      relocation.
 * @post Baked allocations remain pinned and their pointer-bearing words are
 *       registered as GC roots so heap pointers stored there are followed and
 *       rewritten during collection.
 */
extern n00b_result_t(bool)
n00b_gc_register_baked_region_writable(const n00b_gc_baked_region_t *region);

/**
 * @brief Test whether an address lies inside a registered baked allocation.
 *
 * @param addr Candidate address.
 * @return     true when @p addr resolves to a baked static range.
 */
extern bool n00b_gc_addr_in_baked_region(void *addr);
