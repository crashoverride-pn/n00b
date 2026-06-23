/**
 * @file comptime_image.h
 * @brief Offset-relocatable comptime object image support.
 */
#pragma once

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/buffer.h"

#define N00B_CT_IMAGE_MAGIC   UINT64_C(0x6e30306263746d67)
#define N00B_CT_IMAGE_VERSION 1u

#define N00B_CT_IMAGE_FLAG_WRITABLE      UINT32_C(0x01)
#define N00B_CT_IMAGE_FLAG_ROOT_IDENTITY UINT32_C(0x02)

#define N00B_CT_IMAGE_ROOT_IDENTITY_MAGIC UINT32_C(0x63746964)

typedef enum {
    N00B_CT_IMAGE_OK = 0,
    N00B_CT_IMAGE_ERR_NULL_ARG = -260,
    N00B_CT_IMAGE_ERR_BAD_HEADER,
    N00B_CT_IMAGE_ERR_BAD_ABI,
    N00B_CT_IMAGE_ERR_UNSUPPORTED_ROOTS,
    N00B_CT_IMAGE_ERR_MARSHAL,
    N00B_CT_IMAGE_ERR_LIMIT,
    N00B_CT_IMAGE_ERR_NONPORTABLE,
} n00b_ct_image_status_t;

typedef struct {
    uint64_t magic;
    uint16_t version;
    uint16_t abi_tag;
    uint32_t marshal_off;
    uint32_t marshal_len;
    uint32_t root_count;
    uint32_t flags;
} n00b_ct_image_header_t;

typedef struct {
    uint32_t record_magic;
    uint32_t record_len;
    uint32_t identity_version;
    uint32_t identity_kind;
    uint32_t namespace_len;
    uint32_t key_len;
    uint32_t reserved;
    uint32_t reserved2;
} n00b_ct_image_root_identity_record_t;

/**
 * @brief Optional post-relocation repair callback for a comptime image.
 *
 * @param image_base Start of the relocated image bytes.
 * @param image_len  Length of the image region.
 * @param root       Relocated root pointer inside @p image_base.
 * @param user       Caller-supplied hook context.
 * @return           Ok(true) on success, or Err.
 *
 * @pre The image has already been relocated in place.
 * @post Consumer-specific pointers may be repaired before CRT registration.
 */
typedef n00b_result_t(bool) (*n00b_ct_image_repair_fn_t)(void *image_base,
                                                         size_t image_len,
                                                         void *root,
                                                         void *user);

typedef struct {
    n00b_ct_image_repair_fn_t fn;
    void                     *user;
} n00b_ct_image_repair_hook_t;

extern uint16_t n00b_ct_image_host_abi_tag(void);
extern n00b_string_t *n00b_ct_image_status_name(n00b_ct_image_status_t code);

/**
 * @brief Marshal a comptime root graph into an offset-relocatable image.
 *
 * @param root  Root object to bake. Image format version 1 supports exactly
 *              one root.
 * @return      Ok(header-prefixed image bytes), or Err.
 *
 * @pre The n00b runtime is initialized.
 * @pre Host and target ABI are identical; cross-target guard enforcement is WP-004.
 * @post The returned buffer starts with @ref n00b_ct_image_header_t and contains
 *       an unchanged n00b marshal stream at @c header.marshal_off.
 */
extern n00b_result_t(n00b_buffer_t *) n00b_ct_image_export(void *root) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Marshal a root graph into a writable comptime image.
 *
 * @param root Root object to bake.
 * @kw allocator Optional allocator for exported image bytes (nullptr = runtime default).
 * @return     Ok(header-prefixed image bytes with
 *             @ref N00B_CT_IMAGE_FLAG_WRITABLE set), or Err.
 *
 * @pre The n00b runtime is initialized.
 * @pre Host and target ABI are identical; cross-target guard enforcement is WP-004.
 * @post The returned buffer starts with @ref n00b_ct_image_header_t and contains
 *       a marshal stream whose baked region must remain writable after CRT apply.
 */
extern n00b_result_t(n00b_buffer_t *) n00b_ct_image_export_writable(void *root) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Relocate an offset image in place.
 *
 * @param image_base Start of the writable mapped image bytes.
 * @param image_len  Length of the image region.
 * @return           Ok(relocated root pointer inside @p image_base), or Err.
 *
 * @pre The n00b runtime is initialized.
 * @pre @p image_base points to writable image bytes. The caller may mark the
 *      region read-only after this function returns successfully.
 * @post Internal marshal virtual pointers have been rewritten to absolute
 *       addresses inside @p image_base, and static/function patches are rebound.
 */
extern n00b_result_t(void *) n00b_ct_image_relocate_inplace(void *image_base,
                                                            size_t image_len);

/**
 * @brief Relocate an offset image and invoke an optional repair hook.
 *
 * @param image_base  Start of the writable mapped image bytes.
 * @param image_len   Length of the image region.
 * @param repair_hook Optional post-relocation repair hook.
 * @return            Ok(relocated root pointer inside @p image_base), or Err.
 *
 * @pre The n00b runtime is initialized.
 * @post Internal pointers have been relocated and @p repair_hook has been
 *       invoked exactly once when supplied with a non-null function.
 */
extern n00b_result_t(void *)
n00b_ct_image_relocate_inplace_ex(void *image_base,
                                  size_t image_len,
                                  const n00b_ct_image_repair_hook_t *repair_hook);

/**
 * @brief Register or replace a repair hook for one image mapping.
 *
 * @param image_base  Image mapping whose next relocation should use the hook.
 * @param repair_hook Hook to register. A null hook or null @c fn clears any
 *                    existing hook for @p image_base.
 * @return            Ok(true), or Err on invalid arguments.
 *
 * @pre The n00b runtime is initialized.
 * @post A later @ref n00b_ct_image_relocate_inplace call for the same mapping
 *       uses the registered hook. Explicit hooks passed to
 *       @ref n00b_ct_image_relocate_inplace_ex take precedence.
 */
extern n00b_result_t(bool)
n00b_ct_image_set_repair_hook(void *image_base,
                              const n00b_ct_image_repair_hook_t *repair_hook);

/**
 * @brief Return the exported root identity carried by an image, if present.
 *
 * The returned identity is allocated in runtime-global storage and points its
 * strings at copied runtime-global bytes. It is suitable for process-lifetime
 * baked-region registration.
 *
 * @param image_base Start of the mapped image bytes.
 * @param image_len  Length of the image region.
 * @kw allocator Allocator for the copied identity (nullptr = runtime system pool).
 * @return Ok(Some(identity)) when the image carries a root identity, Ok(None)
 *         when it does not, or Err for malformed image metadata.
 *
 * @pre The n00b runtime is initialized.
 * @pre @p image_base points to a complete comptime image header and payload.
 * @post Any returned identity and its string bytes live in @p allocator, or in
 *       runtime system-pool storage when @p allocator is nullptr.
 */
extern n00b_result_t(n00b_option_t(n00b_static_identity_t *))
n00b_ct_image_root_identity(void *image_base, size_t image_len) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};
