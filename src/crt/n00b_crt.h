#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef N00B_USE_INTERNAL_API
#include "adt/result.h"
#include "adt/option.h"
#include "core/gc_map.h"
#include "core/string.h"
#include "util/comptime_image.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief C-level program entry invoked by the platform startup stub.
 *
 * @details This function is defined by ncc-generated C, not by libn00b's static
 * CRT object. The assembly startup stub captures the platform argument block and
 * transfers control here.
 *
 * PRE-RUNTIME CONTEXT: on entry, the n00b runtime is not initialized and the GC
 * does not exist. Code before `n00b_init_simple()` may use only raw C, the
 * platform ABI values passed here, and the plain-C runtime entry symbols needed
 * to bring n00b up and terminate the process. It must not allocate through n00b,
 * construct n00b strings or containers, or use conduit/print APIs.
 *
 * @param argc Argument count captured from the platform ABI.
 * @param argv NULL-terminated argument vector captured from the platform ABI.
 * @param envp NULL-terminated environment vector captured from the platform ABI.
 *
 * @pre Called exactly once, from the initial process thread, by one of the
 *      `n00b_start_*` assembly stubs.
 * @post Does not return; terminates through `n00b_exit()` or an equivalent fatal
 *       path in the generated entry.
 */
[[noreturn]] void n00b_crt_main(int argc, char **argv, char **envp);

#ifdef _WIN32
/**
 * @brief Windows C bridge used by the PE startup stub.
 *
 * @details Windows process entry does not receive `argc/argv/envp` from the
 * loader. This helper obtains the process command line and environment through
 * Win32 APIs, converts them to process-lifetime UTF-8 vectors, and then calls
 * `n00b_crt_main()`.
 *
 * PRE-RUNTIME CONTEXT: this helper may use Win32 process APIs and OS heap
 * allocation only. It must not use n00b allocation, GC, strings, containers, or
 * conduit/print APIs.
 *
 * @pre Called exactly once from a Windows `n00b_start_*` PE entry stub.
 * @post Does not return; transfers to `n00b_crt_main()` or terminates the
 *       process through `ExitProcess()` on unrecoverable setup failure.
 */
[[noreturn]] void n00b_crt_windows_main(void);
#endif

/**
 * @brief Run C/C++ static constructors recorded in the program init-array.
 *
 * @details The custom n00b entry suppresses the platform libc startup object, so
 * libc no longer walks constructor tables on behalf of the program. This helper
 * performs that walk for the generated entry.
 *
 * PRE-RUNTIME CONTEXT: this helper is pure pointer iteration. It must remain safe
 * before the GC and n00b allocator exist. Constructors reached through the table
 * are user/runtime code and must obey the ordering selected by the generated
 * entry.
 *
 * @pre The dynamic loader has mapped the program's static data segments.
 * @post Every constructor in the selected platform init table has been invoked
 *       once, in table order.
 */
void n00b_crt_run_init_array(void);

/**
 * @brief Run constructors in an explicit half-open function-pointer range.
 *
 * @details This is the testable core of `n00b_crt_run_init_array()`. Platform
 * startup table discovery is intentionally separate from the pure pointer walk.
 * Null entries are skipped, matching PE constructor-table sentinel behavior.
 *
 * PRE-RUNTIME CONTEXT: pure pointer iteration only; must not allocate or use
 * initialized n00b runtime services.
 *
 * @param start First table slot to inspect.
 * @param end   One-past-last table slot to inspect.
 *
 * @pre `start <= end`; both pointers identify slots in the same constructor
 *      table or fixture array.
 * @post Every non-null constructor in `[start, end)` has been invoked once, in
 *       table order.
 */
void n00b_crt_run_init_array_range(void (**start)(void), void (**end)(void));

#ifdef N00B_USE_INTERNAL_API

 /**
  * @brief Root descriptor kind for generated static-init capture.
  *
  * @details Pointer roots are already managed object pointers. Value roots are
  * static objects copied into a managed allocation before image export, then
  * copied back into their static storage by generated apply helpers after image
  * relocation.
  */
 typedef enum : uint32_t {
     N00B_CRT_STATIC_ROOT_POINTER = 1, /**< @brief @c addr is a managed root pointer. */
     N00B_CRT_STATIC_ROOT_VALUE   = 2, /**< @brief @c addr points to value bytes to copy. */
 } n00b_crt_static_root_kind_t;

 /**
  * @brief Descriptor consumed by CRT static-root capture helpers.
  *
  * @details ncc-generated comptime entry code builds arrays of these records to
  * capture mixed pointer and value static-init roots through one image export
  * path. For value roots, @c scan_kind, @c scan_cb, and @c scan_user describe the
  * temporary managed copy so marshal and GC preserve pointer-bearing fields.
  */
 typedef struct {
     uint32_t kind;              /**< @brief One @ref n00b_crt_static_root_kind_t value. */
     uint32_t scan_kind;         /**< @brief One @ref n00b_gc_scan_kind_t value for value roots. */
     const void *addr;           /**< @brief Root pointer or address of value bytes. */
     unsigned long long size;    /**< @brief Value-root byte count; ignored for pointer roots. */
     unsigned long long type_hash; /**< @brief Value-root type hash; zero when unknown. */
     void *scan_cb;              /**< @brief Optional scan callback for value roots. */
     void *scan_user;            /**< @brief Optional scan callback user data for value roots. */
 } n00b_crt_static_root_desc_t;

 typedef enum : n00b_err_t {
     N00B_CRT_IMAGE_ERR_ARG = -280,
     N00B_CRT_IMAGE_ERR_EXPORT,
     N00B_CRT_IMAGE_ERR_OPEN,
     N00B_CRT_IMAGE_ERR_WRITE,
     N00B_CRT_IMAGE_ERR_RELOCATE,
     N00B_CRT_IMAGE_ERR_PROTECT,
     N00B_CRT_IMAGE_ERR_GC_REGISTER,
 } n00b_crt_image_err_t;
 
 /**
  * @brief Static diagnostic string for an @c N00B_CRT_IMAGE_ERR_* code.
  */
 extern n00b_string_t *n00b_crt_image_err_str(n00b_err_t err);
 
 /**
  * @brief Export pointer-valued comptime roots to an image file.
  *
  * @details Each root is a heap object pointer captured after `comptime_main()`
  * succeeds. The helper wraps all roots in one GC-scannable pointer array,
  * preserving the v1 single-root image format.
  *
  * @param roots      Pointer roots to bake.
  * @param root_count Number of root slots in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @kw allocator Allocator used for the temporary root array.
  *
  * @return `Ok(true)` when @p path receives a complete comptime image, or an
  *         error result on validation, export, open, or write failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns `Ok(true)` and writes a complete comptime image to @p path, or
  *       returns `Err(N00B_CRT_IMAGE_ERR_*)` / a propagated file error. The
  *       allocator is used for the temporary root array and exported image.
  */
 extern n00b_result_t(bool)
 n00b_crt_capture_comptime_roots_to_path(void *const *roots,
                                         unsigned long long root_count,
                                         n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 };

 /**
  * @brief Export pointer-valued comptime roots to a writable image file.
  *
  * @details Each root is a heap object pointer captured after `comptime_main()`
  * succeeds. The helper wraps all roots in one GC-scannable pointer array,
  * preserving the v1 single-root image format while marking the image writable.
  *
  * @param roots      Pointer roots to bake.
  * @param root_count Number of root slots in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @kw allocator Allocator used for the temporary root array.
  *
  * @return `Ok(true)` when @p path receives a complete writable comptime image,
  *         or an error result on validation, export, open, or write failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns `Ok(true)` and writes a complete writable comptime image to
  *       @p path, or returns `Err(N00B_CRT_IMAGE_ERR_*)` / a propagated file
  *       error. The allocator is used for the temporary root array and exported
  *       image.
  */
 extern n00b_result_t(bool)
 n00b_crt_capture_writable_comptime_roots_to_path(
     void *const *roots,
     unsigned long long root_count,
     n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 };

 /**
  * @brief Export mixed read-only static-init roots to an image file.
  *
  * @details The descriptor array may contain pointer roots and value roots.
  * Value roots are copied into temporary managed allocations using their
  * descriptor size, type hash, and scan metadata before image export.
  *
  * @param roots      Descriptor array for roots to capture.
  * @param root_count Number of descriptors in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @kw allocator Allocator used for temporary root/value allocations.
  *
  * @return `Ok(true)` when @p path receives a complete read-only comptime image,
  *         or an error result on validation, export, open, or write failure.
  *
  * @pre The n00b runtime is initialized; @p roots and @p path are non-null.
  * @post Returns `Ok(true)` and writes a complete read-only comptime image to
  *       @p path, or returns `Err(N00B_CRT_IMAGE_ERR_*)` / a propagated file
  *       error without publishing a partial success.
  */
 extern n00b_result_t(bool)
 n00b_crt_capture_static_roots_to_path(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 };

 /**
  * @brief Export mixed writable static-init roots to an image file.
  *
  * @details This is the writable counterpart to
  * @ref n00b_crt_capture_static_roots_to_path. The exported image is marked
  * writable so final CRT apply can relocate it in place and generated apply
  * helpers can copy relocated value roots back into writable static objects.
  *
  * @param roots      Descriptor array for roots to capture.
  * @param root_count Number of descriptors in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @kw allocator Allocator used for temporary root/value allocations.
  *
  * @return `Ok(true)` when @p path receives a complete writable comptime image,
  *         or an error result on validation, export, open, or write failure.
  *
  * @pre The n00b runtime is initialized; @p roots and @p path are non-null.
  * @post Returns `Ok(true)` and writes a complete writable comptime image to
  *       @p path, or returns `Err(N00B_CRT_IMAGE_ERR_*)` / a propagated file
  *       error without publishing a partial success.
  */
 extern n00b_result_t(bool)
 n00b_crt_capture_writable_static_roots_to_path(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 };
 
 /**
  * @brief C-ABI shim for generated comptime-run entries.
  *
  * @details This flat symbol is intentionally narrow: ncc-generated runtime C can
  * declare it without including n00b result/string headers. The implementation
  * lives in `n00b_crt_comptime_shim.c` and immediately converts to
  * @ref n00b_crt_capture_comptime_roots_to_path.
  *
  * @param roots      Pointer roots to bake.
  * @param root_count Number of root slots in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @return 0 on success, or a nonzero process-exit-suitable status on failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns 0 and writes a complete comptime image to @p path, or returns a
  *       nonzero process-exit-suitable status on marshal or file I/O failure.
  */
 int n00b_crt_capture_comptime_roots(void *const *roots,
                                     unsigned long long root_count,
                                     const char *path);

 /**
  * @brief C-ABI shim for generated writable comptime-run captures.
  *
  * @details This flat symbol is intentionally narrow: ncc-generated runtime C can
  * declare it without including n00b result/string headers. The implementation
  * lives in `n00b_crt_comptime_shim.c` and immediately converts to
  * @ref n00b_crt_capture_writable_comptime_roots_to_path.
  *
  * @param roots      Pointer roots to bake.
  * @param root_count Number of root slots in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @return 0 on success, or a nonzero process-exit-suitable status on failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns 0 and writes a complete writable comptime image to @p path, or
  *       returns a nonzero process-exit-suitable status on marshal or file I/O
  *       failure.
  */
 int n00b_crt_capture_writable_comptime_roots(void *const *roots,
                                              unsigned long long root_count,
                                              const char *path);

 /**
  * @brief C-ABI shim for generated mixed read-only static-root captures.
  *
  * @details This flat symbol is intentionally narrow: ncc-generated runtime C
  * can declare it without including result/string headers. The implementation
  * lives in `n00b_crt_comptime_shim.c` and converts @p path to an n00b string
  * before calling @ref n00b_crt_capture_static_roots_to_path.
  *
  * @param roots      Descriptor array for roots to capture.
  * @param root_count Number of descriptors in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @return 0 on success, or a nonzero process-exit-suitable status on failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns 0 and writes a complete read-only comptime image to @p path,
  *       or returns a nonzero process-exit-suitable status on validation,
  *       marshal, or file I/O failure.
  */
 int n00b_crt_capture_static_roots(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     const char *path);

 /**
  * @brief C-ABI shim for generated mixed writable static-root captures.
  *
  * @details This flat symbol is intentionally narrow: ncc-generated runtime C
  * can declare it without including result/string headers. The implementation
  * lives in `n00b_crt_comptime_shim.c` and converts @p path to an n00b string
  * before calling @ref n00b_crt_capture_writable_static_roots_to_path.
  *
  * @param roots      Descriptor array for roots to capture.
  * @param root_count Number of descriptors in @p roots.
  * @param path       Native filesystem path for the captured image bytes.
  *
  * @return 0 on success, or a nonzero process-exit-suitable status on failure.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns 0 and writes a complete writable comptime image to @p path, or
  *       returns a nonzero process-exit-suitable status on validation, marshal,
  *       or file I/O failure.
  */
 int n00b_crt_capture_writable_static_roots(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     const char *path);

 /**
  * @brief C-ABI allocation shim for generated static-init payloads.
  *
  * @details Generated static-init code uses this flat symbol when it knows a
  * payload element size and runtime type hash but cannot rely on `core/alloc.h`
  * being included by the user's source. The shim forwards to the n00b typed
  * allocation API and applies the supplied scan metadata.
  *
  * @param count     Number of payload elements to allocate.
  * @param elem_size Size of each payload element in bytes.
  * @param type_hash Type hash for the payload element pointer type.
  * @param scan_kind One @ref n00b_gc_scan_kind_t value for the payload.
  * @param scan_cb   Optional scan callback.
  * @param scan_user Optional scan callback user data.
  *
  * @return A managed allocation with the supplied type and scan metadata, or
  *         nullptr when the flat arguments are invalid.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns a zero-filled managed allocation with the supplied type and
  *       scan metadata, or nullptr when the flat arguments are invalid.
  */
 void *n00b_crt_alloc_static_payload(unsigned long long count,
                                     unsigned long long elem_size,
                                     unsigned long long type_hash,
                                     unsigned int scan_kind,
                                     n00b_gc_scan_cb_t scan_cb,
                                     void *scan_user);

 /**
  * @brief C-ABI allocation shim for generated static buffer objects.
  *
  * @details Generated migrated-buffer static-init code uses this flat symbol
  * instead of naming allocator internals. The shim allocates one managed
  * `n00b_buffer_t` with the supplied runtime type hash and records the optional
  * precomputed payload hash in allocation metadata so `n00b_hash()` observes the
  * same cached value as legacy static-buffer descriptors.
  *
  * @param type_hash      Runtime type hash for `n00b_buffer_t`.
  * @param cached_hash_hi High 64 bits of the precomputed cached hash.
  * @param cached_hash_lo Low 64 bits of the precomputed cached hash.
  *
  * @return A managed `n00b_buffer_t *` allocated with the supplied type hash.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns a managed `n00b_buffer_t *`; if the combined cached hash is
  *       nonzero, the returned allocation's cached-hash metadata is stamped
  *       before return.
  */
 n00b_buffer_t *n00b_crt_alloc_static_buffer(unsigned long long type_hash,
                                            unsigned long long cached_hash_hi,
                                            unsigned long long cached_hash_lo);

 /**
  * @brief C-ABI allocation shim for generated static list locks.
  *
  * @details Generated migrated-list static-init code uses this flat symbol to
  * allocate and initialize the default list rwlock without exposing lock or
  * allocator internals to generated C.
  *
  * @return A managed initialized `n00b_rwlock_t *`.
  *
  * @pre The n00b runtime is initialized.
  * @post Returns a managed rwlock whose futex/accounting state has been
  *       initialized by @ref n00b_rw_init.
  */
 n00b_rwlock_t *n00b_crt_alloc_static_rwlock(void);
 
 /**
 * @brief Relocate the linked comptime image section and apply or queue
 *        read-only protection.
  *
  * @return `Ok(Some(root))` when an image is linked and applied, `Ok(None)` when
  *         the program has no linked comptime image, or `Err(...)` on relocation
  *         or protection failure.
  *
  * @pre The n00b runtime is initialized.
 * @post When an image is present, its internal pointers are relocated in place
 *       and the relocated root is returned for generated entry code to assign
 *       back to comptime globals. If no PSPATCH records remain unresolved, the
 *       image mapping is marked read-only before return. Otherwise read-only
 *       protection is queued in runtime state and applied by a later CRT image
 *       apply once all deferred patches resolve.
 */
 extern n00b_result_t(n00b_option_t(void *))
 n00b_crt_apply_linked_comptime_image(void);

 /**
  * @brief Relocate the linked writable comptime image section.
  *
  * @return `Ok(Some(root))` when a writable image is linked and applied,
  *         `Ok(None)` when the program has no linked writable comptime image,
  *         or `Err(...)` on relocation or GC-registration failure.
  *
  * @pre The n00b runtime is initialized.
  * @post When a writable image is present, its internal pointers are relocated
  *       in place, the relocated root is returned for generated entry code to
  *       assign back to writable static-init globals, the image remains
  *       writable, and its pointer-bearing words are registered as GC roots for
  *       update-on-move. Any read-only comptime images queued on unresolved
  *       PSPATCH records are protected once this apply resolves all pending
  *       patches.
  */
 extern n00b_result_t(n00b_option_t(void *))
 n00b_crt_apply_linked_writable_comptime_image(void);

/**
 * @brief Mark a byte range read-only using the platform page-protection API.
 *
 * @param base Start of the byte range to protect.
 * @param len  Length of the byte range to protect.
 *
 * @return `Ok(true)` on success, or `Err(N00B_CRT_IMAGE_ERR_*)`.
 *
 * @pre The n00b runtime is initialized.
 * @post The page range covering `[base, base + len)` is read-only.
 */
extern n00b_result_t(bool) n00b_crt_mark_readonly(void *base, size_t len);
 
 /**
  * @brief C-ABI shim for generated final-binary entries.
  *
  * @details This flat symbol is intentionally narrow: ncc-generated runtime C can
  * declare it without including n00b result/option headers. The implementation
  * lives in `n00b_crt_comptime_shim.c` and immediately converts from
  * @ref n00b_crt_apply_linked_comptime_image.
  *
  * @return The relocated image root, or null when no image is linked. Applying
  *         a linked but malformed image fails closed. If cross-image PSPATCH
  *         targets are still pending, read-only page protection is queued and
  *         flushed by a later CRT image apply once those targets resolve.
  */
 void *n00b_crt_apply_comptime_image(void);

 /**
  * @brief C-ABI shim for generated final-binary writable image entries.
  *
 * @details This flat symbol is intentionally narrow: ncc-generated runtime C can
 * declare it without including n00b result/option headers. The implementation
 * lives in `n00b_crt_comptime_shim.c` and immediately converts from
 * @ref n00b_crt_apply_linked_writable_comptime_image.
 *
 * @return The relocated writable image root, or null when no writable image is
 *         linked.
 *
 * @pre The n00b runtime is initialized.
 * @post When a writable image is linked, its internal pointers are relocated in
 *       place, the image remains writable, and pointer-bearing words in the
 *       image are registered as GC roots for update-on-move. If this apply
 *       resolves all deferred PSPATCH records, queued read-only protection for
 *       earlier read-only comptime images is flushed. Applying a linked but
 *       malformed writable image fails closed by panicking.
 */
 void *n00b_crt_apply_writable_image(void);
 
 /**
  * @brief Testable region core for @ref n00b_crt_apply_comptime_image.
  *
  * @param image_base  Writable image bytes.
  * @param image_len   Logical image byte length.
  * @param protect_len Byte length to mark read-only after relocation.
  *
  * @pre The n00b runtime is initialized; @p image_base is writable.
  * @post Returns `Ok(root)`. On success with no unresolved PSPATCH records, the
  *       page range covering `[image_base, image_base + protect_len)` is
  *       read-only. If PSPATCH targets are still unresolved, protection for
  *       that range is queued in runtime state and applied by a later CRT image
  *       apply once all deferred patches resolve. On failure, returns
  *       `Err(N00B_CRT_IMAGE_ERR_*)` / a propagated error.
  */
extern n00b_result_t(void *)
n00b_crt_apply_comptime_image_region(void *image_base, size_t image_len,
                                     size_t protect_len);

/**
 * @brief Relocate a writable comptime image region without marking it read-only.
 *
 * @param image_base  Writable image bytes.
 * @param image_len   Logical image byte length.
 * @param repair_hook Optional post-relocation repair hook.
 * @return            Ok(relocated root pointer inside @p image_base), or Err.
 *
 * @pre The n00b runtime is initialized; @p image_base is writable.
 * @post Returns `Ok(root)`. On success, the region remains writable, its baked
 *       allocations are pinned, and pointer-bearing words are registered as GC
 *       roots for update-on-move.
 */
extern n00b_result_t(void *)
n00b_crt_apply_writable_image_region(void *image_base,
                                     size_t image_len,
                                     const n00b_ct_image_repair_hook_t *repair_hook);
 
#endif

#ifdef __cplusplus
}
#endif
