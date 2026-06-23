#ifndef N00B_CRT_INIT_ARRAY_ONLY
#define N00B_USE_INTERNAL_API
#endif

#include "n00b_crt.h"

#ifndef N00B_CRT_INIT_ARRAY_ONLY
#include "n00b.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/gc_baked.h"
#include "core/string.h"
#include "util/comptime_image.h"
#include "util/marshal.h"
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef N00B_CRT_INIT_ARRAY_ONLY
#include <errno.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#endif

typedef void (*n00b_crt_init_fn)(void);

#ifndef N00B_CRT_INIT_ARRAY_ONLY

[[gnu::weak]] unsigned char __n00b_ct_image[1];
[[gnu::weak]] const unsigned long long __n00b_ct_image_len = 0;
[[gnu::weak]] const unsigned long long __n00b_ct_image_protect_len = 0;
[[gnu::weak]] unsigned char __n00b_ct_writable_image[1];
[[gnu::weak]] const unsigned long long __n00b_ct_writable_image_len = 0;

typedef struct {
     uintptr_t start;
     size_t    len;
 } n00b_crt_page_range_t;
 
typedef struct {
     void  *base;
     size_t len;
     size_t protect_len;
 } n00b_crt_linked_image_t;

 struct n00b_crt_pending_protect_t {
     void                     *base;
     size_t                    len;
     n00b_crt_pending_protect_t *next;
 };
 
 n00b_string_t *
 n00b_crt_image_err_str(n00b_err_t err)
 {
     switch (err) {
     case N00B_CRT_IMAGE_ERR_ARG:
         return r"invalid comptime image CRT argument";
     case N00B_CRT_IMAGE_ERR_EXPORT:
         return r"comptime image export failed";
     case N00B_CRT_IMAGE_ERR_OPEN:
         return r"comptime image file open failed";
     case N00B_CRT_IMAGE_ERR_WRITE:
         return r"comptime image file write failed";
     case N00B_CRT_IMAGE_ERR_RELOCATE:
         return r"comptime image relocation failed";
     case N00B_CRT_IMAGE_ERR_PROTECT:
         return r"comptime image protection failed";
    case N00B_CRT_IMAGE_ERR_GC_REGISTER:
        return r"comptime image GC registration failed";
     default:
         return r"unknown comptime image CRT error";
     }
 }
 
 static n00b_result_t(n00b_crt_page_range_t)
 n00b_crt_page_range(void *base, size_t len, uintptr_t page)
 {
     if (base == nullptr || len == 0 || page == 0) {
         return n00b_result_err(n00b_crt_page_range_t, N00B_CRT_IMAGE_ERR_ARG);
     }
 
     uintptr_t start_addr = (uintptr_t)base;
     if (len > (size_t)(UINTPTR_MAX - start_addr)) {
         return n00b_result_err(n00b_crt_page_range_t, N00B_CRT_IMAGE_ERR_ARG);
     }
 
     uintptr_t end_addr = start_addr + len;
     uintptr_t start    = start_addr - (start_addr % page);
     uintptr_t end_rem  = end_addr % page;
     uintptr_t end      = end_addr;
 
     if (end_rem != 0) {
         uintptr_t delta = page - end_rem;
         if (delta > UINTPTR_MAX - end) {
             return n00b_result_err(n00b_crt_page_range_t, N00B_CRT_IMAGE_ERR_ARG);
         }
         end += delta;
     }
 
     if (end < start || end - start > (uintptr_t)SIZE_MAX) {
         return n00b_result_err(n00b_crt_page_range_t, N00B_CRT_IMAGE_ERR_ARG);
     }
 
     return n00b_result_ok(n00b_crt_page_range_t,
                           ((n00b_crt_page_range_t){
                               .start = start,
                               .len   = (size_t)(end - start),
                           }));
 }
 
n00b_result_t(bool)
n00b_crt_mark_readonly(void *base, size_t len)
 {
     if (base == nullptr || len == 0) {
         return n00b_result_ok(bool, true);
     }
 
 #if defined(_WIN32)
     SYSTEM_INFO info;
     GetSystemInfo(&info);
     uintptr_t page = info.dwPageSize ? (uintptr_t)info.dwPageSize : 4096u;
     auto range_r = n00b_crt_page_range(base, len, page);
     if (n00b_result_is_err(range_r)) {
         return n00b_result_err(bool, n00b_result_get_err(range_r));
     }
     n00b_crt_page_range_t range = n00b_result_get(range_r);
     DWORD old_protect = 0;
     if (!VirtualProtect((void *)range.start, range.len, PAGE_READONLY,
                         &old_protect)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_PROTECT);
     }
     return n00b_result_ok(bool, true);
 #else
     auto page_r = n00b_check_sysconf(_SC_PAGESIZE);
     if (n00b_result_is_err(page_r)) {
         return n00b_result_err(bool, n00b_result_get_err(page_r));
     }
     int page_int = n00b_result_get(page_r);
     if (page_int <= 0) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_PROTECT);
     }
     auto range_r = n00b_crt_page_range(base, len, (uintptr_t)page_int);
     if (n00b_result_is_err(range_r)) {
         return n00b_result_err(bool, n00b_result_get_err(range_r));
     }
     n00b_crt_page_range_t range = n00b_result_get(range_r);
     auto protect_r = n00b_check_posix(mprotect((void *)range.start,
                                                range.len,
                                                PROT_READ));
     if (n00b_result_is_err(protect_r)) {
         return n00b_result_err(bool, n00b_result_get_err(protect_r));
     }
     return n00b_result_ok(bool, true);
	 #endif
 }

 static void
 n00b_crt_pending_protect_lock_acquire(void)
 {
     n00b_runtime_t *rt = n00b_get_runtime();
     int64_t tid = n00b_thread_unique_id();
     int64_t expected = -1;

     do {
         if (expected == tid) {
             break;
         }
         expected = -1;
     } while (!n00b_cas(&rt->crt_pending_protect_lock, &expected, tid));
 }

 static void
 n00b_crt_pending_protect_lock_release(void)
 {
     n00b_atomic_store(&n00b_get_runtime()->crt_pending_protect_lock,
                       (int64_t)-1);
 }

 static n00b_result_t(bool)
 n00b_crt_defer_readonly_protect(void *base, size_t len)
 {
     n00b_allocator_t *allocator = (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
     n00b_crt_pending_protect_t *pending =
         n00b_alloc(n00b_crt_pending_protect_t, .allocator = allocator);
     *pending = (n00b_crt_pending_protect_t){
         .base = base,
         .len  = len,
     };

     n00b_crt_pending_protect_lock_acquire();
     pending->next = n00b_get_runtime()->crt_pending_protects;
     n00b_get_runtime()->crt_pending_protects = pending;
     n00b_crt_pending_protect_lock_release();
     return n00b_result_ok(bool, true);
 }

 static n00b_result_t(bool)
 n00b_crt_protect_deferred_images_if_complete(void)
 {
     auto deferred_r = n00b_marshal_apply_deferred_static_patches();
     if (n00b_result_is_err(deferred_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_RELOCATE);
     }
     if (!n00b_result_get(deferred_r)) {
         return n00b_result_ok(bool, false);
     }

     n00b_crt_pending_protect_lock_acquire();
     n00b_crt_pending_protect_t *pending = n00b_get_runtime()->crt_pending_protects;
     n00b_get_runtime()->crt_pending_protects = nullptr;
     n00b_crt_pending_protect_lock_release();

     while (pending != nullptr) {
         n00b_crt_pending_protect_t *next = pending->next;
         auto protect_r = n00b_crt_mark_readonly(pending->base, pending->len);
         if (n00b_result_is_err(protect_r)) {
             return n00b_result_err(bool, n00b_result_get_err(protect_r));
         }
         pending = next;
     }
     return n00b_result_ok(bool, true);
 }
 
static n00b_result_t(n00b_option_t(n00b_crt_linked_image_t))
n00b_crt_locate_comptime_image(void)
{
     if (__n00b_ct_image_len == 0) {
         return n00b_result_ok(n00b_option_t(n00b_crt_linked_image_t),
                               n00b_option_none(n00b_crt_linked_image_t));
     }
 
     if (__n00b_ct_image_len > (unsigned long long)SIZE_MAX
         || __n00b_ct_image_protect_len > (unsigned long long)SIZE_MAX) {
         return n00b_result_err(n00b_option_t(n00b_crt_linked_image_t),
                                N00B_CRT_IMAGE_ERR_ARG);
     }
 
     return n00b_result_ok(
         n00b_option_t(n00b_crt_linked_image_t),
         n00b_option_set(n00b_crt_linked_image_t,
                         ((n00b_crt_linked_image_t){
                             .base        = __n00b_ct_image,
                             .len         = (size_t)__n00b_ct_image_len,
                             .protect_len = (size_t)__n00b_ct_image_protect_len,
                         })));
 }

 static n00b_result_t(n00b_option_t(n00b_crt_linked_image_t))
 n00b_crt_locate_writable_comptime_image(void)
 {
     if (__n00b_ct_writable_image_len == 0) {
         return n00b_result_ok(n00b_option_t(n00b_crt_linked_image_t),
                               n00b_option_none(n00b_crt_linked_image_t));
     }

     if (__n00b_ct_writable_image_len > (unsigned long long)SIZE_MAX) {
         return n00b_result_err(n00b_option_t(n00b_crt_linked_image_t),
                                N00B_CRT_IMAGE_ERR_ARG);
     }

     return n00b_result_ok(
         n00b_option_t(n00b_crt_linked_image_t),
         n00b_option_set(n00b_crt_linked_image_t,
                         ((n00b_crt_linked_image_t){
                             .base        = __n00b_ct_writable_image,
                             .len         = (size_t)__n00b_ct_writable_image_len,
                             .protect_len = 0,
                         })));
 }
 
 n00b_result_t(bool)
 n00b_crt_capture_comptime_roots_to_path(void *const *roots,
                                         unsigned long long root_count,
                                         n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 }
 {
     if (roots == nullptr || root_count == 0 || path == nullptr
         || path->data == nullptr || path->u8_bytes == 0
         || root_count > (unsigned long long)SIZE_MAX) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_ARG);
     }
 
     void **root_array = n00b_alloc_array_with_opts(
         void *,
         (size_t)root_count,
         &(n00b_alloc_opts_t){ .allocator = allocator });
     for (size_t i = 0; i < (size_t)root_count; i++) {
         root_array[i] = roots[i];
     }
 
     [[n00b::nomap]] n00b_result_t(n00b_buffer_t *) export_r =
         n00b_ct_image_export(root_array, .allocator = allocator);
     if (n00b_result_is_err(export_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_EXPORT);
     }
 
     n00b_buffer_t *image = n00b_result_get(export_r);
     [[n00b::nomap]] n00b_result_t(n00b_file_t *) open_r =
         n00b_file_open(path, .mode = N00B_FILE_W,
                        .kind = N00B_FILE_KIND_STREAM);
     if (n00b_result_is_err(open_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_OPEN);
     }
 
     n00b_file_t *file = n00b_result_get(open_r);
     [[n00b::nomap]] n00b_result_t(size_t) write_r =
         n00b_file_write_all(file, image);
     [[n00b::nomap]] n00b_result_t(bool) close_r =
         n00b_file_close_result(file);
     if (n00b_result_is_err(write_r) || n00b_result_get(write_r) != image->byte_len
         || n00b_result_is_err(close_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_WRITE);
     }
 
     return n00b_result_ok(bool, true);
 }

 n00b_result_t(bool)
 n00b_crt_capture_writable_comptime_roots_to_path(void *const *roots,
                                                  unsigned long long root_count,
                                                  n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 }
 {
     if (roots == nullptr || root_count == 0 || path == nullptr
         || path->data == nullptr || path->u8_bytes == 0
         || root_count > (unsigned long long)SIZE_MAX) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_ARG);
     }

     void **root_array = n00b_alloc_array_with_opts(
         void *,
         (size_t)root_count,
         &(n00b_alloc_opts_t){ .allocator = allocator });
     for (size_t i = 0; i < (size_t)root_count; i++) {
         root_array[i] = roots[i];
     }

     [[n00b::nomap]] n00b_result_t(n00b_buffer_t *) export_r =
         n00b_ct_image_export_writable(root_array, .allocator = allocator);
     if (n00b_result_is_err(export_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_EXPORT);
     }

     n00b_buffer_t *image = n00b_result_get(export_r);
     [[n00b::nomap]] n00b_result_t(n00b_file_t *) open_r =
         n00b_file_open(path, .mode = N00B_FILE_W,
                        .kind = N00B_FILE_KIND_STREAM);
     if (n00b_result_is_err(open_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_OPEN);
     }

     n00b_file_t *file = n00b_result_get(open_r);
     [[n00b::nomap]] n00b_result_t(size_t) write_r =
         n00b_file_write_all(file, image);
     [[n00b::nomap]] n00b_result_t(bool) close_r =
         n00b_file_close_result(file);
     if (n00b_result_is_err(write_r) || n00b_result_get(write_r) != image->byte_len
         || n00b_result_is_err(close_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_WRITE);
     }

     return n00b_result_ok(bool, true);
 }

 static n00b_result_t(void *)
 n00b_crt_static_root_value_copy(const n00b_crt_static_root_desc_t *desc,
                                 n00b_allocator_t *allocator)
 {
     if (desc == nullptr || desc->addr == nullptr || desc->size == 0
         || desc->size > (unsigned long long)SIZE_MAX
         || desc->scan_kind > N00B_GC_SCAN_KIND_CALLBACK) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_ARG);
     }

     n00b_alloc_opts_t opts = {
         .allocator = allocator,
         .scan_kind = (n00b_gc_scan_kind_t)desc->scan_kind,
         .scan_cb   = (n00b_gc_scan_cb_t)desc->scan_cb,
         .scan_user = desc->scan_user,
     };
     void *copy = n00b_alloc_size_typed_with_opts(1,
                                                  (size_t)desc->size,
                                                  desc->type_hash,
                                                  &opts);
     memcpy(copy, desc->addr, (size_t)desc->size);
     return n00b_result_ok(void *, copy);
 }

 static n00b_result_t(bool)
 n00b_crt_capture_static_roots_impl(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     n00b_string_t *path,
     bool writable,
     n00b_allocator_t *allocator)
 {
     if (roots == nullptr || root_count == 0 || path == nullptr
         || path->data == nullptr || path->u8_bytes == 0
         || root_count > (unsigned long long)SIZE_MAX) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_ARG);
     }

     void **root_array = n00b_alloc_array_with_opts(
         void *,
         (size_t)root_count,
         &(n00b_alloc_opts_t){ .allocator = allocator });
     for (size_t i = 0; i < (size_t)root_count; i++) {
         const n00b_crt_static_root_desc_t *desc = &roots[i];
         switch ((n00b_crt_static_root_kind_t)desc->kind) {
         case N00B_CRT_STATIC_ROOT_POINTER:
             if (desc->addr == nullptr) {
                 return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_ARG);
             }
             root_array[i] = (void *)desc->addr;
             break;
         case N00B_CRT_STATIC_ROOT_VALUE: {
             [[n00b::nomap]] n00b_result_t(void *) copy_r =
                 n00b_crt_static_root_value_copy(desc, allocator);
             if (n00b_result_is_err(copy_r)) {
                 return n00b_result_err(bool, n00b_result_get_err(copy_r));
             }
             root_array[i] = n00b_result_get(copy_r);
             break;
         }
         default:
             return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_ARG);
         }
     }

     [[n00b::nomap]] n00b_result_t(n00b_buffer_t *) export_r =
         writable ? n00b_ct_image_export_writable(root_array,
                                                  .allocator = allocator)
                  : n00b_ct_image_export(root_array,
                                         .allocator = allocator);
     if (n00b_result_is_err(export_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_EXPORT);
     }

     n00b_buffer_t *image = n00b_result_get(export_r);
     [[n00b::nomap]] n00b_result_t(n00b_file_t *) open_r =
         n00b_file_open(path, .mode = N00B_FILE_W,
                        .kind = N00B_FILE_KIND_STREAM);
     if (n00b_result_is_err(open_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_OPEN);
     }

     n00b_file_t *file = n00b_result_get(open_r);
     [[n00b::nomap]] n00b_result_t(size_t) write_r =
         n00b_file_write_all(file, image);
     [[n00b::nomap]] n00b_result_t(bool) close_r =
         n00b_file_close_result(file);
     if (n00b_result_is_err(write_r) || n00b_result_get(write_r) != image->byte_len
         || n00b_result_is_err(close_r)) {
         return n00b_result_err(bool, N00B_CRT_IMAGE_ERR_WRITE);
     }

     return n00b_result_ok(bool, true);
 }

 n00b_result_t(bool)
 n00b_crt_capture_static_roots_to_path(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 }
 {
     return n00b_crt_capture_static_roots_impl(roots,
                                               root_count,
                                               path,
                                               false,
                                               allocator);
 }

 n00b_result_t(bool)
 n00b_crt_capture_writable_static_roots_to_path(
     const n00b_crt_static_root_desc_t *roots,
     unsigned long long root_count,
     n00b_string_t *path) _kargs
 {
     n00b_allocator_t *allocator = nullptr;
 }
 {
     return n00b_crt_capture_static_roots_impl(roots,
                                               root_count,
                                               path,
                                               true,
                                               allocator);
 }
 
 n00b_result_t(void *)
 n00b_crt_apply_comptime_image_region(void *image_base, size_t image_len,
                                      size_t protect_len)
 {
     if (image_base == nullptr || image_len == 0) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_ARG);
     }

     [[n00b::nomap]] n00b_result_t(void *) reloc_r =
         n00b_ct_image_relocate_inplace(image_base, image_len);
     if (n00b_result_is_err(reloc_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_RELOCATE);
     }

     void *root = n00b_result_get(reloc_r);

     if (protect_len < image_len) {
         protect_len = image_len;
     }

     n00b_ct_image_header_t *hdr = image_base;
     auto identity_r = n00b_ct_image_root_identity(image_base, image_len);
     if (n00b_result_is_err(identity_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_RELOCATE);
     }
     auto identity_opt = n00b_result_get(identity_r);
     const n00b_static_identity_t *root_identity =
         n00b_option_is_set(identity_opt) ? n00b_option_get(identity_opt) : nullptr;
     n00b_gc_baked_region_t region = {
         .base           = image_base,
         .len            = image_len,
         .marshal_stream = (char *)image_base + hdr->marshal_off,
         .marshal_len    = hdr->marshal_len,
         .root           = root,
         .root_identity  = root_identity,
         .writable       = false,
     };
     auto register_r = n00b_gc_register_baked_region(&region);
     if (n00b_result_is_err(register_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_GC_REGISTER);
     }

     if (n00b_marshal_deferred_static_patch_count() != 0) {
         auto defer_r = n00b_crt_defer_readonly_protect(image_base, protect_len);
         if (n00b_result_is_err(defer_r)) {
             return n00b_result_err(void *, n00b_result_get_err(defer_r));
         }
     }
     else {
         auto protect_r = n00b_crt_mark_readonly(image_base, protect_len);
         if (n00b_result_is_err(protect_r)) {
             return n00b_result_err(void *, n00b_result_get_err(protect_r));
         }
     }

     auto deferred_protect_r = n00b_crt_protect_deferred_images_if_complete();
     if (n00b_result_is_err(deferred_protect_r)) {
         return n00b_result_err(void *, n00b_result_get_err(deferred_protect_r));
     }
 
     return n00b_result_ok(void *, root);
 }

 n00b_result_t(void *)
 n00b_crt_apply_writable_image_region(void *image_base,
                                      size_t image_len,
                                      const n00b_ct_image_repair_hook_t *repair_hook)
 {
     if (image_base == nullptr || image_len == 0) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_ARG);
     }

     [[n00b::nomap]] n00b_result_t(void *) reloc_r =
         n00b_ct_image_relocate_inplace_ex(image_base, image_len, repair_hook);
     if (n00b_result_is_err(reloc_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_RELOCATE);
     }

     void *root = n00b_result_get(reloc_r);
     n00b_ct_image_header_t *hdr = image_base;
     if ((hdr->flags & N00B_CT_IMAGE_FLAG_WRITABLE) == 0) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_ARG);
     }

     auto identity_r = n00b_ct_image_root_identity(image_base, image_len);
     if (n00b_result_is_err(identity_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_RELOCATE);
     }
     auto identity_opt = n00b_result_get(identity_r);
     const n00b_static_identity_t *root_identity =
         n00b_option_is_set(identity_opt) ? n00b_option_get(identity_opt) : nullptr;

     n00b_gc_baked_region_t region = {
         .base           = image_base,
         .len            = image_len,
         .marshal_stream = (char *)image_base + hdr->marshal_off,
         .marshal_len    = hdr->marshal_len,
         .root           = root,
         .root_identity  = root_identity,
         .writable       = true,
     };
     auto register_r = n00b_gc_register_baked_region_writable(&region);
     if (n00b_result_is_err(register_r)) {
         return n00b_result_err(void *, N00B_CRT_IMAGE_ERR_GC_REGISTER);
     }

     auto deferred_protect_r = n00b_crt_protect_deferred_images_if_complete();
     if (n00b_result_is_err(deferred_protect_r)) {
         return n00b_result_err(void *, n00b_result_get_err(deferred_protect_r));
     }

     return n00b_result_ok(void *, root);
 }
 
 n00b_result_t(n00b_option_t(void *))
 n00b_crt_apply_linked_comptime_image(void)
 {
     auto locate_r = n00b_crt_locate_comptime_image();
     if (n00b_result_is_err(locate_r)) {
         return n00b_result_err(n00b_option_t(void *),
                                n00b_result_get_err(locate_r));
     }
 
     n00b_option_t(n00b_crt_linked_image_t) image_opt =
         n00b_result_get(locate_r);
     if (!n00b_option_is_set(image_opt)) {
         return n00b_result_ok(n00b_option_t(void *), n00b_option_none(void *));
     }
 
     n00b_crt_linked_image_t image = n00b_option_get(image_opt);
     auto apply_r = n00b_crt_apply_comptime_image_region(image.base,
                                                         image.len,
                                                         image.protect_len);
     if (n00b_result_is_err(apply_r)) {
         return n00b_result_err(n00b_option_t(void *),
                                n00b_result_get_err(apply_r));
     }
 
     return n00b_result_ok(n00b_option_t(void *),
                           n00b_option_set(void *, n00b_result_get(apply_r)));
 }

 n00b_result_t(n00b_option_t(void *))
 n00b_crt_apply_linked_writable_comptime_image(void)
 {
     auto locate_r = n00b_crt_locate_writable_comptime_image();
     if (n00b_result_is_err(locate_r)) {
         return n00b_result_err(n00b_option_t(void *),
                                n00b_result_get_err(locate_r));
     }

     n00b_option_t(n00b_crt_linked_image_t) image_opt =
         n00b_result_get(locate_r);
     if (!n00b_option_is_set(image_opt)) {
         return n00b_result_ok(n00b_option_t(void *), n00b_option_none(void *));
     }

     n00b_crt_linked_image_t image = n00b_option_get(image_opt);
     auto apply_r = n00b_crt_apply_writable_image_region(image.base,
                                                         image.len,
                                                         nullptr);
     if (n00b_result_is_err(apply_r)) {
         return n00b_result_err(n00b_option_t(void *),
                                n00b_result_get_err(apply_r));
     }

     return n00b_result_ok(n00b_option_t(void *),
                           n00b_option_set(void *, n00b_result_get(apply_r)));
 }
 
#endif

void
n00b_crt_run_init_array_range(void (**start)(void), void (**end)(void))
{
    while (start < end) {
        void (*fn)(void) = *start++;

        if (fn != nullptr) {
            fn();
        }
    }
}

#if defined(_WIN32)

[[gnu::used, gnu::section(".CRT$XCA")]]
n00b_crt_init_fn n00b_crt_xca[] = { nullptr };
[[gnu::used, gnu::section(".CRT$XCZ")]]
n00b_crt_init_fn n00b_crt_xcz[] = { nullptr };

void
n00b_crt_run_init_array(void)
{
    n00b_crt_run_init_array_range(n00b_crt_xca + 1, n00b_crt_xcz);
}

#elif defined(__APPLE__) && defined(__MACH__)

#define N00B_CRT_MH_MAGIC_64   UINT32_C(0xfeedfacf)
#define N00B_CRT_LC_SEGMENT_64 UINT32_C(0x19)

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} n00b_crt_mach_header_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} n00b_crt_load_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} n00b_crt_segment_command_64_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} n00b_crt_section_64_t;

extern const n00b_crt_mach_header_64_t *_dyld_get_image_header(uint32_t image_index);
extern intptr_t                         _dyld_get_image_vmaddr_slide(uint32_t image_index);

static int
n00b_crt_macho_name_eq(const char field[16], const char *name)
{
    for (size_t i = 0; i < 16; i++) {
        char want = name[i];

        if (field[i] != want) {
            return 0;
        }

        if (want == '\0') {
            return 1;
        }
    }

    return name[16] == '\0';
}

void
n00b_crt_run_init_array(void)
{
    const n00b_crt_mach_header_64_t *header = _dyld_get_image_header(0);

    if (header == nullptr || header->magic != N00B_CRT_MH_MAGIC_64) {
        return;
    }

    intptr_t  slide  = _dyld_get_image_vmaddr_slide(0);
    uintptr_t cursor = (uintptr_t)(header + 1);

    for (uint32_t cmd_ix = 0; cmd_ix < header->ncmds; cmd_ix++) {
        const n00b_crt_load_command_t *load_cmd = (const void *)cursor;

        if (load_cmd->cmdsize < sizeof(*load_cmd)) {
            return;
        }

        if (load_cmd->cmd == N00B_CRT_LC_SEGMENT_64
            && load_cmd->cmdsize >= sizeof(n00b_crt_segment_command_64_t)) {
            const n00b_crt_segment_command_64_t *segment = (const void *)cursor;
            const n00b_crt_section_64_t         *section = (const void *)(segment + 1);

            for (uint32_t sect_ix = 0; sect_ix < segment->nsects; sect_ix++) {
                if (n00b_crt_macho_name_eq(section[sect_ix].sectname,
                                           "__mod_init_func")) {
                    n00b_crt_init_fn *start = (void *)(uintptr_t)(section[sect_ix].addr
                                                                  + (uint64_t)slide);
                    n00b_crt_init_fn *end   = start + (section[sect_ix].size
                                                       / sizeof(*start));
                    n00b_crt_run_init_array_range(start, end);
                }
                else if (n00b_crt_macho_name_eq(section[sect_ix].sectname,
                                                "__init_offsets")) {
                    const uint32_t *start = (const void *)(uintptr_t)(section[sect_ix].addr
                                                                      + (uint64_t)slide);
                    const uint32_t *end   = start + (section[sect_ix].size
                                                     / sizeof(*start));

                    while (start < end) {
                        uint32_t offset = *start++;

                        if (offset != 0) {
                            n00b_crt_init_fn fn = (void *)((uintptr_t)header + offset);
                            fn();
                        }
                    }
                }
            }
        }

        cursor += load_cmd->cmdsize;
    }
}

#else

[[gnu::weak]] extern n00b_crt_init_fn __init_array_start[];
[[gnu::weak]] extern n00b_crt_init_fn __init_array_end[];

void
n00b_crt_run_init_array(void)
{
    if (__init_array_start == nullptr || __init_array_end == nullptr) {
        return;
    }

    n00b_crt_run_init_array_range(__init_array_start, __init_array_end);
}

#endif
