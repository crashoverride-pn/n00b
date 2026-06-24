/**
 * @file n00b.h
 * @brief Central header for the n00b runtime library.
 *
 * Provides core typedefs, forward declarations, and common macros used
 * throughout the n00b project.  Every other n00b header includes this.
 *
 * NOTE: the GC/marshal codegen ABI is an ncc output contract, NOT core data
 * types, so it is NOT included here. It is split in two:
 *   - core/codegen_abi.h        — the volatile type->GC-map dictionary / variant
 *     / transient structs, read only by the GC/marshal runtime + the pre-link
 *     generated dictionary TU (explicit include; editing it does not rebuild
 *     the world).
 *   - core/codegen_abi_inject.h — the stable roots / stack-map / static-object
 *     slice that ncc-emitted code references by name in arbitrary TUs; the build
 *     force-includes it (`-include`) so emitted code compiles.
 * See doc/codegen-abi-prelink-plan.md.
 */
#pragma once

// Current N00b version info.
#define N00B_VERS_MAJOR   0x00
#define N00B_VERS_MINOR   0x03
#define N00B_VERS_PATCH   0x00
#define N00B_VERS_PREVIEW 0x00

#include <assert.h> // IWYU pragma: export
#include <stdint.h> // IWYU pragma: export
#include <stdlib.h> // IWYU pragma: export
#include <stddef.h> // IWYU pragma: export
#include <stdarg.h> // IWYU pragma: export
#include <string.h> // IWYU pragma: export
#include <errno.h>  // IWYU pragma: export
#include <signal.h>
#include <setjmp.h>
#include <stdbool.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
typedef struct {
    int si_signo;
    int si_status;
    int si_pid;
} siginfo_t;
#endif

// This is to shut up IWYU on a mac.
#if defined __APPLE__ && defined(N00B_IWYU_PROBE)
#include <_time.h>     // IWYU pragma: export
#include <_stdlib.h>   // IWYU pragma: export
#include <_stdio.h>    // IWYU pragma: export
#include <_abort.h>    // IWYU pragma: export
#include <_string.h>   // IWYU pragma: export
#include <_printf.h>   // IWYU pragma: export
#include <_ctype.h>    // IWYU pragma: export
#include <sys/time.h>  // IWYU pragma: export
#include <sys/errno.h> // IWYU pragma: export
struct timeval;        // IWYU pragma: export
struct timespec;       // IWYU pragma: export
#endif

typedef void (*n00b_mem_scan_fn)(uint64_t *, void *);
typedef void (*n00b_system_finalizer_fn)(void *);

typedef struct n00b_runtime_t        n00b_runtime_t;
typedef struct n00b_segment_t        n00b_segment_t;
typedef struct n00b_mmap_info_t      n00b_mmap_info_t;
typedef struct n00b_alloc_range_t    n00b_alloc_range_t;
typedef struct n00b_arena_t          n00b_arena_t;
typedef uint64_t                     n00b_alloc_type_info_t;
typedef struct n00b_inline_hdr_t     n00b_inline_hdr_t;
typedef struct n00b_oob_hdr_t        n00b_oob_hdr_t;
typedef enum n00b_dt_kind_t          n00b_dt_kind_t;
typedef struct n00b_finalizer_info_t n00b_finalizer_info_t;

// Forward declarations for the codegen-ABI descriptor structs that pervasive
// headers reference only THROUGH A POINTER (runtime.h's gc_roots list,
// alloc_base.h / mmaps.h / gc_baked.h identity pointers, gc.h root pointers,
// comptime_image.h). Spelling the forward decls here — in the always-present
// umbrella header — lets those headers compile WITHOUT depending on the
// force-included-but-now-decoupled core/codegen_abi_inject.h. TUs that
// dereference these structs, instantiate them by value, or need the enum
// constants include core/codegen_abi_inject.h explicitly. These are all
// tag-named structs, so the forward typedef is a compatible redeclaration of
// the full definition in that header.
typedef struct n00b_gc_root_t            n00b_gc_root_t;
typedef struct n00b_static_identity_t    n00b_static_identity_t;
typedef struct n00b_static_object_desc_t n00b_static_object_desc_t;

// Stable allocator scan API — pervasive (alloc.h/list.h/string.h/buffer.h/dict.h
// and ~58 TUs reference it) and unchanging, so it lives here rather than in the
// volatile core/codegen_abi.h. The GC scan-kind *values* (N00B_GC_SCAN_KIND_*)
// are defined with the full enum in core/gc_map.h.
typedef struct n00b_gc_map_t n00b_gc_map_t;
enum n00b_gc_scan_kind_t : uint8_t;
typedef enum n00b_gc_scan_kind_t n00b_gc_scan_kind_t;
typedef void (*n00b_gc_scan_cb_t)(n00b_gc_map_t *, void *);
// First two are for anything that is an absolute size / length and
// should always be a natural number.
//
// The high-level language prefers 64-bits for everything, so this first
// one should be on most APIs.
typedef uint64_t           n00b_size_t;
// The 'i' here is for internal. For many size objects, it'd be impractical
// to have more than 2^32 of something, in which case we shave off
// memory here and there.
//
// If it's about C interoperability, then use `size_t`.
typedef uint32_t           n00b_isize_t;
// For binary data, such as bitfields, etc.
typedef uint64_t           n00b_word_t;
// Or probably should use:
typedef unsigned long long n00b_ulong_t;
// Indexing can accept negative values that work like Python.
typedef int64_t            n00b_index_t;
// For sorting comparison; needs to be compat w/ underlying C API.
typedef int                n00b_cmp_t;
// Meant for generic coded values, implying that negative numbers are
// error codes.
typedef int64_t            n00b_code_t;
// File descriptors are of type `int` for better or worse.
typedef int                n00b_fd_t;
// For C error codes / int return values.
typedef int                n00b_ccode_t;
typedef int                n00b_cflags_t;
typedef int                n00b_ctick_t;
// If we have a vararg function, it's undefined behavior if the
// final argument requires promotion to 32 bits, which bool does.
typedef uint32_t           n00b_bool32_t;

typedef unsigned _BitInt(128) n00b_uint128_t;
typedef _Atomic(uint32_t)                    n00b_futex_t;
typedef uint32_t                             n00b_codepoint_t;
typedef int32_t                              n00b_color_t;
typedef struct timespec                      n00b_duration_t;
typedef struct n00b_lock_base_t              n00b_lock_base_t;
typedef struct n00b_mutex_t                  n00b_mutex_t;
typedef struct n00b_rwlock_t                 n00b_rwlock_t;
typedef struct n00b_spin_lock_t              n00b_spin_lock_t;
typedef struct n00b_condition_t              n00b_condition_t;
typedef struct n00b_list_t                   n00b_list_t;
typedef struct n00b_dict_untyped_t           n00b_dict_untyped_t;
typedef struct _n00b_dict_internal_t         _n00b_dict_internal_t;
typedef n00b_uint128_t                       n00b_hash_value_t;
typedef struct n00b_dict_untyped_bucket_t    n00b_dict_untyped_bucket_t;
typedef struct n00b_dict_untyped_store_t     n00b_dict_untyped_store_t;
typedef struct n00b_dict_raw_item_t          n00b_dict_raw_item_t;
typedef struct n00b_buffer_t                 n00b_buffer_t;
typedef struct n00b_string_t                 n00b_string_t;
typedef struct n00b_thread_t                 n00b_thread_t;
typedef struct n00b_thread_record_t          n00b_thread_record_t;
typedef struct n00b_lock_atomic_core_t       n00b_lock_atomic_core_t;
typedef struct n00b_lock_log_t               n00b_lock_log_t;
typedef struct n00b_thread_read_log_t        n00b_thread_read_log_t;
typedef struct n00b_condition_thread_state_t n00b_condition_thread_state_t;
typedef struct n00b_sys_list_t               n00b_sys_list_t;
typedef struct n00b_allocator_t              n00b_allocator_t;
typedef struct n00b_base_allocator_t         n00b_base_allocator_t;
typedef struct n00b_mmap_ctx_t               n00b_mmap_ctx_t;
typedef struct n00b_vargs_t                  n00b_vargs_t;
typedef struct n00b_method_param_t           n00b_method_param_t;
typedef struct n00b_method_t                 n00b_method_t;
typedef struct n00b_type_info_t              n00b_type_info_t;

// Style system forward declarations.
typedef struct n00b_text_style_t        n00b_text_style_t;
typedef struct n00b_style_record_t      n00b_style_record_t;
typedef struct n00b_string_style_info_t n00b_string_style_info_t;

// Unicode module forward declarations.
typedef struct n00b_unicode_break_iter_s  n00b_unicode_break_iter_t;
typedef struct n00b_unicode_normalizer_s  n00b_unicode_normalizer_t;
typedef struct n00b_unicode_idna_result_t n00b_unicode_idna_result_t;
typedef struct n00b_unicode_bidi_para_s   n00b_unicode_bidi_para_t;
typedef struct n00b_cp_filter_t           n00b_cp_filter_t;
typedef struct n00b_unicode_ctx_t         n00b_unicode_ctx_t;
typedef struct n00b_regex_ctx_t           n00b_regex_ctx_t;

// Table module forward declarations.
typedef struct n00b_table_t          n00b_table_t;
typedef struct n00b_table_cell_t     n00b_table_cell_t;
typedef struct n00b_table_row_t      n00b_table_row_t;
typedef struct n00b_table_col_spec_t n00b_table_col_spec_t;

// Render module forward declarations.
typedef struct n00b_canvas_t n00b_canvas_t;
typedef struct n00b_plane_t  n00b_plane_t;

// IO module forward declarations.
typedef struct n00b_subproc n00b_subproc_t;

// Type checker forward declarations.
typedef struct n00b_tc_type_s n00b_tc_type_t;
typedef struct n00b_tc_ctx_s  n00b_tc_ctx_t;

// Fallback helper for untransformed r"..." literals that survive macro expansion.
extern n00b_string_t *n00b_ncc_rstr(const char *src);

typedef n00b_hash_value_t (*n00b_hash_fn)(void *);
typedef n00b_string_t *(*n00b_repr_fn)(void *);
typedef void (*n00b_finalizer_t)(void *);
typedef void (*n00b_vtable_entry)(void *, void *);
typedef void (*n00b_signal_handler_t)(int, siginfo_t *, void *);

#define n00b_min(a, b)                                                                         \
    ({                                                                                         \
        __typeof__(a) _a = (a), _b = (b);                                                      \
        _a < _b ? _a : _b;                                                                     \
    })
#define n00b_max(a, b)                                                                         \
    ({                                                                                         \
        __typeof__(a) _a = (a), _b = (b);                                                      \
        _a > _b ? _a : _b;                                                                     \
    })

#define n00b_barrier() atomic_thread_fence(memory_order_seq_cst)

#if !defined(BYTE_ORDER)
#if defined(_WIN32) || defined(__LITTLE_ENDIAN__)
#define BYTE_ORDER    1234
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321
#endif
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define n00b_little_64(x)
#define n00b_little_32(x)
#define n00b_little_16(x)
#elif BYTE_ORDER == BIG_ENDIAN
#if defined(linux)
#define n00b_little_64(x) x = htole64(x)
#define n00b_little_32(x) x = htole32(x)
#define n00b_little_16(x) x = htole16(x)
#else
#define n00b_little_64(x) x = htonll(x)
#define n00b_little_32(x) x = htonl(x)
#define n00b_little_16(x) x = htons(x)
#endif
#else
#error unknown endian
#endif

#define n00b_likely(x)   __builtin_expect(!!(x), 1)
#define n00b_unlikely(x) __builtin_expect(!!(x), 0)

extern bool n00b_gc_inited;

#define N00B_US_PER_SEC 1000000
#define N00B_NS_PER_US  1000
#define N00B_NS_PER_SEC 1000000000ULL

// The GC/marshal codegen ABI is intentionally NOT included here; see the file
// header. core/codegen_abi_inject.h is force-included by the build instead, and
// core/codegen_abi.h is pulled explicitly by the GC/marshal runtime readers.
