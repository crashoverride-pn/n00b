/**
 * @file n00b.h
 * @brief Central header for the n00b runtime library.
 *
 * Provides core typedefs, forward declarations, and common macros used
 * throughout the n00b project.  Every other n00b header includes this.
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
/* Defined in full here (not forward-declared) because ncc's
 * `--ncc-auto-gc-roots` transform emits a `static n00b_gc_root_t[]`
 * table into arbitrary translation units that only include `n00b.h`.
 * The full struct layout must therefore be visible from this header
 * alone, matching the precedent set by `n00b_static_object_desc_t`
 * (which the static-image transform emits similarly). The public GC
 * API (`n00b_gc_register_roots` declaration, `n00b_gc_register_root`
 * macro, `n00b_collect`, etc.) still lives in `include/core/gc.h`. */
typedef struct n00b_gc_root_t {
    void  *addr;      /**< Start of the scannable region. */
    size_t num_words; /**< Number of pointer-sized words to scan. */
} n00b_gc_root_t;
typedef struct n00b_gc_root_section_entry_t {
    const n00b_gc_root_t *roots;
    size_t                count;
} n00b_gc_root_section_entry_t;
typedef struct n00b_gc_map_t n00b_gc_map_t;
enum n00b_gc_scan_kind_t : uint8_t;
typedef enum n00b_gc_scan_kind_t n00b_gc_scan_kind_t;
typedef void (*n00b_gc_scan_cb_t)(n00b_gc_map_t *, void *);

typedef enum {
    N00B_GC_STACK_CONSERVATIVE = 0,
    N00B_GC_STACK_EXACT_WITH_FALLBACK,
    N00B_GC_STACK_EXACT_ONLY,
} n00b_gc_stack_policy_t;

typedef struct {
    uint32_t root_index;
    uint32_t num_words;
} n00b_gc_stack_slot_t;

typedef struct {
    uint32_t                    num_roots;
    uint32_t                    num_slots;
    uint32_t                    flags;
    const n00b_gc_stack_slot_t *slots;
    const char                 *function_name;
    const char                 *file_name;
    uint32_t                    line;
} n00b_gc_stack_map_t;

typedef struct n00b_gc_stack_frame_t {
    struct n00b_gc_stack_frame_t *prev;
    const n00b_gc_stack_map_t    *map;
    void                        **roots;
} n00b_gc_stack_frame_t;

typedef struct n00b_jmp_buf_t {
    jmp_buf                n00b_jmp_env;
    struct n00b_thread_t  *n00b_thread;
    n00b_gc_stack_frame_t *n00b_gc_stack_top;
} n00b_jmp_buf_t;

extern n00b_gc_stack_policy_t n00b_gc_stack_get_policy(void);
extern n00b_gc_stack_policy_t n00b_gc_stack_set_policy(n00b_gc_stack_policy_t policy);
extern void
n00b_gc_stack_push(n00b_gc_stack_frame_t *frame, const n00b_gc_stack_map_t *map, void **roots);
extern void            n00b_gc_stack_pop(n00b_gc_stack_frame_t *frame);
extern n00b_jmp_buf_t *n00b_gc_stack_prepare_jmp(n00b_jmp_buf_t *ctx);
extern void            n00b_gc_stack_restore(n00b_gc_stack_frame_t *top);

/* Declared here (in addition to `include/core/gc.h`) for runtime callers from
 * TUs that only include `n00b.h`. ncc's `--ncc-auto-gc-roots` transform emits
 * `n00b_gc_root_section_entry_t` descriptors in a linker section. */
extern void              n00b_gc_register_roots(const n00b_gc_root_t *roots, size_t count);
[[noreturn]] extern void n00b_longjmp(n00b_jmp_buf_t *ctx, int value);

// Supported non-local-exit interface for code compiled with GC stack maps.
// The checkpoint records the current published frame chain; the jump restores
// it before transferring control so skipped cleanup frames are not scanned.
// Checkpoints must be jumped to only from the same thread that created them.
#define n00b_setjmp(ctx) setjmp(n00b_gc_stack_prepare_jmp((ctx))->n00b_jmp_env)

enum n00b_static_object_flags_t : uint32_t {
    N00B_STATIC_OBJECT_F_NONE        = 0,
    N00B_STATIC_OBJECT_F_READONLY    = 1u << 0,
    N00B_STATIC_OBJECT_F_MUTABLE     = 1u << 1,
    N00B_STATIC_OBJECT_F_INIT_RWLOCK = 1u << 2,
};
typedef enum n00b_static_object_flags_t n00b_static_object_flags_t;

#define N00B_STATIC_IDENTITY_VERSION 1u

typedef enum n00b_static_identity_kind_t : uint8_t {
    N00B_STATIC_IDENTITY_NONE                     = 0,
    N00B_STATIC_IDENTITY_NCC_RSTR                 = 1,
    N00B_STATIC_IDENTITY_NCC_ARRAY_DATA           = 2,
    N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_OBJECT  = 3,
    N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_PAYLOAD = 4,
    N00B_STATIC_IDENTITY_MANUAL                   = 5,
} n00b_static_identity_kind_t;

typedef enum n00b_static_identity_status_t : uint8_t {
    N00B_STATIC_IDENTITY_OK = 0,
    N00B_STATIC_IDENTITY_ERR_NULL,
    N00B_STATIC_IDENTITY_ERR_INVALID,
    N00B_STATIC_IDENTITY_ERR_MISSING,
    N00B_STATIC_IDENTITY_ERR_DUPLICATE,
    N00B_STATIC_IDENTITY_ERR_MUTABILITY,
    N00B_STATIC_IDENTITY_ERR_TYPE,
    N00B_STATIC_IDENTITY_ERR_SCAN,
    N00B_STATIC_IDENTITY_ERR_LENGTH,
    N00B_STATIC_IDENTITY_ERR_CHECK_BYTES,
} n00b_static_identity_status_t;

typedef enum n00b_static_identity_query_checks_t : uint32_t {
    N00B_STATIC_IDENTITY_CHECK_NONE      = 0,
    N00B_STATIC_IDENTITY_CHECK_LEN       = 1u << 0,
    N00B_STATIC_IDENTITY_CHECK_TINFO     = 1u << 1,
    N00B_STATIC_IDENTITY_CHECK_SCAN_KIND = 1u << 2,
    N00B_STATIC_IDENTITY_CHECK_FLAGS     = 1u << 3,
    N00B_STATIC_IDENTITY_CHECK_BYTES     = 1u << 4,
} n00b_static_identity_query_checks_t;

typedef struct n00b_static_identity_t {
    uint32_t                    version;
    n00b_static_identity_kind_t kind;
    uint8_t                     reserved[3];
    const char                 *namespace_id;
    const char                 *object_key;
} n00b_static_identity_t;

typedef struct n00b_static_identity_query_t {
    uint32_t               checks;
    uint64_t               len;
    n00b_alloc_type_info_t tinfo;
    n00b_gc_scan_kind_t    scan_kind;
    uint32_t               flags_mask;
    uint32_t               flags_value;
    uint64_t               check_offset;
    uint32_t               check_len;
    const unsigned char   *check_bytes;
} n00b_static_identity_query_t;

typedef struct n00b_static_object_desc_t {
    const void                   *start;
    uint64_t                      len;
    n00b_alloc_type_info_t        tinfo;
    n00b_gc_scan_kind_t           scan_kind;
    n00b_gc_scan_cb_t             scan_cb;
    void                         *scan_user;
    uint64_t                      object_id;
    const char                   *file;
    const n00b_static_identity_t *identity;
    uint32_t                      flags;
    // Build-time-written cached pointer-key hash. Zero = uncached. The
    // static-init helper writes a nonzero value here for key-bearing
    // static objects; the static-range registration path copies this
    // into n00b_alloc_range_t.cached_hash so n00b_hash() can
    // short-circuit on static-range hits. Placed at the end of the
    // struct so existing descriptor emitters that don't yet supply the
    // field zero-fill it via C's partial aggregate initializer rule.
    // The underlying type matches the `n00b_uint128_t` typedef below;
    // we spell it as `unsigned _BitInt(128)` directly here because the
    // typedef is introduced later in this header.
    unsigned _BitInt(128) cached_hash;
} n00b_static_object_desc_t;

#define N00B_STATIC_IMAGE_CONTRACT_VERSION 1u

typedef enum n00b_static_image_payload_kind_t : uint8_t {
    N00B_STATIC_IMAGE_PAYLOAD_NONE  = 0,
    N00B_STATIC_IMAGE_PAYLOAD_BYTES = 1,
} n00b_static_image_payload_kind_t;

typedef enum n00b_static_image_endian_t : uint8_t {
    N00B_STATIC_IMAGE_ENDIAN_UNKNOWN = 0,
    N00B_STATIC_IMAGE_ENDIAN_LITTLE  = 1,
    N00B_STATIC_IMAGE_ENDIAN_BIG     = 2,
} n00b_static_image_endian_t;

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)                                   \
    && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define N00B_STATIC_IMAGE_HOST_ENDIAN N00B_STATIC_IMAGE_ENDIAN_BIG
#else
#define N00B_STATIC_IMAGE_HOST_ENDIAN N00B_STATIC_IMAGE_ENDIAN_LITTLE
#endif

#define N00B_STATIC_IMAGE_ABI_INIT                                                             \
    {                                                                                          \
        .version       = N00B_STATIC_IMAGE_CONTRACT_VERSION,                                   \
        .pointer_bytes = (uint8_t)sizeof(void *),                                              \
        .size_t_bytes  = (uint8_t)sizeof(size_t),                                              \
        .char_bits     = 8,                                                                    \
        .endian        = N00B_STATIC_IMAGE_HOST_ENDIAN,                                        \
    }

typedef struct n00b_static_image_abi_t {
    uint32_t version;
    uint8_t  pointer_bytes;
    uint8_t  size_t_bytes;
    uint8_t  char_bits;
    uint8_t  endian;
} n00b_static_image_abi_t;

typedef enum n00b_static_init_arg_kind_t : uint8_t {
    N00B_STATIC_INIT_ARG_NONE  = 0,
    N00B_STATIC_INIT_ARG_BYTES = 1,
    N00B_STATIC_INIT_ARG_INT   = 2,
    N00B_STATIC_INIT_ARG_BOOL  = 3,
} n00b_static_init_arg_kind_t;

typedef struct n00b_static_init_arg_t {
    const char                 *name;
    n00b_static_init_arg_kind_t kind;
    union {
        struct {
            const void *data;
            uint64_t    len;
        } bytes;
        int64_t integer;
        bool    boolean;
    };
} n00b_static_init_arg_t;

typedef struct n00b_static_image_request_t {
    uint32_t                         version;
    uint64_t                         type_hash;
    const char                      *type_name;
    const char                      *symbol_prefix;
    const char                      *entry_attr;
    n00b_static_image_payload_kind_t payload_kind;
    const void                      *payload;
    uint64_t                         payload_len;
    const n00b_static_init_arg_t    *args;
    uint64_t                         arg_count;
    n00b_static_image_abi_t          target_abi;
    uint32_t                         object_flags;
    n00b_gc_scan_kind_t              required_scan_kind;
    const char                      *identity_namespace;
    const char                      *identity_object_key;
    const char                      *identity_payload_key;
} n00b_static_image_request_t;

typedef struct n00b_static_image_dependency_t {
    const n00b_static_object_desc_t *desc;
    uint64_t                         relocation_offset;
    const char                      *role;
} n00b_static_image_dependency_t;

typedef struct n00b_static_image_response_t {
    uint32_t                              version;
    const n00b_static_image_request_t    *request;
    const void                           *object_start;
    uint64_t                              object_len;
    n00b_gc_scan_kind_t                   scan_kind;
    n00b_gc_scan_cb_t                     scan_cb;
    void                                 *scan_user;
    const n00b_static_image_dependency_t *dependencies;
    uint64_t                              dependency_count;
} n00b_static_image_response_t;

typedef struct {
    uint64_t stride;
    uint64_t offset;
    uint64_t count;
} n00b_gc_struct_array_t;

// One discriminated-union (n00b_variant_t) field within an element. The
// element's `selector` word (a typehash(T) of the active alternative, or 0 if
// unset) decides whether the `value` word holds a heap pointer: it does iff
// `selector` is one of the variant's pointer alternatives. `ptr_hashes` lists
// those typehashes, sorted ascending for a binary search; `selector_offset`
// and `value_offset` are word offsets from the start of the element.
typedef struct {
    uint64_t        selector_offset;
    uint64_t        value_offset;
    uint64_t        ptr_hash_count;
    const uint64_t *ptr_hashes;
} n00b_gc_variant_field_t;

typedef struct {
    uint64_t                       stride;
    uint64_t                       count;
    uint64_t                       offset_count;
    const uint64_t                *offsets;
    uint64_t                       variant_count;
    const n00b_gc_variant_field_t *variants;
} n00b_gc_struct_layout_t;

extern void n00b_gc_scan_cb_struct_field(n00b_gc_map_t *m, void *user);
extern void n00b_gc_scan_cb_struct_layout(n00b_gc_map_t *m, void *user);
// Length-derived layout scan (element count from allocation size); used by
// the link-time type->GC-map dictionary so one descriptor serves any count.
extern void n00b_gc_scan_cb_type_layout(n00b_gc_map_t *m, void *user);

// D-049 link-time type->GC-map dictionary entry. ncc emits, per TU, a static
// const array of these (one per pointer-bearing aggregate type) into a linker
// section (the static table — laid out by the linker, no runtime assembly).
// The runtime reads the section directly; nothing is built dynamically.
typedef struct n00b_gc_type_map_entry_t {
    uint64_t                       type_hash; // typehash(T *)
    const n00b_gc_struct_layout_t *layout;    // per-element pointer offsets
} n00b_gc_type_map_entry_t;

// Post-link index entry for n00b_gcmap. This section intentionally carries no
// pointers so a post-link pass can sort/fill it without moving chained-fixup
// metadata on Mach-O.
typedef struct n00b_gc_type_map_index_entry_t {
    uint64_t type_hash;   // typehash(T *)
    uint64_t entry_index; // index into n00b_gcmap
} n00b_gc_type_map_index_entry_t;

// Section attribute for emitting gc-map entries. Defined in the umbrella
// header because ncc-generated code references it through n00b.h only.
#if defined(__APPLE__)
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("__DATA,n00b_gcmap"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("__DATA,n00b_gcidx"), gnu::used]]
#elif defined(_WIN32)
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("n00bg$m"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("n00bi$m"), gnu::used]]
#else
#define N00B_GC_TYPE_MAP_SECTION       [[gnu::section("n00b_gcmap"), gnu::used]]
#define N00B_GC_TYPE_MAP_INDEX_SECTION [[gnu::section("n00b_gcidx"), gnu::used]]
#endif
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
typedef uint64_t                             n00b_size_t;
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
