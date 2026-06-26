/**
 * @file core/codegen_abi_inject.h
 * @brief Stable, force-injected slice of the GC/marshal codegen ABI.
 *
 * ncc emits no `#include` of its own, so any struct that ncc-emitted code
 * references *by name* into an arbitrary translation unit must be visible in
 * every such TU. This header holds exactly that slice — the GC root tables,
 * the GC stack-map / non-local-exit runtime API, and the static-object
 * descriptors — and the n00b build force-includes it on every compile via
 * `-include core/codegen_abi_inject.h` (right after `-include n00b.h`).
 *
 * It is deliberately SEPARATE from `core/codegen_abi.h`: the type->GC-map
 * dictionary / variant / transient structs in that header churn frequently and
 * are now decoupled (ncc emits raw `n00b_gcraw` records under
 * `--ncc-gcmap-prelink`, so no TU references those typed structs anymore). The
 * structs here are stable — they change rarely — so force-including them keeps
 * ncc-emitted typed code compiling without coupling the whole tree to the
 * volatile dictionary structs. Editing `codegen_abi.h` no longer rebuilds the
 * world; editing this header does, but it almost never changes.
 *
 * See doc/codegen-abi-prelink-plan.md.
 *
 * Depends on `n00b.h` for the scalar typedefs, `n00b_alloc_type_info_t`, the
 * stable allocator scan API (n00b_gc_scan_kind_t / _cb_t), and <setjmp.h>.
 */
#pragma once

#include "n00b.h"

/* ── GC roots ─────────────────────────────────────────────────────────────
 * Defined in full (not forward-declared) because ncc's `--ncc-auto-gc-roots`
 * transform emits a `static n00b_gc_root_t[]` table plus an
 * `n00b_gc_root_section_entry_t` descriptor into arbitrary translation units.
 * The public GC API (`n00b_gc_register_root` macro, `n00b_collect`, etc.) still
 * lives in `include/core/gc.h`. */
typedef struct n00b_gc_root_t {
    void  *addr;      /**< Start of the scannable region. */
    size_t num_words; /**< Number of pointer-sized words to scan. */
} n00b_gc_root_t;
typedef struct n00b_gc_root_section_entry_t {
    const n00b_gc_root_t *roots;
    size_t                count;
} n00b_gc_root_section_entry_t;

/* Declared here (in addition to `include/core/gc.h`) for ncc-emitted callers. */
extern void n00b_gc_register_roots(const n00b_gc_root_t *roots, size_t count);

/* ── GC stack maps / non-local exit ───────────────────────────────────────
 * ncc-emitted exact-stack-scanning prologues reference these by name. */
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
// push/pop take (void *) — ncc-emitted prologues reference these by name in
// arbitrary TUs and now spell the frame/map as anonymous structs (no codegen-ABI
// header). Declaring them void * here keeps the emitted forward-decls compatible
// with this header in the hand-written TUs that include it. The implementations
// (src/core/gc.c) recover the concrete types internally.
extern void            n00b_gc_stack_push(void *frame, const void *map, void **roots);
extern void            n00b_gc_stack_pop(void *frame);
extern n00b_jmp_buf_t *n00b_gc_stack_prepare_jmp(n00b_jmp_buf_t *ctx);
extern void            n00b_gc_stack_restore(n00b_gc_stack_frame_t *top);
[[noreturn]] extern void n00b_longjmp(n00b_jmp_buf_t *ctx, int value);

// Supported non-local-exit interface for code compiled with GC stack maps.
// The checkpoint records the current published frame chain; the jump restores
// it before transferring control so skipped cleanup frames are not scanned.
// Checkpoints must be jumped to only from the same thread that created them.
#define n00b_setjmp(ctx) setjmp(n00b_gc_stack_prepare_jmp((ctx))->n00b_jmp_env)

/* ── Static-object descriptors ────────────────────────────────────────────
 * The static-image / r-string transforms emit `n00b_static_object_desc_t` and
 * `n00b_static_identity_t` initializers (plus the enums) into arbitrary TUs
 * (r"…"/b"…" literals are pervasive). */
enum n00b_static_object_flags_t : uint32_t {
    N00B_STATIC_OBJECT_F_NONE        = 0,
    N00B_STATIC_OBJECT_F_READONLY    = 1u << 0,
    N00B_STATIC_OBJECT_F_MUTABLE     = 1u << 1,
    N00B_STATIC_OBJECT_F_INIT_RWLOCK = 1u << 2,
    N00B_STATIC_OBJECT_F_BAKED    = 1u << 3,
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

// GC scan callbacks referenced by name in ncc-emitted static-object descriptors
// (`.scan_cb = n00b_gc_scan_cb_*`) — see the r-string templates in meson.build.
// They take the stable n00b_gc_map_t* (in n00b.h); their definitions live in
// the GC runtime. They are declared here (force-included) so emitted descriptors
// in arbitrary TUs resolve them. (The link-time type->GC-map dictionary uses
// n00b_gc_scan_cb_type_layout, length-derived so one descriptor serves any count.)
extern void n00b_gc_scan_cb_struct_field(n00b_gc_map_t *m, void *user);
extern void n00b_gc_scan_cb_struct_layout(n00b_gc_map_t *m, void *user);
extern void n00b_gc_scan_cb_type_layout(n00b_gc_map_t *m, void *user);

// WP-001 transient-field table (force-included because ncc emits these TYPED
// into the few TUs that define a [[n00b::transient]] field — the transient path
// is not raw-ified). A field marked [[n00b::transient]] is GC-scanned/copied
// normally but ZEROED on marshal (fds, handles, any non-portable state that must
// not enter a content hash). ncc emits, per such TU, an n00b_transient_map_entry_t
// array into the n00b_trmap section (sibling to n00b_gcmap) plus a
// post-link-fillable n00b_tridx index. BYTE-granular: a transient field may be a
// sub-word scalar, so offsets/sizes are raw bytes, not words.
typedef struct n00b_transient_layout_t {
    uint64_t        field_count;
    const uint64_t *byte_offsets; // raw byte offset of each transient field
    const uint64_t *byte_sizes;   // raw byte size of each transient field
} n00b_transient_layout_t;

typedef struct n00b_transient_map_entry_t {
    uint64_t                       type_hash; // typehash(T *)
    const n00b_transient_layout_t *layout;
} n00b_transient_map_entry_t;

typedef struct n00b_transient_map_index_entry_t {
    uint64_t type_hash;   // typehash(T *)
    uint64_t entry_index; // index into n00b_trmap
} n00b_transient_map_index_entry_t;

#if defined(__APPLE__)
#define N00B_TRANSIENT_MAP_SECTION       [[gnu::section("__DATA,n00b_trmap"), gnu::used]]
#define N00B_TRANSIENT_MAP_INDEX_SECTION [[gnu::section("__DATA,n00b_tridx"), gnu::used]]
#elif defined(_WIN32)
#define N00B_TRANSIENT_MAP_SECTION       [[gnu::section("n00bt$m"), gnu::used]]
#define N00B_TRANSIENT_MAP_INDEX_SECTION [[gnu::section("n00bj$m"), gnu::used]]
#else
#define N00B_TRANSIENT_MAP_SECTION       [[gnu::section("n00b_trmap"), gnu::used]]
#define N00B_TRANSIENT_MAP_INDEX_SECTION [[gnu::section("n00b_tridx"), gnu::used]]
#endif

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
    // Build-time-written cached pointer-key hash. Zero = uncached.
    // Generated static-init code writes a nonzero value here for key-bearing
    // static objects; the static-range registration path copies this
    // into n00b_alloc_range_t.cached_hash so n00b_hash() can
    // short-circuit on static-range hits. Placed at the end of the
    // struct so existing descriptor emitters that don't yet supply the
    // field zero-fill it via C's partial aggregate initializer rule.
    // The underlying type matches the `n00b_uint128_t` typedef in n00b.h;
    // we spell it as `unsigned _BitInt(128)` directly here because that
    // typedef may not be visible at this point in the include order.
    unsigned _BitInt(128) cached_hash;
} n00b_static_object_desc_t;
