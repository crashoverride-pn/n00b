/**
 * @file string.h
 * @brief Layout and construction helpers for `n00b_string_t`.
 *
 * `n00b_string_t` is a **heap type** (always passed by pointer), like
 * `n00b_buffer_t`.  It is GC-managed and has a vtable-backed
 * constructor (`n00b_string_init`).
 *
 * This header defines the struct layout and declares low-level
 * construction helpers so that other modules (e.g., buffer, unicode)
 * can allocate and populate string objects.  The full string API will
 * be ported separately.
 */
#pragma once

#include "n00b.h"
#include "core/gc_map.h"
#include "core/macros.h"

/**
 * @brief Immutable UTF-8 string with optional styling.
 *
 * @c data points to the raw UTF-8 bytes (not necessarily NUL-terminated).
 * @c styling is reserved for rich-text formatting metadata (TBD).
 */
struct n00b_string_t {
    char  *data;
    size_t u8_bytes;
    size_t codepoints;
    void  *styling;
};

// n00b_option_t(n00b_string_t *) is auto-defined via _generic_struct;
// include adt/option.h so dependent headers can use n00b_option_t().
#include "adt/option.h"


/**
 * @brief Initialize a pre-allocated `n00b_string_t` in place.
 *
 * This is the vtable-registered constructor.  Callers typically use
 * `n00b_string_from_raw()` / `n00b_string_from_cstr()` instead.
 *
 * @param self  Pre-allocated string (from `n00b_alloc`).
 *
 * @kw src       Source UTF-8 bytes (or NUL-terminated C string).
 * @kw byte_len  Byte count (-1 = use strlen).
 * @kw allocator Allocator for `.data` (nullptr = runtime default).
 * @kw cp_count  Optional output pointer for the codepoint count.
 *
 * @pre @p self is non-nullptr and zero-initialized.
 * @post self->data is NUL-terminated, codepoints counted.
 */
extern void n00b_string_init(n00b_string_t *self)
    _kargs {
        const char          *src       = nullptr;
        int64_t              byte_len  = -1;
        n00b_allocator_t    *allocator = nullptr;
        int64_t             *cp_count  = nullptr;
        n00b_gc_scan_kind_t  scan_kind = N00B_GC_SCAN_KIND_NONE;
        n00b_gc_scan_cb_t    scan_cb   = nullptr;
        void                *scan_user = nullptr;
    };

/**
 * @brief Construct an `n00b_string_t *` from UTF-8 data with known length.
 *
 * Allocates a new string, copies @p src (plus NUL terminator), and
 * counts UTF-8 codepoints internally.
 *
 * @param src        Source UTF-8 bytes (may be nullptr if byte_len == 0).
 * @param byte_len   Number of bytes to copy.
 * @return           Heap-allocated `n00b_string_t *`.
 *
 * @kw allocator  Allocator to use (nullptr = runtime default).
 * @kw cp_count   Optional output pointer for the codepoint count.
 *
 * @pre @p byte_len >= 0.
 * @post Returned string's data is NUL-terminated.
 */
extern n00b_string_t *n00b_string_from_raw(const char *src,
                                           int64_t     byte_len)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
        int64_t          *cp_count  = nullptr;
    };

/**
 * @brief Construct a string and rewrite debug/census allocation sites.
 *
 * This is the implementation target for caller-site attribution macros. Normal
 * code should call `n00b_string_from_raw()`.
 */
extern n00b_string_t *_n00b_string_from_raw_at(const char *src,
                                               int64_t     byte_len,
                                               const char *alloc_location)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
        int64_t          *cp_count  = nullptr;
    };

/**
 * @brief Construct an `n00b_string_t *` from a NUL-terminated C string.
 *
 * Computes byte length and counts UTF-8 codepoints.
 *
 * @param src  NUL-terminated C string.
 * @return     Heap-allocated `n00b_string_t *`.
 *
 * @kw allocator  Allocator to use (nullptr = runtime default).
 */
extern n00b_string_t *n00b_string_from_cstr(const char *src)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Construct a C-string string and rewrite debug/census allocation sites.
 *
 * This is the implementation target for caller-site attribution macros. Normal
 * code should call `n00b_string_from_cstr()`.
 */
extern n00b_string_t *_n00b_string_from_cstr_at(const char *src,
                                                const char *alloc_location)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Return an empty `n00b_string_t *`.
 *
 * @kw allocator  Allocator (nullptr = runtime default).
 * @return        Heap-allocated empty string (0 bytes, 0 codepoints).
 */
extern n00b_string_t *n00b_string_empty()
    _kargs { n00b_allocator_t *allocator = nullptr; };

/**
 * @brief Construct an empty string and rewrite debug/census allocation sites.
 *
 * This is the implementation target for caller-site attribution macros. Normal
 * code should call `n00b_string_empty()`.
 */
extern n00b_string_t *_n00b_string_empty_at(const char *alloc_location)
    _kargs { n00b_allocator_t *allocator = nullptr; };

#if (defined(N00B_DEBUG) || defined(N00B_DEBUG_LIVE_CENSUS))                                 \
    && !defined(N00B_NO_STRING_SITE_PROXY)
#define N00B_STRING_SITE_PROXY 1
#define n00b_string_from_raw(src, byte_len, ...)                                              \
    _n00b_string_from_raw_at((src),                                                           \
                             (byte_len),                                                      \
                             N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__))
#define n00b_string_from_cstr(src, ...)                                                       \
    _n00b_string_from_cstr_at((src), N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__))
#define n00b_string_empty(...)                                                                \
    _n00b_string_empty_at(N00B_LOC_STRING() __VA_OPT__(, __VA_ARGS__))
#endif

/* ----------------------------------------------------------------
 * Thread-local string-scratch scope.
 *
 * String-builder functions that allocate intermediate buffers
 * (@ref n00b_string_from_cstr / @ref n00b_string_from_raw /
 * @ref n00b_cformat ...) call @ref n00b_string_scope_enter at the
 * top and @ref n00b_string_scope_exit at the bottom.
 *
 * If the caller passed an explicit @c .allocator kwarg or has an
 * active @ref n00b_with_allocator scope, the builder uses that
 * allocator and the scope is a no-op.
 *
 * Otherwise, the outermost builder call stands up a thread-local
 * scratch pool, lets inner allocations land in it, then on exit
 * deep-copies the result string into the runtime default allocator
 * and tears the scratch down.  Nested builder calls share the
 * outer scratch (no inner re-create).
 *
 * Effect: per-event temp strings (the dominant GC heap pressure
 * source under burst load) never enter the default arena and are
 * not in the GC's scan set.
 * ---------------------------------------------------------------- */

typedef struct {
    bool created;
} n00b_string_scope_t;

/**
 * @brief Begin a string-builder scope.
 * @param resolved In/out: caller's resolved allocator pointer.
 *                 Updated to point at the appropriate allocator
 *                 (explicit / override / scratch) when @c *resolved
 *                 is initially null.
 * @return Scope token; pass to @ref n00b_string_scope_exit.
 */
extern n00b_string_scope_t
n00b_string_scope_enter(n00b_allocator_t **resolved);

/**
 * @brief End a string-builder scope.  Returns the (possibly
 *        deep-copied-to-durable-storage) result.
 */
extern n00b_string_t *
n00b_string_scope_exit(n00b_string_scope_t *scope, n00b_string_t *result);
