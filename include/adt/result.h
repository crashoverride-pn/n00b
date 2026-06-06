/**
 * @file result.h
 * @brief Type-safe result values using typeid().
 *
 * @c n00b_result_t(T) represents a value of type @p T on success,
 * or an @c n00b_result_error_t carrier on failure. The carrier supports
 * integer code errors for errno-style failures and typed pointer payload
 * errors for structured diagnostics.
 */
#pragma once

#include <stdint.h>
#include "util/assert.h"

typedef int n00b_err_t;

/** Error carrier variants supported by @c n00b_result_t(T). */
typedef enum {
    /** Legacy-compatible integer error stored in @c n00b_result_error_t.code. */
    N00B_RESULT_ERROR_CODE,
    /** Typed structured error stored as @c payload_type plus @c payload. */
    N00B_RESULT_ERROR_PAYLOAD,
} n00b_result_error_kind_t;

/**
 * @brief Canonical result error carrier.
 *
 * Code-compatible errors store @c kind as @c N00B_RESULT_ERROR_CODE and
 * expose the legacy @c n00b_err_t value through @c code. For code-compatible
 * errors, @c payload_type is zero and @c payload is @c nullptr.
 *
 * Structured payload errors store @c kind as @c N00B_RESULT_ERROR_PAYLOAD,
 * @c payload_type as @c typehash(E), and @c payload as the typed pointer.
 * Typed helper macros construct, identify, and retrieve pointer payloads
 * without requiring caller casts.
 */
typedef struct n00b_result_error {
    /** Discriminates which carrier fields are meaningful. */
    n00b_result_error_kind_t kind;
    /** Integer error value when @c kind is @c N00B_RESULT_ERROR_CODE. */
    n00b_err_t              code;
    /** Runtime payload type identity when @c kind is @c N00B_RESULT_ERROR_PAYLOAD. */
    uint64_t                payload_type;
    /** Structured error payload pointer when @c kind is @c N00B_RESULT_ERROR_PAYLOAD. */
    void                   *payload;
} n00b_result_error_t;

static inline n00b_result_error_t
_n00b_result_error_from_code(n00b_err_t code)
{
    return (n00b_result_error_t){
        .kind         = N00B_RESULT_ERROR_CODE,
        .code         = code,
        .payload_type = 0,
        .payload      = nullptr,
    };
}

static inline n00b_result_error_t
_n00b_result_error_from_carrier(n00b_result_error_t error)
{
    return error;
}

static inline n00b_result_error_t
_n00b_result_error_from_payload(uint64_t payload_type, void *payload)
{
    return (n00b_result_error_t){
        .kind         = N00B_RESULT_ERROR_PAYLOAD,
        .code         = 0,
        .payload_type = payload_type,
        .payload      = payload,
    };
}

#define _n00b_result_error_from(e)                                                            \
    _Generic((e),                                                                              \
        n00b_result_error_t: _n00b_result_error_from_carrier,                                  \
        default: _n00b_result_error_from_code)(e)

#define n00b_result_tid(T) typeid("result", T)
#define n00b_result_t(T)                                                                       \
    _generic_struct n00b_result_tid(T) {                                                       \
        bool                  is_ok;                                                           \
        T                     ok;                                                              \
        n00b_result_error_t   err;                                                             \
    }

#define n00b_result_ok(T, x)                                                                   \
    ((n00b_result_t(T)){                                                                       \
        .is_ok = true,                                                                         \
        .ok    = (x),                                                                          \
    })

#define n00b_result_err(T, e)                                                                  \
    ((n00b_result_t(T)){                                                                       \
        .is_ok = false,                                                                        \
        .err   = _n00b_result_error_from(e),                                                   \
    })

/**
 * @brief Construct an error result with a typed pointer payload.
 *
 * @param T       Result ok type.
 * @param E       Payload pointer type; stored with @c typehash(E).
 * @param payload Payload pointer value.
 */
#define n00b_result_err_payload(T, E, payload)                                                  \
    ({                                                                                         \
        E _bl_payload = (payload);                                                             \
        typeof(*_bl_payload) *_bl_checked_payload = _bl_payload;                                \
        void *_bl_payload_ptr = (void *)_bl_checked_payload;                                    \
        n00b_result_err(T, _n00b_result_error_from_payload(typehash(E), _bl_payload_ptr));      \
    })

#define n00b_result_is_ok(x)  ((x).is_ok)
#define n00b_result_is_err(x) (!(x).is_ok)

/**
 * @brief Return the raw error carrier.
 *
 * Use this when forwarding or inspecting either integer code errors or
 * structured payload errors. Asserts if the result is ok.
 */
#define n00b_result_get_error(x)                                                               \
    ({                                                                                         \
        auto _bl_r = (x);                                                                      \
        n00b_require(!_bl_r.is_ok, "n00b_result_get_error: result is ok");                     \
        _bl_r.err;                                                                             \
    })

/**
 * @brief Test whether a result is a structured pointer-payload error tagged
 * with @c typehash(E).
 */
#define n00b_result_is_err_payload(E, x)                                                       \
    ({                                                                                         \
        auto _bl_r = (x);                                                                      \
        !_bl_r.is_ok && _bl_r.err.kind == N00B_RESULT_ERROR_PAYLOAD                            \
            && _bl_r.err.payload_type == typehash(E);                                          \
    })

/** @brief Extract the value.  Asserts (aborts) if the result is an error. */
#define n00b_result_get(x)                                                                     \
    ({                                                                                         \
        auto _bl_r = (x);                                                                      \
        n00b_require(_bl_r.is_ok, "n00b_result_get: result is error");                         \
        *(_bl_r.is_ok ? &_bl_r.ok : (typeof(_bl_r.ok) *)nullptr);                              \
    })

/**
 * @brief Extract an integer code error.
 *
 * Use this only for errors created with @c n00b_result_err(T, code) or an
 * equivalent code-compatible carrier. Asserts if the result is ok or carries
 * a structured payload error.
 */
#define n00b_result_get_err(x)                                                                 \
    ({                                                                                         \
        auto _bl_r = (x);                                                                      \
        n00b_require(!_bl_r.is_ok, "n00b_result_get_err: result is ok");                       \
        n00b_require(_bl_r.err.kind == N00B_RESULT_ERROR_CODE,                                  \
                     "n00b_result_get_err: error is not an integer code");                     \
        *(!_bl_r.is_ok && _bl_r.err.kind == N00B_RESULT_ERROR_CODE                             \
              ? &_bl_r.err.code                                                               \
              : (n00b_err_t *)nullptr);                                                        \
    })

/**
 * @brief Extract a typed structured error payload.
 *
 * The payload type @p E must match the pointer type used with
 * @c n00b_result_err_payload(T, E, payload). Asserts if the result is ok, the
 * error is not a payload, or the payload type tag does not match
 * @c typehash(E).
 */
#define n00b_result_get_err_payload(E, x)                                                       \
    ({                                                                                         \
        auto _bl_payload_result = (x);                                                         \
        n00b_require(!_bl_payload_result.is_ok,                                                \
                     "n00b_result_get_err_payload: result is ok");                             \
        n00b_require(_bl_payload_result.err.kind == N00B_RESULT_ERROR_PAYLOAD,                  \
                     "n00b_result_get_err_payload: error is not a payload");                   \
        n00b_require(_bl_payload_result.err.payload_type == typehash(E),                        \
                     "n00b_result_get_err_payload: payload type mismatch");                    \
        E _bl_payload = (E)_bl_payload_result.err.payload;                                     \
        _bl_payload;                                                                           \
    })

#define n00b_result_get_or_else(x, y)                                                          \
    ({                                                                                         \
        auto _bl_r = (x);                                                                      \
        _bl_r.is_ok ? _bl_r.ok : (y);                                                          \
    })

#define n00b_result_match(x, ok_expr, err_expr) ((x).is_ok ? (ok_expr) : (err_expr))

// ============================================================================
// Stdlib wrapper macros — produce n00b_result_t values from system calls
// ============================================================================

/**
 * @brief Wrap a POSIX call that returns 0 on success, nonzero on error.
 * Usage: n00b_result_t(int) r = n00b_check_posix(getrlimit(...));
 */
#define n00b_check_posix(call)                                                                 \
    ({                                                                                         \
        int _rc = (call);                                                                      \
        _rc ? n00b_result_err(int, errno)                                                      \
            : n00b_result_ok(int, 0);                                                          \
    })

/**
 * @brief Wrap an mmap() call — returns MAP_FAILED on error.
 * Usage: n00b_result_t(void *) r = n00b_check_mmap(nullptr, sz, ...);
 */
#ifdef _WIN32
#define n00b_check_mmap(addr, sz, prot, flags, fd, offset)                                     \
    ({                                                                                         \
        (void)(prot); (void)(flags); (void)(fd); (void)(offset);                               \
        void *_p = VirtualAlloc((addr), (sz),                                                  \
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);                                \
        _p == nullptr ? n00b_result_err(void *, ENOMEM)                                        \
                      : n00b_result_ok(void *, _p);                                            \
    })
#else
#define n00b_check_mmap(...)                                                                   \
    ({                                                                                         \
        void *_p = mmap(__VA_ARGS__);                                                          \
        _p == MAP_FAILED ? n00b_result_err(void *, errno)                                      \
                         : n00b_result_ok(void *, _p);                                         \
    })
#endif

/**
 * @brief Wrap a sysconf() call — returns -1 on error.
 * Usage: n00b_result_t(int) r = n00b_check_sysconf(_SC_PAGESIZE);
 */
#define n00b_check_sysconf(name)                                                               \
    ({                                                                                         \
        long _v = sysconf(name);                                                               \
        _v == -1 ? n00b_result_err(int, errno)                                                 \
                 : n00b_result_ok(int, (int)_v);                                               \
    })
