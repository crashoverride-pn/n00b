/**
 * @file type_info.h
 * @brief Type registry: per-type metadata and runtime type lookup.
 *
 * Every registered type gets an `n00b_type_info_t` that carries its name,
 * a fixed-size core vtable of bare function pointers (known signatures),
 * and an optional extension vtable with full signature metadata per method.
 *
 * The registry is a dict mapping `typehash(T)` -> `n00b_type_info_t *`,
 * stored on the runtime and initialized during `n00b_init()`.
 */
#pragma once

#include "n00b.h"
#include "core/gc_map.h"
#include "core/vtable.h"
#include "adt/option.h"

/**
 * @brief Classification of literal syntax for a type.
 */
typedef enum n00b_literal_kind_t : uint8_t {
    N00B_LIT_NONE = 0,
    N00B_LIT_PRIMITIVE,
    N00B_LIT_PREFIX,
    N00B_LIT_CONTAINER,
} n00b_literal_kind_t;

/**
 * @brief Build-time eligibility for generated static object layouts.
 *
 * `DEFAULT_DENY` is the zero value so unannotated registrations are not
 * silently eligible for static literals. `FORBIDDEN` covers representable
 * layouts that should not be emitted as static objects, while `TRANSIENT`
 * covers capability/session-backed types such as file descriptors, subprocesses,
 * or dynamically bound FFI modules. The remaining values describe supported
 * static image strategies.
 */
typedef enum n00b_static_layout_policy_t : uint8_t {
    N00B_STATIC_LAYOUT_DEFAULT_DENY = 0,
    N00B_STATIC_LAYOUT_FORBIDDEN,
    N00B_STATIC_LAYOUT_TRANSIENT,
    N00B_STATIC_LAYOUT_PLAIN,
    N00B_STATIC_LAYOUT_FIXUP,
    N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE,
} n00b_static_layout_policy_t;

/**
 * @brief Static-layout policy metadata attached to a registered type.
 */
typedef struct n00b_static_layout_info_t {
    n00b_static_layout_policy_t policy;
    n00b_gc_scan_kind_t         scan_kind;
    n00b_string_t              *reason;
} n00b_static_layout_info_t;

typedef n00b_option_t(n00b_array_t(n00b_method_t) *) n00b_ext_vtable_opt_t;
typedef n00b_option_t(n00b_static_layout_info_t *) n00b_static_layout_opt_t;

/**
 * @brief Per-type metadata: name, vtables, allocation size, literal info.
 *
 * `core_vtable` is a fixed-size array of bare function pointers indexed by
 * `n00b_builtin_type_fn` -- always present, signatures are known at compile
 * time.
 *
 * `ext_vtable` is an optional pointer to an `n00b_array_t(n00b_method_t)` --
 * none by default, set only for types with custom extension methods, where
 * each method carries full signature metadata.
 *
 * `lock_offset` is the byte offset of the `n00b_rwlock_t *` field in the
 * type's struct, or none if the type has no lock.  Used by the central
 * finalizer to clean up locks without per-object finalizer registration.
 *
 * `static_layout` is the runtime's source of truth for whether generated
 * static object layouts may be emitted for the type.
 */
typedef struct n00b_type_info_t {
    n00b_string_t            *name;
    n00b_vtable_entry        core_vtable[N00B_BI_NUM_FUNCS];
    n00b_ext_vtable_opt_t    ext_vtable;
    uint32_t                 alloc_len;
    n00b_option_t(uint32_t)  lock_offset;
    n00b_static_layout_info_t static_layout;
    n00b_literal_kind_t      literal_kind;
    n00b_string_t            *literal_modifier;
    bool                     ctor_takes_kargs;  /**< ctor(self, kargs) */
    bool                     ctor_takes_vargs;  /**< ctor(self, vargs, kargs) */
} n00b_type_info_t;

// ============================================================================
// Registry API
// ============================================================================

/**
 * @brief Initialize the type registry (called from n00b_init).
 *
 * Allocates the registry dict from the system pool and registers
 * all built-in types.
 */
extern void n00b_type_registry_init(void);

/**
 * @brief Register a type in the global registry.
 * @param type_hash typehash(T) for the type.
 * @param info      Type info to register (deep-copied into the registry).
 * @return true on success, false if the type_hash is already registered.
 */
extern bool n00b_type_register(uint64_t type_hash, const n00b_type_info_t *info);

/**
 * @brief Look up type info by typehash.
 * @param type_hash typehash(T) to look up.
 * @return The registered type info, or none if not found.
 */
extern n00b_option_t(n00b_type_info_t *) n00b_type_lookup(uint64_t type_hash);

/**
 * @brief Look up static-layout policy metadata by typehash.
 * @param type_hash typehash(T) to look up.
 * @return The registered static-layout metadata, or none if not registered.
 */
extern n00b_static_layout_opt_t n00b_type_static_layout(uint64_t type_hash);

/**
 * @brief Whether the registered type has an explicitly supported static layout.
 */
extern bool n00b_type_static_layout_allowed(uint64_t type_hash);

/**
 * @brief Stable policy name for diagnostics and tests.
 *
 * Returns an n00b r-string literal so callers can pass it straight to
 * `n00b_print` / `n00b_eprintf` / `n00b_string_eq`.
 */
extern n00b_string_t *n00b_static_layout_policy_name(n00b_static_layout_policy_t policy);

/**
 * @brief Get the typehash stored in an object's allocation header.
 * @param obj Pointer to a managed allocation.
 * @return The typehash, or 0 if the object has no allocation info.
 */
extern uint64_t n00b_obj_typehash(void *obj);

/**
 * @brief Get the type info for a managed object.
 * @param obj Pointer to a managed allocation.
 * @return Type info, or none if unregistered or not a managed object.
 */
extern n00b_option_t(n00b_type_info_t *) n00b_type_info_for(void *obj);

/**
 * @brief Add an extension method to a registered type.
 * @param type_hash typehash(T) of the type to extend.
 * @param method    Method descriptor (deep-copied into the registry).
 * @return true on success, false if the type is not registered.
 */
extern bool n00b_type_add_method(uint64_t type_hash, const n00b_method_t *method);

/**
 * @brief Look up a core vtable entry for a managed object.
 * @param obj  Pointer to a managed allocation.
 * @param slot Core vtable slot index.
 * @return The function pointer wrapped in `n00b_option_t`, or
 *         `n00b_option_none` if the object's type is unregistered, the
 *         slot index is out of range, or the slot is empty (vtable entry
 *         is nullptr).
 */
static inline n00b_option_t(n00b_vtable_entry)
    n00b_obj_core_method(void *obj, enum n00b_builtin_type_fn slot)
{
    auto info_opt = n00b_type_info_for(obj);

    if (!n00b_option_is_set(info_opt) || slot >= N00B_BI_NUM_FUNCS) {
        return n00b_option_none(n00b_vtable_entry);
    }

    return n00b_option_from_nullable(n00b_vtable_entry,
                                     n00b_option_get(info_opt)->core_vtable[slot]);
}

// ============================================================================
// Registration macros
// ============================================================================

/**
 * @brief Register a type with a pre-built type info struct.
 *
 * Usage:
 * ```c
 * N00B_TYPE_REGISTER(my_type_t,
 *     N00B_CORE_METHOD(N00B_BI_CONSTRUCTOR, my_ctor),
 *     N00B_CORE_METHOD(N00B_BI_FINALIZER, my_dtor),
 * );
 * ```
 */
/**
 * @brief Inline-construct an `n00b_string_t *` for an ASCII identifier.
 *
 * The compound literal lives in the caller's automatic storage at the
 * point of use, but `n00b_type_register` deep-copies into the system
 * pool, so lifetime is correct for the macro context. Type names are
 * pure ASCII identifiers (`uint64_t`, `n00b_buffer_t`, etc.), so
 * `codepoints == u8_bytes`.
 */
#define N00B_TYPE_NAME_LITERAL(name_cstr)                                                      \
    (&(n00b_string_t){                                                                         \
        .data       = (char *)(name_cstr),                                                     \
        .u8_bytes   = sizeof(name_cstr) - 1,                                                   \
        .codepoints = sizeof(name_cstr) - 1,                                                   \
        .styling    = nullptr,                                                                 \
    })

#define N00B_TYPE_REGISTER(T, ...)                                                             \
    n00b_type_register(typehash(T *),                                                          \
                       &(n00b_type_info_t){                                                    \
                           .name      = N00B_TYPE_NAME_LITERAL(N00B_TO_STRING(T)),             \
                           .alloc_len = sizeof(T),                                             \
                           __VA_ARGS__                                                         \
                       })

/**
 * @brief Set a core vtable slot (use inside N00B_TYPE_REGISTER).
 */
#define N00B_CORE_METHOD(slot, fn_ptr) .core_vtable[slot] = (n00b_vtable_entry)(fn_ptr)

/**
 * @brief Set the lock field offset (use inside N00B_TYPE_REGISTER).
 *
 * Tells the central finalizer where to find the `n00b_rwlock_t *`
 * field so it can free the lock without per-object registration.
 */
#define N00B_LOCK_FIELD(T, field) .lock_offset = n00b_option_set(uint32_t, (uint32_t)offsetof(T, field))

/** @brief Mark the constructor as taking kargs: `ctor(self, kargs)`. */
#define N00B_CTOR_KARGS .ctor_takes_kargs = true

/** @brief Mark the constructor as taking vargs+kargs: `ctor(self, vargs, kargs)`. */
#define N00B_CTOR_VARGS .ctor_takes_vargs = true, .ctor_takes_kargs = true

/** @brief Keep a type in the default deny bucket with a specific reason. */
#define N00B_TYPE_STATIC_DENY(reason_text)                                                     \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_DEFAULT_DENY,                                          \
        .scan_kind = N00B_GC_SCAN_KIND_DEFAULT,                                                \
        .reason    = (reason_text),                                                            \
    }

/** @brief Explicitly forbid generated static layouts for a type. */
#define N00B_TYPE_STATIC_FORBIDDEN(reason_text)                                                \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_FORBIDDEN,                                             \
        .scan_kind = N00B_GC_SCAN_KIND_NONE,                                                   \
        .reason    = (reason_text),                                                            \
    }

/** @brief Mark a capability/session-backed type as non-static. */
#define N00B_TYPE_STATIC_TRANSIENT(reason_text)                                                \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_TRANSIENT,                                             \
        .scan_kind = N00B_GC_SCAN_KIND_NONE,                                                   \
        .reason    = (reason_text),                                                            \
    }

/** @brief Mark a type as directly representable by a generated static layout. */
#define N00B_TYPE_STATIC_PLAIN(scan_kind_value)                                                \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_PLAIN,                                                 \
        .scan_kind = (scan_kind_value),                                                        \
    }

/** @brief Mark a type as statically representable after runtime fixup. */
#define N00B_TYPE_STATIC_FIXUP(scan_kind_value, reason_text)                                   \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_FIXUP,                                                 \
        .scan_kind = (scan_kind_value),                                                        \
        .reason    = (reason_text),                                                            \
    }

/** @brief Mark a type as representable by a constructor/marshal static image. */
#define N00B_TYPE_STATIC_CONSTRUCTOR_IMAGE(scan_kind_value, reason_text)                       \
    .static_layout = {                                                                         \
        .policy    = N00B_STATIC_LAYOUT_CONSTRUCTOR_IMAGE,                                     \
        .scan_kind = (scan_kind_value),                                                        \
        .reason    = (reason_text),                                                            \
    }

/**
 * @brief Look up an extension method by type hash and method name.
 * @param type_hash typehash(T) of the type.
 * @param method_name Name of the method to look up.
 * @return The function pointer, or none if not found.
 */
extern n00b_option_t(n00b_vtable_entry)
n00b_type_method_lookup(uint64_t type_hash, const char *method_name);

/**
 * @brief Look up the typehash of a registered type by its declared name.
 *
 * Linear-scans the registry for the first registered type whose
 * `n00b_type_info_t.name` equals @p name (case-sensitive). Returns 0
 * when no match is found. The registry is small (a few dozen entries
 * in practice) so the scan is cheap; the lookup is meant for the rare
 * codegen and inference fallback paths that have only the type's name
 * spelling (e.g., from a `tc_prim_t` or a `n00b_method_param_t.type_name`).
 *
 * @param name  Type name to search for (must be non-NULL).
 * @return      The typehash, or 0 if not registered.
 */
extern uint64_t n00b_type_name_to_hash(const char *name);

/**
 * @brief Look up the full extension method record by type hash and name.
 *
 * Sibling of `n00b_type_method_lookup` that returns a pointer to the
 * registry's `n00b_method_t` so callers can inspect the method's full
 * signature (return type, parameter types). The type-checker uses this
 * to propagate the method's return type into `tc_type_t` during
 * inference; codegen continues to use the lighter `n00b_type_method_lookup`
 * helper when it only needs the bare function pointer.
 *
 * The returned pointer aliases the registry's deep-copied `ext_vtable`
 * array. Callers must not mutate the underlying method.
 *
 * @param type_hash   typehash(T) of the type to query.
 * @param method_name Method name to look up.
 * @return            Pointer to the method, or none if not found.
 */
extern n00b_option_t(n00b_method_t *)
n00b_type_method_lookup_full(uint64_t type_hash, const char *method_name);

/**
 * @brief Register all built-in types (called by n00b_type_registry_init).
 */
extern void n00b_register_builtin_types(void);
