#include "text/strings/style_registry.h"
#include "text/strings/rich_desc.h"
#include "core/alloc.h"
#include "core/gc.h"
#include "core/hash.h"
#include "core/rt_access.h"
#include <string.h>
#include <assert.h>

// We store two dicts in the runtime: one for named styles, one for roles.
// Both are string-keyed (via n00b_hash_cstring) and store n00b_text_style_t *.

static n00b_dict_untyped_t *style_dict = nullptr;
static n00b_dict_untyped_t *role_dict  = nullptr;

// ===================================================================
// Internal helpers
// ===================================================================

static n00b_dict_untyped_t *
new_string_dict(void)
{
    n00b_dict_untyped_t *d = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(d, .hash = n00b_hash_cstring);
    return d;
}

static void
register_into(n00b_dict_untyped_t *d, const char *name,
              const n00b_text_style_t *style)
{
    n00b_text_style_t *copy = n00b_str_style_copy(style);
    n00b_dict_untyped_put(d, name, copy);
}

static n00b_text_style_t *
lookup_from(n00b_dict_untyped_t *d, const char *name)
{
    if (!d) {
        return nullptr;
    }

    bool  found;
    void *val = n00b_dict_untyped_get(d, name, &found);
    return found ? (n00b_text_style_t *)val : nullptr;
}

// ===================================================================
// Default registrations
//
// The implementation of `n00b_str_registry_install_defaults` lives in
// `style_registry_defaults.c`. WP-009 Phase 3 collapsed the old bootstrap
// no-op stub; both bootstrap and full libn00b now link the real defaults.
// ===================================================================

extern void n00b_str_registry_install_defaults(void);

// ===================================================================
// Public API
// ===================================================================

void
n00b_str_registry_init(void)
{
    style_dict = new_string_dict();
    role_dict  = new_string_dict();

    n00b_str_registry_install_defaults();
    n00b_rich_desc_cache_init();
}

void
n00b_str_style_register(const char *name, const n00b_text_style_t *style)
{
    assert(style_dict && "n00b_str_registry_init() must be called first");
    register_into(style_dict, name, style);
}

n00b_option_t(n00b_text_style_t *)
n00b_str_style_lookup(const char *name)
{
    return n00b_option_from_nullable(n00b_text_style_t *, lookup_from(style_dict, name));
}

void
n00b_str_role_register(const char *name, const n00b_text_style_t *style)
{
    assert(role_dict && "n00b_str_registry_init() must be called first");
    register_into(role_dict, name, style);
}

n00b_option_t(n00b_text_style_t *)
n00b_str_role_lookup(const char *name)
{
    return n00b_option_from_nullable(n00b_text_style_t *, lookup_from(role_dict, name));
}
