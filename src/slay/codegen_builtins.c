/**
 * @file codegen_builtins.c
 * @brief Built-in function implementations for the n00b codegen.
 *
 * C runtime helpers that get imported into MIR and called from JIT'd
 * code. The dispatch function checks function names against a small
 * table and emits the appropriate MIR import + call.
 */

#include "n00b.h"
#include "slay/codegen_builtins.h"
#include "slay/codegen.h"
#include "core/string.h"
#include "core/type_info.h"
#include "text/strings/string_ops.h"
#include "text/strings/string_convert.h" // n00b_unicode_str_to_cstr (MIR edge)
#include "text/strings/format.h"         // n00b_cformat

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

// ============================================================================
// Type tag → type hash mapping for vtable dispatch.
//
// The side-table lookup in `n00b_codegen_method_dispatch` consults the
// per-session side-table first via `n00b_cg_val_get_type_hash`. The
// hardcoded primitive switch below is the fallback for values whose
// typehash was never recorded (numerics, generic temps, etc.). Adding
// LIST/DICT etc. here requires registering their type info first.
// ============================================================================

static uint64_t
type_tag_to_hash(n00b_cg_type_tag_t tag)
{
    switch (tag) {
    case N00B_CG_STRING:
        return typehash(n00b_string_t *);
    case N00B_CG_OPTION:
        return typehash(n00b_rt_option_t *);
    case N00B_CG_RESULT:
        return typehash(n00b_rt_result_t *);
    // TODO: LIST, DICT, etc. when registered.
    default:
        return 0;
    }
}

// Maps a `n00b_method_param_t.type_name` C spelling to a codegen type
// tag for the MIR ABI. Recognises the same primitive spellings as
// `n00b_tc_type_from_c_name`; unknown names default to `N00B_CG_I64`
// which shares the MIR_T_I64 layout used by every pointer-like type
// (string, ptr, registered opaques). The mapping mirrors the table
// in `src/n00b/n00b_type_map.c`.
static n00b_cg_type_tag_t
method_ret_type_to_tag(const char *type_name)
{
    if (!type_name) {
        return N00B_CG_I64;
    }

    struct {
        const char        *c_name;
        n00b_cg_type_tag_t tag;
    } table[] = {
        { "void",           N00B_CG_VOID   },
        { "bool",           N00B_CG_BOOL   },
        { "i8",             N00B_CG_I8     },
        { "i16",            N00B_CG_I16    },
        { "i32",            N00B_CG_I32    },
        { "i64",            N00B_CG_I64    },
        { "int",            N00B_CG_I64    },
        { "u8",             N00B_CG_U8     },
        { "u16",            N00B_CG_U16    },
        { "u32",            N00B_CG_U32    },
        { "u64",            N00B_CG_U64    },
        { "f32",            N00B_CG_F32    },
        { "f64",            N00B_CG_F64    },
        { "string",         N00B_CG_STRING },
        { "n00b_string_t *", N00B_CG_STRING },
        { "n00b_string_t*",  N00B_CG_STRING },
        { "nil",            N00B_CG_NIL    },
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(type_name, table[i].c_name) == 0) {
            return table[i].tag;
        }
    }

    // Unknown — likely a registered opaque or pointer. MIR_T_I64
    // is the right ABI; the side-table carries the precise typehash.
    return N00B_CG_I64;
}

static uint64_t
n00b_builtin_hash_key_bytes(uint64_t hash, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

uint64_t
n00b_codegen_session_namespace_key(n00b_cg_session_t *s)
{
    uint64_t hash = 1469598103934665603ULL;
    uint64_t ptr  = (uint64_t)(uintptr_t)s;

    return n00b_builtin_hash_key_bytes(hash, &ptr, sizeof(ptr));
}

static n00b_uint128_t
n00b_rt_value_hash128(n00b_rt_value_t value)
{
    n00b_uint128_t h;

    if (value.tag == N00B_CG_STRING && value.payload != 0) {
        h = n00b_string_hash((void *)(uintptr_t)value.payload);
        h ^= ((n00b_uint128_t)value.tag << 64) | (n00b_uint128_t)value.tag;
    }
    else {
        h = n00b_hash_raw(&value, sizeof(value));
    }

    if (h == (n00b_uint128_t)0) {
        h = (((n00b_uint128_t)0x9e3779b97f4a7c15ULL) << 64) | 0xbf58476d1ce4e5b9ULL;
    }

    return h;
}

n00b_rt_value_t
n00b_rt_value_pack(uint64_t payload, n00b_cg_type_tag_t tag)
{
    return (n00b_rt_value_t){
        .payload = payload,
        .tag     = (uint64_t)tag,
    };
}

bool
n00b_rt_value_eq(n00b_rt_value_t a, n00b_rt_value_t b)
{
    if (a.tag != b.tag) {
        return false;
    }

    if (a.tag == N00B_CG_STRING) {
        if (a.payload == 0 || b.payload == 0) {
            return a.payload == b.payload;
        }

        return n00b_unicode_str_eq((n00b_string_t *)(uintptr_t)a.payload,
                                   (n00b_string_t *)(uintptr_t)b.payload);
    }

    return a.payload == b.payload;
}

uint64_t
n00b_rt_value_hash64(n00b_rt_value_t value)
{
    n00b_uint128_t h = n00b_rt_value_hash128(value);

    return (uint64_t)h ^ (uint64_t)(h >> 64);
}

n00b_rt_value_t
n00b_rt_value_copy(n00b_rt_value_t value)
{
    return value;
}

typedef struct n00b_confspec_state_t {
    uint64_t                      namespace_key;
    int64_t                       section_total;
    int64_t                       field_total;
    struct n00b_confspec_state_t *next;
} n00b_confspec_state_t;

static n00b_confspec_state_t *confspec_states;

static n00b_confspec_state_t *
n00b_confspec_state(uint64_t namespace_key, bool create)
{
    n00b_confspec_state_t *state;
    for (state = confspec_states; state; state = state->next) {
        if (state->namespace_key == namespace_key) {
            return state;
        }
    }

    if (!create) {
        return NULL;
    }

    state                        = n00b_alloc(n00b_confspec_state_t);
    state->namespace_key         = namespace_key;
    state->next                  = confspec_states;
    confspec_states              = state;
    return state;
}

// ============================================================================
// C runtime helpers — called from JIT'd code via MIR import.
// These must have stable ABIs (no _kargs, no ncc extensions).
// ============================================================================

void
n00b_builtin_print_i64(int64_t val)
{
    printf("%" PRId64 "\n", val);
}

void
n00b_builtin_print_u64(uint64_t val)
{
    printf("%" PRIu64 "\n", val);
}

void
n00b_builtin_print_f64(double val)
{
    printf("%g\n", val);
}

void
n00b_builtin_print_bool(int64_t val)
{
    printf("%s\n", val ? "true" : "false");
}

void
n00b_builtin_print_str(void *str_ptr)
{
    if (!str_ptr) {
        printf("nil\n");
        return;
    }

    n00b_string_t *s = (n00b_string_t *)str_ptr;
    printf("%.*s\n", (int)s->u8_bytes, s->data);
}

void
n00b_builtin_print_nil(void)
{
    printf("nil\n");
}

void
n00b_builtin_parameter_validate(void *name, int64_t ok)
{
    if (ok) {
        return;
    }

    n00b_string_t *s = (n00b_string_t *)name;

    if (s && s->data) {
        fprintf(stderr,
                "n00b: parameter validation failed for %.*s\n",
                (int)s->u8_bytes,
                (const char *)s->data);
    }
    else {
        fprintf(stderr, "n00b: parameter validation failed\n");
    }

    exit(1);
}

void
n00b_builtin_confspec_register(uint64_t namespace_key, int64_t sections, int64_t fields)
{
    n00b_confspec_state_t *state = n00b_confspec_state(namespace_key, true);
    state->section_total += sections;
    state->field_total += fields;
}

int64_t
n00b_builtin_confspec_section_count(uint64_t namespace_key)
{
    n00b_confspec_state_t *state = n00b_confspec_state(namespace_key, false);
    return state ? state->section_total : 0;
}

int64_t
n00b_builtin_confspec_field_count(uint64_t namespace_key)
{
    n00b_confspec_state_t *state = n00b_confspec_state(namespace_key, false);
    return state ? state->field_total : 0;
}

static MIR_val_t
n00b_builtin_callback_callv(void *callback, MIR_val_t *args, int32_t n_args)
{
    n00b_rt_callback_t *cb = (n00b_rt_callback_t *)callback;

    if (!cb || !cb->target || !cb->invoke) {
        if (cb && cb->func_name) {
            fprintf(stderr, "n00b: callback invocation failed for %s\n", cb->func_name);
        }
        else {
            fprintf(stderr, "n00b: callback invocation failed\n");
        }
        exit(1);
    }

    MIR_val_t result = {0};

    if (!cb->invoke(cb->target, &result, args, n_args)) {
        if (cb->func_name) {
            fprintf(stderr, "n00b: callback invocation failed for %s\n", cb->func_name);
        }
        else {
            fprintf(stderr, "n00b: callback invocation failed\n");
        }
        exit(1);
    }

    return result;
}

#define N00B_CB_SET_U(slot, value) ((slot).u = (uint64_t)(value))
#define N00B_CB_SET_F(slot, value) ((slot).f = (float)(value))
#define N00B_CB_SET_D(slot, value) ((slot).d = (double)(value))

#define N00B_CB_RETURN_U(result) return (result).u
#define N00B_CB_RETURN_F(result) return (result).f
#define N00B_CB_RETURN_D(result) return (result).d
#define N00B_CB_RETURN_V(result)                                                               \
    do {                                                                                       \
        (void)(result);                                                                        \
        return;                                                                                \
    } while (0)

#define N00B_CB_DEF0(rs, rtype, return_result)                                                 \
    static rtype n00b_builtin_callback_call0_##rs(void *callback)                              \
    {                                                                                          \
        MIR_val_t result = n00b_builtin_callback_callv(callback, NULL, 0);                     \
        return_result(result);                                                                 \
    }

#define N00B_CB_DEF1(rs, rtype, return_result, a0s, a0type, set0)                              \
    static rtype n00b_builtin_callback_call1_##rs##_##a0s(void *callback, a0type arg0)         \
    {                                                                                          \
        MIR_val_t args[1] = {{0}};                                                             \
        set0(args[0], arg0);                                                                   \
        MIR_val_t result = n00b_builtin_callback_callv(callback, args, 1);                     \
        return_result(result);                                                                 \
    }

#define N00B_CB_DEF2(rs, rtype, return_result, a0s, a0type, set0, a1s, a1type, set1)           \
    static rtype n00b_builtin_callback_call2_##rs##_##a0s##_##a1s(void  *callback,             \
                                                                  a0type arg0,                 \
                                                                  a1type arg1)                 \
    {                                                                                          \
        MIR_val_t args[2] = {{0}, {0}};                                                        \
        set0(args[0], arg0);                                                                   \
        set1(args[1], arg1);                                                                   \
        MIR_val_t result = n00b_builtin_callback_callv(callback, args, 2);                     \
        return_result(result);                                                                 \
    }

#define N00B_CB_DEF1_ALL_ARGS(rs, rtype, return_result)                                        \
    N00B_CB_DEF1(rs, rtype, return_result, u, uint64_t, N00B_CB_SET_U)                         \
    N00B_CB_DEF1(rs, rtype, return_result, f, float, N00B_CB_SET_F)                            \
    N00B_CB_DEF1(rs, rtype, return_result, d, double, N00B_CB_SET_D)

#define N00B_CB_DEF2_FOR_ARG1(rs, rtype, return_result, a0s, a0type, set0)                     \
    N00B_CB_DEF2(rs, rtype, return_result, a0s, a0type, set0, u, uint64_t, N00B_CB_SET_U)      \
    N00B_CB_DEF2(rs, rtype, return_result, a0s, a0type, set0, f, float, N00B_CB_SET_F)         \
    N00B_CB_DEF2(rs, rtype, return_result, a0s, a0type, set0, d, double, N00B_CB_SET_D)

#define N00B_CB_DEF2_ALL_ARGS(rs, rtype, return_result)                                        \
    N00B_CB_DEF2_FOR_ARG1(rs, rtype, return_result, u, uint64_t, N00B_CB_SET_U)                \
    N00B_CB_DEF2_FOR_ARG1(rs, rtype, return_result, f, float, N00B_CB_SET_F)                   \
    N00B_CB_DEF2_FOR_ARG1(rs, rtype, return_result, d, double, N00B_CB_SET_D)

#define N00B_CB_DEF_RET(rs, rtype, return_result)                                              \
    N00B_CB_DEF0(rs, rtype, return_result)                                                     \
    N00B_CB_DEF1_ALL_ARGS(rs, rtype, return_result)                                            \
    N00B_CB_DEF2_ALL_ARGS(rs, rtype, return_result)

N00B_CB_DEF_RET(u, uint64_t, N00B_CB_RETURN_U)
N00B_CB_DEF_RET(f, float, N00B_CB_RETURN_F)
N00B_CB_DEF_RET(d, double, N00B_CB_RETURN_D)
N00B_CB_DEF_RET(v, void, N00B_CB_RETURN_V)

uint64_t
n00b_builtin_callback_call0(void *callback)
{
    return n00b_builtin_callback_call0_u(callback);
}

uint64_t
n00b_builtin_callback_call1(void *callback, uint64_t arg0)
{
    return n00b_builtin_callback_call1_u_u(callback, arg0);
}

uint64_t
n00b_builtin_callback_call2(void *callback, uint64_t arg0, uint64_t arg1)
{
    return n00b_builtin_callback_call2_u_u_u(callback, arg0, arg1);
}

typedef enum {
    N00B_CB_ABI_U,
    N00B_CB_ABI_F,
    N00B_CB_ABI_D,
    N00B_CB_ABI_V,
} n00b_cb_abi_t;

typedef struct {
    int32_t       arity;
    n00b_cb_abi_t ret;
    n00b_cb_abi_t arg0;
    n00b_cb_abi_t arg1;
    const char   *name;
    void         *addr;
} n00b_callback_helper_t;

#define N00B_CB_ABI_u N00B_CB_ABI_U
#define N00B_CB_ABI_f N00B_CB_ABI_F
#define N00B_CB_ABI_d N00B_CB_ABI_D
#define N00B_CB_ABI_v N00B_CB_ABI_V

#define N00B_CB_ENTRY0(rs)                                                                     \
    {0,                                                                                        \
     N00B_CB_ABI_##rs,                                                                         \
     N00B_CB_ABI_U,                                                                            \
     N00B_CB_ABI_U,                                                                            \
     "n00b_builtin_callback_call0_" #rs,                                                       \
     (void *)n00b_builtin_callback_call0_##rs}

#define N00B_CB_ENTRY1(rs, a0s)                                                                \
    {1,                                                                                        \
     N00B_CB_ABI_##rs,                                                                         \
     N00B_CB_ABI_##a0s,                                                                        \
     N00B_CB_ABI_U,                                                                            \
     "n00b_builtin_callback_call1_" #rs "_" #a0s,                                              \
     (void *)n00b_builtin_callback_call1_##rs##_##a0s}

#define N00B_CB_ENTRY2(rs, a0s, a1s)                                                           \
    {2,                                                                                        \
     N00B_CB_ABI_##rs,                                                                         \
     N00B_CB_ABI_##a0s,                                                                        \
     N00B_CB_ABI_##a1s,                                                                        \
     "n00b_builtin_callback_call2_" #rs "_" #a0s "_" #a1s,                                     \
     (void *)n00b_builtin_callback_call2_##rs##_##a0s##_##a1s}

#define N00B_CB_ENTRY1_ALL_ARGS(rs)                                                            \
    N00B_CB_ENTRY1(rs, u), N00B_CB_ENTRY1(rs, f), N00B_CB_ENTRY1(rs, d)

#define N00B_CB_ENTRY2_FOR_ARG1(rs, a0s)                                                       \
    N00B_CB_ENTRY2(rs, a0s, u), N00B_CB_ENTRY2(rs, a0s, f), N00B_CB_ENTRY2(rs, a0s, d)

#define N00B_CB_ENTRY2_ALL_ARGS(rs)                                                            \
    N00B_CB_ENTRY2_FOR_ARG1(rs, u), N00B_CB_ENTRY2_FOR_ARG1(rs, f),                            \
        N00B_CB_ENTRY2_FOR_ARG1(rs, d)

#define N00B_CB_ENTRIES_FOR_RET(rs)                                                            \
    N00B_CB_ENTRY0(rs), N00B_CB_ENTRY1_ALL_ARGS(rs), N00B_CB_ENTRY2_ALL_ARGS(rs)

static const n00b_callback_helper_t callback_helpers[] = {
    N00B_CB_ENTRIES_FOR_RET(u),
    N00B_CB_ENTRIES_FOR_RET(f),
    N00B_CB_ENTRIES_FOR_RET(d),
    N00B_CB_ENTRIES_FOR_RET(v),
};

static n00b_cb_abi_t
n00b_callback_ret_abi(n00b_cg_type_tag_t tag)
{
    switch (tag) {
    case N00B_CG_VOID:
        return N00B_CB_ABI_V;
    case N00B_CG_F32:
        return N00B_CB_ABI_F;
    case N00B_CG_F64:
        return N00B_CB_ABI_D;
    default:
        return N00B_CB_ABI_U;
    }
}

static n00b_cb_abi_t
n00b_callback_arg_abi(n00b_cg_type_tag_t tag)
{
    switch (tag) {
    case N00B_CG_F32:
        return N00B_CB_ABI_F;
    case N00B_CG_F64:
        return N00B_CB_ABI_D;
    default:
        return N00B_CB_ABI_U;
    }
}

static bool
n00b_callback_helper_for_signature(int32_t            arity,
                                   n00b_cg_type_tag_t ret_type,
                                   n00b_cg_type_tag_t arg0_type,
                                   n00b_cg_type_tag_t arg1_type,
                                   const char       **name,
                                   void             **addr)
{
    n00b_cb_abi_t ret  = n00b_callback_ret_abi(ret_type);
    n00b_cb_abi_t arg0 = n00b_callback_arg_abi(arg0_type);
    n00b_cb_abi_t arg1 = n00b_callback_arg_abi(arg1_type);
    size_t        n    = sizeof(callback_helpers) / sizeof(callback_helpers[0]);

    for (size_t i = 0; i < n; i++) {
        const n00b_callback_helper_t *helper = &callback_helpers[i];

        if (helper->arity == arity && helper->ret == ret && (arity < 1 || helper->arg0 == arg0)
            && (arity < 2 || helper->arg1 == arg1)) {
            *name = helper->name;
            *addr = helper->addr;
            return true;
        }
    }

    return false;
}

// ============================================================================
// String runtime helpers — thin wrappers with stable C ABI (no _kargs).
// ============================================================================

void *
n00b_builtin_str_concat(void *a, void *b)
{
    return n00b_unicode_str_cat((n00b_string_t *)a, (n00b_string_t *)b);
}

int64_t
n00b_builtin_str_eq(void *a, void *b)
{
    return n00b_unicode_str_eq((n00b_string_t *)a, (n00b_string_t *)b);
}

int64_t
n00b_builtin_str_len(void *s)
{
    if (!s) {
        return 0;
    }

    return (int64_t)((n00b_string_t *)s)->codepoints;
}

void *
n00b_builtin_str_get(void *s, int64_t ix)
{
    if (!s) {
        return n00b_string_empty();
    }

    return n00b_unicode_str_grapheme_at((n00b_string_t *)s, (int32_t)ix);
}

void *
n00b_builtin_str_slice(void *s, int64_t start, int64_t has_start, int64_t end, int64_t has_end)
{
    if (!s) {
        return n00b_string_empty();
    }

    n00b_string_t *str = (n00b_string_t *)s;
    int64_t        lo  = has_start ? start : 0;
    int64_t        hi  = has_end ? end : (int64_t)str->codepoints;

    return n00b_unicode_str_slice(str, (int32_t)lo, (int32_t)hi);
}

// --- List helpers ---

typedef n00b_list_t(n00b_rt_value_t) n00b_rt_value_list_t;

static int64_t
n00b_rt_normalize_slice_bound(int64_t value, int64_t len)
{
    if (value < 0) {
        value += len;
    }

    if (value < 0) {
        return 0;
    }

    if (value > len) {
        return len;
    }

    return value;
}

void *
n00b_builtin_list_new(void)
{
    n00b_rt_value_list_t *list = n00b_alloc(n00b_rt_value_list_t);

    *list = n00b_list_new_private(n00b_rt_value_t);

    return list;
}

void
n00b_builtin_list_push_i64(void *list, uint64_t val)
{
    n00b_builtin_list_push_value(list, val, N00B_CG_I64);
}

void
n00b_builtin_list_push_value(void *list, uint64_t payload, int64_t tag)
{
    if (!list) {
        return;
    }

    n00b_rt_value_list_t *l = (n00b_rt_value_list_t *)list;
    n00b_rt_value_t       v = n00b_rt_value_pack(payload, (n00b_cg_type_tag_t)tag);
    n00b_list_push(*l, v);
}

static n00b_rt_value_t
n00b_builtin_list_get_value(void *list, int64_t ix)
{
    if (!list || ix < 0) {
        fprintf(stderr, "n00b: list index out of bounds\n");
        abort();
    }

    n00b_rt_value_list_t *l = (n00b_rt_value_list_t *)list;

    if ((size_t)ix >= n00b_list_len(*l)) {
        fprintf(stderr, "n00b: list index out of bounds\n");
        abort();
    }

    return n00b_list_get(*l, (size_t)ix);
}

uint64_t
n00b_builtin_list_get_i64(void *list, int64_t ix)
{
    return n00b_builtin_list_get_value(list, ix).payload;
}

uint64_t
n00b_builtin_list_get_value_payload(void *list, int64_t ix)
{
    return n00b_builtin_list_get_value(list, ix).payload;
}

int64_t
n00b_builtin_list_get_value_tag(void *list, int64_t ix)
{
    return (int64_t)n00b_builtin_list_get_value(list, ix).tag;
}

void
n00b_builtin_list_set_i64(void *list, int64_t ix, uint64_t val)
{
    n00b_builtin_list_set_value(list, ix, val, N00B_CG_I64);
}

void
n00b_builtin_list_set_value(void *list, int64_t ix, uint64_t payload, int64_t tag)
{
    if (!list || ix < 0) {
        fprintf(stderr, "n00b: list index out of bounds\n");
        abort();
    }

    n00b_rt_value_list_t *l = (n00b_rt_value_list_t *)list;

    if ((size_t)ix >= n00b_list_len(*l)) {
        fprintf(stderr, "n00b: list index out of bounds\n");
        abort();
    }

    n00b_rt_value_t v = n00b_rt_value_pack(payload, (n00b_cg_type_tag_t)tag);
    n00b_list_set(*l, (size_t)ix, v);
}

int64_t
n00b_builtin_list_len(void *list)
{
    if (!list) {
        return 0;
    }

    n00b_rt_value_list_t *l = (n00b_rt_value_list_t *)list;

    return (int64_t)n00b_list_len(*l);
}

void *
n00b_builtin_list_slice(void   *list,
                        int64_t start,
                        int64_t has_start,
                        int64_t end,
                        int64_t has_end)
{
    n00b_rt_value_list_t *copy = (n00b_rt_value_list_t *)n00b_builtin_list_new();

    if (!list) {
        return copy;
    }

    n00b_rt_value_list_t *src = (n00b_rt_value_list_t *)list;
    int64_t               len = (int64_t)n00b_list_len(*src);
    int64_t               lo  = has_start ? n00b_rt_normalize_slice_bound(start, len) : 0;
    int64_t               hi  = has_end ? n00b_rt_normalize_slice_bound(end, len) : len;

    if (hi < lo) {
        hi = lo;
    }

    for (int64_t i = lo; i < hi; i++) {
        n00b_rt_value_t v = n00b_rt_value_copy(n00b_list_get(*src, (size_t)i));
        n00b_list_push(*copy, v);
    }

    return copy;
}

// --- Dict helpers ---

typedef struct {
    n00b_rt_value_t key;
    n00b_rt_value_t value;
} n00b_rt_dict_entry_t;

typedef n00b_dict_t(n00b_uint128_t, n00b_rt_dict_entry_t) n00b_rt_value_dict_t;
typedef n00b_dict_t(n00b_uint128_t, n00b_rt_value_t) n00b_rt_value_set_t;

void *
n00b_builtin_dict_new(void)
{
    n00b_rt_value_dict_t *dict = n00b_alloc(n00b_rt_value_dict_t);

    n00b_dict_init(dict, .skip_obj_hash = true);

    return dict;
}

void
n00b_builtin_dict_put_i64(void *dict, uint64_t key, uint64_t val)
{
    n00b_builtin_dict_put_value(dict, key, N00B_CG_I64, val, N00B_CG_I64);
}

void
n00b_builtin_dict_put_value(void    *dict,
                            uint64_t key_payload,
                            int64_t  key_tag,
                            uint64_t val_payload,
                            int64_t  val_tag)
{
    if (!dict) {
        return;
    }

    n00b_rt_value_dict_t *d     = (n00b_rt_value_dict_t *)dict;
    n00b_rt_value_t       k     = n00b_rt_value_pack(key_payload, (n00b_cg_type_tag_t)key_tag);
    n00b_rt_dict_entry_t  entry = {
        .key   = k,
        .value = n00b_rt_value_pack(val_payload, (n00b_cg_type_tag_t)val_tag),
    };
    n00b_uint128_t hk = n00b_rt_value_hash128(k);

    n00b_dict_put(d, hk, entry);
}

static n00b_rt_value_t
n00b_builtin_dict_get_value(void *dict, n00b_rt_value_t key)
{
    if (!dict) {
        fprintf(stderr, "n00b: dict key not found\n");
        abort();
    }

    bool                  found = false;
    n00b_rt_value_dict_t *d     = (n00b_rt_value_dict_t *)dict;
    n00b_uint128_t        hk    = n00b_rt_value_hash128(key);
    n00b_rt_dict_entry_t  entry = n00b_dict_get(d, hk, &found);

    if (!found) {
        fprintf(stderr, "n00b: dict key not found\n");
        abort();
    }

    return entry.value;
}

uint64_t
n00b_builtin_dict_get_i64(void *dict, uint64_t key)
{
    return n00b_builtin_dict_get_value(dict, n00b_rt_value_pack(key, N00B_CG_I64)).payload;
}

uint64_t
n00b_builtin_dict_get_value_payload(void *dict, uint64_t key_payload, int64_t key_tag)
{
    return n00b_builtin_dict_get_value(
               dict,
               n00b_rt_value_pack(key_payload, (n00b_cg_type_tag_t)key_tag))
        .payload;
}

int64_t
n00b_builtin_dict_get_value_tag(void *dict, uint64_t key_payload, int64_t key_tag)
{
    return (int64_t)n00b_builtin_dict_get_value(
               dict,
               n00b_rt_value_pack(key_payload, (n00b_cg_type_tag_t)key_tag))
        .tag;
}

int64_t
n00b_builtin_dict_len(void *dict)
{
    if (!dict) {
        return 0;
    }

    return (int64_t)n00b_dict_internal_len((_n00b_dict_internal_t *)dict);
}

// --- Set helpers ---

void *
n00b_builtin_set_new(void)
{
    n00b_rt_value_set_t *set = n00b_alloc(n00b_rt_value_set_t);

    n00b_dict_init(set, .skip_obj_hash = true);

    return set;
}

void
n00b_builtin_set_add_value(void *set, uint64_t payload, int64_t tag)
{
    if (!set) {
        return;
    }

    n00b_rt_value_set_t *s  = (n00b_rt_value_set_t *)set;
    n00b_rt_value_t      v  = n00b_rt_value_pack(payload, (n00b_cg_type_tag_t)tag);
    n00b_uint128_t       hv = n00b_rt_value_hash128(v);

    n00b_dict_put(s, hv, v);
}

int64_t
n00b_builtin_set_len(void *set)
{
    if (!set) {
        return 0;
    }

    return (int64_t)n00b_dict_internal_len((_n00b_dict_internal_t *)set);
}

static n00b_rt_value_list_t *
n00b_builtin_list_copy(void *list)
{
    n00b_rt_value_list_t *copy = (n00b_rt_value_list_t *)n00b_builtin_list_new();

    if (!list) {
        return copy;
    }

    n00b_rt_value_list_t *src = (n00b_rt_value_list_t *)list;
    size_t                len = n00b_list_len(*src);

    for (size_t i = 0; i < len; i++) {
        n00b_rt_value_t v = n00b_rt_value_copy(n00b_list_get(*src, i));
        n00b_list_push(*copy, v);
    }

    return copy;
}

void
n00b_builtin_list_slice_assign(void   *list,
                               int64_t start,
                               int64_t has_start,
                               int64_t end,
                               int64_t has_end,
                               void   *replacement)
{
    if (!list) {
        fprintf(stderr, "n00b: list slice assignment on nil list\n");
        abort();
    }

    n00b_rt_value_list_t *dst = (n00b_rt_value_list_t *)list;
    n00b_rt_value_list_t *src = n00b_builtin_list_copy(replacement);
    int64_t               len = (int64_t)n00b_list_len(*dst);
    int64_t               lo  = has_start ? n00b_rt_normalize_slice_bound(start, len) : 0;
    int64_t               hi  = has_end ? n00b_rt_normalize_slice_bound(end, len) : len;

    if (hi < lo) {
        hi = lo;
    }

    n00b_list_delete_range(*dst, (size_t)lo, (size_t)(hi - lo));
    n00b_list_insert_list(*dst, (size_t)lo, *src);
}

static n00b_rt_value_dict_t *
n00b_builtin_dict_copy(void *dict)
{
    n00b_rt_value_dict_t *copy = (n00b_rt_value_dict_t *)n00b_builtin_dict_new();

    if (!dict) {
        return copy;
    }

    n00b_rt_value_dict_t *src = (n00b_rt_value_dict_t *)dict;

    n00b_dict_foreach(src, hk, entry, {
        n00b_rt_dict_entry_t copied;
        copied.key   = n00b_rt_value_copy(entry.key);
        copied.value = n00b_rt_value_copy(entry.value);
        n00b_dict_put(copy, hk, copied);
    });

    return copy;
}

static n00b_rt_value_set_t *
n00b_builtin_set_copy(void *set)
{
    n00b_rt_value_set_t *copy = (n00b_rt_value_set_t *)n00b_builtin_set_new();

    if (!set) {
        return copy;
    }

    n00b_rt_value_set_t *src = (n00b_rt_value_set_t *)set;

    n00b_dict_foreach(src, hk, value, {
        n00b_rt_value_t copied = n00b_rt_value_copy(value);
        n00b_dict_put(copy, hk, copied);
    });

    return copy;
}

void *
n00b_builtin_copy_collection(void *collection, int64_t tag)
{
    switch ((n00b_cg_type_tag_t)tag) {
    case N00B_CG_LIST:
        return n00b_builtin_list_copy(collection);
    case N00B_CG_DICT:
        return n00b_builtin_dict_copy(collection);
    case N00B_CG_SET:
        return n00b_builtin_set_copy(collection);
    default:
        return collection;
    }
}

typedef struct n00b_once_slot_t {
    uint64_t                 key;
    uint64_t                 value;
    float                    value_f32;
    double                   value_f64;
    bool                     done;
    struct n00b_once_slot_t *next;
} n00b_once_slot_t;

static n00b_once_slot_t *once_slots;

static n00b_once_slot_t *
n00b_once_slot(uint64_t key, bool create)
{
    n00b_once_slot_t *slot;
    for (slot = once_slots; slot; slot = slot->next) {
        if (slot->key == key) {
            return slot;
        }
    }

    if (!create) {
        return NULL;
    }

    slot                   = n00b_alloc(n00b_once_slot_t);
    slot->key              = key;
    slot->next             = once_slots;
    once_slots             = slot;
    return slot;
}

int64_t
n00b_builtin_once_is_done(uint64_t key)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, false);
    return slot && slot->done ? 1 : 0;
}

uint64_t
n00b_builtin_once_get_i64(uint64_t key)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, false);
    return slot ? slot->value : 0;
}

void
n00b_builtin_once_store_i64(uint64_t key, uint64_t value)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, true);
    slot->value            = value;
    slot->done             = true;
}

float
n00b_builtin_once_get_f32(uint64_t key)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, false);
    return slot ? slot->value_f32 : 0.0f;
}

void
n00b_builtin_once_store_f32(uint64_t key, float value)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, true);
    slot->value_f32        = value;
    slot->done             = true;
}

double
n00b_builtin_once_get_f64(uint64_t key)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, false);
    return slot ? slot->value_f64 : 0.0;
}

void
n00b_builtin_once_store_f64(uint64_t key, double value)
{
    n00b_once_slot_t *slot = n00b_once_slot(key, true);
    slot->value_f64        = value;
    slot->done             = true;
}

// --- Typed value printing ---

static void n00b_rt_value_print_inner(n00b_rt_value_t value, int depth);

static void
n00b_rt_list_print(void *list, int depth)
{
    if (!list) {
        printf("[]");
        return;
    }

    n00b_rt_value_list_t *l   = (n00b_rt_value_list_t *)list;
    size_t                len = n00b_list_len(*l);

    printf("[");

    for (size_t i = 0; i < len; i++) {
        if (i != 0) {
            printf(", ");
        }

        n00b_rt_value_print_inner(n00b_list_get(*l, i), depth + 1);
    }

    printf("]");
}

static void
n00b_rt_dict_print(void *dict, int depth)
{
    if (!dict) {
        printf("{}");
        return;
    }

    n00b_rt_value_dict_t *d     = (n00b_rt_value_dict_t *)dict;
    bool                  first = true;

    printf("{");

    n00b_dict_foreach(d, hk, entry, {
        (void)hk;
        if (!first) {
            printf(", ");
        }
        first = false;
        n00b_rt_value_print_inner(entry.key, depth + 1);
        printf(": ");
        n00b_rt_value_print_inner(entry.value, depth + 1);
    });

    printf("}");
}

static void
n00b_rt_set_print(void *set, int depth)
{
    if (!set) {
        printf("{}");
        return;
    }

    n00b_rt_value_set_t *s     = (n00b_rt_value_set_t *)set;
    bool                 first = true;

    printf("{");

    n00b_dict_foreach(s, hk, value, {
        (void)hk;
        if (!first) {
            printf(", ");
        }
        first = false;
        n00b_rt_value_print_inner(value, depth + 1);
    });

    printf("}");
}

static void
n00b_rt_value_print_inner(n00b_rt_value_t value, int depth)
{
    if (depth > 16) {
        printf("<...>");
        return;
    }

    switch ((n00b_cg_type_tag_t)value.tag) {
    case N00B_CG_BOOL:
        printf("%s", value.payload ? "true" : "false");
        break;
    case N00B_CG_STRING:
        if (value.payload == 0) {
            printf("nil");
        }
        else {
            n00b_string_t *s = (n00b_string_t *)(uintptr_t)value.payload;
            printf("%.*s", (int)s->u8_bytes, s->data);
        }
        break;
    case N00B_CG_NIL:
    case N00B_CG_VOID:
        printf("nil");
        break;
    case N00B_CG_LIST:
        n00b_rt_list_print((void *)(uintptr_t)value.payload, depth);
        break;
    case N00B_CG_DICT:
        n00b_rt_dict_print((void *)(uintptr_t)value.payload, depth);
        break;
    case N00B_CG_SET:
        n00b_rt_set_print((void *)(uintptr_t)value.payload, depth);
        break;
    default:
        printf("%" PRIu64, value.payload);
        break;
    }
}

void
n00b_builtin_print_value(uint64_t payload, int64_t tag)
{
    n00b_rt_value_print_inner(n00b_rt_value_pack(payload, (n00b_cg_type_tag_t)tag), 0);
    printf("\n");
}

// n00b_rt_option_t and n00b_rt_result_t are defined in codegen_builtins.h.

// --- Option helpers ---

void *
n00b_builtin_option_some(uint64_t val)
{
    n00b_rt_option_t *o = n00b_alloc(n00b_rt_option_t);
    o->has_value        = true;
    o->value            = val;
    return o;
}

void *
n00b_builtin_option_none(void)
{
    n00b_rt_option_t *o = n00b_alloc(n00b_rt_option_t);
    o->has_value        = false;
    o->value            = 0;
    return o;
}

int64_t
n00b_builtin_option_is_set(void *opt)
{
    if (!opt) {
        return 0;
    }

    return ((n00b_rt_option_t *)opt)->has_value ? 1 : 0;
}

uint64_t
n00b_builtin_option_unwrap(void *opt)
{
    if (!opt || !((n00b_rt_option_t *)opt)->has_value) {
        fprintf(stderr, "n00b: unwrap failed on none\n");
        abort();
    }

    return ((n00b_rt_option_t *)opt)->value;
}

void
n00b_builtin_print_option(void *opt)
{
    if (!opt || !((n00b_rt_option_t *)opt)->has_value) {
        printf("none\n");
        return;
    }

    // For now, print the raw payload as an integer.
    // TODO: type-aware printing of the inner value.
    printf("some(%llu)\n", (unsigned long long)((n00b_rt_option_t *)opt)->value);
}

// --- Result helpers ---

void *
n00b_builtin_result_ok(uint64_t val)
{
    n00b_rt_result_t *r = n00b_alloc(n00b_rt_result_t);
    r->is_ok            = true;
    r->payload          = val;
    r->err_code         = 0;
    r->err_message      = NULL;
    return r;
}

void *
n00b_builtin_result_err_code(int64_t code)
{
    n00b_rt_result_t *r = n00b_alloc(n00b_rt_result_t);
    r->is_ok            = false;
    r->payload          = 0;
    r->err_code         = code;
    r->err_message      = NULL;
    return r;
}

void *
n00b_builtin_result_err_msg(void *msg)
{
    n00b_rt_result_t *r = n00b_alloc(n00b_rt_result_t);
    r->is_ok            = false;
    r->payload          = 0;
    r->err_code         = 0;
    r->err_message      = NULL;

    if (msg) {
        n00b_string_t *s   = (n00b_string_t *)msg;
        // Store a copy of the string data as a C string.
        char          *buf = n00b_alloc_array(char, s->u8_bytes + 1);
        memcpy(buf, s->data, s->u8_bytes);
        buf[s->u8_bytes] = '\0';
        r->err_message   = buf;
    }

    return r;
}

int64_t
n00b_builtin_result_is_ok(void *res)
{
    if (!res) {
        return 0;
    }

    return ((n00b_rt_result_t *)res)->is_ok ? 1 : 0;
}

uint64_t
n00b_builtin_result_unwrap(void *res)
{
    if (!res || !((n00b_rt_result_t *)res)->is_ok) {
        n00b_rt_result_t *r = (n00b_rt_result_t *)res;

        if (r && r->err_message) {
            fprintf(stderr,
                    "n00b: unwrap failed on err(%lld, \"%s\")\n",
                    (long long)r->err_code,
                    r->err_message);
        }
        else if (r) {
            fprintf(stderr, "n00b: unwrap failed on err(%lld)\n", (long long)r->err_code);
        }
        else {
            fprintf(stderr, "n00b: unwrap failed on null result\n");
        }

        abort();
    }

    return ((n00b_rt_result_t *)res)->payload;
}

void
n00b_builtin_print_result(void *res)
{
    if (!res) {
        printf("err(null)\n");
        return;
    }

    n00b_rt_result_t *r = (n00b_rt_result_t *)res;

    if (r->is_ok) {
        printf("ok(%llu)\n", (unsigned long long)r->payload);
    }
    else if (r->err_message) {
        printf("err(%lld, \"%s\")\n", (long long)r->err_code, r->err_message);
    }
    else {
        printf("err(%lld)\n", (long long)r->err_code);
    }
}

// ============================================================================
// Built-in print dispatch: import the right helper and emit a call.
// ============================================================================

static n00b_cg_val_t
codegen_builtin_print(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        // print() with no args → print empty line.
        n00b_cg_import_func(s,
                            "n00b_builtin_print_nil",
                            (void *)n00b_builtin_print_nil,
                            .ret = N00B_CG_VOID);
        n00b_cg_emit_call(s, "n00b_builtin_print_nil", NULL, 0, .ret = N00B_CG_VOID);
        return N00B_CG_VOID_VAL;
    }

    // Dispatch based on the argument's type tag.
    n00b_cg_val_t      arg        = args[0];
    n00b_cg_type_tag_t tag        = arg.type_tag;
    const char        *name       = NULL;
    void              *addr       = NULL;
    n00b_cg_type_tag_t param_type = N00B_CG_I64;

    if (tag == N00B_CG_LIST || tag == N00B_CG_DICT || tag == N00B_CG_SET) {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64, N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_print_value",
                            (void *)n00b_builtin_print_value,
                            .ret         = N00B_CG_VOID,
                            .param_types = pt,
                            .n_params    = 2);
        n00b_cg_val_t tag_arg      = _n00b_cg_const_i64(s, (int64_t)tag);
        n00b_cg_val_t print_args[] = {arg, tag_arg};
        n00b_cg_emit_call(s, "n00b_builtin_print_value", print_args, 2, .ret = N00B_CG_VOID);
        return N00B_CG_VOID_VAL;
    }

    switch (tag) {
    case N00B_CG_BOOL:
        name       = "n00b_builtin_print_bool";
        addr       = (void *)n00b_builtin_print_bool;
        param_type = N00B_CG_I64; // bool is backed by i64
        break;

    case N00B_CG_F32:
    case N00B_CG_F64:
        name       = "n00b_builtin_print_f64";
        addr       = (void *)n00b_builtin_print_f64;
        param_type = N00B_CG_F64;
        break;

    case N00B_CG_STRING:
    case N00B_CG_PTR:
        name       = "n00b_builtin_print_str";
        addr       = (void *)n00b_builtin_print_str;
        param_type = N00B_CG_I64; // Pointer as i64 for MIR compat.
        break;

    case N00B_CG_OPTION:
        name       = "n00b_builtin_print_option";
        addr       = (void *)n00b_builtin_print_option;
        param_type = N00B_CG_I64;
        break;

    case N00B_CG_RESULT:
        name       = "n00b_builtin_print_result";
        addr       = (void *)n00b_builtin_print_result;
        param_type = N00B_CG_I64;
        break;

    case N00B_CG_NIL:
    case N00B_CG_VOID:
        name = "n00b_builtin_print_nil";
        addr = (void *)n00b_builtin_print_nil;
        n00b_cg_import_func(s, name, addr, .ret = N00B_CG_VOID);
        n00b_cg_emit_call(s, name, NULL, 0, .ret = N00B_CG_VOID);
        return N00B_CG_VOID_VAL;

    default:
        // All integer types: i8, i16, i32, i64, u8, u16, u32, u64.
        name       = "n00b_builtin_print_i64";
        addr       = (void *)n00b_builtin_print_i64;
        param_type = N00B_CG_I64;
        break;
    }

    n00b_cg_type_tag_t param_types[] = {param_type};
    n00b_cg_import_func(s,
                        name,
                        addr,
                        .ret         = N00B_CG_VOID,
                        .param_types = param_types,
                        .n_params    = 1);
    n00b_cg_emit_call(s, name, &arg, 1, .ret = N00B_CG_VOID);

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Built-in len(): dispatch based on argument type.
// ============================================================================

static n00b_cg_val_t
codegen_builtin_len(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t      arg = args[0];
    n00b_cg_type_tag_t tag = arg.type_tag;

    switch (tag) {
    case N00B_CG_STRING: {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_str_len",
                            (void *)n00b_builtin_str_len,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        return n00b_cg_emit_call(s, "n00b_builtin_str_len", &arg, 1, .ret = N00B_CG_I64);
    }
    case N00B_CG_LIST: {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_list_len",
                            (void *)n00b_builtin_list_len,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        return n00b_cg_emit_call(s, "n00b_builtin_list_len", &arg, 1, .ret = N00B_CG_I64);
    }
    case N00B_CG_DICT: {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_dict_len",
                            (void *)n00b_builtin_dict_len,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        return n00b_cg_emit_call(s, "n00b_builtin_dict_len", &arg, 1, .ret = N00B_CG_I64);
    }
    case N00B_CG_SET: {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_set_len",
                            (void *)n00b_builtin_set_len,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        return n00b_cg_emit_call(s, "n00b_builtin_set_len", &arg, 1, .ret = N00B_CG_I64);
    }
    default:
        return N00B_CG_VOID_VAL;
    }
}

// ============================================================================
// Option/Result builtin codegen helpers.
// Each imports the C runtime helper and emits a MIR call.
// ============================================================================

// some(val) -> option[T]
static n00b_cg_val_t
codegen_builtin_some(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_option_some",
                        (void *)n00b_builtin_option_some,
                        .ret         = N00B_CG_I64,
                        .param_types = pt,
                        .n_params    = 1);
    n00b_cg_val_t r
        = n00b_cg_emit_call(s, "n00b_builtin_option_some", args, 1, .ret = N00B_CG_I64);
    r.type_tag = N00B_CG_OPTION;
    return r;
}

// none -> option[T]
static n00b_cg_val_t
codegen_builtin_none(n00b_cg_session_t *s)
{
    n00b_cg_import_func(s,
                        "n00b_builtin_option_none",
                        (void *)n00b_builtin_option_none,
                        .ret = N00B_CG_I64);
    n00b_cg_val_t r
        = n00b_cg_emit_call(s, "n00b_builtin_option_none", NULL, 0, .ret = N00B_CG_I64);
    r.type_tag = N00B_CG_OPTION;
    return r;
}

// ok(val) -> result[T]
static n00b_cg_val_t
codegen_builtin_ok(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_result_ok",
                        (void *)n00b_builtin_result_ok,
                        .ret         = N00B_CG_I64,
                        .param_types = pt,
                        .n_params    = 1);
    n00b_cg_val_t r
        = n00b_cg_emit_call(s, "n00b_builtin_result_ok", args, 1, .ret = N00B_CG_I64);
    r.type_tag = N00B_CG_RESULT;
    return r;
}

// err(code) or err("message") -> result[T]
static n00b_cg_val_t
codegen_builtin_err(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    const char        *name;
    void              *addr;
    n00b_cg_type_tag_t pt_tag;

    if (args[0].type_tag == N00B_CG_STRING) {
        name   = "n00b_builtin_result_err_msg";
        addr   = (void *)n00b_builtin_result_err_msg;
        pt_tag = N00B_CG_I64; // pointer as i64
    }
    else {
        name   = "n00b_builtin_result_err_code";
        addr   = (void *)n00b_builtin_result_err_code;
        pt_tag = N00B_CG_I64;
    }

    n00b_cg_type_tag_t pt[] = {pt_tag};
    n00b_cg_import_func(s, name, addr, .ret = N00B_CG_I64, .param_types = pt, .n_params = 1);
    n00b_cg_val_t r = n00b_cg_emit_call(s, name, args, 1, .ret = N00B_CG_I64);
    r.type_tag      = N00B_CG_RESULT;
    return r;
}

// is_set?(opt) -> bool
static n00b_cg_val_t
codegen_builtin_is_set(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_option_is_set",
                        (void *)n00b_builtin_option_is_set,
                        .ret         = N00B_CG_I64,
                        .param_types = pt,
                        .n_params    = 1);
    n00b_cg_val_t r
        = n00b_cg_emit_call(s, "n00b_builtin_option_is_set", args, 1, .ret = N00B_CG_I64);
    r.type_tag = N00B_CG_BOOL;
    return r;
}

// ok?(res) -> bool
static n00b_cg_val_t
codegen_builtin_ok_check(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_result_is_ok",
                        (void *)n00b_builtin_result_is_ok,
                        .ret         = N00B_CG_I64,
                        .param_types = pt,
                        .n_params    = 1);
    n00b_cg_val_t r
        = n00b_cg_emit_call(s, "n00b_builtin_result_is_ok", args, 1, .ret = N00B_CG_I64);
    r.type_tag = N00B_CG_BOOL;
    return r;
}

// err?(res) -> bool (negation of ok?)
static n00b_cg_val_t
codegen_builtin_err_check(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    n00b_cg_val_t ok = codegen_builtin_ok_check(s, args, n_args);

    if (ok.kind == N00B_CG_VAL_VOID) {
        return ok;
    }

    n00b_cg_val_t r = n00b_cg_emit_not(s, ok);
    r.type_tag      = N00B_CG_BOOL;
    return r;
}

// unwrap(opt_or_res) -> T (aborts on none/err)
static n00b_cg_val_t
codegen_builtin_unwrap(n00b_cg_session_t *s, n00b_cg_val_t *args, int32_t n_args)
{
    if (n_args < 1) {
        return N00B_CG_VOID_VAL;
    }

    const char *name;
    void       *addr;

    if (args[0].type_tag == N00B_CG_OPTION) {
        name = "n00b_builtin_option_unwrap";
        addr = (void *)n00b_builtin_option_unwrap;
    }
    else {
        name = "n00b_builtin_result_unwrap";
        addr = (void *)n00b_builtin_result_unwrap;
    }

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s, name, addr, .ret = N00B_CG_I64, .param_types = pt, .n_params = 1);
    return n00b_cg_emit_call(s, name, args, 1, .ret = N00B_CG_I64);
}

// ============================================================================
// Public dispatch: check if a function name is a built-in.
// ============================================================================

bool
n00b_codegen_builtin_call(n00b_cg_session_t *s,
                          const char        *func_name,
                          n00b_cg_val_t     *args,
                          int32_t            n_args,
                          n00b_cg_type_tag_t expected_ret,
                          n00b_cg_val_t     *out)
{
    if (strcmp(func_name, "print") == 0) {
        *out = codegen_builtin_print(s, args, n_args);
        return true;
    }

    if (strcmp(func_name, "len") == 0) {
        *out = codegen_builtin_len(s, args, n_args);
        return true;
    }

    if (strcmp(func_name, "confspec_section_count") == 0) {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_confspec_section_count",
                            (void *)n00b_builtin_confspec_section_count,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        n00b_cg_val_t namespace_arg
            = _n00b_cg_const_i64(s, (int64_t)n00b_codegen_session_namespace_key(s));
        *out = n00b_cg_emit_call(s,
                                 "n00b_builtin_confspec_section_count",
                                 &namespace_arg,
                                 1,
                                 .ret = N00B_CG_I64);
        return true;
    }

    if (strcmp(func_name, "confspec_field_count") == 0) {
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_confspec_field_count",
                            (void *)n00b_builtin_confspec_field_count,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 1);
        n00b_cg_val_t namespace_arg
            = _n00b_cg_const_i64(s, (int64_t)n00b_codegen_session_namespace_key(s));
        *out = n00b_cg_emit_call(s,
                                 "n00b_builtin_confspec_field_count",
                                 &namespace_arg,
                                 1,
                                 .ret = N00B_CG_I64);
        return true;
    }

    if (strcmp(func_name, "call") == 0 && n_args >= 1) {
        const char *name           = NULL;
        void       *addr           = NULL;
        int32_t     callback_arity = n_args - 1;

        if (callback_arity < 0 || callback_arity > 2) {
            *out = N00B_CG_VOID_VAL;
            return true;
        }

        n00b_cg_type_tag_t ret_type = expected_ret;

        if (args[0].kind == N00B_CG_VAL_IMM && args[0].type_tag == N00B_CG_FUNC
            && args[0].aux != 0) {
            n00b_rt_callback_t *cb = (n00b_rt_callback_t *)(uintptr_t)args[0].aux;

            if (cb->has_signature) {
                ret_type = cb->ret_type;
            }
        }

        if (ret_type == N00B_CG_PTR) {
            ret_type = N00B_CG_I64;
        }

        n00b_cg_type_tag_t arg0_type = callback_arity >= 1 ? args[1].type_tag : N00B_CG_I64;
        n00b_cg_type_tag_t arg1_type = callback_arity >= 2 ? args[2].type_tag : N00B_CG_I64;

        if (!n00b_callback_helper_for_signature(callback_arity,
                                                ret_type,
                                                arg0_type,
                                                arg1_type,
                                                &name,
                                                &addr)) {
            *out = N00B_CG_VOID_VAL;
            return true;
        }

        n00b_cg_type_tag_t pt[] = {N00B_CG_FUNC, N00B_CG_I64, N00B_CG_I64};

        for (int32_t i = 1; i < n_args && i < 3; i++) {
            pt[i] = args[i].type_tag;
        }

        n00b_cg_import_func(s,
                            name,
                            addr,
                            .ret         = ret_type,
                            .param_types = pt,
                            .n_params    = n_args);
        *out = n00b_cg_emit_call(s, name, args, n_args, .ret = ret_type);
        return true;
    }

    if (strcmp(func_name, "copy") == 0) {
        if (n_args < 1) {
            *out = N00B_CG_VOID_VAL;
            return true;
        }

        n00b_cg_type_tag_t tag = args[0].type_tag;

        if (tag != N00B_CG_LIST && tag != N00B_CG_DICT && tag != N00B_CG_SET) {
            *out = args[0];
            return true;
        }

        n00b_cg_type_tag_t pt[] = {N00B_CG_I64, N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_copy_collection",
                            (void *)n00b_builtin_copy_collection,
                            .ret         = N00B_CG_I64,
                            .param_types = pt,
                            .n_params    = 2);
        n00b_cg_val_t tag_arg     = _n00b_cg_const_i64(s, (int64_t)tag);
        n00b_cg_val_t call_args[] = {args[0], tag_arg};
        *out                      = n00b_cg_emit_call(s,
                                                      "n00b_builtin_copy_collection",
                                                      call_args,
                                                      2,
                                                      .ret = N00B_CG_I64);
        out->type_tag             = tag;
        return true;
    }

    if (strcmp(func_name, "some") == 0) {
        *out = codegen_builtin_some(s, args, n_args);
        return true;
    }

    if (strcmp(func_name, "none") == 0) {
        *out = codegen_builtin_none(s);
        return true;
    }

    if (strcmp(func_name, "ok") == 0) {
        *out = codegen_builtin_ok(s, args, n_args);
        return true;
    }

    if (strcmp(func_name, "err") == 0) {
        *out = codegen_builtin_err(s, args, n_args);
        return true;
    }

    return false;
}

// ============================================================================
// Method dispatch via vtable.
//
// For method calls (expr.name(args)), the receiver is args[0].
// Look up the method on the receiver's type via the type registry.
// If found, import and call it.
// ============================================================================

bool
n00b_codegen_method_dispatch(n00b_cg_session_t *s,
                             const char        *method_name,
                             n00b_cg_val_t     *args,
                             int32_t            n_args,
                             n00b_cg_val_t     *out)
{
    if (n_args < 1) {
        return false;
    }

    // Side-table first: registered user-defined opaques carry their
    // typehash out-of-band so the hardcoded `type_tag_to_hash` switch
    // doesn't need to know about every type the runtime cares about.
    uint64_t hash = n00b_cg_val_get_type_hash(s, args[0]);

    if (!hash) {
        hash = type_tag_to_hash(args[0].type_tag);
    }

    if (!hash) {
        return false;
    }

    // Look up the full method record so we can propagate the real
    // return-type tag. Falling back to `n00b_type_method_lookup` would
    // give us only the function pointer; the JIT would then tag the
    // result as `i64` and downstream operators would see the wrong
    // semantic type.
    n00b_option_t(n00b_method_t *) method_opt
        = n00b_type_method_lookup_full(hash, method_name);

    if (!n00b_option_is_set(method_opt)) {
        return false;
    }

    n00b_method_t     *method = n00b_option_get(method_opt);
    n00b_vtable_entry  fn     = method->fn;
    n00b_cg_type_tag_t ret_tag = method_ret_type_to_tag(method->return_type.type_name);

    // Build a unique MIR import name the n00b way: format with n00b_cformat,
    // sanitize '?' -> 'Q' (illegal in MIR identifiers) via a string replace,
    // and cross to char* only at the MIR C-ABI edge (n00b_cg_import_func and
    // n00b_cg_emit_call take const char *).
    n00b_string_t *raw_name    = n00b_cformat("_vtm_[|#|]_[|#:x|]",
                                              n00b_string_from_cstr(method_name),
                                              (int64_t)hash);
    n00b_string_t *import_s    = n00b_unicode_str_replace_all(raw_name, r"?", r"Q");
    const char    *import_name = n00b_unicode_str_to_cstr(import_s);

    // Use the I64 ABI for the MIR import (every pointer-like tag is
    // backed by MIR_T_I64). Tag the returned value with the method's
    // real semantic type so downstream operators dispatch correctly.
    //
    // WP-009 Phase 4 enabling: pass through all `n_args` (receiver +
    // user-supplied operands) rather than truncating to the
    // receiver alone. Every argument lowers to the I64 ABI per the
    // pointer-like ABI used throughout the codegen; user-defined
    // opaque receivers + n00b string operands share that
    // representation. The previous (n_params = 1) truncation
    // worked for the WP-010 smoke tests (`arg.value`-style zero-arg
    // methods) but discarded operands on multi-arg methods like
    // `arg.starts_with(prefix)`. Cap at 32 args defensively — the
    // existing surface never declares methods anywhere near that
    // wide.
    n00b_cg_type_tag_t mir_ret = (ret_tag == N00B_CG_VOID) ? N00B_CG_VOID
                                                           : N00B_CG_I64;
    enum { N00B_CG_METHOD_MAX_ARGS = 32 };
    n00b_cg_type_tag_t pt[N00B_CG_METHOD_MAX_ARGS];
    int32_t            cap_args = (n_args > N00B_CG_METHOD_MAX_ARGS)
                                       ? N00B_CG_METHOD_MAX_ARGS
                                       : n_args;
    for (int32_t i = 0; i < cap_args; i++) {
        pt[i] = N00B_CG_I64;
    }
    n00b_cg_import_func(s,
                        import_name,
                        (void *)fn,
                        .ret         = mir_ret,
                        .param_types = pt,
                        .n_params    = cap_args);

    n00b_cg_val_t result = n00b_cg_emit_call(s, import_name, args, cap_args,
                                             .ret = mir_ret);

    if (ret_tag == N00B_CG_BOOL) {
        n00b_cg_val_t one = _n00b_cg_const_i64(s, 1);
        result            = n00b_cg_emit_and(s, result, one);
        result.type_tag   = N00B_CG_BOOL;
    }
    else if (ret_tag != N00B_CG_VOID) {
        result.type_tag = ret_tag;
    }

    // WP-009 Phase 4: if the method's declared return type is a
    // registered user-defined opaque (recognized by name in the type
    // registry), stamp the typehash side-table on the result. This
    // lets chained calls (e.g.,
    // `arg.capture("callee").starts_with("n00b_")`) dispatch the
    // outer method against the right typehash. Without this the
    // outer call falls through to `type_tag_to_hash(I64)` → 0 and
    // method_dispatch returns false, so `.starts_with` is silently
    // skipped by the JIT's fall-through path. The bridge is name-
    // based: `n00b_type_name_to_hash` scans the registry by the
    // `return_type.type_name` C string. Primitives (bool, i64, ...)
    // don't have registry entries and return 0 — the side-table
    // stays clean, preserving the WP-010 behavior for primitive
    // returns.
    if (ret_tag == N00B_CG_I64 && method->return_type.type_name) {
        uint64_t ret_hash = n00b_type_name_to_hash(method->return_type.type_name);
        if (ret_hash) {
            n00b_cg_val_set_type_hash(s, result, ret_hash);
        }
    }
    *out = result;
    return true;
}
