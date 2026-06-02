/**
 * @file n00b_demangle.c
 * @brief C++ Itanium ABI demangler + top-level dispatch.
 *
 * Ported from slop/src/demangle/demangle.c.  Uses malloc/realloc/free
 * for internal temp buffers; returns n00b_string_t* at the public API.
 */

#include "compiler/objfile/demangle.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/alloc.h"
#include "core/string.h"

// n00b-backed substring/string copy for this demangler (n00b's own ncc code —
// no libc allocation).  Call sites use these explicitly; no stdlib names remain.
static char *
n00b_objfile_strndup(const char *s, size_t n)
{
    char *result = n00b_alloc_array(char, n + 1);
    if (!result) {
        return nullptr;
    }
    memcpy(result, s, n);
    result[n] = '\0';
    return result;
}

static char *
n00b_objfile_strdup(const char *s)
{
    return n00b_objfile_strndup(s, strlen(s));
}

// ============================================================================
// Internal string list (replaces demangle_charptr_list_t)
// ============================================================================

typedef struct {
    char  **data;
    size_t  len;
    size_t  cap;
} strlist_t;

static bool
strlist_push(strlist_t *sl, char *s)
{
    if (sl->len == sl->cap) {
        size_t new_cap = sl->cap ? sl->cap * 2 : 8;
        char **p = n00b_alloc_array(char *, new_cap);
        if (!p) return false;
        if (sl->data) {
            memcpy(p, sl->data, sl->len * sizeof(char *));
            n00b_free(sl->data);
        }
        sl->data = p;
        sl->cap  = new_cap;
    }
    sl->data[sl->len++] = s;
    return true;
}

static void
strlist_free_all(strlist_t *sl)
{
    for (size_t i = 0; i < sl->len; i++) {
        n00b_free(sl->data[i]);
    }
    n00b_free(sl->data);
    sl->data = nullptr;
    sl->len = sl->cap = 0;
}

// ============================================================================
// Parser state
// ============================================================================

typedef struct {
    const char *input;
    const char *pos;
    const char *end;
    char       *output;
    size_t      output_size;
    size_t      output_cap;
    strlist_t   subs;
    strlist_t   template_args;
    bool        error;
    int         depth;
    int         max_depth;
} dm_state_t;

#define DM_MAX_DEPTH 256

static void
dm_init(dm_state_t *st, const char *mangled)
{
    memset(st, 0, sizeof(*st));
    st->input      = mangled;
    st->pos        = mangled;
    st->end        = mangled + strlen(mangled);
    st->output_cap = 256;
    st->output     = n00b_alloc_array(char, st->output_cap);
    st->output[0]  = '\0';
    st->max_depth  = DM_MAX_DEPTH;
}

static void
dm_free(dm_state_t *st)
{
    n00b_free(st->output);
    strlist_free_all(&st->subs);
    strlist_free_all(&st->template_args);
}

// ============================================================================
// Output helpers
// ============================================================================

static void
dm_append_n(dm_state_t *st, const char *s, size_t n)
{
    if (st->output_size + n + 1 > st->output_cap) {
        while (st->output_size + n + 1 > st->output_cap)
            st->output_cap *= 2;
        char *p = n00b_alloc_array(char, st->output_cap);
        if (!p) { st->error = true; return; }
        memcpy(p, st->output, st->output_size);
        n00b_free(st->output);
        st->output = p;
    }
    memcpy(st->output + st->output_size, s, n);
    st->output_size += n;
    st->output[st->output_size] = '\0';
}

static void
dm_append(dm_state_t *st, const char *s)
{
    dm_append_n(st, s, strlen(s));
}

static void
dm_append_char(dm_state_t *st, char c)
{
    dm_append_n(st, &c, 1);
}

static void
dm_add_sub(dm_state_t *st, const char *s)
{
    strlist_push(&st->subs, n00b_objfile_strdup(s));
}

// ============================================================================
// Peek / consume helpers
// ============================================================================

static inline bool at_end(dm_state_t *st) { return st->pos >= st->end; }
static inline char peek(dm_state_t *st) { return at_end(st) ? '\0' : *st->pos; }
static inline char peek_n(dm_state_t *st, int n) {
    return st->pos + n >= st->end ? '\0' : st->pos[n];
}

static inline bool
consume(dm_state_t *st, char c)
{
    if (peek(st) == c) { st->pos++; return true; }
    return false;
}

static inline bool
consume_str(dm_state_t *st, const char *s)
{
    size_t len = strlen(s);
    if ((size_t)(st->end - st->pos) >= len && strncmp(st->pos, s, len) == 0) {
        st->pos += len;
        return true;
    }
    return false;
}

// ============================================================================
// Forward declarations
// ============================================================================

static bool dm_parse_encoding(dm_state_t *st);
static bool dm_parse_name(dm_state_t *st);
static bool dm_parse_nested_name(dm_state_t *st);
static bool dm_parse_unscoped_name(dm_state_t *st);
static bool dm_parse_source_name(dm_state_t *st);
static bool dm_parse_operator_name(dm_state_t *st);
static bool dm_parse_type(dm_state_t *st);
static bool dm_parse_builtin_type(dm_state_t *st);
static bool dm_parse_function_type(dm_state_t *st);
static bool dm_parse_bare_function_type(dm_state_t *st);
static bool dm_parse_template_args(dm_state_t *st);
static bool dm_parse_substitution(dm_state_t *st);
static bool dm_parse_ctor_dtor_name(dm_state_t *st);
static bool dm_parse_cv_qualifiers(dm_state_t *st, bool *is_const, bool *is_volatile);
static bool dm_parse_expression(dm_state_t *st);
static bool dm_parse_number(dm_state_t *st, int64_t *out);

// ============================================================================
// Number parsing
// ============================================================================

static bool
dm_parse_number(dm_state_t *st, int64_t *out)
{
    bool neg = consume(st, 'n');
    if (!isdigit(peek(st))) return false;

    int64_t val = 0;
    while (isdigit(peek(st))) {
        int64_t next;
        if (ckd_mul(&next, val, 10) || ckd_add(&next, next, (int64_t)(peek(st) - '0'))) {
            st->error = true;
            return false;
        }
        val = next;
        st->pos++;
    }
    *out = neg ? -val : val;
    return true;
}

static bool
parse_positive_int(dm_state_t *st, size_t *out)
{
    if (!isdigit(peek(st))) return false;

    size_t val = 0;
    while (isdigit(peek(st))) {
        size_t next;
        if (ckd_mul(&next, val, (size_t)10) || ckd_add(&next, next, (size_t)(peek(st) - '0'))) {
            st->error = true;
            return false;
        }
        val = next;
        st->pos++;
    }
    *out = val;
    return true;
}

// ============================================================================
// Source name
// ============================================================================

static bool
dm_parse_source_name(dm_state_t *st)
{
    size_t len;
    if (!parse_positive_int(st, &len)) return false;
    if ((size_t)(st->end - st->pos) < len) { st->error = true; return false; }

    dm_append_n(st, st->pos, len);
    st->pos += len;
    return true;
}

// ============================================================================
// Builtin types
// ============================================================================

static bool
dm_parse_builtin_type(dm_state_t *st)
{
    char c = peek(st);

    if (c == 'u') { st->pos++; return dm_parse_source_name(st); }

    const char *ts = nullptr;
    switch (c) {
    case 'v': ts = "void"; break;
    case 'w': ts = "wchar_t"; break;
    case 'b': ts = "bool"; break;
    case 'c': ts = "char"; break;
    case 'a': ts = "signed char"; break;
    case 'h': ts = "unsigned char"; break;
    case 's': ts = "short"; break;
    case 't': ts = "unsigned short"; break;
    case 'i': ts = "int"; break;
    case 'j': ts = "unsigned int"; break;
    case 'l': ts = "long"; break;
    case 'm': ts = "unsigned long"; break;
    case 'x': ts = "long long"; break;
    case 'y': ts = "unsigned long long"; break;
    case 'n': ts = "__int128"; break;
    case 'o': ts = "unsigned __int128"; break;
    case 'f': ts = "float"; break;
    case 'd': ts = "double"; break;
    case 'e': ts = "long double"; break;
    case 'g': ts = "__float128"; break;
    case 'z': ts = "..."; break;
    case 'D':
        st->pos++;
        switch (peek(st)) {
        case 'd': ts = "decimal64"; break;
        case 'e': ts = "decimal128"; break;
        case 'f': ts = "decimal32"; break;
        case 'h': ts = "half"; break;
        case 'i': ts = "char32_t"; break;
        case 's': ts = "char16_t"; break;
        case 'a': ts = "auto"; break;
        case 'c': ts = "decltype(auto)"; break;
        case 'n': ts = "std::nullptr_t"; break;
        default: st->pos--; return false;
        }
        break;
    default: return false;
    }

    st->pos++;
    dm_append(st, ts);
    return true;
}

// ============================================================================
// CV qualifiers
// ============================================================================

static bool
dm_parse_cv_qualifiers(dm_state_t *st, bool *is_const, bool *is_volatile)
{
    *is_const = *is_volatile = false;
    for (;;) {
        if (consume(st, 'r'))      { /* restrict */ }
        else if (consume(st, 'V')) { *is_volatile = true; }
        else if (consume(st, 'K')) { *is_const = true; }
        else break;
    }
    return true;
}

// ============================================================================
// Operator names
// ============================================================================

static bool
dm_parse_operator_name(dm_state_t *st)
{
    if (st->end - st->pos < 2) return false;

    char c1 = st->pos[0], c2 = st->pos[1];
    const char *op = nullptr;

    if (c1 == 'n') {
        switch (c2) {
        case 'w': op = "operator new"; break;
        case 'a': op = "operator new[]"; break;
        case 'e': op = "operator!="; break;
        case 'g': op = "operator-"; break;
        case 't': op = "operator!"; break;
        }
    } else if (c1 == 'd') {
        switch (c2) {
        case 'l': op = "operator delete"; break;
        case 'a': op = "operator delete[]"; break;
        case 'e': op = "operator*"; break;
        case 'v': op = "operator/"; break;
        }
    } else if (c1 == 'p') {
        switch (c2) {
        case 's': op = "operator+"; break;
        case 'l': op = "operator+"; break;
        case 'L': op = "operator+="; break;
        case 'p': op = "operator++"; break;
        case 't': op = "operator->"; break;
        case 'm': op = "operator->*"; break;
        }
    } else if (c1 == 'm') {
        switch (c2) {
        case 'i': op = "operator-"; break;
        case 'I': op = "operator-="; break;
        case 'l': op = "operator*"; break;
        case 'L': op = "operator*="; break;
        case 'm': op = "operator--"; break;
        }
    } else if (c1 == 'r') {
        switch (c2) {
        case 'm': op = "operator%"; break;
        case 'M': op = "operator%="; break;
        case 's': op = "operator>>"; break;
        case 'S': op = "operator>>="; break;
        }
    } else if (c1 == 'a') {
        switch (c2) {
        case 'n': op = "operator&"; break;
        case 'N': op = "operator&="; break;
        case 'd': op = "operator&&"; break;
        case 'S': op = "operator="; break;
        }
    } else if (c1 == 'o') {
        switch (c2) {
        case 'r': op = "operator|"; break;
        case 'R': op = "operator|="; break;
        case 'o': op = "operator||"; break;
        }
    } else if (c1 == 'e') {
        switch (c2) {
        case 'o': op = "operator^"; break;
        case 'O': op = "operator^="; break;
        case 'q': op = "operator=="; break;
        }
    } else if (c1 == 'l') {
        switch (c2) {
        case 't': op = "operator<"; break;
        case 'e': op = "operator<="; break;
        case 's': op = "operator<<"; break;
        case 'S': op = "operator<<="; break;
        }
    } else if (c1 == 'g') {
        switch (c2) {
        case 't': op = "operator>"; break;
        case 'e': op = "operator>="; break;
        }
    } else if (c1 == 'c') {
        switch (c2) {
        case 'o': op = "operator~"; break;
        case 'm': op = "operator,"; break;
        case 'l': op = "operator()"; break;
        case 'v':
            st->pos += 2;
            dm_append(st, "operator ");
            return dm_parse_type(st);
        }
    } else if (c1 == 'i' && c2 == 'x') {
        op = "operator[]";
    } else if (c1 == 'q' && c2 == 'u') {
        op = "operator?";
    } else if (c1 == 's' && c2 == 's') {
        op = "operator<=>";
    }

    if (c1 == 'l' && c2 == 'i') {
        st->pos += 2;
        dm_append(st, "operator\"\" ");
        return dm_parse_source_name(st);
    }

    if (op) {
        st->pos += 2;
        dm_append(st, op);
        return true;
    }
    return false;
}

// ============================================================================
// Constructor / destructor
// ============================================================================

static bool
dm_parse_ctor_dtor_name(dm_state_t *st)
{
    if (consume(st, 'C')) {
        char k = peek(st);
        if (k >= '1' && k <= '5') {
            st->pos++;
            dm_append(st, "{ctor}");
            return true;
        }
    } else if (consume(st, 'D')) {
        char k = peek(st);
        if (k >= '0' && k <= '5') {
            st->pos++;
            dm_append(st, "~{dtor}");
            return true;
        }
    }
    return false;
}

// ============================================================================
// Substitution
// ============================================================================

static bool
dm_parse_substitution(dm_state_t *st)
{
    if (!consume(st, 'S')) return false;

    char c = peek(st);
    switch (c) {
    case 't': st->pos++; dm_append(st, "std"); return true;
    case 'a': st->pos++; dm_append(st, "std::allocator"); return true;
    case 'b': st->pos++; dm_append(st, "std::basic_string"); return true;
    case 's': st->pos++; dm_append(st, "std::string"); return true;
    case 'i': st->pos++; dm_append(st, "std::istream"); return true;
    case 'o': st->pos++; dm_append(st, "std::ostream"); return true;
    case 'd': st->pos++; dm_append(st, "std::iostream"); return true;
    }

    if (consume(st, '_')) {
        if (st->subs.len > 0) {
            dm_append(st, st->subs.data[0]);
            return true;
        }
        return false;
    }

    size_t idx = 0;
    while (peek(st) != '_' && !at_end(st)) {
        char ch = peek(st);
        int digit;
        if (ch >= '0' && ch <= '9')      digit = ch - '0';
        else if (ch >= 'A' && ch <= 'Z') digit = ch - 'A' + 10;
        else return false;
        idx = idx * 36 + (size_t)digit;
        st->pos++;
    }
    if (!consume(st, '_')) return false;

    idx += 1;
    if (idx < st->subs.len) {
        dm_append(st, st->subs.data[idx]);
        return true;
    }
    return false;
}

// ============================================================================
// Type parsing
// ============================================================================

static bool
dm_parse_type(dm_state_t *st)
{
    if (++st->depth > st->max_depth) return false;

    size_t start = st->output_size;

    bool is_const, is_volatile;
    dm_parse_cv_qualifiers(st, &is_const, &is_volatile);

    char c = peek(st);

    if (c == 'P') {
        st->pos++;
        // Pointer to function type: emit "ret (*)(params)" not "ret(params)*"
        if (peek(st) == 'F') {
            st->pos++;
            consume(st, 'Y');
            if (!dm_parse_type(st)) return false; // return type
            dm_append(st, " (*)(");
            bool first = true;
            while (peek(st) != 'E' && !at_end(st)) {
                if (!first) dm_append(st, ", ");
                first = false;
                if (!dm_parse_type(st)) return false;
            }
            dm_append(st, ")");
            if (!consume(st, 'E')) return false;
        }
        else {
            if (!dm_parse_type(st)) return false;
            dm_append(st, "*");
        }
        goto add_cv;
    }
    if (c == 'R') {
        st->pos++;
        if (!dm_parse_type(st)) return false;
        dm_append(st, "&");
        goto add_cv;
    }
    if (c == 'O') {
        st->pos++;
        if (!dm_parse_type(st)) return false;
        dm_append(st, "&&");
        goto add_cv;
    }
    if (c == 'A') {
        st->pos++;
        int64_t sz = -1;
        if (isdigit(peek(st))) dm_parse_number(st, &sz);
        if (!consume(st, '_')) return false;
        if (!dm_parse_type(st)) return false;
        dm_append(st, "[");
        if (sz >= 0) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%lld", (long long)sz);
            dm_append(st, buf);
        }
        dm_append(st, "]");
        goto add_cv;
    }
    if (c == 'F') {
        st->pos++;
        consume(st, 'Y');
        if (!dm_parse_function_type(st)) return false;
        if (!consume(st, 'E')) return false;
        goto add_cv;
    }
    if (c == 'S') {
        const char *saved = st->pos;
        if (dm_parse_substitution(st)) {
            if (peek(st) == 'I') dm_parse_template_args(st);
            goto add_cv;
        }
        st->pos = saved;
    }
    if (c == 'T') {
        st->pos++;
        size_t idx = 0;
        if (!consume(st, '_')) {
            while (peek(st) != '_' && !at_end(st)) {
                char ch = peek(st);
                if (ch >= '0' && ch <= '9') idx = idx * 10 + (size_t)(ch - '0');
                else return false;
                st->pos++;
            }
            if (!consume(st, '_')) return false;
            idx += 1;
        }
        if (idx < st->template_args.len) {
            dm_append(st, st->template_args.data[idx]);
        } else {
            char buf[32];
            snprintf(buf, sizeof(buf), "T%zu", idx);
            dm_append(st, buf);
        }
        goto add_cv;
    }
    if (c == 'D' && (peek_n(st, 1) == 't' || peek_n(st, 1) == 'T')) {
        st->pos += 2;
        dm_append(st, "decltype(");
        if (!dm_parse_expression(st)) return false;
        dm_append(st, ")");
        if (!consume(st, 'E')) return false;
        goto add_cv;
    }
    if (dm_parse_builtin_type(st)) goto add_cv;
    if (c == 'N') {
        if (!dm_parse_nested_name(st)) return false;
        if (peek(st) == 'I') dm_parse_template_args(st);
        goto add_cv;
    }
    if (isdigit(c)) {
        if (!dm_parse_source_name(st)) return false;
        if (peek(st) == 'I') dm_parse_template_args(st);
        goto add_cv;
    }
    if (c == 'S' && peek_n(st, 1) == 't') {
        st->pos += 2;
        dm_append(st, "std::");
        if (!dm_parse_source_name(st)) return false;
        if (peek(st) == 'I') dm_parse_template_args(st);
        goto add_cv;
    }
    --st->depth;
    return false;

add_cv:
    if (is_const) dm_append(st, " const");
    if (is_volatile) dm_append(st, " volatile");

    if (st->output_size > start) {
        char *ts = n00b_objfile_strndup(st->output + start, st->output_size - start);
        dm_add_sub(st, ts);
        n00b_free(ts);
    }
    --st->depth;
    return true;
}

// ============================================================================
// Function type
// ============================================================================

static bool
dm_parse_function_type(dm_state_t *st)
{
    if (!dm_parse_type(st)) return false;
    dm_append(st, "(");
    bool first = true;
    while (peek(st) != 'E' && !at_end(st)) {
        if (!first) dm_append(st, ", ");
        first = false;
        if (!dm_parse_type(st)) return false;
    }
    dm_append(st, ")");
    return true;
}

static bool
dm_parse_bare_function_type(dm_state_t *st)
{
    dm_append(st, "(");
    if (peek(st) == 'v' && (peek_n(st, 1) == '\0' || peek_n(st, 1) == 'E')) {
        st->pos++;
        dm_append(st, ")");
        return true;
    }
    bool first = true;
    while (!at_end(st)) {
        char c = peek(st);
        if (c == 'E' || c == '\0') break;

        const char *saved_pos  = st->pos;
        size_t      saved_size = st->output_size;

        if (!first) dm_append(st, ", ");
        if (!dm_parse_type(st)) {
            st->pos         = saved_pos;
            st->output_size = saved_size;
            st->output[st->output_size] = '\0';
            break;
        }
        first = false;
    }
    dm_append(st, ")");
    return true;
}

// ============================================================================
// Template arguments
// ============================================================================

static bool
dm_parse_template_args(dm_state_t *st)
{
    if (!consume(st, 'I')) return false;
    dm_append(st, "<");
    bool first = true;
    while (!consume(st, 'E') && !at_end(st)) {
        if (!first) dm_append(st, ", ");
        first = false;

        // Capture each template argument text for T_ resolution.
        size_t arg_start = st->output_size;

        char c = peek(st);
        if (c == 'L') {
            st->pos++;
            if (!dm_parse_type(st)) return false;
            while (!consume(st, 'E') && !at_end(st)) st->pos++;
        } else if (c == 'X') {
            st->pos++;
            if (!dm_parse_expression(st)) return false;
            if (!consume(st, 'E')) return false;
        } else if (c == 'J') {
            st->pos++;
            while (!consume(st, 'E') && !at_end(st)) {
                if (!first) dm_append(st, ", ");
                first = false;
                if (!dm_parse_type(st)) return false;
            }
        } else {
            if (!dm_parse_type(st)) return false;
        }

        // Save the argument text for T_ substitutions.
        size_t arg_len = st->output_size - arg_start;
        if (arg_len > 0) {
            char *arg = n00b_objfile_strndup(st->output + arg_start, arg_len);
            strlist_push(&st->template_args, arg);
        }
    }
    dm_append(st, ">");
    return true;
}

// ============================================================================
// Expression (simplified)
// ============================================================================

static bool
dm_parse_expression(dm_state_t *st)
{
    if (++st->depth > st->max_depth) return false;

    char c = peek(st);

    if (c == 'L') {
        st->pos++;
        if (!dm_parse_type(st)) { --st->depth; return false; }
        while (!consume(st, 'E') && !at_end(st)) {
            if (isdigit(peek(st)) || peek(st) == 'n') {
                int64_t val;
                dm_parse_number(st, &val);
                char buf[32];
                snprintf(buf, sizeof(buf), "%lld", (long long)val);
                dm_append(st, buf);
            } else {
                st->pos++;
            }
        }
        --st->depth;
        return true;
    }
    if (c == 'T') { bool r = dm_parse_type(st); --st->depth; return r; }
    if (c == 's' && peek_n(st, 1) == 't') {
        st->pos += 2;
        dm_append(st, "sizeof(");
        if (!dm_parse_type(st)) { --st->depth; return false; }
        dm_append(st, ")");
        --st->depth;
        return true;
    }
    if (c == 's' && peek_n(st, 1) == 'z') {
        st->pos += 2;
        dm_append(st, "sizeof(");
        if (!dm_parse_expression(st)) { --st->depth; return false; }
        dm_append(st, ")");
        --st->depth;
        return true;
    }
    bool r = dm_parse_name(st);
    --st->depth;
    return r;
}

// ============================================================================
// Nested name
// ============================================================================

static bool
dm_parse_nested_name(dm_state_t *st)
{
    if (!consume(st, 'N')) return false;

    bool is_const, is_volatile;
    dm_parse_cv_qualifiers(st, &is_const, &is_volatile);
    bool is_lvalue_ref = consume(st, 'R');
    bool is_rvalue_ref = !is_lvalue_ref && consume(st, 'O');

    bool        first            = true;
    size_t      class_name_off   = 0;
    size_t      class_len        = 0;
    bool        has_class_name   = false;

    while (!consume(st, 'E') && !at_end(st)) {
        if (!first) dm_append(st, "::");

        size_t name_start = st->output_size;

        if (peek(st) == 'S') {
            const char *saved = st->pos;
            if (dm_parse_substitution(st)) {
                if (peek(st) == 'I') dm_parse_template_args(st);
                first = false;
                continue;
            }
            st->pos = saved;
        }
        if (peek(st) == 'C' || peek(st) == 'D') {
            if (dm_parse_ctor_dtor_name(st)) { first = false; continue; }
        }
        if (dm_parse_operator_name(st)) { first = false; continue; }

        if (isdigit(peek(st))) {
            if (!dm_parse_source_name(st)) return false;

            class_name_off = name_start;
            class_len      = st->output_size - name_start;
            has_class_name = true;

            if (peek(st) == 'I') dm_parse_template_args(st);

            char *sub = n00b_objfile_strndup(st->output, st->output_size);
            dm_add_sub(st, sub);
            n00b_free(sub);

            first = false;
            continue;
        }
        if (peek(st) == 'T') {
            if (!dm_parse_type(st)) return false;
            first = false;
            continue;
        }
        if (peek(st) == 'D' && (peek_n(st, 1) == 't' || peek_n(st, 1) == 'T')) {
            if (!dm_parse_type(st)) return false;
            first = false;
            continue;
        }
        break;
    }

    // Replace {ctor}/{dtor} markers with class name.
    // NOTE: class_name is computed from offset AFTER all parsing is done,
    // so it's safe even if st->output was realloc'd during parsing.
    if (has_class_name && class_len > 0) {
        char *ctor = strstr(st->output, "{ctor}");
        char *dtor = strstr(st->output, "~{dtor}");

        if (ctor || dtor) {
            const char *class_name = st->output + class_name_off;
            char *buf = n00b_alloc_array(char, st->output_cap);
            char *src = st->output;
            char *dst = buf;

            while (*src) {
                if (strncmp(src, "{ctor}", 6) == 0) {
                    memcpy(dst, class_name, class_len);
                    dst += class_len;
                    src += 6;
                } else if (strncmp(src, "~{dtor}", 7) == 0) {
                    *dst++ = '~';
                    memcpy(dst, class_name, class_len);
                    dst += class_len;
                    src += 7;
                } else {
                    *dst++ = *src++;
                }
            }
            *dst = '\0';
            n00b_free(st->output);
            st->output      = buf;
            st->output_size = (size_t)(dst - buf);
        }
    }

    if (is_lvalue_ref)      dm_append(st, " &");
    else if (is_rvalue_ref) dm_append(st, " &&");

    return true;
}

// ============================================================================
// Unscoped name
// ============================================================================

static bool
dm_parse_unscoped_name(dm_state_t *st)
{
    if (consume_str(st, "St")) dm_append(st, "std::");
    if (isdigit(peek(st))) return dm_parse_source_name(st);
    return dm_parse_operator_name(st);
}

// ============================================================================
// Name
// ============================================================================

static bool
dm_parse_name(dm_state_t *st)
{
    if (peek(st) == 'N') return dm_parse_nested_name(st);

    if (peek(st) == 'S') {
        const char *saved = st->pos;
        if (dm_parse_substitution(st)) {
            if (peek(st) == 'I') dm_parse_template_args(st);
            return true;
        }
        st->pos = saved;
    }

    if (consume(st, 'Z')) {
        if (!dm_parse_encoding(st)) return false;
        if (!consume(st, 'E')) return false;
        dm_append(st, "::");
        if (consume(st, 's')) {
            int64_t disc;
            if (isdigit(peek(st))) dm_parse_number(st, &disc);
            return true;
        }
        return dm_parse_name(st);
    }

    if (!dm_parse_unscoped_name(st)) return false;
    if (peek(st) == 'I') dm_parse_template_args(st);
    return true;
}

// ============================================================================
// Encoding
// ============================================================================

static bool
dm_parse_encoding(dm_state_t *st)
{
    if (peek(st) == 'T') {
        char c2 = peek_n(st, 1);
        if (c2 == 'V') { st->pos += 2; dm_append(st, "vtable for "); return dm_parse_type(st); }
        if (c2 == 'T') { st->pos += 2; dm_append(st, "VTT for "); return dm_parse_type(st); }
        if (c2 == 'I') { st->pos += 2; dm_append(st, "typeinfo for "); return dm_parse_type(st); }
        if (c2 == 'S') { st->pos += 2; dm_append(st, "typeinfo name for "); return dm_parse_type(st); }
        if (c2 == 'c') {
            st->pos += 2;
            dm_append(st, "construction vtable for ");
            while (peek(st) != 'N' && !at_end(st) && !isdigit(peek(st)))
                st->pos++;
            return dm_parse_encoding(st);
        }
        if (c2 == 'h' || c2 == 'v') {
            st->pos += 2;
            dm_append(st, c2 == 'h' ? "non-virtual thunk to " : "virtual thunk to ");
            // Skip call offset (digits, possibly preceded by 'n' for negative).
            while (peek(st) != '_' && !at_end(st)) st->pos++;
            consume(st, '_');
            if (c2 == 'v') {
                // Virtual thunks have a second vcall offset.
                while (peek(st) != '_' && !at_end(st)) st->pos++;
                consume(st, '_');
            }
            return dm_parse_encoding(st);
        }
    }
    if (consume_str(st, "GV")) {
        dm_append(st, "guard variable for ");
        return dm_parse_name(st);
    }

    if (!dm_parse_name(st)) return false;

    if (!at_end(st) && peek(st) != 'E')
        dm_parse_bare_function_type(st);

    return true;
}

// ============================================================================
// Internal C string API
// ============================================================================

// Returns malloc'd string or nullptr.
static char *
itanium_demangle_cstr(const char *mangled)
{
    if (!mangled) return nullptr;

    const char *input = mangled;
    if (input[0] == '_' && input[1] == '_' && input[2] == 'Z')
        input++;

    if (input[0] != '_' || input[1] != 'Z')
        return nullptr;

    input += 2;

    dm_state_t st;
    dm_init(&st, input);
    bool ok = dm_parse_encoding(&st);

    char *result = nullptr;
    if (ok && !st.error)
        result = n00b_objfile_strdup(st.output);

    dm_free(&st);
    return result;
}

// ============================================================================
// Rust demangler (defined in n00b_demangle_rust.c)
// ============================================================================

extern char *rust_demangle_cstr(const char *mangled);
extern bool  rust_is_mangled_check(const char *name);

// ============================================================================
// Public API
// ============================================================================

bool
n00b_is_mangled(const char *name)
{
    if (!name) return false;

    // C++ Itanium: _Z or __Z
    if (name[0] == '_') {
        if (name[1] == 'Z') return true;
        if (name[1] == '_' && name[2] == 'Z') return true;
    }
    // Rust v0: _R
    if (name[0] == '_' && name[1] == 'R') {
        char c = name[2];
        return (c == 'C' || c == 'M' || c == 'X' || c == 'Y' ||
                c == 'N' || c == 'I' || c == 'B' ||
                (c >= '0' && c <= '9'));
    }
    return false;
}

n00b_string_t *
n00b_demangle_itanium(const char *mangled)
{
    if (!mangled) return nullptr;

    char *result = itanium_demangle_cstr(mangled);
    if (result) {
        n00b_string_t *s = n00b_string_from_cstr(result);
        n00b_free(result);
        return s;
    }
    // Not mangled or parse failure — return copy of original.
    return n00b_string_from_cstr(mangled);
}

n00b_option_t(n00b_string_t *)
n00b_demangle_rust(const char *mangled)
{
    if (!mangled) return n00b_option_none(n00b_string_t *);

    char *result = rust_demangle_cstr(mangled);
    if (result) {
        n00b_string_t *s = n00b_string_from_cstr(result);
        n00b_free(result);
        return n00b_option_set(n00b_string_t *, s);
    }
    return n00b_option_none(n00b_string_t *);
}

n00b_string_t *
n00b_demangle(const char *mangled)
{
    if (!mangled) return nullptr;

    // Try C++ Itanium first.
    char *cxx = itanium_demangle_cstr(mangled);
    if (cxx) {
        n00b_string_t *s = n00b_string_from_cstr(cxx);
        n00b_free(cxx);
        return s;
    }

    // Try Rust v0.
    char *rs = rust_demangle_cstr(mangled);
    if (rs) {
        n00b_string_t *s = n00b_string_from_cstr(rs);
        n00b_free(rs);
        return s;
    }

    // Not mangled — return copy.
    return n00b_string_from_cstr(mangled);
}
