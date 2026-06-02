#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "n00b.h"
#include "adt/dict.h"
#include "core/rwlock.h"
#include "core/static_image.h"
#include "core/type_info.h"
#include "slay/grammar.h"
#include "slay/bnf.h"
#include "slay/grammar_image.h"

extern void n00b_init_simple(int argc, char *argv[]);
extern void n00b_shutdown(void);

// Per-pair record for `container_kind dict` requests. Mirrors the list
// element stream's single-`cinit` shape, but carries paired key/value
// initializer expressions plus a precomputed key hash (the helper does
// not have access to ncc's full hash machinery for arbitrary keys, so
// ncc -- or the test fixture in Phase 3b -- precomputes the hash and
// passes it as 16 raw little-endian bytes per pair).  `emit_cached_hash`
// is the per-key opt-in for emitting the cached_hash slot on the key's
// static-object descriptor.
typedef struct {
    char    *key_expr;
    char    *value_expr;
    bool     have_hash;
    uint64_t hash_lo;
    uint64_t hash_hi;
    bool     emit_cached_hash;
} dict_pair_t;

typedef struct {
    char                    *type_name;
    uint64_t                 type_hash;
    char                    *symbol_prefix;
    char                    *entry_attr;
    char                    *container_kind;
    char                    *container_target;
    char                    *element_type_name;
    uint64_t                 element_type_hash;
    uint64_t                 data_type_hash;
    uint64_t                 container_len;
    uint64_t                 container_cap;
    char                    *element_scan_kind;
    char                    *element_scan_cb;
    char                    *element_scan_user;
    char                    *element_shape_decl;
    char                    *identity_namespace;
    char                    *identity_object_key;
    char                    *identity_payload_key;
    bool                     readonly;
    bool                     have_abi;
    n00b_static_image_abi_t  abi;
    uint64_t                 expected_arg_count;
    n00b_static_init_arg_t  *args;
    uint64_t                 arg_count;
    char                   **cinit_items;
    uint64_t                 cinit_count;
    uint64_t                 cinit_cap;
    // Dict-specific request fields. The list/array paths leave these
    // zero-initialized and ignore them.
    char                    *key_type_name;
    uint64_t                 key_type_hash;
    char                    *key_scan_kind;
    char                    *key_scan_cb;
    char                    *key_scan_user;
    char                    *key_shape_decl;
    char                    *value_type_name;
    uint64_t                 value_type_hash;
    char                    *value_scan_kind;
    char                    *value_scan_cb;
    char                    *value_scan_user;
    char                    *value_shape_decl;
    bool                     skip_obj_hash;
    bool                     cached_hash_emit_default;
    dict_pair_t             *dict_pairs;
    uint64_t                 dict_pair_count;
    uint64_t                 dict_pair_cap;
    // Grammar-specific request fields (WP-018, `container_kind grammar`).
    // The other container kinds leave these null and ignore them.
    char                    *bnf_path;
    char                    *start_nt;
} helper_request_t;

static char *
read_stdin(void)
{
    size_t cap = 4096;
    size_t len = 0;
    char  *buf = n00b_alloc_array(char, cap);

    if (!buf) {
        return NULL;
    }

    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= cap) {
            cap *= 2;
            // No n00b_realloc: grow by allocating a larger block, copying the
            // bytes written so far, and freeing the old one.
            char *new_buf = n00b_alloc_array(char, cap);
            if (!new_buf) {
                n00b_free(buf);
                return NULL;
            }
            memcpy(new_buf, buf, len);
            n00b_free(buf);
            buf = new_buf;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    return buf;
}

static char *
dup_cstr(const char *s)
{
    size_t len = strlen(s);
    char  *out = n00b_alloc_array(char, len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, len + 1);
    return out;
}

static char *
sibling_tool_path(const char *argv0, const char *name)
{
    const char *slash = strrchr(argv0, '/');
    if (!slash) {
        return dup_cstr(name);
    }

    size_t dir_len  = (size_t)(slash - argv0 + 1);
    size_t name_len = strlen(name);
    char  *out      = n00b_alloc_array(char, dir_len + name_len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, argv0, dir_len);
    memcpy(out + dir_len, name, name_len + 1);
    return out;
}

static int
write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) {
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int
delegate_grammar_request(const char *argv0, const char *input)
{
    char *helper = sibling_tool_path(argv0, "n00b-static-grammar-helper");
    if (!helper) {
        fprintf(stderr, "out of memory finding n00b-static-grammar-helper");
        return 5;
    }

    int in_pipe[2];
    if (pipe(in_pipe) != 0) {
        fprintf(stderr, "cannot create pipe for n00b-static-grammar-helper");
        n00b_free(helper);
        return 5;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "cannot fork n00b-static-grammar-helper");
        close(in_pipe[0]);
        close(in_pipe[1]);
        n00b_free(helper);
        return 5;
    }

    if (pid == 0) {
        close(in_pipe[1]);
        if (dup2(in_pipe[0], STDIN_FILENO) < 0) {
            _exit(126);
        }
        close(in_pipe[0]);
        execl(helper, helper, (char *)NULL);
        _exit(127);
    }

    close(in_pipe[0]);
    int write_status = write_all(in_pipe[1], input, strlen(input));
    close(in_pipe[1]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            n00b_free(helper);
            return 5;
        }
    }
    n00b_free(helper);

    if (write_status != 0) {
        return 5;
    }
    if (!WIFEXITED(status)) {
        return 5;
    }
    return WEXITSTATUS(status);
}

static char *
trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static char *
next_token(char **cursor)
{
    char *p = *cursor;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (!*p) {
        *cursor = p;
        return NULL;
    }

    char *start = p;
    while (*p && !isspace((unsigned char)*p)) {
        p++;
    }
    if (*p) {
        *p++ = '\0';
    }
    *cursor = p;
    return start;
}

static int
hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static void *
hex_decode_exact(const char *hex, uint64_t len, bool nul_term, bool *ok)
{
    size_t hex_len = strlen(hex);
    if (hex_len != (size_t)(len * 2)) {
        *ok = false;
        return NULL;
    }

    unsigned char *out = n00b_alloc_array(unsigned char,
                                           (size_t)len + (nul_term ? 1u : 0u) + 1u);
    if (!out) {
        *ok = false;
        return NULL;
    }

    for (uint64_t i = 0; i < len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            n00b_free(out);
            *ok = false;
            return NULL;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    *ok = true;
    return out;
}

static char *
hex_decode_cstr(const char *hex)
{
    size_t hex_len = strlen(hex);
    if ((hex_len % 2u) != 0) {
        return NULL;
    }

    bool ok = false;
    return hex_decode_exact(hex, (uint64_t)(hex_len / 2u), true, &ok);
}

static bool
parse_u64_token(const char *text, uint64_t *out)
{
    if (!text || !*text) {
        return false;
    }

    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 0);
    if (end == text) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static bool
parse_i64_token(const char *text, int64_t *out)
{
    if (!text || !*text) {
        return false;
    }

    char *end = NULL;
    long long value = strtoll(text, &end, 0);
    if (end == text) {
        return false;
    }
    *out = (int64_t)value;
    return true;
}

static bool
append_arg(helper_request_t *req, n00b_static_init_arg_t arg)
{
    n00b_static_init_arg_t *new_args
        = n00b_alloc_array(n00b_static_init_arg_t,
                           (size_t)(req->arg_count + 1u));
    if (!new_args) {
        return false;
    }
    if (req->args) {
        memcpy(new_args,
               req->args,
               (size_t)req->arg_count * sizeof(*req->args));
        n00b_free(req->args);
    }

    req->args = new_args;
    req->args[req->arg_count++] = arg;
    return true;
}

static bool
append_cinit(helper_request_t *req, char *expr)
{
    if (req->cinit_count == req->cinit_cap) {
        uint64_t new_cap = req->cinit_cap ? req->cinit_cap * 2u : 8u;
        char **new_items = n00b_alloc_array(char *, (size_t)new_cap);
        if (!new_items) {
            return false;
        }
        if (req->cinit_items) {
            memcpy(new_items,
                   req->cinit_items,
                   (size_t)req->cinit_count * sizeof(*new_items));
            n00b_free(req->cinit_items);
        }
        req->cinit_items = new_items;
        req->cinit_cap   = new_cap;
    }

    req->cinit_items[req->cinit_count++] = expr;
    return true;
}

static bool
append_dict_pair(helper_request_t *req, dict_pair_t pair)
{
    if (req->dict_pair_count == req->dict_pair_cap) {
        uint64_t new_cap = req->dict_pair_cap ? req->dict_pair_cap * 2u : 8u;
        dict_pair_t *new_items = n00b_alloc_array(dict_pair_t, (size_t)new_cap);
        if (!new_items) {
            return false;
        }
        if (req->dict_pairs) {
            memcpy(new_items,
                   req->dict_pairs,
                   (size_t)req->dict_pair_count * sizeof(*new_items));
            n00b_free(req->dict_pairs);
        }
        req->dict_pairs    = new_items;
        req->dict_pair_cap = new_cap;
    }

    req->dict_pairs[req->dict_pair_count++] = pair;
    return true;
}

static bool
parse_abi_line(char *line, helper_request_t *req)
{
    char *p = line;
    (void)next_token(&p);

    uint64_t pointer_bytes = 0;
    uint64_t size_t_bytes  = 0;
    uint64_t char_bits     = 0;
    uint64_t endian        = 0;

    if (!parse_u64_token(next_token(&p), &pointer_bytes)
        || !parse_u64_token(next_token(&p), &size_t_bytes)
        || !parse_u64_token(next_token(&p), &char_bits)
        || !parse_u64_token(next_token(&p), &endian)) {
        return false;
    }

    req->abi = (n00b_static_image_abi_t){
        .version       = N00B_STATIC_IMAGE_CONTRACT_VERSION,
        .pointer_bytes = (uint8_t)pointer_bytes,
        .size_t_bytes  = (uint8_t)size_t_bytes,
        .char_bits     = (uint8_t)char_bits,
        .endian        = (uint8_t)endian,
    };
    req->have_abi = true;
    return true;
}

static bool
parse_arg_line(char *line, helper_request_t *req)
{
    char *p = line;
    (void)next_token(&p);

    char *name = next_token(&p);
    char *kind = next_token(&p);
    if (!name || !kind) {
        return false;
    }

    n00b_static_init_arg_t arg = {
        .name = strcmp(name, "-") == 0 ? NULL : dup_cstr(name),
    };
    if (arg.name == NULL && strcmp(name, "-") != 0) {
        return false;
    }

    if (strcmp(kind, "cinit") == 0) {
        uint64_t len = 0;
        if (!parse_u64_token(next_token(&p), &len)) {
            n00b_free((void *)arg.name);
            return false;
        }

        char *hex = trim(p);
        bool  ok  = false;
        char *expr = hex_decode_exact(hex, len, true, &ok);
        n00b_free((void *)arg.name);
        if (!ok) {
            return false;
        }
        if (!append_cinit(req, expr)) {
            n00b_free(expr);
            return false;
        }
        return true;
    }

    if (strcmp(kind, "pair") == 0) {
        // Pair record shape:
        //   arg <name|-> pair cinit <key_len> <key_hex> <val_len> <val_hex>
        //       [hash <hash_lo_hex> <hash_hi_hex>] [emit_hash <0|1>]
        // `name` is reserved for future per-pair labelling; "-" is used
        // for unnamed pairs (the helper does not consume the name today).
        char *subkind = next_token(&p);
        if (!subkind || strcmp(subkind, "cinit") != 0) {
            n00b_free((void *)arg.name);
            return false;
        }

        uint64_t key_len = 0;
        if (!parse_u64_token(next_token(&p), &key_len)) {
            n00b_free((void *)arg.name);
            return false;
        }

        char *key_hex_tok = next_token(&p);
        if (!key_hex_tok) {
            n00b_free((void *)arg.name);
            return false;
        }
        bool  ok       = false;
        char *key_expr = hex_decode_exact(key_hex_tok, key_len, true, &ok);
        if (!ok) {
            n00b_free((void *)arg.name);
            return false;
        }

        uint64_t val_len = 0;
        if (!parse_u64_token(next_token(&p), &val_len)) {
            n00b_free((void *)arg.name);
            n00b_free(key_expr);
            return false;
        }

        char *val_hex_tok = next_token(&p);
        if (!val_hex_tok) {
            n00b_free((void *)arg.name);
            n00b_free(key_expr);
            return false;
        }
        ok = false;
        char *val_expr = hex_decode_exact(val_hex_tok, val_len, true, &ok);
        if (!ok) {
            n00b_free((void *)arg.name);
            n00b_free(key_expr);
            return false;
        }

        dict_pair_t pair = {
            .key_expr         = key_expr,
            .value_expr       = val_expr,
            .have_hash        = false,
            .hash_lo          = 0,
            .hash_hi          = 0,
            .emit_cached_hash = req->cached_hash_emit_default,
        };

        // Optional trailing modifiers.
        char *modifier = next_token(&p);
        while (modifier) {
            if (strcmp(modifier, "hash") == 0) {
                if (!parse_u64_token(next_token(&p), &pair.hash_lo)
                    || !parse_u64_token(next_token(&p), &pair.hash_hi)) {
                    n00b_free((void *)arg.name);
                    n00b_free(key_expr);
                    n00b_free(val_expr);
                    return false;
                }
                pair.have_hash = true;
            }
            else if (strcmp(modifier, "emit_hash") == 0) {
                uint64_t flag = 0;
                if (!parse_u64_token(next_token(&p), &flag)) {
                    n00b_free((void *)arg.name);
                    n00b_free(key_expr);
                    n00b_free(val_expr);
                    return false;
                }
                pair.emit_cached_hash = (flag != 0);
            }
            else {
                n00b_free((void *)arg.name);
                n00b_free(key_expr);
                n00b_free(val_expr);
                return false;
            }
            modifier = next_token(&p);
        }

        n00b_free((void *)arg.name);
        if (!append_dict_pair(req, pair)) {
            n00b_free(key_expr);
            n00b_free(val_expr);
            return false;
        }
        return true;
    }

    if (strcmp(kind, "bytes") == 0) {
        uint64_t len = 0;
        if (!parse_u64_token(next_token(&p), &len)) {
            n00b_free((void *)arg.name);
            return false;
        }

        char *hex = trim(p);
        if (len != 0 && !*hex) {
            n00b_free((void *)arg.name);
            return false;
        }

        bool ok = false;
        void *data = hex_decode_exact(hex, len, false, &ok);
        if (!ok) {
            n00b_free((void *)arg.name);
            return false;
        }

        arg.kind       = N00B_STATIC_INIT_ARG_BYTES;
        arg.bytes.data = data;
        arg.bytes.len  = len;
        return append_arg(req, arg);
    }

    if (strcmp(kind, "int") == 0) {
        int64_t value = 0;
        if (!parse_i64_token(next_token(&p), &value)) {
            n00b_free((void *)arg.name);
            return false;
        }
        arg.kind    = N00B_STATIC_INIT_ARG_INT;
        arg.integer = value;
        return append_arg(req, arg);
    }

    if (strcmp(kind, "bool") == 0) {
        uint64_t value = 0;
        if (!parse_u64_token(next_token(&p), &value)) {
            n00b_free((void *)arg.name);
            return false;
        }
        arg.kind    = N00B_STATIC_INIT_ARG_BOOL;
        arg.boolean = value != 0;
        return append_arg(req, arg);
    }

    n00b_free((void *)arg.name);
    return false;
}

static bool
parse_request(char *input, helper_request_t *req)
{
    uint64_t line_no = 0;

    char *line;
    for (line = input; line;) {
        char *next = strchr(line, '\n');
        if (next) {
            *next++ = '\0';
        }
        line_no++;

        line = trim(line);
        if (!*line || strcmp(line, "NCC_STATIC_INIT 1") == 0
            || strcmp(line, "end") == 0) {
            line = next;
            continue;
        }

        if (strncmp(line, "type_hex ", 9) == 0) {
            n00b_free(req->type_name);
            req->type_name = hex_decode_cstr(trim(line + 9));
            if (!req->type_name) {
                fprintf(stderr, "bad request line %llu: invalid type_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "type_hash ", 10) == 0) {
            if (!parse_u64_token(trim(line + 10), &req->type_hash)) {
                fprintf(stderr, "bad request line %llu: invalid type_hash",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "prefix ", 7) == 0) {
            n00b_free(req->symbol_prefix);
            req->symbol_prefix = dup_cstr(trim(line + 7));
            if (!req->symbol_prefix) {
                fprintf(stderr, "bad request line %llu: invalid prefix",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "container_kind ", 15) == 0) {
            n00b_free(req->container_kind);
            req->container_kind = dup_cstr(trim(line + 15));
            if (!req->container_kind) {
                fprintf(stderr, "bad request line %llu: invalid container_kind",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "bnf_path ", 9) == 0) {
            n00b_free(req->bnf_path);
            req->bnf_path = dup_cstr(trim(line + 9));
            if (!req->bnf_path) {
                fprintf(stderr, "bad request line %llu: invalid bnf_path",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "start_nt ", 9) == 0) {
            n00b_free(req->start_nt);
            req->start_nt = dup_cstr(trim(line + 9));
            if (!req->start_nt) {
                fprintf(stderr, "bad request line %llu: invalid start_nt",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "container_target ", 17) == 0) {
            n00b_free(req->container_target);
            req->container_target = dup_cstr(trim(line + 17));
            if (!req->container_target) {
                fprintf(stderr, "bad request line %llu: invalid container_target",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_type_hex ", 17) == 0) {
            n00b_free(req->element_type_name);
            req->element_type_name = hex_decode_cstr(trim(line + 17));
            if (!req->element_type_name) {
                fprintf(stderr, "bad request line %llu: invalid element_type_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_type_hash ", 18) == 0) {
            if (!parse_u64_token(trim(line + 18), &req->element_type_hash)) {
                fprintf(stderr, "bad request line %llu: invalid element_type_hash",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "data_type_hash ", 15) == 0) {
            if (!parse_u64_token(trim(line + 15), &req->data_type_hash)) {
                fprintf(stderr, "bad request line %llu: invalid data_type_hash",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "readonly ", 9) == 0) {
            uint64_t value = 0;
            if (!parse_u64_token(trim(line + 9), &value)) {
                fprintf(stderr, "bad request line %llu: invalid readonly",
                        (unsigned long long)line_no);
                return false;
            }
            req->readonly = value != 0;
        }
        else if (strncmp(line, "len ", 4) == 0) {
            if (!parse_u64_token(trim(line + 4), &req->container_len)) {
                fprintf(stderr, "bad request line %llu: invalid len",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "cap ", 4) == 0) {
            if (!parse_u64_token(trim(line + 4), &req->container_cap)) {
                fprintf(stderr, "bad request line %llu: invalid cap",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "abi ", 4) == 0) {
            if (!parse_abi_line(line, req)) {
                fprintf(stderr, "bad request line %llu: invalid abi",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "entry_attr_hex ", 15) == 0) {
            n00b_free(req->entry_attr);
            req->entry_attr = hex_decode_cstr(trim(line + 15));
            if (!req->entry_attr) {
                fprintf(stderr, "bad request line %llu: invalid entry_attr_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "identity_namespace_hex ", 23) == 0) {
            n00b_free(req->identity_namespace);
            req->identity_namespace = hex_decode_cstr(trim(line + 23));
            if (!req->identity_namespace) {
                fprintf(stderr,
                        "bad request line %llu: invalid identity_namespace_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "identity_object_key_hex ", 24) == 0) {
            n00b_free(req->identity_object_key);
            req->identity_object_key = hex_decode_cstr(trim(line + 24));
            if (!req->identity_object_key) {
                fprintf(stderr,
                        "bad request line %llu: invalid identity_object_key_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "identity_payload_key_hex ", 25) == 0) {
            n00b_free(req->identity_payload_key);
            req->identity_payload_key = hex_decode_cstr(trim(line + 25));
            if (!req->identity_payload_key) {
                fprintf(stderr,
                        "bad request line %llu: invalid identity_payload_key_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_scan_kind ", 18) == 0) {
            n00b_free(req->element_scan_kind);
            req->element_scan_kind = dup_cstr(trim(line + 18));
            if (!req->element_scan_kind) {
                fprintf(stderr, "bad request line %llu: invalid element_scan_kind",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_scan_cb_hex ", 20) == 0) {
            n00b_free(req->element_scan_cb);
            req->element_scan_cb = hex_decode_cstr(trim(line + 20));
            if (!req->element_scan_cb) {
                fprintf(stderr, "bad request line %llu: invalid element_scan_cb_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_scan_user_hex ", 22) == 0) {
            n00b_free(req->element_scan_user);
            req->element_scan_user = hex_decode_cstr(trim(line + 22));
            if (!req->element_scan_user) {
                fprintf(stderr,
                        "bad request line %llu: invalid element_scan_user_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strcmp(line, "element_shape_decl_hex") == 0) {
            n00b_free(req->element_shape_decl);
            req->element_shape_decl = dup_cstr("");
            if (!req->element_shape_decl) {
                fprintf(stderr,
                        "bad request line %llu: invalid element_shape_decl_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "element_shape_decl_hex ", 23) == 0) {
            n00b_free(req->element_shape_decl);
            req->element_shape_decl = hex_decode_cstr(trim(line + 23));
            if (!req->element_shape_decl) {
                fprintf(stderr,
                        "bad request line %llu: invalid element_shape_decl_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "arg_count ", 10) == 0) {
            if (!parse_u64_token(trim(line + 10), &req->expected_arg_count)) {
                fprintf(stderr, "bad request line %llu: invalid arg_count",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "arg ", 4) == 0) {
            if (!parse_arg_line(line, req)) {
                fprintf(stderr, "bad request line %llu: invalid arg",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "key_type_hex ", 13) == 0) {
            n00b_free(req->key_type_name);
            req->key_type_name = hex_decode_cstr(trim(line + 13));
            if (!req->key_type_name) {
                fprintf(stderr, "bad request line %llu: invalid key_type_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "key_type_hash ", 14) == 0) {
            if (!parse_u64_token(trim(line + 14), &req->key_type_hash)) {
                fprintf(stderr, "bad request line %llu: invalid key_type_hash",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "key_scan_kind ", 14) == 0) {
            n00b_free(req->key_scan_kind);
            req->key_scan_kind = dup_cstr(trim(line + 14));
            if (!req->key_scan_kind) {
                fprintf(stderr, "bad request line %llu: invalid key_scan_kind",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "key_scan_cb_hex ", 16) == 0) {
            n00b_free(req->key_scan_cb);
            req->key_scan_cb = hex_decode_cstr(trim(line + 16));
            if (!req->key_scan_cb) {
                fprintf(stderr, "bad request line %llu: invalid key_scan_cb_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "key_scan_user_hex ", 18) == 0) {
            n00b_free(req->key_scan_user);
            req->key_scan_user = hex_decode_cstr(trim(line + 18));
            if (!req->key_scan_user) {
                fprintf(stderr,
                        "bad request line %llu: invalid key_scan_user_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strcmp(line, "key_shape_decl_hex") == 0) {
            n00b_free(req->key_shape_decl);
            req->key_shape_decl = dup_cstr("");
            if (!req->key_shape_decl) {
                return false;
            }
        }
        else if (strncmp(line, "key_shape_decl_hex ", 19) == 0) {
            n00b_free(req->key_shape_decl);
            req->key_shape_decl = hex_decode_cstr(trim(line + 19));
            if (!req->key_shape_decl) {
                fprintf(stderr,
                        "bad request line %llu: invalid key_shape_decl_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "value_type_hex ", 15) == 0) {
            n00b_free(req->value_type_name);
            req->value_type_name = hex_decode_cstr(trim(line + 15));
            if (!req->value_type_name) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_type_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "value_type_hash ", 16) == 0) {
            if (!parse_u64_token(trim(line + 16), &req->value_type_hash)) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_type_hash",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "value_scan_kind ", 16) == 0) {
            n00b_free(req->value_scan_kind);
            req->value_scan_kind = dup_cstr(trim(line + 16));
            if (!req->value_scan_kind) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_scan_kind",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "value_scan_cb_hex ", 18) == 0) {
            n00b_free(req->value_scan_cb);
            req->value_scan_cb = hex_decode_cstr(trim(line + 18));
            if (!req->value_scan_cb) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_scan_cb_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "value_scan_user_hex ", 20) == 0) {
            n00b_free(req->value_scan_user);
            req->value_scan_user = hex_decode_cstr(trim(line + 20));
            if (!req->value_scan_user) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_scan_user_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strcmp(line, "value_shape_decl_hex") == 0) {
            n00b_free(req->value_shape_decl);
            req->value_shape_decl = dup_cstr("");
            if (!req->value_shape_decl) {
                return false;
            }
        }
        else if (strncmp(line, "value_shape_decl_hex ", 21) == 0) {
            n00b_free(req->value_shape_decl);
            req->value_shape_decl = hex_decode_cstr(trim(line + 21));
            if (!req->value_shape_decl) {
                fprintf(stderr,
                        "bad request line %llu: invalid value_shape_decl_hex",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else if (strncmp(line, "skip_obj_hash ", 14) == 0) {
            uint64_t value = 0;
            if (!parse_u64_token(trim(line + 14), &value)) {
                fprintf(stderr,
                        "bad request line %llu: invalid skip_obj_hash",
                        (unsigned long long)line_no);
                return false;
            }
            req->skip_obj_hash = (value != 0);
        }
        else if (strncmp(line, "cached_hash_emit ", 17) == 0) {
            const char *value = trim(line + 17);
            if (strcmp(value, "yes") == 0) {
                req->cached_hash_emit_default = true;
            }
            else if (strcmp(value, "no") == 0) {
                req->cached_hash_emit_default = false;
            }
            else {
                fprintf(stderr,
                        "bad request line %llu: invalid cached_hash_emit "
                        "(expected 'yes' or 'no')",
                        (unsigned long long)line_no);
                return false;
            }
        }
        else {
            fprintf(stderr, "bad request line %llu: unknown field '%s'",
                    (unsigned long long)line_no, line);
            return false;
        }

        line = next;
    }

    // `container_kind grammar` (WP-018/WP-020) uses a distinct request shape:
    // it carries bnf_path/start_nt/symbol_prefix and emits a marshal-backed
    // grammar materializer, so it does NOT supply
    // type_name/type_hash/entry_attr/abi or argument streams. Validate
    // its own required fields and skip the container-literal checks.
    if (req->container_kind && strcmp(req->container_kind, "grammar") == 0) {
        if (!req->bnf_path || !req->start_nt || !req->symbol_prefix) {
            fprintf(stderr,
                    "bad request: container_kind grammar requires bnf_path, "
                    "start_nt, and symbol_prefix (bnf_path=%d start_nt=%d "
                    "prefix=%d)",
                    req->bnf_path != NULL, req->start_nt != NULL,
                    req->symbol_prefix != NULL);
            return false;
        }
        return true;
    }

    uint64_t supplied_args = req->arg_count + req->cinit_count
                             + req->dict_pair_count;
    if (!req->type_name || req->type_hash == 0 || !req->symbol_prefix
        || !req->entry_attr || !req->have_abi
        || supplied_args != req->expected_arg_count) {
        fprintf(stderr,
                "bad request: missing required fields or arg_count mismatch "
                "(type=%d type_hash=%llu prefix=%d entry_attr=%d abi=%d "
                "args=%llu cinit=%llu pairs=%llu expected=%llu)",
                req->type_name != NULL, (unsigned long long)req->type_hash,
                req->symbol_prefix != NULL, req->entry_attr != NULL,
                req->have_abi, (unsigned long long)req->arg_count,
                (unsigned long long)req->cinit_count,
                (unsigned long long)req->dict_pair_count,
                (unsigned long long)req->expected_arg_count);
        return false;
    }

    return true;
}

static void
free_request(helper_request_t *req)
{
    n00b_free(req->type_name);
    n00b_free(req->symbol_prefix);
    n00b_free(req->entry_attr);
    n00b_free(req->container_kind);
    n00b_free(req->container_target);
    n00b_free(req->element_type_name);
    n00b_free(req->element_scan_kind);
    n00b_free(req->element_scan_cb);
    n00b_free(req->element_scan_user);
    n00b_free(req->element_shape_decl);
    n00b_free(req->identity_namespace);
    n00b_free(req->identity_object_key);
    n00b_free(req->identity_payload_key);
    n00b_free(req->key_type_name);
    n00b_free(req->key_scan_kind);
    n00b_free(req->key_scan_cb);
    n00b_free(req->key_scan_user);
    n00b_free(req->key_shape_decl);
    n00b_free(req->value_type_name);
    n00b_free(req->value_scan_kind);
    n00b_free(req->value_scan_cb);
    n00b_free(req->value_scan_user);
    n00b_free(req->value_shape_decl);
    for (uint64_t i = 0; i < req->arg_count; i++) {
        n00b_free((void *)req->args[i].name);
        if (req->args[i].kind == N00B_STATIC_INIT_ARG_BYTES) {
            n00b_free((void *)req->args[i].bytes.data);
        }
    }
    n00b_free(req->args);
    for (uint64_t i = 0; i < req->cinit_count; i++) {
        n00b_free(req->cinit_items[i]);
    }
    n00b_free(req->cinit_items);
    for (uint64_t i = 0; i < req->dict_pair_count; i++) {
        n00b_free(req->dict_pairs[i].key_expr);
        n00b_free(req->dict_pairs[i].value_expr);
    }
    n00b_free(req->dict_pairs);
    n00b_free(req->bnf_path);
    n00b_free(req->start_nt);
}

static void
emit_c_string_literal(const char *s)
{
    putchar('"');
    const unsigned char *p;
    for (p = (const unsigned char *)(s ? s : ""); *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*p >= 0x20 && *p < 0x7f) {
                putchar((char)*p);
            }
            else {
                printf("\\%03o", (unsigned)*p);
            }
            break;
        }
    }
    putchar('"');
}

static bool
has_identity(const helper_request_t *req)
{
    return req->identity_namespace && req->identity_namespace[0]
        && req->identity_object_key && req->identity_object_key[0]
        && req->identity_payload_key && req->identity_payload_key[0];
}

static void
emit_identity_decls(const helper_request_t *req, bool include_object_identity)
{
    if (!has_identity(req)) {
        return;
    }

    printf("static const n00b_static_identity_t %s_payload_id={"
           ".version=1u,"
           ".kind=N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_PAYLOAD,"
           ".namespace_id=",
           req->symbol_prefix);
    emit_c_string_literal(req->identity_namespace);
    printf(",.object_key=");
    emit_c_string_literal(req->identity_payload_key);
    printf("};");

    if (!include_object_identity) {
        return;
    }

    printf("static const n00b_static_identity_t %s_obj_id={"
           ".version=1u,"
           ".kind=N00B_STATIC_IDENTITY_NCC_STATIC_IMAGE_OBJECT,"
           ".namespace_id=",
           req->symbol_prefix);
    emit_c_string_literal(req->identity_namespace);
    printf(",.object_key=");
    emit_c_string_literal(req->identity_object_key);
    printf("};");
}

static void
emit_request_identity_fields(const helper_request_t *req)
{
    if (!has_identity(req)) {
        printf(".identity_namespace=nullptr,.identity_object_key=nullptr,"
               ".identity_payload_key=nullptr,");
        return;
    }

    printf(".identity_namespace=");
    emit_c_string_literal(req->identity_namespace);
    printf(",.identity_object_key=");
    emit_c_string_literal(req->identity_object_key);
    printf(",.identity_payload_key=");
    emit_c_string_literal(req->identity_payload_key);
    printf(",");
}

static uint64_t
helper_hash_cstr(const char *s)
{
    uint64_t h = UINT64_C(1469598103934665603);
    while (s && *s) {
        h ^= (unsigned char)*s++;
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static const char *
or_default(const char *s, const char *fallback)
{
    return s && *s ? s : fallback;
}

static void
emit_cinit_items(const helper_request_t *req)
{
    for (uint64_t i = 0; i < req->cinit_count; i++) {
        if (i != 0) {
            putchar(',');
        }
        fputs(req->cinit_items[i], stdout);
    }
    if (req->cinit_count == 0) {
        fputs("0", stdout);
    }
}

static int
emit_list_image(const helper_request_t *req)
{
    if (!req->element_type_name || !req->data_type_hash
        || req->container_cap < req->container_len
        || req->cinit_count != req->container_len) {
        fprintf(stderr, "bad n00b list static initializer request");
        return 6;
    }

    bool pointer_target = req->container_target
                       && strcmp(req->container_target, "pointer") == 0;
    const char *flags = req->readonly ? "N00B_STATIC_OBJECT_F_READONLY"
                                      : "N00B_STATIC_OBJECT_F_MUTABLE";
    const char *obj_const = req->readonly ? "const " : "";
    const char *scan_kind = or_default(req->element_scan_kind,
                                       "N00B_GC_SCAN_KIND_NONE");
    const char *scan_cb = or_default(req->element_scan_cb, "nullptr");
    const char *scan_user = or_default(req->element_scan_user, "nullptr");
    uint64_t data_id = helper_hash_cstr(req->symbol_prefix)
                     ^ UINT64_C(0x6c69737464617461);
    uint64_t lock_id = helper_hash_cstr(req->symbol_prefix)
                     ^ UINT64_C(0x6c6973746c6f636b);
    uint64_t obj_id = helper_hash_cstr(req->symbol_prefix)
                    ^ UINT64_C(0x6c6973746f626a);
    unsigned contract_version = (unsigned)req->abi.version;
    unsigned target_endian    = (unsigned)req->abi.endian;

    printf("NCC_STATIC_INIT_OK ");
    if (pointer_target) {
        printf("&%s_obj\n", req->symbol_prefix);
    }
    else {
        printf("{.data=%s_data,.len=(size_t)%lluULL,.cap=(size_t)%lluULL,"
               ".lock=(n00b_rwlock_t*)%s_lock_storage,"
               ".allocator=nullptr,.scan_kind=%s,"
               ".scan_cb=%s,.scan_user=%s}\n",
               req->symbol_prefix,
               (unsigned long long)req->container_len,
               (unsigned long long)req->container_cap,
               req->symbol_prefix, scan_kind, scan_cb, scan_user);
    }

    emit_identity_decls(req, pointer_target);
    printf("%s", req->element_shape_decl ? req->element_shape_decl : "");
    printf("static %s %s_data[%llu]={",
           req->element_type_name, req->symbol_prefix,
           (unsigned long long)(req->container_cap ? req->container_cap : 1));
    emit_cinit_items(req);
    printf("};");
    printf("static const n00b_static_object_desc_t %s_data_desc={"
           ".start=(const void*)%s_data,"
           ".len=(uint64_t)sizeof(%s_data),"
           ".tinfo=%lluULL,.scan_kind=%s,.scan_cb=%s,.scan_user=%s,"
           ".object_id=%lluULL,.file=__FILE__,.identity=",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           (unsigned long long)req->data_type_hash,
           scan_kind, scan_cb, scan_user, (unsigned long long)data_id);
    printf("%s", has_identity(req) ? "&" : "nullptr");
    if (has_identity(req)) {
        printf("%s_payload_id", req->symbol_prefix);
    }
    printf(",.flags=%s};", flags);
    printf("static const n00b_static_object_desc_t * const "
           "%s_data_entry %s=&%s_data_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    printf("static unsigned char %s_lock_storage[%llu] "
           "__attribute__((aligned(%llu)))={0};",
           req->symbol_prefix,
           (unsigned long long)sizeof(n00b_rwlock_t),
           (unsigned long long)_Alignof(n00b_rwlock_t));
    printf("static const n00b_static_object_desc_t %s_lock_desc={"
           ".start=(const void*)%s_lock_storage,"
           ".len=(uint64_t)sizeof(%s_lock_storage),"
           ".tinfo=0,.scan_kind=N00B_GC_SCAN_KIND_NONE,"
           ".scan_cb=nullptr,.scan_user=nullptr,"
           ".object_id=%lluULL,.file=__FILE__,.identity=nullptr,"
           ".flags=N00B_STATIC_OBJECT_F_MUTABLE|N00B_STATIC_OBJECT_F_INIT_RWLOCK};",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           (unsigned long long)lock_id);
    printf("static const n00b_static_object_desc_t * const "
           "%s_lock_entry %s=&%s_lock_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    if (pointer_target) {
        printf("_Static_assert((__builtin_offsetof(%s,data)%%sizeof(void*))==0,"
               "\"list data pointer must be pointer-aligned\");",
               req->type_name);
        printf("static const uint64_t %s_obj_offsets[]={"
               "__builtin_offsetof(%s,data)/sizeof(void*)};",
               req->symbol_prefix, req->type_name);
        printf("static n00b_gc_struct_layout_t %s_obj_shape={"
               ".stride=(sizeof(%s)/sizeof(void*)),.count=1,"
               ".offset_count=1,.offsets=%s_obj_offsets};",
               req->symbol_prefix, req->type_name, req->symbol_prefix);
        printf("static %s%s %s_obj={"
               ".data=%s_data,.len=(size_t)%lluULL,.cap=(size_t)%lluULL,"
               ".lock=(n00b_rwlock_t*)%s_lock_storage,"
               ".allocator=nullptr,.scan_kind=%s,"
               ".scan_cb=%s,.scan_user=%s};",
               obj_const, req->type_name, req->symbol_prefix,
               req->symbol_prefix,
               (unsigned long long)req->container_len,
               (unsigned long long)req->container_cap,
               req->symbol_prefix, scan_kind, scan_cb, scan_user);
        printf("static const n00b_static_object_desc_t %s_obj_desc={"
               ".start=(const void*)&%s_obj,"
               ".len=(uint64_t)sizeof(%s_obj),"
               ".tinfo=%lluULL,.scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
               ".scan_cb=n00b_gc_scan_cb_struct_layout,"
               ".scan_user=&%s_obj_shape,"
               ".object_id=%lluULL,.file=__FILE__,.identity=",
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
               (unsigned long long)req->type_hash, req->symbol_prefix,
               (unsigned long long)obj_id);
        printf("%s", has_identity(req) ? "&" : "nullptr");
        if (has_identity(req)) {
            printf("%s_obj_id", req->symbol_prefix);
        }
        printf(",.flags=%s};", flags);
        printf("static const n00b_static_object_desc_t * const "
               "%s_obj_entry %s=&%s_obj_desc;",
               req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
               req->symbol_prefix);
    }

    printf("static const n00b_static_image_request_t %s_request={"
           ".version=%u,"
           ".type_hash=%lluULL,.type_name=",
           req->symbol_prefix, contract_version,
           (unsigned long long)req->type_hash);
    emit_c_string_literal(req->type_name);
    printf(",.symbol_prefix=");
    emit_c_string_literal(req->symbol_prefix);
    printf(",.entry_attr=");
    emit_c_string_literal(req->entry_attr ? req->entry_attr : "");
    printf(",.payload_kind=N00B_STATIC_IMAGE_PAYLOAD_NONE,"
           ".payload=nullptr,.payload_len=0,.args=nullptr,.arg_count=0,"
           ".target_abi={.version=%u,"
           ".pointer_bytes=(uint8_t)sizeof(void*),"
           ".size_t_bytes=(uint8_t)sizeof(size_t),.char_bits=8,"
           ".endian=%u},"
           ".object_flags=%s,.required_scan_kind=N00B_GC_SCAN_KIND_CALLBACK,",
           contract_version, target_endian, flags);
    emit_request_identity_fields(req);
    printf("};");
    printf("static const n00b_static_image_dependency_t %s_deps[]={"
           "{.desc=&%s_data_desc,.relocation_offset=0,.role=\"data\"},",
           req->symbol_prefix, req->symbol_prefix);
    if (pointer_target) {
        printf("{.desc=&%s_lock_desc,.relocation_offset=__builtin_offsetof(%s,lock),"
               ".role=\"lock\"}};",
               req->symbol_prefix, req->type_name);
    }
    else {
        printf("{.desc=&%s_lock_desc,.relocation_offset=0,.role=\"lock\"}};",
               req->symbol_prefix);
    }
    if (pointer_target) {
        printf("static const n00b_static_image_response_t %s_response "
               "__attribute__((used))={"
               ".version=%u,"
               ".request=&%s_request,"
               ".object_start=(const void*)&%s_obj,"
               ".object_len=(uint64_t)sizeof(%s_obj),"
               ".scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
               ".scan_cb=n00b_gc_scan_cb_struct_layout,"
               ".scan_user=&%s_obj_shape,.dependencies=%s_deps,"
               ".dependency_count=2};",
               req->symbol_prefix, contract_version,
               req->symbol_prefix, req->symbol_prefix,
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix);
    }
    else {
        printf("static const n00b_static_image_response_t %s_response "
               "__attribute__((used))={"
               ".version=%u,"
               ".request=&%s_request,"
               ".object_start=nullptr,.object_len=0,"
               ".scan_kind=N00B_GC_SCAN_KIND_NONE,.scan_cb=nullptr,"
               ".scan_user=nullptr,.dependencies=%s_deps,"
               ".dependency_count=2};",
               req->symbol_prefix, contract_version,
               req->symbol_prefix, req->symbol_prefix);
    }

    return 0;
}

static void
emit_array_identity_decl(const helper_request_t *req)
{
    if (!has_identity(req)) {
        return;
    }

    printf("static const n00b_static_identity_t %s_data_id={"
           ".version=1u,"
           ".kind=N00B_STATIC_IDENTITY_NCC_ARRAY_DATA,"
           ".namespace_id=",
           req->symbol_prefix);
    emit_c_string_literal(req->identity_namespace);
    printf(",.object_key=");
    emit_c_string_literal(req->identity_payload_key);
    printf("};");
}

static int
emit_array_image(const helper_request_t *req)
{
    if (!req->element_type_name || !req->data_type_hash
        || req->container_cap != req->container_len
        || req->cinit_count != req->container_len) {
        fprintf(stderr, "bad n00b array static initializer request");
        return 6;
    }

    const char *flags = req->readonly ? "N00B_STATIC_OBJECT_F_READONLY"
                                      : "N00B_STATIC_OBJECT_F_MUTABLE";
    const char *scan_kind = or_default(req->element_scan_kind,
                                       "N00B_GC_SCAN_KIND_NONE");
    const char *scan_cb = or_default(req->element_scan_cb, "nullptr");
    const char *scan_user = or_default(req->element_scan_user, "nullptr");
    uint64_t data_id = helper_hash_cstr(req->symbol_prefix)
                     ^ UINT64_C(0x6172726179646174);
    unsigned contract_version = (unsigned)req->abi.version;
    unsigned target_endian    = (unsigned)req->abi.endian;

    printf("NCC_STATIC_INIT_OK %s_data\n", req->symbol_prefix);
    emit_array_identity_decl(req);
    printf("%s", req->element_shape_decl ? req->element_shape_decl : "");
    printf("static %s %s_data[%llu]={",
           req->element_type_name, req->symbol_prefix,
           (unsigned long long)(req->container_len ? req->container_len : 1));
    emit_cinit_items(req);
    printf("};");
    printf("static const n00b_static_object_desc_t %s_data_desc={"
           ".start=(const void*)%s_data,"
           ".len=(uint64_t)sizeof(%s_data),"
           ".tinfo=%lluULL,.scan_kind=%s,.scan_cb=%s,.scan_user=%s,"
           ".object_id=%lluULL,.file=__FILE__,.identity=",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           (unsigned long long)req->data_type_hash,
           scan_kind, scan_cb, scan_user, (unsigned long long)data_id);
    printf("%s", has_identity(req) ? "&" : "nullptr");
    if (has_identity(req)) {
        printf("%s_data_id", req->symbol_prefix);
    }
    printf(",.flags=%s};", flags);
    printf("static const n00b_static_object_desc_t * const "
           "%s_data_entry %s=&%s_data_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    printf("static const n00b_static_image_request_t %s_request={"
           ".version=%u,"
           ".type_hash=%lluULL,.type_name=",
           req->symbol_prefix, contract_version,
           (unsigned long long)req->type_hash);
    emit_c_string_literal(req->type_name);
    printf(",.symbol_prefix=");
    emit_c_string_literal(req->symbol_prefix);
    printf(",.entry_attr=");
    emit_c_string_literal(req->entry_attr ? req->entry_attr : "");
    printf(",.payload_kind=N00B_STATIC_IMAGE_PAYLOAD_NONE,"
           ".payload=nullptr,.payload_len=0,.args=nullptr,.arg_count=0,"
           ".target_abi={.version=%u,"
           ".pointer_bytes=(uint8_t)sizeof(void*),"
           ".size_t_bytes=(uint8_t)sizeof(size_t),.char_bits=8,"
           ".endian=%u},"
           ".object_flags=%s,.required_scan_kind=N00B_GC_SCAN_KIND_NONE,",
           contract_version, target_endian, flags);
    emit_request_identity_fields(req);
    printf("};");
    printf("static const n00b_static_image_dependency_t %s_deps[]={"
           "{.desc=&%s_data_desc,.relocation_offset=0,.role=\"data\"}};",
           req->symbol_prefix, req->symbol_prefix);
    printf("static const n00b_static_image_response_t %s_response "
           "__attribute__((used))={"
           ".version=%u,.request=&%s_request,"
           ".object_start=nullptr,.object_len=0,"
           ".scan_kind=N00B_GC_SCAN_KIND_NONE,.scan_cb=nullptr,"
           ".scan_user=nullptr,.dependencies=%s_deps,"
           ".dependency_count=1};",
           req->symbol_prefix, contract_version, req->symbol_prefix,
           req->symbol_prefix);

    return 0;
}

static uint64_t
pow2_ceil_u64(uint64_t v)
{
    if (v <= 1) {
        return 1;
    }
    uint64_t r = 1;
    while (r < v) {
        r <<= 1;
    }
    return r;
}

// Emit a static dict image. Mirrors emit_list_image()'s shape but for
// the typed dict layout (store header + buckets + keys + values arrays).
//
// Lock model: static dict images are LOCKABLE but NOT locked by default
// (per D-070, superseding D-068). The dict object's `lock` slot is a
// `n00b_rwlock_t *` mirroring the WP-010 list precedent; the helper
// emits `.lock = nullptr` (or omits it via C zero-fill) so the static
// dict starts in the unlocked state. Heap dict constructors opt into a
// lock via `n00b_dict_new` (locked) or `n00b_dict_new_private`
// (unlocked).
//
// The dict also carries `_migration_state` (renamed from the legacy
// `futex` field), the migration coordination word for the lock-free
// table-resize protocol. This is NOT a user-facing mutex; it gates
// writers during a store migration, not ordinary reads/writes. The
// helper emits `._migration_state = 0`, which is the protocol's
// "initialized, no migration in progress" state.
static int
emit_dict_image(const helper_request_t *req)
{
    if (!req->key_type_name || !req->value_type_name || !req->data_type_hash
        || req->dict_pair_count != req->container_len) {
        fprintf(stderr,
                "bad n00b dict static initializer request: missing key/value "
                "metadata or pair count mismatch");
        return 6;
    }

    uint64_t entry_count = req->container_len;
    // Defense-in-depth (WP-018 / WP-016 A1): bound entry_count well below
    // 2^63 so that pow2_ceil_u64 cannot run away (it shifts left and would
    // loop forever once the running result drops to zero) and so the
    // subsequent malloc(cap * sizeof(*slot_to_pair)) cannot wrap (see A2).
    // 2^30 entries (~1 billion keys) is far beyond any plausible build-time
    // static dict; a hostile or malformed request that exceeds it is
    // rejected with a clear diagnostic instead of hanging the build.
    if (entry_count > ((uint64_t)1 << 30)) {
        fprintf(stderr,
                "bad n00b dict static initializer request: container_len "
                "(%llu) exceeds maximum supported static-dict capacity "
                "(2^30 entries)",
                (unsigned long long)entry_count);
        return 6;
    }
    uint64_t cap = pow2_ceil_u64(entry_count);
    if (cap < (uint64_t)N00B_DICT_MIN_SIZE) {
        cap = (uint64_t)N00B_DICT_MIN_SIZE;
    }
    // The caller-supplied container_cap is informational; if present, it
    // must agree with the computed capacity to avoid silent drift.
    if (req->container_cap != 0 && req->container_cap != cap) {
        fprintf(stderr,
                "bad n00b dict static initializer request: container_cap "
                "(%llu) does not match dict capacity formula "
                "max(pow2(len),%d)=%llu",
                (unsigned long long)req->container_cap,
                N00B_DICT_MIN_SIZE,
                (unsigned long long)cap);
        return 6;
    }
    uint64_t mask = cap - 1;
    uint32_t threshold = (uint32_t)(cap - (cap >> 2) - 1);

    bool pointer_target = req->container_target
                       && strcmp(req->container_target, "pointer") == 0;
    const char *flags = req->readonly ? "N00B_STATIC_OBJECT_F_READONLY"
                                      : "N00B_STATIC_OBJECT_F_MUTABLE";
    const char *obj_const = req->readonly ? "const " : "";

    const char *key_scan_kind = or_default(req->key_scan_kind,
                                           "N00B_GC_SCAN_KIND_NONE");
    const char *key_scan_cb = or_default(req->key_scan_cb, "nullptr");
    const char *key_scan_user = or_default(req->key_scan_user, "nullptr");
    const char *value_scan_kind = or_default(req->value_scan_kind,
                                             "N00B_GC_SCAN_KIND_NONE");
    const char *value_scan_cb = or_default(req->value_scan_cb, "nullptr");
    const char *value_scan_user = or_default(req->value_scan_user, "nullptr");

    // The dict-level scan_kind reflects the user's logical scan policy
    // (matching the runtime dict's stored scan_kind / scan_cb / scan_user
    // which is replicated into bucket/key/value backing arrays). For the
    // static image the dict object itself uses CALLBACK with a struct
    // layout that finds the `store` pointer; the keys/values arrays each
    // get their own scan policy.
    const char *dict_logical_scan_kind = key_scan_kind;
    if (strcmp(dict_logical_scan_kind, "N00B_GC_SCAN_KIND_NONE") == 0) {
        dict_logical_scan_kind = value_scan_kind;
    }
    const char *dict_logical_scan_cb   = key_scan_cb;
    const char *dict_logical_scan_user = key_scan_user;

    uint64_t store_id = helper_hash_cstr(req->symbol_prefix)
                      ^ UINT64_C(0x646963747374);  // 'dictst'
    uint64_t buckets_id = helper_hash_cstr(req->symbol_prefix)
                        ^ UINT64_C(0x646963746263);  // 'dictbc'
    uint64_t keys_id = helper_hash_cstr(req->symbol_prefix)
                     ^ UINT64_C(0x6469636b65);  // 'dicke'
    uint64_t vals_id = helper_hash_cstr(req->symbol_prefix)
                     ^ UINT64_C(0x646963766c);  // 'dicvl'
    uint64_t obj_id = helper_hash_cstr(req->symbol_prefix)
                    ^ UINT64_C(0x646963746f626a);  // 'dictobj'
    unsigned contract_version = (unsigned)req->abi.version;
    unsigned target_endian    = (unsigned)req->abi.endian;

    // Slot-assign each pair by linear probing from `hash & mask`. Detect
    // duplicate keys (same precomputed hash landing on the same probe
    // path with the same bucket already taken).
    //
    // Defense-in-depth (WP-018 / WP-016 A2): the upstream entry_count cap
    // (2^30) bounds `cap` at `pow2_ceil_u64(2^30) == 2^30`, so
    // `cap * sizeof(int64_t) <= 2^33` bytes - well within size_t on any
    // 32+ bit platform. Guard explicitly anyway in case the cap is ever
    // relaxed; an overflow here would silently allocate a too-small
    // buffer and turn into an OOB write.
    if (cap > (SIZE_MAX / sizeof(int64_t))) {
        fprintf(stderr,
                "bad n00b dict static initializer request: dict capacity "
                "(%llu) would overflow slot-table allocation size",
                (unsigned long long)cap);
        return 6;
    }
    int64_t *slot_to_pair = n00b_alloc_array(int64_t, (size_t)cap);
    if (!slot_to_pair) {
        fprintf(stderr, "out of memory while building dict static image");
        return 6;
    }
    for (uint64_t s = 0; s < cap; s++) {
        slot_to_pair[s] = -1;
    }

    for (uint64_t i = 0; i < entry_count; i++) {
        const dict_pair_t *pair = &req->dict_pairs[i];
        if (!pair->have_hash) {
            fprintf(stderr,
                    "bad n00b dict static initializer request: pair %llu "
                    "is missing the precomputed key hash",
                    (unsigned long long)i);
            n00b_free(slot_to_pair);
            return 6;
        }

        uint64_t start = pair->hash_lo & mask;
        bool     placed = false;
        for (uint64_t probe = 0; probe < cap; probe++) {
            uint64_t s = (start + probe) & mask;
            int64_t  occupant = slot_to_pair[s];
            if (occupant == -1) {
                slot_to_pair[s] = (int64_t)i;
                placed = true;
                break;
            }
            const dict_pair_t *other = &req->dict_pairs[occupant];
            if (other->hash_lo == pair->hash_lo
                && other->hash_hi == pair->hash_hi) {
                fprintf(stderr,
                        "bad n00b dict static initializer request: duplicate "
                        "key hash at pair indices %lld and %llu (likely a "
                        "duplicate key in the dict literal)",
                        (long long)occupant, (unsigned long long)i);
                n00b_free(slot_to_pair);
                return 6;
            }
        }
        if (!placed) {
            fprintf(stderr,
                    "bad n00b dict static initializer request: probe span "
                    "exhausted placing pair %llu (capacity %llu, count %llu)",
                    (unsigned long long)i, (unsigned long long)cap,
                    (unsigned long long)entry_count);
            n00b_free(slot_to_pair);
            return 6;
        }
    }

    printf("NCC_STATIC_INIT_OK ");
    if (pointer_target) {
        printf("&%s_obj\n", req->symbol_prefix);
    }
    else {
        // Value-target initializer: a designated initializer for the
        // user's typed dict struct. Field set matches N00B_BASE_DICT_FIELDS.
        printf("{.store=(void *)&%s_store,"
               ".fn=nullptr,.allocator=nullptr,"
               ".insertion_epoch=0,.wait_ct=0,.length=(n00b_isize_t)%lluULL,"
               "._migration_state=0,.lock=nullptr,.cache=0,.skip_obj_hash=%u,"
               ".scan_kind=%s,.scan_cb=%s,.scan_user=%s}\n",
               req->symbol_prefix,
               (unsigned long long)entry_count,
               req->skip_obj_hash ? 1u : 0u,
               dict_logical_scan_kind, dict_logical_scan_cb,
               dict_logical_scan_user);
    }

    emit_identity_decls(req, pointer_target);
    printf("%s", req->key_shape_decl ? req->key_shape_decl : "");
    printf("%s", req->value_shape_decl ? req->value_shape_decl : "");

    // Buckets array. Empty slots are zero-initialized (hv = 0).
    printf("static n00b_dict_bucket_t %s_buckets[%llu]={",
           req->symbol_prefix, (unsigned long long)cap);
    bool first_bucket = true;
    for (uint64_t s = 0; s < cap; s++) {
        if (!first_bucket) {
            putchar(',');
        }
        first_bucket = false;
        int64_t pair_idx = slot_to_pair[s];
        if (pair_idx < 0) {
            // Empty slot.
            printf("{}");
        }
        else {
            const dict_pair_t *pair = &req->dict_pairs[pair_idx];
            uint32_t insert_order = (uint32_t)(pair_idx + 1);
            printf("{.hv=((n00b_uint128_t)0x%016llxULL<<64)"
                   "|(n00b_uint128_t)0x%016llxULL,"
                   ".insert_order=(uint32_t)%uu,.flags=0}",
                   (unsigned long long)pair->hash_hi,
                   (unsigned long long)pair->hash_lo,
                   (unsigned)insert_order);
        }
    }
    printf("};");

    // Keys array. Initialized at each occupied slot with the user-supplied
    // key expression; empty slots use {} (zero-init for the key type).
    printf("static %s %s_keys[%llu]={",
           req->key_type_name, req->symbol_prefix,
           (unsigned long long)cap);
    bool first_key = true;
    for (uint64_t s = 0; s < cap; s++) {
        if (!first_key) {
            putchar(',');
        }
        first_key = false;
        int64_t pair_idx = slot_to_pair[s];
        if (pair_idx < 0) {
            printf("{}");
        }
        else {
            fputs(req->dict_pairs[pair_idx].key_expr, stdout);
        }
    }
    printf("};");

    // Values array, same shape.
    printf("static %s %s_values[%llu]={",
           req->value_type_name, req->symbol_prefix,
           (unsigned long long)cap);
    bool first_val = true;
    for (uint64_t s = 0; s < cap; s++) {
        if (!first_val) {
            putchar(',');
        }
        first_val = false;
        int64_t pair_idx = slot_to_pair[s];
        if (pair_idx < 0) {
            printf("{}");
        }
        else {
            fputs(req->dict_pairs[pair_idx].value_expr, stdout);
        }
    }
    printf("};");

    // Buckets descriptor (POD; scan_kind NONE; mutable so subsequent
    // runtime puts can use it).
    printf("static const n00b_static_object_desc_t %s_buckets_desc={"
           ".start=(const void*)%s_buckets,"
           ".len=(uint64_t)sizeof(%s_buckets),"
           ".tinfo=0,.scan_kind=N00B_GC_SCAN_KIND_NONE,"
           ".scan_cb=nullptr,.scan_user=nullptr,"
           ".object_id=%lluULL,.file=__FILE__,.identity=nullptr,"
           ".flags=N00B_STATIC_OBJECT_F_MUTABLE};",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           (unsigned long long)buckets_id);
    printf("static const n00b_static_object_desc_t * const "
           "%s_buckets_entry %s=&%s_buckets_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    // Keys descriptor.
    printf("static const n00b_static_object_desc_t %s_keys_desc={"
           ".start=(const void*)%s_keys,"
           ".len=(uint64_t)sizeof(%s_keys),"
           ".tinfo=0,.scan_kind=%s,.scan_cb=%s,.scan_user=%s,"
           ".object_id=%lluULL,.file=__FILE__,.identity=nullptr,"
           ".flags=N00B_STATIC_OBJECT_F_MUTABLE};",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           key_scan_kind, key_scan_cb, key_scan_user,
           (unsigned long long)keys_id);
    printf("static const n00b_static_object_desc_t * const "
           "%s_keys_entry %s=&%s_keys_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    // Values descriptor.
    printf("static const n00b_static_object_desc_t %s_values_desc={"
           ".start=(const void*)%s_values,"
           ".len=(uint64_t)sizeof(%s_values),"
           ".tinfo=0,.scan_kind=%s,.scan_cb=%s,.scan_user=%s,"
           ".object_id=%lluULL,.file=__FILE__,.identity=nullptr,"
           ".flags=N00B_STATIC_OBJECT_F_MUTABLE};",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           value_scan_kind, value_scan_cb, value_scan_user,
           (unsigned long long)vals_id);
    printf("static const n00b_static_object_desc_t * const "
           "%s_values_entry %s=&%s_values_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    // Dict store header. We emit it via the type-erased layout because
    // every typed `n00b_dict_store_t(K, V)` parameterization shares the
    // same field offsets (last_slot, threshold, used_count, buckets,
    // keys, values are all word/pointer sized).
    printf("static __n00b_internal_type_erased_store_t %s_store={"
           ".last_slot=(uint32_t)%uu,.threshold=(uint32_t)%uu,"
           ".used_count=%uu,"
           ".buckets=%s_buckets,"
           ".keys=(void**)%s_keys,"
           ".values=(void**)%s_values};",
           req->symbol_prefix,
           (unsigned)(cap - 1u), (unsigned)threshold,
           (unsigned)entry_count,
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix);

    // Store descriptor. The store itself contains three pointer fields
    // (buckets, keys, values); use CALLBACK + struct_layout to point GC
    // at them, mirroring how the heap dict's store backing alloc is
    // tracked.
    printf("static const uint64_t %s_store_offsets[]={"
           "__builtin_offsetof(__n00b_internal_type_erased_store_t,buckets)"
           "/sizeof(void*),"
           "__builtin_offsetof(__n00b_internal_type_erased_store_t,keys)"
           "/sizeof(void*),"
           "__builtin_offsetof(__n00b_internal_type_erased_store_t,values)"
           "/sizeof(void*)};",
           req->symbol_prefix);
    printf("static n00b_gc_struct_layout_t %s_store_shape={"
           ".stride=(sizeof(__n00b_internal_type_erased_store_t)/sizeof(void*)),"
           ".count=1,.offset_count=3,.offsets=%s_store_offsets};",
           req->symbol_prefix, req->symbol_prefix);
    printf("static const n00b_static_object_desc_t %s_store_desc={"
           ".start=(const void*)&%s_store,"
           ".len=(uint64_t)sizeof(%s_store),"
           ".tinfo=%lluULL,.scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
           ".scan_cb=n00b_gc_scan_cb_struct_layout,"
           ".scan_user=&%s_store_shape,"
           ".object_id=%lluULL,.file=__FILE__,.identity=",
           req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
           (unsigned long long)req->data_type_hash, req->symbol_prefix,
           (unsigned long long)store_id);
    printf("%s", has_identity(req) ? "&" : "nullptr");
    if (has_identity(req)) {
        printf("%s_payload_id", req->symbol_prefix);
    }
    printf(",.flags=N00B_STATIC_OBJECT_F_MUTABLE};");
    printf("static const n00b_static_object_desc_t * const "
           "%s_store_entry %s=&%s_store_desc;",
           req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
           req->symbol_prefix);

    if (pointer_target) {
        // Pointer-target dict literal: emit a top-level static dict
        // object whose address the user-supplied pointer is initialized
        // to. The dict object's only GC-relevant pointer is its `store`
        // field (offset 0).
        printf("_Static_assert((__builtin_offsetof(%s,store)%%sizeof(void*))==0,"
               "\"dict store pointer must be pointer-aligned\");",
               req->type_name);
        printf("static const uint64_t %s_obj_offsets[]={"
               "__builtin_offsetof(%s,store)/sizeof(void*)};",
               req->symbol_prefix, req->type_name);
        printf("static n00b_gc_struct_layout_t %s_obj_shape={"
               ".stride=(sizeof(%s)/sizeof(void*)),.count=1,"
               ".offset_count=1,.offsets=%s_obj_offsets};",
               req->symbol_prefix, req->type_name, req->symbol_prefix);
        printf("static %s%s %s_obj={"
               ".store=(void *)&%s_store,"
               ".fn=nullptr,.allocator=nullptr,"
               ".insertion_epoch=0,.wait_ct=0,.length=(n00b_isize_t)%lluULL,"
               "._migration_state=0,.lock=nullptr,.cache=0,.skip_obj_hash=%u,"
               ".scan_kind=%s,.scan_cb=%s,.scan_user=%s};",
               obj_const, req->type_name, req->symbol_prefix,
               req->symbol_prefix,
               (unsigned long long)entry_count,
               req->skip_obj_hash ? 1u : 0u,
               dict_logical_scan_kind, dict_logical_scan_cb,
               dict_logical_scan_user);
        printf("static const n00b_static_object_desc_t %s_obj_desc={"
               ".start=(const void*)&%s_obj,"
               ".len=(uint64_t)sizeof(%s_obj),"
               ".tinfo=%lluULL,.scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
               ".scan_cb=n00b_gc_scan_cb_struct_layout,"
               ".scan_user=&%s_obj_shape,"
               ".object_id=%lluULL,.file=__FILE__,.identity=",
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
               (unsigned long long)req->type_hash, req->symbol_prefix,
               (unsigned long long)obj_id);
        printf("%s", has_identity(req) ? "&" : "nullptr");
        if (has_identity(req)) {
            printf("%s_obj_id", req->symbol_prefix);
        }
        printf(",.flags=%s};", flags);
        printf("static const n00b_static_object_desc_t * const "
               "%s_obj_entry %s=&%s_obj_desc;",
               req->symbol_prefix, req->entry_attr ? req->entry_attr : "",
               req->symbol_prefix);
    }

    // Static image request/dependencies/response for marshal/dependency
    // tracking. The dependency list covers the store, buckets, keys,
    // values (and, for pointer-target, the dict object itself).
    printf("static const n00b_static_image_request_t %s_request={"
           ".version=%u,"
           ".type_hash=%lluULL,.type_name=",
           req->symbol_prefix, contract_version,
           (unsigned long long)req->type_hash);
    emit_c_string_literal(req->type_name);
    printf(",.symbol_prefix=");
    emit_c_string_literal(req->symbol_prefix);
    printf(",.entry_attr=");
    emit_c_string_literal(req->entry_attr ? req->entry_attr : "");
    printf(",.payload_kind=N00B_STATIC_IMAGE_PAYLOAD_NONE,"
           ".payload=nullptr,.payload_len=0,.args=nullptr,.arg_count=0,"
           ".target_abi={.version=%u,"
           ".pointer_bytes=(uint8_t)sizeof(void*),"
           ".size_t_bytes=(uint8_t)sizeof(size_t),.char_bits=8,"
           ".endian=%u},"
           ".object_flags=%s,.required_scan_kind=N00B_GC_SCAN_KIND_CALLBACK,",
           contract_version, target_endian, flags);
    emit_request_identity_fields(req);
    printf("};");

    if (pointer_target) {
        printf("static const n00b_static_image_dependency_t %s_deps[]={"
               "{.desc=&%s_store_desc,.relocation_offset=__builtin_offsetof(%s,store),"
               ".role=\"store\"},"
               "{.desc=&%s_buckets_desc,.relocation_offset=0,.role=\"buckets\"},"
               "{.desc=&%s_keys_desc,.relocation_offset=0,.role=\"keys\"},"
               "{.desc=&%s_values_desc,.relocation_offset=0,.role=\"values\"}};",
               req->symbol_prefix, req->symbol_prefix, req->type_name,
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix);
        printf("static const n00b_static_image_response_t %s_response "
               "__attribute__((used))={"
               ".version=%u,"
               ".request=&%s_request,"
               ".object_start=(const void*)&%s_obj,"
               ".object_len=(uint64_t)sizeof(%s_obj),"
               ".scan_kind=N00B_GC_SCAN_KIND_CALLBACK,"
               ".scan_cb=n00b_gc_scan_cb_struct_layout,"
               ".scan_user=&%s_obj_shape,.dependencies=%s_deps,"
               ".dependency_count=4};",
               req->symbol_prefix, contract_version,
               req->symbol_prefix, req->symbol_prefix,
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix);
    }
    else {
        printf("static const n00b_static_image_dependency_t %s_deps[]={"
               "{.desc=&%s_store_desc,.relocation_offset=0,.role=\"store\"},"
               "{.desc=&%s_buckets_desc,.relocation_offset=0,.role=\"buckets\"},"
               "{.desc=&%s_keys_desc,.relocation_offset=0,.role=\"keys\"},"
               "{.desc=&%s_values_desc,.relocation_offset=0,.role=\"values\"}};",
               req->symbol_prefix, req->symbol_prefix, req->symbol_prefix,
               req->symbol_prefix, req->symbol_prefix);
        printf("static const n00b_static_image_response_t %s_response "
               "__attribute__((used))={"
               ".version=%u,"
               ".request=&%s_request,"
               ".object_start=nullptr,.object_len=0,"
               ".scan_kind=N00B_GC_SCAN_KIND_NONE,.scan_cb=nullptr,"
               ".scan_user=nullptr,.dependencies=%s_deps,"
               ".dependency_count=4};",
               req->symbol_prefix, contract_version,
               req->symbol_prefix, req->symbol_prefix);
    }

    n00b_free(slot_to_pair);
    return 0;
}

// WP-018: emit a baked static-image for `container_kind grammar`.
//
// Reads the .bnf at req->bnf_path, parses it with the BNF metagrammar
// (the cost this whole feature exists to move to build time), finalizes,
// and emits marshal-backed C source via n00b_grammar_image_emit(). The
// response is the standard NCC_STATIC_INIT_OK shape; the grammar
// registers itself via a [[gnu::constructor]] in the emitted source, so
// the object-expression is the lookup name (a comment expression — the
// grammar literal form has no in-place value, unlike a dict literal).
static int
emit_grammar_image(const helper_request_t *req)
{
    char  *bnf_src = NULL;
    long   bnf_len = 0;
    FILE  *f       = fopen(req->bnf_path, "rb");

    if (!f) {
        fprintf(stderr, "cannot read bnf_path '%s'", req->bnf_path);
        return 4;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (bnf_len = ftell(f)) < 0) {
        fclose(f);
        fprintf(stderr, "cannot size bnf_path '%s'", req->bnf_path);
        return 4;
    }
    rewind(f);
    bnf_src = n00b_alloc_array(char, (size_t)bnf_len + 1);
    if (!bnf_src) {
        fclose(f);
        fprintf(stderr, "out of memory reading '%s'", req->bnf_path);
        return 4;
    }
    size_t got = fread(bnf_src, 1, (size_t)bnf_len, f);
    fclose(f);
    bnf_src[got] = '\0';

    // The baked grammar is PWZ-only and captured structurally without the
    // first-set / left-corner / LR0 analysis (WP-018 DF-EB / DF-EC).
    // finalize no longer computes that analysis (it is Earley-only and now
    // lazy in n00b_earley_new), so load + finalize are already cheap with
    // no flag, matching the bake tool and the generated grammar materializer.
    n00b_string_t  *bnf_text = n00b_string_from_raw(bnf_src, (int64_t)got);
    n00b_string_t  *start_s  = n00b_string_from_cstr(req->start_nt);
    n00b_grammar_t *g        = n00b_grammar_new();

    if (!n00b_bnf_load(bnf_text, start_s, g)) {
        n00b_free(bnf_src);
        fprintf(stderr, "failed to parse grammar '%s'", req->bnf_path);
        return 4;
    }

    n00b_grammar_finalize(g);

    // The grammar lookup name defaults to the start NT (matches the
    // bake tool's default); the symbol prefix is request-supplied.
    n00b_result_t(n00b_string_t *) emit_r = n00b_grammar_image_emit(
        g,
        n00b_string_from_cstr(req->symbol_prefix),
        start_s);

    n00b_free(bnf_src);

    if (n00b_result_is_err(emit_r)) {
        n00b_string_t *why = n00b_grammar_image_emit_err_str(
            n00b_result_get_err(emit_r));
        fprintf(stderr, "grammar image emit failed for '%s': %s",
                req->bnf_path, why->data);
        return 5;
    }

    n00b_string_t *emitted = n00b_result_get(emit_r);

    printf("NCC_STATIC_INIT_OK n00b_static_grammar_lookup(\"%s\")\n%s",
           req->start_nt, emitted->data);
    return 0;
}

int
main(int argc, char **argv)
{
    // n00b_init_simple FIRST so the parse path below can allocate via the n00b
    // allocator (default heap) instead of libc malloc (which "bootstrap" no
    // longer excuses).  init doesn't touch stdin, so reordering is safe.
    n00b_init_simple(argc, argv);

    char *input     = read_stdin();
    char *raw_input = input ? dup_cstr(input) : NULL;
    helper_request_t parsed = {0};

    if (!input || !raw_input || !parse_request(input, &parsed)) {
        fprintf(stderr, "bad n00b static initializer helper request");
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        n00b_shutdown();
        return 2;
    }

    if (parsed.container_kind && strcmp(parsed.container_kind, "array") == 0) {
        int status = emit_array_image(&parsed);
        n00b_shutdown();
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        return status;
    }

    if (parsed.container_kind && strcmp(parsed.container_kind, "list") == 0) {
        int status = emit_list_image(&parsed);
        n00b_shutdown();
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        return status;
    }

    if (parsed.container_kind && strcmp(parsed.container_kind, "dict") == 0) {
        int status = emit_dict_image(&parsed);
        n00b_shutdown();
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        return status;
    }

    if (parsed.container_kind
        && strcmp(parsed.container_kind, "grammar") == 0) {
#ifdef N00B_STATIC_GRAMMAR_HELPER
        int status = emit_grammar_image(&parsed);
#else
        int status = delegate_grammar_request(argv[0], raw_input);
#endif
        n00b_shutdown();
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        return status;
    }

    n00b_gc_scan_kind_t scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
    n00b_static_layout_opt_t layout_opt =
        n00b_type_static_layout(parsed.type_hash);
    if (n00b_option_is_set(layout_opt)) {
        scan_kind = n00b_option_get(layout_opt)->scan_kind;
    }

    n00b_static_image_request_t request = {
        .version            = N00B_STATIC_IMAGE_CONTRACT_VERSION,
        .type_hash          = parsed.type_hash,
        .type_name          = parsed.type_name,
        .symbol_prefix      = parsed.symbol_prefix,
        .entry_attr         = parsed.entry_attr,
        .payload_kind       = N00B_STATIC_IMAGE_PAYLOAD_NONE,
        .payload            = NULL,
        .payload_len        = 0,
        .args               = parsed.args,
        .arg_count          = parsed.arg_count,
        .target_abi         = parsed.abi,
        .object_flags       = parsed.readonly ? N00B_STATIC_OBJECT_F_READONLY
                                               : N00B_STATIC_OBJECT_F_MUTABLE,
        .required_scan_kind = scan_kind,
        .identity_namespace = parsed.identity_namespace,
        .identity_object_key = parsed.identity_object_key,
        .identity_payload_key = parsed.identity_payload_key,
    };

    n00b_static_image_builder_t builder;
    n00b_static_image_status_t status =
        n00b_static_image_build(&request, &builder);
    if (status != N00B_STATIC_IMAGE_OK) {
        fprintf(stderr, "%s", builder.error
                                ? builder.error->data
                                : n00b_static_image_status_name(status)->data);
        n00b_static_image_builder_destroy(&builder);
        n00b_shutdown();
        n00b_free(raw_input);
        n00b_free(input);
        free_request(&parsed);
        return 3;
    }

    printf("NCC_STATIC_INIT_OK %s\n%s",
           builder.expr ? builder.expr->data : "",
           builder.decls ? builder.decls->data : "");

    n00b_static_image_builder_destroy(&builder);
    n00b_shutdown();
    n00b_free(raw_input);
    n00b_free(input);
    free_request(&parsed);
    return 0;
}
