#include "slay/commander.h"
#include "slay/bnf.h"
#include "slay/earley.h"

#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "parsers/token_stream.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// JSON parse tree walking helpers
// ============================================================================

// Collect all token text within a subtree into a buffer.
static void
json_collect_text(n00b_parse_tree_t *tree, char *buf, int *pos, int max)
{
    if (!tree || *pos >= max - 1) {
        return;
    }

    if (n00b_tree_is_leaf(tree)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(tree);

        if (tok && n00b_option_is_set(tok->value)) {
            n00b_string_t *v = n00b_option_get(tok->value);

            for (size_t i = 0; i < v->u8_bytes && *pos < max - 1; i++) {
                buf[(*pos)++] = v->data[i];
            }
        }

        return;
    }

    size_t nc = n00b_tree_num_children(tree);

    for (size_t i = 0; i < nc; i++) {
        json_collect_text(n00b_tree_child(tree, i), buf, pos, max);
    }
}

static char *
json_tree_text(n00b_parse_tree_t *tree)
{
    char buf[4096];
    int  pos = 0;

    json_collect_text(tree, buf, &pos, sizeof(buf));
    buf[pos] = '\0';

    char *out = n00b_alloc_array(char, pos + 1);
    memcpy(out, buf, pos + 1);

    return out;
}

// Extract string value (strip surrounding quotes).
static char *
json_extract_string(n00b_parse_tree_t *tree)
{
    char *raw = json_tree_text(tree);

    if (!raw) {
        return NULL;
    }

    size_t len = strlen(raw);

    if (len >= 2 && raw[0] == '"' && raw[len - 1] == '"') {
        memmove(raw, raw + 1, len - 2);
        raw[len - 2] = '\0';
    }

    return raw;
}

// Get the NT name from a non-leaf tree node.
static const char *
json_node_name(n00b_parse_tree_t *node)
{
    if (!node || n00b_tree_is_leaf(node)) {
        return NULL;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    if (!pn->name || !pn->name->data) {
        return NULL;
    }

    return pn->name->data;
}

// Find a named member in a JSON object parse tree.
static n00b_parse_tree_t *
json_find_member(n00b_parse_tree_t *object, const char *key)
{
    if (!object || n00b_tree_is_leaf(object)) {
        return NULL;
    }

    for (size_t i = 0; i < n00b_tree_num_children(object); i++) {
        n00b_parse_tree_t *child = n00b_tree_child(object, i);

        if (!child || n00b_tree_is_leaf(child)) {
            continue;
        }

        const char *cname = json_node_name(child);

        if (cname && strcmp(cname, "member") == 0) {
            char        *mkey  = NULL;
            n00b_parse_tree_t *mval = NULL;

            for (size_t j = 0; j < n00b_tree_num_children(child); j++) {
                n00b_parse_tree_t *mc = n00b_tree_child(child, j);

                if (!mc || n00b_tree_is_leaf(mc)) {
                    continue;
                }

                const char *mcname = json_node_name(mc);

                if (!mkey && mcname && strcmp(mcname, "string") == 0) {
                    mkey = json_extract_string(mc);
                }

                if (mkey && mcname && strcmp(mcname, "value") == 0) {
                    mval = mc;
                }
            }

            if (mkey && mval && strcmp(mkey, key) == 0) {
                n00b_free(mkey);
                return mval;
            }

            if (mkey) {
                n00b_free(mkey);
            }
        }

        if (cname && strcmp(cname, "members") == 0) {
            n00b_parse_tree_t *found = json_find_member(child, key);

            if (found) {
                return found;
            }
        }
    }

    return NULL;
}

// Get the first <object> child of a <value> node.
static n00b_parse_tree_t *
json_value_as_object(n00b_parse_tree_t *value)
{
    if (!value || n00b_tree_is_leaf(value)) {
        return NULL;
    }

    for (size_t i = 0; i < n00b_tree_num_children(value); i++) {
        n00b_parse_tree_t *c = n00b_tree_child(value, i);

        if (!c || n00b_tree_is_leaf(c)) {
            continue;
        }

        const char *cname = json_node_name(c);

        if (cname && strcmp(cname, "object") == 0) {
            return c;
        }
    }

    return NULL;
}

static char *
json_value_as_string(n00b_parse_tree_t *value)
{
    if (!value || n00b_tree_is_leaf(value)) {
        return NULL;
    }

    for (size_t i = 0; i < n00b_tree_num_children(value); i++) {
        n00b_parse_tree_t *c = n00b_tree_child(value, i);

        if (!c || n00b_tree_is_leaf(c)) {
            continue;
        }

        const char *cname = json_node_name(c);

        if (cname && strcmp(cname, "string") == 0) {
            return json_extract_string(c);
        }
    }

    return json_tree_text(value);
}

static int
json_value_as_int(n00b_parse_tree_t *value)
{
    char *s = json_tree_text(value);

    if (!s) {
        return 0;
    }

    int v = atoi(s);
    n00b_free(s);

    return v;
}

// ============================================================================
// Walk members of a JSON object, calling a callback for each.
// ============================================================================

typedef void (*json_member_cb_t)(const char *key, n00b_parse_tree_t *value,
                                  void *ctx);

static void
json_foreach_member(n00b_parse_tree_t *object, json_member_cb_t cb, void *ctx)
{
    if (!object || n00b_tree_is_leaf(object)) {
        return;
    }

    for (size_t i = 0; i < n00b_tree_num_children(object); i++) {
        n00b_parse_tree_t *child = n00b_tree_child(object, i);

        if (!child || n00b_tree_is_leaf(child)) {
            continue;
        }

        const char *cname = json_node_name(child);

        if (cname && strcmp(cname, "member") == 0) {
            char              *key   = NULL;
            n00b_parse_tree_t *value = NULL;

            for (size_t j = 0; j < n00b_tree_num_children(child); j++) {
                n00b_parse_tree_t *mc = n00b_tree_child(child, j);

                if (!mc || n00b_tree_is_leaf(mc)) {
                    continue;
                }

                const char *mcname = json_node_name(mc);

                if (!key && mcname && strcmp(mcname, "string") == 0) {
                    key = json_extract_string(mc);
                }

                if (key && mcname && strcmp(mcname, "value") == 0) {
                    value = mc;
                }
            }

            if (key && value) {
                cb(key, value, ctx);
            }

            if (key) {
                n00b_free(key);
            }
        }

        if (cname && strcmp(cname, "members") == 0) {
            json_foreach_member(child, cb, ctx);
        }
    }
}

// ============================================================================
// JSON spec -> commander builder
// ============================================================================

typedef struct {
    n00b_cmdr_t *c;
    const char  *cmd_name;
} json_option_ctx_t;

static n00b_cmdr_arg_type_t
json_parse_type_name(const char *type_str)
{
    if (!type_str) {
        return N00B_CMDR_TYPE_WORD;
    }

    if (strcmp(type_str, "bool") == 0) {
        return N00B_CMDR_TYPE_BOOL;
    }

    if (strcmp(type_str, "int") == 0 || strcmp(type_str, "integer") == 0) {
        return N00B_CMDR_TYPE_INT;
    }

    if (strcmp(type_str, "float") == 0 || strcmp(type_str, "number") == 0) {
        return N00B_CMDR_TYPE_FLOAT;
    }

    return N00B_CMDR_TYPE_WORD;
}

static n00b_string_t *
cstr_to_n00b(const char *s)
{
    if (!s || !*s) {
        return n00b_string_empty();
    }

    return n00b_string_from_cstr(s);
}

// Read a "true"/"false" literal from a JSON <value> node, returning
// fallback if the value is absent or unrecognized.
static bool
json_value_as_bool(n00b_parse_tree_t *value, bool fallback)
{
    if (!value) {
        return fallback;
    }

    char *text = json_tree_text(value);

    if (!text) {
        return fallback;
    }

    // Trim leading whitespace -- the <value> rule wraps the literal.
    char *p = text;

    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }

    bool result = fallback;

    if (strncmp(p, "true", 4) == 0) {
        result = true;
    }
    else if (strncmp(p, "false", 5) == 0) {
        result = false;
    }

    n00b_free(text);
    return result;
}

static void
json_process_option(const char *flag_name, n00b_parse_tree_t *value, void *ctx)
{
    json_option_ctx_t *oc  = (json_option_ctx_t *)ctx;
    n00b_parse_tree_t *obj = json_value_as_object(value);

    n00b_cmdr_arg_type_t type = N00B_CMDR_TYPE_BOOL;
    bool takes_value          = false;
    bool multi                = false;
    char *doc                 = NULL;
    char *short_name          = NULL;
    char *type_str            = NULL;

    if (obj) {
        n00b_parse_tree_t *type_val = json_find_member(obj, "type");

        if (type_val) {
            type_str    = json_value_as_string(type_val);
            type        = json_parse_type_name(type_str);
            takes_value = type != N00B_CMDR_TYPE_BOOL;
        }

        n00b_parse_tree_t *doc_val = json_find_member(obj, "doc");

        if (doc_val) {
            doc = json_value_as_string(doc_val);
        }

        n00b_parse_tree_t *short_val = json_find_member(obj, "short");

        if (short_val) {
            short_name = json_value_as_string(short_val);
        }

        n00b_parse_tree_t *multi_val = json_find_member(obj, "multi");

        if (multi_val) {
            multi = json_value_as_bool(multi_val, false);
        }
    }

    if (multi) {
        // A multi flag is always value-taking; type informs eventual
        // coercion but the substrate currently stores strings.
        n00b_cmdr_arg_type_t mt = (type == N00B_CMDR_TYPE_BOOL)
                                    ? N00B_CMDR_TYPE_WORD
                                    : type;
        n00b_cmdr_add_flag_multi(oc->c, cstr_to_n00b(oc->cmd_name),
                                  cstr_to_n00b(flag_name), mt,
                                  cstr_to_n00b(doc));
    }
    else {
        n00b_cmdr_add_flag(oc->c, cstr_to_n00b(oc->cmd_name),
                            cstr_to_n00b(flag_name), type, takes_value,
                            cstr_to_n00b(doc));
    }

    if (short_name) {
        n00b_cmdr_add_flag_alias(oc->c, cstr_to_n00b(oc->cmd_name),
                                  cstr_to_n00b(flag_name),
                                  cstr_to_n00b(short_name));
    }

    if (type_str) {
        n00b_free(type_str);
    }

    if (doc) {
        n00b_free(doc);
    }

    if (short_name) {
        n00b_free(short_name);
    }
}

static void
json_process_command(const char *cmd_name, n00b_parse_tree_t *value, void *ctx)
{
    n00b_cmdr_t       *c   = (n00b_cmdr_t *)ctx;
    n00b_parse_tree_t *obj = json_value_as_object(value);

    if (!obj) {
        return;
    }

    char *doc = NULL;
    n00b_parse_tree_t *doc_val = json_find_member(obj, "doc");

    if (doc_val) {
        doc = json_value_as_string(doc_val);
    }

    n00b_cmdr_add_command(c, cstr_to_n00b(cmd_name), cstr_to_n00b(doc));

    if (doc) {
        n00b_free(doc);
    }

    // Process options
    n00b_parse_tree_t *opts_val = json_find_member(obj, "options");
    n00b_parse_tree_t *opts_obj = opts_val ? json_value_as_object(opts_val)
                                            : NULL;

    if (opts_obj) {
        json_option_ctx_t oc = {.c = c, .cmd_name = cmd_name};
        json_foreach_member(opts_obj, json_process_option, &oc);
    }

    // Process args
    n00b_parse_tree_t *args_val = json_find_member(obj, "args");
    n00b_parse_tree_t *args_obj = args_val ? json_value_as_object(args_val)
                                            : NULL;

    if (args_obj) {
        char *arg_name = NULL;
        n00b_parse_tree_t *name_val = json_find_member(args_obj, "name");

        if (name_val) {
            arg_name = json_value_as_string(name_val);
        }

        n00b_cmdr_arg_type_t arg_type = N00B_CMDR_TYPE_WORD;
        n00b_parse_tree_t *type_val = json_find_member(args_obj, "type");

        if (type_val) {
            char *ts = json_value_as_string(type_val);
            arg_type = json_parse_type_name(ts);

            if (ts) {
                n00b_free(ts);
            }
        }

        int min_args = 0;
        int max_args = -1;

        n00b_parse_tree_t *min_val = json_find_member(args_obj, "min");

        if (min_val) {
            min_args = json_value_as_int(min_val);
        }

        n00b_parse_tree_t *max_val = json_find_member(args_obj, "max");

        if (max_val) {
            max_args = json_value_as_int(max_val);
        }

        n00b_cmdr_add_positional(c, cstr_to_n00b(cmd_name),
                                  cstr_to_n00b(arg_name ? arg_name : "arg"),
                                  arg_type, min_args, max_args);

        if (arg_name) {
            n00b_free(arg_name);
        }
    }
}

// ============================================================================
// Public: n00b_cmdr_from_json
// ============================================================================

// Embedded JSON BNF (avoids needing to locate a grammar file at runtime).
static const char json_bnf_text[] =
    "<value>   ::= <object> | <array> | <string> | <number> "
    "| \"true\" | \"false\" | \"null\"\n"
    "<object>  ::= \"{\" <ws> \"}\" | \"{\" <members> \"}\"\n"
    "<members> ::= <member> | <member> \",\" <members>\n"
    "<member>  ::= <ws> <string> <ws> \":\" <ws> <value> <ws>\n"
    "<array>   ::= \"[\" <ws> \"]\" | \"[\" <elements> \"]\"\n"
    "<elements>::= <ws> <value> <ws> | <ws> <value> <ws> \",\" <elements>\n"
    "<string>  ::= '\"' <chars> '\"'\n"
    "<chars>   ::= \"\" | __JSON_STR <chars> | \"\\\\\" __PRINTABLE <chars>\n"
    "<number>  ::= \"-\"? <int-part> (\".\" __DIGIT+)? <exp-part>?\n"
    "<int-part> ::= __NONZERO_DIGIT __DIGIT+ | __DIGIT\n"
    "<exp-part> ::= (\"e\" | \"E\") (\"+\" | \"-\")? __DIGIT+\n"
    "<ws>      ::= __WHITESPACE*\n";

n00b_cmdr_t *
n00b_cmdr_from_json(n00b_string_t *json)
{
    if (!json || json->u8_bytes == 0) {
        return NULL;
    }

    // Build JSON grammar from BNF.
    n00b_grammar_t *json_g = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_EARLEY_ONLY);

    if (!n00b_bnf_load(n00b_string_from_cstr(json_bnf_text), r"value",
                        json_g)) {
        n00b_grammar_free(json_g);
        return NULL;
    }

    n00b_grammar_finalize(json_g);

    // Create a codepoint-level token stream from the JSON string.
    n00b_token_stream_t *ts = n00b_token_stream_from_codepoints(json);

    // Parse.
    n00b_parse_result_t *pr = n00b_grammar_parse(json_g, ts);

    if (!n00b_parse_result_ok(pr)) {
        n00b_parse_result_free(pr);
        n00b_token_stream_free(ts);
        n00b_grammar_free(json_g);
        return NULL;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    if (!tree) {
        n00b_parse_result_free(pr);
        n00b_token_stream_free(ts);
        n00b_grammar_free(json_g);
        return NULL;
    }

    // Extract spec from JSON parse tree.
    n00b_cmdr_t *c = n00b_cmdr_new();

    // The tree root is <value>. Find the <object> inside it.
    n00b_parse_tree_t *root_obj = json_value_as_object(tree);

    if (!root_obj) {
        // Maybe tree IS the object
        const char *tname = json_node_name(tree);

        if (tname && strcmp(tname, "object") == 0) {
            root_obj = tree;
        }
    }

    if (!root_obj) {
        n00b_parse_result_free(pr);
        n00b_token_stream_free(ts);
        n00b_grammar_free(json_g);
        n00b_cmdr_free(c);
        return NULL;
    }

    // Extract "name"
    n00b_parse_tree_t *name_val = json_find_member(root_obj, "name");

    if (name_val) {
        char *name = json_value_as_string(name_val);

        if (name) {
            n00b_cmdr_set_name(c, n00b_string_from_cstr(name));
            n00b_free(name);
        }
    }

    // Process "commands"
    n00b_parse_tree_t *cmds_val = json_find_member(root_obj, "commands");
    n00b_parse_tree_t *cmds_obj = cmds_val ? json_value_as_object(cmds_val)
                                            : NULL;

    if (cmds_obj) {
        json_foreach_member(cmds_obj, json_process_command, c);
    }

    // Process top-level "options" (global flags)
    n00b_parse_tree_t *opts_val = json_find_member(root_obj, "options");
    n00b_parse_tree_t *opts_obj = opts_val ? json_value_as_object(opts_val)
                                            : NULL;

    if (opts_obj) {
        json_option_ctx_t oc = {.c = c, .cmd_name = NULL};
        json_foreach_member(opts_obj, json_process_option, &oc);
    }

    n00b_parse_result_free(pr);
    n00b_token_stream_free(ts);
    n00b_grammar_free(json_g);

    return c;
}
