#include "slay/commander.h"
#include "slay/bnf.h"
#include "slay/earley.h"

#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "core/hash.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Helpers
// ============================================================================

static n00b_option_t(size_t)
cmdr_find_command_index(n00b_cmdr_t *c, n00b_string_t *name)
{
    int32_t n_subs = n00b_list_len(c->root.subcommands);

    for (int32_t i = 0; i < n_subs; i++) {
        n00b_cmdr_command_t sub = n00b_list_get(c->root.subcommands, i);

        if (sub.has_name
            && sub.name->u8_bytes == name->u8_bytes
            && memcmp(sub.name->data, name->data, name->u8_bytes) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }
    }

    return n00b_option_none(size_t);
}

static n00b_option_t(size_t)
cmdr_find_command_index_cstr(n00b_cmdr_t *c, const char *name)
{
    int32_t n_subs = n00b_list_len(c->root.subcommands);

    for (int32_t i = 0; i < n_subs; i++) {
        n00b_cmdr_command_t sub = n00b_list_get(c->root.subcommands, i);

        if (sub.has_name && strcmp(sub.name->data, name) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }
    }

    return n00b_option_none(size_t);
}

// Get a pointer to the command — returns &c->root for empty name,
// or a pointer into the subcommands list for a named command.
// The returned pointer is stable as long as no elements are added to
// the subcommands list (which is true after finalize).
static n00b_cmdr_command_t *
cmdr_get_command(n00b_cmdr_t *c, n00b_string_t *name)
{
    if (!name || name->u8_bytes == 0) {
        return &c->root;
    }

    n00b_option_t(size_t) idx = cmdr_find_command_index(c, name);

    if (!n00b_option_is_set(idx)) {
        return NULL;
    }

    return &c->root.subcommands.data[n00b_option_get(idx)];
}

static n00b_option_t(size_t)
cmdr_find_flag_index(n00b_cmdr_command_t *cmd, n00b_string_t *flag_name)
{
    if (!cmd || !flag_name) {
        return n00b_option_none(size_t);
    }

    int32_t n_flags = n00b_list_len(cmd->flags);

    for (int32_t i = 0; i < n_flags; i++) {
        n00b_cmdr_flag_spec_t f = n00b_list_get(cmd->flags, i);

        if (f.name->u8_bytes == flag_name->u8_bytes
            && memcmp(f.name->data, flag_name->data, flag_name->u8_bytes) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }

        if (f.has_short
            && f.short_name->u8_bytes == flag_name->u8_bytes
            && memcmp(f.short_name->data, flag_name->data,
                      flag_name->u8_bytes) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }
    }

    return n00b_option_none(size_t);
}

// Find a flag by n00b_string_t name, returning its index.
static n00b_option_t(size_t)
cmdr_find_flag(n00b_cmdr_command_t *cmd, n00b_string_t *flag_name)
{
    return cmdr_find_flag_index(cmd, flag_name);
}

// Find a flag by C string name, returning its index.
static n00b_option_t(size_t)
cmdr_find_flag_cstr(n00b_cmdr_command_t *cmd, const char *flag_name)
{
    if (!cmd || !flag_name) {
        return n00b_option_none(size_t);
    }

    int32_t n_flags = n00b_list_len(cmd->flags);

    for (int32_t i = 0; i < n_flags; i++) {
        n00b_cmdr_flag_spec_t f = n00b_list_get(cmd->flags, i);

        if (strcmp(f.name->data, flag_name) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }

        if (f.has_short && strcmp(f.short_name->data, flag_name) == 0) {
            return n00b_option_set(size_t, (size_t)i);
        }
    }

    return n00b_option_none(size_t);
}

static void
cmdr_init_command(n00b_cmdr_command_t *cmd)
{
    cmd->flags                = n00b_list_new_private(n00b_cmdr_flag_spec_t);
    cmd->positionals          = n00b_list_new_private(n00b_cmdr_positional_spec_t);
    cmd->subcommands          = n00b_list_new_private(n00b_cmdr_command_t);
    cmd->nt                   = NULL;
    cmd->has_name             = false;
    cmd->reject_unknown_flags = false;
    cmd->enforce_arity        = false;
}

// ============================================================================
// Lifecycle
// ============================================================================

n00b_cmdr_t *
n00b_cmdr_new(void)
{
    n00b_cmdr_t *c = n00b_alloc(n00b_cmdr_t);

    cmdr_init_command(&c->root);

    return c;
}

n00b_cmdr_t *
n00b_cmdr_from_bnf(n00b_string_t *bnf, n00b_string_t *start_symbol)
{
    n00b_cmdr_t *c = n00b_cmdr_new();

    c->bnf_text     = bnf;
    c->start_symbol = start_symbol;
    c->has_bnf      = true;

    c->grammar = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_EARLEY_ONLY);

    if (!n00b_bnf_load(bnf, start_symbol, c->grammar)) {
        n00b_cmdr_free(c);
        return NULL;
    }

    n00b_grammar_finalize(c->grammar);
    c->finalized = true;

    return c;
}

void
n00b_cmdr_free(n00b_cmdr_t *c)
{
    if (!c) {
        return;
    }

    if (c->grammar) {
        n00b_grammar_free(c->grammar);
    }

    n00b_free(c);
}

// ============================================================================
// Builder API
// ============================================================================

void
n00b_cmdr_set_name(n00b_cmdr_t *c, n00b_string_t *name)
{
    if (c) {
        c->name = name;
    }
}

void
n00b_cmdr_add_command(n00b_cmdr_t *c, n00b_string_t *name, n00b_string_t *doc)
{
    if (!c || !name) {
        return;
    }

    n00b_cmdr_command_t cmd = {0};
    cmdr_init_command(&cmd);
    cmd.name     = name;
    cmd.doc      = doc;
    cmd.has_name = true;

    n00b_list_push(c->root.subcommands, cmd);
}

void
n00b_cmdr_add_subcommand(n00b_cmdr_t *c, n00b_string_t *parent,
                          n00b_string_t *name, n00b_string_t *doc)
{
    if (!c || !name) {
        return;
    }

    n00b_cmdr_command_t *pcmd = cmdr_get_command(c, parent);

    if (!pcmd) {
        return;
    }

    n00b_cmdr_command_t cmd = {0};
    cmdr_init_command(&cmd);
    cmd.name     = name;
    cmd.doc      = doc;
    cmd.has_name = true;

    n00b_list_push(pcmd->subcommands, cmd);
}

void
n00b_cmdr_add_flag(n00b_cmdr_t *c, n00b_string_t *command,
                    n00b_string_t *flag_name, n00b_cmdr_arg_type_t type,
                    bool takes_value, n00b_string_t *doc)
{
    if (!c || !flag_name) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (!cmd) {
        return;
    }

    n00b_cmdr_flag_spec_t f = {0};
    f.name        = flag_name;
    f.value_type  = type;
    f.takes_value = takes_value;
    f.doc         = doc;
    f.terminal_id = 0;
    f.has_short   = false;
    f.multi       = false;

    n00b_list_push(cmd->flags, f);
}

void
n00b_cmdr_add_flag_multi(n00b_cmdr_t *c, n00b_string_t *command,
                          n00b_string_t *flag_name,
                          n00b_cmdr_arg_type_t value_type,
                          n00b_string_t *doc)
{
    if (!c || !flag_name) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (!cmd) {
        return;
    }

    n00b_cmdr_flag_spec_t f = {};
    f.name        = flag_name;
    f.value_type  = value_type;
    f.takes_value = true;
    f.doc         = doc;
    f.terminal_id = 0;
    f.has_short   = false;
    f.multi       = true;

    n00b_list_push(cmd->flags, f);
}

void
n00b_cmdr_add_flag_alias(n00b_cmdr_t *c, n00b_string_t *command,
                          n00b_string_t *flag_name, n00b_string_t *alias)
{
    if (!c || !flag_name || !alias) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (!cmd) {
        return;
    }

    n00b_option_t(size_t) idx = cmdr_find_flag_index(cmd, flag_name);

    if (!n00b_option_is_set(idx)) {
        return;
    }

    n00b_cmdr_flag_spec_t f = n00b_list_get(cmd->flags, n00b_option_get(idx));
    f.short_name = alias;
    f.has_short  = true;
    n00b_list_set(cmd->flags, n00b_option_get(idx), f);
}

void
n00b_cmdr_add_positional(n00b_cmdr_t *c, n00b_string_t *command,
                          n00b_string_t *name, n00b_cmdr_arg_type_t type,
                          int min, int max)
{
    if (!c || !name) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (!cmd) {
        return;
    }

    n00b_cmdr_positional_spec_t p = {0};
    p.name = name;
    p.type = type;
    p.min  = min;
    p.max  = max;

    n00b_list_push(cmd->positionals, p);
}

void
n00b_cmdr_reject_unknown_flags(n00b_cmdr_t *c, n00b_string_t *command)
{
    if (!c) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (cmd) {
        cmd->reject_unknown_flags = true;
    }
}

void
n00b_cmdr_enforce_arity(n00b_cmdr_t *c, n00b_string_t *command)
{
    if (!c) {
        return;
    }

    n00b_cmdr_command_t *cmd = cmdr_get_command(c, command);

    if (cmd) {
        cmd->enforce_arity = true;
    }
}

// ============================================================================
// Grammar generation from builder spec
// ============================================================================

static void
cmdr_register_command_terminals(n00b_cmdr_t *c, n00b_cmdr_command_t *cmd)
{
    int32_t n_flags = n00b_list_len(cmd->flags);

    for (int32_t i = 0; i < n_flags; i++) {
        n00b_cmdr_flag_spec_t f = n00b_list_get(cmd->flags, i);
        f.terminal_id = n00b_register_terminal(c->grammar, f.name);

        if (f.has_short) {
            n00b_register_terminal(c->grammar, f.short_name);
        }

        // Write back — terminal_id was updated.
        n00b_list_set(cmd->flags, i, f);
    }
}

static n00b_nt_id_t
cmdr_build_flag_nt(n00b_cmdr_t *c, n00b_cmdr_flag_spec_t f,
                    const char *prefix)
{
    char nt_name[256];
    snprintf(nt_name, sizeof(nt_name), "%s-flag-%s", prefix, f.name->data);

    // Capture ID immediately — n00b_add_rule can reallocate nt_list,
    // invalidating any n00b_nonterm_t * pointer.
    n00b_nt_id_t nt_id = n00b_nonterm_id(
        n00b_nonterm(c->grammar, n00b_string_from_cstr(nt_name)));

    int64_t flag_tid = f.terminal_id;
    int64_t eq_tid   = c->tok_ids[N00B_CMDR_TID_EQ];
    int64_t word_tid = c->tok_ids[N00B_CMDR_TID_WORD];
    int64_t int_tid  = c->tok_ids[N00B_CMDR_TID_INT];
    int64_t flt_tid  = c->tok_ids[N00B_CMDR_TID_FLOAT];
    int64_t bool_tid = c->tok_ids[N00B_CMDR_TID_BOOL];

    if (f.takes_value) {
        int64_t value_tids[] = {
            word_tid,
            int_tid,
            flt_tid,
            bool_tid,
        };
        int64_t short_tid = 0;

        if (f.has_short) {
            short_tid = n00b_register_terminal(c->grammar, f.short_name);
        }

        for (size_t i = 0; i < sizeof(value_tids) / sizeof(value_tids[0]); i++) {
            int64_t value_tid = value_tids[i];

            // long flag with equals separator: --flag=value
            n00b_add_rule_v(c->grammar, nt_id, 3,
                             (n00b_match_t[]){
                                 N00B_TERMINAL(flag_tid),
                                 N00B_TERMINAL(eq_tid),
                                 N00B_TERMINAL(value_tid),
                             });

            // long flag with space separator: --flag value
            n00b_add_rule_v(c->grammar, nt_id, 2,
                             (n00b_match_t[]){
                                 N00B_TERMINAL(flag_tid),
                                 N00B_TERMINAL(value_tid),
                             });

            if (f.has_short) {
                n00b_add_rule_v(c->grammar, nt_id, 3,
                                 (n00b_match_t[]){
                                     N00B_TERMINAL(short_tid),
                                     N00B_TERMINAL(eq_tid),
                                     N00B_TERMINAL(value_tid),
                                 });
                n00b_add_rule_v(c->grammar, nt_id, 2,
                                 (n00b_match_t[]){
                                     N00B_TERMINAL(short_tid),
                                     N00B_TERMINAL(value_tid),
                                 });
            }
        }
    }
    else {
        // Boolean flag (no value)
        n00b_add_rule_v(c->grammar, nt_id, 1,
                         (n00b_match_t[]){N00B_TERMINAL(flag_tid)});

        if (f.has_short) {
            int64_t short_tid = n00b_register_terminal(c->grammar,
                                                        f.short_name);
            n00b_add_rule_v(c->grammar, nt_id, 1,
                             (n00b_match_t[]){N00B_TERMINAL(short_tid)});
        }
    }

    return nt_id;
}

static n00b_nt_id_t
cmdr_build_items_nt(n00b_cmdr_t *c, n00b_cmdr_command_t *cmd,
                     const char *prefix)
{
    char nt_name[256];
    snprintf(nt_name, sizeof(nt_name), "%s-items", prefix);

    n00b_nt_id_t items_id = n00b_nonterm_id(
        n00b_nonterm(c->grammar, n00b_string_from_cstr(nt_name)));

    // items -> ""
    n00b_add_rule_v(c->grammar, items_id, 1,
                     (n00b_match_t[]){N00B_EPSILON()});

    // items -> flag items  (for each flag)
    int32_t n_flags = n00b_list_len(cmd->flags);

    for (int32_t i = 0; i < n_flags; i++) {
        n00b_cmdr_flag_spec_t f = n00b_list_get(cmd->flags, i);
        n00b_nt_id_t fnt_id = cmdr_build_flag_nt(c, f, prefix);

        n00b_add_rule_v(c->grammar, items_id, 2,
                         (n00b_match_t[]){
                             (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = fnt_id},
                             (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                         });
    }

    // Also allow root-level flags inside subcommand grammars.
    if (cmd != &c->root) {
        int32_t n_root = n00b_list_len(c->root.flags);

        for (int32_t i = 0; i < n_root; i++) {
            n00b_cmdr_flag_spec_t f = n00b_list_get(c->root.flags, i);
            n00b_nt_id_t fnt_id = cmdr_build_flag_nt(c, f, prefix);

            n00b_add_rule_v(c->grammar, items_id, 2,
                             (n00b_match_t[]){
                                 (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = fnt_id},
                                 (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                             });
        }
    }

    // items -> WORD items | INT items | FLOAT items | BOOL items
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_WORD]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_INT]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_FLOAT]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_BOOL]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });

    // items -> FLAG items  (unknown flags become positional args)
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_FLAG]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });

    // items -> DD items  (-- separator)
    n00b_add_rule_v(c->grammar, items_id, 2,
                     (n00b_match_t[]){
                         N00B_TERMINAL(c->tok_ids[N00B_CMDR_TID_DD]),
                         (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                     });

    return items_id;
}

static void
cmdr_build_command_grammar(n00b_cmdr_t *c, n00b_cmdr_command_t *cmd,
                            n00b_nt_id_t parent_id, const char *prefix)
{
    n00b_nt_id_t items_id = cmdr_build_items_nt(c, cmd, prefix);

    if (cmd->has_name) {
        int64_t name_tid = n00b_register_terminal(c->grammar, cmd->name);
        n00b_add_rule_v(c->grammar, parent_id, 2,
                         (n00b_match_t[]){
                             N00B_TERMINAL(name_tid),
                             (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                         });
    }
    else {
        n00b_add_rule_v(c->grammar, parent_id, 1,
                         (n00b_match_t[]){
                             (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = items_id},
                         });
    }

    // Subcommands
    int32_t n_subs = n00b_list_len(cmd->subcommands);

    for (int32_t i = 0; i < n_subs; i++) {
        n00b_cmdr_command_t sub = n00b_list_get(cmd->subcommands, i);
        char sub_prefix[256];
        snprintf(sub_prefix, sizeof(sub_prefix), "%s-%s",
                 prefix, sub.name->data);

        cmdr_build_command_grammar(c, &sub, parent_id, sub_prefix);
    }
}

void
n00b_cmdr_finalize(n00b_cmdr_t *c)
{
    if (!c || c->finalized) {
        return;
    }

    // Commander parses with Earley but without error recovery (the
    // error-recovery rules cause state explosion with our grammar
    // structure's epsilon rules for optional items). Both are fixed at
    // instantiation.
    c->grammar = n00b_grammar_new(.parse_mode     = N00B_PARSE_MODE_EARLEY_ONLY,
                                  .error_recovery = false);

    // Register base token types.
    c->tok_ids[N00B_CMDR_TID_WORD]  = n00b_register_terminal(c->grammar,
                                                                r"WORD");
    c->tok_ids[N00B_CMDR_TID_INT]   = n00b_register_terminal(c->grammar,
                                                                r"INT");
    c->tok_ids[N00B_CMDR_TID_FLOAT] = n00b_register_terminal(c->grammar,
                                                                r"FLOAT");
    c->tok_ids[N00B_CMDR_TID_BOOL]  = n00b_register_terminal(c->grammar,
                                                                r"BOOL");
    c->tok_ids[N00B_CMDR_TID_EQ]    = n00b_register_terminal(c->grammar,
                                                                r"EQ");
    c->tok_ids[N00B_CMDR_TID_COMMA] = n00b_register_terminal(c->grammar,
                                                                r"COMMA");
    c->tok_ids[N00B_CMDR_TID_DD]    = n00b_register_terminal(c->grammar,
                                                                r"DD");
    c->tok_ids[N00B_CMDR_TID_FLAG]  = n00b_register_terminal(c->grammar,
                                                                r"FLAG");

    // Register all flag names.
    cmdr_register_command_terminals(c, &c->root);

    int32_t n_subs = n00b_list_len(c->root.subcommands);

    for (int32_t i = 0; i < n_subs; i++) {
        n00b_cmdr_command_t sub = n00b_list_get(c->root.subcommands, i);
        cmdr_register_command_terminals(c, &sub);

        if (sub.has_name) {
            n00b_register_terminal(c->grammar, sub.name);
        }

        // Write back — terminal_id was updated on flags.
        n00b_list_set(c->root.subcommands, i, sub);
    }

    // Build grammar.  Save the start NT's id — not a pointer —
    // since building subcommand grammars will grow nt_list and
    // invalidate pointers into it.
    n00b_nt_id_t start_id = n00b_nonterm_id(
        n00b_nonterm(c->grammar, r"cmd"));
    n00b_grammar_set_start_id(c->grammar, start_id);

    if (n_subs > 0) {
        for (int32_t i = 0; i < n_subs; i++) {
            n00b_cmdr_command_t sub = n00b_list_get(c->root.subcommands, i);
            char prefix[256];
            snprintf(prefix, sizeof(prefix), "cmd-%s", sub.name->data);

            cmdr_build_command_grammar(c, &sub, start_id, prefix);
        }

        // Also support global flags without a subcommand
        if (n00b_list_len(c->root.flags) > 0) {
            cmdr_build_command_grammar(c, &c->root, start_id, "cmd-root");
        }
    }
    else {
        cmdr_build_command_grammar(c, &c->root, start_id, "cmd");
    }

    n00b_grammar_finalize(c->grammar);
    c->finalized = true;
}

// ============================================================================
// Parsing
// ============================================================================

static n00b_cmdr_result_t *
cmdr_make_error_result(const char *msg)
{
    n00b_cmdr_result_t *r = n00b_alloc(n00b_cmdr_result_t);

    r->ok     = false;
    r->args   = n00b_list_new_private(n00b_cmdr_arg_t);
    r->errors = n00b_list_new_private(n00b_string_t *);

    n00b_list_push(r->errors, n00b_string_from_cstr(msg));

    n00b_dict_init(&r->flags, .hash = n00b_string_hash, .skip_obj_hash = true);

    return r;
}

// Split a raw flag value string on unescaped ',' separators, applying
// '\,' -> ',' unescape. Appends each resulting element (as an
// n00b_string_t *) to `out`. A backslash followed by anything other
// than ',' is preserved verbatim.
static void
cmdr_split_multi_value(n00b_string_t                *raw,
                       n00b_list_t(n00b_string_t *) *out)
{
    if (!raw || raw->u8_bytes == 0) {
        n00b_list_push(*out, n00b_string_empty());
        return;
    }

    char  *buf = n00b_alloc_array(char, raw->u8_bytes + 1);
    size_t bp  = 0;

    for (size_t i = 0; i < raw->u8_bytes; i++) {
        unsigned char ch = (unsigned char)raw->data[i];

        if (ch == '\\' && i + 1 < raw->u8_bytes && raw->data[i + 1] == ',') {
            buf[bp++] = ',';
            i++;
            continue;
        }

        if (ch == ',') {
            buf[bp] = '\0';
            n00b_list_push(*out,
                            bp > 0 ? n00b_string_from_cstr(buf)
                                   : n00b_string_empty());
            bp = 0;
            continue;
        }

        buf[bp++] = (char)ch;
    }

    buf[bp] = '\0';
    n00b_list_push(*out,
                    bp > 0 ? n00b_string_from_cstr(buf)
                           : n00b_string_empty());

    n00b_free(buf);
}

// Collect all terminal text from a parse tree into a flat list.
static void
cmdr_collect_terminal_text(n00b_parse_tree_t *tree,
                            n00b_list_t(n00b_string_t *) *texts)
{
    if (!tree) {
        return;
    }

    if (n00b_tree_is_leaf(tree)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(tree);

        if (tok && n00b_option_is_set(tok->value)) {
            n00b_string_t *text = n00b_option_get(tok->value);

            if (text && text->u8_bytes > 0) {
                n00b_list_push(*texts, text);
            }
        }

        return;
    }

    size_t nc = n00b_tree_num_children(tree);

    for (size_t i = 0; i < nc; i++) {
        cmdr_collect_terminal_text(n00b_tree_child(tree, i), texts);
    }
}

static n00b_string_t *
cmdr_safe_token(n00b_string_t *text)
{
    if (!text) {
        return r"(none)";
    }
    n00b_string_t *safe = n00b_string_from_raw(text->data,
                                               (int64_t)text->u8_bytes);
    for (size_t i = 0; i < safe->u8_bytes; i++) {
        unsigned char c = (unsigned char)safe->data[i];
        if (c < 0x20 || c == 0x7f) {
            safe->data[i] = '?';
        }
    }
    return safe;
}

static bool
cmdr_parse_int64(n00b_string_t *text, int64_t *out)
{
    if (!text || text->u8_bytes == 0
        || isspace((unsigned char)text->data[0])) {
        return false;
    }
    char *value = n00b_alloc_array(char, text->u8_bytes + 1);
    memcpy(value, text->data, text->u8_bytes);
    char *end = nullptr;
    errno     = 0;
    int64_t parsed = strtoll(value, &end, 10);
    bool valid = errno != ERANGE && end != value && *end == '\0';
    n00b_free(value);
    if (valid && out) {
        *out = parsed;
    }
    return valid;
}

static bool
cmdr_parse_double(n00b_string_t *text, double *out)
{
    if (!text || text->u8_bytes == 0
        || isspace((unsigned char)text->data[0])) {
        return false;
    }
    char *value = n00b_alloc_array(char, text->u8_bytes + 1);
    memcpy(value, text->data, text->u8_bytes);
    char *end = nullptr;
    errno     = 0;
    double parsed = strtod(value, &end);
    bool valid = errno != ERANGE && end != value && *end == '\0';
    n00b_free(value);
    if (valid && out) {
        *out = parsed;
    }
    return valid;
}

static bool
cmdr_is_negative_number(n00b_string_t *text)
{
    return text && text->u8_bytes > 1 && text->data[0] == '-'
           && cmdr_parse_double(text, nullptr);
}

static bool
cmdr_validate_positionals(n00b_cmdr_command_t *cmd, n00b_cmdr_result_t *r)
{
    int32_t n_specs = cmd ? n00b_list_len(cmd->positionals) : 0;
    int64_t n_args  = n00b_list_len(r->args);
    int64_t arg_ix  = 0;

    for (int32_t i = 0; i < n_specs && arg_ix < n_args; i++) {
        n00b_cmdr_positional_spec_t spec =
            n00b_list_get(cmd->positionals, i);
        int64_t later_min = 0;
        for (int32_t j = i + 1; j < n_specs; j++) {
            later_min += n00b_list_get(cmd->positionals, j).min;
        }
        int64_t remaining = n_args - arg_ix;
        int64_t take      = remaining - later_min;
        if (take < spec.min) {
            take = remaining < spec.min ? remaining : spec.min;
        }
        if (spec.max >= 0 && take > spec.max) {
            take = spec.max;
        }
        if (take < 0) {
            take = 0;
        }

        for (int64_t j = 0; j < take; j++, arg_ix++) {
            n00b_cmdr_arg_t arg = n00b_list_get(r->args, arg_ix);
            if (spec.type == N00B_CMDR_TYPE_INT
                && !cmdr_parse_int64(arg.value, &arg.int_val)) {
                r->ok = false;
                n00b_list_push(
                    r->errors,
                    n00b_cformat("integer positional [|#|] value [|#|] is not a valid int64",
                                 cmdr_safe_token(spec.name),
                                 cmdr_safe_token(arg.value)));
                return false;
            }
            if (spec.type == N00B_CMDR_TYPE_FLOAT
                && !cmdr_parse_double(arg.value, &arg.float_val)) {
                r->ok = false;
                n00b_list_push(
                    r->errors,
                    n00b_cformat("float positional [|#|] value [|#|] is not valid",
                                 cmdr_safe_token(spec.name),
                                 cmdr_safe_token(arg.value)));
                return false;
            }
            n00b_list_set(r->args, arg_ix, arg);
        }
    }
    return true;
}

static void
cmdr_extract_result(n00b_cmdr_t *c, n00b_parse_tree_t *tree,
                     n00b_cmdr_result_t *r)
{
    if (!tree || !r) {
        return;
    }

    n00b_list_t(n00b_string_t *) texts = n00b_list_new_private(n00b_string_t *);
    cmdr_collect_terminal_text(tree, &texts);

    int32_t               n       = n00b_list_len(texts);
    bool                  past_dd = false;
    n00b_cmdr_command_t *cmd     = &c->root;

    for (int32_t i = 0; i < n; i++) {
        n00b_string_t *text = n00b_list_get(texts, i);

        if (!text || text->u8_bytes == 0) {
            continue;
        }

        // Track -- separator
        if (text->u8_bytes == 2
            && text->data[0] == '-' && text->data[1] == '-') {
            past_dd = true;
            continue;
        }

        // Check if this is a subcommand name
        if (!r->has_cmd && !past_dd) {
            int32_t n_subs = n00b_list_len(c->root.subcommands);
            bool    found_sub = false;

            for (int32_t si = 0; si < n_subs; si++) {
                n00b_cmdr_command_t sub = n00b_list_get(c->root.subcommands,
                                                         si);

                if (sub.has_name
                    && sub.name->u8_bytes == text->u8_bytes
                    && memcmp(sub.name->data, text->data,
                              text->u8_bytes) == 0) {
                    r->command = text;
                    r->has_cmd = true;
                    found_sub  = true;
                    cmd        = cmdr_get_command(c, text);
                    if (!cmd) {
                        cmd = &c->root;
                    }
                    break;
                }
            }

            if (found_sub) {
                continue;
            }
        }

        // After --, everything is a positional arg
        if (past_dd) {
            goto add_arg;
        }

        // Check if this is a flag
        n00b_option_t(size_t) flag_idx = cmdr_find_flag(cmd, text);
        n00b_cmdr_command_t  *flag_cmd = cmd;

        if (!n00b_option_is_set(flag_idx)) {
            flag_idx = cmdr_find_flag(&c->root, text);
            flag_cmd = &c->root;
        }

        if (n00b_option_is_set(flag_idx)) {
            n00b_cmdr_flag_spec_t flag = n00b_list_get(flag_cmd->flags,
                                                        n00b_option_get(flag_idx));

            // Multi-flag path: accumulate into a list-arm value.
            if (flag.multi) {
                // Skip '=' if present, then consume one value token.
                if (i + 1 < n) {
                    n00b_string_t *next = n00b_list_get(texts, i + 1);

                    if (next && next->u8_bytes == 1 && next->data[0] == '=') {
                        i++;
                    }
                }

                if (i + 1 >= n) {
                    continue;
                }

                i++;
                n00b_string_t *raw = n00b_list_get(texts, i);

                // Fetch or create the list value.
                bool             found = false;
                n00b_cmdr_val_t *v
                    = n00b_dict_get(&r->flags, flag.name, &found);

                if (!found || !v
                    || !n00b_variant_is_type(*v,
                                             n00b_list_t(n00b_string_t *))) {
                    v  = n00b_alloc(n00b_cmdr_val_t);
                    *v = n00b_variant_set(n00b_cmdr_val_t,
                                          n00b_list_t(n00b_string_t *),
                                          n00b_list_new_private(n00b_string_t *));

                    n00b_dict_put(&r->flags, flag.name, v);

                    if (flag.has_short) {
                        n00b_dict_put(&r->flags, flag.short_name, v);
                    }
                }

                cmdr_split_multi_value(
                    raw,
                    &v->value.N00B_VARIANT_FIELD(n00b_list_t(n00b_string_t *)));
                continue;
            }

            n00b_cmdr_val_t *v = n00b_alloc(n00b_cmdr_val_t);

            if (flag.takes_value && i + 1 < n) {
                // Skip '=' if present
                if (i + 1 < n) {
                    n00b_string_t *next = n00b_list_get(texts, i + 1);

                    if (next && next->u8_bytes == 1 && next->data[0] == '=') {
                        i++;
                    }
                }

                if (i + 1 < n) {
                    i++;
                    n00b_string_t *val = n00b_list_get(texts, i);

                    // Need a null-terminated copy for strtoll/strtod
                    char *cval = n00b_alloc_array(char, val->u8_bytes + 1);
                    memcpy(cval, val->data, val->u8_bytes);

                    switch (flag.value_type) {
                    case N00B_CMDR_TYPE_INT: {
                        int64_t parsed = 0;
                        if (!cmdr_parse_int64(val, &parsed)) {
                            r->ok = false;
                            n00b_list_push(
                                r->errors,
                                n00b_cformat("integer flag [|#|] value [|#|] is not a valid int64",
                                             cmdr_safe_token(flag.name),
                                             cmdr_safe_token(val)));
                            n00b_free(cval);
                            n00b_free(v);
                            n00b_list_free(texts);
                            return;
                        }
                        *v = n00b_variant_set(n00b_cmdr_val_t,
                                              int64_t,
                                              parsed);
                        break;
                    }
                    case N00B_CMDR_TYPE_FLOAT: {
                        double parsed = 0.0;
                        if (!cmdr_parse_double(val, &parsed)) {
                            r->ok = false;
                            n00b_list_push(
                                r->errors,
                                n00b_cformat("float flag [|#|] value [|#|] is not valid",
                                             cmdr_safe_token(flag.name),
                                             cmdr_safe_token(val)));
                            n00b_free(cval);
                            n00b_free(v);
                            n00b_list_free(texts);
                            return;
                        }
                        *v = n00b_variant_set(n00b_cmdr_val_t,
                                              double,
                                              parsed);
                        break;
                    }
                    case N00B_CMDR_TYPE_BOOL:
                        *v = n00b_variant_set(n00b_cmdr_val_t,
                                              bool,
                                              (strcmp(cval, "true") == 0
                                               || strcmp(cval, "yes") == 0));
                        break;
                    default:
                        *v = n00b_variant_set(n00b_cmdr_val_t,
                                              n00b_string_t *,
                                              val);
                        break;
                    }

                    n00b_free(cval);
                }
                else {
                    n00b_free(v);
                    continue;
                }
            }
            else {
                *v = n00b_variant_set(n00b_cmdr_val_t, bool, true);
            }

            // Store under long name
            n00b_dict_put(&r->flags, flag.name, v);

            // Also store under alias
            if (flag.has_short) {
                n00b_dict_put(&r->flags, flag.short_name, v);
            }

            continue;
        }

        if (cmd->reject_unknown_flags
            && text->u8_bytes > 1
            && text->data[0] == '-'
            && !cmdr_is_negative_number(text)) {
            r->ok = false;
            n00b_list_push(r->errors,
                           n00b_cformat("unknown flag [|#|]",
                                        cmdr_safe_token(text)));
            n00b_list_free(texts);
            return;
        }

        // Skip '='
        if (text->u8_bytes == 1 && text->data[0] == '=') {
            continue;
        }

        // Positional argument
        add_arg:;
        n00b_cmdr_arg_t arg = {0};
        arg.value = text;

        // Pre-parse numeric values
        char *ctext = n00b_alloc_array(char, text->u8_bytes + 1);
        memcpy(ctext, text->data, text->u8_bytes);

        arg.int_val   = strtoll(ctext, NULL, 10);
        arg.float_val = strtod(ctext, NULL);

        n00b_free(ctext);

        n00b_list_push(r->args, arg);
    }

    int32_t n_specs = cmd ? n00b_list_len(cmd->positionals) : 0;
    bool help_requested = n00b_cmdr_flag_present(r, r"--help");

    if (!help_requested && cmd && cmd->enforce_arity) {
        int64_t min_args = 0;
        int64_t max_args = 0;

        for (int32_t i = 0; i < n_specs; i++) {
            n00b_cmdr_positional_spec_t spec =
                n00b_list_get(cmd->positionals, i);
            min_args += spec.min;
            max_args = spec.max < 0 || max_args < 0
                           ? -1
                           : max_args + spec.max;
        }

        int64_t n_args = n00b_list_len(r->args);
        if (n_args < min_args || (max_args >= 0 && n_args > max_args)) {
            r->ok = false;
            n00b_list_push(r->errors,
                           r"positional argument count is outside declared bounds");
            n00b_list_free(texts);
            return;
        }
    }

    if (!help_requested && !cmdr_validate_positionals(cmd, r)) {
        n00b_list_free(texts);
        return;
    }

    n00b_list_free(texts);
}

n00b_cmdr_result_t *
n00b_cmdr_parse(n00b_cmdr_t *c, int argc, const char **argv)
{
    if (!c) {
        return cmdr_make_error_result("commander not initialized");
    }

    if (!c->finalized) {
        n00b_cmdr_finalize(c);
    }

    if (!c->grammar) {
        return cmdr_make_error_result("grammar not available");
    }

    // Tokenize
    n00b_token_info_t **tokens   = NULL;
    int32_t             n_tokens = 0;

    if (n00b_cmdr_tokenize(argv, argc, c, &tokens, &n_tokens) < 0) {
        return cmdr_make_error_result("tokenization failed");
    }

    // Parse using Earley
    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, n_tokens);

    n00b_parse_result_t *pr = n00b_grammar_parse(c->grammar, ts);

    n00b_cmdr_result_t *r = n00b_alloc(n00b_cmdr_result_t);
    r->args   = n00b_list_new_private(n00b_cmdr_arg_t);
    r->errors = n00b_list_new_private(n00b_string_t *);

    n00b_dict_init(&r->flags, .hash = n00b_string_hash, .skip_obj_hash = true);

    if (!n00b_parse_result_ok(pr)) {
        r->ok = false;

        n00b_string_t *err_str = n00b_parse_result_error_string(pr);

        if (err_str && err_str->u8_bytes > 0) {
            n00b_list_push(r->errors, err_str);
        }
        else {
            n00b_list_push(r->errors, r"parse failed");
        }
    }
    else {
        r->ok = true;

        n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

        if (tree) {
            cmdr_extract_result(c, tree, r);
        }
    }

    n00b_parse_result_free(pr);
    n00b_token_stream_free(ts);

    // Free token array (tokens are GC-managed, but the array itself
    // was allocated by the tokenizer)
    n00b_free(tokens);

    return r;
}

n00b_cmdr_result_t *
n00b_cmdr_parse_string(n00b_cmdr_t *c, n00b_string_t *cmdline)
{
    if (!c) {
        return cmdr_make_error_result("commander not initialized");
    }

    if (!c->finalized) {
        n00b_cmdr_finalize(c);
    }

    if (!c->grammar) {
        return cmdr_make_error_result("grammar not available");
    }

    n00b_token_info_t **tokens   = NULL;
    int32_t             n_tokens = 0;

    if (n00b_cmdr_tokenize_string(cmdline, c, &tokens, &n_tokens) < 0) {
        return cmdr_make_error_result("tokenization failed");
    }

    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, n_tokens);

    n00b_parse_result_t *pr = n00b_grammar_parse(c->grammar, ts);

    n00b_cmdr_result_t *r = n00b_alloc(n00b_cmdr_result_t);
    r->args   = n00b_list_new_private(n00b_cmdr_arg_t);
    r->errors = n00b_list_new_private(n00b_string_t *);

    n00b_dict_init(&r->flags, .hash = n00b_string_hash, .skip_obj_hash = true);

    if (!n00b_parse_result_ok(pr)) {
        r->ok = false;

        n00b_string_t *err_str = n00b_parse_result_error_string(pr);

        if (err_str && err_str->u8_bytes > 0) {
            n00b_list_push(r->errors, err_str);
        }
        else {
            n00b_list_push(r->errors, r"parse failed");
        }
    }
    else {
        r->ok = true;

        n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

        if (tree) {
            cmdr_extract_result(c, tree, r);
        }
    }

    n00b_parse_result_free(pr);
    n00b_token_stream_free(ts);
    n00b_free(tokens);

    return r;
}

// ============================================================================
// Result queries
// ============================================================================

n00b_string_t *
n00b_cmdr_result_command(n00b_cmdr_result_t *r)
{
    if (!r || !r->has_cmd) {
        return n00b_string_empty();
    }

    return r->command;
}

bool
n00b_cmdr_flag_present(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    if (!r || !flag) {
        return false;
    }

    return n00b_dict_contains(&r->flags, flag);
}

n00b_cmdr_val_t *
n00b_cmdr_flag_get(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    if (!r || !flag) {
        return NULL;
    }

    bool           found = false;
    n00b_cmdr_val_t *v   = n00b_dict_get(&r->flags, flag, &found);

    return found ? v : NULL;
}

n00b_string_t *
n00b_cmdr_flag_str(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    n00b_cmdr_val_t *v = n00b_cmdr_flag_get(r, flag);

    if (!v || !n00b_variant_is_type(*v, n00b_string_t *)) {
        return n00b_string_empty();
    }

    return n00b_variant_get(*v, n00b_string_t *);
}

int64_t
n00b_cmdr_flag_int(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    n00b_cmdr_val_t *v = n00b_cmdr_flag_get(r, flag);

    if (!v || !n00b_variant_is_type(*v, int64_t)) {
        return 0;
    }

    return n00b_variant_get(*v, int64_t);
}

bool
n00b_cmdr_flag_bool(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    n00b_cmdr_val_t *v = n00b_cmdr_flag_get(r, flag);

    if (!v || !n00b_variant_is_type(*v, bool)) {
        return false;
    }

    return n00b_variant_get(*v, bool);
}

n00b_option_t(n00b_list_t(n00b_string_t *) *)
    n00b_cmdr_flag_list(n00b_cmdr_result_t *r, n00b_string_t *flag)
{
    n00b_cmdr_val_t *v = n00b_cmdr_flag_get(r, flag);

    if (!v || !n00b_variant_is_type(*v, n00b_list_t(n00b_string_t *))) {
        return n00b_option_none(n00b_list_t(n00b_string_t *) *);
    }

    return n00b_option_set(
        n00b_list_t(n00b_string_t *) *,
        &v->value.N00B_VARIANT_FIELD(n00b_list_t(n00b_string_t *)));
}

int32_t
n00b_cmdr_arg_count(n00b_cmdr_result_t *r)
{
    if (!r) {
        return 0;
    }

    return n00b_list_len(r->args);
}

n00b_string_t *
n00b_cmdr_arg_str(n00b_cmdr_result_t *r, int index)
{
    if (!r || index < 0 || (size_t)index >= n00b_list_len(r->args)) {
        return n00b_string_empty();
    }

    n00b_cmdr_arg_t arg = n00b_list_get(r->args, index);
    return arg.value;
}

int64_t
n00b_cmdr_arg_int(n00b_cmdr_result_t *r, int index)
{
    if (!r || index < 0 || (size_t)index >= n00b_list_len(r->args)) {
        return 0;
    }

    n00b_cmdr_arg_t arg = n00b_list_get(r->args, index);
    return arg.int_val;
}

// ============================================================================
// Error queries
// ============================================================================

int32_t
n00b_cmdr_error_count(n00b_cmdr_result_t *r)
{
    if (!r) {
        return 0;
    }

    return n00b_list_len(r->errors);
}

n00b_string_t *
n00b_cmdr_error_get(n00b_cmdr_result_t *r, int32_t index)
{
    if (!r || index < 0 || (size_t)index >= n00b_list_len(r->errors)) {
        return n00b_string_empty();
    }

    return n00b_list_get(r->errors, index);
}

// ============================================================================
// Result cleanup
// ============================================================================

void
n00b_cmdr_result_free(n00b_cmdr_result_t *r)
{
    if (!r) {
        return;
    }

    n00b_list_free(r->args);
    n00b_list_free(r->errors);
    n00b_free(r);
}
