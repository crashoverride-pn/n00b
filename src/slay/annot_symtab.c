// annot_symtab.c - Phases 2-3: two-pass symbol registration + type binding.
//
// Pass A: symbol-creating annotations (DECLARES, TYPE_DECL, ADT, FIELD, METHOD)
//         → sets nc->last_sym.  Each symbol with a type_node gets type-bound
//         immediately, so multiple symbol-creators on the same rule (e.g.,
//         @type($1) @declares($1) on enum-stmt) all resolve correctly.
// Pass B: symbol-reading annotations (TYPE, LITERAL)
//         → reads nc->last_sym (guaranteed set by pass A).
//
// This two-pass design fixes the ordering bug where @type silently fails
// when it appears before @declares in the grammar rule.

#include "internal/slay/annot_phases.h"
#include "slay/diagnostic.h"
#include "typecheck/unify.h"
#include "typecheck/context.h"

// Translate type_node → concrete type and unify with the symbol's type_var.
static void
bind_sym_type(n00b_annot_walk_ctx_t *ctx, n00b_sym_entry_t *sym)
{
    if (sym && sym->type_node && ctx->tc_ctx && ctx->translate_type_spec) {
        n00b_tc_type_t *declared = ctx->translate_type_spec(
            ctx->tc_ctx, ctx->grammar, sym->type_node);

        if (declared) {
            n00b_tc_unify(ctx->tc_ctx, sym->type_var, declared);
        }
    }
}

void
annot_phase_symtab(n00b_annot_walk_ctx_t *ctx, annot_node_ctx_t *nc)
{
    // ---- Pass A: symbol-creating annotations ----

    for (size_t ai = 0; ai < nc->annot_count; ai++) {
        n00b_annotation_t *a = nc->annots[ai];

        switch (a->kind) {
        case N00B_ANNOT_DECLARES: {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);

            // Detect method declarations: name_node is a <method-name>
            // NT containing ClassName.methodName.
            n00b_string_t *class_name  = NULL;
            n00b_string_t *method_name = NULL;
            bool           is_method   = false;

            if (name_node && n00b_pt_is_nt(name_node, "method-name")) {
                // <method-name> ::= %IDENTIFIER %"." %IDENTIFIER
                // Extract both identifiers.
                size_t mnc = n00b_pt_num_children(name_node);

                for (size_t mi = 0; mi < mnc; mi++) {
                    n00b_parse_tree_t *mc = n00b_pt_get_child(name_node, mi);

                    if (n00b_pt_is_token(mc)) {
                        const char *t = n00b_pt_token_text(mc);
                        size_t      tl = n00b_pt_token_text_len(mc);

                        if (tl == 1 && t[0] == '.') {
                            continue;
                        }

                        if (!class_name) {
                            class_name = n00b_string_from_raw(t, (int64_t)tl);
                        }
                        else if (!method_name) {
                            method_name = n00b_string_from_raw(t, (int64_t)tl);
                        }
                    }
                }

                is_method = class_name && method_name;
            }
            else if (name_node && a->sym_kind
                     && n00b_unicode_str_eq(a->sym_kind, r"function")) {
                // Check if this is a bare method (elided class name).
                // Look for "method" token in the parent func-def node.
                size_t pnc = n00b_pt_num_children(nc->node);

                for (size_t pi = 0; pi < pnc; pi++) {
                    n00b_parse_tree_t *pc = n00b_pt_get_child(nc->node, pi);

                    if (n00b_pt_is_token(pc)) {
                        const char *t = n00b_pt_token_text(pc);
                        size_t      tl = n00b_pt_token_text_len(pc);

                        if (tl == 6 && memcmp(t, "method", 6) == 0) {
                            // Bare method — find the sole class in this module.
                            method_name = n00b_tree_extract_first_identifier(name_node);

                            // Scan ALL scopes for the single class.
                            n00b_sym_entry_t *sole_class = NULL;
                            int class_count = 0;
                            n00b_namespace_t *ns = &ctx->symtab->namespaces[0];

                            for (int32_t si = 0; si < ns->all_count; si++) {
                                n00b_scope_t *sc = ns->all_scopes[si];

                                n00b_sym_entry_t *e;
                                for (e = sc->first_in_scope;
                                     e; e = e->next_in_scope) {
                                    if (e->kind == N00B_SYM_TYPEDEF
                                        && e->exposed_scope
                                        && e->exposed_scope->scope_tag
                                        && n00b_unicode_str_eq(e->exposed_scope->scope_tag, r"class")) {
                                        sole_class = e;
                                        class_count++;
                                    }
                                }
                            }

                            if (class_count == 1 && sole_class && method_name) {
                                class_name = sole_class->name;
                                is_method = true;
                            }
                            else if (method_name && ctx->diag) {
                                n00b_diag_push(ctx->diag,
                                    N00B_DIAG_ERROR, N00B_STAGE_ANNOT,
                                    r"A001",
                                    class_count == 0
                                        ? r"bare method requires a class in the module"
                                        : r"bare method is ambiguous: multiple classes; use ClassName.method()",
                                    n00b_diag_span_from_node(nc->node));
                            }

                            break;
                        }
                    }
                    else {
                        // Check inside func-kind NT for "method" token.
                        if (n00b_pt_is_nt(pc, "func-kind")) {
                            n00b_parse_tree_t *ft = n00b_pt_first_token(pc);

                            if (ft) {
                                const char *ft_text = n00b_pt_token_text(ft);
                                size_t ft_len = n00b_pt_token_text_len(ft);

                                if (ft_len == 6 && memcmp(ft_text, "method", 6) == 0) {
                                    method_name = n00b_tree_extract_first_identifier(name_node);

                                    n00b_sym_entry_t *sole_class = NULL;
                                    int class_count = 0;

                                    // Scan ALL scopes (class sym may be in a sibling scope).
                                    n00b_namespace_t *ns = &ctx->symtab->namespaces[0];

                                    for (int32_t si = 0; si < ns->all_count; si++) {
                                        n00b_scope_t *sc = ns->all_scopes[si];

                                        n00b_sym_entry_t *e;
                                        for (e = sc->first_in_scope;
                                             e; e = e->next_in_scope) {
                                            if (e->kind == N00B_SYM_TYPEDEF
                                                && e->exposed_scope
                                                && e->exposed_scope->scope_tag
                                                && n00b_unicode_str_eq(e->exposed_scope->scope_tag, r"class")) {
                                                sole_class = e;
                                                class_count++;
                                            }
                                        }
                                    }
                                    if (class_count == 1 && sole_class && method_name) {
                                        class_name = sole_class->name;
                                        is_method = true;
                                    }
                                    else if (method_name && ctx->diag) {
                                        n00b_diag_push(ctx->diag,
                                            N00B_DIAG_ERROR, N00B_STAGE_ANNOT,
                                            r"A001",
                                            class_count == 0
                                                ? r"bare method requires a class in the module"
                                                : r"bare method is ambiguous: multiple classes; use ClassName.method()",
                                            n00b_diag_span_from_node(nc->node));
                                    }
                                }
                            }

                            break;
                        }
                    }
                }
            }

            // Build the symbol name: mangled for methods, plain otherwise.
            n00b_string_t *sym_name;

            if (is_method) {
                // Mangle: ClassName$methodName
                size_t mlen = class_name->u8_bytes + 1 + method_name->u8_bytes;
                char *mbuf = n00b_alloc_array(char, mlen + 1);
                memcpy(mbuf, class_name->data, class_name->u8_bytes);
                mbuf[class_name->u8_bytes] = '$';
                memcpy(mbuf + class_name->u8_bytes + 1,
                       method_name->data, method_name->u8_bytes);
                mbuf[mlen] = '\0';
                sym_name = n00b_string_from_raw(mbuf, (int64_t)mlen);
            }
            else {
                sym_name = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();
            }

            if (sym_name && sym_name->u8_bytes > 0) {
                n00b_sym_kind_t sym_kind = N00B_SYM_VARIABLE;

                if (a->sym_kind && a->sym_kind->u8_bytes > 0) {
                    if (n00b_unicode_str_eq(a->sym_kind, r"param")) {
                        sym_kind = N00B_SYM_PARAM;
                    }
                    else if (n00b_unicode_str_eq(a->sym_kind, r"function")) {
                        sym_kind = N00B_SYM_FUNCTION;
                    }
                    else if (n00b_unicode_str_eq(a->sym_kind, r"module")) {
                        sym_kind = N00B_SYM_MODULE;
                    }
                }

                nc->last_sym = n00b_symtab_add(ctx->symtab,
                                                n00b_string_empty(),
                                                sym_name,
                                                sym_kind,
                                                nc->node);

                // Mark as method and register in class scope.
                if (is_method) {
                    nc->last_sym->is_method = true;

                    // Find the class sym and register in its exposed_scope.
                    n00b_sym_entry_t *class_sym = n00b_symtab_lookup_any(
                        ctx->symtab, n00b_string_empty(), class_name);

                    if (class_sym && class_sym->exposed_scope) {
                        // Add a method entry (unmangled name) directly
                        // into the class's exposed_scope chain so that
                        // compute_class_layout and method dispatch can
                        // find it.
                        n00b_sym_entry_t *method_sym = n00b_alloc(n00b_sym_entry_t);
                        method_sym->name           = method_name;
                        method_sym->kind           = N00B_SYM_FUNCTION;
                        method_sym->is_method      = true;
                        method_sym->decl_node      = nc->node;

                        if (ctx->tc_ctx) {
                            method_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                        }

                        // Prepend to the class scope's linked list.
                        n00b_scope_t *cs = class_sym->exposed_scope;
                        method_sym->next_in_scope = cs->first_in_scope;
                        cs->first_in_scope        = method_sym;
                    }
                    else if (ctx->diag) {
                        n00b_diag_push(ctx->diag,
                            N00B_DIAG_ERROR, N00B_STAGE_ANNOT,
                            r"A002",
                            r"method declared on unknown or non-class type",
                            n00b_diag_span_from_node(nc->node));
                    }
                }

                // Stamp mutability: params default to immutable,
                // variables inherit from the enclosing <variable-decl>.
                if (sym_kind == N00B_SYM_PARAM) {
                    nc->last_sym->mutability = N00B_SYM_IMMUTABLE;
                }
                else {
                    nc->last_sym->mutability = ctx->current_mutability;
                }

                // Stamp visibility if set by a preceding @visibility.
                if (ctx->current_visibility) {
                    nc->last_sym->visibility = ctx->current_visibility;
                    ctx->current_visibility  = NULL;
                }

                if (nc->last_sym->shadowed && ctx->shadowed_entries) {
                    n00b_list_push(*ctx->shadowed_entries, nc->last_sym);
                }

                if (ctx->tc_ctx) {
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                }

                // If @declares($name, $type) has a type_ref, set type_node
                // so type binding can bind the explicit annotation.
                if (a->type_ref.kind == N00B_ROLE_BY_INDEX
                        ? a->type_ref.index >= 0
                        : a->type_ref.name != NULL) {
                    n00b_parse_tree_t *tnode
                        = n00b_tree_resolve_child_ref(
                            ctx->grammar, nc->node, a->type_ref);

                    if (tnode) {
                        nc->last_sym->type_node = tnode;
                    }
                }

                bind_sym_type(ctx, nc->last_sym);

                if (sym_kind == N00B_SYM_PARAM && ctx->params) {
                    n00b_list_push(*ctx->params, nc->last_sym);
                }
            }

            break;
        }

        case N00B_ANNOT_TYPE_DECL: {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);
            n00b_string_t *sym_name
                = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();

            if (sym_name && sym_name->u8_bytes > 0) {
                nc->last_sym = n00b_symtab_add(ctx->symtab,
                                                n00b_string_empty(),
                                                sym_name,
                                                N00B_SYM_TYPEDEF,
                                                nc->node);

                if (ctx->tc_ctx) {
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                }

                // Set type_node so type binding translates the name child
                // into a named (prim) type and unifies it with type_var.
                nc->last_sym->type_node = name_node;
                bind_sym_type(ctx, nc->last_sym);
            }

            break;
        }

        case N00B_ANNOT_ADT: {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);
            n00b_string_t *tag_name
                = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();

            if (tag_name && tag_name->u8_bytes > 0) {
                n00b_sym_entry_t *sym = n00b_symtab_add(
                    ctx->symtab,
                    r"tag",
                    tag_name,
                    N00B_SYM_TAG,
                    nc->node);

                n00b_string_t *kind = a->adt_kind;

                if (a->adt_keyword_ref.kind == N00B_ROLE_BY_INDEX
                        ? a->adt_keyword_ref.index >= 0
                        : a->adt_keyword_ref.name != NULL) {
                    n00b_parse_tree_t *kw_node
                        = n00b_tree_resolve_child_ref(
                            ctx->grammar, nc->node, a->adt_keyword_ref);

                    if (kw_node) {
                        n00b_string_t *kw
                            = n00b_tree_extract_first_identifier(kw_node);

                        if (kw && kw->u8_bytes > 0) {
                            kind = kw;
                        }
                    }
                }

                sym->adt_kind = kind;
                nc->last_sym  = sym;

                if (ctx->tc_ctx) {
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                }
            }

            break;
        }

        case N00B_ANNOT_FIELD: {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);
            n00b_string_t *field_name
                = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();

            if (field_name && field_name->u8_bytes > 0) {
                n00b_parse_tree_t *type_node
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->type_ref);

                n00b_sym_entry_t *sym = n00b_symtab_add(
                    ctx->symtab,
                    n00b_string_empty(),
                    field_name,
                    N00B_SYM_VARIABLE,
                    nc->node);

                sym->is_field  = true;
                sym->type_node = type_node;
                nc->last_sym   = sym;

                if (ctx->tc_ctx) {
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                }

                bind_sym_type(ctx, nc->last_sym);
            }

            break;
        }

        case N00B_ANNOT_METHOD: {
            n00b_parse_tree_t *name_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);
            n00b_string_t *method_name
                = name_node
                    ? n00b_tree_extract_first_identifier(name_node)
                    : n00b_string_empty();

            if (method_name && method_name->u8_bytes > 0) {
                n00b_parse_tree_t *type_node
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->type_ref);

                n00b_sym_entry_t *sym = n00b_symtab_add(
                    ctx->symtab,
                    n00b_string_empty(),
                    method_name,
                    N00B_SYM_FUNCTION,
                    nc->node);

                sym->is_method = true;
                sym->type_node = type_node;
                nc->last_sym   = sym;

                if (ctx->tc_ctx) {
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                }

                bind_sym_type(ctx, nc->last_sym);
            }

            break;
        }

        case N00B_ANNOT_RECORD: {
            // @record($fields) — create a structural record type from
            // the named-field-list child. Extracts field names, builds
            // a structural type name, creates a sym entry + scope.
            n00b_parse_tree_t *field_list_node
                = n00b_tree_resolve_child_ref(
                    ctx->grammar, nc->node, a->name_ref);

            if (!field_list_node) {
                break;
            }

            // DFS to collect field names from named-field nodes.
            const char *field_names[32];
            int32_t     n_fields = 0;

            n00b_parse_tree_t *fstack[64];
            int                fsp = 0;

            fstack[fsp++] = field_list_node;

            while (fsp > 0 && n_fields < 32) {
                n00b_parse_tree_t *fc = fstack[--fsp];

                if (!fc || n00b_tree_is_leaf(fc)) {
                    continue;
                }

                n00b_nt_node_t *fpn = &n00b_tree_node_value(fc);

                // Check if this is a named-field node by looking for
                // a ":" token among children.
                bool is_named_field = false;
                size_t fnc_count = n00b_tree_num_children(fc);

                for (size_t fi = 0; fi < fnc_count; fi++) {
                    n00b_parse_tree_t *fcc = n00b_tree_child(fc, fi);

                    if (n00b_tree_is_leaf(fcc)) {
                        n00b_token_info_t *ti = n00b_parse_node_token(fcc);

                        if (ti && n00b_option_is_set(ti->value)) {
                            n00b_string_t *tv = n00b_option_get(ti->value);

                            if (tv->u8_bytes == 1 && tv->data[0] == ':') {
                                is_named_field = true;
                                break;
                            }
                        }
                    }
                }

                if (is_named_field) {
                    // Extract the field name (first token before ':').
                    n00b_string_t *fname = n00b_tree_extract_first_identifier(fc);

                    if (fname && fname->u8_bytes > 0) {
                        char *nbuf = n00b_alloc_array(char, fname->u8_bytes + 1);
                        memcpy(nbuf, fname->data, fname->u8_bytes);
                        nbuf[fname->u8_bytes] = '\0';
                        field_names[n_fields++] = nbuf;
                    }

                    continue;
                }

                // Push children for further search.
                for (size_t fi = fnc_count; fi > 0; fi--) {
                    if (fsp < 64) {
                        fstack[fsp++] = n00b_tree_child(fc, fi - 1);
                    }
                }
            }

            if (n_fields == 0) {
                break;
            }

            // Build structural name: $$tuple$field1$field2$...
            size_t name_len = 7; // "$$tuple"

            for (int32_t fi = 0; fi < n_fields; fi++) {
                name_len += 1 + strlen(field_names[fi]); // "$" + name
            }

            char *tname_buf = n00b_alloc_array(char, name_len + 1);
            char *tp = tname_buf;

            memcpy(tp, "$$tuple", 7);
            tp += 7;

            for (int32_t fi = 0; fi < n_fields; fi++) {
                *tp++ = '$';
                size_t fl = strlen(field_names[fi]);
                memcpy(tp, field_names[fi], fl);
                tp += fl;
            }

            *tp = '\0';

            n00b_string_t *tname = n00b_string_from_raw(tname_buf,
                                                          (int64_t)name_len);

            // Check if this type already exists.
            n00b_sym_entry_t *existing = n00b_symtab_lookup_any(
                ctx->symtab, n00b_string_empty(), tname);

            if (!existing) {
                // Create the typedef sym entry.
                nc->last_sym = n00b_symtab_add(ctx->symtab,
                                                n00b_string_empty(),
                                                tname,
                                                N00B_SYM_TYPEDEF,
                                                nc->node);

                if (ctx->tc_ctx) {
                    // Create a named Prim type for the structural tuple
                    // so that field access can resolve via type name lookup.
                    n00b_tc_type_t *prim = n00b_tc_prim(ctx->tc_ctx, tname);
                    nc->last_sym->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                    n00b_tc_unify(ctx->tc_ctx, nc->last_sym->type_var, prim);
                    // Back-link so codegen can find the sym entry from the type.
                    n00b_tc_find(nc->last_sym->type_var)->user_data = nc->last_sym;
                }

                // Set the node's type to the structural type so that
                // @assigns unification propagates it to the variable.
                if (ctx->node_types) {
                    uintptr_t key = (uintptr_t)nc->node;
                    n00b_dict_put(ctx->node_types, key, nc->last_sym->type_var);
                }

                // Create a scope for the fields.
                n00b_symtab_push_scope(ctx->symtab, n00b_string_empty(),
                                        tname);

                for (int32_t fi = 0; fi < n_fields; fi++) {
                    n00b_string_t *fn = n00b_string_from_cstr(field_names[fi]);
                    n00b_sym_entry_t *fe = n00b_symtab_add(
                        ctx->symtab, n00b_string_empty(), fn,
                        N00B_SYM_VARIABLE, NULL);

                    if (ctx->tc_ctx) {
                        fe->type_var = n00b_tc_fresh_var(ctx->tc_ctx);
                    }
                }

                n00b_scope_t *scope = n00b_symtab_current_scope(
                    ctx->symtab, n00b_string_empty());
                nc->last_sym->exposed_scope = scope;

                n00b_symtab_pop_scope(ctx->symtab, n00b_string_empty());
            }
            else {
                nc->last_sym = existing;
            }

            break;
        }

        default:
            break;
        }
    }

    // ---- Pass B: symbol-reading annotations (last_sym guaranteed set) ----

    for (size_t ai = 0; ai < nc->annot_count; ai++) {
        n00b_annotation_t *a = nc->annots[ai];

        switch (a->kind) {
        case N00B_ANNOT_TYPE: {
            if (nc->last_sym) {
                n00b_parse_tree_t *type_node
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->name_ref);

                if (type_node) {
                    nc->last_sym->type_node = type_node;
                    bind_sym_type(ctx, nc->last_sym);
                }
            }

            break;
        }

        case N00B_ANNOT_EXPOSES: {
            if (nc->last_sym && nc->pn->scope) {
                nc->last_sym->exposed_scope = nc->pn->scope;
            }

            break;
        }

        case N00B_ANNOT_INHERITS: {
            if (nc->last_sym) {
                n00b_parse_tree_t *name_node
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->name_ref);
                n00b_string_t *parent_name
                    = name_node
                        ? n00b_tree_extract_first_identifier(name_node)
                        : NULL;

                if (parent_name && parent_name->u8_bytes > 0) {
                    nc->last_sym->inherits_name = parent_name;
                }
            }

            break;
        }

        case N00B_ANNOT_IMPLEMENTS: {
            if (nc->last_sym) {
                n00b_parse_tree_t *name_node
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->name_ref);
                n00b_string_t *iface_name
                    = name_node
                        ? n00b_tree_extract_first_identifier(name_node)
                        : NULL;

                if (iface_name && iface_name->u8_bytes > 0) {
                    if (!nc->last_sym->implements) {
                        // Canonical idiom: build the scan-info-threaded
                        // lvalue first, then struct-copy into the heap
                        // shell.
                        n00b_list_t(n00b_string_t *) impl_lst
                            = n00b_list_new(n00b_string_t *);
                        nc->last_sym->implements
                            = n00b_alloc(n00b_list_t(n00b_string_t *));
                        *nc->last_sym->implements = impl_lst;
                    }

                    n00b_list_push(*nc->last_sym->implements, iface_name);
                }
            }

            break;
        }

        case N00B_ANNOT_VISIBILITY: {
            // Save visibility in the walk context; it will be stamped
            // on the next symbol created by @declares.
            if (a->visibility_spec && a->visibility_spec->u8_bytes > 0) {
                ctx->current_visibility = a->visibility_spec;
            }

            break;
        }

        case N00B_ANNOT_STATIC: {
            if (nc->last_sym) {
                nc->last_sym->is_static = true;
            }

            break;
        }

        case N00B_ANNOT_ABSTRACT: {
            if (nc->last_sym) {
                nc->last_sym->is_abstract = true;
            }

            break;
        }

        case N00B_ANNOT_LITERAL: {
            n00b_string_t *type_name = a->op_kind;
            n00b_tc_type_t *lit_type = NULL;

            if (type_name && type_name->u8_bytes > 0 && ctx->tc_ctx && ctx->node_types) {
                lit_type = n00b_tc_lookup_prim(ctx->tc_ctx, type_name);
            }

            if (ctx->tc_ctx && ctx->translate_type_spec
                && (a->type_ref.kind == N00B_ROLE_BY_INDEX
                        ? a->type_ref.index >= 0
                        : a->type_ref.name != NULL)) {
                n00b_parse_tree_t *tspec
                    = n00b_tree_resolve_child_ref(
                        ctx->grammar, nc->node, a->type_ref);

                if (tspec) {
                    n00b_tc_type_t *mod_type = ctx->translate_type_spec(
                        ctx->tc_ctx, ctx->grammar, tspec);

                    if (mod_type) {
                        lit_type = mod_type;
                    }
                }
            }

            if (lit_type && ctx->node_types) {
                uintptr_t key = (uintptr_t)nc->node;
                n00b_dict_put(ctx->node_types, key, lit_type);
            }

            break;
        }

        default:
            break;
        }
    }
}
