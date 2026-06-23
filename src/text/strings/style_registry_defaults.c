/**
 * @file style_registry_defaults.c
 * @brief Default templates + procedural installer for the rich-string
 *        style registry.
 *
 * This previously baked two `d{...}` static dict literals via ncc's
 * static-init helper (`--ncc-static-init-helper=PATH`,
 * `n00b_dict_aware_src`).  That baking helper spins at 100% CPU on this
 * file's large dict literal under `-O3`, so — pending the ncc branch
 * that removes baking — the defaults are registered procedurally at
 * runtime in `n00b_str_registry_install_defaults` below, which has no
 * dependency on the helper at all.
 *
 * The bootstrap libn00b still ships a no-op stub
 * (`style_registry_defaults_stub.c`) for the same
 * `n00b_str_registry_install_defaults` symbol; the helper never renders
 * rich text, so the empty default set is functionally correct there.
 *
 * Behavior is identical to the original procedural `register_defaults`
 * in `style_registry.c`: same style names, same field values.  The
 * runtime mutable dicts (`style_dict`, `role_dict` in
 * `style_registry.c`) copy each style via `n00b_str_style_copy` on
 * registration, so the static const templates here are never mutated.
 */

#include "text/strings/style_registry.h"
#include "text/strings/text_style.h"
#include "text/strings/style_ops.h"
#include "core/string.h"
#include "adt/dict.h"

// ===================================================================
// Static defaults — one `static const n00b_text_style_t` per template.
//
// `n00b_text_style_t` is "all-zero except for the int8 palette/font
// indices which use -1 as the unset sentinel".  Each definition below
// initializes the -1 sentinels explicitly so the templates round-trip
// through `n00b_str_style_is_empty` exactly the same way the old
// `n00b_str_style_new()`-built heap templates did.  Tristate /
// text_case / font_hint fields default to zero, which matches
// `N00B_TRI_UNSPECIFIED` / `N00B_TEXT_CASE_NONE` / `N00B_FONT_DEFAULT`
// respectively.
// ===================================================================

#define N00B_STYLE_DEFAULTS                                            \
    .font_index    = -1,                                               \
    .fg_palette_ix = -1,                                               \
    .bg_palette_ix = -1

// --- Named styles ---
static const n00b_text_style_t style_em = {
    N00B_STYLE_DEFAULTS,
    .italic = N00B_TRI_YES,
};

static const n00b_text_style_t style_em2 = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_em3 = {
    N00B_STYLE_DEFAULTS,
    .bold   = N00B_TRI_YES,
    .italic = N00B_TRI_YES,
};

static const n00b_text_style_t style_h1 = {
    N00B_STYLE_DEFAULTS,
    .bold      = N00B_TRI_YES,
    .text_case = N00B_TEXT_CASE_UPPER,
};

static const n00b_text_style_t style_h2 = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_h3 = {
    N00B_STYLE_DEFAULTS,
    .bold   = N00B_TRI_YES,
    .italic = N00B_TRI_YES,
};

static const n00b_text_style_t style_hd_offset = {
    N00B_STYLE_DEFAULTS,
    .dim = N00B_TRI_YES,
};

static const n00b_text_style_t style_hd_ascii = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

// --- Roles ---
static const n00b_text_style_t style_code = {
    N00B_STYLE_DEFAULTS,
    .font_hint = N00B_FONT_MONO,
};

static const n00b_text_style_t style_heading = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_body = {
    N00B_STYLE_DEFAULTS,
};

static const n00b_text_style_t style_error = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_success = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_muted = {
    N00B_STYLE_DEFAULTS,
    .dim = N00B_TRI_YES,
};

static const n00b_text_style_t style_link = {
    N00B_STYLE_DEFAULTS,
    .underline = N00B_TRI_YES,
};

static const n00b_text_style_t style_label = {
    N00B_STYLE_DEFAULTS,
    .bold = N00B_TRI_YES,
};

static const n00b_text_style_t style_button = {
    N00B_STYLE_DEFAULTS,
    .bold    = N00B_TRI_YES,
    .reverse = N00B_TRI_YES,
};

static const n00b_text_style_t style_input = {
    N00B_STYLE_DEFAULTS,
    .underline = N00B_TRI_YES,
};

// ===================================================================
// Defaults installer — invoked from `n00b_str_registry_init` in
// `style_registry.c` after the runtime mutable dicts are constructed.
//
// NOTE (temporary, pending the no-baking ncc branch): the named-style
// and role defaults are registered procedurally at runtime here rather
// than from baked `d{...}` static dict literals.  ncc's static-init
// "baking" helper spins at 100% CPU on this file's large dict literal
// under `-O3` (it bakes fine at `-O0`), so until the ncc branch that
// removes baking lands, we sidestep the helper entirely by building the
// registration table at init time.  `n00b_str_style_register` /
// `_role_register` copy each template (`n00b_str_style_copy`) on
// registration, so passing the `static const` template pointers is
// safe.  Behavior is identical to the dict-literal version: same names,
// same field values.  When the no-baking branch lands, this can return
// to the `d{...}` form (or stay as-is — it has no baking dependency).
// ===================================================================

void
n00b_str_registry_install_defaults(void)
{
    n00b_str_style_register("em", &style_em);
    n00b_str_style_register("em1", &style_em);
    n00b_str_style_register("em2", &style_em2);
    n00b_str_style_register("em3", &style_em3);
    n00b_str_style_register("h1", &style_h1);
    n00b_str_style_register("h2", &style_h2);
    n00b_str_style_register("h3", &style_h3);
    n00b_str_style_register("hexdump.offset", &style_hd_offset);
    n00b_str_style_register("hexdump.ascii", &style_hd_ascii);

    n00b_str_role_register("@code", &style_code);
    n00b_str_role_register("@mono", &style_code);
    n00b_str_role_register("@heading", &style_heading);
    n00b_str_role_register("@body", &style_body);
    n00b_str_role_register("@error", &style_error);
    n00b_str_role_register("@success", &style_success);
    n00b_str_role_register("@muted", &style_muted);
    n00b_str_role_register("@link", &style_link);
    n00b_str_role_register("@label", &style_label);
    n00b_str_role_register("@button", &style_button);
    n00b_str_role_register("@input", &style_input);
}
