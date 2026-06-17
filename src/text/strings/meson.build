# String formatting, styling, conversion, ANSI escapes, markdown.

n00b_text_strings_src = files(
    'string_ops.c',
    'string_convert.c',
    'fptostr.c',
    'fmt_numbers.c',
    'fp_format.c',
    'ansi.c',
    'markdown.c',
    'style_ops.c',
    'string_style.c',
    'style_registry.c',
    'rich_desc.c',
    'format_spec.c',
    'format.c',
    'md_render.c',
    'md_lines.c',
    'theme.c',
)

# WP-011 Phase 5c: the style registry's default named-style / role
# tables are expressed as `d{...}` static dict literals — that
# translation unit (`style_registry_defaults.c`) must be compiled
# with the static-init helper flag, so it lives in
# `n00b_dict_aware_src` and is included only in the full libn00b.
n00b_text_strings_dict_aware_src = files(
    'style_registry_defaults.c',
)

# Paired bootstrap-only stub for the dict-aware defaults file.  The
# bootstrap libn00b (linked into the static-init helper itself) cannot
# use dict literals, so it ships a no-op
# `n00b_str_registry_install_defaults`.  The helper never renders rich
# text, so an empty defaults set is functionally correct there.  This
# stub is NOT included in the full libn00b — the real implementation
# in `n00b_text_strings_dict_aware_src` defines the same symbol.
n00b_text_strings_bootstrap_only_src = files(
    'style_registry_defaults_stub.c',
)
