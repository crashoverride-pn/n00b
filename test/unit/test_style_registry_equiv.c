#include "test_unicode_helpers.h"
#include "text/strings/style_registry.h"

typedef enum {
    STYLE_KIND_NAME,
    STYLE_KIND_ROLE,
} style_entry_kind_t;

typedef struct {
    const char         *name;
    style_entry_kind_t kind;
    n00b_text_style_t  expected;
} expected_style_entry_t;

#define BASE_STYLE                                                       \
    .font_index = -1,                                                    \
    .fg_palette_ix = -1,                                                 \
    .bg_palette_ix = -1

static const expected_style_entry_t expected_styles[] = {
    { "em", STYLE_KIND_NAME, { BASE_STYLE, .italic = N00B_TRI_YES } },
    { "em1", STYLE_KIND_NAME, { BASE_STYLE, .italic = N00B_TRI_YES } },
    { "em2", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "em3", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES,
                                .italic = N00B_TRI_YES } },
    { "h1", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES,
                               .text_case = N00B_TEXT_CASE_UPPER } },
    { "h2", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "h3", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES,
                               .italic = N00B_TRI_YES } },
    { "hexdump.offset", STYLE_KIND_NAME, { BASE_STYLE, .dim = N00B_TRI_YES } },
    { "hexdump.ascii", STYLE_KIND_NAME, { BASE_STYLE, .bold = N00B_TRI_YES } },

    { "@code", STYLE_KIND_ROLE, { BASE_STYLE, .font_hint = N00B_FONT_MONO } },
    { "@mono", STYLE_KIND_ROLE, { BASE_STYLE, .font_hint = N00B_FONT_MONO } },
    { "@heading", STYLE_KIND_ROLE, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "@body", STYLE_KIND_ROLE, { BASE_STYLE } },
    { "@error", STYLE_KIND_ROLE, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "@success", STYLE_KIND_ROLE, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "@muted", STYLE_KIND_ROLE, { BASE_STYLE, .dim = N00B_TRI_YES } },
    { "@link", STYLE_KIND_ROLE, { BASE_STYLE, .underline = N00B_TRI_YES } },
    { "@label", STYLE_KIND_ROLE, { BASE_STYLE, .bold = N00B_TRI_YES } },
    { "@button", STYLE_KIND_ROLE, { BASE_STYLE, .bold = N00B_TRI_YES,
                                    .reverse = N00B_TRI_YES } },
    { "@input", STYLE_KIND_ROLE, { BASE_STYLE, .underline = N00B_TRI_YES } },
};

static void
assert_style_equal(const char *name, const n00b_text_style_t *actual,
                   const n00b_text_style_t *expected)
{
    ASSERT(actual != nullptr);
    ASSERT_EQ(actual->bold, expected->bold);
    ASSERT_EQ(actual->italic, expected->italic);
    ASSERT_EQ(actual->underline, expected->underline);
    ASSERT_EQ(actual->double_underline, expected->double_underline);
    ASSERT_EQ(actual->strikethrough, expected->strikethrough);
    ASSERT_EQ(actual->reverse, expected->reverse);
    ASSERT_EQ(actual->dim, expected->dim);
    ASSERT_EQ(actual->blink, expected->blink);
    ASSERT_EQ(actual->text_case, expected->text_case);
    ASSERT_EQ(actual->font_hint, expected->font_hint);
    ASSERT_EQ(actual->font_index, expected->font_index);
    ASSERT_EQ(actual->fg_palette_ix, expected->fg_palette_ix);
    ASSERT_EQ(actual->bg_palette_ix, expected->bg_palette_ix);
    ASSERT_EQ(actual->fg_rgb, expected->fg_rgb);
    ASSERT_EQ(actual->bg_rgb, expected->bg_rgb);
    ASSERT_EQ(actual->font_size, expected->font_size);
    (void)name;
}

TEST(test_default_registry_snapshot)
{
    size_t resolved = 0;

    for (size_t i = 0; i < sizeof(expected_styles) / sizeof(expected_styles[0]); i++) {
        const expected_style_entry_t *entry = &expected_styles[i];

        if (entry->kind == STYLE_KIND_NAME) {
            auto opt = n00b_str_style_lookup(entry->name);
            ASSERT(n00b_option_is_set(opt));
            assert_style_equal(entry->name, n00b_option_get(opt), &entry->expected);
        }
        else {
            auto opt = n00b_str_role_lookup(entry->name);
            ASSERT(n00b_option_is_set(opt));
            assert_style_equal(entry->name, n00b_option_get(opt), &entry->expected);
        }

        resolved++;
    }

    ASSERT_EQ(resolved, sizeof(expected_styles) / sizeof(expected_styles[0]));
}

TEST(test_default_registry_aliases_are_field_equal)
{
    auto em_opt   = n00b_str_style_lookup("em");
    auto em1_opt  = n00b_str_style_lookup("em1");
    auto code_opt = n00b_str_role_lookup("@code");
    auto mono_opt = n00b_str_role_lookup("@mono");

    ASSERT(n00b_option_is_set(em_opt));
    ASSERT(n00b_option_is_set(em1_opt));
    ASSERT(n00b_option_is_set(code_opt));
    ASSERT(n00b_option_is_set(mono_opt));

    assert_style_equal("em1", n00b_option_get(em1_opt), n00b_option_get(em_opt));
    assert_style_equal("@mono", n00b_option_get(mono_opt), n00b_option_get(code_opt));
}

TEST(test_default_registry_absent_names_stay_absent)
{
    ASSERT(!n00b_option_is_set(n00b_str_style_lookup("style.registry.missing")));
    ASSERT(!n00b_option_is_set(n00b_str_role_lookup("@style.registry.missing")));
}

static void
run_tests(void)
{
    /*
     * TEST_MAIN runs full n00b_init(), which applies the default theme on top of
     * named registry defaults. Reset the registry so this baseline covers the
     * defaults installer and the two builtin dicts that WP-009 migrates.
     */
    n00b_str_registry_init();

    RUN_TEST(test_default_registry_snapshot);
    RUN_TEST(test_default_registry_aliases_are_field_equal);
    RUN_TEST(test_default_registry_absent_names_stay_absent);
}

TEST_MAIN()
