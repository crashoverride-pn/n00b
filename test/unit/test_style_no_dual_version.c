#include "adt/option.h"
#include "core/runtime.h"
#include "text/strings/style_registry.h"
#include "text/strings/text_style.h"

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    auto em_opt = n00b_str_style_lookup("em");
    if (!n00b_option_is_set(em_opt)) {
        return 10;
    }
    n00b_text_style_t *em = n00b_option_get(em_opt);
    if (em->italic != N00B_TRI_YES) {
        return 11;
    }

    auto code_opt = n00b_str_role_lookup("@code");
    if (!n00b_option_is_set(code_opt)) {
        return 20;
    }
    n00b_text_style_t *code = n00b_option_get(code_opt);
    if (code->font_hint != N00B_FONT_MONO) {
        return 21;
    }

    return 0;
}
