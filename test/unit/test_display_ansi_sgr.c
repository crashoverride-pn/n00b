#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "n00b.h"
#include "core/runtime.h"
#include "internal/display/ansi_sgr.h"

typedef struct {
    char   buf[512];
    size_t len;
} cap_t;

static void
capture_emit(void *vctx, const char *data, size_t len)
{
    cap_t *cap = vctx;
    assert(cap->len + len < sizeof(cap->buf));
    memcpy(cap->buf + cap->len, data, len);
    cap->len += len;
    cap->buf[cap->len] = '\0';
}

static void
test_emit_reset(void)
{
    cap_t cap = {};
    n00b_display_ansi_emit_reset(capture_emit, &cap);
    assert(strcmp(cap.buf, "\033[0m") == 0);
    printf("  [PASS] ansi sgr reset\n");
}

static void
test_emit_style_direct_rgb(void)
{
    cap_t cap = {};
    n00b_text_style_t style = {
        .bold      = N00B_TRI_YES,
        .underline = N00B_TRI_YES,
        .fg_rgb    = n00b_color_make(0x112233),
        .bg_rgb    = n00b_color_make(0x445566),
    };

    n00b_display_ansi_emit_style(&style, capture_emit, &cap);

    assert(strstr(cap.buf, "\033[0") == cap.buf);
    assert(strstr(cap.buf, ";1") != nullptr);
    assert(strstr(cap.buf, ";4") != nullptr);
    assert(strstr(cap.buf, ";38;2;17;34;51") != nullptr);
    assert(strstr(cap.buf, ";48;2;68;85;102") != nullptr);
    assert(cap.buf[cap.len - 1] == 'm');
    printf("  [PASS] ansi sgr style direct rgb\n");
}

static void
test_emit_style_null_means_reset(void)
{
    cap_t cap = {};
    n00b_display_ansi_emit_style(nullptr, capture_emit, &cap);
    assert(strcmp(cap.buf, "\033[0m") == 0);
    printf("  [PASS] ansi sgr null style reset\n");
}

int
main(int argc, char **argv)
{
    unsetenv("NO_COLOR");

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running display ANSI SGR tests...\n");
    test_emit_reset();
    test_emit_style_direct_rgb();
    test_emit_style_null_means_reset();

    printf("Display ANSI SGR tests passed.\n");
    n00b_shutdown();
    return 0;
}
