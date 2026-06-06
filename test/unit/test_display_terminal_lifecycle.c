#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "display/render/backend.h"
#include "display/render/canvas.h"
#include "internal/display/terminal_lifecycle.h"

typedef struct {
    n00b_render_cap_t caps;
    int               alt_enter_calls;
} lifecycle_ctx_t;

static n00b_render_cap_t g_init_caps = N00B_RCAP_NONE;

#ifndef _WIN32
typedef struct {
    bool enabled;
    bool stdin_isatty;
    bool tcgetattr_ok;
    bool tcsetattr_fails;
    int  tcsetattr_errno;
    int  tcgetattr_calls;
    int  tcsetattr_calls;
    int  stdout_write_calls;
    int  mouse_enable_writes;
} tty_faults_t;

static tty_faults_t g_tty_faults;

extern int     __real_isatty(int fd);
extern int     __real_tcgetattr(int fd, struct termios *termios_p);
extern int     __real_tcsetattr(int fd,
                                int optional_actions,
                                const struct termios *termios_p);
extern ssize_t __real_write(int fd, const void *buf, size_t count);

static void
tty_faults_reset(void)
{
    memset(&g_tty_faults, 0, sizeof(g_tty_faults));
    g_tty_faults.stdin_isatty    = true;
    g_tty_faults.tcgetattr_ok    = true;
    g_tty_faults.tcsetattr_errno = EIO;
}

static bool
is_mouse_enable_write(const void *buf, size_t count)
{
    return (count == strlen("\033[?1000h")
            && memcmp(buf, "\033[?1000h", count) == 0)
        || (count == strlen("\033[?1002h")
            && memcmp(buf, "\033[?1002h", count) == 0)
        || (count == strlen("\033[?1006h")
            && memcmp(buf, "\033[?1006h", count) == 0);
}

int
__wrap_isatty(int fd)
{
    if (g_tty_faults.enabled && fd == STDIN_FILENO) {
        return g_tty_faults.stdin_isatty ? 1 : 0;
    }

    return __real_isatty(fd);
}

int
__wrap_tcgetattr(int fd, struct termios *termios_p)
{
    if (g_tty_faults.enabled && fd == STDIN_FILENO) {
        g_tty_faults.tcgetattr_calls++;
        if (!g_tty_faults.tcgetattr_ok) {
            errno = ENOTTY;
            return -1;
        }
        memset(termios_p, 0, sizeof(*termios_p));
        return 0;
    }

    return __real_tcgetattr(fd, termios_p);
}

int
__wrap_tcsetattr(int fd,
                 int optional_actions,
                 const struct termios *termios_p)
{
    if (g_tty_faults.enabled && fd == STDIN_FILENO) {
        (void)optional_actions;
        (void)termios_p;
        g_tty_faults.tcsetattr_calls++;
        if (g_tty_faults.tcsetattr_fails) {
            errno = g_tty_faults.tcsetattr_errno;
            return -1;
        }
        return 0;
    }

    return __real_tcsetattr(fd, optional_actions, termios_p);
}

ssize_t
__wrap_write(int fd, const void *buf, size_t count)
{
    if (g_tty_faults.enabled && fd == STDOUT_FILENO) {
        g_tty_faults.stdout_write_calls++;
        if (is_mouse_enable_write(buf, count)) {
            g_tty_faults.mouse_enable_writes++;
        }
        return (ssize_t)count;
    }

    return __real_write(fd, buf, count);
}
#endif

static void *
lifecycle_init(n00b_conduit_topic_t(n00b_buffer_t *) *output)
{
    (void)output;
    lifecycle_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert(ctx != nullptr);
    ctx->caps = g_init_caps;
    return ctx;
}

static void
lifecycle_destroy(void *vctx)
{
    free(vctx);
}

static n00b_render_cap_t
lifecycle_caps(void *vctx)
{
    lifecycle_ctx_t *ctx = vctx;
    return ctx->caps;
}

static n00b_render_size_t
lifecycle_size(void *vctx)
{
    (void)vctx;
    return (n00b_render_size_t){.rows = 4, .cols = 20, .cell_pixel_w = 1, .cell_pixel_h = 1};
}

static void
lifecycle_render_frame(void         *vctx,
                       n00b_rcell_t *cells,
                       n00b_isize_t  rows,
                       n00b_isize_t  cols,
                       n00b_rcell_t *prev_cells)
{
    (void)vctx;
    (void)cells;
    (void)rows;
    (void)cols;
    (void)prev_cells;
}

static void
lifecycle_flush(void *vctx)
{
    (void)vctx;
}

static void
lifecycle_render_planes(void                         *vctx,
                        const n00b_composite_entry_t *entries,
                        n00b_isize_t                  count,
                        n00b_isize_t                  total_rows,
                        n00b_isize_t                  total_cols,
                        n00b_text_style_t            *default_style,
                        n00b_render_cap_t             caps)
{
    (void)vctx;
    (void)entries;
    (void)count;
    (void)total_rows;
    (void)total_cols;
    (void)default_style;
    (void)caps;
}

static void
lifecycle_alt_enter(void *vctx)
{
    lifecycle_ctx_t *ctx = vctx;
    ctx->alt_enter_calls++;
}

static const n00b_renderer_vtable_t lifecycle_renderer = {
    .name             = "lifecycle_test",
    .version          = N00B_RENDERER_ABI_VERSION,
    .init             = lifecycle_init,
    .destroy          = lifecycle_destroy,
    .capabilities     = lifecycle_caps,
    .get_size         = lifecycle_size,
    .render_frame     = lifecycle_render_frame,
    .flush            = lifecycle_flush,
    .render_planes    = lifecycle_render_planes,
    .alt_screen_enter = lifecycle_alt_enter,
};

static void
test_lifecycle_with_managed_tty_backend(void)
{
    g_init_caps = N00B_RCAP_MANAGES_TTY;
    n00b_canvas_t *canvas = n00b_new_kargs(n00b_canvas_t, canvas, .vtable = &lifecycle_renderer);
    lifecycle_ctx_t *ctx = canvas->backend_ctx;

#ifndef _WIN32
    struct sigaction before = {};
    assert(sigaction(SIGINT, nullptr, &before) == 0);
#endif

    assert(n00b_display_terminal_setup(canvas));

#ifndef _WIN32
    struct sigaction after_setup = {};
    assert(sigaction(SIGINT, nullptr, &after_setup) == 0);
    assert(after_setup.sa_handler == before.sa_handler);
#endif

    n00b_display_terminal_teardown(canvas);

#ifndef _WIN32
    struct sigaction after_teardown = {};
    assert(sigaction(SIGINT, nullptr, &after_teardown) == 0);
    assert(after_teardown.sa_handler == before.sa_handler);
#endif

    assert(ctx->alt_enter_calls == 0);
    n00b_canvas_destroy(canvas);
    printf("  [PASS] lifecycle managed tty backend\n");
}

static void
test_lifecycle_with_external_tty_backend(void)
{
    g_init_caps = N00B_RCAP_MOUSE;
    n00b_canvas_t *canvas = n00b_new_kargs(n00b_canvas_t, canvas, .vtable = &lifecycle_renderer);
    lifecycle_ctx_t *ctx = canvas->backend_ctx;

    assert(n00b_display_terminal_setup(canvas));
    n00b_display_terminal_teardown(canvas);

#ifndef _WIN32
    if (isatty(STDIN_FILENO)) {
        assert(ctx->alt_enter_calls == 1);
    }
#endif

    n00b_canvas_destroy(canvas);
    printf("  [PASS] lifecycle external tty backend\n");
}

static void
test_lifecycle_raw_mode_failure_skips_terminal_controls(void)
{
#ifndef _WIN32
    tty_faults_reset();
    g_tty_faults.enabled = true;
    g_tty_faults.tcsetattr_fails = true;

    g_init_caps = N00B_RCAP_MOUSE;
    n00b_canvas_t *canvas = n00b_new_kargs(n00b_canvas_t, canvas, .vtable = &lifecycle_renderer);
    lifecycle_ctx_t *ctx = canvas->backend_ctx;

    bool setup_ok = n00b_display_terminal_setup(canvas);

    assert(!setup_ok);
    assert(g_tty_faults.tcgetattr_calls == 1);
    assert(g_tty_faults.tcsetattr_calls == 1);
    assert(ctx->alt_enter_calls == 0);
    assert(g_tty_faults.mouse_enable_writes == 0);

    n00b_display_terminal_teardown(canvas);
    g_tty_faults.enabled = false;

    n00b_canvas_destroy(canvas);
#endif
    printf("  [PASS] lifecycle raw-mode failure skips terminal controls\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running display terminal-lifecycle tests...\n");
    test_lifecycle_with_managed_tty_backend();
    test_lifecycle_with_external_tty_backend();
    test_lifecycle_raw_mode_failure_skips_terminal_controls();

    printf("Display terminal-lifecycle tests passed.\n");
    n00b_shutdown();
    return 0;
}
