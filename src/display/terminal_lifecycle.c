#include <errno.h>

#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

#include "n00b.h"
#include "display/render/canvas.h"
#include "internal/display/backend_services.h"
#include "internal/display/diagnostics.h"
#include "internal/display/terminal_lifecycle.h"

#ifndef _WIN32
[[n00b::nomap]] static struct termios g_saved_termios;
static bool           g_termios_saved = false;
static bool           g_manages_tty   = false;
static bool           g_terminal_active = false;

static bool tty_write_raw(const char *seq);

static void
terminal_log_errno(const char *op, int err)
{
    n00b_display_diag_log(N00B_DISPLAY_DIAG_ERROR,
                          "terminal_lifecycle",
                          "%s failed err=%d",
                          op ? op : "terminal operation",
                          err);
}

static bool
tty_write_raw(const char *seq)
{
    size_t len = strlen(seq);
    while (len > 0) {
        ssize_t n = write(STDOUT_FILENO, seq, len);
        if (n < 0) {
            terminal_log_errno("write", errno ? errno : EIO);
            return false;
        }
        if (n == 0) {
            terminal_log_errno("write", EIO);
            return false;
        }
        seq += (size_t)n;
        len -= (size_t)n;
    }
    return true;
}
#endif

bool
n00b_display_terminal_setup(n00b_canvas_t *canvas)
{
#ifdef _WIN32
    (void)canvas;
    return true;
#else
    n00b_render_cap_t caps = n00b_display_backend_caps(canvas);
    g_manages_tty = (caps & N00B_RCAP_MANAGES_TTY) != 0;
    bool stdin_is_tty = isatty(STDIN_FILENO) != 0;

    if (stdin_is_tty) {
        if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
            g_termios_saved = true;
        }
        else {
            terminal_log_errno("tcgetattr", errno ? errno : EIO);
            return false;
        }
    }

    if (g_manages_tty || !stdin_is_tty) {
        g_terminal_active = g_manages_tty && stdin_is_tty;
        return true;
    }

    if (g_termios_saved) {
        struct termios raw = g_saved_termios;
        raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | ISIG);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
            terminal_log_errno("tcsetattr(raw)", errno ? errno : EIO);
            g_termios_saved = false;
            return false;
        }
    }
    g_terminal_active = true;

    n00b_canvas_alt_screen_enter(canvas);

    if (caps & N00B_RCAP_MOUSE) {
        if (!tty_write_raw("\033[?1000h")
            || !tty_write_raw("\033[?1002h")
            || !tty_write_raw("\033[?1006h")) {
            n00b_display_terminal_restore();
            return false;
        }
    }
    return true;
#endif
}

void
n00b_display_terminal_restore(void)
{
#ifdef _WIN32
    return;
#else
    if (!g_terminal_active && !g_termios_saved) {
        return;
    }

    if (g_terminal_active && !g_manages_tty) {
        tty_write_raw("\033[?1006l");
        tty_write_raw("\033[?1002l");
        tty_write_raw("\033[?1000l");
        tty_write_raw("\033[?25h");
        tty_write_raw("\033[0m");
        tty_write_raw("\033[?1049l");
    }

    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
        g_termios_saved = false;
    }

    g_manages_tty = false;
    g_terminal_active = false;
#endif
}

void
n00b_display_terminal_teardown(n00b_canvas_t *canvas)
{
    (void)canvas;
    n00b_display_terminal_restore();
}
