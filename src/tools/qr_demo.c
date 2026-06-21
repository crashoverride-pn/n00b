// qr_demo — encode a sample one-time-password (otpauth://) URL and print
// the QR through the render system: n00b_qr_render draws the modules as
// filled cells in a plane; the inline-ANSI backend composites it to
// stdout with theme colors. Run on a color terminal to see / scan it.

#include "n00b.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "display/render/backend.h"
#include "display/render/canvas.h"
#include "display/render/plane.h"
#include "text/qrcode/qrcode.h"

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    n00b_string_t *url =
        r"otpauth://totp/ACME%20Co:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30";

    n00b_printf("[|b|]otpauth URL:[|/b|] [|#|]\n", url);

    n00b_result_t(n00b_plane_t *) pr = n00b_qr_terminal(url);
    if (n00b_result_is_err(pr)) {
        n00b_eprintf("[|red|]encode failed:[|/|] [|#|]\n",
                     n00b_qr_err_str(n00b_result_get_err(pr)));
        return 1;
    }
    n00b_plane_t *p = n00b_result_get(pr);

    n00b_printf("[|#|]x[|#|] cells\n\n", (int64_t)p->width, (int64_t)p->height);

    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_canvas_t  *canvas
        = n00b_new_kargs(n00b_canvas_t,
                         canvas,
                         .vtable = &n00b_renderer_ansi_inline,
                         .output = (n00b_conduit_topic_t(n00b_buffer_t *) *)
                             rt->stdout_topic);
    n00b_canvas_resize(canvas, p->height, p->width);
    n00b_canvas_add_plane(canvas, p);
    n00b_canvas_render(canvas);
    n00b_canvas_flush(canvas);
    n00b_canvas_destroy(canvas);

    return 0;
}
