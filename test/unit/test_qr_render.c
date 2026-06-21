/** @file test/unit/test_qr_render.c — QR renderer (render-system plane).
 *
 *  Validates that n00b_qr_render draws the QR into a plane using the
 *  render system's fill-rect draw commands, in both packings:
 *
 *    [1] Default half-block packing: height halves (two module rows per
 *        cell); one fill-rect per output cell.
 *    [2] Full-cell packing (half_block=false): each module is one cell,
 *        two columns wide; one background fill + one fill per dark module.
 *    [3] quiet kwarg changes geometry.
 *    [4] n00b_qr_terminal round-trips encode + render; bad input errors.
 */

#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/qrcode/qrcode.h"
#include "display/render/plane.h"
#include "display/render/draw_cmd.h"

static int32_t
count_dark(n00b_qr_t *qr)
{
    int32_t n = 0;
    for (int32_t i = 0; i < qr->size * qr->size; i++) {
        n += qr->modules[i] & 1;
    }
    return n;
}

static void
assert_all_fill_rects(n00b_plane_t *p)
{
    for (n00b_isize_t i = 0; i < p->draw_list.count; i++) {
        assert(p->draw_list.cmds[i].type == N00B_DRAW_FILL_RECT);
    }
}

static void
test_half_block_default(void)
{
    n00b_result_t(n00b_qr_t *) er = n00b_qr_encode(r"HELLO WORLD");
    assert(n00b_result_is_ok(er));
    n00b_qr_t *qr = n00b_result_get(er);
    assert(qr->version == 1 && qr->size == 21);

    n00b_plane_t *p = n00b_qr_render(qr, .quiet = 4);

    int32_t total = qr->size + 8;       // 29
    int32_t h     = (total + 1) / 2;    // 15
    assert(p->width == total);
    assert(p->height == h);

    // One fill-rect per output cell.
    assert((int32_t)p->draw_list.count == total * h);
    assert_all_fill_rects(p);

    printf("  [PASS] half-block packing (%dx%d cells)\n", p->width, p->height);
}

static void
test_full_cell(void)
{
    n00b_result_t(n00b_qr_t *) er = n00b_qr_encode(r"HELLO WORLD");
    assert(n00b_result_is_ok(er));
    n00b_qr_t *qr = n00b_result_get(er);

    n00b_plane_t *p = n00b_qr_render(qr, .quiet = 4, .half_block = false);

    int32_t total = qr->size + 8;     // 29
    assert(p->width == total * 2);    // 58
    assert(p->height == total);       // 29

    // Background fill + one fill per dark module.
    assert((int32_t)p->draw_list.count == 1 + count_dark(qr));
    assert_all_fill_rects(p);

    printf("  [PASS] full-cell packing (%dx%d cells)\n", p->width, p->height);
}

static void
test_quiet_kwarg(void)
{
    n00b_result_t(n00b_qr_t *) er = n00b_qr_encode(r"HELLO WORLD");
    assert(n00b_result_is_ok(er));
    n00b_qr_t *qr = n00b_result_get(er);

    n00b_plane_t *p = n00b_qr_render(qr, .quiet = 0);
    assert(p->width == qr->size);
    assert(p->height == (qr->size + 1) / 2);

    printf("  [PASS] quiet kwarg\n");
}

static void
test_terminal(void)
{
    n00b_result_t(n00b_plane_t *) ok = n00b_qr_terminal(r"https://example.com/r/abc");
    assert(n00b_result_is_ok(ok));
    assert(n00b_result_get(ok) != nullptr);

    n00b_result_t(n00b_plane_t *) bad = n00b_qr_terminal(r"");
    assert(n00b_result_is_err(bad));
    assert(n00b_result_get_err(bad) == N00B_QR_ERR_EMPTY_INPUT);

    printf("  [PASS] terminal one-shot + error path\n");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    test_half_block_default();
    test_full_cell();
    test_quiet_kwarg();
    test_terminal();

    fprintf(stderr, "All QR renderer tests passed.\n");
    return 0;
}
