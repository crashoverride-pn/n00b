#pragma once

/**
 * @file text/qrcode/qrcode.h
 * @brief QR code generation (model 2), capped at versions 1-10.
 *
 * Encodes a string (typically a URL) into a QR code module matrix and
 * renders it for a terminal. Built on the reusable Reed-Solomon encoder
 * (`crypto/reed_solomon.h`) for error correction.
 *
 * # Scope / deliberate limits
 *
 * - Versions 1-10 only (symbol sizes 21x21 .. 57x57). Input that does
 *   not fit at the requested ECC level returns #N00B_QR_ERR_TOO_LARGE
 *   rather than silently growing; the cap is easy to raise later by
 *   extending the spec tables.
 * - Two encoding modes: alphanumeric (when every character is in the QR
 *   alphanumeric set) and 8-bit byte mode (everything else, including
 *   any lowercase URL). Mode is chosen for the whole string; no
 *   multi-segment optimization.
 * - Default error correction level is M (~15%).
 *
 * # Symbol prefix
 *
 * `n00b_qr_*` / `N00B_QR_*`.
 */

#include <n00b.h>
#include "adt/result.h"
#include "text/strings/theme.h"
#include "display/render/plane.h"

/**
 * @brief Error-correction level. Values are dense table indices
 *        (NOT the 2-bit format-info codes, which are assigned
 *        separately during matrix generation).
 */
typedef enum {
    N00B_QR_ECC_L = 0,  /**< ~7% recovery. */
    N00B_QR_ECC_M = 1,  /**< ~15% recovery (default). */
    N00B_QR_ECC_Q = 2,  /**< ~25% recovery. */
    N00B_QR_ECC_H = 3,  /**< ~30% recovery. */
} n00b_qr_ecc_t;

/** @brief QR generation error codes (negative, errno-disjoint). */
typedef enum {
    N00B_QR_OK              = 0,
    N00B_QR_ERR_EMPTY_INPUT = -1,  /**< Input string was empty. */
    N00B_QR_ERR_TOO_LARGE   = -2,  /**< Does not fit in v1-10 at level. */
    N00B_QR_ERR_BAD_ECC     = -3,  /**< ecc level out of range. */
} n00b_qr_err_t;

/**
 * @brief A generated QR code: the final masked module matrix.
 *
 * @var n00b_qr_t::version  QR version 1-10.
 * @var n00b_qr_t::size     Modules per side (`4 * version + 17`).
 * @var n00b_qr_t::ecc      Error-correction level used.
 * @var n00b_qr_t::mask     Mask pattern applied (0-7).
 * @var n00b_qr_t::modules  Row-major `size * size` grid; 1 = dark,
 *                          0 = light. Excludes the quiet zone.
 */
typedef struct {
    int32_t       version;
    int32_t       size;
    n00b_qr_ecc_t ecc;
    int32_t       mask;
    uint8_t      *modules;
} n00b_qr_t;

/**
 * @brief Human-readable description of a QR error code.
 * @param err  A code from #n00b_qr_err_t.
 * @return A static styled string describing @p err.
 */
extern n00b_string_t *n00b_qr_err_str(n00b_err_t err);

/**
 * @brief Encode a string into a QR code matrix.
 *
 * Chooses alphanumeric or byte mode, the smallest fitting version
 * (1-10), computes Reed-Solomon ECC, places + masks the matrix, and
 * writes format/version information.
 *
 * @param data  The data to encode (e.g. a URL). Must be non-empty.
 * @kw ecc        Error-correction level (default #N00B_QR_ECC_M).
 * @kw allocator  Allocator (nullptr => runtime default).
 * @return ok with a new #n00b_qr_t, or err with a #n00b_qr_err_t code.
 */
extern n00b_result_t(n00b_qr_t *)
n00b_qr_encode(n00b_string_t *data) _kargs
{
    n00b_qr_ecc_t     ecc       = N00B_QR_ECC_M;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Render a QR matrix into a render-system plane.
 *
 * Each module is drawn as a filled rectangle (`n00b_plane_fill_rect`) in
 * render-system pixel coordinates, colored via theme **palette indices**
 * (the backend resolves them to RGB for the active theme). Modules are
 * @kw module_w columns wide so they read roughly square in a cell
 * terminal. Light modules and the quiet zone are filled with the light
 * color. The returned plane composites onto any canvas (a TUI, or the
 * inline-ANSI backend for a CLI).
 *
 * When @kw half_block is true (default), two module rows are packed into
 * one cell row using the upper-half-block glyph (foreground = top module,
 * background = bottom module), halving the height — each module reads
 * roughly square in one cell. When false, each module is its own cell,
 * two columns wide for square aspect.
 *
 * @param qr  The QR code to render.
 * @kw quiet       Quiet-zone width in modules (default 4).
 * @kw half_block  Pack two module rows per cell (default true).
 * @kw dark        Palette slot for dark modules (default text-primary).
 * @kw light       Palette slot for light modules (default background).
 * @kw allocator   Allocator (nullptr => runtime default).
 * @return A plane sized for the chosen packing.
 */
extern n00b_plane_t *
n00b_qr_render(n00b_qr_t *qr) _kargs
{
    int64_t           quiet      = 4;
    bool              half_block = true;
    n00b_palette_ix_t dark       = N00B_PAL_TEXT_PRIMARY;
    n00b_palette_ix_t light      = N00B_PAL_BACKGROUND;
    n00b_allocator_t *allocator  = nullptr;
};

/**
 * @brief One-shot: encode @p url and render it to a plane.
 *
 * @param url  The string/URL to encode.
 * @kw ecc         Error-correction level (default #N00B_QR_ECC_M).
 * @kw quiet       Quiet-zone width in modules (default 4).
 * @kw half_block  Pack two module rows per cell (default true).
 * @kw dark        Palette slot for dark modules (default text-primary).
 * @kw light       Palette slot for light modules (default background).
 * @kw allocator   Allocator (nullptr => runtime default).
 * @return ok with a plane, or err with a #n00b_qr_err_t code.
 */
extern n00b_result_t(n00b_plane_t *)
n00b_qr_terminal(n00b_string_t *url) _kargs
{
    n00b_qr_ecc_t     ecc        = N00B_QR_ECC_M;
    int64_t           quiet      = 4;
    bool              half_block = true;
    n00b_palette_ix_t dark       = N00B_PAL_TEXT_PRIMARY;
    n00b_palette_ix_t light      = N00B_PAL_BACKGROUND;
    n00b_allocator_t *allocator  = nullptr;
};
