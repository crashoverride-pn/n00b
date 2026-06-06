#pragma once

#include "n00b.h"
#include "display/render/canvas.h"

/**
 * @brief Prepare terminal state for a canvas-backed terminal session.
 * @param canvas Canvas whose renderer capabilities determine ownership.
 */
extern bool n00b_display_terminal_setup(n00b_canvas_t *canvas);

/**
 * @brief Restore terminal state saved by `n00b_display_terminal_setup`.
 *
 * Idempotent. Safe to call during normal runtime shutdown when the caller
 * does not know whether display setup completed.
 */
extern void n00b_display_terminal_restore(void);

/**
 * @brief Tear down a canvas-backed terminal session.
 * @param canvas Canvas passed to `n00b_display_terminal_setup`.
 */
extern void n00b_display_terminal_teardown(n00b_canvas_t *canvas);
