#pragma once
/** @file fp_format.h
 *  @brief libc-free precision double formatting (fixed / scientific / general).
 *
 *  These replace the libc `snprintf("%.*f"/"%.*e"/"%.*g", …)` calls in the
 *  format-spec engine. libc float formatting descends through `dtoa`, which
 *  `malloc`s a Bigint; on an n00b off-libc worker thread (custom stack, not a
 *  registered pthread) that first libc `malloc` traps in libsystem_malloc's
 *  thread-cache init (`pthread_self` -> EXC_BREAKPOINT). All n00b float output
 *  to text must therefore stay off libc.
 *
 *  ### Two backends, chosen at link time (weak/strong)
 *
 *  - **Proper (default):** the Ryū `d2fixed`/`d2exp` algorithm — correctly
 *    rounded at arbitrary precision and malloc-free (integer math over a static
 *    table). Lives in the separate `n00b_fpfmt_ryu` link target (the 329 KB
 *    table is isolated there); its STRONG definitions override the weak
 *    fallbacks when the library is linked.
 *  - **Fallback:** a small Grisu2-shortest + decimal-round approximation,
 *    defined WEAK in libn00b core. Used only when `n00b_fpfmt_ryu` is NOT
 *    linked (size-constrained builds). Correct for typical display precisions;
 *    beyond the shortest significand it pads zeros rather than emitting the
 *    exact binary tail (a deliberate, documented approximation).
 *
 *  All three write a NUL-terminated string into @p buf and return the byte
 *  length written, or -1 if @p bufsz is too small.
 */

#include <stdbool.h>

/** @brief Fixed-point `%.*f`: `precision` digits after the decimal point. */
int n00b_fp_format_fixed(double value, int precision, char *buf, int bufsz);

/** @brief Scientific `%.*e` / `%.*E`: `precision` digits after the point. */
int n00b_fp_format_exp(double value, int precision, bool upper, char *buf,
                       int bufsz);

/** @brief General `%.*g` / `%.*G`: `precision` significant digits, shortest of
 *  fixed/scientific with trailing zeros trimmed (printf %g semantics). Built on
 *  the fixed/exp backends, so it inherits whichever (Ryū or fallback) is linked.
 */
int n00b_fp_format_general(double value, int precision, bool upper, char *buf,
                           int bufsz);
