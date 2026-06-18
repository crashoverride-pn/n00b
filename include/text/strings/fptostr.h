#pragma once
/** @file fptostr.h
 *  @brief Grisu2-based double-to-string conversion.
 *
 *  Converts IEEE 754 doubles to their shortest decimal string
 *  representation using the Grisu2 algorithm.  Handles special values
 *  (NaN, ±Inf, ±0) and writes directly to a caller-provided buffer.
 *
 *  Based on the fpconv implementation by Andreas Samoljuk (MIT license),
 *  which is itself an implementation of Florian Loitsch's Grisu2 algorithm.
 *
 *  ### Related modules
 *
 *  - `strings/fmt_numbers.h` -- higher-level float formatting that uses this
 *
 *  @see https://github.com/night-shift/fpconv
 *  @see http://florian.loitsch.com/publications/dtoa-pldi2010.pdf
 */

#include <stdint.h>

/**
 * @brief Convert a double to its shortest decimal string representation.
 *
 * Uses the Grisu2 algorithm.  Handles ±0, NaN, ±Inf.
 *
 * @param d     The value to convert.
 * @param dest  Output buffer; must hold at least 24 bytes.
 * @return      Number of characters written (not NUL-terminated).
 *
 * @pre  `dest` points to a buffer of at least 24 bytes.
 * @post `dest[0..return)` contains the decimal representation.
 */
int n00b_fptostr(double d, char dest[24]);

/**
 * @brief Raw Grisu2 shortest significant digits of `|d|`.
 *
 * Writes the shortest decimal significand of the magnitude (no sign, no decimal
 * point, NOT NUL-terminated) plus the decimal exponent. The value's magnitude
 * is `(digits as integer) * 10^(*k_out)`, so the leading digit's place value is
 * `10^(*k_out + n - 1)`.
 *
 * @param d      Value (sign ignored; the caller handles it).
 * @param digits Output buffer, at least 18 bytes.
 * @param k_out  Receives the decimal exponent.
 * @return Significant-digit count n (>= 1), or 0 for zero / NaN / Inf.
 */
int n00b_fptostr_digits(double d, char digits[18], int *k_out);
