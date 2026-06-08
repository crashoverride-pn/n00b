#pragma once
/** @file string_ops.h
 *  @brief Unicode-aware string operations: concatenation, slicing, search,
 *         replace, split, trim, pad, and more.
 *
 *  All grapheme-aware operations use grapheme cluster indices (not byte or
 *  codepoint indices) unless explicitly noted.  Functions that produce new
 *  strings accept an optional allocator keyword argument.
 *
 *  ### Related modules
 *
 *  - `strings/string_convert.h` -- string ↔ integer/hex/file conversion
 *  - `strings/string_style.h` -- style attachment on `n00b_string_t`
 *  - `unicode/segmentation.h` -- grapheme cluster boundary detection
 *  - `unicode/linebreak.h` -- line break algorithm used by `n00b_unicode_str_wrap()`
 *  - `unicode/casemap.h` -- case folding for `n00b_unicode_str_eq()` / `n00b_unicode_str_find()`
 */

#include "text/unicode/types_ext.h"
#include "adt/array.h"


// ===================================================================
// Error codes for string operations
// ===================================================================

#define N00B_ERR_STR_INVALID_ESCAPE (-1) /**< Malformed escape sequence */
#define N00B_ERR_STR_ESCAPE_EOS     (-2) /**< Unexpected end of string in escape */
#define N00B_ERR_STR_BAD_HEX        (-3) /**< Invalid hex digit in escape */

// ===================================================================
// Concatenation
// ===================================================================

/** @brief Raw string segment for allocation-efficient concatenation.
 *
 *  @c data may be nullptr only when @c bytes is zero.  @c codepoints may be
 *  set to -1 when the caller does not already know the UTF-8 codepoint count.
 */
typedef struct n00b_unicode_str_part_t {
    const char *data;
    size_t      bytes;
    int64_t     codepoints;
} n00b_unicode_str_part_t;

/** @brief Concatenate two strings.
 *  @param a  First string.
 *  @param b  Second string.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing @p a followed by @p b.
 */
n00b_string_t *n00b_unicode_str_cat(n00b_string_t *a, n00b_string_t *b)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Concatenate an array of strings.
 *  @param parts  Array of strings.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing all parts concatenated in order.
 */
n00b_string_t *n00b_unicode_str_cat_many(n00b_array_t(n00b_string_t *) parts)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Concatenate raw string segments.
 *  @param parts  Raw string segments.
 *  @param count  Number of segments.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing all parts concatenated in order.
 */
n00b_string_t *n00b_unicode_str_cat_parts(const n00b_unicode_str_part_t *parts,
                                          size_t count)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Join an array of strings with a separator.
 *  @param sep    The separator string inserted between parts.
 *  @param parts  Array of strings.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string with all parts joined by @p sep.
 */
n00b_string_t *n00b_unicode_str_join(n00b_string_t *sep,
                                    n00b_array_t(n00b_string_t *) parts)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Slicing (grapheme-aware: indices are grapheme cluster positions)
// ===================================================================

/** @brief Extract a substring by grapheme cluster indices.
 *  @param s      The source string.
 *  @param start  Start grapheme index (negative counts from end).
 *  @param end    End grapheme index, exclusive (negative counts from end).
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing the selected grapheme clusters.
 */
n00b_string_t *n00b_unicode_str_slice(n00b_string_t *s, int32_t start,
                                     int32_t end)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Extract a single grapheme cluster by index.
 *  @param s      The source string.
 *  @param index  Grapheme index (negative counts from end).
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing the grapheme cluster at @p index.
 */
n00b_string_t *n00b_unicode_str_grapheme_at(n00b_string_t *s, int32_t index)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Byte-level slicing
// ===================================================================

/** @brief Extract a substring by byte offsets.
 *  @param s           The source string.
 *  @param byte_start  Start byte offset (inclusive).
 *  @param byte_end    End byte offset (exclusive).
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing bytes [byte_start, byte_end).
 */
n00b_string_t *n00b_unicode_str_slice_bytes(n00b_string_t *s,
                                           uint32_t byte_start,
                                           uint32_t byte_end)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Search
// ===================================================================

/** @brief Find an occurrence of @p needle in @p haystack.
 *
 *  By default both strings are NFC-normalized before comparison.
 *  Additional keyword options control direction, case folding, and
 *  accent stripping.
 *
 *  When any transform is enabled, the returned byte offset is into the
 *  **transformed** haystack (which may differ from the original byte
 *  positions).
 *
 *  @param haystack    The string to search in.
 *  @param needle      The string to search for.
 *  @kw reverse        Search from the right (default: false).
 *  @kw normalize      NFC-normalize before search (default: true).
 *  @kw case_sensitive Case-sensitive match (default: true).  When false,
 *                     both strings are Unicode case-folded.
 *  @kw strip_marks    Strip combining marks / accents (default: false).
 *  @return An option containing the byte offset, or none if not found.
 *
 *  @note Defaults to `.normalize = true` (differs from `n00b_unicode_str_eq`
 *        which defaults to false).
 *
 *  @post When transforms are active (normalize, case-fold, strip marks),
 *        the byte offset refers to the internal transformed copy.  Use
 *        `n00b_unicode_str_contains()` for presence checks with transforms,
 *        or disable transforms when you need sliceable byte offsets.
 */
n00b_option_t(int32_t) n00b_unicode_str_find(n00b_string_t *haystack,
                                             n00b_string_t *needle)
    _kargs {
        bool reverse         = false;
        bool normalize       = true;
        bool case_sensitive  = true;
        bool strip_marks     = false;
    };

/** @brief Test whether @p haystack contains @p needle.
 *
 *  Accepts the same keyword options as @c n00b_unicode_str_find.
 *
 *  @param haystack    The string to search in.
 *  @param needle      The string to search for.
 *  @return true if @p needle is found in @p haystack.
 */
#define n00b_unicode_str_contains(h, n, ...) \
    n00b_option_is_set(n00b_unicode_str_find((h), (n), ##__VA_ARGS__))

/** @deprecated Use `n00b_unicode_str_find(h, n, .reverse = true)`. */
#define n00b_unicode_str_rfind(h, n, ...) \
    n00b_unicode_str_find((h), (n), .reverse = true, ##__VA_ARGS__)

/** @brief Test whether a string starts with a given prefix.
 *  @param s       The string to test.
 *  @param prefix  The prefix to check.
 *  @return true if @p s starts with @p prefix.
 */
bool n00b_unicode_str_starts_with(n00b_string_t *s, n00b_string_t *prefix);

/** @brief Test whether a string ends with a given suffix.
 *  @param s       The string to test.
 *  @param suffix  The suffix to check.
 *  @return true if @p s ends with @p suffix.
 */
bool n00b_unicode_str_ends_with(n00b_string_t *s, n00b_string_t *suffix);

// ===================================================================
// Replace
// ===================================================================

/** @brief Replace the first occurrence of @p old_s with @p new_s.
 *  @param s      The source string.
 *  @param old_s  The substring to find.
 *  @param new_s  The replacement string.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string with the first occurrence replaced.
 */
n00b_string_t *n00b_unicode_str_replace(n00b_string_t *s, n00b_string_t *old_s,
                                       n00b_string_t *new_s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Replace all occurrences of @p old_s with @p new_s.
 *  @param s      The source string.
 *  @param old_s  The substring to find.
 *  @param new_s  The replacement string.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string with all occurrences replaced.
 */
n00b_string_t *n00b_unicode_str_replace_all(n00b_string_t *s,
                                           n00b_string_t *old_s,
                                           n00b_string_t *new_s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Split
// ===================================================================

/** @brief Split a string by a separator.
 *  @param s      The string to split.
 *  @param sep    The separator string.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return An array of strings.
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_split(n00b_string_t *s,
                                                    n00b_string_t *sep)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Split a string at word boundaries (UAX #29).
 *  @param s      The string to split.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return An array of strings.
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_split_words(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Split a string into individual grapheme clusters.
 *  @param s      The string to split.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return An array of strings.
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_split_graphemes(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Split a string into lines (at CR, LF, or CRLF).
 *  @param s      The string to split.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return An array of strings (without line terminators).
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_split_lines(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Trim
// ===================================================================

/** @brief Remove leading and/or trailing Unicode whitespace.
 *  @param s  The string to trim.
 *  @kw left       Trim leading whitespace (default: true).
 *  @kw right      Trim trailing whitespace (default: true).
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new trimmed string.
 */
n00b_string_t *n00b_unicode_str_trim(n00b_string_t *s)
    _kargs {
        bool              left      = true;
        bool              right     = true;
        n00b_allocator_t *allocator = nullptr;
    };

/** @deprecated Use `n00b_unicode_str_trim(s, .right = false)` */
#define n00b_unicode_str_trim_left(s, ...) \
    n00b_unicode_str_trim((s), .right = false, ##__VA_ARGS__)

/** @deprecated Use `n00b_unicode_str_trim(s, .left = false)` */
#define n00b_unicode_str_trim_right(s, ...) \
    n00b_unicode_str_trim((s), .left = false, ##__VA_ARGS__)

// ===================================================================
// Comparison
// ===================================================================

/** @brief Compare two strings (like strcmp), with optional normalization.
 *  @param a  First string.
 *  @param b  Second string.
 *  @kw normalize       NFC-normalize before comparing (default: false).
 *  @kw case_sensitive  Case-sensitive comparison (default: true).
 *  @kw strip_marks     Strip combining marks before comparing (default: false).
 *  @return Negative, zero, or positive.
 *
 *  @note Defaults to `.normalize = false` (same as `n00b_unicode_str_eq`).
 */
int n00b_unicode_str_cmp(n00b_string_t *a, n00b_string_t *b)
    _kargs {
        bool normalize      = false;
        bool case_sensitive  = true;
        bool strip_marks     = false;
    };

/** @brief Test whether two strings are equal.
 *  @param a  First string.
 *  @param b  Second string.
 *  @kw normalize       NFC-normalize before comparing (default: false).
 *  @kw case_sensitive  Case-sensitive comparison (default: true).
 *  @kw strip_marks     Strip combining marks before comparing (default: false).
 *  @return true if the strings are equal under the requested options.
 *
 *  @note Defaults to `.normalize = false` (differs from `n00b_unicode_str_find`
 *        which defaults to true).
 */
bool n00b_unicode_str_eq(n00b_string_t *a, n00b_string_t *b)
    _kargs {
        bool normalize      = false;
        bool case_sensitive  = true;
        bool strip_marks     = false;
    };

/** @deprecated Use `n00b_unicode_str_eq(a, b, .normalize = true)` */
#define n00b_unicode_str_eq_nfc(a, b) \
    n00b_unicode_str_eq((a), (b), .normalize = true)

/** @deprecated Use `n00b_unicode_str_eq(a, b, .case_sensitive = false)` */
#define n00b_unicode_str_eq_casefold(a, b) \
    n00b_unicode_str_eq((a), (b), .case_sensitive = false)

// ===================================================================
// Width-aware padding/truncation
// ===================================================================

/** String alignment constants for `n00b_unicode_str_pad`. */
enum {
    N00B_STR_ALIGN_LEFT   = 0, /**< Left-align text (pad on right). */
    N00B_STR_ALIGN_RIGHT  = 1, /**< Right-align text (pad on left). */
    N00B_STR_ALIGN_CENTER = 2, /**< Center text (pad both sides). */
};

/** @brief Pad/align a string within a given display width.
 *  @param s      The string to pad.
 *  @param width  Target display width in columns.
 *  @kw align      Alignment: `N00B_STR_ALIGN_LEFT` (default), `_RIGHT`, or
 *                 `_CENTER`.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @kw fill       Fill codepoint (default: space U+0020).
 *  @return A new string padded to @p width columns.
 */
n00b_string_t *n00b_unicode_str_pad(n00b_string_t *s, int32_t width)
    _kargs {
        int              align     = N00B_STR_ALIGN_LEFT;
        n00b_allocator_t *allocator = nullptr;
        n00b_codepoint_t  fill      = ' ';
    };

/** @deprecated Use `n00b_unicode_str_pad(s, w, .align = N00B_STR_ALIGN_RIGHT)` */
#define n00b_unicode_str_pad_left(s, w, ...) \
    n00b_unicode_str_pad((s), (w), .align = N00B_STR_ALIGN_RIGHT, ##__VA_ARGS__)

/** @deprecated Use `n00b_unicode_str_pad(s, w)` */
#define n00b_unicode_str_pad_right(s, w, ...) \
    n00b_unicode_str_pad((s), (w), .align = N00B_STR_ALIGN_LEFT, ##__VA_ARGS__)

/** @deprecated Use `n00b_unicode_str_pad(s, w, .align = N00B_STR_ALIGN_CENTER)` */
#define n00b_unicode_str_center(s, w, ...) \
    n00b_unicode_str_pad((s), (w), .align = N00B_STR_ALIGN_CENTER, ##__VA_ARGS__)

/** @brief Truncate a string to fit within a maximum display width.
 *  @param s          The string to truncate.
 *  @param max_width  Maximum display width in columns.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @kw ellipsis   Ellipsis string appended when truncation occurs
 *                 (default: "...").
 *  @return A new string truncated with an ellipsis if it exceeds
 *          @p max_width.
 */
n00b_string_t *n00b_unicode_str_truncate(n00b_string_t *s, int32_t max_width)
    _kargs { n00b_allocator_t *allocator = nullptr;
             const char *ellipsis = "..."; };

// ===================================================================
// Repeat
// ===================================================================

/** @brief Repeat a string a given number of times.
 *  @param s      The string to repeat.
 *  @param count  Number of repetitions.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string containing @p s repeated @p count times.
 */
n00b_string_t *n00b_unicode_str_repeat(n00b_string_t *s, uint32_t count)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Reverse (grapheme-aware)
// ===================================================================

/** @brief Reverse a string at the grapheme cluster level.
 *  @param s  The string to reverse.
 *  @kw allocator  Optional allocator (defaults to the runtime allocator).
 *  @return A new string with grapheme clusters in reverse order.
 */
n00b_string_t *n00b_unicode_str_reverse(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Escape / Unescape
// ===================================================================

/** @brief Escape non-printable and special characters in a string.
 *
 *  Produces named escapes (`\n`, `\t`, etc.), `\xHH` for non-printable
 *  bytes, `\uHHHH` for BMP codepoints, and `\UHHHHHHHH` for supplementary
 *  codepoints.  Quotes and backslashes are always escaped.
 *
 *  @param s  The string to escape.
 *  @kw allocator  Optional allocator.
 *  @return A new string with escape sequences inserted.
 */
n00b_string_t *n00b_unicode_str_escape(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

/** @brief Interpret escape sequences in a string.
 *
 *  Handles all named escapes (`\n`, `\t`, `\a`, etc.) plus hex (`\xHH`),
 *  Unicode (`\uHHHH`, `\UHHHHHHHH`) escapes.
 *
 *  @param s  The string containing escape sequences.
 *  @kw allocator  Optional allocator.
 *  @return Ok(string) on success, or an error code on malformed escapes.
 *  @post Error codes: `N00B_ERR_STR_INVALID_ESCAPE`,
 *        `N00B_ERR_STR_ESCAPE_EOS`, `N00B_ERR_STR_BAD_HEX`.
 */
n00b_result_t(n00b_string_t *) n00b_unicode_str_unescape(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Codepoint access
// ===================================================================

/** @brief Get the codepoint at a given codepoint index.
 *
 *  Supports negative indexing (Python-style: -1 = last codepoint).
 *
 *  @param s      The string.
 *  @param index  Codepoint index (negative counts from end).
 *  @return The codepoint at that index, or none if out of bounds.
 */
n00b_option_t(n00b_codepoint_t) n00b_unicode_str_codepoint_at(
    n00b_string_t *s, int64_t index);

// ===================================================================
// Deep copy
// ===================================================================

/** @brief Deep-copy a string (allocates a new data buffer).
 *  @param s  The string to copy.
 *  @kw allocator  Optional allocator.
 *  @return A new string with independently allocated data.
 */
n00b_string_t *n00b_unicode_str_copy(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Split-and-crop
// ===================================================================

/** @brief Split a string by separator, then truncate each part to a width.
 *  @param s      The string to split.
 *  @param sep    The separator string.
 *  @param width  Maximum display width for each part.
 *  @kw allocator  Optional allocator.
 *  @return An array of truncated strings.
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_split_and_crop(n00b_string_t *s,
    n00b_string_t *sep, int32_t width)
    _kargs { n00b_allocator_t *allocator = nullptr; };

// ===================================================================
// Text wrapping
// ===================================================================

/** @brief Wrap a string to a given column width using Unicode line break rules.
 *
 *  Uses `n00b_unicode_linebreak_wrap()` to determine break positions,
 *  then slices at each break.  The first line uses the full @p width;
 *  subsequent lines use `width - hang`.
 *
 *  When no valid soft-break exists before the column limit, the text is
 *  hard-wrapped (forced break mid-word) unless @p no_hard_wrap is set.
 *
 *  @param s  The string to wrap.
 *  @kw width         Target line width in columns (default: 80).
 *  @kw hang          Hanging indent in columns for continuation lines
 *                    (default: 0).
 *  @kw no_hard_wrap  If true, never force-break inside a word (default:
 *                    false).
 *  @kw allocator     Optional allocator.
 *  @return An array of line strings.
 */
n00b_array_t(n00b_string_t *) n00b_unicode_str_wrap(n00b_string_t *s)
    _kargs { int32_t width = 80; int32_t hang = 0; bool no_hard_wrap = false;
             n00b_allocator_t *allocator = nullptr; };
