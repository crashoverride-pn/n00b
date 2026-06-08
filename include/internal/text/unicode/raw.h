#pragma once
/** @file raw.h
 *  @brief Internal `_raw` variants of public unicode functions.
 *
 *  These preserve the original `(char *, len)` signatures for use by internal
 *  callers (security.c, collation.c, string_ops.c, idna.c, etc.).
 *  Public API wrappers extract `s.data`, `s.u8_bytes` from `n00b_string_t`.
 *
 *  This header must be included AFTER the relevant public unicode headers
 *  in each .c file, since it references types defined there.
 */

#include "text/unicode/types.h"
#include "n00b.h"

// Forward declarations for opaque types used below.
typedef struct n00b_unicode_break_iter_s n00b_unicode_break_iter_t;

// ===========================================================================
// Encoding
// ===========================================================================

bool n00b_unicode_utf8_validate(const char *src, uint32_t len);
int64_t n00b_unicode_utf8_count_codepoints_raw(const char *src, uint32_t len);

// ===========================================================================
// Properties
// ===========================================================================

int32_t n00b_unicode_display_width_raw(const char *data, int64_t len);

// ===========================================================================
// Normalization
// ===========================================================================

n00b_string_t *n00b_unicode_nfc_raw(n00b_allocator_t *allocator,
                                    const char *data, int64_t len);
n00b_string_t *n00b_unicode_nfd_raw(n00b_allocator_t *allocator,
                                    const char *data, int64_t len);
n00b_string_t *n00b_unicode_nfkc_raw(n00b_allocator_t *allocator,
                                     const char *data, int64_t len);
n00b_string_t *n00b_unicode_nfkd_raw(n00b_allocator_t *allocator,
                                     const char *data, int64_t len);
bool n00b_unicode_is_nfc_raw(const char *data, int64_t len);
bool n00b_unicode_is_nfd_raw(const char *data, int64_t len);

// ===========================================================================
// Case mapping
// ===========================================================================

n00b_string_t *n00b_unicode_casefold_raw(n00b_allocator_t *allocator,
                                         const char *data, int64_t len);
n00b_string_t *n00b_unicode_toupper_raw(n00b_allocator_t *allocator,
                                          const char *data, int64_t len,
                                          const char *locale);
n00b_string_t *n00b_unicode_tolower_raw(n00b_allocator_t *allocator,
                                          const char *data, int64_t len,
                                          const char *locale);
n00b_string_t *n00b_unicode_totitle_raw(n00b_allocator_t *allocator,
                                          const char *data, int64_t len,
                                          const char *locale);
int n00b_unicode_casecmp_raw(const char *a, int64_t a_len,
                             const char *b, int64_t b_len);

// ===========================================================================
// Segmentation
// ===========================================================================

n00b_unicode_break_iter_t *n00b_unicode_grapheme_iter_raw(const char *data,
                                                          int64_t len);
n00b_unicode_break_iter_t *n00b_unicode_word_iter_raw(const char *data,
                                                      int64_t len);
n00b_unicode_break_iter_t *n00b_unicode_sentence_iter_raw(const char *data,
                                                          int64_t len);
uint32_t n00b_unicode_grapheme_count_raw(const char *data, int64_t len);

// ===========================================================================
// Linebreak
// ===========================================================================

void n00b_unicode_linebreaks_raw(const char *data, int64_t len,
                                 n00b_unicode_lb_action_t *out);
uint32_t *n00b_unicode_linebreak_wrap_raw(const char *data, int64_t len,
                                          int width, int hang,
                                          bool no_hard_wrap,
                                          uint32_t *num_breaks);

// ===========================================================================
// String ops (used internally by string_ops.c and others)
// ===========================================================================

int32_t n00b_unicode_str_find_raw(const char *h, int64_t hlen,
                                  const char *n, int64_t nlen);
int32_t n00b_unicode_str_rfind_raw(const char *h, int64_t hlen,
                                   const char *n, int64_t nlen);
bool n00b_unicode_str_contains_raw(const char *h, int64_t hlen,
                                   const char *n, int64_t nlen);
bool n00b_unicode_str_starts_with_raw(const char *data, int64_t len,
                                      const char *prefix, int64_t prefix_len);
bool n00b_unicode_str_ends_with_raw(const char *data, int64_t len,
                                    const char *suffix, int64_t suffix_len);
int n00b_unicode_str_cmp_raw(const char *a, int64_t a_len,
                             const char *b, int64_t b_len);
bool n00b_unicode_str_eq_raw(const char *a, int64_t a_len,
                             const char *b, int64_t b_len);

struct n00b_unicode_str_part_t;

n00b_string_t *n00b_unicode_str_cat_raw(n00b_allocator_t *allocator,
                                        const char *a, int64_t a_len,
                                        const char *b, int64_t b_len);

n00b_string_t *n00b_unicode_str_cat_parts_raw(
    n00b_allocator_t *allocator,
    const struct n00b_unicode_str_part_t *parts,
    size_t count);

n00b_string_t *n00b_unicode_str_replace_raw(n00b_allocator_t *allocator,
                                            const char *data, int64_t len,
                                            const char *old_s, int64_t old_len,
                                            const char *new_s,
                                            int64_t new_len);
n00b_string_t *n00b_unicode_str_replace_all_raw(n00b_allocator_t *allocator,
                                                const char *data, int64_t len,
                                                const char *old_s,
                                                int64_t old_len,
                                                const char *new_s,
                                                int64_t new_len);

n00b_string_t **n00b_unicode_str_split_raw(n00b_allocator_t *allocator,
                                          const char *data, int64_t len,
                                          const char *sep, int64_t sep_len,
                                          uint32_t *count);

n00b_string_t *n00b_unicode_str_slice_raw(n00b_allocator_t *allocator,
                                          const char *data, int64_t len,
                                          int32_t start, int32_t end);

// ===========================================================================
// Security
// ===========================================================================

n00b_string_t *n00b_unicode_skeleton_raw(n00b_allocator_t *allocator,
                                         const char *data, int64_t len);
bool n00b_unicode_is_confusable_raw(const char *a, int64_t a_len,
                                    const char *b, int64_t b_len);
n00b_unicode_restriction_level_t
n00b_unicode_script_restriction_raw(const char *data, int64_t len);
bool n00b_unicode_has_mixed_scripts_raw(const char *data, int64_t len);

// ===========================================================================
// Identifiers
// ===========================================================================

bool n00b_unicode_is_valid_identifier_raw(const char *data, int64_t len);

// ===========================================================================
// Emoji
// ===========================================================================

n00b_unicode_emoji_type_t
n00b_unicode_emoji_scan_raw(const char *data, int64_t len,
                            uint32_t byte_pos, uint32_t *seq_bytes);
