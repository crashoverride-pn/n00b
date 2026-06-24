#pragma once
/** @file markdown.h
 *  @brief Parse markdown into an N-ary AST using md4c as backend.
 *
 *  Produces a typed tree of `n00b_md_node_t` nodes representing the
 *  parsed structure.  Only parsing is implemented — no rendering to
 *  tables or styled strings.
 *
 *  The md4c detail structs are stored opaquely in `n00b_md_detail_t.raw`
 *  (md4c.h is only included in the implementation file).  Text nodes
 *  store their content in `n00b_md_detail_t.text`.
 *
 *  ### Related modules
 *
 *  - `core/tree.h` -- typed N-ary tree macros
 *  - `core/string.h` -- `n00b_string_t` for text storage
 */

#include "text/unicode/types_ext.h"
#include "adt/tree.h"

// ===================================================================
// Node kind enumeration
// ===================================================================

/** @brief Classification of a markdown AST node.
 *
 *  Block values 0..15 align with md4c's `MD_BLOCKTYPE`.
 *  Span and text values are offset so the full enum is contiguous.
 */
typedef enum {
    // Block types (values match md4c's MD_BLOCKTYPE)
    N00B_MD_BLOCK_BODY,
    N00B_MD_BLOCK_QUOTE,
    N00B_MD_BLOCK_UL,
    N00B_MD_BLOCK_OL,
    N00B_MD_BLOCK_LI,
    N00B_MD_BLOCK_HR,
    N00B_MD_BLOCK_H,
    N00B_MD_BLOCK_CODE,
    N00B_MD_BLOCK_HTML,
    N00B_MD_BLOCK_P,
    N00B_MD_BLOCK_TABLE,
    N00B_MD_BLOCK_THEAD,
    N00B_MD_BLOCK_TBODY,
    N00B_MD_BLOCK_TR,
    N00B_MD_BLOCK_TH,
    N00B_MD_BLOCK_TD,
    // Span types (offset from MD_SPANTYPE)
    N00B_MD_SPAN_EM,
    N00B_MD_SPAN_STRONG,
    N00B_MD_SPAN_A,
    N00B_MD_SPAN_A_SELF,
    N00B_MD_SPAN_A_CODELINK,
    N00B_MD_SPAN_IMG,
    N00B_MD_SPAN_CODE,
    N00B_MD_SPAN_STRIKETHRU,
    N00B_MD_SPAN_LATEX,
    N00B_MD_SPAN_LATEX_DISPLAY,
    N00B_MD_SPAN_WIKI_LINK,
    N00B_MD_SPAN_U,
    // Text types (offset from MD_TEXTTYPE)
    N00B_MD_TEXT_NORMAL,
    N00B_MD_TEXT_nullptr,
    N00B_MD_TEXT_BR,
    N00B_MD_TEXT_SOFTBR,
    N00B_MD_TEXT_ENTITY,
    N00B_MD_TEXT_CODE,
    N00B_MD_TEXT_HTML,
    N00B_MD_TEXT_LATEX,
    // Synthetic root
    N00B_MD_DOCUMENT,
} n00b_md_node_kind_t;

// ===================================================================
// Detail union (opaque md4c storage + text)
// ===================================================================

/** @brief Per-node detail data.
 *
 *  For text nodes, use the `text` member (an `n00b_string_t *`).
 *  For block/span nodes, the md4c detail struct is stored in `raw[]`;
 *  cast to the appropriate md4c detail type in the implementation.
 */
typedef union [[n00b::raw_union]] {
    n00b_string_t *text;     /**< Text content (for text-kind nodes) */
    uint8_t       raw[96];   /**< Opaque md4c detail storage */
} n00b_md_detail_t;

// ===================================================================
// AST node
// ===================================================================

/** @brief A markdown AST node. */
typedef struct {
    n00b_md_node_kind_t node_type;  /**< Kind of markdown element */
    n00b_md_detail_t    detail;     /**< Detail data (text or md4c struct) */
} n00b_md_node_t;

// ===================================================================
// Public API
// ===================================================================

/**
 * @brief Parse a markdown string into an AST.
 *
 * Uses md4c as the parsing backend with GitHub-Flavored Markdown
 * extensions.  Returns a tree of `n00b_md_node_t` nodes.
 *
 * @param s  The markdown source text.
 * @kw allocator  Optional allocator.
 * @return Root of the parsed AST.
 *
 * @pre  `s.data` is valid UTF-8.
 * @post Returned tree is heap-allocated; caller frees with
 *       `n00b_tree_free_node`.
 */
n00b_tree_t(n00b_md_node_t, n00b_md_node_t) *
n00b_parse_markdown(n00b_string_t *s)
    _kargs { n00b_allocator_t *allocator = nullptr; };
