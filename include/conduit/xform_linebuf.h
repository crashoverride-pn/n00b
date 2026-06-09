/**
 * @file xform_linebuf.h
 * @brief Line-buffering transform for the conduit pipeline.
 *
 * Accumulates incoming `n00b_buffer_t *` data, scanning for a
 * delimiter (default `'\n'`).  For each complete line found, emits
 * a separate output buffer.  Partial data is held until the next
 * input or until flush (upstream close).
 *
 * This is a multi-output transform: one input buffer may produce
 * zero or more output lines via `n00b_conduit_filter_emit`.
 *
 * ### Usage
 *
 * ```c
 * auto r = n00b_conduit_linebuf_new(conduit, upstream_topic);
 * auto xf = n00b_result_get(r);
 * auto out = n00b_conduit_xform_topic(n00b_buffer_t *, n00b_buffer_t *, xf);
 * ```
 */
#pragma once

#include "conduit/xform_types.h"

// ============================================================================
// Linebuf state (stored in xform cookie)
// ============================================================================

/**
 * @brief Internal state for the line-buffering transform.
 */
typedef struct {
    n00b_buffer_t *partial;           /**< Accumulated partial line data */
    uint8_t        delimiter;         /**< Line delimiter byte */
    size_t         max_line_len;      /**< Max line length (0 = unlimited) */
    bool           include_delimiter; /**< Include delimiter in output */
    bool           consume;           /**< Free input buffers after transform */
} n00b_linebuf_state_t;

// ============================================================================
// API
// ============================================================================

/**
 * @brief Create a line-buffering filter transform.
 *
 * @param c        Conduit instance.
 * @param upstream Upstream topic producing `n00b_buffer_t *` payloads.
 *
 * @kw delimiter         Byte to split on (default `'\n'`).
 * @kw max_line_len      Maximum line length; 0 = no limit.
 * @kw include_delimiter If true, include the delimiter in output buffers.
 * @kw consume           If true, free each input buffer after processing.
 *
 * @return Result with filter pointer on success, error code on failure.
 */
extern n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_linebuf_new(n00b_conduit_t                     *c,
                         n00b_conduit_topic_t(n00b_buffer_t *) *upstream)
    _kargs {
        uint8_t delimiter         = '\n';
        size_t  max_line_len      = 0;
        bool    include_delimiter = false;
        bool    consume           = false;
    };

// ============================================================================
// Chain spec
// ============================================================================

/**
 * @brief Chain specification for the linebuf transform.
 *
 * Embed in a `n00b_conduit_xform_spec_base_t` array for use with
 * `n00b_conduit_chain()`.
 */
typedef struct {
    n00b_conduit_xform_spec_base_t base;
    uint8_t                        delimiter;
    size_t                         max_line_len;
    bool                           include_delimiter;
} n00b_conduit_linebuf_spec_t;

extern const n00b_conduit_linebuf_spec_t n00b_conduit_linebuf_default_spec;
