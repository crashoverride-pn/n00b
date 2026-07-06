/*
 * xform_ansi_strip.c — ANSI escape sequence stripping transform.
 */

#include "conduit/xform_ansi_strip.h"
#include "core/alloc.h"

#include <string.h>

// ============================================================================
// Cookie type
// ============================================================================

typedef struct {
    n00b_ansi_ctx *parser;
} ansi_strip_state_t;

// ============================================================================
// Transform callback
// ============================================================================

static n00b_option_t(n00b_buffer_t *)
ansi_strip_transform(n00b_conduit_filter_t(n00b_buffer_t *) *xf,
                     n00b_buffer_t *input)
{
    ansi_strip_state_t *st = n00b_conduit_xform_cookie(
        n00b_buffer_t *, n00b_buffer_t *, xf);

    if (!input || n00b_buffer_len(input) == 0)
        return n00b_option_none(n00b_buffer_t *);

    // Feed input to the incremental ANSI parser.
    n00b_ansi_parse(st->parser, input);

    // Retrieve parsed nodes and convert to plain text (strip controls).
    n00b_list_t(n00b_ansi_node_t *) nodes =
        n00b_ansi_parser_results(st->parser);

    size_t ncount = n00b_list_len(nodes);

    if (ncount == 0)
        return n00b_option_none(n00b_buffer_t *);

    // keep_control=false strips escape sequences, preserves newlines/tabs.
    n00b_string_t *stripped = n00b_ansi_nodes_to_string(nodes, false);

    if (!stripped || stripped->u8_bytes == 0)
        return n00b_option_none(n00b_buffer_t *);

    // Convert string to buffer for the output topic.
    n00b_allocator_t *alloc = xf->conduit ? xf->conduit->allocator : nullptr;
    n00b_buffer_t *out =
        n00b_buffer_from_bytes(stripped->data, (int64_t)stripped->u8_bytes,
                               .allocator = alloc);

    return n00b_option_set(n00b_buffer_t *, out);
}

// ============================================================================
// Ops vtable
// ============================================================================

static n00b_string_t _kind_ansi_strip = {
    .data = "ansi_strip", .u8_bytes = 10, .codepoints = 10, .styling = nullptr
};

[[n00b::nomap]] static const n00b_conduit_filter_ops_t(n00b_buffer_t *) ansi_strip_ops = {
    .transform = ansi_strip_transform,
    .kind      = &_kind_ansi_strip,
};

// ============================================================================
// Constructor
// ============================================================================

n00b_result_t(n00b_conduit_filter_t(n00b_buffer_t *) *)
n00b_conduit_ansi_strip_new(n00b_conduit_t                        *c,
                            n00b_conduit_topic_t(n00b_buffer_t *)  *upstream)
{
    auto r = n00b_conduit_filter_new(n00b_buffer_t *, c, upstream,
                                     &ansi_strip_ops,
                                     sizeof(ansi_strip_state_t));

    if (n00b_result_is_ok(r)) {
        n00b_conduit_filter_t(n00b_buffer_t *) *xf = n00b_result_get(r);
        ansi_strip_state_t *st = n00b_conduit_xform_cookie(
            n00b_buffer_t *, n00b_buffer_t *, xf);
        st->parser = n00b_ansi_parser_create();
    }

    return r;
}

// ============================================================================
// Chain spec
// ============================================================================

static n00b_conduit_xform_base_t *
ansi_strip_create_from_spec(n00b_conduit_t            *c,
                            n00b_conduit_topic_base_t *upstream,
                            const void                *spec)
{
    (void)spec;
    auto r = n00b_conduit_ansi_strip_new(
        c, (n00b_conduit_topic_t(n00b_buffer_t *) *)upstream);
    if (n00b_result_is_err(r)) return nullptr;
    return (n00b_conduit_xform_base_t *)n00b_result_get(r);
}

const n00b_conduit_ansi_strip_spec_t n00b_conduit_ansi_strip_default_spec = {
    .base = {
        .create      = ansi_strip_create_from_spec,
        .cookie_size = sizeof(ansi_strip_state_t),
    },
};
