#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "audit_paths.h"
#include "core/file.h"
#include "core/runtime.h"
#include "internal/slay/grammar_internal.h"
#include "slay/bnf.h"
#include "slay/grammar.h"
#include "util/assert.h"
#include "util/marshal.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static n00b_string_t *
slurp(n00b_string_t *path)
{
    n00b_result_t(n00b_file_t *) open_r =
        n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(open_r));

    n00b_file_t *file = n00b_result_get(open_r);

    n00b_result_t(n00b_buffer_t *) buf_r = n00b_file_as_buffer(file);
    CHECK(n00b_result_is_ok(buf_r));

    n00b_buffer_t *buf = n00b_result_get(buf_r);
    n00b_string_t *text = n00b_string_from_raw(buf->data,
                                               (int64_t)buf->byte_len);
    n00b_file_close(file);

    return text;
}

static n00b_buffer_t *
marshal_checked(void *root, uint32_t base_address)
{
    n00b_marshal_ctx_t *ctx = n00b_marshal_ctx_new(.base_address = base_address);
    n00b_buffer_t      *buf = n00b_marshal_incremental(ctx, root);

    CHECK(n00b_marshal_ctx_status(ctx) == N00B_MARSHAL_OK);
    CHECK(buf != nullptr);
    n00b_marshal_ctx_destroy(ctx);

    return buf;
}

static n00b_grammar_t *
unmarshal_grammar_checked(n00b_buffer_t *buf)
{
    n00b_unmarshal_ctx_t *ctx   = n00b_unmarshal_ctx_new();
    n00b_list_t(void *)   roots = n00b_unmarshal_incremental(ctx, buf);

    CHECK(n00b_unmarshal_ctx_status(ctx) == N00B_MARSHAL_OK);
    CHECK(n00b_list_len(roots) == 1);
    n00b_grammar_t *copy = n00b_list_get(roots, 0);
    CHECK(copy != nullptr);
    n00b_unmarshal_ctx_destroy(ctx);

    return copy;
}

static n00b_grammar_t *
load_n00b_grammar(void)
{
    n00b_string_t  *path = n00b_string_from_cstr(N00B_N00B_GRAMMAR_PATH);
    n00b_string_t  *bnf  = slurp(path);
    n00b_grammar_t *g = n00b_grammar_new(.error_recovery = false);

    CHECK(n00b_bnf_load(bnf, r"module", g));
    CHECK(n00b_list_len(g->rules) > 0);
    CHECK(n00b_list_len(g->nt_list) > 0);

    return g;
}

static void
test_n00b_grammar_marshal_round_trip(void)
{
    n00b_grammar_t *g = load_n00b_grammar();

    size_t rules = n00b_list_len(g->rules);
    size_t nts   = n00b_list_len(g->nt_list);
    // Sanity only: the grammar loaded non-trivially. Don't assert exact
    // rule/NT counts here — those are brittle and churn with every grammar
    // change. The real invariant is the marshal round-trip below: the copy
    // preserves the counts (whatever they are) and re-marshal is
    // byte-identical.
    CHECK(rules > 0);
    CHECK(nts > 0);

    uint32_t       base = 0x10000000u;
    n00b_buffer_t *buf  = marshal_checked(g, base);

    n00b_grammar_t *copy = unmarshal_grammar_checked(buf);
    CHECK(copy != g);
    CHECK(n00b_list_len(copy->rules) == rules);
    CHECK(n00b_list_len(copy->nt_list) == nts);

    n00b_buffer_t *buf2 = marshal_checked(copy, base);
    CHECK(buf->byte_len == buf2->byte_len);
    CHECK(memcmp(buf->data, buf2->data, buf->byte_len) == 0);

}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_n00b_grammar_marshal_round_trip();

    n00b_shutdown();
    return 0;
}
