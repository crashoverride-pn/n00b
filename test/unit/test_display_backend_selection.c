#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/runtime.h"
#include "display/render/backend.h"
#include "display/render/backend_registry.h"
#include "text/strings/string_ops.h"

static void
set_backend_override(const char *value)
{
#ifdef _WIN32
    _putenv_s("N00B_RENDERER_BACKEND", value ? value : "");
#else
    if (value) {
        setenv("N00B_RENDERER_BACKEND", value, 1);
    }
    else {
        unsetenv("N00B_RENDERER_BACKEND");
    }
#endif
}

static n00b_string_t *
candidate_at(n00b_list_t(n00b_string_t *) candidates, size_t ix)
{
    assert(ix < candidates.len);
    return n00b_list_get(candidates, ix);
}

static void
assert_candidate_eq(n00b_list_t(n00b_string_t *) candidates,
                    size_t                       ix,
                    const char                  *expected)
{
    n00b_string_t *actual = candidate_at(candidates, ix);
    assert(actual);
    assert(n00b_unicode_str_eq(actual,
                               n00b_string_from_cstr(expected),
                               .case_sensitive = false));
}

// Mirrors candidate_list_append_auto() in backend_registry.c: on non-Windows a
// non-tty stdout prepends the plain `stream` backend ahead of the rich-first
// order so `auto` never leaks ANSI escapes into a pipe/file. Under the test
// harness stdout is a pipe, so this returns true and `stream` leads.
static bool
auto_prefers_stream(void)
{
#ifndef _WIN32
    return !isatty(STDOUT_FILENO);
#else
    return false;
#endif
}

static void
test_alias_normalization(void)
{
    n00b_list_t(n00b_string_t *) tui =
        n00b_renderer_candidate_names(r"tui",
                                      .allow_fallback     = false,
                                      .allow_env_override = false);
    assert(tui.len == 1);
    assert_candidate_eq(tui, 0, "ansi");

    n00b_list_t(n00b_string_t *) nc =
        n00b_renderer_candidate_names(r"nc",
                                      .allow_fallback     = false,
                                      .allow_env_override = false);
    assert(nc.len == 1);
    assert_candidate_eq(nc, 0, "notcurses");

    printf("  [PASS] backend selection alias normalization\n");
}

static void
test_auto_candidate_order(void)
{
    n00b_list_t(n00b_string_t *) auto_candidates =
        n00b_renderer_candidate_names(r"auto",
                                      .allow_env_override = false);

    assert(auto_candidates.len == 5);
    if (auto_prefers_stream()) {
        // non-tty stdout: `stream` leads, then the rich-first order.
        assert_candidate_eq(auto_candidates, 0, "stream");
        assert_candidate_eq(auto_candidates, 1, "ansi");
        assert_candidate_eq(auto_candidates, 2, "gui");
        assert_candidate_eq(auto_candidates, 3, "notcurses");
        assert_candidate_eq(auto_candidates, 4, "dumb");
    }
    else {
        assert_candidate_eq(auto_candidates, 0, "ansi");
        assert_candidate_eq(auto_candidates, 1, "gui");
        assert_candidate_eq(auto_candidates, 2, "notcurses");
        assert_candidate_eq(auto_candidates, 3, "stream");
        assert_candidate_eq(auto_candidates, 4, "dumb");
    }

    printf("  [PASS] backend selection auto candidate order\n");
}

static void
test_env_override_behavior(void)
{
    set_backend_override("stream");

    n00b_list_t(n00b_string_t *) with_override =
        n00b_renderer_candidate_names(r"auto",
                                      .allow_env_override = true);
    assert(with_override.len >= 1);
    assert_candidate_eq(with_override, 0, "stream");

    n00b_list_t(n00b_string_t *) without_override =
        n00b_renderer_candidate_names(r"auto",
                                      .allow_env_override = false);
    assert(without_override.len >= 1);
    assert_candidate_eq(without_override, 0,
                        auto_prefers_stream() ? "stream" : "ansi");

    set_backend_override(nullptr);
    printf("  [PASS] backend selection env override\n");
}

static void
test_explicit_request_beats_env_override(void)
{
    set_backend_override("stream");

    n00b_list_t(n00b_string_t *) explicit_candidates =
        n00b_renderer_candidate_names(r"ansi",
                                      .allow_fallback     = true,
                                      .allow_env_override = true);
    assert(explicit_candidates.len >= 1);
    assert_candidate_eq(explicit_candidates, 0, "ansi");

    set_backend_override(nullptr);
    printf("  [PASS] explicit backend request beats env override\n");
}

static void
test_fallback_reporting(void)
{
    set_backend_override("stream");
    assert(!n00b_renderer_selection_uses_fallback(r"auto",
                                                  &n00b_renderer_stream,
                                                  .allow_fallback     = true,
                                                  .allow_dynamic_load = false,
                                                  .allow_env_override = true));

    assert(!n00b_renderer_selection_uses_fallback(r"ansi",
                                                  &n00b_renderer_ansi,
                                                  .allow_fallback     = true,
                                                  .allow_dynamic_load = false,
                                                  .allow_env_override = true));

    set_backend_override(nullptr);
    assert(n00b_renderer_selection_uses_fallback(r"missing-backend",
                                                 &n00b_renderer_ansi,
                                                 .allow_fallback     = true,
                                                 .allow_dynamic_load = false,
                                                 .allow_env_override = false));

    n00b_option_t(n00b_renderer_vtable_ptr_t) gui =
        n00b_renderer_find(r"gui");
    if (n00b_option_is_set(gui)) {
        assert(!n00b_renderer_selection_uses_fallback(r"gui",
                                                      n00b_option_get(gui),
                                                      .allow_fallback     = true,
                                                      .allow_dynamic_load = false,
                                                      .allow_env_override = false));
    }

    printf("  [PASS] backend fallback reporting\n");
}

static void
test_resolve_exact(void)
{
    n00b_result_t(n00b_renderer_vtable_ptr_t) stream =
        n00b_renderer_resolve_exact(r"stream",
                                    .allow_dynamic_load = false);
    assert(n00b_result_is_ok(stream));
    assert(n00b_result_get(stream) == &n00b_renderer_stream);

    n00b_result_t(n00b_renderer_vtable_ptr_t) tui =
        n00b_renderer_resolve_exact(r"tui",
                                    .allow_dynamic_load = false);
    assert(n00b_result_is_ok(tui));
    assert(n00b_result_get(tui) == &n00b_renderer_ansi);

    n00b_result_t(n00b_renderer_vtable_ptr_t) missing =
        n00b_renderer_resolve_exact(r"missing-backend",
                                    .allow_dynamic_load = false);
    assert(!n00b_result_is_ok(missing));
    assert(n00b_result_get_err(missing) == ENOENT);

    printf("  [PASS] backend selection exact resolve\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running display backend-selection tests...\n");
    test_alias_normalization();
    test_auto_candidate_order();
    test_env_override_behavior();
    test_explicit_request_beats_env_override();
    test_fallback_reporting();
    test_resolve_exact();
    printf("Display backend-selection tests passed.\n");

    n00b_shutdown();
    return 0;
}
