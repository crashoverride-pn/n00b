#include <assert.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/string.h"
#include "core/thread.h"
#include "text/strings/format.h"
#include "util/worker_pool.h"

typedef struct {
    uint64_t value;
} alloc_probe_t;

typedef struct {
    n00b_allocator_t *thread_allocator;
    n00b_allocator_t *initial_current;
    n00b_allocator_t *inside_current;
    n00b_allocator_t *after_current;
    n00b_allocator_t *allocated_owner;
} thread_alloc_case_t;

static n00b_allocator_t *
owner_of(void *ptr)
{
    auto owner_opt = n00b_mem_get_allocator(ptr);
    assert(n00b_option_is_set(owner_opt));
    return n00b_option_get(owner_opt);
}

static void
assert_owner(void *ptr, n00b_allocator_t *allocator)
{
    assert(owner_of(ptr) == allocator);
}

static void
test_implicit_allocations_use_current_allocator(void)
{
    n00b_arena_t     *scratch = n00b_new_arena(.size   = 32768,
                                               .use_gc = false,
                                               .name   = "test_current_implicit");
    n00b_allocator_t *alloc   = (n00b_allocator_t *)scratch;

    assert(n00b_current_allocator() == nullptr);

    n00b_with_allocator(alloc) {
        assert(n00b_current_allocator() == alloc);

        alloc_probe_t *probe = n00b_alloc(alloc_probe_t);
        probe->value         = 0xC0FFEE;
        assert_owner(probe, alloc);

        n00b_string_t *s = n00b_string_from_cstr("gateway");
        assert_owner(s, alloc);
        assert_owner(s->data, alloc);

        n00b_string_t *formatted = n00b_cformat("raw [|#|]", s);
        assert_owner(formatted, alloc);
        assert_owner(formatted->data, alloc);
    }

    assert(n00b_current_allocator() == nullptr);
    n00b_allocator_destroy(alloc);

    n00b_string_t *stable = n00b_string_from_cstr("gateway");
    n00b_string_t *again  = n00b_cformat("raw [|#|]", stable);
    assert_owner(again, n00b_default_allocator());
}

static void
test_explicit_allocator_wins(void)
{
    n00b_arena_t     *current = n00b_new_arena(.size   = 32768,
                                               .use_gc = false,
                                               .name   = "test_current_outer");
    n00b_arena_t     *explicit = n00b_new_arena(.size   = 32768,
                                                .use_gc = false,
                                                .name   = "test_current_explicit");
    n00b_allocator_t *current_alloc  = (n00b_allocator_t *)current;
    n00b_allocator_t *explicit_alloc = (n00b_allocator_t *)explicit;

    n00b_with_allocator(current_alloc) {
        alloc_probe_t *probe = n00b_alloc_with_opts(
            alloc_probe_t,
            &(n00b_alloc_opts_t){.allocator = explicit_alloc});
        assert_owner(probe, explicit_alloc);

        n00b_string_t *s = n00b_string_from_cstr("durable",
                                                 .allocator = explicit_alloc);
        assert_owner(s, explicit_alloc);
        assert_owner(s->data, explicit_alloc);
    }

    assert(n00b_current_allocator() == nullptr);
    n00b_allocator_destroy(current_alloc);
    n00b_allocator_destroy(explicit_alloc);
}

static void
test_nested_scopes_restore(void)
{
    n00b_arena_t     *outer = n00b_new_arena(.size   = 32768,
                                             .use_gc = false,
                                             .name   = "test_current_nested_outer");
    n00b_arena_t     *inner = n00b_new_arena(.size   = 32768,
                                             .use_gc = false,
                                             .name   = "test_current_nested_inner");
    n00b_allocator_t *outer_alloc = (n00b_allocator_t *)outer;
    n00b_allocator_t *inner_alloc = (n00b_allocator_t *)inner;

    n00b_with_allocator(outer_alloc) {
        assert(n00b_current_allocator() == outer_alloc);
        assert_owner(n00b_alloc(alloc_probe_t), outer_alloc);

        n00b_with_allocator(inner_alloc) {
            assert(n00b_current_allocator() == inner_alloc);
            assert_owner(n00b_alloc(alloc_probe_t), inner_alloc);
        }

        assert(n00b_current_allocator() == outer_alloc);
        assert_owner(n00b_alloc(alloc_probe_t), outer_alloc);
    }

    assert(n00b_current_allocator() == nullptr);
    n00b_allocator_destroy(outer_alloc);
    n00b_allocator_destroy(inner_alloc);
}

static void *
thread_alloc_worker(void *arg)
{
    thread_alloc_case_t *tc = arg;

    tc->initial_current = n00b_current_allocator();

    n00b_with_allocator(tc->thread_allocator) {
        tc->inside_current = n00b_current_allocator();
        alloc_probe_t *probe = n00b_alloc(alloc_probe_t);
        tc->allocated_owner  = owner_of(probe);
    }

    tc->after_current = n00b_current_allocator();
    return nullptr;
}

static void
test_thread_local_independence(void)
{
    n00b_arena_t     *main_arena = n00b_new_arena(.size   = 32768,
                                                  .use_gc = false,
                                                  .name   = "test_current_main");
    n00b_arena_t     *thread_arena = n00b_new_arena(.size   = 32768,
                                                    .use_gc = false,
                                                    .name   = "test_current_thread");
    n00b_allocator_t *main_alloc   = (n00b_allocator_t *)main_arena;
    n00b_allocator_t *thread_alloc = (n00b_allocator_t *)thread_arena;
    thread_alloc_case_t tc = {
        .thread_allocator = thread_alloc,
    };

    n00b_with_allocator(main_alloc) {
        assert(n00b_current_allocator() == main_alloc);

        auto thread_r = n00b_thread_spawn(thread_alloc_worker, &tc);
        assert(n00b_result_is_ok(thread_r));
        n00b_thread_join(n00b_result_get(thread_r));

        assert(n00b_current_allocator() == main_alloc);
    }

    assert(tc.initial_current == nullptr);
    assert(tc.inside_current == thread_alloc);
    assert(tc.allocated_owner == thread_alloc);
    assert(tc.after_current == nullptr);
    assert(n00b_current_allocator() == nullptr);

    n00b_allocator_destroy(main_alloc);
    n00b_allocator_destroy(thread_alloc);
}

// With no allocator scope in effect, the opts argument is the only thing that
// keeps an allocation out of the default arena. Covers all three shapes: the
// keyword-argument tail of these macros is an opaque constructor blob, not a
// place to name an allocator.
static void
test_opts_allocator_without_scope(void)
{
    n00b_arena_t     *named = n00b_new_arena(.size   = 32768,
                                             .use_gc = false,
                                             .name   = "test_current_unscoped");
    n00b_allocator_t *na    = (n00b_allocator_t *)named;

    assert(n00b_current_allocator() == nullptr);

    alloc_probe_t *one = n00b_alloc_with_opts(alloc_probe_t,
                                              &(n00b_alloc_opts_t){.allocator = na});
    assert_owner(one, na);

    alloc_probe_t *many = n00b_alloc_array_with_opts(alloc_probe_t,
                                                     8,
                                                     &(n00b_alloc_opts_t){.allocator = na});
    assert_owner(many, na);

    alloc_probe_t *flex = n00b_alloc_flex_with_opts(alloc_probe_t,
                                                    uint64_t,
                                                    4,
                                                    &(n00b_alloc_opts_t){.allocator = na});
    assert_owner(flex, na);

    assert_owner(n00b_alloc(alloc_probe_t), n00b_default_allocator());

    n00b_allocator_destroy(na);
}

#if !defined(_WIN32) && defined(N00B_DEBUG)
// A child case that finishes without tripping an assertion exits with this.
#define UNBALANCED_NO_ASSERT 42

static n00b_arena_t *
unbalanced_arena(const char *name)
{
    return n00b_new_arena(.size = 32768, .use_gc = false, .name = name);
}

static void
leave_override_in_scope(void)
{
    n00b_allocator_t *outer = (n00b_allocator_t *)unbalanced_arena("unbalanced_outer");
    n00b_allocator_t *inner = (n00b_allocator_t *)unbalanced_arena("unbalanced_inner");

    n00b_with_allocator(outer) {
        n00b_set_current_allocator(inner);
    }
}

static void
leaky_job(void *job, void *user_data)
{
    (void)job;
    n00b_set_current_allocator((n00b_allocator_t *)user_data);
}

static void
leave_override_in_job(void)
{
    n00b_allocator_t   *leaked = (n00b_allocator_t *)unbalanced_arena("unbalanced_job");
    n00b_worker_pool_t *pool   = n00b_worker_pool_new(1, 1, leaky_job, leaked);
    int                 job    = 0;

    n00b_worker_pool_submit(pool, &job);
    n00b_worker_pool_shutdown(pool);
}

// Runs one case in a fresh process and returns its exit status, or 128 plus
// the signal that ended it, with the start of its stderr in @p out.
static int
run_unbalanced_case(const char *self, const char *flag, char *out, size_t cap)
{
    int fds[2];
    assert(pipe(fds) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 2);
        execl(self, self, flag, (char *)nullptr);
        _exit(43);
    }

    close(fds[1]);
    size_t len = 0;
    while (true) {
        char    chunk[512];
        ssize_t n = read(fds[0], chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        size_t keep = (size_t)n < cap - 1 - len ? (size_t)n : cap - 1 - len;
        memcpy(out + len, chunk, keep);
        len += keep;
    }
    out[len] = '\0';
    close(fds[0]);

    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
}

static void
test_unbalanced_override_asserts(const char *self, const char *flag, const char *expr)
{
    char out[4096];
    int  rc = run_unbalanced_case(self, flag, out, sizeof(out));

    if (rc == 0 || rc == UNBALANCED_NO_ASSERT || strstr(out, expr) == nullptr) {
        fprintf(stderr,
                "FAIL %s: an override left installed was not caught "
                "(rc=%d, wanted an assertion on '%s')\n%s\n",
                flag,
                rc,
                expr,
                out);
        abort();
    }
}
#endif

int
main(int argc, char **argv)
{
#if !defined(_WIN32) && defined(N00B_DEBUG)
    if (argc >= 2 && strncmp(argv[1], "--unbalanced=", 13) == 0) {
        n00b_runtime_t child_runtime;
        n00b_init(&child_runtime, 1, argv);
        if (strcmp(argv[1] + 13, "scope") == 0) {
            leave_override_in_scope();
        }
        else if (strcmp(argv[1] + 13, "job") == 0) {
            leave_override_in_job();
        }
        _exit(UNBALANCED_NO_ASSERT);
    }

    // Before n00b_init, while this process is still single-threaded.
    test_unbalanced_override_asserts(argv[0],
                                     "--unbalanced=scope",
                                     "self->current_allocator == scope->installed");
    test_unbalanced_override_asserts(argv[0],
                                     "--unbalanced=job",
                                     "n00b_current_allocator() == job_allocator");
#endif

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_implicit_allocations_use_current_allocator();
    test_explicit_allocator_wins();
    test_opts_allocator_without_scope();
    test_nested_scopes_restore();
    test_thread_local_independence();

    n00b_shutdown();
    return 0;
}
