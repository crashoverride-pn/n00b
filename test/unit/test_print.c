/*
 * test_print.c — Tests for the print API.
 *
 * Tests 1-7: n00b_to_string conversions.
 * Tests 8-11: n00b_print via conduit topic wired to a pipe.
 * Tests 12-13: runtime stdout/stderr topic sanity checks.
 * Tests 14-16: n00b_printf via conduit topic wired to a pipe.
 * Test 17: n00b_eprintf via dup2 redirect of fd 2.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

#include "n00b.h"
#include "conduit/print.h"
#include "conduit/conduit.h"
#include "conduit/io.h"
#include "conduit/fd_managed.h"
#include "conduit/fd_writer.h"
#include "conduit/service.h"
#include "conduit/xform_types.h"
#include "core/alloc.h"
#include "adt/dict_untyped.h"
#include "core/runtime.h"
#include "core/type_info.h"
#include "core/string.h"
#include "core/buffer.h"
#include "text/strings/string_convert.h"
#include "text/strings/fmt_numbers.h"

// Helper: create a pipe and wire a conduit topic + fd_writer to the
// write end, so that n00b_print(.topic = tp.topic) works.
typedef struct {
    int                                    read_fd;
    int                                    write_fd;
    n00b_conduit_topic_t(n00b_buffer_t *) *topic;
} test_pipe_t;

static _Atomic(uint64_t) test_pipe_id = 1;

static int
test_pipe_create(int fds[2])
{
#ifdef _WIN32
    return _pipe(fds, 4096, _O_BINARY);
#else
    return pipe(fds);
#endif
}

static int
test_fd_close(int fd)
{
#ifdef _WIN32
    return _close(fd);
#else
    return close(fd);
#endif
}

static int
test_fd_read(int fd, char *buf, int len)
{
#ifdef _WIN32
    return _read(fd, buf, (unsigned int)len);
#else
    return (int)read(fd, buf, (size_t)len);
#endif
}

static test_pipe_t
make_test_pipe(void)
{
    test_pipe_t tp = {0};
    int fds[2];
    int rc = test_pipe_create(fds);
    assert(rc == 0);

    tp.read_fd  = fds[0];
    tp.write_fd = fds[1];

    // Create a conduit topic + fd_writer for the pipe write end.
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt && rt->default_conduit);

    auto io_opt = n00b_conduit_default_backend(rt->default_conduit);
    assert(n00b_option_is_set(io_opt));

    auto manage_r = n00b_conduit_fd_manage(rt->default_conduit,
                                           n00b_option_get(io_opt),
                                           tp.write_fd,
                                           false);
    assert(n00b_result_is_ok(manage_r));

    uint64_t id = n00b_atomic_add(&test_pipe_id, 1);
    n00b_conduit_uri_t uri = N00B_CONDUIT_URI_FD_WRITE(1000 + id);

    tp.topic = n00b_conduit_topic_init(
        n00b_buffer_t *, rt->default_conduit, uri);
    assert(tp.topic != nullptr);

    auto writer_r = n00b_conduit_fd_writer_new(rt->default_conduit,
                                               tp.topic,
                                               tp.write_fd);
    assert(n00b_result_is_ok(writer_r));

    return tp;
}

// Read bytes written by the synchronous fd_writer after the test closes the
// pipe write end. POSIX keeps the old poll/nonblocking path; Windows CRT pipes
// are read until EOF.
static int
read_pipe(int fd, char *buf, int max_len)
{
#ifdef _WIN32
    int total = 0;
    while (total < max_len) {
        int n = test_fd_read(fd, buf + total, max_len - total);
        if (n <= 0) break;
        total += n;
    }

    buf[total] = '\0';
    return total;
#else
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, 2000);  // 2s timeout
    if (rc <= 0) {
        buf[0] = '\0';
        return 0;
    }

    // Set non-blocking to avoid stalling on the second read.
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int total = 0;
    while (total < max_len) {
        int n = (int)read(fd, buf + total, (size_t)(max_len - total));
        if (n <= 0) break;
        total += n;
    }

    fcntl(fd, F_SETFL, flags);
    buf[total] = '\0';
    return total;
#endif
}

// ============================================================================
// 1. n00b_to_string with nullptr
// ============================================================================

static void
test_to_string_null(void)
{
    n00b_string_t *s = n00b_to_string(nullptr);
    assert(s->u8_bytes == 6);
    assert(memcmp(s->data, "(null)", 6) == 0);

    printf("  [PASS] to_string null\n");
}

// ============================================================================
// 2. n00b_to_string with int64_t
// ============================================================================

static void
test_to_string_int64(void)
{
    int64_t *p = n00b_alloc(int64_t);
    *p = 42;

    n00b_string_t *s = n00b_to_string(p);
    assert(s->u8_bytes == 2);
    assert(memcmp(s->data, "42", 2) == 0);

    printf("  [PASS] to_string int64\n");
}

// ============================================================================
// 3. n00b_to_string with uint64_t
// ============================================================================

static void
test_to_string_uint64(void)
{
    uint64_t *p = n00b_alloc(uint64_t);
    *p = 12345;

    n00b_string_t *s = n00b_to_string(p);
    assert(s->u8_bytes > 0);
    assert(s->data != nullptr);

    printf("  [PASS] to_string uint64\n");
}

// ============================================================================
// 4. n00b_to_string with bool
// ============================================================================

static void
test_to_string_bool(void)
{
    bool *p = n00b_alloc(bool);
    *p = true;

    n00b_string_t *s = n00b_to_string(p);
    assert(s->u8_bytes > 0);

    printf("  [PASS] to_string bool\n");
}

// ============================================================================
// 5. n00b_to_string with double
// ============================================================================

static void
test_to_string_double(void)
{
    double *p = n00b_alloc(double);
    *p = 3.14;

    n00b_string_t *s = n00b_to_string(p);
    assert(s->u8_bytes > 0);

    printf("  [PASS] to_string double\n");
}

// ============================================================================
// 6. n00b_to_string with n00b_string_t (identity)
// ============================================================================

static void
test_to_string_string(void)
{
    n00b_string_t *p = n00b_string_from_raw("hello", 5);

    n00b_string_t *s = n00b_to_string(p);
    assert(s->u8_bytes == 5);
    assert(memcmp(s->data, "hello", 5) == 0);

    printf("  [PASS] to_string string\n");
}

// ============================================================================
// 7. n00b_to_string fallback (unregistered type)
// ============================================================================

static void
test_to_string_fallback(void)
{
    // n00b_dict_untyped_t is registered but has no TO_STRING entry.
    n00b_dict_untyped_t *d = n00b_alloc(n00b_dict_untyped_t);
    n00b_string_t *s = n00b_to_string(d);

    // Should produce something like "<unknown@0x...>"
    assert(s->u8_bytes > 0);
    assert(s->data[0] == '<');

    printf("  [PASS] to_string fallback\n");
}

// ============================================================================
// 8. n00b_print basic (string to pipe via .topic)
// ============================================================================

static void
test_print_basic(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_string_t *msg = n00b_string_from_raw("hello", 5);

    n00b_print(msg, .topic = tp.topic);

    // Close write end to signal EOF, then read.
    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 6);
    assert(memcmp(buf, "hello\n", 6) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] print basic\n");
}

// ============================================================================
// 9. n00b_print with custom end
// ============================================================================

static void
test_print_custom_end(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_string_t *msg = n00b_string_from_raw("world", 5);

    n00b_string_t *end_str = n00b_string_from_raw("!\n", 2);

    n00b_print(msg, .topic = tp.topic, .end = n00b_option_set(n00b_string_t *, end_str));

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 7);
    assert(memcmp(buf, "world!\n", 7) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] print custom end\n");
}

// ============================================================================
// 10. n00b_print with int64_t
// ============================================================================

static void
test_print_int64(void)
{
    test_pipe_t tp = make_test_pipe();

    int64_t *val = n00b_alloc(int64_t);
    *val = -99;

    n00b_print(val, .topic = tp.topic);

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n > 0);
    assert(memcmp(buf, "-99\n", 4) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] print int64\n");
}

// ============================================================================
// 11. n00b_print with nullptr
// ============================================================================

static void
test_print_null(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_print(nullptr, .topic = tp.topic);

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 7);
    assert(memcmp(buf, "(null)\n", 7) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] print null\n");
}

// ============================================================================
// 12. Runtime stdout topic is non-null
// ============================================================================

static void
test_stdout_topic(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt != nullptr);
    assert(rt->stdout_topic != nullptr);

    // Second access should return the same pointer.
    n00b_conduit_topic_base_t *first = rt->stdout_topic;
    assert(rt->stdout_topic == first);

    printf("  [PASS] stdout topic\n");
}

// ============================================================================
// 13. Runtime stderr topic is non-null
// ============================================================================

static void
test_stderr_topic(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt != nullptr);
    assert(rt->stderr_topic != nullptr);

    printf("  [PASS] stderr topic\n");
}

// ============================================================================
// 14. n00b_printf basic (format + print to pipe via .topic)
// ============================================================================

static void
test_printf_basic(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_string_t *name = n00b_string_from_raw("World", 5);

    n00b_printf("Hello [|#|]!", name, .topic = tp.topic);

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 13);
    assert(memcmp(buf, "Hello World!\n", 13) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] printf basic\n");
}

// ============================================================================
// 15. n00b_printf with no trailing newline
// ============================================================================

static void
test_printf_no_newline(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_string_t *empty = n00b_string_from_raw("", 0);

    n00b_printf("ok", .topic = tp.topic, .end = n00b_option_set(n00b_string_t *, empty));

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 2);
    assert(memcmp(buf, "ok", 2) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] printf no newline\n");
}

// ============================================================================
// 16. n00b_printf to pipe via .topic
// ============================================================================

static void
test_printf_topic(void)
{
    test_pipe_t tp = make_test_pipe();

    n00b_printf("err", .topic = tp.topic);

    test_fd_close(tp.write_fd);

    char buf[256];
    int n = read_pipe(tp.read_fd, buf, 255);

    assert(n == 4);
    assert(memcmp(buf, "err\n", 4) == 0);

    test_fd_close(tp.read_fd);
    printf("  [PASS] printf topic\n");
}

// ============================================================================
// 17. n00b_eprintf macro (writes to fd 2 via macro, redirected by dup2)
//
// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running print tests...\n");

    // n00b_to_string tests
    test_to_string_null();
    test_to_string_int64();
    test_to_string_uint64();
    test_to_string_bool();
    test_to_string_double();
    test_to_string_string();
    test_to_string_fallback();

    // n00b_print tests (conduit topic → pipe)
    test_print_basic();
    test_print_custom_end();
    test_print_int64();
    test_print_null();

    // Runtime topic sanity checks
    test_stdout_topic();
    test_stderr_topic();

    // n00b_printf / n00b_eprintf tests
    test_printf_basic();
    test_printf_no_newline();
    test_printf_topic();
    printf("All print tests passed.\n");
    n00b_shutdown();
    return 0;
}
