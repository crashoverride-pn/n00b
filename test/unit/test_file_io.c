// Unit tests for core/file_map and core/file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "core/thread.h"
#if defined(__linux__)
#include "core/syscall.h"
#endif
#include "conduit/conduit.h"
#include "conduit/fd_managed.h"
#include "core/file.h"
#include "core/file_map.h"
#include "adt/result.h"
#include "util/assert.h"
#include "util/path.h"
#include "util/proc.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#ifndef PIPE_BUF
#define PIPE_BUF 512
#endif

// ----------------------------------------------------------------------
// Fixture helpers
// ----------------------------------------------------------------------

static n00b_string_t *
write_temp_file(const char *contents, size_t n)
{
    char path[] = "/tmp/n00b_file_test_XXXXXX";
    int  fd     = mkstemp(path);
    assert(fd >= 0);
    if (n > 0) {
        ssize_t w = write(fd, contents, n);
        assert(w == (ssize_t)n);
    }
    close(fd);
    return n00b_string_from_cstr(path);
}

static void
unlink_path(n00b_string_t *p)
{
    unlink((const char *)p->data);
}

static n00b_string_t *
fresh_libn00b_temp_path(void)
{
    for (int i = 0; i < 64; i++) {
        n00b_string_t *p = n00b_new_temp_path(
            n00b_string_from_cstr("n00b_file_io_"),
            n00b_string_from_cstr(".tmp"));
        if (!n00b_path_exists(p)) {
            return p;
        }
    }

    N00B_TEST_REQUIRE(false);
    return nullptr;
}

#ifndef _WIN32
typedef struct {
    int      fd;
    uint32_t delay_us;
} delayed_close_t;

static void *
delayed_close_worker(void *arg)
{
    delayed_close_t *ctx = (delayed_close_t *)arg;

    base_nanosleep_ns((uint64_t)ctx->delay_us * 1000ULL);
#if defined(__linux__)
    (void)_n00b_raw_linux_syscall1(SYS_close, (long)ctx->fd);
#else
    close(ctx->fd);
#endif

    return nullptr;
}

static void
make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    N00B_TEST_REQUIRE(flags >= 0);
    N00B_TEST_REQUIRE(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}

static void
fill_pipe_then_drain(int read_fd, int write_fd, size_t drain_len)
{
    char buf[4096];

    memset(buf, 0x5a, sizeof(buf));
    while (true) {
        ssize_t n = write(write_fd, buf, sizeof(buf));
        if (n > 0) {
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        N00B_TEST_REQUIRE(n < 0);
        N00B_TEST_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
        break;
    }

    size_t drained = 0;
    while (drained < drain_len) {
        size_t want = drain_len - drained;
        if (want > sizeof(buf)) {
            want = sizeof(buf);
        }

        ssize_t n = read(read_fd, buf, want);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        N00B_TEST_REQUIRE(n > 0);
        drained += (size_t)n;
    }
}
#endif

// ----------------------------------------------------------------------
// file_map: basic mapping + zero-byte file + advise no-op for non-mmap
// ----------------------------------------------------------------------

static void
test_file_map_basic(void)
{
    const char payload[] = "the quick brown fox jumps over the lazy dog";
    n00b_string_t *p     = write_temp_file(payload, strlen(payload));

    auto r = n00b_file_mmap(p);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);
    assert(buf->byte_len == strlen(payload));
    assert(memcmp(buf->data, payload, strlen(payload)) == 0);
    assert((buf->flags & N00B_BUF_F_MMAP) != 0);

    // advise should not crash; it's best-effort.
    n00b_file_mmap_advise(buf, N00B_MMAP_ADVICE_SEQUENTIAL);
    n00b_file_mmap_advise(buf, N00B_MMAP_ADVICE_RANDOM);
    n00b_file_mmap_advise(buf, N00B_MMAP_ADVICE_WILLNEED);
    n00b_file_mmap_advise(buf, N00B_MMAP_ADVICE_DONTNEED);
    n00b_file_mmap_advise(buf, N00B_MMAP_ADVICE_NORMAL);

    // advise on a non-mmap buffer is a no-op.
    n00b_buffer_t *plain = n00b_buffer_from_bytes("xxx", 3);
    n00b_file_mmap_advise(plain, N00B_MMAP_ADVICE_SEQUENTIAL);

    unlink_path(p);
    fflush(stdout); printf("  [PASS] file_map_basic\n");
    fflush(stdout);
}

static void
test_file_map_zero_byte(void)
{
    n00b_string_t *p = write_temp_file("", 0);
    auto r           = n00b_file_mmap(p);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf->byte_len == 0);
    // No mapping for empty files — flag is not set.
    assert((buf->flags & N00B_BUF_F_MMAP) == 0);
    unlink_path(p);
    fflush(stdout); printf("  [PASS] file_map_zero_byte\n");
}

static void
test_file_map_missing(void)
{
    n00b_string_t *p = n00b_string_from_cstr("/tmp/n00b_file_test_does_not_exist_xyz");
    auto r           = n00b_file_mmap(p);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == ENOENT);
    fflush(stdout); printf("  [PASS] file_map_missing\n");
}

// ----------------------------------------------------------------------
// file façade: MMAP kind
// ----------------------------------------------------------------------

static void
test_file_mmap_read_and_seek(void)
{
    const char payload[] = "0123456789abcdef0123456789ABCDEF";
    n00b_string_t *p     = write_temp_file(payload, strlen(payload));

    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_MMAP);
    assert(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);

    assert(n00b_file_get_kind(f) == N00B_FILE_KIND_MMAP);
    assert(n00b_file_size(f) == (int64_t)strlen(payload));
    assert(n00b_file_tell(f) == 0);
    assert(!n00b_file_at_eof(f));

    // Read 10 bytes.
    auto rr1 = n00b_file_read(f, 10);
    assert(n00b_result_is_ok(rr1));
    n00b_buffer_t *c1 = n00b_result_get(rr1);
    assert(c1->byte_len == 10);
    assert(memcmp(c1->data, "0123456789", 10) == 0);
    assert(n00b_file_tell(f) == 10);

    // Seek back to 4.
    auto sr = n00b_file_seek(f, 4, SEEK_SET);
    assert(n00b_result_is_ok(sr));
    assert(n00b_result_get(sr) == 4);

    // Read remaining (28 bytes).
    auto rr2 = n00b_file_read(f, 0);
    assert(n00b_result_is_ok(rr2));
    n00b_buffer_t *c2 = n00b_result_get(rr2);
    assert(c2->byte_len == strlen(payload) - 4);
    assert(n00b_file_at_eof(f));

    // as_buffer returns the whole mapping.
    auto br = n00b_file_as_buffer(f);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *whole = n00b_result_get(br);
    assert(whole->byte_len == strlen(payload));

    // SEEK_END.
    auto sr2 = n00b_file_seek(f, 0, SEEK_END);
    assert(n00b_result_is_ok(sr2));
    assert(n00b_file_tell(f) == (int64_t)strlen(payload));

    n00b_file_close(f);
    unlink_path(p);
    fflush(stdout); printf("  [PASS] file_mmap_read_and_seek\n");
}

// ----------------------------------------------------------------------
// file façade: STREAM kind — read + as_buffer error + seek errors
// ----------------------------------------------------------------------

static void
test_file_stream_read_and_seek(void)
{
    const char payload[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t plen    = strlen(payload);
    n00b_string_t *p     = write_temp_file(payload, plen);

    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_STREAM);
    assert(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);
    assert(n00b_file_get_kind(f) == N00B_FILE_KIND_STREAM);

    // as_buffer should error on STREAM.
    auto br = n00b_file_as_buffer(f);
    assert(n00b_result_is_err(br));
    assert(n00b_result_get_err(br) == ENOTSUP);

    // Read first 5 bytes — exact-N is not guaranteed on STREAM, but
    // for a small file the conduit typically delivers everything in
    // one chunk. We accumulate up to plen.
    char acc[256];
    size_t accn = 0;
    while (!n00b_file_at_eof(f) && accn < plen) {
        auto rr = n00b_file_read(f, 16);
        assert(n00b_result_is_ok(rr));
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (chunk->byte_len == 0) break;
        assert(accn + chunk->byte_len <= sizeof(acc));
        memcpy(acc + accn, chunk->data, chunk->byte_len);
        accn += chunk->byte_len;
    }
    assert(accn == plen);
    assert(memcmp(acc, payload, plen) == 0);

    // After reading everything, backward seek must fail.
    auto sr_back = n00b_file_seek(f, 0, SEEK_SET);
    assert(n00b_result_is_err(sr_back));
    assert(n00b_result_get_err(sr_back) == EINVAL);

    // SEEK_END on stream must fail.
    auto sr_end = n00b_file_seek(f, 0, SEEK_END);
    assert(n00b_result_is_err(sr_end));

    n00b_file_close(f);
    unlink_path(p);
    fflush(stdout); printf("  [PASS] file_stream_read_and_seek\n");
}

// ----------------------------------------------------------------------
// file façade: AUTO chooses MMAP for regular file, STREAM for write
// ----------------------------------------------------------------------

static void
test_file_auto_resolution(void)
{
    const char payload[] = "hello";
    n00b_string_t *p     = write_temp_file(payload, strlen(payload));

    auto fr_r = n00b_file_open(p);
    assert(n00b_result_is_ok(fr_r));
    n00b_file_t *f_r = n00b_result_get(fr_r);
    assert(n00b_file_get_kind(f_r) == N00B_FILE_KIND_MMAP);
    n00b_file_close(f_r);

    n00b_string_t *wp = write_temp_file("", 0);
    auto fr_w = n00b_file_open(wp, .mode = N00B_FILE_W);
    assert(n00b_result_is_ok(fr_w));
    n00b_file_t *f_w = n00b_result_get(fr_w);
    assert(n00b_file_get_kind(f_w) == N00B_FILE_KIND_STREAM);
    n00b_file_close(f_w);

    unlink_path(p);
    unlink_path(wp);
    fflush(stdout); printf("  [PASS] file_auto_resolution\n");
}

// ----------------------------------------------------------------------
// SHA-256 streaming matches mmap+hash on the same file
// ----------------------------------------------------------------------

static void
hash_via_stream(const char *path, uint8_t out[32])
{
    n00b_string_t *p = n00b_string_from_cstr(path);
    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_STREAM);
    assert(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);

    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);
    while (!n00b_file_at_eof(f)) {
        auto rr = n00b_file_read(f, 65536);
        assert(n00b_result_is_ok(rr));
        n00b_buffer_t *chunk = n00b_result_get(rr);
        if (chunk->byte_len == 0) break;
        n00b_sha256_update(&ctx, chunk->data, chunk->byte_len);
    }
    n00b_file_close(f);

    n00b_sha256_digest_t words;
    n00b_sha256_finalize(&ctx, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
}

static void
hash_via_mmap(const char *path, uint8_t out[32])
{
    n00b_string_t *p = n00b_string_from_cstr(path);
    auto mr = n00b_file_mmap(p);
    assert(n00b_result_is_ok(mr));
    n00b_buffer_t *buf = n00b_result_get(mr);
    n00b_sha256_digest_t words;
    n00b_sha256_hash(buf->data, buf->byte_len, words);
    for (int i = 0; i < 8; i++) {
        uint32_t w   = words[i];
        out[i * 4]     = (uint8_t)((w >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((w >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((w >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(w & 0xff);
    }
}

static void
test_hash_stream_vs_mmap(void)
{
    // ~200 KiB file spans many stream chunks. Verifies that the
    // persistent inbox subscription captures every chunk by
    // accumulating the stream output and comparing to a SHA-256
    // computed over the original payload.
    size_t n = 200 * 1024;
    char *payload = n00b_alloc_array(char, n);
    for (size_t i = 0; i < n; i++) payload[i] = (char)((i * 31) ^ 0xa5);
    n00b_string_t *p = write_temp_file(payload, n);

    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_STREAM);
    assert(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);
    char *acc = n00b_alloc_array(char, n + 1024);
    size_t accn = 0;
    while (!n00b_file_at_eof(f)) {
        auto rr = n00b_file_read(f, 65536);
        assert(n00b_result_is_ok(rr));
        n00b_buffer_t *c = n00b_result_get(rr);
        if (c->byte_len == 0) break;
        memcpy(acc + accn, c->data, c->byte_len);
        accn += c->byte_len;
    }
    n00b_file_close(f);
    if (accn != n) {
        fprintf(stderr, "  accn=%zu expected n=%zu (delta=%zd)\n",
                accn, n, (ssize_t)n - (ssize_t)accn);
    }
    assert(accn == n);
    assert(memcmp(acc, payload, n) == 0);

    n00b_sha256_digest_t sw, mw;
    n00b_sha256_hash(acc, accn, sw);
    n00b_sha256_hash(payload, n, mw);
    for (int i = 0; i < 8; i++) assert(sw[i] == mw[i]);
    (void)hash_via_stream; (void)hash_via_mmap;
    unlink_path(p);
    fflush(stdout); printf("  [PASS] hash_stream_vs_mmap\n");
}

// ----------------------------------------------------------------------
// read_async on MMAP delivers inline + INVALID_SUB_HANDLE
// ----------------------------------------------------------------------

static void
test_async_read_mmap_inline(void)
{
    const char payload[] = "async-mmap-inline";
    n00b_string_t *p     = write_temp_file(payload, strlen(payload));

    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_MMAP);
    n00b_file_t *f = n00b_result_get(fr);

    n00b_conduit_t *c = n00b_get_runtime()->default_conduit;
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                             N00B_CONDUIT_BP_UNBOUNDED, 0);

    auto ar = n00b_file_read_async(f, 0, inbox);
    assert(n00b_result_is_ok(ar));
    auto async = n00b_result_get(ar);
    assert(async.handle == N00B_CONDUIT_INVALID_SUB_HANDLE);

    // Message should be there immediately.
    assert(n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox));
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    assert(msg != nullptr);
    assert(msg->payload->byte_len == strlen(payload));
    assert(memcmp(msg->payload->data, payload, strlen(payload)) == 0);

    // sub_cancel on invalid handle is a no-op.
    n00b_conduit_sub_cancel(async.handle);

    n00b_file_close(f);
    unlink_path(p);
    fflush(stdout); printf("  [PASS] async_read_mmap_inline\n");
}

static void
test_async_read_stream_regular_inline(void)
{
    const char payload[] = "async-stream-regular-inline";
    n00b_string_t *p     = write_temp_file(payload, strlen(payload));

    auto fr = n00b_file_open(p, .kind = N00B_FILE_KIND_STREAM);
    assert(n00b_result_is_ok(fr));
    n00b_file_t *f = n00b_result_get(fr);
    assert(n00b_file_get_kind(f) == N00B_FILE_KIND_STREAM);

    n00b_conduit_t *c = n00b_get_runtime()->default_conduit;
    n00b_conduit_inbox_t(n00b_buffer_t *) *inbox =
        n00b_alloc(n00b_conduit_inbox_t(n00b_buffer_t *));
    n00b_conduit_inbox_init(n00b_buffer_t *, inbox, c,
                             N00B_CONDUIT_BP_UNBOUNDED, 0);

    auto ar = n00b_file_read_async(f, 0, inbox);
    assert(n00b_result_is_ok(ar));
    auto async = n00b_result_get(ar);
    assert(async.handle == N00B_CONDUIT_INVALID_SUB_HANDLE);

    assert(n00b_conduit_inbox_has_msg(n00b_buffer_t *, inbox));
    n00b_conduit_message_t(n00b_buffer_t *) *msg =
        n00b_conduit_inbox_pop_msg(n00b_buffer_t *, inbox);
    assert(msg != nullptr);
    assert(msg->payload->byte_len == strlen(payload));
    assert(memcmp(msg->payload->data, payload, strlen(payload)) == 0);
    assert(n00b_file_at_eof(f));

    n00b_conduit_sub_cancel(async.handle);

    n00b_file_close(f);
    unlink_path(p);
    fflush(stdout); printf("  [PASS] async_read_stream_regular_inline\n");
}

// ----------------------------------------------------------------------
// exclusive create: existing files are never truncated or replaced
// ----------------------------------------------------------------------

static void
test_file_open_exclusive_collision(void)
{
    n00b_string_t *p = fresh_libn00b_temp_path();

    auto open_r = n00b_file_open_exclusive(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *f = n00b_result_get(open_r);
    n00b_buffer_t *first = n00b_buffer_from_bytes("first", 5);
    auto write_r = n00b_file_write_all(f, first);
    N00B_TEST_REQUIRE(n00b_result_is_ok(write_r));
    N00B_TEST_REQUIRE(n00b_result_get(write_r) == 5);
    auto close_r = n00b_file_close_result(f);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));

    auto collision_r = n00b_file_open_exclusive(p);
    N00B_TEST_REQUIRE(n00b_result_is_err(collision_r));
    N00B_TEST_REQUIRE(n00b_result_get_err(collision_r) == EEXIST);

    auto read_r = n00b_file_open(p, .kind = N00B_FILE_KIND_MMAP);
    N00B_TEST_REQUIRE(n00b_result_is_ok(read_r));
    n00b_file_t *rf = n00b_result_get(read_r);
    auto buffer_r = n00b_file_as_buffer(rf);
    N00B_TEST_REQUIRE(n00b_result_is_ok(buffer_r));
    n00b_buffer_t *buf = n00b_result_get(buffer_r);
    N00B_TEST_REQUIRE(buf->byte_len == 5);
    N00B_TEST_REQUIRE(memcmp(buf->data, "first", 5) == 0);
    n00b_file_close(rf);

    auto unlink_r = n00b_file_unlink(p, .ignore_missing = true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
}

// ----------------------------------------------------------------------
// write_all loops over whole buffers and accepts empty null-data buffers
// ----------------------------------------------------------------------

static void
test_file_write_all_buffer(void)
{
    n00b_string_t *p = fresh_libn00b_temp_path();
    auto open_r = n00b_file_open_exclusive(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *f = n00b_result_get(open_r);

    n00b_buffer_t empty = {};
    auto empty_r = n00b_file_write_all(f, &empty);
    N00B_TEST_REQUIRE(n00b_result_is_ok(empty_r));
    N00B_TEST_REQUIRE(n00b_result_get(empty_r) == 0);

    size_t n = 128 * 1024;
    char *payload = n00b_alloc_array(char, n);
    for (size_t i = 0; i < n; i++) {
        payload[i] = (char)((i * 17) ^ 0x5a);
    }
    n00b_buffer_t *buf = n00b_buffer_from_bytes(payload, (int64_t)n);
    auto write_r = n00b_file_write_all(f, buf);
    N00B_TEST_REQUIRE(n00b_result_is_ok(write_r));
    N00B_TEST_REQUIRE(n00b_result_get(write_r) == n);
    auto close_r = n00b_file_close_result(f);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));

    auto read_r = n00b_file_open(p, .kind = N00B_FILE_KIND_MMAP);
    N00B_TEST_REQUIRE(n00b_result_is_ok(read_r));
    n00b_file_t *rf = n00b_result_get(read_r);
    auto mapped_r = n00b_file_as_buffer(rf);
    N00B_TEST_REQUIRE(n00b_result_is_ok(mapped_r));
    n00b_buffer_t *mapped = n00b_result_get(mapped_r);
    N00B_TEST_REQUIRE(mapped->byte_len == n);
    N00B_TEST_REQUIRE(memcmp(mapped->data, payload, n) == 0);
    n00b_file_close(rf);

    auto unlink_r = n00b_file_unlink(p, .ignore_missing = true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
}

static void
test_file_write_attempt_helper(void)
{
    n00b_string_t *p = fresh_libn00b_temp_path();
    auto open_r = n00b_file_open_exclusive(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *f = n00b_result_get(open_r);

    auto write_r = n00b_file_write_attempt(f, "attempt", 7);
    N00B_TEST_REQUIRE(n00b_result_is_ok(write_r));
    n00b_file_write_attempt_t attempt = n00b_result_get(write_r);
    N00B_TEST_REQUIRE(attempt.bytes_written == 7);
    N00B_TEST_REQUIRE(!attempt.error);
    N00B_TEST_REQUIRE(attempt.error_code == 0);

    auto close_r = n00b_file_close_result(f);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));

    auto read_r = n00b_file_open(p, .kind = N00B_FILE_KIND_MMAP);
    N00B_TEST_REQUIRE(n00b_result_is_ok(read_r));
    n00b_file_t *rf = n00b_result_get(read_r);
    auto mapped_r = n00b_file_as_buffer(rf);
    N00B_TEST_REQUIRE(n00b_result_is_ok(mapped_r));
    n00b_buffer_t *mapped = n00b_result_get(mapped_r);
    N00B_TEST_REQUIRE(mapped->byte_len == 7);
    N00B_TEST_REQUIRE(memcmp(mapped->data, "attempt", 7) == 0);
    n00b_file_close(rf);

    auto unlink_r = n00b_file_unlink(p, .ignore_missing = true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
}

static void
test_fd_owner_write_attempt_partial_error(void)
{
#ifdef _WIN32
    return;
#else
    int pipe_fds[2] = {-1, -1};
    N00B_TEST_REQUIRE(pipe(pipe_fds) == 0);

    int read_fd  = pipe_fds[0];
    int write_fd = pipe_fds[1];

    make_nonblocking(write_fd);
    fill_pipe_then_drain(read_fd, write_fd, PIPE_BUF);

    n00b_runtime_t *rt = n00b_get_runtime();
    N00B_TEST_REQUIRE(rt != nullptr);
    N00B_TEST_REQUIRE(rt->default_conduit != nullptr);

    auto io_opt = n00b_conduit_default_backend(rt->default_conduit);
    N00B_TEST_REQUIRE(n00b_option_is_set(io_opt));

    n00b_conduit_io_backend_t *io = n00b_option_get(io_opt);
    auto manage_r = n00b_conduit_fd_manage(rt->default_conduit, io, write_fd,
                                           true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(manage_r));
    n00b_conduit_fd_owner_t *owner = n00b_result_get(manage_r);

    char payload[PIPE_BUF * 2];
    memset(payload, 0x7b, sizeof(payload));

    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);
    delayed_close_t close_ctx = {
        .fd       = read_fd,
        .delay_us = 20000,
    };
    auto thread_r = n00b_thread_spawn(delayed_close_worker, &close_ctx);
    N00B_TEST_REQUIRE(n00b_result_is_ok(thread_r));
    n00b_thread_t *thread = n00b_result_get(thread_r);

    auto write_r = n00b_fd_owner_write_attempt(owner, payload,
                                               sizeof(payload));
    n00b_thread_join(thread);
    signal(SIGPIPE, old_sigpipe);

    auto close_r = n00b_conduit_fd_owner_close_result(owner);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));

    N00B_TEST_REQUIRE(n00b_result_is_ok(write_r));
    n00b_fd_owner_write_attempt_t attempt = n00b_result_get(write_r);
    N00B_TEST_REQUIRE(attempt.bytes_written == PIPE_BUF);
    N00B_TEST_REQUIRE(attempt.error);
    N00B_TEST_REQUIRE(attempt.error_code == N00B_CONDUIT_ERR_EPIPE);
#endif
}

// ----------------------------------------------------------------------
// mode application through an open file handle
// ----------------------------------------------------------------------

static void
test_file_apply_mode_helper(void)
{
    n00b_string_t *p = fresh_libn00b_temp_path();
    auto open_r = n00b_file_open_exclusive(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *f = n00b_result_get(open_r);

    auto mode_r = n00b_file_apply_mode(f, 0600);
    if (n00b_result_is_err(mode_r) && n00b_result_get_err(mode_r) == ENOSYS) {
        auto close_r = n00b_file_close_result(f);
        N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));
        auto unlink_r = n00b_file_unlink(p, .ignore_missing = true);
        N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
        return;
    }
    N00B_TEST_REQUIRE(n00b_result_is_ok(mode_r));
    N00B_TEST_REQUIRE(n00b_result_get(mode_r) == 0600);
    auto close_r = n00b_file_close_result(f);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));

    auto get_r = n00b_path_get_mode(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(get_r));
    N00B_TEST_REQUIRE(n00b_result_get(get_r) == 0600);

    auto unlink_r = n00b_file_unlink(p, .ignore_missing = true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
}

// ----------------------------------------------------------------------
// n00b_path_stat + n00b_proc_is_alive (WP-024 OS primitives)
// ----------------------------------------------------------------------

static void
test_path_stat_and_proc_liveness(void)
{
    const char    *body = "hello-stat";
    n00b_string_t *p    = write_temp_file(body, strlen(body));

    // Existing regular file: exists, not dir, size matches, mtime populated.
    n00b_result_t(n00b_path_info_t) sr = n00b_path_stat(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(sr));
    n00b_path_info_t info = n00b_result_get(sr);
    N00B_TEST_REQUIRE(info.exists);
    N00B_TEST_REQUIRE(!info.is_dir);
    N00B_TEST_REQUIRE(info.size == (int64_t)strlen(body));
    N00B_TEST_REQUIRE(info.mtime_ns > 0);

    unlink_path(p);

    // Missing path is a normal result (exists=false), NOT an error.
    n00b_result_t(n00b_path_info_t) mr = n00b_path_stat(p);
    N00B_TEST_REQUIRE(n00b_result_is_ok(mr));
    N00B_TEST_REQUIRE(!n00b_result_get(mr).exists);

    // Directory: exists + is_dir.
    n00b_result_t(n00b_path_info_t) dr
        = n00b_path_stat(n00b_string_from_cstr("/tmp"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(dr));
    n00b_path_info_t dinfo = n00b_result_get(dr);
    N00B_TEST_REQUIRE(dinfo.exists);
    N00B_TEST_REQUIRE(dinfo.is_dir);

    // Null path → Err(EINVAL).
    n00b_result_t(n00b_path_info_t) er = n00b_path_stat(nullptr);
    N00B_TEST_REQUIRE(n00b_result_is_err(er));

    // Process liveness: self is alive; <=0 and an unused high pid are not.
    N00B_TEST_REQUIRE(n00b_proc_is_alive((int64_t)getpid()));
    N00B_TEST_REQUIRE(!n00b_proc_is_alive(0));
    N00B_TEST_REQUIRE(!n00b_proc_is_alive(-1));
    N00B_TEST_REQUIRE(!n00b_proc_is_alive((int64_t)0x3fffffff));

    printf("path_stat + proc_liveness tests passed.\n");
}

// ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running file_io tests...\n");

    test_file_map_basic();
    test_file_map_zero_byte();
    test_file_map_missing();
    test_file_mmap_read_and_seek();
    test_file_stream_read_and_seek();
    test_file_auto_resolution();
    test_hash_stream_vs_mmap();
    test_async_read_mmap_inline();
    test_async_read_stream_regular_inline();
    test_file_open_exclusive_collision();
    test_file_write_all_buffer();
    test_file_write_attempt_helper();
    test_fd_owner_write_attempt_partial_error();
    test_file_apply_mode_helper();
    test_path_stat_and_proc_liveness();

    printf("All file_io tests passed.\n");
    fflush(stdout);
    n00b_shutdown();
    return 0;
}
