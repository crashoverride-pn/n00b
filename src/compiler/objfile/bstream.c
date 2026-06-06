#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "compiler/objfile/bstream.h"
#include "compiler/objfile/endian.h"

// ============================================================================
// Internal: read N bytes from a raw pointer
// ============================================================================

static inline uint8_t
read_u8(const char *p)
{
    return (uint8_t)p[0];
}

static inline uint16_t
read_u16(const char *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint32_t
read_u32(const char *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t
read_u64(const char *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

// ============================================================================
// Construction
// ============================================================================

n00b_bstream_t *
n00b_bstream_new(n00b_buffer_t *buf) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!buf) {
        return nullptr;
    }

    n00b_bstream_t *s =
        n00b_alloc_with_opts(n00b_bstream_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});
    s->buf           = buf;
    s->pos           = 0;
    s->allocator     = allocator;
    s->swap_endian   = false;

    return s;
}

n00b_result_t(n00b_bstream_t *)
n00b_bstream_from_file(const char *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    int fd = open(path, O_RDONLY);

    if (fd < 0) {
        return n00b_result_err(n00b_bstream_t *, errno);
    }

    struct stat st;

    if (fstat(fd, &st) != 0) {
        int e = errno;
        close(fd);
        return n00b_result_err(n00b_bstream_t *, e);
    }

    size_t         file_size = (size_t)st.st_size;
    n00b_buffer_t *buf       = n00b_buffer_new(file_size,
                                               .allocator = allocator);

    if (file_size > 0) {
        ssize_t total = 0;

        while ((size_t)total < file_size) {
            ssize_t n = read(fd, buf->data + total, file_size - (size_t)total);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                int e = errno;
                close(fd);
                n00b_buffer_free(buf);
                return n00b_result_err(n00b_bstream_t *, e);
            }

            if (n == 0) {
                break;
            }

            total += n;
        }

        buf->byte_len = (size_t)total;
    }

    close(fd);

    n00b_bstream_t *s = n00b_bstream_new(buf, .allocator = allocator);

    return n00b_result_ok(n00b_bstream_t *, s);
}

// ============================================================================
// Position
// ============================================================================

size_t
n00b_bstream_pos(n00b_bstream_t *s)
{
    return s->pos;
}

n00b_result_t(bool)
n00b_bstream_setpos(n00b_bstream_t *s, size_t pos)
{
    if (pos > n00b_buffer_len(s->buf)) {
        return n00b_result_err(bool, N00B_ERR_OUT_OF_BOUNDS);
    }

    s->pos = pos;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_bstream_advance(n00b_bstream_t *s, size_t n)
{
    if (s->pos + n > n00b_buffer_len(s->buf)) {
        return n00b_result_err(bool, N00B_ERR_OUT_OF_BOUNDS);
    }

    s->pos += n;
    return n00b_result_ok(bool, true);
}

size_t
n00b_bstream_remaining(n00b_bstream_t *s)
{
    size_t len = n00b_buffer_len(s->buf);

    return (s->pos < len) ? (len - s->pos) : 0;
}

bool
n00b_bstream_can_read(n00b_bstream_t *s, size_t n)
{
    return (s->pos + n) <= n00b_buffer_len(s->buf);
}

n00b_result_t(bool)
n00b_bstream_align(n00b_bstream_t *s, size_t alignment)
{
    if (alignment == 0) {
        return n00b_result_err(bool, N00B_ERR_OUT_OF_BOUNDS);
    }

    size_t remainder = s->pos % alignment;

    if (remainder == 0) {
        return n00b_result_ok(bool, true);
    }

    size_t advance = alignment - remainder;

    return n00b_bstream_advance(s, advance);
}

// ============================================================================
// Read (at current pos, advances)
// ============================================================================

n00b_result_t(uint8_t)
n00b_bstream_read_u8(n00b_bstream_t *s)
{
    if (!n00b_bstream_can_read(s, 1)) {
        return n00b_result_err(uint8_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint8_t v = read_u8(s->buf->data + s->pos);
    s->pos += 1;

    return n00b_result_ok(uint8_t, v);
}

n00b_result_t(uint16_t)
n00b_bstream_read_u16(n00b_bstream_t *s)
{
    if (!n00b_bstream_can_read(s, 2)) {
        return n00b_result_err(uint16_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint16_t v = read_u16(s->buf->data + s->pos);

    if (s->swap_endian) {
        v = n00b_swap16(v);
    }

    s->pos += 2;

    return n00b_result_ok(uint16_t, v);
}

n00b_result_t(uint32_t)
n00b_bstream_read_u32(n00b_bstream_t *s)
{
    if (!n00b_bstream_can_read(s, 4)) {
        return n00b_result_err(uint32_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint32_t v = read_u32(s->buf->data + s->pos);

    if (s->swap_endian) {
        v = n00b_swap32(v);
    }

    s->pos += 4;

    return n00b_result_ok(uint32_t, v);
}

n00b_result_t(uint64_t)
n00b_bstream_read_u64(n00b_bstream_t *s)
{
    if (!n00b_bstream_can_read(s, 8)) {
        return n00b_result_err(uint64_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint64_t v = read_u64(s->buf->data + s->pos);

    if (s->swap_endian) {
        v = n00b_swap64(v);
    }

    s->pos += 8;

    return n00b_result_ok(uint64_t, v);
}

n00b_result_t(int8_t)
n00b_bstream_read_i8(n00b_bstream_t *s)
{
    auto r = n00b_bstream_read_u8(s);

    if (n00b_result_is_err(r)) {
        return n00b_result_err(int8_t, n00b_result_get_err(r));
    }

    return n00b_result_ok(int8_t, (int8_t)n00b_result_get(r));
}

n00b_result_t(int16_t)
n00b_bstream_read_i16(n00b_bstream_t *s)
{
    auto r = n00b_bstream_read_u16(s);

    if (n00b_result_is_err(r)) {
        return n00b_result_err(int16_t, n00b_result_get_err(r));
    }

    return n00b_result_ok(int16_t, (int16_t)n00b_result_get(r));
}

n00b_result_t(int32_t)
n00b_bstream_read_i32(n00b_bstream_t *s)
{
    auto r = n00b_bstream_read_u32(s);

    if (n00b_result_is_err(r)) {
        return n00b_result_err(int32_t, n00b_result_get_err(r));
    }

    return n00b_result_ok(int32_t, (int32_t)n00b_result_get(r));
}

n00b_result_t(int64_t)
n00b_bstream_read_i64(n00b_bstream_t *s)
{
    auto r = n00b_bstream_read_u64(s);

    if (n00b_result_is_err(r)) {
        return n00b_result_err(int64_t, n00b_result_get_err(r));
    }

    return n00b_result_ok(int64_t, (int64_t)n00b_result_get(r));
}

n00b_result_t(n00b_buffer_t *)
n00b_bstream_read_bytes(n00b_bstream_t *s, size_t n)
{
    if (!n00b_bstream_can_read(s, n)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_OUT_OF_BOUNDS);
    }

    n00b_buffer_t *result = n00b_buffer_from_bytes(
        s->buf->data + s->pos,
        n,
        .allocator = s->allocator);
    s->pos += n;

    return n00b_result_ok(n00b_buffer_t *, result);
}

n00b_result_t(n00b_string_t *)
n00b_bstream_read_cstring(n00b_bstream_t *s)
{
    size_t len     = n00b_buffer_len(s->buf);
    size_t start   = s->pos;
    size_t scan    = start;

    while (scan < len) {
        if (s->buf->data[scan] == '\0') {
            size_t         slen = scan - start;
            n00b_string_t *str  = n00b_string_from_raw(s->buf->data + start,
                                                        (int64_t)slen,
                                                        .allocator = s->allocator);
            s->pos = scan + 1; // skip past the NUL
            return n00b_result_ok(n00b_string_t *, str);
        }
        scan++;
    }

    return n00b_result_err(n00b_string_t *, N00B_ERR_OUT_OF_BOUNDS);
}

n00b_result_t(uint64_t)
n00b_bstream_read_uleb128(n00b_bstream_t *s)
{
    uint64_t result = 0;
    int      shift  = 0;

    for (;;) {
        if (!n00b_bstream_can_read(s, 1)) {
            return n00b_result_err(uint64_t, N00B_ERR_OUT_OF_BOUNDS);
        }

        uint8_t byte = (uint8_t)s->buf->data[s->pos];
        s->pos++;

        result |= (uint64_t)(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            break;
        }

        shift += 7;

        if (shift >= 70) {
            return n00b_result_err(uint64_t, N00B_ERR_CORRUPTED);
        }
    }

    return n00b_result_ok(uint64_t, result);
}

n00b_result_t(int64_t)
n00b_bstream_read_sleb128(n00b_bstream_t *s)
{
    int64_t result = 0;
    int     shift  = 0;
    uint8_t byte;

    for (;;) {
        if (!n00b_bstream_can_read(s, 1)) {
            return n00b_result_err(int64_t, N00B_ERR_OUT_OF_BOUNDS);
        }

        byte = (uint8_t)s->buf->data[s->pos];
        s->pos++;

        result |= (int64_t)(byte & 0x7F) << shift;
        shift  += 7;

        if ((byte & 0x80) == 0) {
            break;
        }

        if (shift >= 70) {
            return n00b_result_err(int64_t, N00B_ERR_CORRUPTED);
        }
    }

    // Sign-extend if the high bit of the last byte was set.
    if ((shift < 64) && (byte & 0x40)) {
        result |= -(1LL << shift);
    }

    return n00b_result_ok(int64_t, result);
}

// ============================================================================
// Peek (at offset, no advance)
// ============================================================================

n00b_result_t(uint8_t)
n00b_bstream_peek_u8(n00b_bstream_t *s, size_t offset)
{
    if (offset >= n00b_buffer_len(s->buf)) {
        return n00b_result_err(uint8_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    return n00b_result_ok(uint8_t, read_u8(s->buf->data + offset));
}

n00b_result_t(uint16_t)
n00b_bstream_peek_u16(n00b_bstream_t *s, size_t offset)
{
    if (offset + 2 > n00b_buffer_len(s->buf)) {
        return n00b_result_err(uint16_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint16_t v = read_u16(s->buf->data + offset);

    if (s->swap_endian) {
        v = n00b_swap16(v);
    }

    return n00b_result_ok(uint16_t, v);
}

n00b_result_t(uint32_t)
n00b_bstream_peek_u32(n00b_bstream_t *s, size_t offset)
{
    if (offset + 4 > n00b_buffer_len(s->buf)) {
        return n00b_result_err(uint32_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint32_t v = read_u32(s->buf->data + offset);

    if (s->swap_endian) {
        v = n00b_swap32(v);
    }

    return n00b_result_ok(uint32_t, v);
}

n00b_result_t(uint64_t)
n00b_bstream_peek_u64(n00b_bstream_t *s, size_t offset)
{
    if (offset + 8 > n00b_buffer_len(s->buf)) {
        return n00b_result_err(uint64_t, N00B_ERR_OUT_OF_BOUNDS);
    }

    uint64_t v = read_u64(s->buf->data + offset);

    if (s->swap_endian) {
        v = n00b_swap64(v);
    }

    return n00b_result_ok(uint64_t, v);
}

n00b_result_t(n00b_buffer_t *)
n00b_bstream_peek_bytes(n00b_bstream_t *s, size_t offset, size_t n)
{
    if (offset + n > n00b_buffer_len(s->buf)) {
        return n00b_result_err(n00b_buffer_t *, N00B_ERR_OUT_OF_BOUNDS);
    }

    n00b_buffer_t *result = n00b_buffer_from_bytes(
        s->buf->data + offset,
        n,
        .allocator = s->allocator);

    return n00b_result_ok(n00b_buffer_t *, result);
}

n00b_result_t(n00b_string_t *)
n00b_bstream_peek_cstring(n00b_bstream_t *s, size_t offset)
{
    size_t len  = n00b_buffer_len(s->buf);
    size_t scan = offset;

    if (offset >= len) {
        return n00b_result_err(n00b_string_t *, N00B_ERR_OUT_OF_BOUNDS);
    }

    while (scan < len) {
        if (s->buf->data[scan] == '\0') {
            size_t         slen = scan - offset;
            n00b_string_t *str  = n00b_string_from_raw(s->buf->data + offset,
                                                        (int64_t)slen,
                                                        .allocator = s->allocator);
            return n00b_result_ok(n00b_string_t *, str);
        }
        scan++;
    }

    return n00b_result_err(n00b_string_t *, N00B_ERR_OUT_OF_BOUNDS);
}

// ============================================================================
// Raw access
// ============================================================================

const uint8_t *
n00b_bstream_raw(n00b_bstream_t *s)
{
    if (s->pos >= n00b_buffer_len(s->buf)) {
        return nullptr;
    }

    return (const uint8_t *)(s->buf->data + s->pos);
}

n00b_result_t(const uint8_t *)
n00b_bstream_raw_at(n00b_bstream_t *s, size_t offset)
{
    if (offset >= n00b_buffer_len(s->buf)) {
        return n00b_result_err(const uint8_t *, N00B_ERR_OUT_OF_BOUNDS);
    }

    return n00b_result_ok(const uint8_t *,
                           (const uint8_t *)(s->buf->data + offset));
}

// ============================================================================
// Endianness
// ============================================================================

void
n00b_bstream_set_endian(n00b_bstream_t *s, n00b_endian_t endian)
{
    // Detect host endianness at runtime.
    union {
        uint16_t u;
        uint8_t  b[2];
    } probe = {.u = 1};

    bool host_is_little = (probe.b[0] == 1);

    if (endian == N00B_ENDIAN_LITTLE) {
        s->swap_endian = !host_is_little;
    }
    else {
        s->swap_endian = host_is_little;
    }
}
