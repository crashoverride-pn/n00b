#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "text/unicode/encoding.h"
#include "internal/text/unicode/raw.h"
#include "core/alloc.h"
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

static const char *
portable_read_path(const char *path)
{
#ifdef _WIN32
    if (path != nullptr && strcmp(path, "/dev/null") == 0) {
        return "NUL";
    }
#endif

    return path;
}

// ---------------------------------------------------------------------------
// Integer → string
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_from_int(int64_t n) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    char  buf[21]; // enough for INT64_MIN
    char *p = buf + 20;
    buf[20] = '\0';

    if (n == 0) {
        return n00b_string_from_raw("0", 1, .allocator = allocator);
    }

    if (n < 0) {
        // Work with positive magnitude using unsigned to avoid UB at INT64_MIN.
        uint64_t mag = (uint64_t)(-(n + 1)) + 1;
        while (mag > 0) {
            *--p = '0' + (char)(mag % 10);
            mag /= 10;
        }
        *--p = '-';
    }
    else {
        uint64_t mag = (uint64_t)n;
        while (mag > 0) {
            *--p = '0' + (char)(mag % 10);
            mag /= 10;
        }
    }

    uint32_t len = (uint32_t)(buf + 20 - p);
    return n00b_string_from_raw(p, len, .allocator = allocator); // all ASCII
}

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------

static const char hex_lower_tbl[16] __attribute__((nonstring)) = "0123456789abcdef";
static const char hex_upper_tbl[16] __attribute__((nonstring)) = "0123456789ABCDEF";

n00b_string_t *
n00b_unicode_str_to_hex(n00b_string_t *s) _kargs
{
    bool              upper     = false;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    uint32_t    len = (uint32_t)s->u8_bytes;
    uint32_t    out = len * 2;
    char       *buf = n00b_alloc_array(char, out + 1);
    const char *map = upper ? hex_upper_tbl : hex_lower_tbl;

    for (uint32_t i = 0; i < len; i++) {
        uint8_t c      = (uint8_t)s->data[i];
        buf[i * 2]     = map[c >> 4];
        buf[i * 2 + 1] = map[c & 0x0f];
    }
    buf[out] = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, out, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// ---------------------------------------------------------------------------
// C string conversion
// ---------------------------------------------------------------------------

char *
n00b_unicode_str_to_cstr(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    uint32_t len    = (uint32_t)s->u8_bytes;
    char    *result = n00b_alloc_array(char, len + 1);
    memcpy(result, s->data, len);
    result[len] = '\0';
    return result;
}

// ---------------------------------------------------------------------------
// Literal form
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_to_literal(n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    n00b_string_t *escaped = n00b_unicode_str_escape(s, .allocator = allocator);

    // Build: '"' + escaped + '"'
    uint32_t elen  = (uint32_t)escaped->u8_bytes;
    uint32_t total = elen + 2;
    char    *buf   = n00b_alloc_array(char, total + 1);

    buf[0] = '"';
    memcpy(buf + 1, escaped->data, elen);
    buf[total - 1] = '"';
    buf[total]     = '\0';

    n00b_string_t *result = n00b_string_from_raw(buf, total, .allocator = allocator);
    n00b_free(buf);
    return result;
}

// ---------------------------------------------------------------------------
// Codepoint → string
// ---------------------------------------------------------------------------

n00b_string_t *
n00b_unicode_str_from_codepoint(n00b_codepoint_t cp) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    // Validate codepoint.
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        return n00b_string_from_raw("", 0, .allocator = allocator);
    }

    char     enc[4];
    uint32_t enc_len = n00b_unicode_utf8_encode(cp, enc);
    return n00b_string_from_raw(enc, enc_len, .allocator = allocator);
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

n00b_result_t(n00b_string_t *) n00b_unicode_str_from_file(const char *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    int fd = open(portable_read_path(path), O_RDONLY);
    if (fd < 0) {
        return n00b_result_err(n00b_string_t *, errno);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int e = errno;
        close(fd);
        return n00b_result_err(n00b_string_t *, e);
    }

    off_t file_size = st.st_size;
    if (file_size == 0) {
        close(fd);
        n00b_string_t *empty = n00b_string_from_raw("", 0, .allocator = allocator);
        return n00b_result_ok(n00b_string_t *, empty);
    }

    char   *buf        = n00b_alloc_array(char, (size_t)file_size + 1);
    ssize_t total_read = 0;

    while (total_read < file_size) {
        ssize_t n = read(fd, buf + total_read, (size_t)(file_size - total_read));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            int e = errno;
            close(fd);
            n00b_free(buf);
            return n00b_result_err(n00b_string_t *, e);
        }
        if (n == 0)
            break; // EOF
        total_read += n;
    }
    close(fd);
    buf[total_read] = '\0';

    // Validate UTF-8.
    if (!n00b_unicode_utf8_validate(buf, (uint32_t)total_read)) {
        n00b_free(buf);
        return n00b_result_err(n00b_string_t *, N00B_ERR_STR_INVALID_ESCAPE);
    }

    n00b_string_t *result = n00b_string_from_raw(buf, total_read, .allocator = allocator);
    n00b_free(buf);
    return n00b_result_ok(n00b_string_t *, result);
}

// ---------------------------------------------------------------------------
// C string array
// ---------------------------------------------------------------------------

n00b_array_t(n00b_cstr_t) n00b_unicode_make_cstr_array(n00b_array_t(n00b_string_t *) parts) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!allocator)
        allocator = nullptr;

    uint32_t count                   = (uint32_t)parts.len;
    n00b_array_t(n00b_cstr_t) result = n00b_array_new(n00b_cstr_t, count);
    for (uint32_t i = 0; i < count; i++) {
        result.data[i] = n00b_unicode_str_to_cstr(parts.data[i], .allocator = allocator);
    }
    result.len = count;
    return result;
}
