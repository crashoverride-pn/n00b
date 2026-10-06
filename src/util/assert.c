#include "n00b.h"
#include "conduit/print.h"
#include "core/exit.h"
#include "core/string.h"
#include "core/runtime.h"
#include "core/syscall.h"
#include "util/assert.h"

// An assertion that fires INSIDE a stop-the-world collection cannot report
// itself the ordinary way: n00b_eprintf formats through n00b_string_t, which
// allocates, and allocating mid-collection re-enters the collector and wedges
// the process. The failure then presents as a hang rather than an abort, which
// is strictly worse than the assertion it was trying to report -- the whole
// point of `require` is to stop loudly.
//
// n00b#234 is exactly this: a TYPE_LAYOUT scan descriptor check fires from
// n00b_gc_map_mark_type_layout during n00b_scan_thread_stacks, and the process
// hangs in the reporter instead of aborting. It survived a 300s timeout, so it
// read as an infinite loop in the collector rather than as a failed invariant.
//
// While the world is stopped, fall back to raw writes: no allocation, no
// locks, no formatting machinery. Same reasoning (and the same primitive) as
// the crash dumper in core/crash.c.
static bool
assert_world_is_stopped(void)
{
    if (!n00b_default_runtime_is_set()) {
        return false;
    }
    n00b_runtime_t *rt = n00b_default_runtime_or_null();
    return rt != nullptr && n00b_atomic_load(&rt->stw_active);
}

static void
assert_raw_str(const char *s)
{
    if (s == nullptr) {
        return;
    }
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    n00b_raw_write_all_brief(2, s, (unsigned long)n);
}

static void
assert_raw_int(int64_t v)
{
    char b[24];
    int  n = 0;
    if (v < 0) {
        assert_raw_str("-");
        v = -v;
    }
    if (v == 0) {
        b[n++] = '0';
    }
    while (v != 0 && n < (int)sizeof(b)) {
        b[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        char t = b[i];
        b[i]   = b[j];
        b[j]   = t;
    }
    n00b_raw_write_all_brief(2, b, (unsigned long)n);
}

// Raw equivalent of the rich reports below. Kept byte-compatible in wording so
// existing log greps keep matching.
static void
assert_raw_report(const char *kind,
                  const char *cond,
                  const char *msg,
                  const char *func,
                  const char *file,
                  int         line)
{
    assert_raw_str(kind);
    assert_raw_str(cond);
    if (msg != nullptr) {
        assert_raw_str("\nMessage: ");
        assert_raw_str(msg);
    }
    assert_raw_str("\nFunction: ");
    assert_raw_str(func);
    assert_raw_str("\nLocation: ");
    assert_raw_str(file);
    assert_raw_str(":");
    assert_raw_int((int64_t)line);
    assert_raw_str("\n[reported without formatting: the world is stopped]\n");
}

[[noreturn]] void
_n00b_assert_failed(const char *expr,
                    const char *func,
                    const char *file,
                    int         line)
{
    if (assert_world_is_stopped()) {
        assert_raw_report("ASSERTION FAILED: ", expr, nullptr, func, file, line);
        n00b_abort();
    }
    n00b_eprintf("ASSERTION FAILED: «#»\nFunction: «#»\nLocation: «#»:«#»",
                 n00b_string_from_cstr(expr),
                 n00b_string_from_cstr(func),
                 n00b_string_from_cstr(file),
                 (int64_t)line);
    n00b_abort();
}

[[noreturn]] void
_n00b_require_failed(const char *cond,
                     const char *msg,
                     const char *func,
                     const char *file,
                     int         line)
{
    if (assert_world_is_stopped()) {
        assert_raw_report("REQUIREMENT FAILED: ", cond, msg ? msg : "",
                          func, file, line);
        n00b_abort();
    }
    n00b_eprintf("REQUIREMENT FAILED: «#»\nMessage: «#»\nFunction: «#»\nLocation: «#»:«#»",
                 n00b_string_from_cstr(cond),
                 n00b_string_from_cstr(msg ? msg : ""),
                 n00b_string_from_cstr(func),
                 n00b_string_from_cstr(file),
                 (int64_t)line);
    n00b_abort();
}

