/*
 * print.c - Print API implementation.
 *
 * Converts objects to strings via vtable dispatch and writes the
 * resulting UTF-8 bytes to managed file descriptors or conduit topics.
 */

#include "conduit/print.h"
#include "conduit/write.h"
#include "core/alloc.h"
#include "core/syscall.h" // n00b_raw_write_all -- libc-free last-resort write
#include "core/platform.h" // base_nanosleep_ns
#include "core/runtime.h"
#include "core/type_info.h"
#include "core/string.h"
#include "core/buffer.h"
#include "text/strings/format.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "text/strings/fmt_numbers.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// n00b_to_string
// ============================================================================

n00b_string_t *
n00b_to_string(void *obj)
{
    if (!obj) {
        return n00b_string_from_raw("(null)", 6);
    }

    n00b_option_t(n00b_vtable_entry) fn_opt =
        n00b_obj_core_method(obj, N00B_BI_TO_STRING);

    if (n00b_option_is_set(fn_opt)) {
        typedef n00b_string_t *(*to_string_fn)(void *);
        return ((to_string_fn)n00b_option_get(fn_opt))(obj);
    }

    // Fallback: "<typename@0xADDR>"
    auto info_opt = n00b_type_info_for(obj);
    n00b_string_t *tname = r"unknown";

    if (n00b_option_is_set(info_opt)) {
        n00b_string_t *registered = n00b_option_get(info_opt)->name;
        if (registered) {
            tname = registered;
        }
    }

    n00b_string_t *prefix = r"<";
    n00b_string_t *at     = n00b_fmt_pointer(obj);
    n00b_string_t *suffix = r">";

    n00b_string_t *s = n00b_unicode_str_cat(prefix, tname);
    s                = n00b_unicode_str_cat(s, at);
    s                = n00b_unicode_str_cat(s, suffix);

    return s;
}

// ============================================================================
// Topic lookup for print
// ============================================================================

static n00b_conduit_topic_t(n00b_buffer_t *) *
get_print_topic(int fd)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) {
        return nullptr;
    }

    if (fd == 1) {
        return (n00b_conduit_topic_t(n00b_buffer_t *) *)rt->stdout_topic;
    }
    if (fd == 2) {
        return (n00b_conduit_topic_t(n00b_buffer_t *) *)rt->stderr_topic;
    }

    return nullptr;
}

// ============================================================================
// Shared write helper
// ============================================================================

// n00b#490: a print must not vanish.
//
// Every error return in the write path (include/conduit/rw.h) happens BEFORE
// the deliver step -- once the publisher claim succeeds, that path always
// returns Ok. So an Err from n00b_write means the payload was never
// delivered, and writing the bytes directly cannot double-print them.
//
// ALREADY_CLAIMED is the transient case: another thread holds the topic's
// publisher for the length of its own deliver. Retry it rather than going
// straight to the fd, because the fallback bypasses the topic -- anything
// subscribed to stdout/stderr (a tee, a log capture) does not observe bytes
// written directly to the descriptor. The other codes (CLOSED, SHUTDOWN,
// ALLOC) do not improve by retrying.
//
// The retry has to outlast a deliver, which includes a write syscall. A bare
// spin of a few try_claims is a sub-microsecond window against a holder that
// runs for microseconds to milliseconds, so it would lose nearly every race
// it exists to win and leave the fallback as the common path -- defeating the
// point of retrying at all. Back off instead, starting at 50us and doubling,
// for a total ceiling near 1.5ms.
#define PRINT_CLAIM_RETRIES   5
#define PRINT_CLAIM_BACKOFF_NS 50000ULL

// Fall back only when the topic was resolved from `fd`. A caller-supplied
// .topic says nothing about which descriptor it drains to -- `fd` is still
// its default of 1 -- so writing there would misdirect the line to stdout.
static void
print_write(n00b_conduit_topic_t(n00b_buffer_t *) *topic,
            n00b_buffer_t                         *buf,
            bool                                   sync,
            bool                                   fd_is_topics,
            int                                    fd,
            n00b_string_t                         *s)
{
    uint64_t backoff = PRINT_CLAIM_BACKOFF_NS;

    for (int attempt = 0; attempt <= PRINT_CLAIM_RETRIES; attempt++) {
        auto wr = n00b_write(n00b_buffer_t *, topic, buf, .sync = sync);
        if (n00b_result_is_ok(wr)) {
            return;
        }
        if (n00b_result_get_err(wr) != N00B_CONDUIT_ERR_ALREADY_CLAIMED) {
            break;
        }
        if (attempt < PRINT_CLAIM_RETRIES) {
            base_nanosleep_ns(backoff);
            backoff *= 2;
        }
    }

    if (fd_is_topics) {
        n00b_raw_write_all(fd, s->data, (unsigned long)s->u8_bytes);
    }
}

static void
do_print_string(n00b_string_t *s, n00b_option_t(n00b_string_t *) end, int fd,
                n00b_conduit_topic_t(n00b_buffer_t *) *topic, bool sync)
{
    n00b_string_t *end_str = n00b_option_is_set(end)
        ? n00b_option_get(end)
        : n00b_string_from_raw("\n", 1);

    s = n00b_unicode_str_cat(s, end_str);

    // Whether `fd` describes where `topic` ends up, and so whether it is a
    // sound target if publishing fails.
    bool fd_is_topics = (topic == nullptr);

    if (!topic) {
        topic = get_print_topic(fd);
    }

    if (!topic) {
        // No runtime yet, or fd is neither 1 nor 2. Before #490 this
        // dropped the line outright.
        //
        // Still does on Windows for an fd outside {1, 2}: resolving an
        // arbitrary descriptor there needs _get_osfhandle, i.e. the CRT,
        // which n00b_raw_write_all must not touch. POSIX writes to any fd.
        n00b_raw_write_all(fd, s->data, (unsigned long)s->u8_bytes);
        return;
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    n00b_allocator_t          *alloc = base && base->conduit
                                           ? base->conduit->allocator
                                           : nullptr;
    n00b_buffer_t *buf = n00b_buffer_from_bytes(s->data,
                                                (int64_t)s->u8_bytes,
                                                .allocator = alloc);
    print_write(topic, buf, sync, fd_is_topics, fd, s);
}

// ============================================================================
// n00b_print
// ============================================================================

void
n00b_print(void *obj) _kargs
{
    n00b_conduit_topic_t(n00b_buffer_t *) *topic = nullptr;
    n00b_option_t(n00b_string_t *)          end   = n00b_option_none(n00b_string_t *);
    int                                    fd    = 1;
    bool                                   sync  = true;
}
{
    n00b_string_t *s = n00b_to_string(obj);

    do_print_string(s, end, fd, topic, sync);
}

// ============================================================================
// n00b_printf
// ============================================================================

void
n00b_printf(const char *fmt, +) _kargs
{
    n00b_conduit_topic_t(n00b_buffer_t *) *topic = nullptr;
    int                                    fd    = 1;
    n00b_option_t(n00b_string_t *)          end   = n00b_option_none(n00b_string_t *);
    bool                                   sync  = true;
}
{
    n00b_string_t *s = _n00b_format_impl(fmt, (int32_t)strlen(fmt), vargs);
    do_print_string(s, end, fd, topic, sync);
}
