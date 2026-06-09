/* Live fixture runner for the WP-013 wax cache tool. */

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/file.h"
#include "conduit/print.h"
#include "rocs/n00b_rocs.h"
#include "rocs/wax.h"

#define ROCS_WAX_CACHE_LIVE_COMMIT_TOPIC_ID 0x013041u

extern n00b_result_t(bool)
rocs_wax_cache_print_header(int32_t format);

extern n00b_result_t(bool)
rocs_wax_cache_print_hit(n00b_store_t     *store,
                         n00b_query_hit_t *hit,
                         int32_t           format);

typedef struct {
    uint64_t lines_read;
    uint64_t events_ingested;
    uint64_t events_rejected;
} rocs_wax_cache_live_fixture_stats_t;

static bool
rocs_wax_cache_live_str_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_live_read_text(n00b_string_t *path)
{
    if (rocs_wax_cache_live_str_empty(path)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_file_t *file  = n00b_result_get(open_r);
    auto         buf_r = n00b_file_as_buffer(file);
    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(file);
        return n00b_result_err(n00b_string_t *, N00B_ROCS_WAX_ERR_SOURCE);
    }

    n00b_buffer_t *copy = n00b_buffer_copy(n00b_result_get(buf_r));
    n00b_file_close(file);
    return n00b_result_ok(n00b_string_t *, n00b_buffer_to_string(copy));
}

static n00b_result_t(rocs_wax_cache_live_fixture_stats_t)
rocs_wax_cache_live_ingest_fixture(n00b_store_t   *store,
                                   n00b_string_t  *path)
{
    rocs_wax_cache_live_fixture_stats_t stats = {};
    if (rocs_wax_cache_live_str_empty(path)) {
        return n00b_result_ok(rocs_wax_cache_live_fixture_stats_t, stats);
    }

    auto text_r = rocs_wax_cache_live_read_text(path);
    if (n00b_result_is_err(text_r)) {
        return n00b_result_err(rocs_wax_cache_live_fixture_stats_t,
                               n00b_result_get_err(text_r));
    }

    n00b_string_t *text  = n00b_result_get(text_r);
    size_t         start = 0;
    for (size_t i = 0; i <= text->u8_bytes; i++) {
        if (i < text->u8_bytes && text->data[i] != '\n') {
            continue;
        }
        if (i == text->u8_bytes && start == i) {
            break;
        }

        size_t end = i;
        if (end > start && text->data[end - 1] == '\r') {
            end--;
        }

        n00b_string_t *line = n00b_string_from_raw(text->data + start,
                                                   (int64_t)(end - start));
        stats.lines_read++;

        auto record_r = n00b_rocs_wax_record_from_line(line);
        if (n00b_result_is_err(record_r)) {
            stats.events_rejected++;
            start = i + 1;
            continue;
        }

        auto ingest_r = n00b_store_ingest(store, n00b_result_get(record_r));
        if (n00b_result_is_err(ingest_r)) {
            return n00b_result_err(rocs_wax_cache_live_fixture_stats_t,
                                   N00B_ROCS_WAX_ERR_STORE);
        }
        stats.events_ingested++;
        start = i + 1;
    }

    auto flush_r = n00b_store_flush(store);
    if (n00b_result_is_err(flush_r)) {
        return n00b_result_err(rocs_wax_cache_live_fixture_stats_t,
                               N00B_ROCS_WAX_ERR_STORE);
    }

    return n00b_result_ok(rocs_wax_cache_live_fixture_stats_t, stats);
}

static n00b_result_t(uint64_t)
rocs_wax_cache_live_snapshot_count(n00b_store_t      *store,
                                   n00b_filter_t     *filter,
                                   n00b_store_pos_t  *resume,
                                   uint64_t           limit)
{
    auto view_r = n00b_query_view(store,
                                  filter,
                                  .resume = resume,
                                  .limit  = limit);
    if (n00b_result_is_err(view_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(view_r));
    }

    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view);
    if (n00b_result_is_err(cursor_r)) {
        (void)n00b_query_view_close(view);
        return n00b_result_err(uint64_t, n00b_result_get_err(cursor_r));
    }

    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);
    uint64_t             count  = 0;
    while (true) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            return n00b_result_err(uint64_t, n00b_result_get_err(next_r));
        }
        if (!n00b_option_is_set(n00b_result_get(next_r))) {
            break;
        }
        count++;
    }

    auto cursor_close_r = n00b_query_cursor_close(cursor);
    auto view_close_r   = n00b_query_view_close(view);
    if (n00b_result_is_err(cursor_close_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(cursor_close_r));
    }
    if (n00b_result_is_err(view_close_r)) {
        return n00b_result_err(uint64_t, n00b_result_get_err(view_close_r));
    }
    return n00b_result_ok(uint64_t, count);
}

static n00b_result_t(n00b_string_t *)
rocs_wax_cache_live_cursor_resume(n00b_query_cursor_t *cursor,
                                  n00b_string_t       *fallback)
{
    auto pos_r = n00b_query_cursor_position(cursor);
    if (n00b_result_is_err(pos_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(pos_r));
    }
    n00b_option_t(n00b_store_pos_t) pos_opt = n00b_result_get(pos_r);
    if (n00b_option_is_set(pos_opt)) {
        return n00b_store_pos_encode(n00b_option_get(pos_opt));
    }
    if (!rocs_wax_cache_live_str_empty(fallback)) {
        return n00b_result_ok(n00b_string_t *, fallback);
    }
    return n00b_result_ok(n00b_string_t *, r"");
}

static void
rocs_wax_cache_live_detach_commit_topic(n00b_store_t    *store,
                                        n00b_conduit_t  *conduit)
{
    if (store != nullptr) {
        (void)n00b_store_set_commit_topic(store, nullptr);
    }
    if (conduit != nullptr) {
        n00b_conduit_destroy(conduit);
    }
}

n00b_result_t(bool)
rocs_wax_cache_run_live(n00b_store_t    *store,
                        n00b_filter_t   *filter,
                        n00b_string_t   *fixture,
                        n00b_string_t   *resume_token,
                        uint64_t         limit,
                        int32_t          format)
{
    n00b_store_pos_t  resume_pos = {};
    n00b_store_pos_t *resume     = nullptr;
    if (!rocs_wax_cache_live_str_empty(resume_token)) {
        auto resume_r = n00b_store_pos_decode(resume_token);
        if (n00b_result_is_err(resume_r)) {
            return n00b_result_err(bool, N00B_QUERY_ERR_INVALID_OPTION);
        }
        resume_pos = n00b_result_get(resume_r);
        resume     = &resume_pos;
    }

    auto conduit_r = n00b_conduit_new();
    if (n00b_result_is_err(conduit_r)) {
        return n00b_result_err(bool, n00b_result_get_err(conduit_r));
    }
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);

    auto topic_r = n00b_store_commit_topic_get(
        conduit,
        N00B_CONDUIT_URI_USER_EVENT(ROCS_WAX_CACHE_LIVE_COMMIT_TOPIC_ID));
    if (n00b_result_is_err(topic_r)) {
        rocs_wax_cache_live_detach_commit_topic(nullptr, conduit);
        return n00b_result_err(bool, n00b_result_get_err(topic_r));
    }

    auto set_topic_r =
        n00b_store_set_commit_topic(store, n00b_result_get(topic_r));
    if (n00b_result_is_err(set_topic_r)) {
        rocs_wax_cache_live_detach_commit_topic(nullptr, conduit);
        return n00b_result_err(bool, n00b_result_get_err(set_topic_r));
    }

    auto view_r = n00b_query_view(store,
                                  filter,
                                  .mode   = N00B_QUERY_MODE_LIVE,
                                  .resume = resume,
                                  .limit  = limit);
    if (n00b_result_is_err(view_r)) {
        rocs_wax_cache_live_detach_commit_topic(store, conduit);
        return n00b_result_err(bool, n00b_result_get_err(view_r));
    }

    n00b_query_view_t *view = n00b_result_get(view_r);
    auto cursor_r = n00b_query_cursor(view);
    if (n00b_result_is_err(cursor_r)) {
        (void)n00b_query_view_close(view);
        rocs_wax_cache_live_detach_commit_topic(store, conduit);
        return n00b_result_err(bool, n00b_result_get_err(cursor_r));
    }
    n00b_query_cursor_t *cursor = n00b_result_get(cursor_r);

    auto fixture_r = rocs_wax_cache_live_ingest_fixture(store, fixture);
    if (n00b_result_is_err(fixture_r)) {
        (void)n00b_query_cursor_close(cursor);
        (void)n00b_query_view_close(view);
        rocs_wax_cache_live_detach_commit_topic(store, conduit);
        return n00b_result_err(bool, n00b_result_get_err(fixture_r));
    }
    rocs_wax_cache_live_fixture_stats_t stats = n00b_result_get(fixture_r);

    auto expected_r = rocs_wax_cache_live_snapshot_count(store,
                                                         filter,
                                                         resume,
                                                         limit);
    if (n00b_result_is_err(expected_r)) {
        (void)n00b_query_cursor_close(cursor);
        (void)n00b_query_view_close(view);
        rocs_wax_cache_live_detach_commit_topic(store, conduit);
        return n00b_result_err(bool, n00b_result_get_err(expected_r));
    }

    uint64_t expected = n00b_result_get(expected_r);
    uint64_t delivered = 0;
    auto header_r = rocs_wax_cache_print_header(format);
    if (n00b_result_is_err(header_r)) {
        (void)n00b_query_cursor_close(cursor);
        (void)n00b_query_view_close(view);
        rocs_wax_cache_live_detach_commit_topic(store, conduit);
        return header_r;
    }

    while (delivered < expected) {
        auto next_r = n00b_query_cursor_next(cursor);
        if (n00b_result_is_err(next_r)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            rocs_wax_cache_live_detach_commit_topic(store, conduit);
            return n00b_result_err(bool, n00b_result_get_err(next_r));
        }
        n00b_option_t(n00b_query_hit_t *) hit_opt = n00b_result_get(next_r);
        if (!n00b_option_is_set(hit_opt)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            rocs_wax_cache_live_detach_commit_topic(store, conduit);
            return n00b_result_err(bool, N00B_QUERY_ERR_EXECUTION);
        }

        auto print_r = rocs_wax_cache_print_hit(store,
                                                n00b_option_get(hit_opt),
                                                format);
        if (n00b_result_is_err(print_r)) {
            (void)n00b_query_cursor_close(cursor);
            (void)n00b_query_view_close(view);
            rocs_wax_cache_live_detach_commit_topic(store, conduit);
            return print_r;
        }
        delivered++;
    }

    auto resume_r = rocs_wax_cache_live_cursor_resume(cursor, resume_token);
    n00b_string_t *next_resume = r"";
    if (n00b_result_is_ok(resume_r)) {
        next_resume = n00b_result_get(resume_r);
    }

    auto cursor_close_r = n00b_query_cursor_close(cursor);
    auto view_close_r   = n00b_query_view_close(view);
    rocs_wax_cache_live_detach_commit_topic(store, conduit);
    if (n00b_result_is_err(cursor_close_r)) {
        return n00b_result_err(bool, n00b_result_get_err(cursor_close_r));
    }
    if (n00b_result_is_err(view_close_r)) {
        return n00b_result_err(bool, n00b_result_get_err(view_close_r));
    }
    if (n00b_result_is_err(resume_r)) {
        return n00b_result_err(bool, n00b_result_get_err(resume_r));
    }

    n00b_eprintf("n00b-rocs-wax-cache: live lines=«#» ingested=«#» rejected=«#» delivered=«#» dropped=0 resume=«#»",
                 (int64_t)stats.lines_read,
                 (int64_t)stats.events_ingested,
                 (int64_t)stats.events_rejected,
                 (int64_t)delivered,
                 next_resume);
    return n00b_result_ok(bool, true);
}
