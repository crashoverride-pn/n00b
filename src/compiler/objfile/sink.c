#include "compiler/objfile/sink.h"

#include "core/file.h"
#include "util/assert.h"
#include "util/path.h"

#include <errno.h>

struct n00b_objfile_sink_result {
    n00b_string_t                 *destination_path;
    n00b_string_t                 *temp_path;
    bool                           has_temp_path;
    uint64_t                       bytes_requested;
    uint64_t                       bytes_written;
    n00b_objfile_sink_mode_t       mode_requested;
    n00b_objfile_sink_mode_t       mode_used;
    n00b_objfile_sink_overwrite_t  overwrite;
    bool                           commit_attempted;
    bool                           commit_completed;
    bool                           rollback_attempted;
    bool                           rollback_succeeded;
    bool                           cleanup_attempted;
    bool                           cleanup_succeeded;
    uint32_t                       file_mode_requested;
    bool                           has_file_mode_requested;
    uint32_t                       file_mode_applied;
    bool                           has_file_mode_applied;
    bool                           file_mode_supported;
};

struct n00b_objfile_sink_error {
    n00b_objfile_sink_error_code_t code;
    n00b_string_t                 *message;
    n00b_objfile_sink_result_t    *facts;
    bool                           has_facts;
    n00b_string_t                 *destination_path;
    bool                           has_destination_path;
    n00b_string_t                 *temp_path;
    bool                           has_temp_path;
    n00b_objfile_sink_mode_t       mode;
    bool                           has_mode;
    n00b_objfile_sink_overwrite_t  overwrite;
    bool                           has_overwrite;
    int64_t                        detail;
    bool                           has_detail;
};

#define OBJFILE_SINK_ERR(T, code, message, allocator)                                         \
    n00b_result_err_payload(                                                                  \
        T,                                                                                    \
        n00b_objfile_sink_error_t *,                                                          \
        _n00b_objfile_sink_error_new((code), (message), (allocator)))

#define OBJFILE_SINK_ERR_PAYLOAD(T, error)                                                    \
    n00b_result_err_payload(T, n00b_objfile_sink_error_t *, (error))

static n00b_objfile_sink_error_t *
_n00b_objfile_sink_error_new(n00b_objfile_sink_error_code_t code,
                             n00b_string_t                 *message,
                             n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_error_t *error =
        n00b_alloc(n00b_objfile_sink_error_t, .allocator = allocator);

    error->code                 = code;
    error->message              = message;
    error->facts                = nullptr;
    error->has_facts            = false;
    error->destination_path     = nullptr;
    error->has_destination_path = false;
    error->temp_path            = nullptr;
    error->has_temp_path        = false;
    error->mode                 = N00B_OBJFILE_SINK_MODE_ATOMIC;
    error->has_mode             = false;
    error->overwrite            = N00B_OBJFILE_SINK_REJECT_EXISTING;
    error->has_overwrite        = false;
    error->detail               = 0;
    error->has_detail           = false;

    return error;
}

static n00b_objfile_sink_result_t *
_n00b_objfile_sink_result_new(n00b_string_t                 *destination_path,
                              uint64_t                       bytes_requested,
                              n00b_objfile_sink_mode_t       mode_requested,
                              n00b_objfile_sink_mode_t       mode_used,
                              n00b_objfile_sink_overwrite_t  overwrite,
                              n00b_option_t(uint32_t)        file_mode,
                              n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_result_t *result =
        n00b_alloc(n00b_objfile_sink_result_t, .allocator = allocator);

    result->destination_path        = destination_path;
    result->temp_path               = nullptr;
    result->has_temp_path           = false;
    result->bytes_requested         = bytes_requested;
    result->bytes_written           = 0;
    result->mode_requested          = mode_requested;
    result->mode_used               = mode_used;
    result->overwrite               = overwrite;
    result->commit_attempted        = false;
    result->commit_completed        = false;
    result->rollback_attempted      = false;
    result->rollback_succeeded      = false;
    result->cleanup_attempted       = false;
    result->cleanup_succeeded       = false;
    result->file_mode_requested     = 0;
    result->has_file_mode_requested = false;
    result->file_mode_applied       = 0;
    result->has_file_mode_applied   = false;
    result->file_mode_supported     = true;

    if (n00b_option_is_set(file_mode)) {
        result->file_mode_requested     = n00b_option_get(file_mode);
        result->has_file_mode_requested = true;
    }

    return result;
}

static void
_n00b_objfile_sink_result_set_temp(n00b_objfile_sink_result_t *result,
                                   n00b_string_t              *temp_path)
{
    result->temp_path     = temp_path;
    result->has_temp_path = temp_path != nullptr;
}

static void
_n00b_objfile_sink_result_set_mode_request(
    n00b_objfile_sink_result_t *result,
    uint32_t                    mode)
{
    result->file_mode_requested     = mode;
    result->has_file_mode_requested = true;
}

static void
_n00b_objfile_sink_result_set_mode_applied(
    n00b_objfile_sink_result_t *result,
    uint32_t                    mode)
{
    result->file_mode_applied     = mode;
    result->has_file_mode_applied = true;
    result->file_mode_supported   = true;
}

static void
_n00b_objfile_sink_error_attach_facts(
    n00b_objfile_sink_error_t  *error,
    n00b_objfile_sink_result_t *facts)
{
    error->facts     = facts;
    error->has_facts = facts != nullptr;

    if (facts != nullptr) {
        error->destination_path     = facts->destination_path;
        error->has_destination_path = facts->destination_path != nullptr;
        if (facts->has_temp_path) {
            error->temp_path     = facts->temp_path;
            error->has_temp_path = facts->temp_path != nullptr;
        }
    }
}

static n00b_objfile_sink_error_t *
_n00b_objfile_sink_error_with_destination(
    n00b_objfile_sink_error_code_t code,
    n00b_string_t                 *message,
    n00b_string_t                 *destination_path,
    n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_error_t *error =
        _n00b_objfile_sink_error_new(code, message, allocator);

    error->destination_path     = destination_path;
    error->has_destination_path = destination_path != nullptr;

    return error;
}

static n00b_objfile_sink_error_t *
_n00b_objfile_sink_error_with_facts(
    n00b_objfile_sink_error_code_t code,
    n00b_string_t                 *message,
    n00b_objfile_sink_result_t    *facts,
    n00b_objfile_sink_mode_t       mode,
    n00b_objfile_sink_overwrite_t  overwrite,
    int64_t                        detail,
    bool                           has_detail,
    n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_error_t *error =
        _n00b_objfile_sink_error_new(code, message, allocator);

    error->mode          = mode;
    error->has_mode      = true;
    error->overwrite     = overwrite;
    error->has_overwrite = true;
    error->detail        = detail;
    error->has_detail    = has_detail;
    _n00b_objfile_sink_error_attach_facts(error, facts);

    return error;
}

static n00b_objfile_sink_error_t *
_n00b_objfile_sink_error_with_request(
    n00b_objfile_sink_error_code_t code,
    n00b_string_t                 *message,
    n00b_string_t                 *destination_path,
    n00b_objfile_sink_mode_t       mode,
    n00b_objfile_sink_overwrite_t  overwrite,
    int64_t                        detail,
    bool                           has_detail,
    n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_error_t *error =
        _n00b_objfile_sink_error_with_destination(code,
                                                  message,
                                                  destination_path,
                                                  allocator);

    error->mode          = mode;
    error->has_mode      = true;
    error->overwrite     = overwrite;
    error->has_overwrite = true;
    error->detail        = detail;
    error->has_detail    = has_detail;

    return error;
}

static bool
_n00b_objfile_sink_mode_valid(n00b_objfile_sink_mode_t mode)
{
    return mode == N00B_OBJFILE_SINK_MODE_ATOMIC
           || mode == N00B_OBJFILE_SINK_MODE_DIRECT;
}

static bool
_n00b_objfile_sink_overwrite_valid(n00b_objfile_sink_overwrite_t overwrite)
{
    return overwrite == N00B_OBJFILE_SINK_REJECT_EXISTING
           || overwrite == N00B_OBJFILE_SINK_REPLACE_EXISTING;
}

static n00b_path_commit_policy_t
_n00b_objfile_sink_commit_policy(n00b_objfile_sink_overwrite_t overwrite)
{
    return overwrite == N00B_OBJFILE_SINK_REPLACE_EXISTING
               ? N00B_PATH_COMMIT_REPLACE_EXISTING
               : N00B_PATH_COMMIT_REJECT_EXISTING;
}

static n00b_objfile_sink_error_code_t
_n00b_objfile_sink_open_error_code(int err)
{
    return err == ENOSYS ? N00B_OBJFILE_SINK_ERR_UNSUPPORTED
                         : N00B_OBJFILE_SINK_ERR_WRITE_FAILED;
}

static n00b_objfile_sink_error_code_t
_n00b_objfile_sink_invalid_or_open_error_code(int err)
{
    if (err == EINVAL) {
        return N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT;
    }
    return _n00b_objfile_sink_open_error_code(err);
}

static n00b_objfile_sink_error_code_t
_n00b_objfile_sink_commit_error_code(int err)
{
    return err == ENOSYS ? N00B_OBJFILE_SINK_ERR_UNSUPPORTED
                         : N00B_OBJFILE_SINK_ERR_COMMIT_FAILED;
}

typedef struct {
    bool     has_mode;
    bool     failed;
    bool     unsupported;
    uint32_t mode;
    int64_t  detail;
} n00b_objfile_sink_mode_plan_t;

static n00b_objfile_sink_mode_plan_t
_n00b_objfile_sink_plan_mode(n00b_string_t           *destination_path,
                             n00b_option_t(uint32_t) file_mode,
                             bool                    preserve_existing_mode)
{
    n00b_objfile_sink_mode_plan_t plan = {};

    if (n00b_option_is_set(file_mode)) {
        plan.has_mode = true;
        plan.mode     = n00b_option_get(file_mode);
        return plan;
    }

    if (!preserve_existing_mode || !n00b_path_exists(destination_path)) {
        return plan;
    }

    auto mode_r = n00b_path_get_mode(destination_path);
    if (n00b_result_is_ok(mode_r)) {
        plan.has_mode = true;
        plan.mode     = n00b_result_get(mode_r);
        return plan;
    }

    int err = n00b_result_get_err(mode_r);
    if (err == ENOENT) {
        return plan;
    }
    if (err == ENOSYS) {
        plan.unsupported = true;
        return plan;
    }

    plan.failed = true;
    plan.detail = err;
    return plan;
}

static n00b_objfile_sink_error_t *
_n00b_objfile_sink_error_from_facts(
    n00b_objfile_sink_error_code_t code,
    n00b_string_t                 *message,
    n00b_objfile_sink_result_t    *facts,
    int64_t                        detail,
    bool                           has_detail,
    n00b_allocator_t              *allocator)
{
    return _n00b_objfile_sink_error_with_facts(code,
                                               message,
                                               facts,
                                               facts->mode_requested,
                                               facts->overwrite,
                                               detail,
                                               has_detail,
                                               allocator);
}

static void
_n00b_objfile_sink_cleanup_temp(n00b_objfile_sink_result_t *facts)
{
    if (facts == nullptr || !facts->has_temp_path) {
        return;
    }

    facts->cleanup_attempted = true;
    auto cleanup_r = n00b_file_unlink(facts->temp_path, .ignore_missing = true);
    facts->cleanup_succeeded = n00b_result_is_ok(cleanup_r);
}

static n00b_result_t(n00b_objfile_sink_result_t *)
_n00b_objfile_sink_finish_mode_facts(
    n00b_objfile_sink_result_t *facts,
    n00b_allocator_t           *allocator)
{
    if (!facts->file_mode_supported) {
        return n00b_result_ok(n00b_objfile_sink_result_t *, facts);
    }

    auto mode_r = n00b_path_get_mode(facts->destination_path);
    if (n00b_result_is_ok(mode_r)) {
        _n00b_objfile_sink_result_set_mode_applied(facts,
                                                   n00b_result_get(mode_r));
        return n00b_result_ok(n00b_objfile_sink_result_t *, facts);
    }

    int err = n00b_result_get_err(mode_r);
    if (err == ENOSYS) {
        facts->file_mode_supported = false;
        return n00b_result_ok(n00b_objfile_sink_result_t *, facts);
    }

    return OBJFILE_SINK_ERR_PAYLOAD(
        n00b_objfile_sink_result_t *,
        _n00b_objfile_sink_error_from_facts(
            N00B_OBJFILE_SINK_ERR_MODE_FAILED,
            r"object-file sink: committed output mode could not be observed",
            facts,
            err,
            true,
            allocator));
}

static n00b_result_t(n00b_objfile_sink_result_t *)
_n00b_objfile_sink_apply_open_mode(n00b_objfile_sink_result_t *facts,
                                   n00b_file_t                *file,
                                   uint32_t                    mode,
                                   n00b_allocator_t           *allocator)
{
    auto applied = n00b_file_apply_mode(file, mode);
    if (n00b_result_is_ok(applied)) {
        _n00b_objfile_sink_result_set_mode_applied(
            facts, n00b_result_get(applied));
        return n00b_result_ok(n00b_objfile_sink_result_t *, facts);
    }

    int err = n00b_result_get_err(applied);
    if (err == ENOSYS) {
        facts->file_mode_supported = false;
        return n00b_result_ok(n00b_objfile_sink_result_t *, facts);
    }

    return OBJFILE_SINK_ERR_PAYLOAD(
        n00b_objfile_sink_result_t *,
        _n00b_objfile_sink_error_from_facts(
            N00B_OBJFILE_SINK_ERR_MODE_FAILED,
            r"object-file sink: requested output mode could not be applied",
            facts,
            err,
            true,
            allocator));
}

static n00b_result_t(size_t)
_n00b_objfile_sink_write_buffer(n00b_file_t                *file,
                                n00b_buffer_t              *object_bytes,
                                n00b_objfile_sink_result_t *facts)
{
    size_t total = object_bytes->byte_len;
    if (total == 0) {
        return n00b_result_ok(size_t, 0);
    }

    size_t written = 0;
    while (written < total) {
        size_t remaining = total - written;
        auto write_r = n00b_file_write_attempt(file,
                                               object_bytes->data + written,
                                               remaining);
        if (n00b_result_is_err(write_r)) {
            return n00b_result_err(size_t, n00b_result_get_err(write_r));
        }

        n00b_file_write_attempt_t attempt = n00b_result_get(write_r);
        written += attempt.bytes_written;
        facts->bytes_written = written;

        if (attempt.error) {
            return n00b_result_err(size_t, attempt.error_code);
        }
        if (attempt.bytes_written == 0 || attempt.bytes_written > remaining) {
            return n00b_result_err(size_t, EIO);
        }
    }

    return n00b_result_ok(size_t, written);
}

static n00b_result_t(n00b_objfile_sink_result_t *)
_n00b_objfile_sink_write_atomic(n00b_buffer_t                  *object_bytes,
                                n00b_string_t                  *destination_path,
                                n00b_objfile_sink_mode_t        sink_mode,
                                n00b_objfile_sink_overwrite_t   overwrite,
                                n00b_option_t(uint32_t)         file_mode,
                                bool                            preserve_existing_mode,
                                n00b_allocator_t               *allocator)
{
    n00b_objfile_sink_result_t *facts =
        _n00b_objfile_sink_result_new(destination_path,
                                      object_bytes->byte_len,
                                      sink_mode,
                                      N00B_OBJFILE_SINK_MODE_ATOMIC,
                                      overwrite,
                                      file_mode,
                                      allocator);

    n00b_objfile_sink_mode_plan_t mode_plan =
        _n00b_objfile_sink_plan_mode(destination_path,
                                     file_mode,
                                     preserve_existing_mode);
    if (mode_plan.unsupported) {
        facts->file_mode_supported = false;
    }
    if (mode_plan.failed) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_MODE_FAILED,
                r"object-file sink: existing output mode could not be observed",
                facts,
                mode_plan.detail,
                true,
                allocator));
    }
    if (mode_plan.has_mode) {
        _n00b_objfile_sink_result_set_mode_request(facts, mode_plan.mode);
    }

    uint32_t create_mode = mode_plan.has_mode ? mode_plan.mode : 0600u;
    auto temp_r = n00b_new_sibling_temp_file(destination_path,
                                             .file_mode = create_mode,
                                             .allocator = allocator);
    if (n00b_result_is_err(temp_r)) {
        int err = n00b_result_get_err(temp_r);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                _n00b_objfile_sink_invalid_or_open_error_code(err),
                r"object-file sink: sibling temp file could not be created",
                facts,
                err,
                true,
                allocator));
    }

    n00b_sibling_temp_file_t *temp = n00b_result_get(temp_r);
    _n00b_objfile_sink_result_set_temp(facts, temp->path);

    if (mode_plan.has_mode) {
        auto mode_r = _n00b_objfile_sink_apply_open_mode(facts,
                                                         temp->file,
                                                         mode_plan.mode,
                                                         allocator);
        if (n00b_result_is_err(mode_r)) {
            (void)n00b_file_close_result(temp->file);
            _n00b_objfile_sink_cleanup_temp(facts);
            return mode_r;
        }
    }

    auto write_r = _n00b_objfile_sink_write_buffer(temp->file,
                                                   object_bytes,
                                                   facts);
    if (n00b_result_is_err(write_r)) {
        int err = n00b_result_get_err(write_r);
        (void)n00b_file_close_result(temp->file);
        _n00b_objfile_sink_cleanup_temp(facts);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_WRITE_FAILED,
                r"object-file sink: temp file write failed",
                facts,
                err,
                true,
                allocator));
    }
    facts->bytes_written = n00b_result_get(write_r);

    auto close_r = n00b_file_close_result(temp->file);
    if (n00b_result_is_err(close_r)) {
        int err = n00b_result_get_err(close_r);
        _n00b_objfile_sink_cleanup_temp(facts);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_WRITE_FAILED,
                r"object-file sink: temp file close failed",
                facts,
                err,
                true,
                allocator));
    }

    facts->commit_attempted = true;
    auto commit_r = n00b_path_commit_exact(
        temp->path,
        destination_path,
        .policy = _n00b_objfile_sink_commit_policy(overwrite));
    if (n00b_result_is_err(commit_r)) {
        int err = n00b_result_get_err(commit_r);
        _n00b_objfile_sink_cleanup_temp(facts);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                _n00b_objfile_sink_commit_error_code(err),
                r"object-file sink: temp file commit failed",
                facts,
                err,
                true,
                allocator));
    }

    facts->commit_completed = true;
    return _n00b_objfile_sink_finish_mode_facts(facts, allocator);
}

static n00b_result_t(n00b_file_t *)
_n00b_objfile_sink_open_direct(n00b_string_t                 *destination_path,
                               n00b_objfile_sink_overwrite_t overwrite,
                               uint32_t                      create_mode,
                               n00b_allocator_t             *allocator)
{
    if (overwrite == N00B_OBJFILE_SINK_REJECT_EXISTING) {
        return n00b_file_open_exclusive(destination_path,
                                        .file_mode = create_mode,
                                        .allocator = allocator);
    }

    return n00b_file_open(destination_path,
                          .mode = N00B_FILE_W,
                          .kind = N00B_FILE_KIND_STREAM);
}

static n00b_result_t(n00b_objfile_sink_result_t *)
_n00b_objfile_sink_write_direct(n00b_buffer_t                 *object_bytes,
                                n00b_string_t                 *destination_path,
                                n00b_objfile_sink_mode_t       sink_mode,
                                n00b_objfile_sink_overwrite_t  overwrite,
                                n00b_option_t(uint32_t)        file_mode,
                                bool                           preserve_existing_mode,
                                n00b_allocator_t              *allocator)
{
    n00b_objfile_sink_result_t *facts =
        _n00b_objfile_sink_result_new(destination_path,
                                      object_bytes->byte_len,
                                      sink_mode,
                                      N00B_OBJFILE_SINK_MODE_DIRECT,
                                      overwrite,
                                      file_mode,
                                      allocator);

    n00b_objfile_sink_mode_plan_t mode_plan =
        _n00b_objfile_sink_plan_mode(destination_path,
                                     file_mode,
                                     preserve_existing_mode);
    if (mode_plan.unsupported) {
        facts->file_mode_supported = false;
    }
    if (mode_plan.failed) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_MODE_FAILED,
                r"object-file sink: existing output mode could not be observed",
                facts,
                mode_plan.detail,
                true,
                allocator));
    }
    if (mode_plan.has_mode) {
        _n00b_objfile_sink_result_set_mode_request(facts, mode_plan.mode);
    }

    uint32_t create_mode = mode_plan.has_mode ? mode_plan.mode : 0600u;
    auto open_r = _n00b_objfile_sink_open_direct(destination_path,
                                                 overwrite,
                                                 create_mode,
                                                 allocator);
    if (n00b_result_is_err(open_r)) {
        int err = n00b_result_get_err(open_r);
        n00b_objfile_sink_error_code_t code =
            err == EEXIST ? N00B_OBJFILE_SINK_ERR_COMMIT_FAILED
                          : _n00b_objfile_sink_open_error_code(err);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                code,
                err == EEXIST
                    ? r"object-file sink: destination already exists"
                    : r"object-file sink: direct destination open failed",
                facts,
                err,
                true,
                allocator));
    }

    n00b_file_t *file = n00b_result_get(open_r);
    facts->commit_attempted = true;

    if (mode_plan.has_mode) {
        auto mode_r = _n00b_objfile_sink_apply_open_mode(facts,
                                                         file,
                                                         mode_plan.mode,
                                                         allocator);
        if (n00b_result_is_err(mode_r)) {
            (void)n00b_file_close_result(file);
            return mode_r;
        }
    }

    auto write_r = _n00b_objfile_sink_write_buffer(file,
                                                   object_bytes,
                                                   facts);
    if (n00b_result_is_err(write_r)) {
        int err = n00b_result_get_err(write_r);
        (void)n00b_file_close_result(file);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_WRITE_FAILED,
                r"object-file sink: direct destination write failed",
                facts,
                err,
                true,
                allocator));
    }
    facts->bytes_written = n00b_result_get(write_r);

    auto close_r = n00b_file_close_result(file);
    if (n00b_result_is_err(close_r)) {
        int err = n00b_result_get_err(close_r);
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_from_facts(
                N00B_OBJFILE_SINK_ERR_WRITE_FAILED,
                r"object-file sink: direct destination close failed",
                facts,
                err,
                true,
                allocator));
    }

    facts->commit_completed = true;
    return _n00b_objfile_sink_finish_mode_facts(facts, allocator);
}

n00b_result_t(n00b_objfile_sink_result_t *)
n00b_objfile_sink_write(n00b_buffer_t *object_bytes,
                        n00b_string_t *destination_path) _kargs
{
    n00b_objfile_sink_mode_t      sink_mode = N00B_OBJFILE_SINK_MODE_ATOMIC;
    n00b_objfile_sink_overwrite_t overwrite = N00B_OBJFILE_SINK_REJECT_EXISTING;
    n00b_option_t(uint32_t)       file_mode = n00b_option_none(uint32_t);
    bool                          preserve_existing_mode = true;
    n00b_allocator_t             *allocator = nullptr;
}
{
    if (object_bytes == nullptr) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_with_destination(
                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                r"object-file sink: object bytes must not be null",
                destination_path,
                allocator));
    }

    if (object_bytes->byte_len != 0 && object_bytes->data == nullptr) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_with_destination(
                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                r"object-file sink: non-empty buffer has no data",
                destination_path,
                allocator));
    }

    if (destination_path == nullptr || destination_path->data == nullptr
        || destination_path->u8_bytes == 0) {
        return OBJFILE_SINK_ERR(n00b_objfile_sink_result_t *,
                                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                                r"object-file sink: destination path must not be empty",
                                allocator);
    }

    if (!_n00b_objfile_sink_mode_valid(sink_mode)) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_with_request(
                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                r"object-file sink: invalid sink mode",
                destination_path,
                sink_mode,
                overwrite,
                (int64_t)sink_mode,
                true,
                allocator));
    }

    if (!_n00b_objfile_sink_overwrite_valid(overwrite)) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_with_request(
                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                r"object-file sink: invalid overwrite policy",
                destination_path,
                sink_mode,
                overwrite,
                (int64_t)overwrite,
                true,
                allocator));
    }

    if (n00b_option_is_set(file_mode)
        && n00b_option_get(file_mode) > 07777u) {
        return OBJFILE_SINK_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_objfile_sink_error_with_request(
                N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT,
                r"object-file sink: invalid file mode",
                destination_path,
                sink_mode,
                overwrite,
                (int64_t)n00b_option_get(file_mode),
                true,
                allocator));
    }

    if (sink_mode == N00B_OBJFILE_SINK_MODE_ATOMIC) {
        return _n00b_objfile_sink_write_atomic(object_bytes,
                                               destination_path,
                                               sink_mode,
                                               overwrite,
                                               file_mode,
                                               preserve_existing_mode,
                                               allocator);
    }

    return _n00b_objfile_sink_write_direct(object_bytes,
                                           destination_path,
                                           sink_mode,
                                           overwrite,
                                           file_mode,
                                           preserve_existing_mode,
                                           allocator);
}

n00b_string_t *
n00b_objfile_sink_result_destination_path(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->destination_path;
}

n00b_option_t(n00b_string_t *)
n00b_objfile_sink_result_temp_path(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    if (!result->has_temp_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, result->temp_path);
}

uint64_t
n00b_objfile_sink_result_bytes_requested(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->bytes_requested;
}

uint64_t
n00b_objfile_sink_result_bytes_written(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->bytes_written;
}

n00b_objfile_sink_mode_t
n00b_objfile_sink_result_mode_requested(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->mode_requested;
}

n00b_objfile_sink_mode_t
n00b_objfile_sink_result_mode_used(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->mode_used;
}

n00b_objfile_sink_overwrite_t
n00b_objfile_sink_result_overwrite(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->overwrite;
}

bool
n00b_objfile_sink_result_commit_attempted(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->commit_attempted;
}

bool
n00b_objfile_sink_result_commit_completed(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->commit_completed;
}

bool
n00b_objfile_sink_result_rollback_attempted(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->rollback_attempted;
}

bool
n00b_objfile_sink_result_rollback_succeeded(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->rollback_succeeded;
}

bool
n00b_objfile_sink_result_cleanup_attempted(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->cleanup_attempted;
}

bool
n00b_objfile_sink_result_cleanup_succeeded(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->cleanup_succeeded;
}

n00b_option_t(uint32_t)
n00b_objfile_sink_result_file_mode_requested(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    if (!result->has_file_mode_requested) {
        return n00b_option_none(uint32_t);
    }

    return n00b_option_set(uint32_t, result->file_mode_requested);
}

n00b_option_t(uint32_t)
n00b_objfile_sink_result_file_mode_applied(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    if (!result->has_file_mode_applied) {
        return n00b_option_none(uint32_t);
    }

    return n00b_option_set(uint32_t, result->file_mode_applied);
}

bool
n00b_objfile_sink_result_file_mode_supported(n00b_objfile_sink_result_t *result)
{
    n00b_require(result != nullptr, "object-file sink result must not be null");

    return result->file_mode_supported;
}

n00b_objfile_sink_error_code_t
n00b_objfile_sink_error_code(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    return error->code;
}

n00b_string_t *
n00b_objfile_sink_err_str(n00b_err_t err)
{
    switch ((n00b_objfile_sink_error_code_t)err) {
    case N00B_OBJFILE_SINK_ERR_OK:
        return r"object-file sink: ok";
    case N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT:
        return r"object-file sink: invalid argument";
    case N00B_OBJFILE_SINK_ERR_UNSUPPORTED:
        return r"object-file sink: unsupported operation";
    case N00B_OBJFILE_SINK_ERR_WRITE_FAILED:
        return r"object-file sink: write failed";
    case N00B_OBJFILE_SINK_ERR_COMMIT_FAILED:
        return r"object-file sink: commit failed";
    case N00B_OBJFILE_SINK_ERR_CLEANUP_FAILED:
        return r"object-file sink: cleanup failed";
    case N00B_OBJFILE_SINK_ERR_MODE_FAILED:
        return r"object-file sink: mode operation failed";
    default:
        return r"object-file sink: unknown error code";
    }
}

n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_message(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    return n00b_option_from_nullable(n00b_string_t *, error->message);
}

n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_destination_path(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_destination_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, error->destination_path);
}

n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_temp_path(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_temp_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, error->temp_path);
}

n00b_option_t(n00b_objfile_sink_result_t *)
n00b_objfile_sink_error_result_facts(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_facts) {
        return n00b_option_none(n00b_objfile_sink_result_t *);
    }

    return n00b_option_from_nullable(n00b_objfile_sink_result_t *,
                                     error->facts);
}

n00b_option_t(n00b_objfile_sink_mode_t)
n00b_objfile_sink_error_mode(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_mode) {
        return n00b_option_none(n00b_objfile_sink_mode_t);
    }

    return n00b_option_set(n00b_objfile_sink_mode_t, error->mode);
}

n00b_option_t(n00b_objfile_sink_overwrite_t)
n00b_objfile_sink_error_overwrite(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_overwrite) {
        return n00b_option_none(n00b_objfile_sink_overwrite_t);
    }

    return n00b_option_set(n00b_objfile_sink_overwrite_t, error->overwrite);
}

n00b_option_t(int64_t)
n00b_objfile_sink_error_detail(n00b_objfile_sink_error_t *error)
{
    n00b_require(error != nullptr, "object-file sink error must not be null");

    if (!error->has_detail) {
        return n00b_option_none(int64_t);
    }

    return n00b_option_set(int64_t, error->detail);
}
