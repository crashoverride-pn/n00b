/**
 * @file sink.h
 * @brief Format-neutral object-file byte sink contract.
 *
 * The sink layer writes an already-produced object-file byte buffer to a
 * destination path. It is deliberately format-neutral: ELF, Mach-O, and PE
 * callers produce bytes elsewhere, then hand those bytes to this contract for
 * path-level persistence.
 *
 * WP-011 defines the public result/error surface and the generic filesystem
 * implementation. Integration with object-bundle carrier production is layered
 * above this sink.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"

typedef struct n00b_objfile_sink_result n00b_objfile_sink_result_t;
typedef struct n00b_objfile_sink_error n00b_objfile_sink_error_t;

typedef enum {
    N00B_OBJFILE_SINK_MODE_ATOMIC,
    N00B_OBJFILE_SINK_MODE_DIRECT,
} n00b_objfile_sink_mode_t;

typedef enum {
    N00B_OBJFILE_SINK_REJECT_EXISTING,
    N00B_OBJFILE_SINK_REPLACE_EXISTING,
} n00b_objfile_sink_overwrite_t;

typedef enum {
    N00B_OBJFILE_SINK_ERR_OK               = 0,
    N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT = -3801,
    N00B_OBJFILE_SINK_ERR_UNSUPPORTED      = -3802,
    N00B_OBJFILE_SINK_ERR_WRITE_FAILED     = -3803,
    N00B_OBJFILE_SINK_ERR_COMMIT_FAILED    = -3804,
    N00B_OBJFILE_SINK_ERR_CLEANUP_FAILED   = -3805,
    N00B_OBJFILE_SINK_ERR_MODE_FAILED      = -3806,
} n00b_objfile_sink_error_code_t;

/**
 * @pre @p object_bytes is non-null.
 * @pre @p destination_path is non-null and non-empty.
 * @post On success, returns structured sink facts for the committed write.
 * @post On error, returns structured sink facts when filesystem side effects
 *       were attempted and those facts are known.
 * @kw sink_mode Atomic sibling-temp commit or direct write; default
 *      `N00B_OBJFILE_SINK_MODE_ATOMIC`.
 * @kw overwrite Whether an existing destination may be replaced; default
 *      `N00B_OBJFILE_SINK_REJECT_EXISTING`.
 * @kw file_mode Requested filesystem mode when set, otherwise no explicit
 *      mode request; default none.
 * @kw preserve_existing_mode Preserve destination mode when replacing an
 *      existing file if supported. A preserved mode is reported as the
 *      mode requested from the filesystem by this sink; default `true`.
 * @kw allocator Optional allocator for result/error payloads; default
 *      `nullptr`.
 */
extern n00b_result_t(n00b_objfile_sink_result_t *)
n00b_objfile_sink_write(n00b_buffer_t *object_bytes,
                        n00b_string_t *destination_path) _kargs {
    n00b_objfile_sink_mode_t      sink_mode = N00B_OBJFILE_SINK_MODE_ATOMIC;
    n00b_objfile_sink_overwrite_t overwrite = N00B_OBJFILE_SINK_REJECT_EXISTING;
    n00b_option_t(uint32_t)       file_mode = n00b_option_none(uint32_t);
    bool                          preserve_existing_mode = true;
    n00b_allocator_t             *allocator = nullptr;
};

/**
 * @pre @p result is non-null.
 * @return Caller-requested destination path for the sink operation.
 */
extern n00b_string_t *
n00b_objfile_sink_result_destination_path(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Same-directory temporary path used by an atomic write when one was
 *         allocated, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_objfile_sink_result_temp_path(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of input bytes the sink was asked to persist.
 */
extern uint64_t
n00b_objfile_sink_result_bytes_requested(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of bytes actually written before success or the reported
 *         failure boundary.
 */
extern uint64_t
n00b_objfile_sink_result_bytes_written(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Atomic or direct mode requested by the caller.
 */
extern n00b_objfile_sink_mode_t
n00b_objfile_sink_result_mode_requested(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Atomic or direct mode actually used by the sink.
 */
extern n00b_objfile_sink_mode_t
n00b_objfile_sink_result_mode_used(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Filesystem overwrite policy requested by the caller.
 */
extern n00b_objfile_sink_overwrite_t
n00b_objfile_sink_result_overwrite(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether the final destination commit was attempted.
 */
extern bool
n00b_objfile_sink_result_commit_attempted(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether the final destination commit completed.
 */
extern bool
n00b_objfile_sink_result_commit_completed(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether a rollback step was attempted after a visible side effect.
 */
extern bool
n00b_objfile_sink_result_rollback_attempted(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether the attempted rollback succeeded.
 */
extern bool
n00b_objfile_sink_result_rollback_succeeded(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether temporary-file cleanup was attempted.
 */
extern bool
n00b_objfile_sink_result_cleanup_attempted(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether attempted cleanup succeeded.
 */
extern bool
n00b_objfile_sink_result_cleanup_succeeded(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Filesystem mode requested from the host when the caller supplied an
 *         explicit mode or the sink derived one by preserving an existing
 *         destination, otherwise none.
 */
extern n00b_option_t(uint32_t)
n00b_objfile_sink_result_file_mode_requested(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Observed filesystem mode for the committed destination when mode
 *         observation was supported, otherwise none.
 */
extern n00b_option_t(uint32_t)
n00b_objfile_sink_result_file_mode_applied(n00b_objfile_sink_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether the host/backend supported the requested mode behavior.
 */
extern bool
n00b_objfile_sink_result_file_mode_supported(n00b_objfile_sink_result_t *result);

/**
 * @pre @p error is non-null.
 * @return Stable sink error code carried by @p error.
 */
extern n00b_objfile_sink_error_code_t
n00b_objfile_sink_error_code(n00b_objfile_sink_error_t *error);

/**
 * @return Human-readable description for any object-file sink error code.
 */
extern n00b_string_t *
n00b_objfile_sink_err_str(n00b_err_t err);

/**
 * @pre @p error is non-null.
 * @return Error message when one was attached, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_message(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Destination path context when known, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_destination_path(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Temporary path context when known, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_objfile_sink_error_temp_path(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Structured sink facts for a failed operation when filesystem
 *         side effects were attempted, otherwise none.
 */
extern n00b_option_t(n00b_objfile_sink_result_t *)
n00b_objfile_sink_error_result_facts(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Requested sink mode when known, otherwise none.
 */
extern n00b_option_t(n00b_objfile_sink_mode_t)
n00b_objfile_sink_error_mode(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Requested overwrite policy when known, otherwise none.
 */
extern n00b_option_t(n00b_objfile_sink_overwrite_t)
n00b_objfile_sink_error_overwrite(n00b_objfile_sink_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Backend-specific detail value when one was attached, otherwise none.
 */
extern n00b_option_t(int64_t)
n00b_objfile_sink_error_detail(n00b_objfile_sink_error_t *error);
