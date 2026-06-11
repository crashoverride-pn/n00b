#pragma once

/**
 * @file obj_bundle_exec.h
 * @brief Internal cross-TU seam for the execute-from-bundle runner (WP-016).
 *
 * This header is a private declaration point shared between the neutral runner
 * (`obj_bundle_exec_run.c`, which defines the helper) and its callers
 * (`obj_bundle.c` plan resolution, the runner test). It is not part of the
 * public object-bundle API. Keeping the prototype here prevents the signature
 * from drifting silently across translation units.
 */

#include "compiler/objfile/obj_bundle.h"

/**
 * @brief Map a requested execution mode to a concrete, currently-available mode.
 *
 * Resolves `AUTO` (or an unsupported explicit request) using the per-platform
 * order (macOS `nfs -> extraction`; Linux `memfd -> extraction`; other:
 * extraction only), honoring @p allow_extraction_fallback.
 *
 * @param requested The caller-requested mode (may be `AUTO`).
 * @param allow_extraction_fallback Whether extraction may be selected as a
 *        fallback when no in-memory mode is available.
 * @return The selected concrete mode, or `N00B_OBJ_BUNDLE_EXEC_AUTO` as the
 *         "nothing available" sentinel.
 */
extern n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_select_mode(n00b_obj_bundle_exec_mode_t requested,
                                  bool allow_extraction_fallback);

/**
 * @brief Whether the NFS execution mode is currently available on this host.
 *
 * True only on macOS AND when the setuid mount helper is present, executable,
 * and carries the setuid bit at its fixed install path; false everywhere else
 * (including Linux, where NFS mode is out of scope). Exposed for the gated
 * execution test so it can assert that mode selection stays consistent with the
 * actual host availability (which differs between a normal CI host with no
 * installed helper and a privileged host where the helper is installed).
 */
extern bool
_n00b_obj_bundle_exec_mode_nfs_available(void);

/**
 * @brief Whether the memfd execution mode is currently available on this host.
 *
 * True only on Linux (where `memfd_create`/`fexecve` exist); false everywhere
 * else (including macOS, where the memfd arm is `#if`-compiled out and execution
 * falls through to extraction). Exposed for the gated execution test so it can
 * assert that mode selection stays consistent with the actual host availability.
 */
extern bool
_n00b_obj_bundle_exec_mode_memfd_available(void);

/**
 * @brief Return the payload bytes of the artifact at @p logical_path.
 *
 * The in-memory NFS executor serves the selected target's bytes directly from
 * the decoded bundle artifact, never re-reading them from disk. This internal
 * seam lets the runner reach the artifact payload without exposing the private
 * artifact struct in the public API.
 *
 * @param bundle       Decoded object bundle.
 * @param logical_path Normalized logical path of the target artifact.
 * @return The artifact's payload buffer, or `nullptr` when no artifact matches
 *         @p logical_path or the matched artifact carries no payload.
 */
extern const n00b_buffer_t *
_n00b_obj_bundle_artifact_bytes_for_path(n00b_obj_bundle_t *bundle,
                                         n00b_string_t     *logical_path);
