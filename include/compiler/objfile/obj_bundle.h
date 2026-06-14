/**
 * @file obj_bundle.h
 * @brief Format-neutral object bundle construction and manifest codec API.
 *
 * Object bundles are canonical, carrier-independent collections of artifacts,
 * execution mappings, and policy records. ELF, Mach-O, and PE carriers are
 * backend concerns layered below this API.
 *
 * Related modules:
 * - @ref result.h for structured result payloads.
 * - @ref buffer.h for artifact and manifest byte payloads.
 * - @ref sink.h for filesystem persistence of rewritten object bytes.
 * - @ref types.h for object-file format enums.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "n00b.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "compiler/objfile/sink.h"
#include "compiler/objfile/types.h"
#include "chalk/n00b_chalk_macho.h"
#include "chalk/n00b_chalk_resign.h"

/**
 * @brief Canonical manifest and policy payload constants.
 * @details Embedded v1 policy payloads use a fixed envelope containing magic,
 * version, reserved fields, compatibility flags, fallback mirror, and source
 * length before the UTF-8 N00b predicate source bytes.
 */
#define N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN 8u
#define N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN   8u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN 8u
#define N00B_OBJ_BUNDLE_MANIFEST_MAJOR     1u
#define N00B_OBJ_BUNDLE_MANIFEST_MINOR     0u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR 1u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR 0u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_HEADER_SIZE 48u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF 48u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS 0ull
#define N00B_OBJ_BUNDLE_CONTENT_ID_LEN     32u
#define N00B_OBJ_BUNDLE_DIGEST_LEN         32u
#define N00B_OBJ_BUNDLE_ARTIFACT_ID_NONE   UINT64_MAX
#define N00B_OBJ_BUNDLE_POLICY_ID_NONE     UINT64_MAX

extern const uint8_t
    N00B_OBJ_BUNDLE_MANIFEST_MAGIC[N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN];
extern const uint8_t
    N00B_OBJ_BUNDLE_POLICY_MAGIC[N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN];
/** @brief Magic prefix for canonical v1 embedded N00b policy payloads. */
extern const uint8_t
    N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC[
        N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN];

typedef struct n00b_obj_bundle n00b_obj_bundle_t;
typedef struct n00b_obj_bundle_artifact n00b_obj_bundle_artifact_t;
typedef struct n00b_obj_bundle_error n00b_obj_bundle_error_t;
typedef struct n00b_obj_bundle_extract_result
    n00b_obj_bundle_extract_result_t;
typedef struct n00b_obj_bundle_exec_plan_record n00b_obj_bundle_exec_plan_t;
/**
 * @brief Opaque exec-result record produced by the fork+wait runner variant.
 *
 * Records the resolved mode actually used, the launched logical path, whether a
 * fallback mode was used, the child pid, the child exit status, and whether the
 * child exited normally. Inspect via the @c n00b_obj_bundle_exec_result_* family.
 */
typedef struct n00b_obj_bundle_exec_result_record
    n00b_obj_bundle_exec_result_t;
/** @brief Planned argv list type recorded by execution plans. */
typedef n00b_list_t(n00b_string_t *) n00b_obj_bundle_exec_argv_t;
/** @brief Planned environment overlay type recorded by execution plans. */
typedef n00b_dict_t(n00b_string_t *, n00b_string_t *)
    n00b_obj_bundle_exec_env_t;

typedef enum {
    N00B_OBJ_BUNDLE_ARTIFACT_FILE,
    N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
    N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY,
    N00B_OBJ_BUNDLE_ARTIFACT_METADATA,
    N00B_OBJ_BUNDLE_ARTIFACT_OPAQUE,
} n00b_obj_bundle_artifact_kind_t;

/**
 * @brief Carrier placement requested for object-bundle read/write APIs.
 *
 * The public API stays format-neutral. Backends map these policies onto their
 * native carriers; for ELF, `.0c001.bundle` is the selected carrier state.
 */
typedef enum {
    /**
     * Backend default carrier. ELF writes raw canonical metadata bytes in
     * `.0c001.bundle`; it does not silently choose loadable or split carriers.
     */
    N00B_OBJ_BUNDLE_CARRIER_AUTO,
    /**
     * Raw canonical object-bundle bytes in the metadata carrier. ELF stores
     * the canonical bundle directly in non-loadable `.0c001.bundle`.
     */
    N00B_OBJ_BUNDLE_CARRIER_METADATA,
    /**
     * Descriptor-backed loadable carrier. ELF stores a descriptor in
     * `.0c001.bundle` and the complete canonical bundle bytes in a new
     * `PT_LOAD`; readers validate descriptor bounds and digest before decode.
     */
    N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
    /**
     * Descriptor-backed split carrier. ELF stores a descriptor/skeleton in
     * `.0c001.bundle` and selected executable-compatible payload slices in a
     * new `PT_LOAD`; readers validate reconstruction records and rebuild the
     * canonical bundle bytes before decode.
     */
    N00B_OBJ_BUNDLE_CARRIER_SPLIT,
} n00b_obj_bundle_carrier_t;

typedef enum {
    N00B_OBJ_BUNDLE_REJECT_EXISTING,
    N00B_OBJ_BUNDLE_REPLACE_EXISTING,
} n00b_obj_bundle_replace_policy_t;

/**
 * @brief Host-entrypoint mutation requested by object-bundle writes.
 *
 * The default preserves the input object's entrypoint. Host-entrypoint
 * mutation is an explicit opt-in path; unsupported backends or phases report
 * structured errors before emitting rewritten object bytes.
 */
typedef enum {
    N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE,
    N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT,
} n00b_obj_bundle_entrypoint_policy_t;

typedef enum {
    N00B_OBJ_BUNDLE_POLICY_ENFORCE,
    N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY,
} n00b_obj_bundle_policy_mode_t;

typedef enum {
    N00B_OBJ_BUNDLE_POLICY_KIND_NONE,
    N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
    N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
    /** Embedded N00b predicate policy payload; codec-valid before runtime eval. */
    N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
} n00b_obj_bundle_policy_kind_t;

typedef enum {
    N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE       = 0,
    N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION = 1u << 0,
    N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION  = 1u << 1,
    N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH =
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION
        | N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
} n00b_obj_bundle_policy_scope_t;

typedef enum {
    N00B_OBJ_BUNDLE_POLICY_F_REQUIRED         = 1u << 0,
    N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL         = 1u << 1,
    N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED = 1u << 2,
} n00b_obj_bundle_policy_flags_t;

/** @brief Requested execution mode for logical execution planning. */
typedef enum {
    N00B_OBJ_BUNDLE_EXEC_AUTO,
    N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
    N00B_OBJ_BUNDLE_EXEC_MEMFD,
    N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT,
    /**
     * In-memory loopback NFS execution mode (darwin-only at run time). Appended
     * as the LAST member so every existing ordinal stays stable (D-050/OQ-7).
     */
    N00B_OBJ_BUNDLE_EXEC_NFS,
} n00b_obj_bundle_exec_mode_t;

/** @brief Source used for deterministic execution target selection. */
typedef enum {
    N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE,
    N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT,
    N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING,
} n00b_obj_bundle_exec_selection_source_t;

/** @brief Platform support state for the resolved logical execution mode. */
typedef enum {
    N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORT_NONE,
    N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORTED,
    N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED,
} n00b_obj_bundle_exec_platform_support_t;

typedef enum {
    N00B_OBJ_BUNDLE_ERR_OK                     = 0,
    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT       = -3701,
    N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH   = -3702,
    N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH = -3703,
    N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR     = -3704,
    N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC  = -3705,
    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET         = -3706,
    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_VERSION    = -3707,
    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE    = -3708,
    N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST     = -3709,
    N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST = -3710,
    N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS          = -3711,
    N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH        = -3712,
    N00B_OBJ_BUNDLE_ERR_BUILD                  = -3713,
    N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID    = -3714,
    N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND       = -3715,
    N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER = -3716,
    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER = -3717,
    N00B_OBJ_BUNDLE_ERR_REPLACE_REQUIRED       = -3718,
    N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED = -3719,
    N00B_OBJ_BUNDLE_ERR_FOREIGN_LEGACY_BUNDLE  = -3720,
    N00B_OBJ_BUNDLE_ERR_ALREADY_WRAPPED_OR_RESERVED = -3721,
    N00B_OBJ_BUNDLE_ERR_GUARD_SECTION_PRESENT  = -3722,
    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER    = -3723,
    N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE        = -3724,
    N00B_OBJ_BUNDLE_ERR_EXTRACT_UNSUPPORTED    = -3725,
    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE  = -3726,
    N00B_OBJ_BUNDLE_ERR_POLICY_DENIED          = -3727,
    N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED     = -3728,
    N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE = -3729,
} n00b_obj_bundle_error_code_t;

/**
 * @post On success, returns an empty mutable object bundle.
 * @post The returned bundle and its owned data use @c allocator.
 * @kw allocator Optional allocator for the returned bundle; default `nullptr`.
 */
extern n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_new() _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @pre @p bundle is non-null and mutable.
 * @pre @p logical_path is non-null and valid UTF-8.
 * @pre @p bytes is non-null for file, executable, and opaque artifacts.
 * @post On success, @p bundle contains one artifact at the normalized path.
 * @post On error, @p bundle is unchanged.
 * @kw kind Artifact kind; default `N00B_OBJ_BUNDLE_ARTIFACT_FILE`.
 * @kw role Optional role string; default `nullptr`.
 * @kw mode Intended filesystem mode for extraction; default `0`.
 * @kw flags Required/optional artifact flags; default `0`.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_add_artifact(n00b_obj_bundle_t *bundle,
                             n00b_string_t     *logical_path,
                             const n00b_buffer_t *bytes) _kargs {
    n00b_obj_bundle_artifact_kind_t kind  = N00B_OBJ_BUNDLE_ARTIFACT_FILE;
    n00b_string_t                  *role  = nullptr;
    uint32_t                        mode  = 0;
    uint64_t                        flags = 0;
};

/**
 * @pre @p bundle is non-null and mutable.
 * @pre @p logical_path names an existing executable-compatible artifact.
 * @post On success, @p logical_path is the bundle's only default executable.
 * @post On error, @p bundle is unchanged.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_set_default_exec(n00b_obj_bundle_t *bundle,
                                 n00b_string_t     *logical_path);

/**
 * @pre @p bundle is non-null and mutable.
 * @pre @p selector is non-null.
 * @pre @p target_path names an existing executable-compatible artifact.
 * @post On success, @p selector maps to @p target_path.
 * @post Duplicate selectors are rejected and leave @p bundle unchanged.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_add_exec_mapping(n00b_obj_bundle_t *bundle,
                                 n00b_string_t     *selector,
                                 n00b_string_t     *target_path);

/**
 * @pre @p bundle is non-null and mutable.
 * @post On success, @p bundle contains one policy record with @p policy_id.
 * @post On error, @p bundle is unchanged.
 * @kw flags Policy compatibility flags; default
 *      `N00B_OBJ_BUNDLE_POLICY_F_REQUIRED`.
 * @kw priority Selection priority among policies for the same scope; default
 *      `0`.
 * @kw payload Optional policy payload bytes; default `nullptr`.
 * @kw fallback_policy_id Lower-priority fallback policy or no-fallback
 *      sentinel; default `N00B_OBJ_BUNDLE_POLICY_ID_NONE`.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_add_policy(n00b_obj_bundle_t             *bundle,
                           uint64_t                      policy_id,
                           n00b_obj_bundle_policy_kind_t  kind,
                           n00b_obj_bundle_policy_scope_t scope) _kargs {
    uint64_t       flags              = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    uint64_t       priority           = 0;
    const n00b_buffer_t *payload      = nullptr;
    uint64_t       fallback_policy_id = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
};

/**
 * @pre @p bundle is non-null.
 * @post On success, all bundle model invariants hold.
 * @post Validation has no side effects.
 * @kw strict Reject non-canonical but otherwise interpretable input when true;
 *      default `true`.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_validate(n00b_obj_bundle_t *bundle) _kargs {
    bool strict = true;
};

/**
 * @pre @p bundle is non-null and valid.
 * @post On success, returns canonical object-bundle bytes independent of any
 *       object-file carrier.
 * @post The returned buffer is independent of @p bundle mutation after return.
 * @kw allocator Optional allocator for the returned buffer; default `nullptr`.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_obj_bundle_encode(n00b_obj_bundle_t *bundle) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @pre @p bundle_bytes is non-null.
 * @post On success, returns a fully valid object bundle.
 * @post On error, no partially decoded bundle escapes.
 * @kw strict Reject non-canonical manifests when true; default `true`.
 * @kw allocator Optional allocator for the returned bundle; default `nullptr`.
 */
extern n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_decode(n00b_buffer_t *bundle_bytes) _kargs {
    bool              strict    = true;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @pre @p object_bytes is non-null.
 * @post On success, returns the unique valid object bundle carried by the
 *       input object file.
 * @post The input buffer is not modified.
 * @post Descriptor-backed carriers are validated before canonical bundle
 *       decoding. For ELF, raw canonical `.0c001.bundle` bytes remain the
 *       metadata carrier; descriptor `.0c001.bundle` bytes select loadable or
 *       split payload/reconstruction state.
 * @post Readers follow only the selected carrier state. Stale loadable bytes
 *       left behind by a later descriptor or metadata replacement are ignored.
 * @post A fat/universal Mach-O input (multiple slices) is read from its arm64
 *       slice's carrier: the arm64 slice is selected (D-002/D-035), detached, and
 *       re-parsed as a thin object before the carrier is read. A fat input with
 *       no arm64 slice returns @c N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER.
 * @kw format Object format, or `N00B_FMT_UNKNOWN` for auto-detect.
 * @kw strict Forwarded to manifest decode/canonical validation; default `true`.
 *      Neighbor foreign/reserved/Chalk/guard sections do not block reading a
 *      unique valid bundle carrier.
 * @kw allocator Optional allocator for the returned bundle; default `nullptr`.
 */
extern n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_read(n00b_buffer_t *object_bytes) _kargs {
    n00b_format_t    format    = N00B_FMT_UNKNOWN;
    bool             strict    = true;
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @pre @p object_bytes and @p bundle are non-null.
 * @pre @p bundle is valid.
 * @post On success, returns a new object-file byte buffer containing the
 *       selected carrier.
 * @post The input object buffer and @p bundle are not modified.
 * @post All non-planned object-file byte ranges are preserved.
 * @post `AUTO` writes the backend default carrier. ELF keeps `AUTO` as raw
 *       metadata and explicit `METADATA` as raw canonical `.0c001.bundle`
 *       bytes, not descriptor-wrapped bytes.
 * @post Explicit `LOADABLE` and `SPLIT` writes use descriptor-backed carriers
 *       when the backend supports them. ELF stores the authoritative descriptor
 *       in `.0c001.bundle`; stale bytes from an earlier loadable or split
 *       carrier may remain in non-selected object ranges and are ignored by
 *       later reads.
 * @post Existing N00b-owned metadata, loadable, or split carriers require
 *       `replace = N00B_OBJ_BUNDLE_REPLACE_EXISTING` before replacement.
 *       Replacement is scoped to a unique, valid N00b-owned `.0c001.bundle`
 *       carrier. It does not authorize repairing malformed or duplicate
 *       carriers, importing Brandon `.0c001.file`, rewrapping
 *       `.0c001.wrap` / `.0c001.code`, overwriting unknown `.0c001.*`
 *       occupants, or ignoring guard sections.
 * @post By default, and with
 *       `entrypoint = N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE`, the host object
 *       entrypoint is preserved. The write API does not launch a process,
 *       evaluate runtime entrypoint behavior, or patch architecture-specific
 *       trampoline bytes.
 * @post Host-entrypoint mutation is caller opt-in. ELF64 little-endian
 *       x86-64 `LOADABLE` and `SPLIT` writes can redirect `e_entry` to the
 *       selected executable artifact after execution-policy evaluation. `AUTO`
 *       and `METADATA` do not upgrade carriers for entrypoint mutation and
 *       return structured unsupported-mode errors before emitting output.
 *       Unsupported object formats, architectures, and unsafe targets also
 *       reject before emission.
 * @post Carrier, descriptor, rewrite, replacement, bounds, digest, and
 *       canonical-decode failures return structured
 *       @c n00b_obj_bundle_error_t payloads with format/carrier/detail context
 *       when available.
 * @post The returned bytes are rewritten but UNSIGNED. For Mach-O these are
 *       NON-LOADABLE on arm64 until re-signed; code signing requires an
 *       on-disk path, so signing is available only via
 *       @ref n00b_obj_bundle_write_file. Callers that need a runnable arm64
 *       image MUST use @ref n00b_obj_bundle_write_file rather than this
 *       pure-buffer entry point.
 * @post A fat/universal Mach-O input (multiple slices) produces a rewritten fat
 *       output with the same slice count: the bundle carrier is embedded in the
 *       arm64 slice(s) only and every non-arm64 slice is byte-identical to the
 *       input slice (D-002/D-035). A fat input with no arm64 slice returns
 *       @c N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER. Host-entrypoint mutation is
 *       not supported on a fat input.
 * @kw format Object format, or `N00B_FMT_UNKNOWN` for auto-detect.
 * @kw carrier Carrier selection policy; default
 *      `N00B_OBJ_BUNDLE_CARRIER_AUTO`.
 * @kw replace Whether an existing N00b-owned bundle carrier may be replaced;
 *      default `N00B_OBJ_BUNDLE_REJECT_EXISTING`.
 * @kw strict Forwarded to existing-carrier manifest validation; default
 *      `true`. Write policy validates the selected existing carrier before
 *      considering reserved/wrapped environment blockers; malformed or
 *      duplicate carriers reject regardless of replacement policy, and
 *      reserved/foreign/wrapped inputs reject regardless of this caller
 *      control.
 * @kw entrypoint Host-entrypoint mutation policy; default
 *      `N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE`.
 * @kw entrypoint_selector Optional execution selector used for opt-in
 *      host-entrypoint target selection; only valid with host-entrypoint
 *      mutation. Selector mapping wins over the default executable; default
 *      `nullptr`.
 * @kw entrypoint_strict_selector Whether an unmatched host-entrypoint selector
 *      should reject rather than fall back to the default executable; only
 *      valid with host-entrypoint mutation; default `false`.
 * @kw entrypoint_policy_mode Policy mode used while evaluating execution
 *      policy for opt-in host-entrypoint target planning; non-default values
 *      are only valid with host-entrypoint mutation; default
 *      `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allocator Optional allocator for the returned buffer; default `nullptr`.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_obj_bundle_write(n00b_buffer_t     *object_bytes,
                      n00b_obj_bundle_t *bundle) _kargs {
    n00b_format_t                    format    = N00B_FMT_UNKNOWN;
    n00b_obj_bundle_carrier_t        carrier   = N00B_OBJ_BUNDLE_CARRIER_AUTO;
    n00b_obj_bundle_replace_policy_t replace   = N00B_OBJ_BUNDLE_REJECT_EXISTING;
    bool                             strict    = true;
    n00b_obj_bundle_entrypoint_policy_t entrypoint =
        N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE;
    n00b_string_t                   *entrypoint_selector = nullptr;
    bool                             entrypoint_strict_selector = false;
    n00b_obj_bundle_policy_mode_t    entrypoint_policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t                *allocator = nullptr;
};

/**
 * @pre @p object_bytes, @p bundle, and @p destination_path are non-null and
 *      @p bundle is valid. These are validated as structured @c Err returns by
 *      the rewrite and sink callees (D-031), not trapped here, so the
 *      implementation carries a guarded @c ensures (D-028) and no @c requires.
 * @post On success, rewrites @p object_bytes exactly as
 *       @ref n00b_obj_bundle_write would for the same bundle/carrier inputs,
 *       then persists those bytes through @ref n00b_objfile_sink_write.
 * @post On success, returns sink facts for @p destination_path; callers can
 *       inspect bytes-written, temp-path, commit, cleanup, and mode facts via
 *       the object-file sink result accessors.
 * @post The input object buffer and @p bundle are not modified.
 * @post Carrier selection, descriptor validation, replacement policy, raw
 *       metadata default behavior, descriptor-backed loadable/split writes,
 *       stale loadable-byte handling, host-entrypoint preservation or opt-in
 *       mutation/rejection behavior, fat/universal Mach-O carrier production
 *       (carrier in the arm64 slice(s), non-arm64 slices byte-identical), and
 *       structured rewrite errors are the same as @ref n00b_obj_bundle_write.
 * @post Filesystem persistence is attempted only after object-bundle carrier
 *       policy accepts the input. Rejected reserved, foreign, wrapped,
 *       malformed, duplicate, or guarded carrier environments return the same
 *       structured object-bundle error payload as @ref n00b_obj_bundle_write
 *       and do not authorize sink replacement.
 * @post Rewrite failures carry a @c n00b_obj_bundle_error_t payload. Sink
 *       failures carry a @c n00b_objfile_sink_error_t payload.
 * @post For Mach-O inputs the persisted output is re-signed: the ordering is
 *       strip (any inbound signature, no-op when unsigned) -> carrier rewrite
 *       -> persist -> re-sign the on-disk file. On success the on-disk file is
 *       ad-hoc signed when @c signer_identity is `nullptr`, or signed with the
 *       supplied identity otherwise. On a non-macOS host the re-sign collapses
 *       to strip-only and the file is left unsigned with a recorded warning.
 *       Re-sign failures carry a @c n00b_obj_bundle_error_t payload
 *       (format MACHO) and the call returns an error. Non-Mach-O inputs are
 *       neither stripped nor re-signed.
 * @kw format Object format, or `N00B_FMT_UNKNOWN` for auto-detect.
 * @kw carrier Carrier selection policy; default
 *      `N00B_OBJ_BUNDLE_CARRIER_AUTO`.
 * @kw replace Whether an existing N00b-owned bundle carrier may be replaced;
 *      default `N00B_OBJ_BUNDLE_REJECT_EXISTING`.
 * @kw strict Forwarded to existing-carrier manifest validation; default
 *      `true`. Replacement remains scoped to unique valid N00b-owned carriers
 *      and does not authorize foreign, reserved, wrapped, malformed,
 *      duplicate, or guarded inputs.
 * @kw entrypoint Host-entrypoint mutation policy; default
 *      `N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE`.
 * @kw entrypoint_selector Optional execution selector used for opt-in
 *      host-entrypoint target selection; only valid with host-entrypoint
 *      mutation. Selector mapping wins over the default executable; default
 *      `nullptr`.
 * @kw entrypoint_strict_selector Whether an unmatched host-entrypoint selector
 *      should reject rather than fall back to the default executable; only
 *      valid with host-entrypoint mutation; default `false`.
 * @kw entrypoint_policy_mode Policy mode used while evaluating execution
 *      policy for opt-in host-entrypoint target planning; non-default values
 *      are only valid with host-entrypoint mutation; default
 *      `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw sink_mode Sink persistence mode; default
 *      `N00B_OBJFILE_SINK_MODE_ATOMIC`.
 * @kw overwrite Filesystem destination policy; default
 *      `N00B_OBJFILE_SINK_REJECT_EXISTING`.
 * @kw file_mode Optional requested output mode; default none.
 * @kw preserve_existing_mode Preserve the existing destination mode when
 *      replacing and no explicit @c file_mode is supplied; default `true`.
 * @kw signer_identity Optional resolved signer identity used to re-sign a
 *      persisted Mach-O output; default `nullptr` selects ad-hoc signing.
 *      Bundle binaries carry no Endpoint-Security / Network-Extension /
 *      Developer-ID entitlement, so the ad-hoc default is correct here
 *      (CLAUDE.md feedback_signing.md). Ignored for non-Mach-O inputs.
 * @kw allocator Optional allocator for intermediate rewrite bytes, sink facts,
 *      and structured error payloads; default `nullptr`.
 */
extern n00b_result_t(n00b_objfile_sink_result_t *)
n00b_obj_bundle_write_file(n00b_buffer_t     *object_bytes,
                           n00b_obj_bundle_t *bundle,
                           n00b_string_t     *destination_path) _kargs {
    n00b_format_t                    format    = N00B_FMT_UNKNOWN;
    n00b_obj_bundle_carrier_t        carrier   = N00B_OBJ_BUNDLE_CARRIER_AUTO;
    n00b_obj_bundle_replace_policy_t replace   = N00B_OBJ_BUNDLE_REJECT_EXISTING;
    bool                             strict    = true;
    n00b_obj_bundle_entrypoint_policy_t entrypoint =
        N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE;
    n00b_string_t                   *entrypoint_selector = nullptr;
    bool                             entrypoint_strict_selector = false;
    n00b_obj_bundle_policy_mode_t    entrypoint_policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_objfile_sink_mode_t         sink_mode = N00B_OBJFILE_SINK_MODE_ATOMIC;
    n00b_objfile_sink_overwrite_t    overwrite = N00B_OBJFILE_SINK_REJECT_EXISTING;
    n00b_option_t(uint32_t)          file_mode = n00b_option_none(uint32_t);
    bool                             preserve_existing_mode = true;
    n00b_chalk_signer_identity_t    *signer_identity = nullptr;
    n00b_allocator_t                *allocator = nullptr;
};

/**
 * @brief Wrap one or more target binaries behind an EMBEDDED_N00B policy program.
 *
 * The generic "wrap any binary with a n00b policy" composition (FR-27): reads
 * each @p target_paths entry from the filesystem, embeds it under its BASENAME as
 * a bundle artifact, attaches @p policy_source as an EMBEDDED_N00B EXECUTION
 * policy (a full n00b PROGRAM run by the wrap runtime — FR-26), and persists the
 * result into the @p host_bytes carrier at @p output_path. Format-neutral: works
 * wherever the carrier writer exists (Mach-O today).
 *
 * @param host_bytes   Carrier object-file bytes the bundle is embedded into
 *                     (e.g. a copy of the self-detecting `n00b-wrap` binary).
 * @param target_paths Non-empty list of filesystem paths to the binaries to
 *                     embed. Each is read via `n00b_file_open(MMAP)` +
 *                     `n00b_file_as_buffer` and embedded under its basename
 *                     (e.g. `/usr/bin/git` -> logical `git`).
 * @param policy_source The EMBEDDED_N00B policy program source.
 * @param output_path  Destination path for the wrapped output.
 *
 * @kw default_exec Logical path (basename) of the default-exec target; when null
 *      it defaults to the FIRST target's basename. (default: nullptr)
 * @kw policy_id    Policy record id. (default: 1)
 * @kw allocator    Allocator for intermediate bytes, sink facts, and error
 *      payloads (§4.1). (default: nullptr)
 *
 * @pre (advisory, D-031) all four positional arguments non-null and
 *      @p target_paths non-empty; otherwise a body-guarded
 *      `Err(N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT)`. A target path that cannot be
 *      read, or has no filename component, is likewise a body-guarded Err.
 * @post On Ok, `result.ok` is non-null and @p output_path is a wrapped binary
 *       embedding every target (executable, mode 0755) plus the EMBEDDED_N00B
 *       EXECUTION policy, with `default_exec` set; the input buffers are
 *       unmodified.
 */
extern n00b_result_t(n00b_objfile_sink_result_t *)
n00b_obj_bundle_wrap(n00b_buffer_t                *host_bytes,
                     n00b_list_t(n00b_string_t *) *target_paths,
                     n00b_string_t                *policy_source,
                     n00b_string_t                *output_path) _kargs {
    n00b_string_t    *default_exec = nullptr;
    uint64_t          policy_id    = 1;
    n00b_allocator_t *allocator    = nullptr;
};

/**
 * @pre @p bundle is non-null.
 * @pre @p destination_root is non-null and non-empty.
 * @post Validates the bundle and extraction plan before materialization.
 * @post With @c policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY, returns
 *       success facts without filesystem writes.
 * @post With @c atomic = false, materializes the validated direct extraction
 *       plan for supported v1 artifacts.
 * @post With @c atomic = true, stages the validated plan under a sibling temp
 *       root and commits it to @p destination_root only when exact no-replace
 *       root commit semantics are available.
 * @kw overwrite Whether extraction may overwrite existing destinations;
 *      default `false`.
 * @kw atomic Request temp-tree extraction with commit/rollback semantics;
 *      default `true`.
 * @kw preserve_modes Preserve supported file mode metadata; default `true`.
 * @kw create_dirs Create destination directories as needed; default `true`.
 * @kw allow_absolute_paths Permit absolute bundle logical paths after policy
 *      evaluation; default `false`.
 * @kw allow_parent_refs Permit parent-directory references after policy
 *      evaluation; default `false`.
 * @kw policy_mode Enforce or validate extraction policy; default
 *      `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allocator Optional allocator for result/error payloads; default
 *      `nullptr`.
 */
extern n00b_result_t(n00b_obj_bundle_extract_result_t *)
n00b_obj_bundle_extract(n00b_obj_bundle_t *bundle,
                        n00b_string_t     *destination_root) _kargs {
    bool                          overwrite = false;
    bool                          atomic = true;
    bool                          preserve_modes = true;
    bool                          create_dirs = true;
    bool                          allow_absolute_paths = false;
    bool                          allow_parent_refs = false;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t             *allocator = nullptr;
};

/**
 * @pre @p bundle is non-null.
 * @post Planning has no filesystem, process, environment, object-file,
 *       extraction, `memfd`, or host-entrypoint side effects.
 * @post On success, returns an opaque execution plan allocated with
 *       @c allocator. The plan records caller controls and the selected
 *       executable-compatible target.
 * @post Selector facts are borrowed caller-provided pointers. Planned argv and
 *       env overlay facts are plan-owned shallow semantic copies: their list or
 *       dict containers and string entries are allocated with @c allocator and
 *       should be treated as read-only by callers. Selected logical-path facts
 *       are borrowed from @p bundle.
 * @post If @c argv is omitted, planned argv contains one entry: the selected
 *       target logical path as `argv[0]`.
 * @post Execution target selection is deterministic. Execution-scope policy
 *       evaluation runs after the selected target is known and before a
 *       successful plan is returned, so embedded policy can inspect selected
 *       target context. Validate-only mode still evaluates policy and
 *       policy-denied execution still fails.
 * @post `AUTO` and `EXTRACTED` resolve to a logical extracted-execution
 *       dependency without calling extraction; future modes fail with
 *       structured unsupported-mode errors.
 * @post On error, returns a @c n00b_obj_bundle_error_t payload allocated with
 *       @c allocator.
 * @kw selector Optional logical execution selector; default `nullptr`.
 * @kw argv Optional caller argv list to preserve in the plan; default
 *      `nullptr`.
 * @kw env Optional caller environment overlay to preserve in the plan; default
 *      `nullptr`.
 * @kw inherit_env Whether a later executor would inherit the process
 *      environment; default `true`.
 * @kw strict_selector Whether an unmatched selector should reject rather than
 *      fall back to the default executable; default `false`.
 * @kw mode Requested execution mode; default `N00B_OBJ_BUNDLE_EXEC_AUTO`.
 * @kw policy_mode Execution-policy mode; default
 *      `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allocator Optional allocator for the plan and structured error payload;
 *      default `nullptr`.
 */
extern n00b_result_t(n00b_obj_bundle_exec_plan_t *)
n00b_obj_bundle_exec_plan(n00b_obj_bundle_t *bundle) _kargs {
    n00b_string_t                             *selector = nullptr;
    n00b_obj_bundle_exec_argv_t               *argv = nullptr;
    n00b_obj_bundle_exec_env_t                *env = nullptr;
    bool                                       inherit_env = true;
    bool                                       strict_selector = false;
    n00b_obj_bundle_exec_mode_t                mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t              policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t                          *allocator = nullptr;
};

/**
 * @pre @p plan is non-null.
 * @return Borrowed caller selector when supplied, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_exec_plan_selector(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Plan-owned argv list. Callers must treat the returned list and its
 *         strings as read-only.
 */
extern n00b_option_t(n00b_obj_bundle_exec_argv_t *)
n00b_obj_bundle_exec_plan_argv(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Plan-owned environment overlay when supplied, otherwise none. Callers
 *         must treat the returned dictionary and its strings as read-only.
 */
extern n00b_option_t(n00b_obj_bundle_exec_env_t *)
n00b_obj_bundle_exec_plan_env(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Whether environment inheritance was requested.
 */
extern bool
n00b_obj_bundle_exec_plan_inherit_env(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Whether strict selector matching was requested.
 */
extern bool
n00b_obj_bundle_exec_plan_strict_selector(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Caller-requested execution mode.
 */
extern n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_plan_requested_mode(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Resolved logical execution mode.
 */
extern n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_plan_resolved_mode(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Platform support state for the resolved execution mode.
 */
extern n00b_obj_bundle_exec_platform_support_t
n00b_obj_bundle_exec_plan_platform_support(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Whether a later executor depends on extraction before execution.
 */
extern bool
n00b_obj_bundle_exec_plan_requires_extraction(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Caller-requested execution-policy mode.
 */
extern n00b_obj_bundle_policy_mode_t
n00b_obj_bundle_exec_plan_policy_mode(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Selected execution policy kind when policy selection completed,
 *         otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_exec_plan_policy_kind(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Selected execution policy scope when policy selection completed,
 *         otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_exec_plan_policy_scope(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Whether execution policy selection used a manifest-declared fallback.
 */
extern bool
n00b_obj_bundle_exec_plan_fallback_used(n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Source used to choose the execution target.
 */
extern n00b_obj_bundle_exec_selection_source_t
n00b_obj_bundle_exec_plan_selection_source(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Selected artifact ID when target selection has completed, otherwise
 *         none.
 */
extern n00b_option_t(uint64_t)
n00b_obj_bundle_exec_plan_selected_artifact_id(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @pre @p plan is non-null.
 * @return Selected target logical path when target selection has completed,
 *         otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_exec_plan_selected_logical_path(
    n00b_obj_bundle_exec_plan_t *plan);

/**
 * @brief Run a bundle's selected executable IN PLACE (exec-replace).
 *
 * Resolves the execution mode for the current platform (resolved order:
 * macOS/darwin nfs -> extraction; Linux memfd -> extraction (NO nfs); other:
 * extraction only; AUTO uses this order, an explicit mode is tried then falls
 * through only if it is AUTO-equivalent), brings up the selected mode, and
 * replaces the current process image with the bundle's selected target (same
 * pid/stdio/exit). On SUCCESS this function DOES NOT RETURN. It returns only on
 * failure, with a structured error.
 *
 * @param bundle Non-null decoded object bundle (from n00b_obj_bundle_read).
 * @kw selector       Optional logical execution selector; default `nullptr`.
 * @kw argv           Optional caller argv overlay; default `nullptr` (argv0 =
 *                    the selected target logical path).
 * @kw env            Optional environment overlay; default `nullptr`.
 * @kw inherit_env    Whether to inherit the process environment; default `true`.
 * @kw strict_selector Reject (vs. fall back) an unmatched selector; default
 *                    `false`.
 * @kw mode           Requested mode; default `N00B_OBJ_BUNDLE_EXEC_AUTO`.
 * @kw policy_mode    Execution-policy mode; default
 *                    `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allow_extraction_fallback Whether selection may fall through to
 *                    extraction; default `true`. When false and no in-memory
 *                    mode is available, fails with
 *                    `N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE`.
 * @kw allocator      Optional allocator for transient plan/error; default
 *                    `nullptr`.
 * @return Does not return on success. On failure: Err(n00b_obj_bundle_error_t*),
 *         code one of N00B_OBJ_BUNDLE_ERR_{INVALID_ARGUMENT, MISSING_TARGET,
 *         POLICY_DENIED, UNSUPPORTED_EXEC_MODE, EXEC_NO_MODE_AVAILABLE,
 *         EXEC_LAUNCH_FAILED, EXTRACT_UNSUPPORTED}.
 * @pre @p bundle is non-null.
 * @post On a returned value, the call FAILED (success exec-replaces and never
 *       returns); the error payload names the failing mode + reason.
 */
extern n00b_result_t(bool)
n00b_obj_bundle_exec_run(n00b_obj_bundle_t *bundle) _kargs {
    n00b_string_t                *selector = nullptr;
    n00b_obj_bundle_exec_argv_t  *argv = nullptr;
    n00b_obj_bundle_exec_env_t   *env = nullptr;
    bool                          inherit_env = true;
    bool                          strict_selector = false;
    n00b_obj_bundle_exec_mode_t   mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    bool                          allow_extraction_fallback = true;
    n00b_allocator_t             *allocator = nullptr;
};

/**
 * @brief Run a bundle's selected executable in a CHILD process and wait.
 *
 * Same mode resolution and bring-up as @ref n00b_obj_bundle_exec_run, but runs
 * the target as a child via the n00b child-process primitive while the caller
 * regains control and waits for the child. Returns an exec-result recording the
 * resolved mode, launched path, fallback usage, child pid, and child exit
 * status.
 *
 * @param bundle Non-null decoded object bundle.
 * @kw selector       Optional logical execution selector; default `nullptr`.
 * @kw argv           Optional caller argv overlay; default `nullptr`.
 * @kw env            Optional environment overlay; default `nullptr`.
 * @kw inherit_env    Whether to inherit the process environment; default `true`.
 * @kw strict_selector Reject (vs. fall back) an unmatched selector; default
 *                    `false`.
 * @kw mode           Requested mode; default `N00B_OBJ_BUNDLE_EXEC_AUTO`.
 * @kw policy_mode    Execution-policy mode; default
 *                    `N00B_OBJ_BUNDLE_POLICY_ENFORCE`.
 * @kw allow_extraction_fallback Whether selection may fall through to
 *                    extraction; default `true`.
 * @kw allocator      Optional allocator for the result/error payloads; default
 *                    `nullptr`.
 * @return Ok(n00b_obj_bundle_exec_result_t*) when the child was launched and
 *         reaped (regardless of the child's own exit code — inspect the result),
 *         or Err(n00b_obj_bundle_error_t*) when launch/mode-bring-up failed.
 * @pre @p bundle is non-null.
 * @post On Ok, the result's resolved-mode/launched-path/exit-status accessors
 *       report the child outcome; the parent process image is unchanged.
 */
extern n00b_result_t(n00b_obj_bundle_exec_result_t *)
n00b_obj_bundle_exec_spawn(n00b_obj_bundle_t *bundle) _kargs {
    n00b_string_t                *selector = nullptr;
    n00b_obj_bundle_exec_argv_t  *argv = nullptr;
    n00b_obj_bundle_exec_env_t   *env = nullptr;
    bool                          inherit_env = true;
    bool                          strict_selector = false;
    n00b_obj_bundle_exec_mode_t   mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    bool                          allow_extraction_fallback = true;
    n00b_allocator_t             *allocator = nullptr;
};

/**
 * @pre @p r is non-null.
 * @return Resolved execution mode actually used by the spawn.
 */
extern n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_result_resolved_mode(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p r is non-null.
 * @return Launched target logical path.
 */
extern n00b_string_t *
n00b_obj_bundle_exec_result_launched_path(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p r is non-null.
 * @return Whether a fallback mode was used relative to the requested mode.
 */
extern bool
n00b_obj_bundle_exec_result_fallback_used(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p r is non-null.
 * @return Child pid, or -1 when no pid was captured.
 */
extern int64_t
n00b_obj_bundle_exec_result_pid(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p r is non-null.
 * @return Child exit status (exit code when exited normally, otherwise the
 *         terminating signal number).
 */
extern int64_t
n00b_obj_bundle_exec_result_exit_status(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p r is non-null.
 * @return Whether the child exited normally (vs. terminated by a signal).
 */
extern bool
n00b_obj_bundle_exec_result_exited_normally(n00b_obj_bundle_exec_result_t *r);

/**
 * @pre @p result is non-null.
 * @return Caller-requested extraction destination root.
 */
extern n00b_string_t *
n00b_obj_bundle_extract_result_destination_root(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Temporary extraction root when one was allocated, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_extract_result_temp_root(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of regular/executable files in the validated extraction plan.
 */
extern uint64_t
n00b_obj_bundle_extract_result_files_planned(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of directories in the validated extraction plan.
 */
extern uint64_t
n00b_obj_bundle_extract_result_directories_planned(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of files written before success or the reported failure.
 */
extern uint64_t
n00b_obj_bundle_extract_result_files_written(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Number of directories materialized before success or failure.
 */
extern uint64_t
n00b_obj_bundle_extract_result_directories_written(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Selected policy kind when policy evaluation completed, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_extract_result_policy_kind(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Selected policy scope when policy evaluation completed, otherwise
 *         none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_extract_result_policy_scope(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether policy fallback was used.
 */
extern bool
n00b_obj_bundle_extract_result_fallback_used(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Filesystem overwrite policy requested by the caller.
 */
extern bool
n00b_obj_bundle_extract_result_overwrite(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether atomic extraction was requested.
 */
extern bool
n00b_obj_bundle_extract_result_atomic_requested(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether atomic extraction staging was actually used.
 */
extern bool
n00b_obj_bundle_extract_result_atomic_used(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether supported file modes should be preserved.
 */
extern bool
n00b_obj_bundle_extract_result_preserve_modes(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether destination directories should be created.
 */
extern bool
n00b_obj_bundle_extract_result_create_dirs(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether absolute logical paths are allowed after policy evaluation.
 */
extern bool
n00b_obj_bundle_extract_result_allow_absolute_paths(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether parent-directory references are allowed after policy
 *         evaluation.
 */
extern bool
n00b_obj_bundle_extract_result_allow_parent_refs(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Policy evaluation mode requested by the caller.
 */
extern n00b_obj_bundle_policy_mode_t
n00b_obj_bundle_extract_result_policy_mode(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether final tree commit was attempted.
 */
extern bool
n00b_obj_bundle_extract_result_commit_attempted(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether final tree commit completed.
 */
extern bool
n00b_obj_bundle_extract_result_commit_completed(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether rollback was attempted after a visible side effect.
 */
extern bool
n00b_obj_bundle_extract_result_rollback_attempted(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether attempted rollback succeeded.
 */
extern bool
n00b_obj_bundle_extract_result_rollback_succeeded(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether temp-tree cleanup was attempted.
 */
extern bool
n00b_obj_bundle_extract_result_cleanup_attempted(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p result is non-null.
 * @return Whether attempted temp-tree cleanup succeeded.
 */
extern bool
n00b_obj_bundle_extract_result_cleanup_succeeded(
    n00b_obj_bundle_extract_result_t *result);

/**
 * @pre @p error is non-null.
 * @return Stable object-bundle error code carried by @p error.
 */
extern n00b_obj_bundle_error_code_t
n00b_obj_bundle_error_code(n00b_obj_bundle_error_t *error);

/**
 * @return Human-readable description for any object-bundle error code.
 */
extern n00b_string_t *
n00b_obj_bundle_err_str(n00b_err_t err);

/**
 * @pre @p error is non-null.
 * @return Error message when one was attached, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_message(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Object format context when the error is carrier-specific,
 *         otherwise none.
 */
extern n00b_option_t(n00b_format_t)
n00b_obj_bundle_error_format(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Carrier-placement context when known, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_carrier_t)
n00b_obj_bundle_error_carrier(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Logical bundle path associated with the error, otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_logical_path(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Extraction destination path/root associated with the error,
 *         otherwise none.
 */
extern n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_destination_path(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Artifact ID associated with the error, otherwise none.
 */
extern n00b_option_t(uint64_t)
n00b_obj_bundle_error_artifact_id(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Policy kind associated with the error, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_error_policy_kind(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Policy scope associated with the error, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_error_policy_scope(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Backend-specific detail value associated with the error, otherwise
 *         none.
 */
extern n00b_option_t(int64_t)
n00b_obj_bundle_error_detail(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Requested execution mode associated with an execution-planning
 *         error, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_exec_mode_t)
n00b_obj_bundle_error_exec_requested_mode(n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Platform support state associated with an execution-planning error,
 *         otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_exec_platform_support_t)
n00b_obj_bundle_error_exec_platform_support(
    n00b_obj_bundle_error_t *error);

/**
 * @pre @p error is non-null.
 * @return Structured extraction facts for a failed extraction attempt when
 *         available, otherwise none.
 */
extern n00b_option_t(n00b_obj_bundle_extract_result_t *)
n00b_obj_bundle_error_extract_result_facts(n00b_obj_bundle_error_t *error);
