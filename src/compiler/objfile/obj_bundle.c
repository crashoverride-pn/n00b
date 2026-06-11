#include "compiler/objfile/obj_bundle.h"

#include "adt/dict.h"
#include "adt/list.h"
#include "chalk/n00b_chalk_macho.h"
#include "chalk/n00b_chalk_resign.h"
#include "compiler/objfile/abstract.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf_rewrite.h"
#include "compiler/objfile/elf_types.h"
#include "compiler/objfile/writer.h"
#include "core/crc32.h"
#include "core/sha256.h"
#include "core/type_info.h"
#include "internal/compiler/objfile/obj_bundle_arith.h"
#include "internal/compiler/objfile/obj_bundle_exec.h"
#include "internal/compiler/objfile/obj_bundle_macho.h"
#include "internal/compiler/objfile/obj_bundle_policy.h"
#include "n00b/eval.h"
#include "text/unicode/encoding.h"
#include "util/path.h"

#include <errno.h>
#include <sys/stat.h>

const uint8_t N00B_OBJ_BUNDLE_MANIFEST_MAGIC[N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN] = {
    'N', '0', '0', 'B', 'N', 'D', 'L', '1',
};

const uint8_t N00B_OBJ_BUNDLE_POLICY_MAGIC[N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN] = {
    'N', '0', '0', 'B', 'P', 'O', 'L', '1',
};

const uint8_t N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC[
    N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN] = {
    'N', '0', '0', 'B', 'E', 'P', 'O', 'L',
};

#define N00B_OBJ_BUNDLE_HEADER_SIZE        208u
#define N00B_OBJ_BUNDLE_CONTENT_ID_OFF     32u
#define N00B_OBJ_BUNDLE_PAYLOAD_AREA_OFF_OFF 176u
#define N00B_OBJ_BUNDLE_PAYLOAD_AREA_LEN_OFF 184u
#define N00B_OBJ_BUNDLE_ARTIFACT_REC_SIZE  72u
#define N00B_OBJ_BUNDLE_PAYLOAD_REC_SIZE   64u
#define N00B_OBJ_BUNDLE_EXEC_REC_SIZE      24u
#define N00B_OBJ_BUNDLE_POLICY_REC_SIZE    88u
#define N00B_OBJ_BUNDLE_NO_PAYLOAD_INDEX   UINT32_MAX
#define N00B_OBJ_BUNDLE_EXEC_REC_DEFAULT   1u
#define N00B_OBJ_BUNDLE_EXEC_REC_SELECTOR  2u

#define N00B_OBJ_BUNDLE_DECL_POLICY_SIZE                 64u
#define N00B_OBJ_BUNDLE_DECL_POLICY_MAJOR                1u
#define N00B_OBJ_BUNDLE_DECL_POLICY_MINOR                0u
#define N00B_OBJ_BUNDLE_DECL_POLICY_DECL_FLAGS_OFF       16u
#define N00B_OBJ_BUNDLE_DECL_POLICY_PATH_FLAGS_OFF       24u
#define N00B_OBJ_BUNDLE_DECL_POLICY_ARTIFACT_MASK_OFF    32u
#define N00B_OBJ_BUNDLE_DECL_POLICY_EXEC_FLAGS_OFF       40u
#define N00B_OBJ_BUNDLE_DECL_POLICY_FALLBACK_ID_OFF      48u
#define N00B_OBJ_BUNDLE_DECL_POLICY_RESERVED1_OFF        56u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_RESERVED0_OFF    12u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u
#define N00B_OBJ_BUNDLE_EMBEDDED_POLICY_RESERVED1_OFF    40u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC_LEN         8u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAJOR             1u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MINOR             0u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE       112u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_VERSION_OFF       8u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE_OFF   12u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_KIND_OFF          16u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_FLAGS_OFF         20u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_PAYLOAD_OFF_OFF   24u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_PAYLOAD_LEN_OFF   32u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_PAYLOAD_DIGEST_OFF 40u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_AUX_OFF_OFF       72u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_AUX_LEN_OFF       80u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_AUX_COUNT_OFF     88u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_RESERVED0_OFF     96u
#define N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_RESERVED1_OFF     104u
#define N00B_OBJ_BUNDLE_ELF_SPLIT_REC_SIZE               64u
#define N00B_OBJ_BUNDLE_DECL_PATH_RELATIVE               (1ull << 0)
#define N00B_OBJ_BUNDLE_DECL_PATH_NO_EMPTY_COMPONENTS    (1ull << 1)
#define N00B_OBJ_BUNDLE_DECL_PATH_NO_PARENT_REFERENCES   (1ull << 2)
#define N00B_OBJ_BUNDLE_DECL_PATH_NO_ABSOLUTE_PATHS      (1ull << 3)
#define N00B_OBJ_BUNDLE_DECL_PATH_VALID_UTF8             (1ull << 4)
#define N00B_OBJ_BUNDLE_DECL_PATH_DEFAULT                \
    (N00B_OBJ_BUNDLE_DECL_PATH_RELATIVE                  \
     | N00B_OBJ_BUNDLE_DECL_PATH_NO_EMPTY_COMPONENTS     \
     | N00B_OBJ_BUNDLE_DECL_PATH_NO_PARENT_REFERENCES    \
     | N00B_OBJ_BUNDLE_DECL_PATH_NO_ABSOLUTE_PATHS       \
     | N00B_OBJ_BUNDLE_DECL_PATH_VALID_UTF8)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_FILE          \
    (1ull << N00B_OBJ_BUNDLE_ARTIFACT_FILE)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_EXECUTABLE    \
    (1ull << N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DIRECTORY     \
    (1ull << N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_METADATA      \
    (1ull << N00B_OBJ_BUNDLE_ARTIFACT_METADATA)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_OPAQUE        \
    (1ull << N00B_OBJ_BUNDLE_ARTIFACT_OPAQUE)
#define N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DEFAULT       \
    (N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_FILE             \
     | N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_EXECUTABLE     \
     | N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DIRECTORY      \
     | N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_METADATA       \
     | N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_OPAQUE)
#define N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC           (1ull << 0)
#define N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING       (1ull << 1)
#define N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT                \
    (N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC              \
     | N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING)
#define N00B_OBJ_BUNDLE_ELF_GUARD_SECTION_TYPE 0xc001u

static const uint8_t N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC[
    N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC_LEN] = {
    'N', '0', '0', 'B', 'C', 'A', 'R', '1',
};

typedef struct n00b_obj_bundle_exec_mapping {
    n00b_string_t *selector;
    uint64_t       target_artifact_id;
} n00b_obj_bundle_exec_mapping_t;

typedef struct n00b_obj_bundle_policy {
    uint64_t                      policy_id;
    n00b_obj_bundle_policy_kind_t kind;
    n00b_obj_bundle_policy_scope_t scope;
    uint64_t                      flags;
    uint64_t                      priority;
    const n00b_buffer_t          *payload;
    uint64_t                      fallback_policy_id;
} n00b_obj_bundle_policy_t;

struct n00b_obj_bundle {
    n00b_allocator_t                              *allocator;
    bool                                          is_mutable;
    uint64_t                                      next_artifact_id;
    n00b_list_t(n00b_obj_bundle_artifact_t *)     artifacts;
    bool                                          has_default_exec;
    uint64_t                                      default_exec_id;
    n00b_list_t(n00b_obj_bundle_exec_mapping_t *) exec_mappings;
    n00b_list_t(n00b_obj_bundle_policy_t *)       policies;
};

struct n00b_obj_bundle_artifact {
    uint64_t                        id;
    n00b_obj_bundle_artifact_kind_t kind;
    n00b_string_t                  *logical_path;
    const n00b_buffer_t            *payload;
    n00b_string_t                  *role;
    uint32_t                        mode;
    uint64_t                        flags;
};

struct n00b_obj_bundle_extract_result {
    n00b_string_t                    *destination_root;
    n00b_string_t                    *temp_root;
    bool                              has_temp_root;
    uint64_t                          files_planned;
    uint64_t                          directories_planned;
    uint64_t                          files_written;
    uint64_t                          directories_written;
    n00b_obj_bundle_policy_kind_t     policy_kind;
    bool                              has_policy_kind;
    n00b_obj_bundle_policy_scope_t    policy_scope;
    bool                              has_policy_scope;
    bool                              fallback_used;
    bool                              overwrite;
    bool                              atomic_requested;
    bool                              atomic_used;
    bool                              preserve_modes;
    bool                              create_dirs;
    bool                              allow_absolute_paths;
    bool                              allow_parent_refs;
    n00b_obj_bundle_policy_mode_t     policy_mode;
    bool                              commit_attempted;
    bool                              commit_completed;
    bool                              rollback_attempted;
    bool                              rollback_succeeded;
    bool                              cleanup_attempted;
    bool                              cleanup_succeeded;
};

struct n00b_obj_bundle_exec_plan_record {
    n00b_string_t                             *selector;
    n00b_obj_bundle_exec_argv_t               *argv;
    n00b_obj_bundle_exec_env_t                *env;
    bool                                       inherit_env;
    bool                                       strict_selector;
    n00b_obj_bundle_exec_mode_t                requested_mode;
    n00b_obj_bundle_exec_mode_t                resolved_mode;
    n00b_obj_bundle_exec_platform_support_t    platform_support;
    bool                                       requires_extraction;
    n00b_obj_bundle_policy_mode_t              policy_mode;
    n00b_obj_bundle_policy_kind_t              policy_kind;
    bool                                       has_policy_kind;
    n00b_obj_bundle_policy_scope_t             policy_scope;
    bool                                       has_policy_scope;
    bool                                       fallback_used;
    uint64_t                                   selected_artifact_id;
    bool                                       has_selected_artifact_id;
    n00b_string_t                             *selected_logical_path;
    bool                                       has_selected_logical_path;
    n00b_obj_bundle_exec_selection_source_t    selection_source;
};

struct n00b_obj_bundle_error {
    n00b_obj_bundle_error_code_t    code;
    n00b_string_t                  *message;
    n00b_format_t                   format;
    bool                            has_format;
    n00b_obj_bundle_carrier_t       carrier;
    bool                            has_carrier;
    n00b_string_t                  *logical_path;
    bool                            has_logical_path;
    n00b_string_t                  *destination_path;
    bool                            has_destination_path;
    uint64_t                        artifact_id;
    bool                            has_artifact_id;
    n00b_obj_bundle_policy_kind_t   policy_kind;
    bool                            has_policy_kind;
    n00b_obj_bundle_policy_scope_t  policy_scope;
    bool                            has_policy_scope;
    int64_t                         detail;
    bool                            has_detail;
    n00b_obj_bundle_exec_mode_t              exec_requested_mode;
    bool                                     has_exec_requested_mode;
    n00b_obj_bundle_exec_platform_support_t  exec_platform_support;
    bool                                     has_exec_platform_support;
    n00b_obj_bundle_extract_result_t        *extract_result;
    bool                                     has_extract_result;
};

typedef struct n00b_obj_bundle_manifest_strtab {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    bool     error;
} n00b_obj_bundle_manifest_strtab_t;

typedef struct n00b_obj_bundle_encode_artifact {
    n00b_obj_bundle_artifact_t *artifact;
    uint64_t                    encoded_id;
    uint32_t                    path_off;
    uint32_t                    role_off;
    uint32_t                    payload_index;
    uint64_t                    payload_off;
    uint64_t                    payload_len;
    uint8_t                     digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
} n00b_obj_bundle_encode_artifact_t;

typedef struct n00b_obj_bundle_encode_exec_mapping {
    n00b_obj_bundle_exec_mapping_t *mapping;
    uint32_t                        selector_off;
    uint64_t                        target_encoded_id;
} n00b_obj_bundle_encode_exec_mapping_t;

typedef struct n00b_obj_bundle_encode_policy {
    n00b_obj_bundle_policy_t *policy;
    uint64_t                  payload_off;
    uint64_t                  payload_len;
    uint8_t                   digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
} n00b_obj_bundle_encode_policy_t;

typedef struct n00b_obj_bundle_manifest_range {
    uint64_t off;
    uint64_t len;
} n00b_obj_bundle_manifest_range_t;

typedef struct n00b_obj_bundle_elf_descriptor {
    n00b_obj_bundle_carrier_t        carrier;
    uint16_t                         major;
    uint16_t                         minor;
    uint32_t                         header_size;
    uint32_t                         flags;
    n00b_obj_bundle_manifest_range_t payload;
    uint8_t                          payload_digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
    n00b_obj_bundle_manifest_range_t aux;
    uint64_t                         aux_record_count;
    uint64_t                         reserved0;
    uint64_t                         reserved1;
} n00b_obj_bundle_elf_descriptor_t;

typedef struct n00b_obj_bundle_elf_split_record {
    n00b_obj_bundle_manifest_range_t canonical;
    n00b_obj_bundle_manifest_range_t object;
    uint8_t                          digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
} n00b_obj_bundle_elf_split_record_t;

typedef struct n00b_obj_bundle_elf_split_range {
    n00b_obj_bundle_manifest_range_t canonical;
    uint64_t                         artifact_id;
    uint64_t                         loadable_payload_off;
    uint8_t                          digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
} n00b_obj_bundle_elf_split_range_t;

typedef struct n00b_obj_bundle_host_entrypoint_request {
    n00b_obj_bundle_entrypoint_policy_t entrypoint;
    n00b_string_t                      *selector;
    bool                                strict_selector;
    n00b_obj_bundle_policy_mode_t       policy_mode;
} n00b_obj_bundle_host_entrypoint_request_t;

typedef struct n00b_obj_bundle_host_entrypoint_selection {
    n00b_obj_bundle_artifact_t              *artifact;
    n00b_obj_bundle_exec_selection_source_t  selection_source;
} n00b_obj_bundle_host_entrypoint_selection_t;

typedef struct n00b_obj_bundle_decode_artifact {
    uint64_t                         id;
    n00b_obj_bundle_artifact_kind_t  kind;
    uint32_t                         record_flags;
    uint64_t                         flags;
    uint32_t                         path_off;
    uint32_t                         role_off;
    uint32_t                         mode;
    uint32_t                         payload_index;
    uint8_t                          digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
    n00b_string_t                   *logical_path;
    n00b_string_t                   *role;
    const n00b_buffer_t             *payload;
} n00b_obj_bundle_decode_artifact_t;

typedef struct n00b_obj_bundle_decode_payload {
    uint64_t artifact_id;
    uint64_t flags;
    uint64_t payload_off;
    uint64_t payload_len;
    uint8_t  digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
} n00b_obj_bundle_decode_payload_t;

typedef struct n00b_obj_bundle_decode_exec {
    uint32_t       kind;
    uint32_t       flags;
    uint32_t       selector_off;
    uint32_t       reserved;
    uint64_t       target_id;
    n00b_string_t *selector;
} n00b_obj_bundle_decode_exec_t;

typedef struct n00b_obj_bundle_decode_policy {
    uint64_t                      policy_id;
    n00b_obj_bundle_policy_kind_t kind;
    n00b_obj_bundle_policy_scope_t scope;
    uint64_t                      flags;
    uint64_t                      priority;
    uint64_t                      payload_off;
    uint64_t                      payload_len;
    uint64_t                      fallback_policy_id;
    uint8_t                       digest[N00B_OBJ_BUNDLE_DIGEST_LEN];
    const n00b_buffer_t          *payload;
} n00b_obj_bundle_decode_policy_t;

typedef struct n00b_obj_bundle_extract_policy {
    n00b_obj_bundle_policy_kind_t  kind;
    n00b_obj_bundle_policy_scope_t scope;
    bool                           fallback_used;
    bool                           can_fallback_to_builtin;
    uint64_t                       policy_id;
    uint64_t                       flags;
    uint64_t                       priority;
    uint64_t                       fallback_policy_id;
    const n00b_buffer_t           *payload;
    uint64_t                       path_flags;
    uint64_t                       artifact_kind_mask;
    uint64_t                       execution_flags;
} n00b_obj_bundle_extract_policy_t;

typedef struct n00b_obj_bundle_exec_policy {
    n00b_obj_bundle_policy_kind_t  kind;
    n00b_obj_bundle_policy_scope_t scope;
    bool                           fallback_used;
    bool                           can_fallback_to_builtin;
    uint64_t                       policy_id;
    uint64_t                       flags;
    uint64_t                       priority;
    uint64_t                       fallback_policy_id;
    const n00b_buffer_t           *payload;
    uint64_t                       execution_flags;
} n00b_obj_bundle_exec_policy_t;

typedef struct n00b_obj_bundle_extract_plan_entry {
    n00b_obj_bundle_artifact_t *artifact;
    n00b_string_t              *destination_path;
    n00b_string_t              *parent_path;
} n00b_obj_bundle_extract_plan_entry_t;

typedef struct n00b_obj_bundle_extract_plan {
    n00b_string_t *destination_root;
    n00b_list_t(n00b_obj_bundle_extract_plan_entry_t *) entries;
} n00b_obj_bundle_extract_plan_t;

struct n00b_obj_bundle_policy_context {
    n00b_obj_bundle_policy_scope_t          scope;
    n00b_string_t                          *logical_path;
    n00b_obj_bundle_artifact_kind_t         artifact_kind;
    n00b_obj_bundle_exec_selection_source_t selection_source;
    bool                                    overwrite;
    bool                                    create_dirs;
    bool                                    inherit_env;
    bool                                    strict_selector;
    n00b_obj_bundle_exec_mode_t             requested_mode;
    n00b_obj_bundle_policy_mode_t           policy_mode;
};

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_new(n00b_obj_bundle_error_code_t code,
                           n00b_string_t               *message,
                           n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        n00b_alloc_with_opts(n00b_obj_bundle_error_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    error->code             = code;
    error->message          = message;
    error->format           = N00B_FMT_UNKNOWN;
    error->has_format       = false;
    error->carrier          = N00B_OBJ_BUNDLE_CARRIER_AUTO;
    error->has_carrier      = false;
    error->logical_path     = nullptr;
    error->has_logical_path = false;
    error->destination_path = nullptr;
    error->has_destination_path = false;
    error->artifact_id      = N00B_OBJ_BUNDLE_ARTIFACT_ID_NONE;
    error->has_artifact_id  = false;
    error->policy_kind      = N00B_OBJ_BUNDLE_POLICY_KIND_NONE;
    error->has_policy_kind  = false;
    error->policy_scope     = N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE;
    error->has_policy_scope = false;
    error->detail           = 0;
    error->has_detail       = false;
    error->exec_requested_mode       = N00B_OBJ_BUNDLE_EXEC_AUTO;
    error->has_exec_requested_mode   = false;
    error->exec_platform_support     =
        N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORT_NONE;
    error->has_exec_platform_support = false;
    error->extract_result            = nullptr;
    error->has_extract_result        = false;

    return error;
}

#define OBJ_BUNDLE_ERR(T, code, message, allocator)                                           \
    n00b_result_err_payload(                                                                  \
        T,                                                                                    \
        n00b_obj_bundle_error_t *,                                                            \
        _n00b_obj_bundle_error_new((code), (message), (allocator)))

#define OBJ_BUNDLE_ERR_PAYLOAD(T, error)                                                      \
    n00b_result_err_payload(T, n00b_obj_bundle_error_t *, (error))

// Internal constructor exposed for the neutral runner (obj_bundle_exec_run.c),
// which lives in a separate translation unit and cannot reach the static
// _n00b_obj_bundle_error_new directly. Builds a code+message error with the
// runner-supplied execution mode/path context attached.
n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_make_exec(n00b_obj_bundle_error_code_t code,
                                 n00b_string_t               *message,
                                 n00b_obj_bundle_exec_mode_t  mode,
                                 n00b_string_t               *logical_path,
                                 n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->policy_scope     = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION;
    error->has_policy_scope = true;

    error->exec_requested_mode     = mode;
    error->has_exec_requested_mode = true;

    if (logical_path != nullptr) {
        error->logical_path     = logical_path;
        error->has_logical_path = true;
    }

    return error;
}

static n00b_allocator_t *
_n00b_obj_bundle_allocator(n00b_obj_bundle_t *bundle)
{
    return bundle == nullptr ? nullptr : bundle->allocator;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_path(n00b_obj_bundle_error_code_t code,
                                 n00b_string_t               *message,
                                 n00b_string_t               *path,
                                 n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->logical_path     = path;
    error->has_logical_path = path != nullptr;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_destination(
    n00b_obj_bundle_error_code_t code,
    n00b_string_t               *message,
    n00b_string_t               *destination_path,
    n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->destination_path =
        destination_path != nullptr
        && destination_path->data != nullptr
        && destination_path->u8_bytes != 0
            ? destination_path
            : nullptr;
    error->has_destination_path = error->destination_path != nullptr;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_extract_result(
    n00b_obj_bundle_error_code_t       code,
    n00b_string_t                     *message,
    n00b_string_t                     *destination_path,
    n00b_obj_bundle_extract_result_t  *extract_result,
    n00b_allocator_t                  *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_destination(code,
                                                message,
                                                destination_path,
                                                allocator);

    error->policy_scope      = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION;
    error->has_policy_scope  = true;
    error->extract_result    = extract_result;
    error->has_extract_result = extract_result != nullptr;

    if (extract_result != nullptr && extract_result->has_policy_kind) {
        error->policy_kind     = extract_result->policy_kind;
        error->has_policy_kind = true;
    }

    if (extract_result != nullptr && extract_result->has_policy_scope) {
        error->policy_scope = extract_result->policy_scope;
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_attach_extract_result(
    n00b_obj_bundle_error_t          *error,
    n00b_string_t                    *destination_path,
    n00b_obj_bundle_extract_result_t *extract_result)
{
    if (error == nullptr) {
        return nullptr;
    }

    if (!error->has_destination_path
        && destination_path != nullptr
        && destination_path->data != nullptr
        && destination_path->u8_bytes != 0) {
        error->destination_path     = destination_path;
        error->has_destination_path = true;
    }

    if (!error->has_policy_scope) {
        error->policy_scope     = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION;
        error->has_policy_scope = true;
    }

    if (extract_result != nullptr) {
        error->extract_result     = extract_result;
        error->has_extract_result = true;

        if (!error->has_policy_kind && extract_result->has_policy_kind) {
            error->policy_kind     = extract_result->policy_kind;
            error->has_policy_kind = true;
        }

        if (extract_result->has_policy_scope) {
            error->policy_scope     = extract_result->policy_scope;
            error->has_policy_scope = true;
        }
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_clone_with_extract_result(
    n00b_obj_bundle_error_t          *source,
    n00b_string_t                    *destination_path,
    n00b_obj_bundle_extract_result_t *extract_result,
    n00b_allocator_t                 *allocator)
{
    if (source == nullptr) {
        return _n00b_obj_bundle_error_with_extract_result(
            N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
            r"object bundle: invalid extraction validation error",
            destination_path,
            extract_result,
            allocator);
    }

    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_extract_result(source->code,
                                                   source->message,
                                                   destination_path,
                                                   extract_result,
                                                   allocator);

    error->format      = source->format;
    error->has_format  = source->has_format;
    error->carrier     = source->carrier;
    error->has_carrier = source->has_carrier;

    error->logical_path     = source->logical_path;
    error->has_logical_path = source->has_logical_path;

    if (source->has_destination_path) {
        error->destination_path     = source->destination_path;
        error->has_destination_path = true;
    }

    error->artifact_id     = source->artifact_id;
    error->has_artifact_id = source->has_artifact_id;
    error->detail          = source->detail;
    error->has_detail      = source->has_detail;

    if (source->has_policy_kind) {
        error->policy_kind     = source->policy_kind;
        error->has_policy_kind = true;
    }

    if (source->has_policy_scope) {
        error->policy_scope     = source->policy_scope;
        error->has_policy_scope = true;
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_artifact(n00b_obj_bundle_error_code_t code,
                                     n00b_string_t               *message,
                                     uint64_t                     artifact_id,
                                     n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->artifact_id     = artifact_id;
    error->has_artifact_id = true;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_mark_execution(n00b_obj_bundle_error_t *error)
{
    if (error != nullptr) {
        error->policy_scope     = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION;
        error->has_policy_scope = true;
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_exec_mode(
    n00b_obj_bundle_error_code_t             code,
    n00b_string_t                           *message,
    n00b_obj_bundle_exec_mode_t              mode,
    n00b_obj_bundle_exec_platform_support_t  support,
    n00b_allocator_t                        *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->exec_requested_mode       = mode;
    error->has_exec_requested_mode   = true;
    error->exec_platform_support     = support;
    error->has_exec_platform_support = true;
    error->detail                    = (int64_t)mode;
    error->has_detail                = true;

    return _n00b_obj_bundle_error_mark_execution(error);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_host_entrypoint_unsupported_error(
    n00b_format_t              format,
    bool                       has_format,
    n00b_obj_bundle_carrier_t  carrier,
    bool                       has_carrier,
    n00b_allocator_t          *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_exec_mode(
            N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE,
            r"object bundle: host-entrypoint mutation is unsupported for carrier",
            N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT,
            N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED,
            allocator);

    error->format      = format;
    error->has_format  = has_format;
    error->carrier     = carrier;
    error->has_carrier = has_carrier;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_clone_for_execution(
    n00b_obj_bundle_error_t *source,
    n00b_allocator_t       *allocator)
{
    if (source == nullptr) {
        return _n00b_obj_bundle_error_mark_execution(
            _n00b_obj_bundle_error_new(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid execution validation error",
                allocator));
    }

    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(source->code,
                                   source->message,
                                   allocator);

    error->format      = source->format;
    error->has_format  = source->has_format;
    error->carrier     = source->carrier;
    error->has_carrier = source->has_carrier;

    error->logical_path     = source->logical_path;
    error->has_logical_path = source->has_logical_path;

    error->destination_path     = source->destination_path;
    error->has_destination_path = source->has_destination_path;

    error->artifact_id     = source->artifact_id;
    error->has_artifact_id = source->has_artifact_id;

    error->policy_kind     = source->policy_kind;
    error->has_policy_kind = source->has_policy_kind;
    error->detail          = source->detail;
    error->has_detail      = source->has_detail;

    error->exec_requested_mode     = source->exec_requested_mode;
    error->has_exec_requested_mode = source->has_exec_requested_mode;
    error->exec_platform_support     = source->exec_platform_support;
    error->has_exec_platform_support = source->has_exec_platform_support;

    error->extract_result     = source->extract_result;
    error->has_extract_result = source->has_extract_result;

    return _n00b_obj_bundle_error_mark_execution(error);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_policy(n00b_obj_bundle_error_code_t    code,
                                   n00b_string_t                  *message,
                                   n00b_obj_bundle_policy_kind_t   kind,
                                   n00b_obj_bundle_policy_scope_t  scope,
                                   uint64_t                        detail,
                                   n00b_allocator_t               *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->policy_kind      = kind;
    error->has_policy_kind  = true;
    error->policy_scope     = scope;
    error->has_policy_scope = true;
    error->detail           = (int64_t)detail;
    error->has_detail       = true;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_format_carrier(
    n00b_obj_bundle_error_code_t code,
    n00b_string_t               *message,
    n00b_format_t                format,
    bool                         has_format,
    n00b_obj_bundle_carrier_t    carrier,
    bool                         has_carrier,
    n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->format      = format;
    error->has_format  = has_format;
    error->carrier     = carrier;
    error->has_carrier = has_carrier;

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_with_format_carrier_detail(
    n00b_obj_bundle_error_code_t code,
    n00b_string_t               *message,
    n00b_format_t                format,
    bool                         has_format,
    n00b_obj_bundle_carrier_t    carrier,
    bool                         has_carrier,
    int64_t                      detail,
    bool                         has_detail,
    n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_format_carrier(code,
                                                   message,
                                                   format,
                                                   has_format,
                                                   carrier,
                                                   has_carrier,
                                                   allocator);

    error->detail     = detail;
    error->has_detail = has_detail;

    return error;
}

static bool
_n00b_obj_bundle_string_len_is_supported(n00b_string_t *s)
{
    return s != nullptr && s->u8_bytes <= UINT32_MAX && s->u8_bytes <= INT64_MAX;
}

static bool
_n00b_obj_bundle_string_bytes_eq(n00b_string_t *a, n00b_string_t *b)
{
    if (a == nullptr || b == nullptr) {
        return a == b;
    }

    if (a->u8_bytes != b->u8_bytes) {
        return false;
    }

    if (a->u8_bytes == 0) {
        return true;
    }

    return memcmp(a->data, b->data, a->u8_bytes) == 0;
}

static int
_n00b_obj_bundle_string_bytes_cmp(n00b_string_t *a, n00b_string_t *b)
{
    if (a == nullptr || b == nullptr) {
        return (a != nullptr) - (b != nullptr);
    }

    size_t min_len = a->u8_bytes < b->u8_bytes ? a->u8_bytes : b->u8_bytes;
    int    cmp     = min_len == 0 ? 0 : memcmp(a->data, b->data, min_len);

    if (cmp != 0) {
        return cmp;
    }

    return (a->u8_bytes > b->u8_bytes) - (a->u8_bytes < b->u8_bytes);
}

static int
_n00b_obj_bundle_buffer_bytes_cmp(const n00b_buffer_t *a,
                                  const n00b_buffer_t *b)
{
    if (a == nullptr || b == nullptr) {
        return (a != nullptr) - (b != nullptr);
    }

    size_t min_len = a->byte_len < b->byte_len ? a->byte_len : b->byte_len;
    int    cmp     = min_len == 0 ? 0 : memcmp(a->data, b->data, min_len);

    if (cmp != 0) {
        return cmp;
    }

    return (a->byte_len > b->byte_len) - (a->byte_len < b->byte_len);
}

static n00b_string_t *
_n00b_obj_bundle_copy_string(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s == nullptr) {
        return nullptr;
    }

    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static n00b_buffer_t *
_n00b_obj_bundle_copy_buffer(const n00b_buffer_t *buffer,
                             n00b_allocator_t    *allocator)
{
    if (buffer == nullptr) {
        return nullptr;
    }

    return n00b_buffer_copy((n00b_buffer_t *)buffer, .allocator = allocator);
}

static bool
_n00b_obj_bundle_string_has_nul(n00b_string_t *s)
{
    if (s == nullptr || s->u8_bytes == 0) {
        return false;
    }

    return memchr(s->data, '\0', s->u8_bytes) != nullptr;
}

static uint64_t
_n00b_obj_bundle_align_u64(uint64_t value, uint64_t alignment)
{
    if (alignment <= 1) {
        return value;
    }

    uint64_t rem = value % alignment;

    return rem == 0 ? value : value + alignment - rem;
}

static void
_n00b_obj_bundle_sha256_bytes(const void *data,
                              size_t      len,
                              uint8_t     out[N00B_OBJ_BUNDLE_DIGEST_LEN])
{
    n00b_sha256_digest_t digest;

    n00b_sha256_hash(data, len, digest);

    for (size_t i = 0; i < N00B_SHA256_DIGEST_WORDS; i++) {
        uint32_t word = digest[i];

        out[i * 4]     = (uint8_t)(word >> 24);
        out[i * 4 + 1] = (uint8_t)(word >> 16);
        out[i * 4 + 2] = (uint8_t)(word >> 8);
        out[i * 4 + 3] = (uint8_t)word;
    }
}

static n00b_obj_bundle_manifest_strtab_t *
_n00b_obj_bundle_manifest_strtab_new(void)
{
    n00b_obj_bundle_manifest_strtab_t *tab =
        n00b_alloc(n00b_obj_bundle_manifest_strtab_t);

    tab->cap    = 256;
    tab->data   = n00b_alloc_array(uint8_t, tab->cap);
    tab->len    = 1;
    tab->error  = false;
    tab->data[0] = 0;

    return tab;
}

static void
_n00b_obj_bundle_manifest_strtab_ensure(
    n00b_obj_bundle_manifest_strtab_t *tab,
    size_t                             need)
{
    if (tab->error || need <= tab->cap) {
        return;
    }

    size_t new_cap = tab->cap;

    while (new_cap < need) {
        if (new_cap > SIZE_MAX / 2) {
            tab->error = true;
            return;
        }

        new_cap *= 2;
    }

    uint8_t *new_data = n00b_alloc_array(uint8_t, new_cap);

    memcpy(new_data, tab->data, tab->len);
    tab->data = new_data;
    tab->cap  = new_cap;
}

static uint32_t
_n00b_obj_bundle_manifest_strtab_add(
    n00b_obj_bundle_manifest_strtab_t *tab,
    n00b_string_t                     *s)
{
    if (tab->error || s == nullptr || s->u8_bytes == 0) {
        return 0;
    }

    if (_n00b_obj_bundle_string_has_nul(s)) {
        tab->error = true;
        return 0;
    }

    for (size_t i = 1; i < tab->len; ) {
        size_t len = 0;

        while (i + len < tab->len && tab->data[i + len] != 0) {
            len++;
        }

        if (i + len >= tab->len) {
            tab->error = true;
            return 0;
        }

        if (len == s->u8_bytes
            && memcmp(tab->data + i, s->data, len) == 0) {
            return (uint32_t)i;
        }

        i += len + 1;
    }

    size_t need = tab->len + s->u8_bytes + 1;

    if (need > UINT32_MAX) {
        tab->error = true;
        return 0;
    }

    _n00b_obj_bundle_manifest_strtab_ensure(tab, need);

    if (tab->error) {
        return 0;
    }

    uint32_t off = (uint32_t)tab->len;

    memcpy(tab->data + tab->len, s->data, s->u8_bytes);
    tab->len += s->u8_bytes;
    tab->data[tab->len++] = 0;

    return off;
}

static n00b_result_t(n00b_string_t *)
_n00b_obj_bundle_normalize_logical_path(n00b_string_t     *path,
                                        n00b_allocator_t  *allocator)
{
    if (path == nullptr || !_n00b_obj_bundle_string_len_is_supported(path)) {
        return OBJ_BUNDLE_ERR(n00b_string_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid logical path argument",
                              allocator);
    }

    if (path->u8_bytes == 0 || path->data == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_string_t *,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                r"object bundle: empty logical path",
                path,
                allocator));
    }

    if (!n00b_unicode_str_validate(path)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_string_t *,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                r"object bundle: logical path is not valid UTF-8",
                path,
                allocator));
    }

    const uint8_t *data = (const uint8_t *)path->data;
    size_t         len  = path->u8_bytes;

    if (data[0] == '/' || data[len - 1] == '/') {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_string_t *,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                r"object bundle: logical path has invalid slash syntax",
                path,
                allocator));
    }

    size_t component_start = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i != len && data[i] != '/') {
            continue;
        }

        size_t component_len = i - component_start;

        if (component_len == 0
            || (component_len == 1 && data[component_start] == '.')
            || (component_len == 2
                && data[component_start] == '.'
                && data[component_start + 1] == '.')) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_string_t *,
                _n00b_obj_bundle_error_with_path(
                    N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                    r"object bundle: logical path has invalid component",
                    path,
                    allocator));
        }

        component_start = i + 1;
    }

    return n00b_result_ok(n00b_string_t *,
                          _n00b_obj_bundle_copy_string(path, allocator));
}

static bool
_n00b_obj_bundle_artifact_kind_is_valid(n00b_obj_bundle_artifact_kind_t kind)
{
    switch (kind) {
    case N00B_OBJ_BUNDLE_ARTIFACT_FILE:
    case N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE:
    case N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY:
    case N00B_OBJ_BUNDLE_ARTIFACT_METADATA:
    case N00B_OBJ_BUNDLE_ARTIFACT_OPAQUE:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_artifact_kind_requires_payload(
    n00b_obj_bundle_artifact_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_ARTIFACT_FILE
           || kind == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE
           || kind == N00B_OBJ_BUNDLE_ARTIFACT_OPAQUE;
}

static bool
_n00b_obj_bundle_artifact_has_valid_payload(
    n00b_obj_bundle_artifact_kind_t kind,
    const n00b_buffer_t            *payload)
{
    if (kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
        return payload == nullptr;
    }

    if (_n00b_obj_bundle_artifact_kind_requires_payload(kind)) {
        return payload != nullptr;
    }

    return true;
}

static bool
_n00b_obj_bundle_artifact_is_executable(n00b_obj_bundle_artifact_t *artifact)
{
    if (artifact == nullptr) {
        return false;
    }

    if (artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE) {
        return true;
    }

    return artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_FILE
           && (artifact->mode & 0111u) != 0;
}

static n00b_obj_bundle_artifact_t *
_n00b_obj_bundle_find_artifact_by_path(n00b_obj_bundle_t *bundle,
                                       n00b_string_t     *path)
{
    size_t n = n00b_list_len(bundle->artifacts);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_artifact_t *artifact =
            n00b_list_get(bundle->artifacts, i);

        if (_n00b_obj_bundle_string_bytes_eq(artifact->logical_path, path)) {
            return artifact;
        }
    }

    return nullptr;
}

static n00b_obj_bundle_artifact_t *
_n00b_obj_bundle_find_artifact_by_id(n00b_obj_bundle_t *bundle,
                                     uint64_t           artifact_id)
{
    size_t n = n00b_list_len(bundle->artifacts);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_artifact_t *artifact =
            n00b_list_get(bundle->artifacts, i);

        if (artifact->id == artifact_id) {
            return artifact;
        }
    }

    return nullptr;
}

// Internal seam exposed for the neutral runner (obj_bundle_exec_run.c): the
// in-memory NFS executor serves the selected target's bytes directly from the
// decoded artifact payload rather than re-reading them from disk. Declared in
// internal/compiler/objfile/obj_bundle_exec.h.
const n00b_buffer_t *
_n00b_obj_bundle_artifact_bytes_for_path(n00b_obj_bundle_t *bundle,
                                         n00b_string_t     *logical_path)
{
    if (bundle == nullptr || logical_path == nullptr) {
        return nullptr;
    }

    n00b_obj_bundle_artifact_t *artifact =
        _n00b_obj_bundle_find_artifact_by_path(bundle, logical_path);

    if (artifact == nullptr) {
        return nullptr;
    }

    return artifact->payload;
}

static bool
_n00b_obj_bundle_selector_is_valid(n00b_string_t *selector)
{
    return _n00b_obj_bundle_string_len_is_supported(selector)
           && selector->u8_bytes != 0
           && selector->data != nullptr
           && n00b_unicode_str_validate(selector);
}

static n00b_obj_bundle_exec_mapping_t *
_n00b_obj_bundle_find_mapping_by_selector(n00b_obj_bundle_t *bundle,
                                          n00b_string_t     *selector)
{
    size_t n = n00b_list_len(bundle->exec_mappings);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_exec_mapping_t *mapping =
            n00b_list_get(bundle->exec_mappings, i);

        if (_n00b_obj_bundle_string_bytes_eq(mapping->selector, selector)) {
            return mapping;
        }
    }

    return nullptr;
}

static bool
_n00b_obj_bundle_policy_kind_is_known(n00b_obj_bundle_policy_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B;
}

static bool
_n00b_obj_bundle_policy_kind_is_supported(n00b_obj_bundle_policy_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1;
}

static bool
_n00b_obj_bundle_extraction_policy_kind_is_supported(
    n00b_obj_bundle_policy_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B;
}

static bool
_n00b_obj_bundle_policy_scope_is_valid(n00b_obj_bundle_policy_scope_t scope)
{
    return scope != N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE
           && (scope & ~N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH) == 0;
}

static bool
_n00b_obj_bundle_policy_flags_are_valid(uint64_t flags)
{
    uint64_t allowed = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED
                       | N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                       | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED;
    bool has_required = (flags & N00B_OBJ_BUNDLE_POLICY_F_REQUIRED) != 0;
    bool has_optional = (flags & N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL) != 0;

    return (flags & ~allowed) == 0 && has_required != has_optional;
}

static n00b_obj_bundle_policy_t *
_n00b_obj_bundle_find_policy_by_id(n00b_obj_bundle_t *bundle,
                                   uint64_t           policy_id)
{
    size_t n = n00b_list_len(bundle->policies);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_policy_t *policy = n00b_list_get(bundle->policies, i);

        if (policy->policy_id == policy_id) {
            return policy;
        }
    }

    return nullptr;
}

static uint16_t
_n00b_obj_bundle_le16_at(const uint8_t *data, size_t off)
{
    return (uint16_t)data[off] | ((uint16_t)data[off + 1] << 8);
}

static uint32_t
_n00b_obj_bundle_le32_at(const uint8_t *data, size_t off)
{
    return (uint32_t)data[off]
           | ((uint32_t)data[off + 1] << 8)
           | ((uint32_t)data[off + 2] << 16)
           | ((uint32_t)data[off + 3] << 24);
}

static uint64_t
_n00b_obj_bundle_le64_at(const uint8_t *data, size_t off)
{
    return (uint64_t)_n00b_obj_bundle_le32_at(data, off)
           | ((uint64_t)_n00b_obj_bundle_le32_at(data, off + 4) << 32);
}

static bool
_n00b_obj_bundle_declarative_policy_payload_is_valid(
    const n00b_buffer_t *payload,
    uint64_t             fallback_policy_id)
{
    if (payload == nullptr
        || payload->byte_len != N00B_OBJ_BUNDLE_DECL_POLICY_SIZE) {
        return false;
    }

    const uint8_t *data = (const uint8_t *)payload->data;

    if (memcmp(data,
               N00B_OBJ_BUNDLE_POLICY_MAGIC,
               N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN) != 0) {
        return false;
    }

    uint16_t major = _n00b_obj_bundle_le16_at(data, 8);
    uint16_t minor = _n00b_obj_bundle_le16_at(data, 10);
    uint32_t reserved0 = _n00b_obj_bundle_le32_at(data, 12);
    uint64_t decl_flags =
        _n00b_obj_bundle_le64_at(data,
                                 N00B_OBJ_BUNDLE_DECL_POLICY_DECL_FLAGS_OFF);
    uint64_t path_flags =
        _n00b_obj_bundle_le64_at(data,
                                 N00B_OBJ_BUNDLE_DECL_POLICY_PATH_FLAGS_OFF);
    uint64_t artifact_kind_mask =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_DECL_POLICY_ARTIFACT_MASK_OFF);
    uint64_t execution_flags =
        _n00b_obj_bundle_le64_at(data,
                                 N00B_OBJ_BUNDLE_DECL_POLICY_EXEC_FLAGS_OFF);
    uint64_t payload_fallback_id =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_DECL_POLICY_FALLBACK_ID_OFF);
    uint64_t reserved1 =
        _n00b_obj_bundle_le64_at(data,
                                 N00B_OBJ_BUNDLE_DECL_POLICY_RESERVED1_OFF);

    return major == N00B_OBJ_BUNDLE_DECL_POLICY_MAJOR
           && minor == N00B_OBJ_BUNDLE_DECL_POLICY_MINOR
           && reserved0 == 0
           && decl_flags == 0
           && path_flags == N00B_OBJ_BUNDLE_DECL_PATH_DEFAULT
           && artifact_kind_mask
                  == N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DEFAULT
           && (execution_flags & ~N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT) == 0
           && payload_fallback_id == fallback_policy_id
           && reserved1 == 0;
}

static bool
_n00b_obj_bundle_utf8_bytes_are_valid(const uint8_t *data, uint64_t len)
{
    if (data == nullptr || len > UINT32_MAX) {
        return false;
    }

    return n00b_unicode_utf8_validate((const char *)data, (uint32_t)len);
}

static bool
_n00b_obj_bundle_embedded_policy_payload_is_valid(
    const n00b_buffer_t *payload,
    uint64_t             fallback_policy_id)
{
    if (payload == nullptr
        || payload->byte_len < N00B_OBJ_BUNDLE_EMBEDDED_POLICY_HEADER_SIZE) {
        return false;
    }

    const uint8_t *data = (const uint8_t *)payload->data;

    if (memcmp(data,
               N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC,
               N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN) != 0) {
        return false;
    }

    uint16_t major = _n00b_obj_bundle_le16_at(data, 8);
    uint16_t minor = _n00b_obj_bundle_le16_at(data, 10);
    uint32_t reserved0 =
        _n00b_obj_bundle_le32_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_RESERVED0_OFF);
    uint64_t compat_flags =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_COMPAT_FLAGS_OFF);
    uint64_t payload_fallback_id =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_FALLBACK_ID_OFF);
    uint64_t source_len =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_LEN_OFF);
    uint64_t reserved1 =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_RESERVED1_OFF);

    if (source_len == 0
        || source_len > UINT64_MAX
                            - N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF) {
        return false;
    }

    uint64_t expected_len =
        N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF + source_len;

    if (expected_len != (uint64_t)payload->byte_len) {
        return false;
    }

    return major == N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR
           && minor == N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR
           && reserved0 == 0
           && (compat_flags
               & ~N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS)
                  == 0
           && payload_fallback_id == fallback_policy_id
           && reserved1 == 0
           && _n00b_obj_bundle_utf8_bytes_are_valid(
               data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
               source_len);
}

static bool
_n00b_obj_bundle_policy_payload_is_valid(n00b_obj_bundle_policy_kind_t kind,
                                         const n00b_buffer_t          *payload,
                                         uint64_t fallback_policy_id)
{
    if (kind == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT) {
        return payload == nullptr;
    }

    if (kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1) {
        return _n00b_obj_bundle_declarative_policy_payload_is_valid(
            payload,
            fallback_policy_id);
    }

    if (kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B) {
        return _n00b_obj_bundle_embedded_policy_payload_is_valid(
            payload,
            fallback_policy_id);
    }

    return false;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_embedded_policy_error(
    n00b_obj_bundle_error_code_t       code,
    n00b_string_t                     *message,
    n00b_obj_bundle_policy_scope_t     scope,
    n00b_obj_bundle_policy_context_t  *context,
    int64_t                            detail,
    bool                               has_detail,
    n00b_allocator_t                  *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(code, message, allocator);

    error->policy_kind      = N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B;
    error->has_policy_kind  = true;
    error->policy_scope     = scope;
    error->has_policy_scope = true;

    if (has_detail) {
        error->detail     = detail;
        error->has_detail = true;
    }

    if (context != nullptr && context->logical_path != nullptr) {
        error->logical_path     = context->logical_path;
        error->has_logical_path = true;
    }

    return error;
}

static n00b_result_t(n00b_string_t *)
_n00b_obj_bundle_embedded_policy_source(
    const n00b_buffer_t               *payload,
    uint64_t                           fallback_policy_id,
    n00b_obj_bundle_policy_scope_t     scope,
    n00b_obj_bundle_policy_context_t  *context,
    n00b_allocator_t                  *allocator)
{
    if (!_n00b_obj_bundle_embedded_policy_payload_is_valid(
            payload,
            fallback_policy_id)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_string_t *,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid embedded policy payload",
                scope,
                context,
                0,
                false,
                allocator));
    }

    const uint8_t *data = (const uint8_t *)payload->data;
    uint64_t       source_len =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_LEN_OFF);

    return n00b_result_ok(
        n00b_string_t *,
        n00b_string_from_raw(
            (const char *)data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
            (int64_t)source_len,
            .allocator = allocator));
}

static bool
_n00b_obj_bundle_embedded_policy_source_has_expression_start(
    n00b_string_t *source)
{
    if (source == nullptr || source->data == nullptr) {
        return false;
    }

    for (size_t i = 0; i < source->u8_bytes; i++) {
        char ch = source->data[i];

        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
            continue;
        }

        return ch != ';' && ch != '}' && ch != '@';
    }

    return false;
}

static n00b_obj_bundle_policy_context_t *
_n00b_obj_bundle_policy_context_new(
    n00b_obj_bundle_policy_scope_t          scope,
    n00b_string_t                          *logical_path,
    n00b_obj_bundle_artifact_kind_t         artifact_kind,
    n00b_obj_bundle_exec_selection_source_t selection_source,
    bool                                    overwrite,
    bool                                    create_dirs,
    bool                                    inherit_env,
    bool                                    strict_selector,
    n00b_obj_bundle_exec_mode_t             requested_mode,
    n00b_obj_bundle_policy_mode_t           policy_mode,
    n00b_allocator_t                       *allocator)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_alloc_with_opts(
            n00b_obj_bundle_policy_context_t,
            &(n00b_alloc_opts_t){
                .allocator = allocator,
                .scan_kind = N00B_GC_SCAN_KIND_ALL,
            });

    context->scope            = scope;
    context->logical_path     =
        _n00b_obj_bundle_copy_string(logical_path, allocator);
    context->artifact_kind    = artifact_kind;
    context->selection_source = selection_source;
    context->overwrite        = overwrite;
    context->create_dirs      = create_dirs;
    context->inherit_env      = inherit_env;
    context->strict_selector  = strict_selector;
    context->requested_mode   = requested_mode;
    context->policy_mode      = policy_mode;

    return context;
}

n00b_obj_bundle_policy_context_t *
n00b_obj_bundle_policy_context_for_extraction(
    n00b_string_t                    *logical_path,
    n00b_obj_bundle_artifact_kind_t   artifact_kind) _kargs
{
    bool                         overwrite   = false;
    bool                         create_dirs = true;
    n00b_obj_bundle_policy_mode_t policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t *allocator = nullptr;
}
{
    return _n00b_obj_bundle_policy_context_new(
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        logical_path,
        artifact_kind,
        N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE,
        overwrite,
        create_dirs,
        false,
        false,
        N00B_OBJ_BUNDLE_EXEC_AUTO,
        policy_mode,
        allocator);
}

n00b_obj_bundle_policy_context_t *
n00b_obj_bundle_policy_context_for_execution(
    n00b_string_t                           *logical_path,
    n00b_obj_bundle_artifact_kind_t          artifact_kind) _kargs
{
    n00b_obj_bundle_exec_selection_source_t selection_source =
        N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT;
    bool                         inherit_env     = true;
    bool                         strict_selector = false;
    n00b_obj_bundle_exec_mode_t  requested_mode  = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t *allocator = nullptr;
}
{
    return _n00b_obj_bundle_policy_context_new(
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        logical_path,
        artifact_kind,
        selection_source,
        false,
        false,
        inherit_env,
        strict_selector,
        requested_mode,
        policy_mode,
        allocator);
}

int64_t
n00b_obj_bundle_policy_context_scope(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr) {
        return 0;
    }

    return (int64_t)context->scope;
}

n00b_string_t *
n00b_obj_bundle_policy_context_logical_path(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr || context->logical_path == nullptr) {
        return r"";
    }

    return context->logical_path;
}

int64_t
n00b_obj_bundle_policy_context_artifact_kind(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr) {
        return 0;
    }

    return (int64_t)context->artifact_kind;
}

int64_t
n00b_obj_bundle_policy_context_selection_source(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr) {
        return 0;
    }

    return (int64_t)context->selection_source;
}

bool
n00b_obj_bundle_policy_context_overwrite(
    n00b_obj_bundle_policy_context_t *context)
{
    return context != nullptr && context->overwrite;
}

bool
n00b_obj_bundle_policy_context_create_dirs(
    n00b_obj_bundle_policy_context_t *context)
{
    return context != nullptr && context->create_dirs;
}

bool
n00b_obj_bundle_policy_context_inherit_env(
    n00b_obj_bundle_policy_context_t *context)
{
    return context != nullptr && context->inherit_env;
}

bool
n00b_obj_bundle_policy_context_strict_selector(
    n00b_obj_bundle_policy_context_t *context)
{
    return context != nullptr && context->strict_selector;
}

int64_t
n00b_obj_bundle_policy_context_requested_mode(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr) {
        return 0;
    }

    return (int64_t)context->requested_mode;
}

int64_t
n00b_obj_bundle_policy_context_policy_mode(
    n00b_obj_bundle_policy_context_t *context)
{
    if (context == nullptr) {
        return 0;
    }

    return (int64_t)context->policy_mode;
}

static bool s_obj_bundle_policy_context_type_registered = false;

void
n00b_obj_bundle_policy_context_type_register(void)
{
    if (s_obj_bundle_policy_context_type_registered) {
        return;
    }

    (void)N00B_TYPE_REGISTER(
        n00b_obj_bundle_policy_context_t,
        N00B_TYPE_STATIC_TRANSIENT(
            r"object-bundle policy contexts are predicate-scoped"));

    uint64_t th = typehash(n00b_obj_bundle_policy_context_t *);

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)n00b_obj_bundle_policy_context_scope,
        .name        = "scope",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_logical_path,
        .name        = "logical_path",
        .return_type = {
            .type_hash = typehash(n00b_string_t *),
            .type_name = "string",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_artifact_kind,
        .name        = "artifact_kind",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_selection_source,
        .name        = "selection_source",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_overwrite,
        .name        = "overwrite",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_create_dirs,
        .name        = "create_dirs",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_inherit_env,
        .name        = "inherit_env",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_strict_selector,
        .name        = "strict_selector",
        .return_type = {
            .type_hash = typehash(bool),
            .type_name = "bool",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_requested_mode,
        .name        = "requested_mode",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    n00b_type_add_method(th, &(n00b_method_t){
        .fn          = (n00b_vtable_entry)
            n00b_obj_bundle_policy_context_policy_mode,
        .name        = "policy_mode",
        .return_type = {
            .type_hash = typehash(int64_t),
            .type_name = "i64",
        },
    });

    s_obj_bundle_policy_context_type_registered = true;
}

n00b_result_t(n00b_eval_session_t *)
n00b_obj_bundle_policy_eval_session_new(
    n00b_obj_bundle_policy_scope_t scope) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto session = n00b_eval_session_new(.allocator = allocator);

    if (n00b_result_is_err(session)) {
        n00b_eval_err_t eval_err =
            (n00b_eval_err_t)n00b_result_get_err(session);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_eval_session_t *,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                n00b_eval_err_str(eval_err),
                scope,
                nullptr,
                (int64_t)eval_err,
                true,
                allocator));
    }

    n00b_obj_bundle_policy_context_type_register();

    return session;
}

n00b_result_t(bool)
n00b_obj_bundle_policy_evaluate_embedded(
    n00b_eval_session_t                  *session,
    const n00b_buffer_t                  *payload,
    uint64_t                              fallback_policy_id,
    n00b_obj_bundle_policy_scope_t        scope,
    n00b_obj_bundle_policy_context_t     *context) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (context == nullptr || !_n00b_obj_bundle_policy_scope_is_valid(scope)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid embedded policy evaluation argument",
                scope,
                context,
                0,
                false,
                allocator));
    }

    auto source = _n00b_obj_bundle_embedded_policy_source(
        payload,
        fallback_policy_id,
        scope,
        context,
        allocator);

    if (n00b_result_is_err(source)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, source));
    }

    n00b_string_t *source_text = n00b_result_get(source);

    if (!_n00b_obj_bundle_embedded_policy_source_has_expression_start(
            source_text)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                n00b_eval_err_str(N00B_EVAL_ERR_PARSE),
                scope,
                context,
                (int64_t)N00B_EVAL_ERR_PARSE,
                true,
                allocator));
    }

    n00b_eval_session_t *eval_session = session;
    bool                 owns_session = false;

    if (eval_session == nullptr) {
        auto create = n00b_obj_bundle_policy_eval_session_new(
            scope,
            .allocator = allocator);

        if (n00b_result_is_err(create)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            create));
        }

        eval_session = n00b_result_get(create);
        owns_session = true;
    }
    else {
        n00b_obj_bundle_policy_context_type_register();
    }

    auto compiled = n00b_eval_compile_predicate(
        eval_session,
        source_text,
        r"n00b_obj_bundle_policy_context_t",
        .allocator = allocator);

    if (n00b_result_is_err(compiled)) {
        n00b_eval_err_t eval_err =
            (n00b_eval_err_t)n00b_result_get_err(compiled);

        n00b_result_t(bool) result = OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                n00b_eval_err_str(eval_err),
                scope,
                context,
                (int64_t)eval_err,
                true,
                allocator));

        if (owns_session) {
            n00b_eval_session_free(eval_session);
        }

        return result;
    }

    n00b_eval_predicate_fn_t fn = n00b_result_get(compiled);

    if (fn == nullptr) {
        n00b_result_t(bool) result = OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: embedded policy predicate is null",
                scope,
                context,
                (int64_t)N00B_EVAL_ERR_JIT,
                true,
                allocator));

        if (owns_session) {
            n00b_eval_session_free(eval_session);
        }

        return result;
    }

    bool allowed = fn((void *)context);

    if (!allowed) {
        n00b_result_t(bool) result = OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_POLICY_DENIED,
                r"object bundle: embedded policy denied operation",
                scope,
                context,
                0,
                true,
                allocator));

        if (owns_session) {
            n00b_eval_session_free(eval_session);
        }

        return result;
    }

    if (owns_session) {
        n00b_eval_session_free(eval_session);
    }

    return n00b_result_ok(bool, true);
}

static bool
_n00b_obj_bundle_format_request_is_valid(n00b_format_t format)
{
    switch (format) {
    case N00B_FMT_UNKNOWN:
    case N00B_FMT_ELF:
    case N00B_FMT_MACHO:
    case N00B_FMT_PE:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_carrier_request_is_valid(n00b_obj_bundle_carrier_t carrier)
{
    switch (carrier) {
    case N00B_OBJ_BUNDLE_CARRIER_AUTO:
    case N00B_OBJ_BUNDLE_CARRIER_METADATA:
    case N00B_OBJ_BUNDLE_CARRIER_LOADABLE:
    case N00B_OBJ_BUNDLE_CARRIER_SPLIT:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_replace_policy_is_valid(
    n00b_obj_bundle_replace_policy_t replace)
{
    switch (replace) {
    case N00B_OBJ_BUNDLE_REJECT_EXISTING:
    case N00B_OBJ_BUNDLE_REPLACE_EXISTING:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_entrypoint_policy_is_valid(
    n00b_obj_bundle_entrypoint_policy_t entrypoint)
{
    switch (entrypoint) {
    case N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE:
    case N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_policy_mode_is_valid(
    n00b_obj_bundle_policy_mode_t policy_mode)
{
    switch (policy_mode) {
    case N00B_OBJ_BUNDLE_POLICY_ENFORCE:
    case N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY:
        return true;
    default:
        return false;
    }
}

static bool
_n00b_obj_bundle_exec_mode_is_valid(n00b_obj_bundle_exec_mode_t mode)
{
    switch (mode) {
    case N00B_OBJ_BUNDLE_EXEC_AUTO:
    case N00B_OBJ_BUNDLE_EXEC_EXTRACTED:
    case N00B_OBJ_BUNDLE_EXEC_MEMFD:
    case N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT:
    case N00B_OBJ_BUNDLE_EXEC_NFS:
        return true;
    default:
        return false;
    }
}

// _n00b_obj_bundle_exec_select_mode is implemented in obj_bundle_exec_run.c
// (the neutral runner) and declared in obj_bundle_exec.h (included above).

static bool
_n00b_obj_bundle_exec_mode_is_supported(n00b_obj_bundle_exec_mode_t mode)
{
    if (mode == N00B_OBJ_BUNDLE_EXEC_AUTO
        || mode == N00B_OBJ_BUNDLE_EXEC_EXTRACTED) {
        return true;
    }

#if defined(__MACH__)
    // NFS is a macOS-only execution mode (Linux = memfd -> extraction, no NFS).
    // Planning marks NFS supported on macOS; the runner's runtime probe
    // (helper present + executable + setuid) is the final arbiter and falls
    // through to extraction when the helper is absent (D-050 / OQ-3).
    if (mode == N00B_OBJ_BUNDLE_EXEC_NFS) {
        return true;
    }
#endif

#if defined(__linux__)
    // memfd is a Linux-only execution mode (anonymous fd + fexecve). Planning
    // marks MEMFD supported on Linux; the runner's runtime probe is the final
    // arbiter and falls through to extraction if it is ever unavailable.
    if (mode == N00B_OBJ_BUNDLE_EXEC_MEMFD) {
        return true;
    }
#endif

    return false;
}

static n00b_obj_bundle_exec_mode_t
_n00b_obj_bundle_exec_mode_resolve(n00b_obj_bundle_exec_mode_t mode)
{
    if (mode == N00B_OBJ_BUNDLE_EXEC_AUTO) {
        n00b_obj_bundle_exec_mode_t selected =
            _n00b_obj_bundle_exec_select_mode(N00B_OBJ_BUNDLE_EXEC_AUTO, true);

        // Planning always offers the extraction fallback, so the selection
        // helper never returns the "nothing available" sentinel here; keep the
        // historical EXTRACTED contract for AUTO if it somehow does.
        return selected == N00B_OBJ_BUNDLE_EXEC_AUTO
                   ? N00B_OBJ_BUNDLE_EXEC_EXTRACTED
                   : selected;
    }

    return mode;
}

static n00b_obj_bundle_exec_argv_t *
_n00b_obj_bundle_exec_argv_plan(
    n00b_obj_bundle_exec_argv_t *argv,
    n00b_string_t               *default_argv0,
    n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_exec_argv_t *planned =
        n00b_alloc_with_opts(n00b_obj_bundle_exec_argv_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    *planned = n00b_list_new(n00b_string_t *, .allocator = allocator);

    if (argv != nullptr) {
        size_t n = n00b_list_len(*argv);

        for (size_t i = 0; i < n; i++) {
            n00b_string_t *arg = n00b_list_get(*argv, i);
            n00b_list_push(*planned,
                           _n00b_obj_bundle_copy_string(arg, allocator));
        }

        return planned;
    }

    n00b_list_push(*planned,
                   _n00b_obj_bundle_copy_string(default_argv0, allocator));

    return planned;
}

static n00b_obj_bundle_exec_env_t *
_n00b_obj_bundle_exec_env_plan(n00b_obj_bundle_exec_env_t *env,
                               n00b_allocator_t          *allocator)
{
    if (env == nullptr) {
        return nullptr;
    }

    n00b_obj_bundle_exec_env_t *planned =
        n00b_dict_new_private(n00b_string_t *,
                              n00b_string_t *,
                              .allocator = allocator);

    n00b_dict_foreach(env, key, value, {
        n00b_string_t *planned_key =
            _n00b_obj_bundle_copy_string(key, allocator);
        n00b_string_t *planned_value =
            _n00b_obj_bundle_copy_string(value, allocator);

        n00b_dict_put(planned, planned_key, planned_value);
    });

    return planned;
}

static bool
_n00b_obj_bundle_object_bytes_arg_is_valid(n00b_buffer_t *object_bytes)
{
    return object_bytes != nullptr && object_bytes->data != nullptr;
}

static bool
_n00b_obj_bundle_extract_destination_arg_is_valid(
    n00b_string_t *destination_root)
{
    return destination_root != nullptr
           && destination_root->data != nullptr
           && destination_root->u8_bytes != 0;
}

static n00b_obj_bundle_exec_plan_t *
_n00b_obj_bundle_exec_plan_new(
    n00b_string_t                             *selector,
    n00b_obj_bundle_exec_argv_t               *argv,
    n00b_obj_bundle_exec_env_t                *env,
    bool                                       inherit_env,
    bool                                       strict_selector,
    n00b_obj_bundle_exec_mode_t                mode,
    n00b_obj_bundle_policy_mode_t              policy_mode,
    n00b_allocator_t                          *allocator)
{
    n00b_obj_bundle_exec_plan_t *plan =
        n00b_alloc_with_opts(n00b_obj_bundle_exec_plan_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    plan->selector                 = selector;
    plan->argv                     = argv;
    plan->env                      = env;
    plan->inherit_env              = inherit_env;
    plan->strict_selector          = strict_selector;
    plan->requested_mode           = mode;
    plan->resolved_mode            = _n00b_obj_bundle_exec_mode_resolve(mode);
    plan->platform_support         =
        N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORTED;
    plan->requires_extraction      = true;
    plan->policy_mode              = policy_mode;
    plan->policy_kind              = N00B_OBJ_BUNDLE_POLICY_KIND_NONE;
    plan->has_policy_kind          = false;
    plan->policy_scope             = N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE;
    plan->has_policy_scope         = false;
    plan->fallback_used            = false;
    plan->selected_artifact_id     = N00B_OBJ_BUNDLE_ARTIFACT_ID_NONE;
    plan->has_selected_artifact_id = false;
    plan->selected_logical_path    = nullptr;
    plan->has_selected_logical_path = false;
    plan->selection_source = N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE;

    return plan;
}

static n00b_obj_bundle_extract_result_t *
_n00b_obj_bundle_extract_result_new(
    n00b_string_t                    *destination_root,
    bool                              overwrite,
    bool                              atomic,
    bool                              preserve_modes,
    bool                              create_dirs,
    bool                              allow_absolute_paths,
    bool                              allow_parent_refs,
    n00b_obj_bundle_policy_mode_t     policy_mode,
    n00b_allocator_t                 *allocator)
{
    n00b_obj_bundle_extract_result_t *result =
        n00b_alloc_with_opts(n00b_obj_bundle_extract_result_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    result->destination_root      = destination_root;
    result->temp_root             = nullptr;
    result->has_temp_root         = false;
    result->files_planned         = 0;
    result->directories_planned   = 0;
    result->files_written         = 0;
    result->directories_written   = 0;
    result->policy_kind           = N00B_OBJ_BUNDLE_POLICY_KIND_NONE;
    result->has_policy_kind       = false;
    result->policy_scope          = N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE;
    result->has_policy_scope      = false;
    result->fallback_used         = false;
    result->overwrite             = overwrite;
    result->atomic_requested      = atomic;
    result->atomic_used           = false;
    result->preserve_modes        = preserve_modes;
    result->create_dirs           = create_dirs;
    result->allow_absolute_paths  = allow_absolute_paths;
    result->allow_parent_refs     = allow_parent_refs;
    result->policy_mode           = policy_mode;
    result->commit_attempted      = false;
    result->commit_completed      = false;
    result->rollback_attempted    = false;
    result->rollback_succeeded    = false;
    result->cleanup_attempted     = false;
    result->cleanup_succeeded     = false;

    return result;
}

static void
_n00b_obj_bundle_extract_result_set_policy(
    n00b_obj_bundle_extract_result_t *result,
    n00b_obj_bundle_extract_policy_t *policy)
{
    result->policy_kind      = policy->kind;
    result->has_policy_kind  = true;
    result->policy_scope     = policy->scope;
    result->has_policy_scope = true;
    result->fallback_used    = policy->fallback_used;
}

static void
_n00b_obj_bundle_declarative_policy_fields(
    n00b_obj_bundle_policy_t         *policy,
    n00b_obj_bundle_extract_policy_t *extract_policy)
{
    const uint8_t *data = (const uint8_t *)policy->payload->data;

    extract_policy->path_flags =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_DECL_POLICY_PATH_FLAGS_OFF);
    extract_policy->artifact_kind_mask =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_DECL_POLICY_ARTIFACT_MASK_OFF);
    extract_policy->execution_flags =
        _n00b_obj_bundle_le64_at(
            data,
            N00B_OBJ_BUNDLE_DECL_POLICY_EXEC_FLAGS_OFF);
}

static bool
_n00b_obj_bundle_policy_applies_to_extraction(
    n00b_obj_bundle_policy_t *policy)
{
    return policy != nullptr
           && (policy->scope & N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION) != 0;
}

static bool
_n00b_obj_bundle_policy_is_better_candidate(
    n00b_obj_bundle_policy_t *candidate,
    n00b_obj_bundle_policy_t *current)
{
    if (current == nullptr) {
        return true;
    }

    if (candidate->priority != current->priority) {
        return candidate->priority > current->priority;
    }

    return candidate->kind > current->kind;
}

static bool
_n00b_obj_bundle_policy_payload_is_supported(
    n00b_obj_bundle_policy_t *policy)
{
    return policy != nullptr
           && _n00b_obj_bundle_policy_kind_is_supported(policy->kind)
           && _n00b_obj_bundle_policy_payload_is_valid(
               policy->kind,
               policy->payload,
               policy->fallback_policy_id);
}

static bool
_n00b_obj_bundle_extraction_policy_payload_is_supported(
    n00b_obj_bundle_policy_t *policy)
{
    return policy != nullptr
           && _n00b_obj_bundle_extraction_policy_kind_is_supported(
               policy->kind)
           && _n00b_obj_bundle_policy_payload_is_valid(
               policy->kind,
               policy->payload,
               policy->fallback_policy_id);
}

static bool
_n00b_obj_bundle_execution_policy_kind_is_supported(
    n00b_obj_bundle_policy_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1
           || kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B;
}

static bool
_n00b_obj_bundle_execution_policy_payload_is_supported(
    n00b_obj_bundle_policy_t *policy)
{
    return policy != nullptr
           && _n00b_obj_bundle_execution_policy_kind_is_supported(
               policy->kind)
           && _n00b_obj_bundle_policy_payload_is_valid(
               policy->kind,
               policy->payload,
               policy->fallback_policy_id);
}

static void
_n00b_obj_bundle_extract_policy_set_builtin_fallback(
    n00b_obj_bundle_extract_policy_t *policy)
{
    policy->kind = N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT;
    policy->scope                   = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION;
    policy->fallback_used           = true;
    policy->can_fallback_to_builtin = false;
    policy->policy_id               = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->flags                   = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    policy->priority                = 0;
    policy->fallback_policy_id      = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->payload                 = nullptr;
    policy->path_flags              = N00B_OBJ_BUNDLE_DECL_PATH_DEFAULT;
    policy->artifact_kind_mask      = N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DEFAULT;
    policy->execution_flags         = N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT;
}

static void
_n00b_obj_bundle_exec_policy_set_builtin_fallback(
    n00b_obj_bundle_exec_policy_t *policy)
{
    policy->kind =
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT;
    policy->scope                   = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION;
    policy->fallback_used           = true;
    policy->can_fallback_to_builtin = false;
    policy->policy_id               = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->flags                   = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    policy->priority                = 0;
    policy->fallback_policy_id      = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->payload                 = nullptr;
    policy->execution_flags         = N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT;
}

static n00b_obj_bundle_policy_t *
_n00b_obj_bundle_extraction_policy_fallback(
    n00b_obj_bundle_t        *bundle,
    n00b_obj_bundle_policy_t *policy)
{
    if (policy == nullptr
        || policy->fallback_policy_id == N00B_OBJ_BUNDLE_POLICY_ID_NONE
        || (policy->flags & N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED) == 0) {
        return nullptr;
    }

    n00b_obj_bundle_policy_t *fallback =
        _n00b_obj_bundle_find_policy_by_id(bundle, policy->fallback_policy_id);

    if (fallback == nullptr
        || fallback->kind != N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
        || !_n00b_obj_bundle_policy_scope_is_valid(fallback->scope)
        || !_n00b_obj_bundle_policy_flags_are_valid(fallback->flags)
        || !_n00b_obj_bundle_policy_payload_is_supported(fallback)
        || fallback->priority >= policy->priority
        || (fallback->scope & N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION) == 0) {
        return nullptr;
    }

    return fallback;
}

static n00b_result_t(n00b_obj_bundle_extract_policy_t *)
_n00b_obj_bundle_select_extraction_policy(n00b_obj_bundle_t *bundle,
                                          n00b_allocator_t  *allocator)
{
    n00b_obj_bundle_policy_t *selected = nullptr;
    size_t                    n        = n00b_list_len(bundle->policies);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_policy_t *policy = n00b_list_get(bundle->policies, i);

        if (policy == nullptr
            || !_n00b_obj_bundle_policy_scope_is_valid(policy->scope)
            || !_n00b_obj_bundle_policy_flags_are_valid(policy->flags)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_policy_t *,
                _n00b_obj_bundle_error_with_policy(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid extraction policy record",
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_KIND_NONE
                        : policy->kind,
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE
                        : policy->scope,
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_ID_NONE
                        : policy->policy_id,
                    allocator));
        }

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_policy_t *other = n00b_list_get(bundle->policies,
                                                            j);

            if (other != nullptr && policy->policy_id == other->policy_id) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID,
                        r"object bundle: duplicate extraction policy ID",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }
        }

        if (!_n00b_obj_bundle_policy_applies_to_extraction(policy)) {
            if (_n00b_obj_bundle_policy_kind_is_known(policy->kind)
                && !_n00b_obj_bundle_policy_payload_is_valid(
                    policy->kind,
                    policy->payload,
                    policy->fallback_policy_id)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid non-extraction policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            continue;
        }

        n00b_obj_bundle_policy_t *fallback =
            _n00b_obj_bundle_extraction_policy_fallback(bundle, policy);

        if (!_n00b_obj_bundle_extraction_policy_kind_is_supported(
                policy->kind)) {
            if (_n00b_obj_bundle_policy_kind_is_known(policy->kind)
                && !_n00b_obj_bundle_policy_payload_is_valid(
                    policy->kind,
                    policy->payload,
                    policy->fallback_policy_id)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid extraction policy payload",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if ((policy->flags & N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL) == 0
                || fallback == nullptr) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                        r"object bundle: unsupported extraction policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (_n00b_obj_bundle_policy_is_better_candidate(policy,
                                                            selected)) {
                selected = policy;
            }

            continue;
        }

        if (!_n00b_obj_bundle_extraction_policy_payload_is_supported(policy)) {
            if (policy->kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid embedded extraction policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (fallback == nullptr) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid declarative extraction policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (_n00b_obj_bundle_policy_is_better_candidate(policy,
                                                            selected)) {
                selected = policy;
            }

            continue;
        }

        if (policy->fallback_policy_id != N00B_OBJ_BUNDLE_POLICY_ID_NONE
            && fallback == nullptr) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_policy_t *,
                _n00b_obj_bundle_error_with_policy(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid extraction policy fallback",
                    policy->kind,
                    policy->scope,
                    policy->fallback_policy_id,
                    allocator));
        }

        if (_n00b_obj_bundle_policy_is_better_candidate(policy, selected)) {
            selected = policy;
        }
    }

    n00b_obj_bundle_extract_policy_t *policy =
        n00b_alloc_with_opts(n00b_obj_bundle_extract_policy_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    policy->scope              = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION;
    policy->fallback_used      = false;
    policy->can_fallback_to_builtin = false;
    policy->policy_id          = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->flags              = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    policy->priority           = 0;
    policy->fallback_policy_id = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->payload            = nullptr;
    policy->path_flags         = N00B_OBJ_BUNDLE_DECL_PATH_DEFAULT;
    policy->artifact_kind_mask = N00B_OBJ_BUNDLE_DECL_ARTIFACT_KIND_DEFAULT;
    policy->execution_flags    = N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT;

    if (selected == nullptr) {
        policy->kind = N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT;
        return n00b_result_ok(n00b_obj_bundle_extract_policy_t *, policy);
    }

    n00b_obj_bundle_policy_t *fallback =
        _n00b_obj_bundle_extraction_policy_fallback(bundle, selected);

    if (!_n00b_obj_bundle_extraction_policy_payload_is_supported(selected)
        && fallback != nullptr) {
        _n00b_obj_bundle_extract_policy_set_builtin_fallback(policy);
        return n00b_result_ok(n00b_obj_bundle_extract_policy_t *, policy);
    }

    policy->kind                    = selected->kind;
    policy->policy_id               = selected->policy_id;
    policy->flags                   = selected->flags;
    policy->priority                = selected->priority;
    policy->fallback_policy_id      = selected->fallback_policy_id;
    policy->payload                 = selected->payload;
    policy->can_fallback_to_builtin = fallback != nullptr
                                      && (selected->flags
                                          & N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL)
                                             != 0;

    if (selected->kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1) {
        _n00b_obj_bundle_declarative_policy_fields(selected, policy);
    }

    return n00b_result_ok(n00b_obj_bundle_extract_policy_t *, policy);
}

static bool
_n00b_obj_bundle_policy_applies_to_execution(
    n00b_obj_bundle_policy_t *policy)
{
    return policy != nullptr
           && (policy->scope & N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION) != 0;
}

static n00b_obj_bundle_policy_t *
_n00b_obj_bundle_execution_policy_fallback(
    n00b_obj_bundle_t        *bundle,
    n00b_obj_bundle_policy_t *policy)
{
    if (policy == nullptr
        || policy->fallback_policy_id == N00B_OBJ_BUNDLE_POLICY_ID_NONE
        || (policy->flags & N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED) == 0) {
        return nullptr;
    }

    n00b_obj_bundle_policy_t *fallback =
        _n00b_obj_bundle_find_policy_by_id(bundle, policy->fallback_policy_id);

    if (fallback == nullptr
        || fallback->kind != N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
        || !_n00b_obj_bundle_policy_scope_is_valid(fallback->scope)
        || !_n00b_obj_bundle_policy_flags_are_valid(fallback->flags)
        || !_n00b_obj_bundle_policy_payload_is_supported(fallback)
        || fallback->priority >= policy->priority
        || (fallback->scope & N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION) == 0) {
        return nullptr;
    }

    return fallback;
}

static n00b_result_t(n00b_obj_bundle_exec_policy_t *)
_n00b_obj_bundle_select_execution_policy(n00b_obj_bundle_t *bundle,
                                         n00b_allocator_t  *allocator)
{
    n00b_obj_bundle_policy_t *selected = nullptr;
    size_t                    n        = n00b_list_len(bundle->policies);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_policy_t *policy = n00b_list_get(bundle->policies, i);

        if (policy == nullptr
            || !_n00b_obj_bundle_policy_scope_is_valid(policy->scope)
            || !_n00b_obj_bundle_policy_flags_are_valid(policy->flags)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_exec_policy_t *,
                _n00b_obj_bundle_error_with_policy(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid execution policy record",
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_KIND_NONE
                        : policy->kind,
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_SCOPE_NONE
                        : policy->scope,
                    policy == nullptr
                        ? N00B_OBJ_BUNDLE_POLICY_ID_NONE
                        : policy->policy_id,
                    allocator));
        }

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_policy_t *other = n00b_list_get(bundle->policies,
                                                            j);

            if (other != nullptr && policy->policy_id == other->policy_id) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID,
                        r"object bundle: duplicate execution policy ID",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }
        }

        if (!_n00b_obj_bundle_policy_applies_to_execution(policy)) {
            if (_n00b_obj_bundle_policy_kind_is_known(policy->kind)
                && !_n00b_obj_bundle_policy_payload_is_valid(
                    policy->kind,
                    policy->payload,
                    policy->fallback_policy_id)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid non-execution policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            continue;
        }

        n00b_obj_bundle_policy_t *fallback =
            _n00b_obj_bundle_execution_policy_fallback(bundle, policy);

        if (!_n00b_obj_bundle_execution_policy_kind_is_supported(
                policy->kind)) {
            if (_n00b_obj_bundle_policy_kind_is_known(policy->kind)
                && !_n00b_obj_bundle_policy_payload_is_valid(
                    policy->kind,
                    policy->payload,
                    policy->fallback_policy_id)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid execution policy payload",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if ((policy->flags & N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL) == 0
                || fallback == nullptr) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                        r"object bundle: unsupported execution policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (_n00b_obj_bundle_policy_is_better_candidate(policy,
                                                            selected)) {
                selected = policy;
            }

            continue;
        }

        if (!_n00b_obj_bundle_execution_policy_payload_is_supported(policy)) {
            if (policy->kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid embedded execution policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (fallback == nullptr) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_policy_t *,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                        r"object bundle: invalid declarative execution policy",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        allocator));
            }

            if (_n00b_obj_bundle_policy_is_better_candidate(policy,
                                                            selected)) {
                selected = policy;
            }

            continue;
        }

        if (policy->fallback_policy_id != N00B_OBJ_BUNDLE_POLICY_ID_NONE
            && fallback == nullptr) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_exec_policy_t *,
                _n00b_obj_bundle_error_with_policy(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid execution policy fallback",
                    policy->kind,
                    policy->scope,
                    policy->fallback_policy_id,
                    allocator));
        }

        if (_n00b_obj_bundle_policy_is_better_candidate(policy, selected)) {
            selected = policy;
        }
    }

    n00b_obj_bundle_exec_policy_t *policy =
        n00b_alloc_with_opts(n00b_obj_bundle_exec_policy_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    policy->scope                   = N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION;
    policy->fallback_used           = false;
    policy->can_fallback_to_builtin = false;
    policy->policy_id               = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->flags                   = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    policy->priority                = 0;
    policy->fallback_policy_id      = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
    policy->payload                 = nullptr;
    policy->execution_flags         = N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT;

    if (selected == nullptr) {
        policy->kind = N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT;
        return n00b_result_ok(n00b_obj_bundle_exec_policy_t *, policy);
    }

    n00b_obj_bundle_policy_t *fallback =
        _n00b_obj_bundle_execution_policy_fallback(bundle, selected);

    if (!_n00b_obj_bundle_execution_policy_payload_is_supported(selected)
        && fallback != nullptr) {
        _n00b_obj_bundle_exec_policy_set_builtin_fallback(policy);
        return n00b_result_ok(n00b_obj_bundle_exec_policy_t *, policy);
    }

    policy->kind                    = selected->kind;
    policy->policy_id               = selected->policy_id;
    policy->flags                   = selected->flags;
    policy->priority                = selected->priority;
    policy->fallback_policy_id      = selected->fallback_policy_id;
    policy->payload                 = selected->payload;
    policy->can_fallback_to_builtin = fallback != nullptr
                                      && (selected->flags
                                          & N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL)
                                             != 0;

    if (selected->kind == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1) {
        const uint8_t *data = (const uint8_t *)selected->payload->data;

        policy->execution_flags =
            _n00b_obj_bundle_le64_at(
                data,
                N00B_OBJ_BUNDLE_DECL_POLICY_EXEC_FLAGS_OFF);
    }

    return n00b_result_ok(n00b_obj_bundle_exec_policy_t *, policy);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_exec_policy_denied(
    n00b_obj_bundle_exec_policy_t *policy,
    n00b_string_t                 *message,
    n00b_string_t                 *logical_path,
    n00b_obj_bundle_artifact_t    *artifact,
    uint64_t                       detail,
    n00b_allocator_t              *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_policy(
            N00B_OBJ_BUNDLE_ERR_POLICY_DENIED,
            message,
            policy == nullptr ? N00B_OBJ_BUNDLE_POLICY_KIND_NONE
                              : policy->kind,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
            detail,
            allocator);

    if (logical_path != nullptr) {
        error->logical_path     = logical_path;
        error->has_logical_path = true;
    }

    if (artifact != nullptr) {
        if (!error->has_logical_path) {
            error->logical_path     = artifact->logical_path;
            error->has_logical_path = artifact->logical_path != nullptr;
        }

        error->artifact_id     = artifact->id;
        error->has_artifact_id = true;
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_exec_attach_selected_error(
    n00b_obj_bundle_error_t       *error,
    n00b_obj_bundle_artifact_t    *artifact)
{
    error = _n00b_obj_bundle_error_mark_execution(error);

    if (error != nullptr && artifact != nullptr) {
        if (!error->has_logical_path) {
            error->logical_path     = artifact->logical_path;
            error->has_logical_path = artifact->logical_path != nullptr;
        }

        if (!error->has_artifact_id) {
            error->artifact_id     = artifact->id;
            error->has_artifact_id = true;
        }
    }

    return error;
}

static uint64_t
_n00b_obj_bundle_extract_artifact_kind_bit(
    n00b_obj_bundle_artifact_kind_t kind)
{
    return 1ull << kind;
}

static bool
_n00b_obj_bundle_extract_artifact_kind_is_supported(
    n00b_obj_bundle_artifact_kind_t kind)
{
    return kind == N00B_OBJ_BUNDLE_ARTIFACT_FILE
           || kind == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE
           || kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY;
}

static bool
_n00b_obj_bundle_logical_path_has_parent_dir(n00b_string_t *path)
{
    return path != nullptr
           && path->data != nullptr
           && path->u8_bytes != 0
           && memchr(path->data, '/', path->u8_bytes) != nullptr;
}

static bool
_n00b_obj_bundle_logical_path_has_prefix_component(n00b_string_t *prefix,
                                                   n00b_string_t *path)
{
    if (prefix == nullptr
        || path == nullptr
        || prefix->data == nullptr
        || path->data == nullptr
        || prefix->u8_bytes >= path->u8_bytes) {
        return false;
    }

    if (memcmp(prefix->data, path->data, prefix->u8_bytes) != 0) {
        return false;
    }

    return ((const uint8_t *)path->data)[prefix->u8_bytes] == '/';
}

static bool
_n00b_obj_bundle_extract_path_is_safe(
    n00b_string_t                    *path,
    n00b_obj_bundle_extract_policy_t *policy,
    n00b_obj_bundle_extract_result_t *facts)
{
    if (path == nullptr
        || path->data == nullptr
        || path->u8_bytes == 0
        || !_n00b_obj_bundle_string_len_is_supported(path)) {
        return false;
    }

    if ((policy->path_flags & N00B_OBJ_BUNDLE_DECL_PATH_VALID_UTF8) != 0
        && !n00b_unicode_str_validate(path)) {
        return false;
    }

    const uint8_t *data = (const uint8_t *)path->data;
    size_t         len  = path->u8_bytes;
    bool no_absolute =
        (policy->path_flags & N00B_OBJ_BUNDLE_DECL_PATH_RELATIVE) != 0
        || (policy->path_flags
            & N00B_OBJ_BUNDLE_DECL_PATH_NO_ABSOLUTE_PATHS) != 0
        || !facts->allow_absolute_paths;
    bool no_empty =
        (policy->path_flags
         & N00B_OBJ_BUNDLE_DECL_PATH_NO_EMPTY_COMPONENTS) != 0;
    bool no_parent =
        (policy->path_flags
         & N00B_OBJ_BUNDLE_DECL_PATH_NO_PARENT_REFERENCES) != 0
        || !facts->allow_parent_refs;

    if (data[0] == '/' && no_absolute) {
        return false;
    }

    size_t component_start = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i != len && data[i] != '/') {
            continue;
        }

        size_t component_len = i - component_start;

        if (component_len == 0 && no_empty) {
            return false;
        }

        if (component_len == 1 && data[component_start] == '.') {
            return false;
        }

        if (component_len == 2
            && data[component_start] == '.'
            && data[component_start + 1] == '.'
            && no_parent) {
            return false;
        }

        component_start = i + 1;
    }

    return true;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_extract_planner_error(
    n00b_obj_bundle_error_code_t       code,
    n00b_string_t                     *message,
    n00b_obj_bundle_artifact_t        *artifact,
    n00b_string_t                     *destination_root,
    n00b_obj_bundle_extract_result_t  *facts,
    uint64_t                           detail,
    bool                               has_detail,
    n00b_allocator_t                  *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_extract_result(code,
                                                   message,
                                                   destination_root,
                                                   facts,
                                                   allocator);

    if (artifact != nullptr) {
        error->logical_path     = artifact->logical_path;
        error->has_logical_path = artifact->logical_path != nullptr;
        error->artifact_id      = artifact->id;
        error->has_artifact_id  = true;
    }

    if (has_detail && detail <= (uint64_t)INT64_MAX) {
        error->detail     = (int64_t)detail;
        error->has_detail = true;
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_extract_attach_artifact_error(
    n00b_obj_bundle_error_t          *error,
    n00b_obj_bundle_artifact_t       *artifact,
    n00b_string_t                    *destination_root,
    n00b_obj_bundle_extract_result_t *facts)
{
    error = _n00b_obj_bundle_error_attach_extract_result(error,
                                                         destination_root,
                                                         facts);

    if (error != nullptr && artifact != nullptr) {
        if (!error->has_logical_path) {
            error->logical_path     = artifact->logical_path;
            error->has_logical_path = artifact->logical_path != nullptr;
        }

        if (!error->has_artifact_id) {
            error->artifact_id     = artifact->id;
            error->has_artifact_id = true;
        }
    }

    return error;
}

static bool
_n00b_obj_bundle_embedded_failure_can_fallback(
    n00b_obj_bundle_extract_policy_t *policy,
    n00b_obj_bundle_error_t          *error)
{
    return policy != nullptr
           && policy->kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B
           && policy->can_fallback_to_builtin
           && error != nullptr
           && error->code == N00B_OBJ_BUNDLE_ERR_BUILD;
}

static bool
_n00b_obj_bundle_exec_embedded_failure_can_fallback(
    n00b_obj_bundle_exec_policy_t *policy,
    n00b_obj_bundle_error_t       *error)
{
    return policy != nullptr
           && policy->kind == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B
           && policy->can_fallback_to_builtin
           && error != nullptr
           && error->code == N00B_OBJ_BUNDLE_ERR_BUILD;
}

static n00b_result_t(bool)
_n00b_obj_bundle_exec_evaluate_embedded_policy(
    n00b_obj_bundle_exec_policy_t             *policy,
    n00b_obj_bundle_artifact_t                *artifact,
    n00b_obj_bundle_exec_selection_source_t    selection_source,
    bool                                       inherit_env,
    bool                                       strict_selector,
    n00b_obj_bundle_exec_mode_t                requested_mode,
    n00b_obj_bundle_policy_mode_t              policy_mode,
    n00b_allocator_t                          *allocator)
{
    if (policy->kind != N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B) {
        return n00b_result_ok(bool, true);
    }

    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_execution(
            artifact->logical_path,
            artifact->kind,
            .selection_source = selection_source,
            .inherit_env = inherit_env,
            .strict_selector = strict_selector,
            .requested_mode = requested_mode,
            .policy_mode = policy_mode,
            .allocator = allocator);

    auto source = _n00b_obj_bundle_embedded_policy_source(
        policy->payload,
        policy->fallback_policy_id,
        policy->scope,
        context,
        allocator);

    if (n00b_result_is_err(source)) {
        n00b_obj_bundle_error_t *error =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        source);
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_exec_attach_selected_error(error, artifact));
    }

    n00b_string_t *source_text = n00b_result_get(source);

    if (!_n00b_obj_bundle_embedded_policy_source_has_expression_start(
            source_text)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_embedded_policy_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                n00b_eval_err_str(N00B_EVAL_ERR_PARSE),
                policy->scope,
                context,
                (int64_t)N00B_EVAL_ERR_PARSE,
                true,
                allocator);

        if (_n00b_obj_bundle_exec_embedded_failure_can_fallback(policy,
                                                                error)) {
            _n00b_obj_bundle_exec_policy_set_builtin_fallback(policy);
            return n00b_result_ok(bool, true);
        }

        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_exec_attach_selected_error(error, artifact));
    }

    auto session_result =
        n00b_obj_bundle_policy_eval_session_new(policy->scope,
                                                .allocator = allocator);

    if (n00b_result_is_err(session_result)) {
        n00b_obj_bundle_error_t *error =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        session_result);

        if (_n00b_obj_bundle_exec_embedded_failure_can_fallback(policy,
                                                                error)) {
            _n00b_obj_bundle_exec_policy_set_builtin_fallback(policy);
            return n00b_result_ok(bool, true);
        }

        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_exec_attach_selected_error(error, artifact));
    }

    n00b_eval_session_t *session = n00b_result_get(session_result);
    auto eval_result =
        n00b_obj_bundle_policy_evaluate_embedded(session,
                                                 policy->payload,
                                                 policy->fallback_policy_id,
                                                 policy->scope,
                                                 context,
                                                 .allocator = allocator);
    n00b_eval_session_free(session);

    if (n00b_result_is_ok(eval_result)) {
        return n00b_result_ok(bool, true);
    }

    n00b_obj_bundle_error_t *error =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                    eval_result);

    if (_n00b_obj_bundle_exec_embedded_failure_can_fallback(policy, error)) {
        _n00b_obj_bundle_exec_policy_set_builtin_fallback(policy);
        return n00b_result_ok(bool, true);
    }

    return OBJ_BUNDLE_ERR_PAYLOAD(
        bool,
        _n00b_obj_bundle_exec_attach_selected_error(error, artifact));
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_evaluate_embedded_policy(
    n00b_obj_bundle_extract_policy_t   *policy,
    n00b_obj_bundle_artifact_t         *artifact,
    n00b_string_t                      *destination_root,
    n00b_obj_bundle_extract_result_t   *facts,
    n00b_eval_session_t               **session,
    n00b_allocator_t                   *allocator)
{
    if (policy->kind != N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B) {
        return n00b_result_ok(bool, true);
    }

    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_extraction(
            artifact->logical_path,
            artifact->kind,
            .overwrite = facts->overwrite,
            .create_dirs = facts->create_dirs,
            .policy_mode = facts->policy_mode,
            .allocator = allocator);

    if (*session == nullptr) {
        auto source = _n00b_obj_bundle_embedded_policy_source(
            policy->payload,
            policy->fallback_policy_id,
            policy->scope,
            context,
            allocator);

        if (n00b_result_is_err(source)) {
            n00b_obj_bundle_error_t *error =
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            source);
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_attach_artifact_error(
                    error,
                    artifact,
                    destination_root,
                    facts));
        }

        n00b_string_t *source_text = n00b_result_get(source);

        if (!_n00b_obj_bundle_embedded_policy_source_has_expression_start(
                source_text)) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_embedded_policy_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    n00b_eval_err_str(N00B_EVAL_ERR_PARSE),
                    policy->scope,
                    context,
                    (int64_t)N00B_EVAL_ERR_PARSE,
                    true,
                    allocator);

            if (_n00b_obj_bundle_embedded_failure_can_fallback(policy,
                                                               error)) {
                _n00b_obj_bundle_extract_policy_set_builtin_fallback(policy);
                _n00b_obj_bundle_extract_result_set_policy(facts, policy);
                return n00b_result_ok(bool, true);
            }

            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_attach_artifact_error(
                    error,
                    artifact,
                    destination_root,
                    facts));
        }

        auto session_result =
            n00b_obj_bundle_policy_eval_session_new(policy->scope,
                                                    .allocator = allocator);

        if (n00b_result_is_err(session_result)) {
            n00b_obj_bundle_error_t *error =
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            session_result);

            if (_n00b_obj_bundle_embedded_failure_can_fallback(policy,
                                                               error)) {
                _n00b_obj_bundle_extract_policy_set_builtin_fallback(policy);
                _n00b_obj_bundle_extract_result_set_policy(facts, policy);
                return n00b_result_ok(bool, true);
            }

            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_attach_artifact_error(
                    error,
                    artifact,
                    destination_root,
                    facts));
        }

        *session = n00b_result_get(session_result);
    }

    auto eval_result =
        n00b_obj_bundle_policy_evaluate_embedded(*session,
                                                 policy->payload,
                                                 policy->fallback_policy_id,
                                                 policy->scope,
                                                 context,
                                                 .allocator = allocator);

    if (n00b_result_is_ok(eval_result)) {
        return n00b_result_ok(bool, true);
    }

    n00b_obj_bundle_error_t *error =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, eval_result);

    if (_n00b_obj_bundle_embedded_failure_can_fallback(policy, error)) {
        _n00b_obj_bundle_extract_policy_set_builtin_fallback(policy);
        _n00b_obj_bundle_extract_result_set_policy(facts, policy);
        return n00b_result_ok(bool, true);
    }

    return OBJ_BUNDLE_ERR_PAYLOAD(
        bool,
        _n00b_obj_bundle_extract_attach_artifact_error(error,
                                                       artifact,
                                                       destination_root,
                                                       facts));
}

static n00b_string_t *
_n00b_obj_bundle_resolve_path_copy(n00b_string_t    *path,
                                   n00b_allocator_t *allocator)
{
    return n00b_resolve_path_alloc(path, .allocator = allocator);
}

static n00b_string_t *
_n00b_obj_bundle_path_join_child(n00b_string_t    *dir,
                                 n00b_string_t    *child,
                                 n00b_allocator_t *allocator)
{
    if (child == nullptr || child->data == nullptr) {
        return _n00b_obj_bundle_copy_string(dir, allocator);
    }

    if (child->u8_bytes != 0 && child->data[0] == '/') {
        return _n00b_obj_bundle_copy_string(child, allocator);
    }

    if (dir == nullptr || dir->data == nullptr || dir->u8_bytes == 0) {
        dir = n00b_string_from_raw("/", 1, .allocator = allocator);
    }

    if (dir->data[dir->u8_bytes - 1] == '/') {
        return n00b_unicode_str_cat(dir, child, .allocator = allocator);
    }

    n00b_string_t *with_slash = n00b_unicode_str_cat(
        dir,
        n00b_string_from_raw("/", 1, .allocator = allocator),
        .allocator = allocator);
    return n00b_unicode_str_cat(with_slash, child, .allocator = allocator);
}

static n00b_obj_bundle_extract_plan_t *
_n00b_obj_bundle_extract_plan_new(n00b_string_t    *destination_root,
                                  n00b_allocator_t *allocator)
{
    n00b_obj_bundle_extract_plan_t *plan =
        n00b_alloc_with_opts(n00b_obj_bundle_extract_plan_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    plan->destination_root =
        _n00b_obj_bundle_resolve_path_copy(destination_root, allocator);
    plan->entries =
        n00b_list_new(n00b_obj_bundle_extract_plan_entry_t *,
                      .allocator = allocator);

    return plan;
}

static n00b_string_t *
_n00b_obj_bundle_extract_relative_path(n00b_string_t    *logical_path,
                                       n00b_allocator_t *allocator)
{
    size_t start = 0;

    while (start < logical_path->u8_bytes
           && ((const uint8_t *)logical_path->data)[start] == '/') {
        start++;
    }

    if (start == 0) {
        return logical_path;
    }

    if (start == logical_path->u8_bytes) {
        return n00b_string_empty(.allocator = allocator);
    }

    return n00b_string_from_raw(logical_path->data + start,
                                (int64_t)(logical_path->u8_bytes - start),
                                .allocator = allocator);
}

static bool
_n00b_obj_bundle_extract_path_is_under_root(n00b_string_t *root,
                                            n00b_string_t *path)
{
    if (root == nullptr
        || path == nullptr
        || root->data == nullptr
        || path->data == nullptr
        || root->u8_bytes == 0
        || path->u8_bytes == 0) {
        return false;
    }

    size_t root_len = root->u8_bytes;

    while (root_len > 1
           && ((const uint8_t *)root->data)[root_len - 1] == '/') {
        root_len--;
    }

    if (root_len == 1 && ((const uint8_t *)root->data)[0] == '/') {
        return path->data[0] == '/';
    }

    if (path->u8_bytes == root_len
        && memcmp(path->data, root->data, root_len) == 0) {
        return true;
    }

    return path->u8_bytes > root_len
           && memcmp(path->data, root->data, root_len) == 0
           && ((const uint8_t *)path->data)[root_len] == '/';
}

static n00b_string_t *
_n00b_obj_bundle_extract_parent_path(n00b_string_t    *destination_path,
                                     n00b_allocator_t *allocator)
{
    if (destination_path == nullptr
        || destination_path->data == nullptr
        || destination_path->u8_bytes == 0) {
        return nullptr;
    }

    size_t end = destination_path->u8_bytes;

    while (end > 1 && destination_path->data[end - 1] == '/') {
        end--;
    }

    size_t last_slash = SIZE_MAX;

    for (size_t i = 0; i < end; i++) {
        if (destination_path->data[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash == SIZE_MAX) {
        return nullptr;
    }

    if (last_slash == 0) {
        return n00b_string_from_raw("/", 1, .allocator = allocator);
    }

    return n00b_string_from_raw(destination_path->data,
                                (int64_t)last_slash,
                                .allocator = allocator);
}

static n00b_result_t(n00b_obj_bundle_extract_plan_entry_t *)
_n00b_obj_bundle_extract_plan_entry_new(
    n00b_obj_bundle_artifact_t       *artifact,
    n00b_obj_bundle_extract_plan_t   *plan,
    n00b_string_t                    *destination_root,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    n00b_string_t *relative =
        _n00b_obj_bundle_extract_relative_path(artifact->logical_path,
                                               allocator);

    if (relative == nullptr || relative->u8_bytes == 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_plan_entry_t *,
            _n00b_obj_bundle_extract_planner_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                r"object bundle: unsafe extraction logical path",
                artifact,
                destination_root,
                facts,
                0,
                false,
                allocator));
    }

    n00b_string_t *joined =
        _n00b_obj_bundle_path_join_child(plan->destination_root,
                                         relative,
                                         allocator);
    n00b_string_t *destination_path =
        _n00b_obj_bundle_resolve_path_copy(joined, allocator);

    if (!_n00b_obj_bundle_extract_path_is_under_root(
            plan->destination_root,
            destination_path)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_extract_planner_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                r"object bundle: mapped extraction destination escapes root",
                artifact,
                destination_path,
                facts,
                0,
                false,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_plan_entry_t *,
            error);
    }

    n00b_obj_bundle_extract_plan_entry_t *entry =
        n00b_alloc_with_opts(n00b_obj_bundle_extract_plan_entry_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    entry->artifact         = artifact;
    entry->destination_path = destination_path;
    entry->parent_path      =
        _n00b_obj_bundle_extract_parent_path(destination_path, allocator);

    return n00b_result_ok(n00b_obj_bundle_extract_plan_entry_t *, entry);
}

static n00b_result_t(n00b_obj_bundle_extract_plan_t *)
_n00b_obj_bundle_extract_plan_remap_root(
    n00b_obj_bundle_extract_plan_t   *source_plan,
    n00b_string_t                    *destination_root,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    n00b_obj_bundle_extract_plan_t *plan =
        _n00b_obj_bundle_extract_plan_new(destination_root, allocator);

    if (plan->destination_root == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_plan_t *,
            _n00b_obj_bundle_extract_planner_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid extraction staging root",
                nullptr,
                destination_root,
                facts,
                EINVAL,
                true,
                allocator));
    }

    for (size_t i = 0; i < n00b_list_len(source_plan->entries); i++) {
        n00b_obj_bundle_extract_plan_entry_t *source_entry =
            n00b_list_get(source_plan->entries, i);
        auto entry_r =
            _n00b_obj_bundle_extract_plan_entry_new(source_entry->artifact,
                                                    plan,
                                                    destination_root,
                                                    facts,
                                                    allocator);

        if (n00b_result_is_err(entry_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            entry_r));
        }

        n00b_list_push(plan->entries, n00b_result_get(entry_r));
    }

    return n00b_result_ok(n00b_obj_bundle_extract_plan_t *, plan);
}

static bool
_n00b_obj_bundle_plan_entries_collide(
    n00b_obj_bundle_extract_plan_entry_t *left,
    n00b_obj_bundle_extract_plan_entry_t *right,
    n00b_obj_bundle_extract_plan_entry_t **colliding_parent)
{
    if (_n00b_obj_bundle_string_bytes_eq(left->destination_path,
                                         right->destination_path)) {
        *colliding_parent = left;
        return true;
    }

    if (_n00b_obj_bundle_logical_path_has_prefix_component(
            left->destination_path,
            right->destination_path)
        && left->artifact->kind != N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
        *colliding_parent = left;
        return true;
    }

    if (_n00b_obj_bundle_logical_path_has_prefix_component(
            right->destination_path,
            left->destination_path)
        && right->artifact->kind != N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
        *colliding_parent = right;
        return true;
    }

    return false;
}

static n00b_result_t(n00b_obj_bundle_extract_plan_t *)
_n00b_obj_bundle_plan_extraction(n00b_obj_bundle_t                  *bundle,
                                 n00b_string_t                      *destination_root,
                                 n00b_obj_bundle_extract_policy_t   *policy,
                                 n00b_obj_bundle_extract_result_t   *facts,
                                 n00b_eval_session_t               **policy_session,
                                 n00b_allocator_t                   *allocator)
{
    size_t   n     = n00b_list_len(bundle->artifacts);
    uint64_t files = 0;
    uint64_t dirs  = 0;
    n00b_obj_bundle_extract_plan_t *plan =
        _n00b_obj_bundle_extract_plan_new(destination_root, allocator);

    if (plan->destination_root == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_plan_t *,
            _n00b_obj_bundle_extract_planner_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid extraction destination root",
                nullptr,
                destination_root,
                facts,
                EINVAL,
                true,
                allocator));
    }

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_artifact_t *artifact =
            n00b_list_get(bundle->artifacts, i);

        if (artifact == nullptr) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid extraction artifact",
                    nullptr,
                    destination_root,
                    facts,
                    0,
                    false,
                    allocator));
        }

        if (artifact->flags != 0) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                    r"object bundle: unsupported extraction artifact flags",
                    artifact,
                    destination_root,
                    facts,
                    artifact->flags,
                    true,
                    allocator));
        }

        if (!_n00b_obj_bundle_extract_path_is_safe(artifact->logical_path,
                                                   policy,
                                                   facts)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH,
                    r"object bundle: unsafe extraction logical path",
                    artifact,
                    destination_root,
                    facts,
                    0,
                    false,
                    allocator));
        }

        if ((policy->artifact_kind_mask
             & _n00b_obj_bundle_extract_artifact_kind_bit(artifact->kind))
            == 0) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                    r"object bundle: extraction artifact denied by policy",
                    artifact,
                    destination_root,
                    facts,
                    artifact->kind,
                    true,
                    allocator));
        }

        if (!_n00b_obj_bundle_extract_artifact_kind_is_supported(
                artifact->kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                    r"object bundle: unsupported extraction artifact kind",
                    artifact,
                    destination_root,
                    facts,
                    artifact->kind,
                    true,
                    allocator));
        }

        if (!facts->create_dirs
            && (artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY
                || _n00b_obj_bundle_logical_path_has_parent_dir(
                    artifact->logical_path))) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                _n00b_obj_bundle_extract_planner_error(
                    N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                    r"object bundle: extraction requires directory creation",
                    artifact,
                    destination_root,
                    facts,
                    artifact->kind,
                    true,
                    allocator));
        }

        auto policy_eval =
            _n00b_obj_bundle_extract_evaluate_embedded_policy(
                policy,
                artifact,
                destination_root,
                facts,
                policy_session,
                allocator);

        if (n00b_result_is_err(policy_eval)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            policy_eval));
        }

        if (artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
            dirs++;
        }
        else {
            files++;
        }

        auto entry_r =
            _n00b_obj_bundle_extract_plan_entry_new(artifact,
                                                    plan,
                                                    destination_root,
                                                    facts,
                                                    allocator);

        if (n00b_result_is_err(entry_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_plan_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            entry_r));
        }

        n00b_list_push(plan->entries, n00b_result_get(entry_r));
    }

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_extract_plan_entry_t *left =
            n00b_list_get(plan->entries, i);

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_extract_plan_entry_t *right =
                n00b_list_get(plan->entries, j);

            if (_n00b_obj_bundle_logical_path_has_prefix_component(
                    left->artifact->logical_path,
                    right->artifact->logical_path)
                && left->artifact->kind
                       != N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_plan_t *,
                    _n00b_obj_bundle_extract_planner_error(
                        N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                        r"object bundle: extraction path collision",
                        left->artifact,
                        destination_root,
                        facts,
                        right->artifact->id,
                        true,
                        allocator));
            }

            if (_n00b_obj_bundle_logical_path_has_prefix_component(
                    right->artifact->logical_path,
                    left->artifact->logical_path)
                && right->artifact->kind
                       != N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_plan_t *,
                    _n00b_obj_bundle_extract_planner_error(
                        N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                        r"object bundle: extraction path collision",
                        right->artifact,
                        destination_root,
                        facts,
                        left->artifact->id,
                        true,
                        allocator));
            }

            n00b_obj_bundle_extract_plan_entry_t *colliding_parent = nullptr;
            if (_n00b_obj_bundle_plan_entries_collide(left,
                                                      right,
                                                      &colliding_parent)) {
                n00b_obj_bundle_extract_plan_entry_t *other =
                    colliding_parent == left ? right : left;
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_plan_t *,
                    _n00b_obj_bundle_extract_planner_error(
                        N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                        r"object bundle: extraction destination collision",
                        colliding_parent->artifact,
                        destination_root,
                        facts,
                        other->artifact->id,
                        true,
                        allocator));
            }
        }
    }

    facts->files_planned       = files;
    facts->directories_planned = dirs;

    return n00b_result_ok(n00b_obj_bundle_extract_plan_t *, plan);
}

static bool
_n00b_obj_bundle_extract_mode_is_valid(uint32_t mode)
{
    return (mode & ~07777u) == 0;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_extract_filesystem_error(
    n00b_obj_bundle_error_code_t              code,
    n00b_string_t                            *message,
    n00b_obj_bundle_extract_plan_entry_t     *entry,
    n00b_string_t                            *destination_path,
    n00b_obj_bundle_extract_result_t         *facts,
    int64_t                                   detail,
    bool                                      has_detail,
    n00b_allocator_t                         *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_with_extract_result(code,
                                                   message,
                                                   destination_path,
                                                   facts,
                                                   allocator);

    if (entry != nullptr && entry->artifact != nullptr) {
        error->logical_path     = entry->artifact->logical_path;
        error->has_logical_path = entry->artifact->logical_path != nullptr;
        error->artifact_id      = entry->artifact->id;
        error->has_artifact_id  = true;
    }

    if (has_detail) {
        error->detail     = detail;
        error->has_detail = true;
    }

    return error;
}

static bool
_n00b_obj_bundle_file_kind_is_directory(n00b_file_kind kind)
{
    return kind == N00B_FK_IS_DIR;
}

static bool
_n00b_obj_bundle_file_kind_is_file(n00b_file_kind kind)
{
    return kind == N00B_FK_IS_REG_FILE;
}

static n00b_file_kind
_n00b_obj_bundle_file_kind_no_follow(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0) {
        return N00B_FK_NOT_FOUND;
    }

    struct stat info;

    if (lstat(path->data, &info) != 0) {
        return N00B_FK_NOT_FOUND;
    }

    switch (info.st_mode & S_IFMT) {
    case S_IFREG:
        return N00B_FK_IS_REG_FILE;
    case S_IFDIR:
        return N00B_FK_IS_DIR;
    case S_IFLNK:
        return N00B_FK_IS_FLINK;
    case S_IFSOCK:
        return N00B_FK_IS_SOCK;
    case S_IFCHR:
        return N00B_FK_IS_CHR_DEVICE;
    case S_IFBLK:
        return N00B_FK_IS_BLOCK_DEVICE;
    case S_IFIFO:
        return N00B_FK_IS_FIFO;
    default:
        return N00B_FK_OTHER;
    }
}

static n00b_string_t *
_n00b_obj_bundle_extract_relative_component_path(
    n00b_string_t    *root,
    n00b_string_t    *path,
    n00b_allocator_t *allocator)
{
    if (!_n00b_obj_bundle_extract_path_is_under_root(root, path)) {
        return nullptr;
    }

    size_t root_len = root->u8_bytes;

    while (root_len > 1 && root->data[root_len - 1] == '/') {
        root_len--;
    }

    if (path->u8_bytes == root_len
        && memcmp(path->data, root->data, root_len) == 0) {
        return n00b_string_empty(.allocator = allocator);
    }

    size_t start = root_len == 1 && root->data[0] == '/'
                       ? 1
                       : root_len + 1;
    if (start > path->u8_bytes) {
        return nullptr;
    }

    return n00b_string_from_raw(path->data + start,
                                (int64_t)(path->u8_bytes - start),
                                .allocator = allocator);
}

static n00b_list_t(n00b_string_t *) *
_n00b_obj_bundle_path_components(n00b_string_t    *path,
                                 n00b_allocator_t *allocator)
{
    n00b_list_t(n00b_string_t *) parts =
        n00b_list_new(n00b_string_t *, .allocator = allocator);
    n00b_list_t(n00b_string_t *) *result =
        n00b_alloc(n00b_list_t(n00b_string_t *), .allocator = allocator);
    *result = parts;

    if (path == nullptr || path->data == nullptr || path->u8_bytes == 0) {
        return result;
    }

    size_t start = 0;

    for (size_t i = 0; i <= path->u8_bytes; i++) {
        if (i != path->u8_bytes && path->data[i] != '/') {
            continue;
        }

        if (i > start) {
            n00b_list_push(
                *result,
                n00b_string_from_raw(path->data + start,
                                     (int64_t)(i - start),
                                     .allocator = allocator));
        }

        start = i + 1;
    }

    return result;
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_preflight_parent_components(
    n00b_obj_bundle_extract_plan_t       *plan,
    n00b_obj_bundle_extract_plan_entry_t *entry,
    n00b_obj_bundle_extract_result_t     *facts,
    n00b_allocator_t                     *allocator)
{
    n00b_string_t *relative =
        _n00b_obj_bundle_extract_relative_component_path(
            plan->destination_root,
            entry->parent_path,
            allocator);

    if (relative == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: extraction destination parent escapes root",
                entry,
                entry->parent_path,
                facts,
                EINVAL,
                true,
                allocator));
    }

    n00b_list_t(n00b_string_t *) *parts =
        _n00b_obj_bundle_path_components(relative, allocator);
    n00b_string_t *current = plan->destination_root;

    for (size_t i = 0; i < n00b_list_len(*parts); i++) {
        current = _n00b_obj_bundle_path_join_child(
            current,
            n00b_list_get(*parts, i),
            allocator);

        n00b_file_kind kind =
            _n00b_obj_bundle_file_kind_no_follow(current);
        if (kind == N00B_FK_NOT_FOUND) {
            return n00b_result_ok(bool, true);
        }
        if (!_n00b_obj_bundle_file_kind_is_directory(kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction destination parent is not a directory",
                    entry,
                    current,
                    facts,
                    EEXIST,
                    true,
                    allocator));
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_preflight_destination(
    n00b_obj_bundle_extract_plan_t   *plan,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    n00b_file_kind root_kind =
        _n00b_obj_bundle_file_kind_no_follow(plan->destination_root);

    if (root_kind != N00B_FK_NOT_FOUND
        && !_n00b_obj_bundle_file_kind_is_directory(root_kind)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: extraction root is not a directory",
                nullptr,
                plan->destination_root,
                facts,
                EEXIST,
                true,
                allocator));
    }

    if (!facts->create_dirs
        && !_n00b_obj_bundle_file_kind_is_directory(root_kind)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: extraction root directory is missing",
                nullptr,
                plan->destination_root,
                facts,
                ENOENT,
                true,
                allocator));
    }

    for (size_t i = 0; i < n00b_list_len(plan->entries); i++) {
        n00b_obj_bundle_extract_plan_entry_t *entry =
            n00b_list_get(plan->entries, i);
        n00b_obj_bundle_artifact_t *artifact = entry->artifact;

        if (entry->parent_path == nullptr) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction destination parent is invalid",
                    entry,
                    entry->destination_path,
                    facts,
                    EINVAL,
                    true,
                allocator));
        }

        auto components_r =
            _n00b_obj_bundle_extract_preflight_parent_components(plan,
                                                                 entry,
                                                                 facts,
                                                                 allocator);
        if (n00b_result_is_err(components_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            components_r));
        }

        n00b_file_kind parent_kind =
            _n00b_obj_bundle_file_kind_no_follow(entry->parent_path);
        if (parent_kind != N00B_FK_NOT_FOUND
            && !_n00b_obj_bundle_file_kind_is_directory(parent_kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction destination parent is not a directory",
                    entry,
                    entry->parent_path,
                    facts,
                    EEXIST,
                    true,
                    allocator));
        }
        if (!facts->create_dirs
            && !_n00b_obj_bundle_file_kind_is_directory(parent_kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction destination parent is missing",
                    entry,
                    entry->parent_path,
                    facts,
                    ENOENT,
                    true,
                    allocator));
        }

        n00b_file_kind destination_kind =
            _n00b_obj_bundle_file_kind_no_follow(entry->destination_path);

        if (artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
            if (destination_kind != N00B_FK_NOT_FOUND
                && !_n00b_obj_bundle_file_kind_is_directory(
                    destination_kind)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    bool,
                    _n00b_obj_bundle_extract_filesystem_error(
                        N00B_OBJ_BUNDLE_ERR_BUILD,
                        r"object bundle: extraction directory destination already exists",
                        entry,
                        entry->destination_path,
                        facts,
                        EEXIST,
                        true,
                        allocator));
            }

            continue;
        }

        if (_n00b_obj_bundle_file_kind_is_directory(destination_kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction file destination is a directory",
                    entry,
                    entry->destination_path,
                    facts,
                    EISDIR,
                    true,
                    allocator));
        }

        if (destination_kind != N00B_FK_NOT_FOUND
            && !_n00b_obj_bundle_file_kind_is_file(destination_kind)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction file destination already exists",
                    entry,
                    entry->destination_path,
                    facts,
                    EEXIST,
                    true,
                    allocator));
        }

        if (!facts->overwrite && destination_kind != N00B_FK_NOT_FOUND) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction destination already exists",
                    entry,
                    entry->destination_path,
                    facts,
                    EEXIST,
                    true,
                    allocator));
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_ensure_directory(
    n00b_obj_bundle_extract_plan_entry_t *entry,
    n00b_string_t                        *path,
    n00b_obj_bundle_extract_result_t     *facts,
    uint32_t                              mode,
    n00b_allocator_t                     *allocator)
{
    n00b_list_t(n00b_string_t *) *parts =
        _n00b_obj_bundle_path_components(path, allocator);
    n00b_string_t *current =
        n00b_string_from_raw("/", 1, .allocator = allocator);
    bool created = false;

    for (size_t i = 0; i < n00b_list_len(*parts); i++) {
        n00b_string_t *part = n00b_list_get(*parts, i);

        current = _n00b_obj_bundle_path_join_child(current,
                                                   part,
                                                   allocator);

        uint32_t component_mode =
            i + 1 == n00b_list_len(*parts) ? mode : 0775u;
        auto mkdir_r = n00b_path_mkdir_p(current,
                                         .mode = component_mode,
                                         .allocator = allocator);

        if (n00b_result_is_err(mkdir_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: extraction directory could not be created",
                    entry,
                    current,
                    facts,
                    n00b_result_get_err(mkdir_r),
                    true,
                    allocator));
        }

        if (n00b_result_get(mkdir_r)) {
            facts->directories_written++;
            created = true;
        }
    }

    return n00b_result_ok(bool, created);
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_apply_directory_mode(
    n00b_obj_bundle_extract_plan_entry_t *entry,
    n00b_obj_bundle_extract_result_t     *facts,
    n00b_allocator_t                     *allocator)
{
    uint32_t mode = entry->artifact->mode;

    if (!facts->preserve_modes || mode == 0) {
        return n00b_result_ok(bool, true);
    }

    if (!_n00b_obj_bundle_extract_mode_is_valid(mode)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid extraction directory mode",
                entry,
                entry->destination_path,
                facts,
                mode,
                true,
                allocator));
    }

    auto mode_r = n00b_path_set_mode(entry->destination_path, mode);
    if (n00b_result_is_ok(mode_r)) {
        return n00b_result_ok(bool, true);
    }

    int err = n00b_result_get_err(mode_r);
    return OBJ_BUNDLE_ERR_PAYLOAD(
        bool,
        _n00b_obj_bundle_extract_filesystem_error(
            err == ENOSYS ? N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE
                          : N00B_OBJ_BUNDLE_ERR_BUILD,
            err == ENOSYS
                ? r"object bundle: extraction directory mode is unsupported"
                : r"object bundle: extraction directory mode could not be applied",
            entry,
            entry->destination_path,
            facts,
            err,
            true,
            allocator));
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_extract_error_from_sink(
    n00b_objfile_sink_error_t             *sink_error,
    n00b_obj_bundle_extract_plan_entry_t  *entry,
    n00b_obj_bundle_extract_result_t      *facts,
    n00b_allocator_t                      *allocator)
{
    n00b_obj_bundle_error_code_t code = N00B_OBJ_BUNDLE_ERR_BUILD;

    if (sink_error != nullptr) {
        switch (n00b_objfile_sink_error_code(sink_error)) {
        case N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT:
            code = N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT;
            break;
        case N00B_OBJFILE_SINK_ERR_UNSUPPORTED:
            code = N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE;
            break;
        default:
            code = N00B_OBJ_BUNDLE_ERR_BUILD;
            break;
        }
    }

    n00b_string_t *message =
        r"object bundle: extraction file write failed";
    int64_t detail = 0;
    bool    has_detail = false;

    if (sink_error != nullptr) {
        auto sink_message = n00b_objfile_sink_error_message(sink_error);
        if (n00b_option_is_set(sink_message)) {
            message = n00b_option_get(sink_message);
        }

        auto sink_detail = n00b_objfile_sink_error_detail(sink_error);
        if (n00b_option_is_set(sink_detail)) {
            detail     = n00b_option_get(sink_detail);
            has_detail = true;
        }
    }

    return _n00b_obj_bundle_extract_filesystem_error(
        code,
        message,
        entry,
        entry->destination_path,
        facts,
        detail,
        has_detail,
        allocator);
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_write_file(
    n00b_obj_bundle_extract_plan_entry_t *entry,
    n00b_obj_bundle_extract_result_t     *facts,
    n00b_allocator_t                     *allocator)
{
    n00b_option_t(uint32_t) file_mode = n00b_option_none(uint32_t);

    if (facts->preserve_modes && entry->artifact->mode != 0) {
        if (!_n00b_obj_bundle_extract_mode_is_valid(entry->artifact->mode)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid extraction file mode",
                    entry,
                    entry->destination_path,
                    facts,
                    entry->artifact->mode,
                    true,
                    allocator));
        }

        file_mode = n00b_option_set(uint32_t, entry->artifact->mode);
    }

    auto sink_r = n00b_objfile_sink_write(
        (n00b_buffer_t *)entry->artifact->payload,
        entry->destination_path,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT,
        .overwrite = facts->overwrite
                         ? N00B_OBJFILE_SINK_REPLACE_EXISTING
                         : N00B_OBJFILE_SINK_REJECT_EXISTING,
        .file_mode = file_mode,
        .preserve_existing_mode = false,
        .allocator = allocator);

    if (n00b_result_is_err(sink_r)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_error_from_sink(
                n00b_result_get_err_payload(n00b_objfile_sink_error_t *,
                                            sink_r),
                entry,
                facts,
                allocator));
    }

    n00b_objfile_sink_result_t *sink_facts = n00b_result_get(sink_r);

    facts->files_written++;

    if (n00b_option_is_set(file_mode)
        && !n00b_objfile_sink_result_file_mode_supported(sink_facts)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                r"object bundle: extraction file mode is unsupported",
                entry,
                entry->destination_path,
                facts,
                ENOSYS,
                true,
                allocator));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_obj_bundle_extract_result_t *)
_n00b_obj_bundle_materialize_direct(
    n00b_obj_bundle_extract_plan_t   *plan,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    auto preflight =
        _n00b_obj_bundle_extract_preflight_destination(plan,
                                                       facts,
                                                       allocator);
    if (n00b_result_is_err(preflight)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        preflight));
    }

    if (n00b_list_len(plan->entries) == 0) {
        return n00b_result_ok(n00b_obj_bundle_extract_result_t *, facts);
    }

    if (facts->create_dirs) {
        auto root_r = _n00b_obj_bundle_extract_ensure_directory(
            nullptr,
            plan->destination_root,
            facts,
            0775u,
            allocator);
        if (n00b_result_is_err(root_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            root_r));
        }
    }

    for (size_t i = 0; i < n00b_list_len(plan->entries); i++) {
        n00b_obj_bundle_extract_plan_entry_t *entry =
            n00b_list_get(plan->entries, i);

        if (entry->artifact->kind != N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
            continue;
        }

        uint32_t create_mode =
            facts->preserve_modes && entry->artifact->mode != 0
                ? entry->artifact->mode
                : 0775u;
        if (!_n00b_obj_bundle_extract_mode_is_valid(create_mode)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_result_t *,
                _n00b_obj_bundle_extract_filesystem_error(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid extraction directory mode",
                    entry,
                    entry->destination_path,
                    facts,
                    create_mode,
                    true,
                    allocator));
        }

        auto mkdir_r =
            _n00b_obj_bundle_extract_ensure_directory(entry,
                                                       entry->destination_path,
                                                       facts,
                                                       create_mode,
                                                       allocator);
        if (n00b_result_is_err(mkdir_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            mkdir_r));
        }

        auto mode_r =
            _n00b_obj_bundle_extract_apply_directory_mode(entry,
                                                          facts,
                                                          allocator);
        if (n00b_result_is_err(mode_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            mode_r));
        }
    }

    for (size_t i = 0; i < n00b_list_len(plan->entries); i++) {
        n00b_obj_bundle_extract_plan_entry_t *entry =
            n00b_list_get(plan->entries, i);

        if (entry->artifact->kind == N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY) {
            continue;
        }

        if (facts->create_dirs) {
            auto parent_r = _n00b_obj_bundle_extract_ensure_directory(
                entry,
                entry->parent_path,
                facts,
                0775u,
                allocator);
            if (n00b_result_is_err(parent_r)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_extract_result_t *,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                parent_r));
            }
        }

        auto write_r =
            _n00b_obj_bundle_extract_write_file(entry, facts, allocator);
        if (n00b_result_is_err(write_r)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_extract_result_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            write_r));
        }
    }

    return n00b_result_ok(n00b_obj_bundle_extract_result_t *, facts);
}

static n00b_result_t(bool)
_n00b_obj_bundle_extract_preflight_atomic_destination(
    n00b_obj_bundle_extract_plan_t   *plan,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    n00b_file_kind root_kind =
        _n00b_obj_bundle_file_kind_no_follow(plan->destination_root);

    if (root_kind != N00B_FK_NOT_FOUND) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: atomic extraction destination root already exists",
                nullptr,
                plan->destination_root,
                facts,
                EEXIST,
                true,
                allocator));
    }

    n00b_string_t *parent =
        _n00b_obj_bundle_extract_parent_path(plan->destination_root,
                                             allocator);
    if (parent == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: atomic extraction destination parent is invalid",
                nullptr,
                plan->destination_root,
                facts,
                EINVAL,
                true,
                allocator));
    }

    n00b_file_kind parent_kind =
        _n00b_obj_bundle_file_kind_no_follow(parent);
    if (!_n00b_obj_bundle_file_kind_is_directory(parent_kind)) {
        int64_t detail = parent_kind == N00B_FK_NOT_FOUND ? ENOENT : EEXIST;
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                parent_kind == N00B_FK_NOT_FOUND
                    ? r"object bundle: atomic extraction destination parent is missing"
                    : r"object bundle: atomic extraction destination parent is not a directory",
                nullptr,
                parent,
                facts,
                detail,
                true,
                allocator));
    }

    return n00b_result_ok(bool, true);
}

static void
_n00b_obj_bundle_extract_cleanup_temp(
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    if (facts->has_temp_root == false || facts->temp_root == nullptr) {
        return;
    }

    facts->cleanup_attempted = true;

    auto cleanup_r = n00b_path_remove_tree(facts->temp_root,
                                           .ignore_missing = true,
                                           .allocator = allocator);
    facts->cleanup_succeeded = n00b_result_is_ok(cleanup_r);
}

static n00b_result_t(n00b_obj_bundle_extract_result_t *)
_n00b_obj_bundle_materialize_atomic(
    n00b_obj_bundle_extract_plan_t   *plan,
    n00b_obj_bundle_extract_result_t *facts,
    n00b_allocator_t                 *allocator)
{
    auto preflight =
        _n00b_obj_bundle_extract_preflight_atomic_destination(plan,
                                                              facts,
                                                              allocator);
    if (n00b_result_is_err(preflight)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        preflight));
    }

    if (n00b_list_len(plan->entries) == 0) {
        return n00b_result_ok(n00b_obj_bundle_extract_result_t *, facts);
    }

    auto temp_r = n00b_new_sibling_temp_dir(plan->destination_root,
                                            .allocator = allocator);
    if (n00b_result_is_err(temp_r)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            _n00b_obj_bundle_extract_filesystem_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: atomic extraction temp root could not be created",
                nullptr,
                plan->destination_root,
                facts,
                n00b_result_get_err(temp_r),
                true,
                allocator));
    }

    n00b_string_t *temp_root = n00b_result_get(temp_r);
    facts->temp_root         = temp_root;
    facts->has_temp_root     = true;
    facts->atomic_used       = true;
    facts->directories_written++;

    auto staged_plan_r =
        _n00b_obj_bundle_extract_plan_remap_root(plan,
                                                 temp_root,
                                                 facts,
                                                 allocator);
    if (n00b_result_is_err(staged_plan_r)) {
        _n00b_obj_bundle_extract_cleanup_temp(facts, allocator);
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        staged_plan_r));
    }

    n00b_obj_bundle_extract_plan_t *staged_plan =
        n00b_result_get(staged_plan_r);
    auto stage_r =
        _n00b_obj_bundle_materialize_direct(staged_plan, facts, allocator);
    if (n00b_result_is_err(stage_r)) {
        _n00b_obj_bundle_extract_cleanup_temp(facts, allocator);
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        stage_r));
    }

    facts->commit_attempted = true;
    auto commit_r = n00b_path_commit_exact(
        temp_root,
        plan->destination_root,
        .policy = N00B_PATH_COMMIT_REJECT_EXISTING);

    if (n00b_result_is_ok(commit_r)) {
        facts->commit_completed = true;
        return n00b_result_ok(n00b_obj_bundle_extract_result_t *, facts);
    }

    int err = n00b_result_get_err(commit_r);
    _n00b_obj_bundle_extract_cleanup_temp(facts, allocator);

    return OBJ_BUNDLE_ERR_PAYLOAD(
        n00b_obj_bundle_extract_result_t *,
        _n00b_obj_bundle_extract_filesystem_error(
            err == ENOSYS ? N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE
                          : N00B_OBJ_BUNDLE_ERR_BUILD,
            err == ENOSYS
                ? r"object bundle: atomic extraction exact commit is unsupported"
                : r"object bundle: atomic extraction exact commit failed",
            nullptr,
            plan->destination_root,
            facts,
            err,
            true,
            allocator));
}

static bool
_n00b_obj_bundle_policy_fallback_is_valid(n00b_obj_bundle_t        *bundle,
                                          n00b_obj_bundle_policy_t *policy)
{
    if (policy->fallback_policy_id == N00B_OBJ_BUNDLE_POLICY_ID_NONE) {
        return true;
    }

    if ((policy->flags & N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED) == 0) {
        return false;
    }

    n00b_obj_bundle_policy_t *fallback =
        _n00b_obj_bundle_find_policy_by_id(bundle, policy->fallback_policy_id);

    if (fallback == nullptr
        || fallback->kind != N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT
        || fallback->priority >= policy->priority) {
        return false;
    }

    return (fallback->scope & policy->scope) == policy->scope;
}

static int
_n00b_obj_bundle_encode_artifact_cmp(const void *a, const void *b)
{
    const n00b_obj_bundle_encode_artifact_t *left  = a;
    const n00b_obj_bundle_encode_artifact_t *right = b;

    return _n00b_obj_bundle_string_bytes_cmp(left->artifact->logical_path,
                                             right->artifact->logical_path);
}

static int
_n00b_obj_bundle_encode_mapping_cmp(const void *a, const void *b)
{
    const n00b_obj_bundle_encode_exec_mapping_t *left  = a;
    const n00b_obj_bundle_encode_exec_mapping_t *right = b;

    return _n00b_obj_bundle_string_bytes_cmp(left->mapping->selector,
                                             right->mapping->selector);
}

static int
_n00b_obj_bundle_encode_policy_cmp(const void *a, const void *b)
{
    const n00b_obj_bundle_encode_policy_t *left  = a;
    const n00b_obj_bundle_encode_policy_t *right = b;
    n00b_obj_bundle_policy_t              *lp    = left->policy;
    n00b_obj_bundle_policy_t              *rp    = right->policy;

    if (lp->priority != rp->priority) {
        return (lp->priority > rp->priority) - (lp->priority < rp->priority);
    }

    if (lp->policy_id != rp->policy_id) {
        return (lp->policy_id > rp->policy_id)
               - (lp->policy_id < rp->policy_id);
    }

    if (lp->kind != rp->kind) {
        return (lp->kind > rp->kind) - (lp->kind < rp->kind);
    }

    if (lp->scope != rp->scope) {
        return (lp->scope > rp->scope) - (lp->scope < rp->scope);
    }

    if (lp->flags != rp->flags) {
        return (lp->flags > rp->flags) - (lp->flags < rp->flags);
    }

    int cmp = _n00b_obj_bundle_buffer_bytes_cmp(lp->payload, rp->payload);

    if (cmp != 0) {
        return cmp;
    }

    return (lp->fallback_policy_id > rp->fallback_policy_id)
           - (lp->fallback_policy_id < rp->fallback_policy_id);
}

static int
_n00b_obj_bundle_decode_policy_cmp(
    const n00b_obj_bundle_decode_policy_t *left,
    const n00b_obj_bundle_decode_policy_t *right)
{
    if (left->priority != right->priority) {
        return (left->priority > right->priority)
               - (left->priority < right->priority);
    }

    if (left->policy_id != right->policy_id) {
        return (left->policy_id > right->policy_id)
               - (left->policy_id < right->policy_id);
    }

    if (left->kind != right->kind) {
        return (left->kind > right->kind) - (left->kind < right->kind);
    }

    if (left->scope != right->scope) {
        return (left->scope > right->scope) - (left->scope < right->scope);
    }

    if (left->flags != right->flags) {
        return (left->flags > right->flags)
               - (left->flags < right->flags);
    }

    int cmp = _n00b_obj_bundle_buffer_bytes_cmp(left->payload,
                                                right->payload);

    if (cmp != 0) {
        return cmp;
    }

    return (left->fallback_policy_id > right->fallback_policy_id)
           - (left->fallback_policy_id < right->fallback_policy_id);
}

static bool
_n00b_obj_bundle_encoded_artifact_id(
    n00b_obj_bundle_encode_artifact_t *artifacts,
    size_t                             artifact_count,
    uint64_t                           internal_id,
    uint64_t                          *encoded_id)
{
    for (size_t i = 0; i < artifact_count; i++) {
        if (artifacts[i].artifact->id == internal_id) {
            *encoded_id = artifacts[i].encoded_id;
            return true;
        }
    }

    return false;
}

// _n00b_obj_bundle_u64_add / _range_end / _range_within / _ranges_overlap are
// shared with the Mach-O carrier backend (obj_bundle_macho.c) via
// internal/compiler/objfile/obj_bundle_arith.h (included above).

static bool
_n00b_obj_bundle_u64_mul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return false;
    }

    *out = a * b;
    return true;
}

static bool
_n00b_obj_bundle_is_aligned(uint64_t value, uint64_t alignment)
{
    return alignment != 0 && (value % alignment) == 0;
}

static bool
_n00b_obj_bundle_read_u16(n00b_bstream_t *stream, uint16_t *out)
{
    auto result = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(result)) {
        return false;
    }

    *out = n00b_result_get(result);
    return true;
}

static bool
_n00b_obj_bundle_read_u32(n00b_bstream_t *stream, uint32_t *out)
{
    auto result = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(result)) {
        return false;
    }

    *out = n00b_result_get(result);
    return true;
}

static bool
_n00b_obj_bundle_read_u64(n00b_bstream_t *stream, uint64_t *out)
{
    auto result = n00b_bstream_read_u64(stream);

    if (n00b_result_is_err(result)) {
        return false;
    }

    *out = n00b_result_get(result);
    return true;
}

static bool
_n00b_obj_bundle_read_digest(
    n00b_bstream_t *stream,
    uint8_t         out[N00B_OBJ_BUNDLE_DIGEST_LEN])
{
    if (!n00b_bstream_can_read(stream, N00B_OBJ_BUNDLE_DIGEST_LEN)) {
        return false;
    }

    memcpy(out, n00b_bstream_raw(stream), N00B_OBJ_BUNDLE_DIGEST_LEN);

    auto advance = n00b_bstream_advance(stream, N00B_OBJ_BUNDLE_DIGEST_LEN);

    return n00b_result_is_ok(advance);
}

static bool
_n00b_obj_bundle_setpos(n00b_bstream_t *stream, uint64_t off)
{
    if (off > SIZE_MAX) {
        return false;
    }

    auto result = n00b_bstream_setpos(stream, (size_t)off);

    return n00b_result_is_ok(result);
}

static bool
_n00b_obj_bundle_digest_is_zero(
    const uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN])
{
    for (size_t i = 0; i < N00B_OBJ_BUNDLE_DIGEST_LEN; i++) {
        if (digest[i] != 0) {
            return false;
        }
    }

    return true;
}

static bool
_n00b_obj_bundle_decode_string(const uint8_t      *table,
                               uint64_t            table_len,
                               uint32_t            off,
                               bool                allow_empty,
                               n00b_allocator_t   *allocator,
                               n00b_string_t     **out)
{
    *out = nullptr;

    if (off == 0) {
        return allow_empty;
    }

    if (off >= table_len) {
        return false;
    }

    uint64_t len = 0;

    while ((uint64_t)off + len < table_len
           && table[(uint64_t)off + len] != 0) {
        len++;
    }

    if ((uint64_t)off + len >= table_len) {
        return false;
    }

    if (len == 0 || len > UINT32_MAX || len > INT64_MAX) {
        return false;
    }

    const void *raw = table + off;

    if (!n00b_unicode_utf8_validate(raw, (uint32_t)len)) {
        return false;
    }

    *out = n00b_string_from_raw(raw, (int64_t)len, .allocator = allocator);
    return true;
}

static n00b_buffer_t *
_n00b_obj_bundle_decode_payload_slice(const uint8_t    *payload_area,
                                      uint64_t          off,
                                      uint64_t          len,
                                      n00b_allocator_t *allocator)
{
    if (len > INT64_MAX) {
        return nullptr;
    }

    n00b_buffer_t *buffer = n00b_buffer_new((int64_t)len,
                                            .allocator = allocator);

    if (len != 0) {
        memcpy(buffer->data, payload_area + off, (size_t)len);
    }

    return buffer;
}

static void
_n00b_obj_bundle_write_digest(n00b_writer_t *writer,
                              const uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN])
{
    n00b_writer_write_bytes(writer, digest, N00B_OBJ_BUNDLE_DIGEST_LEN);
}

static void
_n00b_obj_bundle_write_zero_digest(n00b_writer_t *writer)
{
    n00b_writer_write_zeros(writer, N00B_OBJ_BUNDLE_DIGEST_LEN);
}

static void
_n00b_obj_bundle_write_artifact_record(
    n00b_writer_t                       *writer,
    n00b_obj_bundle_encode_artifact_t   *artifact)
{
    n00b_writer_write_u64(writer, artifact->encoded_id);
    n00b_writer_write_u32(writer, artifact->artifact->kind);
    n00b_writer_write_u32(writer, 0);
    n00b_writer_write_u64(writer, artifact->artifact->flags);
    n00b_writer_write_u32(writer, artifact->path_off);
    n00b_writer_write_u32(writer, artifact->role_off);
    n00b_writer_write_u32(writer, artifact->artifact->mode);
    n00b_writer_write_u32(writer, artifact->payload_index);

    if (artifact->artifact->payload == nullptr) {
        _n00b_obj_bundle_write_zero_digest(writer);
    }
    else {
        _n00b_obj_bundle_write_digest(writer, artifact->digest);
    }
}

static void
_n00b_obj_bundle_write_payload_record(
    n00b_writer_t                       *writer,
    n00b_obj_bundle_encode_artifact_t   *artifact)
{
    n00b_writer_write_u64(writer, artifact->encoded_id);
    n00b_writer_write_u64(writer, 0);
    n00b_writer_write_u64(writer, artifact->payload_off);
    n00b_writer_write_u64(writer, artifact->payload_len);
    _n00b_obj_bundle_write_digest(writer, artifact->digest);
}

static void
_n00b_obj_bundle_write_policy_record(n00b_writer_t                    *writer,
                                     n00b_obj_bundle_encode_policy_t  *policy)
{
    n00b_obj_bundle_policy_t *p = policy->policy;

    n00b_writer_write_u64(writer, p->policy_id);
    n00b_writer_write_u32(writer, p->kind);
    n00b_writer_write_u32(writer, p->scope);
    n00b_writer_write_u64(writer, p->flags);
    n00b_writer_write_u64(writer, p->priority);
    n00b_writer_write_u64(writer, policy->payload_off);
    n00b_writer_write_u64(writer, policy->payload_len);
    n00b_writer_write_u64(writer, p->fallback_policy_id);

    if (p->payload == nullptr) {
        _n00b_obj_bundle_write_zero_digest(writer);
    }
    else {
        _n00b_obj_bundle_write_digest(writer, policy->digest);
    }
}

n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_obj_bundle_t *bundle =
        n00b_alloc_with_opts(n00b_obj_bundle_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    bundle->allocator        = allocator;
    bundle->is_mutable       = true;
    bundle->next_artifact_id = 0;
    bundle->artifacts =
        n00b_list_new_private(n00b_obj_bundle_artifact_t *,
                              .allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);
    bundle->has_default_exec = false;
    bundle->default_exec_id  = N00B_OBJ_BUNDLE_ARTIFACT_ID_NONE;
    bundle->exec_mappings =
        n00b_list_new_private(n00b_obj_bundle_exec_mapping_t *,
                              .allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);
    bundle->policies =
        n00b_list_new_private(n00b_obj_bundle_policy_t *,
                              .allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_ALL);

    return n00b_result_ok(n00b_obj_bundle_t *, bundle);
}

n00b_result_t(bool)
n00b_obj_bundle_add_artifact(n00b_obj_bundle_t *bundle,
                             n00b_string_t     *logical_path,
                             const n00b_buffer_t *bytes) _kargs
{
    n00b_obj_bundle_artifact_kind_t kind  = N00B_OBJ_BUNDLE_ARTIFACT_FILE;
    n00b_string_t                  *role  = nullptr;
    uint32_t                        mode  = 0;
    uint64_t                        flags = 0;
}
{
    if (bundle == nullptr || logical_path == nullptr) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null artifact argument",
                              _n00b_obj_bundle_allocator(bundle));
    }

    n00b_allocator_t *allocator = bundle->allocator;

    if (!bundle->is_mutable
        || !_n00b_obj_bundle_artifact_kind_is_valid(kind)
        || !_n00b_obj_bundle_artifact_has_valid_payload(kind, bytes)) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid artifact argument",
                              allocator);
    }

    if (role != nullptr
        && (!_n00b_obj_bundle_string_len_is_supported(role)
            || !n00b_unicode_str_validate(role))) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid artifact role",
                              allocator);
    }

    auto normalized =
        _n00b_obj_bundle_normalize_logical_path(logical_path, allocator);

    if (n00b_result_is_err(normalized)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        normalized));
    }

    n00b_string_t *path = n00b_result_get(normalized);

    if (_n00b_obj_bundle_find_artifact_by_path(bundle, path) != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH,
                r"object bundle: duplicate logical path",
                path,
                allocator));
    }

    n00b_obj_bundle_artifact_t *artifact =
        n00b_alloc_with_opts(n00b_obj_bundle_artifact_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    artifact->id           = bundle->next_artifact_id++;
    artifact->kind         = kind;
    artifact->logical_path = path;
    artifact->payload      = _n00b_obj_bundle_copy_buffer(bytes, allocator);
    artifact->role         = _n00b_obj_bundle_copy_string(role, allocator);
    artifact->mode         = mode;
    artifact->flags        = flags;

    n00b_list_push(bundle->artifacts, artifact);

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_obj_bundle_set_default_exec(n00b_obj_bundle_t *bundle,
                                 n00b_string_t     *logical_path)
{
    if (bundle == nullptr || logical_path == nullptr) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null default executable argument",
                              _n00b_obj_bundle_allocator(bundle));
    }

    n00b_allocator_t *allocator = bundle->allocator;

    if (!bundle->is_mutable) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: immutable bundle",
                              allocator);
    }

    auto normalized =
        _n00b_obj_bundle_normalize_logical_path(logical_path, allocator);

    if (n00b_result_is_err(normalized)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        normalized));
    }

    n00b_string_t *path = n00b_result_get(normalized);

    if (bundle->has_default_exec) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC,
                r"object bundle: default executable already exists",
                path,
                allocator));
    }

    n00b_obj_bundle_artifact_t *artifact =
        _n00b_obj_bundle_find_artifact_by_path(bundle, path);

    if (!_n00b_obj_bundle_artifact_is_executable(artifact)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                r"object bundle: default executable target is missing",
                path,
                allocator));
    }

    bundle->has_default_exec = true;
    bundle->default_exec_id  = artifact->id;

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_obj_bundle_add_exec_mapping(n00b_obj_bundle_t *bundle,
                                 n00b_string_t     *selector,
                                 n00b_string_t     *target_path)
{
    if (bundle == nullptr || selector == nullptr || target_path == nullptr) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null execution mapping argument",
                              _n00b_obj_bundle_allocator(bundle));
    }

    n00b_allocator_t *allocator = bundle->allocator;

    if (!bundle->is_mutable || !_n00b_obj_bundle_selector_is_valid(selector)) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid execution selector",
                              allocator);
    }

    if (_n00b_obj_bundle_find_mapping_by_selector(bundle, selector) != nullptr) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR,
                              r"object bundle: duplicate execution selector",
                              allocator);
    }

    auto normalized =
        _n00b_obj_bundle_normalize_logical_path(target_path, allocator);

    if (n00b_result_is_err(normalized)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        normalized));
    }

    n00b_string_t *path = n00b_result_get(normalized);

    n00b_obj_bundle_artifact_t *artifact =
        _n00b_obj_bundle_find_artifact_by_path(bundle, path);

    if (!_n00b_obj_bundle_artifact_is_executable(artifact)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                r"object bundle: execution mapping target is missing",
                path,
                allocator));
    }

    n00b_obj_bundle_exec_mapping_t *mapping =
        n00b_alloc_with_opts(n00b_obj_bundle_exec_mapping_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    mapping->selector =
        _n00b_obj_bundle_copy_string(selector, allocator);
    mapping->target_artifact_id = artifact->id;

    n00b_list_push(bundle->exec_mappings, mapping);

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_obj_bundle_add_policy(n00b_obj_bundle_t             *bundle,
                           uint64_t                      policy_id,
                           n00b_obj_bundle_policy_kind_t  kind,
                           n00b_obj_bundle_policy_scope_t scope) _kargs
{
    uint64_t       flags              = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;
    uint64_t       priority           = 0;
    const n00b_buffer_t *payload      = nullptr;
    uint64_t       fallback_policy_id = N00B_OBJ_BUNDLE_POLICY_ID_NONE;
}
{
    if (bundle == nullptr
        || policy_id == N00B_OBJ_BUNDLE_POLICY_ID_NONE
        || !_n00b_obj_bundle_policy_kind_is_known(kind)
        || !_n00b_obj_bundle_policy_scope_is_valid(scope)) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid policy argument",
                              _n00b_obj_bundle_allocator(bundle));
    }

    n00b_allocator_t *allocator = bundle->allocator;

    if (!bundle->is_mutable
        || !_n00b_obj_bundle_policy_flags_are_valid(flags)
        || !_n00b_obj_bundle_policy_payload_is_valid(kind,
                                                     payload,
                                                     fallback_policy_id)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_policy(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid policy record",
                kind,
                scope,
                policy_id,
                allocator));
    }

    if (_n00b_obj_bundle_find_policy_by_id(bundle, policy_id) != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_policy(
                N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID,
                r"object bundle: duplicate policy ID",
                kind,
                scope,
                policy_id,
                allocator));
    }

    n00b_obj_bundle_policy_t candidate = {
        .policy_id          = policy_id,
        .kind               = kind,
        .scope              = scope,
        .flags              = flags,
        .priority           = priority,
        .payload            = payload,
        .fallback_policy_id = fallback_policy_id,
    };

    if (!_n00b_obj_bundle_policy_fallback_is_valid(bundle, &candidate)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_error_with_policy(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid policy fallback",
                kind,
                scope,
                fallback_policy_id,
                allocator));
    }

    n00b_obj_bundle_policy_t *policy =
        n00b_alloc_with_opts(n00b_obj_bundle_policy_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    policy->policy_id = policy_id;
    policy->kind      = kind;
    policy->scope     = scope;
    policy->flags     = flags;
    policy->priority  = priority;
    policy->payload   = _n00b_obj_bundle_copy_buffer(payload, allocator);
    policy->fallback_policy_id = fallback_policy_id;

    n00b_list_push(bundle->policies, policy);

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_n00b_obj_bundle_validate_artifacts(n00b_obj_bundle_t *bundle)
{
    size_t n = n00b_list_len(bundle->artifacts);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_artifact_t *artifact =
            n00b_list_get(bundle->artifacts, i);

        if (artifact == nullptr
            || !_n00b_obj_bundle_artifact_kind_is_valid(artifact->kind)
            || !_n00b_obj_bundle_artifact_has_valid_payload(artifact->kind,
                                                            artifact->payload)) {
            return OBJ_BUNDLE_ERR(bool,
                                  N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                                  r"object bundle: invalid artifact record",
                                  bundle->allocator);
        }

        auto path =
            _n00b_obj_bundle_normalize_logical_path(artifact->logical_path,
                                                   bundle->allocator);

        if (n00b_result_is_err(path)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *, path));
        }

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_artifact_t *other =
                n00b_list_get(bundle->artifacts, j);

            if (_n00b_obj_bundle_string_bytes_eq(artifact->logical_path,
                                                 other->logical_path)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    bool,
                    _n00b_obj_bundle_error_with_path(
                        N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH,
                        r"object bundle: duplicate logical path",
                        artifact->logical_path,
                        bundle->allocator));
            }
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_n00b_obj_bundle_validate_exec_map(n00b_obj_bundle_t *bundle)
{
    if (bundle->has_default_exec) {
        n00b_obj_bundle_artifact_t *artifact =
            _n00b_obj_bundle_find_artifact_by_id(bundle,
                                                bundle->default_exec_id);

        if (!_n00b_obj_bundle_artifact_is_executable(artifact)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_error_with_artifact(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: invalid default executable target",
                    bundle->default_exec_id,
                    bundle->allocator));
        }
    }

    size_t n = n00b_list_len(bundle->exec_mappings);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_exec_mapping_t *mapping =
            n00b_list_get(bundle->exec_mappings, i);

        if (mapping == nullptr
            || !_n00b_obj_bundle_selector_is_valid(mapping->selector)) {
            return OBJ_BUNDLE_ERR(bool,
                                  N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                                  r"object bundle: invalid execution selector",
                                  bundle->allocator);
        }

        n00b_obj_bundle_artifact_t *artifact =
            _n00b_obj_bundle_find_artifact_by_id(bundle,
                                                mapping->target_artifact_id);

        if (!_n00b_obj_bundle_artifact_is_executable(artifact)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_error_with_artifact(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: invalid execution mapping target",
                    mapping->target_artifact_id,
                    bundle->allocator));
        }

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_exec_mapping_t *other =
                n00b_list_get(bundle->exec_mappings, j);

            if (_n00b_obj_bundle_string_bytes_eq(mapping->selector,
                                                 other->selector)) {
                return OBJ_BUNDLE_ERR(bool,
                                      N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR,
                                      r"object bundle: duplicate selector",
                                      bundle->allocator);
            }
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
_n00b_obj_bundle_validate_policies(n00b_obj_bundle_t *bundle)
{
    size_t n = n00b_list_len(bundle->policies);

    for (size_t i = 0; i < n; i++) {
        n00b_obj_bundle_policy_t *policy = n00b_list_get(bundle->policies, i);

        if (policy == nullptr
            || !_n00b_obj_bundle_policy_kind_is_known(policy->kind)
            || !_n00b_obj_bundle_policy_scope_is_valid(policy->scope)
            || !_n00b_obj_bundle_policy_flags_are_valid(policy->flags)
            || !_n00b_obj_bundle_policy_payload_is_valid(policy->kind,
                                                         policy->payload,
                                                         policy->fallback_policy_id)) {
            return OBJ_BUNDLE_ERR(bool,
                                  N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                                  r"object bundle: invalid policy record",
                                  bundle->allocator);
        }

        if (!_n00b_obj_bundle_policy_fallback_is_valid(bundle, policy)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_error_with_policy(
                    N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                    r"object bundle: invalid policy fallback",
                    policy->kind,
                    policy->scope,
                    policy->fallback_policy_id,
                    bundle->allocator));
        }

        for (size_t j = i + 1; j < n; j++) {
            n00b_obj_bundle_policy_t *other = n00b_list_get(bundle->policies,
                                                            j);

            if (policy->policy_id == other->policy_id) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    bool,
                    _n00b_obj_bundle_error_with_policy(
                        N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID,
                        r"object bundle: duplicate policy ID",
                        policy->kind,
                        policy->scope,
                        policy->policy_id,
                        bundle->allocator));
            }
        }
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_obj_bundle_validate(n00b_obj_bundle_t *bundle) _kargs
{
    bool strict = true;
}
{
    (void)strict;

    if (bundle == nullptr) {
        return OBJ_BUNDLE_ERR(bool,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null bundle",
                              nullptr);
    }

    auto artifacts = _n00b_obj_bundle_validate_artifacts(bundle);

    if (n00b_result_is_err(artifacts)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        artifacts));
    }

    auto exec_map = _n00b_obj_bundle_validate_exec_map(bundle);

    if (n00b_result_is_err(exec_map)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        exec_map));
    }

    auto policies = _n00b_obj_bundle_validate_policies(bundle);

    if (n00b_result_is_err(policies)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        policies));
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_buffer_t *)
n00b_obj_bundle_encode(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bundle == nullptr) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null bundle",
                              allocator);
    }

    auto valid = n00b_obj_bundle_validate(bundle);

    if (n00b_result_is_err(valid)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, valid));
    }

    size_t artifact_count = n00b_list_len(bundle->artifacts);
    size_t mapping_count  = n00b_list_len(bundle->exec_mappings);
    size_t policy_count   = n00b_list_len(bundle->policies);
    size_t exec_count     = mapping_count + (bundle->has_default_exec ? 1 : 0);

    n00b_obj_bundle_encode_artifact_t *artifacts = nullptr;
    n00b_obj_bundle_encode_exec_mapping_t *mappings = nullptr;
    n00b_obj_bundle_encode_policy_t *policies = nullptr;

    if (artifact_count != 0) {
        artifacts = n00b_alloc_array(n00b_obj_bundle_encode_artifact_t,
                                     artifact_count);

        for (size_t i = 0; i < artifact_count; i++) {
            artifacts[i].artifact = n00b_list_get(bundle->artifacts, i);
        }

        qsort(artifacts,
              artifact_count,
              sizeof(artifacts[0]),
              _n00b_obj_bundle_encode_artifact_cmp);

        for (size_t i = 0; i < artifact_count; i++) {
            artifacts[i].encoded_id = i;
        }
    }

    if (mapping_count != 0) {
        mappings = n00b_alloc_array(n00b_obj_bundle_encode_exec_mapping_t,
                                    mapping_count);

        for (size_t i = 0; i < mapping_count; i++) {
            mappings[i].mapping = n00b_list_get(bundle->exec_mappings, i);
        }

        qsort(mappings,
              mapping_count,
              sizeof(mappings[0]),
              _n00b_obj_bundle_encode_mapping_cmp);
    }

    if (policy_count != 0) {
        policies = n00b_alloc_array(n00b_obj_bundle_encode_policy_t,
                                    policy_count);

        for (size_t i = 0; i < policy_count; i++) {
            policies[i].policy = n00b_list_get(bundle->policies, i);
        }

        qsort(policies,
              policy_count,
              sizeof(policies[0]),
              _n00b_obj_bundle_encode_policy_cmp);
    }

    n00b_obj_bundle_manifest_strtab_t *strings =
        _n00b_obj_bundle_manifest_strtab_new();
    uint32_t payload_index = 0;

    for (size_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_artifact_t *artifact = artifacts[i].artifact;

        artifacts[i].path_off =
            _n00b_obj_bundle_manifest_strtab_add(strings,
                                                 artifact->logical_path);
        artifacts[i].role_off =
            _n00b_obj_bundle_manifest_strtab_add(strings, artifact->role);

        if (artifact->payload == nullptr) {
            artifacts[i].payload_index = N00B_OBJ_BUNDLE_NO_PAYLOAD_INDEX;
            continue;
        }

        artifacts[i].payload_index = payload_index++;
        artifacts[i].payload_len   = artifact->payload->byte_len;
        _n00b_obj_bundle_sha256_bytes(artifact->payload->data,
                                      artifact->payload->byte_len,
                                      artifacts[i].digest);
    }

    size_t payload_count = payload_index;

    for (size_t i = 0; i < mapping_count; i++) {
        mappings[i].selector_off =
            _n00b_obj_bundle_manifest_strtab_add(strings,
                                                 mappings[i].mapping->selector);

        if (!_n00b_obj_bundle_encoded_artifact_id(
                artifacts,
                artifact_count,
                mappings[i].mapping->target_artifact_id,
                &mappings[i].target_encoded_id)) {
            return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                                  N00B_OBJ_BUNDLE_ERR_BUILD,
                                  r"object bundle: missing encoded target",
                                  allocator);
        }
    }

    uint64_t default_encoded_id = N00B_OBJ_BUNDLE_ARTIFACT_ID_NONE;

    if (bundle->has_default_exec
        && !_n00b_obj_bundle_encoded_artifact_id(artifacts,
                                                artifact_count,
                                                bundle->default_exec_id,
                                                &default_encoded_id)) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_BUILD,
                              r"object bundle: missing encoded default target",
                              allocator);
    }

    if (strings->error) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_BUILD,
                              r"object bundle: string table build failed",
                              allocator);
    }

    uint64_t payload_cursor = 0;

    for (size_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_artifact_t *artifact = artifacts[i].artifact;

        if (artifact->payload == nullptr) {
            continue;
        }

        artifacts[i].payload_off = payload_cursor;

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      artifact->payload->byte_len,
                                      &payload_cursor)) {
            return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                                  N00B_OBJ_BUNDLE_ERR_BUILD,
                                  r"object bundle: payload area too large",
                                  allocator);
        }
    }

    for (size_t i = 0; i < policy_count; i++) {
        n00b_obj_bundle_policy_t *policy = policies[i].policy;

        if (policy->payload == nullptr) {
            continue;
        }

        policies[i].payload_off = payload_cursor;
        policies[i].payload_len = policy->payload->byte_len;
        _n00b_obj_bundle_sha256_bytes(policy->payload->data,
                                      policy->payload->byte_len,
                                      policies[i].digest);

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      policy->payload->byte_len,
                                      &payload_cursor)) {
            return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                                  N00B_OBJ_BUNDLE_ERR_BUILD,
                                  r"object bundle: payload area too large",
                                  allocator);
        }
    }

    uint64_t artifact_table_len = 0;
    uint64_t payload_table_len  = 0;
    uint64_t exec_table_len     = 0;
    uint64_t policy_table_len   = 0;

    if (!_n00b_obj_bundle_u64_mul(artifact_count,
                                  N00B_OBJ_BUNDLE_ARTIFACT_REC_SIZE,
                                  &artifact_table_len)
        || !_n00b_obj_bundle_u64_mul(payload_count,
                                     N00B_OBJ_BUNDLE_PAYLOAD_REC_SIZE,
                                     &payload_table_len)
        || !_n00b_obj_bundle_u64_mul(exec_count,
                                     N00B_OBJ_BUNDLE_EXEC_REC_SIZE,
                                     &exec_table_len)
        || !_n00b_obj_bundle_u64_mul(policy_count,
                                     N00B_OBJ_BUNDLE_POLICY_REC_SIZE,
                                     &policy_table_len)) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_BUILD,
                              r"object bundle: table too large",
                              allocator);
    }

    uint64_t artifact_table_off = N00B_OBJ_BUNDLE_HEADER_SIZE;
    uint64_t payload_table_off =
        _n00b_obj_bundle_align_u64(artifact_table_off + artifact_table_len, 8);
    uint64_t exec_table_off =
        _n00b_obj_bundle_align_u64(payload_table_off + payload_table_len, 8);
    uint64_t policy_table_off =
        _n00b_obj_bundle_align_u64(exec_table_off + exec_table_len, 8);
    uint64_t string_table_off =
        _n00b_obj_bundle_align_u64(policy_table_off + policy_table_len, 8);
    uint64_t payload_area_off =
        _n00b_obj_bundle_align_u64(string_table_off + strings->len, 8);
    uint64_t extension_table_off = payload_area_off + payload_cursor;
    uint64_t total_len          = extension_table_off;

    if (total_len > INT64_MAX) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_BUILD,
                              r"object bundle: manifest too large",
                              allocator);
    }

    n00b_writer_t *writer = n00b_writer_new((size_t)total_len,
                                            .allocator = allocator);
    n00b_writer_set_endian(writer, N00B_ENDIAN_LITTLE);

    n00b_writer_write_bytes(writer,
                            N00B_OBJ_BUNDLE_MANIFEST_MAGIC,
                            N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN);
    n00b_writer_write_u16(writer, N00B_OBJ_BUNDLE_MANIFEST_MAJOR);
    n00b_writer_write_u16(writer, N00B_OBJ_BUNDLE_MANIFEST_MINOR);
    n00b_writer_write_u32(writer, N00B_OBJ_BUNDLE_HEADER_SIZE);
    n00b_writer_write_u64(writer, total_len);
    n00b_writer_write_u64(writer, 0);
    n00b_writer_write_zeros(writer, N00B_OBJ_BUNDLE_CONTENT_ID_LEN);
    n00b_writer_write_u64(writer, artifact_count);
    n00b_writer_write_u64(writer, payload_count);
    n00b_writer_write_u64(writer, exec_count);
    n00b_writer_write_u64(writer, policy_count);
    n00b_writer_write_u64(writer, artifact_table_off);
    n00b_writer_write_u64(writer, artifact_table_len);
    n00b_writer_write_u64(writer, payload_table_off);
    n00b_writer_write_u64(writer, payload_table_len);
    n00b_writer_write_u64(writer, exec_table_off);
    n00b_writer_write_u64(writer, exec_table_len);
    n00b_writer_write_u64(writer, policy_table_off);
    n00b_writer_write_u64(writer, policy_table_len);
    n00b_writer_write_u64(writer, string_table_off);
    n00b_writer_write_u64(writer, strings->len);
    n00b_writer_write_u64(writer, payload_area_off);
    n00b_writer_write_u64(writer, payload_cursor);
    n00b_writer_write_u64(writer, extension_table_off);
    n00b_writer_write_u64(writer, 0);

    n00b_writer_setpos(writer, artifact_table_off);

    for (size_t i = 0; i < artifact_count; i++) {
        _n00b_obj_bundle_write_artifact_record(writer, &artifacts[i]);
    }

    n00b_writer_setpos(writer, payload_table_off);

    for (size_t i = 0; i < artifact_count; i++) {
        if (artifacts[i].artifact->payload != nullptr) {
            _n00b_obj_bundle_write_payload_record(writer, &artifacts[i]);
        }
    }

    n00b_writer_setpos(writer, exec_table_off);

    if (bundle->has_default_exec) {
        n00b_writer_write_u32(writer, N00B_OBJ_BUNDLE_EXEC_REC_DEFAULT);
        n00b_writer_write_u32(writer, 0);
        n00b_writer_write_u32(writer, 0);
        n00b_writer_write_u32(writer, 0);
        n00b_writer_write_u64(writer, default_encoded_id);
    }

    for (size_t i = 0; i < mapping_count; i++) {
        n00b_writer_write_u32(writer, N00B_OBJ_BUNDLE_EXEC_REC_SELECTOR);
        n00b_writer_write_u32(writer, 0);
        n00b_writer_write_u32(writer, mappings[i].selector_off);
        n00b_writer_write_u32(writer, 0);
        n00b_writer_write_u64(writer, mappings[i].target_encoded_id);
    }

    n00b_writer_setpos(writer, policy_table_off);

    for (size_t i = 0; i < policy_count; i++) {
        _n00b_obj_bundle_write_policy_record(writer, &policies[i]);
    }

    n00b_writer_setpos(writer, string_table_off);
    n00b_writer_write_bytes(writer, strings->data, strings->len);
    n00b_writer_setpos(writer, payload_area_off);

    for (size_t i = 0; i < artifact_count; i++) {
        const n00b_buffer_t *payload = artifacts[i].artifact->payload;

        if (payload != nullptr && payload->byte_len != 0) {
            n00b_writer_write_bytes(writer, payload->data, payload->byte_len);
        }
    }

    for (size_t i = 0; i < policy_count; i++) {
        const n00b_buffer_t *payload = policies[i].policy->payload;

        if (payload != nullptr && payload->byte_len != 0) {
            n00b_writer_write_bytes(writer, payload->data, payload->byte_len);
        }
    }

    n00b_writer_setpos(writer, total_len);

    if (n00b_writer_has_error(writer)) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_BUILD,
                              r"object bundle: writer failed",
                              allocator);
    }

    n00b_buffer_t *encoded = n00b_writer_finalize(writer);
    uint8_t        content_id[N00B_OBJ_BUNDLE_CONTENT_ID_LEN];

    memset(encoded->data + N00B_OBJ_BUNDLE_CONTENT_ID_OFF,
           0,
           N00B_OBJ_BUNDLE_CONTENT_ID_LEN);
    _n00b_obj_bundle_sha256_bytes(encoded->data, encoded->byte_len, content_id);
    memcpy(encoded->data + N00B_OBJ_BUNDLE_CONTENT_ID_OFF,
           content_id,
           N00B_OBJ_BUNDLE_CONTENT_ID_LEN);

    // encoded is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    return n00b_result_ok(n00b_buffer_t *, encoded);
}

n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_decode(n00b_buffer_t *bundle_bytes) _kargs
{
    bool              strict    = true;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bundle_bytes == nullptr || bundle_bytes->data == nullptr) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null manifest bytes",
                              allocator);
    }

    if (bundle_bytes->byte_len < N00B_OBJ_BUNDLE_HEADER_SIZE
        || bundle_bytes->byte_len > INT64_MAX) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: manifest header is malformed",
                              allocator);
    }

    const uint8_t *data      = (const uint8_t *)bundle_bytes->data;
    uint64_t       total_len = (uint64_t)bundle_bytes->byte_len;

    if (memcmp(data,
               N00B_OBJ_BUNDLE_MANIFEST_MAGIC,
               N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN) != 0) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: manifest magic mismatch",
                              allocator);
    }

    n00b_bstream_t *stream = n00b_bstream_new(bundle_bytes,
                                              .allocator = allocator);
    n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);

    uint16_t major       = 0;
    uint16_t minor       = 0;
    uint32_t header_size = 0;
    uint64_t manifest_len = 0;
    uint64_t manifest_flags = 0;
    uint64_t artifact_count = 0;
    uint64_t payload_count  = 0;
    uint64_t exec_count     = 0;
    uint64_t policy_count   = 0;
    uint8_t  content_id[N00B_OBJ_BUNDLE_CONTENT_ID_LEN];
    n00b_obj_bundle_manifest_range_t artifact_table = {};
    n00b_obj_bundle_manifest_range_t payload_table  = {};
    n00b_obj_bundle_manifest_range_t exec_table     = {};
    n00b_obj_bundle_manifest_range_t policy_table   = {};
    n00b_obj_bundle_manifest_range_t string_table   = {};
    n00b_obj_bundle_manifest_range_t payload_area   = {};
    n00b_obj_bundle_manifest_range_t extension_table = {};

    if (!_n00b_obj_bundle_setpos(stream, 8)
        || !_n00b_obj_bundle_read_u16(stream, &major)
        || !_n00b_obj_bundle_read_u16(stream, &minor)
        || !_n00b_obj_bundle_read_u32(stream, &header_size)
        || !_n00b_obj_bundle_read_u64(stream, &manifest_len)
        || !_n00b_obj_bundle_read_u64(stream, &manifest_flags)
        || !_n00b_obj_bundle_setpos(stream, 64)
        || !_n00b_obj_bundle_read_u64(stream, &artifact_count)
        || !_n00b_obj_bundle_read_u64(stream, &payload_count)
        || !_n00b_obj_bundle_read_u64(stream, &exec_count)
        || !_n00b_obj_bundle_read_u64(stream, &policy_count)
        || !_n00b_obj_bundle_read_u64(stream, &artifact_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &artifact_table.len)
        || !_n00b_obj_bundle_read_u64(stream, &payload_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &payload_table.len)
        || !_n00b_obj_bundle_read_u64(stream, &exec_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &exec_table.len)
        || !_n00b_obj_bundle_read_u64(stream, &policy_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &policy_table.len)
        || !_n00b_obj_bundle_read_u64(stream, &string_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &string_table.len)
        || !_n00b_obj_bundle_read_u64(stream, &payload_area.off)
        || !_n00b_obj_bundle_read_u64(stream, &payload_area.len)
        || !_n00b_obj_bundle_read_u64(stream, &extension_table.off)
        || !_n00b_obj_bundle_read_u64(stream, &extension_table.len)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: manifest header is truncated",
                              allocator);
    }

    memcpy(content_id,
           data + N00B_OBJ_BUNDLE_CONTENT_ID_OFF,
           N00B_OBJ_BUNDLE_CONTENT_ID_LEN);

    if (major != N00B_OBJ_BUNDLE_MANIFEST_MAJOR
        || minor != N00B_OBJ_BUNDLE_MANIFEST_MINOR) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_VERSION,
                              r"object bundle: unsupported manifest version",
                              allocator);
    }

    if (header_size != N00B_OBJ_BUNDLE_HEADER_SIZE) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: unsupported header size",
                              allocator);
    }

    if (manifest_len != total_len) {
        n00b_obj_bundle_error_code_t code =
            manifest_len > total_len
                ? N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS
                : N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST;
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              code,
                              r"object bundle: manifest length mismatch",
                              allocator);
    }

    if (manifest_flags != 0) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                              r"object bundle: unsupported manifest flags",
                              allocator);
    }

    uint64_t artifact_table_len = 0;
    uint64_t payload_table_len  = 0;
    uint64_t exec_table_len     = 0;
    uint64_t policy_table_len   = 0;

    if (!_n00b_obj_bundle_u64_mul(artifact_count,
                                  N00B_OBJ_BUNDLE_ARTIFACT_REC_SIZE,
                                  &artifact_table_len)
        || !_n00b_obj_bundle_u64_mul(payload_count,
                                     N00B_OBJ_BUNDLE_PAYLOAD_REC_SIZE,
                                     &payload_table_len)
        || !_n00b_obj_bundle_u64_mul(exec_count,
                                     N00B_OBJ_BUNDLE_EXEC_REC_SIZE,
                                     &exec_table_len)
        || !_n00b_obj_bundle_u64_mul(policy_count,
                                     N00B_OBJ_BUNDLE_POLICY_REC_SIZE,
                                     &policy_table_len)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: manifest table is too large",
                              allocator);
    }

    if (artifact_table.len != artifact_table_len
        || payload_table.len != payload_table_len
        || exec_table.len != exec_table_len
        || policy_table.len != policy_table_len) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: manifest table length mismatch",
                              allocator);
    }

    if (!_n00b_obj_bundle_range_within(artifact_table.off,
                                       artifact_table.len,
                                       total_len)
        || !_n00b_obj_bundle_range_within(payload_table.off,
                                          payload_table.len,
                                          total_len)
        || !_n00b_obj_bundle_range_within(exec_table.off,
                                          exec_table.len,
                                          total_len)
        || !_n00b_obj_bundle_range_within(policy_table.off,
                                          policy_table.len,
                                          total_len)
        || !_n00b_obj_bundle_range_within(string_table.off,
                                          string_table.len,
                                          total_len)
        || !_n00b_obj_bundle_range_within(payload_area.off,
                                          payload_area.len,
                                          total_len)
        || !_n00b_obj_bundle_range_within(extension_table.off,
                                          extension_table.len,
                                          total_len)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: manifest table is out of bounds",
                              allocator);
    }

    uint64_t expected_artifact_off = N00B_OBJ_BUNDLE_HEADER_SIZE;
    uint64_t expected_payload_off =
        _n00b_obj_bundle_align_u64(expected_artifact_off
                                       + artifact_table.len,
                                   8);
    uint64_t expected_exec_off =
        _n00b_obj_bundle_align_u64(expected_payload_off + payload_table.len,
                                   8);
    uint64_t expected_policy_off =
        _n00b_obj_bundle_align_u64(expected_exec_off + exec_table.len, 8);
    uint64_t expected_string_off =
        _n00b_obj_bundle_align_u64(expected_policy_off + policy_table.len, 8);
    uint64_t expected_payload_area_off =
        _n00b_obj_bundle_align_u64(expected_string_off + string_table.len, 8);
    uint64_t expected_extension_off = expected_payload_area_off
                                      + payload_area.len;

    if (artifact_table.off != expected_artifact_off
        || payload_table.off != expected_payload_off
        || exec_table.off != expected_exec_off
        || policy_table.off != expected_policy_off
        || string_table.off != expected_string_off
        || payload_area.off != expected_payload_area_off
        || extension_table.off != expected_extension_off
        || extension_table.len != 0
        || extension_table.off != total_len
        || !_n00b_obj_bundle_is_aligned(artifact_table.off, 8)
        || !_n00b_obj_bundle_is_aligned(payload_table.off, 8)
        || !_n00b_obj_bundle_is_aligned(exec_table.off, 8)
        || !_n00b_obj_bundle_is_aligned(policy_table.off, 8)
        || !_n00b_obj_bundle_is_aligned(string_table.off, 8)
        || !_n00b_obj_bundle_is_aligned(payload_area.off, 8)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                              r"object bundle: manifest table order is non-canonical",
                              allocator);
    }

    if (string_table.len == 0 || data[string_table.off] != 0) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                              r"object bundle: string table is malformed",
                              allocator);
    }

    n00b_buffer_t *content_copy = n00b_buffer_copy(bundle_bytes);
    uint8_t        expected_content_id[N00B_OBJ_BUNDLE_CONTENT_ID_LEN];

    memset(content_copy->data + N00B_OBJ_BUNDLE_CONTENT_ID_OFF,
           0,
           N00B_OBJ_BUNDLE_CONTENT_ID_LEN);
    _n00b_obj_bundle_sha256_bytes(content_copy->data,
                                  content_copy->byte_len,
                                  expected_content_id);

    if (memcmp(content_id,
               expected_content_id,
               N00B_OBJ_BUNDLE_CONTENT_ID_LEN) != 0) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                              r"object bundle: content ID mismatch",
                              allocator);
    }

    const uint8_t *string_base  = data + string_table.off;
    const uint8_t *payload_base = data + payload_area.off;

    n00b_obj_bundle_decode_artifact_t *artifacts = nullptr;
    n00b_obj_bundle_decode_payload_t  *payloads  = nullptr;
    n00b_obj_bundle_decode_exec_t     *execs     = nullptr;
    n00b_obj_bundle_decode_policy_t   *policies  = nullptr;

    if (artifact_count != 0) {
        artifacts = n00b_alloc_array(n00b_obj_bundle_decode_artifact_t,
                                     (size_t)artifact_count);
    }

    if (payload_count != 0) {
        payloads = n00b_alloc_array(n00b_obj_bundle_decode_payload_t,
                                    (size_t)payload_count);
    }

    if (exec_count != 0) {
        execs = n00b_alloc_array(n00b_obj_bundle_decode_exec_t,
                                 (size_t)exec_count);
    }

    if (policy_count != 0) {
        policies = n00b_alloc_array(n00b_obj_bundle_decode_policy_t,
                                    (size_t)policy_count);
    }

    if (!_n00b_obj_bundle_setpos(stream, artifact_table.off)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: artifact table is out of bounds",
                              allocator);
    }

    for (uint64_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_decode_artifact_t *artifact = &artifacts[i];
        uint32_t kind = 0;

        if (!_n00b_obj_bundle_read_u64(stream, &artifact->id)
            || !_n00b_obj_bundle_read_u32(stream, &kind)
            || !_n00b_obj_bundle_read_u32(stream, &artifact->record_flags)
            || !_n00b_obj_bundle_read_u64(stream, &artifact->flags)
            || !_n00b_obj_bundle_read_u32(stream, &artifact->path_off)
            || !_n00b_obj_bundle_read_u32(stream, &artifact->role_off)
            || !_n00b_obj_bundle_read_u32(stream, &artifact->mode)
            || !_n00b_obj_bundle_read_u32(stream, &artifact->payload_index)
            || !_n00b_obj_bundle_read_digest(stream, artifact->digest)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: artifact record is truncated",
                                  allocator);
        }

        artifact->kind = (n00b_obj_bundle_artifact_kind_t)kind;

        if (artifact->id != i) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: artifact IDs are non-canonical",
                                  allocator);
        }

        if (!_n00b_obj_bundle_artifact_kind_is_valid(artifact->kind)
            || artifact->record_flags != 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                                  r"object bundle: unsupported artifact record",
                                  allocator);
        }

        if (!_n00b_obj_bundle_decode_string(string_base,
                                            string_table.len,
                                            artifact->path_off,
                                            false,
                                            allocator,
                                            &artifact->logical_path)
            || !_n00b_obj_bundle_decode_string(string_base,
                                               string_table.len,
                                               artifact->role_off,
                                               true,
                                               allocator,
                                               &artifact->role)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                                  r"object bundle: artifact string reference is invalid",
                                  allocator);
        }

        if (i != 0) {
            int cmp = _n00b_obj_bundle_string_bytes_cmp(
                artifacts[i - 1].logical_path,
                artifact->logical_path);

            if (cmp == 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH,
                                      r"object bundle: duplicate artifact path",
                                      allocator);
            }

            if (cmp > 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                      r"object bundle: artifact order is non-canonical",
                                      allocator);
            }
        }

        if (artifact->payload_index == N00B_OBJ_BUNDLE_NO_PAYLOAD_INDEX) {
            if (!_n00b_obj_bundle_digest_is_zero(artifact->digest)) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                                      r"object bundle: empty artifact digest is nonzero",
                                      allocator);
            }
        }
        else if (artifact->payload_index >= payload_count) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: artifact payload index is out of bounds",
                                  allocator);
        }
    }

    uint64_t payload_cursor = 0;

    if (!_n00b_obj_bundle_setpos(stream, payload_table.off)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: payload table is out of bounds",
                              allocator);
    }

    for (uint64_t i = 0; i < payload_count; i++) {
        n00b_obj_bundle_decode_payload_t *payload = &payloads[i];

        if (!_n00b_obj_bundle_read_u64(stream, &payload->artifact_id)
            || !_n00b_obj_bundle_read_u64(stream, &payload->flags)
            || !_n00b_obj_bundle_read_u64(stream, &payload->payload_off)
            || !_n00b_obj_bundle_read_u64(stream, &payload->payload_len)
            || !_n00b_obj_bundle_read_digest(stream, payload->digest)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: payload record is truncated",
                                  allocator);
        }

        if (payload->flags != 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                                  r"object bundle: unsupported payload flags",
                                  allocator);
        }

        if (payload->artifact_id >= artifact_count) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                                  r"object bundle: payload artifact target is missing",
                                  allocator);
        }

        if (i != 0 && payload->artifact_id <= payloads[i - 1].artifact_id) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: payload order is non-canonical",
                                  allocator);
        }

        n00b_obj_bundle_decode_artifact_t *artifact =
            &artifacts[payload->artifact_id];

        if (artifact->payload_index != i) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: payload index is non-canonical",
                                  allocator);
        }

        if (!_n00b_obj_bundle_range_within(payload->payload_off,
                                           payload->payload_len,
                                           payload_area.len)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: payload bytes are out of bounds",
                                  allocator);
        }

        if (payload->payload_off != payload_cursor) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: payload placement is non-canonical",
                                  allocator);
        }

        artifact->payload =
            _n00b_obj_bundle_decode_payload_slice(payload_base,
                                                  payload->payload_off,
                                                  payload->payload_len,
                                                  allocator);

        if (artifact->payload == nullptr) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: payload is too large",
                                  allocator);
        }

        uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN];

        _n00b_obj_bundle_sha256_bytes(artifact->payload->data,
                                      artifact->payload->byte_len,
                                      digest);

        if (memcmp(digest, payload->digest, N00B_OBJ_BUNDLE_DIGEST_LEN) != 0
            || memcmp(digest,
                      artifact->digest,
                      N00B_OBJ_BUNDLE_DIGEST_LEN) != 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                                  r"object bundle: payload digest mismatch",
                                  allocator);
        }

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      payload->payload_len,
                                      &payload_cursor)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: payload area is too large",
                                  allocator);
        }
    }

    for (uint64_t i = 0; i < artifact_count; i++) {
        if (!_n00b_obj_bundle_artifact_has_valid_payload(artifacts[i].kind,
                                                         artifacts[i].payload)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                                  r"object bundle: artifact payload is invalid",
                                  allocator);
        }
    }

    if (!_n00b_obj_bundle_setpos(stream, exec_table.off)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: exec table is out of bounds",
                              allocator);
    }

    bool has_default_exec = false;
    bool saw_selector     = false;

    for (uint64_t i = 0; i < exec_count; i++) {
        n00b_obj_bundle_decode_exec_t *exec = &execs[i];

        if (!_n00b_obj_bundle_read_u32(stream, &exec->kind)
            || !_n00b_obj_bundle_read_u32(stream, &exec->flags)
            || !_n00b_obj_bundle_read_u32(stream, &exec->selector_off)
            || !_n00b_obj_bundle_read_u32(stream, &exec->reserved)
            || !_n00b_obj_bundle_read_u64(stream, &exec->target_id)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: exec record is truncated",
                                  allocator);
        }

        if (exec->flags != 0 || exec->reserved != 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                                  r"object bundle: unsupported exec record flags",
                                  allocator);
        }

        if (exec->target_id >= artifact_count) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                                  r"object bundle: exec target is missing",
                                  allocator);
        }

        n00b_obj_bundle_decode_artifact_t *target = &artifacts[exec->target_id];
        bool target_is_exec = target->kind == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE
                              || (target->kind == N00B_OBJ_BUNDLE_ARTIFACT_FILE
                                  && (target->mode & 0111u) != 0);

        if (!target_is_exec) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                                  r"object bundle: exec target is not executable",
                                  allocator);
        }

        if (exec->kind == N00B_OBJ_BUNDLE_EXEC_REC_DEFAULT) {
            if (has_default_exec) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC,
                                      r"object bundle: multiple default exec records",
                                      allocator);
            }

            if (saw_selector || exec->selector_off != 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                      r"object bundle: default exec order is non-canonical",
                                      allocator);
            }

            has_default_exec = true;
            continue;
        }

        if (exec->kind != N00B_OBJ_BUNDLE_EXEC_REC_SELECTOR) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                                  r"object bundle: unknown exec record kind",
                                  allocator);
        }

        saw_selector = true;

        if (!_n00b_obj_bundle_decode_string(string_base,
                                            string_table.len,
                                            exec->selector_off,
                                            false,
                                            allocator,
                                            &exec->selector)
            || !_n00b_obj_bundle_selector_is_valid(exec->selector)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                                  r"object bundle: selector string is invalid",
                                  allocator);
        }

        for (uint64_t j = 0; j < i; j++) {
            if (execs[j].kind != N00B_OBJ_BUNDLE_EXEC_REC_SELECTOR) {
                continue;
            }

            int cmp = _n00b_obj_bundle_string_bytes_cmp(execs[j].selector,
                                                        exec->selector);

            if (cmp == 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR,
                                      r"object bundle: duplicate selector",
                                      allocator);
            }

            if (cmp > 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                      r"object bundle: selector order is non-canonical",
                                      allocator);
            }
        }
    }

    if (!_n00b_obj_bundle_setpos(stream, policy_table.off)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                              r"object bundle: policy table is out of bounds",
                              allocator);
    }

    for (uint64_t i = 0; i < policy_count; i++) {
        n00b_obj_bundle_decode_policy_t *policy = &policies[i];
        uint32_t kind = 0;
        uint32_t scope = 0;

        if (!_n00b_obj_bundle_read_u64(stream, &policy->policy_id)
            || !_n00b_obj_bundle_read_u32(stream, &kind)
            || !_n00b_obj_bundle_read_u32(stream, &scope)
            || !_n00b_obj_bundle_read_u64(stream, &policy->flags)
            || !_n00b_obj_bundle_read_u64(stream, &policy->priority)
            || !_n00b_obj_bundle_read_u64(stream, &policy->payload_off)
            || !_n00b_obj_bundle_read_u64(stream, &policy->payload_len)
            || !_n00b_obj_bundle_read_u64(stream, &policy->fallback_policy_id)
            || !_n00b_obj_bundle_read_digest(stream, policy->digest)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                  r"object bundle: policy record is truncated",
                                  allocator);
        }

        policy->kind  = (n00b_obj_bundle_policy_kind_t)kind;
        policy->scope = (n00b_obj_bundle_policy_scope_t)scope;

        if (!_n00b_obj_bundle_policy_kind_is_known(policy->kind)
            || !_n00b_obj_bundle_policy_scope_is_valid(policy->scope)
            || !_n00b_obj_bundle_policy_flags_are_valid(policy->flags)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE,
                                  r"object bundle: unsupported policy record",
                                  allocator);
        }

        for (uint64_t j = 0; j < i; j++) {
            if (policies[j].policy_id == policy->policy_id) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID,
                                      r"object bundle: duplicate policy ID",
                                      allocator);
            }
        }

        if (policy->payload_len == 0) {
            if (policy->payload_off != 0
                || !_n00b_obj_bundle_digest_is_zero(policy->digest)) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                      r"object bundle: empty policy payload is non-canonical",
                                      allocator);
            }
        }
        else {
            if (!_n00b_obj_bundle_range_within(policy->payload_off,
                                               policy->payload_len,
                                               payload_area.len)) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                      r"object bundle: policy payload is out of bounds",
                                      allocator);
            }

            if (policy->payload_off != payload_cursor) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                      r"object bundle: policy payload placement is non-canonical",
                                      allocator);
            }

            policy->payload =
                _n00b_obj_bundle_decode_payload_slice(payload_base,
                                                      policy->payload_off,
                                                      policy->payload_len,
                                                      allocator);

            if (policy->payload == nullptr) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                      r"object bundle: policy payload is too large",
                                      allocator);
            }

            uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN];

            _n00b_obj_bundle_sha256_bytes(policy->payload->data,
                                          policy->payload->byte_len,
                                          digest);

            if (memcmp(digest,
                       policy->digest,
                       N00B_OBJ_BUNDLE_DIGEST_LEN) != 0) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                                      r"object bundle: policy digest mismatch",
                                      allocator);
            }

            if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                          policy->payload_len,
                                          &payload_cursor)) {
                return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                      N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                                      r"object bundle: payload area is too large",
                                      allocator);
            }
        }

        if (!_n00b_obj_bundle_policy_payload_is_valid(policy->kind,
                                                      policy->payload,
                                                      policy->fallback_policy_id)) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST,
                                  r"object bundle: policy payload is invalid",
                                  allocator);
        }

        if (i != 0
            && _n00b_obj_bundle_decode_policy_cmp(&policies[i - 1],
                                                  policy) > 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: policy order is non-canonical",
                                  allocator);
        }
    }

    if (payload_cursor != payload_area.len) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                              r"object bundle: payload area has non-canonical trailing bytes",
                              allocator);
    }

    auto create = n00b_obj_bundle_new(.allocator = allocator);

    if (n00b_result_is_err(create)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, create));
    }

    n00b_obj_bundle_t *bundle = n00b_result_get(create);

    for (uint64_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_decode_artifact_t *artifact = &artifacts[i];
        auto add = n00b_obj_bundle_add_artifact(bundle,
                                                artifact->logical_path,
                                                artifact->payload,
                                                .kind = artifact->kind,
                                                .role = artifact->role,
                                                .mode = artifact->mode,
                                                .flags = artifact->flags);

        if (n00b_result_is_err(add)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *, add));
        }
    }

    for (uint64_t i = 0; i < exec_count; i++) {
        n00b_obj_bundle_decode_exec_t *exec = &execs[i];
        n00b_string_t *target_path = artifacts[exec->target_id].logical_path;

        if (exec->kind == N00B_OBJ_BUNDLE_EXEC_REC_DEFAULT) {
            auto set_default =
                n00b_obj_bundle_set_default_exec(bundle, target_path);

            if (n00b_result_is_err(set_default)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                set_default));
            }

            continue;
        }

        auto add_mapping = n00b_obj_bundle_add_exec_mapping(bundle,
                                                            exec->selector,
                                                            target_path);

        if (n00b_result_is_err(add_mapping)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            add_mapping));
        }
    }

    for (uint64_t i = 0; i < policy_count; i++) {
        n00b_obj_bundle_decode_policy_t *policy = &policies[i];
        auto add_policy = n00b_obj_bundle_add_policy(
            bundle,
            policy->policy_id,
            policy->kind,
            policy->scope,
            .flags = policy->flags,
            .priority = policy->priority,
            .payload = policy->payload,
            .fallback_policy_id = policy->fallback_policy_id);

        if (n00b_result_is_err(add_policy)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            add_policy));
        }
    }

    auto valid = n00b_obj_bundle_validate(bundle);

    if (n00b_result_is_err(valid)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, valid));
    }

    if (strict) {
        auto encoded = n00b_obj_bundle_encode(bundle, .allocator = allocator);

        if (n00b_result_is_err(encoded)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            encoded));
        }

        n00b_buffer_t *canonical = n00b_result_get(encoded);

        if (canonical->byte_len != bundle_bytes->byte_len
            || memcmp(canonical->data,
                      bundle_bytes->data,
                      bundle_bytes->byte_len) != 0) {
            return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                                  N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST,
                                  r"object bundle: manifest is non-canonical",
                                  allocator);
        }
    }

    bundle->is_mutable = false;

    return n00b_result_ok(n00b_obj_bundle_t *, bundle);
}

static bool
_n00b_obj_bundle_elf_section_is_metadata_carrier(
    n00b_elf_section_t *section)
{
    return section != nullptr
           && _n00b_obj_bundle_string_bytes_eq(section->name,
                                               r".0c001.bundle");
}

static bool
_n00b_obj_bundle_string_starts_with(n00b_string_t *s, n00b_string_t *prefix)
{
    return s != nullptr
           && prefix != nullptr
           && s->u8_bytes >= prefix->u8_bytes
           && memcmp(s->data, prefix->data, prefix->u8_bytes) == 0;
}

static bool
_n00b_obj_bundle_elf_section_is_foreign_legacy(n00b_elf_section_t *section)
{
    return section != nullptr
           && _n00b_obj_bundle_string_bytes_eq(section->name,
                                               r".0c001.file");
}

static bool
_n00b_obj_bundle_elf_section_is_wrapped_or_reserved(
    n00b_elf_section_t *section)
{
    return section != nullptr
           && (_n00b_obj_bundle_string_bytes_eq(section->name,
                                                r".0c001.wrap")
               || _n00b_obj_bundle_string_bytes_eq(section->name,
                                                   r".0c001.code"));
}

static bool
_n00b_obj_bundle_elf_section_is_unknown_0c001(n00b_elf_section_t *section)
{
    return section != nullptr
           && section->name != nullptr
           && _n00b_obj_bundle_string_starts_with(section->name, r".0c001.")
           && !_n00b_obj_bundle_elf_section_is_metadata_carrier(section)
           && !_n00b_obj_bundle_elf_section_is_foreign_legacy(section)
           && !_n00b_obj_bundle_elf_section_is_wrapped_or_reserved(section);
}

static bool
_n00b_obj_bundle_elf_section_is_nonconflicting_chalk(
    n00b_elf_section_t *section)
{
    return section != nullptr
           && (_n00b_obj_bundle_string_bytes_eq(section->name,
                                               r".chalk.mark")
               || _n00b_obj_bundle_string_bytes_eq(section->name,
                                                   r".chalk.free"));
}

static int64_t
_n00b_obj_bundle_elf_carrier_shape_detail(n00b_elf_section_t *section)
{
    if (section->type != SHT_PROGBITS) {
        return (int64_t)section->type;
    }

    if ((section->flags & SHF_ALLOC) != 0) {
        return section->flags > INT64_MAX ? INT64_MAX : (int64_t)section->flags;
    }

    if (section->size > INT64_MAX) {
        return INT64_MAX;
    }

    return (int64_t)section->size;
}

static bool
_n00b_obj_bundle_elf_carrier_shape_is_valid(n00b_elf_section_t *section)
{
    return section != nullptr
           && section->type == SHT_PROGBITS
           && (section->flags & SHF_ALLOC) == 0
           && section->content != nullptr
           && section->content->data != nullptr;
}

static int64_t
_n00b_obj_bundle_decode_failure_detail(
    n00b_result_t(n00b_obj_bundle_t *) decode)
{
    if (n00b_result_is_err_payload(n00b_obj_bundle_error_t *, decode)) {
        n00b_obj_bundle_error_t *lower =
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, decode);

        return lower == nullptr ? 0 : lower->code;
    }

    return n00b_result_get_err(decode);
}

static int64_t
_n00b_obj_bundle_i64_detail_from_u64(uint64_t value)
{
    return value > INT64_MAX ? INT64_MAX : (int64_t)value;
}

static bool
_n00b_obj_bundle_elf_descriptor_magic_matches(n00b_buffer_t *bytes)
{
    return bytes != nullptr
           && bytes->data != nullptr
           && bytes->byte_len >= N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC_LEN
           && memcmp(bytes->data,
                     N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC,
                     N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC_LEN) == 0;
}

static bool
_n00b_obj_bundle_elf_descriptor_carrier_from_kind(
    uint32_t                    kind,
    n00b_obj_bundle_carrier_t  *carrier)
{
    if (kind == N00B_OBJ_BUNDLE_CARRIER_LOADABLE
        || kind == N00B_OBJ_BUNDLE_CARRIER_SPLIT) {
        *carrier = (n00b_obj_bundle_carrier_t)kind;
        return true;
    }

    return false;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_elf_descriptor_error(
    n00b_obj_bundle_error_code_t code,
    n00b_string_t               *message,
    n00b_obj_bundle_carrier_t    carrier,
    int64_t                      detail,
    bool                         has_detail,
    n00b_allocator_t            *allocator)
{
    return _n00b_obj_bundle_error_with_format_carrier_detail(
        code,
        message,
        N00B_FMT_ELF,
        true,
        carrier,
        true,
        detail,
        has_detail,
        allocator);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_elf_carrier_error(
    n00b_obj_bundle_error_code_t code,
    n00b_string_t               *message,
    n00b_obj_bundle_carrier_t    carrier,
    int64_t                      detail,
    bool                         has_detail,
    n00b_allocator_t            *allocator)
{
    return _n00b_obj_bundle_error_with_format_carrier_detail(
        code,
        message,
        N00B_FMT_ELF,
        true,
        carrier,
        true,
        detail,
        has_detail,
        allocator);
}

static n00b_buffer_t *
_n00b_obj_bundle_elf_descriptor_encode(
    n00b_obj_bundle_elf_descriptor_t *descriptor,
    n00b_allocator_t                 *allocator)
{
    n00b_writer_t *writer =
        n00b_writer_new(N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE,
                        .allocator = allocator);

    n00b_writer_set_endian(writer, N00B_ENDIAN_LITTLE);
    n00b_writer_write_bytes(writer,
                            N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC,
                            N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAGIC_LEN);
    n00b_writer_write_u16(writer, descriptor->major);
    n00b_writer_write_u16(writer, descriptor->minor);
    n00b_writer_write_u32(writer, descriptor->header_size);
    n00b_writer_write_u32(writer, (uint32_t)descriptor->carrier);
    n00b_writer_write_u32(writer, descriptor->flags);
    n00b_writer_write_u64(writer, descriptor->payload.off);
    n00b_writer_write_u64(writer, descriptor->payload.len);
    _n00b_obj_bundle_write_digest(writer, descriptor->payload_digest);
    n00b_writer_write_u64(writer, descriptor->aux.off);
    n00b_writer_write_u64(writer, descriptor->aux.len);
    n00b_writer_write_u64(writer, descriptor->aux_record_count);
    n00b_writer_write_u64(writer, descriptor->reserved0);
    n00b_writer_write_u64(writer, descriptor->reserved1);

    if (n00b_writer_has_error(writer)) {
        return nullptr;
    }

    n00b_buffer_t *encoded = n00b_writer_finalize(writer);

    // encoded is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    return encoded;
}

static bool
_n00b_obj_bundle_elf_descriptor_is_canonical(
    n00b_obj_bundle_elf_descriptor_t *descriptor,
    n00b_buffer_t                    *descriptor_bytes,
    n00b_allocator_t                 *allocator)
{
    n00b_buffer_t *encoded =
        _n00b_obj_bundle_elf_descriptor_encode(descriptor, allocator);

    return encoded != nullptr
           && descriptor_bytes->byte_len >= encoded->byte_len
           && memcmp(encoded->data,
                     descriptor_bytes->data,
                     encoded->byte_len) == 0;
}

static void
_n00b_obj_bundle_elf_split_record_write(
    n00b_writer_t                       *writer,
    n00b_obj_bundle_elf_split_record_t  *record)
{
    n00b_writer_write_u64(writer, record->canonical.off);
    n00b_writer_write_u64(writer, record->canonical.len);
    n00b_writer_write_u64(writer, record->object.off);
    n00b_writer_write_u64(writer, record->object.len);
    _n00b_obj_bundle_write_digest(writer, record->digest);
}

static bool
_n00b_obj_bundle_elf_split_record_read(
    n00b_bstream_t                      *stream,
    n00b_obj_bundle_elf_split_record_t  *record)
{
    return _n00b_obj_bundle_read_u64(stream, &record->canonical.off)
           && _n00b_obj_bundle_read_u64(stream, &record->canonical.len)
           && _n00b_obj_bundle_read_u64(stream, &record->object.off)
           && _n00b_obj_bundle_read_u64(stream, &record->object.len)
           && _n00b_obj_bundle_read_digest(stream, record->digest);
}

static n00b_result_t(n00b_obj_bundle_elf_descriptor_t *)
_n00b_obj_bundle_elf_descriptor_decode(n00b_buffer_t     *descriptor_bytes,
                                       n00b_buffer_t     *object_bytes,
                                       n00b_allocator_t  *allocator)
{
    if (!_n00b_obj_bundle_elf_descriptor_magic_matches(descriptor_bytes)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF descriptor carrier magic mismatch",
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                0,
                false,
                allocator));
    }

    if (descriptor_bytes->byte_len
        < N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor carrier is truncated",
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor_bytes->byte_len),
                true,
                allocator));
    }

    n00b_bstream_t *stream = n00b_bstream_new(descriptor_bytes,
                                              .allocator = allocator);
    n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);

    uint32_t kind = 0;
    n00b_obj_bundle_elf_descriptor_t *descriptor =
        n00b_alloc_with_opts(n00b_obj_bundle_elf_descriptor_t,
                             &(n00b_alloc_opts_t){.allocator = allocator});

    if (!_n00b_obj_bundle_setpos(stream,
                                 N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_VERSION_OFF)
        || !_n00b_obj_bundle_read_u16(stream, &descriptor->major)
        || !_n00b_obj_bundle_read_u16(stream, &descriptor->minor)
        || !_n00b_obj_bundle_read_u32(stream, &descriptor->header_size)
        || !_n00b_obj_bundle_read_u32(stream, &kind)
        || !_n00b_obj_bundle_read_u32(stream, &descriptor->flags)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->payload.off)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->payload.len)
        || !_n00b_obj_bundle_read_digest(stream,
                                         descriptor->payload_digest)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->aux.off)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->aux.len)
        || !_n00b_obj_bundle_read_u64(stream,
                                      &descriptor->aux_record_count)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->reserved0)
        || !_n00b_obj_bundle_read_u64(stream, &descriptor->reserved1)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor carrier is truncated",
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor_bytes->byte_len),
                true,
                allocator));
    }

    n00b_obj_bundle_carrier_t descriptor_carrier =
        N00B_OBJ_BUNDLE_CARRIER_METADATA;
    bool has_descriptor_carrier =
        _n00b_obj_bundle_elf_descriptor_carrier_from_kind(
            kind,
            &descriptor_carrier);

    descriptor->carrier = descriptor_carrier;

    if (descriptor->major != N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAJOR
        || descriptor->minor != N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MINOR) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_VERSION,
                r"object bundle: unsupported ELF descriptor carrier version",
                descriptor_carrier,
                ((int64_t)descriptor->major << 16) | descriptor->minor,
                true,
                allocator));
    }

    if (!has_descriptor_carrier) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF descriptor carrier kind is invalid",
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                _n00b_obj_bundle_i64_detail_from_u64(kind),
                true,
                allocator));
    }

    if (descriptor->header_size != N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE
        || descriptor_bytes->byte_len < descriptor->header_size) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor carrier length mismatch",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->header_size),
                true,
                allocator));
    }

    if (descriptor->flags != 0
        || descriptor->reserved0 != 0
        || descriptor->reserved1 != 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF descriptor carrier reserved field is set",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(descriptor->flags),
                true,
                allocator));
    }

    if (descriptor->payload.len == 0
        || !_n00b_obj_bundle_range_within(descriptor->payload.off,
                                          descriptor->payload.len,
                                          object_bytes->byte_len)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor payload range is invalid",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->payload.off),
                true,
                allocator));
    }

    if ((descriptor->aux.len == 0 && descriptor->aux.off != 0)
        || (descriptor->aux.len != 0
            && !_n00b_obj_bundle_range_within(descriptor->aux.off,
                                              descriptor->aux.len,
                                              object_bytes->byte_len))) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor auxiliary range is invalid",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(descriptor->aux.off),
                true,
                allocator));
    }

    if (descriptor->aux.len == 0 && descriptor->aux_record_count != 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF descriptor auxiliary records are invalid",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->aux_record_count),
                true,
                allocator));
    }

    if (!_n00b_obj_bundle_elf_descriptor_is_canonical(descriptor,
                                                      descriptor_bytes,
                                                      allocator)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF descriptor carrier is non-canonical",
                descriptor_carrier,
                0,
                false,
                allocator));
    }

    uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN];

    const uint8_t *object_data = (const uint8_t *)object_bytes->data;

    _n00b_obj_bundle_sha256_bytes(object_data + descriptor->payload.off,
                                  (size_t)descriptor->payload.len,
                                  digest);

    if (memcmp(digest,
               descriptor->payload_digest,
               N00B_OBJ_BUNDLE_DIGEST_LEN) != 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_elf_descriptor_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                r"object bundle: ELF descriptor payload digest mismatch",
                descriptor_carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->payload.off),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_obj_bundle_elf_descriptor_t *, descriptor);
}

static n00b_result_t(n00b_obj_bundle_t *)
_n00b_obj_bundle_read_elf_loadable_descriptor(
    n00b_buffer_t                    *object_bytes,
    n00b_obj_bundle_elf_descriptor_t *descriptor,
    bool                              strict,
    n00b_allocator_t                 *allocator)
{
    uint64_t payload_end = 0;

    if (!_n00b_obj_bundle_range_end(descriptor->payload.off,
                                    descriptor->payload.len,
                                    &payload_end)
        || descriptor->payload.off > INT64_MAX
        || payload_end > INT64_MAX) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF descriptor payload range is invalid",
                descriptor->carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->payload.off),
                true,
                allocator));
    }

    n00b_buffer_t *payload = n00b_buffer_get_slice(
        object_bytes,
        (int64_t)descriptor->payload.off,
        (int64_t)payload_end,
        .allocator = allocator);

    auto decoded = n00b_obj_bundle_decode(payload,
                                          .strict = strict,
                                          .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF loadable descriptor payload is malformed",
                descriptor->carrier,
                _n00b_obj_bundle_decode_failure_detail(decoded),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
}

static n00b_result_t(n00b_obj_bundle_t *)
_n00b_obj_bundle_read_elf_split_descriptor(
    n00b_buffer_t                    *object_bytes,
    n00b_obj_bundle_elf_descriptor_t *descriptor,
    bool                              strict,
    n00b_allocator_t                 *allocator)
{
    uint64_t skeleton_end = 0;
    uint64_t aux_end      = 0;
    uint64_t expected_aux_len = 0;

    if (descriptor->aux_record_count == 0
        || descriptor->aux_record_count > SIZE_MAX
        || !_n00b_obj_bundle_u64_mul(descriptor->aux_record_count,
                                     N00B_OBJ_BUNDLE_ELF_SPLIT_REC_SIZE,
                                     &expected_aux_len)
        || descriptor->aux.len != expected_aux_len
        || descriptor->aux.off > INT64_MAX
        || descriptor->payload.off > INT64_MAX
        || !_n00b_obj_bundle_range_end(descriptor->payload.off,
                                       descriptor->payload.len,
                                       &skeleton_end)
        || !_n00b_obj_bundle_range_end(descriptor->aux.off,
                                       descriptor->aux.len,
                                       &aux_end)
        || skeleton_end > INT64_MAX
        || aux_end > INT64_MAX) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF split descriptor records are invalid",
                descriptor->carrier,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor->aux_record_count),
                true,
                allocator));
    }

    n00b_buffer_t *skeleton = n00b_buffer_get_slice(
        object_bytes,
        (int64_t)descriptor->payload.off,
        (int64_t)skeleton_end,
        .allocator = allocator);
    n00b_buffer_t *aux = n00b_buffer_get_slice(object_bytes,
                                               (int64_t)descriptor->aux.off,
                                               (int64_t)aux_end,
                                               .allocator = allocator);
    n00b_bstream_t *stream = n00b_bstream_new(aux, .allocator = allocator);

    n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);

    uint64_t previous_canonical_end = 0;
    uint64_t total_moved            = 0;
    n00b_obj_bundle_elf_split_record_t *records =
        n00b_alloc_array(n00b_obj_bundle_elf_split_record_t,
                         (size_t)descriptor->aux_record_count);

    for (uint64_t i = 0; i < descriptor->aux_record_count; i++) {
        n00b_obj_bundle_elf_split_record_t record = {};
        uint64_t canonical_end = 0;

        if (!_n00b_obj_bundle_elf_split_record_read(stream, &record)
            || record.canonical.len == 0
            || record.object.len != record.canonical.len
            || !_n00b_obj_bundle_range_end(record.canonical.off,
                                           record.canonical.len,
                                           &canonical_end)
            || !_n00b_obj_bundle_range_within(record.object.off,
                                              record.object.len,
                                              object_bytes->byte_len)
            || (i != 0 && record.canonical.off < previous_canonical_end)
            || !_n00b_obj_bundle_u64_add(total_moved,
                                         record.canonical.len,
                                         &total_moved)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_elf_descriptor_error(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: ELF split reconstruction record is invalid",
                    descriptor->carrier,
                    _n00b_obj_bundle_i64_detail_from_u64(i),
                    true,
                    allocator));
        }

        for (uint64_t j = 0; j < i; j++) {
            if (_n00b_obj_bundle_ranges_overlap(record.object.off,
                                                record.object.len,
                                                records[j].object.off,
                                                records[j].object.len)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_elf_descriptor_error(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: ELF split object slice overlaps",
                        descriptor->carrier,
                        _n00b_obj_bundle_i64_detail_from_u64(i),
                        true,
                        allocator));
            }
        }

        uint8_t digest[N00B_OBJ_BUNDLE_DIGEST_LEN];

        _n00b_obj_bundle_sha256_bytes(
            (const uint8_t *)object_bytes->data + record.object.off,
            (size_t)record.object.len,
            digest);

        if (memcmp(digest,
                   record.digest,
                   N00B_OBJ_BUNDLE_DIGEST_LEN) != 0) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_elf_descriptor_error(
                    N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH,
                    r"object bundle: ELF split slice digest mismatch",
                    descriptor->carrier,
                    _n00b_obj_bundle_i64_detail_from_u64(record.object.off),
                    true,
                    allocator));
        }

        records[i] = record;
        previous_canonical_end = canonical_end;
    }

    uint64_t reconstructed_len = 0;

    if (!_n00b_obj_bundle_u64_add(descriptor->payload.len,
                                  total_moved,
                                  &reconstructed_len)
        || reconstructed_len > SIZE_MAX) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS,
                r"object bundle: ELF split reconstruction size overflowed",
                descriptor->carrier,
                _n00b_obj_bundle_i64_detail_from_u64(descriptor->payload.len),
                true,
                allocator));
    }

    n00b_writer_t *writer = n00b_writer_new((size_t)reconstructed_len,
                                            .allocator = allocator);
    uint64_t canonical_cursor = 0;
    uint64_t skeleton_cursor  = 0;

    for (uint64_t i = 0; i < descriptor->aux_record_count; i++) {
        n00b_obj_bundle_elf_split_record_t *record = &records[i];
        uint64_t canonical_end = 0;

        if (!_n00b_obj_bundle_range_end(record->canonical.off,
                                        record->canonical.len,
                                        &canonical_end)
            || record->canonical.off < canonical_cursor) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_elf_descriptor_error(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: ELF split reconstruction range is invalid",
                    descriptor->carrier,
                    _n00b_obj_bundle_i64_detail_from_u64(record->canonical.off),
                    true,
                    allocator));
        }

        uint64_t gap_len = record->canonical.off - canonical_cursor;

        if (!_n00b_obj_bundle_range_within(skeleton_cursor,
                                           gap_len,
                                           descriptor->payload.len)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_elf_descriptor_error(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: ELF split skeleton range is invalid",
                    descriptor->carrier,
                    _n00b_obj_bundle_i64_detail_from_u64(skeleton_cursor),
                    true,
                    allocator));
        }

        n00b_writer_write_bytes(writer,
                                skeleton->data + skeleton_cursor,
                                (size_t)gap_len);
        n00b_writer_write_bytes(writer,
                                object_bytes->data + record->object.off,
                                (size_t)record->object.len);

        skeleton_cursor += gap_len;
        canonical_cursor = canonical_end;
    }

    if (canonical_cursor > reconstructed_len) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF split reconstruction length is invalid",
                descriptor->carrier,
                _n00b_obj_bundle_i64_detail_from_u64(canonical_cursor),
                true,
                allocator));
    }

    uint64_t trailing_len = reconstructed_len - canonical_cursor;
    uint64_t skeleton_final = 0;

    if (!_n00b_obj_bundle_range_within(skeleton_cursor,
                                       trailing_len,
                                       descriptor->payload.len)
        || !_n00b_obj_bundle_u64_add(skeleton_cursor,
                                     trailing_len,
                                     &skeleton_final)
        || skeleton_final != descriptor->payload.len) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF split skeleton length is invalid",
                descriptor->carrier,
                _n00b_obj_bundle_i64_detail_from_u64(skeleton_cursor),
                true,
                allocator));
    }

    n00b_writer_write_bytes(writer,
                            skeleton->data + skeleton_cursor,
                            (size_t)trailing_len);
    n00b_writer_setpos(writer, (size_t)reconstructed_len);

    if (n00b_writer_has_error(writer)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF split reconstruction failed",
                descriptor->carrier,
                0,
                false,
                allocator));
    }

    n00b_buffer_t *reconstructed = n00b_writer_finalize(writer);

    // reconstructed is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    auto decoded = n00b_obj_bundle_decode(reconstructed,
                                          .strict = strict,
                                          .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF split reconstruction is malformed",
                descriptor->carrier,
                _n00b_obj_bundle_decode_failure_detail(decoded),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
}

static n00b_result_t(n00b_obj_bundle_t *)
_n00b_obj_bundle_read_elf_metadata_carrier(n00b_buffer_t     *object_bytes,
                                           bool               strict,
                                           n00b_allocator_t  *allocator)
{
    n00b_bstream_t *stream = n00b_bstream_new(object_bytes,
                                              .allocator = allocator);
    auto            parsed = n00b_elf_parse(stream, .allocator = allocator);

    if (n00b_result_is_err(parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF object is malformed",
                N00B_FMT_ELF,
                true,
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                true,
                n00b_result_get_err(parsed),
                true,
                allocator));
    }

    n00b_elf_binary_t  *elf     = n00b_result_get(parsed);
    n00b_elf_section_t *carrier = nullptr;
    size_t              count   = 0;

    for (uint32_t i = 0; i < elf->num_sections; i++) {
        n00b_elf_section_t *section = &elf->sections[i];

        if (!_n00b_obj_bundle_elf_section_is_metadata_carrier(section)) {
            continue;
        }

        count++;

        if (carrier == nullptr) {
            carrier = section;
        }
    }

    if (count == 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier(
                N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND,
                r"object bundle: ELF metadata carrier not found",
                N00B_FMT_ELF,
                true,
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                true,
                allocator));
    }

    if (count > 1) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER,
                r"object bundle: duplicate ELF metadata carriers",
                N00B_FMT_ELF,
                true,
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                true,
                (int64_t)count,
                true,
                allocator));
    }

    if (!_n00b_obj_bundle_elf_carrier_shape_is_valid(carrier)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF metadata carrier has invalid shape",
                N00B_FMT_ELF,
                true,
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                true,
                _n00b_obj_bundle_elf_carrier_shape_detail(carrier),
                true,
                allocator));
    }

    if (_n00b_obj_bundle_elf_descriptor_magic_matches(carrier->content)) {
        auto descriptor = _n00b_obj_bundle_elf_descriptor_decode(
            carrier->content,
            object_bytes,
            allocator);

        if (n00b_result_is_err(descriptor)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            descriptor));
        }

        n00b_obj_bundle_elf_descriptor_t *facts =
            n00b_result_get(descriptor);

        if (facts->carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE) {
            return _n00b_obj_bundle_read_elf_loadable_descriptor(
                object_bytes,
                facts,
                strict,
                allocator);
        }

        if (facts->carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT) {
            return _n00b_obj_bundle_read_elf_split_descriptor(
                object_bytes,
                facts,
                strict,
                allocator);
        }

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_elf_descriptor_error(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER,
                r"object bundle: ELF descriptor carrier read is unsupported",
                facts->carrier,
                (int64_t)facts->carrier,
                true,
                allocator));
    }

    auto decoded = n00b_obj_bundle_decode(carrier->content,
                                          .strict = strict,
                                          .allocator = allocator);

    if (n00b_result_is_err(decoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF metadata carrier payload is malformed",
                N00B_FMT_ELF,
                true,
                N00B_OBJ_BUNDLE_CARRIER_METADATA,
                true,
                _n00b_obj_bundle_decode_failure_detail(decoded),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_elf_metadata_error(n00b_obj_bundle_error_code_t code,
                                    n00b_string_t               *message,
                                    int64_t                      detail,
                                    bool                         has_detail,
                                    n00b_allocator_t            *allocator)
{
    return _n00b_obj_bundle_error_with_format_carrier_detail(
        code,
        message,
        N00B_FMT_ELF,
        true,
        N00B_OBJ_BUNDLE_CARRIER_METADATA,
        true,
        detail,
        has_detail,
        allocator);
}

static n00b_result_t(n00b_elf_binary_t *)
_n00b_obj_bundle_parse_elf_for_write(n00b_buffer_t     *object_bytes,
                                     n00b_allocator_t  *allocator)
{
    n00b_bstream_t *stream = n00b_bstream_new(object_bytes,
                                              .allocator = allocator);
    auto            parsed = n00b_elf_parse(stream, .allocator = allocator);

    if (n00b_result_is_err(parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_elf_binary_t *,
            _n00b_obj_bundle_elf_metadata_error(
                N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                r"object bundle: ELF object is malformed",
                n00b_result_get_err(parsed),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_elf_binary_t *, n00b_result_get(parsed));
}

static n00b_result_t(bool)
_n00b_obj_bundle_validate_elf_write_environment(n00b_elf_binary_t *elf,
                                                n00b_obj_bundle_replace_policy_t replace,
                                                bool strict,
                                                n00b_allocator_t *allocator)
{
    n00b_elf_section_t *bundle_carrier = nullptr;
    size_t              bundle_count   = 0;
    n00b_obj_bundle_carrier_t existing_carrier =
        N00B_OBJ_BUNDLE_CARRIER_METADATA;
    n00b_obj_bundle_error_t *foreign_error = nullptr;
    n00b_obj_bundle_error_t *wrapped_error = nullptr;
    n00b_obj_bundle_error_t *reserved_error = nullptr;
    n00b_obj_bundle_error_t *guard_error = nullptr;

    for (uint32_t i = 0; i < elf->num_sections; i++) {
        n00b_elf_section_t *section = &elf->sections[i];
        int64_t             detail  = (int64_t)i;

        if (_n00b_obj_bundle_elf_section_is_metadata_carrier(section)) {
            bundle_count++;

            if (bundle_carrier == nullptr) {
                bundle_carrier = section;
            }

            continue;
        }

        if (section->type == N00B_OBJ_BUNDLE_ELF_GUARD_SECTION_TYPE) {
            if (guard_error == nullptr) {
                guard_error = _n00b_obj_bundle_elf_metadata_error(
                    N00B_OBJ_BUNDLE_ERR_GUARD_SECTION_PRESENT,
                    r"object bundle: ELF guard section blocks carrier write",
                    section->type,
                    true,
                    allocator);
            }

            continue;
        }

        if (_n00b_obj_bundle_elf_section_is_foreign_legacy(section)) {
            if (foreign_error == nullptr) {
                foreign_error = _n00b_obj_bundle_elf_metadata_error(
                    N00B_OBJ_BUNDLE_ERR_FOREIGN_LEGACY_BUNDLE,
                    r"object bundle: ELF foreign legacy carrier blocks write",
                    detail,
                    true,
                    allocator);
            }

            continue;
        }

        if (_n00b_obj_bundle_elf_section_is_wrapped_or_reserved(section)) {
            if (wrapped_error == nullptr) {
                wrapped_error = _n00b_obj_bundle_elf_metadata_error(
                    N00B_OBJ_BUNDLE_ERR_ALREADY_WRAPPED_OR_RESERVED,
                    r"object bundle: ELF wrapped input blocks carrier write",
                    detail,
                    true,
                    allocator);
            }

            continue;
        }

        if (_n00b_obj_bundle_elf_section_is_unknown_0c001(section)) {
            if (reserved_error == nullptr) {
                reserved_error = _n00b_obj_bundle_elf_metadata_error(
                    N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED,
                    r"object bundle: ELF reserved namespace blocks write",
                    detail,
                    true,
                    allocator);
            }
        }
    }

    if (bundle_count > 1) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_elf_metadata_error(
                N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER,
                r"object bundle: duplicate ELF metadata carriers",
                (int64_t)bundle_count,
                true,
                allocator));
    }

    if (bundle_count == 1) {
        if (!_n00b_obj_bundle_elf_carrier_shape_is_valid(bundle_carrier)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_elf_metadata_error(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: ELF metadata carrier has invalid shape",
                    _n00b_obj_bundle_elf_carrier_shape_detail(bundle_carrier),
                    true,
                    allocator));
        }

        if (_n00b_obj_bundle_elf_descriptor_magic_matches(
                bundle_carrier->content)) {
            auto descriptor = _n00b_obj_bundle_elf_descriptor_decode(
                bundle_carrier->content,
                elf->stream->buf,
                allocator);

            if (n00b_result_is_err(descriptor)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    bool,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                descriptor));
            }

            n00b_obj_bundle_elf_descriptor_t *facts =
                n00b_result_get(descriptor);

            existing_carrier = facts->carrier;

            if (facts->carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE) {
                auto decoded = _n00b_obj_bundle_read_elf_loadable_descriptor(
                    elf->stream->buf,
                    facts,
                    strict,
                    allocator);

                if (n00b_result_is_err(decoded)) {
                    return OBJ_BUNDLE_ERR_PAYLOAD(
                        bool,
                        n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                    decoded));
                }
            }
            else if (facts->carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT) {
                auto decoded = _n00b_obj_bundle_read_elf_split_descriptor(
                    elf->stream->buf,
                    facts,
                    strict,
                    allocator);

                if (n00b_result_is_err(decoded)) {
                    return OBJ_BUNDLE_ERR_PAYLOAD(
                        bool,
                        n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                    decoded));
                }
            }
        }
        else {
            auto decoded = n00b_obj_bundle_decode(bundle_carrier->content,
                                                  .strict = strict,
                                                  .allocator = allocator);

            if (n00b_result_is_err(decoded)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    bool,
                    _n00b_obj_bundle_elf_metadata_error(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: ELF metadata carrier payload is malformed",
                        _n00b_obj_bundle_decode_failure_detail(decoded),
                        true,
                        allocator));
            }
        }
    }

    if (foreign_error != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(bool, foreign_error);
    }

    if (wrapped_error != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(bool, wrapped_error);
    }

    if (reserved_error != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(bool, reserved_error);
    }

    if (guard_error != nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(bool, guard_error);
    }

    if (bundle_count == 1 && replace != N00B_OBJ_BUNDLE_REPLACE_EXISTING) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REPLACE_REQUIRED,
                r"object bundle: ELF carrier replacement is explicit",
                existing_carrier,
                1,
                true,
                allocator));
    }

    return n00b_result_ok(bool, bundle_count == 1);
}

static bool
_n00b_obj_bundle_mask_elf_carrier_for_loadable_rewrite(n00b_elf_binary_t *elf)
{
    if (elf == nullptr) {
        return false;
    }

    for (uint32_t i = 0; i < elf->num_sections; i++) {
        n00b_elf_section_t *section = &elf->sections[i];

        if (_n00b_obj_bundle_elf_section_is_metadata_carrier(section)) {
            /*
             * The selected carrier was already validated. Mask it only in the
             * transient parse tree so generic loadable admission can plan the
             * replacement before the final descriptor rewrite.
             */
            section->name = r".n00b.object-bundle.replacing";
            return true;
        }
    }

    return false;
}

static void
_n00b_obj_bundle_mask_elf_chalk_for_loadable_rewrite(n00b_elf_binary_t *elf)
{
    if (elf == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < elf->num_sections; i++) {
        n00b_elf_section_t *section = &elf->sections[i];

        if (_n00b_obj_bundle_elf_section_is_nonconflicting_chalk(section)) {
            section->name = r".n00b.chalk-preserved";
        }
    }
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_from_rewrite_plan(n00b_elf_rewrite_plan_t *plan,
                                         n00b_allocator_t        *allocator)
{
    if (plan == nullptr) {
        return _n00b_obj_bundle_elf_metadata_error(
            N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
            r"object bundle: ELF rewrite planning failed",
            0,
            false,
            allocator);
    }

    return _n00b_obj_bundle_elf_metadata_error(
        N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
        r"object bundle: ELF rewrite plan was rejected",
        plan->rejection_reason,
        true,
        allocator);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_from_loadable_plan_for_carrier(
    n00b_elf_rewrite_loadable_plan_t *plan,
    n00b_obj_bundle_carrier_t         carrier,
    n00b_allocator_t                 *allocator)
{
    if (plan == nullptr) {
        return _n00b_obj_bundle_elf_carrier_error(
            N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
            r"object bundle: ELF loadable rewrite planning failed",
            carrier,
            0,
            false,
            allocator);
    }

    return _n00b_obj_bundle_elf_carrier_error(
        N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
        r"object bundle: ELF loadable rewrite plan was rejected",
        carrier,
        plan->rejection_reason,
        true,
        allocator);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_error_from_loadable_plan(
    n00b_elf_rewrite_loadable_plan_t *plan,
    n00b_allocator_t                 *allocator)
{
    return _n00b_obj_bundle_error_from_loadable_plan_for_carrier(
        plan,
        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        allocator);
}

static bool
_n00b_obj_bundle_manifest_payload_area(n00b_buffer_t *bundle_bytes,
                                       n00b_obj_bundle_manifest_range_t *range,
                                       n00b_allocator_t *allocator)
{
    if (bundle_bytes == nullptr
        || bundle_bytes->data == nullptr
        || bundle_bytes->byte_len < N00B_OBJ_BUNDLE_HEADER_SIZE) {
        return false;
    }

    n00b_bstream_t *stream = n00b_bstream_new(bundle_bytes,
                                              .allocator = allocator);

    n00b_bstream_set_endian(stream, N00B_ENDIAN_LITTLE);

    return _n00b_obj_bundle_setpos(stream,
                                   N00B_OBJ_BUNDLE_PAYLOAD_AREA_OFF_OFF)
           && _n00b_obj_bundle_read_u64(stream, &range->off)
           && _n00b_obj_bundle_read_u64(stream, &range->len)
           && _n00b_obj_bundle_range_within(range->off,
                                            range->len,
                                            bundle_bytes->byte_len);
}

static bool
_n00b_obj_bundle_host_entrypoint_requested(
    n00b_obj_bundle_host_entrypoint_request_t *entrypoint)
{
    return entrypoint != nullptr
           && entrypoint->entrypoint
                  == N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_host_entrypoint_attach_error(
    n00b_obj_bundle_error_t       *error,
    n00b_obj_bundle_carrier_t      carrier,
    n00b_obj_bundle_artifact_t    *artifact)
{
    error = _n00b_obj_bundle_error_mark_execution(error);

    if (error == nullptr) {
        return nullptr;
    }

    if (!error->has_format) {
        error->format     = N00B_FMT_ELF;
        error->has_format = true;
    }

    error->carrier     = carrier;
    error->has_carrier = true;

    if (!error->has_exec_requested_mode) {
        error->exec_requested_mode     = N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT;
        error->has_exec_requested_mode = true;
    }

    if (artifact != nullptr) {
        if (!error->has_logical_path) {
            error->logical_path     = artifact->logical_path;
            error->has_logical_path = artifact->logical_path != nullptr;
        }

        if (!error->has_artifact_id) {
            error->artifact_id     = artifact->id;
            error->has_artifact_id = true;
        }
    }

    return error;
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_host_entrypoint_rejected_error(
    n00b_obj_bundle_carrier_t                            carrier,
    n00b_obj_bundle_artifact_t                           *artifact,
    n00b_elf_rewrite_host_entrypoint_rejection_reason_t   reason,
    n00b_allocator_t                                     *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(
            N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE,
            r"object bundle: host-entrypoint target is unsupported",
            allocator);

    error->detail                    = (int64_t)reason;
    error->has_detail                = true;
    error->exec_platform_support     =
        N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED;
    error->has_exec_platform_support = true;

    return _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                         carrier,
                                                         artifact);
}

static n00b_obj_bundle_error_t *
_n00b_obj_bundle_host_entrypoint_split_target_error(
    n00b_obj_bundle_artifact_t *artifact,
    n00b_allocator_t          *allocator)
{
    n00b_obj_bundle_error_t *error =
        _n00b_obj_bundle_error_new(
            N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE,
            r"object bundle: host-entrypoint target is not in split loadable payload",
            allocator);

    error->exec_platform_support     =
        N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED;
    error->has_exec_platform_support = true;

    return _n00b_obj_bundle_host_entrypoint_attach_error(
        error,
        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        artifact);
}

static n00b_result_t(n00b_obj_bundle_host_entrypoint_selection_t *)
_n00b_obj_bundle_select_host_entrypoint_target(
    n00b_obj_bundle_t                         *bundle,
    n00b_obj_bundle_host_entrypoint_request_t *entrypoint,
    n00b_obj_bundle_carrier_t                  carrier,
    n00b_allocator_t                          *allocator)
{
    auto valid_artifacts = _n00b_obj_bundle_validate_artifacts(bundle);

    if (n00b_result_is_err(valid_artifacts)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_clone_for_execution(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_artifacts),
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_host_entrypoint_selection_t *,
            _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                          carrier,
                                                          nullptr));
    }

    auto valid_exec = _n00b_obj_bundle_validate_exec_map(bundle);

    if (n00b_result_is_err(valid_exec)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_clone_for_execution(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_exec),
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_host_entrypoint_selection_t *,
            _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                          carrier,
                                                          nullptr));
    }

    auto policy_result =
        _n00b_obj_bundle_select_execution_policy(bundle, allocator);

    if (n00b_result_is_err(policy_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_host_entrypoint_selection_t *,
            _n00b_obj_bundle_host_entrypoint_attach_error(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            policy_result),
                carrier,
                nullptr));
    }

    n00b_obj_bundle_exec_policy_t *policy = n00b_result_get(policy_result);
    n00b_obj_bundle_artifact_t *selected = nullptr;
    n00b_obj_bundle_exec_selection_source_t selection_source =
        N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE;
    n00b_string_t *selector = entrypoint->selector;

    if (selector != nullptr) {
        n00b_obj_bundle_exec_mapping_t *mapping =
            _n00b_obj_bundle_find_mapping_by_selector(bundle, selector);

        if (mapping != nullptr) {
            selected = _n00b_obj_bundle_find_artifact_by_id(
                bundle,
                mapping->target_artifact_id);
            selection_source =
                N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING;

            if (!_n00b_obj_bundle_artifact_is_executable(selected)) {
                n00b_obj_bundle_error_t *error =
                    _n00b_obj_bundle_error_with_artifact(
                        N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: invalid execution mapping target",
                        mapping->target_artifact_id,
                        allocator);

                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_host_entrypoint_selection_t *,
                    _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                                  carrier,
                                                                  selected));
            }

            if ((policy->execution_flags
                 & N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING) == 0) {
                n00b_obj_bundle_error_t *error =
                    _n00b_obj_bundle_exec_policy_denied(
                        policy,
                        r"object bundle: execution selector mapping denied by policy",
                        selector,
                        selected,
                        N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING,
                        allocator);

                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_host_entrypoint_selection_t *,
                    _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                                  carrier,
                                                                  selected));
            }
        }
        else if (entrypoint->strict_selector) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_error_with_path(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: execution selector has no mapping",
                    selector,
                    allocator);

            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_host_entrypoint_selection_t *,
                _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                              carrier,
                                                              nullptr));
        }
    }

    if (selected == nullptr && bundle->has_default_exec) {
        selected = _n00b_obj_bundle_find_artifact_by_id(bundle,
                                                       bundle->default_exec_id);
        selection_source = N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT;

        if (!_n00b_obj_bundle_artifact_is_executable(selected)) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_error_with_artifact(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: invalid default executable target",
                    bundle->default_exec_id,
                    allocator);

            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_host_entrypoint_selection_t *,
                _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                              carrier,
                                                              selected));
        }

        if ((policy->execution_flags
             & N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC) == 0) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_exec_policy_denied(
                    policy,
                    r"object bundle: default execution denied by policy",
                    selected->logical_path,
                    selected,
                    N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC,
                    allocator);

            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_host_entrypoint_selection_t *,
                _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                              carrier,
                                                              selected));
        }
    }

    if (selected == nullptr) {
        n00b_obj_bundle_error_t *error =
            selector == nullptr
                ? _n00b_obj_bundle_error_new(
                      N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                      r"object bundle: no execution target available",
                      allocator)
                : _n00b_obj_bundle_error_with_path(
                      N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                      r"object bundle: execution selector has no fallback target",
                      selector,
                      allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_host_entrypoint_selection_t *,
            _n00b_obj_bundle_host_entrypoint_attach_error(error,
                                                          carrier,
                                                          nullptr));
    }

    auto embedded_policy =
        _n00b_obj_bundle_exec_evaluate_embedded_policy(
            policy,
            selected,
            selection_source,
            true,
            entrypoint->strict_selector,
            N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT,
            entrypoint->policy_mode,
            allocator);

    if (n00b_result_is_err(embedded_policy)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_host_entrypoint_selection_t *,
            _n00b_obj_bundle_host_entrypoint_attach_error(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            embedded_policy),
                carrier,
                selected));
    }

    n00b_obj_bundle_host_entrypoint_selection_t *selection =
        n00b_alloc_with_opts(
            n00b_obj_bundle_host_entrypoint_selection_t,
            &(n00b_alloc_opts_t){.allocator = allocator});

    selection->artifact         = selected;
    selection->selection_source = selection_source;

    return n00b_result_ok(n00b_obj_bundle_host_entrypoint_selection_t *,
                          selection);
}

static n00b_result_t(bool)
_n00b_obj_bundle_encoded_artifact_payload_offset(
    n00b_obj_bundle_t           *bundle,
    n00b_buffer_t               *bundle_bytes,
    n00b_obj_bundle_artifact_t  *selected,
    n00b_obj_bundle_carrier_t    carrier,
    uint64_t                    *offset_out,
    n00b_allocator_t            *allocator)
{
    n00b_obj_bundle_manifest_range_t payload_area = {};

    if (selected == nullptr
        || selected->payload == nullptr
        || !_n00b_obj_bundle_manifest_payload_area(bundle_bytes,
                                                   &payload_area,
                                                   allocator)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_host_entrypoint_attach_error(
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: host-entrypoint payload facts are unavailable",
                    carrier,
                    0,
                    false,
                    allocator),
                carrier,
                selected));
    }

    size_t artifact_count = n00b_list_len(bundle->artifacts);
    n00b_obj_bundle_encode_artifact_t *artifacts =
        n00b_alloc_array(n00b_obj_bundle_encode_artifact_t, artifact_count);

    for (size_t i = 0; i < artifact_count; i++) {
        artifacts[i].artifact = n00b_list_get(bundle->artifacts, i);
    }

    qsort(artifacts,
          artifact_count,
          sizeof(artifacts[0]),
          _n00b_obj_bundle_encode_artifact_cmp);

    uint64_t payload_cursor = 0;

    for (size_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_artifact_t *artifact = artifacts[i].artifact;

        if (artifact->payload == nullptr) {
            continue;
        }

        uint64_t canonical_off = 0;

        if (!_n00b_obj_bundle_u64_add(payload_area.off,
                                      payload_cursor,
                                      &canonical_off)
            || !_n00b_obj_bundle_range_within(
                canonical_off,
                artifact->payload->byte_len,
                bundle_bytes->byte_len)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_host_entrypoint_attach_error(
                    _n00b_obj_bundle_elf_carrier_error(
                        N00B_OBJ_BUNDLE_ERR_BUILD,
                        r"object bundle: host-entrypoint payload range is invalid",
                        carrier,
                        _n00b_obj_bundle_i64_detail_from_u64(payload_cursor),
                        true,
                        allocator),
                    carrier,
                    selected));
        }

        if (artifact == selected) {
            *offset_out = canonical_off;
            return n00b_result_ok(bool, true);
        }

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      artifact->payload->byte_len,
                                      &payload_cursor)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                bool,
                _n00b_obj_bundle_host_entrypoint_attach_error(
                    _n00b_obj_bundle_elf_carrier_error(
                        N00B_OBJ_BUNDLE_ERR_BUILD,
                        r"object bundle: host-entrypoint payload cursor overflowed",
                        carrier,
                        _n00b_obj_bundle_i64_detail_from_u64(payload_cursor),
                        true,
                        allocator),
                    carrier,
                    selected));
        }
    }

    return OBJ_BUNDLE_ERR_PAYLOAD(
        bool,
        _n00b_obj_bundle_host_entrypoint_attach_error(
            _n00b_obj_bundle_error_with_artifact(
                N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                r"object bundle: selected entrypoint payload was not encoded",
                selected->id,
                allocator),
            carrier,
            selected));
}

static n00b_result_t(bool)
_n00b_obj_bundle_enable_host_entrypoint(
    n00b_elf_binary_t                         *elf,
    n00b_elf_rewrite_loadable_plan_t          *plan,
    n00b_obj_bundle_carrier_t                  carrier,
    n00b_obj_bundle_artifact_t                *selected,
    uint64_t                                   target_payload_offset,
    uint64_t                                   target_size,
    n00b_allocator_t                          *allocator)
{
    auto target_result =
        n00b_elf_rewrite_plan_host_entrypoint_target(
            elf,
            plan,
            target_payload_offset,
            target_size);

    if (n00b_result_is_err(target_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_host_entrypoint_attach_error(
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                    r"object bundle: ELF host-entrypoint planning failed",
                    carrier,
                    n00b_result_get_err(target_result),
                    true,
                    allocator),
                carrier,
                selected));
    }

    n00b_elf_rewrite_host_entrypoint_target_t target =
        n00b_result_get(target_result);

    if (target.outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_host_entrypoint_rejected_error(
                carrier,
                selected,
                target.rejection_reason,
                allocator));
    }

    auto enabled = n00b_elf_rewrite_loadable_plan_enable_entrypoint(
        plan,
        target.replacement_entrypoint);

    if (n00b_result_is_err(enabled)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            bool,
            _n00b_obj_bundle_host_entrypoint_attach_error(
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                    r"object bundle: ELF entrypoint patch enable failed",
                    carrier,
                    n00b_result_get_err(enabled),
                    true,
                    allocator),
                carrier,
                selected));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_build_elf_split_payloads(
    n00b_obj_bundle_t                  *bundle,
    n00b_buffer_t                      *bundle_bytes,
    n00b_obj_bundle_elf_split_range_t **ranges_out,
    size_t                             *range_count_out,
    n00b_buffer_t                     **skeleton_out,
    n00b_allocator_t                   *allocator)
{
    *ranges_out       = nullptr;
    *range_count_out  = 0;
    *skeleton_out     = nullptr;

    n00b_obj_bundle_manifest_range_t payload_area = {};

    if (!_n00b_obj_bundle_manifest_payload_area(bundle_bytes,
                                                &payload_area,
                                                allocator)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: split payload-area facts are unavailable",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    size_t artifact_count = n00b_list_len(bundle->artifacts);

    if (artifact_count == 0) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER,
                r"object bundle: split carrier has no movable payloads",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    n00b_obj_bundle_encode_artifact_t *artifacts =
        n00b_alloc_array(n00b_obj_bundle_encode_artifact_t, artifact_count);
    n00b_obj_bundle_elf_split_range_t *ranges =
        n00b_alloc_array(n00b_obj_bundle_elf_split_range_t, artifact_count);

    for (size_t i = 0; i < artifact_count; i++) {
        artifacts[i].artifact = n00b_list_get(bundle->artifacts, i);
    }

    qsort(artifacts,
          artifact_count,
          sizeof(artifacts[0]),
          _n00b_obj_bundle_encode_artifact_cmp);

    uint64_t payload_cursor  = 0;
    uint64_t loadable_cursor = 0;
    size_t   selected_count  = 0;

    for (size_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_artifact_t *artifact = artifacts[i].artifact;

        if (artifact->payload == nullptr) {
            continue;
        }

        uint64_t payload_len = artifact->payload->byte_len;
        uint64_t canonical_off = 0;

        if (!_n00b_obj_bundle_u64_add(payload_area.off,
                                      payload_cursor,
                                      &canonical_off)
            || !_n00b_obj_bundle_range_within(canonical_off,
                                              payload_len,
                                              bundle_bytes->byte_len)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: split payload range is invalid",
                    N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                    _n00b_obj_bundle_i64_detail_from_u64(payload_cursor),
                    true,
                    allocator));
        }

        if (_n00b_obj_bundle_artifact_is_executable(artifact)
            && payload_len != 0) {
            n00b_obj_bundle_elf_split_range_t *range =
                &ranges[selected_count++];

            range->canonical = (n00b_obj_bundle_manifest_range_t){
                .off = canonical_off,
                .len = payload_len,
            };
            range->artifact_id = artifact->id;
            range->loadable_payload_off = loadable_cursor;
            _n00b_obj_bundle_sha256_bytes(
                (const uint8_t *)bundle_bytes->data + canonical_off,
                (size_t)payload_len,
                range->digest);

            if (!_n00b_obj_bundle_u64_add(loadable_cursor,
                                          payload_len,
                                          &loadable_cursor)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    _n00b_obj_bundle_elf_carrier_error(
                        N00B_OBJ_BUNDLE_ERR_BUILD,
                        r"object bundle: split loadable payload is too large",
                        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                        _n00b_obj_bundle_i64_detail_from_u64(loadable_cursor),
                        true,
                        allocator));
            }
        }

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      payload_len,
                                      &payload_cursor)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: split payload cursor overflowed",
                    N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                    _n00b_obj_bundle_i64_detail_from_u64(payload_cursor),
                    true,
                    allocator));
        }
    }

    if (selected_count == 0 || loadable_cursor == 0
        || loadable_cursor > bundle_bytes->byte_len
        || loadable_cursor > INT64_MAX) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER,
                r"object bundle: split carrier has no movable payloads",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    uint64_t skeleton_len = bundle_bytes->byte_len - loadable_cursor;

    if (skeleton_len > SIZE_MAX) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: split skeleton payload is too large",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                _n00b_obj_bundle_i64_detail_from_u64(skeleton_len),
                true,
                allocator));
    }

    n00b_writer_t *skeleton_writer =
        n00b_writer_new((size_t)skeleton_len, .allocator = allocator);
    uint64_t canonical_cursor = 0;

    for (size_t i = 0; i < selected_count; i++) {
        n00b_obj_bundle_elf_split_range_t *range = &ranges[i];
        uint64_t canonical_end = 0;

        if (!_n00b_obj_bundle_range_end(range->canonical.off,
                                        range->canonical.len,
                                        &canonical_end)
            || range->canonical.off < canonical_cursor) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: split skeleton range is invalid",
                    N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                    _n00b_obj_bundle_i64_detail_from_u64(
                        range->canonical.off),
                    true,
                    allocator));
        }

        uint64_t gap_len = range->canonical.off - canonical_cursor;

        n00b_writer_write_bytes(skeleton_writer,
                                bundle_bytes->data + canonical_cursor,
                                (size_t)gap_len);

        canonical_cursor = canonical_end;
    }

    uint64_t trailing_len = bundle_bytes->byte_len - canonical_cursor;

    n00b_writer_write_bytes(skeleton_writer,
                            bundle_bytes->data + canonical_cursor,
                            (size_t)trailing_len);
    n00b_writer_setpos(skeleton_writer, (size_t)skeleton_len);

    if (n00b_writer_has_error(skeleton_writer)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: split skeleton payload build failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    n00b_buffer_t *skeleton = n00b_writer_finalize(skeleton_writer);

    // skeleton is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    // The loadable payload also escapes this function (returned alongside the
    // skeleton), so it must be on the caller's allocator too — otherwise the two
    // outputs would be a cross-arena pair (NFR-05). Forward .allocator (no
    // re-home copy was ever present here).
    n00b_writer_t *writer = n00b_writer_new((size_t)loadable_cursor,
                                            .allocator = allocator);

    for (size_t i = 0; i < selected_count; i++) {
        n00b_obj_bundle_elf_split_range_t *range = &ranges[i];

        n00b_writer_write_bytes(writer,
                                bundle_bytes->data + range->canonical.off,
                                (size_t)range->canonical.len);
    }

    n00b_writer_setpos(writer, (size_t)loadable_cursor);

    if (n00b_writer_has_error(writer)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: split loadable payload build failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    *ranges_out      = ranges;
    *range_count_out = selected_count;
    *skeleton_out    = skeleton;
    return n00b_result_ok(n00b_buffer_t *, n00b_writer_finalize(writer));
}

static n00b_buffer_t *
_n00b_obj_bundle_build_elf_split_aux(
    n00b_obj_bundle_elf_split_range_t *ranges,
    size_t                             range_count,
    uint64_t                           loadable_file_off,
    n00b_allocator_t                  *allocator)
{
    uint64_t aux_len = 0;

    if (!_n00b_obj_bundle_u64_mul((uint64_t)range_count,
                                  N00B_OBJ_BUNDLE_ELF_SPLIT_REC_SIZE,
                                  &aux_len)
        || aux_len > SIZE_MAX) {
        return nullptr;
    }

    n00b_writer_t *writer =
        n00b_writer_new((size_t)aux_len, .allocator = allocator);

    n00b_writer_set_endian(writer, N00B_ENDIAN_LITTLE);

    for (size_t i = 0; i < range_count; i++) {
        n00b_obj_bundle_elf_split_range_t *range = &ranges[i];
        uint64_t object_off = 0;

        if (!_n00b_obj_bundle_u64_add(loadable_file_off,
                                      range->loadable_payload_off,
                                      &object_off)) {
            return nullptr;
        }

        n00b_obj_bundle_elf_split_record_t record = {
            .canonical = range->canonical,
            .object = {
                .off = object_off,
                .len = range->canonical.len,
            },
        };

        memcpy(record.digest, range->digest, N00B_OBJ_BUNDLE_DIGEST_LEN);
        _n00b_obj_bundle_elf_split_record_write(writer, &record);
    }

    if (n00b_writer_has_error(writer)) {
        return nullptr;
    }

    n00b_buffer_t *aux = n00b_writer_finalize(writer);

    // aux is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    return aux;
}

static n00b_buffer_t *
_n00b_obj_bundle_build_elf_split_descriptor_payload(
    n00b_buffer_t     *skeleton,
    n00b_buffer_t     *aux,
    n00b_allocator_t  *allocator)
{
    uint64_t body_len = 0;
    uint64_t total_len = 0;

    if (!_n00b_obj_bundle_u64_add(skeleton->byte_len,
                                  aux->byte_len,
                                  &body_len)
        || !_n00b_obj_bundle_u64_add(
               N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE,
               body_len,
               &total_len)
        || total_len > INT64_MAX) {
        return nullptr;
    }

    n00b_writer_t *writer = n00b_writer_new((size_t)total_len,
                                            .allocator = allocator);

    n00b_writer_write_zeros(writer,
                            N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE);
    n00b_writer_write_bytes(writer, skeleton->data, skeleton->byte_len);
    n00b_writer_write_bytes(writer, aux->data, aux->byte_len);
    n00b_writer_setpos(writer, (size_t)total_len);

    if (n00b_writer_has_error(writer)) {
        return nullptr;
    }

    n00b_buffer_t *payload = n00b_writer_finalize(writer);

    // payload is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    return payload;
}

// ============================================================================
// Mach-O SPLIT carrier planning (WP-010 Phase 1; D-040 true excised split).
//
// These three file-local statics live in obj_bundle.c (not obj_bundle_macho.c)
// because they must read the opaque `n00b_obj_bundle` / `n00b_obj_bundle_artifact`
// structs and the file-private artifact-ordering helpers
// (`_n00b_obj_bundle_encode_artifact_cmp`, `_n00b_obj_bundle_manifest_payload_area`,
// `_n00b_obj_bundle_u64_add`, `_n00b_obj_bundle_range_within`) that are defined
// only in this translation unit — exactly the reason the ELF split internals
// live here too (D-040 Consequences). The Mach-O write_carrier SPLIT arm (in
// obj_bundle_macho.c) lays the slices-only payload into the LC_SEGMENT_64 and
// writes the descriptor (header + skeleton + records) into the carrier LC_NOTE;
// it does not re-derive records.
//
// Excised-split model (D-040, literal ELF mirror): the SPLIT segment payload is
// the executable-compatible artifact slices ONLY, concatenated in deterministic
// order: `[slice0][slice1]…`. Each slice record's `slice_payload_offset` is its
// offset within that slices-only payload, `reconstruct_offset` is the slice's
// canonical offset, and `slice_digest_crc` is the §4.1 CRC-32 fast pre-check.
// The excised SKELETON = the canonical bundle with the slice ranges removed
// (concatenated gaps + trailing) is stored in the carrier LC_NOTE trailer — NOT
// in the segment, and there is NO skeleton record. SPLIT requires ≥1 executable
// slice (else Err UNSUPPORTED_CARRIER, mirroring the ELF "no movable payloads"
// path). The authoritative integrity gate remains the bundle-level SHA-256 over
// the reconstructed bytes; the per-slice CRC is only a cheap pre-check.

// Build the SPLIT payloads from the canonical bundle: the slices-only segment
// payload (returned), the per-executable-slice records (selected and ordered
// exactly as the ELF split path does, for byte-identical determinism — each with
// a slice_digest_crc = n00b_crc32 over the slice bytes), and the excised skeleton
// = canonical − slices (concatenated gaps). Requires ≥1 executable slice. Returns
// Ok(segment_payload) with *records_out/*count_out/*skeleton_out set, or a
// structured N00B_MACHO_CARRIER_ERR_* on overflow/out-of-range/no-executable
// (never UB).
static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_macho_build_split_payloads(
    n00b_obj_bundle_t                  *bundle,
    n00b_buffer_t                      *canonical_bundle,
    n00b_macho_carrier_split_record_t **records_out,
    uint64_t                           *count_out,
    n00b_buffer_t                     **skeleton_out,
    n00b_allocator_t                   *allocator)
{
    *records_out  = nullptr;
    *count_out    = 0;
    *skeleton_out = nullptr;

    uint64_t canonical_len = (uint64_t)canonical_bundle->byte_len;

    n00b_obj_bundle_manifest_range_t payload_area = {};

    if (!_n00b_obj_bundle_manifest_payload_area(canonical_bundle,
                                                &payload_area,
                                                allocator)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    size_t artifact_count = n00b_list_len(bundle->artifacts);

    if (artifact_count == 0) {
        // No artifacts ⇒ no executable slices ⇒ SPLIT unavailable (D-040).
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER);
    }

    n00b_obj_bundle_encode_artifact_t *artifacts =
        n00b_alloc_array(n00b_obj_bundle_encode_artifact_t,
                         artifact_count,
                         .allocator = allocator);

    for (size_t i = 0; i < artifact_count; i++) {
        artifacts[i].artifact = n00b_list_get(bundle->artifacts, i);
    }

    // Deterministic ordering (FR determinism 01:135): reuse the ELF encode
    // artifact comparator so the slice order is byte-identical to the ELF split
    // path and stable across runs.
    qsort(artifacts,
          artifact_count,
          sizeof(artifacts[0]),
          _n00b_obj_bundle_encode_artifact_cmp);

    n00b_macho_carrier_split_record_t *records =
        n00b_alloc_array(n00b_macho_carrier_split_record_t,
                         artifact_count,
                         .allocator = allocator);

    uint64_t record_count  = 0;
    uint64_t payload_cursor = 0; // walks every artifact payload in canonical
    uint64_t slice_cursor   = 0; // offset within the slices-only segment payload

    for (size_t i = 0; i < artifact_count; i++) {
        n00b_obj_bundle_artifact_t *artifact = artifacts[i].artifact;

        if (artifact->payload == nullptr) {
            continue;
        }

        uint64_t payload_len   = (uint64_t)artifact->payload->byte_len;
        uint64_t canonical_off = 0;

        // canonical offset of this artifact payload = payload_area.off + cursor
        // (same layout the ELF split path walks). Range-check it against the
        // canonical bundle; never UB on overflow/out-of-range.
        if (!_n00b_obj_bundle_u64_add(payload_area.off,
                                      payload_cursor,
                                      &canonical_off)
            || !_n00b_obj_bundle_range_within(canonical_off,
                                              payload_len,
                                              canonical_len)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        if (_n00b_obj_bundle_artifact_is_executable(artifact)
            && payload_len != 0) {
            records[record_count] = (n00b_macho_carrier_split_record_t){
                .slice_payload_offset = slice_cursor,
                .slice_len            = payload_len,
                .reconstruct_offset   = canonical_off,
                .artifact_id          = artifact->id,
                .slice_flags          = 0,
                .pad                  = 0,
                .slice_digest_crc     = n00b_crc32(
                    (const uint8_t *)canonical_bundle->data + canonical_off,
                    (size_t)payload_len),
                .pad2                 = 0,
            };
            record_count++;

            if (!_n00b_obj_bundle_u64_add(slice_cursor,
                                          payload_len,
                                          &slice_cursor)) {
                return n00b_result_err(n00b_buffer_t *,
                                       N00B_MACHO_CARRIER_ERR_BOUNDS);
            }
        }

        if (!_n00b_obj_bundle_u64_add(payload_cursor,
                                      payload_len,
                                      &payload_cursor)) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }
    }

    // D-040: SPLIT requires ≥1 executable slice (mirror the ELF "no movable
    // payloads" UNSUPPORTED_CARRIER path; surfaced to the neutral core as a
    // structured carrier error). slice_cursor is the slices-only payload length.
    if (record_count == 0 || slice_cursor == 0 || slice_cursor > canonical_len
        || slice_cursor > INT64_MAX) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_UNSUPPORTED_CARRIER);
    }

    uint64_t slices_len  = slice_cursor;
    uint64_t skeleton_len = canonical_len - slices_len;

    if (skeleton_len > INT64_MAX) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    // Build the excised skeleton = canonical with the slice ranges removed
    // (concatenated gaps + trailing), exactly as _build_elf_split_payloads does.
    // Records are in deterministic (comparator) order, but the skeleton must be
    // assembled in canonical (reconstruct_offset) order; the comparator orders by
    // canonical layout, so records are already canonical-ascending here.
    n00b_writer_t *skeleton_writer = n00b_writer_new((size_t)skeleton_len,
                                                     .allocator = allocator);
    uint64_t       canonical_cursor = 0;

    for (uint64_t i = 0; i < record_count; i++) {
        n00b_macho_carrier_split_record_t *rec = &records[i];
        uint64_t canonical_end = 0;

        if (!_n00b_obj_bundle_range_end(rec->reconstruct_offset,
                                        rec->slice_len,
                                        &canonical_end)
            || rec->reconstruct_offset < canonical_cursor) {
            return n00b_result_err(n00b_buffer_t *,
                                   N00B_MACHO_CARRIER_ERR_BOUNDS);
        }

        uint64_t gap_len = rec->reconstruct_offset - canonical_cursor;

        n00b_writer_write_bytes(skeleton_writer,
                                canonical_bundle->data + canonical_cursor,
                                (size_t)gap_len);

        canonical_cursor = canonical_end;
    }

    uint64_t trailing_len = canonical_len - canonical_cursor;

    n00b_writer_write_bytes(skeleton_writer,
                            canonical_bundle->data + canonical_cursor,
                            (size_t)trailing_len);
    n00b_writer_setpos(skeleton_writer, (size_t)skeleton_len);

    if (n00b_writer_has_error(skeleton_writer)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    n00b_buffer_t *skeleton = n00b_writer_finalize(skeleton_writer);

    // skeleton is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    // Build the slices-only segment payload: [slice0][slice1]… in record order.
    n00b_writer_t *slice_writer = n00b_writer_new((size_t)slices_len,
                                                  .allocator = allocator);

    for (uint64_t i = 0; i < record_count; i++) {
        n00b_macho_carrier_split_record_t *rec = &records[i];

        n00b_writer_write_bytes(slice_writer,
                                canonical_bundle->data + rec->reconstruct_offset,
                                (size_t)rec->slice_len);
    }

    n00b_writer_setpos(slice_writer, (size_t)slices_len);

    if (n00b_writer_has_error(slice_writer)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_CARRIER_ERR_BOUNDS);
    }

    n00b_buffer_t *segment_payload = n00b_writer_finalize(slice_writer);

    // segment_payload is already allocator-owned (writer forwarded .allocator;
    // zero-copy, DF-007-01).

    *records_out  = records;
    *count_out    = record_count;
    *skeleton_out = skeleton;
    return n00b_result_ok(n00b_buffer_t *, segment_payload);
}

// Assemble the SPLIT descriptor: kind/version, payload_len over the slices-only
// segment payload, the excised skeleton blob, the records array, and the
// segment-level SHA-256 payload_digest (over the slices-only payload — the same
// serializer the read side / verify_digest uses, so they cannot diverge).
// payload_file_offset is left 0 here; the write_carrier arm sets it to the
// planned LC_SEGMENT_64 file offset.
static n00b_result_t(n00b_macho_carrier_descriptor_t *)
_n00b_obj_bundle_macho_build_split_descriptor(
    n00b_buffer_t                     *segment_payload,
    n00b_buffer_t                     *skeleton,
    n00b_macho_carrier_split_record_t *records,
    uint64_t                           record_count,
    n00b_allocator_t                  *allocator)
{
    n00b_macho_carrier_descriptor_t *desc =
        n00b_alloc(n00b_macho_carrier_descriptor_t, .allocator = allocator);

    desc->kind                = N00B_MACHO_CARRIER_KIND_SPLIT;
    desc->version_major       = N00B_MACHO_CARRIER_MAJOR;
    desc->version_minor       = N00B_MACHO_CARRIER_MINOR;
    desc->payload_file_offset = 0; // set by write_carrier to the segment offset
    desc->payload_len         = (uint64_t)segment_payload->byte_len;
    desc->skeleton            = skeleton;
    desc->skeleton_len        = (uint64_t)skeleton->byte_len;
    desc->records             = records;
    desc->record_count        = record_count;

    n00b_macho_carrier_compute_digest(segment_payload, desc->payload_digest);

    return n00b_result_ok(n00b_macho_carrier_descriptor_t *, desc);
}

n00b_result_t(n00b_macho_carrier_descriptor_t *)
_n00b_obj_bundle_macho_plan_split(
    n00b_obj_bundle_t *bundle,
    n00b_buffer_t     *canonical_bundle) _kargs {
    n00b_buffer_t   **segment_payload_out = nullptr;
    n00b_allocator_t *allocator           = nullptr;
}
    requires {
        // D-031: bundle/canonical_bundle/byte_len are DOCUMENTED-Err inputs
        // (body-guarded → Err(NULL_INPUT) below), so they are NOT trapping
        // requires. Only `segment_payload_out` is a genuine internal precondition
        // (the caller MUST supply the out-slot) → trapping requires.
        segment_payload_out != nullptr;
    }
    ensures {
        // Guarded by success (D-028): on Err, result.ok is null.
        !result.is_ok
            || (result.ok != nullptr
                && result.ok->kind == N00B_MACHO_CARRIER_KIND_SPLIT
                && result.ok->record_count >= 1
                && result.ok->skeleton != nullptr);
    }
{
    // Release-path guard for the documented-Err inputs (D-031): null/
    // empty user inputs are Err returns, so guard rather than trap.
    if (bundle == nullptr || canonical_bundle == nullptr
        || canonical_bundle->byte_len == 0) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               N00B_MACHO_CARRIER_ERR_NULL_INPUT);
    }

    n00b_macho_carrier_split_record_t *records      = nullptr;
    uint64_t                           record_count = 0;
    n00b_buffer_t                     *skeleton     = nullptr;

    auto payloads = _n00b_obj_bundle_macho_build_split_payloads(
        bundle,
        canonical_bundle,
        &records,
        &record_count,
        &skeleton,
        allocator);

    if (n00b_result_is_err(payloads)) {
        return n00b_result_err(n00b_macho_carrier_descriptor_t *,
                               n00b_result_get_err(payloads));
    }

    n00b_buffer_t *segment_payload = n00b_result_get(payloads);

    auto descriptor = _n00b_obj_bundle_macho_build_split_descriptor(
        segment_payload,
        skeleton,
        records,
        record_count,
        allocator);

    if (n00b_result_is_ok(descriptor)) {
        *segment_payload_out = segment_payload;
    }

    return descriptor;
}

static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_write_elf_metadata_payload(
    n00b_buffer_t                    *object_bytes,
    n00b_buffer_t                    *payload,
    n00b_obj_bundle_replace_policy_t  replace,
    bool                              strict,
    n00b_allocator_t                 *allocator)
{
    auto parsed = _n00b_obj_bundle_parse_elf_for_write(object_bytes, allocator);

    if (n00b_result_is_err(parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, parsed));
    }

    n00b_elf_binary_t *elf = n00b_result_get(parsed);
    auto environment =
        _n00b_obj_bundle_validate_elf_write_environment(elf,
                                                        replace,
                                                        strict,
                                                        allocator);

    if (n00b_result_is_err(environment)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        environment));
    }

    n00b_elf_rewrite_metadata_request_t request = {
        .section_name          = r".0c001.bundle",
        .payload               = payload,
        .file_alignment        = 8,
        .section_type          = SHT_PROGBITS,
        .section_flags         = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy                = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };

    bool has_existing_bundle = n00b_result_get(environment);
    auto plan_result =
        has_existing_bundle && replace == N00B_OBJ_BUNDLE_REPLACE_EXISTING
            ? n00b_elf_rewrite_plan_object_bundle_replace(
                  elf,
                  &request,
                  .allocator = allocator)
            : n00b_elf_rewrite_plan_object_bundle_insert(
                  elf,
                  &request,
                  .allocator = allocator);

    if (n00b_result_is_err(plan_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_metadata_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF rewrite planning failed",
                n00b_result_get_err(plan_result),
                true,
                allocator));
    }

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_from_rewrite_plan(plan, allocator));
    }

    auto applied = n00b_elf_rewrite_apply_object_bundle_plan(
        elf,
        plan,
        .allocator = allocator);

    if (n00b_result_is_err(applied)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_metadata_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF rewrite apply failed",
                n00b_result_get_err(applied),
                true,
                allocator));
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(applied));
}

static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_write_elf_metadata_carrier(
    n00b_buffer_t                    *object_bytes,
    n00b_obj_bundle_t                *bundle,
    n00b_obj_bundle_replace_policy_t  replace,
    bool                              strict,
    n00b_allocator_t                 *allocator)
{
    auto encoded = n00b_obj_bundle_encode(bundle, .allocator = allocator);

    if (n00b_result_is_err(encoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, encoded));
    }

    return _n00b_obj_bundle_write_elf_metadata_payload(
        object_bytes,
        n00b_result_get(encoded),
        replace,
        strict,
        allocator);
}

static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_write_elf_loadable_carrier(
    n00b_buffer_t                              *object_bytes,
    n00b_obj_bundle_t                          *bundle,
    n00b_obj_bundle_replace_policy_t            replace,
    bool                                        strict,
    n00b_obj_bundle_host_entrypoint_request_t  *entrypoint,
    n00b_allocator_t                           *allocator)
{
    auto encoded = n00b_obj_bundle_encode(bundle, .allocator = allocator);

    if (n00b_result_is_err(encoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, encoded));
    }

    n00b_buffer_t *bundle_bytes = n00b_result_get(encoded);
    auto parsed = _n00b_obj_bundle_parse_elf_for_write(object_bytes,
                                                       allocator);

    if (n00b_result_is_err(parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, parsed));
    }

    n00b_elf_binary_t *elf = n00b_result_get(parsed);
    auto environment = _n00b_obj_bundle_validate_elf_write_environment(
        elf,
        replace,
        strict,
        allocator);

    if (n00b_result_is_err(environment)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        environment));
    }

    bool has_existing_bundle = n00b_result_get(environment);
    uint64_t loadable_policy_flags =
        N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
      | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY;

    if (has_existing_bundle) {
        loadable_policy_flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;

        if (!_n00b_obj_bundle_mask_elf_carrier_for_loadable_rewrite(elf)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: ELF loadable replacement carrier was not found",
                    N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                    0,
                    false,
                    allocator));
        }
    }

    _n00b_obj_bundle_mask_elf_chalk_for_loadable_rewrite(elf);

    n00b_elf_rewrite_loadable_request_t request = {
        .payload          = bundle_bytes,
        .segment_flags    = PF_R | PF_X,
        .file_alignment   = 8,
        .vaddr_alignment  = 0x1000,
        .p_memsz          = bundle_bytes->byte_len,
        .phtab_strategy   = has_existing_bundle
            ? N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE
            : N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .policy           = {
            .flags = loadable_policy_flags,
        },
    };

    auto plan_result = n00b_elf_rewrite_plan_loadable_insert(
        elf,
        &request,
        .allocator = allocator);

    if (n00b_result_is_err(plan_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF loadable rewrite planning failed",
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                n00b_result_get_err(plan_result),
                true,
                allocator));
    }

    n00b_elf_rewrite_loadable_plan_t *plan = n00b_result_get(plan_result);

    if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_from_loadable_plan(plan, allocator));
    }

    if (_n00b_obj_bundle_host_entrypoint_requested(entrypoint)) {
        auto selection_result =
            _n00b_obj_bundle_select_host_entrypoint_target(
                bundle,
                entrypoint,
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                allocator);

        if (n00b_result_is_err(selection_result)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            selection_result));
        }

        n00b_obj_bundle_host_entrypoint_selection_t *selection =
            n00b_result_get(selection_result);
        uint64_t target_payload_offset = 0;
        auto     offset_result =
            _n00b_obj_bundle_encoded_artifact_payload_offset(
                bundle,
                bundle_bytes,
                selection->artifact,
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                &target_payload_offset,
                allocator);

        if (n00b_result_is_err(offset_result)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            offset_result));
        }

        auto entrypoint_result =
            _n00b_obj_bundle_enable_host_entrypoint(
                elf,
                plan,
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                selection->artifact,
                target_payload_offset,
                selection->artifact->payload->byte_len,
                allocator);

        if (n00b_result_is_err(entrypoint_result)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            entrypoint_result));
        }
    }

    auto loadable_applied = n00b_elf_rewrite_apply_loadable_insert_plan(
        elf,
        plan,
        .allocator = allocator);

    if (n00b_result_is_err(loadable_applied)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF loadable rewrite apply failed",
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                n00b_result_get_err(loadable_applied),
                true,
                allocator));
    }

    uint8_t payload_digest[N00B_OBJ_BUNDLE_DIGEST_LEN] = {};

    _n00b_obj_bundle_sha256_bytes(bundle_bytes->data,
                                  bundle_bytes->byte_len,
                                  payload_digest);

    n00b_obj_bundle_elf_descriptor_t descriptor = {
        .carrier    = N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
        .major      = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAJOR,
        .minor      = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MINOR,
        .header_size = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE,
        .flags      = 0,
        .payload    = {
            .off = plan->payload_placement.file_offset,
            .len = bundle_bytes->byte_len,
        },
        .aux = {},
        .aux_record_count = 0,
        .reserved0 = 0,
        .reserved1 = 0,
    };

    memcpy(descriptor.payload_digest,
           payload_digest,
           N00B_OBJ_BUNDLE_DIGEST_LEN);

    n00b_buffer_t *descriptor_payload =
        _n00b_obj_bundle_elf_descriptor_encode(&descriptor, allocator);

    if (descriptor_payload == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: ELF loadable descriptor build failed",
                N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                0,
                false,
                allocator));
    }

    auto descriptor_applied = _n00b_obj_bundle_write_elf_metadata_payload(
        n00b_result_get(loadable_applied),
        descriptor_payload,
        replace,
        strict,
        allocator);

    if (n00b_result_is_err(descriptor_applied)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        descriptor_applied));
    }

    n00b_buffer_t *final_bytes = n00b_result_get(descriptor_applied);
    auto           readback =
        _n00b_obj_bundle_read_elf_metadata_carrier(final_bytes,
                                                   strict,
                                                   allocator);

    if (n00b_result_is_err(readback)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        readback));
    }

    return n00b_result_ok(n00b_buffer_t *, final_bytes);
}

static n00b_result_t(n00b_buffer_t *)
_n00b_obj_bundle_write_elf_split_carrier(
    n00b_buffer_t                              *object_bytes,
    n00b_obj_bundle_t                          *bundle,
    n00b_obj_bundle_replace_policy_t            replace,
    bool                                        strict,
    n00b_obj_bundle_host_entrypoint_request_t  *entrypoint,
    n00b_allocator_t                           *allocator)
{
    auto encoded = n00b_obj_bundle_encode(bundle, .allocator = allocator);

    if (n00b_result_is_err(encoded)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, encoded));
    }

    n00b_buffer_t *bundle_bytes = n00b_result_get(encoded);
    n00b_obj_bundle_elf_split_range_t *ranges = nullptr;
    size_t range_count = 0;
    n00b_buffer_t *skeleton = nullptr;
    auto split_payload = _n00b_obj_bundle_build_elf_split_payloads(
        bundle,
        bundle_bytes,
        &ranges,
        &range_count,
        &skeleton,
        allocator);

    if (n00b_result_is_err(split_payload)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        split_payload));
    }

    n00b_buffer_t *loadable_payload = n00b_result_get(split_payload);
    auto parsed = _n00b_obj_bundle_parse_elf_for_write(object_bytes,
                                                       allocator);

    if (n00b_result_is_err(parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *, parsed));
    }

    n00b_elf_binary_t *elf = n00b_result_get(parsed);
    auto environment = _n00b_obj_bundle_validate_elf_write_environment(
        elf,
        replace,
        strict,
        allocator);

    if (n00b_result_is_err(environment)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        environment));
    }

    bool has_existing_bundle = n00b_result_get(environment);
    uint64_t loadable_policy_flags =
        N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
      | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY;

    if (has_existing_bundle) {
        loadable_policy_flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;

        if (!_n00b_obj_bundle_mask_elf_carrier_for_loadable_rewrite(elf)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_elf_carrier_error(
                    N00B_OBJ_BUNDLE_ERR_BUILD,
                    r"object bundle: ELF split replacement carrier was not found",
                    N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                    0,
                    false,
                    allocator));
        }
    }

    _n00b_obj_bundle_mask_elf_chalk_for_loadable_rewrite(elf);

    n00b_elf_rewrite_loadable_request_t loadable_request = {
        .payload          = loadable_payload,
        .segment_flags    = PF_R | PF_X,
        .file_alignment   = 8,
        .vaddr_alignment  = 0x1000,
        .p_memsz          = loadable_payload->byte_len,
        .phtab_strategy   = has_existing_bundle
            ? N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE
            : N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
        .policy           = {
            .flags = loadable_policy_flags,
        },
    };

    auto loadable_plan_result = n00b_elf_rewrite_plan_loadable_insert(
        elf,
        &loadable_request,
        .allocator = allocator);

    if (n00b_result_is_err(loadable_plan_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF split loadable rewrite planning failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                n00b_result_get_err(loadable_plan_result),
                true,
                allocator));
    }

    n00b_elf_rewrite_loadable_plan_t *loadable_plan =
        n00b_result_get(loadable_plan_result);

    if (loadable_plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_from_loadable_plan_for_carrier(
                loadable_plan,
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                allocator));
    }

    if (_n00b_obj_bundle_host_entrypoint_requested(entrypoint)) {
        auto selection_result =
            _n00b_obj_bundle_select_host_entrypoint_target(
                bundle,
                entrypoint,
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                allocator);

        if (n00b_result_is_err(selection_result)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            selection_result));
        }

        n00b_obj_bundle_host_entrypoint_selection_t *selection =
            n00b_result_get(selection_result);
        bool     found_target = false;
        uint64_t target_payload_offset = 0;
        uint64_t target_size = 0;

        for (size_t i = 0; i < range_count; i++) {
            if (ranges[i].artifact_id == selection->artifact->id) {
                found_target          = true;
                target_payload_offset = ranges[i].loadable_payload_off;
                target_size           = ranges[i].canonical.len;
                break;
            }
        }

        if (!found_target) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_host_entrypoint_split_target_error(
                    selection->artifact,
                    allocator));
        }

        auto entrypoint_result =
            _n00b_obj_bundle_enable_host_entrypoint(
                elf,
                loadable_plan,
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                selection->artifact,
                target_payload_offset,
                target_size,
                allocator);

        if (n00b_result_is_err(entrypoint_result)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            entrypoint_result));
        }
    }

    auto loadable_applied = n00b_elf_rewrite_apply_loadable_insert_plan(
        elf,
        loadable_plan,
        .allocator = allocator);

    if (n00b_result_is_err(loadable_applied)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF split loadable rewrite apply failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                n00b_result_get_err(loadable_applied),
                true,
                allocator));
    }

    n00b_buffer_t *aux = _n00b_obj_bundle_build_elf_split_aux(
        ranges,
        range_count,
        loadable_plan->payload_placement.file_offset,
        allocator);

    if (aux == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: ELF split reconstruction records failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    n00b_buffer_t *descriptor_payload =
        _n00b_obj_bundle_build_elf_split_descriptor_payload(skeleton,
                                                           aux,
                                                           allocator);

    if (descriptor_payload == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: ELF split descriptor build failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    n00b_buffer_t *loadable_output = n00b_result_get(loadable_applied);
    auto descriptor_parsed = _n00b_obj_bundle_parse_elf_for_write(
        loadable_output,
        allocator);

    if (n00b_result_is_err(descriptor_parsed)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        descriptor_parsed));
    }

    n00b_elf_binary_t *descriptor_elf = n00b_result_get(descriptor_parsed);
    auto descriptor_environment =
        _n00b_obj_bundle_validate_elf_write_environment(
            descriptor_elf,
            replace,
            strict,
            allocator);

    if (n00b_result_is_err(descriptor_environment)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        descriptor_environment));
    }

    n00b_elf_rewrite_metadata_request_t descriptor_request = {
        .section_name          = r".0c001.bundle",
        .payload               = descriptor_payload,
        .file_alignment        = 8,
        .section_type          = SHT_PROGBITS,
        .section_flags         = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy                = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };
    bool has_existing_descriptor = n00b_result_get(descriptor_environment);
    auto descriptor_plan_result =
        has_existing_descriptor && replace == N00B_OBJ_BUNDLE_REPLACE_EXISTING
            ? n00b_elf_rewrite_plan_object_bundle_replace(
                  descriptor_elf,
                  &descriptor_request,
                  .allocator = allocator)
            : n00b_elf_rewrite_plan_object_bundle_insert(
                  descriptor_elf,
                  &descriptor_request,
                  .allocator = allocator);

    if (n00b_result_is_err(descriptor_plan_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF split descriptor rewrite planning failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                n00b_result_get_err(descriptor_plan_result),
                true,
                allocator));
    }

    n00b_elf_rewrite_plan_t *descriptor_plan =
        n00b_result_get(descriptor_plan_result);

    if (descriptor_plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_from_rewrite_plan(descriptor_plan,
                                                     allocator));
    }

    uint64_t skeleton_file_off = 0;
    uint64_t aux_file_off      = 0;
    uint64_t aux_file_end      = 0;

    if (!_n00b_obj_bundle_u64_add(
            descriptor_plan->payload_offset,
            N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE,
            &skeleton_file_off)
        || !_n00b_obj_bundle_u64_add(skeleton_file_off,
                                     skeleton->byte_len,
                                     &aux_file_off)
        || !_n00b_obj_bundle_u64_add(aux_file_off,
                                     aux->byte_len,
                                     &aux_file_end)
        || aux_file_end != descriptor_plan->payload_end) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: ELF split descriptor placement is invalid",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                _n00b_obj_bundle_i64_detail_from_u64(
                    descriptor_plan->payload_offset),
                true,
                allocator));
    }

    uint8_t skeleton_digest[N00B_OBJ_BUNDLE_DIGEST_LEN] = {};

    _n00b_obj_bundle_sha256_bytes(skeleton->data,
                                  skeleton->byte_len,
                                  skeleton_digest);

    n00b_obj_bundle_elf_descriptor_t descriptor = {
        .carrier    = N00B_OBJ_BUNDLE_CARRIER_SPLIT,
        .major      = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MAJOR,
        .minor      = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_MINOR,
        .header_size = N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE,
        .flags      = 0,
        .payload    = {
            .off = skeleton_file_off,
            .len = skeleton->byte_len,
        },
        .aux = {
            .off = aux_file_off,
            .len = aux->byte_len,
        },
        .aux_record_count = range_count,
        .reserved0 = 0,
        .reserved1 = 0,
    };

    memcpy(descriptor.payload_digest,
           skeleton_digest,
           N00B_OBJ_BUNDLE_DIGEST_LEN);

    n00b_buffer_t *descriptor_header =
        _n00b_obj_bundle_elf_descriptor_encode(&descriptor, allocator);

    if (descriptor_header == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_BUILD,
                r"object bundle: ELF split descriptor header build failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                0,
                false,
                allocator));
    }

    memcpy(descriptor_payload->data,
           descriptor_header->data,
           N00B_OBJ_BUNDLE_ELF_DESCRIPTOR_HEADER_SIZE);

    auto descriptor_applied = n00b_elf_rewrite_apply_object_bundle_plan(
        descriptor_elf,
        descriptor_plan,
        .allocator = allocator);

    if (n00b_result_is_err(descriptor_applied)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_elf_carrier_error(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: ELF split descriptor rewrite apply failed",
                N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                n00b_result_get_err(descriptor_applied),
                true,
                allocator));
    }

    n00b_buffer_t *final_bytes = n00b_result_get(descriptor_applied);
    auto readback = _n00b_obj_bundle_read_elf_metadata_carrier(final_bytes,
                                                               strict,
                                                               allocator);

    if (n00b_result_is_err(readback)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        readback));
    }

    return n00b_result_ok(n00b_buffer_t *, final_bytes);
}

n00b_result_t(n00b_obj_bundle_t *)
n00b_obj_bundle_read(n00b_buffer_t *object_bytes) _kargs
{
    n00b_format_t    format    = N00B_FMT_UNKNOWN;
    bool             strict    = true;
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!_n00b_obj_bundle_object_bytes_arg_is_valid(object_bytes)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid object bytes",
                              allocator);
    }

    if (!_n00b_obj_bundle_format_request_is_valid(format)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_t *,
            _n00b_obj_bundle_error_with_format_carrier(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid object format request",
                format,
                true,
                N00B_OBJ_BUNDLE_CARRIER_AUTO,
                false,
                allocator));
    }

    n00b_format_t effective_format = format;

    if (format == N00B_FMT_UNKNOWN) {
        n00b_bstream_t *stream = n00b_bstream_new(object_bytes,
                                                  .allocator = allocator);

        effective_format = n00b_detect_format(stream);
    }

    if (effective_format == N00B_FMT_ELF) {
        return _n00b_obj_bundle_read_elf_metadata_carrier(object_bytes,
                                                          strict,
                                                          allocator);
    }

    if (effective_format == N00B_FMT_MACHO) {
        n00b_bstream_t *macho_stream = n00b_bstream_new(object_bytes,
                                                        .allocator = allocator);
        // WP-015: parse fat-aware. n00b_macho_parse wraps even a thin object in
        // a count==1 fat container, so the thin path is the count==1 case below.
        auto            parsed       = n00b_macho_parse(macho_stream);

        if (n00b_result_is_err(parsed)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O object is malformed",
                    N00B_FMT_MACHO,
                    true,
                    N00B_OBJ_BUNDLE_CARRIER_METADATA,
                    true,
                    n00b_result_get_err(parsed),
                    true,
                    allocator));
        }

        n00b_macho_fat_t *fat = n00b_result_get(parsed);

        // WP-015 slice-selection prologue: for a fat input, isolate the arm64
        // carrier slice as a detached thin binary (fat_offset==0, D-034) and run
        // the EXISTING thin detect/read switch on it unchanged. A thin input is
        // the count==1 case, binding the same binary the old n00b_macho_parse_single
        // produced (behavior-identical by construction).
        n00b_macho_binary_t *bin;

        if (fat->count > 1) {
            auto selected = _n00b_obj_bundle_macho_select_carrier_slice(
                fat,
                .allocator = allocator);

            if (n00b_result_is_err(selected)) {
                // The selector returns a raw obj_bundle -37xx error code
                // (UNSUPPORTED_CARRIER when there is no arm64 slice, else
                // MALFORMED_BUNDLE_CARRIER); wrap it as a structured payload,
                // preserving the code.
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier(
                        (n00b_obj_bundle_error_code_t)
                            n00b_result_get_err(selected),
                        r"object bundle: Mach-O fat carrier slice selection failed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_AUTO,
                        false,
                        allocator));
            }

            bin = n00b_result_get(selected);
        }
        else {
            bin = fat->binaries[0];
        }

        auto detected = _n00b_obj_bundle_macho_detect_carrier(
            bin,
            .allocator = allocator);

        if (n00b_result_is_err(detected)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O carrier could not be classified",
                    N00B_FMT_MACHO,
                    true,
                    N00B_OBJ_BUNDLE_CARRIER_METADATA,
                    true,
                    n00b_result_get_err(detected),
                    true,
                    allocator));
        }

        n00b_obj_bundle_macho_carrier_state_t state = n00b_result_get(detected);

        switch (state) {
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_METADATA_RAW: {
            auto canonical = _n00b_obj_bundle_macho_read_metadata(
                bin,
                .allocator = allocator);

            if (n00b_result_is_err(canonical)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O metadata carrier read failed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_METADATA,
                        true,
                        n00b_result_get_err(canonical),
                        true,
                        allocator));
            }

            n00b_buffer_t *payload = n00b_result_get(canonical);
            auto decoded = n00b_obj_bundle_decode(payload,
                                                  .strict    = strict,
                                                  .allocator = allocator);

            if (n00b_result_is_err(decoded)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O metadata carrier payload is malformed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_METADATA,
                        true,
                        n00b_result_get_err(decoded),
                        true,
                        allocator));
            }

            return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
        }
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_LOADABLE: {
            auto loadable = _n00b_obj_bundle_macho_read_loadable(
                bin,
                .allocator = allocator);

            if (n00b_result_is_err(loadable)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O loadable carrier read failed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                        true,
                        n00b_result_get_err(loadable),
                        true,
                        allocator));
            }

            // The loadable reader returns the canonical bundle bytes; decode
            // them into a bundle (mirror the METADATA_RAW branch above).
            n00b_buffer_t *payload = n00b_result_get(loadable);
            auto decoded = n00b_obj_bundle_decode(payload,
                                                  .strict    = strict,
                                                  .allocator = allocator);

            if (n00b_result_is_err(decoded)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O loadable carrier payload is malformed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                        true,
                        n00b_result_get_err(decoded),
                        true,
                        allocator));
            }

            return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
        }
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_DESCRIPTOR_SPLIT: {
            auto split = _n00b_obj_bundle_macho_read_split(
                bin,
                .allocator = allocator);

            if (n00b_result_is_err(split)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O split carrier read failed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                        true,
                        n00b_result_get_err(split),
                        true,
                        allocator));
            }

            // The split reader returns the reconstructed canonical bundle bytes;
            // decode them into a bundle (mirror the LOADABLE branch above). The
            // bundle-level SHA-256 re-check inside n00b_obj_bundle_decode is the
            // authoritative reconstruction integrity gate (D-040).
            n00b_buffer_t *payload = n00b_result_get(split);
            auto decoded = n00b_obj_bundle_decode(payload,
                                                  .strict    = strict,
                                                  .allocator = allocator);

            if (n00b_result_is_err(decoded)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_t *,
                    _n00b_obj_bundle_error_with_format_carrier_detail(
                        N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                        r"object bundle: Mach-O split carrier payload is malformed",
                        N00B_FMT_MACHO,
                        true,
                        N00B_OBJ_BUNDLE_CARRIER_SPLIT,
                        true,
                        n00b_result_get_err(decoded),
                        true,
                        allocator));
            }

            return n00b_result_ok(n00b_obj_bundle_t *, n00b_result_get(decoded));
        }
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_MALFORMED:
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_DUPLICATE:
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O metadata carrier is malformed or duplicated",
                    N00B_FMT_MACHO,
                    true,
                    N00B_OBJ_BUNDLE_CARRIER_METADATA,
                    true,
                    (int64_t)state,
                    true,
                    allocator));
        case N00B_OBJ_BUNDLE_MACHO_CARRIER_NONE:
        default:
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_t *,
                _n00b_obj_bundle_error_with_format_carrier(
                    N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND,
                    r"object bundle: Mach-O metadata carrier not found",
                    N00B_FMT_MACHO,
                    true,
                    N00B_OBJ_BUNDLE_CARRIER_METADATA,
                    true,
                    allocator));
        }
    }

    return OBJ_BUNDLE_ERR_PAYLOAD(
        n00b_obj_bundle_t *,
        _n00b_obj_bundle_error_with_format_carrier(
            N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER,
            r"object bundle: carrier read is unsupported for object format",
            effective_format,
            effective_format != N00B_FMT_UNKNOWN,
            N00B_OBJ_BUNDLE_CARRIER_AUTO,
            false,
            allocator));
}

n00b_result_t(n00b_buffer_t *)
n00b_obj_bundle_write(n00b_buffer_t     *object_bytes,
                      n00b_obj_bundle_t *bundle) _kargs
{
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
}
{
    if (!_n00b_obj_bundle_object_bytes_arg_is_valid(object_bytes)
        || bundle == nullptr) {
        return OBJ_BUNDLE_ERR(n00b_buffer_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid carrier write argument",
                              allocator);
    }

    if (!_n00b_obj_bundle_format_request_is_valid(format)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_with_format_carrier(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid object format request",
                format,
                true,
                carrier,
                _n00b_obj_bundle_carrier_request_is_valid(carrier),
                allocator));
    }

    if (!_n00b_obj_bundle_carrier_request_is_valid(carrier)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_with_format_carrier(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid carrier request",
                format,
                format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                allocator));
    }

    if (!_n00b_obj_bundle_replace_policy_is_valid(replace)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_with_format_carrier(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid replacement policy",
                format,
                format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                allocator));
    }

    if (!_n00b_obj_bundle_entrypoint_policy_is_valid(entrypoint)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid entrypoint policy",
                format,
                format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                (int64_t)entrypoint,
                true,
                allocator));
    }

    if (!_n00b_obj_bundle_policy_mode_is_valid(entrypoint_policy_mode)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid entrypoint policy mode",
                format,
                format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                (int64_t)entrypoint_policy_mode,
                true,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_mark_execution(error));
    }

    if (entrypoint_selector != nullptr
        && !_n00b_obj_bundle_selector_is_valid(entrypoint_selector)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid entrypoint selector",
                entrypoint_selector,
                allocator);

        error->format      = format;
        error->has_format  = format != N00B_FMT_UNKNOWN;
        error->carrier     = carrier;
        error->has_carrier = true;

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_mark_execution(error));
    }

    if (entrypoint == N00B_OBJ_BUNDLE_ENTRYPOINT_PRESERVE
        && (entrypoint_selector != nullptr
            || entrypoint_strict_selector
            || entrypoint_policy_mode
                   != N00B_OBJ_BUNDLE_POLICY_ENFORCE)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: entrypoint target controls require host-entrypoint policy",
                format,
                format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                (int64_t)entrypoint,
                true,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_error_mark_execution(error));
    }

    n00b_format_t effective_format = format;

    if (format == N00B_FMT_UNKNOWN) {
        n00b_bstream_t *stream = n00b_bstream_new(object_bytes,
                                                  .allocator = allocator);

        effective_format = n00b_detect_format(stream);
    }

    // Host-entrypoint redirect is wired for ELF (LOADABLE/SPLIT) and, since
    // WP-009 Phase 2, for Mach-O LOADABLE (the arm64 LC_MAIN redirect). SPLIT
    // host-entry for Mach-O is WP-010. Reject the unsupported combinations; the
    // neutral selection function is unchanged (FR-23 / D-002) — this is dispatch
    // wiring only.
    bool host_entry_supported =
        (effective_format == N00B_FMT_ELF
         && (carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE
             || carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT))
        || (effective_format == N00B_FMT_MACHO
            && carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE);

    if (entrypoint == N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT
        && !host_entry_supported) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_buffer_t *,
            _n00b_obj_bundle_host_entrypoint_unsupported_error(
                effective_format,
                effective_format != N00B_FMT_UNKNOWN,
                carrier,
                true,
                allocator));
    }

    n00b_obj_bundle_host_entrypoint_request_t entrypoint_request = {
        .entrypoint       = entrypoint,
        .selector         = entrypoint_selector,
        .strict_selector  = entrypoint_strict_selector,
        .policy_mode      = entrypoint_policy_mode,
    };

    if (effective_format == N00B_FMT_ELF) {
        if (carrier == N00B_OBJ_BUNDLE_CARRIER_LOADABLE) {
            return _n00b_obj_bundle_write_elf_loadable_carrier(object_bytes,
                                                               bundle,
                                                               replace,
                                                               strict,
                                                               &entrypoint_request,
                                                               allocator);
        }

        if (carrier == N00B_OBJ_BUNDLE_CARRIER_SPLIT) {
            return _n00b_obj_bundle_write_elf_split_carrier(object_bytes,
                                                            bundle,
                                                            replace,
                                                            strict,
                                                            &entrypoint_request,
                                                            allocator);
        }

        return _n00b_obj_bundle_write_elf_metadata_carrier(object_bytes,
                                                           bundle,
                                                           replace,
                                                           strict,
                                                           allocator);
    }

    if (effective_format == N00B_FMT_MACHO) {
        n00b_bstream_t *macho_stream = n00b_bstream_new(object_bytes,
                                                        .allocator = allocator);
        // Parse fat-aware: even a thin object is wrapped in a fat with count==1
        // (macho.h). A fat/universal input (count > 1) is dispatched to the
        // WP-014 fat carrier-write orchestrator; a thin input takes the existing
        // single-slice path unchanged.
        auto            parsed       = n00b_macho_parse(macho_stream);

        if (n00b_result_is_err(parsed)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O object is malformed",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    n00b_result_get_err(parsed),
                    true,
                    allocator));
        }

        n00b_macho_fat_t *fat = n00b_result_get(parsed);

        if (fat == nullptr || fat->count == 0 || fat->binaries == nullptr) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_error_with_format_carrier(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O object is malformed",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    allocator));
        }

        // Fat/universal input: the host-entrypoint redirect is not yet wired for
        // the fat write path (LOADABLE/SPLIT host-entry on a fat slice is future
        // work); the WP-014 dispatch is carrier-only. Encode the canonical bundle
        // once and orchestrate the per-slice carrier write + re-fat.
        if (fat->count > 1) {
            if (entrypoint == N00B_OBJ_BUNDLE_ENTRYPOINT_HOST_ENTRYPOINT) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    _n00b_obj_bundle_host_entrypoint_unsupported_error(
                        effective_format,
                        true,
                        carrier,
                        true,
                        allocator));
            }

            auto fat_encoded = n00b_obj_bundle_encode(bundle,
                                                      .allocator = allocator);

            if (n00b_result_is_err(fat_encoded)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                fat_encoded));
            }

            n00b_buffer_t *fat_canonical = n00b_result_get(fat_encoded);

            auto fat_written = _n00b_obj_bundle_macho_write_carrier_fat(
                fat,
                fat_canonical,
                carrier,
                replace,
                .bundle    = bundle,
                .allocator = allocator);

            if (n00b_result_is_err(fat_written)) {
                // The fat orchestrator already returns obj_bundle -37xx codes
                // (UNSUPPORTED_CARRIER / REWRITE_FAILURE / MALFORMED_BUNDLE_CARRIER);
                // surface that code verbatim rather than collapsing it.
                n00b_obj_bundle_error_code_t fat_code =
                    (n00b_obj_bundle_error_code_t)n00b_result_get_err(fat_written);

                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    _n00b_obj_bundle_error_with_format_carrier(
                        fat_code,
                        r"object bundle: Mach-O fat carrier write failed",
                        N00B_FMT_MACHO,
                        true,
                        carrier,
                        true,
                        allocator));
            }

            return n00b_result_ok(n00b_buffer_t *,
                                  n00b_result_get(fat_written));
        }

        n00b_macho_binary_t *bin = fat->binaries[0];
        auto reserved = _n00b_obj_bundle_macho_check_reserved(
            bin,
            replace,
            .allocator = allocator);

        if (n00b_result_is_err(reserved)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER,
                    r"object bundle: Mach-O carrier could not be classified",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    n00b_result_get_err(reserved),
                    true,
                    allocator));
        }

        n00b_obj_bundle_error_code_t guard = n00b_result_get(reserved);

        if (guard != N00B_OBJ_BUNDLE_ERR_OK) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_error_with_format_carrier(
                    guard,
                    r"object bundle: Mach-O carrier reserved-namespace check failed",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    allocator));
        }

        auto encoded = n00b_obj_bundle_encode(bundle, .allocator = allocator);

        if (n00b_result_is_err(encoded)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *, encoded));
        }

        n00b_buffer_t *canonical = n00b_result_get(encoded);

        // Thread the format-neutral host-entrypoint selection into the Mach-O
        // LOADABLE write path, mirroring the ELF arm (the selection function is
        // unmodified — FR-23 / D-002; this is dispatch wiring only). When a host
        // entrypoint is requested, select the neutral target, resolve its offset
        // within the encoded canonical bundle, and pass it to the writer so the
        // LOADABLE arm can fold the arm64 LC_MAIN redirect into the loadable plan.
        n00b_option_t(uint64_t) macho_host_entry_offset =
            n00b_option_none(uint64_t);
        uint64_t macho_host_entry_size = 0;

        if (_n00b_obj_bundle_host_entrypoint_requested(&entrypoint_request)) {
            auto selection_result =
                _n00b_obj_bundle_select_host_entrypoint_target(
                    bundle,
                    &entrypoint_request,
                    N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                    allocator);

            if (n00b_result_is_err(selection_result)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                selection_result));
            }

            n00b_obj_bundle_host_entrypoint_selection_t *selection =
                n00b_result_get(selection_result);
            uint64_t target_payload_offset = 0;
            auto     offset_result =
                _n00b_obj_bundle_encoded_artifact_payload_offset(
                    bundle,
                    canonical,
                    selection->artifact,
                    N00B_OBJ_BUNDLE_CARRIER_LOADABLE,
                    &target_payload_offset,
                    allocator);

            if (n00b_result_is_err(offset_result)) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_buffer_t *,
                    n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                                offset_result));
            }

            macho_host_entry_offset =
                n00b_option_set(uint64_t, target_payload_offset);
            macho_host_entry_size = selection->artifact->payload->byte_len;
        }

        auto written = _n00b_obj_bundle_macho_write_carrier(
            bin,
            canonical,
            carrier,
            replace,
            .host_entry_payload_offset = macho_host_entry_offset,
            .host_entry_size           = macho_host_entry_size,
            .bundle                    = bundle,
            .allocator                 = allocator);

        if (n00b_result_is_err(written)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_buffer_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                    r"object bundle: Mach-O carrier write failed",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    n00b_result_get_err(written),
                    true,
                    allocator));
        }

        return n00b_result_ok(n00b_buffer_t *, n00b_result_get(written));
    }

    return OBJ_BUNDLE_ERR_PAYLOAD(
        n00b_buffer_t *,
        _n00b_obj_bundle_error_with_format_carrier(
            N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER,
            r"object bundle: carrier write is unsupported for object format",
            effective_format,
            effective_format != N00B_FMT_UNKNOWN,
            carrier,
            true,
            allocator));
}

n00b_result_t(n00b_objfile_sink_result_t *)
n00b_obj_bundle_write_file(n00b_buffer_t     *object_bytes,
                           n00b_obj_bundle_t *bundle,
                           n00b_string_t     *destination_path) _kargs
{
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
}
    // D-031: null object_bytes / bundle / destination_path are documented-Err
    // inputs (they propagate to n00b_obj_bundle_write's INVALID_ARGUMENT Err and
    // the sink's validation), so they are guarded as Err returns by the callees
    // rather than trapped here. No genuine caller-bug precondition remains, so
    // `requires` is omitted (a bare `requires {}` would assert nothing).
    ensures {
        // D-028: guarded by success — on Err, result.ok is null. On success the
        // sink facts are populated, and (for the Mach-O strip->rewrite->persist
        // ->resign path) the persisted file has been re-signed before return;
        // the on-disk signature state is asserted by the WP-011 P1 test matrix
        // (ncc has no old(); the ordering invariant is verified by test, not a
        // call-bearing ensures).
        !result.is_ok || result.ok != nullptr;
    }
{
    // Detect the inbound object format so the Mach-O strip/resign
    // reconciliation (§5) runs only on Mach-O carriers. Non-Mach-O
    // formats take the exact pre-WP-011 path (no strip, no resign).
    n00b_format_t input_format = format;

    if (input_format == N00B_FMT_UNKNOWN && object_bytes != nullptr) {
        n00b_bstream_t *detect_stream =
            n00b_bstream_new(object_bytes, .allocator = allocator);
        input_format = n00b_detect_format(detect_stream);
    }

    bool is_macho = input_format == N00B_FMT_MACHO;

    // §5 step 1 — strip any inbound signature BEFORE the carrier
    // rewrite so no LC_CODE_SIGNATURE survives over rewritten bytes
    // (documented no-op when the input is unsigned). The rewrite then
    // runs over the stripped bytes.
    n00b_buffer_t *rewrite_input = object_bytes;

    if (is_macho) {
        auto stripped = n00b_chalk_macho_strip_signature(object_bytes);

        if (n00b_result_is_err(stripped)) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_objfile_sink_result_t *,
                _n00b_obj_bundle_error_with_format_carrier_detail(
                    N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                    r"object bundle: Mach-O signature strip failed",
                    N00B_FMT_MACHO,
                    true,
                    carrier,
                    true,
                    n00b_result_get_err(stripped),
                    true,
                    allocator));
        }

        rewrite_input = n00b_result_get(stripped);
    }

    // §5 step 2 — carrier rewrite produces rewritten-but-UNSIGNED bytes.
    auto rewritten = n00b_obj_bundle_write(rewrite_input,
                                           bundle,
                                           .format    = format,
                                           .carrier   = carrier,
                                           .replace   = replace,
                                           .strict    = strict,
                                           .entrypoint = entrypoint,
                                           .entrypoint_selector =
                                               entrypoint_selector,
                                           .entrypoint_strict_selector =
                                               entrypoint_strict_selector,
                                           .entrypoint_policy_mode =
                                               entrypoint_policy_mode,
                                           .allocator = allocator);

    if (n00b_result_is_err(rewritten)) {
        // n00b_result_get_error (not _get_err): forward the raw error CARRIER
        // across result types so a payload-kind error (n00b_obj_bundle_error_t)
        // is preserved, not flattened to its integer code (_get_err would assert
        // on a payload error). CR-12: the structured carrier error propagates.
        return n00b_result_err(n00b_objfile_sink_result_t *,
                               n00b_result_get_error(rewritten));
    }

    // §5 step 3 — PERSIST the rewritten bytes to the destination path.
    auto persisted = n00b_objfile_sink_write(n00b_result_get(rewritten),
                                             destination_path,
                                             .sink_mode = sink_mode,
                                             .overwrite = overwrite,
                                             .file_mode = file_mode,
                                             .preserve_existing_mode =
                                                 preserve_existing_mode,
                                             .allocator = allocator);

    if (!is_macho || n00b_result_is_err(persisted)) {
        return persisted;
    }

    // §5 step 4 — RESIGN the on-disk file (codesign operates on a path,
    // not a buffer). nullptr signer_identity selects ad-hoc; a supplied
    // identity selects a real Developer ID. Bundle binaries carry no
    // ES/NetExt/Developer-ID entitlement, so the ad-hoc default is
    // correct here (CLAUDE.md feedback_signing.md).
    n00b_string_t *persisted_path =
        n00b_objfile_sink_result_destination_path(n00b_result_get(persisted));

    auto resigned = n00b_chalk_macho_resign(persisted_path,
                                            .signer_identity = signer_identity,
                                            .allocator       = allocator);

    if (n00b_result_is_err(resigned)) {
        // CR-12 — map the chalk resign failure into a structured
        // neutral carrier error (mirrors mark.c:783-785).
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_objfile_sink_result_t *,
            _n00b_obj_bundle_error_with_format_carrier_detail(
                N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE,
                r"object bundle: Mach-O re-sign failed",
                N00B_FMT_MACHO,
                true,
                carrier,
                true,
                n00b_result_get_err(resigned),
                true,
                allocator));
    }

    return persisted;
}

n00b_result_t(n00b_obj_bundle_extract_result_t *)
n00b_obj_bundle_extract(n00b_obj_bundle_t *bundle,
                        n00b_string_t     *destination_root) _kargs
{
    bool                          overwrite = false;
    bool                          atomic = true;
    bool                          preserve_modes = true;
    bool                          create_dirs = true;
    bool                          allow_absolute_paths = false;
    bool                          allow_parent_refs = false;
    n00b_obj_bundle_policy_mode_t policy_mode = N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t             *allocator = nullptr;
}
{
    if (bundle == nullptr) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            _n00b_obj_bundle_error_with_destination(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: null extraction bundle",
                destination_root,
                allocator));
    }

    if (!_n00b_obj_bundle_extract_destination_arg_is_valid(destination_root)) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_extract_result_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: invalid extraction destination root",
                              allocator);
    }

    n00b_obj_bundle_extract_result_t *facts =
        _n00b_obj_bundle_extract_result_new(destination_root,
                                           overwrite,
                                           atomic,
                                           preserve_modes,
                                           create_dirs,
                                           allow_absolute_paths,
                                           allow_parent_refs,
                                           policy_mode,
                                           allocator);

    if (!_n00b_obj_bundle_policy_mode_is_valid(policy_mode)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_extract_result(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid extraction policy mode",
                destination_root,
                facts,
                allocator);

        error->detail     = (int64_t)policy_mode;
        error->has_detail = true;

        return OBJ_BUNDLE_ERR_PAYLOAD(n00b_obj_bundle_extract_result_t *,
                                      error);
    }

    auto valid_artifacts = _n00b_obj_bundle_validate_artifacts(bundle);

    if (n00b_result_is_err(valid_artifacts)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            _n00b_obj_bundle_error_clone_with_extract_result(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_artifacts),
                destination_root,
                facts,
                allocator));
    }

    auto valid_exec = _n00b_obj_bundle_validate_exec_map(bundle);

    if (n00b_result_is_err(valid_exec)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            _n00b_obj_bundle_error_clone_with_extract_result(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_exec),
                destination_root,
                facts,
                allocator));
    }

    auto policy_result =
        _n00b_obj_bundle_select_extraction_policy(bundle, allocator);

    if (n00b_result_is_err(policy_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            _n00b_obj_bundle_error_attach_extract_result(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            policy_result),
                destination_root,
                facts));
    }

    n00b_obj_bundle_extract_policy_t *policy =
        n00b_result_get(policy_result);

    _n00b_obj_bundle_extract_result_set_policy(facts, policy);

    n00b_eval_session_t *policy_session = nullptr;

    auto plan_result = _n00b_obj_bundle_plan_extraction(bundle,
                                                        destination_root,
                                                        policy,
                                                        facts,
                                                        &policy_session,
                                                        allocator);

    if (n00b_result_is_err(plan_result)) {
        n00b_eval_session_free(policy_session);
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_extract_result_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        plan_result));
    }

    n00b_obj_bundle_extract_plan_t *plan = n00b_result_get(plan_result);

    if (policy_mode == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY) {
        n00b_eval_session_free(policy_session);
        return n00b_result_ok(n00b_obj_bundle_extract_result_t *, facts);
    }

    n00b_result_t(n00b_obj_bundle_extract_result_t *) extracted;

    if (!atomic) {
        extracted = _n00b_obj_bundle_materialize_direct(plan,
                                                        facts,
                                                        allocator);
    }
    else {
        extracted = _n00b_obj_bundle_materialize_atomic(plan,
                                                        facts,
                                                        allocator);
    }

    n00b_eval_session_free(policy_session);
    return extracted;
}

n00b_result_t(n00b_obj_bundle_exec_plan_t *)
n00b_obj_bundle_exec_plan(n00b_obj_bundle_t *bundle) _kargs
{
    n00b_string_t                             *selector = nullptr;
    n00b_obj_bundle_exec_argv_t               *argv = nullptr;
    n00b_obj_bundle_exec_env_t                *env = nullptr;
    bool                                       inherit_env = true;
    bool                                       strict_selector = false;
    n00b_obj_bundle_exec_mode_t                mode = N00B_OBJ_BUNDLE_EXEC_AUTO;
    n00b_obj_bundle_policy_mode_t              policy_mode =
        N00B_OBJ_BUNDLE_POLICY_ENFORCE;
    n00b_allocator_t                          *allocator = nullptr;
}
{
    if (bundle == nullptr) {
        return OBJ_BUNDLE_ERR(n00b_obj_bundle_exec_plan_t *,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                              r"object bundle: null execution bundle",
                              allocator);
    }

    if (!_n00b_obj_bundle_policy_mode_is_valid(policy_mode)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_policy(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid execution policy mode",
                N00B_OBJ_BUNDLE_POLICY_KIND_NONE,
                N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                (uint64_t)policy_mode,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(n00b_obj_bundle_exec_plan_t *, error);
    }

    if (!_n00b_obj_bundle_exec_mode_is_valid(mode)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_policy(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid execution mode",
                N00B_OBJ_BUNDLE_POLICY_KIND_NONE,
                N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                (uint64_t)mode,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(n00b_obj_bundle_exec_plan_t *, error);
    }

    if (selector != nullptr && !_n00b_obj_bundle_selector_is_valid(selector)) {
        n00b_obj_bundle_error_t *error =
            _n00b_obj_bundle_error_with_path(
                N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT,
                r"object bundle: invalid execution selector",
                selector,
                allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            _n00b_obj_bundle_error_mark_execution(error));
    }

    auto valid_artifacts = _n00b_obj_bundle_validate_artifacts(bundle);

    if (n00b_result_is_err(valid_artifacts)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            _n00b_obj_bundle_error_clone_for_execution(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_artifacts),
                allocator));
    }

    auto valid_exec = _n00b_obj_bundle_validate_exec_map(bundle);

    if (n00b_result_is_err(valid_exec)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            _n00b_obj_bundle_error_clone_for_execution(
                n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                            valid_exec),
                allocator));
    }

    auto policy_result =
        _n00b_obj_bundle_select_execution_policy(bundle, allocator);

    if (n00b_result_is_err(policy_result)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        policy_result));
    }

    n00b_obj_bundle_exec_policy_t *policy = n00b_result_get(policy_result);
    n00b_obj_bundle_artifact_t *selected = nullptr;
    n00b_obj_bundle_exec_selection_source_t selection_source =
        N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE;

    if (selector != nullptr) {
        n00b_obj_bundle_exec_mapping_t *mapping =
            _n00b_obj_bundle_find_mapping_by_selector(bundle, selector);

        if (mapping != nullptr) {
            selected =
                _n00b_obj_bundle_find_artifact_by_id(bundle,
                                                    mapping->target_artifact_id);
            selection_source =
                N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING;

            if (!_n00b_obj_bundle_artifact_is_executable(selected)) {
                n00b_obj_bundle_error_t *error =
                    _n00b_obj_bundle_error_with_artifact(
                        N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                        r"object bundle: invalid execution mapping target",
                        mapping->target_artifact_id,
                        allocator);

                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_plan_t *,
                    _n00b_obj_bundle_error_mark_execution(error));
            }

            if ((policy->execution_flags
                 & N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING) == 0) {
                return OBJ_BUNDLE_ERR_PAYLOAD(
                    n00b_obj_bundle_exec_plan_t *,
                    _n00b_obj_bundle_exec_policy_denied(
                        policy,
                        r"object bundle: execution selector mapping denied by policy",
                        selector,
                        selected,
                        N00B_OBJ_BUNDLE_DECL_EXEC_SELECTOR_MAPPING,
                        allocator));
            }
        }
        else if (strict_selector) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_error_with_path(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: execution selector has no mapping",
                    selector,
                    allocator);

            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_exec_plan_t *,
                _n00b_obj_bundle_error_mark_execution(error));
        }
    }

    if (selected == nullptr && bundle->has_default_exec) {
        selected = _n00b_obj_bundle_find_artifact_by_id(bundle,
                                                       bundle->default_exec_id);
        selection_source = N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT;

        if (!_n00b_obj_bundle_artifact_is_executable(selected)) {
            n00b_obj_bundle_error_t *error =
                _n00b_obj_bundle_error_with_artifact(
                    N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                    r"object bundle: invalid default executable target",
                    bundle->default_exec_id,
                    allocator);

            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_exec_plan_t *,
                _n00b_obj_bundle_error_mark_execution(error));
        }

        if ((policy->execution_flags
             & N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC) == 0) {
            return OBJ_BUNDLE_ERR_PAYLOAD(
                n00b_obj_bundle_exec_plan_t *,
                _n00b_obj_bundle_exec_policy_denied(
                    policy,
                    r"object bundle: default execution denied by policy",
                    selected->logical_path,
                    selected,
                    N00B_OBJ_BUNDLE_DECL_EXEC_DEFAULT_EXEC,
                    allocator));
        }
    }

    if (selected == nullptr) {
        n00b_obj_bundle_error_t *error =
            selector == nullptr
                ? _n00b_obj_bundle_error_new(
                      N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                      r"object bundle: no execution target available",
                      allocator)
                : _n00b_obj_bundle_error_with_path(
                      N00B_OBJ_BUNDLE_ERR_MISSING_TARGET,
                      r"object bundle: execution selector has no fallback target",
                      selector,
                      allocator);

        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            _n00b_obj_bundle_error_mark_execution(error));
    }

    auto embedded_policy =
        _n00b_obj_bundle_exec_evaluate_embedded_policy(policy,
                                                       selected,
                                                       selection_source,
                                                       inherit_env,
                                                       strict_selector,
                                                       mode,
                                                       policy_mode,
                                                       allocator);

    if (n00b_result_is_err(embedded_policy)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            n00b_result_get_err_payload(n00b_obj_bundle_error_t *,
                                        embedded_policy));
    }

    if (!_n00b_obj_bundle_exec_mode_is_supported(mode)) {
        return OBJ_BUNDLE_ERR_PAYLOAD(
            n00b_obj_bundle_exec_plan_t *,
            _n00b_obj_bundle_error_with_exec_mode(
                N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE,
                r"object bundle: unsupported execution mode",
                mode,
                N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED,
                allocator));
    }

    n00b_obj_bundle_exec_argv_t *planned_argv =
        _n00b_obj_bundle_exec_argv_plan(argv,
                                        selected->logical_path,
                                        allocator);
    n00b_obj_bundle_exec_env_t *planned_env =
        _n00b_obj_bundle_exec_env_plan(env, allocator);

    n00b_obj_bundle_exec_plan_t *plan =
        _n00b_obj_bundle_exec_plan_new(selector,
                                       planned_argv,
                                       planned_env,
                                       inherit_env,
                                       strict_selector,
                                       mode,
                                       policy_mode,
                                       allocator);

    plan->policy_kind               = policy->kind;
    plan->has_policy_kind           = true;
    plan->policy_scope              = policy->scope;
    plan->has_policy_scope          = true;
    plan->fallback_used             = policy->fallback_used;
    plan->selected_artifact_id      = selected->id;
    plan->has_selected_artifact_id  = true;
    plan->selected_logical_path     = selected->logical_path;
    plan->has_selected_logical_path = selected->logical_path != nullptr;
    plan->selection_source          = selection_source;

    return n00b_result_ok(n00b_obj_bundle_exec_plan_t *, plan);
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_exec_plan_selector(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return n00b_option_from_nullable(n00b_string_t *, plan->selector);
}

n00b_option_t(n00b_obj_bundle_exec_argv_t *)
n00b_obj_bundle_exec_plan_argv(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return n00b_option_from_nullable(n00b_obj_bundle_exec_argv_t *,
                                     plan->argv);
}

n00b_option_t(n00b_obj_bundle_exec_env_t *)
n00b_obj_bundle_exec_plan_env(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return n00b_option_from_nullable(n00b_obj_bundle_exec_env_t *,
                                     plan->env);
}

bool
n00b_obj_bundle_exec_plan_inherit_env(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->inherit_env;
}

bool
n00b_obj_bundle_exec_plan_strict_selector(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->strict_selector;
}

n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_plan_requested_mode(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->requested_mode;
}

n00b_obj_bundle_exec_mode_t
n00b_obj_bundle_exec_plan_resolved_mode(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->resolved_mode;
}

n00b_obj_bundle_exec_platform_support_t
n00b_obj_bundle_exec_plan_platform_support(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->platform_support;
}

bool
n00b_obj_bundle_exec_plan_requires_extraction(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->requires_extraction;
}

n00b_obj_bundle_policy_mode_t
n00b_obj_bundle_exec_plan_policy_mode(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->policy_mode;
}

n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_exec_plan_policy_kind(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    if (!plan->has_policy_kind) {
        return n00b_option_none(n00b_obj_bundle_policy_kind_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_kind_t,
                           plan->policy_kind);
}

n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_exec_plan_policy_scope(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    if (!plan->has_policy_scope) {
        return n00b_option_none(n00b_obj_bundle_policy_scope_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_scope_t,
                           plan->policy_scope);
}

bool
n00b_obj_bundle_exec_plan_fallback_used(n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->fallback_used;
}

n00b_obj_bundle_exec_selection_source_t
n00b_obj_bundle_exec_plan_selection_source(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    return plan->selection_source;
}

n00b_option_t(uint64_t)
n00b_obj_bundle_exec_plan_selected_artifact_id(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    if (!plan->has_selected_artifact_id) {
        return n00b_option_none(uint64_t);
    }

    return n00b_option_set(uint64_t, plan->selected_artifact_id);
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_exec_plan_selected_logical_path(
    n00b_obj_bundle_exec_plan_t *plan)
{
    n00b_require(plan != nullptr,
                 "object bundle execution plan must not be null");

    if (!plan->has_selected_logical_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *,
                                     plan->selected_logical_path);
}

n00b_string_t *
n00b_obj_bundle_extract_result_destination_root(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->destination_root;
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_extract_result_temp_root(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    if (!result->has_temp_root) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, result->temp_root);
}

uint64_t
n00b_obj_bundle_extract_result_files_planned(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->files_planned;
}

uint64_t
n00b_obj_bundle_extract_result_directories_planned(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->directories_planned;
}

uint64_t
n00b_obj_bundle_extract_result_files_written(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->files_written;
}

uint64_t
n00b_obj_bundle_extract_result_directories_written(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->directories_written;
}

n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_extract_result_policy_kind(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    if (!result->has_policy_kind) {
        return n00b_option_none(n00b_obj_bundle_policy_kind_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_kind_t,
                           result->policy_kind);
}

n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_extract_result_policy_scope(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    if (!result->has_policy_scope) {
        return n00b_option_none(n00b_obj_bundle_policy_scope_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_scope_t,
                           result->policy_scope);
}

bool
n00b_obj_bundle_extract_result_fallback_used(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->fallback_used;
}

bool
n00b_obj_bundle_extract_result_overwrite(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->overwrite;
}

bool
n00b_obj_bundle_extract_result_atomic_requested(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->atomic_requested;
}

bool
n00b_obj_bundle_extract_result_atomic_used(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->atomic_used;
}

bool
n00b_obj_bundle_extract_result_preserve_modes(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->preserve_modes;
}

bool
n00b_obj_bundle_extract_result_create_dirs(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->create_dirs;
}

bool
n00b_obj_bundle_extract_result_allow_absolute_paths(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->allow_absolute_paths;
}

bool
n00b_obj_bundle_extract_result_allow_parent_refs(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->allow_parent_refs;
}

n00b_obj_bundle_policy_mode_t
n00b_obj_bundle_extract_result_policy_mode(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->policy_mode;
}

bool
n00b_obj_bundle_extract_result_commit_attempted(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->commit_attempted;
}

bool
n00b_obj_bundle_extract_result_commit_completed(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->commit_completed;
}

bool
n00b_obj_bundle_extract_result_rollback_attempted(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->rollback_attempted;
}

bool
n00b_obj_bundle_extract_result_rollback_succeeded(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->rollback_succeeded;
}

bool
n00b_obj_bundle_extract_result_cleanup_attempted(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->cleanup_attempted;
}

bool
n00b_obj_bundle_extract_result_cleanup_succeeded(
    n00b_obj_bundle_extract_result_t *result)
{
    n00b_require(result != nullptr,
                 "object bundle extraction result must not be null");

    return result->cleanup_succeeded;
}

n00b_obj_bundle_error_code_t
n00b_obj_bundle_error_code(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    return error->code;
}

n00b_string_t *
n00b_obj_bundle_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_OBJ_BUNDLE_ERR_OK:
        return r"object bundle: ok";
    case N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT:
        return r"object bundle: invalid argument";
    case N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH:
        return r"object bundle: invalid logical path";
    case N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH:
        return r"object bundle: duplicate logical path";
    case N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR:
        return r"object bundle: duplicate execution selector";
    case N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC:
        return r"object bundle: multiple default executables";
    case N00B_OBJ_BUNDLE_ERR_MISSING_TARGET:
        return r"object bundle: missing execution target";
    case N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_VERSION:
        return r"object bundle: unsupported version";
    case N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE:
        return r"object bundle: unsupported feature";
    case N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST:
        return r"object bundle: malformed manifest";
    case N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST:
        return r"object bundle: non-canonical manifest";
    case N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS:
        return r"object bundle: table or payload out of bounds";
    case N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH:
        return r"object bundle: digest mismatch";
    case N00B_OBJ_BUNDLE_ERR_BUILD:
        return r"object bundle: build failure";
    case N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID:
        return r"object bundle: duplicate policy ID";
    case N00B_OBJ_BUNDLE_ERR_BUNDLE_NOT_FOUND:
        return r"object bundle: bundle carrier not found";
    case N00B_OBJ_BUNDLE_ERR_DUPLICATE_BUNDLE_CARRIER:
        return r"object bundle: duplicate bundle carrier";
    case N00B_OBJ_BUNDLE_ERR_MALFORMED_BUNDLE_CARRIER:
        return r"object bundle: malformed bundle carrier";
    case N00B_OBJ_BUNDLE_ERR_REPLACE_REQUIRED:
        return r"object bundle: replacement required";
    case N00B_OBJ_BUNDLE_ERR_RESERVED_NAMESPACE_OCCUPIED:
        return r"object bundle: reserved namespace occupied";
    case N00B_OBJ_BUNDLE_ERR_FOREIGN_LEGACY_BUNDLE:
        return r"object bundle: foreign legacy bundle";
    case N00B_OBJ_BUNDLE_ERR_ALREADY_WRAPPED_OR_RESERVED:
        return r"object bundle: already wrapped or reserved";
    case N00B_OBJ_BUNDLE_ERR_GUARD_SECTION_PRESENT:
        return r"object bundle: guard section present";
    case N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_CARRIER:
        return r"object bundle: unsupported carrier";
    case N00B_OBJ_BUNDLE_ERR_REWRITE_FAILURE:
        return r"object bundle: rewrite failure";
    case N00B_OBJ_BUNDLE_ERR_EXTRACT_UNSUPPORTED:
        return r"object bundle: extraction unsupported";
    case N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE:
        return r"object bundle: unsupported execution mode";
    case N00B_OBJ_BUNDLE_ERR_POLICY_DENIED:
        return r"object bundle: policy denied";
    case N00B_OBJ_BUNDLE_ERR_EXEC_LAUNCH_FAILED:
        return r"object bundle: execution launch failed";
    case N00B_OBJ_BUNDLE_ERR_EXEC_NO_MODE_AVAILABLE:
        return r"object bundle: no execution mode available";
    default:
        return r"object bundle: unknown error code";
    }
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_message(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    return n00b_option_from_nullable(n00b_string_t *, error->message);
}

n00b_option_t(n00b_format_t)
n00b_obj_bundle_error_format(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_format) {
        return n00b_option_none(n00b_format_t);
    }

    return n00b_option_set(n00b_format_t, error->format);
}

n00b_option_t(n00b_obj_bundle_carrier_t)
n00b_obj_bundle_error_carrier(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_carrier) {
        return n00b_option_none(n00b_obj_bundle_carrier_t);
    }

    return n00b_option_set(n00b_obj_bundle_carrier_t, error->carrier);
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_logical_path(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_logical_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, error->logical_path);
}

n00b_option_t(n00b_string_t *)
n00b_obj_bundle_error_destination_path(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_destination_path) {
        return n00b_option_none(n00b_string_t *);
    }

    return n00b_option_from_nullable(n00b_string_t *, error->destination_path);
}

n00b_option_t(uint64_t)
n00b_obj_bundle_error_artifact_id(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_artifact_id) {
        return n00b_option_none(uint64_t);
    }

    return n00b_option_set(uint64_t, error->artifact_id);
}

n00b_option_t(n00b_obj_bundle_policy_kind_t)
n00b_obj_bundle_error_policy_kind(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_policy_kind) {
        return n00b_option_none(n00b_obj_bundle_policy_kind_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_kind_t, error->policy_kind);
}

n00b_option_t(n00b_obj_bundle_policy_scope_t)
n00b_obj_bundle_error_policy_scope(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_policy_scope) {
        return n00b_option_none(n00b_obj_bundle_policy_scope_t);
    }

    return n00b_option_set(n00b_obj_bundle_policy_scope_t, error->policy_scope);
}

n00b_option_t(int64_t)
n00b_obj_bundle_error_detail(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_detail) {
        return n00b_option_none(int64_t);
    }

    return n00b_option_set(int64_t, error->detail);
}

n00b_option_t(n00b_obj_bundle_exec_mode_t)
n00b_obj_bundle_error_exec_requested_mode(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_exec_requested_mode) {
        return n00b_option_none(n00b_obj_bundle_exec_mode_t);
    }

    return n00b_option_set(n00b_obj_bundle_exec_mode_t,
                           error->exec_requested_mode);
}

n00b_option_t(n00b_obj_bundle_exec_platform_support_t)
n00b_obj_bundle_error_exec_platform_support(
    n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_exec_platform_support) {
        return n00b_option_none(n00b_obj_bundle_exec_platform_support_t);
    }

    return n00b_option_set(n00b_obj_bundle_exec_platform_support_t,
                           error->exec_platform_support);
}

n00b_option_t(n00b_obj_bundle_extract_result_t *)
n00b_obj_bundle_error_extract_result_facts(n00b_obj_bundle_error_t *error)
{
    n00b_require(error != nullptr, "object bundle error must not be null");

    if (!error->has_extract_result) {
        return n00b_option_none(n00b_obj_bundle_extract_result_t *);
    }

    return n00b_option_from_nullable(n00b_obj_bundle_extract_result_t *,
                                     error->extract_result);
}
