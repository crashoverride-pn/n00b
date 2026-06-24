/**
 * @file static_objects.h
 * @brief Descriptor-backed generated static objects.
 */
#pragma once

#include "n00b.h"
// Full codegen-ABI descriptor definitions: the N00B_STATIC_OBJECT macro
// instantiates n00b_static_object_desc_t by value, and this header declares the
// n00b_static_identity_query_t API.
#include "core/codegen_abi_inject.h"
#include "core/alloc_base.h"
#include "core/macros.h"

#if !defined(__has_attribute)
#define __has_attribute(x) 0
#endif

#if __has_attribute(retain)
#define N00B_STATIC_OBJECT_RETAIN __attribute__((retain))
#else
#define N00B_STATIC_OBJECT_RETAIN
#endif

#if defined(_WIN32)
#if defined(_MSC_VER) && !defined(__clang__)
#pragma section(".n00bs$m", read)
#define N00B_STATIC_OBJECT_SECTION_PRE(section_name)  __declspec(allocate(section_name))
#define N00B_STATIC_OBJECT_SECTION_POST(section_name)
#else
#define N00B_STATIC_OBJECT_SECTION_PRE(section_name)
#define N00B_STATIC_OBJECT_SECTION_POST(section_name) \
    [[gnu::section(section_name), gnu::used]]
#endif
#define N00B_STATIC_OBJECT_SECTION_NAME ".n00bs$m"
#elif defined(__APPLE__)
#define N00B_STATIC_OBJECT_SECTION_PRE(section_name)
#define N00B_STATIC_OBJECT_SECTION_POST(section_name) \
    [[gnu::section(section_name), gnu::used]]
#define N00B_STATIC_OBJECT_SECTION_NAME "__DATA,n00b_stobj"
#else
#define N00B_STATIC_OBJECT_SECTION_PRE(section_name)
#define N00B_STATIC_OBJECT_SECTION_POST(section_name) \
    [[gnu::section(section_name), gnu::used]] N00B_STATIC_OBJECT_RETAIN
#define N00B_STATIC_OBJECT_SECTION_NAME "n00b_stobj"
#endif

typedef const n00b_static_object_desc_t *n00b_static_object_entry_t;

typedef void (*n00b_static_object_iter_cb)(const n00b_static_object_desc_t *desc,
                                           void *user);

#define N00B_STATIC_OBJECT_LINK_DESCRIPTOR(desc_name)                                           \
    N00B_STATIC_OBJECT_SECTION_PRE(N00B_STATIC_OBJECT_SECTION_NAME)                            \
    static n00b_static_object_entry_t const __n00b_static_object_entry_##desc_name             \
        N00B_STATIC_OBJECT_SECTION_POST(N00B_STATIC_OBJECT_SECTION_NAME) = &(desc_name)

#define N00B_STATIC_OBJECT_DESCRIPTOR_EX(desc_name,                                             \
                                         object_start,                                          \
                                         object_len,                                            \
                                         type_hash_val,                                         \
                                         flags_val,                                             \
                                         scan_kind_val,                                         \
                                         scan_cb_val,                                           \
                                         scan_user_val,                                         \
                                         object_id_val,                                         \
                                         identity_val,                                          \
                                         cached_hash_val)                                       \
    static const n00b_static_object_desc_t desc_name = {                                        \
        .start       = (const void *)(object_start),                                            \
        .len         = (uint64_t)(object_len),                                                  \
        .tinfo       = (n00b_alloc_type_info_t)(type_hash_val),                                 \
        .scan_kind   = (scan_kind_val),                                                         \
        .scan_cb     = (scan_cb_val),                                                           \
        .scan_user   = (void *)(scan_user_val),                                                 \
        .object_id   = (uint64_t)(object_id_val),                                               \
        .file        = N00B_LOC_STRING(),                                                       \
        .identity    = (identity_val),                                                          \
        .flags       = (uint32_t)(flags_val),                                                   \
        .cached_hash = (n00b_uint128_t)(cached_hash_val),                                       \
    };                                                                                          \
    N00B_STATIC_OBJECT_LINK_DESCRIPTOR(desc_name)

#define N00B_STATIC_OBJECT_DESCRIPTOR(desc_name,                                                \
                                      object_start,                                             \
                                      object_len,                                               \
                                      type_hash_val,                                            \
                                      flags_val,                                                \
                                      scan_kind_val,                                            \
                                      scan_cb_val,                                              \
                                      scan_user_val,                                            \
                                      object_id_val)                                            \
    N00B_STATIC_OBJECT_DESCRIPTOR_EX(desc_name,                                                 \
                                     object_start,                                              \
                                     object_len,                                                \
                                     type_hash_val,                                             \
                                     flags_val,                                                 \
                                     scan_kind_val,                                             \
                                     scan_cb_val,                                               \
                                     scan_user_val,                                             \
                                     object_id_val,                                             \
                                     nullptr,                                                   \
                                     0)

#define N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY(desc_name,                                  \
                                                    object_start,                               \
                                                    object_len,                                 \
                                                    type_hash_val,                              \
                                                    flags_val,                                  \
                                                    scan_kind_val,                              \
                                                    scan_cb_val,                                \
                                                    scan_user_val,                              \
                                                    object_id_val,                              \
                                                    identity_val)                               \
    N00B_STATIC_OBJECT_DESCRIPTOR_EX(desc_name,                                                 \
                                     object_start,                                              \
                                     object_len,                                                \
                                     type_hash_val,                                             \
                                     flags_val,                                                 \
                                     scan_kind_val,                                             \
                                     scan_cb_val,                                               \
                                     scan_user_val,                                             \
                                     object_id_val,                                             \
                                     identity_val,                                              \
                                     0)

#define N00B_STATIC_OBJECT_DESCRIPTOR_WITH_HASH(desc_name,                                      \
                                                object_start,                                   \
                                                object_len,                                     \
                                                type_hash_val,                                  \
                                                flags_val,                                      \
                                                scan_kind_val,                                  \
                                                scan_cb_val,                                    \
                                                scan_user_val,                                  \
                                                object_id_val,                                  \
                                                cached_hash_val)                                \
    N00B_STATIC_OBJECT_DESCRIPTOR_EX(desc_name,                                                 \
                                     object_start,                                              \
                                     object_len,                                                \
                                     type_hash_val,                                             \
                                     flags_val,                                                 \
                                     scan_kind_val,                                             \
                                     scan_cb_val,                                               \
                                     scan_user_val,                                             \
                                     object_id_val,                                             \
                                     nullptr,                                                   \
                                     cached_hash_val)

#define N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY_AND_HASH(desc_name,                         \
                                                             object_start,                      \
                                                             object_len,                        \
                                                             type_hash_val,                     \
                                                             flags_val,                         \
                                                             scan_kind_val,                     \
                                                             scan_cb_val,                       \
                                                             scan_user_val,                     \
                                                             object_id_val,                     \
                                                             identity_val,                      \
                                                             cached_hash_val)                   \
    N00B_STATIC_OBJECT_DESCRIPTOR_EX(desc_name,                                                 \
                                     object_start,                                              \
                                     object_len,                                                \
                                     type_hash_val,                                             \
                                     flags_val,                                                 \
                                     scan_kind_val,                                             \
                                     scan_cb_val,                                               \
                                     scan_user_val,                                             \
                                     object_id_val,                                             \
                                     identity_val,                                              \
                                     cached_hash_val)

#define N00B_STATIC_OBJECT_DESCRIPTOR_FOR(desc_name,                                            \
                                          object_name,                                          \
                                          type_hash_val,                                        \
                                          flags_val,                                            \
                                          scan_kind_val,                                        \
                                          scan_cb_val,                                          \
                                          scan_user_val,                                        \
                                          object_id_val)                                        \
    N00B_STATIC_OBJECT_DESCRIPTOR(desc_name,                                                     \
                                  &(object_name),                                               \
                                  sizeof(object_name),                                          \
                                  type_hash_val,                                                \
                                  flags_val,                                                    \
                                  scan_kind_val,                                                \
                                  scan_cb_val,                                                  \
                                  scan_user_val,                                                \
                                  object_id_val)

#define N00B_STATIC_OBJECT_DESCRIPTOR_FOR_WITH_IDENTITY(desc_name,                              \
                                                        object_name,                            \
                                                        type_hash_val,                          \
                                                        flags_val,                              \
                                                        scan_kind_val,                          \
                                                        scan_cb_val,                            \
                                                        scan_user_val,                          \
                                                        object_id_val,                          \
                                                        identity_val)                           \
    N00B_STATIC_OBJECT_DESCRIPTOR_WITH_IDENTITY(desc_name,                                      \
                                                &(object_name),                                  \
                                                sizeof(object_name),                             \
                                                type_hash_val,                                   \
                                                flags_val,                                       \
                                                scan_kind_val,                                   \
                                                scan_cb_val,                                     \
                                                scan_user_val,                                   \
                                                object_id_val,                                   \
                                                identity_val)

extern n00b_static_identity_status_t
n00b_static_identity_register(const n00b_static_identity_t *identity,
                              n00b_alloc_range_t *range);
extern n00b_static_identity_status_t
n00b_static_identity_lookup(const n00b_static_identity_t *identity,
                            const n00b_static_identity_query_t *query,
                            n00b_alloc_range_t **out_range);
extern const char *
n00b_static_identity_status_name(n00b_static_identity_status_t status);

extern size_t n00b_static_objects_enumerate(n00b_static_object_iter_cb cb,
                                            void *user);
extern size_t n00b_static_objects_register_all(void);
extern n00b_alloc_range_t *
n00b_static_object_register_desc(const n00b_static_object_desc_t *desc);

#if defined(__APPLE__)
struct mach_header;
extern size_t n00b_static_objects_register_macho_image(
    const struct mach_header *hdr,
    intptr_t slide);
#endif
