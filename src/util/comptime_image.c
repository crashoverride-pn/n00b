#include "n00b.h"
#include "util/comptime_image.h"
#include "util/marshal.h"

#include "core/buffer.h"
#include "core/mmaps.h"
#include "core/runtime.h"

struct n00b_ct_image_repair_registration_t {
    void                                  *image_base;
    n00b_ct_image_repair_hook_t            hook;
    n00b_ct_image_repair_registration_t   *next;
};

static size_t
ct_image_align8(size_t n)
{
    return (n + 7u) & ~(size_t)7u;
}

static bool
ct_image_static_identity_valid(const n00b_static_identity_t *identity)
{
    return identity != nullptr
        && identity->version == N00B_STATIC_IDENTITY_VERSION
        && identity->kind != N00B_STATIC_IDENTITY_NONE
        && identity->namespace_id != nullptr
        && identity->namespace_id[0] != '\0'
        && identity->object_key != nullptr
        && identity->object_key[0] != '\0';
}

static const n00b_static_identity_t *
ct_image_root_source_identity(void *root)
{
    auto range_opt = n00b_mmap_range_by_address(root);
    if (!n00b_option_is_set(range_opt)) {
        return nullptr;
    }

    n00b_alloc_range_t *range = n00b_option_get(range_opt);
    if (range->start != root || !ct_image_static_identity_valid(range->identity)) {
        return nullptr;
    }
    return range->identity;
}

static n00b_allocator_t *
ct_image_system_allocator(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->system_pool;
}

static void
ct_image_repair_hook_lock_acquire(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    int64_t tid = n00b_thread_unique_id();
    int64_t expected = -1;

    do {
        if (expected == tid) {
            break;
        }
        expected = -1;
    } while (!n00b_cas(&rt->ct_image_repair_hook_lock, &expected, tid));
}

static void
ct_image_repair_hook_lock_release(void)
{
    n00b_atomic_store(&n00b_get_runtime()->ct_image_repair_hook_lock, (int64_t)-1);
}

static n00b_ct_image_repair_registration_t **
ct_image_repair_hook_slot(void *image_base)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    n00b_ct_image_repair_registration_t **slot = &rt->ct_image_repair_hooks;

    while (*slot != nullptr && (*slot)->image_base != image_base) {
        slot = &(*slot)->next;
    }
    return slot;
}

static n00b_option_t(n00b_ct_image_repair_hook_t)
ct_image_registered_repair_hook(void *image_base)
{
    ct_image_repair_hook_lock_acquire();
    n00b_ct_image_repair_registration_t **slot = ct_image_repair_hook_slot(image_base);
    if (*slot == nullptr || (*slot)->hook.fn == nullptr) {
        ct_image_repair_hook_lock_release();
        return n00b_option_none(n00b_ct_image_repair_hook_t);
    }

    n00b_ct_image_repair_hook_t hook = (*slot)->hook;
    ct_image_repair_hook_lock_release();
    return n00b_option_set(n00b_ct_image_repair_hook_t, hook);
}

static bool
ct_image_identity_record_len(const n00b_static_identity_t *identity,
                             size_t *record_len_out,
                             uint32_t *namespace_len_out,
                             uint32_t *key_len_out)
{
    if (!ct_image_static_identity_valid(identity)) {
        return false;
    }

    size_t namespace_len = strlen(identity->namespace_id);
    size_t key_len       = strlen(identity->object_key);
    size_t record_len    = ct_image_align8(sizeof(n00b_ct_image_root_identity_record_t)
                                           + namespace_len
                                           + key_len);

    if (namespace_len == 0 || key_len == 0
        || namespace_len > UINT32_MAX || key_len > UINT32_MAX
        || record_len > UINT32_MAX) {
        return false;
    }

    *record_len_out    = record_len;
    *namespace_len_out = (uint32_t)namespace_len;
    *key_len_out       = (uint32_t)key_len;
    return true;
}

static bool
ct_image_validate_root_identity_record(const n00b_ct_image_header_t *hdr,
                                       size_t image_len)
{
    if ((hdr->flags & N00B_CT_IMAGE_FLAG_ROOT_IDENTITY) == 0) {
        return true;
    }
    if (hdr->marshal_off <= sizeof(*hdr)
        || hdr->marshal_off > image_len
        || hdr->marshal_off - sizeof(*hdr) < sizeof(n00b_ct_image_root_identity_record_t)) {
        return false;
    }

    const n00b_ct_image_root_identity_record_t *rec =
        (const void *)((const char *)hdr + sizeof(*hdr));
    size_t ext_len = hdr->marshal_off - sizeof(*hdr);
    if (rec->record_magic != N00B_CT_IMAGE_ROOT_IDENTITY_MAGIC
        || rec->record_len == 0
        || rec->record_len > ext_len
        || (rec->record_len & 7u) != 0
        || rec->identity_version != N00B_STATIC_IDENTITY_VERSION
        || rec->identity_kind == N00B_STATIC_IDENTITY_NONE
        || rec->namespace_len == 0
        || rec->key_len == 0) {
        return false;
    }

    size_t used = sizeof(*rec)
                + (size_t)rec->namespace_len
                + (size_t)rec->key_len;
    if (used > rec->record_len) {
        return false;
    }

    const char *namespace_id = (const char *)(rec + 1);
    const char *object_key   = namespace_id + rec->namespace_len;
    return memchr(namespace_id, '\0', rec->namespace_len) == nullptr
        && memchr(object_key, '\0', rec->key_len) == nullptr;
}

uint16_t
n00b_ct_image_host_abi_tag(void)
{
    uint16_t tag = 0;
    tag |= (uint16_t)(sizeof(void *) & 0xffu);
    tag |= (uint16_t)((sizeof(uint64_t) & 0x0fu) << 8);

    uint16_t endian_probe = 1;
    if (*(uint8_t *)&endian_probe == 1) {
        tag |= UINT16_C(1) << 12;
    }
    return tag;
}

n00b_string_t *
n00b_ct_image_status_name(n00b_ct_image_status_t code)
{
    switch (code) {
    case N00B_CT_IMAGE_OK:
        return r"ok";
    case N00B_CT_IMAGE_ERR_NULL_ARG:
        return r"null-arg";
    case N00B_CT_IMAGE_ERR_BAD_HEADER:
        return r"bad-header";
    case N00B_CT_IMAGE_ERR_BAD_ABI:
        return r"bad-abi";
    case N00B_CT_IMAGE_ERR_UNSUPPORTED_ROOTS:
        return r"unsupported-roots";
    case N00B_CT_IMAGE_ERR_MARSHAL:
        return r"marshal";
    case N00B_CT_IMAGE_ERR_LIMIT:
        return r"limit";
    case N00B_CT_IMAGE_ERR_NONPORTABLE:
        return r"nonportable";
    }
    return r"unknown";
}

static n00b_result_t(n00b_buffer_t *)
ct_image_export_raw(void *root, n00b_allocator_t *allocator, uint32_t flags)
{
    if (root == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_NULL_ARG);
    }
    if ((flags & ~(N00B_CT_IMAGE_FLAG_WRITABLE
                   | N00B_CT_IMAGE_FLAG_ROOT_IDENTITY)) != 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_BAD_HEADER);
    }

    const n00b_static_identity_t *root_identity =
        ct_image_root_source_identity(root);
    size_t   identity_record_len = 0;
    uint32_t namespace_len = 0;
    uint32_t key_len = 0;
    if (root_identity != nullptr) {
        if (!ct_image_identity_record_len(root_identity,
                                          &identity_record_len,
                                          &namespace_len,
                                          &key_len)) {
            return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_BAD_HEADER);
        }
        flags |= N00B_CT_IMAGE_FLAG_ROOT_IDENTITY;
    }

    n00b_marshal_ctx_t *mctx = n00b_marshal_ctx_new(.flags = N00B_MARSHAL_F_STW);
    n00b_buffer_t      *payload = n00b_marshal_incremental(mctx, root);
    if (payload == nullptr || n00b_marshal_ctx_status(mctx) != N00B_MARSHAL_OK) {
        n00b_marshal_ctx_destroy(mctx);
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_MARSHAL);
    }

    n00b_result_t(bool) portable = n00b_marshal_stream_is_comptime_portable(payload);
    if (n00b_result_is_err(portable)) {
        n00b_marshal_ctx_destroy(mctx);
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_MARSHAL);
    }
    if (!n00b_result_get(portable)) {
        n00b_marshal_ctx_destroy(mctx);
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_NONPORTABLE);
    }

    size_t header_len = sizeof(n00b_ct_image_header_t) + identity_record_len;

    if (payload->byte_len > UINT32_MAX
        || sizeof(n00b_ct_image_header_t) > UINT32_MAX
        || header_len > UINT32_MAX
        || payload->byte_len > SIZE_MAX - header_len) {
        n00b_marshal_ctx_destroy(mctx);
        return n00b_result_err(n00b_buffer_t *, N00B_CT_IMAGE_ERR_LIMIT);
    }

    n00b_ct_image_header_t hdr = {
        .magic       = N00B_CT_IMAGE_MAGIC,
        .version     = N00B_CT_IMAGE_VERSION,
        .abi_tag     = n00b_ct_image_host_abi_tag(),
        .marshal_off = (uint32_t)header_len,
        .marshal_len = (uint32_t)payload->byte_len,
        .root_count  = 1,
        .flags       = flags,
    };

    n00b_buffer_t *image = n00b_buffer_new(
        (int64_t)(header_len + payload->byte_len),
        .allocator = allocator);
    memcpy(image->data, &hdr, sizeof(hdr));
    if (root_identity != nullptr) {
        n00b_ct_image_root_identity_record_t rec = {
            .record_magic     = N00B_CT_IMAGE_ROOT_IDENTITY_MAGIC,
            .record_len       = (uint32_t)identity_record_len,
            .identity_version = root_identity->version,
            .identity_kind    = root_identity->kind,
            .namespace_len    = namespace_len,
            .key_len          = key_len,
        };
        char *ext = image->data + sizeof(hdr);
        memcpy(ext, &rec, sizeof(rec));
        memcpy(ext + sizeof(rec), root_identity->namespace_id, namespace_len);
        memcpy(ext + sizeof(rec) + namespace_len,
               root_identity->object_key,
               key_len);
        memset(ext + sizeof(rec) + namespace_len + key_len,
               0,
               identity_record_len - sizeof(rec) - namespace_len - key_len);
    }
    memcpy(image->data + header_len, payload->data, payload->byte_len);
    image->byte_len = header_len + payload->byte_len;

    n00b_marshal_ctx_destroy(mctx);
    return n00b_result_ok(n00b_buffer_t *, image);
}

n00b_result_t(n00b_buffer_t *)
n00b_ct_image_export(void *root) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return ct_image_export_raw(root, allocator, 0);
}

n00b_result_t(n00b_buffer_t *)
n00b_ct_image_export_writable(void *root) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return ct_image_export_raw(root, allocator, N00B_CT_IMAGE_FLAG_WRITABLE);
}

static n00b_result_t(void *)
ct_image_relocate_raw(void *image_base,
                      size_t image_len,
                      const n00b_ct_image_repair_hook_t *repair_hook)
{
    if (image_base == nullptr) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_NULL_ARG);
    }
    if (image_len < sizeof(n00b_ct_image_header_t)) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_BAD_HEADER);
    }

    n00b_ct_image_header_t *hdr = image_base;
    if (hdr->magic != N00B_CT_IMAGE_MAGIC
        || hdr->version != N00B_CT_IMAGE_VERSION
        || (hdr->flags & ~(N00B_CT_IMAGE_FLAG_WRITABLE
                           | N00B_CT_IMAGE_FLAG_ROOT_IDENTITY)) != 0
        || hdr->root_count != 1) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_BAD_HEADER);
    }
    if (hdr->abi_tag != n00b_ct_image_host_abi_tag()) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_BAD_ABI);
    }
    if (hdr->marshal_off < sizeof(*hdr)
        || hdr->marshal_off > image_len
        || hdr->marshal_len > image_len - hdr->marshal_off) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_BAD_HEADER);
    }
    if (!ct_image_validate_root_identity_record(hdr, image_len)) {
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_BAD_HEADER);
    }

    n00b_unmarshal_ctx_t *uctx = n00b_unmarshal_ctx_new();
    auto relocate_r = n00b_unmarshal_relocate_inplace(
        uctx,
        (char *)image_base + hdr->marshal_off,
        hdr->marshal_len);
    if (n00b_result_is_err(relocate_r)) {
        n00b_unmarshal_ctx_destroy(uctx);
        return n00b_result_err(void *, N00B_CT_IMAGE_ERR_MARSHAL);
    }

    void *root = n00b_result_get(relocate_r);
    n00b_ct_image_repair_hook_t registered_hook = {};
    if (repair_hook == nullptr || repair_hook->fn == nullptr) {
        auto hook_opt = ct_image_registered_repair_hook(image_base);
        if (n00b_option_is_set(hook_opt)) {
            registered_hook = n00b_option_get(hook_opt);
            repair_hook = &registered_hook;
        }
    }
    if (repair_hook != nullptr && repair_hook->fn != nullptr) {
        auto repair_r = repair_hook->fn(image_base,
                                        image_len,
                                        root,
                                        repair_hook->user);
        if (n00b_result_is_err(repair_r) || !n00b_result_get(repair_r)) {
            n00b_unmarshal_ctx_destroy(uctx);
            return n00b_result_err(void *, N00B_CT_IMAGE_ERR_MARSHAL);
        }
    }
    n00b_unmarshal_ctx_destroy(uctx);
    return n00b_result_ok(void *, root);
}

n00b_result_t(void *)
n00b_ct_image_relocate_inplace(void *image_base, size_t image_len)
{
    return ct_image_relocate_raw(image_base, image_len, nullptr);
}

n00b_result_t(void *)
n00b_ct_image_relocate_inplace_ex(void *image_base,
                                  size_t image_len,
                                  const n00b_ct_image_repair_hook_t *repair_hook)
{
    return ct_image_relocate_raw(image_base, image_len, repair_hook);
}

n00b_result_t(bool)
n00b_ct_image_set_repair_hook(void *image_base,
                              const n00b_ct_image_repair_hook_t *repair_hook)
{
    if (image_base == nullptr) {
        return n00b_result_err(bool, N00B_CT_IMAGE_ERR_NULL_ARG);
    }

    ct_image_repair_hook_lock_acquire();
    n00b_ct_image_repair_registration_t **slot = ct_image_repair_hook_slot(image_base);
    if (repair_hook == nullptr || repair_hook->fn == nullptr) {
        if (*slot != nullptr) {
            *slot = (*slot)->next;
        }
        ct_image_repair_hook_lock_release();
        return n00b_result_ok(bool, true);
    }

    if (*slot == nullptr) {
        *slot = n00b_alloc(n00b_ct_image_repair_registration_t,
                           .allocator = ct_image_system_allocator());
        (*slot)->image_base = image_base;
    }
    (*slot)->hook = *repair_hook;
    ct_image_repair_hook_lock_release();
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_option_t(n00b_static_identity_t *))
n00b_ct_image_root_identity(void *image_base, size_t image_len) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (image_base == nullptr || image_len < sizeof(n00b_ct_image_header_t)) {
        return n00b_result_err(n00b_option_t(n00b_static_identity_t *),
                               N00B_CT_IMAGE_ERR_NULL_ARG);
    }

    n00b_ct_image_header_t *hdr = image_base;
    if (hdr->magic != N00B_CT_IMAGE_MAGIC) {
        return n00b_result_err(n00b_option_t(n00b_static_identity_t *),
                               N00B_CT_IMAGE_ERR_BAD_HEADER);
    }
    if ((hdr->flags & N00B_CT_IMAGE_FLAG_ROOT_IDENTITY) == 0) {
        return n00b_result_ok(n00b_option_t(n00b_static_identity_t *),
                              n00b_option_none(n00b_static_identity_t *));
    }
    if (!ct_image_validate_root_identity_record(hdr, image_len)) {
        return n00b_result_err(n00b_option_t(n00b_static_identity_t *),
                               N00B_CT_IMAGE_ERR_BAD_HEADER);
    }

    const n00b_ct_image_root_identity_record_t *rec =
        (const void *)((const char *)image_base + sizeof(*hdr));
    const char *namespace_src = (const char *)(rec + 1);
    const char *key_src       = namespace_src + rec->namespace_len;

    n00b_allocator_t *alloc = allocator != nullptr ? allocator : ct_image_system_allocator();
    n00b_static_identity_t *identity = n00b_alloc(n00b_static_identity_t,
                                                  .allocator = alloc);
    char *namespace_id = n00b_alloc_array_with_opts(
        char,
        rec->namespace_len + 1,
        &(n00b_alloc_opts_t){ .allocator = alloc,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE });
    char *object_key = n00b_alloc_array_with_opts(
        char,
        rec->key_len + 1,
        &(n00b_alloc_opts_t){ .allocator = alloc,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE });

    memcpy(namespace_id, namespace_src, rec->namespace_len);
    namespace_id[rec->namespace_len] = '\0';
    memcpy(object_key, key_src, rec->key_len);
    object_key[rec->key_len] = '\0';

    *identity = (n00b_static_identity_t){
        .version      = rec->identity_version,
        .kind         = (n00b_static_identity_kind_t)rec->identity_kind,
        .namespace_id = namespace_id,
        .object_key   = object_key,
    };
    return n00b_result_ok(n00b_option_t(n00b_static_identity_t *),
                          n00b_option_set(n00b_static_identity_t *, identity));
}
