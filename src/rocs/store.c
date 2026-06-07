#include "rocs/store.h"

#include "conduit/conduit.h"
#include "core/buffer.h"
#include "core/data_lock.h"
#include "core/hash.h"
#include "core/thread.h"
#include "core/time.h"
#include "internal/rocs/store.h"
#include "rocs/normalizer.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"
#include "util/worker_pool.h"
#include "vfs/vfs.h"

typedef n00b_list_t(n00b_store_field_t *) rocs_store_field_list_t;
typedef n00b_list_t(n00b_store_catalog_entry_t *)
    rocs_store_catalog_list_t;
typedef n00b_list_t(n00b_store_posting_list_t *)
    rocs_store_posting_target_list_t;
typedef struct rocs_store_batch_term rocs_store_batch_term_t;
typedef n00b_list_t(rocs_store_batch_term_t *)
    rocs_store_batch_term_list_t;

N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_commit_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_commit_t);
N00B_CONDUIT_SUBSCRIPTION_IMPL(n00b_store_ingest_payload_t);
N00B_CONDUIT_TOPIC_IMPL(n00b_store_ingest_payload_t);

#define ROCS_STORE_CATALOG_MAGIC_LEN 8
#define ROCS_STORE_CATALOG_VERSION   2
#define ROCS_STORE_CATALOG_VERSION_MIN 1

struct n00b_store_field_t {
    n00b_string_t          *name;
    bool                    required;
    n00b_store_index_kind_t index_kind;
};

struct n00b_store_schema_t {
    rocs_store_field_list_t *fields;
    n00b_allocator_t        *allocator;
    bool                     frozen;
};

struct n00b_store_partition_policy_t {
    n00b_store_partition_kind_t kind;
    n00b_string_t              *field;
    uint64_t                    bucket_width;
    uint32_t                    buckets;
};

struct n00b_store_retain_policy_t {
    n00b_store_retain_kind_t kind;
};

struct n00b_store_shard_retention_policy_t {
    uint64_t       max_sealed_shards;
    uint64_t       drop_before_seal_ts;
    n00b_string_t *drop_reason;
};

struct n00b_store_seal_policy_t {
    uint64_t max_records;
    uint64_t max_bytes;
    uint64_t max_open_ns;
};

struct n00b_store_catalog_entry_t {
    n00b_store_t  *owner;
    n00b_string_t *object_path;
    n00b_string_t *partition_key;
    n00b_string_t *etag;
    n00b_store_map_t *resident_map;
    uint64_t       shard_id;
    uint64_t       generation;
    uint64_t       byte_len;
    uint64_t       record_count;
    uint64_t       schema_generation;
    uint64_t       seal_ts;
    uint64_t       resident_pins;
    uint64_t       last_access_ns;
};

struct n00b_store_t {
    n00b_vfs_t                    *vfs;
    n00b_string_t                 *root;
    n00b_string_t                 *display_name;
    n00b_store_schema_t           *schema;
    n00b_store_partition_policy_t *partition_policy;
    n00b_store_retain_policy_t    *retain_policy;
    n00b_store_seal_policy_t      *seal_policy;
    n00b_store_residency_policy_t  residency_policy;
    n00b_vfs_cache_t              *cache;
    n00b_store_commit_topic_t     *commit_topic;
    n00b_store_lifecycle_topic_t  *lifecycle_topic;
    n00b_store_shard_t            *hot_shard;
    n00b_string_t                 *hot_partition_key;
    rocs_store_catalog_list_t     *catalog;
    n00b_allocator_t              *allocator;
    n00b_rwlock_t                 *residency_lock;
    n00b_rwlock_t                 *commit_lock;
    n00b_store_state_t             state;
    uint64_t                       next_shard_id;
    uint64_t                       generation;
    uint64_t                       schema_generation;
    n00b_store_pos_t               oldest_available;
    bool                           has_oldest_available;
    uint64_t                       active_pins;
    uint64_t                       resident_bytes;
    uint64_t                       resident_shards;
};

struct n00b_store_pin_t {
    n00b_store_t *store;
    bool          released;
};

struct n00b_store_resident_shard_t {
    n00b_store_t               *store;
    n00b_store_catalog_entry_t *entry;
    bool                        released;
};

struct rocs_store_batch_term {
    n00b_string_t  *field;
    n00b_uint128_t  key;
};

typedef struct {
    n00b_store_t                   *store;
    n00b_json_node_t               *input_record;
    n00b_buffer_t                  *source;
    n00b_json_node_t               *record;
    n00b_buffer_t                  *raw;
    n00b_string_t                  *route;
    rocs_store_batch_term_list_t   *terms;
    n00b_err_t                      err;
} rocs_store_batch_job_t;

struct n00b_store_conduit_ingest_t {
    n00b_store_t                       *store;
    n00b_store_ingest_topic_t          *topic;
    n00b_store_ingest_inbox_t          *inbox;
    n00b_conduit_sub_handle_t           sub;
    n00b_worker_pool_t                 *pool;
    n00b_thread_t                      *thread;
    n00b_rwlock_t                      *lock;
    n00b_allocator_t                   *allocator;
    n00b_store_conduit_ingest_stats_t   stats;
    bool                                stop_requested;
    bool                                closed;
    bool                                joined;
};

typedef struct {
    n00b_store_conduit_ingest_t *adapter;
    n00b_store_ingest_payload_t  payload;
} rocs_store_conduit_job_t;

static rocs_store_field_list_t *
rocs_store_field_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_field_list_t *fields = n00b_alloc_with_opts(
        rocs_store_field_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *fields = n00b_list_new_private(n00b_store_field_t *,
                                    .allocator = allocator,
                                    .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return fields;
}

static rocs_store_catalog_list_t *
rocs_store_catalog_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_catalog_list_t *entries = n00b_alloc_with_opts(
        rocs_store_catalog_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *entries = n00b_list_new_private(n00b_store_catalog_entry_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return entries;
}

static bool
rocs_store_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->u8_bytes == 0;
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_catalog_buffer_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_buffer_t *buf = n00b_buffer_new(0, .allocator = allocator);
    if (buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_INTERNAL);
    }
    return n00b_result_ok(n00b_buffer_t *, buf);
}

static n00b_result_t(bool)
rocs_store_catalog_append_u8(n00b_buffer_t *buf, uint8_t byte)
{
    if (buf == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    uint64_t pos = (uint64_t)n00b_buffer_len(buf);
    if (pos >= (uint64_t)INT64_MAX) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_buffer_resize(buf, pos + 1);
    auto set_r = n00b_buffer_set_index(buf, (int64_t)pos, byte);
    if (n00b_result_is_err(set_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_append_u64(n00b_buffer_t *buf, uint64_t value)
{
    for (uint8_t i = 0; i < 8; i++) {
        auto append_r = rocs_store_catalog_append_u8(
            buf,
            (uint8_t)((value >> (i * 8)) & 0xff));
        if (n00b_result_is_err(append_r)) {
            return append_r;
        }
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_append_string(n00b_buffer_t *buf, n00b_string_t *s) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    uint64_t len = s == nullptr ? 0 : (uint64_t)s->u8_bytes;
    if (len > (uint64_t)INT64_MAX) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    auto len_r = rocs_store_catalog_append_u64(buf, len);
    if (n00b_result_is_err(len_r)) {
        return len_r;
    }
    if (len == 0) {
        return n00b_result_ok(bool, true);
    }

    n00b_buffer_t *piece = n00b_buffer_from_bytes(s->data,
                                                  (int64_t)len,
                                                  .allocator = allocator);
    if (piece == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }
    n00b_buffer_concat(buf, piece);
    return n00b_result_ok(bool, true);
}

typedef struct {
    n00b_buffer_t *buf;
    uint64_t       pos;
    uint64_t       len;
} rocs_store_catalog_reader_t;

static n00b_result_t(uint8_t)
rocs_store_catalog_read_u8(rocs_store_catalog_reader_t *reader)
{
    if (reader == nullptr || reader->buf == nullptr
        || reader->pos >= reader->len || reader->pos > (uint64_t)INT64_MAX) {
        return n00b_result_err(uint8_t, N00B_STORE_ERR_CORRUPT);
    }

    auto byte_r = n00b_buffer_get_index(reader->buf, (int64_t)reader->pos);
    if (n00b_result_is_err(byte_r)) {
        return n00b_result_err(uint8_t, N00B_STORE_ERR_CORRUPT);
    }

    reader->pos++;
    return n00b_result_ok(uint8_t, n00b_result_get(byte_r));
}

static n00b_result_t(uint64_t)
rocs_store_catalog_read_u64(rocs_store_catalog_reader_t *reader)
{
    uint64_t value = 0;

    for (uint8_t i = 0; i < 8; i++) {
        auto byte_r = rocs_store_catalog_read_u8(reader);
        if (n00b_result_is_err(byte_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(byte_r));
        }
        value |= ((uint64_t)n00b_result_get(byte_r)) << (i * 8);
    }

    return n00b_result_ok(uint64_t, value);
}

static n00b_result_t(n00b_string_t *)
rocs_store_catalog_read_string(rocs_store_catalog_reader_t *reader) _kargs
{
    bool              allow_empty = true;
    n00b_allocator_t *allocator   = nullptr;
}
{
    auto len_r = rocs_store_catalog_read_u64(reader);
    if (n00b_result_is_err(len_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(len_r));
    }

    uint64_t len = n00b_result_get(len_r);
    if (!allow_empty && len == 0) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_CORRUPT);
    }
    if (reader->pos > reader->len || len > (uint64_t)INT64_MAX
        || reader->len - reader->pos < len) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_CORRUPT);
    }
    if (len == 0) {
        return n00b_result_ok(n00b_string_t *, nullptr);
    }

    n00b_string_t *value =
        n00b_string_from_raw(reader->buf->data + reader->pos,
                             (int64_t)len,
                             .allocator = allocator);
    reader->pos += len;
    return n00b_result_ok(n00b_string_t *, value);
}

static bool
rocs_store_root_valid(n00b_string_t *root)
{
    return !rocs_store_string_empty(root) && root->data != nullptr
        && root->data[0] == '/';
}

static n00b_result_t(n00b_string_t *)
rocs_store_path_join(n00b_string_t *parent, n00b_string_t *child) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (parent == nullptr || child == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    if (parent->u8_bytes == 1 && parent->data[0] == '/') {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_unicode_str_cat(r"/", child, .allocator = allocator));
    }
    if (parent->u8_bytes > 0 && parent->data[parent->u8_bytes - 1] == '/') {
        return n00b_result_ok(
            n00b_string_t *,
            n00b_unicode_str_cat(parent, child, .allocator = allocator));
    }

    n00b_string_t *with_slash =
        n00b_unicode_str_cat(parent, r"/", .allocator = allocator);
    return n00b_result_ok(
        n00b_string_t *,
        n00b_unicode_str_cat(with_slash, child, .allocator = allocator));
}

static n00b_result_t(n00b_string_t *)
rocs_store_parent_path(n00b_string_t *path) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_store_root_valid(path)) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    uint64_t last_slash = 0;
    for (uint64_t i = 1; i < path->u8_bytes; i++) {
        if (path->data[i] == '/') {
            last_slash = i;
        }
    }

    if (last_slash == 0) {
        return n00b_result_ok(n00b_string_t *, r"/");
    }

    return n00b_result_ok(
        n00b_string_t *,
        n00b_string_from_raw(path->data,
                             (int64_t)last_slash,
                             .allocator = allocator));
}

static n00b_result_t(n00b_string_t *)
rocs_store_catalog_path(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    auto path_r = rocs_store_path_join(store->root,
                                       r"catalog.rocs",
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static n00b_result_t(n00b_string_t *)
rocs_store_shard_dir_path(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    auto path_r = rocs_store_path_join(store->root,
                                       r"shards",
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static n00b_result_t(n00b_string_t *)
rocs_store_shard_object_path(n00b_store_t *store, uint64_t shard_id)
{
    if (shard_id > (uint64_t)INT64_MAX) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    auto dir_r = rocs_store_shard_dir_path(store);
    if (n00b_result_is_err(dir_r)) {
        return dir_r;
    }

    n00b_string_t *id_s =
        n00b_unicode_str_from_int((int64_t)shard_id,
                                  .allocator = store->allocator);
    n00b_string_t *file =
        n00b_unicode_str_cat(id_s, r".n00b", .allocator = store->allocator);
    auto path_r = rocs_store_path_join(n00b_result_get(dir_r),
                                       file,
                                       .allocator = store->allocator);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_string_t *, n00b_result_get_err(path_r));
    }
    return path_r;
}

static bool
rocs_store_index_kind_valid(n00b_store_index_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_INDEX_NONE:
    case N00B_STORE_INDEX_TERM:
    case N00B_STORE_INDEX_FULLTEXT:
    case N00B_STORE_INDEX_NGRAM:
    case N00B_STORE_INDEX_NUMERIC:
    case N00B_STORE_INDEX_BOOL:
    case N00B_STORE_INDEX_VECTOR:
        return true;
    }
    return false;
}

static n00b_option_t(n00b_store_field_t *)
rocs_store_schema_find_field_raw(n00b_store_schema_t *schema,
                                 n00b_string_t       *name)
{
    if (schema == nullptr || schema->fields == nullptr || name == nullptr) {
        return n00b_option_none(n00b_store_field_t *);
    }

    n00b_list_foreach(*schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field != nullptr && field->name != nullptr
            && n00b_unicode_str_eq(field->name, name)) {
            return n00b_option_set(n00b_store_field_t *, field);
        }
    }

    return n00b_option_none(n00b_store_field_t *);
}

static n00b_store_partition_policy_t *
rocs_store_partition_policy_new(n00b_store_partition_kind_t kind) _kargs
{
    n00b_string_t    *field        = nullptr;
    uint64_t          bucket_width = 0;
    uint32_t          buckets      = 0;
    n00b_allocator_t *allocator    = nullptr;
}
{
    n00b_store_partition_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_partition_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    policy->kind         = kind;
    policy->field        = field;
    policy->bucket_width = bucket_width;
    policy->buckets      = buckets;
    return policy;
}

static n00b_result_t(n00b_string_t *)
rocs_store_route_bucket(n00b_string_t *prefix,
                        uint64_t       bucket) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bucket > (uint64_t)INT64_MAX) {
        return n00b_result_ok(n00b_string_t *, r"default");
    }

    n00b_string_t *bucket_s =
        n00b_unicode_str_from_int((int64_t)bucket, .allocator = allocator);
    n00b_string_t *route =
        n00b_unicode_str_cat(prefix, bucket_s, .allocator = allocator);
    return n00b_result_ok(n00b_string_t *, route);
}

static n00b_option_t(uint64_t)
rocs_store_time_bucket_from_route(n00b_string_t *route)
{
    if (route == nullptr || route->data == nullptr || route->u8_bytes <= 5) {
        return n00b_option_none(uint64_t);
    }
    if (route->data[0] != 't' || route->data[1] != 'i'
        || route->data[2] != 'm' || route->data[3] != 'e'
        || route->data[4] != '/') {
        return n00b_option_none(uint64_t);
    }

    uint64_t bucket = 0;
    for (uint64_t i = 5; i < route->u8_bytes; i++) {
        uint8_t c = (uint8_t)route->data[i];
        if (c < (uint8_t)'0' || c > (uint8_t)'9') {
            return n00b_option_none(uint64_t);
        }
        uint64_t digit = (uint64_t)(c - (uint8_t)'0');
        if (bucket > (UINT64_MAX - digit) / 10) {
            return n00b_option_none(uint64_t);
        }
        bucket = bucket * 10 + digit;
    }

    return n00b_option_set(uint64_t, bucket);
}

static n00b_option_t(n00b_json_node_t *)
rocs_store_partition_value(n00b_store_partition_policy_t *policy,
                           n00b_json_node_t              *record)
{
    if (policy == nullptr || policy->field == nullptr || record == nullptr
        || n00b_json_type(record) != N00B_JSON_OBJECT) {
        return n00b_option_none(n00b_json_node_t *);
    }

    return n00b_option_from_nullable(n00b_json_node_t *,
                                     n00b_json_object_get(record,
                                                          policy->field));
}

static bool
rocs_store_retain_kind_valid(n00b_store_retain_kind_t kind)
{
    switch (kind) {
    case N00B_STORE_RETAIN_NONE:
    case N00B_STORE_RETAIN_INLINE:
    case N00B_STORE_RETAIN_EXTERNAL:
        return true;
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_ensure_dir(n00b_store_t *store, n00b_string_t *path)
{
    auto stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_ok(stat_r)) {
        if (n00b_result_get(stat_r).kind == N00B_VFS_OBJ_DIR) {
            return n00b_result_ok(bool, true);
        }
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    if (n00b_result_get_err(stat_r) != N00B_VFS_ERR_NOT_FOUND) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto mkdir_r = n00b_vfs_mkdir(store->vfs, path);
    if (n00b_result_is_ok(mkdir_r)) {
        return n00b_result_ok(bool, true);
    }
    if (n00b_result_get_err(mkdir_r) == N00B_VFS_ERR_EXISTS) {
        return n00b_result_ok(bool, true);
    }

    return n00b_result_err(bool, N00B_STORE_ERR_VFS);
}

static n00b_result_t(bool)
rocs_store_ensure_layout(n00b_store_t *store)
{
    auto root_r = rocs_store_ensure_dir(store, store->root);
    if (n00b_result_is_err(root_r)) {
        return root_r;
    }

    auto shard_dir_r = rocs_store_shard_dir_path(store);
    if (n00b_result_is_err(shard_dir_r)) {
        return n00b_result_err(bool, n00b_result_get_err(shard_dir_r));
    }

    return rocs_store_ensure_dir(store, n00b_result_get(shard_dir_r));
}

static n00b_result_t(bool)
rocs_store_sync_if_supported(n00b_store_t *store, n00b_string_t *path)
{
    auto sync_r = n00b_vfs_sync(store->vfs, path);
    if (n00b_result_is_ok(sync_r)) {
        return n00b_result_ok(bool, true);
    }
    if (n00b_result_get_err(sync_r) == N00B_VFS_ERR_NOT_SUPPORTED) {
        return n00b_result_ok(bool, false);
    }
    return n00b_result_err(bool, N00B_STORE_ERR_VFS);
}

static n00b_result_t(bool)
rocs_store_sync_path_and_parent(n00b_store_t *store, n00b_string_t *path)
{
    auto sync_r = rocs_store_sync_if_supported(store, path);
    if (n00b_result_is_err(sync_r)) {
        return sync_r;
    }

    auto parent_r = rocs_store_parent_path(path, .allocator = store->allocator);
    if (n00b_result_is_err(parent_r)) {
        return n00b_result_err(bool, n00b_result_get_err(parent_r));
    }

    return rocs_store_sync_if_supported(store, n00b_result_get(parent_r));
}

static n00b_result_t(bool)
rocs_store_write_vfs_object(n00b_store_t  *store,
                            n00b_string_t *path,
                            n00b_buffer_t *data) _kargs
{
    bool create_exclusive = false;
}
{
    if (store == nullptr || path == nullptr || data == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    uint32_t flags = N00B_VFS_O_W
                   | (create_exclusive ? N00B_VFS_OPEN_EXCL : 0);
    auto open_r = n00b_vfs_open(store->vfs, path, flags);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_fh_t fh  = n00b_result_get(open_r);
    uint64_t       len = (uint64_t)n00b_buffer_len(data);

    auto write_r = n00b_vfs_write(store->vfs, fh, data);
    if (n00b_result_is_err(write_r) || n00b_result_get(write_r) != len) {
        (void)n00b_vfs_close(store->vfs, fh);
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto close_r = n00b_vfs_close(store->vfs, fh);
    if (n00b_result_is_err(close_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    return rocs_store_sync_path_and_parent(store, path);
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_read_vfs_object(n00b_store_t *store, n00b_string_t *path)
{
    auto stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_err(stat_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }
    if (n00b_result_get(stat_r).kind != N00B_VFS_OBJ_FILE) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t expected_len = n00b_result_get(stat_r).size;
    auto     open_r       = n00b_vfs_open(store->vfs, path, N00B_VFS_O_R);
    if (n00b_result_is_err(open_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_fh_t fh     = n00b_result_get(open_r);
    auto          read_r = n00b_vfs_read(store->vfs,
                                         fh,
                                         expected_len,
                                         .allocator = store->allocator);
    auto          close_r = n00b_vfs_close(store->vfs, fh);

    if (n00b_result_is_err(read_r) || n00b_result_is_err(close_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_VFS);
    }
    if ((uint64_t)n00b_buffer_len(n00b_result_get(read_r)) != expected_len) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_CORRUPT);
    }

    return read_r;
}

static n00b_store_catalog_entry_t *
rocs_store_catalog_entry_new(n00b_store_t *store) _kargs
{
    uint64_t       shard_id          = 0;
    uint64_t       generation        = 0;
    n00b_string_t *object_path       = nullptr;
    uint64_t       byte_len          = 0;
    uint64_t       record_count      = 0;
    uint64_t       schema_generation = 0;
    uint64_t       seal_ts           = 0;
    n00b_string_t *partition_key     = nullptr;
    n00b_string_t *etag              = nullptr;
}
{
    n00b_store_catalog_entry_t *entry = n00b_alloc_with_opts(
        n00b_store_catalog_entry_t,
        &(n00b_alloc_opts_t){
            .allocator = store == nullptr ? nullptr : store->allocator,
        });

    entry->object_path       = object_path;
    entry->owner             = store;
    entry->partition_key     = partition_key == nullptr ? r"default" : partition_key;
    entry->etag              = etag;
    entry->shard_id          = shard_id;
    entry->generation        = generation;
    entry->byte_len          = byte_len;
    entry->record_count      = record_count;
    entry->schema_generation = schema_generation;
    entry->seal_ts           = seal_ts;
    return entry;
}

static n00b_option_t(n00b_store_catalog_entry_t *)
rocs_store_catalog_find_raw(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_option_none(n00b_store_catalog_entry_t *);
    }

    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry != nullptr && entry->shard_id == shard_id) {
            return n00b_option_set(n00b_store_catalog_entry_t *, entry);
        }
    }

    return n00b_option_none(n00b_store_catalog_entry_t *);
}

static bool
rocs_store_catalog_find_index(n00b_store_t *store,
                              uint64_t      shard_id,
                              uint64_t     *index_out)
{
    if (store == nullptr || store->catalog == nullptr) {
        return false;
    }

    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry != nullptr && entry->shard_id == shard_id) {
            if (index_out != nullptr) {
                *index_out = (uint64_t)i;
            }
            return true;
        }
    }

    return false;
}

static bool
rocs_store_entry_pos_less(n00b_store_catalog_entry_t *a,
                          n00b_store_catalog_entry_t *b)
{
    if (a == nullptr) {
        return false;
    }
    if (b == nullptr) {
        return true;
    }
    if (a->generation != b->generation) {
        return a->generation < b->generation;
    }
    return a->shard_id < b->shard_id;
}

static n00b_option_t(n00b_store_pos_t)
rocs_store_compute_oldest_available(n00b_store_t               *store,
                                    n00b_store_catalog_entry_t *pending_entry)
{
    if (store == nullptr) {
        return n00b_option_none(n00b_store_pos_t);
    }

    n00b_store_catalog_entry_t *oldest = nullptr;
    if (store->catalog != nullptr) {
        size_t len = n00b_list_len(*store->catalog);
        for (size_t i = 0; i < len; i++) {
            n00b_store_catalog_entry_t *entry =
                n00b_list_get(*store->catalog, i);
            if (entry != nullptr && rocs_store_entry_pos_less(entry, oldest)) {
                oldest = entry;
            }
        }
    }
    if (pending_entry != nullptr
        && rocs_store_entry_pos_less(pending_entry, oldest)) {
        oldest = pending_entry;
    }

    if (oldest == nullptr) {
        return n00b_option_none(n00b_store_pos_t);
    }

    return n00b_option_set(
        n00b_store_pos_t,
        ((n00b_store_pos_t){
            .shard_id   = oldest->shard_id,
            .ordinal    = 0,
            .generation = oldest->generation,
        }));
}

static void
rocs_store_refresh_oldest_available(n00b_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    n00b_option_t(n00b_store_pos_t) oldest =
        rocs_store_compute_oldest_available(store, nullptr);
    store->has_oldest_available = n00b_option_is_set(oldest);
    store->oldest_available =
        store->has_oldest_available
            ? n00b_option_get(oldest)
            : (n00b_store_pos_t){};
}

static bool
rocs_store_catalog_owns_entry(n00b_store_t              *store,
                              n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || store->catalog == nullptr || entry == nullptr) {
        return false;
    }

    n00b_list_foreach(*store->catalog, p) {
        if (*p == entry) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_resident_unload_entry(n00b_store_t              *store,
                                 n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (entry->resident_map == nullptr) {
        return n00b_result_ok(bool, false);
    }
    if (entry->resident_pins != 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    auto close_r = n00b_store_map_close(entry->resident_map);
    if (n00b_result_is_err(close_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_RESIDENCY);
    }

    entry->resident_map   = nullptr;
    entry->last_access_ns = 0;
    if (store->resident_bytes >= entry->byte_len) {
        store->resident_bytes -= entry->byte_len;
    }
    else {
        store->resident_bytes = 0;
    }
    if (store->resident_shards != 0) {
        store->resident_shards--;
    }
    return n00b_result_ok(bool, true);
}

static n00b_result_t(uint64_t)
rocs_store_resident_unload_all_unpinned(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t released = 0;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry == nullptr || entry->resident_map == nullptr) {
            continue;
        }
        if (entry->resident_pins != 0) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_PINNED);
        }
        uint64_t len = entry->byte_len;
        auto unload_r = rocs_store_resident_unload_entry(store, entry);
        if (n00b_result_is_err(unload_r)) {
            return n00b_result_err(uint64_t, n00b_result_get_err(unload_r));
        }
        if (n00b_result_get(unload_r)) {
            released += len;
        }
    }
    return n00b_result_ok(uint64_t, released);
}

static n00b_store_catalog_entry_t *
rocs_store_oldest_unpinned_resident(n00b_store_t *store, uint64_t now_ns)
{
    n00b_store_catalog_entry_t *best = nullptr;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry == nullptr || entry->resident_map == nullptr
            || entry->resident_pins != 0) {
            continue;
        }
        if (store->residency_policy.idle_ns != 0
            && entry->last_access_ns != 0
            && now_ns >= entry->last_access_ns
            && now_ns - entry->last_access_ns >= store->residency_policy.idle_ns) {
            return entry;
        }
        if (best == nullptr || entry->last_access_ns < best->last_access_ns) {
            best = entry;
        }
    }
    return best;
}

static n00b_result_t(n00b_store_map_t *)
rocs_store_resident_load_entry(n00b_store_t              *store,
                               n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    if (entry->resident_map != nullptr) {
        entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
        return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
    }

    auto verify_r = n00b_store_catalog_entry_verify_object(store, entry);
    if (n00b_result_is_err(verify_r)) {
        return n00b_result_err(n00b_store_map_t *, n00b_result_get_err(verify_r));
    }

    auto map_r = n00b_store_map_open_vfs(store->vfs,
                                         entry->object_path,
                                         .cache     = store->cache,
                                         .policy    = &store->residency_policy,
                                         .allocator = store->allocator);
    if (n00b_result_is_err(map_r)) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_RESIDENCY);
    }

    if (store->resident_bytes > UINT64_MAX - entry->byte_len
        || store->resident_shards == UINT64_MAX) {
        (void)n00b_store_map_close(n00b_result_get(map_r));
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }

    entry->resident_map   = n00b_result_get(map_r);
    entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
    store->resident_bytes += entry->byte_len;
    store->resident_shards++;
    return n00b_result_ok(n00b_store_map_t *, entry->resident_map);
}

static n00b_result_t(bool)
rocs_store_catalog_append_entry(n00b_store_t               *store,
                                n00b_buffer_t              *buf,
                                n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->object_path == nullptr
        || entry->partition_key == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    auto r = rocs_store_catalog_append_u64(buf, entry->shard_id);
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->generation);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->byte_len);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->record_count);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->schema_generation);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_u64(buf, entry->seal_ts);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->object_path,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->partition_key,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_ok(r)) {
        r = rocs_store_catalog_append_string(buf,
                                             entry->etag,
                                             .allocator = store->allocator);
    }
    if (n00b_result_is_err(r)) {
        return n00b_result_err(bool, n00b_result_get_err(r));
    }

    return n00b_result_ok(bool, true);
}

static n00b_result_t(n00b_buffer_t *)
rocs_store_catalog_serialize(n00b_store_t *store) _kargs
{
    n00b_store_catalog_entry_t *pending_entry       = nullptr;
    uint64_t                    next_open_shard_id  = 0;
}
{
    auto buf_r = rocs_store_catalog_buffer_new(.allocator = store->allocator);
    if (n00b_result_is_err(buf_r)) {
        return buf_r;
    }
    n00b_buffer_t *buf = n00b_result_get(buf_r);

    uint8_t magic[ROCS_STORE_CATALOG_MAGIC_LEN] = {
        'R', 'O', 'C', 'S', 'C', 'A', 'T', '1',
    };
    for (uint8_t i = 0; i < ROCS_STORE_CATALOG_MAGIC_LEN; i++) {
        auto magic_r = rocs_store_catalog_append_u8(buf, magic[i]);
        if (n00b_result_is_err(magic_r)) {
            return n00b_result_err(n00b_buffer_t *, n00b_result_get_err(magic_r));
        }
    }

    uint64_t serialized_open_shard_id =
        next_open_shard_id != 0
            ? next_open_shard_id
            : (store->hot_shard == nullptr ? store->next_shard_id
                                           : store->hot_shard->shard_id);

    uint64_t entry_count =
        store->catalog == nullptr ? 0 : (uint64_t)n00b_list_len(*store->catalog);
    if (pending_entry != nullptr) {
        entry_count++;
    }

    auto oldest_opt = rocs_store_compute_oldest_available(store, pending_entry);
    n00b_store_pos_t oldest = n00b_option_is_set(oldest_opt)
                                  ? n00b_option_get(oldest_opt)
                                  : (n00b_store_pos_t){};

    auto version_r = rocs_store_catalog_append_u64(buf,
                                                   ROCS_STORE_CATALOG_VERSION);
    auto generation_r = rocs_store_catalog_append_u64(buf, store->generation);
    auto next_r = rocs_store_catalog_append_u64(buf, serialized_open_shard_id);
    auto schema_r = rocs_store_catalog_append_u64(buf, store->schema_generation);
    auto oldest_gen_r = rocs_store_catalog_append_u64(buf, oldest.generation);
    auto oldest_shard_r = rocs_store_catalog_append_u64(buf, oldest.shard_id);
    auto oldest_ordinal_r = rocs_store_catalog_append_u64(buf, oldest.ordinal);
    auto count_r = rocs_store_catalog_append_u64(buf, entry_count);
    if (n00b_result_is_err(version_r) || n00b_result_is_err(generation_r)
        || n00b_result_is_err(next_r) || n00b_result_is_err(schema_r)
        || n00b_result_is_err(oldest_gen_r)
        || n00b_result_is_err(oldest_shard_r)
        || n00b_result_is_err(oldest_ordinal_r)
        || n00b_result_is_err(count_r)) {
        return n00b_result_err(n00b_buffer_t *, N00B_STORE_ERR_INTERNAL);
    }

    n00b_err_t entry_err = N00B_STORE_OK;
    n00b_list_foreach(*store->catalog, p) {
        n00b_store_catalog_entry_t *entry = *p;
        if (entry_err == N00B_STORE_OK) {
            auto append_r = rocs_store_catalog_append_entry(store, buf, entry);
            if (n00b_result_is_err(append_r)) {
                entry_err = n00b_result_get_err(append_r);
            }
        }
    }
    if (entry_err != N00B_STORE_OK) {
        return n00b_result_err(n00b_buffer_t *, entry_err);
    }
    if (pending_entry != nullptr) {
        auto append_r =
            rocs_store_catalog_append_entry(store, buf, pending_entry);
        if (n00b_result_is_err(append_r)) {
            return n00b_result_err(n00b_buffer_t *,
                                   n00b_result_get_err(append_r));
        }
    }

    return n00b_result_ok(n00b_buffer_t *, buf);
}

static n00b_result_t(bool)
rocs_store_catalog_parse(n00b_store_t *store, n00b_buffer_t *buf)
{
    rocs_store_catalog_reader_t reader = {
        .buf = buf,
        .pos = 0,
        .len = (uint64_t)n00b_buffer_len(buf),
    };

    uint8_t magic[ROCS_STORE_CATALOG_MAGIC_LEN] = {
        'R', 'O', 'C', 'S', 'C', 'A', 'T', '1',
    };
    for (uint8_t i = 0; i < ROCS_STORE_CATALOG_MAGIC_LEN; i++) {
        auto byte_r = rocs_store_catalog_read_u8(&reader);
        if (n00b_result_is_err(byte_r)
            || n00b_result_get(byte_r) != magic[i]) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }
    }

    auto version_r = rocs_store_catalog_read_u64(&reader);
    auto gen_r     = rocs_store_catalog_read_u64(&reader);
    auto next_r    = rocs_store_catalog_read_u64(&reader);
    auto schema_r  = rocs_store_catalog_read_u64(&reader);
    if (n00b_result_is_err(version_r) || n00b_result_is_err(gen_r)
        || n00b_result_is_err(next_r) || n00b_result_is_err(schema_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t version = n00b_result_get(version_r);
    if (version < ROCS_STORE_CATALOG_VERSION_MIN
        || version > ROCS_STORE_CATALOG_VERSION) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    store->generation        = n00b_result_get(gen_r);
    store->schema_generation = n00b_result_get(schema_r);
    store->has_oldest_available = false;
    store->oldest_available     = (n00b_store_pos_t){};

    if (version >= 2) {
        auto oldest_gen_r     = rocs_store_catalog_read_u64(&reader);
        auto oldest_shard_r   = rocs_store_catalog_read_u64(&reader);
        auto oldest_ordinal_r = rocs_store_catalog_read_u64(&reader);
        if (n00b_result_is_err(oldest_gen_r)
            || n00b_result_is_err(oldest_shard_r)
            || n00b_result_is_err(oldest_ordinal_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        uint64_t oldest_shard = n00b_result_get(oldest_shard_r);
        if (oldest_shard != 0) {
            store->oldest_available = (n00b_store_pos_t){
                .generation = n00b_result_get(oldest_gen_r),
                .shard_id   = oldest_shard,
                .ordinal    = n00b_result_get(oldest_ordinal_r),
            };
            store->has_oldest_available = true;
        }
    }

    auto count_r = rocs_store_catalog_read_u64(&reader);
    if (n00b_result_is_err(count_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    uint64_t next_open_shard_id = n00b_result_get(next_r);
    uint64_t entry_count        = n00b_result_get(count_r);
    uint64_t max_shard_id       = 0;

    for (uint64_t i = 0; i < entry_count; i++) {
        auto shard_id_r  = rocs_store_catalog_read_u64(&reader);
        auto entry_gen_r = rocs_store_catalog_read_u64(&reader);
        auto bytes_r     = rocs_store_catalog_read_u64(&reader);
        auto records_r   = rocs_store_catalog_read_u64(&reader);
        auto schema_gen_r = rocs_store_catalog_read_u64(&reader);
        auto seal_ts_r   = rocs_store_catalog_read_u64(&reader);
        if (n00b_result_is_err(shard_id_r) || n00b_result_is_err(entry_gen_r)
            || n00b_result_is_err(bytes_r) || n00b_result_is_err(records_r)
            || n00b_result_is_err(schema_gen_r)
            || n00b_result_is_err(seal_ts_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        auto path_r = rocs_store_catalog_read_string(
            &reader,
            .allow_empty = false,
            .allocator   = store->allocator);
        auto partition_r = rocs_store_catalog_read_string(
            &reader,
            .allow_empty = false,
            .allocator   = store->allocator);
        auto etag_r = rocs_store_catalog_read_string(
            &reader,
            .allocator = store->allocator);
        if (n00b_result_is_err(path_r) || n00b_result_is_err(partition_r)
            || n00b_result_is_err(etag_r)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }

        uint64_t shard_id = n00b_result_get(shard_id_r);
        auto     shard_opt = rocs_store_catalog_find_raw(store, shard_id);
        if (shard_id == 0 || n00b_option_is_set(shard_opt)) {
            return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
        }
        if (shard_id > max_shard_id) {
            max_shard_id = shard_id;
        }

        n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
            store,
            .shard_id          = shard_id,
            .generation        = n00b_result_get(entry_gen_r),
            .object_path       = n00b_result_get(path_r),
            .byte_len          = n00b_result_get(bytes_r),
            .record_count      = n00b_result_get(records_r),
            .schema_generation = n00b_result_get(schema_gen_r),
            .seal_ts           = n00b_result_get(seal_ts_r),
            .partition_key     = n00b_result_get(partition_r),
            .etag              = n00b_result_get(etag_r));
        n00b_list_push(*store->catalog, entry);
    }

    if (reader.pos != reader.len || next_open_shard_id == 0
        || next_open_shard_id <= max_shard_id) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    store->next_shard_id = next_open_shard_id + 1;
    rocs_store_refresh_oldest_available(store);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_catalog_load(n00b_store_t *store)
{
    auto path_r = rocs_store_catalog_path(store);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(bool, n00b_result_get_err(path_r));
    }

    n00b_string_t *path   = n00b_result_get(path_r);
    auto           stat_r = n00b_vfs_stat(store->vfs, path);
    if (n00b_result_is_err(stat_r)) {
        if (n00b_result_get_err(stat_r) == N00B_VFS_ERR_NOT_FOUND) {
            return n00b_result_ok(bool, false);
        }
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    auto buf_r = rocs_store_read_vfs_object(store, path);
    if (n00b_result_is_err(buf_r)) {
        return n00b_result_err(bool, n00b_result_get_err(buf_r));
    }

    return rocs_store_catalog_parse(store, n00b_result_get(buf_r));
}

static n00b_result_t(bool)
rocs_store_catalog_write_staged(n00b_store_t               *store,
                                n00b_store_catalog_entry_t *pending_entry,
                                uint64_t                    next_open_shard_id)
{
    auto path_r = rocs_store_catalog_path(store);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(bool, n00b_result_get_err(path_r));
    }

    auto buf_r = rocs_store_catalog_serialize(
        store,
        .pending_entry      = pending_entry,
        .next_open_shard_id = next_open_shard_id);
    if (n00b_result_is_err(buf_r)) {
        return n00b_result_err(bool, n00b_result_get_err(buf_r));
    }

    return rocs_store_write_vfs_object(store,
                                       n00b_result_get(path_r),
                                       n00b_result_get(buf_r));
}

static n00b_result_t(bool)
rocs_store_catalog_write(n00b_store_t *store)
{
    return rocs_store_catalog_write_staged(store, nullptr, 0);
}

static bool
rocs_store_commit_topic_ready(n00b_store_commit_topic_t *topic)
{
    if (topic == nullptr) {
        return false;
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    return n00b_conduit_topic_is_active(base) && base->conduit != nullptr;
}

static bool
rocs_store_emit_commit(n00b_store_t             *store,
                       n00b_store_commit_kind_t  kind,
                       uint64_t                  shard_id,
                       uint64_t                  ordinal,
                       uint64_t                  record_count,
                       uint64_t                  seal_ts,
                       n00b_string_t            *partition_key)
{
    if (store == nullptr || !rocs_store_commit_topic_ready(store->commit_topic)) {
        return false;
    }

    n00b_conduit_topic_base_t *base =
        (n00b_conduit_topic_base_t *)store->commit_topic;
    n00b_result_t(n00b_conduit_publisher_t *) pub_r =
        n00b_conduit_publish_try_claim(base);
    if (n00b_result_is_err(pub_r)) {
        return false;
    }

    n00b_conduit_publisher_t *pub = n00b_result_get(pub_r);
    n00b_store_commit_msg_t  *msg = n00b_alloc_with_opts(
        n00b_store_commit_msg_t,
        &(n00b_alloc_opts_t){
            .allocator = base->conduit->allocator,
        });
    if (msg == nullptr) {
        n00b_conduit_publish_yield(pub);
        return false;
    }

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = base;
    msg->header.generation = n00b_conduit_topic_generation(base);
    msg->header.epoch      = n00b_conduit_topic_epoch(base);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload.kind          = kind;
    msg->payload.generation    = store->generation;
    msg->payload.shard_id      = shard_id;
    msg->payload.ordinal       = ordinal;
    msg->payload.record_count  = record_count;
    msg->payload.seal_ts       = seal_ts;
    msg->payload.partition_key = partition_key == nullptr ? r"default"
                                                          : partition_key;

    n00b_conduit_topic_deliver_msg(n00b_store_commit_t,
                                   store->commit_topic,
                                   msg,
                                   N00B_CONDUIT_OP_ALL);
    n00b_conduit_publish_yield(pub);
    return true;
}

static n00b_result_t(n00b_store_catalog_entry_t *)
rocs_store_seal_hot_shard_unlocked(n00b_store_t  *store,
                                   uint64_t       seal_ts,
                                   uint32_t       base_address,
                                   n00b_allocator_t *allocator,
                                   n00b_string_t *partition_key)
{
    if (store == nullptr || store->hot_shard == nullptr
        || store->catalog == nullptr) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_STATE);
    }
    if (store->next_shard_id == UINT64_MAX) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_STATE);
    }

    n00b_string_t *entry_partition =
        partition_key != nullptr ? partition_key
        : store->hot_partition_key != nullptr ? store->hot_partition_key
                                              : r"default";

    uint64_t shard_id = store->hot_shard->shard_id;
    auto existing = rocs_store_catalog_find_raw(store, shard_id);
    if (shard_id == 0 || n00b_option_is_set(existing)) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_CORRUPT);
    }

    auto path_r = rocs_store_shard_object_path(store, shard_id);
    if (n00b_result_is_err(path_r)) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(path_r));
    }
    n00b_string_t *object_path = n00b_result_get(path_r);

    n00b_shard_state_t old_shard_state   = store->hot_shard->state;
    uint64_t           old_shard_seal_ts = store->hot_shard->seal_ts;

    auto image_r = n00b_store_shard_seal(store->hot_shard,
                                         .seal_ts      = seal_ts,
                                         .base_address = base_address,
                                         .allocator    = allocator);
    if (n00b_result_is_err(image_r)) {
        n00b_err_t err = n00b_result_get_err(image_r);
        if (err == N00B_STORE_SHARD_ERR_ARG) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   N00B_STORE_ERR_ARG);
        }
        if (err == N00B_STORE_SHARD_ERR_STATE) {
            return n00b_result_err(n00b_store_catalog_entry_t *,
                                   N00B_STORE_ERR_STATE);
        }
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_buffer_t *image   = n00b_result_get(image_r);
    uint64_t       img_len = (uint64_t)n00b_buffer_len(image);

    auto write_r = rocs_store_write_vfs_object(store,
                                               object_path,
                                               image,
                                               .create_exclusive = true);
    if (n00b_result_is_err(write_r)) {
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(write_r));
    }

    auto stat_r = n00b_vfs_stat(store->vfs, object_path);
    if (n00b_result_is_err(stat_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_VFS);
    }
    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != img_len) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_CORRUPT);
    }

    n00b_store_catalog_entry_t *entry = rocs_store_catalog_entry_new(
        store,
        .shard_id          = shard_id,
        .generation        = store->generation,
        .object_path       = object_path,
        .byte_len          = stat.size,
        .record_count      = store->hot_shard->record_count,
        .schema_generation = store->schema_generation,
        .seal_ts           = store->hot_shard->seal_ts,
        .partition_key     = entry_partition,
        .etag              = stat.etag);

    uint64_t next_hot_id = store->next_shard_id;

    auto shard_r = n00b_store_shard_new(
        .shard_id   = next_hot_id,
        .retain_raw = store->retain_policy != nullptr
                   && store->retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = store->allocator);
    if (n00b_result_is_err(shard_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(shard_r));
    }

    auto catalog_r = rocs_store_catalog_write_staged(store, entry, next_hot_id);
    if (n00b_result_is_err(catalog_r)) {
        (void)n00b_vfs_delete(store->vfs, object_path);
        store->hot_shard->state   = old_shard_state;
        store->hot_shard->seal_ts = old_shard_seal_ts;
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               n00b_result_get_err(catalog_r));
    }

    n00b_list_push(*store->catalog, entry);
    store->hot_shard        = n00b_result_get(shard_r);
    store->hot_partition_key = r"default";
    store->next_shard_id    = next_hot_id + 1;
    rocs_store_refresh_oldest_available(store);

    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_SEAL,
                                 entry->shard_id,
                                 UINT64_MAX,
                                 entry->record_count,
                                 entry->seal_ts,
                                 entry->partition_key);

    return n00b_result_ok(n00b_store_catalog_entry_t *, entry);
}

static n00b_err_t
rocs_store_preflight_ingest(n00b_store_t     *store,
                            n00b_json_node_t *record,
                            n00b_buffer_t    *raw)
{
    if (store == nullptr || record == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    if (store->state != N00B_STORE_STATE_OPEN || store->hot_shard == nullptr) {
        return N00B_STORE_ERR_STATE;
    }
    if (n00b_json_type(record) != N00B_JSON_OBJECT) {
        return N00B_STORE_ERR_ARG;
    }
    if (store->retain_policy == nullptr || store->partition_policy == nullptr
        || store->seal_policy == nullptr || store->schema == nullptr
        || store->schema->fields == nullptr) {
        return N00B_STORE_ERR_STATE;
    }
    if (store->retain_policy->kind == N00B_STORE_RETAIN_EXTERNAL) {
        return N00B_STORE_ERR_POLICY;
    }
    if (store->retain_policy->kind == N00B_STORE_RETAIN_INLINE
        && raw == nullptr) {
        return N00B_STORE_ERR_ARG;
    }

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field == nullptr || field->name == nullptr) {
            return N00B_STORE_ERR_STATE;
        }
        if (field->required
            && n00b_json_object_get(record, field->name) == nullptr) {
            return N00B_STORE_ERR_FIELD;
        }
        switch (field->index_kind) {
        case N00B_STORE_INDEX_NONE:
        case N00B_STORE_INDEX_TERM:
            break;
        case N00B_STORE_INDEX_FULLTEXT:
        case N00B_STORE_INDEX_NGRAM:
        case N00B_STORE_INDEX_NUMERIC:
        case N00B_STORE_INDEX_BOOL:
        case N00B_STORE_INDEX_VECTOR:
            return N00B_STORE_ERR_INDEX;
        default:
            return N00B_STORE_ERR_POLICY;
        }
    }

    return N00B_STORE_OK;
}

static rocs_store_posting_target_list_t *
rocs_store_posting_target_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_posting_target_list_t *targets = n00b_alloc_with_opts(
        rocs_store_posting_target_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *targets = n00b_list_new_private(n00b_store_posting_list_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return targets;
}

static n00b_store_posting_list_t *
rocs_store_posting_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_posting_list_t *records = n00b_alloc_with_opts(
        n00b_store_posting_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *records = n00b_list_new_private(n00b_json_node_t *,
                                     .allocator = allocator,
                                     .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return records;
}

static n00b_store_column_t *
rocs_store_column_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_column_t *column = n00b_alloc_with_opts(
        n00b_store_column_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    n00b_dict_init(column,
                   .allocator       = allocator,
                   .skip_obj_hash   = true,
                   .locked          = false,
                   .key_scan_kind   = N00B_GC_SCAN_KIND_NONE,
                   .value_scan_kind = N00B_GC_SCAN_KIND_ALL);
    return column;
}

static n00b_result_t(n00b_store_column_t *)
rocs_store_column_get_or_create(n00b_store_shard_t *shard,
                                n00b_string_t      *field)
{
    if (shard == nullptr || shard->columns == nullptr || field == nullptr) {
        return n00b_result_err(n00b_store_column_t *,
                               N00B_STORE_ERR_INDEX);
    }

    bool found = false;
    n00b_store_column_t *column = n00b_dict_get(shard->columns, field, &found);
    if (found) {
        if (column == nullptr) {
            return n00b_result_err(n00b_store_column_t *,
                                   N00B_STORE_ERR_INDEX);
        }
        return n00b_result_ok(n00b_store_column_t *, column);
    }

    n00b_allocator_t *allocator = shard->columns->allocator;
    column = rocs_store_column_new(.allocator = allocator);

    n00b_string_t *stored_field =
        n00b_string_from_raw(field->data,
                             (int64_t)field->u8_bytes,
                             .allocator = allocator);
    n00b_dict_put(shard->columns, stored_field, column);
    return n00b_result_ok(n00b_store_column_t *, column);
}

static n00b_result_t(n00b_store_posting_list_t *)
rocs_store_column_postings_get_or_create(n00b_store_column_t *column,
                                         n00b_uint128_t       key)
{
    if (column == nullptr) {
        return n00b_result_err(n00b_store_posting_list_t *,
                               N00B_STORE_ERR_INDEX);
    }

    bool found = false;
    n00b_store_posting_list_t *postings = n00b_dict_get(column, key, &found);
    if (found) {
        if (postings == nullptr) {
            return n00b_result_err(n00b_store_posting_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }
        return n00b_result_ok(n00b_store_posting_list_t *, postings);
    }

    postings = rocs_store_posting_list_new(.allocator = column->allocator);
    n00b_dict_put(column, key, postings);
    return n00b_result_ok(n00b_store_posting_list_t *, postings);
}

static n00b_result_t(n00b_uint128_t)
rocs_store_term_key(n00b_store_normalized_t *term) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    auto hash_r = n00b_store_normalize_hash(N00B_STORE_INDEX_TERM,
                                            term,
                                            .allocator = allocator);
    if (n00b_result_is_err(hash_r)) {
        return n00b_result_err(n00b_uint128_t, N00B_STORE_ERR_INDEX);
    }
    return n00b_result_ok(n00b_uint128_t, n00b_result_get(hash_r));
}

static rocs_store_batch_term_list_t *
rocs_store_batch_term_list_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    rocs_store_batch_term_list_t *terms = n00b_alloc_with_opts(
        rocs_store_batch_term_list_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    *terms = n00b_list_new_private(rocs_store_batch_term_t *,
                                   .allocator = allocator,
                                   .scan_kind = N00B_GC_SCAN_KIND_ALL);
    return terms;
}

static n00b_result_t(rocs_store_batch_term_list_t *)
rocs_store_build_batch_terms(n00b_store_t     *store,
                             n00b_json_node_t *record)
{
    if (store == nullptr || record == nullptr || store->schema == nullptr
        || store->schema->fields == nullptr) {
        return n00b_result_err(rocs_store_batch_term_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    rocs_store_batch_term_list_t *out =
        rocs_store_batch_term_list_new(.allocator = store->allocator);

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field->index_kind != N00B_STORE_INDEX_TERM) {
            continue;
        }

        n00b_json_node_t *field_value = n00b_json_object_get(record,
                                                             field->name);
        if (field_value == nullptr) {
            continue;
        }

        auto terms_r = n00b_store_normalize_json(
            field_value,
            .allocator = store->allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(rocs_store_batch_term_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
        size_t                        len   = n00b_list_len(*terms);
        for (size_t i = 0; i < len; i++) {
            n00b_store_normalized_t *term = n00b_list_get(*terms, i);
            auto key_r = rocs_store_term_key(term,
                                             .allocator = store->allocator);
            if (n00b_result_is_err(key_r)) {
                return n00b_result_err(rocs_store_batch_term_list_t *,
                                       n00b_result_get_err(key_r));
            }

            rocs_store_batch_term_t *item = n00b_alloc_with_opts(
                rocs_store_batch_term_t,
                &(n00b_alloc_opts_t){
                    .allocator = store->allocator,
                    .scan_kind = N00B_GC_SCAN_KIND_ALL,
                });
            item->field = field->name;
            item->key   = n00b_result_get(key_r);
            n00b_list_push(*out, item);
        }
    }

    return n00b_result_ok(rocs_store_batch_term_list_t *, out);
}

static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets_from_terms(n00b_store_t                 *store,
                                            n00b_store_shard_t           *shard,
                                            rocs_store_batch_term_list_t *terms)
{
    if (store == nullptr || shard == nullptr || terms == nullptr
        || shard->columns == nullptr) {
        return n00b_result_err(rocs_store_posting_target_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    rocs_store_posting_target_list_t *targets =
        rocs_store_posting_target_list_new(.allocator = store->allocator);

    size_t len = n00b_list_len(*terms);
    for (size_t i = 0; i < len; i++) {
        rocs_store_batch_term_t *term = n00b_list_get(*terms, i);
        if (term == nullptr || term->field == nullptr) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        auto column_r = rocs_store_column_get_or_create(shard, term->field);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   n00b_result_get_err(column_r));
        }

        auto postings_r = rocs_store_column_postings_get_or_create(
            n00b_result_get(column_r),
            term->key);
        if (n00b_result_is_err(postings_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   n00b_result_get_err(postings_r));
        }

        n00b_list_push(*targets, n00b_result_get(postings_r));
    }

    return n00b_result_ok(rocs_store_posting_target_list_t *, targets);
}

static n00b_result_t(rocs_store_posting_target_list_t *)
rocs_store_prepare_index_targets(n00b_store_t     *store,
                                 n00b_store_shard_t *shard,
                                 n00b_json_node_t *record)
{
    if (store == nullptr || shard == nullptr || record == nullptr
        || store->schema == nullptr || store->schema->fields == nullptr
        || shard->columns == nullptr) {
        return n00b_result_err(rocs_store_posting_target_list_t *,
                               N00B_STORE_ERR_STATE);
    }

    rocs_store_posting_target_list_t *targets =
        rocs_store_posting_target_list_new(.allocator = store->allocator);

    n00b_list_foreach(*store->schema->fields, p) {
        n00b_store_field_t *field = *p;
        if (field->index_kind != N00B_STORE_INDEX_TERM) {
            continue;
        }

        n00b_json_node_t *field_value = n00b_json_object_get(record,
                                                             field->name);
        if (field_value == nullptr) {
            continue;
        }

        auto terms_r = n00b_store_normalize_json(field_value,
                                                 .allocator = store->allocator);
        if (n00b_result_is_err(terms_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   N00B_STORE_ERR_INDEX);
        }

        n00b_store_normalized_list_t *terms = n00b_result_get(terms_r);
        size_t                        len   = n00b_list_len(*terms);
        if (len == 0) {
            continue;
        }

        auto column_r = rocs_store_column_get_or_create(shard, field->name);
        if (n00b_result_is_err(column_r)) {
            return n00b_result_err(rocs_store_posting_target_list_t *,
                                   n00b_result_get_err(column_r));
        }
        n00b_store_column_t *column = n00b_result_get(column_r);

        for (size_t i = 0; i < len; i++) {
            n00b_store_normalized_t *term = n00b_list_get(*terms, i);
            auto key_r = rocs_store_term_key(term,
                                             .allocator = store->allocator);
            if (n00b_result_is_err(key_r)) {
                return n00b_result_err(rocs_store_posting_target_list_t *,
                                       n00b_result_get_err(key_r));
            }

            auto postings_r = rocs_store_column_postings_get_or_create(
                column,
                n00b_result_get(key_r));
            if (n00b_result_is_err(postings_r)) {
                return n00b_result_err(rocs_store_posting_target_list_t *,
                                       n00b_result_get_err(postings_r));
            }

            n00b_list_push(*targets, n00b_result_get(postings_r));
        }
    }

    return n00b_result_ok(rocs_store_posting_target_list_t *, targets);
}

static void
rocs_store_commit_index_targets(rocs_store_posting_target_list_t *targets,
                                n00b_json_node_t                 *record)
{
    if (targets == nullptr || record == nullptr) {
        return;
    }

    size_t len = n00b_list_len(*targets);
    for (size_t i = 0; i < len; i++) {
        n00b_store_posting_list_t *postings = n00b_list_get(*targets, i);
        if (postings != nullptr) {
            n00b_list_push(*postings, record);
        }
    }
}

static n00b_err_t
rocs_store_parse_source(n00b_buffer_t     *source,
                        n00b_buffer_t    **raw_out,
                        n00b_json_node_t **record_out,
                        n00b_allocator_t  *allocator)
{
    if (source == nullptr || raw_out == nullptr || record_out == nullptr) {
        return N00B_STORE_ERR_ARG;
    }
    *raw_out    = nullptr;
    *record_out = nullptr;

    uint64_t source_len = (uint64_t)n00b_buffer_len(source);
    if (source_len == 0) {
        return N00B_STORE_ERR_PARSE;
    }
    if (source_len > (uint64_t)INT64_MAX || source_len > (uint64_t)SIZE_MAX) {
        return N00B_STORE_ERR_ARG;
    }

    _n00b_buffer_rlock(source);
    n00b_buffer_t *raw = n00b_buffer_from_bytes(source->data,
                                                (int64_t)source_len,
                                                .allocator = allocator);
    _n00b_buffer_unlock(source);
    if (raw == nullptr) {
        return N00B_STORE_ERR_INTERNAL;
    }

    const char       *parse_err = nullptr;
    n00b_json_node_t *record    = nullptr;
    _n00b_buffer_rlock(raw);
    record = n00b_json_parse(raw->data, (size_t)source_len, &parse_err);
    _n00b_buffer_unlock(raw);
    if (record == nullptr) {
        (void)parse_err;
        return N00B_STORE_ERR_PARSE;
    }

    *raw_out    = raw;
    *record_out = record;
    return N00B_STORE_OK;
}

static void
rocs_store_batch_worker(void *job_ptr, void *user_data)
{
    (void)user_data;

    rocs_store_batch_job_t *job = job_ptr;
    if (job == nullptr || job->store == nullptr) {
        return;
    }

    job->err = N00B_STORE_OK;

    if (job->source != nullptr) {
        job->err = rocs_store_parse_source(job->source,
                                           &job->raw,
                                           &job->record,
                                           job->store->allocator);
        if (job->err != N00B_STORE_OK) {
            return;
        }
    }
    else {
        job->record = job->input_record;
    }

    job->err = rocs_store_preflight_ingest(job->store, job->record, job->raw);
    if (job->err != N00B_STORE_OK) {
        return;
    }

    auto route_r = n00b_store_partition_route(job->store->partition_policy,
                                              job->record,
                                              .allocator =
                                                  job->store->allocator);
    if (n00b_result_is_err(route_r)) {
        job->err = n00b_result_get_err(route_r);
        return;
    }
    job->route = n00b_result_get(route_r);
    if (job->route == nullptr) {
        job->route = r"default";
    }

    auto terms_r = rocs_store_build_batch_terms(job->store, job->record);
    if (n00b_result_is_err(terms_r)) {
        job->err = n00b_result_get_err(terms_r);
        return;
    }
    job->terms = n00b_result_get(terms_r);
}

static bool
rocs_store_should_seal_hot(n00b_store_t *store)
{
    if (store == nullptr || store->hot_shard == nullptr
        || store->seal_policy == nullptr) {
        return false;
    }
    if (store->seal_policy->max_records != 0
        && store->hot_shard->record_count >= store->seal_policy->max_records) {
        return true;
    }
    if (store->seal_policy->max_bytes != 0
        && store->hot_shard->byte_estimate >= store->seal_policy->max_bytes) {
        return true;
    }
    if (store->seal_policy->max_open_ns != 0
        && store->hot_shard->open_ts != 0) {
        uint64_t now = (uint64_t)n00b_ns_timestamp();
        if (now >= store->hot_shard->open_ts
            && now - store->hot_shard->open_ts
                   >= store->seal_policy->max_open_ns) {
            return true;
        }
    }
    return false;
}

static n00b_result_t(bool)
rocs_store_ingest_prepared_unlocked(n00b_store_t                 *store,
                                    n00b_json_node_t             *record,
                                    n00b_buffer_t                *raw,
                                    n00b_string_t                *route,
                                    rocs_store_batch_term_list_t *terms)
{
    if (store == nullptr || record == nullptr || store->hot_shard == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (route == nullptr) {
        route = r"default";
    }

    if (store->hot_partition_key == nullptr) {
        store->hot_partition_key = r"default";
    }
    if (store->hot_shard->record_count == 0) {
        store->hot_partition_key = route;
    }
    else if (!n00b_unicode_str_eq(store->hot_partition_key, route)) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            store->allocator,
            store->hot_partition_key);
        if (n00b_result_is_err(seal_r)) {
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
        store->hot_partition_key = route;
    }

    n00b_result_t(rocs_store_posting_target_list_t *) targets_r =
        terms == nullptr
            ? rocs_store_prepare_index_targets(store, store->hot_shard, record)
            : rocs_store_prepare_index_targets_from_terms(store,
                                                          store->hot_shard,
                                                          terms);
    if (n00b_result_is_err(targets_r)) {
        return n00b_result_err(bool, n00b_result_get_err(targets_r));
    }
    rocs_store_posting_target_list_t *targets = n00b_result_get(targets_r);

    auto append_r = n00b_store_shard_append(store->hot_shard,
                                            record,
                                            .raw = raw);
    if (n00b_result_is_err(append_r)) {
        n00b_err_t err = n00b_result_get_err(append_r);
        return n00b_result_err(bool,
                               err == N00B_STORE_SHARD_ERR_STATE
                                   ? N00B_STORE_ERR_STATE
                                   : N00B_STORE_ERR_ARG);
    }
    uint64_t ordinal = n00b_result_get(append_r);

    rocs_store_commit_index_targets(targets, record);

    (void)rocs_store_emit_commit(store,
                                 N00B_STORE_COMMIT_RECORD,
                                 store->hot_shard->shard_id,
                                 ordinal,
                                 store->hot_shard->record_count,
                                 0,
                                 store->hot_partition_key);

    if (rocs_store_should_seal_hot(store)) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            store->allocator,
            store->hot_partition_key);
        (void)seal_r;
    }

    return n00b_result_ok(bool, true);
}

n00b_string_t *
n00b_store_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_STORE_OK:            return r"OK";
    case N00B_STORE_ERR_ARG:       return r"ARG";
    case N00B_STORE_ERR_STATE:     return r"STATE";
    case N00B_STORE_ERR_DUP_FIELD: return r"DUP_FIELD";
    case N00B_STORE_ERR_FIELD:     return r"FIELD";
    case N00B_STORE_ERR_POLICY:    return r"POLICY";
    case N00B_STORE_ERR_PINNED:    return r"PINNED";
    case N00B_STORE_ERR_VFS:       return r"VFS";
    case N00B_STORE_ERR_INTERNAL:  return r"INTERNAL";
    case N00B_STORE_ERR_CORRUPT:   return r"CORRUPT";
    case N00B_STORE_ERR_RESIDENCY: return r"RESIDENCY";
    case N00B_STORE_ERR_PARSE:     return r"PARSE";
    case N00B_STORE_ERR_INDEX:     return r"INDEX";
    case N00B_STORE_ERR_RETENTION: return r"RETENTION";
    }
    return r"UNKNOWN";
}

n00b_result_t(n00b_store_commit_topic_t *)
n00b_store_commit_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri)
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_commit_topic_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_commit_topic_t *topic =
        n00b_conduit_topic_init(n00b_store_commit_t, conduit, uri);
    if (topic == nullptr) {
        return n00b_result_err(n00b_store_commit_topic_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_store_commit_topic_t *, topic);
}

n00b_result_t(n00b_store_commit_inbox_t *)
n00b_store_commit_inbox_new(n00b_conduit_t *conduit) _kargs
{
    n00b_conduit_backpressure_t backpressure = N00B_CONDUIT_BP_DROP_NEWEST;
    uint32_t                    limit        = 1024;
    n00b_allocator_t           *allocator    = nullptr;
}
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (allocator == nullptr) {
        allocator = conduit->allocator;
    }

    n00b_store_commit_inbox_t *inbox = n00b_alloc_with_opts(
        n00b_store_commit_inbox_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    if (inbox == nullptr) {
        return n00b_result_err(n00b_store_commit_inbox_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_inbox_init(n00b_store_commit_t,
                            inbox,
                            conduit,
                            backpressure,
                            limit);
    return n00b_result_ok(n00b_store_commit_inbox_t *, inbox);
}

n00b_result_t(n00b_conduit_sub_handle_t)
n00b_store_commit_subscribe(n00b_store_commit_topic_t *topic,
                            n00b_store_commit_inbox_t *inbox) _kargs
{
    uint32_t operations = N00B_CONDUIT_OP_ALL;
    uint32_t flags      = 0;
    uint32_t timeout_ms = 0;
}
{
    if (topic == nullptr || inbox == nullptr) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_ARG);
    }
    if (!rocs_store_commit_topic_ready(topic)) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_sub_handle_t handle =
        n00b_conduit_subscribe(n00b_store_commit_t,
                               topic,
                               inbox,
                               .operations   = operations,
                               .flags        = flags,
                               .timeout_ms   = timeout_ms);
    if (handle == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        return n00b_result_err(n00b_conduit_sub_handle_t,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_conduit_sub_handle_t, handle);
}

n00b_result_t(bool)
n00b_store_set_commit_topic(n00b_store_t              *store,
                            n00b_store_commit_topic_t *topic)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->commit_topic = topic;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_set_lifecycle_topic(n00b_store_t                 *store,
                               n00b_store_lifecycle_topic_t *topic)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    store->lifecycle_topic = topic;
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_ingest_topic_t *)
n00b_store_ingest_topic_get(n00b_conduit_t *conduit,
                            n00b_conduit_uri_t uri)
{
    if (conduit == nullptr) {
        return n00b_result_err(n00b_store_ingest_topic_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_ingest_topic_t *topic =
        n00b_conduit_topic_init(n00b_store_ingest_payload_t, conduit, uri);
    if (topic == nullptr) {
        return n00b_result_err(n00b_store_ingest_topic_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_store_ingest_topic_t *, topic);
}

n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_record(n00b_json_node_t *record)
{
    if (record == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        n00b_variant_set(n00b_store_ingest_payload_t,
                         n00b_json_node_t *,
                         record));
}

n00b_result_t(n00b_store_ingest_payload_t)
n00b_store_ingest_payload_source(n00b_buffer_t *source)
{
    if (source == nullptr) {
        return n00b_result_err(n00b_store_ingest_payload_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_ingest_payload_t,
        n00b_variant_set(n00b_store_ingest_payload_t,
                         n00b_buffer_t *,
                         source));
}

n00b_result_t(bool)
n00b_store_ingest_topic_publish(n00b_store_ingest_topic_t   *topic,
                                n00b_store_ingest_payload_t  payload)
{
    if (topic == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    if (!n00b_conduit_topic_is_active(base) || base->conduit == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_result_t(n00b_conduit_publisher_t *) pub_r =
        n00b_conduit_publish_try_claim(base);
    if (n00b_result_is_err(pub_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    n00b_conduit_publisher_t *pub = n00b_result_get(pub_r);
    n00b_store_ingest_msg_t  *msg = n00b_alloc_with_opts(
        n00b_store_ingest_msg_t,
        &(n00b_alloc_opts_t){
            .allocator = base->conduit->allocator,
        });
    if (msg == nullptr) {
        n00b_conduit_publish_yield(pub);
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    msg->header.type       = N00B_CONDUIT_MSG_USER;
    msg->header.topic      = base;
    msg->header.generation = n00b_conduit_topic_generation(base);
    msg->header.epoch      = n00b_conduit_topic_epoch(base);
    msg->header.timestamp  = 0;
    msg->header.next       = nullptr;
    msg->payload           = payload;

    n00b_conduit_topic_deliver_msg(n00b_store_ingest_payload_t,
                                   topic,
                                   msg,
                                   N00B_CONDUIT_OP_ALL);
    n00b_conduit_publish_yield(pub);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_schema_t *)
n00b_store_schema_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_store_schema_t *schema = n00b_alloc_with_opts(
        n00b_store_schema_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });

    schema->fields    = rocs_store_field_list_new(.allocator = allocator);
    schema->allocator = allocator;
    schema->frozen    = false;
    return n00b_result_ok(n00b_store_schema_t *, schema);
}

n00b_result_t(n00b_store_field_t *)
n00b_store_schema_add_field(n00b_store_schema_t *schema,
                            n00b_string_t       *name) _kargs
{
    bool                    required   = false;
    n00b_store_index_kind_t index_kind = N00B_STORE_INDEX_NONE;
}
{
    if (schema == nullptr || schema->fields == nullptr
        || rocs_store_string_empty(name)) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_ARG);
    }
    if (schema->frozen) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_STATE);
    }
    if (!rocs_store_index_kind_valid(index_kind)) {
        return n00b_result_err(n00b_store_field_t *, N00B_STORE_ERR_POLICY);
    }
    auto existing = rocs_store_schema_find_field_raw(schema, name);
    if (n00b_option_is_set(existing)) {
        return n00b_result_err(n00b_store_field_t *,
                               N00B_STORE_ERR_DUP_FIELD);
    }

    n00b_store_field_t *field = n00b_alloc_with_opts(
        n00b_store_field_t,
        &(n00b_alloc_opts_t){
            .allocator = schema->allocator,
        });
    field->name       = name;
    field->required   = required;
    field->index_kind = index_kind;
    n00b_list_push(*schema->fields, field);

    return n00b_result_ok(n00b_store_field_t *, field);
}

n00b_result_t(bool)
n00b_store_schema_freeze(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->fields == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    schema->frozen = true;
    return n00b_result_ok(bool, true);
}

n00b_result_t(bool)
n00b_store_schema_is_frozen(n00b_store_schema_t *schema)
{
    if (schema == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(bool, schema->frozen);
}

n00b_result_t(uint64_t)
n00b_store_schema_get_field_count(n00b_store_schema_t *schema)
{
    if (schema == nullptr || schema->fields == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*schema->fields));
}

n00b_result_t(n00b_option_t(n00b_store_field_t *))
n00b_store_schema_find_field(n00b_store_schema_t *schema,
                             n00b_string_t       *name)
{
    if (schema == nullptr || schema->fields == nullptr || name == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_field_t *),
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_field_t *),
                          rocs_store_schema_find_field_raw(schema, name));
}

n00b_result_t(n00b_string_t *)
n00b_store_field_get_name(n00b_store_field_t *field)
{
    if (field == nullptr || field->name == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, field->name);
}

n00b_result_t(bool)
n00b_store_field_is_required(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(bool, field->required);
}

n00b_result_t(n00b_store_index_kind_t)
n00b_store_field_get_index_kind(n00b_store_field_t *field)
{
    if (field == nullptr) {
        return n00b_result_err(n00b_store_index_kind_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_index_kind_t, field->index_kind);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_none() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_NONE,
                                        .allocator = allocator));
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_time(n00b_string_t *field,
                                     uint64_t       bucket_width) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (rocs_store_string_empty(field) || bucket_width == 0) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_TIME,
                                        .field        = field,
                                        .bucket_width = bucket_width,
                                        .allocator    = allocator));
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_new_hash(n00b_string_t *field,
                                     uint32_t       buckets) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (rocs_store_string_empty(field) || buckets == 0) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(
        n00b_store_partition_policy_t *,
        rocs_store_partition_policy_new(N00B_STORE_PARTITION_HASH,
                                        .field     = field,
                                        .buckets   = buckets,
                                        .allocator = allocator));
}

n00b_result_t(n00b_store_partition_kind_t)
n00b_store_partition_policy_get_kind(n00b_store_partition_policy_t *policy)
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_store_partition_kind_t,
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_partition_kind_t, policy->kind);
}

static n00b_result_t(n00b_string_t *)
rocs_store_partition_route_value(
    n00b_store_partition_policy_t        *policy,
    n00b_option_t(n00b_json_node_t *)     value_opt) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    switch (policy->kind) {
    case N00B_STORE_PARTITION_NONE:
        return n00b_result_ok(n00b_string_t *, r"default");

    case N00B_STORE_PARTITION_TIME: {
        if (!n00b_option_is_set(value_opt)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        n00b_json_node_t *value = n00b_option_get(value_opt);
        if (n00b_json_type(value) != N00B_JSON_INT) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        int64_t ts = n00b_json_as_i64(value);
        if (ts < 0) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        uint64_t bucket = (uint64_t)ts / policy->bucket_width;
        return rocs_store_route_bucket(r"time/",
                                       bucket,
                                       .allocator = allocator);
    }

    case N00B_STORE_PARTITION_HASH: {
        if (!n00b_option_is_set(value_opt)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        n00b_json_node_t *value = n00b_option_get(value_opt);
        auto term_r = n00b_store_normalize_scalar(value, .allocator = allocator);
        if (n00b_result_is_err(term_r)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        auto hash_r = n00b_store_normalize_hash(N00B_STORE_INDEX_TERM,
                                                n00b_result_get(term_r),
                                                .allocator = allocator);
        if (n00b_result_is_err(hash_r)) {
            return n00b_result_ok(n00b_string_t *, r"default");
        }

        uint64_t bucket = (uint64_t)n00b_result_get(hash_r) % policy->buckets;
        return rocs_store_route_bucket(r"hash/",
                                       bucket,
                                       .allocator = allocator);
    }
    }

    return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_POLICY);
}

n00b_result_t(n00b_string_t *)
n00b_store_partition_route(n00b_store_partition_policy_t *policy,
                           n00b_json_node_t              *record) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return rocs_store_partition_route_value(
        policy,
        rocs_store_partition_value(policy, record),
        .allocator = allocator);
}

n00b_result_t(n00b_store_partition_policy_t *)
n00b_store_partition_policy_for_plan(n00b_store_t *store)
{
    if (store == nullptr || store->partition_policy == nullptr) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_store_partition_policy_t *,
                               N00B_STORE_ERR_STATE);
    }

    return n00b_result_ok(n00b_store_partition_policy_t *,
                          store->partition_policy);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_partition_policy_field_for_plan(
    n00b_store_partition_policy_t *policy)
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }

    switch (policy->kind) {
    case N00B_STORE_PARTITION_NONE:
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    case N00B_STORE_PARTITION_TIME:
    case N00B_STORE_PARTITION_HASH:
        if (policy->field == nullptr) {
            return n00b_result_err(n00b_option_t(n00b_string_t *),
                                   N00B_STORE_ERR_STATE);
        }
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_set(n00b_string_t *,
                                              policy->field));
    }

    return n00b_result_err(n00b_option_t(n00b_string_t *),
                           N00B_STORE_ERR_POLICY);
}

n00b_result_t(n00b_string_t *)
n00b_store_partition_route_value_for_plan(
    n00b_store_partition_policy_t *policy,
    n00b_json_node_t              *value) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (policy == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    n00b_option_t(n00b_json_node_t *) value_opt =
        value == nullptr
            ? n00b_option_none(n00b_json_node_t *)
            : n00b_option_set(n00b_json_node_t *, value);
    return rocs_store_partition_route_value(policy,
                                            value_opt,
                                            .allocator = allocator);
}

n00b_result_t(n00b_store_retain_policy_t *)
n00b_store_retain_policy_new(n00b_store_retain_kind_t kind) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!rocs_store_retain_kind_valid(kind)) {
        return n00b_result_err(n00b_store_retain_policy_t *,
                               N00B_STORE_ERR_POLICY);
    }

    n00b_store_retain_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_retain_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    policy->kind = kind;

    return n00b_result_ok(n00b_store_retain_policy_t *, policy);
}

n00b_result_t(n00b_store_shard_retention_policy_t *)
n00b_store_shard_retention_policy_new() _kargs
{
    uint64_t          max_sealed_shards  = 0;
    uint64_t          drop_before_seal_ts = 0;
    n00b_string_t    *drop_reason        = nullptr;
    n00b_allocator_t *allocator          = nullptr;
}
{
    if (max_sealed_shards == 0 && drop_before_seal_ts == 0) {
        return n00b_result_err(n00b_store_shard_retention_policy_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_shard_retention_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_shard_retention_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    policy->max_sealed_shards  = max_sealed_shards;
    policy->drop_before_seal_ts = drop_before_seal_ts;
    policy->drop_reason        = drop_reason == nullptr ? r"retention"
                                                        : drop_reason;

    return n00b_result_ok(n00b_store_shard_retention_policy_t *, policy);
}

n00b_result_t(n00b_store_seal_policy_t *)
n00b_store_seal_policy_new() _kargs
{
    uint64_t          max_records = 0;
    uint64_t          max_bytes   = 0;
    uint64_t          max_open_ns = 0;
    n00b_allocator_t *allocator   = nullptr;
}
{
    n00b_store_seal_policy_t *policy = n00b_alloc_with_opts(
        n00b_store_seal_policy_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    policy->max_records = max_records;
    policy->max_bytes   = max_bytes;
    policy->max_open_ns = max_open_ns;

    return n00b_result_ok(n00b_store_seal_policy_t *, policy);
}

n00b_store_residency_policy_t
n00b_store_residency_policy_get_default(void)
{
    return (n00b_store_residency_policy_t){
        .preferred_backing    = N00B_STORE_IMAGE_AUTO,
        .max_resident_bytes   = 0,
        .max_resident_shards  = 0,
        .idle_ns              = 0,
        .prefetch_pruned_shards = false,
        .allow_direct_mmap    = true,
    };
}

n00b_result_t(n00b_store_t *)
n00b_store_open_vfs(n00b_vfs_t          *vfs,
                    n00b_string_t       *root,
                    n00b_store_schema_t *schema) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
    n00b_store_retain_policy_t    *retain_policy    = nullptr;
    n00b_store_seal_policy_t      *seal_policy      = nullptr;
    n00b_store_residency_policy_t *residency_policy = nullptr;
    n00b_vfs_cache_t              *cache            = nullptr;
    n00b_store_commit_topic_t     *commit_topic     = nullptr;
    n00b_store_lifecycle_topic_t  *lifecycle_topic  = nullptr;
    n00b_string_t                 *display_name     = nullptr;
    n00b_allocator_t              *allocator        = nullptr;
}
{
    if (vfs == nullptr || schema == nullptr || schema->fields == nullptr
        || !rocs_store_root_valid(root)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_ARG);
    }

    auto freeze_r = n00b_store_schema_freeze(schema);
    if (n00b_result_is_err(freeze_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(freeze_r));
    }

    if (partition_policy == nullptr) {
        auto part_r = n00b_store_partition_policy_new_none(
            .allocator = allocator);
        if (n00b_result_is_err(part_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(part_r));
        }
        partition_policy = n00b_result_get(part_r);
    }
    if (retain_policy == nullptr) {
        auto retain_r = n00b_store_retain_policy_new(N00B_STORE_RETAIN_NONE,
                                                     .allocator = allocator);
        if (n00b_result_is_err(retain_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(retain_r));
        }
        retain_policy = n00b_result_get(retain_r);
    }
    if (seal_policy == nullptr) {
        auto seal_r = n00b_store_seal_policy_new(.allocator = allocator);
        if (n00b_result_is_err(seal_r)) {
            return n00b_result_err(n00b_store_t *, n00b_result_get_err(seal_r));
        }
        seal_policy = n00b_result_get(seal_r);
    }

    n00b_store_residency_policy_t residency =
        residency_policy == nullptr
            ? n00b_store_residency_policy_get_default()
            : *residency_policy;

    n00b_store_t *store = n00b_alloc_with_opts(
        n00b_store_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    store->vfs              = vfs;
    store->root             = root;
    store->display_name     = display_name;
    store->schema           = schema;
    store->partition_policy = partition_policy;
    store->retain_policy    = retain_policy;
    store->seal_policy      = seal_policy;
    store->residency_policy = residency;
    store->cache            = cache;
    store->commit_topic     = commit_topic;
    store->lifecycle_topic  = lifecycle_topic;
    store->hot_shard        = nullptr;
    store->hot_partition_key = r"default";
    store->catalog          = rocs_store_catalog_list_new(.allocator = allocator);
    store->allocator        = allocator;
    store->residency_lock   = n00b_data_lock_new(.allocator = allocator);
    store->commit_lock      = n00b_data_lock_new(.allocator = allocator);
    store->state            = N00B_STORE_STATE_OPEN;
    store->next_shard_id    = 2;
    store->generation       = 0;
    store->schema_generation = 0;
    store->oldest_available = (n00b_store_pos_t){};
    store->has_oldest_available = false;
    store->active_pins      = 0;

    auto layout_r = rocs_store_ensure_layout(store);
    if (n00b_result_is_err(layout_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(layout_r));
    }

    auto catalog_r = rocs_store_catalog_load(store);
    if (n00b_result_is_err(catalog_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(catalog_r));
    }

    uint64_t hot_shard_id = store->next_shard_id - 1;
    auto shard_r = n00b_store_shard_new(
        .shard_id   = hot_shard_id,
        .retain_raw = retain_policy->kind == N00B_STORE_RETAIN_INLINE,
        .open_ts    = (uint64_t)n00b_ns_timestamp(),
        .allocator  = allocator);
    if (n00b_result_is_err(shard_r)) {
        return n00b_result_err(n00b_store_t *, n00b_result_get_err(shard_r));
    }
    store->hot_shard = n00b_result_get(shard_r);

    return n00b_result_ok(n00b_store_t *, store);
}

n00b_result_t(bool)
n00b_store_flush(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    if (store->hot_shard != nullptr && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            store->allocator,
            store->hot_partition_key);
        if (n00b_result_is_err(seal_r)) {
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, true);
    }

    auto write_r = rocs_store_catalog_write(store);
    n00b_data_unlock(store->commit_lock);
    return write_r;
}

n00b_result_t(bool)
n00b_store_close(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins != 0) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    if (store->hot_shard != nullptr && store->hot_shard->record_count != 0) {
        auto seal_r = rocs_store_seal_hot_shard_unlocked(
            store,
            (uint64_t)n00b_ns_timestamp(),
            0,
            store->allocator,
            store->hot_partition_key);
        if (n00b_result_is_err(seal_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(bool, n00b_result_get_err(seal_r));
        }
    }
    else {
        auto catalog_r = rocs_store_catalog_write(store);
        if (n00b_result_is_err(catalog_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return catalog_r;
        }
    }

    auto unload_r = rocs_store_resident_unload_all_unpinned(store);
    if (n00b_result_is_err(unload_r)) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(unload_r));
    }

    store->state = N00B_STORE_STATE_CLOSED;
    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_state_t)
n00b_store_get_state(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_state_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->residency_lock);
    n00b_store_state_t state = store->state;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(n00b_store_state_t, state);
}

n00b_result_t(n00b_store_schema_t *)
n00b_store_get_schema(n00b_store_t *store)
{
    if (store == nullptr || store->schema == nullptr) {
        return n00b_result_err(n00b_store_schema_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_schema_t *, store->schema);
}

n00b_result_t(n00b_string_t *)
n00b_store_get_root(n00b_store_t *store)
{
    if (store == nullptr || store->root == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_string_t *, store->root);
}

n00b_result_t(uint64_t)
n00b_store_get_generation(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, store->generation);
}

n00b_result_t(n00b_store_catalog_entry_t *)
n00b_store_seal_hot_shard(n00b_store_t *store) _kargs
{
    uint64_t          seal_ts      = 0;
    uint32_t          base_address = 0;
    n00b_allocator_t *allocator    = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_catalog_entry_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    auto seal_r = rocs_store_seal_hot_shard_unlocked(store,
                                                     seal_ts,
                                                     base_address,
                                                     allocator,
                                                     store->hot_partition_key);
    n00b_data_unlock(store->commit_lock);
    return seal_r;
}

n00b_result_t(bool)
n00b_store_apply_event_time_watermark(n00b_store_t *store,
                                      uint64_t      watermark_ts)
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN
        || store->hot_shard == nullptr
        || store->partition_policy == nullptr) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (store->partition_policy->kind != N00B_STORE_PARTITION_TIME
        || store->partition_policy->bucket_width == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_POLICY);
    }
    if (store->hot_shard->record_count == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    n00b_option_t(uint64_t) bucket_opt =
        rocs_store_time_bucket_from_route(store->hot_partition_key);
    if (!n00b_option_is_set(bucket_opt)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    uint64_t bucket = n00b_option_get(bucket_opt);
    if (watermark_ts / store->partition_policy->bucket_width <= bucket) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(bool, false);
    }

    auto seal_r = rocs_store_seal_hot_shard_unlocked(
        store,
        (uint64_t)n00b_ns_timestamp(),
        0,
        store->allocator,
        store->hot_partition_key);
    if (n00b_result_is_err(seal_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(seal_r));
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(bool, true);
}

static n00b_result_t(bool)
rocs_store_ingest_common(n00b_store_t     *store,
                         n00b_json_node_t *record,
                         n00b_buffer_t    *raw)
{
    if (store == nullptr || record == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);

    n00b_err_t preflight = rocs_store_preflight_ingest(store, record, raw);
    if (preflight != N00B_STORE_OK) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, preflight);
    }

    auto route_r = n00b_store_partition_route(store->partition_policy,
                                              record,
                                              .allocator = store->allocator);
    if (n00b_result_is_err(route_r)) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(bool, n00b_result_get_err(route_r));
    }
    n00b_string_t *route = n00b_result_get(route_r);
    if (route == nullptr) {
        route = r"default";
    }

    auto ingest_r = rocs_store_ingest_prepared_unlocked(store,
                                                        record,
                                                        raw,
                                                        route,
                                                        nullptr);
    n00b_data_unlock(store->commit_lock);
    return ingest_r;
}

n00b_result_t(bool)
n00b_store_ingest(n00b_store_t *store, n00b_json_node_t *record)
{
    return rocs_store_ingest_common(store, record, nullptr);
}

n00b_result_t(bool)
n00b_store_ingest_buf(n00b_store_t *store, n00b_buffer_t *source)
{
    if (store == nullptr || source == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_buffer_t *raw = nullptr;
    n00b_json_node_t *record = nullptr;
    n00b_err_t err = rocs_store_parse_source(source,
                                             &raw,
                                             &record,
                                             store->allocator);
    if (err != N00B_STORE_OK) {
        return n00b_result_err(bool, err);
    }

    return rocs_store_ingest_common(store, record, raw);
}

static n00b_result_t(uint64_t)
rocs_store_ingest_batch_common(n00b_store_t             *store,
                               n00b_store_record_list_t *records,
                               n00b_store_source_list_t *sources,
                               int32_t                   worker_count,
                               int32_t                   queue_capacity)
{
    if (store == nullptr || (records == nullptr && sources == nullptr)
        || (records != nullptr && sources != nullptr)) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    if (worker_count < 0 || queue_capacity < 0) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    uint64_t count = records != nullptr ? (uint64_t)n00b_list_len(*records)
                                        : (uint64_t)n00b_list_len(*sources);
    if (count > (uint64_t)INT32_MAX) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }
    if (count == 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(uint64_t, 0);
    }

    int32_t workers = worker_count == 0 ? 4 : worker_count;
    if (workers > (int32_t)count) {
        workers = (int32_t)count;
    }
    if (workers <= 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    int32_t cap = queue_capacity == 0 ? workers : queue_capacity;
    if (cap <= 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    rocs_store_batch_job_t **jobs = n00b_alloc_array(
        rocs_store_batch_job_t *,
        (int64_t)count,
        N00B_ALLOC_OPTS(store->allocator));
    if (jobs == nullptr) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }

    n00b_worker_pool_t *pool = n00b_worker_pool_new(workers,
                                                    cap,
                                                    rocs_store_batch_worker,
                                                    nullptr,
                                                    .allocator =
                                                        store->allocator);
    if (pool == nullptr) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_INTERNAL);
    }

    for (uint64_t i = 0; i < count; i++) {
        rocs_store_batch_job_t *job = n00b_alloc(
            rocs_store_batch_job_t,
            N00B_ALLOC_OPTS(store->allocator));
        job->store        = store;
        job->input_record = nullptr;
        job->source       = nullptr;
        job->record       = nullptr;
        job->raw          = nullptr;
        job->route        = nullptr;
        job->terms        = nullptr;
        job->err          = N00B_STORE_OK;
        if (records != nullptr) {
            job->input_record = n00b_list_get(*records, (size_t)i);
        }
        else {
            job->source = n00b_list_get(*sources, (size_t)i);
        }
        jobs[i] = job;
        n00b_worker_pool_submit(pool, job);
    }

    n00b_worker_pool_quiesce(pool);
    n00b_worker_pool_shutdown(pool);

    for (uint64_t i = 0; i < count; i++) {
        if (jobs[i] == nullptr || jobs[i]->err != N00B_STORE_OK) {
            n00b_err_t err = jobs[i] == nullptr ? N00B_STORE_ERR_INTERNAL
                                                : jobs[i]->err;
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(uint64_t, err);
        }
    }

    uint64_t committed = 0;
    for (uint64_t i = 0; i < count; i++) {
        auto ingest_r = rocs_store_ingest_prepared_unlocked(store,
                                                            jobs[i]->record,
                                                            jobs[i]->raw,
                                                            jobs[i]->route,
                                                            jobs[i]->terms);
        if (n00b_result_is_err(ingest_r)) {
            n00b_err_t err = n00b_result_get_err(ingest_r);
            n00b_data_unlock(store->commit_lock);
            /*
             * result_t cannot carry both an error and a committed prefix.
             * Once any prefix is visible, the batch retry contract is
             * Ok(committed); callers resume from that index.
             */
            if (committed != 0) {
                return n00b_result_ok(uint64_t, committed);
            }
            return n00b_result_err(uint64_t, err);
        }
        committed++;
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(uint64_t, committed);
}

n00b_result_t(uint64_t)
n00b_store_ingest_batch(n00b_store_t             *store,
                        n00b_store_record_list_t *records) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
}
{
    return rocs_store_ingest_batch_common(store,
                                          records,
                                          nullptr,
                                          worker_count,
                                          queue_capacity);
}

n00b_result_t(uint64_t)
n00b_store_ingest_buf_batch(n00b_store_t             *store,
                            n00b_store_source_list_t *sources) _kargs
{
    int32_t worker_count   = 0;
    int32_t queue_capacity = 0;
}
{
    return rocs_store_ingest_batch_common(store,
                                          nullptr,
                                          sources,
                                          worker_count,
                                          queue_capacity);
}

static void
rocs_store_emit_lifecycle_drop(n00b_store_t               *store,
                               n00b_store_catalog_entry_t *entry,
                               n00b_string_t              *drop_reason)
{
    if (store == nullptr || entry == nullptr
        || store->lifecycle_topic == nullptr) {
        return;
    }

    n00b_store_lifecycle_t event = {
        .kind         = N00B_STORE_LIFECYCLE_DROPPED,
        .shard_id     = entry->shard_id,
        .record_count = entry->record_count,
        .byte_size    = entry->byte_len,
        .open_ts      = 0,
        .seal_ts      = entry->seal_ts,
        .drop_reason  = drop_reason == nullptr ? r"retention" : drop_reason,
    };
    auto event_r = n00b_store_lifecycle_publish(store->lifecycle_topic, event);
    (void)event_r;
}

static n00b_result_t(bool)
rocs_store_drop_sealed_shard_locked(n00b_store_t  *store,
                                    uint64_t       shard_id,
                                    n00b_string_t *drop_reason)
{
    if (store == nullptr || store->catalog == nullptr || shard_id == 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    uint64_t index = 0;
    if (!rocs_store_catalog_find_index(store, shard_id, &index)) {
        return n00b_result_err(bool, N00B_STORE_ERR_RETENTION);
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    if (entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }
    if (entry->resident_pins != 0) {
        return n00b_result_err(bool, N00B_STORE_ERR_PINNED);
    }

    n00b_store_pos_t old_oldest = store->oldest_available;
    bool             old_has_oldest = store->has_oldest_available;

    if (entry->resident_map != nullptr) {
        auto unload_r = rocs_store_resident_unload_entry(store, entry);
        if (n00b_result_is_err(unload_r)) {
            return n00b_result_err(bool, n00b_result_get_err(unload_r));
        }
    }

    n00b_list_delete(*store->catalog, (size_t)index);
    rocs_store_refresh_oldest_available(store);

    auto catalog_r = rocs_store_catalog_write(store);
    if (n00b_result_is_err(catalog_r)) {
        n00b_list_insert(*store->catalog, (size_t)index, entry);
        store->oldest_available     = old_oldest;
        store->has_oldest_available = old_has_oldest;
        return n00b_result_err(bool, n00b_result_get_err(catalog_r));
    }

    auto delete_r = n00b_vfs_delete(store->vfs, entry->object_path);
    if (n00b_result_is_err(delete_r)
        && n00b_result_get_err(delete_r) != N00B_VFS_ERR_NOT_FOUND) {
        n00b_list_insert(*store->catalog, (size_t)index, entry);
        store->oldest_available     = old_oldest;
        store->has_oldest_available = old_has_oldest;
        auto rollback_r = rocs_store_catalog_write(store);
        (void)rollback_r;
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    rocs_store_emit_lifecycle_drop(store, entry, drop_reason);
    return n00b_result_ok(bool, true);
}

static n00b_store_catalog_entry_t *
rocs_store_oldest_retention_candidate(n00b_store_t                        *store,
                                      n00b_store_shard_retention_policy_t *policy)
{
    if (store == nullptr || policy == nullptr || store->catalog == nullptr) {
        return nullptr;
    }

    uint64_t count = (uint64_t)n00b_list_len(*store->catalog);
    bool over_count = policy->max_sealed_shards != 0
                   && count > policy->max_sealed_shards;

    n00b_store_catalog_entry_t *candidate = nullptr;
    size_t len = n00b_list_len(*store->catalog);
    for (size_t i = 0; i < len; i++) {
        n00b_store_catalog_entry_t *entry = n00b_list_get(*store->catalog, i);
        if (entry == nullptr) {
            continue;
        }
        bool old_by_time = policy->drop_before_seal_ts != 0
                        && entry->seal_ts < policy->drop_before_seal_ts;
        if (!over_count && !old_by_time) {
            continue;
        }
        if (rocs_store_entry_pos_less(entry, candidate)) {
            candidate = entry;
        }
    }

    return candidate;
}

n00b_result_t(uint64_t)
n00b_store_apply_shard_retention(
    n00b_store_t                        *store,
    n00b_store_shard_retention_policy_t *policy)
{
    if (store == nullptr || policy == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t dropped = 0;
    while (true) {
        n00b_store_catalog_entry_t *candidate =
            rocs_store_oldest_retention_candidate(store, policy);
        if (candidate == nullptr) {
            break;
        }

        uint64_t shard_id = candidate->shard_id;
        auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                          shard_id,
                                                          policy->drop_reason);
        if (n00b_result_is_err(drop_r)) {
            n00b_data_unlock(store->residency_lock);
            n00b_data_unlock(store->commit_lock);
            return n00b_result_err(uint64_t, n00b_result_get_err(drop_r));
        }
        dropped++;
    }

    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(uint64_t, dropped);
}

n00b_result_t(bool)
n00b_store_drop_sealed_shard(n00b_store_t *store,
                             uint64_t      shard_id) _kargs
{
    n00b_string_t *drop_reason = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(store->commit_lock);
    n00b_data_write_lock(store->residency_lock);
    auto drop_r = rocs_store_drop_sealed_shard_locked(store,
                                                      shard_id,
                                                      drop_reason);
    n00b_data_unlock(store->residency_lock);
    n00b_data_unlock(store->commit_lock);
    return drop_r;
}

n00b_result_t(n00b_option_t(n00b_store_pos_t))
n00b_store_oldest_available_pos(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_pos_t),
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    n00b_option_t(n00b_store_pos_t) result =
        store->has_oldest_available
            ? n00b_option_set(n00b_store_pos_t, store->oldest_available)
            : n00b_option_none(n00b_store_pos_t);
    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_option_t(n00b_store_pos_t), result);
}

n00b_result_t(n00b_store_resume_check_t)
n00b_store_resume_check(n00b_store_t *store, n00b_store_pos_t pos)
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_resume_check_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->commit_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_err(n00b_store_resume_check_t,
                               N00B_STORE_ERR_STATE);
    }
    if (pos.generation != store->generation) {
        n00b_store_resume_check_t check = {
            .available        = false,
            .oldest_available = store->has_oldest_available
                                    ? store->oldest_available
                                    : (n00b_store_pos_t){},
        };
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_store_resume_check_t, check);
    }

    n00b_store_resume_check_t check = {
        .available        = false,
        .oldest_available = store->has_oldest_available
                                ? store->oldest_available
                                : (n00b_store_pos_t){},
    };
    if (!store->has_oldest_available
        || n00b_store_pos_compare(pos, store->oldest_available) < 0) {
        n00b_data_unlock(store->commit_lock);
        return n00b_result_ok(n00b_store_resume_check_t, check);
    }

    auto entry_opt = rocs_store_catalog_find_raw(store, pos.shard_id);
    if (n00b_option_is_set(entry_opt)) {
        n00b_store_catalog_entry_t *entry = n00b_option_get(entry_opt);
        check.available = entry != nullptr
                       && pos.ordinal < entry->record_count
                       && pos.generation == entry->generation;
    }

    n00b_data_unlock(store->commit_lock);
    return n00b_result_ok(n00b_store_resume_check_t, check);
}

static void
rocs_store_conduit_stats_record(n00b_store_conduit_ingest_t *adapter,
                                bool                         ok,
                                n00b_err_t                   err)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(adapter->lock);
    if (ok) {
        adapter->stats.committed++;
    }
    else {
        adapter->stats.failed++;
        adapter->stats.last_error = err;
    }
    n00b_data_unlock(adapter->lock);
}

static void
rocs_store_conduit_worker(void *job_ptr, void *user_data)
{
    (void)user_data;

    rocs_store_conduit_job_t *job = job_ptr;
    if (job == nullptr || job->adapter == nullptr
        || job->adapter->store == nullptr) {
        return;
    }

    n00b_result_t(bool) ingest_r;
    if (n00b_variant_is_type(job->payload, n00b_json_node_t *)) {
        ingest_r = n00b_store_ingest(
            job->adapter->store,
            n00b_variant_get(job->payload, n00b_json_node_t *));
    }
    else if (n00b_variant_is_type(job->payload, n00b_buffer_t *)) {
        ingest_r = n00b_store_ingest_buf(
            job->adapter->store,
            n00b_variant_get(job->payload, n00b_buffer_t *));
    }
    else {
        rocs_store_conduit_stats_record(job->adapter,
                                        false,
                                        N00B_STORE_ERR_ARG);
        return;
    }

    if (n00b_result_is_ok(ingest_r)) {
        rocs_store_conduit_stats_record(job->adapter, true, N00B_STORE_OK);
    }
    else {
        rocs_store_conduit_stats_record(job->adapter,
                                        false,
                                        n00b_result_get_err(ingest_r));
    }
}

static void
rocs_store_conduit_submit(n00b_store_conduit_ingest_t *adapter,
                          n00b_store_ingest_payload_t  payload)
{
    rocs_store_conduit_job_t *job = n00b_alloc(
        rocs_store_conduit_job_t,
        N00B_ALLOC_OPTS(adapter->allocator));
    job->adapter = adapter;
    job->payload = payload;

    n00b_worker_pool_submit(adapter->pool, job);

    n00b_data_write_lock(adapter->lock);
    adapter->stats.submitted++;
    n00b_data_unlock(adapter->lock);
}

static void
rocs_store_conduit_cancel_subscription(n00b_store_conduit_ingest_t *adapter)
{
    if (adapter == nullptr || adapter->lock == nullptr) {
        return;
    }

    n00b_data_write_lock(adapter->lock);
    n00b_conduit_sub_handle_t sub = adapter->sub;
    n00b_store_ingest_topic_t *topic = adapter->topic;
    adapter->sub = N00B_CONDUIT_INVALID_SUB_HANDLE;
    n00b_data_unlock(adapter->lock);

    if (sub == N00B_CONDUIT_INVALID_SUB_HANDLE || topic == nullptr) {
        return;
    }

    _n00b_list_write_lock(&topic->subscriptions);
    n00b_conduit_sub_cancel(sub);
    _n00b_list_unlock(&topic->subscriptions);
}

static void *
rocs_store_conduit_loop(void *arg)
{
    n00b_store_conduit_ingest_t *adapter = arg;
    if (adapter == nullptr || adapter->inbox == nullptr) {
        return nullptr;
    }

    while (true) {
        n00b_store_ingest_msg_t *msg =
            n00b_store_ingest_inbox_pop(adapter->inbox);
        if (msg != nullptr) {
            rocs_store_conduit_submit(adapter, msg->payload);
            continue;
        }

        n00b_conduit_sys_msg_t *sys =
            n00b_conduit_inbox_pop_sys(adapter->inbox);
        if (sys != nullptr
            && (sys->header.type == N00B_CONDUIT_MSG_TOPIC_CLOSED
                || sys->header.type == N00B_CONDUIT_MSG_PUBLISHER_LOST)) {
            break;
        }

        n00b_data_read_lock(adapter->lock);
        bool stop_requested = adapter->stop_requested;
        n00b_data_unlock(adapter->lock);
        if (stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)) {
            break;
        }

        n00b_condition_lock(&adapter->inbox->cv);
        n00b_data_read_lock(adapter->lock);
        stop_requested = adapter->stop_requested;
        n00b_data_unlock(adapter->lock);
        if (!stop_requested
            && !n00b_store_ingest_inbox_has_messages(adapter->inbox)
            && !n00b_conduit_inbox_has_sys(adapter->inbox)) {
            n00b_condition_wait(&adapter->inbox->cv,
                                .timeout_ms  = 100,
                                .auto_unlock = true);
        }
        else {
            n00b_condition_unlock(&adapter->inbox->cv);
        }
    }

    rocs_store_conduit_cancel_subscription(adapter);

    n00b_worker_pool_quiesce(adapter->pool);
    n00b_worker_pool_shutdown(adapter->pool);

    n00b_data_write_lock(adapter->lock);
    adapter->closed = true;
    n00b_data_unlock(adapter->lock);
    return nullptr;
}

n00b_result_t(n00b_store_conduit_ingest_t *)
n00b_store_conduit_ingest_start(n00b_store_t               *store,
                                n00b_store_ingest_topic_t  *topic) _kargs
{
    int32_t           worker_count   = 0;
    int32_t           queue_capacity = 0;
    n00b_allocator_t *allocator      = nullptr;
}
{
    if (store == nullptr || topic == nullptr || worker_count < 0
        || queue_capacity < 0) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_ARG);
    }
    n00b_conduit_topic_base_t *base = (n00b_conduit_topic_base_t *)topic;
    if (!n00b_conduit_topic_is_active(base) || base->conduit == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    int32_t workers = worker_count == 0 ? 1 : worker_count;
    int32_t cap     = queue_capacity == 0 ? workers : queue_capacity;
    if (workers <= 0 || cap <= 0) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_ARG);
    }

    n00b_store_conduit_ingest_t *adapter = n00b_alloc_with_opts(
        n00b_store_conduit_ingest_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    adapter->store          = store;
    adapter->topic          = topic;
    adapter->sub            = N00B_CONDUIT_INVALID_SUB_HANDLE;
    adapter->lock           = n00b_data_lock_new(.allocator = allocator);
    adapter->allocator      = allocator;
    adapter->stats          = (n00b_store_conduit_ingest_stats_t){};
    adapter->stop_requested = false;
    adapter->closed         = false;
    adapter->joined         = false;

    adapter->inbox = n00b_alloc_with_opts(
        n00b_store_ingest_inbox_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    n00b_conduit_inbox_init(n00b_store_ingest_payload_t,
                            adapter->inbox,
                            base->conduit,
                            N00B_CONDUIT_BP_UNBOUNDED,
                            0);

    adapter->pool = n00b_worker_pool_new(workers,
                                         cap,
                                         rocs_store_conduit_worker,
                                         nullptr,
                                         .allocator = allocator);
    if (adapter->pool == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    adapter->sub = n00b_conduit_subscribe(n00b_store_ingest_payload_t,
                                          topic,
                                          adapter->inbox,
                                          .operations = N00B_CONDUIT_OP_ALL);
    if (adapter->sub == N00B_CONDUIT_INVALID_SUB_HANDLE) {
        n00b_worker_pool_shutdown(adapter->pool);
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }

    auto thread_r = n00b_thread_spawn(rocs_store_conduit_loop, adapter);
    if (n00b_result_is_err(thread_r)) {
        n00b_conduit_sub_cancel(adapter->sub);
        n00b_worker_pool_shutdown(adapter->pool);
        return n00b_result_err(n00b_store_conduit_ingest_t *,
                               N00B_STORE_ERR_INTERNAL);
    }
    adapter->thread = n00b_result_get(thread_r);

    return n00b_result_ok(n00b_store_conduit_ingest_t *, adapter);
}

n00b_result_t(bool)
n00b_store_conduit_ingest_close(n00b_store_conduit_ingest_t *ingest)
{
    if (ingest == nullptr || ingest->lock == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }

    n00b_data_write_lock(ingest->lock);
    if (ingest->joined) {
        n00b_data_unlock(ingest->lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    ingest->stop_requested = true;
    n00b_data_unlock(ingest->lock);

    rocs_store_conduit_cancel_subscription(ingest);

    if (ingest->inbox != nullptr) {
        n00b_condition_lock(&ingest->inbox->cv);
        n00b_condition_notify(&ingest->inbox->cv,
                              .all = true,
                              .auto_unlock = true);
    }
    if (ingest->thread != nullptr) {
        n00b_thread_join(ingest->thread);
    }

    n00b_data_write_lock(ingest->lock);
    ingest->closed = true;
    ingest->joined = true;
    n00b_data_unlock(ingest->lock);

    return n00b_result_ok(bool, true);
}

n00b_result_t(n00b_store_conduit_ingest_stats_t)
n00b_store_conduit_ingest_stats(n00b_store_conduit_ingest_t *ingest)
{
    if (ingest == nullptr || ingest->lock == nullptr) {
        return n00b_result_err(n00b_store_conduit_ingest_stats_t,
                               N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(ingest->lock);
    n00b_store_conduit_ingest_stats_t stats = ingest->stats;
    n00b_data_unlock(ingest->lock);
    return n00b_result_ok(n00b_store_conduit_ingest_stats_t, stats);
}

n00b_result_t(uint64_t)
n00b_store_catalog_get_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*store->catalog));
}

n00b_result_t(uint64_t)
n00b_store_catalog_visible_entry_count(n00b_store_t *store)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    return n00b_result_ok(uint64_t, (uint64_t)n00b_list_len(*store->catalog));
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_visible_entry_at(n00b_store_t *store, uint64_t index)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    uint64_t len = (uint64_t)n00b_list_len(*store->catalog);
    if (index >= len || index > (uint64_t)SIZE_MAX) {
        return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                              n00b_option_none(n00b_store_catalog_entry_t *));
    }

    n00b_store_catalog_entry_t *entry =
        n00b_list_get(*store->catalog, (size_t)index);
    if (entry == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_STATE);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                          n00b_option_set(n00b_store_catalog_entry_t *,
                                          entry));
}

n00b_result_t(n00b_option_t(n00b_store_catalog_entry_t *))
n00b_store_catalog_find_shard(n00b_store_t *store, uint64_t shard_id)
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_store_catalog_entry_t *),
                               N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_option_t(n00b_store_catalog_entry_t *),
                          rocs_store_catalog_find_raw(store, shard_id));
}

n00b_result_t(bool)
n00b_store_catalog_entry_verify_object(n00b_store_t              *store,
                                       n00b_store_catalog_entry_t *entry)
{
    if (store == nullptr || entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    if (store->state != N00B_STORE_STATE_OPEN) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    auto stat_r = n00b_vfs_stat(store->vfs, entry->object_path);
    if (n00b_result_is_err(stat_r)) {
        return n00b_result_err(bool, N00B_STORE_ERR_VFS);
    }

    n00b_vfs_obj_stat_t stat = n00b_result_get(stat_r);
    if (stat.kind != N00B_VFS_OBJ_FILE || stat.size != entry->byte_len) {
        return n00b_result_err(bool, N00B_STORE_ERR_CORRUPT);
    }

    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_shard_id(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->shard_id);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_generation(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->generation);
}

n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_object_path(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->object_path == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_string_t *, entry->object_path);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_byte_len(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->byte_len);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_record_count(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->record_count);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_schema_generation(
    n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->schema_generation);
}

n00b_result_t(uint64_t)
n00b_store_catalog_entry_get_seal_ts(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(uint64_t, entry->seal_ts);
}

n00b_result_t(n00b_string_t *)
n00b_store_catalog_entry_get_partition_key(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr || entry->partition_key == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_string_t *, entry->partition_key);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_store_catalog_entry_get_etag(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }
    if (entry->etag == nullptr) {
        return n00b_result_ok(n00b_option_t(n00b_string_t *),
                              n00b_option_none(n00b_string_t *));
    }

    return n00b_result_ok(n00b_option_t(n00b_string_t *),
                          n00b_option_set(n00b_string_t *, entry->etag));
}

n00b_result_t(bool)
n00b_store_catalog_entry_is_resident(n00b_store_catalog_entry_t *entry)
{
    if (entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_store_t *store = entry->owner;
    if (store != nullptr) {
        n00b_data_read_lock(store->residency_lock);
    }
    bool resident = entry->resident_map != nullptr;
    if (store != nullptr) {
        n00b_data_unlock(store->residency_lock);
    }
    return n00b_result_ok(bool, resident);
}

n00b_result_t(n00b_store_resident_shard_t *)
n00b_store_resident_shard_acquire(n00b_store_t               *store,
                                  n00b_store_catalog_entry_t *entry) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr || entry == nullptr) {
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_STATE);
    }
    if (!rocs_store_catalog_owns_entry(store, entry)) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_ARG);
    }
    if (store->active_pins == UINT64_MAX
        || entry->resident_pins == UINT64_MAX) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               N00B_STORE_ERR_STATE);
    }

    auto map_r = rocs_store_resident_load_entry(store, entry);
    if (n00b_result_is_err(map_r)) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_resident_shard_t *,
                               n00b_result_get_err(map_r));
    }

    n00b_store_resident_shard_t *resident = n00b_alloc_with_opts(
        n00b_store_resident_shard_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    resident->store    = store;
    resident->entry    = entry;
    resident->released = false;
    entry->resident_pins++;
    store->active_pins++;
    n00b_data_unlock(store->residency_lock);

    return n00b_result_ok(n00b_store_resident_shard_t *, resident);
}

n00b_result_t(n00b_store_map_t *)
n00b_store_resident_shard_map(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr || resident->entry == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    n00b_store_t *store = resident->store;
    if (store == nullptr) {
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (resident->released || resident->entry->resident_map == nullptr) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_map_t *, N00B_STORE_ERR_STATE);
    }
    resident->entry->last_access_ns = (uint64_t)n00b_ns_timestamp();
    n00b_store_map_t *map = resident->entry->resident_map;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(n00b_store_map_t *, map);
}

n00b_result_t(bool)
n00b_store_resident_shard_release(n00b_store_resident_shard_t *resident)
{
    if (resident == nullptr || resident->store == nullptr
        || resident->entry == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(resident->store->residency_lock);
    if (resident->released) {
        n00b_data_unlock(resident->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (resident->entry->resident_pins == 0
        || resident->store->active_pins == 0) {
        n00b_data_unlock(resident->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_INTERNAL);
    }

    resident->entry->resident_pins--;
    resident->store->active_pins--;
    resident->released = true;
    n00b_data_unlock(resident->store->residency_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_bytes(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->residency_lock);
    uint64_t resident_bytes = store->resident_bytes;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_bytes);
}

n00b_result_t(uint64_t)
n00b_store_get_resident_shard_count(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_read_lock(store->residency_lock);
    uint64_t resident_shards = store->resident_shards;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, resident_shards);
}

n00b_result_t(uint64_t)
n00b_store_residency_trim(n00b_store_t *store) _kargs
{
    uint64_t target_resident_bytes = 0;
}
{
    if (store == nullptr || store->catalog == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(uint64_t, N00B_STORE_ERR_STATE);
    }

    uint64_t target_bytes = target_resident_bytes;
    if (target_bytes == 0 && store->residency_policy.max_resident_bytes != 0) {
        target_bytes = store->residency_policy.max_resident_bytes;
    }
    uint64_t target_shards = store->residency_policy.max_resident_shards;
    uint64_t released      = 0;
    uint64_t now_ns        = (uint64_t)n00b_ns_timestamp();

    while (true) {
        bool bytes_over =
            target_bytes != 0 && store->resident_bytes > target_bytes;
        bool shards_over =
            target_shards != 0 && store->resident_shards > target_shards;
        n00b_store_catalog_entry_t *victim =
            rocs_store_oldest_unpinned_resident(store, now_ns);

        bool idle_victim = victim != nullptr
                        && store->residency_policy.idle_ns != 0
                        && victim->last_access_ns != 0
                        && now_ns >= victim->last_access_ns
                        && now_ns - victim->last_access_ns
                               >= store->residency_policy.idle_ns;
        if (!bytes_over && !shards_over && !idle_victim) {
            break;
        }
        if (victim == nullptr) {
            break;
        }

        uint64_t len = victim->byte_len;
        auto unload_r = rocs_store_resident_unload_entry(store, victim);
        if (n00b_result_is_err(unload_r)) {
            n00b_data_unlock(store->residency_lock);
            return n00b_result_err(uint64_t, n00b_result_get_err(unload_r));
        }
        if (n00b_result_get(unload_r)) {
            released += len;
        }
    }

    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, released);
}

n00b_result_t(n00b_string_t *)
n00b_store_pos_encode(n00b_store_pos_t pos) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    static const char hex_digits[] = "0123456789abcdef";
    char              token_bytes[48];
    uint64_t          words[3] = {
        pos.generation,
        pos.shard_id,
        pos.ordinal,
    };

    uint64_t out = 0;
    for (uint64_t w = 0; w < 3; w++) {
        for (uint8_t i = 0; i < 8; i++) {
            uint8_t byte =
                (uint8_t)((words[w] >> (56 - (i * 8))) & UINT64_C(0xff));
            token_bytes[out++] = hex_digits[byte >> 4];
            token_bytes[out++] = hex_digits[byte & 0x0f];
        }
    }

    n00b_string_t *token = n00b_string_from_raw(token_bytes,
                                                48,
                                                .allocator = allocator);
    if (token == nullptr) {
        return n00b_result_err(n00b_string_t *, N00B_STORE_ERR_INTERNAL);
    }

    return n00b_result_ok(n00b_string_t *, token);
}

static n00b_result_t(uint8_t)
rocs_store_hex_nibble(uint8_t byte)
{
    if (byte >= '0' && byte <= '9') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - '0'));
    }
    if (byte >= 'a' && byte <= 'f') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - 'a' + 10));
    }
    if (byte >= 'A' && byte <= 'F') {
        return n00b_result_ok(uint8_t, (uint8_t)(byte - 'A' + 10));
    }
    return n00b_result_err(uint8_t, N00B_STORE_ERR_ARG);
}

static n00b_result_t(uint64_t)
rocs_store_pos_decode_u64(n00b_string_t *token, uint64_t start)
{
    uint64_t value = 0;
    for (uint64_t i = 0; i < 16; i++) {
        auto nibble_r = rocs_store_hex_nibble(
            (uint8_t)token->data[start + i]);
        if (n00b_result_is_err(nibble_r)) {
            return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
        }
        value = (value << 4) | n00b_result_get(nibble_r);
    }
    return n00b_result_ok(uint64_t, value);
}

n00b_result_t(n00b_store_pos_t)
n00b_store_pos_decode(n00b_string_t *token)
{
    if (token == nullptr || token->data == nullptr || token->u8_bytes != 48) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    auto generation_r = rocs_store_pos_decode_u64(token, 0);
    auto shard_r      = rocs_store_pos_decode_u64(token, 16);
    auto ordinal_r    = rocs_store_pos_decode_u64(token, 32);
    if (n00b_result_is_err(generation_r) || n00b_result_is_err(shard_r)
        || n00b_result_is_err(ordinal_r)) {
        return n00b_result_err(n00b_store_pos_t, N00B_STORE_ERR_ARG);
    }

    return n00b_result_ok(n00b_store_pos_t,
                          ((n00b_store_pos_t){
                              .shard_id   = n00b_result_get(shard_r),
                              .ordinal    = n00b_result_get(ordinal_r),
                              .generation = n00b_result_get(generation_r),
                          }));
}

int32_t
n00b_store_pos_compare(n00b_store_pos_t a, n00b_store_pos_t b)
{
    if (a.generation != b.generation) {
        return a.generation < b.generation ? -1 : 1;
    }
    if (a.shard_id != b.shard_id) {
        return a.shard_id < b.shard_id ? -1 : 1;
    }
    if (a.ordinal != b.ordinal) {
        return a.ordinal < b.ordinal ? -1 : 1;
    }
    return 0;
}

n00b_result_t(n00b_store_pin_t *)
n00b_store_pin_acquire(n00b_store_t *store) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (store == nullptr) {
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_ARG);
    }
    n00b_data_write_lock(store->residency_lock);
    if (store->state != N00B_STORE_STATE_OPEN) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }
    if (store->active_pins == UINT64_MAX) {
        n00b_data_unlock(store->residency_lock);
        return n00b_result_err(n00b_store_pin_t *, N00B_STORE_ERR_STATE);
    }

    n00b_store_pin_t *pin = n00b_alloc_with_opts(
        n00b_store_pin_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    pin->store    = store;
    pin->released = false;
    store->active_pins++;
    n00b_data_unlock(store->residency_lock);

    return n00b_result_ok(n00b_store_pin_t *, pin);
}

n00b_result_t(bool)
n00b_store_pin_release(n00b_store_pin_t *pin)
{
    if (pin == nullptr || pin->store == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    n00b_data_write_lock(pin->store->residency_lock);
    if (pin->released) {
        n00b_data_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }
    if (pin->store->active_pins == 0) {
        n00b_data_unlock(pin->store->residency_lock);
        return n00b_result_err(bool, N00B_STORE_ERR_STATE);
    }

    pin->store->active_pins--;
    pin->released = true;
    n00b_data_unlock(pin->store->residency_lock);
    return n00b_result_ok(bool, true);
}

n00b_result_t(uint64_t)
n00b_store_get_active_pins(n00b_store_t *store)
{
    if (store == nullptr) {
        return n00b_result_err(uint64_t, N00B_STORE_ERR_ARG);
    }

    n00b_data_read_lock(store->residency_lock);
    uint64_t active_pins = store->active_pins;
    n00b_data_unlock(store->residency_lock);
    return n00b_result_ok(uint64_t, active_pins);
}
