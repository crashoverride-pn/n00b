#include "n00b.h"
#include "rocs/map.h"
#include "rocs/shard.h"
#include "rocs/store.h"
#include "rocs/wax.h"
#include "text/strings/string_ops.h"
#include "util/path.h"
#include "vfs/backend_local.h"
#include "vfs/vfs.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    ROCS_SHARDS_CMD_NONE,
    ROCS_SHARDS_CMD_LIST,
    ROCS_SHARDS_CMD_VERIFY,
    ROCS_SHARDS_CMD_SCAN,
    ROCS_SHARDS_CMD_QUARANTINE,
    ROCS_SHARDS_CMD_PURGE_QUARANTINED,
    ROCS_SHARDS_CMD_DROP,
} rocs_shards_cmd_t;

typedef struct {
    rocs_shards_cmd_t  cmd;
    n00b_string_t     *store_root;
    uint64_t           shard_id;
    bool               has_shard_id;
    bool               quarantine;
    bool               list_quarantined;
    bool               yes;
} rocs_shards_args_t;

static void
usage(void)
{
    fprintf(stderr,
            "usage: rocsctl [--store-root PATH] list\n"
            "       rocsctl [--store-root PATH] list --quarantined\n"
            "       rocsctl [--store-root PATH] verify --shard-id N\n"
            "       rocsctl [--store-root PATH] scan [--quarantine --yes]\n"
            "       rocsctl [--store-root PATH] quarantine --shard-id N --yes\n"
            "       rocsctl [--store-root PATH] purge-quarantined --yes\n"
            "       rocsctl [--store-root PATH] drop --shard-id N --yes\n"
            "\n"
            "PATH may be the Crayon support dir, rocs-cache dir, or rocs-cache/store.\n");
}

static void
print_string(n00b_string_t *s)
{
    if (s == NULL || s->data == NULL) {
        return;
    }
    printf("%.*s", (int)s->u8_bytes, s->data);
}

static bool
parse_u64_arg(const char *s, uint64_t *out)
{
    if (s == NULL || *s == '\0') {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static n00b_string_t *
strip_suffix_bytes(n00b_string_t *s, const char *suffix, size_t suffix_len)
{
    if (s == NULL || s->u8_bytes < suffix_len) {
        return NULL;
    }
    if (memcmp(s->data + s->u8_bytes - suffix_len,
               suffix,
               suffix_len) != 0) {
        return NULL;
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)(s->u8_bytes - suffix_len));
}

static bool
parse_args(int argc, char **argv, rocs_shards_args_t *args)
{
    *args = (rocs_shards_args_t){0};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--store-root") == 0) {
            if (++i >= argc) {
                return false;
            }
            args->store_root = n00b_string_from_cstr(argv[i]);
            continue;
        }
        if (strcmp(argv[i], "--shard-id") == 0) {
            if (++i >= argc || !parse_u64_arg(argv[i], &args->shard_id)) {
                return false;
            }
            args->has_shard_id = true;
            continue;
        }
        if (strcmp(argv[i], "--yes") == 0) {
            args->yes = true;
            continue;
        }
        if (strcmp(argv[i], "--quarantine") == 0) {
            args->quarantine = true;
            continue;
        }
        if (strcmp(argv[i], "--quarantined") == 0) {
            args->list_quarantined = true;
            continue;
        }
        if (strcmp(argv[i], "list") == 0) {
            args->cmd = ROCS_SHARDS_CMD_LIST;
            continue;
        }
        if (strcmp(argv[i], "verify") == 0) {
            args->cmd = ROCS_SHARDS_CMD_VERIFY;
            continue;
        }
        if (strcmp(argv[i], "scan") == 0) {
            args->cmd = ROCS_SHARDS_CMD_SCAN;
            continue;
        }
        if (strcmp(argv[i], "quarantine") == 0) {
            args->cmd = ROCS_SHARDS_CMD_QUARANTINE;
            continue;
        }
        if (strcmp(argv[i], "purge-quarantined") == 0) {
            args->cmd = ROCS_SHARDS_CMD_PURGE_QUARANTINED;
            continue;
        }
        if (strcmp(argv[i], "drop") == 0) {
            args->cmd = ROCS_SHARDS_CMD_DROP;
            continue;
        }
        return false;
    }

    if (args->store_root == NULL || args->cmd == ROCS_SHARDS_CMD_NONE) {
        return false;
    }
    if ((args->cmd == ROCS_SHARDS_CMD_VERIFY
         || args->cmd == ROCS_SHARDS_CMD_QUARANTINE
         || args->cmd == ROCS_SHARDS_CMD_DROP)
        && (!args->has_shard_id || args->shard_id == 0)) {
        return false;
    }
    if (args->quarantine && args->cmd != ROCS_SHARDS_CMD_SCAN) {
        return false;
    }
    if (args->list_quarantined && args->cmd != ROCS_SHARDS_CMD_LIST) {
        return false;
    }
    if (args->cmd != ROCS_SHARDS_CMD_DROP
        && args->cmd != ROCS_SHARDS_CMD_QUARANTINE
        && args->cmd != ROCS_SHARDS_CMD_PURGE_QUARANTINED
        && !(args->cmd == ROCS_SHARDS_CMD_SCAN && args->quarantine)
        && args->yes) {
        return false;
    }
    if (args->cmd == ROCS_SHARDS_CMD_SCAN && args->quarantine && !args->yes) {
        return false;
    }
    if (args->cmd == ROCS_SHARDS_CMD_PURGE_QUARANTINED && !args->yes) {
        return false;
    }
    return true;
}

static int
print_store_err(const char *op, n00b_err_t err)
{
    fprintf(stderr,
            "rocsctl: %s failed: ",
            op);
    print_string(n00b_store_err_str(err));
    fprintf(stderr, " (%" PRId64 ")\n", (int64_t)err);
    return 1;
}

static int
print_map_err(const char *op, n00b_err_t err)
{
    fprintf(stderr,
            "rocsctl: %s failed: ",
            op);
    print_string(n00b_store_map_err_str(err));
    fprintf(stderr, " (%" PRId64 ")\n", (int64_t)err);
    return 1;
}

static n00b_result_t(n00b_store_t *)
open_wax_store(n00b_string_t *local_store_root)
{
    auto schema_r = n00b_rocs_wax_schema_new();
    if (n00b_result_is_err(schema_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_CONFIG);
    }
    auto partition_r = n00b_rocs_wax_partition_policy_new();
    auto seal_r      = n00b_rocs_wax_seal_policy_new();
    if (n00b_result_is_err(partition_r) || n00b_result_is_err(seal_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_POLICY);
    }

    auto vfs_r = n00b_vfs_new();
    if (n00b_result_is_err(vfs_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
    }
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    n00b_string_t *backend_root = strip_suffix_bytes(local_store_root,
                                                     "/store",
                                                     6);
    if (backend_root == NULL
        && n00b_unicode_str_ends_with(local_store_root, r"/rocs-cache")) {
        backend_root = local_store_root;
    }
    if (backend_root == NULL) {
        backend_root = n00b_path_join_v(local_store_root, r"rocs-cache");
    }

    auto backend_r = n00b_vfs_backend_local_new(backend_root);
    if (n00b_result_is_err(backend_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
    }
    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(backend_r), 0);
    if (n00b_result_is_err(mount_r)) {
        return n00b_result_err(n00b_store_t *, N00B_STORE_ERR_VFS);
    }

    static n00b_store_residency_policy_t policy;
    policy                     = n00b_store_residency_policy_get_default();
    policy.preferred_backing   = N00B_STORE_IMAGE_LOCAL_MMAP;
    policy.allow_direct_mmap   = true;
    policy.validate_on_open    = false;
    policy.max_resident_bytes  = 0;
    policy.max_resident_shards = 1;

    return n00b_store_open_vfs(vfs,
                               r"/store",
                               n00b_result_get(schema_r),
                               .partition_policy = n00b_result_get(partition_r),
                               .seal_policy      = n00b_result_get(seal_r),
                               .residency_policy = &policy,
                               .retention_window_ns = 0,
                               .retention_max_total_bytes = 0,
                               .display_name     = r"rocsctl");
}

static void
format_epoch_ns(uint64_t epoch_ns, char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0) {
        return;
    }
    if (epoch_ns == 0) {
        snprintf(buf, buf_len, "-");
        return;
    }

    time_t seconds = (time_t)(epoch_ns / 1000000000ULL);
    uint64_t millis = (epoch_ns % 1000000000ULL) / 1000000ULL;
    struct tm tm = {0};
    if (gmtime_r(&seconds, &tm) == NULL) {
        snprintf(buf, buf_len, "epoch-ns:%" PRIu64, epoch_ns);
        return;
    }
    snprintf(buf,
             buf_len,
             "%04d-%02d-%02dT%02d:%02d:%02d.%03" PRIu64 "Z",
             tm.tm_year + 1900,
             tm.tm_mon + 1,
             tm.tm_mday,
             tm.tm_hour,
             tm.tm_min,
             tm.tm_sec,
             millis);
}

static uint64_t
entry_expires_at(uint64_t seal_ts, uint64_t retention_window_ns)
{
    if (seal_ts == 0 || retention_window_ns == 0) {
        return 0;
    }
    uint64_t expires_at = seal_ts + retention_window_ns;
    return expires_at < seal_ts ? UINT64_MAX : expires_at;
}

static int
run_list(n00b_store_t *store, bool quarantined_only)
{
    auto count_r = n00b_store_catalog_all_entry_count(store);
    if (n00b_result_is_err(count_r)) {
        return print_store_err("catalog count", n00b_result_get_err(count_r));
    }
    uint64_t count = n00b_result_get(count_r);
    uint64_t retention_window_ns = N00B_STORE_DEFAULT_RETENTION_NS;
    uint64_t sealed      = 0;
    uint64_t quarantine  = 0;
    uint64_t failed_seal = 0;
    printf("catalog_entries=%" PRIu64 "\n", count);
    for (uint64_t i = 0; i < count; i++) {
        auto entry_r = n00b_store_catalog_all_entry_at(store, i);
        if (n00b_result_is_err(entry_r)) {
            return print_store_err("catalog entry", n00b_result_get_err(entry_r));
        }
        n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(entry_r);
        if (!n00b_option_is_set(opt)) {
            continue;
        }
        n00b_store_catalog_entry_t *entry = n00b_option_get(opt);
        auto id_r    = n00b_store_catalog_entry_get_shard_id(entry);
        auto gen_r   = n00b_store_catalog_entry_get_generation(entry);
        auto rec_r   = n00b_store_catalog_entry_get_record_count(entry);
        auto bytes_r = n00b_store_catalog_entry_get_byte_len(entry);
        auto path_r  = n00b_store_catalog_entry_get_object_path(entry);
        auto state_r = n00b_store_catalog_entry_get_state(entry);
        if (n00b_result_is_err(id_r) || n00b_result_is_err(gen_r)
            || n00b_result_is_err(rec_r) || n00b_result_is_err(bytes_r)
            || n00b_result_is_err(path_r) || n00b_result_is_err(state_r)) {
            return print_store_err("catalog entry fields", N00B_STORE_ERR_CORRUPT);
        }
        n00b_store_catalog_entry_state_t state = n00b_result_get(state_r);
        if (quarantined_only
            && state != N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED) {
            continue;
        }
        auto state_name_r = n00b_store_catalog_entry_state_name(state);
        if (n00b_result_is_err(state_name_r)) {
            return print_store_err("catalog entry state", n00b_result_get_err(state_name_r));
        }
        if (state == N00B_STORE_CATALOG_ENTRY_STATE_SEALED) {
            sealed++;
        } else if (state == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED) {
            quarantine++;
        } else if (state == N00B_STORE_CATALOG_ENTRY_STATE_FAILED_SEAL) {
            failed_seal++;
        }
        auto seal_r = n00b_store_catalog_entry_get_seal_ts(entry);
        if (n00b_result_is_err(seal_r)) {
            return print_store_err("catalog entry seal timestamp",
                                   n00b_result_get_err(seal_r));
        }
        uint64_t seal_ts = n00b_result_get(seal_r);
        uint64_t expires_at = entry_expires_at(seal_ts, retention_window_ns);
        char seal_time[64];
        char expires_time[64];
        format_epoch_ns(seal_ts, seal_time, sizeof(seal_time));
        format_epoch_ns(expires_at, expires_time, sizeof(expires_time));
        printf("shard=%" PRIu64 " generation=%" PRIu64
               " state=",
               n00b_result_get(id_r),
               n00b_result_get(gen_r));
        print_string(n00b_result_get(state_name_r));
        printf(" quarantined=%u records=%" PRIu64 " bytes=%" PRIu64
               " seal_time=%s expires_at=%s path=",
               state == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED ? 1 : 0,
               n00b_result_get(rec_r),
               n00b_result_get(bytes_r),
               seal_time,
               expires_time);
        print_string(n00b_result_get(path_r));
        printf("\n");
    }
    printf("sealed_shards=%" PRIu64 " quarantined_shards=%" PRIu64
           " failed_seal_jobs=%" PRIu64 "\n",
           sealed,
           quarantine,
           failed_seal);
    return 0;
}

static int
find_entry(n00b_store_t *store,
           uint64_t      shard_id,
           n00b_store_catalog_entry_t **out)
{
    auto find_r = n00b_store_catalog_find_any_shard(store, shard_id);
    if (n00b_result_is_err(find_r)) {
        return print_store_err("find shard", n00b_result_get_err(find_r));
    }
    n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(find_r);
    if (!n00b_option_is_set(opt)) {
        fprintf(stderr,
                "rocsctl: shard %" PRIu64 " is not in catalog\n",
                shard_id);
        return 1;
    }
    *out = n00b_option_get(opt);
    return 0;
}

static int
scan_store_err(uint64_t shard_id, const char *op, n00b_err_t err)
{
    printf("shard=%" PRIu64 " verify=fail op=%s code=%" PRId64 " label=",
           shard_id,
           op,
           (int64_t)err);
    print_string(n00b_store_err_str(err));
    printf("\n");
    return 1;
}

static int
scan_map_err(uint64_t shard_id, const char *op, n00b_err_t err)
{
    printf("shard=%" PRIu64 " verify=fail op=%s code=%" PRId64 " label=",
           shard_id,
           op,
           (int64_t)err);
    print_string(n00b_store_map_err_str(err));
    printf("\n");
    return 1;
}

static int
verify_entry(n00b_store_t              *store,
             n00b_store_catalog_entry_t *entry,
             uint64_t                   shard_id,
             bool                       verbose)
{
    auto object_r = n00b_store_catalog_entry_verify_object(store, entry);
    if (n00b_result_is_err(object_r)) {
        n00b_err_t err = n00b_result_get_err(object_r);
        if (verbose) {
            return print_store_err("catalog object", err);
        }
        return scan_store_err(shard_id, "catalog_object", err);
    }

    auto catalog_records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto catalog_seal_r    = n00b_store_catalog_entry_get_seal_ts(entry);
    if (n00b_result_is_err(catalog_records_r)
        || n00b_result_is_err(catalog_seal_r)) {
        n00b_err_t err = n00b_result_is_err(catalog_records_r)
                           ? n00b_result_get_err(catalog_records_r)
                           : n00b_result_get_err(catalog_seal_r);
        if (verbose) {
            return print_store_err("catalog metadata", err);
        }
        return scan_store_err(shard_id, "catalog_metadata", err);
    }

    uint64_t catalog_records = n00b_result_get(catalog_records_r);
    uint64_t catalog_seal    = n00b_result_get(catalog_seal_r);

    auto resident_r = n00b_store_resident_shard_acquire(store, entry);
    if (n00b_result_is_err(resident_r)) {
        n00b_err_t err = n00b_result_get_err(resident_r);
        if (verbose) {
            return print_store_err("resident acquire", err);
        }
        return scan_store_err(shard_id, "resident_acquire", err);
    }
    n00b_store_resident_shard_t *resident = n00b_result_get(resident_r);

    auto map_r = n00b_store_resident_shard_map(resident);
    if (n00b_result_is_err(map_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(map_r);
        if (verbose) {
            return print_store_err("resident map", err);
        }
        return scan_store_err(shard_id, "resident_map", err);
    }

    auto root_r = n00b_store_map_root(n00b_result_get(map_r));
    if (n00b_result_is_err(root_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(root_r);
        if (verbose) {
            return print_map_err("map root", err);
        }
        return scan_map_err(shard_id, "map_root", err);
    }
    n00b_store_map_shard_t *root = n00b_result_get(root_r);

    auto id_r      = n00b_store_map_shard_id(root);
    auto state_r   = n00b_store_map_shard_state(root);
    auto records_r = n00b_store_map_shard_records_len(root);
    auto seal_r    = n00b_store_map_shard_seal_ts(root);
    if (n00b_result_is_err(id_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(id_r);
        if (verbose) {
            return print_map_err("mapped shard id", err);
        }
        return scan_map_err(shard_id, "mapped_shard_id", err);
    }
    if (n00b_result_is_err(state_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(state_r);
        if (verbose) {
            return print_map_err("mapped shard state", err);
        }
        return scan_map_err(shard_id, "mapped_shard_state", err);
    }
    if (n00b_result_is_err(records_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(records_r);
        if (verbose) {
            return print_map_err("mapped record count", err);
        }
        return scan_map_err(shard_id, "mapped_record_count", err);
    }
    if (n00b_result_is_err(seal_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(seal_r);
        if (verbose) {
            return print_map_err("mapped seal timestamp", err);
        }
        return scan_map_err(shard_id, "mapped_seal_ts", err);
    }
    uint64_t records   = n00b_result_get(records_r);
    uint64_t mapped_id = n00b_result_get(id_r);
    n00b_shard_state_t mapped_state = n00b_result_get(state_r);
    uint64_t mapped_seal = n00b_result_get(seal_r);

    /*
     * Some pre-0.6 development shards were sealed before the current shard-root
     * prefix gained state/open_ts/seal_ts. They still have valid catalog entries
     * and valid shard objects, but the current direct-mapped accessors read the
     * old record_count as state and the old shard_id as seal_ts. Treat that as a
     * legacy sealed layout instead of quarantining every historical shard.
     */
    bool legacy_root_layout = mapped_id != shard_id
                           && mapped_seal == shard_id
                           && (uint64_t)(uint32_t)mapped_state
                                  == catalog_records;
    if (legacy_root_layout) {
        auto release_r = n00b_store_resident_shard_release(resident);
        if (n00b_result_is_err(release_r)) {
            n00b_err_t err = n00b_result_get_err(release_r);
            if (verbose) {
                return print_store_err("resident release", err);
            }
            return scan_store_err(shard_id, "resident_release", err);
        }
        if (verbose) {
            printf("shard=%" PRIu64 " records=%" PRIu64
                   " layout=legacy-root verify=ok\n",
                   shard_id,
                   catalog_records);
        }
        return 0;
    }

    bool current_scalars_ok = mapped_id == shard_id
                           && mapped_state == N00B_SHARD_STATE_SEALED
                           && records == catalog_records
                           && mapped_seal == catalog_seal;
    if (!current_scalars_ok) {
        (void)n00b_store_resident_shard_release(resident);
        if (verbose) {
            fprintf(stderr,
                    "rocsctl: mapped metadata mismatch "
                    "shard=%" PRIu64 " mapped_id=%" PRIu64
                    " mapped_state=%u mapped_records=%" PRIu64
                    " mapped_seal=%" PRIu64
                    " catalog_records=%" PRIu64
                    " catalog_seal=%" PRIu64 "\n",
                    shard_id,
                    mapped_id,
                    (unsigned)mapped_state,
                    records,
                    mapped_seal,
                    catalog_records,
                    catalog_seal);
            return print_store_err("mapped metadata mismatch",
                                   N00B_STORE_ERR_CORRUPT);
        }
        return scan_store_err(shard_id,
                              "mapped_metadata_mismatch",
                              N00B_STORE_ERR_CORRUPT);
    }

    auto list_r = n00b_store_map_shard_records(root);
    if (n00b_result_is_err(list_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(list_r);
        if (verbose) {
            return print_map_err("mapped records list", err);
        }
        return scan_map_err(shard_id, "mapped_records_list", err);
    }

    n00b_store_map_list_t *records_list = n00b_result_get(list_r);
    auto list_len_r = n00b_store_map_list_len(records_list);
    if (n00b_result_is_err(list_len_r)) {
        (void)n00b_store_resident_shard_release(resident);
        n00b_err_t err = n00b_result_get_err(list_len_r);
        if (verbose) {
            return print_map_err("mapped records length", err);
        }
        return scan_map_err(shard_id, "mapped_records_len", err);
    }

    uint64_t list_len = n00b_result_get(list_len_r);
    if (list_len != catalog_records) {
        (void)n00b_store_resident_shard_release(resident);
        if (verbose) {
            fprintf(stderr,
                    "rocsctl: mapped record list mismatch "
                    "shard=%" PRIu64 " mapped_list_len=%" PRIu64
                    " catalog_records=%" PRIu64 "\n",
                    shard_id,
                    list_len,
                    catalog_records);
            return print_store_err("mapped record list mismatch",
                                   N00B_STORE_ERR_CORRUPT);
        }
        return scan_store_err(shard_id,
                              "mapped_records_len_mismatch",
                              N00B_STORE_ERR_CORRUPT);
    }

    auto release_r = n00b_store_resident_shard_release(resident);
    if (n00b_result_is_err(release_r)) {
        n00b_err_t err = n00b_result_get_err(release_r);
        if (verbose) {
            return print_store_err("resident release", err);
        }
        return scan_store_err(shard_id, "resident_release", err);
    }

    if (verbose) {
        printf("shard=%" PRIu64 " mapped_id=%" PRIu64
               " records=%" PRIu64 " verify=ok\n",
               shard_id,
               mapped_id,
               records);
    }
    return 0;
}

static int
run_verify(n00b_store_t *store, uint64_t shard_id)
{
    n00b_store_catalog_entry_t *entry = NULL;
    int rc = find_entry(store, shard_id, &entry);
    if (rc != 0) {
        return rc;
    }

    auto state_r = n00b_store_catalog_entry_get_state(entry);
    if (n00b_result_is_err(state_r)) {
        return print_store_err("catalog entry state", n00b_result_get_err(state_r));
    }
    if (n00b_result_get(state_r) != N00B_STORE_CATALOG_ENTRY_STATE_SEALED) {
        auto name_r = n00b_store_catalog_entry_state_name(n00b_result_get(state_r));
        fprintf(stderr,
                "rocsctl: shard %" PRIu64 " is not sealed; state=",
                shard_id);
        if (n00b_result_is_ok(name_r)) {
            print_string(n00b_result_get(name_r));
        } else {
            fprintf(stderr, "unknown");
        }
        fprintf(stderr, "\n");
        return 1;
    }

    return verify_entry(store, entry, shard_id, true);
}

static int
run_scan(n00b_store_t *store, bool quarantine)
{
    auto count_r = n00b_store_catalog_all_entry_count(store);
    if (n00b_result_is_err(count_r)) {
        return print_store_err("catalog count", n00b_result_get_err(count_r));
    }

    uint64_t count       = n00b_result_get(count_r);
    uint64_t sealed      = 0;
    uint64_t bad         = 0;
    uint64_t quarantined = 0;
    for (uint64_t i = 0; i < count; i++) {
        auto entry_r = n00b_store_catalog_all_entry_at(store, i);
        if (n00b_result_is_err(entry_r)) {
            return print_store_err("catalog entry", n00b_result_get_err(entry_r));
        }
        n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(entry_r);
        if (!n00b_option_is_set(opt)) {
            continue;
        }
        n00b_store_catalog_entry_t *entry = n00b_option_get(opt);
        auto id_r = n00b_store_catalog_entry_get_shard_id(entry);
        auto state_r = n00b_store_catalog_entry_get_state(entry);
        if (n00b_result_is_err(id_r) || n00b_result_is_err(state_r)) {
            return print_store_err("catalog entry shard id",
                                   n00b_result_is_err(id_r)
                                       ? n00b_result_get_err(id_r)
                                       : n00b_result_get_err(state_r));
        }
        if (n00b_result_get(state_r)
            != N00B_STORE_CATALOG_ENTRY_STATE_SEALED) {
            continue;
        }
        sealed++;
        uint64_t shard_id = n00b_result_get(id_r);
        if (verify_entry(store, entry, shard_id, false) != 0) {
            bad++;
            if (quarantine) {
                auto quarantine_r = n00b_store_quarantine_shard(
                    store,
                    shard_id,
                    .reason = r"verify_failed");
                if (n00b_result_is_err(quarantine_r)) {
                    return print_store_err("quarantine shard",
                                           n00b_result_get_err(quarantine_r));
                }
                if (n00b_result_get(quarantine_r)) {
                    quarantined++;
                    printf("shard=%" PRIu64 " quarantined=1\n", shard_id);
                }
            }
        }
    }

    printf("sealed_shards=%" PRIu64 " bad_shards=%" PRIu64
           " quarantined_now=%" PRIu64 "\n",
           sealed,
           bad,
           quarantined);
    return bad == 0 ? 0 : 1;
}

static int
run_quarantine(n00b_store_t *store, uint64_t shard_id, bool yes)
{
    if (!yes) {
        fprintf(stderr,
                "rocsctl: refusing to quarantine shard %" PRIu64
                " without --yes\n",
                shard_id);
        return 1;
    }

    auto quarantine_r = n00b_store_quarantine_shard(store,
                                                    shard_id,
                                                    .reason = r"operator");
    if (n00b_result_is_err(quarantine_r)) {
        return print_store_err("quarantine shard",
                               n00b_result_get_err(quarantine_r));
    }
    if (!n00b_result_get(quarantine_r)) {
        fprintf(stderr,
                "rocsctl: shard %" PRIu64 " was not quarantined\n",
                shard_id);
        return 1;
    }
    printf("shard=%" PRIu64 " quarantined=1\n", shard_id);
    return 0;
}

static int
run_purge_quarantined(n00b_store_t *store, bool yes)
{
    if (!yes) {
        fprintf(stderr,
                "rocsctl: refusing to purge quarantined shards without --yes\n");
        return 1;
    }

    auto count_r = n00b_store_catalog_all_entry_count(store);
    if (n00b_result_is_err(count_r)) {
        return print_store_err("catalog count", n00b_result_get_err(count_r));
    }

    n00b_list_t(uint64_t) ids = n00b_list_new_private(uint64_t);
    n00b_list_t(n00b_string_t *) paths = n00b_list_new_private(n00b_string_t *);
    uint64_t count = n00b_result_get(count_r);
    for (uint64_t i = 0; i < count; i++) {
        auto entry_r = n00b_store_catalog_all_entry_at(store, i);
        if (n00b_result_is_err(entry_r)) {
            return print_store_err("catalog entry", n00b_result_get_err(entry_r));
        }
        n00b_option_t(n00b_store_catalog_entry_t *) opt = n00b_result_get(entry_r);
        if (!n00b_option_is_set(opt)) {
            continue;
        }
        n00b_store_catalog_entry_t *entry = n00b_option_get(opt);
        auto state_r = n00b_store_catalog_entry_get_state(entry);
        auto id_r = n00b_store_catalog_entry_get_shard_id(entry);
        auto path_r = n00b_store_catalog_entry_get_object_path(entry);
        if (n00b_result_is_err(state_r) || n00b_result_is_err(id_r)
            || n00b_result_is_err(path_r)) {
            return print_store_err("catalog entry fields", N00B_STORE_ERR_CORRUPT);
        }
        if (n00b_result_get(state_r)
            == N00B_STORE_CATALOG_ENTRY_STATE_QUARANTINED) {
            n00b_list_push(ids, n00b_result_get(id_r));
            n00b_string_t *path = n00b_result_get(path_r);
            n00b_list_push(paths,
                           n00b_string_from_raw(path->data,
                                                (int64_t)path->u8_bytes));
        }
    }

    uint64_t purged = 0;
    size_t len = n00b_list_len(ids);
    for (size_t i = 0; i < len; i++) {
        uint64_t shard_id = n00b_list_get(ids, i);
        auto drop_r = n00b_store_drop_sealed_shard(
            store,
            shard_id,
            .drop_reason = r"purge_quarantined");
        if (n00b_result_is_err(drop_r)) {
            return print_store_err("purge quarantined shard",
                                   n00b_result_get_err(drop_r));
        }
        if (n00b_result_get(drop_r)) {
            purged++;
            printf("shard=%" PRIu64 " purged=1 path=", shard_id);
            print_string(n00b_list_get(paths, i));
            printf("\n");
        }
    }
    printf("purged_quarantined_shards=%" PRIu64 "\n", purged);
    return 0;
}

static int
run_drop(n00b_store_t *store, uint64_t shard_id, bool yes)
{
    if (!yes) {
        fprintf(stderr,
                "rocsctl: refusing to drop shard %" PRIu64
                " without --yes\n",
                shard_id);
        return 1;
    }

    n00b_store_catalog_entry_t *entry = NULL;
    int rc = find_entry(store, shard_id, &entry);
    if (rc != 0) {
        return rc;
    }
    (void)entry;

    auto drop_r = n00b_store_drop_sealed_shard(store,
                                               shard_id,
                                               .drop_reason = r"operator");
    if (n00b_result_is_err(drop_r)) {
        return print_store_err("drop shard", n00b_result_get_err(drop_r));
    }
    if (!n00b_result_get(drop_r)) {
        fprintf(stderr,
                "rocsctl: shard %" PRIu64 " was not dropped\n",
                shard_id);
        return 1;
    }
    printf("shard=%" PRIu64 " dropped=1\n", shard_id);
    return 0;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    rocs_shards_args_t args = {0};
    if (!parse_args(argc, argv, &args)) {
        usage();
        return 2;
    }

    auto store_r = open_wax_store(args.store_root);
    if (n00b_result_is_err(store_r)) {
        return print_store_err("open store", n00b_result_get_err(store_r));
    }
    n00b_store_t *store = n00b_result_get(store_r);

    int rc = 0;
    switch (args.cmd) {
    case ROCS_SHARDS_CMD_LIST:
        rc = run_list(store, args.list_quarantined);
        break;
    case ROCS_SHARDS_CMD_VERIFY:
        rc = run_verify(store, args.shard_id);
        break;
    case ROCS_SHARDS_CMD_SCAN:
        rc = run_scan(store, args.quarantine);
        break;
    case ROCS_SHARDS_CMD_QUARANTINE:
        rc = run_quarantine(store, args.shard_id, args.yes);
        break;
    case ROCS_SHARDS_CMD_PURGE_QUARANTINED:
        rc = run_purge_quarantined(store, args.yes);
        break;
    case ROCS_SHARDS_CMD_DROP:
        rc = run_drop(store, args.shard_id, args.yes);
        break;
    case ROCS_SHARDS_CMD_NONE:
        usage();
        rc = 2;
        break;
    }

    auto close_r = n00b_store_close(store);
    if (rc == 0 && n00b_result_is_err(close_r)) {
        return print_store_err("close store", n00b_result_get_err(close_r));
    }
    return rc;
}
