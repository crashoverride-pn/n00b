#include "rocs/service.h"

#include "core/buffer.h"
#include "core/env.h"
#include "core/file.h"
#include "internal/rocs/store.h"
#include "text/strings/string_convert.h"
#include "text/strings/string_ops.h"

struct n00b_rocs_service_config_t {
    n00b_store_config_t *store_config;
    n00b_string_t       *http_addr;
    bool                 read_only;
    n00b_allocator_t    *allocator;
};

static bool
rocs_service_string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static n00b_string_t *
rocs_service_string_copy(n00b_string_t *s, n00b_allocator_t *allocator)
{
    if (s == nullptr) {
        return nullptr;
    }
    return n00b_string_from_raw(s->data,
                                (int64_t)s->u8_bytes,
                                .allocator = allocator);
}

static n00b_string_t *
rocs_service_env_key(n00b_string_t    *prefix,
                     n00b_string_t    *key,
                     n00b_allocator_t *allocator)
{
    if (rocs_service_string_empty(prefix)) {
        return key;
    }
    return n00b_unicode_str_cat(prefix, key, .allocator = allocator);
}

static n00b_string_t *
rocs_service_env(n00b_string_t    *prefix,
                 n00b_string_t    *key,
                 n00b_allocator_t *allocator)
{
    return n00b_getenv(rocs_service_env_key(prefix, key, allocator));
}

static n00b_option_t(uint64_t)
rocs_service_parse_cgroup_u64(n00b_buffer_t *buf)
{
    if (buf == nullptr || buf->data == nullptr) {
        return n00b_option_none(uint64_t);
    }

    uint64_t value = 0;
    bool     saw   = false;
    size_t   len   = n00b_buffer_len(buf);
    uint8_t *data  = (uint8_t *)buf->data;

    for (size_t i = 0; i < len; i++) {
        uint8_t ch = data[i];
        if (ch >= '0' && ch <= '9') {
            uint64_t digit = (uint64_t)(ch - '0');
            if (value > (UINT64_MAX - digit) / 10ull) {
                return n00b_option_none(uint64_t);
            }
            value = value * 10ull + digit;
            saw   = true;
            continue;
        }
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            if (saw) {
                break;
            }
            continue;
        }
        return n00b_option_none(uint64_t);
    }

    if (!saw || value == 0 || value == UINT64_MAX) {
        return n00b_option_none(uint64_t);
    }
    return n00b_option_set(uint64_t, value);
}

static n00b_option_t(uint64_t)
rocs_service_read_cgroup_u64(n00b_string_t *path)
{
    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(open_r)) {
        return n00b_option_none(uint64_t);
    }

    n00b_file_t *file   = n00b_result_get(open_r);
    auto         read_r = n00b_file_read(file, 64);
    (void)n00b_file_close_result(file);
    if (n00b_result_is_err(read_r)) {
        return n00b_option_none(uint64_t);
    }

    return rocs_service_parse_cgroup_u64(n00b_result_get(read_r));
}

n00b_option_t(uint64_t)
rocs_store_cgroup_memory_limit(void)
{
    n00b_string_t *paths[] = {
        r"/sys/fs/cgroup/memory.max",
        r"/sys/fs/cgroup/memory/memory.limit_in_bytes",
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        n00b_option_t(uint64_t) opt = rocs_service_read_cgroup_u64(paths[i]);
        if (n00b_option_is_set(opt)) {
            return opt;
        }
    }

    return n00b_option_none(uint64_t);
}

n00b_result_t(n00b_rocs_service_config_t *)
n00b_rocs_service_config_from_env() _kargs
{
    n00b_string_t    *prefix    = nullptr;
    n00b_allocator_t *allocator = nullptr;
}
{
    auto store_r = n00b_store_config_from_env(.prefix    = prefix,
                                              .allocator = allocator);
    if (n00b_result_is_err(store_r)) {
        return n00b_result_err(n00b_rocs_service_config_t *,
                               n00b_result_get_err(store_r));
    }

    n00b_rocs_service_config_t *config = n00b_alloc_with_opts(
        n00b_rocs_service_config_t,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
        });
    config->store_config = n00b_result_get(store_r);
    config->allocator    = allocator;
    config->http_addr    = rocs_service_string_copy(r"127.0.0.1:8080",
                                                    allocator);

    n00b_string_t *http_addr = rocs_service_env(prefix,
                                                r"ROCS_HTTP_ADDR",
                                                allocator);
    if (http_addr != nullptr) {
        if (rocs_service_string_empty(http_addr)) {
            return n00b_result_err(n00b_rocs_service_config_t *,
                                   N00B_STORE_ERR_CONFIG);
        }
        config->http_addr = rocs_service_string_copy(http_addr, allocator);
    }

    auto read_only_r = n00b_store_config_get_read_only(config->store_config);
    if (n00b_result_is_err(read_only_r)) {
        return n00b_result_err(n00b_rocs_service_config_t *,
                               n00b_result_get_err(read_only_r));
    }
    config->read_only = n00b_result_get(read_only_r);

    return n00b_result_ok(n00b_rocs_service_config_t *, config);
}

n00b_result_t(n00b_store_config_t *)
n00b_rocs_service_config_get_store_config(n00b_rocs_service_config_t *config)
{
    if (config == nullptr || config->store_config == nullptr) {
        return n00b_result_err(n00b_store_config_t *, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(n00b_store_config_t *, config->store_config);
}

n00b_result_t(n00b_option_t(n00b_string_t *))
n00b_rocs_service_config_get_http_addr(n00b_rocs_service_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(n00b_option_t(n00b_string_t *),
                               N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(
        n00b_option_t(n00b_string_t *),
        n00b_option_from_nullable(n00b_string_t *, config->http_addr));
}

n00b_result_t(bool)
n00b_rocs_service_config_get_read_only(n00b_rocs_service_config_t *config)
{
    if (config == nullptr) {
        return n00b_result_err(bool, N00B_STORE_ERR_ARG);
    }
    return n00b_result_ok(bool, config->read_only);
}
