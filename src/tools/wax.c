#include "n00b.h"
#include "conduit/print.h"
#include "core/file.h"
#include "core/runtime.h"
#include "core/string.h"
#include "net/http/http_client.h"
#include "parsers/toml.h"
#include "slay/commander.h"
#include "text/strings/string_ops.h"
#include "util/errno_str.h"
#include "util/parse_num.h"
#include "util/path.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    n00b_string_t *server_url;
    n00b_string_t *http_addr;
    n00b_string_t *cache_dir;
    n00b_string_t *state_dir;
    n00b_string_t *pid_file;
    n00b_string_t *log_file;
    n00b_string_t *subscriber_pid_file;
    n00b_string_t *subscriber_log_file;
    n00b_string_t *checkpoint;
    n00b_string_t *sync_log_file;
    n00b_string_t *service_bin;
    n00b_string_t *cache_bin;
    n00b_string_t *gateway_socket;
    n00b_string_t *support_dir;
    n00b_string_t *store_name;
} wax_config_t;

static void
wax_usage(void)
{
    n00b_eprintf(
        "usage:\n"
        "  wax status\n"
        "  wax start\n"
        "  wax stop\n"
        "  wax ingest FILE [--checkpoint PATH]\n"
        "  wax sync [PATH]\n"
        "  wax search [TERM] [--regex REGEX] "
        "[--field-regex FIELD=REGEX] [--kind KIND] "
        "[--format text|table|jsonl]\n"
        "\n"
        "common options:\n"
        "  --config PATH       optional TOML config file\n"
        "  --server-url URL    rocs HTTP service URL "
        "(default http://127.0.0.1:8080)\n"
        "  --http-addr ADDR    daemon listen addr when wax starts it\n"
        "  --cache-dir PATH    rocs cache dir\n"
        "  --state-dir PATH    wax state dir\n"
        "  --service-bin PATH  n00b-rocs-service binary\n"
        "  --cache-bin PATH    n00b-rocs-wax-cache binary\n"
        "  --gateway-socket P  wax gateway AF_UNIX socket\n"
        "  --support-dir PATH  Crayon support dir for sync\n"
        "\n"
        "wax search queries the local cache and opportunistically starts the "
        "local rocs daemon. wax sync starts the daemon and tries to keep the "
        "gateway subscriber running. Config defaults to\n"
        "$XDG_CONFIG_HOME/n00b/wax.toml when that file exists.\n");
}

static bool
wax_streq(n00b_string_t *s, const char *lit)
{
    size_t len = strlen(lit);

    return s != nullptr && s->u8_bytes == len && memcmp(s->data, lit, len) == 0;
}

static bool
wax_has_slash(n00b_string_t *s)
{
    return s != nullptr && strchr((char *)s->data, '/') != nullptr;
}

static bool
wax_has_prefix(n00b_string_t *s, const char *prefix)
{
    size_t len = strlen(prefix);

    return s != nullptr && s->u8_bytes >= len
        && memcmp(s->data, prefix, len) == 0;
}

static bool
wax_has_suffix(n00b_string_t *s, const char *suffix)
{
    size_t len = strlen(suffix);

    return s != nullptr && s->u8_bytes >= len
        && memcmp(s->data + s->u8_bytes - len, suffix, len) == 0;
}

static n00b_string_t *
wax_join(n00b_string_t *a, n00b_string_t *b)
{
    return n00b_path_join_v(a, b);
}

static n00b_string_t *
wax_url_path(n00b_string_t *base, const char *path)
{
    if (base->u8_bytes > 0 && base->data[base->u8_bytes - 1] == '/') {
        return n00b_cformat("[|#|][|#|]",
                            base,
                            n00b_string_from_cstr(path + 1));
    }

    return n00b_cformat("[|#|][|#|]", base, n00b_string_from_cstr(path));
}

static n00b_string_t *
wax_sibling_bin(const char *argv0, const char *name)
{
    n00b_string_t *fallback = n00b_string_from_cstr(name);
    n00b_string_t *self     = n00b_string_from_cstr(argv0);

    for (int64_t i = self->u8_bytes - 1; i >= 0; --i) {
        if (self->data[i] != '/') {
            continue;
        }

        n00b_string_t *dir = n00b_unicode_str_slice_bytes(self, 0, i);
        n00b_string_t *bin = wax_join(dir, fallback);

        if (n00b_file_exists(bin)) {
            return bin;
        }

        break;
    }

    return fallback;
}

static wax_config_t
wax_config_default(const char *argv0)
{
    wax_config_t cfg = {
        .server_url  = r"http://127.0.0.1:8080",
        .http_addr   = r"127.0.0.1:8080",
        .cache_dir   = n00b_xdg_cache_path(r"n00b", r"wax", r"rocs"),
        .state_dir   = n00b_xdg_state_path(r"n00b", r"wax"),
        .service_bin = wax_sibling_bin(argv0, "n00b-rocs-service"),
        .cache_bin   = wax_sibling_bin(argv0, "n00b-rocs-wax-cache"),
        .gateway_socket =
            r"/Library/Application Support/Crayon/subscription.sock",
        .support_dir =
            r"/Library/Application Support/Crayon",
        .store_name  = r"wax",
    };

    cfg.pid_file            = wax_join(cfg.state_dir, r"service.pid");
    cfg.log_file            = wax_join(cfg.state_dir, r"service.log");
    cfg.subscriber_pid_file = wax_join(cfg.state_dir, r"subscriber.pid");
    cfg.subscriber_log_file = wax_join(cfg.state_dir, r"subscriber.log");
    cfg.checkpoint          = wax_join(cfg.state_dir, r"checkpoint.txt");
    cfg.sync_log_file       = wax_join(cfg.state_dir, r"sync.log");

    return cfg;
}

static n00b_string_t *
wax_default_config_path(void)
{
    return n00b_xdg_config_path(r"n00b", r"wax.toml");
}

static n00b_string_t *
wax_toml_string(n00b_toml_node_t *root, const char *key)
{
    n00b_option_t(n00b_toml_node_t *) opt =
        n00b_toml_table_get_cstr(root, key);

    if (!n00b_option_is_set(opt)) {
        return nullptr;
    }

    n00b_toml_node_t *node = n00b_option_get(opt);

    if (n00b_toml_type(node) != N00B_TOML_STRING) {
        return nullptr;
    }

    return n00b_toml_as_string(node);
}

static void
wax_apply_pathish_toml(n00b_string_t **slot,
                       n00b_toml_node_t *root,
                       const char       *key,
                       bool              canonicalize)
{
    n00b_string_t *value = wax_toml_string(root, key);

    if (value == nullptr) {
        return;
    }

    if (canonicalize && value->u8_bytes > 0 && value->data[0] != '/') {
        value = n00b_path_canonical(value, .resolve_symlinks = false);
    }

    *slot = value;
}

static bool
wax_load_config(wax_config_t *cfg, n00b_string_t *path, bool explicit_path)
{
    if (!n00b_file_exists(path)) {
        if (explicit_path) {
            n00b_eprintf("wax: config file does not exist: «#»", path);
            return false;
        }

        return true;
    }

    auto parsed_r = n00b_toml_parse_file(path);

    if (n00b_result_is_err(parsed_r)) {
        n00b_eprintf("wax: could not parse config file: «#»: «#»",
                     path,
                     n00b_toml_last_error());
        return false;
    }

    n00b_toml_node_t *root = n00b_result_get(parsed_r);

    if (root == nullptr || n00b_toml_type(root) != N00B_TOML_TABLE) {
        n00b_eprintf("wax: config file root is not a TOML table: «#»", path);
        return false;
    }

    n00b_string_t *state_dir = wax_toml_string(root, "state_dir");

    if (state_dir != nullptr) {
        if (state_dir->u8_bytes > 0 && state_dir->data[0] != '/') {
            state_dir = n00b_path_canonical(state_dir, .resolve_symlinks = false);
        }

        cfg->state_dir           = state_dir;
        cfg->pid_file            = wax_join(cfg->state_dir, r"service.pid");
        cfg->log_file            = wax_join(cfg->state_dir, r"service.log");
        cfg->subscriber_pid_file = wax_join(cfg->state_dir, r"subscriber.pid");
        cfg->subscriber_log_file = wax_join(cfg->state_dir, r"subscriber.log");
        cfg->checkpoint          = wax_join(cfg->state_dir, r"checkpoint.txt");
        cfg->sync_log_file       = wax_join(cfg->state_dir, r"sync.log");
    }

    wax_apply_pathish_toml(&cfg->server_url, root, "server_url", false);
    wax_apply_pathish_toml(&cfg->http_addr, root, "http_addr", false);
    wax_apply_pathish_toml(&cfg->cache_dir, root, "cache_dir", true);
    wax_apply_pathish_toml(&cfg->pid_file, root, "pid_file", true);
    wax_apply_pathish_toml(&cfg->log_file, root, "log_file", true);
    wax_apply_pathish_toml(&cfg->subscriber_pid_file,
                           root,
                           "subscriber_pid_file",
                           true);
    wax_apply_pathish_toml(&cfg->subscriber_log_file,
                           root,
                           "subscriber_log_file",
                           true);
    wax_apply_pathish_toml(&cfg->checkpoint, root, "checkpoint", true);
    wax_apply_pathish_toml(&cfg->sync_log_file, root, "sync_log_file", true);
    wax_apply_pathish_toml(&cfg->service_bin, root, "service_bin", false);
    wax_apply_pathish_toml(&cfg->cache_bin, root, "cache_bin", false);
    wax_apply_pathish_toml(&cfg->gateway_socket, root, "gateway_socket", true);
    wax_apply_pathish_toml(&cfg->support_dir, root, "support_dir", true);
    wax_apply_pathish_toml(&cfg->store_name, root, "store_name", false);

    return true;
}

static n00b_string_t *
wax_flag_str(n00b_cmdr_result_t *r, const char *name)
{
    n00b_string_t *flag = n00b_string_from_cstr(name);

    if (!n00b_cmdr_flag_present(r, flag)) {
        return nullptr;
    }

    return n00b_cmdr_flag_str(r, flag);
}

static void
wax_apply_common_flags(wax_config_t *cfg, n00b_cmdr_result_t *r)
{
    n00b_string_t *value;

    value = wax_flag_str(r, "--server-url");
    if (value != nullptr) {
        cfg->server_url = value;
    }

    value = wax_flag_str(r, "--http-addr");
    if (value != nullptr) {
        cfg->http_addr = value;
    }

    value = wax_flag_str(r, "--cache-dir");
    if (value != nullptr) {
        if (value->u8_bytes > 0 && value->data[0] != '/') {
            value = n00b_path_canonical(value, .resolve_symlinks = false);
        }
        cfg->cache_dir = value;
    }

    value = wax_flag_str(r, "--state-dir");
    if (value != nullptr) {
        if (value->u8_bytes > 0 && value->data[0] != '/') {
            value = n00b_path_canonical(value, .resolve_symlinks = false);
        }
        cfg->state_dir           = value;
        cfg->pid_file            = wax_join(cfg->state_dir, r"service.pid");
        cfg->log_file            = wax_join(cfg->state_dir, r"service.log");
        cfg->subscriber_pid_file = wax_join(cfg->state_dir, r"subscriber.pid");
        cfg->subscriber_log_file = wax_join(cfg->state_dir, r"subscriber.log");
        cfg->checkpoint          = wax_join(cfg->state_dir, r"checkpoint.txt");
        cfg->sync_log_file       = wax_join(cfg->state_dir, r"sync.log");
    }

    value = wax_flag_str(r, "--service-bin");
    if (value != nullptr) {
        cfg->service_bin = value;
    }

    value = wax_flag_str(r, "--cache-bin");
    if (value != nullptr) {
        cfg->cache_bin = value;
    }

    value = wax_flag_str(r, "--gateway-socket");
    if (value != nullptr) {
        if (value->u8_bytes > 0 && value->data[0] != '/') {
            value = n00b_path_canonical(value, .resolve_symlinks = false);
        }
        cfg->gateway_socket = value;
    }

    value = wax_flag_str(r, "--support-dir");
    if (value != nullptr) {
        if (value->u8_bytes > 0 && value->data[0] != '/') {
            value = n00b_path_canonical(value, .resolve_symlinks = false);
        }
        cfg->support_dir = value;
    }
}

static bool
wax_write_text_file(n00b_string_t *path, n00b_string_t *text)
{
    n00b_result_t(n00b_file_t *) open_r = n00b_file_open(path,
                                                         .mode = N00B_FILE_W,
                                                         .kind = N00B_FILE_KIND_STREAM);

    if (n00b_result_is_err(open_r)) {
        return false;
    }

    n00b_file_t *file = n00b_result_get(open_r);
    n00b_result_t(size_t) write_r = n00b_file_write(file,
                                                    text->data,
                                                    text->u8_bytes);
    n00b_result_t(bool) close_r = n00b_file_close_result(file);

    return n00b_result_is_ok(write_r) && n00b_result_is_ok(close_r);
}

static n00b_string_t *
wax_read_text_file(n00b_string_t *path)
{
    n00b_result_t(n00b_file_t *) open_r = n00b_file_open(path,
                                                         .kind = N00B_FILE_KIND_MMAP);

    if (n00b_result_is_err(open_r)) {
        return nullptr;
    }

    n00b_file_t *file = n00b_result_get(open_r);
    n00b_result_t(n00b_buffer_t *) buf_r = n00b_file_as_buffer(file);
    n00b_result_t(bool) close_r = n00b_file_close_result(file);

    if (n00b_result_is_err(buf_r) || n00b_result_is_err(close_r)) {
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_result_get(buf_r);

    return n00b_string_from_raw((char *)buf->data, buf->byte_len);
}

static bool
wax_parse_pid(n00b_string_t *text, pid_t *out)
{
    if (text == nullptr) {
        return false;
    }

    auto parsed_r = n00b_parse_i64(text);

    if (n00b_result_is_err(parsed_r)) {
        return false;
    }

    int64_t pid = n00b_result_get(parsed_r);

    if (pid <= 0 || pid > INT_MAX) {
        return false;
    }

    *out = (pid_t)pid;

    return true;
}

static bool
wax_pid_alive(pid_t pid)
{
    if (pid <= 0) {
        return false;
    }

    if (kill(pid, 0) == 0) {
        return true;
    }

    return errno == EPERM;
}

static bool
wax_service_ready(n00b_string_t *server_url)
{
    n00b_string_t *ready_url = wax_url_path(server_url, "/healthz/ready");
    n00b_result_t(n00b_http_response_t *) resp_r
        = n00b_http_request_sync(ready_url, .allow_plain_http = true);

    if (n00b_result_is_err(resp_r)) {
        return false;
    }

    n00b_http_response_t *resp = n00b_result_get(resp_r);
    int                   code = n00b_http_response_status(resp);

    return code >= 200 && code < 300;
}

static bool
wax_ensure_dirs(wax_config_t *cfg)
{
    auto state_mkdir_r = n00b_path_mkdir_p(cfg->state_dir);

    if (n00b_result_is_err(state_mkdir_r)) {
        n00b_eprintf("wax: could not create state dir: «#»", cfg->state_dir);
        return false;
    }

    auto cache_mkdir_r = n00b_path_mkdir_p(cfg->cache_dir);

    if (n00b_result_is_err(cache_mkdir_r)) {
        n00b_eprintf("wax: could not create cache dir: «#»", cfg->cache_dir);
        return false;
    }

    return true;
}

static void
wax_set_rocs_env(wax_config_t *cfg, bool read_only)
{
    setenv("ROCS_PROFILE", "service_local", 1);
    setenv("ROCS_SCHEMA", "wax.normalized.v1", 1);
    setenv("ROCS_READ_ONLY", read_only ? "true" : "false", 1);
    setenv("ROCS_WRITER_MODE", read_only ? "read_replica" : "single", 1);
    setenv("ROCS_NAME", (char *)cfg->store_name->data, 1);
    setenv("ROCS_HTTP_ADDR", (char *)cfg->http_addr->data, 1);
    setenv("ROCS_CACHE_DIR", (char *)cfg->cache_dir->data, 1);
}

static bool
wax_wait_pid_dead(pid_t pid, int attempts)
{
    for (int i = 0; i < attempts; ++i) {
        if (!wax_pid_alive(pid)) {
            return true;
        }
        usleep(100000);
    }
    return !wax_pid_alive(pid);
}

static bool
wax_terminate_managed_pid(pid_t pid)
{
    if (pid <= 0 || !wax_pid_alive(pid)) {
        return true;
    }

    if (kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        return false;
    }
    if (wax_wait_pid_dead(pid, 50)) {
        return true;
    }

    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        return false;
    }
    return wax_wait_pid_dead(pid, 50);
}

[[noreturn]] static void
wax_exec_service_child(wax_config_t *cfg)
{
    (void)setsid();

    int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        (void)dup2(null_fd, STDIN_FILENO);
        close(null_fd);
    }

    int log_fd = open((char *)cfg->log_file->data,
                      O_CREAT | O_WRONLY | O_APPEND,
                      0644);
    if (log_fd >= 0) {
        (void)dup2(log_fd, STDOUT_FILENO);
        (void)dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }

    wax_set_rocs_env(cfg, false);

    char *argv[] = {
        (char *)cfg->service_bin->data,
        "--serve",
        nullptr,
    };

    if (wax_has_slash(cfg->service_bin)) {
        execv((char *)cfg->service_bin->data, argv);
    }
    else {
        execvp((char *)cfg->service_bin->data, argv);
    }

    _exit(127);
}

static pid_t
wax_spawn_service(wax_config_t *cfg)
{
    pid_t child = fork();

    if (child == 0) {
        wax_exec_service_child(cfg);
    }

    return child;
}

static int
wax_start_service(wax_config_t *cfg, bool verbose)
{
    if (wax_service_ready(cfg->server_url)) {
        if (verbose) {
            n00b_printf("wax: daemon already ready at «#»", cfg->server_url);
        }

        return 0;
    }

    if (!wax_ensure_dirs(cfg)) {
        return 2;
    }

    n00b_string_t *old_pid_text = wax_read_text_file(cfg->pid_file);
    pid_t          old_pid;
    if (wax_parse_pid(old_pid_text, &old_pid) && wax_pid_alive(old_pid)) {
        if (verbose) {
            n00b_eprintf("wax: replacing unready daemon pid=«#»",
                         (int64_t)old_pid);
        }
        if (!wax_terminate_managed_pid(old_pid)) {
            n00b_eprintf("wax: unready daemon pid=«#» did not stop",
                         (int64_t)old_pid);
            return 2;
        }
        n00b_file_unlink(cfg->pid_file, .ignore_missing = true);
    }

    pid_t child = wax_spawn_service(cfg);

    if (child < 0) {
        n00b_eprintf("wax: fork failed: «#»", n00b_errno_str(errno));
        return 2;
    }

    n00b_string_t *pid_text = n00b_cformat("[|#|]\n", (int64_t)child);

    if (!wax_write_text_file(cfg->pid_file, pid_text)) {
        (void)wax_terminate_managed_pid(child);
        n00b_eprintf("wax: could not write pid file: «#»", cfg->pid_file);
        return 2;
    }

    for (int i = 0; i < 50; ++i) {
        if (wax_service_ready(cfg->server_url)) {
            if (verbose) {
                n00b_printf("wax: started daemon pid=[|#|] at [|#|]",
                            (int64_t)child,
                            cfg->server_url,
                            .fd = 1);
            }

            return 0;
        }

        if (!wax_pid_alive(child)) {
            break;
        }

        usleep(100000);
    }

    n00b_eprintf("wax: daemon did not become ready at «#»; log: «#»",
                 cfg->server_url,
                 cfg->log_file);

    return 2;
}

static void
wax_try_start_service(wax_config_t *cfg)
{
    if (!wax_ensure_dirs(cfg)) {
        return;
    }

    n00b_string_t *old_pid_text = wax_read_text_file(cfg->pid_file);
    pid_t          old_pid;
    if (wax_parse_pid(old_pid_text, &old_pid)) {
        if (wax_pid_alive(old_pid)) {
            return;
        }
        n00b_file_unlink(cfg->pid_file, .ignore_missing = true);
    }

    pid_t child = wax_spawn_service(cfg);
    if (child < 0) {
        return;
    }

    n00b_string_t *pid_text = n00b_cformat("[|#|]\n", (int64_t)child);
    if (!wax_write_text_file(cfg->pid_file, pid_text)) {
        (void)kill(child, SIGTERM);
    }
}

static int
wax_start_subscriber(wax_config_t *cfg, bool verbose)
{
    n00b_string_t *pid_text = wax_read_text_file(cfg->subscriber_pid_file);
    pid_t          pid;

    if (wax_parse_pid(pid_text, &pid)) {
        if (wax_pid_alive(pid)) {
            if (verbose) {
                n00b_printf(
                    "wax: subscriber already running pid=[|#|] socket=[|#|]",
                    (int64_t)pid,
                    cfg->gateway_socket,
                    .fd = 1);
            }
            return 0;
        }
        n00b_file_unlink(cfg->subscriber_pid_file, .ignore_missing = true);
    }

    if (!wax_service_ready(cfg->server_url)) {
        n00b_eprintf("wax: rocs daemon is not ready at «#»", cfg->server_url);
        return 2;
    }

    if (!wax_ensure_dirs(cfg)) {
        return 2;
    }

    pid_t child = fork();
    if (child < 0) {
        n00b_eprintf("wax: fork failed: «#»", n00b_errno_str(errno));
        return 2;
    }

    if (child == 0) {
        (void)setsid();

        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }

        int log_fd = open((char *)cfg->subscriber_log_file->data,
                          O_CREAT | O_WRONLY | O_APPEND,
                          0644);
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDOUT_FILENO);
            (void)dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        char *argv[] = {
            (char *)cfg->cache_bin->data,
            "--server-url",
            (char *)cfg->server_url->data,
            "--subscribe-gateway",
            (char *)cfg->gateway_socket->data,
            nullptr,
        };

        if (wax_has_slash(cfg->cache_bin)) {
            execv((char *)cfg->cache_bin->data, argv);
        }
        else {
            execvp((char *)cfg->cache_bin->data, argv);
        }

        _exit(127);
    }

    n00b_string_t *pid_out = n00b_cformat("[|#|]\n", (int64_t)child);
    if (!wax_write_text_file(cfg->subscriber_pid_file, pid_out)) {
        n00b_eprintf("wax: could not write subscriber pid file: «#»",
                     cfg->subscriber_pid_file);
        return 2;
    }

    for (int i = 0; i < 5; ++i) {
        if (!wax_pid_alive(child)) {
            n00b_eprintf("wax: subscriber exited immediately; log: «#»",
                         cfg->subscriber_log_file);
            return 2;
        }
        usleep(100000);
    }

    if (verbose) {
        n00b_printf("wax: started subscriber pid=[|#|] socket=[|#|]",
                    (int64_t)child,
                    cfg->gateway_socket,
                    .fd = 1);
    }

    return 0;
}

static void
wax_try_start_subscriber(wax_config_t *cfg)
{
    if (!n00b_file_exists(cfg->gateway_socket)) {
        return;
    }

    (void)wax_start_subscriber(cfg, false);
}

static int
wax_stop_service(wax_config_t *cfg)
{
    n00b_string_t *pid_text = wax_read_text_file(cfg->pid_file);
    pid_t          pid;

    if (!wax_parse_pid(pid_text, &pid)) {
        if (wax_service_ready(cfg->server_url)) {
            n00b_eprintf("wax: daemon is ready at «#», but no wax pid file exists",
                         cfg->server_url);
            return 2;
        }

        n00b_printf("wax: daemon is not running\n");
        return 0;
    }

    if (!wax_pid_alive(pid)) {
        n00b_file_unlink(cfg->pid_file, .ignore_missing = true);
        n00b_printf("wax: removed stale pid file «#»", cfg->pid_file);
        return 0;
    }

    if (kill(pid, SIGTERM) != 0) {
        n00b_eprintf("wax: could not stop daemon pid=«#»: «#»",
                     (int64_t)pid,
                     n00b_errno_str(errno));
        return 2;
    }

    for (int i = 0; i < 50; ++i) {
        if (!wax_pid_alive(pid)) {
            n00b_file_unlink(cfg->pid_file, .ignore_missing = true);
            n00b_printf("wax: stopped daemon pid=«#»", (int64_t)pid);
            return 0;
        }

        usleep(100000);
    }

    n00b_eprintf("wax: daemon pid=«#» did not stop within 5s",
                 (int64_t)pid);

    return 2;
}

static int
wax_stop_subscriber(wax_config_t *cfg)
{
    n00b_string_t *pid_text = wax_read_text_file(cfg->subscriber_pid_file);
    pid_t          pid;

    if (!wax_parse_pid(pid_text, &pid)) {
        n00b_printf("wax: subscriber is not running\n");
        return 0;
    }

    if (!wax_pid_alive(pid)) {
        n00b_file_unlink(cfg->subscriber_pid_file, .ignore_missing = true);
        n00b_printf("wax: removed stale subscriber pid file «#»",
                    cfg->subscriber_pid_file);
        return 0;
    }

    if (kill(pid, SIGTERM) != 0) {
        n00b_eprintf("wax: could not stop subscriber pid=«#»: «#»",
                     (int64_t)pid,
                     n00b_errno_str(errno));
        return 2;
    }

    for (int i = 0; i < 50; ++i) {
        if (!wax_pid_alive(pid)) {
            n00b_file_unlink(cfg->subscriber_pid_file, .ignore_missing = true);
            n00b_printf("wax: stopped subscriber pid=«#»", (int64_t)pid);
            return 0;
        }

        usleep(100000);
    }

    n00b_eprintf("wax: subscriber pid=«#» did not stop within 5s",
                 (int64_t)pid);
    return 2;
}

static int
wax_status(wax_config_t *cfg)
{
    pid_t          pid;
    n00b_string_t *pid_text = wax_read_text_file(cfg->pid_file);
    bool           has_pid  = wax_parse_pid(pid_text, &pid);
    bool           ready    = wax_service_ready(cfg->server_url);
    pid_t          sub_pid;
    n00b_string_t *sub_pid_text = wax_read_text_file(cfg->subscriber_pid_file);
    bool           has_sub_pid  = wax_parse_pid(sub_pid_text, &sub_pid);
    bool           sub_alive    = has_sub_pid && wax_pid_alive(sub_pid);

    if (ready) {
        if (has_pid && wax_pid_alive(pid)) {
            n00b_printf("wax: ready at [|#|] pid=[|#|]",
                        cfg->server_url,
                        (int64_t)pid,
                        .fd = 1);
        }
        else {
            n00b_printf("wax: ready at «#» (external daemon)",
                        cfg->server_url);
        }
    }
    else if (has_pid && wax_pid_alive(pid)) {
        n00b_printf(
            "wax: daemon pid=[|#|] is running but not ready at [|#|]; log: [|#|]",
            (int64_t)pid,
            cfg->server_url,
            cfg->log_file,
            .fd = 1);
    }
    else {
        n00b_printf("wax: daemon is not running at «#»", cfg->server_url);
    }

    if (sub_alive) {
        n00b_printf("wax: subscriber running pid=[|#|] socket=[|#|]",
                    (int64_t)sub_pid,
                    cfg->gateway_socket,
                    .fd = 1);
    }
    else if (has_sub_pid) {
        n00b_printf("wax: subscriber pid file is stale: «#»",
                    cfg->subscriber_pid_file);
    }
    else {
        n00b_printf("wax: subscriber is not running for socket «#»",
                    cfg->gateway_socket);
    }

    return ready && sub_alive ? 0 : 1;
}

static void
wax_add_arg(char **argv, int *argc, n00b_string_t *arg)
{
    argv[*argc] = (char *)arg->data;
    *argc += 1;
}

static void
wax_add_carg(char **argv, int *argc, const char *arg)
{
    argv[*argc] = (char *)arg;
    *argc += 1;
}

static int
wax_exec_wait(char **argv)
{
    pid_t child = fork();

    if (child < 0) {
        n00b_eprintf("wax: fork failed: «#»", n00b_errno_str(errno));
        return 2;
    }

    if (child == 0) {
        execvp(argv[0], argv);
        n00b_eprintf("wax: could not exec «#»: «#»",
                     n00b_string_from_cstr(argv[0]),
                     n00b_errno_str(errno));
        _exit(127);
    }

    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            n00b_eprintf("wax: wait failed: «#»", n00b_errno_str(errno));
            return 2;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        n00b_eprintf("wax: command terminated by signal «#»",
                     (int64_t)WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }

    return 2;
}

static int
wax_exec_wait_logged(char **argv, n00b_string_t *log_file)
{
    pid_t child = fork();

    if (child < 0) {
        n00b_eprintf("wax: fork failed: «#»", n00b_errno_str(errno));
        return 2;
    }

    if (child == 0) {
        int log_fd = open((char *)log_file->data,
                          O_CREAT | O_WRONLY | O_APPEND,
                          0644);
        if (log_fd >= 0) {
            (void)dup2(log_fd, STDOUT_FILENO);
            (void)dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }

        execvp(argv[0], argv);
        n00b_eprintf("wax: could not exec «#»: «#»",
                     n00b_string_from_cstr(argv[0]),
                     n00b_errno_str(errno));
        _exit(127);
    }

    int status = 0;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            n00b_eprintf("wax: wait failed: «#»", n00b_errno_str(errno));
            return 2;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        n00b_eprintf("wax: command terminated by signal «#»",
                     (int64_t)WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }

    return 2;
}

static void
wax_add_search_string_flag(char              **argv,
                           int               *argc,
                           n00b_cmdr_result_t *r,
                           const char        *name)
{
    n00b_string_t *value = wax_flag_str(r, name);

    if (value == nullptr) {
        return;
    }

    wax_add_carg(argv, argc, name);
    wax_add_arg(argv, argc, value);
}

static void
wax_add_search_int_flag(char              **argv,
                        int               *argc,
                        n00b_cmdr_result_t *r,
                        const char        *name)
{
    n00b_string_t *flag = n00b_string_from_cstr(name);

    if (!n00b_cmdr_flag_present(r, flag)) {
        return;
    }

    int64_t        value = n00b_cmdr_flag_int(r, flag);
    n00b_string_t *s     = n00b_cformat("[|#|]", value);

    wax_add_carg(argv, argc, name);
    wax_add_arg(argv, argc, s);
}

static int
wax_run_ingest(wax_config_t *cfg, n00b_cmdr_result_t *r)
{
    n00b_string_t *source     = n00b_cmdr_arg_str(r, 0);
    n00b_string_t *checkpoint = wax_flag_str(r, "--checkpoint");
    char          *argv[12];
    int            argc = 0;

    if (checkpoint == nullptr) {
        checkpoint = cfg->checkpoint;
    }

    wax_add_arg(argv, &argc, cfg->cache_bin);
    wax_add_carg(argv, &argc, "--server-url");
    wax_add_arg(argv, &argc, cfg->server_url);
    wax_add_carg(argv, &argc, "--run-fixture");
    wax_add_arg(argv, &argc, source);
    wax_add_arg(argv, &argc, checkpoint);
    argv[argc] = nullptr;

    return wax_exec_wait(argv);
}

static n00b_string_t *
wax_basename(n00b_string_t *path)
{
    if (path == nullptr || path->data == nullptr) {
        return r"";
    }

    size_t start = 0;
    for (size_t i = 0; i < path->u8_bytes; i++) {
        if (path->data[i] == '/') {
            start = i + 1;
        }
    }

    return n00b_string_from_raw(path->data + start,
                                (int64_t)(path->u8_bytes - start));
}

static bool
wax_is_stream_artifact(n00b_string_t *path)
{
    n00b_string_t *base = wax_basename(path);

    return wax_streq(base, "live-stream.json")
        || (wax_has_prefix(base, "live-stream.")
            && wax_has_suffix(base, ".json"));
}

static n00b_string_t *
wax_sync_checkpoint_path(wax_config_t *cfg, n00b_string_t *source)
{
    n00b_string_t *sync_dir = wax_join(cfg->state_dir, r"sync-checkpoints");
    auto           mkdir_r  = n00b_path_mkdir_p(sync_dir);

    if (n00b_result_is_err(mkdir_r)) {
        return nullptr;
    }

    n00b_string_t *base = wax_basename(source);
    n00b_string_t *name = n00b_cformat("[|#|].checkpoint", base);

    return wax_join(sync_dir, name);
}

static int
wax_run_sync_source(wax_config_t *cfg, n00b_string_t *source)
{
    n00b_string_t *checkpoint = wax_sync_checkpoint_path(cfg, source);
    if (checkpoint == nullptr) {
        n00b_eprintf("wax: could not create sync checkpoint path for «#»",
                     source);
        return 2;
    }

    char *argv[12];
    int   argc = 0;

    wax_add_arg(argv, &argc, cfg->cache_bin);
    wax_add_carg(argv, &argc, "--server-url");
    wax_add_arg(argv, &argc, cfg->server_url);
    wax_add_carg(argv, &argc, "--run-fixture");
    wax_add_arg(argv, &argc, source);
    wax_add_arg(argv, &argc, checkpoint);
    argv[argc] = nullptr;

    return wax_exec_wait(argv);
}

static int
wax_run_sync(wax_config_t *cfg, n00b_cmdr_result_t *r)
{
    n00b_string_t *source = cfg->support_dir;

    if (n00b_cmdr_arg_count(r) > 0) {
        source = n00b_cmdr_arg_str(r, 0);
        if (source != nullptr && source->u8_bytes > 0 && source->data[0] != '/') {
            source = n00b_path_canonical(source, .resolve_symlinks = false);
        }
    }

    if (source == nullptr || !n00b_path_exists(source)) {
        n00b_eprintf("wax: sync source does not exist: «#»",
                     source == nullptr ? r"" : source);
        return 2;
    }

    if (n00b_path_is_file(source)) {
        if (!wax_is_stream_artifact(source)) {
            n00b_eprintf("wax: sync file is not a live-stream JSON artifact: «#»",
                         source);
            return 2;
        }

        int rc = wax_run_sync_source(cfg, source);
        n00b_printf("wax: sync path=[|#|] files=1 ok=[|#|] failed=[|#|]",
                    source,
                    rc == 0 ? (int64_t)1 : (int64_t)0,
                    rc == 0 ? (int64_t)0 : (int64_t)1);
        return rc;
    }

    if (n00b_path_is_directory(source)) {
        int rc = wax_run_sync_source(cfg, source);
        n00b_printf("wax: sync path=[|#|] ok=[|#|] failed=[|#|]",
                    source,
                    rc == 0 ? (int64_t)1 : (int64_t)0,
                    rc == 0 ? (int64_t)0 : (int64_t)1);
        return rc;
    }

    n00b_eprintf("wax: sync source is not a regular file or directory: «#»",
                 source);
    return 2;
}

static int
wax_run_search(wax_config_t *cfg, n00b_cmdr_result_t *r)
{
    char *argv[64];
    int   argc = 0;

    wax_set_rocs_env(cfg, true);

    wax_add_arg(argv, &argc, cfg->cache_bin);
    wax_add_carg(argv, &argc, "--search");

    wax_add_search_string_flag(argv, &argc, r, "--kind");
    wax_add_search_string_flag(argv, &argc, r, "--class");
    wax_add_search_string_flag(argv, &argc, r, "--family");
    wax_add_search_string_flag(argv, &argc, r, "--event-id");
    wax_add_search_string_flag(argv, &argc, r, "--regex");
    wax_add_search_string_flag(argv, &argc, r, "--field-eq");
    wax_add_search_string_flag(argv, &argc, r, "--field-regex");
    wax_add_search_int_flag(argv, &argc, r, "--time-from");
    wax_add_search_int_flag(argv, &argc, r, "--time-to");
    wax_add_search_int_flag(argv, &argc, r, "--limit");
    wax_add_search_string_flag(argv, &argc, r, "--order");
    wax_add_search_string_flag(argv, &argc, r, "--format");

    if (n00b_cmdr_arg_count(r) > 0) {
        wax_add_arg(argv, &argc, n00b_cmdr_arg_str(r, 0));
    }

    argv[argc] = nullptr;

    return wax_exec_wait(argv);
}

static void
wax_add_common_flags(n00b_cmdr_t *cmdr, n00b_string_t *command)
{
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--config",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"optional TOML config file");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--server-url",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"rocs HTTP service URL");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--http-addr",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"daemon listen addr");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--cache-dir",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"rocs cache dir");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--state-dir",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"wax state dir");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--service-bin",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"n00b-rocs-service binary");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--cache-bin",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"n00b-rocs-wax-cache binary");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--gateway-socket",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"wax gateway AF_UNIX socket");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--support-dir",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"Crayon support dir for sync");
    n00b_cmdr_add_flag(cmdr,
                       command,
                       r"--help",
                       N00B_CMDR_TYPE_BOOL,
                       false,
                       r"show usage");
}

static n00b_cmdr_t *
wax_build_cmdr(void)
{
    n00b_cmdr_t *cmdr = n00b_cmdr_new();

    n00b_cmdr_set_name(cmdr, r"wax");
    wax_add_common_flags(cmdr, r"");

    n00b_cmdr_add_command(cmdr, r"status", r"show daemon status");
    wax_add_common_flags(cmdr, r"status");

    n00b_cmdr_add_command(cmdr, r"start", r"start daemon");
    wax_add_common_flags(cmdr, r"start");

    n00b_cmdr_add_command(cmdr, r"stop", r"stop daemon started by wax");
    wax_add_common_flags(cmdr, r"stop");

    n00b_cmdr_add_command(cmdr, r"ingest", r"ingest wax gateway events");
    wax_add_common_flags(cmdr, r"ingest");
    n00b_cmdr_add_positional(cmdr,
                             r"ingest",
                             r"file",
                             N00B_CMDR_TYPE_WORD,
                             1,
                             1);
    n00b_cmdr_add_flag(cmdr,
                       r"ingest",
                       r"--checkpoint",
                       N00B_CMDR_TYPE_WORD,
                       true,
                       r"checkpoint file");

    n00b_cmdr_add_command(cmdr, r"sync", r"sync Crayon stream artifacts");
    wax_add_common_flags(cmdr, r"sync");
    n00b_cmdr_add_positional(cmdr,
                             r"sync",
                             r"path",
                             N00B_CMDR_TYPE_WORD,
                             0,
                             1);

    n00b_cmdr_add_command(cmdr, r"search", r"search cached wax events");
    wax_add_common_flags(cmdr, r"search");
    n00b_cmdr_add_positional(cmdr,
                             r"search",
                             r"term",
                             N00B_CMDR_TYPE_WORD,
                             0,
                             1);

    n00b_cmdr_add_command(cmdr, r"query", r"alias for search");
    wax_add_common_flags(cmdr, r"query");
    n00b_cmdr_add_positional(cmdr,
                             r"query",
                             r"term",
                             N00B_CMDR_TYPE_WORD,
                             0,
                             1);

    for (int i = 0; i < 2; ++i) {
        n00b_string_t *cmd = i == 0 ? r"search" : r"query";

        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--kind",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"event kind filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--class",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"class filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--family",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"family filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--event-id",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"event id filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--regex",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"search_text regex filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--field-eq",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"field=value filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--field-regex",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"field=regex filter");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--time-from",
                           N00B_CMDR_TYPE_INT,
                           true,
                           r"minimum unix timestamp");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--time-to",
                           N00B_CMDR_TYPE_INT,
                           true,
                           r"maximum unix timestamp");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--limit",
                           N00B_CMDR_TYPE_INT,
                           true,
                           r"maximum rows");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--order",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"durable or ranked");
        n00b_cmdr_add_flag(cmdr,
                           cmd,
                           r"--format",
                           N00B_CMDR_TYPE_WORD,
                           true,
                           r"text, table, or jsonl");
    }

    n00b_cmdr_finalize(cmdr);

    return cmdr;
}

static bool
wax_print_parse_errors(n00b_cmdr_result_t *r)
{
    int64_t n = n00b_cmdr_error_count(r);

    for (int64_t i = 0; i < n; ++i) {
        n00b_eprintf("wax: «#»", n00b_cmdr_error_get(r, i));
    }

    return n != 0;
}

static bool
wax_is_command_arg(const char *arg)
{
    return strcmp(arg, "status") == 0 || strcmp(arg, "start") == 0
           || strcmp(arg, "stop") == 0 || strcmp(arg, "ingest") == 0
           || strcmp(arg, "sync") == 0 || strcmp(arg, "search") == 0
           || strcmp(arg, "query") == 0;
}

static bool
wax_is_leading_common_flag(const char *arg, bool *takes_value)
{
    if (strcmp(arg, "--help") == 0) {
        *takes_value = false;
        return true;
    }

    if (strcmp(arg, "--config") == 0 || strcmp(arg, "--server-url") == 0
        || strcmp(arg, "--http-addr") == 0 || strcmp(arg, "--cache-dir") == 0
        || strcmp(arg, "--state-dir") == 0
        || strcmp(arg, "--service-bin") == 0
        || strcmp(arg, "--cache-bin") == 0
        || strcmp(arg, "--gateway-socket") == 0
        || strcmp(arg, "--support-dir") == 0) {
        *takes_value = true;
        return true;
    }

    return false;
}

static const char **
wax_normalize_argv(int argc, char **argv, int *parse_argc)
{
    int tail_argc = argc > 0 ? argc - 1 : 0;

    *parse_argc = tail_argc;

    if (tail_argc <= 1) {
        return (const char **)(argv + 1);
    }

    const char **tail = (const char **)(argv + 1);
    int          i    = 0;

    while (i < tail_argc) {
        bool takes_value = false;

        if (!wax_is_leading_common_flag(tail[i], &takes_value)) {
            break;
        }

        ++i;
        if (takes_value && i < tail_argc) {
            ++i;
        }
    }

    if (i == 0 || i >= tail_argc || !wax_is_command_arg(tail[i])) {
        return tail;
    }

    const char **normalized = n00b_alloc_array(const char *, tail_argc);
    int          out        = 0;

    normalized[out++] = tail[i];

    for (int j = 0; j < i; ++j) {
        normalized[out++] = tail[j];
    }

    for (int j = i + 1; j < tail_argc; ++j) {
        normalized[out++] = tail[j];
    }

    return normalized;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    int          parse_argc = 0;
    const char **parse_argv = wax_normalize_argv(argc, argv, &parse_argc);

    n00b_cmdr_t        *cmdr = wax_build_cmdr();
    n00b_cmdr_result_t *r    = n00b_cmdr_parse(cmdr, parse_argc, parse_argv);

    if (wax_print_parse_errors(r)) {
        wax_usage();
        return 2;
    }

    if (n00b_cmdr_flag_present(r, r"--help") || argc <= 1) {
        wax_usage();
        return 0;
    }

    wax_config_t   cfg                  = wax_config_default(argv[0]);
    n00b_string_t *explicit_config_path = wax_flag_str(r, "--config");
    n00b_string_t *config_path          = explicit_config_path;

    if (config_path == nullptr) {
        config_path = wax_default_config_path();
    }

    if (!wax_load_config(&cfg, config_path, explicit_config_path != nullptr)) {
        return 2;
    }

    wax_apply_common_flags(&cfg, r);

    n00b_string_t *command = n00b_cmdr_result_command(r);

    if (command == nullptr || command->u8_bytes == 0) {
        wax_usage();
        return 0;
    }

    if (wax_streq(command, "status")) {
        return wax_status(&cfg);
    }

    if (wax_streq(command, "start")) {
        int rc = wax_start_service(&cfg, true);
        if (rc != 0) {
            return rc;
        }
        return wax_start_subscriber(&cfg, true);
    }

    if (wax_streq(command, "stop")) {
        int sub_rc = wax_stop_subscriber(&cfg);
        int svc_rc = wax_stop_service(&cfg);
        return sub_rc != 0 ? sub_rc : svc_rc;
    }

    if (wax_streq(command, "ingest")) {
        int rc = wax_start_service(&cfg, false);

        if (rc != 0) {
            return rc;
        }

        return wax_run_ingest(&cfg, r);
    }

    if (wax_streq(command, "sync")) {
        int rc = wax_start_service(&cfg, false);

        if (rc != 0) {
            return rc;
        }

        wax_try_start_subscriber(&cfg);

        return wax_run_sync(&cfg, r);
    }

    if (wax_streq(command, "search") || wax_streq(command, "query")) {
        wax_try_start_service(&cfg);
        return wax_run_search(&cfg, r);
    }

    wax_usage();

    return 2;
}
