/* test/unit/test_rocs_k8s_manifests.c - WP-012 Phase 4 manifest checks. */

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "parsers/json.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#ifndef ROCS_TEST_SOURCE_ROOT
#define ROCS_TEST_SOURCE_ROOT "."
#endif

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_string_t *
repo_file(n00b_string_t *rel)
{
    return n00b_unicode_str_cat(n00b_string_from_cstr(ROCS_TEST_SOURCE_ROOT),
                                rel);
}

static n00b_string_t *
read_text(n00b_string_t *rel)
{
    auto open_r = n00b_file_open(repo_file(rel), .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(open_r));

    n00b_file_t *file = n00b_result_get(open_r);
    auto         buf_r = n00b_file_as_buffer(file);
    CHECK(n00b_result_is_ok(buf_r));

    n00b_buffer_t *copy = n00b_buffer_copy(n00b_result_get(buf_r));
    n00b_file_close(file);
    return n00b_buffer_to_string(copy);
}

static void
must_contain(n00b_string_t *text, n00b_string_t *needle)
{
    CHECK(n00b_unicode_str_contains(text, needle));
}

static bool
byte_contains(n00b_string_t *text, n00b_string_t *needle)
{
    size_t text_len   = text->u8_bytes;
    size_t needle_len = needle->u8_bytes;

    if (needle_len == 0) {
        return true;
    }

    if (text_len < needle_len) {
        return false;
    }

    const char *haystack = text->data;
    const char *pattern  = needle->data;

    for (size_t i = 0; i <= text_len - needle_len; i++) {
        if (memcmp(haystack + i, pattern, needle_len) == 0) {
            return true;
        }
    }

    return false;
}

static void
must_not_contain(n00b_string_t *text, n00b_string_t *needle)
{
    CHECK(!byte_contains(text, needle));
}

static void
must_json_string(n00b_json_node_t *obj, n00b_string_t *key, n00b_string_t *expected)
{
    n00b_json_node_t *node = n00b_json_object_get(obj, key);

    CHECK(node != nullptr);
    CHECK(n00b_json_is_string(node));
    CHECK(n00b_unicode_str_eq(n00b_json_as_string(node), expected));
}

static n00b_json_node_t *
must_json_object(n00b_json_node_t *obj, n00b_string_t *key)
{
    n00b_json_node_t *node = n00b_json_object_get(obj, key);

    CHECK(node != nullptr);
    CHECK(n00b_json_is_object(node));
    return node;
}

static n00b_json_node_t *
must_json_array(n00b_json_node_t *obj, n00b_string_t *key)
{
    n00b_json_node_t *node = n00b_json_object_get(obj, key);

    CHECK(node != nullptr);
    CHECK(n00b_json_is_array(node));
    return node;
}

static n00b_json_node_t *
read_manifest_list(void)
{
    n00b_string_t *text = read_text(r"/deploy/rocs/rocs-service.json");

    must_not_contain(text, r"/Users/");

    n00b_json_node_t *root = n00b_json_parse(text->data, text->u8_bytes, nullptr);
    CHECK(root != nullptr);
    CHECK(n00b_json_is_object(root));
    must_json_string(root, r"apiVersion", r"v1");
    must_json_string(root, r"kind", r"List");
    CHECK(n00b_json_array_len(must_json_array(root, r"items")) == 8);
    return root;
}

static n00b_json_node_t *
manifest_item(n00b_json_node_t *root, n00b_string_t *kind, n00b_string_t *name)
{
    n00b_json_node_t *items = must_json_array(root, r"items");
    size_t            n     = n00b_json_array_len(items);

    for (size_t i = 0; i < n; i++) {
        n00b_json_node_t *item = n00b_json_array_get(items, i);
        CHECK(item != nullptr);
        CHECK(n00b_json_is_object(item));

        n00b_json_node_t *kind_node = n00b_json_object_get(item, r"kind");
        if (kind_node == nullptr || !n00b_json_is_string(kind_node)
            || !n00b_unicode_str_eq(n00b_json_as_string(kind_node), kind)) {
            continue;
        }

        n00b_json_node_t *metadata = must_json_object(item, r"metadata");
        n00b_json_node_t *name_node = n00b_json_object_get(metadata, r"name");
        if (name_node != nullptr && n00b_json_is_string(name_node)
            && n00b_unicode_str_eq(n00b_json_as_string(name_node), name)) {
            return item;
        }
    }

    CHECK(false);
    return nullptr;
}

static n00b_string_t *
join2(n00b_string_t *a, n00b_string_t *b)
{
    return n00b_unicode_str_cat(a, b);
}

static void
test_manifest_parseable_documents(void)
{
    n00b_json_node_t *root = read_manifest_list();

    manifest_item(root, r"ServiceAccount", r"rocs-service");
    manifest_item(root, r"ConfigMap", r"rocs-service-config");
    manifest_item(root, r"Secret", r"rocs-service-schema");
    manifest_item(root, r"Deployment", r"rocs-writer");
    manifest_item(root, r"Deployment", r"rocs-reader");
    manifest_item(root, r"Service", r"rocs-writer");
    manifest_item(root, r"Service", r"rocs-reader");
    manifest_item(root, r"PodDisruptionBudget", r"rocs-reader");
    n00b_printf("  [PASS] Kubernetes JSON manifest parses and lists resources");
}

static void
test_container_package(void)
{
    n00b_string_t *text = read_text(r"/docker/rocs-service.Dockerfile");

    must_contain(text, r"bash /src/build.sh");
    must_contain(text, r"N00B_BUILD_TARGETS=n00b-rocs-service");
    must_contain(text, r"N00B_SKIP_VCS_CHECK=1");
    must_contain(text, r"COPY --from=build");
    must_contain(text, r"/usr/local/bin/n00b-rocs-service");
    must_contain(text, r"ENTRYPOINT [\"/usr/local/bin/n00b-rocs-service\"]");
    must_contain(text, r"CMD [\"--serve\"]");
    must_contain(text, r"ROCS_PROFILE=service_s3");
    must_contain(text, r"ROCS_CACHE_DIR=/var/cache/rocs");
    must_not_contain(text, r"/Users/");
    n00b_printf("  [PASS] service container package wiring");
}

static void
test_topology_and_config_refs(void)
{
    n00b_string_t *text = read_text(r"/deploy/rocs/rocs-service.json");

    must_contain(text, r"ROCS_PROFILE");
    must_contain(text, r"service_s3");
    must_contain(text, r"ROCS_S3_BUCKET");
    must_contain(text, r"replace-with-bucket");
    must_contain(text, r"ROCS_S3_PREFIX");
    must_contain(text, r"rocs/prod");
    must_contain(text, r"ROCS_AWS_REGION");
    must_contain(text, r"us-east-1");
    must_contain(text, r"ROCS_S3_PATH_STYLE");
    must_contain(text, r"ROCS_CACHE_BYTES");
    must_contain(text, r"ROCS_RESIDENT_BYTES");
    must_contain(text, r"ROCS_RESIDENT_SHARDS");
    must_contain(text, r"\"ROCS_SCHEMA\"");
    must_contain(text, r"\"name\": \"rocs-writer\"");
    must_contain(text, r"\"replicas\": 1");
    must_contain(text, r"\"value\": \"false\"");
    must_contain(text, r"\"value\": \"single_writer\"");
    must_contain(text, r"\"secretKeyRef\"");
    must_contain(text, r"\"name\": \"rocs-service-schema\"");
    must_contain(text, r"\"key\": \"ROCS_SCHEMA\"");
    must_contain(text, r"\"name\": \"rocs-reader\"");
    must_contain(text, r"\"replicas\": 2");
    must_contain(text, r"\"value\": \"true\"");
    must_contain(text, r"\"value\": \"read_replica\"");

    n00b_printf("  [PASS] writer/read-replica topology and config references");
}

static void
test_probes_metrics_resources_and_cache(void)
{
    n00b_string_t *text = read_text(r"/deploy/rocs/rocs-service.json");

    must_contain(text, r"\"path\": \"/healthz/startup\"");
    must_contain(text, r"\"path\": \"/healthz/ready\"");
    must_contain(text, r"\"path\": \"/healthz/live\"");
    must_contain(text, r"\"prometheus.io/path\": \"/metrics\"");
    must_contain(text, r"\"resources\"");
    must_contain(text, r"\"requests\"");
    must_contain(text, r"\"limits\"");
    must_contain(text, r"\"mountPath\": \"/var/cache/rocs\"");
    must_contain(text, r"\"emptyDir\"");
    must_contain(text, r"\"sizeLimit\": \"2Gi\"");
    must_contain(text, r"\"args\": [\"--serve\"]");
    must_contain(text, r"\"targetPort\": \"http\"");
    must_contain(text, r"\"minAvailable\": 1");
    n00b_printf("  [PASS] probes, metrics, resources, and cache wiring");
}

static void
check_no_static_credentials(n00b_string_t *rel)
{
    n00b_string_t *text          = read_text(rel);
    n00b_string_t *access_key    = join2(r"ACCESS", r"_KEY");
    n00b_string_t *secret_access = join2(r"SECRET", r"_ACCESS");
    n00b_string_t *session_token = join2(r"SESSION", r"_TOKEN");
    n00b_string_t *access_key_l  = join2(r"access", r"_key");
    n00b_string_t *secret_access_l = join2(r"secret", r"_access");
    n00b_string_t *session_token_l = join2(r"session", r"_token");
    n00b_string_t *aws_key_prefix  = join2(r"AK", r"IA");

    must_not_contain(text, access_key);
    must_not_contain(text, secret_access);
    must_not_contain(text, session_token);
    must_not_contain(text, access_key_l);
    must_not_contain(text, secret_access_l);
    must_not_contain(text, session_token_l);
    must_not_contain(text, aws_key_prefix);
    must_not_contain(text, r"/Users/");
}

static void
test_no_static_cloud_credentials(void)
{
    check_no_static_credentials(r"/docker/rocs-service.Dockerfile");
    check_no_static_credentials(r"/deploy/rocs/rocs-service.json");
    check_no_static_credentials(r"/deploy/rocs/README.md");

    n00b_string_t *sa = read_text(r"/deploy/rocs/rocs-service.json");
    must_contain(sa, r"eks.amazonaws.com/role-arn");

    n00b_string_t *notes = read_text(r"/deploy/rocs/README.md");
    must_contain(notes, r"workload identity");
    must_contain(notes, r"Do not put long-lived cloud credential values");
    n00b_printf("  [PASS] workload identity notes and no static credentials");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_k8s_manifests:");
    test_manifest_parseable_documents();
    test_container_package();
    test_topology_and_config_refs();
    test_probes_metrics_resources_and_cache();
    test_no_static_cloud_credentials();

    n00b_shutdown();
    return 0;
}
