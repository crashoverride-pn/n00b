#include <stdint.h>
#include <string.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/macho.h"
#include "core/buffer.h"
#include "core/gc_baked.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "internal/slay/grammar_internal.h"
#include "parsers/token_stream.h"
#include "slay/grammar_image.h"
#include "slay/n00b_parse.h"
#include "util/assert.h"
#include "util/comptime_image.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

static n00b_grammar_t *
new_fixture_grammar(void)
{
    n00b_grammar_t *g = n00b_grammar_new(.parse_mode = N00B_PARSE_MODE_PWZ_ONLY);
    n00b_nonterm_t *nt = n00b_nonterm(g, r"expr");
    int64_t terminal_id = n00b_register_terminal(g, r"TOKEN");
    n00b_add_rule(g, nt, N00B_TERMINAL(terminal_id));
    n00b_grammar_set_start(g, nt);
    n00b_grammar_finalize(g);
    g->tokenizer_name = r"text";
    return g;
}

static bool
buffer_contains(n00b_buffer_t *buf, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || buf == nullptr || buf->data == nullptr
        || buf->byte_len < needle_len) {
        return false;
    }

    for (size_t i = 0; i <= buf->byte_len - needle_len; i++) {
        if (memcmp(buf->data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static n00b_token_info_t *
make_token(int64_t tid, const char *text, int32_t index)
{
    n00b_token_info_t *t = n00b_alloc(n00b_token_info_t);

    t->tid    = tid;
    t->index  = index;
    t->line   = 1;
    t->column = (uint32_t)(index + 1);

    if (text != nullptr) {
        t->value = n00b_option_set(n00b_string_t *,
                                   n00b_string_from_cstr(text));
    }

    return t;
}

static void
assert_fixture_parse(n00b_grammar_t *g)
{
    CHECK(g->rules.len == 1);
    CHECK(g->rules.data[0].contents.len == 1);
    int64_t tid = g->rules.data[0].contents.data[0].terminal_id;

    n00b_token_info_t *tokens[] = {
        make_token(tid, "token", 0),
    };
    n00b_token_stream_t *ts = n00b_token_stream_from_array(tokens, 1);
    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

    CHECK(n00b_parse_result_ok(r));
    CHECK(n00b_parse_result_tree_count(r) == 1);
    CHECK(n00b_parse_result_tree(r) != nullptr);

    n00b_parse_result_free(r);
    n00b_token_stream_free(ts);
}

static void
assert_scrubbed_dict(void *dict)
{
    if (dict == nullptr) {
        return;
    }

    _n00b_dict_internal_t *d = (_n00b_dict_internal_t *)dict;
    CHECK(d->allocator == nullptr);
    CHECK(!d->lock);
    CHECK(d->scan_kind == N00B_GC_SCAN_KIND_NONE);
    CHECK(d->scan_cb == nullptr);
    CHECK(d->scan_user == nullptr);
    CHECK(d->key_scan_kind == N00B_GC_SCAN_KIND_NONE);
    CHECK(d->value_scan_kind == N00B_GC_SCAN_KIND_NONE);
}

static n00b_buffer_t *
grammar_object_section(n00b_buffer_t *object)
{
#if defined(__APPLE__)
    n00b_bstream_t *stream = n00b_bstream_new(object);
    auto parse_r = n00b_macho_parse(stream);
    CHECK(n00b_result_is_ok(parse_r));
    n00b_macho_fat_t *fat = n00b_result_get(parse_r);
    CHECK(fat->count == 1);
    n00b_macho_binary_t *bin = fat->binaries[0];
    auto sec_opt = n00b_macho_section_by_name(
        bin,
        N00B_GRAMMAR_IMAGE_SECTION_MACHO_SEG,
        N00B_GRAMMAR_IMAGE_SECTION_MACHO_SECT);
    CHECK(n00b_option_is_set(sec_opt));
    n00b_macho_section_t *sec = n00b_option_get(sec_opt);
    CHECK(sec->content != nullptr);
    return sec->content;
#elif defined(__ELF__)
    n00b_bstream_t *stream = n00b_bstream_new(object);
    auto parse_r = n00b_elf_parse(stream);
    CHECK(n00b_result_is_ok(parse_r));
    n00b_elf_binary_t *bin = n00b_result_get(parse_r);
    CHECK(bin->header.type == ET_REL);
    auto sec_opt = n00b_elf_section_by_name(bin, "n00b_gimage");
    CHECK(n00b_option_is_set(sec_opt));
    n00b_elf_section_t *sec = n00b_option_get(sec_opt);
    CHECK(sec->content != nullptr);
    return sec->content;
#else
    (void)object;
    return nullptr;
#endif
}

static void *
map_image_copy(const char *image, size_t image_len, size_t *protect_len_out)
{
    size_t protect_len = n00b_page_align(image_len);
    auto map_r = n00b_mmap(protect_len,
                           .kind = n00b_mmap_api_mmap,
                           .name = "grammar-image-object");
    CHECK(n00b_result_is_ok(map_r));
    void *mapping = n00b_result_get(map_r);
    memcpy(mapping, image, image_len);
    *protect_len_out = protect_len;
    return mapping;
}

static void
test_grammar_object_roundtrip(void)
{
#if defined(_WIN32) || (!defined(__APPLE__) && !defined(__ELF__))
    n00b_print(r"[SKIP] grammar_image_object: host object emission unsupported on this platform in Phase 2");
    return;
#else
    n00b_grammar_t *g = new_fixture_grammar();
    auto object_r = n00b_grammar_image_emit_object(g, r"tiny_grammar");
    CHECK(n00b_result_is_ok(object_r));

    n00b_buffer_t *object = n00b_result_get(object_r);
    CHECK(object->byte_len > 0);
    CHECK(!buffer_contains(object, "_b64"));
    CHECK(!buffer_contains(object, "n00b_base64_decode"));
    CHECK(!buffer_contains(object, "n00b_static_grammar_register"));
    CHECK(!buffer_contains(object, "_register"));

    n00b_buffer_t *section = grammar_object_section(object);
    CHECK(section != nullptr);
    CHECK(section->byte_len >= sizeof(n00b_grammar_image_record_t));

    n00b_grammar_image_record_t rec = {};
    memcpy(&rec, section->data, sizeof(rec));
    CHECK(rec.magic == N00B_GRAMMAR_IMAGE_RECORD_MAGIC);
    CHECK(rec.version == N00B_GRAMMAR_IMAGE_RECORD_VERSION);
    CHECK(rec.header_len == sizeof(n00b_grammar_image_record_t));
    CHECK(rec.name_len == strlen("tiny_grammar"));
    CHECK(rec.image_off >= rec.header_len + rec.name_len);
    CHECK(rec.record_len <= section->byte_len);
    CHECK(rec.image_len > sizeof(n00b_ct_image_header_t));
    CHECK((size_t)rec.image_off + rec.image_len <= section->byte_len);
    CHECK(memcmp(section->data + rec.header_len,
                 "tiny_grammar",
                 rec.name_len) == 0);

    n00b_ct_image_header_t image_hdr = {};
    memcpy(&image_hdr, section->data + rec.image_off, sizeof(image_hdr));
    CHECK(image_hdr.magic == N00B_CT_IMAGE_MAGIC);
    CHECK(image_hdr.version == N00B_CT_IMAGE_VERSION);
    CHECK(image_hdr.root_count == 1);

    size_t protect_len = 0;
    void *mapping = map_image_copy(section->data + rec.image_off,
                                   rec.image_len,
                                   &protect_len);
    n00b_ct_image_repair_hook_t hook = {
        .fn = n00b_grammar_image_repair_hook,
    };
    auto relocate_r = n00b_ct_image_relocate_inplace_ex(mapping,
                                                        rec.image_len,
                                                        &hook);
    CHECK(n00b_result_is_ok(relocate_r));

    n00b_grammar_t *copy = n00b_result_get(relocate_r);
    CHECK(copy != g);
    CHECK(copy->finalized);
    CHECK(copy->rules.allocator == nullptr);
    CHECK(copy->rules.scan_kind == N00B_GC_SCAN_KIND_NONE);
    CHECK(copy->rules.scan_cb == nullptr);
    CHECK(copy->rules.scan_user == nullptr);
    CHECK(copy->nt_list.allocator == nullptr);
    CHECK(copy->nt_list.scan_kind == N00B_GC_SCAN_KIND_NONE);
    CHECK(copy->nt_list.scan_cb == nullptr);
    CHECK(copy->nt_list.scan_user == nullptr);
    assert_scrubbed_dict(copy->nt_map);
    assert_scrubbed_dict(copy->terminal_map);
    assert_scrubbed_dict(copy->literal_type_map);
    assert_scrubbed_dict(copy->valid_tokens);
    assert_scrubbed_dict(copy->terminal_by_id);
    assert_scrubbed_dict(copy->terminal_categories);
    for (size_t i = 0; i < copy->rules.len; i++) {
        n00b_parse_rule_t *rule = &copy->rules.data[i];
        CHECK(rule->contents.allocator == nullptr);
        CHECK(rule->contents.scan_kind == N00B_GC_SCAN_KIND_NONE);
        CHECK(rule->contents.scan_cb == nullptr);
        CHECK(rule->contents.scan_user == nullptr);
        CHECK(rule->annotations.allocator == nullptr);
        CHECK(rule->annotations.scan_kind == N00B_GC_SCAN_KIND_NONE);
        CHECK(rule->annotations.scan_cb == nullptr);
        CHECK(rule->annotations.scan_user == nullptr);
        assert_scrubbed_dict(rule->first_set);
    }
    for (size_t i = 0; i < copy->nt_list.len; i++) {
        n00b_nonterm_t *nt = &copy->nt_list.data[i];
        CHECK(nt->rule_ids.allocator == nullptr);
        CHECK(nt->rule_ids.scan_kind == N00B_GC_SCAN_KIND_NONE);
        CHECK(nt->rule_ids.scan_cb == nullptr);
        CHECK(nt->rule_ids.scan_user == nullptr);
        CHECK(nt->pending_annotations.allocator == nullptr);
        CHECK(nt->pending_annotations.scan_kind == N00B_GC_SCAN_KIND_NONE);
        CHECK(nt->pending_annotations.scan_cb == nullptr);
        CHECK(nt->pending_annotations.scan_user == nullptr);
        assert_scrubbed_dict(nt->first_set);
    }
    CHECK(copy->tokenize_cb != nullptr);
    assert_fixture_parse(copy);

    n00b_ct_image_header_t *hdr = mapping;
    n00b_gc_baked_region_t region = {
        .base           = mapping,
        .len            = rec.image_len,
        .marshal_stream = (char *)mapping + hdr->marshal_off,
        .marshal_len    = hdr->marshal_len,
        .root           = copy,
    };
    auto register_r = n00b_gc_register_baked_region(&region);
    CHECK(n00b_result_is_ok(register_r));
    CHECK(n00b_gc_addr_in_baked_region(copy));

    auto unmap_r = n00b_munmap(mapping);
    CHECK(n00b_result_is_ok(unmap_r));
    (void)protect_len;
#endif
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_grammar_object_roundtrip();

    n00b_shutdown();
    return 0;
}
