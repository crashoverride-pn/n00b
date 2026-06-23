// grammar_image.c - Build-time grammar object baking + runtime repair.
//
// The live bake path exports a finalized `n00b_grammar_t` as a WP-005
// offset-relocatable comptime image, wraps it in a grammar-image section
// record, and emits linkable object bytes. Runtime lookup relocates the image
// and invokes the repair hook below after marshal FNPATCH has restored exported
// function pointers. The hook still owns dictionary hash callbacks because
// those are function-pointer metadata, not GC object-pointer slots.

#include "slay/grammar_image.h"
#include "compiler/objfile/elf_build.h"
#include "compiler/objfile/macho.h"
#include "internal/slay/grammar_internal.h"
#include "core/align.h"
#include "core/string.h"
#include "util/comptime_image.h"
#include "parsers/tokenizer_registry.h"
#include <string.h>

#define N00B_GRAMMAR_IMAGE_SECTION_ALIGN       UINT64_C(0x4000)
#define N00B_GRAMMAR_IMAGE_MACHO_ALIGN_LOG2    14

static inline void
repair_dict_hash(_n00b_dict_internal_t *d, n00b_hash_fn fn)
{
    if (d == nullptr) {
        return;
    }

    d->fn            = fn;
    d->skip_obj_hash = true;
}

static inline void
repair_word_set(n00b_dict_t(int64_t, bool) *d)
{
    repair_dict_hash((_n00b_dict_internal_t *)d, n00b_hash_word);
}

void
n00b_grammar_image_repair(n00b_grammar_t *g)
{
    if (g == nullptr) {
        return;
    }

    // FNPATCH restores exported function pointers that the marshal scanner
    // visits. Dict hash callbacks are function-pointer metadata outside the
    // GC object-pointer map, so grammar repair owns rebinding them.
    repair_dict_hash((_n00b_dict_internal_t *)g->nt_map, n00b_string_hash);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_map, n00b_string_hash);
    repair_dict_hash((_n00b_dict_internal_t *)g->literal_type_map,
                     n00b_string_hash);
    repair_word_set(g->valid_tokens);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_by_id,
                     n00b_hash_word);
    repair_dict_hash((_n00b_dict_internal_t *)g->terminal_categories,
                     n00b_hash_word);

    // Grammar action hooks are process-local callbacks, so the baked image
    // must not retain them. The tokenizer callback is re-resolved from its
    // stable registry name below.
    for (size_t i = 0; i < g->nt_list.len; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];

        repair_word_set(nt->first_set);
        nt->action    = nullptr;
        nt->user_data = nullptr;
    }

    for (size_t i = 0; i < g->rules.len; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];

        repair_word_set(rule->first_set);
        rule->thunk = nullptr;
    }

    g->default_action = nullptr;
    g->disambiguator  = nullptr;
    g->tokenize_cb    = nullptr;

    if (g->tokenizer_name != nullptr && g->tokenizer_name->data != nullptr) {
        bool found = false;
        g->tokenize_cb = n00b_tokenizer_lookup(g->tokenizer_name->data,
                                               &found);
        if (found == false) {
            g->tokenize_cb = nullptr;
        }
    }
}

n00b_result_t(bool)
n00b_grammar_image_repair_hook(void *image_base,
                               size_t image_len,
                               void *root,
                               void *user)
{
    (void)image_base;
    (void)image_len;
    (void)user;

    n00b_grammar_image_repair((n00b_grammar_t *)root);
    return n00b_result_ok(bool, true);
}

// ============================================================================
// Object emitter
// ============================================================================

n00b_string_t *
n00b_grammar_image_emit_err_str(n00b_err_t err)
{
    switch ((n00b_grammar_image_err_t)err) {
    case N00B_GRAMMAR_IMAGE_OK:
        return r"ok";
    case N00B_GRAMMAR_IMAGE_ERR_NULL_ARG:
        return r"a required grammar image argument was null";
    case N00B_GRAMMAR_IMAGE_ERR_NOT_FINAL:
        return r"grammar is not finalized";
    case N00B_GRAMMAR_IMAGE_ERR_MARSHAL:
        return r"grammar could not be exported as a comptime image";
    case N00B_GRAMMAR_IMAGE_ERR_OBJECT:
        return r"grammar comptime-image object could not be emitted";
    }

    return r"unknown grammar-image error";
}

static inline size_t
grammar_image_align8(size_t n)
{
    return (n + 7u) & ~(size_t)7u;
}

static n00b_result_t(n00b_buffer_t *)
grammar_image_record(n00b_string_t *grammar_name,
                     n00b_buffer_t *image,
                     n00b_allocator_t *allocator)
{
    if (grammar_name == nullptr || grammar_name->data == nullptr
        || grammar_name->u8_bytes <= 0 || image == nullptr
        || image->data == nullptr || image->byte_len == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_NULL_ARG);
    }

    size_t name_len = (size_t)grammar_name->u8_bytes;
    size_t header_len = sizeof(n00b_grammar_image_record_t);
    size_t image_off = grammar_image_align8(header_len + name_len);
    if (name_len > UINT32_MAX || image->byte_len > UINT32_MAX
        || image_off > UINT32_MAX
        || image->byte_len > SIZE_MAX - image_off
        || image_off + image->byte_len > UINT32_MAX) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    size_t record_len = image_off + image->byte_len;
    n00b_buffer_t *record = n00b_buffer_new((int64_t)record_len,
                                            .allocator = allocator);
    record->byte_len = record_len;

    n00b_grammar_image_record_t hdr = {
        .magic      = N00B_GRAMMAR_IMAGE_RECORD_MAGIC,
        .version    = N00B_GRAMMAR_IMAGE_RECORD_VERSION,
        .header_len = (uint16_t)header_len,
        .record_len = (uint32_t)record_len,
        .name_len   = (uint32_t)name_len,
        .image_off  = (uint32_t)image_off,
        .image_len  = (uint32_t)image->byte_len,
    };

    memcpy(record->data, &hdr, sizeof(hdr));
    memcpy(record->data + header_len, grammar_name->data, name_len);
    memcpy(record->data + image_off, image->data, image->byte_len);
    return n00b_result_ok(n00b_buffer_t *, record);
}

static n00b_result_t(n00b_buffer_t *)
grammar_image_padded_section(n00b_buffer_t *record,
                             n00b_allocator_t *allocator)
{
    if ((uint64_t)record->byte_len
        > UINT64_MAX - (N00B_GRAMMAR_IMAGE_SECTION_ALIGN - 1)) {
        return n00b_result_err(n00b_buffer_t *, N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    uint64_t padded_len = n00b_align_ceil(record->byte_len,
                                          N00B_GRAMMAR_IMAGE_SECTION_ALIGN);
    if (padded_len > INT64_MAX) {
        return n00b_result_err(n00b_buffer_t *, N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    n00b_buffer_t *section = n00b_buffer_new((int64_t)padded_len,
                                             .allocator = allocator);
    section->byte_len = (int64_t)padded_len;
    memcpy(section->data, record->data, record->byte_len);
    return n00b_result_ok(n00b_buffer_t *, section);
}

static n00b_result_t(n00b_buffer_t *)
grammar_image_emit_elf_object([[maybe_unused]] n00b_buffer_t *record,
                              [[maybe_unused]] n00b_allocator_t *allocator)
{
#if defined(__ELF__)
    uint16_t machine = EM_NONE;
#if defined(__x86_64__)
    machine = EM_X86_64;
#elif defined(__aarch64__)
    machine = EM_AARCH64;
#endif
    if (machine == EM_NONE) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    n00b_elf_binary_t *bin = n00b_elf_binary_new(ET_REL,
                                                 machine,
                                                 .allocator = allocator);
    auto section_r = grammar_image_padded_section(record, allocator);
    if (n00b_result_is_err(section_r)) {
        return section_r;
    }
    n00b_buffer_t *section = n00b_result_get(section_r);

    n00b_elf_section_t *sec = n00b_elf_add_section(
        bin,
        N00B_GRAMMAR_IMAGE_SECTION_ELF,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_WRITE);
    sec->content = section;
    sec->size = section->byte_len;
    sec->addralign = N00B_GRAMMAR_IMAGE_SECTION_ALIGN;

    auto build_r = n00b_elf_build(bin, .allocator = allocator);
    if (n00b_result_is_err(build_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }
    return build_r;
#else
    return n00b_result_err(n00b_buffer_t *, N00B_GRAMMAR_IMAGE_ERR_OBJECT);
#endif
}

static bool
grammar_image_buf_write(n00b_buffer_t *buf, size_t *pos, const void *src,
                        size_t len)
{
    if (*pos > (size_t)buf->byte_len || len > (size_t)buf->byte_len - *pos) {
        return false;
    }

    if (len > 0) {
        memcpy(buf->data + *pos, src, len);
        *pos += len;
    }
    return true;
}

static bool
grammar_image_buf_write_u32(n00b_buffer_t *buf, size_t *pos, uint32_t v)
{
    return grammar_image_buf_write(buf, pos, &v, sizeof(v));
}

static bool
grammar_image_buf_write_u64(n00b_buffer_t *buf, size_t *pos, uint64_t v)
{
    return grammar_image_buf_write(buf, pos, &v, sizeof(v));
}

static bool
grammar_image_buf_write_fixed16(n00b_buffer_t *buf, size_t *pos,
                                const char *name)
{
    char fixed[16] = {};
    size_t len = strlen(name);
    if (len > sizeof(fixed)) {
        len = sizeof(fixed);
    }
    memcpy(fixed, name, len);
    return grammar_image_buf_write(buf, pos, fixed, sizeof(fixed));
}

static n00b_result_t(n00b_buffer_t *)
grammar_image_emit_macho_object([[maybe_unused]] n00b_buffer_t *record,
                                [[maybe_unused]] n00b_allocator_t *allocator)
{
#if defined(__APPLE__)
    uint32_t cputype = 0;
    uint32_t cpusubtype = CPU_SUBTYPE_ALL;
#if defined(__x86_64__)
    cputype = CPU_TYPE_X86_64;
    cpusubtype = CPU_SUBTYPE_X86_64_ALL;
#elif defined(__aarch64__)
    cputype = CPU_TYPE_ARM64;
    cpusubtype = CPU_SUBTYPE_ARM64_ALL;
#endif
    if (cputype == 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    const uint32_t header_size = 32;
    const uint32_t segment_size = 72;
    const uint32_t section_size = 80;
    const uint32_t data_off = header_size + segment_size + section_size;
    auto section_r = grammar_image_padded_section(record, allocator);
    if (n00b_result_is_err(section_r)) {
        return section_r;
    }
    n00b_buffer_t *section = n00b_result_get(section_r);

    if (section->byte_len > UINT32_MAX - data_off) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }

    size_t total_len = data_off + section->byte_len;
    n00b_buffer_t *obj = n00b_buffer_new((int64_t)total_len,
                                         .allocator = allocator);
    obj->byte_len = (int64_t)total_len;
    size_t pos = 0;
    bool ok = true;

    ok &= grammar_image_buf_write_u32(obj, &pos, MH_MAGIC_64);
    ok &= grammar_image_buf_write_u32(obj, &pos, cputype);
    ok &= grammar_image_buf_write_u32(obj, &pos, cpusubtype);
    ok &= grammar_image_buf_write_u32(obj, &pos, MH_OBJECT);
    ok &= grammar_image_buf_write_u32(obj, &pos, 1);
    ok &= grammar_image_buf_write_u32(obj, &pos, segment_size + section_size);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);

    ok &= grammar_image_buf_write_u32(obj, &pos, LC_SEGMENT_64);
    ok &= grammar_image_buf_write_u32(obj, &pos, segment_size + section_size);
    ok &= grammar_image_buf_write_fixed16(
        obj,
        &pos,
        N00B_GRAMMAR_IMAGE_SECTION_MACHO_SEG);
    ok &= grammar_image_buf_write_u64(obj, &pos, 0);
    ok &= grammar_image_buf_write_u64(obj, &pos, (uint64_t)section->byte_len);
    ok &= grammar_image_buf_write_u64(obj, &pos, data_off);
    ok &= grammar_image_buf_write_u64(obj, &pos, (uint64_t)section->byte_len);
    ok &= grammar_image_buf_write_u32(obj, &pos, 3);
    ok &= grammar_image_buf_write_u32(obj, &pos, 3);
    ok &= grammar_image_buf_write_u32(obj, &pos, 1);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);

    ok &= grammar_image_buf_write_fixed16(
        obj,
        &pos,
        N00B_GRAMMAR_IMAGE_SECTION_MACHO_SECT);
    ok &= grammar_image_buf_write_fixed16(
        obj,
        &pos,
        N00B_GRAMMAR_IMAGE_SECTION_MACHO_SEG);
    ok &= grammar_image_buf_write_u64(obj, &pos, 0);
    ok &= grammar_image_buf_write_u64(obj, &pos, (uint64_t)section->byte_len);
    ok &= grammar_image_buf_write_u32(obj, &pos, data_off);
    ok &= grammar_image_buf_write_u32(obj, &pos,
                                      N00B_GRAMMAR_IMAGE_MACHO_ALIGN_LOG2);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write_u32(obj, &pos, S_REGULAR);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write_u32(obj, &pos, 0);
    ok &= grammar_image_buf_write(obj, &pos, section->data, section->byte_len);

    if (ok == false || pos != total_len) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_OBJECT);
    }
    return n00b_result_ok(n00b_buffer_t *, obj);
#else
    return n00b_result_err(n00b_buffer_t *, N00B_GRAMMAR_IMAGE_ERR_OBJECT);
#endif
}

typedef struct {
    n00b_allocator_t   *allocator;
    n00b_gc_scan_kind_t scan_kind;
    n00b_gc_scan_cb_t   scan_cb;
    void               *scan_user;
} grammar_image_list_header_state_t;

typedef struct {
    n00b_allocator_t   *allocator;
    uint8_t             lock;
    n00b_gc_scan_kind_t scan_kind;
    n00b_gc_scan_cb_t   scan_cb;
    void               *scan_user;
    n00b_gc_scan_kind_t key_scan_kind;
    n00b_gc_scan_kind_t value_scan_kind;
} grammar_image_dict_header_state_t;

typedef struct {
    n00b_walk_action_t action;
    void              *user_data;
} grammar_image_nonterm_process_state_t;

typedef struct {
    void *thunk;
} grammar_image_rule_process_state_t;

typedef struct {
    grammar_image_list_header_state_t  rules;
    grammar_image_list_header_state_t  nt_list;
    grammar_image_list_header_state_t *rule_contents;
    grammar_image_list_header_state_t *rule_annotations;
    grammar_image_list_header_state_t *nt_rule_ids;
    grammar_image_list_header_state_t *nt_pending_annotations;
    grammar_image_dict_header_state_t  nt_map;
    grammar_image_dict_header_state_t  terminal_map;
    grammar_image_dict_header_state_t  literal_type_map;
    grammar_image_dict_header_state_t  valid_tokens;
    grammar_image_dict_header_state_t  terminal_by_id;
    grammar_image_dict_header_state_t  terminal_categories;
    grammar_image_dict_header_state_t *rule_first_sets;
    grammar_image_dict_header_state_t *nt_first_sets;
    grammar_image_rule_process_state_t *rule_process;
    grammar_image_nonterm_process_state_t *nt_process;
    n00b_scan_cb_t                    tokenize_cb;
    n00b_walk_action_t                default_action;
    n00b_tree_disambig_fn_t           disambiguator;
    size_t                            rule_count;
    size_t                            nt_count;
} grammar_image_header_state_t;

#define grammar_image_save_list(dst, list_ptr)                                                \
    do {                                                                                      \
        (dst)->allocator = (list_ptr)->allocator;                                             \
        (dst)->scan_kind = (list_ptr)->scan_kind;                                             \
        (dst)->scan_cb   = (list_ptr)->scan_cb;                                               \
        (dst)->scan_user = (list_ptr)->scan_user;                                             \
    } while (0)

#define grammar_image_scrub_list(list_ptr)                                                    \
    do {                                                                                      \
        (list_ptr)->allocator = nullptr;                                                      \
        (list_ptr)->scan_kind = N00B_GC_SCAN_KIND_NONE;                                      \
        (list_ptr)->scan_cb   = nullptr;                                                      \
        (list_ptr)->scan_user = nullptr;                                                      \
    } while (0)

#define grammar_image_restore_list(list_ptr, src)                                             \
    do {                                                                                      \
        (list_ptr)->allocator = (src)->allocator;                                             \
        (list_ptr)->scan_kind = (src)->scan_kind;                                             \
        (list_ptr)->scan_cb   = (src)->scan_cb;                                               \
        (list_ptr)->scan_user = (src)->scan_user;                                             \
    } while (0)

#define grammar_image_save_dict(dst, dict_ptr)                                                \
    do {                                                                                      \
        _n00b_dict_internal_t *_bl_d = (_n00b_dict_internal_t *)(dict_ptr);                  \
        if (_bl_d != nullptr) {                                                               \
            (dst)->allocator       = _bl_d->allocator;                                       \
            (dst)->lock            = _bl_d->lock;                                            \
            (dst)->scan_kind       = _bl_d->scan_kind;                                       \
            (dst)->scan_cb         = _bl_d->scan_cb;                                         \
            (dst)->scan_user       = _bl_d->scan_user;                                       \
            (dst)->key_scan_kind   = _bl_d->key_scan_kind;                                  \
            (dst)->value_scan_kind = _bl_d->value_scan_kind;                                \
        }                                                                                     \
    } while (0)

#define grammar_image_scrub_dict(dict_ptr)                                                    \
    do {                                                                                      \
        _n00b_dict_internal_t *_bl_d = (_n00b_dict_internal_t *)(dict_ptr);                  \
        if (_bl_d != nullptr) {                                                               \
            _bl_d->allocator       = nullptr;                                                 \
            _bl_d->lock            = 0;                                                       \
            _bl_d->scan_kind       = N00B_GC_SCAN_KIND_NONE;                                 \
            _bl_d->scan_cb         = nullptr;                                                 \
            _bl_d->scan_user       = nullptr;                                                 \
            _bl_d->key_scan_kind   = N00B_GC_SCAN_KIND_NONE;                                 \
            _bl_d->value_scan_kind = N00B_GC_SCAN_KIND_NONE;                                 \
        }                                                                                     \
    } while (0)

#define grammar_image_restore_dict(dict_ptr, src)                                             \
    do {                                                                                      \
        _n00b_dict_internal_t *_bl_d = (_n00b_dict_internal_t *)(dict_ptr);                  \
        if (_bl_d != nullptr) {                                                               \
            _bl_d->allocator       = (src)->allocator;                                       \
            _bl_d->lock            = (src)->lock;                                            \
            _bl_d->scan_kind       = (src)->scan_kind;                                       \
            _bl_d->scan_cb         = (src)->scan_cb;                                         \
            _bl_d->scan_user       = (src)->scan_user;                                       \
            _bl_d->key_scan_kind   = (src)->key_scan_kind;                                  \
            _bl_d->value_scan_kind = (src)->value_scan_kind;                                \
        }                                                                                     \
    } while (0)

static grammar_image_list_header_state_t *
grammar_image_list_state_array(size_t n, n00b_allocator_t *allocator)
{
    if (n == 0) {
        return nullptr;
    }

    return n00b_alloc_array_with_opts(
        grammar_image_list_header_state_t,
        n,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
}

static grammar_image_dict_header_state_t *
grammar_image_dict_state_array(size_t n, n00b_allocator_t *allocator)
{
    if (n == 0) {
        return nullptr;
    }

    return n00b_alloc_array_with_opts(
        grammar_image_dict_header_state_t,
        n,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
}

static grammar_image_header_state_t
grammar_image_scrub_headers(n00b_grammar_t *g, n00b_allocator_t *allocator)
{
    grammar_image_header_state_t state = {
        .rule_count = g->rules.len,
        .nt_count   = g->nt_list.len,
    };

    state.rule_contents = grammar_image_list_state_array(state.rule_count,
                                                         allocator);
    state.rule_annotations = grammar_image_list_state_array(state.rule_count,
                                                            allocator);
    state.nt_rule_ids = grammar_image_list_state_array(state.nt_count,
                                                       allocator);
    state.nt_pending_annotations = grammar_image_list_state_array(
        state.nt_count,
        allocator);
    state.rule_first_sets = grammar_image_dict_state_array(state.rule_count,
                                                           allocator);
    state.nt_first_sets = grammar_image_dict_state_array(state.nt_count,
                                                         allocator);
    state.rule_process = n00b_alloc_array_with_opts(
        grammar_image_rule_process_state_t,
        state.rule_count == 0 ? 1 : state.rule_count,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    state.nt_process = n00b_alloc_array_with_opts(
        grammar_image_nonterm_process_state_t,
        state.nt_count == 0 ? 1 : state.nt_count,
        &(n00b_alloc_opts_t){
            .allocator = allocator,
            .scan_kind = N00B_GC_SCAN_KIND_ALL,
        });
    state.tokenize_cb    = g->tokenize_cb;
    state.default_action = g->default_action;
    state.disambiguator  = g->disambiguator;

    grammar_image_save_list(&state.rules, &g->rules);
    grammar_image_save_list(&state.nt_list, &g->nt_list);
    grammar_image_save_dict(&state.nt_map, g->nt_map);
    grammar_image_save_dict(&state.terminal_map, g->terminal_map);
    grammar_image_save_dict(&state.literal_type_map, g->literal_type_map);
    grammar_image_save_dict(&state.valid_tokens, g->valid_tokens);
    grammar_image_save_dict(&state.terminal_by_id, g->terminal_by_id);
    grammar_image_save_dict(&state.terminal_categories,
                            g->terminal_categories);
    grammar_image_scrub_list(&g->rules);
    grammar_image_scrub_list(&g->nt_list);
    grammar_image_scrub_dict(g->nt_map);
    grammar_image_scrub_dict(g->terminal_map);
    grammar_image_scrub_dict(g->literal_type_map);
    grammar_image_scrub_dict(g->valid_tokens);
    grammar_image_scrub_dict(g->terminal_by_id);
    grammar_image_scrub_dict(g->terminal_categories);
    g->tokenize_cb     = nullptr;
    g->default_action  = nullptr;
    g->disambiguator   = nullptr;

    for (size_t i = 0; i < state.rule_count; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];
        grammar_image_save_list(&state.rule_contents[i], &rule->contents);
        grammar_image_save_list(&state.rule_annotations[i], &rule->annotations);
        grammar_image_save_dict(&state.rule_first_sets[i], rule->first_set);
        state.rule_process[i].thunk = rule->thunk;
        rule->thunk = nullptr;
        grammar_image_scrub_list(&rule->contents);
        grammar_image_scrub_list(&rule->annotations);
        grammar_image_scrub_dict(rule->first_set);
    }

    for (size_t i = 0; i < state.nt_count; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];
        grammar_image_save_list(&state.nt_rule_ids[i], &nt->rule_ids);
        grammar_image_save_list(&state.nt_pending_annotations[i],
                                &nt->pending_annotations);
        grammar_image_save_dict(&state.nt_first_sets[i], nt->first_set);
        state.nt_process[i].action = nt->action;
        state.nt_process[i].user_data = nt->user_data;
        nt->action = nullptr;
        nt->user_data = nullptr;
        grammar_image_scrub_list(&nt->rule_ids);
        grammar_image_scrub_list(&nt->pending_annotations);
        grammar_image_scrub_dict(nt->first_set);
    }

    return state;
}

static void
grammar_image_restore_headers(n00b_grammar_t *g,
                              grammar_image_header_state_t state)
{
    grammar_image_restore_list(&g->rules, &state.rules);
    grammar_image_restore_list(&g->nt_list, &state.nt_list);
    grammar_image_restore_dict(g->nt_map, &state.nt_map);
    grammar_image_restore_dict(g->terminal_map, &state.terminal_map);
    grammar_image_restore_dict(g->literal_type_map, &state.literal_type_map);
    grammar_image_restore_dict(g->valid_tokens, &state.valid_tokens);
    grammar_image_restore_dict(g->terminal_by_id, &state.terminal_by_id);
    grammar_image_restore_dict(g->terminal_categories,
                               &state.terminal_categories);
    g->tokenize_cb     = state.tokenize_cb;
    g->default_action  = state.default_action;
    g->disambiguator   = state.disambiguator;

    for (size_t i = 0; i < state.rule_count; i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];
        grammar_image_restore_list(&rule->contents,
                                   &state.rule_contents[i]);
        grammar_image_restore_list(&rule->annotations,
                                   &state.rule_annotations[i]);
        grammar_image_restore_dict(rule->first_set,
                                   &state.rule_first_sets[i]);
        rule->thunk = state.rule_process[i].thunk;
    }

    for (size_t i = 0; i < state.nt_count; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];
        grammar_image_restore_list(&nt->rule_ids, &state.nt_rule_ids[i]);
        grammar_image_restore_list(&nt->pending_annotations,
                                   &state.nt_pending_annotations[i]);
        grammar_image_restore_dict(nt->first_set, &state.nt_first_sets[i]);
        nt->action    = state.nt_process[i].action;
        nt->user_data = state.nt_process[i].user_data;
    }
}

n00b_result_t(n00b_buffer_t *)
n00b_grammar_image_emit_object(n00b_grammar_t *g,
                               n00b_string_t *grammar_name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (g == nullptr || grammar_name == nullptr || grammar_name->data == nullptr
        || grammar_name->u8_bytes <= 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_NULL_ARG);
    }
    if (g->finalized == false) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_NOT_FINAL);
    }

    grammar_image_header_state_t header_state = grammar_image_scrub_headers(
        g,
        allocator);
    auto image_r = n00b_ct_image_export(g, .allocator = allocator);
    grammar_image_restore_headers(g, header_state);
    if (n00b_result_is_err(image_r)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_GRAMMAR_IMAGE_ERR_MARSHAL);
    }

    auto record_r = grammar_image_record(grammar_name,
                                         n00b_result_get(image_r),
                                         allocator);
    if (n00b_result_is_err(record_r)) {
        return record_r;
    }

    n00b_buffer_t *record = n00b_result_get(record_r);
#if defined(__APPLE__)
    return grammar_image_emit_macho_object(record, allocator);
#elif defined(__ELF__)
    return grammar_image_emit_elf_object(record, allocator);
#else
    return n00b_result_err(n00b_buffer_t *, N00B_GRAMMAR_IMAGE_ERR_OBJECT);
#endif
}
