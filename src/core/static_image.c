#define N00B_USE_INTERNAL_API

#include "core/static_image.h"
#include "core/string.h"
#include "core/gc.h"
#include "core/gc_baked.h"
#include "core/atomic.h"
#include "../crt/n00b_crt.h"
#include "slay/grammar_image.h"
#include "text/strings/string_ops.h"
#include "util/comptime_image.h"
#include "util/panic.h"

#include <string.h>

#if defined(__APPLE__)
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#endif

// ============================================================================
// Static grammar images (WP-018/WP-008)
// ============================================================================
//
// The live path discovers grammar-image records linked into the host object
// under the n00b_gimage section, relocates each image once, and registers the
// relocated allocation ranges with baked GC metadata.

#define N00B_STATIC_GRAMMAR_MAX 32

typedef enum {
    N00B_STATIC_GRAMMAR_SLOT_EMPTY = 0,
    N00B_STATIC_GRAMMAR_SLOT_BAKED,
} n00b_static_grammar_slot_kind_t;

typedef struct {
    n00b_static_grammar_slot_kind_t kind;
    const char                     *raw_name;
    uint32_t                        raw_name_len;
    n00b_grammar_t                 *materialized;
} n00b_static_grammar_slot_t;

static n00b_static_grammar_slot_t n00b_static_grammar_table[N00B_STATIC_GRAMMAR_MAX];
static int                        n00b_static_grammar_count = 0;
static _Atomic int                 n00b_static_grammar_discovery_state = 0;

static bool
n00b_static_grammar_raw_name_eq(const char *raw_name,
                                uint32_t raw_name_len,
                                n00b_string_t *name)
{
    if (raw_name == nullptr || name == nullptr || name->data == nullptr
        || name->u8_bytes < 0 || (uint64_t)name->u8_bytes != raw_name_len) {
        return false;
    }

    return memcmp(raw_name, name->data, raw_name_len) == 0;
}

static bool
n00b_static_grammar_slot_raw_eq(const n00b_static_grammar_slot_t *slot,
                                const char *raw_name,
                                uint32_t raw_name_len)
{
    return slot != nullptr
        && slot->kind == N00B_STATIC_GRAMMAR_SLOT_BAKED
        && slot->raw_name_len == raw_name_len
        && memcmp(slot->raw_name, raw_name, raw_name_len) == 0;
}

static bool
n00b_static_grammar_slot_name_eq(const n00b_static_grammar_slot_t *slot,
                                 n00b_string_t *name)
{
    return slot != nullptr
        && slot->kind == N00B_STATIC_GRAMMAR_SLOT_BAKED
        && n00b_static_grammar_raw_name_eq(slot->raw_name,
                                          slot->raw_name_len,
                                          name);
}

static void
n00b_static_grammar_register_baked(const char *raw_name,
                                   uint32_t raw_name_len,
                                   n00b_grammar_t *grammar)
{
    if (raw_name == nullptr || raw_name_len == 0 || grammar == nullptr) {
        return;
    }

    for (int i = 0; i < n00b_static_grammar_count; i++) {
        n00b_static_grammar_slot_t *slot = &n00b_static_grammar_table[i];
        if (!n00b_static_grammar_slot_raw_eq(slot, raw_name, raw_name_len)) {
            continue;
        }

        slot->kind         = N00B_STATIC_GRAMMAR_SLOT_BAKED;
        slot->raw_name     = raw_name;
        slot->raw_name_len = raw_name_len;
        slot->materialized = grammar;
        return;
    }

    if (n00b_static_grammar_count >= N00B_STATIC_GRAMMAR_MAX) {
        return;
    }

    n00b_static_grammar_slot_t *slot
        = &n00b_static_grammar_table[n00b_static_grammar_count++];
    slot->kind         = N00B_STATIC_GRAMMAR_SLOT_BAKED;
    slot->raw_name     = raw_name;
    slot->raw_name_len = raw_name_len;
    slot->materialized = grammar;
}

static size_t
n00b_static_grammar_align8(size_t n)
{
    return (n + 7u) & ~(size_t)7u;
}

static bool
n00b_static_grammar_record_bounds_ok(const n00b_grammar_image_record_t *rec,
                                     size_t remaining)
{
    if (rec == nullptr || rec->magic != N00B_GRAMMAR_IMAGE_RECORD_MAGIC
        || rec->version != N00B_GRAMMAR_IMAGE_RECORD_VERSION
        || rec->header_len != sizeof(n00b_grammar_image_record_t)
        || rec->record_len < rec->header_len
        || rec->record_len > remaining || rec->name_len == 0
        || rec->image_len == 0 || rec->image_off >= rec->record_len
        || rec->image_len > rec->record_len - rec->image_off
        || rec->header_len > rec->record_len
        || rec->name_len > rec->record_len - rec->header_len
        || n00b_static_grammar_align8(rec->header_len + rec->name_len)
               != rec->image_off) {
        return false;
    }

    return true;
}

static void
n00b_static_grammar_apply_record(void *record_base, size_t remaining)
{
    n00b_grammar_image_record_t rec = {};
    memcpy(&rec, record_base, sizeof(rec));
    if (!n00b_static_grammar_record_bounds_ok(&rec, remaining)) {
        return;
    }

    char *record = record_base;
    char *image  = record + rec.image_off;
    n00b_ct_image_repair_hook_t hook = {
        .fn = n00b_grammar_image_repair_hook,
    };

    [[n00b::nomap]] auto relocate_r =
        n00b_ct_image_relocate_inplace_ex(image, rec.image_len, &hook);
    if (n00b_result_is_err(relocate_r)) {
        return;
    }

    n00b_grammar_t *grammar = n00b_result_get(relocate_r);
    n00b_ct_image_header_t *hdr = (void *)image;
    auto identity_r = n00b_ct_image_root_identity(image, rec.image_len);
    if (n00b_result_is_err(identity_r)) {
        return;
    }
    auto identity_opt = n00b_result_get(identity_r);
    const n00b_static_identity_t *root_identity =
        n00b_option_is_set(identity_opt) ? n00b_option_get(identity_opt) : nullptr;

    n00b_gc_baked_region_t region = {
        .base           = image,
        .len            = rec.image_len,
        .marshal_stream = image + hdr->marshal_off,
        .marshal_len    = hdr->marshal_len,
        .root           = grammar,
        .root_identity  = root_identity,
        .writable       = false,
    };
    auto register_r = n00b_gc_register_baked_region(&region);
    if (n00b_result_is_err(register_r)) {
        return;
    }

    n00b_static_grammar_register_baked(record + rec.header_len,
                                       rec.name_len,
                                       grammar);
}

static void
n00b_static_grammar_apply_section(void *section_base, size_t section_len)
{
    if (section_base == nullptr
        || section_len < sizeof(n00b_grammar_image_record_t)) {
        return;
    }

    char *cur = section_base;
    char *end = cur + section_len;
    while ((size_t)(end - cur) >= sizeof(n00b_grammar_image_record_t)) {
        n00b_grammar_image_record_t rec = {};
        memcpy(&rec, cur, sizeof(rec));
        if (rec.magic == 0) {
            break;
        }
        if (!n00b_static_grammar_record_bounds_ok(&rec, (size_t)(end - cur))) {
            return;
        }

        n00b_static_grammar_apply_record(cur, (size_t)(end - cur));
        cur += n00b_static_grammar_align8(rec.record_len);
    }

    auto protect_r = n00b_crt_mark_readonly(section_base, section_len);
    if (n00b_result_is_err(protect_r)) {
        n00b_panic("static grammar image read-only protection failed");
    }
}

#if defined(__APPLE__)
static void
n00b_static_grammar_discover_sections(void)
{
    unsigned long size = 0;
    uint8_t *section = getsectiondata(&_mh_execute_header,
                                      N00B_GRAMMAR_IMAGE_SECTION_MACHO_SEG,
                                      N00B_GRAMMAR_IMAGE_SECTION_MACHO_SECT,
                                      &size);
    n00b_static_grammar_apply_section(section, (size_t)size);
}
#elif defined(_WIN32)
static void
n00b_static_grammar_discover_sections(void)
{
}
#else
[[gnu::weak]] extern uint8_t __start_n00b_gimage[];
[[gnu::weak]] extern uint8_t __stop_n00b_gimage[];

static void
n00b_static_grammar_discover_sections(void)
{
    if (__start_n00b_gimage == nullptr || __stop_n00b_gimage == nullptr
        || __stop_n00b_gimage < __start_n00b_gimage) {
        return;
    }

    n00b_static_grammar_apply_section(__start_n00b_gimage,
                                      (size_t)(__stop_n00b_gimage
                                               - __start_n00b_gimage));
}
#endif

static void
n00b_static_grammar_discover_once(void)
{
    enum { undiscovered = 0, discovering = 1, discovered = 2 };

    int state = n00b_atomic_load(&n00b_static_grammar_discovery_state);
    if (state == discovered) {
        return;
    }

    int expected = undiscovered;
    if (n00b_atomic_cas(&n00b_static_grammar_discovery_state,
                        &expected,
                        discovering)) {
        n00b_static_grammar_discover_sections();
        n00b_atomic_store(&n00b_static_grammar_discovery_state, discovered);
        return;
    }

    while (n00b_atomic_load(&n00b_static_grammar_discovery_state) == discovering) {
    }
}

n00b_option_t(n00b_grammar_t *)
n00b_static_grammar_lookup(n00b_string_t *name)
{
    if (name == nullptr || name->data == nullptr) {
        return n00b_option_none(n00b_grammar_t *);
    }

    n00b_static_grammar_discover_once();

    for (int i = 0; i < n00b_static_grammar_count; i++) {
        n00b_static_grammar_slot_t *slot = &n00b_static_grammar_table[i];
        if (!n00b_static_grammar_slot_name_eq(slot, name)) {
            continue;
        }
        if (slot->materialized == nullptr) {
            return n00b_option_none(n00b_grammar_t *);
        }
        return n00b_option_set(n00b_grammar_t *, slot->materialized);
    }

    return n00b_option_none(n00b_grammar_t *);
}
