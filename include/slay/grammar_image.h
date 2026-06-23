#pragma once

/**
 * @file grammar_image.h
 * @brief Build-time grammar object baking + runtime repair for a
 *        pre-compiled `n00b_grammar_t`.
 *
 * The runtime cost of parsing a `.bnf` file via the BNF metagrammar dominates
 * small single-file naudit invocations. This module lets the grammar be baked
 * at build time into a linkable object containing an offset-relocatable
 * comptime image, then looked up at runtime without reparsing the grammar.
 *
 * The image captures the finalized object graph exactly. Runtime relocation
 * applies marshal FNPATCH for exported function pointers and then calls
 * `n00b_grammar_image_repair_hook()` for grammar-specific dictionary hash and
 * process-local callback repair.
 */

#include "slay/grammar.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "adt/result.h"

#define N00B_GRAMMAR_IMAGE_RECORD_MAGIC   UINT32_C(0x6e306267)
#define N00B_GRAMMAR_IMAGE_RECORD_VERSION UINT16_C(1)

#define N00B_GRAMMAR_IMAGE_SECTION_ELF        r"n00b_gimage"
#define N00B_GRAMMAR_IMAGE_SECTION_MACHO_SEG  "__DATA"
#define N00B_GRAMMAR_IMAGE_SECTION_MACHO_SECT "n00b_gimage"
#define N00B_GRAMMAR_IMAGE_SECTION_PE         ".n00bgi$m"

/**
 * @brief Self-describing record stored in the grammar-image linker section.
 *
 * The bytes following this header are `name_len` UTF-8 bytes of grammar lookup
 * name, padding to 8-byte alignment, then the raw offset-relocatable comptime
 * image at `image_off`. All offsets are relative to the start of this record,
 * so the object format needs no relocation entries for the Phase 3 lookup path.
 */
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t header_len;
    uint32_t record_len;
    uint32_t name_len;
    uint32_t image_off;
    uint32_t image_len;
    uint32_t reserved;
} n00b_grammar_image_record_t;

/**
 * @brief Repair process-local callbacks after materializing a grammar image.
 *
 * Comptime images preserve pointer-bearing grammar state by construction, and
 * marshal FNPATCH restores exported function pointers that appear in scanned
 * pointer slots. Dictionary hash callbacks are function-pointer metadata, so
 * this repair rebinds them explicitly, clears optional grammar action hooks and
 * nonterminal user data, and re-resolves `tokenize_cb` from `tokenizer_name`
 * through the tokenizer registry.
 *
 * @param g  Relocated grammar image root, or null.
 */
extern void n00b_grammar_image_repair(n00b_grammar_t *g);

/**
 * @brief Post-relocation repair hook for a baked grammar image.
 *
 * Compatible with `n00b_ct_image_repair_fn_t`. The comptime image has already
 * been relocated in place and marshal FNPATCH has already run; this hook applies
 * grammar-specific hash and callback repair that FNPATCH cannot express.
 *
 * @param image_base  Start of the relocated image bytes (unused by this repair).
 * @param image_len   Length of the image region (unused by this repair).
 * @param root        Relocated `n00b_grammar_t *` root.
 * @param user        Caller context (unused).
 * @return            Ok(true). A null root is treated like
 *                    `n00b_grammar_image_repair(nullptr)` and is a no-op.
 *
 * @pre If @p root is non-null, it points at a relocated `n00b_grammar_t`.
 * @post Grammar dictionary hashes are rebound, action hooks and nonterminal
 *       user data are cleared, and `tokenize_cb` is either resolved from
 *       `tokenizer_name` or left null.
 */
extern n00b_result_t(bool)
n00b_grammar_image_repair_hook(void *image_base,
                               size_t image_len,
                               void *root,
                               void *user);

// ============================================================================
// Emitter (build-time)
// ============================================================================

/**
 * @brief Error codes for grammar image emission.
 *
 * Negative to avoid collision with `errno` (n00b-api-guidelines § 5.1).
 */
typedef enum {
    N00B_GRAMMAR_IMAGE_OK            = 0,
    N00B_GRAMMAR_IMAGE_ERR_NULL_ARG  = -1, ///< A required argument was null.
    N00B_GRAMMAR_IMAGE_ERR_NOT_FINAL = -2, ///< @p g was not finalized.
    N00B_GRAMMAR_IMAGE_ERR_MARSHAL   = -3, ///< @p g could not be marshaled.
    N00B_GRAMMAR_IMAGE_ERR_OBJECT    = -5, ///< Object/section emission failed.
} n00b_grammar_image_err_t;

/**
 * @brief Human-readable description for a grammar image emission error.
 *
 * @param err  An `n00b_grammar_image_err_t` value (passed as the generic
 *             `n00b_err_t` carried by `n00b_result_t`).
 * @return A static description string (never null).
 */
extern n00b_string_t *n00b_grammar_image_emit_err_str(n00b_err_t err);

/**
 * @brief Emit a grammar-specific comptime-image object.
 *
 * Exports @p g with the WP-005 offset-relocatable image format, wraps the raw
 * image and @p grammar_name in a self-describing grammar-image section record,
 * and returns linkable object bytes for supported host object formats. Mach-O
 * and ELF relocatable objects are supported; other host formats, including the
 * reserved PE section-name route, return @ref N00B_GRAMMAR_IMAGE_ERR_OBJECT
 * until their object writer is implemented.
 *
 * @param g             Finalized grammar to bake.
 * @param grammar_name  Lookup name carried in the section record.
 * @kw allocator        Optional allocator for returned object bytes.
 * @return Object bytes, or an error code from @ref n00b_grammar_image_err_t.
 *
 * @pre The n00b runtime is initialized and @p g is finalized.
 * @post The returned object has one grammar-image record and no legacy
 *       `_b64`, `_build`, `_register`, or base64-decode materializer source.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_grammar_image_emit_object(n00b_grammar_t *g,
                               n00b_string_t *grammar_name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};
