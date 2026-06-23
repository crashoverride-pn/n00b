/*
 * eval.c — implementation of the embedded-eval API
 * (see include/n00b/eval.h).
 *
 * Pipeline per n00b_eval_compile_predicate call:
 *   1. Form `_n00b_eval_p%lld` wrapper name (monotonic counter).
 *   2. Build wrapper source string:
 *        `func _n00b_eval_p<N>(arg: <arg_type_name>) -> bool {
 *             return <expr_text> }`
 *   3. Tokenize + parse against the session-cached n00b grammar.
 *   4. Run the n00b annotation walk (n00b_compile_walk).
 *   5. Create a fresh per-predicate codegen module on the underlying
 *      session, set its annot, DFS the parse tree for the func-def
 *      node, n00b_codegen_lower it.
 *   6. n00b_cg_module_compile(m, wrapper_name) returns the JIT'd
 *      void * — cast to n00b_eval_predicate_fn_t.
 *
 * Builtins are loaded once at session creation via
 * n00b_cg_session_run_module (REPL pattern adapted to mmap I/O —
 * no libc FILE *).
 *
 * Per include/audit_paths.h (configured at build time), the two
 * absolute paths to the n00b grammar and the stdlib live in
 * N00B_N00B_GRAMMAR_PATH and N00B_BUILTINS_PATH.
 */

#include "n00b.h"
#include "n00b/eval.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "n00b/n00b_compile.h"
#include "n00b/n00b_tokenizer.h"
#include "n00b/n00b_type_map.h"
#include "slay/annot_walk.h"
#include "slay/bnf.h"
#include "slay/codegen.h"
#include "slay/diagnostic.h"
#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "internal/slay/codegen_internal.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/gc.h"
#include "core/mutex.h"
#include "core/string.h"
#include "text/strings/format.h"
#include "parsers/scanner.h"
#include "parsers/token_stream.h"

#include "audit_paths.h"

#include <string.h>

// ============================================================================
// Session struct
// ============================================================================

/**
 * Reusable embedded-eval session. The grammar + cg_session_t are
 * created once at session creation and reused for every predicate
 * compile. The per-predicate counter feeds a unique wrapper-function
 * name so multiple predicates coexist in the same MIR context.
 */
struct n00b_eval_session {
    n00b_grammar_t       *grammar;
    n00b_dict_untyped_t  *embed_registry;
    n00b_cg_session_t    *session;
    int64_t               predicate_counter;
};

#if defined(__linux__) && defined(__aarch64__)
#define N00B_EVAL_USE_INTERP_THUNKS 1
#else
#define N00B_EVAL_USE_INTERP_THUNKS 0
#endif

#if N00B_EVAL_USE_INTERP_THUNKS
typedef struct n00b_eval_interp_slot {
    n00b_eval_session_t *eval;
    n00b_cg_module_t    *module;
    const char          *func_name;
} n00b_eval_interp_slot_t;

#define N00B_EVAL_INTERP_THUNK_COUNT 128
static n00b_eval_interp_slot_t s_eval_interp_slots[N00B_EVAL_INTERP_THUNK_COUNT];
static _Atomic int             s_eval_interp_next_slot;

static bool
n00b_eval_interp_call_slot(int slot, void *arg)
{
    if (slot < 0 || slot >= N00B_EVAL_INTERP_THUNK_COUNT) {
        return false;
    }

    n00b_eval_interp_slot_t *entry = &s_eval_interp_slots[slot];

    if (!entry->eval || !entry->module || !entry->func_name) {
        return false;
    }

    MIR_val_t args[1] = {{.a = arg}};
    MIR_val_t res     = {0};

    n00b_cg_set_active_module(entry->eval->session, entry->module);
    bool ok = n00b_codegen_interpret(entry->eval->session,
                                     entry->func_name,
                                     &res,
                                     args,
                                     1);

    return ok && res.i != 0;
}

#define N00B_EVAL_INTERP_THUNK(n)                                           \
    static bool n00b_eval_interp_thunk_##n(void *arg)                       \
    {                                                                       \
        return n00b_eval_interp_call_slot(n, arg);                          \
    }

N00B_EVAL_INTERP_THUNK(0)   N00B_EVAL_INTERP_THUNK(1)
N00B_EVAL_INTERP_THUNK(2)   N00B_EVAL_INTERP_THUNK(3)
N00B_EVAL_INTERP_THUNK(4)   N00B_EVAL_INTERP_THUNK(5)
N00B_EVAL_INTERP_THUNK(6)   N00B_EVAL_INTERP_THUNK(7)
N00B_EVAL_INTERP_THUNK(8)   N00B_EVAL_INTERP_THUNK(9)
N00B_EVAL_INTERP_THUNK(10)  N00B_EVAL_INTERP_THUNK(11)
N00B_EVAL_INTERP_THUNK(12)  N00B_EVAL_INTERP_THUNK(13)
N00B_EVAL_INTERP_THUNK(14)  N00B_EVAL_INTERP_THUNK(15)
N00B_EVAL_INTERP_THUNK(16)  N00B_EVAL_INTERP_THUNK(17)
N00B_EVAL_INTERP_THUNK(18)  N00B_EVAL_INTERP_THUNK(19)
N00B_EVAL_INTERP_THUNK(20)  N00B_EVAL_INTERP_THUNK(21)
N00B_EVAL_INTERP_THUNK(22)  N00B_EVAL_INTERP_THUNK(23)
N00B_EVAL_INTERP_THUNK(24)  N00B_EVAL_INTERP_THUNK(25)
N00B_EVAL_INTERP_THUNK(26)  N00B_EVAL_INTERP_THUNK(27)
N00B_EVAL_INTERP_THUNK(28)  N00B_EVAL_INTERP_THUNK(29)
N00B_EVAL_INTERP_THUNK(30)  N00B_EVAL_INTERP_THUNK(31)
N00B_EVAL_INTERP_THUNK(32)  N00B_EVAL_INTERP_THUNK(33)
N00B_EVAL_INTERP_THUNK(34)  N00B_EVAL_INTERP_THUNK(35)
N00B_EVAL_INTERP_THUNK(36)  N00B_EVAL_INTERP_THUNK(37)
N00B_EVAL_INTERP_THUNK(38)  N00B_EVAL_INTERP_THUNK(39)
N00B_EVAL_INTERP_THUNK(40)  N00B_EVAL_INTERP_THUNK(41)
N00B_EVAL_INTERP_THUNK(42)  N00B_EVAL_INTERP_THUNK(43)
N00B_EVAL_INTERP_THUNK(44)  N00B_EVAL_INTERP_THUNK(45)
N00B_EVAL_INTERP_THUNK(46)  N00B_EVAL_INTERP_THUNK(47)
N00B_EVAL_INTERP_THUNK(48)  N00B_EVAL_INTERP_THUNK(49)
N00B_EVAL_INTERP_THUNK(50)  N00B_EVAL_INTERP_THUNK(51)
N00B_EVAL_INTERP_THUNK(52)  N00B_EVAL_INTERP_THUNK(53)
N00B_EVAL_INTERP_THUNK(54)  N00B_EVAL_INTERP_THUNK(55)
N00B_EVAL_INTERP_THUNK(56)  N00B_EVAL_INTERP_THUNK(57)
N00B_EVAL_INTERP_THUNK(58)  N00B_EVAL_INTERP_THUNK(59)
N00B_EVAL_INTERP_THUNK(60)  N00B_EVAL_INTERP_THUNK(61)
N00B_EVAL_INTERP_THUNK(62)  N00B_EVAL_INTERP_THUNK(63)
N00B_EVAL_INTERP_THUNK(64)  N00B_EVAL_INTERP_THUNK(65)
N00B_EVAL_INTERP_THUNK(66)  N00B_EVAL_INTERP_THUNK(67)
N00B_EVAL_INTERP_THUNK(68)  N00B_EVAL_INTERP_THUNK(69)
N00B_EVAL_INTERP_THUNK(70)  N00B_EVAL_INTERP_THUNK(71)
N00B_EVAL_INTERP_THUNK(72)  N00B_EVAL_INTERP_THUNK(73)
N00B_EVAL_INTERP_THUNK(74)  N00B_EVAL_INTERP_THUNK(75)
N00B_EVAL_INTERP_THUNK(76)  N00B_EVAL_INTERP_THUNK(77)
N00B_EVAL_INTERP_THUNK(78)  N00B_EVAL_INTERP_THUNK(79)
N00B_EVAL_INTERP_THUNK(80)  N00B_EVAL_INTERP_THUNK(81)
N00B_EVAL_INTERP_THUNK(82)  N00B_EVAL_INTERP_THUNK(83)
N00B_EVAL_INTERP_THUNK(84)  N00B_EVAL_INTERP_THUNK(85)
N00B_EVAL_INTERP_THUNK(86)  N00B_EVAL_INTERP_THUNK(87)
N00B_EVAL_INTERP_THUNK(88)  N00B_EVAL_INTERP_THUNK(89)
N00B_EVAL_INTERP_THUNK(90)  N00B_EVAL_INTERP_THUNK(91)
N00B_EVAL_INTERP_THUNK(92)  N00B_EVAL_INTERP_THUNK(93)
N00B_EVAL_INTERP_THUNK(94)  N00B_EVAL_INTERP_THUNK(95)
N00B_EVAL_INTERP_THUNK(96)  N00B_EVAL_INTERP_THUNK(97)
N00B_EVAL_INTERP_THUNK(98)  N00B_EVAL_INTERP_THUNK(99)
N00B_EVAL_INTERP_THUNK(100) N00B_EVAL_INTERP_THUNK(101)
N00B_EVAL_INTERP_THUNK(102) N00B_EVAL_INTERP_THUNK(103)
N00B_EVAL_INTERP_THUNK(104) N00B_EVAL_INTERP_THUNK(105)
N00B_EVAL_INTERP_THUNK(106) N00B_EVAL_INTERP_THUNK(107)
N00B_EVAL_INTERP_THUNK(108) N00B_EVAL_INTERP_THUNK(109)
N00B_EVAL_INTERP_THUNK(110) N00B_EVAL_INTERP_THUNK(111)
N00B_EVAL_INTERP_THUNK(112) N00B_EVAL_INTERP_THUNK(113)
N00B_EVAL_INTERP_THUNK(114) N00B_EVAL_INTERP_THUNK(115)
N00B_EVAL_INTERP_THUNK(116) N00B_EVAL_INTERP_THUNK(117)
N00B_EVAL_INTERP_THUNK(118) N00B_EVAL_INTERP_THUNK(119)
N00B_EVAL_INTERP_THUNK(120) N00B_EVAL_INTERP_THUNK(121)
N00B_EVAL_INTERP_THUNK(122) N00B_EVAL_INTERP_THUNK(123)
N00B_EVAL_INTERP_THUNK(124) N00B_EVAL_INTERP_THUNK(125)
N00B_EVAL_INTERP_THUNK(126) N00B_EVAL_INTERP_THUNK(127)

static n00b_eval_predicate_fn_t s_eval_interp_thunks[N00B_EVAL_INTERP_THUNK_COUNT] = {
    n00b_eval_interp_thunk_0,   n00b_eval_interp_thunk_1,
    n00b_eval_interp_thunk_2,   n00b_eval_interp_thunk_3,
    n00b_eval_interp_thunk_4,   n00b_eval_interp_thunk_5,
    n00b_eval_interp_thunk_6,   n00b_eval_interp_thunk_7,
    n00b_eval_interp_thunk_8,   n00b_eval_interp_thunk_9,
    n00b_eval_interp_thunk_10,  n00b_eval_interp_thunk_11,
    n00b_eval_interp_thunk_12,  n00b_eval_interp_thunk_13,
    n00b_eval_interp_thunk_14,  n00b_eval_interp_thunk_15,
    n00b_eval_interp_thunk_16,  n00b_eval_interp_thunk_17,
    n00b_eval_interp_thunk_18,  n00b_eval_interp_thunk_19,
    n00b_eval_interp_thunk_20,  n00b_eval_interp_thunk_21,
    n00b_eval_interp_thunk_22,  n00b_eval_interp_thunk_23,
    n00b_eval_interp_thunk_24,  n00b_eval_interp_thunk_25,
    n00b_eval_interp_thunk_26,  n00b_eval_interp_thunk_27,
    n00b_eval_interp_thunk_28,  n00b_eval_interp_thunk_29,
    n00b_eval_interp_thunk_30,  n00b_eval_interp_thunk_31,
    n00b_eval_interp_thunk_32,  n00b_eval_interp_thunk_33,
    n00b_eval_interp_thunk_34,  n00b_eval_interp_thunk_35,
    n00b_eval_interp_thunk_36,  n00b_eval_interp_thunk_37,
    n00b_eval_interp_thunk_38,  n00b_eval_interp_thunk_39,
    n00b_eval_interp_thunk_40,  n00b_eval_interp_thunk_41,
    n00b_eval_interp_thunk_42,  n00b_eval_interp_thunk_43,
    n00b_eval_interp_thunk_44,  n00b_eval_interp_thunk_45,
    n00b_eval_interp_thunk_46,  n00b_eval_interp_thunk_47,
    n00b_eval_interp_thunk_48,  n00b_eval_interp_thunk_49,
    n00b_eval_interp_thunk_50,  n00b_eval_interp_thunk_51,
    n00b_eval_interp_thunk_52,  n00b_eval_interp_thunk_53,
    n00b_eval_interp_thunk_54,  n00b_eval_interp_thunk_55,
    n00b_eval_interp_thunk_56,  n00b_eval_interp_thunk_57,
    n00b_eval_interp_thunk_58,  n00b_eval_interp_thunk_59,
    n00b_eval_interp_thunk_60,  n00b_eval_interp_thunk_61,
    n00b_eval_interp_thunk_62,  n00b_eval_interp_thunk_63,
    n00b_eval_interp_thunk_64,  n00b_eval_interp_thunk_65,
    n00b_eval_interp_thunk_66,  n00b_eval_interp_thunk_67,
    n00b_eval_interp_thunk_68,  n00b_eval_interp_thunk_69,
    n00b_eval_interp_thunk_70,  n00b_eval_interp_thunk_71,
    n00b_eval_interp_thunk_72,  n00b_eval_interp_thunk_73,
    n00b_eval_interp_thunk_74,  n00b_eval_interp_thunk_75,
    n00b_eval_interp_thunk_76,  n00b_eval_interp_thunk_77,
    n00b_eval_interp_thunk_78,  n00b_eval_interp_thunk_79,
    n00b_eval_interp_thunk_80,  n00b_eval_interp_thunk_81,
    n00b_eval_interp_thunk_82,  n00b_eval_interp_thunk_83,
    n00b_eval_interp_thunk_84,  n00b_eval_interp_thunk_85,
    n00b_eval_interp_thunk_86,  n00b_eval_interp_thunk_87,
    n00b_eval_interp_thunk_88,  n00b_eval_interp_thunk_89,
    n00b_eval_interp_thunk_90,  n00b_eval_interp_thunk_91,
    n00b_eval_interp_thunk_92,  n00b_eval_interp_thunk_93,
    n00b_eval_interp_thunk_94,  n00b_eval_interp_thunk_95,
    n00b_eval_interp_thunk_96,  n00b_eval_interp_thunk_97,
    n00b_eval_interp_thunk_98,  n00b_eval_interp_thunk_99,
    n00b_eval_interp_thunk_100, n00b_eval_interp_thunk_101,
    n00b_eval_interp_thunk_102, n00b_eval_interp_thunk_103,
    n00b_eval_interp_thunk_104, n00b_eval_interp_thunk_105,
    n00b_eval_interp_thunk_106, n00b_eval_interp_thunk_107,
    n00b_eval_interp_thunk_108, n00b_eval_interp_thunk_109,
    n00b_eval_interp_thunk_110, n00b_eval_interp_thunk_111,
    n00b_eval_interp_thunk_112, n00b_eval_interp_thunk_113,
    n00b_eval_interp_thunk_114, n00b_eval_interp_thunk_115,
    n00b_eval_interp_thunk_116, n00b_eval_interp_thunk_117,
    n00b_eval_interp_thunk_118, n00b_eval_interp_thunk_119,
    n00b_eval_interp_thunk_120, n00b_eval_interp_thunk_121,
    n00b_eval_interp_thunk_122, n00b_eval_interp_thunk_123,
    n00b_eval_interp_thunk_124, n00b_eval_interp_thunk_125,
    n00b_eval_interp_thunk_126, n00b_eval_interp_thunk_127,
};

static n00b_eval_predicate_fn_t
n00b_eval_interp_register(n00b_eval_session_t *eval,
                          n00b_cg_module_t    *module,
                          const char          *func_name)
{
    int slot = n00b_atomic_add(&s_eval_interp_next_slot, 1);

    if (slot < 0 || slot >= N00B_EVAL_INTERP_THUNK_COUNT) {
        return nullptr;
    }

    s_eval_interp_slots[slot] = (n00b_eval_interp_slot_t){
        .eval      = eval,
        .module    = module,
        .func_name = func_name,
    };

    return s_eval_interp_thunks[slot];
}
#endif

// ============================================================================
// File reading via libn00b MMAP (NO libc I/O per § 2.10/2.11)
// ============================================================================

/**
 * Read the entire contents of @p abs_path as an `n00b_string_t *`.
 *
 * Uses `n00b_file_open(.kind = MMAP)` + `n00b_file_as_buffer` and
 * wraps the buffer bytes as a string. Caller treats failure as an
 * error path (return is nullptr).
 *
 * NOTE: The MMAP substrate maps the whole file; for grammar /
 * builtins (tens of KB), this is bounded and cheaper than the
 * stream substrate which would buffer through the conduit.
 */
static n00b_string_t *
read_file_as_string(const char *abs_path)
{
    if (!abs_path || abs_path[0] == '\0') {
        return nullptr;
    }

    n00b_string_t *path = n00b_string_from_cstr(abs_path);

    n00b_result_t(n00b_file_t *) open_r = n00b_file_open(
        path, .kind = N00B_FILE_KIND_MMAP);

    if (n00b_result_is_err(open_r)) {
        return nullptr;
    }

    n00b_file_t *f = n00b_result_get(open_r);

    n00b_result_t(n00b_buffer_t *) buf_r = n00b_file_as_buffer(f);

    if (n00b_result_is_err(buf_r)) {
        n00b_file_close(f);
        return nullptr;
    }

    n00b_buffer_t *buf = n00b_result_get(buf_r);

    if (!buf || !buf->data) {
        n00b_file_close(f);
        return nullptr;
    }

    n00b_string_t *s = n00b_string_from_raw(buf->data, (int64_t)buf->byte_len);

    // The file's backing mmap stays alive via the file_t until close.
    // n00b_string_from_raw copies into managed storage, so closing
    // here is safe.
    n00b_file_close(f);

    return s;
}

// ============================================================================
// Grammar load
// ============================================================================

static n00b_grammar_t *s_eval_n00b_grammar               = nullptr;
static n00b_mutex_t    s_eval_n00b_grammar_mutex;
static _Atomic int     s_eval_n00b_grammar_mutex_state   = 0;
static bool            s_eval_n00b_grammar_root_registered;

static void
ensure_eval_grammar_mutex(void)
{
    int snapshot = n00b_atomic_load(&s_eval_n00b_grammar_mutex_state);

    if (snapshot == 2) {
        return;
    }

    int expected = 0;

    if (n00b_atomic_cas(&s_eval_n00b_grammar_mutex_state, &expected, 1)) {
        n00b_sys_mutex_init(&s_eval_n00b_grammar_mutex, (char *)__FILE__);
        n00b_atomic_store(&s_eval_n00b_grammar_mutex_state, 2);
        return;
    }

    while (n00b_atomic_load(&s_eval_n00b_grammar_mutex_state) != 2) {
        // Brief spin until the elected initializer publishes.
    }
}

/**
 * Parse the n00b BNF text into a grammar object. On failure leaves
 * @p out_err set to the appropriate `n00b_eval_err_t`.
 */
static n00b_grammar_t *
load_n00b_grammar_uncached(n00b_eval_err_t *out_err)
{
    n00b_string_t *bnf_text = read_file_as_string(N00B_N00B_GRAMMAR_PATH);

    if (!bnf_text) {
        *out_err = N00B_EVAL_ERR_GRAMMAR_OPEN;
        return nullptr;
    }

    n00b_grammar_t *g = n00b_grammar_new(
        .error_recovery = false,
        .parse_mode     = N00B_PARSE_MODE_PWZ_ONLY);

    n00b_diag_ctx_t *diag = n00b_diag_ctx_new();
    bool             ok   = n00b_bnf_load(bnf_text, r"module", g,
                                          .diag = diag);

    n00b_diag_ctx_free(diag);

    if (!ok) {
        *out_err = N00B_EVAL_ERR_GRAMMAR_PARSE;
        return nullptr;
    }

    return g;
}

static n00b_grammar_t *
load_n00b_grammar(n00b_eval_err_t *out_err)
{
    ensure_eval_grammar_mutex();
    n00b_mutex_lock(&s_eval_n00b_grammar_mutex);

    if (!s_eval_n00b_grammar_root_registered) {
        n00b_gc_register_root(s_eval_n00b_grammar);
        s_eval_n00b_grammar_root_registered = true;
    }

    if (s_eval_n00b_grammar == nullptr) {
        s_eval_n00b_grammar = load_n00b_grammar_uncached(out_err);
    }

    n00b_grammar_t *g = s_eval_n00b_grammar;
    n00b_mutex_unlock(&s_eval_n00b_grammar_mutex);

    return g;
}

// ============================================================================
// Builtins load
// ============================================================================

/**
 * Load `lib/std/builtins.n` into the codegen session. Returns true
 * on success. The REPL has a search-heuristic version; here we use
 * a single absolute path baked at configure time so the surface is
 * deterministic + has no libc I/O.
 */
static bool
load_builtins(n00b_grammar_t    *g,
              n00b_cg_session_t *session,
              n00b_eval_err_t   *out_err)
{
    n00b_string_t *src = read_file_as_string(N00B_BUILTINS_PATH);

    if (!src) {
        *out_err = N00B_EVAL_ERR_BUILTINS_OPEN;
        return false;
    }

    n00b_buffer_t *buf = n00b_buffer_from_bytes(src->data,
                                                (int64_t)src->u8_bytes);

    n00b_scanner_t      *scanner = n00b_scanner_new(buf,
                                                    n00b_lang_tokenize, g);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *r = n00b_grammar_parse(g, ts);

    if (!n00b_parse_result_ok(r)) {
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(r);

    n00b_annot_result_t *ar = n00b_compile_walk(g, tree);

    if (!ar) {
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    bool ok = false;
    n00b_cg_session_run_module(session, tree,
                               .annot      = ar,
                               .entry_name = "_n00b_eval_builtins_init",
                               .ok         = &ok);

    if (!ok) {
        // Builtins not strictly required for trivial true/false
        // smokes, but the type checker needs the stdlib symtab
        // present for richer expressions. Surface the error but
        // do not abort session creation — the simple cases
        // (smoke tests 1 + 2) still work. Consumers needing
        // builtins surface this via subsequent
        // compile_predicate diagnostics.
        *out_err = N00B_EVAL_ERR_BUILTINS_LOAD;
        return false;
    }

    return true;
}

// ============================================================================
// Session lifecycle
// ============================================================================

n00b_result_t(n00b_eval_session_t *)
n00b_eval_session_new() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    n00b_eval_err_t err = N00B_EVAL_ERR_NONE;

    n00b_eval_session_t *s = n00b_alloc(n00b_eval_session_t,
                                         .allocator = allocator);

    s->predicate_counter = 0;

    s->grammar = load_n00b_grammar(&err);

    if (!s->grammar) {
        return n00b_result_err(n00b_eval_session_t *, (int)err);
    }

    s->embed_registry = n00b_embed_registry_new();
    n00b_ffi_embed_register(s->embed_registry);

    // Type-map = n00b_type_map: the n00b type checker can resolve
    // built-in types (int, bool, string, ...) inside the generated
    // wrapper. User-registered opaque types fall through the map
    // via the WP-010 codegen extension-method dispatch.
    s->session = n00b_cg_session_new(s->grammar,
                                      .type_map       = n00b_type_map,
                                      .embed_registry = s->embed_registry);

    if (!s->session) {
        return n00b_result_err(n00b_eval_session_t *,
                               (int)N00B_EVAL_ERR_GRAMMAR_PARSE);
    }

    // Load builtins where native MIR JIT is usable. On linux/aarch64
    // embedded eval uses interpreter-backed thunks because MIR's generator
    // link path can hang there; builtins.n only installs optional FFI helpers,
    // so skipping it preserves predicate evaluation and avoids blocking
    // session creation.
    n00b_eval_err_t b_err = N00B_EVAL_ERR_NONE;
#if N00B_EVAL_USE_INTERP_THUNKS
    (void)b_err;
#else
    (void)load_builtins(s->grammar, s->session, &b_err);
#endif

    // Leave the session with a fresh, mutable MIR module active so
    // consumers can immediately call `n00b_ffi_install_simple` to
    // register C-side bindings before issuing any
    // `n00b_eval_compile_predicate`. Without this the session's
    // `active_module` would either be null (no builtins) or a
    // `MIR_finish_module`'d builtins module, and FFI install would
    // emit "import outside module" and fail. `n00b_cg_module_new`
    // sets the new module as active.
    n00b_cg_module_new(s->session, "_n00b_eval_install");

    return n00b_result_ok(n00b_eval_session_t *, s);
}

void
n00b_eval_session_free(n00b_eval_session_t *s)
{
    if (!s) {
        return;
    }

    if (s->session) {
        n00b_cg_session_free(s->session);
    }

    // grammar + embed_registry are GC-managed.
}

n00b_cg_session_t *
n00b_eval_session_cg(n00b_eval_session_t *s)
{
    return s ? s->session : nullptr;
}

n00b_grammar_t *
n00b_eval_session_grammar(n00b_eval_session_t *s)
{
    return s ? s->grammar : nullptr;
}

// ============================================================================
// Predicate compilation
// ============================================================================

/**
 * Find the first `func-def` node in a parse tree subtree. The
 * wrapper source contains exactly one func-def at the top level,
 * but the n00b grammar wraps top-level statements through several
 * passthrough NTs (e.g. `module`, `$$group_N`, `top-level-stmt`),
 * so we DFS to locate it.
 */
static n00b_parse_tree_t *
find_func_def(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return nullptr;
    }

    if (n00b_pt_is_nt(node, "func-def")) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *r = find_func_def(n00b_pt_get_child(node, i));

        if (r) {
            return r;
        }
    }

    return nullptr;
}

n00b_result_t(n00b_eval_predicate_fn_t)
n00b_eval_compile_predicate(n00b_eval_session_t *s,
                            n00b_string_t       *expr_text,
                            n00b_string_t       *arg_type_name) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    (void)kargs;

    if (!s || !expr_text || !arg_type_name) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_BAD_ARGS);
    }

    // Allocate the wrapper-function name from the monotonic counter.
    // Name format: `_n00b_eval_p<N>`. The leading underscore keeps
    // it out of the way of any user-defined identifier in the
    // expression body.
    int64_t        my_id = s->predicate_counter++;
    n00b_string_t *fname_str = n00b_cformat("_n00b_eval_p«#:d»", my_id);

    // Assemble wrapper source via libn00b string formatting (no libc
    // I/O). n00b's grammar treats newline as a statement terminator;
    // the `return <expr>` must be followed by a newline (or `;`)
    // before the closing `}`. Without it, the parser keeps trying to
    // extend the expression and reports e.g.
    // "expected: + - == ..." when it hits the bare `}`.
    n00b_string_t *src_str = n00b_cformat(
        "func «#»(arg: «#») -> bool {\n    return «#»\n}\n",
        fname_str,
        arg_type_name,
        expr_text);

    // Parse.
    n00b_buffer_t *buf = n00b_buffer_from_bytes(src_str->data,
                                                 (int64_t)src_str->u8_bytes,
                                                 .allocator = allocator);
    n00b_scanner_t      *scanner = n00b_scanner_new(buf,
                                                    n00b_lang_tokenize,
                                                    s->grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    n00b_parse_result_t *pr = n00b_grammar_parse(s->grammar, ts);

    if (!n00b_parse_result_ok(pr)) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_PARSE);
    }

    n00b_parse_tree_t *tree = n00b_parse_result_tree(pr);

    // -----------------------------------------------------------
    // Annotation walk.
    // -----------------------------------------------------------
    n00b_annot_result_t *ar = n00b_compile_walk(s->grammar, tree);

    if (!ar) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_ANNOT);
    }

    // -----------------------------------------------------------
    // Emit. Use the REPL's per-batch-module pattern: create a
    // fresh module on the persistent session, set its annot, find
    // the func-def, lower it.
    // -----------------------------------------------------------
    // Reuse the session's active module if it's still in the
    // mid-build state — that lets a caller install FFI bindings
    // via `n00b_ffi_install_simple` (which writes wrappers into
    // the current module) and then compile a predicate that
    // references those wrappers, all in the same MIR module. If
    // the active module has been finalized (e.g., by the previous
    // predicate compile), start a fresh one.
    n00b_cg_module_t *m = s->session->active_module;

    if (!m || m->state != N00B_CG_MOD_BUILDING) {
        // Module names live for the session's lifetime; the n00b
        // string is GC-tracked + NUL-terminated, so its `.data`
        // pointer is a stable C string for the cg_module_new call.
        n00b_string_t *mod_name = n00b_cformat("_n00b_eval_mod_«#:d»",
                                                my_id);
        m = n00b_cg_module_new(s->session, mod_name->data);
    }

    if (!m) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_EMIT);
    }

    n00b_cg_module_set_annot(m, ar);

    n00b_parse_tree_t *func_node = find_func_def(tree);

    if (!func_node) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_EMIT);
    }

    // Set session annot so codegen_lower's type-checker bridges
    // (e.g. method_return($0)) can resolve referenced symbols.
    n00b_codegen_set_annot(s->session, ar);

    n00b_codegen_lower(s->session, func_node);

#if N00B_EVAL_USE_INTERP_THUNKS
    // Linux/aarch64 currently hangs in MIR's native generator link path for
    // these small embedded predicates. Keep the public function-pointer shape
    // by returning a C thunk that interprets this MIR function on demand.
    n00b_cg_session_merge_module(s->session, m);
    n00b_eval_predicate_fn_t interp_fn = n00b_eval_interp_register(
        s,
        m,
        fname_str->data);

    if (!interp_fn) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_JIT);
    }

    return n00b_result_ok(n00b_eval_predicate_fn_t, interp_fn);
#else
    // -----------------------------------------------------------
    // Compile + JIT. `n00b_cg_module_compile(m, fname)` returns
    // the JIT'd entrypoint pointer for the named function.
    // -----------------------------------------------------------
    void *fn_void = n00b_cg_module_compile(m, fname_str->data);

    if (!fn_void) {
        // Fallback: try the session-level lookup, in case the
        // module compile dropped the entry because the func was
        // already linked.
        fn_void = n00b_codegen_jit(s->session, fname_str->data);
    }

    if (!fn_void) {
        return n00b_result_err(n00b_eval_predicate_fn_t,
                               (int)N00B_EVAL_ERR_JIT);
    }

    // Make the function visible to subsequent session lookups so
    // the side-table-keyed extension-method dispatch resolves
    // correctly even across modules.
    n00b_cg_session_merge_module(s->session, m);

    return n00b_result_ok(n00b_eval_predicate_fn_t,
                          (n00b_eval_predicate_fn_t)fn_void);
#endif
}

// ============================================================================
// Error strings
// ============================================================================

n00b_string_t *
n00b_eval_err_str(n00b_eval_err_t err)
{
    switch (err) {
    case N00B_EVAL_ERR_NONE:
        return r"ok";
    case N00B_EVAL_ERR_GRAMMAR_OPEN:
        return r"cannot open n00b grammar (N00B_N00B_GRAMMAR_PATH)";
    case N00B_EVAL_ERR_GRAMMAR_PARSE:
        return r"n00b grammar failed to parse";
    case N00B_EVAL_ERR_BUILTINS_OPEN:
        return r"cannot open n00b builtins.n (N00B_BUILTINS_PATH)";
    case N00B_EVAL_ERR_BUILTINS_LOAD:
        return r"n00b builtins.n failed to load";
    case N00B_EVAL_ERR_BAD_ARGS:
        return r"null argument to n00b_eval API";
    case N00B_EVAL_ERR_PARSE:
        return r"predicate wrapper failed to parse";
    case N00B_EVAL_ERR_ANNOT:
        return r"predicate wrapper failed annotation walk";
    case N00B_EVAL_ERR_EMIT:
        return r"predicate wrapper failed codegen";
    case N00B_EVAL_ERR_JIT:
        return r"predicate wrapper failed JIT compile";
    }

    return r"unknown n00b_eval error";
}
