#pragma once

/**
 * @file commander.h
 * @brief Grammar-based command-line parser.
 *
 * Commander builds a formal Earley grammar from a command-line specification,
 * then parses argv against it. This gives unambiguous, predictable parsing
 * with proper error reporting.
 *
 * Three ways to define a command-line interface:
 *
 *  1. **Programmatic builder** — call n00b_cmdr_add_command(),
 *     n00b_cmdr_add_flag(), etc. to build the spec in code.
 *  2. **JSON spec** — pass a JSON string to n00b_cmdr_from_json().
 *  3. **Raw BNF** — pass a BNF grammar string to n00b_cmdr_from_bnf().
 *
 * After defining the interface, parse with n00b_cmdr_parse() (argc/argv)
 * or n00b_cmdr_parse_string() (single string). Query results with
 * n00b_cmdr_flag_*() and n00b_cmdr_arg_*().
 */

#include "slay/grammar.h"
#include "slay/n00b_parse.h"
#include "slay/parse_tree.h"
#include "parsers/token_stream.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/variant.h"

// ============================================================================
// Token type indices (used as n00b_cmdr_t.tok_ids[] indices)
// ============================================================================

enum {
    N00B_CMDR_TID_WORD  = 0, /**< Generic word token. */
    N00B_CMDR_TID_INT   = 1, /**< Integer literal. */
    N00B_CMDR_TID_FLOAT = 2, /**< Float literal. */
    N00B_CMDR_TID_BOOL  = 3, /**< Boolean literal. */
    N00B_CMDR_TID_EQ    = 4, /**< Equals sign in --flag=value. */
    N00B_CMDR_TID_COMMA = 5, /**< Comma separator (reserved). */
    N00B_CMDR_TID_DD    = 6, /**< Double-dash separator "--". */
    N00B_CMDR_TID_FLAG  = 7, /**< Unknown flag (passed through). */
    N00B_CMDR_TID_COUNT = 8, /**< Number of token type slots. */
};

// ============================================================================
// Types
// ============================================================================

/** @brief Argument type for flags and positional arguments. */
typedef enum {
    N00B_CMDR_TYPE_BOOL,  /**< Boolean (no value, or "true"/"false"/"yes"/"no"). */
    N00B_CMDR_TYPE_WORD,  /**< Arbitrary string. */
    N00B_CMDR_TYPE_INT,   /**< Integer (parsed with strtoll). */
    N00B_CMDR_TYPE_FLOAT, /**< Floating-point (parsed with strtod). */
} n00b_cmdr_arg_type_t;

/**
 * @brief A tagged value from a parsed flag.
 *
 * Expressed as an `n00b_variant_t` over the five value shapes below. The
 * variant's `selector` is the discriminator: dispatch with
 * `n00b_variant_is_type` / `n00b_variant_get`. An empty/unset value (the
 * old @c N00B_CMDR_VAL_NONE) is `selector == 0` — test with
 * `n00b_variant_is_set`.
 *
 * For flags declared with @c n00b_cmdr_add_flag_multi (or
 * @c "multi": true in the JSON spec), the active arm is the
 * @c n00b_list_t(n00b_string_t *) — a list holding each occurrence (or
 * comma-separated element) in order.
 */
typedef n00b_variant_t(bool,
                       int64_t,
                       double,
                       n00b_string_t *,
                       n00b_list_t(n00b_string_t *)) n00b_cmdr_val_t;

/** @brief A positional argument with raw string and pre-parsed numeric values. */
typedef struct n00b_cmdr_arg {
    n00b_string_t *value;     /**< Raw string value. */
    int64_t       int_val;   /**< Value parsed as integer (0 if not numeric). */
    double        float_val; /**< Value parsed as float (0.0 if not numeric). */
} n00b_cmdr_arg_t;

/**
 * @brief Specification for a single flag (e.g., --verbose, -o).
 *
 * Flags that take a value (takes_value == true) accept both
 * "--flag value" and "--flag=value" syntax.
 *
 * When @c multi is true, repeated occurrences accumulate into a
 * list-arm value, and the value-parse site splits an
 * unescaped `,` separator into multiple elements (with `\,` → literal
 * `,`). Default is false: repeated occurrences are last-write-wins
 * and the raw value is preserved verbatim.
 */
typedef struct n00b_cmdr_flag_spec {
    n00b_string_t       *name;        /**< Long name including dashes (e.g., "--output"). */
    n00b_string_t       *short_name;  /**< Short alias (e.g., "-o"), or empty. */
    n00b_cmdr_arg_type_t value_type; /**< Type of the flag's value. */
    bool                takes_value; /**< Whether this flag expects a value argument. */
    n00b_string_t       *doc;         /**< Human-readable description, or empty. */
    int64_t             terminal_id; /**< Grammar terminal ID (set during finalize). */
    bool                has_short;   /**< True if short_name is set. */
    bool                multi;       /**< Repeatable + comma-split flag (see above). */
} n00b_cmdr_flag_spec_t;

/**
 * @brief Specification for a positional argument slot.
 *
 * Use max=-1 for unlimited.
 */
typedef struct n00b_cmdr_positional_spec {
    n00b_string_t       *name; /**< Display name (e.g., "file"). */
    n00b_cmdr_arg_type_t type; /**< Expected type of the argument. */
    int                  min;  /**< Minimum number of arguments required. */
    int                  max;  /**< Maximum number of arguments (-1 = unlimited). */
} n00b_cmdr_positional_spec_t;

/** @brief A command or subcommand with its flags and positional args. */
typedef struct n00b_cmdr_command n00b_cmdr_command_t;

struct n00b_cmdr_command {
    n00b_string_t                           *name;        /**< Command name, or empty for root. */
    n00b_string_t                           *doc;         /**< Description, or empty. */
    n00b_list_t(n00b_cmdr_flag_spec_t)       flags;       /**< Flag specs. */
    n00b_list_t(n00b_cmdr_positional_spec_t) positionals; /**< Positional arg specs. */
    n00b_list_t(n00b_cmdr_command_t)         subcommands; /**< Subcommands. */
    n00b_nonterm_t                          *nt;          /**< Grammar non-terminal (internal). */
    bool                                     has_name;    /**< True if name is set. */
};

/**
 * @brief The main commander instance.
 *
 * Create with n00b_cmdr_new() (programmatic), n00b_cmdr_from_json(),
 * or n00b_cmdr_from_bnf().
 */
typedef struct n00b_cmdr {
    n00b_grammar_t     *grammar;                       /**< Underlying grammar. */
    n00b_cmdr_command_t root;                           /**< Root command. */
    int64_t             next_flag_id;                   /**< Next terminal ID for flags. */
    bool                finalized;                      /**< True after grammar is built. */
    n00b_string_t      *name;                           /**< Program name. */
    int64_t             tok_ids[N00B_CMDR_TID_COUNT];   /**< Terminal IDs for base token types. */
    n00b_string_t      *bnf_text;                       /**< BNF source (BNF mode only). */
    n00b_string_t      *start_symbol;                   /**< BNF start symbol. */
    bool                has_bnf;                        /**< True if bnf_text is set. */
} n00b_cmdr_t;

/**
 * @brief Parse result from n00b_cmdr_parse() or n00b_cmdr_parse_string().
 *
 * Check r->ok first. On success, query with n00b_cmdr_result_command(),
 * n00b_cmdr_flag_*(), and n00b_cmdr_arg_*(). On failure, r->errors
 * contains diagnostic messages.
 */
typedef struct n00b_cmdr_result {
    n00b_string_t               *command;  /**< Matched subcommand name, or empty. */
    n00b_dict_t(n00b_string_t *, n00b_cmdr_val_t *) flags; /**< Parsed flags: string key -> n00b_cmdr_val_t *. */
    n00b_list_t(n00b_cmdr_arg_t) args;     /**< Positional arguments. */
    n00b_list_t(n00b_string_t *)   errors;   /**< Error messages (on failure). */
    bool                         ok;       /**< True if parsing succeeded. */
    bool                         has_cmd;  /**< True if command is set. */
    n00b_parse_tree_t           *tree;     /**< Raw parse tree (advanced use). */
} n00b_cmdr_result_t;

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * @brief Create an empty commander for the programmatic builder API.
 * @return New commander instance. Caller must n00b_cmdr_free().
 */
n00b_cmdr_t *n00b_cmdr_new(void);

/**
 * @brief Create a commander from a raw BNF grammar string.
 *
 * @param bnf           BNF grammar text.
 * @param start_symbol  Name of the start non-terminal.
 * @return Finalized commander, or NULL on grammar error.
 */
n00b_cmdr_t *n00b_cmdr_from_bnf(n00b_string_t *bnf, n00b_string_t *start_symbol);

/**
 * @brief Create a commander from a JSON specification string.
 *
 * The JSON object can contain:
 *   - `"name"`: (string) Program name.
 *   - `"options"`: (object) Global flags, keyed by flag name.
 *   - `"commands"`: (object) Subcommands, keyed by command name.
 *
 * Each flag object supports:
 *   - `"type"`: "bool" | "int" | "integer" | "float" | "number" | "word"
 *   - `"doc"`: (string) Description.
 *   - `"short"`: (string) Short alias (e.g., "-v").
 *   - `"multi"`: (bool) If true, the flag is repeatable and comma-split;
 *     repeats and comma-separated values accumulate into a list value
 *     (see @ref n00b_cmdr_add_flag_multi). Default: false.
 *
 * Each command object supports:
 *   - `"doc"`: (string) Description.
 *   - `"options"`: (object) Command-specific flags.
 *   - `"args"`: (object) Positional arg spec with "name", "type", "min", "max".
 *
 * @param json  JSON specification string.
 * @return Commander instance, or NULL on parse error.
 */
n00b_cmdr_t *n00b_cmdr_from_json(n00b_string_t *json);

/**
 * @brief Free a commander instance and all associated resources.
 * @param c  Commander to free (NULL-safe).
 */
void n00b_cmdr_free(n00b_cmdr_t *c);

// ============================================================================
// Programmatic builder
// ============================================================================

/**
 * @brief Set the program name.
 * @param c     Commander instance.
 * @param name  Program name string.
 */
void n00b_cmdr_set_name(n00b_cmdr_t *c, n00b_string_t *name);

/**
 * @brief Add a top-level subcommand.
 * @param c     Commander instance.
 * @param name  Command name (e.g., "build").
 * @param doc   Description string.
 */
void n00b_cmdr_add_command(n00b_cmdr_t *c, n00b_string_t *name, n00b_string_t *doc);

/**
 * @brief Add a nested subcommand under an existing command.
 * @param c       Commander instance.
 * @param parent  Parent command name, or empty for root.
 * @param name    Subcommand name.
 * @param doc     Description string.
 */
void n00b_cmdr_add_subcommand(n00b_cmdr_t *c, n00b_string_t *parent,
                               n00b_string_t *name, n00b_string_t *doc);

/**
 * @brief Add a flag to a command.
 * @param c            Commander instance.
 * @param command      Command name, or empty for global.
 * @param flag_name    Flag name including dashes (e.g., "--verbose").
 * @param type         Value type.
 * @param takes_value  Whether the flag expects a following value.
 * @param doc          Description string.
 */
void n00b_cmdr_add_flag(n00b_cmdr_t *c, n00b_string_t *command,
                         n00b_string_t *flag_name, n00b_cmdr_arg_type_t type,
                         bool takes_value, n00b_string_t *doc);

/**
 * @brief Add a repeatable / comma-split flag to a command.
 *
 * Identical to @ref n00b_cmdr_add_flag except that the resulting flag's
 * spec has @c multi set to true. At parse time:
 *
 * - Each occurrence on the command line (e.g. `--out a --out b`)
 *   appends one element to the value list.
 * - A single occurrence with comma-separated values (`--out=a,b,c`)
 *   appends each element to the list. Backslash-escaped commas
 *   (`a\,b`) are treated as a literal `,` inside one element.
 * - Mixed forms compose: `--out=a,b --out c` yields a 3-element list.
 *
 * The resulting flag's active variant arm is the
 * @c n00b_list_t(n00b_string_t *) and the list is retrieved with
 * @ref n00b_cmdr_flag_list. The flag is always
 * value-taking; @c takes_value is implicit.
 *
 * @param c           Commander instance.
 * @param command     Command name, or empty for global.
 * @param flag_name   Flag name including dashes (e.g., "--out").
 * @param value_type  Type tag (currently informative; values are
 *                    stored as strings inside the list).
 * @param doc         Description string.
 */
void n00b_cmdr_add_flag_multi(n00b_cmdr_t *c, n00b_string_t *command,
                               n00b_string_t *flag_name,
                               n00b_cmdr_arg_type_t value_type,
                               n00b_string_t *doc);

/**
 * @brief Add a short alias for an existing flag.
 * @param c          Commander instance.
 * @param command    Command name, or empty for global.
 * @param flag_name  Long flag name (must already exist).
 * @param alias      Short alias (e.g., "-v").
 */
void n00b_cmdr_add_flag_alias(n00b_cmdr_t *c, n00b_string_t *command,
                               n00b_string_t *flag_name, n00b_string_t *alias);

/**
 * @brief Add a positional argument spec to a command.
 * @param c        Commander instance.
 * @param command  Command name, or empty for root.
 * @param name     Display name for the argument.
 * @param type     Expected argument type.
 * @param min      Minimum number of arguments required.
 * @param max      Maximum number of arguments (-1 for unlimited).
 */
void n00b_cmdr_add_positional(n00b_cmdr_t *c, n00b_string_t *command,
                               n00b_string_t *name, n00b_cmdr_arg_type_t type,
                               int min, int max);

/**
 * @brief Build the internal grammar from the current spec.
 *
 * Called automatically by n00b_cmdr_parse() if not called explicitly.
 *
 * @param c  Commander instance.
 */
void n00b_cmdr_finalize(n00b_cmdr_t *c);

// ============================================================================
// Parsing
// ============================================================================

/**
 * @brief Parse an argument vector.
 *
 * Automatically calls n00b_cmdr_finalize() if not already done.
 *
 * @param c     Commander instance.
 * @param argc  Number of arguments (typically argc-1, skipping argv[0]).
 * @param argv  Argument strings (typically argv+1).
 * @return Parse result. Caller must n00b_cmdr_result_free(). Check r->ok.
 */
n00b_cmdr_result_t *n00b_cmdr_parse(n00b_cmdr_t *c, int argc, const char **argv);

/**
 * @brief Parse a single command-line string.
 *
 * Splits on whitespace (respecting quotes), then parses as argv.
 *
 * @param c        Commander instance.
 * @param cmdline  Command-line string.
 * @return Parse result. Caller must n00b_cmdr_result_free(). Check r->ok.
 */
n00b_cmdr_result_t *n00b_cmdr_parse_string(n00b_cmdr_t *c, n00b_string_t *cmdline);

/**
 * @brief Free a parse result.
 * @param r  Result to free (NULL-safe).
 */
void n00b_cmdr_result_free(n00b_cmdr_result_t *r);

// ============================================================================
// Result queries
// ============================================================================

/**
 * @brief Get the matched subcommand name.
 * @param r  Parse result.
 * @return Subcommand name, or empty string if none matched.
 */
n00b_string_t *n00b_cmdr_result_command(n00b_cmdr_result_t *r);

/**
 * @brief Check whether a flag was present on the command line.
 * @param r     Parse result.
 * @param flag  Flag name to check (long or short).
 * @return True if the flag was present.
 */
bool n00b_cmdr_flag_present(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get the raw n00b_cmdr_val_t for a flag.
 * @param r     Parse result.
 * @param flag  Flag name (long or short).
 * @return Pointer to the value, or NULL if not present.
 */
n00b_cmdr_val_t *n00b_cmdr_flag_get(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get a flag's value as a string.
 * @return String value, or empty string if not present or not a string type.
 */
n00b_string_t *n00b_cmdr_flag_str(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get a flag's value as an integer.
 * @return Integer value, or 0 if not present or not an int type.
 */
int64_t n00b_cmdr_flag_int(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get a flag's value as a boolean.
 * @return Boolean value, or false if not present.
 */
bool n00b_cmdr_flag_bool(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get a multi-flag's value as a list of strings.
 *
 * For flags declared via @ref n00b_cmdr_add_flag_multi (or @c "multi": true
 * in the JSON spec), returns the accumulated list of values in order of
 * appearance. Both repeated occurrences and comma-split elements within a
 * single occurrence contribute.
 *
 * @param r     Parse result.
 * @param flag  Flag name (long or short).
 * @return The accumulated value list wrapped in @c n00b_option_t. Returns
 *         @c n00b_option_none(n00b_list_t(n00b_string_t *) *) if the flag
 *         was not present, was not declared multi, or the underlying value
 *         is not a list arm.
 *
 * @post The returned list (once unwrapped via @ref n00b_option_get) is
 *       owned by @p r and lives until @ref n00b_cmdr_result_free is
 *       called.
 */
n00b_option_t(n00b_list_t(n00b_string_t *) *)
    n00b_cmdr_flag_list(n00b_cmdr_result_t *r, n00b_string_t *flag);

/**
 * @brief Get the number of positional arguments.
 */
int32_t n00b_cmdr_arg_count(n00b_cmdr_result_t *r);

/**
 * @brief Get a positional argument as a string.
 * @param index  0-based argument index.
 * @return String value, or empty string if out of range.
 */
n00b_string_t *n00b_cmdr_arg_str(n00b_cmdr_result_t *r, int index);

/**
 * @brief Get a positional argument as an integer.
 * @param index  0-based argument index.
 * @return Integer value, or 0 if out of range.
 */
int64_t n00b_cmdr_arg_int(n00b_cmdr_result_t *r, int index);

// ============================================================================
// Error output
// ============================================================================

/**
 * @brief Get the number of errors from a failed parse.
 * @return Number of errors, or 0 if the result was OK.
 */
int32_t n00b_cmdr_error_count(n00b_cmdr_result_t *r);

/**
 * @brief Get an error message by index.
 * @return Error string, or empty string if out of range.
 */
n00b_string_t *n00b_cmdr_error_get(n00b_cmdr_result_t *r, int32_t index);

// ============================================================================
// Tokenizer (used internally, exposed for testing)
// ============================================================================

/**
 * @brief Tokenize an argv array for commander's grammar.
 *
 * @param argv        Argument strings.
 * @param argc        Number of arguments.
 * @param c           Finalized commander.
 * @param tokens_out  Output: array of token pointers.
 * @param n_tokens_out Output: number of tokens (including trailing EOF).
 * @return 0 on success, -1 on error.
 */
int32_t n00b_cmdr_tokenize(const char **argv, int argc,
                            n00b_cmdr_t *c,
                            n00b_token_info_t ***tokens_out,
                            int32_t *n_tokens_out);

/**
 * @brief Tokenize a command-line string.
 *
 * Splits on whitespace (respecting quotes), then tokenizes as argv.
 *
 * @param cmdline       Command-line string.
 * @param c             Finalized commander.
 * @param tokens_out    Output: array of token pointers.
 * @param n_tokens_out  Output: number of tokens.
 * @return 0 on success, -1 on error.
 */
int32_t n00b_cmdr_tokenize_string(n00b_string_t *cmdline,
                                   n00b_cmdr_t *c,
                                   n00b_token_info_t ***tokens_out,
                                   int32_t *n_tokens_out);

// Debug: dump the grammar to stderr.
void n00b_cmdr_dump_grammar(n00b_cmdr_t *c);
