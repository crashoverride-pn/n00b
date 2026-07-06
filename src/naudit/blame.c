/*
 * WP-013 — libgit2-backed blame-lineage anchor for exemption matching.
 *
 * Implements the public surface declared in `naudit/blame.h`. The
 * libgit2 dependency is contained to this translation unit: no other
 * naudit source includes `<git2.h>`.
 *
 * # Design summary (white paper § 4)
 *
 * 1. The *signing commit* of an exemption file is derived at audit
 *    time by walking `git_blame_file` on that file and selecting the
 *    hunk whose introducing commit has the OLDEST committer
 *    timestamp. That is the commit that introduced the file (the
 *    chronological root, not the line-1 hunk). Per § 5.2 the SHA is
 *    NEVER stored in the exemption record — embedding one would
 *    create a tampering target, would not exist at signing time,
 *    and would conflict with history rewrites.
 *
 * 2. For each audit finding, blame on the audited file's CURRENT
 *    working-tree bytes (computed as a two-step overlay: first
 *    `git_blame_file` produces a HEAD-only base, then
 *    `git_blame_buffer` overlays that base with the working-tree
 *    bytes) tells us, per source line, which historical commit +
 *    line pair the working-tree line traces to. The finding is
 *    anchored to the exemption iff every line in the finding's
 *    region traces back to a line in the signing-commit's exempted
 *    range (paper § 13.2 strict variant; configurable later if a
 *    quorum becomes useful).
 *
 * 3. The pre-commit fallback (exemption file signed locally but not
 *    yet committed) leaves the signing-commit lookup returning a
 *    "none" option; the caller (`n00b_audit_exemption_match`) drops
 *    back to pure-fingerprint matching, the WP-011 behavior.
 *
 * # DF-AA resolution — layered HEAD + working-tree blame
 *
 * libgit2 exposes `git_blame_file` (a HEAD-only blame, returning a
 * `git_blame *` opaque handle) and `git_blame_buffer` (which takes
 * an existing `git_blame *` as `reference` plus a working-tree
 * buffer and returns a new `git_blame *` whose hunks overlay the
 * base with the buffer's contents). We call them in that order:
 * `git_blame_file` for the base, then `git_blame_buffer` to overlay
 * the audited file's current bytes (read via `n00b_file_open` +
 * `n00b_file_as_buffer`). Committed lines retain their historical
 * attribution while uncommitted edits show up with a zero
 * `final_commit_id`. Always performing the overlay subsumes the
 * committed-only single-step case while keeping the public surface
 * one entry point deep. Both `git_blame_file` and
 * `git_blame_buffer` have been part of libgit2 since well before
 * 1.0; the meson `>=1.7.0` floor is set by
 * `git_blame_options_init` (the most recent API we call), not by
 * the blame entry points themselves.
 *
 * # DF-AB resolution — blame caching
 *
 * Per-call recompute, NO cache state. Rationale: typical naudit
 * workloads (handful of exemption files, handful of audited
 * files per invocation) are fast enough not to warrant a cache.
 * Adding one means inventing an invalidation policy against
 * working-tree mutation that the engine cannot observe. A future
 * WP can add caching if profiling justifies it.
 *
 * # Path discipline
 *
 * Every entry point that takes a path argument calls
 * `n00b_path_canonical` on entry (per the path-handling rule in
 * `feedback_path_handling.md` / PR #72). After canonicalization we
 * derive the repo-relative path by stripping the repo-root prefix
 * (libgit2's `git_blame_file*` requires a path relative to the
 * working tree, not absolute).
 *
 * # libgit2 1.9.3 copy-tracking flag note
 *
 * `git_blame_options.min_match_characters` only takes effect when a
 * `GIT_BLAME_TRACK_COPIES_*` flag is set in `flags`. In 1.9.3 all
 * four such flags are documented as "not yet implemented and
 * reserved for future use." We still set
 * `GIT_BLAME_TRACK_COPIES_SAME_FILE` + the user-provided
 * `min_match_characters` for forward-compat; we do NOT rely on
 * the explicit copy-detection flags for correctness. Rename
 * detection in 1.9.3 is driven by the index-similarity machinery
 * underneath the blame walk and DOES work — see
 * `test_naudit_blame.test_rename`, which exercises a rename and
 * confirms blame attributes the new file back to the original's
 * introducing commit (paper § 4.5 "rename and move are handled by
 * the VCS library").
 *
 * Per project DECISIONS.md D-005, public functions in this file
 * carry no `_kargs` block. Per D-008, null guards use the `!ptr`
 * idiom.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/string.h"
#include "util/path.h"
#include "adt/list.h"

#include "naudit/blame.h"

#include <git2.h>

/* ---------------------------------------------------------------- */
/* libgit2 init — idempotent per process                            */
/* ---------------------------------------------------------------- */

/*
 * Per-process state for the one-shot `git_libgit2_init` call.
 *
 *   `g_init_status` lifecycle:
 *     0  - never attempted (default zero-initialization on the BSS
 *          segment under naudit's allocator discipline; we do NOT
 *          rely on `{0}` syntax per the n00b reflex map).
 *     1  - init succeeded; subsequent calls are no-ops.
 *     -1 - init failed; subsequent calls return false immediately.
 *
 * We do NOT call `git_libgit2_shutdown` — the process lives until
 * naudit exits, the kernel reclaims everything. libgit2 itself is
 * happy with shutdown-elided lifetimes; the WP plan explicitly
 * leaves shutdown management for a future process-lifecycle WP.
 */
static int g_blame_init_status;

bool
n00b_audit_blame_init(void)
{
    if (g_blame_init_status == 1) {
        return true;
    }
    if (g_blame_init_status == -1) {
        return false;
    }
    int rc = git_libgit2_init();
    if (rc < 0) {
        g_blame_init_status = -1;
        return false;
    }
    g_blame_init_status = 1;
    return true;
}

/* ---------------------------------------------------------------- */
/* Repository discovery + relative-path derivation                  */
/* ---------------------------------------------------------------- */

/*
 * Open the repository containing `path` via libgit2's discover
 * primitive (handles being called with the working-tree root OR
 * any subdirectory underneath it; mirrors how `git` itself walks
 * up looking for `.git/`). Returns nullptr if discovery fails or
 * the repo can't be opened.
 *
 * Caller owns the returned handle; release with
 * `git_repository_free`.
 *
 * Per the WP-013 audit-revision note, we do NOT use
 * `GIT_REPOSITORY_OPEN_FROM_ENV` — that flag ignores the path arg
 * and reads `GIT_DIR` from the environment, which silently opens
 * the wrong repo if an env var happens to be set in the calling
 * shell.
 */
static git_repository *
open_repo(n00b_string_t *path)
{
    git_buf gitdir = {nullptr, 0, 0};
    int rc = git_repository_discover(&gitdir, path->data, /*across_fs=*/0,
                                     /*ceiling_dirs=*/nullptr);
    if (rc < 0) {
        return nullptr;
    }
    git_repository *repo = nullptr;
    rc = git_repository_open(&repo, gitdir.ptr);
    git_buf_dispose(&gitdir);
    if (rc < 0 || !repo) {
        return nullptr;
    }
    return repo;
}

/*
 * Compute the repo-relative path of `absolute_path` against `repo`'s
 * working-tree root.
 *
 * `git_repository_workdir` returns the working-tree root with a
 * trailing slash (libgit2 convention). We compare byte-by-byte; on
 * a prefix match we return the suffix. Returns nullptr if the
 * absolute_path does not start with the working-tree root (the
 * caller treats this as "blame not applicable").
 *
 * Edge case: macOS `/private/var/...` vs `/var/...` symlink. We
 * already canonicalized via `n00b_path_canonical` at the call
 * site, but `n00b_path_canonical` does not call `realpath()` by
 * default. To make discovery + working-tree comparison robust we
 * pass `.resolve_symlinks = true` at the call site for the paths
 * we hand to libgit2 — see `signing_commit` + `traces_to`.
 */
static n00b_string_t *
relative_path(git_repository *repo, n00b_string_t *absolute_path)
{
    const char *workdir = git_repository_workdir(repo);
    if (!workdir) {
        return nullptr;
    }
    size_t wd_len = strlen(workdir);
    if (wd_len == 0) {
        return nullptr;
    }
    /* Strip trailing slash from workdir for the comparison; libgit2
     * adds it, n00b_path_canonical doesn't. */
    if (workdir[wd_len - 1] == '/') {
        wd_len--;
    }
    const char *abs = absolute_path->data;
    size_t      abs_len = absolute_path->u8_bytes;
    if (abs_len < wd_len || memcmp(abs, workdir, wd_len) != 0) {
        return nullptr;
    }
    /* Skip the separator after the workdir prefix. */
    size_t off = wd_len;
    if (off < abs_len && abs[off] == '/') {
        off++;
    }
    if (off >= abs_len) {
        /* The path IS the working tree root; not a file. */
        return nullptr;
    }
    return n00b_string_from_raw(abs + off, (int64_t)(abs_len - off));
}

/* ---------------------------------------------------------------- */
/* Working-tree file read for blame buffer overlay                  */
/* ---------------------------------------------------------------- */

/*
 * Read the working-tree bytes of an audited file into a fresh
 * n00b buffer. The caller passes the result to `git_blame_buffer`
 * (alongside a HEAD-only `git_blame *` from `git_blame_file`) to
 * overlay HEAD with the current uncommitted contents. Returns
 * nullptr on any I/O failure (caller treats as "blame not
 * applicable").
 */
static n00b_buffer_t *
read_working_tree_bytes(n00b_string_t *path)
{
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) {
        return nullptr;
    }
    n00b_file_t *f  = n00b_result_get(fr);
    auto         br = n00b_file_as_buffer(f);
    n00b_file_close(f);
    if (n00b_result_is_err(br)) {
        return nullptr;
    }
    n00b_buffer_t *mmap_buf = n00b_result_get(br);
    /* Copy: the caller may keep the buffer past the file close. */
    return n00b_buffer_copy(mmap_buf);
}

/* ---------------------------------------------------------------- */
/* OID hex formatting                                               */
/* ---------------------------------------------------------------- */

/*
 * Format a `git_oid` as a 40-character lowercase hex
 * `n00b_string_t *`. Uses `git_oid_tostr` which writes exactly 40
 * bytes for an SHA-1 OID (libgit2 1.9.3 is built without
 * `GIT_EXPERIMENTAL_SHA256` on the dev matrix). We add a final
 * NUL ourselves because `git_oid_tostr` requires `n` ≥
 * GIT_OID_SHA1_HEXSIZE + 1 to include one.
 */
static n00b_string_t *
oid_to_hex_string(const git_oid *oid)
{
    char buf[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(buf, sizeof(buf), oid);
    return n00b_string_from_raw(buf, GIT_OID_SHA1_HEXSIZE);
}

/*
 * Test whether a `git_oid` is the all-zero OID (libgit2's marker
 * for an uncommitted line in a buffer-overlay blame).
 */
static bool
oid_is_zero(const git_oid *oid)
{
    static const unsigned char zero[GIT_OID_MAX_SIZE];
    return memcmp(oid->id, zero, GIT_OID_MAX_SIZE) == 0;
}

/* ---------------------------------------------------------------- */
/* Signing-commit selection                                         */
/* ---------------------------------------------------------------- */

n00b_option_t(n00b_string_t *)
n00b_audit_blame_signing_commit(n00b_string_t *repo_path,
                                n00b_string_t *exemption_file_path)
{
    if (!repo_path || !exemption_file_path) {
        return n00b_option_none(n00b_string_t *);
    }
    if (!n00b_audit_blame_init()) {
        return n00b_option_none(n00b_string_t *);
    }

    /*
     * Canonicalize with symlink resolution. libgit2's working-tree
     * root comes from `git_repository_workdir`, which returns a
     * realpath()-resolved path on macOS (e.g.
     * `/private/var/folders/...` rather than `/var/folders/...`).
     * To make `relative_path` work robustly we resolve symlinks
     * here too.
     */
    n00b_string_t *canon_repo =
        n00b_path_canonical(repo_path, .resolve_symlinks = true);
    n00b_string_t *canon_file =
        n00b_path_canonical(exemption_file_path, .resolve_symlinks = true);

    git_repository *repo = open_repo(canon_repo);
    if (!repo) {
        return n00b_option_none(n00b_string_t *);
    }

    n00b_string_t *rel = relative_path(repo, canon_file);
    if (!rel) {
        git_repository_free(repo);
        return n00b_option_none(n00b_string_t *);
    }

    /*
     * For signing-commit discovery we use plain `git_blame_file`
     * (HEAD-only) — the file must be committed for the lookup to
     * succeed. The pre-commit case (uncommitted exemption file)
     * surfaces here as "blame returns zero hunks" and the caller
     * falls back to fingerprint-only matching.
     */
    git_blame_options bo;
    git_blame_options_init(&bo, GIT_BLAME_OPTIONS_VERSION);

    git_blame *blame = nullptr;
    int rc = git_blame_file(&blame, repo, rel->data, &bo);
    if (rc < 0 || !blame) {
        git_repository_free(repo);
        return n00b_option_none(n00b_string_t *);
    }

    size_t nhunks = git_blame_hunkcount(blame);
    if (nhunks == 0) {
        git_blame_free(blame);
        git_repository_free(repo);
        return n00b_option_none(n00b_string_t *);
    }

    /*
     * Walk every hunk; for each, look up the commit and ask for its
     * committer timestamp. Track the OLDEST. This is critical per
     * the audit revision: `git_blame_file` returns hunks in source-
     * line order, NOT chronological order — picking `hunk[0]` would
     * select the hunk covering line 1, which is rarely the
     * chronologically-first commit on the file.
     */
    git_oid    oldest_oid;
    git_time_t oldest_time = 0;
    bool       have_oldest = false;

    for (size_t i = 0; i < nhunks; i++) {
        const git_blame_hunk *h = git_blame_hunk_byindex(blame, i);
        if (!h) {
            continue;
        }
        /* Uncommitted (working-tree) hunks have a zero OID — skip
         * them; they aren't candidates for the signing commit. */
        if (oid_is_zero(&h->orig_commit_id)) {
            continue;
        }
        git_commit *c = nullptr;
        if (git_commit_lookup(&c, repo, &h->orig_commit_id) < 0 || !c) {
            continue;
        }
        git_time_t t = git_commit_time(c);
        git_commit_free(c);
        if (!have_oldest || t < oldest_time) {
            oldest_oid  = h->orig_commit_id;
            oldest_time = t;
            have_oldest = true;
        }
    }

    n00b_option_t(n00b_string_t *) result = n00b_option_none(n00b_string_t *);
    if (have_oldest) {
        result = n00b_option_set(n00b_string_t *,
                                 oid_to_hex_string(&oldest_oid));
    }

    git_blame_free(blame);
    git_repository_free(repo);
    return result;
}

/* ---------------------------------------------------------------- */
/* Per-line trace                                                   */
/* ---------------------------------------------------------------- */

bool
n00b_audit_blame_traces_to(n00b_string_t *repo_path,
                           n00b_string_t *audited_file_path,
                           int64_t        finding_start_line,
                           int64_t        finding_end_line,
                           n00b_string_t *signing_commit_oid_hex,
                           int64_t        exempt_start_line,
                           int64_t        exempt_end_line,
                           int            similarity_threshold)
{
    if (!repo_path || !audited_file_path || !signing_commit_oid_hex) {
        return false;
    }
    if (finding_start_line < 1 || finding_end_line < finding_start_line) {
        return false;
    }
    if (exempt_start_line < 1 || exempt_end_line < exempt_start_line) {
        return false;
    }
    if (signing_commit_oid_hex->u8_bytes != GIT_OID_SHA1_HEXSIZE) {
        return false;
    }
    if (!n00b_audit_blame_init()) {
        return false;
    }

    git_oid target_oid;
    /*
     * `git_oid_fromstr` (the SHA-1 form available without
     * `GIT_EXPERIMENTAL_SHA256`) takes the first GIT_OID_SHA1_HEXSIZE
     * bytes of the input. Our caller passed a properly-sized hex
     * string (validated above).
     */
    if (git_oid_fromstr(&target_oid, signing_commit_oid_hex->data) < 0) {
        return false;
    }

    n00b_string_t *canon_repo =
        n00b_path_canonical(repo_path, .resolve_symlinks = true);
    n00b_string_t *canon_file =
        n00b_path_canonical(audited_file_path, .resolve_symlinks = true);

    git_repository *repo = open_repo(canon_repo);
    if (!repo) {
        return false;
    }

    n00b_string_t *rel = relative_path(repo, canon_file);
    if (!rel) {
        git_repository_free(repo);
        return false;
    }

    /* Read the audited file's current working-tree bytes for the
     * buffer overlay (DF-AA). */
    n00b_buffer_t *wt = read_working_tree_bytes(canon_file);
    if (!wt) {
        git_repository_free(repo);
        return false;
    }

    /*
     * Blame options:
     *   - flags: TRACK_COPIES_SAME_FILE — forward-compat marker so
     *     that when libgit2 implements the in-file copy heuristic
     *     it picks up our threshold. In 1.9.3 the flag is
     *     documented as reserved-for-future-use; rename detection
     *     still works without it.
     *   - min_match_characters: passed through from the project's
     *     `@blame_similarity` directive; 0 means "let libgit2's
     *     default of 20 apply".
     */
    git_blame_options bo;
    git_blame_options_init(&bo, GIT_BLAME_OPTIONS_VERSION);
    bo.flags |= GIT_BLAME_TRACK_COPIES_SAME_FILE;
    if (similarity_threshold > 0 && similarity_threshold <= UINT16_MAX) {
        bo.min_match_characters = (uint16_t)similarity_threshold;
    }

    git_blame *base = nullptr;
    int rc = git_blame_file(&base, repo, rel->data, &bo);
    if (rc < 0 || !base) {
        git_repository_free(repo);
        return false;
    }

    git_blame *overlay = nullptr;
    rc = git_blame_buffer(&overlay, base, wt->data, (size_t)wt->byte_len);
    /*
     * If the buffer-overlay step fails (it occasionally does on
     * very-short files in libgit2 1.9.x — observed during fixture
     * development), fall back to the HEAD-only blame. This still
     * gives correct results for any line unchanged from HEAD,
     * which is the dominant case at audit time.
     */
    git_blame *blame = overlay ? overlay : base;

    /*
     * For each line in the finding's range, look up its hunk and
     * verify it traces to the signing commit's exempted range.
     * Strict variant per paper § 13.2: every line must trace; any
     * line that doesn't kills the anchor.
     */
    bool covered_all = true;
    for (int64_t ln = finding_start_line; ln <= finding_end_line; ln++) {
        const git_blame_hunk *h = git_blame_hunk_byline(blame, (size_t)ln);
        if (!h) {
            covered_all = false;
            break;
        }
        /* Uncommitted lines (zero OID) cannot match the signing
         * commit — they were added in the working tree after the
         * signing-commit's view of the file. */
        if (oid_is_zero(&h->orig_commit_id)) {
            covered_all = false;
            break;
        }
        if (git_oid_cmp(&h->orig_commit_id, &target_oid) != 0) {
            covered_all = false;
            break;
        }
        /*
         * The hunk's signing-commit view: `orig_start_line_number`
         * is the 1-based line within the file at the signing
         * commit; the line in question is offset by
         * `(ln - h->final_start_line_number)` lines into the hunk
         * (the hunk covers `lines_in_hunk` consecutive lines at
         * both ends — committed `orig_*` and final `final_*` — so
         * the offset is shared).
         */
        size_t offset = (size_t)ln - h->final_start_line_number;
        size_t orig_line = h->orig_start_line_number + offset;
        if ((int64_t)orig_line < exempt_start_line
            || (int64_t)orig_line > exempt_end_line) {
            covered_all = false;
            break;
        }
    }

    if (overlay) {
        git_blame_free(overlay);
    }
    git_blame_free(base);
    git_repository_free(repo);
    return covered_all;
}
