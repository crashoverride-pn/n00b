#pragma once

/**
 * @file n00b_attest_mark.h
 * @brief n00b_attest ↔ libchalk bridge — the in-binary attestation
 *        mark surface (WP-005 Phase 1).
 *
 * Public library API for the three "Cut M" entry points:
 * `n00b_attest_mark_artifact`, `n00b_attest_unmark`, and
 * `n00b_attest_extract_from_artifact`. These compose libchalk's
 * mark / extract / delete dispatch with n00b_attest's DSSE
 * envelope substrate to produce + read chalk marks whose
 * `ATTESTATION` field carries the canonical JSON shape documented
 * in `docs/attest/04-in-container-identity.md` §1.
 *
 * # IC-4 enablement
 *
 * `mark_artifact` returns the unchalked SHA-256 (32 raw bytes,
 * NOT `sha256:<hex>` form) as part of the
 * @ref n00b_attest_mark_result_t row type. Callers cross-check
 * the value against the envelope's
 * `subject.digest.sha256` (the WP-003 verifier handles that on
 * the verify path). The byte form is chosen so the cross-check
 * is byte-comparison; CLI shims that need a hex display format
 * locally.
 *
 * # IC-5 sentinel discrimination
 *
 * `extract_from_artifact` distinguishes the four IC-5 cases via
 * four Err-code legs:
 *
 *   - @ref N00B_ATTEST_ERR_CHALK_NO_MARK — case (i): artifact
 *     carries no chalk mark.
 *   - @ref N00B_ATTEST_ERR_CHALK_NO_ATTESTATION — case (ii):
 *     mark present but `ATTESTATION` field absent.
 *   - @ref N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION — case
 *     (iii): `ATTESTATION` field present but content does not
 *     match the canonical JSON shape.
 *   - @ref N00B_ATTEST_ERR_CHALK_CODEC_LOOKUP_FAILED — case
 *     (iv): bytes do not match any libchalk codec
 *     (`n00b_chalk_detect_file` returned `N00B_CHALK_CODEC_NONE`).
 *
 * The Err-code shape is chosen over a discriminated Ok-payload
 * enum because all four cases carry no useful Ok value and the
 * `n00b_result_t(T) → Err(err_t)` convention is the established
 * n00b_attest precedent.
 *
 * # ATTESTATION JSON shape
 *
 * Per `docs/attest/04-in-container-identity.md` §1, the
 * canonical shape is:
 *
 * ```json
 * {
 *   "envelope_digest":   "sha256:...",
 *   "predicate_types":   ["https://slsa.dev/provenance/v1", ...],
 *   "registry_hint":     "ghcr.io/myorg/myrepo:tag",
 *   "signer_keyid":      "ab12cd34...",
 *
 *   // Present in bundled mode (default), absent in lazy mode:
 *   "envelopes": [
 *     {
 *       "predicate_type":  "https://slsa.dev/provenance/v1",
 *       "envelope_base64": "<DSSE bytes>"
 *     },
 *     ...
 *   ]
 * }
 * ```
 *
 * `envelope_digest` is the SHA-256 of envelope[0]'s wire bytes
 * when multiple envelopes are bundled (the field is singular per
 * the spec); the per-envelope digests are derivable from
 * `envelopes[]` in bundled mode. Field order is fixed via
 * ordered string concatenation (D-056 — `n00b_dict_t` iteration
 * order is not guaranteed and would break byte-stability).
 *
 * # Allocator discipline
 *
 * Every allocating entry point carries `.allocator = nullptr`
 * per FR-21 / D-060 — `nullptr` selects the runtime default;
 * any non-null allocator is threaded forward through every
 * downstream allocation (including the libchalk dispatch's
 * scratch buffers via the `alloc_for_call` idiom; D-045).
 *
 * # Scope of Phase 1
 *
 * Phase 1 ships the n00b-attest-side library + tests only.
 * Out-of-scope and landed in later phases:
 *
 *   - CLI verb shims (`mark`, `unmark`, `extract`): Phase 2.
 *   - libchalk re-sign helpers (PE Authenticode, Mach-O
 *     codesign): Phases 3-5.
 *   - `signer_identity` kwarg on `_mark_artifact`: Phase 6.
 *   - `harvest` verb + `_harvest_attestations`: deferred to a
 *     future WP-015 ("Cut H") per the no-deferrals constraint;
 *     not surfaced here as a deferral because the user
 *     pre-dispositioned the carve-out at WP-005 kickoff.
 */

#include <n00b.h>
#include "adt/result.h"
#include "adt/list.h"

#include <chalk/n00b_chalk_codec.h>
#include <chalk/n00b_chalk_resign.h>

#include <attest/n00b_attest_dsse.h>
#include <attest/n00b_attest_error.h>

/**
 * @brief Row type returned by @ref n00b_attest_mark_artifact on the
 *        Ok leg.
 *
 * Carries the IC-4 enabler (the unchalked SHA-256 as 32 raw bytes)
 * plus the libchalk-dispatch output discriminants (in-band vs
 * sidecar; sidecar suffix when applicable).
 */
typedef struct n00b_attest_mark_result {
    /**
     * @brief The unchalked SHA-256 of the artifact at the point
     *        `_mark_artifact` was invoked (pre-insert hash).
     *
     * Exactly 32 bytes (`byte_len == 32`). Raw bytes — NOT
     * `sha256:<hex>` string form. Callers that need a hex display
     * format convert at the display layer; the byte form is
     * preserved here so the IC-4 cross-check against the
     * envelope's `subject.digest.sha256` is byte-comparison.
     *
     * @note The hash is computed from the artifact bytes read at call time
     * using libchalk's codec-specific "unchalked" hash. Supported ELF inputs
     * use the surgical `.chalk.mark` view: unmarked ELFs hash their original
     * bytes, and marked ELFs hash the bytes produced by deleting the mark
     * without a canonical rebuild.
     */
    n00b_buffer_t        *unchalked_sha256_32;

    /**
     * @brief Whether libchalk wrote the rewritten bytes back to
     *        the artifact path (in-band) or emitted a sidecar.
     *
     * Forwarded verbatim from libchalk's
     * @c n00b_chalk_io_result_t.kind. For ELF / Mach-O / PE /
     * GGUF / SafeTensors / ZIP / PyC the value is
     * @c N00B_CHALK_OUT_IN_BAND (the artifact's bytes were
     * rewritten in place). For sidecar codecs (`*.onnx`,
     * `*.safetensors-sidecar`, `*.pem`) the value is
     * @c N00B_CHALK_OUT_SIDECAR; the sidecar file path is
     * `<artifact_path><sidecar_suffix>`.
     */
    n00b_chalk_out_kind_t kind;

    /**
     * @brief The sidecar suffix libchalk used when @c kind is
     *        @c N00B_CHALK_OUT_SIDECAR; `nullptr` otherwise.
     *
     * Borrowed pointer — the suffix string is owned by the
     * allocator passed to `_mark_artifact` (or the runtime
     * default).
     */
    n00b_string_t        *sidecar_suffix;
} n00b_attest_mark_result_t;

/**
 * @brief Row type returned by @ref n00b_attest_extract_from_artifact
 *        on the Ok leg.
 *
 * Carries the decoded ATTESTATION JSON fields plus, in bundled
 * mode, the parsed envelopes. The four IC-5 cases that distinguish
 * "no usable attestation" surface as Err legs (see the @ref
 * n00b_attest_extract_from_artifact return doc); this row type
 * only represents the Ok-shaped result.
 */
typedef struct n00b_attest_extract_result {
    /**
     * @brief The artifact's unchalked SHA-256 as recorded in the
     *        mark's `HASH` field, expressed as `sha256:<hex>`.
     *
     * Borrowed pointer — owned by the per-call allocator. May be
     * `nullptr` if libchalk's extracted mark did not carry a HASH
     * key (defensive — every libchalk-emitted mark has one, but
     * the extractor does not enforce). Callers needing the raw
     * 32-byte form should hex-decode the suffix.
     */
    n00b_string_t *unchalked_hash_hex;

    /**
     * @brief The `envelope_digest` field from the ATTESTATION
     *        JSON (`sha256:<hex>` of envelope[0]'s wire bytes).
     *
     * Borrowed pointer — owned by the per-call allocator. Always
     * non-null on Ok.
     */
    n00b_string_t *envelope_digest;

    /**
     * @brief The validated full image reference from the
     *        ATTESTATION JSON's `registry_hint` field, or
     *        `nullptr` when the mark was created without a hint.
     *
     * Borrowed pointer.
     */
    n00b_string_t *registry_hint;

    /**
     * @brief The `signer_keyid` field from the ATTESTATION JSON
     *        (canonical lowercase-hex SHA-256 of the signer's
     *        SPKI DER per D-039).
     *
     * Borrowed pointer. Always non-null on Ok.
     */
    n00b_string_t *signer_keyid;

    /**
     * @brief Predicate-type URIs of the bundled envelopes, in the
     *        same order as `envelopes`.
     *
     * Always non-null and non-empty on Ok (the ATTESTATION JSON's
     * `predicate_types[]` must have at least one entry).
     */
    n00b_list_t(n00b_string_t *) *predicate_types;

    /**
     * @brief Parsed DSSE envelopes, in the order they appeared in
     *        the ATTESTATION JSON's `envelopes[]` array.
     *
     * In bundled mode this list is non-empty; in lazy mode it is
     * empty (the caller fetches envelopes from the registry hint
     * via WP-004's `_pull_envelope`).
     */
    n00b_list_t(n00b_attest_envelope_t *) *envelopes;

    /**
     * @brief Whether the mark used bundled mode (`envelopes[]`
     *        present in the ATTESTATION JSON) or lazy mode
     *        (omitted).
     *
     * Convenience flag; equivalent to checking whether
     * `envelopes` is non-empty AT EXTRACT TIME, but documents the
     * producer's intent independent of the count.
     */
    bool                                    bundled;
} n00b_attest_extract_result_t;

/**
 * @brief Mark an artifact in place with an ATTESTATION JSON tree
 *        composed from the supplied DSSE envelopes, returning the
 *        artifact's pre-insert unchalked SHA-256 for IC-4 cross-
 *        check.
 *
 * @param artifact_path  Filesystem path to the artifact to mark.
 *                       libchalk's @c n00b_chalk_detect_file
 *                       picks the codec; ELF / Mach-O / PE / GGUF
 *                       / SafeTensors / ZIP / PyC / source mark
 *                       in-band, sidecar codecs (`*.onnx`,
 *                       `*.pem`) write a sidecar file beside the
 *                       artifact. Required.
 * @param envelopes      One-or-more DSSE envelopes whose
 *                       canonical wire bytes will be folded into
 *                       the ATTESTATION JSON (bundled mode) or
 *                       referenced by digest (lazy mode).
 *                       Required (must be non-null and contain
 *                       at least one envelope). Each envelope
 *                       must have a payload attached (the
 *                       Statement bytes) and that Statement must
 *                       carry a `predicateType` — failing those
 *                       conditions surfaces as @ref
 *                       N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE.
 *
 * @kw bundled        Whether to fold the envelopes' wire bytes
 *                    into the mark's `envelopes[]` array
 *                    (bundled mode, default `true`) or to record
 *                    only their digest + predicate type (lazy
 *                    mode, `false`). Lazy mode shrinks the mark's
 *                    on-disk footprint at the cost of requiring
 *                    the verifier to fetch the envelopes
 *                    out-of-band (typically via `registry_hint`
 *                    + WP-004's `_pull_envelope`).
 * @kw registry_hint  Optional full OCI image reference (e.g.
 *                    `ghcr.io/myorg/myrepo:tag`) recorded in the
 *                    mark's `registry_hint` field. Validated at
 *                    mark time via
 *                    @c n00b_attest_oci_url_parse; an invalid
 *                    reference surfaces as @ref
 *                    N00B_ATTEST_ERR_CHALK_BAD_REGISTRY_HINT
 *                    BEFORE the artifact's bytes are touched.
 *                    `nullptr` (default) omits the field from
 *                    the JSON (the verifier falls back to
 *                    discovery via subject digest).
 * @kw allocator       Optional allocator (defaults to the runtime
 *                     allocator). Threaded through every internal
 *                     allocation (libchalk dispatch, JSON build,
 *                     base64 encode); the returned row type and
 *                     its embedded buffer / string fields all live
 *                     in this allocator.
 * @kw signer_identity Optional resolved signer identity. When
 *                     non-null AND the codec is PE or Mach-O, the
 *                     mark insertion is followed by a re-sign
 *                     dispatch (`n00b_chalk_pe_resign` /
 *                     `n00b_chalk_macho_resign`) that hashes the
 *                     post-mark bytes, builds an Authenticode /
 *                     Mach-O signature with the supplied identity,
 *                     and writes the signed binary back. For ELF
 *                     and all other codecs the kwarg is ignored
 *                     (the re-sign step is skipped regardless of
 *                     its value). `nullptr` (default) selects no
 *                     re-sign: the mark is inserted but no
 *                     platform signature is added.
 *
 *                     Identity URIs are resolved by the caller via
 *                     `n00b_chalk_signer_identity_resolve` —
 *                     supported URI shapes are
 *                     `file://cert.pem,file://key.pem` (paired PEM
 *                     files) and `store://<name>` (XDG store).
 *                     `n00b_chalk_signer_identity_release` must be
 *                     called by the caller on success or failure.
 *
 * @return `n00b_result_ok(n00b_attest_mark_result_t *, row)` on
 *         success — the row carries the pre-insert unchalked
 *         SHA-256 (32 raw bytes), the libchalk output kind, and
 *         the sidecar suffix (when applicable). Err legs route
 *         through:
 *
 *         - @ref N00B_ATTEST_ERR_CHALK_BAD_REGISTRY_HINT — the
 *           `registry_hint` kwarg failed
 *           `n00b_attest_oci_url_parse`.
 *         - @ref N00B_ATTEST_ERR_CHALK_BAD_ENVELOPE — one of the
 *           supplied envelopes is malformed
 *           (`_get_payload` failed or the embedded Statement
 *           lacks a predicateType).
 *         - @ref N00B_ATTEST_ERR_CHALK_INSERT_FAILED — libchalk's
 *           @c n00b_chalk_insert_file returned an Err leg
 *           (codec mismatch, file-read failure, codec-internal
 *           failure, file-write failure; the libchalk Err code
 *           shape is not currently differentiated at this layer).
 *         - @ref N00B_ATTEST_ERR_CHALK_RESIGN_FAILED — the
 *           post-insert re-sign dispatch
 *           (`n00b_chalk_pe_resign` or `n00b_chalk_macho_resign`)
 *           returned `N00B_CHALK_ERR_RESIGN_FAILED`. The artifact
 *           HAS been mark-inserted at this point (the bytes are
 *           rewritten on disk); only the post-insert signature
 *           step failed. Callers that need atomicity of mark + sign
 *           should snapshot the pre-mark bytes themselves and
 *           restore on this Err.
 *         - @ref N00B_ATTEST_ERR_DSSE_BAD_INPUT — a null
 *           envelope was passed in the `envelopes` list, or the
 *           `envelopes` list itself was null/empty, or
 *           `artifact_path` was null/empty.
 *
 * @pre `artifact_path` is non-null, non-empty, and names a file
 *      libchalk can read.
 * @pre `envelopes` is a non-null, non-empty list whose entries
 *      are all non-null envelopes returned by
 *      @ref n00b_attest_envelope_new or
 *      @ref n00b_attest_envelope_parse with payloads attached.
 *
 * @post On Ok, the artifact's bytes have been rewritten in place
 *       (in-band codecs) or a sidecar file has been written
 *       (sidecar codecs). For PE / Mach-O artifacts with a
 *       non-null @c signer_identity, the post-mark bytes have
 *       additionally been re-signed in place. On Err, the
 *       artifact's bytes are not touched UNLESS the Err code is
 *       @ref N00B_ATTEST_ERR_CHALK_RESIGN_FAILED — in that case
 *       the mark insertion succeeded and the bytes are rewritten
 *       but unsigned.
 */
extern n00b_result_t(n00b_attest_mark_result_t *)
n00b_attest_mark_artifact(n00b_string_t                       *artifact_path,
                          n00b_list_t(n00b_attest_envelope_t *) *envelopes)
    _kargs {
        bool                          bundled         = true;
        n00b_string_t                *registry_hint   = nullptr;
        n00b_allocator_t             *allocator       = nullptr;
        n00b_chalk_signer_identity_t *signer_identity = nullptr;
    };

/**
 * @brief Remove the chalk mark (if any) from an artifact in place.
 *
 * @param artifact_path  Filesystem path to the artifact. Required.
 *
 * @kw allocator  Optional allocator (defaults to the runtime
 *                allocator). Threaded through libchalk's
 *                read / unmark / write dispatch.
 *
 * @return `n00b_result_ok(bool, true)` on success.
 *         `n00b_result_err(bool, N00B_ATTEST_ERR_CHALK_DELETE_FAILED)`
 *         on any libchalk failure (file-read, codec mismatch,
 *         file-write). `n00b_result_err(bool, N00B_ATTEST_ERR_DSSE_BAD_INPUT)`
 *         if `artifact_path` is null or empty.
 *
 * @note "No mark to delete" routes through @ref
 *       N00B_ATTEST_ERR_CHALK_DELETE_FAILED rather than
 *       @ref N00B_ATTEST_ERR_CHALK_NO_MARK because libchalk's
 *       `n00b_chalk_delete_file` Err shape does not currently
 *       differentiate the conditions. Splitting that out is a
 *       future libchalk public-Err lift, NOT a Phase 1 deferral.
 */
extern n00b_result_t(bool)
n00b_attest_unmark(n00b_string_t *artifact_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };

/**
 * @brief Extract the ATTESTATION JSON tree from an artifact's
 *        chalk mark, returning the parsed envelopes (bundled
 *        mode) plus the metadata fields needed by a verifier.
 *
 * @param artifact_path  Filesystem path to the artifact. Required.
 *
 * @kw allocator  Optional allocator (defaults to the runtime
 *                allocator). Threaded through libchalk's
 *                read / extract dispatch and the JSON parse /
 *                base64 decode of the embedded envelopes.
 *
 * @return `n00b_result_ok(n00b_attest_extract_result_t *, row)`
 *         on success — the row carries the parsed metadata
 *         fields (`envelope_digest`, `registry_hint`,
 *         `signer_keyid`, `predicate_types[]`) plus the decoded
 *         envelopes (bundled mode) or an empty envelope list
 *         (lazy mode).
 *
 *         Err legs route through:
 *         - @ref N00B_ATTEST_ERR_CHALK_CODEC_LOOKUP_FAILED —
 *           IC-5 case (iv): the artifact's bytes do not match
 *           any libchalk codec.
 *         - @ref N00B_ATTEST_ERR_CHALK_NO_MARK — IC-5 case (i):
 *           the artifact's codec recognized the bytes but no
 *           chalk mark is embedded.
 *         - @ref N00B_ATTEST_ERR_CHALK_NO_ATTESTATION — IC-5
 *           case (ii): a chalk mark was extracted but it carries
 *           no `ATTESTATION` field.
 *         - @ref N00B_ATTEST_ERR_CHALK_MALFORMED_ATTESTATION —
 *           IC-5 case (iii): the mark carries an `ATTESTATION`
 *           field but its content does not match the canonical
 *           JSON shape (missing required fields, wrong field
 *           types, malformed embedded envelope base64, etc.).
 *         - @ref N00B_ATTEST_ERR_CHALK_EXTRACT_FAILED — libchalk
 *           returned an Err leg for a reason that is NOT one of
 *           the IC-5 sentinels (file-read failure, codec-
 *           internal failure).
 *         - @ref N00B_ATTEST_ERR_DSSE_BAD_INPUT — `artifact_path`
 *           is null or empty.
 *
 * @pre `artifact_path` is non-null and non-empty.
 *
 * @post On Ok, the row's embedded buffers / strings live in the
 *       per-call allocator. The artifact's bytes are NOT
 *       modified by this entry point.
 */
extern n00b_result_t(n00b_attest_extract_result_t *)
n00b_attest_extract_from_artifact(n00b_string_t *artifact_path)
    _kargs {
        n00b_allocator_t *allocator = nullptr;
    };
