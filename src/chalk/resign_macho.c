/** @file src/chalk/resign_macho.c — Mach-O re-sign body (WP-005 P5).
 *
 *  Cross-platform dispatcher for `n00b_chalk_macho_resign`. The
 *  declaration shipped in P4 as a stub returning
 *  `_RESIGN_FAILED`; this file fills the body.
 *
 *  Two host targets:
 *
 *  - **macOS** (`__APPLE__` && `__MACH__`): the real body lives in
 *    `resign_macho_darwin.m` (Security-framework-mediated re-sign
 *    via `SecCodeSigner`). This file's macOS branch declares the
 *    extern bridge function and forwards the call. The bridge
 *    returns an integer status code (0 = success, non-zero =
 *    failure) which we wrap into the libchalk `n00b_result_t(bool)`
 *    shape.
 *
 *  - **Non-macOS** (Linux / Windows / other): cross-platform
 *    Mach-O code-signing emission is enormous (per the WP-005
 *    plan §Phase 5 disposition) and deferred to a future
 *    ergonomics WP. This file's non-macOS branch implements a
 *    strip-only fallback: any prior code-signature is removed via
 *    the existing `n00b_chalk_macho_strip_signature` buffer
 *    surface, the result is written back, and a structured
 *    warning is emitted to stderr ("binary is no longer
 *    codesigned"). Returns `Ok(true)`.
 *
 *  The `signer_identity == nullptr` case on macOS host means
 *  ad-hoc signing (Apple's `codesign --sign -` convention) — the
 *  bridge passes a nullptr identity to `kSecCodeSignerIdentity`
 *  which the Security framework interprets as ad-hoc.
 *
 *  ## Bridge ABI between resign_macho.c and resign_macho_darwin.m
 *
 *  The .m file exposes a pure-C entry point — no n00b types cross
 *  the bridge — matching the precedent set by
 *  `src/net/quic/secret_keychain.m` +
 *  `src/net/quic/acme_trust_macos.m`. The shape is:
 *
 *  ```c
 *  int _n00b_chalk_macho_resign_darwin(const char                   *path,
 *                                      n00b_chalk_signer_identity_t *id);
 *  ```
 *
 *  Returns 0 on success, non-zero on failure.
 *  `n00b_chalk_signer_identity_t *` is opaque on the .m side; the
 *  bridge calls the `_n00b_chalk_signer_identity_*` accessors
 *  (declared in `internal/chalk/resign_identity_internal.h`) to
 *  read out cert DER + issuer DN + serial + RSA (n, d) for the
 *  Keychain lookup.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/file.h"
#include "conduit/print.h"
#include "chalk/n00b_chalk_resign.h"
#include "chalk/n00b_chalk_macho.h"

#include <stdint.h>
#include <string.h>

#if defined(__APPLE__) && defined(__MACH__)

// Bridge into the Objective-C body in resign_macho_darwin.m. The
// bridge surface is pure C — no n00b types — so the .m file can
// compile through the system ObjC compiler without ncc.
extern int
_n00b_chalk_macho_resign_darwin(const char                   *path,
                                n00b_chalk_signer_identity_t *id);

#endif // __APPLE__ && __MACH__

// ---------------------------------------------------------------------------
// File I/O: read the full Mach-O bytes via the MMAP substrate, then
// COPY into an allocator-owned buffer so the binary is decoupled
// from the file's lifetime (allowing us to write back to the same
// path). Same shape as resign_pe.c's helpers.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
read_file_full(n00b_string_t *path, n00b_allocator_t *alloc)
{
    if (path == nullptr) return nullptr;
    auto fr = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    if (n00b_result_is_err(fr)) return nullptr;
    n00b_file_t *f = n00b_result_get(fr);
    auto br = n00b_file_as_buffer(f);
    if (n00b_result_is_err(br)) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *raw = n00b_result_get(br);
    if (raw == nullptr || raw->byte_len == 0) {
        n00b_file_close(f);
        return nullptr;
    }
    n00b_buffer_t *copy = n00b_buffer_from_bytes(raw->data,
                                                 (int64_t)raw->byte_len,
                                                 .allocator = alloc);
    n00b_file_close(f);
    n00b_buffer_free(raw);
    return copy;
}

static bool
write_file_full(n00b_string_t *path, n00b_buffer_t *bytes)
{
    if (path == nullptr || bytes == nullptr) return false;
    auto fr = n00b_file_open(path,
                             .mode = N00B_FILE_W,
                             .kind = N00B_FILE_KIND_STREAM);
    if (n00b_result_is_err(fr)) return false;
    n00b_file_t *f  = n00b_result_get(fr);
    auto         wr = n00b_file_write(f, bytes->data, bytes->byte_len);
    n00b_file_close(f);
    return n00b_result_is_ok(wr);
}

// ---------------------------------------------------------------------------
// Strip-only fallback: read the file, strip any prior code-
// signature via the libchalk buffer surface, write back, emit
// structured warning.
//
// Used on every non-macOS host AND on macOS when the bridge
// signals "strip-only mode requested" (signer_identity == nullptr
// and ad-hoc signing is not desired by the caller's host). The
// macOS host's nullptr path is handled by the bridge itself
// (ad-hoc signing); this strip-only path is the non-macOS fallback.
// ---------------------------------------------------------------------------

static n00b_result_t(bool)
strip_only_resign(n00b_string_t *path, n00b_allocator_t *alloc)
{
    n00b_buffer_t *raw = read_file_full(path, alloc);
    if (raw == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    auto sr = n00b_chalk_macho_strip_signature(raw);
    if (n00b_result_is_err(sr)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    n00b_buffer_t *stripped = n00b_result_get(sr);
    if (stripped == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    if (!write_file_full(path, stripped)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    n00b_eprintf("[n00b_chalk] warning: Mach-O re-signed in strip-only mode; binary is no longer codesigned. Cross-platform Mach-O code-signing is not implemented; this build is non-loadable on macOS Gatekeeper-enforcing environments: «#»",
                 path);
    return n00b_result_ok(bool, true);
}

// ---------------------------------------------------------------------------
// Public surface — Mach-O re-sign.
// ---------------------------------------------------------------------------

n00b_result_t(bool)
n00b_chalk_macho_resign(n00b_string_t *path) _kargs
{
    n00b_chalk_signer_identity_t *signer_identity = nullptr;
    n00b_allocator_t             *allocator       = nullptr;
}
{
    if (path == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

#if defined(__APPLE__) && defined(__MACH__)
    // macOS host: forward to the Objective-C bridge for the real
    // Security-framework re-sign. The bridge accepts nullptr to
    // request ad-hoc signing (kSecCodeSignerIdentity = nullptr).
    (void)allocator;
    char path_c[4096];
    if (path->u8_bytes >= sizeof(path_c)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    memcpy(path_c, path->data, path->u8_bytes);
    path_c[path->u8_bytes] = '\0';

    int rc = _n00b_chalk_macho_resign_darwin(path_c, signer_identity);
    if (rc != 0) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    return n00b_result_ok(bool, true);
#else
    // Non-macOS host: strip-only fallback regardless of whether the
    // caller supplied an identity (cross-platform Mach-O code-
    // signing emission is out of scope per WP-005 §Phase 5
    // disposition).
    (void)signer_identity;
    return strip_only_resign(path, allocator);
#endif
}
