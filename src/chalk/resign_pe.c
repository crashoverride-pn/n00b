/** @file src/chalk/resign_pe.c — PE re-sign body (WP-005 P4).
 *
 *  Composes the Phase 3 Authenticode primitives — PE parser /
 *  builder, `n00b_pe_authentihash_sha256`, the DER encoder, the
 *  PKCS#7 SignedData builder, and the RSA-PKCS1-v1.5 SHA-256
 *  sign primitive — into a single re-sign entry point.
 *
 *  Flow:
 *    1. Read the file in full into a buffer (mmap substrate).
 *    2. Parse via `n00b_pe_parse`.
 *    3. If no signer identity → clear the cert table on the
 *       parsed binary, rebuild via `n00b_pe_build`, write back,
 *       emit a structured warning to stderr. Done (strip-only
 *       mode).
 *    4. Else: clear the cert table, rebuild WITHOUT the cert
 *       table so the Authenticode hash is computed over the
 *       cert-free bytes, compute the Authenticode SHA-256 via
 *       `n00b_pe_authentihash_sha256` against the rebuilt bytes,
 *       compose an `SpcIndirectDataContent` blob, wrap it in a
 *       PKCS#7 SignedData with the supplied cert + key, attach
 *       to `bin->certificates[]`, rebuild via `n00b_pe_build`
 *       again (P3's cert-table-aware path), write back. Done.
 *
 *  Deterministic signing: the SignedData builder + RSA-PKCS1-v1.5
 *  sign primitive produce byte-identical output for the same
 *  inputs. No timestamp authority is consulted; v1 ships without
 *  RFC 3161 counter-signature support (future ergonomics WP).
 *
 *  Internal-helper accessors `_n00b_chalk_signer_identity_*` live
 *  in `resign_identity.c`; this file forward-declares them so the
 *  identity struct stays opaque outside its translation unit.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/alloc.h"
#include "core/file.h"
#include "conduit/print.h"
#include "compiler/objfile/pe.h"
#include "compiler/objfile/pe_build.h"
#include "compiler/objfile/pe_types.h"
#include "compiler/objfile/bstream.h"
#include "chalk/n00b_chalk_resign.h"
#include "internal/chalk/file_io.h"
#include "internal/chalk/resign_identity_internal.h"
#include "crypto/pkcs7.h"
#include "crypto/der_encode.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Authenticode SpcIndirectDataContent OID 1.3.6.1.4.1.311.2.1.4.
static uint32_t k_spc_indirect_data_oid_arcs[] = {
    1, 3, 6, 1, 4, 1, 311, 2, 1, 4
};

// Authenticode WIN_CERTIFICATE revision/type values for the
// embedded SignedData. RFC: WIN_CERT_REVISION_2_0 = 0x0200,
// WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002 (matches
// test/unit/test_pe_cert_table_emit.c).
#define N00B_CHALK_WIN_CERT_REVISION_2_0     0x0200
#define N00B_CHALK_WIN_CERT_TYPE_PKCS_SIGNED 0x0002

// ---------------------------------------------------------------------------
// File I/O: read the full PE bytes via the MMAP substrate, then
// COPY into an allocator-owned buffer so the binary is decoupled
// from the file's lifetime (allowing us to write back to the
// same path).
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
    // Copy into an allocator-owned buffer and release the mmap view
    // before overwriting the same file.
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
// Compose the PKCS#7 SignedData blob from the Authenticode hash +
// signer identity. Returns the serialized SignedData bytes; nullptr
// on failure.
// ---------------------------------------------------------------------------

static n00b_buffer_t *
build_signed_data(n00b_buffer_t                *authentihash_sha256,
                  n00b_chalk_signer_identity_t *identity,
                  n00b_allocator_t             *alloc)
{
    n00b_buffer_t *cert_der = _n00b_chalk_signer_identity_cert_der(identity);
    n00b_buffer_t *issuer   = _n00b_chalk_signer_identity_issuer_dn(identity);
    if (cert_der == nullptr || issuer == nullptr) return nullptr;

    const uint8_t *serial    = nullptr;
    size_t         serial_len = 0;
    _n00b_chalk_signer_identity_serial(identity, &serial, &serial_len);

    const uint8_t *n_bytes = nullptr;
    size_t         n_len   = 0;
    const uint8_t *d_bytes = nullptr;
    size_t         d_len   = 0;
    _n00b_chalk_signer_identity_rsa(identity, &n_bytes, &n_len, &d_bytes, &d_len);
    if (n_bytes == nullptr || d_bytes == nullptr || serial == nullptr) {
        return nullptr;
    }

    // SpcIndirectDataContent blob — the inner content of the
    // SignedData. Encodes the SpcAttributeTypeAndOptionalValue
    // (SPC_PE_IMAGE_DATA OID) plus the DigestInfo (SHA-256 +
    // 32-byte authentihash).
    n00b_buffer_t *spc = n00b_pkcs7_build_spc_indirect_data(
        authentihash_sha256, .allocator = alloc);
    if (spc == nullptr) return nullptr;

    // Content-type OID for the SignedData inner content
    // (Authenticode SpcIndirectDataContent).
    n00b_buffer_t *content_oid = n00b_der_encode_oid(
        k_spc_indirect_data_oid_arcs,
        sizeof(k_spc_indirect_data_oid_arcs) / sizeof(uint32_t),
        .allocator = alloc);
    if (content_oid == nullptr) return nullptr;

    // Build the SignedData via Phase 3's PKCS#7 builder.
    n00b_pkcs7_signed_data_t *sd = n00b_pkcs7_signed_data_new(
        .allocator = alloc);
    if (sd == nullptr) return nullptr;

    n00b_pkcs7_signed_data_set_content(sd, content_oid, spc);
    n00b_pkcs7_signed_data_add_certificate(sd, cert_der);

    auto sr = n00b_pkcs7_signed_data_add_signer(
        sd,
        issuer,
        serial, serial_len,
        spc,                                  // content_for_digest
        n_bytes, n_len,
        d_bytes, d_len);
    if (n00b_result_is_err(sr)) return nullptr;

    auto rr = n00b_pkcs7_signed_data_serialize(sd);
    if (n00b_result_is_err(rr)) return nullptr;
    return n00b_result_get(rr);
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

n00b_result_t(bool)
n00b_chalk_pe_resign(n00b_string_t *path) _kargs
{
    n00b_chalk_signer_identity_t *signer_identity = nullptr;
    n00b_allocator_t             *allocator       = nullptr;
}
{
    if (path == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    // 1. Read the file in full.
    n00b_buffer_t *raw = read_file_full(path, allocator);
    if (raw == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    // 2. Parse the PE.
    n00b_bstream_t *bs = n00b_bstream_new(raw);
    if (bs == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    auto pr = n00b_pe_parse(bs);
    if (n00b_result_is_err(pr)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    n00b_pe_binary_t *bin = n00b_result_get(pr);

    // 3. Strip any prior cert table on the parsed binary. (The
    // strip-only fallback and the signed path both start here:
    // the cert table is rebuilt from `bin->certificates[]`, so
    // clearing the field is sufficient to drop any prior
    // signature.)
    bin->certificates     = nullptr;
    bin->num_certificates = 0;
    // Also clear the cert table data directory so the
    // pre-rebuild hash sees zeros there. P3's n00b_pe_build
    // patches the directory itself from the cert array; clearing
    // here keeps the in-struct view consistent.
    bin->data_dirs[N00B_PE_DD_CERTIFICATE].VirtualAddress = 0;
    bin->data_dirs[N00B_PE_DD_CERTIFICATE].Size           = 0;

    if (signer_identity == nullptr) {
        // Strip-only fallback. Rebuild the binary without the
        // cert table, write back, emit a structured warning.
        auto br = n00b_pe_build(bin);
        if (n00b_result_is_err(br)) {
            return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
        }
        n00b_buffer_t *stripped = n00b_result_get(br);
        if (!write_file_full(path, stripped)) {
            return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
        }
        n00b_eprintf("[n00b_chalk] warning: PE re-signed in strip-only mode; binary is no longer Authenticode-signed: «#»",
                     path);
        return n00b_result_ok(bool, true);
    }

    // 4. Rebuild the PE WITHOUT the cert table so the
    // Authenticode hash is computed over the cert-free bytes.
    auto br1 = n00b_pe_build(bin);
    if (n00b_result_is_err(br1)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    n00b_buffer_t *stripped_bytes = n00b_result_get(br1);

    // 5. Re-parse the stripped bytes to compute the Authenticode
    // hash. `n00b_pe_authentihash_sha256` operates on a parsed
    // binary that's backed by a stream, so we wrap the stripped
    // bytes and parse them again.
    n00b_bstream_t *bs2 = n00b_bstream_new(stripped_bytes);
    auto pr2 = n00b_pe_parse(bs2);
    if (n00b_result_is_err(pr2)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    n00b_pe_binary_t *stripped_bin = n00b_result_get(pr2);
    n00b_buffer_t    *authentihash = n00b_pe_authentihash_sha256(stripped_bin);
    if (authentihash == nullptr || authentihash->byte_len != 32) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    // 6. Build the SignedData blob.
    n00b_buffer_t *sd_bytes = build_signed_data(authentihash,
                                                signer_identity,
                                                allocator);
    if (sd_bytes == nullptr) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    // 7. Attach the SignedData to the parsed binary's cert array
    // and rebuild via the cert-table-aware n00b_pe_build path
    // (P3 sub-deliverable 3).
    bin->certificates = n00b_alloc_array(n00b_pe_certificate_t,
                                         1,
                                         .allocator = allocator);
    bin->certificates[0].revision         = N00B_CHALK_WIN_CERT_REVISION_2_0;
    bin->certificates[0].certificate_type = N00B_CHALK_WIN_CERT_TYPE_PKCS_SIGNED;
    bin->certificates[0].raw_data         = sd_bytes;
    bin->num_certificates                 = 1;

    auto br2 = n00b_pe_build(bin);
    if (n00b_result_is_err(br2)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }
    n00b_buffer_t *signed_bytes = n00b_result_get(br2);

    // 8. Write back to disk.
    if (!write_file_full(path, signed_bytes)) {
        return n00b_result_err(bool, N00B_CHALK_ERR_RESIGN_FAILED);
    }

    return n00b_result_ok(bool, true);
}

// Mach-O re-sign body lives in resign_macho.c (cross-platform
// dispatcher + non-macOS strip-only body) + resign_macho_darwin.m
// (Security-framework body on macOS). The P4 pre-stub was removed
// in P5; do not re-add a no-op stub here.
