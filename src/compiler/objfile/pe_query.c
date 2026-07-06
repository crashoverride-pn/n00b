#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdio.h>
#include "compiler/objfile/pe.h"
#include "compiler/objfile/demangle.h"
#include "compiler/objfile/md5.h"
#include "core/sha256.h"

// ============================================================================
// RVA / VA / Offset utilities
// ============================================================================

uint32_t
n00b_pe_rva_to_offset(n00b_pe_binary_t *bin, uint32_t rva)
{
    if (!bin) {
        return 0;
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_pe_section_t *s = &bin->sections[i];

        if (rva >= s->virtual_address
            && rva < s->virtual_address + s->virtual_size) {
            return s->raw_offset + (rva - s->virtual_address);
        }
    }

    return 0;
}

uint32_t
n00b_pe_offset_to_rva(n00b_pe_binary_t *bin, uint32_t offset)
{
    if (!bin) {
        return 0;
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_pe_section_t *s = &bin->sections[i];

        if (s->raw_size > 0
            && offset >= s->raw_offset
            && offset < s->raw_offset + s->raw_size) {
            return s->virtual_address + (offset - s->raw_offset);
        }
    }

    return 0;
}

uint64_t
n00b_pe_rva_to_va(n00b_pe_binary_t *bin, uint32_t rva)
{
    if (!bin) {
        return 0;
    }

    return bin->imagebase + rva;
}

uint32_t
n00b_pe_va_to_rva(n00b_pe_binary_t *bin, uint64_t va)
{
    if (!bin || va < bin->imagebase) {
        return 0;
    }

    return (uint32_t)(va - bin->imagebase);
}

uint32_t
n00b_pe_va_to_offset(n00b_pe_binary_t *bin, uint64_t va)
{
    uint32_t rva = n00b_pe_va_to_rva(bin, va);

    if (rva == 0 && va != bin->imagebase) {
        return 0;
    }

    return n00b_pe_rva_to_offset(bin, rva);
}

n00b_buffer_t *
n00b_pe_get_content_at_rva(n00b_pe_binary_t *bin, uint32_t rva, uint32_t size)
{
    if (!bin || !bin->stream || size == 0) {
        return nullptr;
    }

    uint32_t off = n00b_pe_rva_to_offset(bin, rva);

    if (off == 0) {
        return nullptr;
    }

    size_t buf_len = (size_t)n00b_buffer_len(bin->stream->buf);

    if (off + size > buf_len) {
        return nullptr;
    }

    auto seek_r = n00b_bstream_setpos(bin->stream, off);

    if (n00b_result_is_err(seek_r)) {
        return nullptr;
    }

    auto r = n00b_bstream_read_bytes(bin->stream, size);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r);
    }

    return nullptr;
}

n00b_buffer_t *
n00b_pe_get_content_at_va(n00b_pe_binary_t *bin, uint64_t va, uint32_t size)
{
    if (!bin) {
        return nullptr;
    }

    uint32_t rva = n00b_pe_va_to_rva(bin, va);

    return n00b_pe_get_content_at_rva(bin, rva, size);
}

// ============================================================================
// Section queries
// ============================================================================

n00b_pe_section_t *
n00b_pe_section_by_name(n00b_pe_binary_t *bin, const char *name)
{
    if (!bin || !name) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name
            && strcmp(bin->sections[i].name->data, name) == 0) {
            return &bin->sections[i];
        }
    }

    return nullptr;
}

n00b_pe_section_t *
n00b_pe_section_at_rva(n00b_pe_binary_t *bin, uint32_t rva)
{
    if (!bin) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        uint32_t va   = bin->sections[i].virtual_address;
        uint32_t vsz  = bin->sections[i].virtual_size;

        if (rva >= va && rva < va + vsz) {
            return &bin->sections[i];
        }
    }

    return nullptr;
}

bool
n00b_pe_has_section(n00b_pe_binary_t *bin, const char *name)
{
    return n00b_pe_section_by_name(bin, name) != nullptr;
}

bool
n00b_pe_is_dll(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return false;
    }

    return (bin->characteristics & N00B_PE_CHAR_DLL) != 0;
}

// ============================================================================
// Import queries
// ============================================================================

n00b_pe_import_t *
n00b_pe_import_by_name(n00b_pe_binary_t *bin, const char *dll)
{
    if (!bin || !dll) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_imports; i++) {
        if (bin->imports[i].name
            && strcasecmp(bin->imports[i].name->data, dll) == 0) {
            return &bin->imports[i];
        }
    }

    return nullptr;
}

n00b_pe_imported_func_t *
n00b_pe_imported_func_by_name(n00b_pe_import_t *imp, const char *name)
{
    if (!imp || !name) {
        return nullptr;
    }

    for (uint32_t i = 0; i < imp->num_functions; i++) {
        if (imp->functions[i].name
            && strcmp(imp->functions[i].name->data, name) == 0) {
            return &imp->functions[i];
        }
    }

    return nullptr;
}

bool
n00b_pe_has_imports(n00b_pe_binary_t *bin)
{
    return bin && bin->num_imports > 0;
}

// ============================================================================
// Export queries
// ============================================================================

n00b_pe_exported_func_t *
n00b_pe_export_by_name(n00b_pe_binary_t *bin, const char *name)
{
    if (!bin || !name || !bin->export_info) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->export_info->num_functions; i++) {
        if (bin->export_info->functions[i].name
            && strcmp(bin->export_info->functions[i].name->data, name) == 0) {
            return &bin->export_info->functions[i];
        }
    }

    return nullptr;
}

n00b_pe_exported_func_t *
n00b_pe_export_by_ordinal(n00b_pe_binary_t *bin, uint32_t ordinal)
{
    if (!bin || !bin->export_info) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->export_info->num_functions; i++) {
        if (bin->export_info->functions[i].ordinal == ordinal) {
            return &bin->export_info->functions[i];
        }
    }

    return nullptr;
}

bool
n00b_pe_has_exports(n00b_pe_binary_t *bin)
{
    return bin && bin->export_info != nullptr
           && bin->export_info->num_functions > 0;
}

// ============================================================================
// Rich header queries
// ============================================================================

bool
n00b_pe_has_rich_header(n00b_pe_binary_t *bin)
{
    return bin && bin->num_rich_entries > 0;
}

// ============================================================================
// Debug / TLS / Resource queries
// ============================================================================

bool
n00b_pe_has_tls(n00b_pe_binary_t *bin)
{
    return bin && bin->tls != nullptr;
}

n00b_pe_tls_t *
n00b_pe_get_tls(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    return bin->tls;
}

bool
n00b_pe_has_debug(n00b_pe_binary_t *bin)
{
    return bin && bin->num_debug_entries > 0;
}

n00b_pe_debug_entry_t *
n00b_pe_debug_entry_by_type(n00b_pe_binary_t *bin, uint32_t type)
{
    if (!bin) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_debug_entries; i++) {
        if (bin->debug_entries[i].type == type) {
            return &bin->debug_entries[i];
        }
    }

    return nullptr;
}

n00b_string_t *
n00b_pe_pdb_path(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_debug_entries; i++) {
        if (bin->debug_entries[i].type == N00B_PE_DEBUG_TYPE_CODEVIEW
            && bin->debug_entries[i].pdb_path != nullptr) {
            return bin->debug_entries[i].pdb_path;
        }
    }

    return nullptr;
}

bool
n00b_pe_has_resources(n00b_pe_binary_t *bin)
{
    return bin && bin->resources != nullptr && bin->resources->num_children > 0;
}

n00b_pe_resource_node_t *
n00b_pe_resource_by_type(n00b_pe_binary_t *bin, uint32_t type_id)
{
    if (!bin || !bin->resources) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->resources->num_children; i++) {
        if (bin->resources->children[i].id == type_id) {
            return &bin->resources->children[i];
        }
    }

    return nullptr;
}

// ============================================================================
// Load Configuration queries
// ============================================================================

bool
n00b_pe_has_configuration(n00b_pe_binary_t *bin)
{
    return bin && bin->load_config != nullptr;
}

n00b_pe_load_config_t *
n00b_pe_get_load_config(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    return bin->load_config;
}

bool
n00b_pe_has_guard_cf(n00b_pe_binary_t *bin)
{
    if (!bin || !bin->load_config) {
        return false;
    }

    return (bin->load_config->guard_flags
            & N00B_PE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0;
}

// ============================================================================
// Delay import queries
// ============================================================================

bool
n00b_pe_has_delay_imports(n00b_pe_binary_t *bin)
{
    return bin && bin->num_delay_imports > 0;
}

n00b_pe_delay_import_t *
n00b_pe_delay_import_by_name(n00b_pe_binary_t *bin, const char *dll)
{
    if (!bin || !dll) {
        return nullptr;
    }

    for (uint32_t i = 0; i < bin->num_delay_imports; i++) {
        if (bin->delay_imports[i].name
            && strcasecmp(bin->delay_imports[i].name->data, dll) == 0) {
            return &bin->delay_imports[i];
        }
    }

    return nullptr;
}

// ============================================================================
// Exception queries
// ============================================================================

bool
n00b_pe_has_exceptions(n00b_pe_binary_t *bin)
{
    return bin && bin->num_exceptions > 0;
}

n00b_pe_exception_entry_t *
n00b_pe_exception_at_rva(n00b_pe_binary_t *bin, uint32_t rva)
{
    if (!bin || bin->num_exceptions == 0) {
        return nullptr;
    }

    // Binary search — exception entries are sorted by begin_rva.
    uint32_t lo = 0;
    uint32_t hi = bin->num_exceptions;

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;

        if (rva < bin->exceptions[mid].begin_rva) {
            hi = mid;
        }
        else if (rva >= bin->exceptions[mid].end_rva) {
            lo = mid + 1;
        }
        else {
            return &bin->exceptions[mid];
        }
    }

    return nullptr;
}

// ============================================================================
// COFF symbol queries
// ============================================================================

bool
n00b_pe_has_symbols(n00b_pe_binary_t *bin)
{
    return bin && bin->num_symbols > 0;
}

// ============================================================================
// Bound import queries
// ============================================================================

bool
n00b_pe_has_bound_imports(n00b_pe_binary_t *bin)
{
    return bin && bin->num_bound_imports > 0;
}

// ============================================================================
// Checksum
// ============================================================================

uint32_t
n00b_pe_compute_checksum(n00b_pe_binary_t *bin)
{
    if (!bin || !bin->stream) {
        return 0;
    }

    size_t   file_len = (size_t)n00b_buffer_len(bin->stream->buf);
    const uint8_t *data = (const uint8_t *)bin->stream->buf->data;

    // The checksum field is at pe_offset + 4 (PE sig) + 20 (file hdr) + 64
    // = pe_offset + 88 within the optional header.
    uint32_t checksum_offset = bin->pe_offset + 4 + 20 + 64;

    uint64_t sum = 0;

    for (size_t i = 0; i + 1 < file_len; i += 2) {
        // Skip the 4-byte checksum field.
        if (i >= checksum_offset && i < checksum_offset + 4) {
            continue;
        }

        uint16_t word;

        memcpy(&word, data + i, 2);
        sum += word;

        // Fold carries.
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Handle trailing byte if file length is odd.
    if (file_len % 2 != 0) {
        sum += data[file_len - 1];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Final fold.
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint32_t)((sum & 0xFFFF) + file_len);
}

bool
n00b_pe_verify_checksum(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return false;
    }

    uint32_t stored  = bin->checksum;
    uint32_t computed = n00b_pe_compute_checksum(bin);

    return stored == computed;
}

// ============================================================================
// Section entropy
// ============================================================================

double
n00b_pe_section_entropy(n00b_pe_section_t *section)
{
    if (!section || !section->content) {
        return 0.0;
    }

    size_t len = (size_t)n00b_buffer_len(section->content);

    if (len == 0) {
        return 0.0;
    }

    const uint8_t *data = (const uint8_t *)section->content->data;
    uint64_t freq[256]  = {0};

    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) {
            continue;
        }

        double p = (double)freq[i] / (double)len;

        entropy -= p * log2(p);
    }

    return entropy;
}

// ============================================================================
// Demangled names
// ============================================================================

n00b_string_t *
n00b_pe_imported_func_demangled(n00b_pe_imported_func_t *f)
{
    if (!f || !f->name) {
        return nullptr;
    }

    return n00b_demangle(f->name->data);
}

n00b_string_t *
n00b_pe_exported_func_demangled(n00b_pe_exported_func_t *f)
{
    if (!f || !f->name) {
        return nullptr;
    }

    return n00b_demangle(f->name->data);
}

// ============================================================================
// Import hash (imphash)
// ============================================================================

/// Helper: lowercase a C string in place.
static void
str_tolower(char *s)
{
    for (; *s; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

n00b_string_t *
n00b_pe_imphash(n00b_pe_binary_t *bin)
{
    if (!bin || bin->num_imports == 0) {
        return nullptr;
    }

    // Build the concatenation: "dll.func,dll.func,..."
    // Per pefile convention, strip ".dll" extension from DLL name.
    size_t total_len = 0;

    // First pass: compute total length.
    for (uint32_t i = 0; i < bin->num_imports; i++) {
        n00b_pe_import_t *imp = &bin->imports[i];

        if (!imp->name) {
            continue;
        }

        size_t dll_len = strlen(imp->name->data);

        // Strip ".dll" suffix.
        if (dll_len > 4) {
            const char *suffix = imp->name->data + dll_len - 4;

            if (strcasecmp(suffix, ".dll") == 0) {
                dll_len -= 4;
            }
        }

        for (uint32_t f = 0; f < imp->num_functions; f++) {
            if (imp->functions[f].is_ordinal) {
                total_len += dll_len + 1 + 12; // "dll.ord123" approx
            }
            else if (imp->functions[f].name) {
                total_len += dll_len + 1 + strlen(imp->functions[f].name->data);
            }
            else {
                continue;
            }

            total_len += 1; // comma separator
        }
    }

    if (total_len == 0) {
        return nullptr;
    }

    // Second pass: build the string.
    char  *buf = n00b_alloc_flex(char, char, total_len + 1);
    size_t pos = 0;
    bool   first = true;

    for (uint32_t i = 0; i < bin->num_imports; i++) {
        n00b_pe_import_t *imp = &bin->imports[i];

        if (!imp->name) {
            continue;
        }

        size_t dll_len = strlen(imp->name->data);
        const char *dll_ext_check = imp->name->data + dll_len - 4;

        if (dll_len > 4 && strcasecmp(dll_ext_check, ".dll") == 0) {
            dll_len -= 4;
        }

        for (uint32_t f = 0; f < imp->num_functions; f++) {
            const char *func_name = nullptr;
            char        ord_buf[16];

            if (imp->functions[f].is_ordinal) {
                snprintf(ord_buf, sizeof(ord_buf), "ord%u",
                         (unsigned)imp->functions[f].ordinal);
                func_name = ord_buf;
            }
            else if (imp->functions[f].name) {
                func_name = imp->functions[f].name->data;
            }
            else {
                continue;
            }

            if (!first) {
                buf[pos++] = ',';
            }

            memcpy(buf + pos, imp->name->data, dll_len);
            pos += dll_len;
            buf[pos++] = '.';
            size_t fn_len = strlen(func_name);

            memcpy(buf + pos, func_name, fn_len);
            pos += fn_len;
            first = false;
        }
    }

    buf[pos] = '\0';

    // Lowercase everything.
    str_tolower(buf);

    // MD5 hash.
    uint8_t md5_digest[16];

    n00b_md5((const uint8_t *)buf, pos, md5_digest);

    // Convert to hex string.
    char hex[33];

    for (int i = 0; i < 16; i++) {
        snprintf(hex + i * 2, 3, "%02x", md5_digest[i]);
    }

    return n00b_string_from_cstr(hex);
}

// ============================================================================
// Authenticode / Certificate queries
// ============================================================================

bool
n00b_pe_has_signatures(n00b_pe_binary_t *bin)
{
    return bin && bin->num_certificates > 0;
}

n00b_buffer_t *
n00b_pe_authentihash_sha256(n00b_pe_binary_t *bin)
{
    if (!bin || !bin->stream) {
        return nullptr;
    }

    size_t         file_len = (size_t)n00b_buffer_len(bin->stream->buf);
    const uint8_t *data     = (const uint8_t *)bin->stream->buf->data;

    // Regions to exclude:
    // 1. Checksum field: pe_offset + 4 + 20 + 64, 4 bytes
    // 2. Certificate data dir entry: pe_offset + 4 + 20 + 128 (offset of DD[4]), 8 bytes
    //    DD starts at pe_offset + 4 + 20 + 112. DD[4] is at +4*8 = +32.
    //    So cert DD entry is at pe_offset + 4 + 20 + 112 + 32 = pe_offset + 168
    // 3. Certificate table data: from cert_off to cert_off + cert_size

    uint32_t checksum_off = bin->pe_offset + 4 + 20 + 64;
    uint32_t certdd_off   = bin->pe_offset + 4 + 20 + 112 + N00B_PE_DD_CERTIFICATE * 8;
    uint32_t cert_off     = 0;
    uint32_t cert_size    = 0;

    if (bin->num_data_dirs > N00B_PE_DD_CERTIFICATE) {
        cert_off  = bin->data_dirs[N00B_PE_DD_CERTIFICATE].VirtualAddress;
        cert_size = bin->data_dirs[N00B_PE_DD_CERTIFICATE].Size;
    }

    // Hash end is either cert_off (excluding cert table) or file_len.
    size_t hash_end = file_len;

    if (cert_off > 0 && cert_size > 0 && cert_off < file_len) {
        hash_end = cert_off;
    }

    n00b_sha256_ctx_t ctx;
    n00b_sha256_init(&ctx);

    // Hash in three segments with exclusions:
    // Segment 1: [0, checksum_off)
    if (checksum_off > 0) {
        n00b_sha256_update(&ctx, data, checksum_off);
    }

    // Skip checksum (4 bytes)
    size_t after_ck = checksum_off + 4;

    // Segment 2: [after_ck, certdd_off)
    if (certdd_off > after_ck) {
        n00b_sha256_update(&ctx, data + after_ck, certdd_off - after_ck);
    }

    // Skip cert data dir entry (8 bytes)
    size_t after_dd = certdd_off + 8;

    // Segment 3: [after_dd, hash_end)
    if (hash_end > after_dd) {
        n00b_sha256_update(&ctx, data + after_dd, hash_end - after_dd);
    }

    n00b_sha256_digest_t digest;
    n00b_sha256_finalize(&ctx, digest);

    n00b_buffer_t *result = n00b_buffer_new(32);

    memcpy(result->data, digest, 32);
    result->byte_len = 32;

    return result;
}

// ============================================================================
// Resource interpretation
// ============================================================================

/// Find the first data leaf under a resource type node (depth-first).
/// Resource tree is: root → type → name/id → language → data leaf.
static n00b_buffer_t *
resource_first_leaf(n00b_pe_resource_node_t *type_node)
{
    if (!type_node) {
        return nullptr;
    }

    // type_node is a directory whose children are name/id nodes
    for (uint32_t i = 0; i < type_node->num_children; i++) {
        n00b_pe_resource_node_t *mid = &type_node->children[i];

        if (!mid->is_directory) {
            // Direct data leaf at level 1 (unusual but handle it)
            if (mid->data) {
                return mid->data;
            }

            continue;
        }

        // mid is a directory whose children are language leaves
        for (uint32_t j = 0; j < mid->num_children; j++) {
            n00b_pe_resource_node_t *leaf = &mid->children[j];

            if (!leaf->is_directory && leaf->data) {
                return leaf->data;
            }
        }
    }

    return nullptr;
}

/// Read a UTF-16LE u16 from a raw buffer at a byte offset.
static uint16_t
read_u16le(const uint8_t *data, size_t off)
{
    uint16_t v;

    memcpy(&v, data + off, 2);

    return v;
}

/// Read a little-endian u32 from a raw buffer at a byte offset.
static uint32_t
read_u32le(const uint8_t *data, size_t off)
{
    uint32_t v;

    memcpy(&v, data + off, 4);

    return v;
}

/// Align a byte offset up to the next DWORD boundary.
static size_t
align4(size_t off)
{
    return (off + 3) & ~(size_t)3;
}

/// Read a null-terminated UTF-16LE string starting at `off`.
/// Returns UTF-8 string and advances `off` past the null terminator.
static n00b_string_t *
read_utf16_sz(const uint8_t *data, size_t len, size_t *off)
{
    char   utf8[1024];
    size_t utf8_len = 0;
    size_t pos      = *off;

    while (pos + 2 <= len) {
        uint16_t cp = read_u16le(data, pos);
        pos += 2;

        if (cp == 0) {
            break;
        }

        if (cp < 0x80 && utf8_len < 1020) {
            utf8[utf8_len++] = (char)cp;
        }
        else if (cp < 0x800 && utf8_len < 1020) {
            utf8[utf8_len++] = (char)(0xC0 | (cp >> 6));
            utf8[utf8_len++] = (char)(0x80 | (cp & 0x3F));
        }
        else if (utf8_len < 1020) {
            utf8[utf8_len++] = (char)(0xE0 | (cp >> 12));
            utf8[utf8_len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            utf8[utf8_len++] = (char)(0x80 | (cp & 0x3F));
        }
    }

    *off = pos;

    if (utf8_len == 0) {
        return nullptr;
    }

    return n00b_string_from_raw(utf8, utf8_len);
}

n00b_pe_version_info_t *
n00b_pe_get_version_info(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    n00b_pe_resource_node_t *ver_node = n00b_pe_resource_by_type(bin,
                                                                  N00B_PE_RT_VERSION);
    n00b_buffer_t *buf = resource_first_leaf(ver_node);

    if (!buf) {
        return nullptr;
    }

    const uint8_t *d   = (const uint8_t *)buf->data;
    size_t         len = (size_t)n00b_buffer_len(buf);

    // VS_VERSIONINFO: u16 wLength, u16 wValueLength, u16 wType,
    //                 then UTF-16LE key "VS_VERSION_INFO\0", DWORD-align,
    //                 then VS_FIXEDFILEINFO (52 bytes, sig 0xFEEF04BD).
    if (len < 6) {
        return nullptr;
    }

    // Skip wLength(2) + wValueLength(2) + wType(2)
    size_t pos = 6;

    // Skip the key string "VS_VERSION_INFO"
    // Each char is 2 bytes UTF-16LE, 15 chars + null = 32 bytes
    // But let's just scan past it.
    while (pos + 2 <= len && read_u16le(d, pos) != 0) {
        pos += 2;
    }

    pos += 2; // skip null terminator
    pos = align4(pos);

    n00b_pe_version_info_t *vi = n00b_alloc(n00b_pe_version_info_t);

    // Check for VS_FIXEDFILEINFO (signature 0xFEEF04BD)
    if (pos + 52 <= len && read_u32le(d, pos) == 0xFEEF04BD) {
        // VS_FIXEDFILEINFO layout:
        // +0:  dwSignature (4)
        // +4:  dwStrucVersion (4)
        // +8:  dwFileVersionMS (4)
        // +12: dwFileVersionLS (4)
        // +16: dwProductVersionMS (4)
        // +20: dwProductVersionLS (4)
        // +24: dwFileFlagsMask (4)
        // +28: dwFileFlags (4)
        // +32: dwFileOS (4)
        // +36: dwFileType (4)
        // +40: dwFileSubtype (4)
        // +44: dwFileDateMS (4)
        // +48: dwFileDateLS (4)
        vi->file_version_ms    = read_u32le(d, pos + 8);
        vi->file_version_ls    = read_u32le(d, pos + 12);
        vi->product_version_ms = read_u32le(d, pos + 16);
        vi->product_version_ls = read_u32le(d, pos + 20);
        vi->file_flags_mask    = read_u32le(d, pos + 24);
        vi->file_flags         = read_u32le(d, pos + 28);
        vi->file_os            = read_u32le(d, pos + 32);
        vi->file_type          = read_u32le(d, pos + 36);
        vi->file_subtype       = read_u32le(d, pos + 40);

        pos += 52;
    }

    pos = align4(pos);

    // Now parse children: StringFileInfo / VarFileInfo
    // We look for StringFileInfo which contains StringTable(s).
    // StringFileInfo: wLength(2), wValueLength(2), wType(2),
    //                 key="StringFileInfo\0", DWORD-align,
    //                 then StringTable children.
    if (pos + 6 > len) {
        return vi;
    }

    uint16_t sfi_len = read_u16le(d, pos);
    size_t   sfi_end = pos + sfi_len;

    if (sfi_end > len) {
        sfi_end = len;
    }

    // Skip wLength + wValueLength + wType
    size_t sfi_pos = pos + 6;

    // Read and check key
    n00b_string_t *sfi_key = read_utf16_sz(d, sfi_end, &sfi_pos);

    if (!sfi_key || strcmp(sfi_key->data, "StringFileInfo") != 0) {
        return vi;
    }

    sfi_pos = align4(sfi_pos);

    // Parse StringTable children
    // StringTable: wLength(2), wValueLength(2), wType(2),
    //              key="LANGCP\0" (8 hex chars), DWORD-align,
    //              then String children.
    if (sfi_pos + 6 > sfi_end) {
        return vi;
    }

    uint16_t st_len = read_u16le(d, sfi_pos);
    size_t   st_end = sfi_pos + st_len;

    if (st_end > sfi_end) {
        st_end = sfi_end;
    }

    size_t st_pos = sfi_pos + 6;

    // Skip StringTable key (e.g. "040904b0")
    while (st_pos + 2 <= st_end && read_u16le(d, st_pos) != 0) {
        st_pos += 2;
    }

    st_pos += 2; // skip null
    st_pos = align4(st_pos);

    // Count strings (first pass)
    uint32_t count = 0;
    size_t   scan  = st_pos;

    while (scan + 6 <= st_end) {
        uint16_t s_len = read_u16le(d, scan);

        if (s_len < 6) {
            break;
        }

        count++;
        scan += s_len;
        scan = align4(scan);
    }

    if (count == 0) {
        return vi;
    }

    vi->strings     = n00b_alloc_array(n00b_pe_version_string_t, count);
    vi->num_strings = count;

    // Second pass: extract key-value pairs
    scan = st_pos;

    for (uint32_t i = 0; i < count && scan + 6 <= st_end; i++) {
        uint16_t s_len  = read_u16le(d, scan);
        uint16_t s_vlen = read_u16le(d, scan + 2);
        // s_type at scan+4

        if (s_len < 6) {
            vi->num_strings = i;
            break;
        }

        size_t s_end  = scan + s_len;
        size_t s_pos  = scan + 6;

        vi->strings[i].key = read_utf16_sz(d, s_end, &s_pos);
        s_pos               = align4(s_pos);

        if (s_vlen > 0 && s_pos + 2 <= s_end) {
            vi->strings[i].value = read_utf16_sz(d, s_end, &s_pos);
        }

        scan = s_end;
        scan = align4(scan);
    }

    return vi;
}

n00b_string_t *
n00b_pe_get_manifest(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return nullptr;
    }

    n00b_pe_resource_node_t *man_node = n00b_pe_resource_by_type(bin,
                                                                  N00B_PE_RT_MANIFEST);
    n00b_buffer_t *buf = resource_first_leaf(man_node);

    if (!buf) {
        return nullptr;
    }

    size_t len = (size_t)n00b_buffer_len(buf);

    if (len == 0) {
        return nullptr;
    }

    return n00b_string_from_raw(buf->data, len);
}

uint32_t
n00b_pe_icon_count(n00b_pe_binary_t *bin)
{
    if (!bin) {
        return 0;
    }

    n00b_pe_resource_node_t *grp = n00b_pe_resource_by_type(bin,
                                                             N00B_PE_RT_GROUP_ICON);
    n00b_buffer_t *buf = resource_first_leaf(grp);

    if (!buf) {
        return 0;
    }

    // GRPICONDIR: u16 idReserved, u16 idType, u16 idCount
    size_t len = (size_t)n00b_buffer_len(buf);

    if (len < 6) {
        return 0;
    }

    return read_u16le((const uint8_t *)buf->data, 4);
}

n00b_buffer_t *
n00b_pe_get_icon(n00b_pe_binary_t *bin, uint32_t index)
{
    if (!bin) {
        return nullptr;
    }

    n00b_pe_resource_node_t *grp = n00b_pe_resource_by_type(bin,
                                                             N00B_PE_RT_GROUP_ICON);
    n00b_buffer_t *grp_buf = resource_first_leaf(grp);

    if (!grp_buf) {
        return nullptr;
    }

    const uint8_t *gd  = (const uint8_t *)grp_buf->data;
    size_t         glen = (size_t)n00b_buffer_len(grp_buf);

    if (glen < 6) {
        return nullptr;
    }

    uint16_t count = read_u16le(gd, 4);

    if (index >= count) {
        return nullptr;
    }

    // GRPICONDIRENTRY is 14 bytes each, starting at offset 6.
    // Layout: bWidth(1), bHeight(1), bColorCount(1), bReserved(1),
    //         wPlanes(2), wBitCount(2), dwBytesInRes(4), nID(2)
    size_t entry_off = 6 + (size_t)index * 14;

    if (entry_off + 14 > glen) {
        return nullptr;
    }

    uint16_t icon_id = read_u16le(gd, entry_off + 12);

    // Find the RT_ICON resource with matching ID
    n00b_pe_resource_node_t *icon_type = n00b_pe_resource_by_type(bin,
                                                                   N00B_PE_RT_ICON);

    if (!icon_type || !icon_type->is_directory) {
        return nullptr;
    }

    for (uint32_t i = 0; i < icon_type->num_children; i++) {
        n00b_pe_resource_node_t *id_node = &icon_type->children[i];

        if (id_node->id != icon_id) {
            continue;
        }

        // If directory, get first language leaf
        if (id_node->is_directory) {
            for (uint32_t j = 0; j < id_node->num_children; j++) {
                if (!id_node->children[j].is_directory
                    && id_node->children[j].data) {
                    return id_node->children[j].data;
                }
            }
        }
        else if (id_node->data) {
            return id_node->data;
        }
    }

    return nullptr;
}

// ============================================================================
// Relocation block grouping
// ============================================================================

n00b_pe_reloc_block_t *
n00b_pe_reloc_blocks(n00b_pe_binary_t *bin, uint32_t *num_blocks)
{
    if (!bin || !num_blocks || bin->num_relocations == 0) {
        if (num_blocks) {
            *num_blocks = 0;
        }

        return nullptr;
    }

    // First pass: count distinct pages.
    uint32_t count    = 0;
    uint32_t prev_page = ~(uint32_t)0;

    for (uint32_t i = 0; i < bin->num_relocations; i++) {
        uint32_t page = bin->relocations[i].rva & ~(uint32_t)0xFFF;

        if (page != prev_page) {
            count++;
            prev_page = page;
        }
    }

    n00b_pe_reloc_block_t *blocks = n00b_alloc_array(n00b_pe_reloc_block_t,
                                                      count);
    *num_blocks = count;

    // Second pass: fill blocks.
    uint32_t bi       = 0;
    uint32_t start    = 0;
    prev_page         = bin->relocations[0].rva & ~(uint32_t)0xFFF;

    for (uint32_t i = 1; i <= bin->num_relocations; i++) {
        uint32_t page = (i < bin->num_relocations)
                            ? (bin->relocations[i].rva & ~(uint32_t)0xFFF)
                            : ~(uint32_t)0;

        if (page != prev_page) {
            blocks[bi].page_rva    = prev_page;
            blocks[bi].entries     = &bin->relocations[start];
            blocks[bi].num_entries = i - start;
            bi++;
            start     = i;
            prev_page = page;
        }
    }

    return blocks;
}
