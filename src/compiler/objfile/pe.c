#include <string.h>
#include "compiler/objfile/pe.h"

// ============================================================================
// Helpers
// ============================================================================

static inline bool
pe_bstream_setpos(n00b_bstream_t *stream, size_t offset)
{
    auto r = n00b_bstream_setpos(stream, offset);
    return n00b_result_is_ok(r);
}

/// Read a NUL-terminated C string at a file offset.
static n00b_string_t *
read_string_at(n00b_bstream_t *stream, size_t offset)
{
    size_t saved = n00b_bstream_pos(stream);

    if (!pe_bstream_setpos(stream, offset)) {
        return nullptr;
    }

    auto r = n00b_bstream_read_cstring(stream);
    (void)pe_bstream_setpos(stream, saved);

    if (n00b_result_is_ok(r)) {
        return n00b_result_get(r);
    }

    return nullptr;
}

/// Internal alias for the public RVA-to-offset utility.
static inline uint32_t
rva_to_file_offset(n00b_pe_binary_t *bin, uint32_t rva)
{
    return n00b_pe_rva_to_offset(bin, rva);
}

// ============================================================================
// Pass 1: DOS header
// ============================================================================

static n00b_result_t(int)
parse_dos_header(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (!pe_bstream_setpos(stream, 0)) {
        return n00b_result_err(int, N00B_ERR_READ);
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (buf_len < N00B_PE_DOS_HEADER_SIZE) {
        return n00b_result_err(int, N00B_ERR_READ);
    }

    // Read full DOS header (64 bytes)
    const uint8_t *p = (const uint8_t *)stream->buf->data;

    memcpy(&bin->dos_header, p, N00B_PE_DOS_HEADER_SIZE);

    if (bin->dos_header.e_magic != N00B_PE_MAGIC_MZ) {
        return n00b_result_err(int, N00B_ERR_PARSE);
    }

    bin->pe_offset = bin->dos_header.e_lfanew;

    // Capture DOS stub (bytes between end of DOS header and PE signature)
    if (bin->pe_offset > N00B_PE_DOS_HEADER_SIZE) {
        uint32_t stub_size = bin->pe_offset - N00B_PE_DOS_HEADER_SIZE;

        if (!pe_bstream_setpos(stream, N00B_PE_DOS_HEADER_SIZE)) {
            return n00b_result_err(int, N00B_ERR_READ);
        }

        auto stub_r = n00b_bstream_read_bytes(stream, stub_size);

        if (n00b_result_is_ok(stub_r)) {
            bin->dos_stub = n00b_result_get(stub_r);
        }
    }

    return n00b_result_ok(int, 0);
}

// ============================================================================
// Pass 1b: Rich header (between DOS header and PE signature)
// ============================================================================

static void
parse_rich_header(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    // Rich header lives between DOS header (0x40) and PE signature (e_lfanew).
    // Search backward from e_lfanew for "Rich" magic. The 4 bytes after "Rich"
    // are the XOR key. Decrypt backward until "DanS" magic. Entries are pairs
    // of (comp_id ^ key, count ^ key). comp_id = (tool_id << 16) | build_id.

    uint32_t pe_off = bin->pe_offset;

    if (pe_off < N00B_PE_DOS_HEADER_SIZE + 8) {
        return; // No room for a rich header.
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (pe_off > buf_len) {
        return;
    }

    const uint8_t *base = (const uint8_t *)stream->buf->data;

    // Search backward from pe_off for "Rich" signature (4-byte aligned).
    uint32_t rich_off = 0;

    for (uint32_t off = pe_off - 4; off >= N00B_PE_DOS_HEADER_SIZE; off -= 4) {
        uint32_t val;

        memcpy(&val, base + off, 4);

        if (val == N00B_PE_RICH_MAGIC) {
            rich_off = off;
            break;
        }

        if (off < 4) {
            break;
        }
    }

    if (rich_off == 0) {
        return; // No Rich header found.
    }

    // XOR key is the 4 bytes immediately after "Rich".
    if (rich_off + 8 > pe_off) {
        return;
    }

    uint32_t key;
    memcpy(&key, base + rich_off + 4, 4);
    bin->rich_key = key;

    // Decrypt backward from "Rich" to find "DanS".
    // The decrypted region starts with "DanS" followed by 3 zero dwords (padding),
    // then pairs of (comp_id, count).
    uint32_t dans_off = 0;

    for (uint32_t off = rich_off - 4; off >= N00B_PE_DOS_HEADER_SIZE; off -= 4) {
        uint32_t val;

        memcpy(&val, base + off, 4);

        if ((val ^ key) == N00B_PE_DANS_MAGIC) {
            dans_off = off;
            break;
        }

        if (off < 4) {
            break;
        }
    }

    if (dans_off == 0) {
        return; // Malformed: "Rich" without "DanS".
    }

    // Store raw decrypted bytes (from DanS to Rich inclusive).
    uint32_t raw_size = rich_off - dans_off;
    n00b_buffer_t *raw = n00b_buffer_new(raw_size);
    memcpy(raw->data, base + dans_off, raw_size);
    raw->byte_len = raw_size;

    // Decrypt in place.
    uint8_t *rp = (uint8_t *)raw->data;

    for (uint32_t i = 0; i < raw_size; i += 4) {
        uint32_t val;

        memcpy(&val, rp + i, 4);
        val ^= key;
        memcpy(rp + i, &val, 4);
    }

    bin->rich_raw = raw;

    // Entries start after "DanS" + 3 padding dwords = 16 bytes into the raw buffer.
    // Each entry is 8 bytes: (comp_id, count).
    if (raw_size <= 16) {
        return; // Only header, no entries.
    }

    uint32_t entry_bytes = raw_size - 16;
    uint32_t num_entries = entry_bytes / 8;

    if (num_entries == 0) {
        return;
    }

    n00b_pe_rich_entry_t *entries = n00b_alloc_flex(n00b_pe_rich_entry_t,
                                                    n00b_pe_rich_entry_t,
                                                    num_entries);

    const uint8_t *ep = (const uint8_t *)raw->data + 16;

    for (uint32_t i = 0; i < num_entries; i++) {
        uint32_t comp_id;
        uint32_t count;

        memcpy(&comp_id, ep + i * 8, 4);
        memcpy(&count, ep + i * 8 + 4, 4);

        entries[i].tool_id  = (uint16_t)(comp_id >> 16);
        entries[i].build_id = (uint16_t)(comp_id & 0xFFFF);
        entries[i].count    = count;
    }

    bin->rich_entries     = entries;
    bin->num_rich_entries = num_entries;
}

// ============================================================================
// Pass 2: PE signature + file header + optional header + data directories
// ============================================================================

/// Helper macro: read a typed value from stream, store into field on success.
#define READ_INTO(stream, type, field)                          \
    do {                                                         \
        auto _r = n00b_bstream_read_##type(stream);              \
        if (n00b_result_is_ok(_r)) (field) = n00b_result_get(_r); \
    } while (0)

static n00b_result_t(int)
parse_pe_headers(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (!pe_bstream_setpos(stream, bin->pe_offset)) {
        return n00b_result_err(int, N00B_ERR_READ);
    }

    // Validate PE signature
    auto sig_r = n00b_bstream_read_u32(stream);

    if (n00b_result_is_err(sig_r)) {
        return n00b_result_err(int, N00B_ERR_READ);
    }

    if (n00b_result_get(sig_r) != N00B_PE_SIGNATURE) {
        return n00b_result_err(int, N00B_ERR_PARSE);
    }

    // File header (20 bytes)
    uint16_t num_sections = 0;

    READ_INTO(stream, u16, bin->machine);
    READ_INTO(stream, u16, num_sections);
    READ_INTO(stream, u32, bin->time_date_stamp);
    READ_INTO(stream, u32, bin->pointer_to_symbol_table);
    READ_INTO(stream, u32, bin->number_of_symbols);

    auto ohsz_r = n00b_bstream_read_u16(stream);
    (void)ohsz_r;

    READ_INTO(stream, u16, bin->characteristics);

    // Optional header — check magic
    auto omag_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(omag_r)) {
        return n00b_result_err(int, N00B_ERR_READ);
    }

    bin->magic = n00b_result_get(omag_r);

    if (bin->magic != N00B_PE_OPT_MAGIC_PE32P) {
        return n00b_result_err(int, N00B_ERR_NOT_SUPPORTED);
    }

    READ_INTO(stream, u8,  bin->major_linker_version);
    READ_INTO(stream, u8,  bin->minor_linker_version);
    READ_INTO(stream, u32, bin->size_of_code);
    READ_INTO(stream, u32, bin->size_of_initialized_data);
    READ_INTO(stream, u32, bin->size_of_uninitialized_data);
    READ_INTO(stream, u32, bin->entry_point);
    READ_INTO(stream, u32, bin->base_of_code);
    READ_INTO(stream, u64, bin->imagebase);
    READ_INTO(stream, u32, bin->section_alignment);
    READ_INTO(stream, u32, bin->file_alignment);
    READ_INTO(stream, u16, bin->major_os_version);
    READ_INTO(stream, u16, bin->minor_os_version);
    READ_INTO(stream, u16, bin->major_image_version);
    READ_INTO(stream, u16, bin->minor_image_version);
    READ_INTO(stream, u16, bin->major_subsystem_version);
    READ_INTO(stream, u16, bin->minor_subsystem_version);
    READ_INTO(stream, u32, bin->win32_version_value);
    READ_INTO(stream, u32, bin->size_of_image);
    READ_INTO(stream, u32, bin->size_of_headers);
    READ_INTO(stream, u32, bin->checksum);
    READ_INTO(stream, u16, bin->subsystem);
    READ_INTO(stream, u16, bin->dll_characteristics);
    READ_INTO(stream, u64, bin->size_of_stack_reserve);
    READ_INTO(stream, u64, bin->size_of_stack_commit);
    READ_INTO(stream, u64, bin->size_of_heap_reserve);
    READ_INTO(stream, u64, bin->size_of_heap_commit);
    READ_INTO(stream, u32, bin->loader_flags);

    // NumberOfRvaAndSizes
    auto ndd_r = n00b_bstream_read_u32(stream);
    uint32_t num_dd = N00B_PE_NUM_DATA_DIRS;

    if (n00b_result_is_ok(ndd_r)) {
        uint32_t v = n00b_result_get(ndd_r);

        if (v < num_dd) {
            num_dd = v;
        }
    }

    bin->num_data_dirs = num_dd;

    // Data directories
    for (uint32_t i = 0; i < num_dd; i++) {
        READ_INTO(stream, u32, bin->data_dirs[i].VirtualAddress);
        READ_INTO(stream, u32, bin->data_dirs[i].Size);
    }

    // Now store num_sections so parse_sections can use it
    bin->num_sections = num_sections;

    return n00b_result_ok(int, 0);
}

// ============================================================================
// Pass 3: Sections
// ============================================================================

static void
parse_sections(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    uint32_t n = bin->num_sections;

    if (n == 0) {
        return;
    }

    bin->sections = n00b_alloc_array(n00b_pe_section_t, n);

    // Section headers follow immediately after the optional header.
    // Position: pe_offset + 4 (sig) + 20 (file hdr) + optional header size
    // The optional header size for PE32+ is 240 bytes.
    size_t sec_hdr_start = bin->pe_offset + 4 + N00B_PE_FILE_HEADER_SIZE
                           + N00B_PE_OPTIONAL_HEADER64_SIZE;
    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    for (uint32_t i = 0; i < n; i++) {
        size_t off = sec_hdr_start + (size_t)i * N00B_PE_SECTION_HEADER_SIZE;

        if (off + N00B_PE_SECTION_HEADER_SIZE > buf_len) {
            bin->num_sections = i;
            return;
        }

        if (!pe_bstream_setpos(stream, off)) {
            bin->num_sections = i;
            return;
        }

        // Name: 8-byte fixed field, may not be NUL-terminated
        auto name_r = n00b_bstream_read_bytes(stream, 8);

        if (n00b_result_is_ok(name_r)) {
            n00b_buffer_t *nb     = n00b_result_get(name_r);
            const char    *rawnam = nb->data;
            size_t         namlen = strnlen(rawnam, 8);

            bin->sections[i].name = n00b_string_from_raw(rawnam, namlen);
        }

        auto vs_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(vs_r)) {
            bin->sections[i].virtual_size = n00b_result_get(vs_r);
        }

        auto va_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(va_r)) {
            bin->sections[i].virtual_address = n00b_result_get(va_r);
        }

        auto srd_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(srd_r)) {
            bin->sections[i].raw_size = n00b_result_get(srd_r);
        }

        auto prd_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(prd_r)) {
            bin->sections[i].raw_offset = n00b_result_get(prd_r);
        }

        // Skip PointerToRelocations, PointerToLinenumbers,
        //      NumberOfRelocations, NumberOfLinenumbers
        if (!pe_bstream_setpos(stream, n00b_bstream_pos(stream) + 12)) {
            bin->num_sections = i;
            return;
        }

        auto ch_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(ch_r)) {
            bin->sections[i].characteristics = n00b_result_get(ch_r);
        }

        // Load section content
        uint32_t raw_off  = bin->sections[i].raw_offset;
        uint32_t raw_size = bin->sections[i].raw_size;

        if (raw_size > 0 && raw_off > 0 && raw_off + raw_size <= buf_len) {
            if (!pe_bstream_setpos(stream, raw_off)) {
                continue;
            }

            auto data_r = n00b_bstream_read_bytes(stream, raw_size);

            if (n00b_result_is_ok(data_r)) {
                bin->sections[i].content = n00b_result_get(data_r);
            }
        }
    }
}

// ============================================================================
// Pass 4: Imports
// ============================================================================

static void
parse_imports(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_IMPORT) {
        return;
    }

    uint32_t import_rva  = bin->data_dirs[N00B_PE_DD_IMPORT].VirtualAddress;
    uint32_t import_size = bin->data_dirs[N00B_PE_DD_IMPORT].Size;

    if (import_rva == 0 || import_size == 0) {
        return;
    }

    uint32_t import_off = rva_to_file_offset(bin, import_rva);

    if (import_off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    // Count descriptors (terminated by all-zero 20-byte entry)
    uint32_t count = 0;

    for (uint32_t i = 0;; i++) {
        size_t off = import_off + (size_t)i * N00B_PE_IMPORT_DESCRIPTOR_SIZE;

        if (off + N00B_PE_IMPORT_DESCRIPTOR_SIZE > buf_len) {
            break;
        }

        // Check if descriptor is all zeros (terminator)
        const uint8_t *p = (const uint8_t *)stream->buf->data + off;
        bool all_zero    = true;

        for (int j = 0; j < N00B_PE_IMPORT_DESCRIPTOR_SIZE; j++) {
            if (p[j] != 0) {
                all_zero = false;
                break;
            }
        }

        if (all_zero) {
            break;
        }

        count++;
    }

    if (count == 0) {
        return;
    }

    bin->imports     = n00b_alloc_array(n00b_pe_import_t, count);
    bin->num_imports = count;

    for (uint32_t i = 0; i < count; i++) {
        size_t off = import_off + (size_t)i * N00B_PE_IMPORT_DESCRIPTOR_SIZE;

        if (!pe_bstream_setpos(stream, off)) {
            bin->num_imports = i;
            break;
        }

        uint32_t ilt_rva = 0;
        auto     ilt_r   = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(ilt_r)) {
            ilt_rva = n00b_result_get(ilt_r);
        }

        bin->imports[i].ilt_rva = ilt_rva;

        READ_INTO(stream, u32, bin->imports[i].time_date_stamp);
        READ_INTO(stream, u32, bin->imports[i].forwarder_chain);

        uint32_t name_rva = 0;
        auto     name_r   = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(name_r)) {
            name_rva = n00b_result_get(name_r);
        }

        uint32_t iat_rva = 0;
        auto     iat_r   = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(iat_r)) {
            iat_rva = n00b_result_get(iat_r);
        }

        bin->imports[i].iat_rva = iat_rva;

        // Read DLL name
        if (name_rva != 0) {
            uint32_t name_off = rva_to_file_offset(bin, name_rva);

            if (name_off != 0) {
                bin->imports[i].name = read_string_at(stream, name_off);
            }
        }

        // Read ILT entries (8-byte thunks for PE32+, terminated by zero)
        uint32_t thunk_rva = ilt_rva != 0 ? ilt_rva : iat_rva;

        if (thunk_rva == 0) {
            continue;
        }

        uint32_t thunk_off = rva_to_file_offset(bin, thunk_rva);

        if (thunk_off == 0) {
            continue;
        }

        // Count thunks
        uint32_t func_count = 0;

        for (uint32_t j = 0;; j++) {
            size_t toff = thunk_off + (size_t)j * 8;

            if (toff + 8 > buf_len) {
                break;
            }

            if (!pe_bstream_setpos(stream, toff)) {
                break;
            }

            auto tv_r = n00b_bstream_read_u64(stream);

            if (n00b_result_is_err(tv_r)) {
                break;
            }

            if (n00b_result_get(tv_r) == 0) {
                break;
            }

            func_count++;
        }

        if (func_count == 0) {
            continue;
        }

        bin->imports[i].functions = n00b_alloc_array(n00b_pe_imported_func_t,
                                                      func_count);
        bin->imports[i].num_functions = func_count;

        for (uint32_t j = 0; j < func_count; j++) {
            size_t toff = thunk_off + (size_t)j * 8;

            if (!pe_bstream_setpos(stream, toff)) {
                break;
            }

            auto tv_r = n00b_bstream_read_u64(stream);

            if (n00b_result_is_err(tv_r)) {
                break;
            }

            uint64_t thunk_val = n00b_result_get(tv_r);

            bin->imports[i].functions[j].iat_value = thunk_val;

            if (thunk_val & N00B_PE_IMPORT_ORDINAL_FLAG64) {
                // Ordinal import
                bin->imports[i].functions[j].is_ordinal = true;
                bin->imports[i].functions[j].ordinal
                    = (uint16_t)(thunk_val & 0xFFFF);
            }
            else {
                // Import by name: thunk_val is RVA to hint/name entry
                uint32_t hn_off = rva_to_file_offset(bin, (uint32_t)thunk_val);

                if (hn_off != 0 && hn_off + 2 < buf_len) {
                    if (!pe_bstream_setpos(stream, hn_off)) {
                        continue;
                    }

                    auto hint_r = n00b_bstream_read_u16(stream);

                    if (n00b_result_is_ok(hint_r)) {
                        bin->imports[i].functions[j].hint
                            = n00b_result_get(hint_r);
                    }

                    auto fn_r = n00b_bstream_read_cstring(stream);

                    if (n00b_result_is_ok(fn_r)) {
                        bin->imports[i].functions[j].name
                            = n00b_result_get(fn_r);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Pass 5: Exports
// ============================================================================

static void
parse_exports(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_EXPORT) {
        return;
    }

    uint32_t export_rva  = bin->data_dirs[N00B_PE_DD_EXPORT].VirtualAddress;
    uint32_t export_size = bin->data_dirs[N00B_PE_DD_EXPORT].Size;

    if (export_rva == 0 || export_size == 0) {
        return;
    }

    uint32_t export_off = rva_to_file_offset(bin, export_rva);

    if (export_off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (export_off + 40 > buf_len) {
        return;
    }

    // Read export directory (40 bytes)
    if (!pe_bstream_setpos(stream, export_off)) {
        return;
    }

    uint32_t exp_characteristics = 0;
    uint32_t exp_timestamp       = 0;
    uint16_t exp_major_ver       = 0;
    uint16_t exp_minor_ver       = 0;

    READ_INTO(stream, u32, exp_characteristics);
    READ_INTO(stream, u32, exp_timestamp);
    READ_INTO(stream, u16, exp_major_ver);
    READ_INTO(stream, u16, exp_minor_ver);

    uint32_t name_rva = 0;
    auto     name_r   = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(name_r)) {
        name_rva = n00b_result_get(name_r);
    }

    uint32_t ordinal_base = 0;
    auto     base_r       = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(base_r)) {
        ordinal_base = n00b_result_get(base_r);
    }

    uint32_t num_functions = 0;
    auto     nf_r          = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(nf_r)) {
        num_functions = n00b_result_get(nf_r);
    }

    uint32_t num_names = 0;
    auto     nn_r      = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(nn_r)) {
        num_names = n00b_result_get(nn_r);
    }

    uint32_t addr_table_rva = 0;
    auto     at_r           = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(at_r)) {
        addr_table_rva = n00b_result_get(at_r);
    }

    uint32_t name_table_rva = 0;
    auto     nt_r           = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(nt_r)) {
        name_table_rva = n00b_result_get(nt_r);
    }

    uint32_t ord_table_rva = 0;
    auto     ot_r          = n00b_bstream_read_u32(stream);

    if (n00b_result_is_ok(ot_r)) {
        ord_table_rva = n00b_result_get(ot_r);
    }

    if (num_functions == 0) {
        return;
    }

    // Allocate export info
    n00b_pe_export_info_t *ei = n00b_alloc(n00b_pe_export_info_t);

    bin->export_info          = ei;
    ei->ordinal_base          = ordinal_base;
    ei->num_functions         = num_functions;
    ei->characteristics       = exp_characteristics;
    ei->time_date_stamp       = exp_timestamp;
    ei->major_version         = exp_major_ver;
    ei->minor_version         = exp_minor_ver;
    ei->functions             = n00b_alloc_array(n00b_pe_exported_func_t,
                                                  num_functions);

    // Read module name
    if (name_rva != 0) {
        uint32_t mod_name_off = rva_to_file_offset(bin, name_rva);

        if (mod_name_off != 0) {
            ei->name = read_string_at(stream, mod_name_off);
        }
    }

    // Read function address table
    uint32_t addr_off = rva_to_file_offset(bin, addr_table_rva);

    if (addr_off == 0) {
        return;
    }

    for (uint32_t i = 0; i < num_functions; i++) {
        size_t off = addr_off + (size_t)i * 4;

        if (off + 4 > buf_len) {
            break;
        }

        if (!pe_bstream_setpos(stream, off)) {
            break;
        }

        auto faddr_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(faddr_r)) {
            ei->functions[i].rva = n00b_result_get(faddr_r);
        }

        ei->functions[i].ordinal = ordinal_base + i;

        // Detect forwarded exports: RVA points within the export directory
        uint32_t func_rva = ei->functions[i].rva;

        if (func_rva >= export_rva
            && func_rva < export_rva + export_size) {
            ei->functions[i].is_forwarded = true;
            uint32_t fwd_off = rva_to_file_offset(bin, func_rva);

            if (fwd_off != 0) {
                n00b_string_t *fwd = read_string_at(stream, fwd_off);

                ei->functions[i].forward_name = fwd;

                // Split "library.function" on first '.'
                if (fwd) {
                    const char *dot = strchr(fwd->data, '.');

                    if (dot) {
                        size_t lib_len = (size_t)(dot - fwd->data);

                        ei->functions[i].forward_library
                            = n00b_string_from_raw(fwd->data, lib_len);
                        ei->functions[i].forward_function
                            = n00b_string_from_cstr(dot + 1);
                    }
                }
            }
        }
    }

    // Match names to functions via ordinal table
    uint32_t names_off = rva_to_file_offset(bin, name_table_rva);
    uint32_t ords_off  = rva_to_file_offset(bin, ord_table_rva);

    if (names_off == 0 || ords_off == 0) {
        return;
    }

    for (uint32_t i = 0; i < num_names; i++) {
        size_t no = names_off + (size_t)i * 4;
        size_t oo = ords_off + (size_t)i * 2;

        if (no + 4 > buf_len || oo + 2 > buf_len) {
            break;
        }

        // Read name RVA
        if (!pe_bstream_setpos(stream, no)) {
            continue;
        }

        auto fnr = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(fnr)) {
            continue;
        }

        uint32_t fn_rva = n00b_result_get(fnr);

        // Read ordinal index (not the actual ordinal — index into addr table)
        if (!pe_bstream_setpos(stream, oo)) {
            continue;
        }

        auto oidx_r = n00b_bstream_read_u16(stream);

        if (n00b_result_is_err(oidx_r)) {
            continue;
        }

        uint16_t ordinal_idx = n00b_result_get(oidx_r);

        if (ordinal_idx >= num_functions) {
            continue;
        }

        // Read the name
        uint32_t fn_off = rva_to_file_offset(bin, fn_rva);

        if (fn_off != 0) {
            ei->functions[ordinal_idx].name = read_string_at(stream, fn_off);
        }
    }
}

// ============================================================================
// Pass 6: Base relocations
// ============================================================================

static void
parse_base_relocs(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_BASERELOC) {
        return;
    }

    uint32_t reloc_rva  = bin->data_dirs[N00B_PE_DD_BASERELOC].VirtualAddress;
    uint32_t reloc_size = bin->data_dirs[N00B_PE_DD_BASERELOC].Size;

    if (reloc_rva == 0 || reloc_size == 0) {
        return;
    }

    uint32_t reloc_off = rva_to_file_offset(bin, reloc_rva);

    if (reloc_off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    // First pass: count relocations (excluding ABSOLUTE)
    uint32_t total = 0;
    size_t   pos   = reloc_off;

    while (pos + 8 <= buf_len && pos < reloc_off + reloc_size) {
        if (!pe_bstream_setpos(stream, pos)) {
            break;
        }

        auto prv_r = n00b_bstream_read_u32(stream);
        auto bsz_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(prv_r) || n00b_result_is_err(bsz_r)) {
            break;
        }

        uint32_t block_size = n00b_result_get(bsz_r);

        if (block_size < 8) {
            break;
        }

        uint32_t num_entries = (block_size - 8) / 2;

        for (uint32_t i = 0; i < num_entries; i++) {
            size_t eoff = pos + 8 + (size_t)i * 2;

            if (eoff + 2 > buf_len) {
                break;
            }

            if (!pe_bstream_setpos(stream, eoff)) {
                break;
            }

            auto ev_r = n00b_bstream_read_u16(stream);

            if (n00b_result_is_ok(ev_r)) {
                uint16_t entry = n00b_result_get(ev_r);
                uint8_t  type  = entry >> 12;

                if (type != N00B_PE_REL_BASED_ABSOLUTE) {
                    total++;
                }
            }
        }

        pos += block_size;
    }

    if (total == 0) {
        return;
    }

    bin->relocations     = n00b_alloc_array(n00b_pe_relocation_t, total);
    bin->num_relocations = total;

    // Second pass: fill
    uint32_t idx = 0;

    pos = reloc_off;

    while (pos + 8 <= buf_len && pos < reloc_off + reloc_size) {
        if (!pe_bstream_setpos(stream, pos)) {
            break;
        }

        auto prv_r = n00b_bstream_read_u32(stream);
        auto bsz_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(prv_r) || n00b_result_is_err(bsz_r)) {
            break;
        }

        uint32_t page_rva   = n00b_result_get(prv_r);
        uint32_t block_size = n00b_result_get(bsz_r);

        if (block_size < 8) {
            break;
        }

        uint32_t num_entries = (block_size - 8) / 2;

        for (uint32_t i = 0; i < num_entries && idx < total; i++) {
            size_t eoff = pos + 8 + (size_t)i * 2;

            if (eoff + 2 > buf_len) {
                break;
            }

            if (!pe_bstream_setpos(stream, eoff)) {
                break;
            }

            auto ev_r = n00b_bstream_read_u16(stream);

            if (n00b_result_is_ok(ev_r)) {
                uint16_t entry  = n00b_result_get(ev_r);
                uint8_t  type   = entry >> 12;
                uint16_t offset = entry & 0x0FFF;

                if (type != N00B_PE_REL_BASED_ABSOLUTE) {
                    bin->relocations[idx].rva  = page_rva + offset;
                    bin->relocations[idx].type = type;
                    idx++;
                }
            }
        }

        pos += block_size;
    }

    bin->num_relocations = idx;
}

// ============================================================================
// Pass 7: Debug directory
// ============================================================================

static void
parse_debug(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_DEBUG) {
        return;
    }

    uint32_t debug_rva  = bin->data_dirs[N00B_PE_DD_DEBUG].VirtualAddress;
    uint32_t debug_size = bin->data_dirs[N00B_PE_DD_DEBUG].Size;

    if (debug_rva == 0 || debug_size == 0) {
        return;
    }

    uint32_t debug_off = rva_to_file_offset(bin, debug_rva);

    if (debug_off == 0) {
        return;
    }

    // Each debug directory entry is 28 bytes
    uint32_t count  = debug_size / 28;
    size_t   buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (count == 0) {
        return;
    }

    bin->debug_entries     = n00b_alloc_array(n00b_pe_debug_entry_t, count);
    bin->num_debug_entries = count;

    for (uint32_t i = 0; i < count; i++) {
        size_t off = debug_off + (size_t)i * 28;

        if (off + 28 > buf_len) {
            bin->num_debug_entries = i;
            break;
        }

        if (!pe_bstream_setpos(stream, off)) {
            bin->num_debug_entries = i;
            break;
        }

        auto chr_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(chr_r)) {
            bin->debug_entries[i].characteristics = n00b_result_get(chr_r);
        }

        auto ts_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(ts_r)) {
            bin->debug_entries[i].time_date_stamp = n00b_result_get(ts_r);
        }

        auto mav_r = n00b_bstream_read_u16(stream);

        if (n00b_result_is_ok(mav_r)) {
            bin->debug_entries[i].major_version = n00b_result_get(mav_r);
        }

        auto miv_r = n00b_bstream_read_u16(stream);

        if (n00b_result_is_ok(miv_r)) {
            bin->debug_entries[i].minor_version = n00b_result_get(miv_r);
        }

        auto type_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(type_r)) {
            bin->debug_entries[i].type = n00b_result_get(type_r);
        }

        auto sod_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(sod_r)) {
            bin->debug_entries[i].size_of_data = n00b_result_get(sod_r);
        }

        auto ard_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(ard_r)) {
            bin->debug_entries[i].address_of_raw_data = n00b_result_get(ard_r);
        }

        auto prd_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_ok(prd_r)) {
            bin->debug_entries[i].pointer_to_raw_data = n00b_result_get(prd_r);
        }

        // Read typed payload based on debug type.
        uint32_t raw_ptr = bin->debug_entries[i].pointer_to_raw_data;
        uint32_t raw_sz  = bin->debug_entries[i].size_of_data;

        if (raw_ptr == 0 || raw_sz == 0 || raw_ptr + raw_sz > buf_len) {
            continue;
        }

        // Store raw data for all types.
        if (!pe_bstream_setpos(stream, raw_ptr)) {
            continue;
        }

        auto rd_r = n00b_bstream_read_bytes(stream, raw_sz);

        if (n00b_result_is_ok(rd_r)) {
            bin->debug_entries[i].raw_data = n00b_result_get(rd_r);
        }

        switch (bin->debug_entries[i].type) {
        case N00B_PE_DEBUG_TYPE_CODEVIEW: {
            if (raw_sz < 24) {
                break;
            }

            if (!pe_bstream_setpos(stream, raw_ptr)) {
                break;
            }

            auto sig_r = n00b_bstream_read_u32(stream);

            if (n00b_result_is_ok(sig_r)
                && n00b_result_get(sig_r) == N00B_PE_CV_SIGNATURE_RSDS) {
                // Read GUID (16 bytes)
                size_t guid_off = n00b_bstream_pos(stream);

                if (guid_off + 16 <= buf_len) {
                    const uint8_t *bp = (const uint8_t *)stream->buf->data;

                    memcpy(bin->debug_entries[i].guid, bp + guid_off, 16);
                    if (!pe_bstream_setpos(stream, guid_off + 16)) {
                        break;
                    }
                }

                // Read age (4 bytes)
                READ_INTO(stream, u32, bin->debug_entries[i].age);

                // Read PDB path
                auto path_r = n00b_bstream_read_cstring(stream);

                if (n00b_result_is_ok(path_r)) {
                    bin->debug_entries[i].pdb_path = n00b_result_get(path_r);
                }
            }

            break;
        }

        case N00B_PE_DEBUG_TYPE_POGO: {
            // POGO: 4-byte signature, then entries of (rva, size, name).
            if (raw_sz < 8) {
                break;
            }

            if (!pe_bstream_setpos(stream, raw_ptr + 4)) {
                break;
            }

            // Two-pass: count entries, then fill.
            uint32_t pogo_count = 0;
            size_t   scan_pos   = raw_ptr + 4;

            while (scan_pos + 8 <= raw_ptr + raw_sz) {
                uint32_t e_rva = 0;
                auto     er    = n00b_bstream_peek_u32(stream, scan_pos);

                if (n00b_result_is_err(er)) {
                    break;
                }

                e_rva = n00b_result_get(er);

                if (e_rva == 0 && scan_pos > raw_ptr + 4) {
                    break;
                }

                // Skip rva(4) + size(4) to reach name
                size_t name_pos = scan_pos + 8;

                // Find end of null-terminated name
                while (name_pos < raw_ptr + raw_sz) {
                    const uint8_t *bp = (const uint8_t *)stream->buf->data;

                    if (bp[name_pos] == 0) {
                        name_pos++;
                        break;
                    }

                    name_pos++;
                }

                // Align to 4 bytes
                while (name_pos % 4 != 0 && name_pos < raw_ptr + raw_sz) {
                    name_pos++;
                }

                pogo_count++;
                scan_pos = name_pos;
            }

            if (pogo_count == 0) {
                break;
            }

            bin->debug_entries[i].pogo_entries = n00b_alloc_flex(
                n00b_pe_pogo_entry_t, n00b_pe_pogo_entry_t, pogo_count);
            bin->debug_entries[i].num_pogo_entries = pogo_count;

            if (!pe_bstream_setpos(stream, raw_ptr + 4)) {
                break;
            }

            scan_pos = raw_ptr + 4;

            for (uint32_t pe = 0; pe < pogo_count && scan_pos + 8 <= raw_ptr + raw_sz; pe++) {
                if (!pe_bstream_setpos(stream, scan_pos)) {
                    break;
                }

                READ_INTO(stream, u32, bin->debug_entries[i].pogo_entries[pe].rva);
                READ_INTO(stream, u32, bin->debug_entries[i].pogo_entries[pe].size);

                size_t name_pos = scan_pos + 8;

                bin->debug_entries[i].pogo_entries[pe].name
                    = read_string_at(stream, name_pos);

                // Advance past the name + null + alignment
                while (name_pos < raw_ptr + raw_sz) {
                    const uint8_t *bp = (const uint8_t *)stream->buf->data;

                    if (bp[name_pos] == 0) {
                        name_pos++;
                        break;
                    }

                    name_pos++;
                }

                while (name_pos % 4 != 0 && name_pos < raw_ptr + raw_sz) {
                    name_pos++;
                }

                scan_pos = name_pos;
            }

            break;
        }

        case N00B_PE_DEBUG_TYPE_REPRO: {
            // REPRO: 4-byte hash length, then hash bytes.
            if (raw_sz < 4) {
                break;
            }

            if (!pe_bstream_setpos(stream, raw_ptr)) {
                break;
            }

            uint32_t hash_len = 0;
            READ_INTO(stream, u32, hash_len);

            if (hash_len > 0 && hash_len <= raw_sz - 4) {
                auto hr = n00b_bstream_read_bytes(stream, hash_len);

                if (n00b_result_is_ok(hr)) {
                    bin->debug_entries[i].repro_hash = n00b_result_get(hr);
                }
            }

            break;
        }

        case N00B_PE_DEBUG_TYPE_PDBCHECKSUM: {
            // PDBCHECKSUM: null-terminated algorithm string, then checksum bytes.
            if (raw_sz < 2) {
                break;
            }

            if (!pe_bstream_setpos(stream, raw_ptr)) {
                break;
            }

            auto alg_r = n00b_bstream_read_cstring(stream);

            if (n00b_result_is_ok(alg_r)) {
                bin->debug_entries[i].checksum_algorithm = n00b_result_get(alg_r);
                size_t alg_end = n00b_bstream_pos(stream);
                size_t remaining = raw_ptr + raw_sz - alg_end;

                if (remaining > 0) {
                    auto cr = n00b_bstream_read_bytes(stream, remaining);

                    if (n00b_result_is_ok(cr)) {
                        bin->debug_entries[i].checksum_data = n00b_result_get(cr);
                    }
                }
            }

            break;
        }

        case N00B_PE_DEBUG_TYPE_EX_DLLCHAR: {
            // EX_DLLCHAR: single u32 characteristics.
            if (raw_sz < 4) {
                break;
            }

            if (!pe_bstream_setpos(stream, raw_ptr)) {
                break;
            }

            READ_INTO(stream, u32, bin->debug_entries[i].ex_dll_characteristics);
            break;
        }

        default:
            break;
        }
    }
}

// ============================================================================
// Pass 8: TLS
// ============================================================================

static void
parse_tls(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_TLS) {
        return;
    }

    uint32_t tls_rva  = bin->data_dirs[N00B_PE_DD_TLS].VirtualAddress;
    uint32_t tls_size = bin->data_dirs[N00B_PE_DD_TLS].Size;

    if (tls_rva == 0 || tls_size == 0) {
        return;
    }

    uint32_t tls_off = rva_to_file_offset(bin, tls_rva);

    if (tls_off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    // TLS directory is 40 bytes for PE32+
    if (tls_off + 40 > buf_len) {
        return;
    }

    n00b_pe_tls_t *tls = n00b_alloc(n00b_pe_tls_t);

    bin->tls = tls;
    if (!pe_bstream_setpos(stream, tls_off)) {
        return;
    }

    auto rds_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_ok(rds_r)) {
        tls->raw_data_start_va = n00b_result_get(rds_r);
    }

    auto rde_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_ok(rde_r)) {
        tls->raw_data_end_va = n00b_result_get(rde_r);
    }

    auto aoi_r = n00b_bstream_read_u64(stream);

    if (n00b_result_is_ok(aoi_r)) {
        tls->address_of_index = n00b_result_get(aoi_r);
    }

    auto aoc_r = n00b_bstream_read_u64(stream);
    uint64_t callbacks_va = 0;

    if (n00b_result_is_ok(aoc_r)) {
        callbacks_va = n00b_result_get(aoc_r);
    }

    // Read SizeOfZeroFill and Characteristics (last 8 bytes of TLS dir)
    READ_INTO(stream, u32, tls->size_of_zero_fill);
    READ_INTO(stream, u32, tls->characteristics);

    // Read callbacks array (VA-terminated by zero)
    if (callbacks_va != 0 && bin->imagebase != 0) {
        uint32_t cb_rva = (uint32_t)(callbacks_va - bin->imagebase);
        uint32_t cb_off = rva_to_file_offset(bin, cb_rva);

        if (cb_off != 0) {
            // Count callbacks
            uint32_t cb_count = 0;

            for (uint32_t i = 0;; i++) {
                size_t co = cb_off + (size_t)i * 8;

                if (co + 8 > buf_len) {
                    break;
                }

                if (!pe_bstream_setpos(stream, co)) {
                    break;
                }

                auto cv_r = n00b_bstream_read_u64(stream);

                if (n00b_result_is_err(cv_r)
                    || n00b_result_get(cv_r) == 0) {
                    break;
                }

                cb_count++;
            }

            if (cb_count > 0) {
                tls->callbacks     = n00b_alloc_array(uint64_t, cb_count);
                tls->num_callbacks = cb_count;

                for (uint32_t i = 0; i < cb_count; i++) {
                    if (!pe_bstream_setpos(stream, cb_off + (size_t)i * 8)) {
                        break;
                    }

                    auto cv_r = n00b_bstream_read_u64(stream);

                    if (n00b_result_is_ok(cv_r)) {
                        tls->callbacks[i] = n00b_result_get(cv_r);
                    }
                }
            }
        }
    }

    // Read raw TLS data if start < end
    if (tls->raw_data_start_va != 0
        && tls->raw_data_end_va > tls->raw_data_start_va
        && bin->imagebase != 0) {
        uint32_t data_rva = (uint32_t)(tls->raw_data_start_va
                                        - bin->imagebase);
        uint32_t data_sz  = (uint32_t)(tls->raw_data_end_va
                                        - tls->raw_data_start_va);
        uint32_t data_off = rva_to_file_offset(bin, data_rva);

        if (data_off != 0 && data_off + data_sz <= buf_len) {
            if (!pe_bstream_setpos(stream, data_off)) {
                return;
            }

            auto rd_r = n00b_bstream_read_bytes(stream, data_sz);

            if (n00b_result_is_ok(rd_r)) {
                tls->raw_data = n00b_result_get(rd_r);
            }
        }
    }
}

// ============================================================================
// Pass 9: Resources
// ============================================================================

#define N00B_PE_RESOURCE_MAX_DEPTH 8

static void
parse_resource_dir(n00b_bstream_t *stream, n00b_pe_binary_t *bin,
                   n00b_pe_resource_node_t *node,
                   uint32_t rsrc_off, size_t buf_len, uint32_t depth)
{
    if (depth > N00B_PE_RESOURCE_MAX_DEPTH) {
        return;
    }

    // Read directory header: 16 bytes
    auto chr_r = n00b_bstream_read_u32(stream);  // Characteristics
    auto ts_r  = n00b_bstream_read_u32(stream);  // TimeDateStamp
    auto mav_r = n00b_bstream_read_u16(stream);  // MajorVersion
    auto miv_r = n00b_bstream_read_u16(stream);  // MinorVersion

    (void)chr_r;
    (void)ts_r;
    (void)mav_r;
    (void)miv_r;

    auto nne_r = n00b_bstream_read_u16(stream);
    auto nie_r = n00b_bstream_read_u16(stream);

    if (n00b_result_is_err(nne_r) || n00b_result_is_err(nie_r)) {
        return;
    }

    uint16_t num_named = n00b_result_get(nne_r);
    uint16_t num_id    = n00b_result_get(nie_r);
    uint32_t total     = (uint32_t)num_named + (uint32_t)num_id;

    if (total == 0) {
        return;
    }

    node->is_directory  = true;
    node->children      = n00b_alloc_array(n00b_pe_resource_node_t, total);
    node->num_children  = total;

    for (uint32_t i = 0; i < total; i++) {
        auto nid_r  = n00b_bstream_read_u32(stream);
        auto odat_r = n00b_bstream_read_u32(stream);

        if (n00b_result_is_err(nid_r) || n00b_result_is_err(odat_r)) {
            node->num_children = i;
            return;
        }

        uint32_t name_or_id  = n00b_result_get(nid_r);
        uint32_t offset_data = n00b_result_get(odat_r);

        // Set ID or name
        if (name_or_id & 0x80000000) {
            // Named entry: read UTF-16LE string
            uint32_t str_off = rsrc_off + (name_or_id & 0x7FFFFFFF);

            node->children[i].id = 0;

            if (str_off + 2 <= buf_len) {
                size_t saved_name = n00b_bstream_pos(stream);

                if (!pe_bstream_setpos(stream, str_off)) {
                    continue;
                }

                auto len_r = n00b_bstream_read_u16(stream);

                if (n00b_result_is_ok(len_r)) {
                    uint16_t wlen = n00b_result_get(len_r);

                    if (wlen > 0 && str_off + 2 + (size_t)wlen * 2 <= buf_len) {
                        // Convert UTF-16LE to UTF-8
                        char    utf8[512];
                        size_t  utf8_len = 0;

                        for (uint16_t ci = 0; ci < wlen && utf8_len < 500; ci++) {
                            auto cp_r = n00b_bstream_read_u16(stream);

                            if (n00b_result_is_err(cp_r)) {
                                break;
                            }

                            uint16_t cp = n00b_result_get(cp_r);

                            if (cp < 0x80) {
                                utf8[utf8_len++] = (char)cp;
                            }
                            else if (cp < 0x800) {
                                utf8[utf8_len++] = (char)(0xC0 | (cp >> 6));
                                utf8[utf8_len++] = (char)(0x80 | (cp & 0x3F));
                            }
                            else {
                                utf8[utf8_len++] = (char)(0xE0 | (cp >> 12));
                                utf8[utf8_len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                                utf8[utf8_len++] = (char)(0x80 | (cp & 0x3F));
                            }
                        }

                        if (utf8_len > 0) {
                            node->children[i].name
                                = n00b_string_from_raw(utf8, utf8_len);
                        }
                    }
                }

                (void)pe_bstream_setpos(stream, saved_name);
            }
        }
        else {
            node->children[i].id = name_or_id;
        }

        size_t saved = n00b_bstream_pos(stream);

        if (offset_data & 0x80000000) {
            // Subdirectory
            uint32_t sub_off = rsrc_off + (offset_data & 0x7FFFFFFF);

            if (sub_off + 16 <= buf_len) {
                if (pe_bstream_setpos(stream, sub_off)) {
                    parse_resource_dir(stream, bin, &node->children[i],
                                       rsrc_off, buf_len, depth + 1);
                }
            }
        }
        else {
            // Data entry
            uint32_t entry_off = rsrc_off + offset_data;

            if (entry_off + 16 <= buf_len) {
                if (!pe_bstream_setpos(stream, entry_off)) {
                    continue;
                }

                auto data_rva_r = n00b_bstream_read_u32(stream);
                auto data_sz_r  = n00b_bstream_read_u32(stream);
                auto cp_r       = n00b_bstream_read_u32(stream);

                node->children[i].is_directory = false;

                if (n00b_result_is_ok(cp_r)) {
                    node->children[i].code_page = n00b_result_get(cp_r);
                }

                if (n00b_result_is_ok(data_rva_r)
                    && n00b_result_is_ok(data_sz_r)) {
                    uint32_t drva = n00b_result_get(data_rva_r);
                    uint32_t dsz  = n00b_result_get(data_sz_r);
                    uint32_t doff = rva_to_file_offset(bin, drva);

                    if (doff != 0 && doff + dsz <= buf_len) {
                        if (!pe_bstream_setpos(stream, doff)) {
                            continue;
                        }

                        auto rd_r = n00b_bstream_read_bytes(stream, dsz);

                        if (n00b_result_is_ok(rd_r)) {
                            node->children[i].data = n00b_result_get(rd_r);
                        }
                    }
                }
            }
        }

        (void)pe_bstream_setpos(stream, saved);
    }
}

static void
parse_resources(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_RESOURCE) {
        return;
    }

    uint32_t rsrc_rva  = bin->data_dirs[N00B_PE_DD_RESOURCE].VirtualAddress;
    uint32_t rsrc_size = bin->data_dirs[N00B_PE_DD_RESOURCE].Size;

    if (rsrc_rva == 0 || rsrc_size == 0) {
        return;
    }

    uint32_t rsrc_off = rva_to_file_offset(bin, rsrc_rva);

    if (rsrc_off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (rsrc_off + 16 > buf_len) {
        return;
    }

    bin->resources = n00b_alloc(n00b_pe_resource_node_t);
    if (!pe_bstream_setpos(stream, rsrc_off)) {
        return;
    }

    parse_resource_dir(stream, bin, bin->resources, rsrc_off, buf_len, 0);
}

// ============================================================================
// Pass 9b: Load Configuration (data dir 10)
// ============================================================================

static void
parse_load_config(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_LOAD_CONFIG) {
        return;
    }

    uint32_t rva  = bin->data_dirs[N00B_PE_DD_LOAD_CONFIG].VirtualAddress;
    uint32_t dsize = bin->data_dirs[N00B_PE_DD_LOAD_CONFIG].Size;

    if (rva == 0 || dsize == 0) {
        return;
    }

    uint32_t off = rva_to_file_offset(bin, rva);

    if (off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (off + 4 > buf_len) {
        return;
    }

    // Read declared size first.
    if (!pe_bstream_setpos(stream, off)) {
        return;
    }

    uint32_t declared_size = 0;
    READ_INTO(stream, u32, declared_size);

    if (declared_size < 4) {
        return;
    }

    // Clamp to available data.
    if (off + declared_size > buf_len) {
        declared_size = (uint32_t)(buf_len - off);
    }

    n00b_pe_load_config_t *lc = n00b_alloc(n00b_pe_load_config_t);
    bin->load_config = lc;
    lc->size = declared_size;

    // Helper: read field if enough bytes remain. Track bytes consumed.
    // Base fields start at offset 4 (after size).
    if (!pe_bstream_setpos(stream, off + 4)) {
        return;
    }

    uint32_t consumed = 4;

#define LC_READ_U32(field) do { \
    if (consumed + 4 > declared_size) goto done; \
    READ_INTO(stream, u32, lc->field); \
    consumed += 4; \
} while (0)

#define LC_READ_U16(field) do { \
    if (consumed + 2 > declared_size) goto done; \
    READ_INTO(stream, u16, lc->field); \
    consumed += 2; \
} while (0)

#define LC_READ_U64(field) do { \
    if (consumed + 8 > declared_size) goto done; \
    READ_INTO(stream, u64, lc->field); \
    consumed += 8; \
} while (0)

    LC_READ_U32(time_date_stamp);
    LC_READ_U16(major_version);
    LC_READ_U16(minor_version);
    LC_READ_U32(global_flags_clear);
    LC_READ_U32(global_flags_set);
    LC_READ_U32(critical_section_default_timeout);
    LC_READ_U64(decommit_free_block_threshold);
    LC_READ_U64(decommit_total_free_threshold);
    LC_READ_U64(lock_prefix_table);
    LC_READ_U64(maximum_allocation_size);
    LC_READ_U64(virtual_memory_threshold);
    LC_READ_U64(process_affinity_mask);
    LC_READ_U32(process_heap_flags);
    LC_READ_U16(csd_version);
    LC_READ_U16(dependent_load_flags);
    LC_READ_U64(edit_list);
    LC_READ_U64(security_cookie);
    LC_READ_U64(se_handler_table);
    LC_READ_U64(se_handler_count);
    // CFG fields
    LC_READ_U64(guard_cf_check_function_pointer);
    LC_READ_U64(guard_cf_dispatch_function_pointer);
    LC_READ_U64(guard_cf_function_table);
    LC_READ_U64(guard_cf_function_count);
    LC_READ_U32(guard_flags);

done:

#undef LC_READ_U32
#undef LC_READ_U16
#undef LC_READ_U64

    (void)consumed;
}

// ============================================================================
// Pass 10: Overlay
// ============================================================================

static void
parse_overlay(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_sections == 0) {
        return;
    }

    // Find end of last section
    uint32_t end = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        uint32_t sec_end = bin->sections[i].raw_offset
                           + bin->sections[i].raw_size;

        if (sec_end > end) {
            end = sec_end;
        }
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (end >= buf_len) {
        return;
    }

    size_t overlay_size = buf_len - end;

    if (overlay_size > 0) {
        if (!pe_bstream_setpos(stream, end)) {
            return;
        }

        auto r = n00b_bstream_read_bytes(stream, overlay_size);

        if (n00b_result_is_ok(r)) {
            bin->overlay = n00b_result_get(r);
        }
    }
}

// ============================================================================
// Pass 11: Delay imports (data dir 13)
// ============================================================================

static void
parse_delay_imports(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_DELAY_IMPORT) {
        return;
    }

    uint32_t rva  = bin->data_dirs[N00B_PE_DD_DELAY_IMPORT].VirtualAddress;
    uint32_t size = bin->data_dirs[N00B_PE_DD_DELAY_IMPORT].Size;

    if (rva == 0 || size == 0) {
        return;
    }

    uint32_t off = rva_to_file_offset(bin, rva);

    if (off == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    // Count descriptors (terminated by an all-zero entry).
    uint32_t count = 0;

    for (uint32_t pos = off; pos + N00B_PE_DELAY_IMPORT_DESC_SIZE <= buf_len; pos += N00B_PE_DELAY_IMPORT_DESC_SIZE) {
        if (!pe_bstream_setpos(stream, pos)) {
            break;
        }

        // Check if Name RVA is zero (terminator).
        auto name_r = n00b_bstream_peek_u32(stream, pos + 4);

        if (n00b_result_is_err(name_r) || n00b_result_get(name_r) == 0) {
            break;
        }

        count++;
    }

    if (count == 0) {
        return;
    }

    bin->delay_imports     = n00b_alloc_flex(n00b_pe_delay_import_t,
                                             n00b_pe_delay_import_t,
                                             count);
    bin->num_delay_imports = count;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t desc_off = off + i * N00B_PE_DELAY_IMPORT_DESC_SIZE;

        if (!pe_bstream_setpos(stream, desc_off)) {
            bin->num_delay_imports = i;
            break;
        }

        n00b_pe_delay_import_t *di = &bin->delay_imports[i];

        READ_INTO(stream, u32, di->attributes);

        uint32_t name_rva = 0;
        READ_INTO(stream, u32, name_rva);

        READ_INTO(stream, u32, di->handle_rva);

        uint32_t iat_rva = 0;
        READ_INTO(stream, u32, iat_rva);

        uint32_t int_rva = 0;
        READ_INTO(stream, u32, int_rva);

        // Skip BoundDelayImportTable, UnloadDelayImportTable, TimeDateStamp.

        // Read DLL name.
        if (name_rva != 0) {
            uint32_t name_off = rva_to_file_offset(bin, name_rva);

            if (name_off != 0) {
                di->name = read_string_at(stream, name_off);
            }
        }

        // Read delay INT (Import Name Table) for function names.
        if (int_rva == 0) {
            continue;
        }

        uint32_t int_off = rva_to_file_offset(bin, int_rva);

        if (int_off == 0) {
            continue;
        }

        // Count functions (null-terminated array of 8-byte entries for PE32+).
        uint32_t func_count = 0;

        for (uint32_t fp = int_off; fp + 8 <= buf_len; fp += 8) {
            uint64_t entry = 0;
            auto     er    = n00b_bstream_peek_u64(stream, fp);

            if (n00b_result_is_err(er)) {
                break;
            }

            entry = n00b_result_get(er);

            if (entry == 0) {
                break;
            }

            func_count++;
        }

        if (func_count == 0) {
            continue;
        }

        di->functions     = n00b_alloc_flex(n00b_pe_imported_func_t,
                                            n00b_pe_imported_func_t,
                                            func_count);
        di->num_functions = func_count;

        for (uint32_t f = 0; f < func_count; f++) {
            uint64_t entry = 0;
            auto     er    = n00b_bstream_peek_u64(stream, int_off + f * 8);

            if (n00b_result_is_err(er)) {
                break;
            }

            entry = n00b_result_get(er);

            if (entry & N00B_PE_IMPORT_ORDINAL_FLAG64) {
                di->functions[f].is_ordinal = true;
                di->functions[f].ordinal    = (uint16_t)(entry & 0xFFFF);
            }
            else {
                uint32_t hint_rva = (uint32_t)(entry & 0x7FFFFFFF);
                uint32_t hint_off = rva_to_file_offset(bin, hint_rva);

                if (hint_off != 0 && hint_off + 2 < buf_len) {
                    auto hr = n00b_bstream_peek_u16(stream, hint_off);

                    if (n00b_result_is_ok(hr)) {
                        di->functions[f].hint = n00b_result_get(hr);
                    }

                    di->functions[f].name = read_string_at(stream, hint_off + 2);
                }
            }

            // Read IAT entry value if available.
            if (iat_rva != 0) {
                uint32_t iat_off = rva_to_file_offset(bin, iat_rva);

                if (iat_off != 0) {
                    auto ir = n00b_bstream_peek_u64(stream, iat_off + f * 8);

                    if (n00b_result_is_ok(ir)) {
                        di->functions[f].iat_value = n00b_result_get(ir);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Pass 12: Exception table (data dir 3, x64 RUNTIME_FUNCTION)
// ============================================================================

static void
parse_exceptions(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_EXCEPTION) {
        return;
    }

    uint32_t rva  = bin->data_dirs[N00B_PE_DD_EXCEPTION].VirtualAddress;
    uint32_t size = bin->data_dirs[N00B_PE_DD_EXCEPTION].Size;

    if (rva == 0 || size == 0) {
        return;
    }

    uint32_t off = rva_to_file_offset(bin, rva);

    if (off == 0) {
        return;
    }

    uint32_t count = size / N00B_PE_RUNTIME_FUNCTION_SIZE;

    if (count == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (off + count * N00B_PE_RUNTIME_FUNCTION_SIZE > buf_len) {
        count = (uint32_t)((buf_len - off) / N00B_PE_RUNTIME_FUNCTION_SIZE);
    }

    if (count == 0) {
        return;
    }

    bin->exceptions     = n00b_alloc_flex(n00b_pe_exception_entry_t,
                                          n00b_pe_exception_entry_t,
                                          count);
    bin->num_exceptions = count;

    if (!pe_bstream_setpos(stream, off)) {
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        READ_INTO(stream, u32, bin->exceptions[i].begin_rva);
        READ_INTO(stream, u32, bin->exceptions[i].end_rva);
        READ_INTO(stream, u32, bin->exceptions[i].unwind_rva);
    }
}

// ============================================================================
// Pass 13: COFF symbol table
// ============================================================================

static void
parse_coff_symbols(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->pointer_to_symbol_table == 0 || bin->number_of_symbols == 0) {
        return;
    }

    uint32_t sym_off   = bin->pointer_to_symbol_table;
    uint32_t num_syms  = bin->number_of_symbols;
    size_t   buf_len   = (size_t)n00b_buffer_len(stream->buf);

    if (sym_off + (uint64_t)num_syms * N00B_PE_COFF_SYMBOL_SIZE > buf_len) {
        return;
    }

    // String table starts immediately after the symbol table.
    uint32_t strtab_off = sym_off + num_syms * N00B_PE_COFF_SYMBOL_SIZE;
    uint32_t strtab_size = 0;

    if (strtab_off + 4 <= buf_len) {
        auto sr = n00b_bstream_peek_u32(stream, strtab_off);

        if (n00b_result_is_ok(sr)) {
            strtab_size = n00b_result_get(sr);
        }
    }

    // Count actual symbols (skip aux records).
    uint32_t real_count = 0;

    for (uint32_t i = 0; i < num_syms;) {
        uint32_t rec_off = sym_off + i * N00B_PE_COFF_SYMBOL_SIZE;

        // NumberOfAuxSymbols is at offset 17 in the 18-byte record.
        auto aux_r = n00b_bstream_peek_u8(stream, rec_off + 17);
        uint8_t num_aux = 0;

        if (n00b_result_is_ok(aux_r)) {
            num_aux = n00b_result_get(aux_r);
        }

        real_count++;
        i += 1 + num_aux;
    }

    if (real_count == 0) {
        return;
    }

    bin->symbols     = n00b_alloc_flex(n00b_pe_symbol_t,
                                       n00b_pe_symbol_t,
                                       real_count);
    bin->num_symbols = real_count;

    uint32_t out_idx = 0;

    for (uint32_t i = 0; i < num_syms && out_idx < real_count;) {
        uint32_t rec_off = sym_off + i * N00B_PE_COFF_SYMBOL_SIZE;

        n00b_pe_symbol_t *sym = &bin->symbols[out_idx];

        // Name: first 8 bytes. If first 4 bytes are zero, next 4 are string table offset.
        const uint8_t *base = (const uint8_t *)stream->buf->data;
        uint32_t name_zeroes;

        memcpy(&name_zeroes, base + rec_off, 4);

        if (name_zeroes == 0) {
            // Long name: offset into string table.
            uint32_t str_offset;

            memcpy(&str_offset, base + rec_off + 4, 4);

            if (strtab_size > 0 && str_offset < strtab_size
                && strtab_off + str_offset < buf_len) {
                sym->name = read_string_at(stream, strtab_off + str_offset);
            }
        }
        else {
            // Short name: up to 8 bytes, null-padded.
            char short_name[9];

            memcpy(short_name, base + rec_off, 8);
            short_name[8] = '\0';
            sym->name     = n00b_string_from_cstr(short_name);
        }

        // Value (offset 8, 4 bytes)
        memcpy(&sym->value, base + rec_off + 8, 4);

        // SectionNumber (offset 12, 2 bytes, signed)
        memcpy(&sym->section_number, base + rec_off + 12, 2);

        // Type (offset 14, 2 bytes)
        memcpy(&sym->type, base + rec_off + 14, 2);

        // StorageClass (offset 16, 1 byte)
        sym->storage_class = base[rec_off + 16];

        // NumberOfAuxSymbols (offset 17, 1 byte)
        uint8_t num_aux = base[rec_off + 17];

        out_idx++;
        i += 1 + num_aux;
    }
}

// ============================================================================
// Pass 14: Bound imports (data dir 11)
// ============================================================================

static void
parse_bound_imports(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_BOUND_IMPORT) {
        return;
    }

    // NOTE: For bound imports, VirtualAddress is a file offset, not an RVA.
    uint32_t off  = bin->data_dirs[N00B_PE_DD_BOUND_IMPORT].VirtualAddress;
    uint32_t size = bin->data_dirs[N00B_PE_DD_BOUND_IMPORT].Size;

    if (off == 0 || size == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (off + size > buf_len) {
        return;
    }

    // Count entries (terminated by all-zero descriptor).
    uint32_t count   = 0;
    uint32_t tbl_off = off;

    for (uint32_t pos = tbl_off; pos + N00B_PE_BOUND_IMPORT_DESC_SIZE <= tbl_off + size; pos += N00B_PE_BOUND_IMPORT_DESC_SIZE) {
        uint32_t ts = 0;
        auto     tr = n00b_bstream_peek_u32(stream, pos);

        if (n00b_result_is_err(tr)) {
            break;
        }

        ts = n00b_result_get(tr);

        if (ts == 0) {
            break;
        }

        count++;

        // Skip forwarder refs.
        auto nr = n00b_bstream_peek_u16(stream, pos + 6);

        if (n00b_result_is_ok(nr)) {
            uint16_t num_fwd = n00b_result_get(nr);
            pos += num_fwd * N00B_PE_BOUND_IMPORT_DESC_SIZE;
        }
    }

    if (count == 0) {
        return;
    }

    bin->bound_imports     = n00b_alloc_flex(n00b_pe_bound_import_t,
                                             n00b_pe_bound_import_t,
                                             count);
    bin->num_bound_imports = count;

    uint32_t out_idx = 0;
    uint32_t pos     = tbl_off;

    for (; out_idx < count && pos + N00B_PE_BOUND_IMPORT_DESC_SIZE <= tbl_off + size; out_idx++) {
        n00b_pe_bound_import_t *bi = &bin->bound_imports[out_idx];

        if (!pe_bstream_setpos(stream, pos)) {
            break;
        }

        READ_INTO(stream, u32, bi->time_date_stamp);

        uint16_t name_offset = 0;
        READ_INTO(stream, u16, name_offset);

        uint16_t num_fwd = 0;
        READ_INTO(stream, u16, num_fwd);

        // Name is at tbl_off + name_offset (offset from start of bound import table).
        if (name_offset > 0 && tbl_off + name_offset < buf_len) {
            bi->name = read_string_at(stream, tbl_off + name_offset);
        }

        pos += N00B_PE_BOUND_IMPORT_DESC_SIZE;
        pos += num_fwd * N00B_PE_BOUND_IMPORT_DESC_SIZE;
    }
}

// ============================================================================
// Pass 15: Certificates (data dir 4 — VirtualAddress is file offset, not RVA)
// ============================================================================

static void
parse_certificates(n00b_bstream_t *stream, n00b_pe_binary_t *bin)
{
    if (bin->num_data_dirs <= N00B_PE_DD_CERTIFICATE) {
        return;
    }

    // NOTE: For certificates, VirtualAddress is a file offset, not an RVA.
    uint32_t cert_off  = bin->data_dirs[N00B_PE_DD_CERTIFICATE].VirtualAddress;
    uint32_t cert_size = bin->data_dirs[N00B_PE_DD_CERTIFICATE].Size;

    if (cert_off == 0 || cert_size == 0) {
        return;
    }

    size_t buf_len = (size_t)n00b_buffer_len(stream->buf);

    if (cert_off + cert_size > buf_len) {
        return;
    }

    // Count certificates (WIN_CERTIFICATE entries: length, revision, type, data).
    // Each entry is 8-byte aligned.
    uint32_t count = 0;
    uint32_t pos   = cert_off;

    while (pos + 8 <= cert_off + cert_size) {
        uint32_t entry_len = 0;
        auto     lr        = n00b_bstream_peek_u32(stream, pos);

        if (n00b_result_is_err(lr)) {
            break;
        }

        entry_len = n00b_result_get(lr);

        if (entry_len < 8) {
            break;
        }

        count++;
        pos += entry_len;

        // Align to 8 bytes.
        pos = (pos + 7) & ~(uint32_t)7;
    }

    if (count == 0) {
        return;
    }

    bin->certificates     = n00b_alloc_flex(n00b_pe_certificate_t,
                                            n00b_pe_certificate_t,
                                            count);
    bin->num_certificates = count;

    pos = cert_off;

    for (uint32_t i = 0; i < count && pos + 8 <= cert_off + cert_size; i++) {
        if (!pe_bstream_setpos(stream, pos)) {
            bin->num_certificates = i;
            break;
        }

        uint32_t entry_len = 0;
        READ_INTO(stream, u32, entry_len);

        if (entry_len < 8) {
            bin->num_certificates = i;
            break;
        }

        READ_INTO(stream, u16, bin->certificates[i].revision);
        READ_INTO(stream, u16, bin->certificates[i].certificate_type);

        uint32_t data_len = entry_len - 8;

        if (data_len > 0 && pos + 8 + data_len <= buf_len) {
            auto dr = n00b_bstream_read_bytes(stream, data_len);

            if (n00b_result_is_ok(dr)) {
                bin->certificates[i].raw_data = n00b_result_get(dr);
            }
        }

        pos += entry_len;
        pos  = (pos + 7) & ~(uint32_t)7;
    }
}

// ============================================================================
// Top-level parse
// ============================================================================

n00b_result_t(n00b_pe_binary_t *)
n00b_pe_parse(n00b_bstream_t *stream)
{
    if (!stream) {
        return n00b_result_err(n00b_pe_binary_t *, N00B_ERR_READ);
    }

    n00b_pe_binary_t *bin = n00b_alloc(n00b_pe_binary_t);

    bin->stream = stream;

    // Pass 1: DOS header
    auto dos_r = parse_dos_header(stream, bin);

    if (n00b_result_is_err(dos_r)) {
        return n00b_result_err(n00b_pe_binary_t *, n00b_result_get_err(dos_r));
    }

    // Pass 1b: Rich header (optional, between DOS stub and PE sig)
    parse_rich_header(stream, bin);

    // Pass 2: PE headers
    auto pe_r = parse_pe_headers(stream, bin);

    if (n00b_result_is_err(pe_r)) {
        return n00b_result_err(n00b_pe_binary_t *, n00b_result_get_err(pe_r));
    }

    // Pass 3: Sections
    parse_sections(stream, bin);

    // Pass 4: Imports
    parse_imports(stream, bin);

    // Pass 5: Exports
    parse_exports(stream, bin);

    // Pass 6: Base relocations
    parse_base_relocs(stream, bin);

    // Pass 7: Debug
    parse_debug(stream, bin);

    // Pass 8: TLS
    parse_tls(stream, bin);

    // Pass 9: Resources
    parse_resources(stream, bin);

    // Pass 9b: Load Configuration
    parse_load_config(stream, bin);

    // Pass 10: Overlay
    parse_overlay(stream, bin);

    // Pass 11: Delay imports
    parse_delay_imports(stream, bin);

    // Pass 12: Exceptions
    parse_exceptions(stream, bin);

    // Pass 13: COFF symbols
    parse_coff_symbols(stream, bin);

    // Pass 14: Bound imports
    parse_bound_imports(stream, bin);

    // Pass 15: Certificates
    parse_certificates(stream, bin);

    return n00b_result_ok(n00b_pe_binary_t *, bin);
}
