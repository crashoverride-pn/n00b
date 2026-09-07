#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "compiler/objfile/pe.h"
#include "compiler/objfile/pe_build.h"
#include "compiler/objfile/demangle.h"
#include "compiler/objfile/md5.h"
#include "compiler/objfile/pe_types.h"
#include "compiler/objfile/abstract.h"
#include "compiler/objfile/bstream.h"

// ============================================================================
// Helpers — write little-endian values at a byte pointer
// ============================================================================

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

// ============================================================================
// Synthetic PE32+ binary factory
// ============================================================================

/// Build a minimal PE32+ with 2 sections (.text and .data).
/// Layout:
///   0x000: DOS header (64 bytes)
///   0x040 - 0x07F: padding (DOS stub area)
///   0x080: PE signature (4)
///   0x084: File header (20)
///   0x098: Optional header (240)
///   0x188: Section headers (2 * 40 = 80)
///   0x1D8: padding to 0x200 (file alignment)
///   0x200: .text section data (0x200 bytes)
///   0x400: .data section data (0x200 bytes)
static n00b_buffer_t *
make_minimal_pe64(void)
{
    size_t total = 0x600;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    // DOS header
    put16(p + 0, N00B_PE_MAGIC_MZ);      // e_magic
    put32(p + 0x3C, 0x80);          // e_lfanew

    // PE signature at 0x80
    put32(p + 0x80, N00B_PE_SIGNATURE);

    // File header at 0x84
    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);     // Machine
    put16(fh + 2, 2);                    // NumberOfSections
    put32(fh + 4, 0x5F3B3020);          // TimeDateStamp
    put32(fh + 8, 0);                    // PointerToSymbolTable
    put32(fh + 12, 0);                   // NumberOfSymbols
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE); // SizeOfOptionalHeader
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    // Optional header at 0x98
    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);       // Magic
    oh[2] = 14;                                // MajorLinkerVersion
    oh[3] = 0;                                 // MinorLinkerVersion
    put32(oh + 4, 0x200);                      // SizeOfCode
    put32(oh + 8, 0x200);                      // SizeOfInitializedData
    put32(oh + 12, 0);                         // SizeOfUninitializedData
    put32(oh + 16, 0x1000);                    // AddressOfEntryPoint
    put32(oh + 20, 0x1000);                    // BaseOfCode
    put64(oh + 24, 0x0000000140000000ULL);     // ImageBase
    put32(oh + 32, 0x1000);                    // SectionAlignment
    put32(oh + 36, 0x200);                     // FileAlignment
    put16(oh + 40, 6);                         // MajorOperatingSystemVersion
    put16(oh + 42, 0);                         // MinorOperatingSystemVersion
    put16(oh + 44, 0);                         // MajorImageVersion
    put16(oh + 46, 0);                         // MinorImageVersion
    put16(oh + 48, 6);                         // MajorSubsystemVersion
    put16(oh + 50, 0);                         // MinorSubsystemVersion
    put32(oh + 52, 0);                         // Win32VersionValue
    put32(oh + 56, 0x3000);                    // SizeOfImage
    put32(oh + 60, 0x200);                     // SizeOfHeaders
    put32(oh + 64, 0);                         // CheckSum
    put16(oh + 68, N00B_PE_SUBSYSTEM_WINDOWS_CUI);  // Subsystem
    put16(oh + 70, N00B_PE_DLLCHAR_DYNAMIC_BASE | N00B_PE_DLLCHAR_NX_COMPAT);
    put64(oh + 72, 0x100000);                  // SizeOfStackReserve
    put64(oh + 80, 0x1000);                    // SizeOfStackCommit
    put64(oh + 88, 0x100000);                  // SizeOfHeapReserve
    put64(oh + 96, 0x1000);                    // SizeOfHeapCommit
    put32(oh + 104, 0);                        // LoaderFlags
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);         // NumberOfRvaAndSizes
    // Data directories (16 * 8 = 128 bytes) — all zero for minimal PE

    // Section headers at 0x188
    uint8_t *sh0 = p + 0x188;  // .text
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);     // VirtualSize
    put32(sh0 + 12, 0x1000);    // VirtualAddress
    put32(sh0 + 16, 0x200);     // SizeOfRawData
    put32(sh0 + 20, 0x200);     // PointerToRawData
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    uint8_t *sh1 = p + 0x188 + 40;  // .data
    memcpy(sh1, ".data\0\0\0", 8);
    put32(sh1 + 8,  0x200);     // VirtualSize
    put32(sh1 + 12, 0x2000);    // VirtualAddress
    put32(sh1 + 16, 0x200);     // SizeOfRawData
    put32(sh1 + 20, 0x400);     // PointerToRawData
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ
                    | N00B_PE_SCN_MEM_WRITE);

    // Write some recognizable content in .text
    p[0x200] = 0xCC;  // int3
    p[0x201] = 0x90;  // nop
    p[0x202] = 0xC3;  // ret

    // Write some content in .data
    memcpy(p + 0x400, "Hello PE!", 9);

    return buf;
}

// ============================================================================
// Build a PE with imports
// ============================================================================

/// Build PE with import table for 2 DLLs.
/// Uses .idata section at offset 0x600, RVA 0x3000.
static n00b_buffer_t *
make_pe_with_imports(void)
{
    // Start from minimal PE
    size_t total = 0xC00;  // plenty of room
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    // DOS header
    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);

    // PE signature
    put32(p + 0x80, N00B_PE_SIGNATURE);

    // File header
    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 3);  // 3 sections: .text, .data, .idata
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    // Optional header
    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put32(oh + 16, 0x1000);                // EntryPoint
    put64(oh + 24, 0x0000000140000000ULL); // ImageBase
    put32(oh + 32, 0x1000);               // SectionAlignment
    put32(oh + 36, 0x200);                 // FileAlignment
    put32(oh + 56, 0x4000);               // SizeOfImage
    put32(oh + 60, 0x200);                 // SizeOfHeaders
    put16(oh + 68, N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    put16(oh + 70, N00B_PE_DLLCHAR_DYNAMIC_BASE | N00B_PE_DLLCHAR_NX_COMPAT);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    // Data directory: Import at index 1
    uint8_t *dd = oh + 112;  // Start of data directories
    put32(dd + N00B_PE_DD_IMPORT * 8, 0x3000);     // Import RVA
    put32(dd + N00B_PE_DD_IMPORT * 8 + 4, 0x200);  // Import size

    // Section headers at 0x188
    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .data
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".data\0\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ
                    | N00B_PE_SCN_MEM_WRITE);

    // .idata
    uint8_t *sh2 = p + 0x188 + 80;
    memcpy(sh2, ".idata\0\0", 8);
    put32(sh2 + 8,  0x400);     // VirtualSize
    put32(sh2 + 12, 0x3000);    // VirtualAddress
    put32(sh2 + 16, 0x400);     // SizeOfRawData
    put32(sh2 + 20, 0x600);     // PointerToRawData
    put32(sh2 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Build import tables at file offset 0x600 (RVA 0x3000)
    // Layout within .idata:
    //   0x000: Import descriptor 1 (kernel32.dll)
    //   0x014: Import descriptor 2 (user32.dll)
    //   0x028: Null terminator descriptor
    //   0x03C: ILT for kernel32 (2 entries + null)
    //   0x054: ILT for user32 (1 entry + null)
    //   0x064: Hint/Name for ExitProcess
    //   0x076: Hint/Name for GetLastError
    //   0x08A: Hint/Name for MessageBoxA
    //   0x09C: "KERNEL32.dll"
    //   0x0A9: "USER32.dll"
    //   0x0B4: IAT for kernel32 (copy of ILT)
    //   0x0CC: IAT for user32 (copy of ILT)

    uint8_t *idata = p + 0x600;

    // Hint/Name entries first (to know their RVAs)
    // ExitProcess at offset 0x100 from .idata start → RVA 0x3100
    uint8_t *hn0 = idata + 0x100;
    put16(hn0, 0);  // hint
    memcpy(hn0 + 2, "ExitProcess", 12);  // includes NUL

    // GetLastError at offset 0x110 → RVA 0x3110
    uint8_t *hn1 = idata + 0x110;
    put16(hn1, 1);  // hint
    memcpy(hn1 + 2, "GetLastError", 13);

    // MessageBoxA at offset 0x120 → RVA 0x3120
    uint8_t *hn2 = idata + 0x120;
    put16(hn2, 2);  // hint
    memcpy(hn2 + 2, "MessageBoxA", 12);

    // DLL names
    // kernel32.dll at offset 0x140 → RVA 0x3140
    memcpy(idata + 0x140, "KERNEL32.dll", 13);
    // user32.dll at offset 0x150 → RVA 0x3150
    memcpy(idata + 0x150, "USER32.dll", 11);

    // ILT for kernel32 at offset 0x080 → RVA 0x3080 (2 named imports + null)
    uint8_t *ilt0 = idata + 0x080;
    put64(ilt0 + 0, 0x3100);   // RVA to ExitProcess hint/name
    put64(ilt0 + 8, 0x3110);   // RVA to GetLastError hint/name
    put64(ilt0 + 16, 0);       // null terminator

    // ILT for user32 at offset 0x098 → RVA 0x3098 (1 named import + null)
    uint8_t *ilt1 = idata + 0x098;
    put64(ilt1 + 0, 0x3120);   // RVA to MessageBoxA hint/name
    put64(ilt1 + 8, 0);        // null terminator

    // IAT for kernel32 at offset 0x0B0 → RVA 0x30B0
    uint8_t *iat0 = idata + 0x0B0;
    put64(iat0 + 0, 0x3100);
    put64(iat0 + 8, 0x3110);
    put64(iat0 + 16, 0);

    // IAT for user32 at offset 0x0C8 → RVA 0x30C8
    uint8_t *iat1 = idata + 0x0C8;
    put64(iat1 + 0, 0x3120);
    put64(iat1 + 8, 0);

    // Import descriptors
    // Descriptor 0: kernel32.dll
    put32(idata + 0,  0x3080);   // OriginalFirstThunk (ILT RVA)
    put32(idata + 4,  0);        // TimeDateStamp
    put32(idata + 8,  0);        // ForwarderChain
    put32(idata + 12, 0x3140);   // Name RVA
    put32(idata + 16, 0x30B0);   // FirstThunk (IAT RVA)

    // Descriptor 1: user32.dll
    put32(idata + 20, 0x3098);   // OriginalFirstThunk
    put32(idata + 24, 0);
    put32(idata + 28, 0);
    put32(idata + 32, 0x3150);   // Name RVA
    put32(idata + 36, 0x30C8);   // FirstThunk

    // Null terminator (20 zero bytes) — already zero

    return buf;
}

// ============================================================================
// Build a PE with ordinal import
// ============================================================================

static n00b_buffer_t *
make_pe_with_ordinal_import(void)
{
    size_t total = 0xA00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_IMPORT * 8, 0x2000);
    put32(dd + N00B_PE_DD_IMPORT * 8 + 4, 0x100);

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .idata
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".idata\0\0", 8);
    put32(sh1 + 8,  0x400);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x400);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    uint8_t *idata = p + 0x400;

    // DLL name at offset 0x100 → RVA 0x2100
    memcpy(idata + 0x100, "WS2_32.dll", 11);

    // ILT at offset 0x080 → RVA 0x2080 (ordinal import)
    put64(idata + 0x080, N00B_PE_IMPORT_ORDINAL_FLAG64 | 23);  // ordinal 23
    put64(idata + 0x088, 0);  // null term

    // Descriptor
    put32(idata + 0, 0x2080);   // OriginalFirstThunk
    put32(idata + 12, 0x2100);  // Name
    put32(idata + 16, 0x2080);  // FirstThunk (same as ILT for simplicity)

    // Null terminator descriptor at +20

    return buf;
}

// ============================================================================
// Build a PE with exports
// ============================================================================

static n00b_buffer_t *
make_pe_with_exports(void)
{
    size_t total = 0xA00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_DLL);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_EXPORT * 8, 0x2000);     // Export RVA
    put32(dd + N00B_PE_DD_EXPORT * 8 + 4, 0x200);  // Export size

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .edata
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".edata\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Export directory at file offset 0x400 (RVA 0x2000)
    uint8_t *edata = p + 0x400;

    // 3 exported functions: "Add" (ordinal 1), "Mul" (ordinal 2), unnamed (ordinal 3)
    // Module name at +0x100 → RVA 0x2100
    memcpy(edata + 0x100, "mylib.dll", 10);

    // Function address table at +0x028 → RVA 0x2028 (3 entries)
    put32(edata + 0x028, 0x1000);  // Add → RVA 0x1000
    put32(edata + 0x02C, 0x1020);  // Mul → RVA 0x1020
    put32(edata + 0x030, 0x1040);  // ordinal-only → RVA 0x1040

    // Name pointer table at +0x034 → RVA 0x2034 (2 named entries, sorted)
    // "Add" at +0x110 → RVA 0x2110
    memcpy(edata + 0x110, "Add", 4);
    // "Mul" at +0x114 → RVA 0x2114
    memcpy(edata + 0x114, "Mul", 4);
    put32(edata + 0x034, 0x2110);  // → "Add"
    put32(edata + 0x038, 0x2114);  // → "Mul"

    // Ordinal table at +0x03C → RVA 0x203C (index into address table)
    put16(edata + 0x03C, 0);  // "Add" → index 0
    put16(edata + 0x03E, 1);  // "Mul" → index 1

    // Export directory header (40 bytes)
    put32(edata + 0, 0);            // Characteristics
    put32(edata + 4, 0);            // TimeDateStamp
    put16(edata + 8, 0);            // MajorVersion
    put16(edata + 10, 0);           // MinorVersion
    put32(edata + 12, 0x2100);      // Name RVA
    put32(edata + 16, 1);           // Base (ordinal base)
    put32(edata + 20, 3);           // NumberOfFunctions
    put32(edata + 24, 2);           // NumberOfNames
    put32(edata + 28, 0x2028);      // AddressOfFunctions
    put32(edata + 32, 0x2034);      // AddressOfNames
    put32(edata + 36, 0x203C);      // AddressOfNameOrdinals

    return buf;
}

// ============================================================================
// Build a PE with forwarded export
// ============================================================================

static n00b_buffer_t *
make_pe_with_forwarded_export(void)
{
    size_t total = 0xA00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_DLL);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    // Export dir at RVA 0x2000, size 0x200 (all of .edata)
    put32(dd + N00B_PE_DD_EXPORT * 8, 0x2000);
    put32(dd + N00B_PE_DD_EXPORT * 8 + 4, 0x200);

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .edata
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".edata\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    uint8_t *edata = p + 0x400;

    // Module name at +0x100 → RVA 0x2100
    memcpy(edata + 0x100, "fwdlib.dll", 11);

    // Forwarder string at +0x110 → RVA 0x2110 (within export dir range)
    memcpy(edata + 0x110, "NTDLL.RtlInitUnicodeString", 27);

    // Function address table at +0x028 → one forwarded export
    put32(edata + 0x028, 0x2110);  // Points into export dir → forwarded

    // Name pointer + ordinal at +0x030/+0x034
    memcpy(edata + 0x130, "ForwardedFunc", 14);  // after forwarder string
    put32(edata + 0x030, 0x2130);  // name RVA
    put16(edata + 0x034, 0);       // ordinal index 0

    // Export directory header
    put32(edata + 12, 0x2100);   // Name
    put32(edata + 16, 1);        // Base
    put32(edata + 20, 1);        // NumberOfFunctions
    put32(edata + 24, 1);        // NumberOfNames
    put32(edata + 28, 0x2028);   // AddressOfFunctions
    put32(edata + 32, 0x2030);   // AddressOfNames
    put32(edata + 36, 0x2034);   // AddressOfNameOrdinals

    return buf;
}

// ============================================================================
// Build PE with base relocations
// ============================================================================

static n00b_buffer_t *
make_pe_with_relocs(void)
{
    size_t total = 0xA00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_BASERELOC * 8, 0x2000);    // Reloc RVA
    put32(dd + N00B_PE_DD_BASERELOC * 8 + 4, 20);    // Size (1 block)

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .reloc
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".reloc\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ
                    | N00B_PE_SCN_MEM_DISCARDABLE);

    // Relocation block at file offset 0x400
    uint8_t *reloc = p + 0x400;
    put32(reloc + 0, 0x1000);   // PageRVA
    put32(reloc + 4, 20);       // BlockSize (8 + 6*2 = 20)
    // 6 entries: 3 DIR64 + 2 ABSOLUTE (padding) + 1 HIGHLOW
    put16(reloc + 8,  (N00B_PE_REL_BASED_DIR64 << 12) | 0x010);  // 0x1010
    put16(reloc + 10, (N00B_PE_REL_BASED_DIR64 << 12) | 0x020);  // 0x1020
    put16(reloc + 12, (N00B_PE_REL_BASED_ABSOLUTE << 12) | 0);    // padding
    put16(reloc + 14, (N00B_PE_REL_BASED_DIR64 << 12) | 0x030);  // 0x1030
    put16(reloc + 16, (N00B_PE_REL_BASED_ABSOLUTE << 12) | 0);    // padding
    put16(reloc + 18, (N00B_PE_REL_BASED_HIGHLOW << 12) | 0x040); // 0x1040

    return buf;
}

// ============================================================================
// Build PE with debug (CodeView/RSDS) + TLS
// ============================================================================

static n00b_buffer_t *
make_pe_with_debug_and_tls(void)
{
    size_t total = 0xE00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 3);  // .text, .debug, .tls
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x5000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_DEBUG * 8, 0x2000);     // Debug RVA
    put32(dd + N00B_PE_DD_DEBUG * 8 + 4, 28);     // 1 debug entry (28 bytes)
    put32(dd + N00B_PE_DD_TLS * 8, 0x3000);       // TLS RVA
    put32(dd + N00B_PE_DD_TLS * 8 + 4, 40);       // TLS size

    // Sections
    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .debug section
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".debug\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // .tls section
    uint8_t *sh2 = p + 0x188 + 80;
    memcpy(sh2, ".tls\0\0\0\0", 8);
    put32(sh2 + 8,  0x200);
    put32(sh2 + 12, 0x3000);
    put32(sh2 + 16, 0x200);
    put32(sh2 + 20, 0x600);
    put32(sh2 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ
                    | N00B_PE_SCN_MEM_WRITE);

    // Debug directory at file offset 0x400 (RVA 0x2000)
    uint8_t *dbg = p + 0x400;
    put32(dbg + 0, 0);                       // Characteristics
    put32(dbg + 4, 0x5F3B3020);             // TimeDateStamp
    put16(dbg + 8, 0);                       // MajorVersion
    put16(dbg + 10, 0);                      // MinorVersion
    put32(dbg + 12, N00B_PE_DEBUG_TYPE_CODEVIEW); // Type
    put32(dbg + 16, 60);                     // SizeOfData
    put32(dbg + 20, 0x2040);                 // AddressOfRawData
    put32(dbg + 24, 0x440);                  // PointerToRawData

    // RSDS record at file offset 0x440
    uint8_t *rsds = p + 0x440;
    put32(rsds + 0, N00B_PE_CV_SIGNATURE_RSDS);   // "RSDS"
    // 16-byte GUID (arbitrary)
    memset(rsds + 4, 0xAB, 16);
    put32(rsds + 20, 1);                     // Age
    memcpy(rsds + 24, "C:\\project\\test.pdb", 19);  // PDB path

    // TLS directory at file offset 0x600 (RVA 0x3000)
    uint8_t *tls = p + 0x600;
    put64(tls + 0, 0x0000000140004000ULL);   // RawDataStartVA
    put64(tls + 8, 0x0000000140004010ULL);   // RawDataEndVA
    put64(tls + 16, 0x0000000140003050ULL);  // AddressOfIndex
    put64(tls + 24, 0x0000000140003060ULL);  // AddressOfCallBacks

    // Callback array at RVA 0x3060 = file offset 0x660
    uint8_t *cbs = p + 0x660;
    put64(cbs + 0, 0x0000000140001000ULL);   // Callback 1
    put64(cbs + 8, 0x0000000140001020ULL);   // Callback 2
    put64(cbs + 16, 0);                       // Null terminator

    return buf;
}

// ============================================================================
// Build PE with resources
// ============================================================================

static n00b_buffer_t *
make_pe_with_resources(void)
{
    size_t total = 0xC00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_RESOURCE * 8, 0x2000);    // Resource RVA
    put32(dd + N00B_PE_DD_RESOURCE * 8 + 4, 0x200); // Resource size

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .rsrc
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".rsrc\0\0\0", 8);
    put32(sh1 + 8,  0x400);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x400);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Resource directory at file offset 0x400 (rsrc_off)
    // 3-level tree: root → type(MANIFEST=24) → name(ID=1) → lang(ID=1033) → data
    uint8_t *rsrc = p + 0x400;

    // Root directory (level 0): 1 ID entry (type RT_MANIFEST=24)
    put16(rsrc + 12, 0);  // NumberOfNamedEntries
    put16(rsrc + 14, 1);  // NumberOfIdEntries
    // Entry: id=24, offset to subdir at 0x20 with high bit set
    put32(rsrc + 16, N00B_PE_RT_MANIFEST);
    put32(rsrc + 20, 0x80000020);  // Subdir at offset 0x20

    // Level 1 directory at offset 0x20: 1 ID entry (name ID=1)
    uint8_t *l1 = rsrc + 0x20;
    put16(l1 + 12, 0);
    put16(l1 + 14, 1);
    put32(l1 + 16, 1);            // Name ID = 1
    put32(l1 + 20, 0x80000040);   // Subdir at offset 0x40

    // Level 2 directory at offset 0x40: 1 ID entry (lang=1033)
    uint8_t *l2 = rsrc + 0x40;
    put16(l2 + 12, 0);
    put16(l2 + 14, 1);
    put32(l2 + 16, 1033);        // Language ID
    put32(l2 + 20, 0x60);        // Data entry at offset 0x60 (NOT subdir, no high bit)

    // Data entry at offset 0x60
    uint8_t *de = rsrc + 0x60;
    put32(de + 0, 0x2100);    // RVA of data (within .rsrc)
    put32(de + 4, 30);        // Size
    put32(de + 8, 0);         // CodePage
    put32(de + 12, 0);        // Reserved

    // Actual data at RVA 0x2100 = rsrc offset 0x100 = file offset 0x500
    memcpy(p + 0x500, "<?xml version=\"1.0\"?>TEST", 24);

    return buf;
}

// ============================================================================
// Tests
// ============================================================================

static void
test_detect_pe(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    assert(n00b_detect_format(s) == N00B_FMT_PE);
    printf("  [PASS] detect_pe\n");
}

static void
test_parse_headers(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->machine == N00B_PE_MACHINE_AMD64);
    assert(pe->imagebase == 0x0000000140000000ULL);
    assert(pe->entry_point == 0x1000);
    assert(pe->section_alignment == 0x1000);
    assert(pe->file_alignment == 0x200);
    assert(pe->magic == N00B_PE_OPT_MAGIC_PE32P);

    printf("  [PASS] parse_headers\n");
}

static void
test_parse_sections(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->num_sections == 2);
    assert(strcmp(pe->sections[0].name->data, ".text") == 0);
    assert(strcmp(pe->sections[1].name->data, ".data") == 0);
    assert(pe->sections[0].virtual_address == 0x1000);
    assert(pe->sections[1].virtual_address == 0x2000);
    assert(pe->sections[0].raw_offset == 0x200);
    assert(pe->sections[0].characteristics
           == (N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ));

    printf("  [PASS] parse_sections\n");
}

static void
test_section_content(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->sections[0].content != nullptr);

    uint8_t *data = (uint8_t *)pe->sections[0].content->data;
    assert(data[0] == 0xCC);
    assert(data[1] == 0x90);
    assert(data[2] == 0xC3);

    printf("  [PASS] section_content\n");
}

static void
test_section_by_name(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_section_by_name(pe, ".text") != nullptr);
    assert(n00b_pe_section_by_name(pe, ".foo") == nullptr);

    printf("  [PASS] section_by_name\n");
}

static void
test_has_section(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_section(pe, ".text") == true);
    assert(n00b_pe_has_section(pe, ".foo") == false);

    printf("  [PASS] has_section\n");
}

static void
test_is_dll(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_is_dll(pe) == false);

    // Flip the DLL bit and re-parse
    uint8_t *p = (uint8_t *)buf->data;
    uint16_t chars;
    memcpy(&chars, p + 0x84 + 18, 2);
    chars |= N00B_PE_CHAR_DLL;
    memcpy(p + 0x84 + 18, &chars, 2);

    s = n00b_bstream_new(buf);
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));
    pe = n00b_result_get(r2);
    assert(n00b_pe_is_dll(pe) == true);

    printf("  [PASS] is_dll\n");
}

static void
test_bad_magic(void)
{
    n00b_buffer_t *buf = n00b_buffer_new(64);

    memset(buf->data, 0, 64);
    buf->byte_len = 64;
    memcpy(buf->data, "NOTMZ", 5);

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_err(r));

    printf("  [PASS] bad_magic\n");
}

static void
test_bad_pe_sig(void)
{
    n00b_buffer_t *buf = n00b_buffer_new(256);

    memset(buf->data, 0, 256);
    buf->byte_len = 256;
    uint8_t *p = (uint8_t *)buf->data;
    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, 0xDEADBEEF);  // Bad PE signature

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_err(r));

    printf("  [PASS] bad_pe_sig\n");
}

static void
test_pe32_rejected(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    // Change optional header magic to PE32 (0x10B)
    uint8_t *p = (uint8_t *)buf->data;
    put16(p + 0x98, N00B_PE_OPT_MAGIC_PE32);

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_NOT_SUPPORTED);

    printf("  [PASS] pe32_rejected\n");
}

static void
test_abstract_pe(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);

    // We can't use n00b_parse_file (needs a real file), so test
    // the pieces manually: parse PE, create abstract binary, verify.
    auto pe_r = n00b_pe_parse(stream);
    assert(n00b_result_is_ok(pe_r));
    n00b_pe_binary_t *pe = n00b_result_get(pe_r);

    // Simulate what n00b_parse_file does
    n00b_binary_t *b = n00b_alloc(n00b_binary_t);
    b->format     = N00B_FMT_PE;
    b->arch       = N00B_ARCH_X86_64;
    b->entrypoint = pe->imagebase + pe->entry_point;
    b->imagebase  = pe->imagebase;
    b->is_pie     = (pe->dll_characteristics & N00B_PE_DLLCHAR_DYNAMIC_BASE) != 0;
    b->impl       = pe;

    assert(n00b_binary_format(b) == N00B_FMT_PE);
    assert(n00b_binary_arch(b) == N00B_ARCH_X86_64);
    assert(n00b_binary_entrypoint(b) == 0x0000000140001000ULL);
    assert(n00b_binary_imagebase(b) == 0x0000000140000000ULL);
    assert(n00b_binary_is_pie(b) == true);
    assert(n00b_binary_section_count(b) == 2);

    n00b_abstract_section_t sec0 = n00b_binary_section_at(b, 0);
    assert(sec0.name != nullptr);
    assert(strcmp(sec0.name->data, ".text") == 0);
    assert(sec0.addr == 0x1000);

    n00b_option_t(n00b_pe_binary_t *) downcast_opt = n00b_binary_as_pe(b);
    assert(n00b_option_is_set(downcast_opt));
    assert(n00b_option_get(downcast_opt) == pe);

    printf("  [PASS] abstract_pe\n");
}

static void
test_parse_imports(void)
{
    n00b_buffer_t *buf = make_pe_with_imports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->num_imports == 2);
    assert(n00b_pe_has_imports(pe));

    assert(strcmp(pe->imports[0].name->data, "KERNEL32.dll") == 0);
    assert(pe->imports[0].num_functions == 2);
    assert(strcmp(pe->imports[0].functions[0].name->data, "ExitProcess") == 0);
    assert(strcmp(pe->imports[0].functions[1].name->data, "GetLastError") == 0);

    assert(strcmp(pe->imports[1].name->data, "USER32.dll") == 0);
    assert(pe->imports[1].num_functions == 1);
    assert(strcmp(pe->imports[1].functions[0].name->data, "MessageBoxA") == 0);

    printf("  [PASS] parse_imports\n");
}

static void
test_parse_ordinal_import(void)
{
    n00b_buffer_t *buf = make_pe_with_ordinal_import();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->num_imports == 1);
    assert(pe->imports[0].num_functions == 1);
    assert(pe->imports[0].functions[0].is_ordinal == true);
    assert(pe->imports[0].functions[0].ordinal == 23);

    printf("  [PASS] parse_ordinal_import\n");
}

static void
test_import_by_name(void)
{
    n00b_buffer_t *buf = make_pe_with_imports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    n00b_pe_import_t *k32 = n00b_pe_import_by_name(pe, "KERNEL32.dll");
    assert(k32 != nullptr);
    assert(k32->num_functions == 2);

    n00b_pe_import_t *nope = n00b_pe_import_by_name(pe, "NOEXIST.dll");
    assert(nope == nullptr);

    printf("  [PASS] import_by_name\n");
}

static void
test_imported_func_by_name(void)
{
    n00b_buffer_t *buf = make_pe_with_imports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    n00b_pe_import_t *k32 = n00b_pe_import_by_name(pe, "KERNEL32.dll");
    assert(k32 != nullptr);

    n00b_pe_imported_func_t *ep = n00b_pe_imported_func_by_name(k32,
                                                                 "ExitProcess");
    assert(ep != nullptr);
    assert(ep->hint == 0);

    n00b_pe_imported_func_t *nf = n00b_pe_imported_func_by_name(k32,
                                                                 "NoSuchFunc");
    assert(nf == nullptr);

    printf("  [PASS] imported_func_by_name\n");
}

static void
test_parse_exports(void)
{
    n00b_buffer_t *buf = make_pe_with_exports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_exports(pe));
    assert(pe->export_info->num_functions == 3);
    assert(strcmp(pe->export_info->name->data, "mylib.dll") == 0);
    assert(pe->export_info->ordinal_base == 1);

    // Named exports
    n00b_pe_exported_func_t *add_fn = n00b_pe_export_by_name(pe, "Add");
    assert(add_fn != nullptr);
    assert(add_fn->rva == 0x1000);
    assert(add_fn->ordinal == 1);

    n00b_pe_exported_func_t *mul_fn = n00b_pe_export_by_name(pe, "Mul");
    assert(mul_fn != nullptr);
    assert(mul_fn->rva == 0x1020);

    printf("  [PASS] parse_exports\n");
}

static void
test_export_by_name(void)
{
    n00b_buffer_t *buf = make_pe_with_exports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_export_by_name(pe, "Add") != nullptr);
    assert(n00b_pe_export_by_name(pe, "NonExist") == nullptr);

    printf("  [PASS] export_by_name\n");
}

static void
test_export_by_ordinal(void)
{
    n00b_buffer_t *buf = make_pe_with_exports();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    n00b_pe_exported_func_t *f = n00b_pe_export_by_ordinal(pe, 1);
    assert(f != nullptr);
    assert(f->rva == 0x1000);

    // Ordinal 3 = unnamed function (index 2)
    n00b_pe_exported_func_t *f3 = n00b_pe_export_by_ordinal(pe, 3);
    assert(f3 != nullptr);
    assert(f3->rva == 0x1040);
    assert(f3->name == nullptr);

    assert(n00b_pe_export_by_ordinal(pe, 99) == nullptr);

    printf("  [PASS] export_by_ordinal\n");
}

static void
test_forwarded_export(void)
{
    n00b_buffer_t *buf = make_pe_with_forwarded_export();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_exports(pe));
    assert(pe->export_info->num_functions == 1);

    n00b_pe_exported_func_t *f = &pe->export_info->functions[0];
    assert(f->is_forwarded == true);
    assert(f->forward_name != nullptr);
    assert(strcmp(f->forward_name->data, "NTDLL.RtlInitUnicodeString") == 0);

    printf("  [PASS] forwarded_export\n");
}

static void
test_parse_relocs(void)
{
    n00b_buffer_t *buf = make_pe_with_relocs();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    // 6 entries, 2 are ABSOLUTE (padding) → 4 real relocations
    assert(pe->num_relocations == 4);

    printf("  [PASS] parse_relocs\n");
}

static void
test_parse_reloc_types(void)
{
    n00b_buffer_t *buf = make_pe_with_relocs();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->relocations[0].type == N00B_PE_REL_BASED_DIR64);
    assert(pe->relocations[0].rva == 0x1010);
    assert(pe->relocations[1].type == N00B_PE_REL_BASED_DIR64);
    assert(pe->relocations[1].rva == 0x1020);
    assert(pe->relocations[2].type == N00B_PE_REL_BASED_DIR64);
    assert(pe->relocations[2].rva == 0x1030);
    assert(pe->relocations[3].type == N00B_PE_REL_BASED_HIGHLOW);
    assert(pe->relocations[3].rva == 0x1040);

    printf("  [PASS] parse_reloc_types\n");
}

static void
test_parse_debug_codeview(void)
{
    n00b_buffer_t *buf = make_pe_with_debug_and_tls();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_debug(pe));
    assert(pe->num_debug_entries == 1);
    assert(pe->debug_entries[0].type == N00B_PE_DEBUG_TYPE_CODEVIEW);
    assert(pe->debug_entries[0].pdb_path != nullptr);
    assert(strcmp(pe->debug_entries[0].pdb_path->data,
                  "C:\\project\\test.pdb") == 0);

    printf("  [PASS] parse_debug_codeview\n");
}

static void
test_parse_tls_callbacks(void)
{
    n00b_buffer_t *buf = make_pe_with_debug_and_tls();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_tls(pe));

    n00b_pe_tls_t *tls = n00b_pe_get_tls(pe);
    assert(tls != nullptr);
    assert(tls->num_callbacks == 2);
    assert(tls->callbacks[0] == 0x0000000140001000ULL);
    assert(tls->callbacks[1] == 0x0000000140001020ULL);

    printf("  [PASS] parse_tls_callbacks\n");
}

static void
test_pdb_path_query(void)
{
    n00b_buffer_t *buf = make_pe_with_debug_and_tls();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    n00b_string_t *path = n00b_pe_pdb_path(pe);
    assert(path != nullptr);
    assert(strcmp(path->data, "C:\\project\\test.pdb") == 0);

    printf("  [PASS] pdb_path_query\n");
}

static void
test_no_debug(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_debug(pe) == false);
    assert(pe->num_debug_entries == 0);

    printf("  [PASS] no_debug\n");
}

static void
test_no_tls(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_tls(pe) == false);
    assert(n00b_pe_get_tls(pe) == nullptr);

    printf("  [PASS] no_tls\n");
}

static void
test_parse_resources(void)
{
    n00b_buffer_t *buf = make_pe_with_resources();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_resources(pe));
    assert(pe->resources->num_children == 1);
    assert(pe->resources->children[0].id == N00B_PE_RT_MANIFEST);

    printf("  [PASS] parse_resources\n");
}

static void
test_resource_by_type(void)
{
    n00b_buffer_t *buf = make_pe_with_resources();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    n00b_pe_resource_node_t *manifest = n00b_pe_resource_by_type(pe,
                                                                  N00B_PE_RT_MANIFEST);
    assert(manifest != nullptr);
    assert(manifest->id == N00B_PE_RT_MANIFEST);

    n00b_pe_resource_node_t *nope = n00b_pe_resource_by_type(pe, N00B_PE_RT_ICON);
    assert(nope == nullptr);

    printf("  [PASS] resource_by_type\n");
}

static void
test_no_resources(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_resources(pe) == false);
    assert(n00b_pe_resource_by_type(pe, N00B_PE_RT_MANIFEST) == nullptr);

    printf("  [PASS] no_resources\n");
}

// ============================================================================
// Phase 9a: DOS header fields
// ============================================================================

static void
test_dos_header_fields(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;

    // Set some non-default DOS header fields
    put16(p + 2,  0x0090);   // e_cblp
    put16(p + 4,  0x0003);   // e_cp
    put16(p + 8,  0x0004);   // e_cparhdr
    put16(p + 12, 0xFFFF);   // e_maxalloc (offset 12 in DOS header)

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->dos_header.e_magic == N00B_PE_MAGIC_MZ);
    assert(pe->dos_header.e_cblp == 0x0090);
    assert(pe->dos_header.e_cp == 0x0003);
    assert(pe->dos_header.e_cparhdr == 0x0004);
    assert(pe->dos_header.e_maxalloc == 0xFFFF);
    assert(pe->dos_header.e_lfanew == 0x80);
    assert(pe->pe_offset == 0x80);

    printf("  [PASS] dos_header_fields\n");
}

// ============================================================================
// Phase 9a: Optional header full read
// ============================================================================

static void
test_optional_header_full(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // These were already set by make_minimal_pe64:
    //   oh[2]=14 (MajorLinkerVersion), oh[3]=0 (MinorLinkerVersion)
    //   oh+4=SizeOfCode, oh+8=SizeOfInitializedData, oh+20=BaseOfCode
    // Verify they're parsed now (instead of skipped)

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(pe->major_linker_version == 14);
    assert(pe->minor_linker_version == 0);
    assert(pe->size_of_code == 0x200);
    assert(pe->size_of_initialized_data == 0x200);
    assert(pe->size_of_uninitialized_data == 0);
    assert(pe->base_of_code == 0x1000);

    // Check image/subsystem version fields
    assert(pe->major_image_version == 0);
    assert(pe->minor_image_version == 0);
    assert(pe->major_subsystem_version == 6);
    assert(pe->minor_subsystem_version == 0);
    assert(pe->win32_version_value == 0);

    // Stack/heap sizes
    assert(pe->size_of_stack_reserve == 0x100000);
    assert(pe->size_of_stack_commit == 0x1000);
    assert(pe->size_of_heap_reserve == 0x100000);
    assert(pe->size_of_heap_commit == 0x1000);
    assert(pe->loader_flags == 0);

    printf("  [PASS] optional_header_full\n");
}

// ============================================================================
// Phase 9a: Optional header round-trip through builder
// ============================================================================

static void
test_optional_header_roundtrip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point              = 0x1000;
    bin->major_linker_version     = 14;
    bin->minor_linker_version     = 30;
    bin->size_of_code             = 0x400;
    bin->size_of_initialized_data = 0x200;
    bin->base_of_code             = 0x1000;
    bin->major_image_version      = 1;
    bin->minor_image_version      = 2;
    bin->major_subsystem_version  = 10;
    bin->minor_subsystem_version  = 0;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->major_linker_version == 14);
    assert(parsed->minor_linker_version == 30);
    assert(parsed->size_of_code == 0x400);
    assert(parsed->size_of_initialized_data == 0x200);
    assert(parsed->base_of_code == 0x1000);
    assert(parsed->major_image_version == 1);
    assert(parsed->minor_image_version == 2);
    assert(parsed->major_subsystem_version == 10);
    assert(parsed->minor_subsystem_version == 0);

    printf("  [PASS] optional_header_roundtrip\n");
}

// ============================================================================
// Phase 9a: Import timestamp and forwarder chain
// ============================================================================

static void
test_import_timestamp_forwarder(void)
{
    // Build a PE with imports via the builder, parse it, check defaults are 0
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    n00b_pe_import_t *k32 = n00b_pe_add_import(bin, "KERNEL32.dll");
    n00b_pe_add_imported_func(k32, "ExitProcess", 0);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->num_imports == 1);
    assert(parsed->imports[0].time_date_stamp == 0);
    assert(parsed->imports[0].forwarder_chain == 0);

    printf("  [PASS] import_timestamp_forwarder\n");
}

// ============================================================================
// Phase 9a: Export directory fields
// ============================================================================

static void
test_export_dir_fields(void)
{
    // Build a DLL with exports, parse, check directory fields
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->characteristics |= N00B_PE_CHAR_DLL;
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    n00b_pe_set_export_name(bin, "test.dll");
    bin->export_info->ordinal_base = 1;
    n00b_pe_add_export(bin, "Func1", 0x1000, 1);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(n00b_pe_has_exports(parsed));

    // Builder writes zeros for these — verify parse reads them
    assert(parsed->export_info->characteristics == 0);
    assert(parsed->export_info->time_date_stamp == 0);
    assert(parsed->export_info->major_version == 0);
    assert(parsed->export_info->minor_version == 0);

    printf("  [PASS] export_dir_fields\n");
}

// ============================================================================
// Phase 9a: Export forward name splitting
// ============================================================================

static void
test_export_forward_split(void)
{
    // Use the forwarded export factory
    n00b_buffer_t *buf = make_pe_with_forwarded_export();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_exports(pe));

    // Find the forwarded export
    bool found_fwd = false;

    for (uint32_t i = 0; i < pe->export_info->num_functions; i++) {
        if (pe->export_info->functions[i].is_forwarded) {
            found_fwd = true;
            n00b_pe_exported_func_t *f = &pe->export_info->functions[i];

            assert(f->forward_name != nullptr);
            assert(f->forward_library != nullptr);
            assert(f->forward_function != nullptr);

            // The forward_name should contain a '.'
            assert(strchr(f->forward_name->data, '.') != nullptr);
            break;
        }
    }

    assert(found_fwd);
    printf("  [PASS] export_forward_split\n");
}

// ============================================================================
// Phase 9a: TLS characteristics
// ============================================================================

static void
test_tls_characteristics(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;

    // Extend buffer to fit TLS data
    size_t new_total = 0x1000;
    n00b_buffer_t *big = n00b_buffer_new(new_total);
    memset(big->data, 0, new_total);
    memcpy(big->data, p, 0x600);
    big->byte_len = new_total;
    p = (uint8_t *)big->data;

    // Add a third section for TLS at RVA 0x3000, file offset 0x600
    uint8_t *fh = p + 0x84;
    put16(fh + 2, 3);  // 3 sections

    uint8_t *sh2 = p + 0x188 + 80;  // third section header
    memcpy(sh2, ".tls\0\0\0\0", 8);
    put32(sh2 + 8,  0x200);     // VirtualSize
    put32(sh2 + 12, 0x3000);    // VirtualAddress
    put32(sh2 + 16, 0x200);     // SizeOfRawData
    put32(sh2 + 20, 0x600);     // PointerToRawData
    put32(sh2 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Update SizeOfImage
    uint8_t *oh2 = p + 0x98;
    put32(oh2 + 56, 0x4000);

    // Set TLS data directory: RVA 0x3000, size 40
    uint8_t *dd = oh2 + 112;  // start of data directories
    put32(dd + N00B_PE_DD_TLS * 8, 0x3000);
    put32(dd + N00B_PE_DD_TLS * 8 + 4, 40);

    // Write TLS directory at file offset 0x600
    uint8_t *tls = p + 0x600;
    put64(tls + 0,  0x0000000140004000ULL);   // RawDataStartVA
    put64(tls + 8,  0x0000000140004100ULL);   // RawDataEndVA
    put64(tls + 16, 0x0000000140003000ULL);   // AddressOfIndex
    put64(tls + 24, 0);                        // AddressOfCallBacks (none)
    put32(tls + 32, 0x100);                    // SizeOfZeroFill
    put32(tls + 36, 0x00300000);               // Characteristics (alignment)

    n00b_bstream_t *s = n00b_bstream_new(big);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_tls(pe));
    assert(pe->tls->size_of_zero_fill == 0x100);
    assert(pe->tls->characteristics == 0x00300000);

    printf("  [PASS] tls_characteristics\n");
}

// ============================================================================
// Phase 9a: Resource named entry
// ============================================================================

static void
test_resource_named_entry(void)
{
    // Build a PE with a resource that has a named entry using UTF-16LE
    size_t total = 0x1000;
    n00b_buffer_t *buf = n00b_buffer_new(total);
    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    // Minimal DOS + PE headers
    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);  // 2 sections
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x4000);
    put32(oh + 60, 0x200);
    put16(oh + 68, N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    // Section headers
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_READ);

    uint8_t *sh1 = sh0 + 40;
    memcpy(sh1, ".rsrc\0\0\0", 8);
    put32(sh1 + 8,  0x400);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x400);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Resource data directory
    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_RESOURCE * 8, 0x2000);
    put32(dd + N00B_PE_DD_RESOURCE * 8 + 4, 0x400);

    // Resource tree at file offset 0x400 (RVA 0x2000)
    // Root directory: 1 named entry, 0 ID entries
    uint8_t *rsrc = p + 0x400;
    put32(rsrc + 0,  0);       // Characteristics
    put32(rsrc + 4,  0);       // TimeDateStamp
    put16(rsrc + 8,  0);       // MajorVersion
    put16(rsrc + 10, 0);       // MinorVersion
    put16(rsrc + 12, 1);       // NumberOfNamedEntries
    put16(rsrc + 14, 0);       // NumberOfIdEntries

    // Entry: name offset with high bit set, data offset
    // Name string at offset 0x80 within .rsrc
    put32(rsrc + 16, 0x80000080);  // Named: high bit + offset 0x80
    put32(rsrc + 20, 0x60);        // Data entry at offset 0x60

    // UTF-16LE name "Test" at rsrc + 0x80
    uint8_t *name_str = rsrc + 0x80;
    put16(name_str + 0, 4);       // Length (4 chars)
    put16(name_str + 2, 'T');
    put16(name_str + 4, 'e');
    put16(name_str + 6, 's');
    put16(name_str + 8, 't');

    // Data entry at rsrc + 0x60
    uint8_t *data_entry = rsrc + 0x60;
    put32(data_entry + 0, 0x2100);  // RVA to data (within .rsrc)
    put32(data_entry + 4, 4);       // Size
    put32(data_entry + 8, 0);       // CodePage

    // Data at file offset 0x400 + 0x100 = 0x500 (RVA 0x2100)
    memcpy(p + 0x500, "ABCD", 4);

    n00b_bstream_t *s = n00b_bstream_new(buf);
    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);
    assert(n00b_pe_has_resources(pe));
    assert(pe->resources->num_children == 1);

    // The named entry should have name "Test"
    assert(pe->resources->children[0].name != nullptr);
    assert(strcmp(pe->resources->children[0].name->data, "Test") == 0);
    assert(pe->resources->children[0].id == 0);

    printf("  [PASS] resource_named_entry\n");
}

// ============================================================================
// Phase 9b: RVA/VA/offset utilities
// ============================================================================

static void
test_rva_to_offset(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    // .text: RVA 0x1000, file offset 0x200
    assert(n00b_pe_rva_to_offset(pe, 0x1000) == 0x200);
    assert(n00b_pe_rva_to_offset(pe, 0x1100) == 0x300);

    // .data: RVA 0x2000, file offset 0x400
    assert(n00b_pe_rva_to_offset(pe, 0x2000) == 0x400);

    // Invalid RVA
    assert(n00b_pe_rva_to_offset(pe, 0x9000) == 0);

    printf("  [PASS] rva_to_offset\n");
}

static void
test_offset_to_rva(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    // .text: file offset 0x200 → RVA 0x1000
    assert(n00b_pe_offset_to_rva(pe, 0x200) == 0x1000);
    assert(n00b_pe_offset_to_rva(pe, 0x300) == 0x1100);

    // .data: file offset 0x400 → RVA 0x2000
    assert(n00b_pe_offset_to_rva(pe, 0x400) == 0x2000);

    // Invalid offset
    assert(n00b_pe_offset_to_rva(pe, 0x9000) == 0);

    printf("  [PASS] offset_to_rva\n");
}

static void
test_va_conversions(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    // RVA to VA
    assert(n00b_pe_rva_to_va(pe, 0x1000)
           == 0x0000000140000000ULL + 0x1000);

    // VA to RVA
    assert(n00b_pe_va_to_rva(pe, 0x0000000140001000ULL) == 0x1000);

    // VA to offset
    assert(n00b_pe_va_to_offset(pe, 0x0000000140001000ULL) == 0x200);

    // Invalid VA (below imagebase)
    assert(n00b_pe_va_to_rva(pe, 0x100) == 0);

    printf("  [PASS] va_conversions\n");
}

static void
test_content_at_rva(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    // .text at RVA 0x1000: first 3 bytes are 0xCC, 0x90, 0xC3
    n00b_buffer_t *content = n00b_pe_get_content_at_rva(pe, 0x1000, 3);
    assert(content != nullptr);
    uint8_t *d = (uint8_t *)content->data;
    assert(d[0] == 0xCC && d[1] == 0x90 && d[2] == 0xC3);

    // .data at RVA 0x2000: "Hello PE!"
    n00b_buffer_t *data = n00b_pe_get_content_at_rva(pe, 0x2000, 9);
    assert(data != nullptr);
    assert(memcmp(data->data, "Hello PE!", 9) == 0);

    // Invalid RVA
    assert(n00b_pe_get_content_at_rva(pe, 0x9000, 1) == nullptr);

    printf("  [PASS] content_at_rva\n");
}

static void
test_content_at_va(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    n00b_bstream_t *s   = n00b_bstream_new(buf);

    auto r = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r));

    n00b_pe_binary_t *pe = n00b_result_get(r);

    // VA for .text: imagebase + 0x1000
    uint64_t text_va = pe->imagebase + 0x1000;
    n00b_buffer_t *content = n00b_pe_get_content_at_va(pe, text_va, 3);
    assert(content != nullptr);
    uint8_t *d = (uint8_t *)content->data;
    assert(d[0] == 0xCC && d[1] == 0x90 && d[2] == 0xC3);

    printf("  [PASS] content_at_va\n");
}

// ============================================================================
// Phase 9a: DOS header round-trip through builder
// ============================================================================

static void
test_dos_header_roundtrip(void)
{
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    // Set non-default DOS header fields
    bin->dos_header.e_cblp    = 0x0090;
    bin->dos_header.e_cp      = 0x0003;
    bin->dos_header.e_cparhdr = 0x0004;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
        N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = {0xC3};
    text->content = n00b_buffer_from_bytes((char *)code, 1);

    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto r2 = n00b_pe_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_pe_binary_t *parsed = n00b_result_get(r2);
    assert(parsed->dos_header.e_magic == N00B_PE_MAGIC_MZ);
    assert(parsed->dos_header.e_cblp == 0x0090);
    assert(parsed->dos_header.e_cp == 0x0003);
    assert(parsed->dos_header.e_cparhdr == 0x0004);
    assert(parsed->dos_header.e_lfanew == parsed->pe_offset);

    printf("  [PASS] dos_header_roundtrip\n");
}

// ============================================================================
// Rich header factory
// ============================================================================

/// Build a minimal PE64 with a Rich header in the DOS stub area (0x40..0x80).
/// Contains 3 entries with XOR key = 0xDEADBEEF.
static n00b_buffer_t *
make_pe_with_rich_header(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;

    // Rich header layout in the DOS stub area (0x40 to 0x80):
    //   0x40: DanS ^ key
    //   0x44: 0 ^ key  (padding)
    //   0x48: 0 ^ key  (padding)
    //   0x4C: 0 ^ key  (padding)
    //   0x50: comp_id_0 ^ key, count_0 ^ key   (entry 0)
    //   0x58: comp_id_1 ^ key, count_1 ^ key   (entry 1)
    //   0x60: comp_id_2 ^ key, count_2 ^ key   (entry 2)
    //   0x68: "Rich"
    //   0x6C: key
    //
    // comp_id = (tool_id << 16) | build_id
    // Entry 0: tool_id=0x0093, build_id=0x7809, count=12
    // Entry 1: tool_id=0x0001, build_id=0x0000, count=42
    // Entry 2: tool_id=0x00FF, build_id=0x6030, count=1

    uint32_t key = 0xDEADBEEF;

    uint32_t comp0 = (0x0093 << 16) | 0x7809;  // 0x00937809
    uint32_t cnt0  = 12;
    uint32_t comp1 = (0x0001 << 16) | 0x0000;  // 0x00010000
    uint32_t cnt1  = 42;
    uint32_t comp2 = (0x00FF << 16) | 0x6030;  // 0x00FF6030
    uint32_t cnt2  = 1;

    // Write encrypted "DanS" + 3 zero padding dwords
    put32(p + 0x40, N00B_PE_DANS_MAGIC ^ key);
    put32(p + 0x44, 0 ^ key);
    put32(p + 0x48, 0 ^ key);
    put32(p + 0x4C, 0 ^ key);

    // Write encrypted entries
    put32(p + 0x50, comp0 ^ key);
    put32(p + 0x54, cnt0  ^ key);
    put32(p + 0x58, comp1 ^ key);
    put32(p + 0x5C, cnt1  ^ key);
    put32(p + 0x60, comp2 ^ key);
    put32(p + 0x64, cnt2  ^ key);

    // Write "Rich" signature and key (unencrypted)
    put32(p + 0x68, N00B_PE_RICH_MAGIC);
    put32(p + 0x6C, key);

    return buf;
}

// ============================================================================
// Phase 9c: Rich Header tests
// ============================================================================

static void
test_rich_header_parse(void)
{
    n00b_buffer_t *buf    = make_pe_with_rich_header();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_rich_header(bin));
    assert(bin->num_rich_entries == 3);

    // Entry 0: tool_id=0x0093, build_id=0x7809, count=12
    assert(bin->rich_entries[0].tool_id  == 0x0093);
    assert(bin->rich_entries[0].build_id == 0x7809);
    assert(bin->rich_entries[0].count    == 12);

    // Entry 1: tool_id=0x0001, build_id=0x0000, count=42
    assert(bin->rich_entries[1].tool_id  == 0x0001);
    assert(bin->rich_entries[1].build_id == 0x0000);
    assert(bin->rich_entries[1].count    == 42);

    // Entry 2: tool_id=0x00FF, build_id=0x6030, count=1
    assert(bin->rich_entries[2].tool_id  == 0x00FF);
    assert(bin->rich_entries[2].build_id == 0x6030);
    assert(bin->rich_entries[2].count    == 1);

    printf("  [PASS] rich_header_parse\n");
}

static void
test_rich_header_key(void)
{
    n00b_buffer_t *buf    = make_pe_with_rich_header();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(bin->rich_key == 0xDEADBEEF);

    // raw buffer should be non-null and contain decrypted data
    assert(bin->rich_raw != nullptr);
    assert(n00b_buffer_len(bin->rich_raw) > 0);

    // First 4 bytes of decrypted raw should be "DanS"
    uint32_t dans;
    memcpy(&dans, bin->rich_raw->data, 4);
    assert(dans == N00B_PE_DANS_MAGIC);

    printf("  [PASS] rich_header_key\n");
}

static void
test_no_rich_header(void)
{
    // The basic make_minimal_pe64 has zeros in the stub area — no Rich header.
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_rich_header(bin));
    assert(bin->num_rich_entries == 0);
    assert(bin->rich_entries == nullptr);
    assert(bin->rich_raw == nullptr);

    printf("  [PASS] no_rich_header\n");
}

// ============================================================================
// Phase 9d: Delay import factory + tests
// ============================================================================

/// Build a PE64 with one delay import (ADVAPI32.dll) containing one function.
/// Delay import descriptor at .data RVA 0x2000 (file 0x400).
/// Delay INT (name table) at .data RVA 0x2040 (file 0x440).
/// Hint/name at .data RVA 0x2060 (file 0x460).
/// DLL name at .data RVA 0x2080 (file 0x480).
static n00b_buffer_t *
make_pe_with_delay_imports(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // Data dir 13 (delay import): RVA=0x2000, Size=64 (2 descriptors: 1 real + 1 null terminator)
    put32(oh + 112 + 13 * 8,     0x2000);
    put32(oh + 112 + 13 * 8 + 4, 64);

    // Delay import descriptor at file offset 0x400 (RVA 0x2000)
    uint8_t *di = p + 0x400;
    put32(di + 0,  1);        // Attributes (1 = RVA-based)
    put32(di + 4,  0x2080);   // Name RVA
    put32(di + 8,  0);        // ModuleHandle
    put32(di + 12, 0);        // DelayImportAddressTable
    put32(di + 16, 0x2040);   // DelayImportNameTable RVA
    put32(di + 20, 0);        // BoundDelayImportTable
    put32(di + 24, 0);        // UnloadDelayImportTable
    put32(di + 28, 0);        // TimeDateStamp
    // Second descriptor (all zeros = terminator) is already zero.

    // Delay INT at file offset 0x440 (RVA 0x2040): one entry + null terminator
    put64(p + 0x440, 0x2060);  // Points to hint/name
    put64(p + 0x448, 0);       // Null terminator

    // Hint/name at file offset 0x460 (RVA 0x2060)
    put16(p + 0x460, 42);     // Hint
    memcpy(p + 0x462, "RegOpenKeyExW\0", 14);

    // DLL name at file offset 0x480 (RVA 0x2080)
    memcpy(p + 0x480, "ADVAPI32.dll\0", 13);

    return buf;
}

static void
test_delay_import_parse(void)
{
    n00b_buffer_t *buf    = make_pe_with_delay_imports();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_delay_imports(bin));
    assert(bin->num_delay_imports == 1);
    assert(bin->delay_imports[0].name != nullptr);
    assert(strcmp(bin->delay_imports[0].name->data, "ADVAPI32.dll") == 0);
    assert(bin->delay_imports[0].num_functions == 1);
    assert(bin->delay_imports[0].functions[0].name != nullptr);
    assert(strcmp(bin->delay_imports[0].functions[0].name->data, "RegOpenKeyExW") == 0);
    assert(bin->delay_imports[0].functions[0].hint == 42);

    printf("  [PASS] delay_import_parse\n");
}

static void
test_delay_import_by_name(void)
{
    n00b_buffer_t *buf    = make_pe_with_delay_imports();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_delay_import_t *di = n00b_pe_delay_import_by_name(bin, "advapi32.dll");
    assert(di != nullptr);
    assert(di->num_functions == 1);

    // Not found case
    assert(n00b_pe_delay_import_by_name(bin, "nosuch.dll") == nullptr);

    printf("  [PASS] delay_import_by_name\n");
}

static void
test_no_delay_imports(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_delay_imports(bin));
    assert(bin->num_delay_imports == 0);

    printf("  [PASS] no_delay_imports\n");
}

// ============================================================================
// Phase 9d: Exception table factory + tests
// ============================================================================

/// Build a PE64 with 3 exception entries in .text section.
/// Exception table at .text RVA 0x1100 (file 0x300).
static n00b_buffer_t *
make_pe_with_exceptions(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // Data dir 3 (exception): RVA=0x1100, Size=36 (3 entries * 12 bytes)
    put32(oh + 112 + 3 * 8,     0x1100);
    put32(oh + 112 + 3 * 8 + 4, 36);

    // Exception entries at file offset 0x300 (RVA 0x1100 = 0x1000 + 0x100,
    // .text starts at RVA 0x1000 / file 0x200, so offset = 0x200 + 0x100 = 0x300)
    uint8_t *ex = p + 0x300;

    // Entry 0: [0x1000, 0x1020) -> unwind at 0x1080
    put32(ex + 0,  0x1000);
    put32(ex + 4,  0x1020);
    put32(ex + 8,  0x1080);

    // Entry 1: [0x1020, 0x1050) -> unwind at 0x1090
    put32(ex + 12, 0x1020);
    put32(ex + 16, 0x1050);
    put32(ex + 20, 0x1090);

    // Entry 2: [0x1050, 0x1100) -> unwind at 0x10A0
    put32(ex + 24, 0x1050);
    put32(ex + 28, 0x1100);
    put32(ex + 32, 0x10A0);

    return buf;
}

static void
test_exception_parse(void)
{
    n00b_buffer_t *buf    = make_pe_with_exceptions();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_exceptions(bin));
    assert(bin->num_exceptions == 3);

    assert(bin->exceptions[0].begin_rva  == 0x1000);
    assert(bin->exceptions[0].end_rva    == 0x1020);
    assert(bin->exceptions[0].unwind_rva == 0x1080);

    assert(bin->exceptions[1].begin_rva  == 0x1020);
    assert(bin->exceptions[2].begin_rva  == 0x1050);

    printf("  [PASS] exception_parse\n");
}

static void
test_exception_at_rva(void)
{
    n00b_buffer_t *buf    = make_pe_with_exceptions();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // Exact start of entry 0
    n00b_pe_exception_entry_t *e = n00b_pe_exception_at_rva(bin, 0x1000);
    assert(e != nullptr);
    assert(e->begin_rva == 0x1000);

    // Middle of entry 1
    e = n00b_pe_exception_at_rva(bin, 0x1030);
    assert(e != nullptr);
    assert(e->begin_rva == 0x1020);

    // Not found (before all entries — but 0x0FFF is before first)
    e = n00b_pe_exception_at_rva(bin, 0x0FFF);
    assert(e == nullptr);

    // Not found (past last entry)
    e = n00b_pe_exception_at_rva(bin, 0x1100);
    assert(e == nullptr);

    printf("  [PASS] exception_at_rva\n");
}

static void
test_no_exceptions(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_exceptions(bin));

    printf("  [PASS] no_exceptions\n");
}

// ============================================================================
// Phase 9d: COFF symbol factory + tests
// ============================================================================

/// Build a PE64 with a COFF symbol table containing 2 symbols + string table.
/// Symbol table placed after section data, at file offset 0x600.
/// Layout: 2 symbols * 18 = 36 bytes, then string table.
/// String table: 4-byte size + "long_symbol_name\0"
static n00b_buffer_t *
make_pe_with_coff_symbols(void)
{
    size_t total = 0x700;  // Need more room than minimal
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    // Copy DOS header basics
    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    // File header
    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put32(fh + 4, 0x5F3B3020);
    put32(fh + 8,  0x600);           // PointerToSymbolTable
    put32(fh + 12, 2);               // NumberOfSymbols (including aux)
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    // Optional header
    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    oh[2] = 14;
    put32(oh + 16, 0x1000);
    put32(oh + 20, 0x1000);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x3000);
    put32(oh + 60, 0x200);
    put16(oh + 68, N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    // Section headers
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".data\0\0\0", 8);
    put32(sh1 + 8,  0x200);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0x200);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ | N00B_PE_SCN_MEM_WRITE);

    // COFF symbol table at 0x600
    uint8_t *sym = p + 0x600;

    // Symbol 0: short name "_main", value=0x1000, section=1, type=0x20, class=EXTERNAL
    memcpy(sym, "_main\0\0\0", 8);
    put32(sym + 8, 0x1000);       // Value
    put16(sym + 12, 1);           // SectionNumber
    put16(sym + 14, 0x20);        // Type (function)
    sym[16] = N00B_PE_SYM_CLASS_EXTERNAL;  // StorageClass
    sym[17] = 0;                  // NumberOfAuxSymbols

    // Symbol 1: long name (via string table), value=0x2000, section=2
    uint8_t *sym1 = sym + 18;
    put32(sym1, 0);               // Zeroes (long name indicator)
    put32(sym1 + 4, 4);           // Offset into string table (past 4-byte size)
    put32(sym1 + 8, 0x2000);      // Value
    put16(sym1 + 12, 2);          // SectionNumber
    put16(sym1 + 14, 0);          // Type
    sym1[16] = N00B_PE_SYM_CLASS_STATIC;
    sym1[17] = 0;

    // String table at 0x600 + 36 = 0x624
    uint8_t *strtab = p + 0x624;
    const char *long_name = "long_symbol_name";
    uint32_t strtab_size = 4 + (uint32_t)strlen(long_name) + 1;
    put32(strtab, strtab_size);
    memcpy(strtab + 4, long_name, strlen(long_name) + 1);

    return buf;
}

static void
test_coff_symbols_parse(void)
{
    n00b_buffer_t *buf    = make_pe_with_coff_symbols();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_symbols(bin));
    assert(bin->num_symbols == 2);

    // Symbol 0: short name
    assert(bin->symbols[0].name != nullptr);
    assert(strcmp(bin->symbols[0].name->data, "_main") == 0);
    assert(bin->symbols[0].value == 0x1000);
    assert(bin->symbols[0].section_number == 1);
    assert(bin->symbols[0].storage_class == N00B_PE_SYM_CLASS_EXTERNAL);

    // Symbol 1: long name via string table
    assert(bin->symbols[1].name != nullptr);
    assert(strcmp(bin->symbols[1].name->data, "long_symbol_name") == 0);
    assert(bin->symbols[1].value == 0x2000);
    assert(bin->symbols[1].section_number == 2);
    assert(bin->symbols[1].storage_class == N00B_PE_SYM_CLASS_STATIC);

    printf("  [PASS] coff_symbols_parse\n");
}

static void
test_no_symbols(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_symbols(bin));
    assert(bin->num_symbols == 0);

    printf("  [PASS] no_symbols\n");
}

// ============================================================================
// Phase 9d: Bound import factory + tests
// ============================================================================

/// Build a PE64 with bound imports. The bound import table is at file offset
/// 0x500 (we place it in padding area at end of .data). Contains 1 entry.
/// NOTE: For bound imports, VirtualAddress in data dir is a file offset.
static n00b_buffer_t *
make_pe_with_bound_imports(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // Data dir 11 (bound import): VirtualAddress is file offset = 0x500, Size=24
    // (1 descriptor of 8 bytes + null terminator of 8 bytes + name data)
    put32(oh + 112 + 11 * 8,     0x500);
    put32(oh + 112 + 11 * 8 + 4, 16);

    // Bound import descriptor at file offset 0x500
    uint8_t *bi = p + 0x500;
    put32(bi + 0, 0x5F3B3020);   // TimeDateStamp
    put16(bi + 4, 16);           // OffsetModuleName (relative to 0x500)
    put16(bi + 6, 0);            // NumberOfModuleForwarderRefs

    // Null terminator descriptor at 0x508
    // Already zero.

    // DLL name at 0x500 + 16 = 0x510
    memcpy(p + 0x510, "KERNEL32.dll\0", 13);

    return buf;
}

static void
test_bound_import_parse(void)
{
    n00b_buffer_t *buf    = make_pe_with_bound_imports();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_bound_imports(bin));
    assert(bin->num_bound_imports == 1);
    assert(bin->bound_imports[0].name != nullptr);
    assert(strcmp(bin->bound_imports[0].name->data, "KERNEL32.dll") == 0);
    assert(bin->bound_imports[0].time_date_stamp == 0x5F3B3020);

    printf("  [PASS] bound_import_parse\n");
}

// ============================================================================
// Phase 9e: Enhanced debug subtypes factory + tests
// ============================================================================

/// Build a PE64 with 4 debug entries: CODEVIEW, POGO, REPRO, EX_DLLCHAR.
/// Debug directory at .debug RVA 0x2000 (file 0x400) — 4 entries * 28 = 112 bytes.
/// Raw data for each starts after the directory: 0x470 onward.
static n00b_buffer_t *
make_pe_with_debug_subtypes(void)
{
    size_t total = 0xE00;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);
    put32(oh + 36, 0x200);
    put32(oh + 56, 0x5000);
    put32(oh + 60, 0x200);
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    // Data dir 6 (debug): RVA=0x2000, Size=112 (4 entries)
    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_DEBUG * 8,     0x2000);
    put32(dd + N00B_PE_DD_DEBUG * 8 + 4, 112);

    // Sections
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8,  0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".debug\0\0", 8);
    put32(sh1 + 8,  0xA00);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0xA00);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Debug directory entries at file 0x400 (RVA 0x2000)
    uint8_t *dbg = p + 0x400;

    // Entry 0: CODEVIEW at file 0x470 (RVA 0x2070)
    put32(dbg + 12, N00B_PE_DEBUG_TYPE_CODEVIEW);
    put32(dbg + 16, 50);       // SizeOfData
    put32(dbg + 20, 0x2070);   // AddressOfRawData
    put32(dbg + 24, 0x470);    // PointerToRawData

    // RSDS record at 0x470
    uint8_t *rsds = p + 0x470;
    put32(rsds + 0, N00B_PE_CV_SIGNATURE_RSDS);
    memset(rsds + 4, 0xAB, 16);  // GUID
    put32(rsds + 20, 7);          // Age
    memcpy(rsds + 24, "C:\\test.pdb\0", 12);

    // Entry 1: POGO at file 0x4C0 (RVA 0x20C0)
    uint8_t *dbg1 = dbg + 28;
    put32(dbg1 + 12, N00B_PE_DEBUG_TYPE_POGO);
    put32(dbg1 + 16, 40);      // SizeOfData
    put32(dbg1 + 20, 0x20C0);
    put32(dbg1 + 24, 0x4C0);

    // POGO data at 0x4C0: 4-byte signature + 2 entries
    uint8_t *pogo = p + 0x4C0;
    put32(pogo + 0, 0x4C544347);  // "GCTL" signature
    // Entry 0: rva=0x1000, size=0x200, name=".text\0" (6 bytes, pad to 8)
    put32(pogo + 4,  0x1000);
    put32(pogo + 8,  0x200);
    memcpy(pogo + 12, ".text\0\0\0", 8);  // 6 + 2 pad = 8
    // Entry 1: rva=0x2000, size=0x100, name=".data\0" (6 bytes, pad to 8)
    put32(pogo + 20, 0x2000);
    put32(pogo + 24, 0x100);
    memcpy(pogo + 28, ".data\0\0\0", 8);

    // Entry 2: REPRO at file 0x500 (RVA 0x2100)
    uint8_t *dbg2 = dbg + 56;
    put32(dbg2 + 12, N00B_PE_DEBUG_TYPE_REPRO);
    put32(dbg2 + 16, 36);       // SizeOfData (4 + 32 hash)
    put32(dbg2 + 20, 0x2100);
    put32(dbg2 + 24, 0x500);

    // REPRO data at 0x500: 4-byte hash length + 32-byte hash
    uint8_t *repro = p + 0x500;
    put32(repro + 0, 32);         // hash length
    memset(repro + 4, 0xCC, 32);  // hash bytes

    // Entry 3: EX_DLLCHAR at file 0x530 (RVA 0x2130)
    uint8_t *dbg3 = dbg + 84;
    put32(dbg3 + 12, N00B_PE_DEBUG_TYPE_EX_DLLCHAR);
    put32(dbg3 + 16, 4);
    put32(dbg3 + 20, 0x2130);
    put32(dbg3 + 24, 0x530);

    // EX_DLLCHAR data at 0x530: single u32
    put32(p + 0x530, 0x0001);  // CET shadow stack compatible

    return buf;
}

static void
test_debug_codeview_guid(void)
{
    n00b_buffer_t *buf    = make_pe_with_debug_subtypes();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_debug_entry_t *cv = n00b_pe_debug_entry_by_type(bin, N00B_PE_DEBUG_TYPE_CODEVIEW);
    assert(cv != nullptr);
    assert(cv->pdb_path != nullptr);
    assert(strcmp(cv->pdb_path->data, "C:\\test.pdb") == 0);
    assert(cv->age == 7);

    // Check GUID bytes
    for (int j = 0; j < 16; j++) {
        assert(cv->guid[j] == 0xAB);
    }

    printf("  [PASS] debug_codeview_guid\n");
}

static void
test_debug_pogo(void)
{
    n00b_buffer_t *buf    = make_pe_with_debug_subtypes();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_debug_entry_t *pg = n00b_pe_debug_entry_by_type(bin, N00B_PE_DEBUG_TYPE_POGO);
    assert(pg != nullptr);
    assert(pg->num_pogo_entries == 2);

    assert(pg->pogo_entries[0].rva  == 0x1000);
    assert(pg->pogo_entries[0].size == 0x200);
    assert(pg->pogo_entries[0].name != nullptr);
    assert(strcmp(pg->pogo_entries[0].name->data, ".text") == 0);

    assert(pg->pogo_entries[1].rva  == 0x2000);
    assert(pg->pogo_entries[1].size == 0x100);
    assert(pg->pogo_entries[1].name != nullptr);
    assert(strcmp(pg->pogo_entries[1].name->data, ".data") == 0);

    printf("  [PASS] debug_pogo\n");
}

static void
test_debug_repro(void)
{
    n00b_buffer_t *buf    = make_pe_with_debug_subtypes();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_debug_entry_t *rp = n00b_pe_debug_entry_by_type(bin, N00B_PE_DEBUG_TYPE_REPRO);
    assert(rp != nullptr);
    assert(rp->repro_hash != nullptr);
    assert((uint32_t)n00b_buffer_len(rp->repro_hash) == 32);

    const uint8_t *h = (const uint8_t *)rp->repro_hash->data;

    for (int j = 0; j < 32; j++) {
        assert(h[j] == 0xCC);
    }

    printf("  [PASS] debug_repro\n");
}

static void
test_debug_by_type_query(void)
{
    n00b_buffer_t *buf    = make_pe_with_debug_subtypes();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(bin->num_debug_entries == 4);

    // EX_DLLCHAR
    n00b_pe_debug_entry_t *ex = n00b_pe_debug_entry_by_type(bin, N00B_PE_DEBUG_TYPE_EX_DLLCHAR);
    assert(ex != nullptr);
    assert(ex->ex_dll_characteristics == 0x0001);

    // Not found
    assert(n00b_pe_debug_entry_by_type(bin, N00B_PE_DEBUG_TYPE_FPO) == nullptr);

    printf("  [PASS] debug_by_type_query\n");
}

// ============================================================================
// Phase 9d (continued): Bound import tests
// ============================================================================

static void
test_no_bound_imports(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_bound_imports(bin));
    assert(bin->num_bound_imports == 0);

    printf("  [PASS] no_bound_imports\n");
}

// ============================================================================
// Phase 9f: Load Configuration factory + tests
// ============================================================================

/// Build a PE64 with a Load Configuration directory.
/// Load config data at .data RVA 0x2000 (file 0x400).
/// Declared size = 112 bytes (covers through security_cookie, no CFG).
static n00b_buffer_t *
make_pe_with_load_config_basic(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // Data dir 10 (load config): RVA=0x2000, Size=112
    put32(oh + 112 + 10 * 8,     0x2000);
    put32(oh + 112 + 10 * 8 + 4, 112);

    // Load config at file offset 0x400 (RVA 0x2000)
    uint8_t *lc = p + 0x400;
    put32(lc + 0,  112);                   // Size
    put32(lc + 4,  0x5F3B3020);           // TimeDateStamp
    put16(lc + 8,  1);                     // MajorVersion
    put16(lc + 10, 0);                     // MinorVersion
    put32(lc + 12, 0);                     // GlobalFlagsClear
    put32(lc + 16, 0);                     // GlobalFlagsSet
    put32(lc + 20, 0);                     // CriticalSectionDefaultTimeout
    put64(lc + 24, 0);                     // DeCommitFreeBlockThreshold
    put64(lc + 32, 0);                     // DeCommitTotalFreeThreshold
    put64(lc + 40, 0);                     // LockPrefixTable
    put64(lc + 48, 0);                     // MaximumAllocationSize
    put64(lc + 56, 0);                     // VirtualMemoryThreshold
    put64(lc + 64, 0);                     // ProcessAffinityMask
    put32(lc + 72, 0);                     // ProcessHeapFlags
    put16(lc + 76, 0);                     // CSDVersion
    put16(lc + 78, 0);                     // DependentLoadFlags
    put64(lc + 80, 0);                     // EditList
    put64(lc + 88, 0x0000000140003000ULL); // SecurityCookie
    put64(lc + 96, 0);                     // SEHandlerTable
    put64(lc + 104, 0);                    // SEHandlerCount

    return buf;
}

/// Build a PE64 with a Load Configuration that includes CFG fields.
/// Declared size = 148 bytes (through guard_flags).
static n00b_buffer_t *
make_pe_with_load_config_cfg(void)
{
    n00b_buffer_t *buf = make_pe_with_load_config_basic();
    uint8_t       *p   = (uint8_t *)buf->data;
    uint8_t       *oh  = p + 0x98;

    // Increase data dir size to 148
    put32(oh + 112 + 10 * 8 + 4, 148);

    uint8_t *lc = p + 0x400;
    put32(lc + 0, 148);                              // Size

    // CFG fields (after SE handler count at offset 104+8=112)
    put64(lc + 112, 0x0000000140004000ULL);          // GuardCFCheckFunctionPointer
    put64(lc + 120, 0x0000000140004008ULL);          // GuardCFDispatchFunctionPointer
    put64(lc + 128, 0x0000000140005000ULL);          // GuardCFFunctionTable
    put64(lc + 136, 42);                              // GuardCFFunctionCount
    put32(lc + 144, N00B_PE_GUARD_CF_INSTRUMENTED
                    | N00B_PE_GUARD_CF_FUNCTION_TABLE_PRESENT); // GuardFlags

    return buf;
}

static void
test_load_config_basic(void)
{
    n00b_buffer_t *buf    = make_pe_with_load_config_basic();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_has_configuration(bin));
    n00b_pe_load_config_t *lc = n00b_pe_get_load_config(bin);
    assert(lc != nullptr);
    assert(lc->size == 112);
    assert(lc->time_date_stamp == 0x5F3B3020);
    assert(lc->major_version == 1);
    assert(lc->security_cookie == 0x0000000140003000ULL);

    // CFG fields should be zero (not present in 112-byte config)
    assert(lc->guard_flags == 0);
    assert(!n00b_pe_has_guard_cf(bin));

    printf("  [PASS] load_config_basic\n");
}

static void
test_load_config_cfg(void)
{
    n00b_buffer_t *buf    = make_pe_with_load_config_cfg();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_load_config_t *lc = n00b_pe_get_load_config(bin);
    assert(lc != nullptr);
    assert(lc->size == 148);
    assert(lc->guard_cf_function_count == 42);
    assert((lc->guard_flags & N00B_PE_GUARD_CF_INSTRUMENTED) != 0);
    assert((lc->guard_flags & N00B_PE_GUARD_CF_FUNCTION_TABLE_PRESENT) != 0);
    assert(n00b_pe_has_guard_cf(bin));

    printf("  [PASS] load_config_cfg\n");
}

static void
test_has_guard_cf(void)
{
    // A PE without load config should report no guard CF.
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_configuration(bin));
    assert(!n00b_pe_has_guard_cf(bin));
    assert(n00b_pe_get_load_config(bin) == nullptr);

    printf("  [PASS] has_guard_cf\n");
}

// ============================================================================
// Phase 9g: Checksum, entropy, demangling tests
// ============================================================================

static void
test_compute_checksum(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    uint32_t ck = n00b_pe_compute_checksum(bin);

    // With a zero stored checksum, the computed checksum should be non-zero
    // (file_length is added at the end).
    assert(ck > 0);

    // Now store the computed checksum and verify it matches.
    bin->checksum = ck;

    // Write it back into the buffer at the checksum offset
    uint8_t *p = (uint8_t *)buf->data;
    uint32_t ck_off = bin->pe_offset + 4 + 20 + 64;

    put32(p + ck_off, ck);

    assert(n00b_pe_verify_checksum(bin));

    printf("  [PASS] compute_checksum\n");
}

static void
test_verify_checksum(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // Stored checksum is 0, computed won't be 0, so verification should fail.
    assert(!n00b_pe_verify_checksum(bin));

    printf("  [PASS] verify_checksum\n");
}

static void
test_entropy_zeros(void)
{
    // .data section of make_minimal_pe64 has "Hello PE!" at start, rest is zeros.
    // Let's make a section that's all zeros for clean testing.
    n00b_buffer_t *buf    = make_minimal_pe64();

    // Zero out the .data content area
    memset((uint8_t *)buf->data + 0x400, 0, 0x200);

    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // .data section (index 1)
    assert(bin->num_sections >= 2);
    n00b_pe_section_t *data_sec = &bin->sections[1];
    assert(data_sec->content != nullptr);

    double e = n00b_pe_section_entropy(data_sec);

    // All zeros = entropy 0.0
    assert(e == 0.0);

    printf("  [PASS] entropy_zeros\n");
}

static void
test_entropy_random(void)
{
    n00b_buffer_t *buf = make_minimal_pe64();

    // Fill .text section (0x200..0x400) with pseudo-random-like bytes.
    uint8_t *p = (uint8_t *)buf->data;

    for (int i = 0; i < 0x200; i++) {
        p[0x200 + i] = (uint8_t)((i * 131 + 17) & 0xFF);
    }

    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_section_t *text_sec = &bin->sections[0];
    double e = n00b_pe_section_entropy(text_sec);

    // Should have relatively high entropy (>6.0) for well-distributed bytes.
    assert(e > 6.0);
    assert(e <= 8.0);

    printf("  [PASS] entropy_random\n");
}

static void
test_demangled_plain(void)
{
    // A plain (unmangled) name should come back unchanged.
    n00b_pe_imported_func_t f = {0};
    n00b_string_t *name = n00b_string_from_cstr("CreateFileW");

    f.name = name;

    n00b_string_t *dem = n00b_pe_imported_func_demangled(&f);
    assert(dem != nullptr);
    assert(strcmp(dem->data, "CreateFileW") == 0);

    printf("  [PASS] demangled_plain\n");
}

static void
test_demangled_import(void)
{
    // A C++ mangled name should be demangled.
    n00b_pe_imported_func_t f = {0};
    n00b_string_t *name = n00b_string_from_cstr("_ZN3foo3barEv");

    f.name = name;

    n00b_string_t *dem = n00b_pe_imported_func_demangled(&f);
    assert(dem != nullptr);
    // Should contain "foo" and "bar"
    assert(strstr(dem->data, "foo") != nullptr);
    assert(strstr(dem->data, "bar") != nullptr);

    printf("  [PASS] demangled_import\n");
}

static void
test_has_queries(void)
{
    // Test convenience has_* queries on minimal PE (most should be false).
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_rich_header(bin));
    assert(!n00b_pe_has_delay_imports(bin));
    assert(!n00b_pe_has_exceptions(bin));
    assert(!n00b_pe_has_symbols(bin));
    assert(!n00b_pe_has_bound_imports(bin));
    assert(!n00b_pe_has_configuration(bin));
    assert(!n00b_pe_has_tls(bin));
    assert(!n00b_pe_has_debug(bin));
    assert(!n00b_pe_has_resources(bin));
    assert(!n00b_pe_has_imports(bin));
    assert(!n00b_pe_has_exports(bin));

    printf("  [PASS] has_queries\n");
}

// ============================================================================
// Phase 9h: MD5, imphash, authenticode tests
// ============================================================================

static void
test_md5_basic(void)
{
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    uint8_t digest[16];

    n00b_md5(nullptr, 0, digest);

    // Actually pass empty string
    n00b_md5((const uint8_t *)"", 0, digest);
    assert(digest[0]  == 0xd4);
    assert(digest[1]  == 0x1d);
    assert(digest[15] == 0x7e);

    // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    n00b_md5((const uint8_t *)"abc", 3, digest);
    assert(digest[0] == 0x90);
    assert(digest[1] == 0x01);
    assert(digest[2] == 0x50);

    printf("  [PASS] md5_basic\n");
}

static void
test_imphash_known(void)
{
    // Build PE with known imports to get a deterministic imphash.
    n00b_buffer_t *buf = make_pe_with_imports();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_string_t *hash = n00b_pe_imphash(bin);
    assert(hash != nullptr);
    assert(strlen(hash->data) == 32);  // 32 hex chars

    // Verify it's a valid hex string.
    for (int i = 0; i < 32; i++) {
        char c = hash->data[i];

        assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    printf("  [PASS] imphash_known\n");
}

static void
test_imphash_empty(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // No imports → null imphash.
    assert(n00b_pe_imphash(bin) == nullptr);

    printf("  [PASS] imphash_empty\n");
}

static void
test_no_certificates(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(!n00b_pe_has_signatures(bin));
    assert(bin->num_certificates == 0);

    printf("  [PASS] no_certificates\n");
}

static void
test_authentihash(void)
{
    // Compute authentihash on minimal PE — should produce a 32-byte SHA-256.
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_buffer_t *hash = n00b_pe_authentihash_sha256(bin);
    assert(hash != nullptr);
    assert((uint32_t)n00b_buffer_len(hash) == 32);

    // Verify it's not all zeros.
    const uint8_t *h = (const uint8_t *)hash->data;
    bool all_zero = true;

    for (int i = 0; i < 32; i++) {
        if (h[i] != 0) {
            all_zero = false;
            break;
        }
    }

    assert(!all_zero);

    printf("  [PASS] authentihash\n");
}

// ============================================================================
// Phase 9i: Resource interpretation — factories and tests
// ============================================================================

/// Build a PE with RT_VERSION, RT_MANIFEST, RT_GROUP_ICON, and RT_ICON resources.
/// Layout:
///   0x000-0x1FF: headers (DOS, PE sig, file hdr, opt hdr, 2 section hdrs)
///   0x200-0x3FF: .text section
///   0x400-0xFFF: .rsrc section (resource directory + data)
static n00b_buffer_t *
make_pe_with_rich_resources(void)
{
    size_t total = 0x1000;
    n00b_buffer_t *buf = n00b_buffer_new(total);

    memset(buf->data, 0, total);
    buf->byte_len = total;
    uint8_t *p = (uint8_t *)buf->data;

    put16(p + 0, N00B_PE_MAGIC_MZ);
    put32(p + 0x3C, 0x80);
    put32(p + 0x80, N00B_PE_SIGNATURE);

    uint8_t *fh = p + 0x84;
    put16(fh + 0, N00B_PE_MACHINE_AMD64);
    put16(fh + 2, 2);            // 2 sections
    put16(fh + 16, N00B_PE_OPTIONAL_HEADER64_SIZE);
    put16(fh + 18, N00B_PE_CHAR_EXECUTABLE_IMAGE | N00B_PE_CHAR_LARGE_ADDRESS);

    uint8_t *oh = p + 0x98;
    put16(oh + 0, N00B_PE_OPT_MAGIC_PE32P);
    put64(oh + 24, 0x0000000140000000ULL);
    put32(oh + 32, 0x1000);   // section alignment
    put32(oh + 36, 0x200);    // file alignment
    put32(oh + 56, 0x4000);   // image size
    put32(oh + 60, 0x200);    // header size
    put32(oh + 108, N00B_PE_NUM_DATA_DIRS);

    uint8_t *dd = oh + 112;
    put32(dd + N00B_PE_DD_RESOURCE * 8, 0x2000);     // Resource RVA
    put32(dd + N00B_PE_DD_RESOURCE * 8 + 4, 0xC00);  // Resource size

    // .text
    uint8_t *sh0 = p + 0x188;
    memcpy(sh0, ".text\0\0\0", 8);
    put32(sh0 + 8, 0x200);
    put32(sh0 + 12, 0x1000);
    put32(sh0 + 16, 0x200);
    put32(sh0 + 20, 0x200);
    put32(sh0 + 36, N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE | N00B_PE_SCN_MEM_READ);

    // .rsrc: file offset 0x400, RVA 0x2000, size 0xC00
    uint8_t *sh1 = p + 0x188 + 40;
    memcpy(sh1, ".rsrc\0\0\0", 8);
    put32(sh1 + 8, 0xC00);
    put32(sh1 + 12, 0x2000);
    put32(sh1 + 16, 0xC00);
    put32(sh1 + 20, 0x400);
    put32(sh1 + 36, N00B_PE_SCN_CNT_INITIALIZED | N00B_PE_SCN_MEM_READ);

    // Resource directory at file offset 0x400
    uint8_t *rsrc = p + 0x400;

    // ---- Root directory (level 0): 4 type entries ----
    // RT_ICON(3), RT_GROUP_ICON(14), RT_VERSION(16), RT_MANIFEST(24)
    put16(rsrc + 12, 0);  // num named
    put16(rsrc + 14, 4);  // num ID

    // Entries at rsrc+16, each 8 bytes
    // Entry 0: RT_ICON(3) → subdir at 0x50
    put32(rsrc + 16, N00B_PE_RT_ICON);
    put32(rsrc + 20, 0x80000050);
    // Entry 1: RT_GROUP_ICON(14) → subdir at 0xA0
    put32(rsrc + 24, N00B_PE_RT_GROUP_ICON);
    put32(rsrc + 28, 0x800000A0);
    // Entry 2: RT_VERSION(16) → subdir at 0xF0
    put32(rsrc + 32, N00B_PE_RT_VERSION);
    put32(rsrc + 36, 0x800000F0);
    // Entry 3: RT_MANIFEST(24) → subdir at 0x140
    put32(rsrc + 40, N00B_PE_RT_MANIFEST);
    put32(rsrc + 44, 0x80000140);

    // ---- RT_ICON subdir at 0x50: 2 icon resources (ID 1, 2) ----
    uint8_t *icon_dir = rsrc + 0x50;
    put16(icon_dir + 12, 0);
    put16(icon_dir + 14, 2);
    // Icon ID=1 → subdir at 0x70
    put32(icon_dir + 16, 1);
    put32(icon_dir + 20, 0x80000070);
    // Icon ID=2 → subdir at 0x88
    put32(icon_dir + 24, 2);
    put32(icon_dir + 28, 0x80000088);

    // Icon 1 lang dir at 0x70: 1 entry
    uint8_t *icon1_lang = rsrc + 0x70;
    put16(icon1_lang + 12, 0);
    put16(icon1_lang + 14, 1);
    put32(icon1_lang + 16, 1033);      // lang
    put32(icon1_lang + 20, 0x0190);    // data entry at 0x190

    // Icon 2 lang dir at 0x88: 1 entry
    uint8_t *icon2_lang = rsrc + 0x88;
    put16(icon2_lang + 12, 0);
    put16(icon2_lang + 14, 1);
    put32(icon2_lang + 16, 1033);
    put32(icon2_lang + 20, 0x01A0);    // data entry at 0x1A0

    // ---- RT_GROUP_ICON subdir at 0xA0: 1 entry (ID=1) ----
    uint8_t *grp_dir = rsrc + 0xA0;
    put16(grp_dir + 12, 0);
    put16(grp_dir + 14, 1);
    put32(grp_dir + 16, 1);
    put32(grp_dir + 20, 0x800000C0);  // subdir at 0xC0

    // GRP lang dir at 0xC0: 1 entry
    uint8_t *grp_lang = rsrc + 0xC0;
    put16(grp_lang + 12, 0);
    put16(grp_lang + 14, 1);
    put32(grp_lang + 16, 1033);
    put32(grp_lang + 20, 0x01B0);     // data entry at 0x1B0

    // ---- RT_VERSION subdir at 0xF0: 1 entry (ID=1) ----
    uint8_t *ver_dir = rsrc + 0xF0;
    put16(ver_dir + 12, 0);
    put16(ver_dir + 14, 1);
    put32(ver_dir + 16, 1);
    put32(ver_dir + 20, 0x80000110);   // subdir at 0x110

    // Version lang dir at 0x110: 1 entry
    uint8_t *ver_lang = rsrc + 0x110;
    put16(ver_lang + 12, 0);
    put16(ver_lang + 14, 1);
    put32(ver_lang + 16, 1033);
    put32(ver_lang + 20, 0x01C0);     // data entry at 0x1C0

    // ---- RT_MANIFEST subdir at 0x140: 1 entry (ID=1) ----
    uint8_t *man_dir = rsrc + 0x140;
    put16(man_dir + 12, 0);
    put16(man_dir + 14, 1);
    put32(man_dir + 16, 1);
    put32(man_dir + 20, 0x80000160);   // subdir at 0x160

    // Manifest lang dir at 0x160: 1 entry
    uint8_t *man_lang = rsrc + 0x160;
    put16(man_lang + 12, 0);
    put16(man_lang + 14, 1);
    put32(man_lang + 16, 1033);
    put32(man_lang + 20, 0x01D0);     // data entry at 0x1D0

    // ================================================================
    // Data entries (16 bytes each)
    // ================================================================

    // Data for actual resource content starts at rsrc+0x300 (file 0x700)

    // Icon 1 data entry at 0x190
    uint8_t *de_icon1 = rsrc + 0x190;
    put32(de_icon1 + 0, 0x2300);  // RVA → rsrc+0x300 → file 0x700
    put32(de_icon1 + 4, 16);     // size
    put32(de_icon1 + 8, 0);      // codepage

    // Icon 2 data entry at 0x1A0
    uint8_t *de_icon2 = rsrc + 0x1A0;
    put32(de_icon2 + 0, 0x2310);  // RVA → rsrc+0x310 → file 0x710
    put32(de_icon2 + 4, 16);
    put32(de_icon2 + 8, 0);

    // GRP_ICON data entry at 0x1B0
    uint8_t *de_grp = rsrc + 0x1B0;
    put32(de_grp + 0, 0x2320);   // RVA → rsrc+0x320 → file 0x720
    put32(de_grp + 4, 34);       // size: 6 (header) + 2*14 (2 entries)
    put32(de_grp + 8, 0);

    // VERSION data entry at 0x1C0
    uint8_t *de_ver = rsrc + 0x1C0;
    put32(de_ver + 0, 0x2400);   // RVA → rsrc+0x400 → file 0x800
    put32(de_ver + 4, 0x200);    // size (enough for version struct)
    put32(de_ver + 8, 0);

    // MANIFEST data entry at 0x1D0
    uint8_t *de_man = rsrc + 0x1D0;
    put32(de_man + 0, 0x2600);   // RVA → rsrc+0x600 → file 0xA00
    put32(de_man + 4, 50);       // size
    put32(de_man + 8, 0);

    // ================================================================
    // Actual resource data
    // ================================================================

    // Icon 1 data at file 0x700 (16 bytes of pattern)
    for (int i = 0; i < 16; i++) {
        p[0x700 + i] = (uint8_t)(0xAA ^ i);
    }

    // Icon 2 data at file 0x710 (16 bytes of pattern)
    for (int i = 0; i < 16; i++) {
        p[0x710 + i] = (uint8_t)(0xBB ^ i);
    }

    // GRPICONDIR at file 0x720
    // Header: idReserved=0, idType=1, idCount=2
    uint8_t *grp_data = p + 0x720;
    put16(grp_data + 0, 0);    // reserved
    put16(grp_data + 2, 1);    // type = icon
    put16(grp_data + 4, 2);    // count = 2

    // Entry 0: 16x16, 0 colors, planes=1, bits=32, bytes=16, nID=1
    grp_data[6]  = 16;  // width
    grp_data[7]  = 16;  // height
    grp_data[8]  = 0;   // color count
    grp_data[9]  = 0;   // reserved
    put16(grp_data + 10, 1);   // planes
    put16(grp_data + 12, 32);  // bit count
    put32(grp_data + 14, 16);  // bytes in resource
    put16(grp_data + 18, 1);   // nID = 1

    // Entry 1: 32x32, 0 colors, planes=1, bits=32, bytes=16, nID=2
    grp_data[20] = 32;  // width
    grp_data[21] = 32;  // height
    grp_data[22] = 0;
    grp_data[23] = 0;
    put16(grp_data + 24, 1);
    put16(grp_data + 26, 32);
    put32(grp_data + 28, 16);
    put16(grp_data + 32, 2);  // nID = 2

    // VS_VERSIONINFO at file 0x800
    uint8_t *ver = p + 0x800;
    size_t   vpos = 0;

    // VS_VERSIONINFO header
    // We'll write a total length of ~280 bytes
    put16(ver + 0, 280);     // wLength (will adjust)
    put16(ver + 2, 52);      // wValueLength (size of VS_FIXEDFILEINFO)
    put16(ver + 4, 0);       // wType = binary
    vpos = 6;

    // Key: "VS_VERSION_INFO" in UTF-16LE (15 chars + null = 32 bytes)
    const char *vskey = "VS_VERSION_INFO";
    for (int i = 0; vskey[i]; i++) {
        put16(ver + vpos, (uint16_t)vskey[i]);
        vpos += 2;
    }
    put16(ver + vpos, 0); // null terminator
    vpos += 2;

    // DWORD-align
    vpos = (vpos + 3) & ~(size_t)3;

    // VS_FIXEDFILEINFO (52 bytes)
    put32(ver + vpos, 0xFEEF04BD);       // signature
    put32(ver + vpos + 4, 0x00010000);    // struct version
    put32(ver + vpos + 8, 0x00020003);    // file version MS (2.3)
    put32(ver + vpos + 12, 0x00040005);   // file version LS (4.5)
    put32(ver + vpos + 16, 0x00060007);   // product version MS (6.7)
    put32(ver + vpos + 20, 0x00080009);   // product version LS (8.9)
    put32(ver + vpos + 24, 0x3F);         // file flags mask
    put32(ver + vpos + 28, 0x01);         // file flags (debug)
    put32(ver + vpos + 32, 0x00040004);   // file OS (VOS_NT_WINDOWS32)
    put32(ver + vpos + 36, 0x01);         // file type (VFT_APP)
    put32(ver + vpos + 40, 0);            // file subtype
    put32(ver + vpos + 44, 0);            // file date MS
    put32(ver + vpos + 48, 0);            // file date LS
    vpos += 52;

    // DWORD-align
    vpos = (vpos + 3) & ~(size_t)3;

    // StringFileInfo
    size_t sfi_start = vpos;
    put16(ver + vpos + 2, 0);  // wValueLength
    put16(ver + vpos + 4, 1);  // wType = text
    vpos += 6;

    // Key: "StringFileInfo" in UTF-16LE
    const char *sfi_key = "StringFileInfo";
    for (int i = 0; sfi_key[i]; i++) {
        put16(ver + vpos, (uint16_t)sfi_key[i]);
        vpos += 2;
    }
    put16(ver + vpos, 0);
    vpos += 2;
    vpos = (vpos + 3) & ~(size_t)3;

    // StringTable
    size_t st_start = vpos;
    put16(ver + vpos + 2, 0);
    put16(ver + vpos + 4, 1);
    vpos += 6;

    // StringTable key: "040904b0" in UTF-16LE
    const char *st_key = "040904b0";
    for (int i = 0; st_key[i]; i++) {
        put16(ver + vpos, (uint16_t)st_key[i]);
        vpos += 2;
    }
    put16(ver + vpos, 0);
    vpos += 2;
    vpos = (vpos + 3) & ~(size_t)3;

    // String entry: "FileVersion" = "2.3.4.5"
    size_t s_start = vpos;
    vpos += 6; // skip header for now

    const char *s_key = "FileVersion";
    for (int i = 0; s_key[i]; i++) {
        put16(ver + vpos, (uint16_t)s_key[i]);
        vpos += 2;
    }
    put16(ver + vpos, 0);
    vpos += 2;
    vpos = (vpos + 3) & ~(size_t)3;

    const char *s_val = "2.3.4.5";
    for (int i = 0; s_val[i]; i++) {
        put16(ver + vpos, (uint16_t)s_val[i]);
        vpos += 2;
    }
    put16(ver + vpos, 0);
    vpos += 2;
    vpos = (vpos + 3) & ~(size_t)3;

    uint16_t val_chars = (uint16_t)(strlen(s_val) + 1);
    put16(ver + s_start, (uint16_t)(vpos - s_start));  // wLength
    put16(ver + s_start + 2, val_chars);               // wValueLength (in chars)
    put16(ver + s_start + 4, 1);                       // wType = text

    // Fix StringTable length
    put16(ver + st_start, (uint16_t)(vpos - st_start));

    // Fix StringFileInfo length
    put16(ver + sfi_start, (uint16_t)(vpos - sfi_start));

    // Fix VS_VERSIONINFO total length
    put16(ver + 0, (uint16_t)vpos);

    // Manifest at file 0xA00
    const char *manifest = "<?xml version=\"1.0\"?>TestManifest";
    memcpy(p + 0xA00, manifest, strlen(manifest));

    return buf;
}

static void
test_version_info(void)
{
    n00b_buffer_t *buf    = make_pe_with_rich_resources();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_pe_version_info_t *vi = n00b_pe_get_version_info(bin);
    assert(vi != nullptr);

    assert(vi->file_version_ms    == 0x00020003);
    assert(vi->file_version_ls    == 0x00040005);
    assert(vi->product_version_ms == 0x00060007);
    assert(vi->product_version_ls == 0x00080009);
    assert(vi->file_flags_mask    == 0x3F);
    assert(vi->file_flags         == 0x01);
    assert(vi->file_os            == 0x00040004);
    assert(vi->file_type          == 0x01);

    // Check string table
    assert(vi->num_strings >= 1);
    assert(strcmp(vi->strings[0].key->data, "FileVersion") == 0);
    assert(strcmp(vi->strings[0].value->data, "2.3.4.5") == 0);

    printf("  [PASS] version_info\n");
}

static void
test_manifest(void)
{
    n00b_buffer_t *buf    = make_pe_with_rich_resources();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    n00b_string_t *manifest = n00b_pe_get_manifest(bin);
    assert(manifest != nullptr);
    assert(strncmp(manifest->data, "<?xml", 5) == 0);
    assert(strstr(manifest->data, "TestManifest") != nullptr);

    printf("  [PASS] manifest\n");
}

static void
test_no_version_info(void)
{
    // Minimal PE has no resources at all.
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_get_version_info(bin) == nullptr);
    assert(n00b_pe_get_manifest(bin) == nullptr);
    assert(n00b_pe_icon_count(bin) == 0);

    printf("  [PASS] no_version_info\n");
}

static void
test_icon_count(void)
{
    n00b_buffer_t *buf    = make_pe_with_rich_resources();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    assert(n00b_pe_icon_count(bin) == 2);

    // Get icon 0
    n00b_buffer_t *icon0 = n00b_pe_get_icon(bin, 0);
    assert(icon0 != nullptr);
    assert((uint32_t)n00b_buffer_len(icon0) == 16);

    // Verify icon data matches pattern
    const uint8_t *id = (const uint8_t *)icon0->data;
    assert(id[0] == (uint8_t)(0xAA ^ 0));
    assert(id[1] == (uint8_t)(0xAA ^ 1));

    // Get icon 1
    n00b_buffer_t *icon1 = n00b_pe_get_icon(bin, 1);
    assert(icon1 != nullptr);
    const uint8_t *id1 = (const uint8_t *)icon1->data;
    assert(id1[0] == (uint8_t)(0xBB ^ 0));

    // Out of range
    assert(n00b_pe_get_icon(bin, 2) == nullptr);

    printf("  [PASS] icon_count\n");
}

// ============================================================================
// Phase 9k: Relocation enhancements
// ============================================================================

static void
test_reloc_blocks(void)
{
    // Build a PE with relocations on multiple pages via the builder.
    n00b_pe_binary_t *bin = n00b_pe_binary_new(N00B_PE_MACHINE_AMD64,
                                                N00B_PE_SUBSYSTEM_WINDOWS_CUI);
    bin->entry_point = 0x1000;

    n00b_pe_section_t *text = n00b_pe_add_section(bin, ".text",
                                  N00B_PE_SCN_CNT_CODE | N00B_PE_SCN_MEM_EXECUTE
                                  | N00B_PE_SCN_MEM_READ);
    uint8_t code[] = { 0xCC };
    text->content  = n00b_buffer_new(1);
    memcpy(text->content->data, code, 1);
    text->content->byte_len = 1;
    text->virtual_size = 0x3000;

    // Page 0x1000: 2 relocations
    n00b_pe_add_relocation(bin, 0x1010, N00B_PE_REL_BASED_DIR64);
    n00b_pe_add_relocation(bin, 0x1020, N00B_PE_REL_BASED_DIR64);
    // Page 0x2000: 1 relocation
    n00b_pe_add_relocation(bin, 0x2008, N00B_PE_REL_BASED_HIGHLOW);
    // Page 0x3000: 1 relocation
    n00b_pe_add_relocation(bin, 0x3000, N00B_PE_REL_BASED_DIR64);

    // Build, parse, then test block grouping.
    auto r = n00b_pe_build(bin);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s = n00b_bstream_new(n00b_result_get(r));
    auto           r2 = n00b_pe_parse(s);

    assert(n00b_result_is_ok(r2));
    n00b_pe_binary_t *parsed = n00b_result_get(r2);

    assert(parsed->num_relocations == 4);

    uint32_t              num = 0;
    n00b_pe_reloc_block_t *blocks = n00b_pe_reloc_blocks(parsed, &num);

    assert(num == 3);  // 3 distinct pages

    assert(blocks[0].page_rva == 0x1000);
    assert(blocks[0].num_entries == 2);

    assert(blocks[1].page_rva == 0x2000);
    assert(blocks[1].num_entries == 1);
    assert(blocks[1].entries[0].type == N00B_PE_REL_BASED_HIGHLOW);

    assert(blocks[2].page_rva == 0x3000);
    assert(blocks[2].num_entries == 1);

    printf("  [PASS] reloc_blocks\n");
}

static void
test_reloc_type_constants(void)
{
    // Verify type constants have expected values.
    assert(N00B_PE_REL_BASED_ABSOLUTE == 0);
    assert(N00B_PE_REL_BASED_HIGH == 1);
    assert(N00B_PE_REL_BASED_LOW == 2);
    assert(N00B_PE_REL_BASED_HIGHLOW == 3);
    assert(N00B_PE_REL_BASED_HIGHADJ == 4);
    assert(N00B_PE_REL_BASED_ARM_MOV32 == 5);
    assert(N00B_PE_REL_BASED_THUMB_MOV32 == 7);
    assert(N00B_PE_REL_BASED_RISCV_LOW12S == 8);
    assert(N00B_PE_REL_BASED_DIR64 == 10);

    // ARM and RISC-V share values (architecture-dependent interpretation)
    assert(N00B_PE_REL_BASED_RISCV_HIGH20 == N00B_PE_REL_BASED_ARM_MOV32);
    assert(N00B_PE_REL_BASED_RISCV_LOW12I == N00B_PE_REL_BASED_THUMB_MOV32);

    printf("  [PASS] reloc_type_constants\n");
}

// ============================================================================
// Test: section_at_rva
// ============================================================================

static void
test_section_at_rva(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // .text is at RVA 0x1000, .data at RVA 0x2000
    n00b_pe_section_t *s1 = n00b_pe_section_at_rva(bin, 0x1000);
    assert(s1 != nullptr);
    assert(strcmp(s1->name->data, ".text") == 0);

    n00b_pe_section_t *s2 = n00b_pe_section_at_rva(bin, 0x2000);
    assert(s2 != nullptr);
    assert(strcmp(s2->name->data, ".data") == 0);

    // An RVA within .text (0x1000..0x11FF)
    n00b_pe_section_t *s3 = n00b_pe_section_at_rva(bin, 0x1100);
    assert(s3 != nullptr);
    assert(strcmp(s3->name->data, ".text") == 0);

    // RVA outside any section
    n00b_pe_section_t *s4 = n00b_pe_section_at_rva(bin, 0x9000);
    assert(s4 == nullptr);

    printf("  [PASS] section_at_rva\n");
}

// ============================================================================
// Test: exported_func_demangled (plain names stay plain)
// ============================================================================

static void
test_exported_func_demangled(void)
{
    n00b_buffer_t *buf    = make_pe_with_exports();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);
    assert(bin->export_info != nullptr);

    // "Add" is a plain name — demangled should return same or non-null
    n00b_pe_exported_func_t *f = n00b_pe_export_by_name(bin, "Add");
    assert(f != nullptr);

    n00b_string_t *dem = n00b_pe_exported_func_demangled(f);
    // Plain names should either return the name itself or nullptr
    // (implementation-dependent). Just ensure no crash and if non-null,
    // it should contain "Add".
    if (dem != nullptr) {
        const char *cs = dem->data;
        assert(strstr(cs, "Add") != nullptr);
    }

    printf("  [PASS] exported_func_demangled\n");
}

// ============================================================================
// Test: add imported func by ordinal (builder)
// ============================================================================

static void
test_import_by_ordinal_builder(void)
{
    n00b_buffer_t *buf    = make_minimal_pe64();
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto           r      = n00b_pe_parse(stream);

    assert(n00b_result_is_ok(r));
    n00b_pe_binary_t *bin = n00b_result_get(r);

    // Add an import DLL with an ordinal-only import
    n00b_pe_import_t *imp = n00b_pe_add_import(bin, "ordtest.dll");
    assert(imp != nullptr);

    n00b_pe_imported_func_t *func = n00b_pe_add_imported_func_ordinal(imp, 42);
    assert(func != nullptr);
    assert(func->is_ordinal);
    assert(func->ordinal == 42);
    assert(func->name == nullptr);
    assert(imp->num_functions == 1);

    // Add a second ordinal import
    n00b_pe_imported_func_t *func2 = n00b_pe_add_imported_func_ordinal(imp, 99);
    assert(func2 != nullptr);
    assert(func2->ordinal == 99);
    assert(imp->num_functions == 2);

    printf("  [PASS] import_by_ordinal_builder\n");
}

// ============================================================================
// Test: MD5 streaming (init/update/finalize)
// ============================================================================

static void
test_md5_streaming(void)
{
    // Known MD5: md5("") = d41d8cd98f00b204e9800998ecf8427e
    n00b_md5_ctx_t ctx;
    uint8_t digest[16];

    n00b_md5_init(&ctx);
    n00b_md5_finalize(&ctx, digest);

    uint8_t expected_empty[16] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    assert(memcmp(digest, expected_empty, 16) == 0);

    // Streaming: md5("abc") = 900150983cd24fb0d6963f7d28e17f72
    n00b_md5_init(&ctx);
    n00b_md5_update(&ctx, "a", 1);
    n00b_md5_update(&ctx, "bc", 2);
    n00b_md5_finalize(&ctx, digest);

    uint8_t expected_abc[16] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    assert(memcmp(digest, expected_abc, 16) == 0);

    // Compare streaming vs one-shot
    uint8_t oneshot[16];
    n00b_md5((const uint8_t *)"abc", 3, oneshot);
    assert(memcmp(digest, oneshot, 16) == 0);

    printf("  [PASS] md5_streaming\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running PE parser + query tests...\n");

    test_detect_pe();
    test_parse_headers();
    test_parse_sections();
    test_section_content();
    test_section_by_name();
    test_has_section();
    test_is_dll();
    test_bad_magic();
    test_bad_pe_sig();
    test_pe32_rejected();
    test_abstract_pe();
    test_parse_imports();
    test_parse_ordinal_import();
    test_import_by_name();
    test_imported_func_by_name();
    test_parse_exports();
    test_export_by_name();
    test_export_by_ordinal();
    test_forwarded_export();
    test_parse_relocs();
    test_parse_reloc_types();
    test_parse_debug_codeview();
    test_parse_tls_callbacks();
    test_pdb_path_query();
    test_no_debug();
    test_no_tls();
    test_parse_resources();
    test_resource_by_type();
    test_no_resources();

    // Phase 9b tests
    test_rva_to_offset();
    test_offset_to_rva();
    test_va_conversions();
    test_content_at_rva();
    test_content_at_va();

    // Phase 9a tests
    test_dos_header_fields();
    test_optional_header_full();
    test_optional_header_roundtrip();
    test_import_timestamp_forwarder();
    test_export_dir_fields();
    test_export_forward_split();
    test_tls_characteristics();
    test_resource_named_entry();
    test_dos_header_roundtrip();

    // Phase 9c tests
    test_rich_header_parse();
    test_rich_header_key();
    test_no_rich_header();

    // Phase 9d tests
    test_delay_import_parse();
    test_delay_import_by_name();
    test_no_delay_imports();
    test_exception_parse();
    test_exception_at_rva();
    test_no_exceptions();
    test_coff_symbols_parse();
    test_no_symbols();
    test_bound_import_parse();
    test_no_bound_imports();

    // Phase 9e tests
    test_debug_codeview_guid();
    test_debug_pogo();
    test_debug_repro();
    test_debug_by_type_query();

    // Phase 9f tests
    test_load_config_basic();
    test_load_config_cfg();
    test_has_guard_cf();

    // Phase 9g tests
    test_compute_checksum();
    test_verify_checksum();
    test_entropy_zeros();
    test_entropy_random();
    test_demangled_plain();
    test_demangled_import();
    test_has_queries();

    // Phase 9h tests
    test_md5_basic();
    test_imphash_known();
    test_imphash_empty();
    test_no_certificates();
    test_authentihash();

    // Phase 9i tests
    test_version_info();
    test_manifest();
    test_no_version_info();
    test_icon_count();

    // Phase 9k tests
    test_reloc_blocks();
    test_reloc_type_constants();

    // Phase 10 gap-fill tests
    test_section_at_rva();
    test_exported_func_demangled();
    test_import_by_ordinal_builder();
    test_md5_streaming();

    printf("All PE parser tests passed.\n");

    n00b_shutdown();

    return 0;
}
