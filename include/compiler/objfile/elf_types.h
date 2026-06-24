/**
 * @file n00b_elf_types.h
 * @brief Raw on-disk ELF64 packed structures and ELF constants.
 *
 * All structures use `#pragma pack(push, 1)` to match on-disk layout.
 * Only 64-bit variants are provided.
 */
#pragma once

#include <stdint.h>

// ============================================================================
// ELF identification indices (e_ident[])
// ============================================================================

#define EI_MAG0        0
#define EI_MAG1        1
#define EI_MAG2        2
#define EI_MAG3        3
#define EI_CLASS       4
#define EI_DATA        5
#define EI_VERSION     6
#define EI_OSABI       7
#define EI_ABIVERSION  8
#define EI_PAD         9
#define EI_NIDENT      16

// EI_CLASS values
#define ELFCLASSNONE   0
#define ELFCLASS32     1
#define ELFCLASS64     2

// EI_DATA values
#define ELFDATANONE    0
#define ELFDATA2LSB    1
#define ELFDATA2MSB    2

// EI_VERSION values
#define EV_NONE        0
#define EV_CURRENT     1

// EI_OSABI values
#define ELFOSABI_NONE       0
#define ELFOSABI_HPUX       1
#define ELFOSABI_NETBSD     2
#define ELFOSABI_GNU        3
#define ELFOSABI_LINUX      3
#define ELFOSABI_SOLARIS    6
#define ELFOSABI_AIX        7
#define ELFOSABI_IRIX       8
#define ELFOSABI_FREEBSD    9
#define ELFOSABI_TRU64      10
#define ELFOSABI_MODESTO    11
#define ELFOSABI_OPENBSD    12
#define ELFOSABI_OPENVMS    13
#define ELFOSABI_NSK        14
#define ELFOSABI_AROS       15
#define ELFOSABI_FENIXOS    16
#define ELFOSABI_ARM        97
#define ELFOSABI_STANDALONE 255

// ============================================================================
// Object file types (e_type)
// ============================================================================

#define ET_NONE    0
#define ET_REL     1
#define ET_EXEC    2
#define ET_DYN     3
#define ET_CORE    4
#define ET_LOOS    0xFE00
#define ET_HIOS    0xFEFF
#define ET_LOPROC  0xFF00
#define ET_HIPROC  0xFFFF

// ============================================================================
// Machine types (e_machine) — common subset
// ============================================================================

#define EM_NONE          0
#define EM_SPARC         2
#define EM_386           3
#define EM_MIPS          8
#define EM_PPC           20
#define EM_PPC64         21
#define EM_S390          22
#define EM_ARM           40
#define EM_SPARCV9       43
#define EM_IA_64         50
#define EM_X86_64        62
#define EM_AARCH64       183
#define EM_RISCV         243
#define EM_LOONGARCH     258

// ============================================================================
// Section header types (sh_type)
// ============================================================================

#define SHT_NULL              0
#define SHT_PROGBITS          1
#define SHT_SYMTAB            2
#define SHT_STRTAB            3
#define SHT_RELA              4
#define SHT_HASH              5
#define SHT_DYNAMIC           6
#define SHT_NOTE              7
#define SHT_NOBITS            8
#define SHT_REL               9
#define SHT_SHLIB             10
#define SHT_DYNSYM            11
#define SHT_INIT_ARRAY        14
#define SHT_FINI_ARRAY        15
#define SHT_PREINIT_ARRAY     16
#define SHT_GROUP             17
#define SHT_SYMTAB_SHNDX      18
#define SHT_RELR              19
#define SHT_GNU_HASH          0x6FFFFFF6
#define SHT_GNU_VERDEF        0x6FFFFFFD
#define SHT_GNU_VERNEED       0x6FFFFFFE
#define SHT_GNU_VERSYM        0x6FFFFFFF
#define SHT_GNU_ATTRIBUTES    0x6FFFFFF5
#define SHT_ANDROID_REL       0x60000001
#define SHT_ANDROID_RELA      0x60000002
#define SHT_LOOS              0x60000000
#define SHT_HIOS              0x6FFFFFFF
#define SHT_LOPROC            0x70000000
#define SHT_HIPROC            0x7FFFFFFF
#define SHT_ARM_EXIDX         0x70000001
#define SHT_ARM_ATTRIBUTES    0x70000003

// ============================================================================
// Section header flags (sh_flags)
// ============================================================================

#define SHF_WRITE             0x1
#define SHF_ALLOC             0x2
#define SHF_EXECINSTR         0x4
#define SHF_MERGE             0x10
#define SHF_STRINGS           0x20
#define SHF_INFO_LINK         0x40
#define SHF_LINK_ORDER        0x80
#define SHF_OS_NONCONFORMING  0x100
#define SHF_GROUP             0x200
#define SHF_TLS               0x400

// ============================================================================
// Program header types (p_type)
// ============================================================================

#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_SHLIB        5
#define PT_PHDR         6
#define PT_TLS          7
#define PT_LOOS         0x60000000
#define PT_HIOS         0x6FFFFFFF
#define PT_GNU_EH_FRAME 0x6474E550
#define PT_GNU_STACK    0x6474E551
#define PT_GNU_RELRO    0x6474E552
#define PT_GNU_PROPERTY 0x6474E553
#define PT_LOPROC       0x70000000
#define PT_HIPROC       0x7FFFFFFF
#define PT_ARM_EXIDX    0x70000001

// ============================================================================
// Program header flags (p_flags)
// ============================================================================

#define PF_X  0x1
#define PF_W  0x2
#define PF_R  0x4

// ============================================================================
// Dynamic table tags (d_tag)
// ============================================================================

#define DT_NULL         0
#define DT_NEEDED       1
#define DT_PLTRELSZ     2
#define DT_PLTGOT       3
#define DT_HASH         4
#define DT_STRTAB       5
#define DT_SYMTAB       6
#define DT_RELA         7
#define DT_RELASZ       8
#define DT_RELAENT      9
#define DT_STRSZ        10
#define DT_SYMENT       11
#define DT_INIT         12
#define DT_FINI         13
#define DT_SONAME       14
#define DT_RPATH        15
#define DT_SYMBOLIC     16
#define DT_REL          17
#define DT_RELSZ        18
#define DT_RELENT       19
#define DT_PLTREL       20
#define DT_DEBUG        21
#define DT_TEXTREL      22
#define DT_JMPREL       23
#define DT_BIND_NOW     24
#define DT_INIT_ARRAY   25
#define DT_FINI_ARRAY   26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH      29
#define DT_FLAGS        30
#define DT_PREINIT_ARRAY    32
#define DT_PREINIT_ARRAYSZ  33

#define DT_GNU_HASH     0x6FFFFEF5
#define DT_VERSYM       0x6FFFFFF0
#define DT_RELRSZ       36
#define DT_RELR         37
#define DT_RELRENT      38
#define DT_RELACOUNT    0x6FFFFFF9
#define DT_RELCOUNT     0x6FFFFFFA
#define DT_FLAGS_1      0x6FFFFFFB
#define DT_VERDEF       0x6FFFFFFC
#define DT_VERDEFNUM    0x6FFFFFFD
#define DT_VERNEED      0x6FFFFFFE
#define DT_VERNEEDNUM   0x6FFFFFFF

// DT_FLAGS_1 sub-flags
#define DF_1_NOW        0x00000001
#define DF_1_GLOBAL     0x00000002
#define DF_1_GROUP      0x00000004
#define DF_1_NODELETE   0x00000008
#define DF_1_LOADFLTR   0x00000010
#define DF_1_INITFIRST  0x00000020
#define DF_1_NOOPEN     0x00000040
#define DF_1_ORIGIN     0x00000080
#define DF_1_DIRECT     0x00000100
#define DF_1_INTERPOSE  0x00000400
#define DF_1_NODEFLIB   0x00000800
#define DF_1_NODUMP     0x00001000
#define DF_1_CONFALT    0x00002000
#define DF_1_ENDFILTEE  0x00004000
#define DF_1_DISPRELDNE 0x00008000
#define DF_1_DISPRELPND 0x00010000
#define DF_1_NODIRECT   0x00020000
#define DF_1_PIE        0x08000000

// ============================================================================
// Symbol binding (N00B_ELF64_ST_BIND)
// ============================================================================

#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2

// ============================================================================
// Symbol type (N00B_ELF64_ST_TYPE)
// ============================================================================

#define STT_NOTYPE   0
#define STT_OBJECT   1
#define STT_FUNC     2
#define STT_SECTION  3
#define STT_FILE     4
#define STT_COMMON   5
#define STT_TLS      6
#define STT_GNU_IFUNC 10

// ============================================================================
// Symbol visibility (N00B_ELF64_ST_VISIBILITY)
// ============================================================================

#define STV_DEFAULT    0
#define STV_INTERNAL   1
#define STV_HIDDEN     2
#define STV_PROTECTED  3

// ============================================================================
// Symbol info helpers
// ============================================================================

#define N00B_ELF64_ST_BIND(info)        ((info) >> 4)
#define N00B_ELF64_ST_TYPE(info)        ((info) & 0xF)
#define N00B_ELF64_ST_INFO(bind, type)  (((bind) << 4) | ((type) & 0xF))
#define N00B_ELF64_ST_VISIBILITY(other) ((other) & 0x3)

// ============================================================================
// Relocation helpers
// ============================================================================

#define N00B_ELF64_R_SYM(info)          ((info) >> 32)
#define N00B_ELF64_R_TYPE(info)         ((uint32_t)(info))
#define N00B_ELF64_R_INFO(sym, type)    (((uint64_t)(sym) << 32) | (uint32_t)(type))

// ============================================================================
// x86_64 relocation types (common subset)
// ============================================================================

#define R_X86_64_NONE             0
#define R_X86_64_64               1
#define R_X86_64_PC32             2
#define R_X86_64_GOT32            3
#define R_X86_64_PLT32            4
#define R_X86_64_COPY             5
#define R_X86_64_GLOB_DAT         6
#define R_X86_64_JUMP_SLOT        7
#define R_X86_64_RELATIVE         8
#define R_X86_64_GOTPCREL         9
#define R_X86_64_32               10
#define R_X86_64_32S              11
#define R_X86_64_16               12
#define R_X86_64_PC16             13
#define R_X86_64_8                14
#define R_X86_64_PC8              15
#define R_X86_64_DTPMOD64         16
#define R_X86_64_DTPOFF64         17
#define R_X86_64_TPOFF64          18
#define R_X86_64_TLSGD            19
#define R_X86_64_TLSLD            20
#define R_X86_64_IRELATIVE        37
#define R_X86_64_GOTPCRELX        41
#define R_X86_64_REX_GOTPCRELX    42

// ============================================================================
// AArch64 relocation types (common subset)
// ============================================================================

#define R_AARCH64_NONE            0
#define R_AARCH64_ABS64           257
#define R_AARCH64_ABS32           258
#define R_AARCH64_ABS16           259
#define R_AARCH64_PREL64          260
#define R_AARCH64_PREL32          261
#define R_AARCH64_PREL16          262
#define R_AARCH64_ADR_PREL_PG_HI21     275
#define R_AARCH64_ADD_ABS_LO12_NC      277
#define R_AARCH64_LDST8_ABS_LO12_NC    278
#define R_AARCH64_JUMP26          282
#define R_AARCH64_CALL26          283
#define R_AARCH64_LDST16_ABS_LO12_NC   284
#define R_AARCH64_LDST32_ABS_LO12_NC   285
#define R_AARCH64_LDST64_ABS_LO12_NC   286
#define R_AARCH64_LDST128_ABS_LO12_NC  299
#define R_AARCH64_ADR_GOT_PAGE         311
#define R_AARCH64_LD64_GOT_LO12_NC     312
#define R_AARCH64_COPY            1024
#define R_AARCH64_GLOB_DAT        1025
#define R_AARCH64_JUMP_SLOT       1026
#define R_AARCH64_RELATIVE        1027
#define R_AARCH64_TLS_DTPMOD      1028
#define R_AARCH64_TLS_DTPREL      1029
#define R_AARCH64_TLS_TPREL       1030
#define R_AARCH64_TLSDESC         1031
#define R_AARCH64_IRELATIVE       1032

// ============================================================================
// Special section indices
// ============================================================================

#define SHN_UNDEF     0
#define SHN_LOPROC    0xFF00
#define SHN_HIPROC    0xFF1F
#define SHN_LOOS      0xFF20
#define SHN_HIOS      0xFF3F
#define SHN_ABS       0xFFF1
#define SHN_COMMON    0xFFF2
#define SHN_XINDEX    0xFFFF

// ============================================================================
// Note types
// ============================================================================

#define NT_GNU_ABI_TAG       1
#define NT_GNU_HWCAP         2
#define NT_GNU_BUILD_ID      3
#define NT_GNU_GOLD_VERSION  4
#define NT_GNU_PROPERTY_TYPE_0  5

// ============================================================================
// Core dump note types (name = "CORE" or "LINUX")
// ============================================================================

#define NT_PRSTATUS          1
#define NT_FPREGSET          2
#define NT_PRPSINFO          3
#define NT_TASKSTRUCT        4
#define NT_AUXV              6
#define NT_SIGINFO           0x53494749u
#define NT_FILE              0x46494c45u

// ============================================================================
// Version definition/requirement flags
// ============================================================================

#define VER_DEF_CURRENT  1
#define VER_FLG_BASE     1
#define VER_FLG_WEAK     2
#define VER_NDX_LOCAL    0
#define VER_NDX_GLOBAL   1

// ============================================================================
// Raw on-disk ELF64 structures
// ============================================================================

#pragma pack(push, 1)

/// ELF64 file header.
typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} n00b_elf64_ehdr_t;

/// ELF64 section header.
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} n00b_elf64_shdr_t;

/// ELF64 program header (segment).
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} n00b_elf64_phdr_t;

/// ELF64 symbol table entry.
typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} n00b_elf64_sym_t;

/// ELF64 relocation without addend.
typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
} n00b_elf64_rel_t;

/// ELF64 relocation with addend.
typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} n00b_elf64_rela_t;

/// ELF64 dynamic table entry.
typedef struct {
    int64_t d_tag;
    union [[n00b::raw_union]] {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
} n00b_elf64_dyn_t;

/// ELF64 note header.
typedef struct {
    uint32_t n_namesz;
    uint32_t n_descsz;
    uint32_t n_type;
} n00b_elf64_nhdr_t;

/// ELF64 version definition.
typedef struct {
    uint16_t vd_version;
    uint16_t vd_flags;
    uint16_t vd_ndx;
    uint16_t vd_cnt;
    uint32_t vd_hash;
    uint32_t vd_aux;
    uint32_t vd_next;
} n00b_elf64_verdef_t;

/// ELF64 version definition auxiliary entry.
typedef struct {
    uint32_t vda_name;
    uint32_t vda_next;
} n00b_elf64_verdaux_t;

/// ELF64 version requirement.
typedef struct {
    uint16_t vn_version;
    uint16_t vn_cnt;
    uint32_t vn_file;
    uint32_t vn_aux;
    uint32_t vn_next;
} n00b_elf64_verneed_t;

/// ELF64 version requirement auxiliary entry.
typedef struct {
    uint32_t vna_hash;
    uint16_t vna_flags;
    uint16_t vna_other;
    uint32_t vna_name;
    uint32_t vna_next;
} n00b_elf64_vernaux_t;

#pragma pack(pop)
