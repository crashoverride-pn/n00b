#!/usr/bin/env python3
"""
gen_tables.py — Download Unicode Character Database files and generate
optimized two-stage lookup tables as C source for the unicode library.

Usage:
    python3 tools/gen_tables.py [--version 16.0.0] [--cache-dir .unicode_cache]
                                [--allow-downloads] [--strict|--no-strict]
                                [--check-inputs]
"""

import argparse
import hashlib
import os
import shutil
import struct
import sys
import urllib.request
import zipfile
from collections import defaultdict
from io import BytesIO
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCK_SIZE = 256  # Stage-2 block size (codepoints per block)
MAX_CP = 0x110000  # U+0000..U+10FFFF
NUM_BLOCKS = MAX_CP // BLOCK_SIZE  # 4352 stage-1 entries

UNICODE_BASE = "https://www.unicode.org/Public/{version}/ucd"

# Files to download relative to the UCD base
UNICODE_FILES = [
    "UnicodeData.txt",
    "PropList.txt",
    "DerivedCoreProperties.txt",
    "DerivedNormalizationProps.txt",
    "Scripts.txt",
    "ScriptExtensions.txt",
    "Blocks.txt",
    "DerivedAge.txt",
    "BidiBrackets.txt",
    "BidiMirroring.txt",
    "CaseFolding.txt",
    "SpecialCasing.txt",
    "CompositionExclusions.txt",
    "auxiliary/GraphemeBreakProperty.txt",
    "auxiliary/WordBreakProperty.txt",
    "auxiliary/SentenceBreakProperty.txt",
    "LineBreak.txt",
    "EastAsianWidth.txt",
    "ArabicShaping.txt",
    "emoji/emoji-data.txt",
    "PropertyValueAliases.txt",
]

# Test data files
TEST_FILES = [
    "NormalizationTest.txt",
    "auxiliary/GraphemeBreakTest.txt",
    "auxiliary/WordBreakTest.txt",
    "auxiliary/SentenceBreakTest.txt",
    "auxiliary/LineBreakTest.txt",
    "BidiTest.txt",
    "BidiCharacterTest.txt",
]

# Additional files with special URL patterns
SPECIAL_FILES = {
    # version-specific subdirs
    "allkeys.txt":       "https://www.unicode.org/Public/UCA/{version}/allkeys.txt",
    "CollationTest.zip": "https://www.unicode.org/Public/UCA/{version}/CollationTest.zip",
    "confusables.txt":   "https://www.unicode.org/Public/security/{version}/confusables.txt",
    "IdentifierStatus.txt": "https://www.unicode.org/Public/security/{version}/IdentifierStatus.txt",
    "IdentifierType.txt":   "https://www.unicode.org/Public/security/{version}/IdentifierType.txt",
    "IdnaMappingTable.txt": "https://www.unicode.org/Public/idna/{version}/IdnaMappingTable.txt",
}

GENERATED_FILES = [
    "gen_age.c",
    "gen_bidi_brackets.c",
    "gen_bidi_class.c",
    "gen_blocks.c",
    "gen_casemap.c",
    "gen_categories.c",
    "gen_collation.c",
    "gen_combining.c",
    "gen_composition.c",
    "gen_confusables.c",
    "gen_decomposition.c",
    "gen_eaw.c",
    "gen_emoji.c",
    "gen_grapheme.c",
    "gen_identifiers.c",
    "gen_idna.c",
    "gen_joining.c",
    "gen_linebreak.c",
    "gen_names.c",
    "gen_normprops.c",
    "gen_numeric.c",
    "gen_proplist.c",
    "gen_script_extensions.c",
    "gen_scripts.c",
    "gen_sentbreak.c",
    "gen_wordbreak.c",
]

REQUIRED_CACHE_FILES = (
    [f.replace("/", "_") for f in UNICODE_FILES]
    + [f.replace("/", "_") for f in TEST_FILES]
    + list(SPECIAL_FILES.keys())
)

EXPECTED_TEST_DATA_FILES = [f.split("/")[-1] for f in TEST_FILES] + ["CollationTest.zip"]
REQUIRED_TEST_DATA_FILES = EXPECTED_TEST_DATA_FILES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fail(message):
    raise SystemExit(f"ERROR: {message}")


def require_nonempty_file(path, label):
    if not path.exists():
        fail(f"missing {label}: {path}")
    if not path.is_file():
        fail(f"{label} is not a file: {path}")
    if path.stat().st_size == 0:
        fail(f"empty {label}: {path}")


def is_nonempty_file(path):
    return path.exists() and path.is_file() and path.stat().st_size > 0


def download_file(url, dest, allow_downloads):
    """Ensure file exists locally, optionally downloading when missing."""
    if dest.exists() and not dest.is_file():
        fail(f"Unicode cache path is not a file: {dest}")
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  cached: {dest.name}")
        return True

    if not allow_downloads:
        return False

    print(f"  downloading: {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (unicode-gen-tables/1.0)"
        })
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
        if not data:
            print(f"  WARNING: downloaded empty Unicode data file: {url}")
            return False
        with open(tmp, "wb") as f:
            f.write(data)
        tmp.replace(dest)
        return True
    except Exception as e:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        print(f"  WARNING: failed to download {url}: {e}")
        return False


def copy_cached_file(src, dest):
    """Populate generated test data from the required cache."""
    if dest.exists() and not dest.is_file():
        fail(f"Unicode test data path is not a file: {dest}")
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  cached: {dest.name}")
        return

    require_nonempty_file(src, "Unicode cache file")
    print(f"  copying: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.copyfile(src, tmp)
    tmp.replace(dest)


def validate_cache_inputs(cache_dir):
    for name in REQUIRED_CACHE_FILES:
        require_nonempty_file(cache_dir / name, "Unicode cache file")

    if not zipfile.is_zipfile(cache_dir / "CollationTest.zip"):
        fail(f"invalid Unicode collation zip: {cache_dir / 'CollationTest.zip'}")


def validate_test_data_inputs(test_data_dir):
    for name in REQUIRED_TEST_DATA_FILES:
        require_nonempty_file(test_data_dir / name, "Unicode test data file")

    if not zipfile.is_zipfile(test_data_dir / "CollationTest.zip"):
        fail(f"invalid Unicode collation zip: {test_data_dir / 'CollationTest.zip'}")


def validate_inputs(cache_dir, test_data_dir):
    validate_cache_inputs(cache_dir)
    validate_test_data_inputs(test_data_dir)


def validate_generated_outputs(out_dir):
    for name in GENERATED_FILES:
        require_nonempty_file(out_dir / name, "generated Unicode table")


def download_all(version, cache_dir, test_data_dir, allow_downloads):
    """Populate cache/test data and report missing files."""
    base = UNICODE_BASE.format(version=version)

    if allow_downloads:
        print(f"Downloading UCD {version} files...")
    else:
        print(f"Checking cached UCD {version} files (downloads disabled)...")

    for f in UNICODE_FILES:
        url = f"{base}/{f}"
        dest = cache_dir / f.replace("/", "_")
        download_file(url, dest, allow_downloads)

    for f in TEST_FILES:
        url = f"{base}/{f}"
        cache_dest = cache_dir / f.replace("/", "_")
        if download_file(url, cache_dest, allow_downloads):
            copy_cached_file(cache_dest, test_data_dir / f.split("/")[-1])

    for name, url_template in SPECIAL_FILES.items():
        url = url_template.format(version=version)
        cache_dest = cache_dir / name
        downloaded = download_file(url, cache_dest, allow_downloads)
        if name == "CollationTest.zip":
            if downloaded:
                copy_cached_file(cache_dest, test_data_dir / name)
            else:
                download_file(url, test_data_dir / name, allow_downloads)

    if allow_downloads:
        print("Download complete.")

    missing_required = [name for name in REQUIRED_CACHE_FILES
                        if not is_nonempty_file(cache_dir / name)]
    missing_test_data = [name for name in EXPECTED_TEST_DATA_FILES
                         if not is_nonempty_file(test_data_dir / name)]
    return missing_required, missing_test_data


def parse_semicolon_file(path, fields=None):
    """Parse a standard UCD semicolon-delimited file.
    Yields (codepoint_or_range, [field_values]).
    codepoint_or_range is (start, end) tuple.
    """
    if not is_nonempty_file(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            cp_field = parts[0]
            rest = parts[1:] if len(parts) > 1 else []

            if ".." in cp_field:
                start, end = cp_field.split("..")
                cp_range = (int(start, 16), int(end, 16))
            else:
                cp = int(cp_field, 16)
                cp_range = (cp, cp)

            if fields is not None:
                rest = rest[:fields]
            yield cp_range, rest


def parse_unicode_data(path):
    """Parse UnicodeData.txt which has a special format with ranges."""
    entries = {}
    if not is_nonempty_file(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        prev_range_start = None
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(";")
            cp = int(parts[0], 16)
            name = parts[1]

            if name.endswith(", First>"):
                prev_range_start = cp
                # Store the field data for range fill
                entries[cp] = parts
                continue
            elif name.endswith(", Last>"):
                if prev_range_start is not None:
                    # Fill in the range with the same properties
                    template = entries[prev_range_start]
                    for c in range(prev_range_start, cp + 1):
                        entries[c] = template[:]
                        entries[c][0] = f"{c:04X}"
                    prev_range_start = None
                continue

            entries[cp] = parts

    return entries


# ---------------------------------------------------------------------------
# Enum definitions — must match the C enums exactly
# ---------------------------------------------------------------------------

GC_VALUES = [
    "Lu", "Ll", "Lt", "Lm", "Lo",
    "Mn", "Mc", "Me",
    "Nd", "Nl", "No",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
    "Sm", "Sc", "Sk", "So",
    "Zs", "Zl", "Zp",
    "Cc", "Cf", "Cs", "Co", "Cn",
]
GC_MAP = {v: i for i, v in enumerate(GC_VALUES)}

BIDI_CLASS_VALUES = [
    "L", "R", "AL",
    "EN", "ES", "ET", "AN", "CS",
    "NSM", "BN",
    "B", "S", "WS", "ON",
    "LRE", "LRO", "RLE", "RLO", "PDF",
    "LRI", "RLI", "FSI", "PDI",
]
BIDI_CLASS_MAP = {v: i for i, v in enumerate(BIDI_CLASS_VALUES)}

EAW_VALUES = ["N", "Na", "H", "W", "F", "A"]
EAW_MAP = {v: i for i, v in enumerate(EAW_VALUES)}

SCRIPT_VALUES = []  # Populated from Scripts.txt
SCRIPT_MAP = {}

BLOCK_VALUES = []  # Populated from Blocks.txt
BLOCK_MAP = {}

LINE_BREAK_VALUES = [
    "XX", "BK", "CR", "LF", "CM", "NL", "SG", "WJ",
    "ZW", "GL", "SP", "ZWJ",
    "B2", "BA", "BB", "HY", "CB",
    "CL", "CP", "EX", "IN", "NS", "OP", "QU",
    "IS", "NU", "PO", "PR", "SY",
    "AI", "AL", "CJ", "EB", "EM", "H2", "H3",
    "HL", "ID", "JL", "JT", "JV", "RI", "SA",
    "AK", "AP", "AS", "VF", "VI",
]
LINE_BREAK_MAP = {v: i for i, v in enumerate(LINE_BREAK_VALUES)}

GRAPHEME_BREAK_VALUES = [
    "Other", "CR", "LF", "Control", "Extend", "ZWJ",
    "Regional_Indicator", "Prepend", "SpacingMark",
    "L", "V", "T", "LV", "LVT",
    "InCB_Consonant", "InCB_Extend", "InCB_Linker",
]
GRAPHEME_BREAK_MAP = {v: i for i, v in enumerate(GRAPHEME_BREAK_VALUES)}

WORD_BREAK_VALUES = [
    "Other", "CR", "LF", "Newline", "Extend", "ZWJ",
    "Regional_Indicator", "Format", "Katakana",
    "Hebrew_Letter", "ALetter", "Single_Quote",
    "Double_Quote", "MidNumLet", "MidLetter",
    "MidNum", "Numeric", "ExtendNumLet", "WSegSpace",
]
WORD_BREAK_MAP = {v: i for i, v in enumerate(WORD_BREAK_VALUES)}

SENTENCE_BREAK_VALUES = [
    "Other", "CR", "LF", "Extend", "Sep", "Format",
    "Sp", "Lower", "Upper", "OLetter", "Numeric",
    "ATerm", "STerm", "Close", "SContinue",
]
SENTENCE_BREAK_MAP = {v: i for i, v in enumerate(SENTENCE_BREAK_VALUES)}

JOINING_TYPE_VALUES = ["U", "C", "D", "L", "R", "T"]
JOINING_TYPE_MAP = {v: i for i, v in enumerate(JOINING_TYPE_VALUES)}

# Binary properties — packed into uint64_t bitmask per codepoint
BINARY_PROPERTIES = [
    "White_Space", "Alphabetic", "Noncharacter_Code_Point",
    "Default_Ignorable_Code_Point", "Deprecated", "Logical_Order_Exception",
    "Variation_Selector", "Uppercase", "Lowercase",
    "Soft_Dotted", "Case_Ignorable", "Cased",
    "Changes_When_Lowercased", "Changes_When_Uppercased",
    "Changes_When_Titlecased", "Changes_When_Casefolded",
    "Changes_When_Casemapped", "ID_Start", "ID_Continue",
    "XID_Start", "XID_Continue", "Pattern_Syntax",
    "Pattern_White_Space", "Dash", "Quotation_Mark",
    "Terminal_Punctuation", "Sentence_Terminal",
    "Diacritic", "Extender", "Grapheme_Base",
    "Grapheme_Extend", "Grapheme_Link", "Math",
    "Hex_Digit", "ASCII_Hex_Digit", "Ideographic",
    "Unified_Ideograph", "Radical", "IDS_Binary_Operator",
    "IDS_Trinary_Operator", "Join_Control",
    "Emoji", "Emoji_Presentation", "Emoji_Modifier",
    "Emoji_Modifier_Base", "Emoji_Component",
    "Extended_Pictographic",
]
BINARY_PROP_MAP = {v: i for i, v in enumerate(BINARY_PROPERTIES)}

# Quick_Check values: Yes=0, Maybe=1, No=2
# Pack NFC_QC (2 bits) | NFD_QC (2 bits) | NFKC_QC (2 bits) | NFKD_QC (2 bits)
# into one uint8_t

# ---------------------------------------------------------------------------
# Two-stage table builder
# ---------------------------------------------------------------------------

class TwoStageTable:
    """Build a two-stage lookup table for per-codepoint data."""

    def __init__(self, name, c_type, default_value=0):
        self.name = "n00b_" + name
        self.c_type = c_type
        self.default_value = default_value
        self.data = [default_value] * MAX_CP

    def set(self, cp, value):
        if 0 <= cp < MAX_CP:
            self.data[cp] = value

    def set_range(self, start, end, value):
        for cp in range(start, min(end + 1, MAX_CP)):
            self.data[cp] = value

    def build(self):
        """Return (stage1, stage2_flat, unique_blocks_count)."""
        blocks = []
        for i in range(NUM_BLOCKS):
            block = tuple(self.data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE])
            blocks.append(block)

        # Deduplicate blocks
        unique = {}
        stage1 = []
        for block in blocks:
            if block not in unique:
                unique[block] = len(unique)
            stage1.append(unique[block])

        # Flatten stage2
        index_to_block = {v: k for k, v in unique.items()}
        stage2 = []
        for i in range(len(unique)):
            stage2.extend(index_to_block[i])

        return stage1, stage2, len(unique)

    def generate_c(self, out_path):
        """Write the C source file."""
        stage1, stage2, n_unique = self.build()
        print(f"  {self.name}: {n_unique} unique blocks, "
              f"stage1={NUM_BLOCKS * 2}B, "
              f"stage2={len(stage2) * self._type_size()}B")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"// Auto-generated by gen_tables.py — do not edit\n")
            f.write(f'#include "text/unicode/types.h"\n\n')

            # Stage 1 — index into stage2 blocks
            # Use uint16_t if n_unique < 65536, else uint32_t
            s1_type = "uint16_t" if n_unique < 65536 else "uint32_t"
            f.write(f"const {s1_type} {self.name}_stage1[{NUM_BLOCKS}] = {{\n")
            for i in range(0, NUM_BLOCKS, 16):
                vals = stage1[i:i + 16]
                f.write("    " + ", ".join(str(v) for v in vals) + ",\n")
            f.write("};\n\n")

            # Stage 2 — flattened blocks
            f.write(f"const {self.c_type} {self.name}_stage2[{len(stage2)}] = {{\n")
            for i in range(0, len(stage2), 16):
                vals = stage2[i:i + 16]
                if self.c_type == "uint64_t":
                    f.write("    " + ", ".join(f"0x{v:016x}ULL" for v in vals) + ",\n")
                else:
                    f.write("    " + ", ".join(str(v) for v in vals) + ",\n")
            f.write("};\n")

        return n_unique

    def _type_size(self):
        sizes = {"uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8, "int8_t": 1}
        return sizes.get(self.c_type, 1)


# ---------------------------------------------------------------------------
# Sparse mapping builder
# ---------------------------------------------------------------------------

class SparseMapping:
    """Build a sorted array for sparse codepoint→data mappings."""

    def __init__(self, name):
        self.name = "n00b_" + name
        self.entries = {}  # cp → data (list of uint32_t or codepoints)

    def add(self, cp, data):
        self.entries[cp] = data

    def generate_c(self, out_path, append=False):
        """Write sorted mapping + data array."""
        sorted_cps = sorted(self.entries.keys())
        # Build data array
        data_array = []
        offsets = {}
        for cp in sorted_cps:
            offsets[cp] = len(data_array)
            vals = self.entries[cp]
            # Store length first, then values
            data_array.append(len(vals))
            data_array.extend(vals)

        mode = "a" if append else "w"
        with open(out_path, mode, encoding="utf-8") as f:
            if not append:
                f.write(f"// Auto-generated by gen_tables.py — do not edit\n")
                f.write(f'#include "text/unicode/types.h"\n\n')

            # Index array: {codepoint, data_offset}
            f.write(f"const uint32_t {self.name}_index[][2] = {{\n")
            for cp in sorted_cps:
                f.write(f"    {{ 0x{cp:06X}, {offsets[cp]} }},\n")
            f.write("};\n")
            f.write(f"const uint32_t {self.name}_index_len = {len(sorted_cps)};\n\n")

            # Data array
            f.write(f"const uint32_t {self.name}_data[] = {{\n")
            for i in range(0, len(data_array), 16):
                vals = data_array[i:i + 16]
                f.write("    " + ", ".join(
                    f"0x{v & 0xFFFFFFFF:08X}" for v in vals) + ",\n")
            f.write("};\n\n")

        print(f"  {self.name}: {len(sorted_cps)} entries, "
              f"{len(data_array)} data words")


# ---------------------------------------------------------------------------
# Generators for each property
# ---------------------------------------------------------------------------

def gen_categories(cache_dir, out_dir):
    """Generate General_Category two-stage table from UnicodeData.txt."""
    print("Generating gen_categories.c ...")
    table = TwoStageTable("unicode_gc", "uint8_t", GC_MAP["Cn"])

    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        gc = parts[2] if len(parts) > 2 else "Cn"
        if gc in GC_MAP:
            table.set(cp, GC_MAP[gc])

    table.generate_c(out_dir / "gen_categories.c")


def gen_combining(cache_dir, out_dir):
    """Generate Canonical_Combining_Class table from UnicodeData.txt."""
    print("Generating gen_combining.c ...")
    table = TwoStageTable("unicode_ccc", "uint8_t", 0)

    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        ccc = int(parts[3]) if len(parts) > 3 and parts[3] else 0
        table.set(cp, ccc)

    table.generate_c(out_dir / "gen_combining.c")


def gen_bidi_class(cache_dir, out_dir):
    """Generate Bidi_Class table from UnicodeData.txt."""
    print("Generating gen_bidi_class.c ...")
    table = TwoStageTable("unicode_bidi", "uint8_t", BIDI_CLASS_MAP["L"])

    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        bc = parts[4] if len(parts) > 4 else "L"
        if bc in BIDI_CLASS_MAP:
            table.set(cp, BIDI_CLASS_MAP[bc])

    table.generate_c(out_dir / "gen_bidi_class.c")


def gen_bidi_brackets(cache_dir, out_dir):
    """Generate BidiBrackets + BidiMirroring tables."""
    print("Generating gen_bidi_brackets.c ...")

    brackets = SparseMapping("unicode_bidi_bracket")
    for (start, end), fields in parse_semicolon_file(cache_dir / "BidiBrackets.txt"):
        if len(fields) >= 2:
            paired = int(fields[0], 16)
            bracket_type = 1 if fields[1] == "o" else 2  # 1=open, 2=close
            brackets.add(start, [paired, bracket_type])

    mirrors = SparseMapping("unicode_bidi_mirror")
    for (start, end), fields in parse_semicolon_file(cache_dir / "BidiMirroring.txt"):
        if fields:
            mirrored = int(fields[0], 16)
            mirrors.add(start, [mirrored])

    brackets.generate_c(out_dir / "gen_bidi_brackets.c")
    mirrors.generate_c(out_dir / "gen_bidi_brackets.c", append=True)


def gen_scripts(cache_dir, out_dir):
    """Generate Script two-stage table from Scripts.txt."""
    print("Generating gen_scripts.c ...")

    # First pass: collect all script names
    scripts = set()
    for (start, end), fields in parse_semicolon_file(cache_dir / "Scripts.txt"):
        if fields:
            scripts.add(fields[0])

    global SCRIPT_VALUES, SCRIPT_MAP
    SCRIPT_VALUES = sorted(scripts)
    # Put "Unknown" (or "Common") first
    if "Common" in SCRIPT_VALUES:
        SCRIPT_VALUES.remove("Common")
        SCRIPT_VALUES.insert(0, "Common")
    if "Unknown" in SCRIPT_VALUES:
        SCRIPT_VALUES.remove("Unknown")
        SCRIPT_VALUES.insert(0, "Unknown")
    SCRIPT_MAP = {v: i for i, v in enumerate(SCRIPT_VALUES)}

    table = TwoStageTable("unicode_script", "uint8_t", SCRIPT_MAP.get("Unknown", 0))
    for (start, end), fields in parse_semicolon_file(cache_dir / "Scripts.txt"):
        if fields and fields[0] in SCRIPT_MAP:
            table.set_range(start, end, SCRIPT_MAP[fields[0]])

    n = table.generate_c(out_dir / "gen_scripts.c")

    # Append script name list
    with open(out_dir / "gen_scripts.c", "a", encoding="utf-8") as f:
        f.write(f"\nconst char *n00b_unicode_script_names[{len(SCRIPT_VALUES)}] = {{\n")
        for s in SCRIPT_VALUES:
            f.write(f'    "{s}",\n')
        f.write("};\n")
        f.write(f"const uint32_t n00b_unicode_script_count = {len(SCRIPT_VALUES)};\n")


def gen_script_extensions(cache_dir, out_dir):
    """Generate Script_Extensions sparse table from ScriptExtensions.txt."""
    print("Generating gen_script_extensions.c ...")

    # Build abbreviation → full-name map from PropertyValueAliases.txt
    abbrev_map = {}
    pva_path = cache_dir / "PropertyValueAliases.txt"
    require_nonempty_file(pva_path, "Unicode input file")
    with open(pva_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) >= 3 and parts[0] == "sc":
                abbr = parts[1]  # 4-letter abbreviation
                full = parts[2]  # Full name
                abbrev_map[abbr] = full

    # Parse ScriptExtensions.txt
    scext = SparseMapping("unicode_script_ext")
    path = cache_dir / "ScriptExtensions.txt"
    require_nonempty_file(path, "Unicode input file")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 2:
                continue
            cp_field = parts[0]
            abbrs = parts[1].split()

            # Map abbreviations to script indices
            indices = []
            for abbr in abbrs:
                full = abbrev_map.get(abbr, abbr)
                if full in SCRIPT_MAP:
                    indices.append(SCRIPT_MAP[full])

            if not indices:
                continue

            indices.sort()

            if ".." in cp_field:
                start, end = cp_field.split("..")
                for cp in range(int(start, 16), int(end, 16) + 1):
                    scext.add(cp, indices)
            else:
                scext.add(int(cp_field, 16), indices)

    # Find Common and Inherited indices
    common_idx = SCRIPT_MAP.get("Common", 0)
    inherited_idx = SCRIPT_MAP.get("Inherited", 0)

    with open(out_dir / "gen_script_extensions.c", "w", encoding="utf-8") as f:
        f.write("// Auto-generated by gen_tables.py — do not edit\n")
        f.write('#include "text/unicode/types.h"\n\n')
        f.write(f"#define N00B_UNICODE_SCRIPT_COMMON {common_idx}\n")
        f.write(f"#define N00B_UNICODE_SCRIPT_INHERITED {inherited_idx}\n\n")

    scext.generate_c(out_dir / "gen_script_extensions.c", append=True)

    print(f"  script_extensions: Common={common_idx}, Inherited={inherited_idx}")


def gen_blocks(cache_dir, out_dir):
    """Generate Block ranges from Blocks.txt."""
    print("Generating gen_blocks.c ...")

    global BLOCK_VALUES, BLOCK_MAP
    blocks = []
    for (start, end), fields in parse_semicolon_file(cache_dir / "Blocks.txt"):
        if fields:
            name = fields[0]
            blocks.append((start, end, name))

    BLOCK_VALUES = ["No_Block"] + [b[2] for b in blocks]
    BLOCK_MAP = {v: i for i, v in enumerate(BLOCK_VALUES)}

    with open(out_dir / "gen_blocks.c", "w", encoding="utf-8") as f:
        f.write("// Auto-generated by gen_tables.py — do not edit\n")
        f.write('#include "text/unicode/types.h"\n\n')

        f.write(f"const uint32_t n00b_unicode_block_ranges[][2] = {{\n")
        for start, end, name in blocks:
            f.write(f"    {{ 0x{start:06X}, 0x{end:06X} }},  // {name}\n")
        f.write("};\n")
        f.write(f"const uint16_t n00b_unicode_block_ids[] = {{\n")
        for start, end, name in blocks:
            f.write(f"    {BLOCK_MAP[name]},  // {name}\n")
        f.write("};\n")
        f.write(f"const uint32_t n00b_unicode_block_count = {len(blocks)};\n\n")

        f.write(f"const char *n00b_unicode_block_names[{len(BLOCK_VALUES)}] = {{\n")
        for b in BLOCK_VALUES:
            f.write(f'    "{b}",\n')
        f.write("};\n")

    print(f"  blocks: {len(blocks)} block ranges")


def gen_eaw(cache_dir, out_dir):
    """Generate East_Asian_Width table."""
    print("Generating gen_eaw.c ...")
    table = TwoStageTable("unicode_eaw", "uint8_t", EAW_MAP["N"])

    for (start, end), fields in parse_semicolon_file(cache_dir / "EastAsianWidth.txt"):
        if fields and fields[0] in EAW_MAP:
            table.set_range(start, end, EAW_MAP[fields[0]])

    table.generate_c(out_dir / "gen_eaw.c")


def gen_linebreak(cache_dir, out_dir):
    """Generate Line_Break property table."""
    print("Generating gen_linebreak.c ...")
    table = TwoStageTable("unicode_lb", "uint8_t", LINE_BREAK_MAP["XX"])

    for (start, end), fields in parse_semicolon_file(cache_dir / "LineBreak.txt"):
        if fields and fields[0] in LINE_BREAK_MAP:
            table.set_range(start, end, LINE_BREAK_MAP[fields[0]])

    table.generate_c(out_dir / "gen_linebreak.c")


def gen_grapheme(cache_dir, out_dir):
    """Generate Grapheme_Cluster_Break table."""
    print("Generating gen_grapheme.c ...")
    table = TwoStageTable("unicode_gcb", "uint8_t", GRAPHEME_BREAK_MAP["Other"])

    for (start, end), fields in parse_semicolon_file(
            cache_dir / "auxiliary_GraphemeBreakProperty.txt"):
        if fields and fields[0] in GRAPHEME_BREAK_MAP:
            table.set_range(start, end, GRAPHEME_BREAK_MAP[fields[0]])

    # Parse InCB (Indic Conjunct Break) from DerivedCoreProperties.txt
    # Format: cp ; InCB; Consonant/Linker/Extend
    # Only override Consonant and Linker — InCB_Extend characters keep their
    # GCB=Extend value since GB9 needs them to match as Extend.
    incb_map = {
        "Consonant": GRAPHEME_BREAK_MAP["InCB_Consonant"],
        "Linker":    GRAPHEME_BREAK_MAP["InCB_Linker"],
    }
    for (start, end), fields in parse_semicolon_file(
            cache_dir / "DerivedCoreProperties.txt"):
        if len(fields) >= 2 and fields[0] == "InCB" and fields[1] in incb_map:
            table.set_range(start, end, incb_map[fields[1]])

    table.generate_c(out_dir / "gen_grapheme.c")


def gen_wordbreak(cache_dir, out_dir):
    """Generate Word_Break table."""
    print("Generating gen_wordbreak.c ...")
    table = TwoStageTable("unicode_wb", "uint8_t", WORD_BREAK_MAP["Other"])

    for (start, end), fields in parse_semicolon_file(
            cache_dir / "auxiliary_WordBreakProperty.txt"):
        if fields and fields[0] in WORD_BREAK_MAP:
            table.set_range(start, end, WORD_BREAK_MAP[fields[0]])

    table.generate_c(out_dir / "gen_wordbreak.c")


def gen_sentbreak(cache_dir, out_dir):
    """Generate Sentence_Break table."""
    print("Generating gen_sentbreak.c ...")
    table = TwoStageTable("unicode_sb", "uint8_t", SENTENCE_BREAK_MAP["Other"])

    for (start, end), fields in parse_semicolon_file(
            cache_dir / "auxiliary_SentenceBreakProperty.txt"):
        if fields and fields[0] in SENTENCE_BREAK_MAP:
            table.set_range(start, end, SENTENCE_BREAK_MAP[fields[0]])

    table.generate_c(out_dir / "gen_sentbreak.c")


def gen_joining(cache_dir, out_dir):
    """Generate Joining_Type table from ArabicShaping.txt."""
    print("Generating gen_joining.c ...")
    table = TwoStageTable("unicode_jt", "uint8_t", JOINING_TYPE_MAP["U"])

    # ArabicShaping.txt has format: cp ; name ; joining_type ; joining_group
    path = cache_dir / "ArabicShaping.txt"
    require_nonempty_file(path, "Unicode input file")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) >= 3:
                cp_str = parts[0]
                jt = parts[2]
                if ".." in cp_str:
                    start, end = cp_str.split("..")
                    for cp in range(int(start, 16), int(end, 16) + 1):
                        if jt in JOINING_TYPE_MAP:
                            table.set(cp, JOINING_TYPE_MAP[jt])
                else:
                    cp = int(cp_str, 16)
                    if jt in JOINING_TYPE_MAP:
                        table.set(cp, JOINING_TYPE_MAP[jt])

    table.generate_c(out_dir / "gen_joining.c")


def gen_numeric(cache_dir, out_dir):
    """Generate Numeric_Value/Type from UnicodeData.txt."""
    print("Generating gen_numeric.c ...")

    # Numeric types: 0=None, 1=Decimal, 2=Digit, 3=Numeric
    # From UnicodeData.txt fields 6,7,8:
    #   field 6: decimal digit value
    #   field 7: digit value
    #   field 8: numeric value (can be fraction like 1/2)

    numeric_entries = SparseMapping("unicode_numeric")
    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        if len(parts) <= 8:
            continue
        dec = parts[6].strip() if len(parts) > 6 else ""
        dig = parts[7].strip() if len(parts) > 7 else ""
        num = parts[8].strip() if len(parts) > 8 else ""

        if dec:
            # Decimal digit
            numeric_entries.add(cp, [1, int(dec), 1])  # type=1, numerator, denominator
        elif dig:
            numeric_entries.add(cp, [2, int(dig), 1])
        elif num:
            if "/" in num:
                n, d = num.split("/")
                numeric_entries.add(cp, [3, int(n), int(d)])
            else:
                numeric_entries.add(cp, [3, int(num), 1])

    numeric_entries.generate_c(out_dir / "gen_numeric.c")


def gen_age(cache_dir, out_dir):
    """Generate Age ranges from DerivedAge.txt."""
    print("Generating gen_age.c ...")

    ages = set()
    entries = []
    for (start, end), fields in parse_semicolon_file(cache_dir / "DerivedAge.txt"):
        if fields:
            age = fields[0]
            ages.add(age)
            entries.append((start, end, age))

    age_list = sorted(ages, key=lambda a: tuple(int(x) for x in a.split(".")))
    age_map = {v: i + 1 for i, v in enumerate(age_list)}  # 0 = unassigned
    age_list = ["Unassigned"] + age_list

    table = TwoStageTable("unicode_age", "uint8_t", 0)
    for start, end, age in entries:
        table.set_range(start, end, age_map[age])

    table.generate_c(out_dir / "gen_age.c")

    with open(out_dir / "gen_age.c", "a", encoding="utf-8") as f:
        f.write(f"\nconst char *n00b_unicode_age_names[{len(age_list)}] = {{\n")
        for a in age_list:
            f.write(f'    "{a}",\n')
        f.write("};\n")
        f.write(f"const uint32_t n00b_unicode_age_count = {len(age_list)};\n")


def gen_proplist(cache_dir, out_dir):
    """Generate binary properties packed into uint64_t."""
    print("Generating gen_proplist.c ...")
    table = TwoStageTable("unicode_props", "uint64_t", 0)

    # Parse PropList.txt
    for (start, end), fields in parse_semicolon_file(cache_dir / "PropList.txt"):
        if fields and fields[0] in BINARY_PROP_MAP:
            bit = BINARY_PROP_MAP[fields[0]]
            for cp in range(start, end + 1):
                if cp < MAX_CP:
                    table.data[cp] |= (1 << bit)

    # Parse DerivedCoreProperties.txt
    for (start, end), fields in parse_semicolon_file(
            cache_dir / "DerivedCoreProperties.txt"):
        if fields and fields[0] in BINARY_PROP_MAP:
            bit = BINARY_PROP_MAP[fields[0]]
            for cp in range(start, end + 1):
                if cp < MAX_CP:
                    table.data[cp] |= (1 << bit)

    # Parse emoji properties
    for (start, end), fields in parse_semicolon_file(
            cache_dir / "emoji_emoji-data.txt"):
        if fields and fields[0] in BINARY_PROP_MAP:
            bit = BINARY_PROP_MAP[fields[0]]
            for cp in range(start, end + 1):
                if cp < MAX_CP:
                    table.data[cp] |= (1 << bit)

    table.generate_c(out_dir / "gen_proplist.c")


def gen_decomposition(cache_dir, out_dir):
    """Generate canonical + compatibility decomposition mappings."""
    print("Generating gen_decomposition.c ...")

    canonical = SparseMapping("unicode_canon_decomp")
    compat = SparseMapping("unicode_compat_decomp")

    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        if len(parts) <= 5:
            continue
        decomp = parts[5].strip()
        if not decomp:
            continue

        # Check for compatibility tag
        is_compat = False
        if decomp.startswith("<"):
            is_compat = True
            # Strip tag
            idx = decomp.index(">")
            decomp = decomp[idx + 1:].strip()

        cps = [int(x, 16) for x in decomp.split()]
        if not cps:
            continue

        if is_compat:
            compat.add(cp, cps)
        else:
            canonical.add(cp, cps)
            # Also add to compat (canonical decomps are also compat decomps)
            compat.add(cp, cps)

    canonical.generate_c(out_dir / "gen_decomposition.c")
    compat.generate_c(out_dir / "gen_decomposition.c", append=True)


def gen_composition(cache_dir, out_dir):
    """Generate canonical composition hash table."""
    print("Generating gen_composition.c ...")

    # Load composition exclusions
    exclusions = set()
    for (start, end), fields in parse_semicolon_file(
            cache_dir / "CompositionExclusions.txt"):
        for cp in range(start, end + 1):
            exclusions.add(cp)

    # Build composition pairs from UnicodeData.txt canonical decompositions
    compositions = {}  # (starter, combining) → composed
    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        if len(parts) <= 5:
            continue
        decomp = parts[5].strip()
        if not decomp or decomp.startswith("<"):
            continue

        cps = [int(x, 16) for x in decomp.split()]
        if len(cps) != 2:
            continue  # Only binary decompositions compose

        if cp in exclusions:
            continue

        # Singleton decompositions don't compose
        # (these are in composition exclusions anyway)

        # S0 = Full_Composition_Exclusion check:
        # Already handled by CompositionExclusions.txt

        starter, combining = cps[0], cps[1]
        compositions[(starter, combining)] = cp

    # Build open-addressing hash table
    n_entries = len(compositions)
    table_size = 1
    while table_size < n_entries * 2:
        table_size *= 2

    EMPTY = 0xFFFFFFFF
    keys = [(EMPTY, EMPTY)] * table_size
    values = [0] * table_size

    for (starter, combining), composed in compositions.items():
        key = (starter << 21) | combining
        h = key % table_size
        while keys[h] != (EMPTY, EMPTY):
            h = (h + 1) % table_size
        keys[h] = (starter, combining)
        values[h] = composed

    with open(out_dir / "gen_composition.c", "w", encoding="utf-8") as f:
        f.write("// Auto-generated by gen_tables.py — do not edit\n")
        f.write('#include "text/unicode/types.h"\n\n')

        f.write(f"#define N00B_UNICODE_COMP_TABLE_SIZE {table_size}\n")
        f.write(f"#define N00B_UNICODE_COMP_EMPTY 0xFFFFFFFFU\n\n")

        # Store as parallel arrays: starter[], combining[], composed[]
        f.write(f"const uint32_t n00b_unicode_comp_starter[{table_size}] = {{\n")
        for i in range(0, table_size, 8):
            vals = [f"0x{keys[j][0]:08X}" for j in range(i, min(i + 8, table_size))]
            f.write("    " + ", ".join(vals) + ",\n")
        f.write("};\n\n")

        f.write(f"const uint32_t n00b_unicode_comp_combining[{table_size}] = {{\n")
        for i in range(0, table_size, 8):
            vals = [f"0x{keys[j][1]:08X}" for j in range(i, min(i + 8, table_size))]
            f.write("    " + ", ".join(vals) + ",\n")
        f.write("};\n\n")

        f.write(f"const uint32_t n00b_unicode_comp_result[{table_size}] = {{\n")
        for i in range(0, table_size, 8):
            vals = [f"0x{values[j]:06X}" for j in range(i, min(i + 8, table_size))]
            f.write("    " + ", ".join(vals) + ",\n")
        f.write("};\n")

    print(f"  composition: {n_entries} pairs in {table_size}-slot table "
          f"({n_entries * 100 / table_size:.0f}% load)")


def gen_normprops(cache_dir, out_dir):
    """Generate NFC/NFD/NFKC/NFKD Quick_Check values."""
    print("Generating gen_normprops.c ...")

    # QC values: Y=0, M=1, N=2
    # Pack: bits 0-1=NFC_QC, 2-3=NFD_QC, 4-5=NFKC_QC, 6-7=NFKD_QC
    table = TwoStageTable("unicode_nqc", "uint8_t", 0)

    qc_map = {"Y": 0, "M": 1, "N": 2}
    form_shift = {"NFC_QC": 0, "NFD_QC": 2, "NFKC_QC": 4, "NFKD_QC": 6}

    for (start, end), fields in parse_semicolon_file(
            cache_dir / "DerivedNormalizationProps.txt"):
        if not fields:
            continue
        prop = fields[0]
        if prop in form_shift:
            val = qc_map.get(fields[1] if len(fields) > 1 else "Y", 0)
            shift = form_shift[prop]
            for cp in range(start, end + 1):
                if cp < MAX_CP:
                    table.data[cp] = (table.data[cp] & ~(3 << shift)) | (val << shift)

    table.generate_c(out_dir / "gen_normprops.c")


def gen_casemap(cache_dir, out_dir):
    """Generate simple + full case mappings + case folding."""
    print("Generating gen_casemap.c ...")

    # Simple case mappings from UnicodeData.txt fields 12, 13, 14
    simple_upper = SparseMapping("unicode_simple_upper")
    simple_lower = SparseMapping("unicode_simple_lower")
    simple_title = SparseMapping("unicode_simple_title")

    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")
    for cp, parts in ud.items():
        if len(parts) > 12 and parts[12].strip():
            simple_upper.add(cp, [int(parts[12].strip(), 16)])
        if len(parts) > 13 and parts[13].strip():
            simple_lower.add(cp, [int(parts[13].strip(), 16)])
        if len(parts) > 14 and parts[14].strip():
            simple_title.add(cp, [int(parts[14].strip(), 16)])

    # Full case mappings from SpecialCasing.txt
    full_upper = SparseMapping("unicode_full_upper")
    full_lower = SparseMapping("unicode_full_lower")
    full_title = SparseMapping("unicode_full_title")

    path = cache_dir / "SpecialCasing.txt"
    require_nonempty_file(path, "Unicode input file")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 4:
                continue
            # Skip conditional mappings (have a 5th field with conditions)
            if len(parts) >= 5 and parts[4].strip():
                continue

            cp = int(parts[0], 16)
            lower_cps = [int(x, 16) for x in parts[1].split()] if parts[1].strip() else []
            title_cps = [int(x, 16) for x in parts[2].split()] if parts[2].strip() else []
            upper_cps = [int(x, 16) for x in parts[3].split()] if parts[3].strip() else []

            if lower_cps:
                full_lower.add(cp, lower_cps)
            if title_cps:
                full_title.add(cp, title_cps)
            if upper_cps:
                full_upper.add(cp, upper_cps)

    # Case folding from CaseFolding.txt
    simple_fold = SparseMapping("unicode_casefold_simple")
    full_fold = SparseMapping("unicode_casefold_full")

    for (start, end), fields in parse_semicolon_file(cache_dir / "CaseFolding.txt"):
        if len(fields) < 2:
            continue
        status = fields[0]
        mapping = [int(x, 16) for x in fields[1].split()]

        if status == "C" or status == "S":
            # Common/Simple — single codepoint
            simple_fold.add(start, mapping)
        if status == "C" or status == "F":
            # Common/Full — possibly multi-codepoint
            full_fold.add(start, mapping)

    with open(out_dir / "gen_casemap.c", "w", encoding="utf-8") as f:
        f.write("// Auto-generated by gen_tables.py — do not edit\n")
        f.write('#include "text/unicode/types.h"\n\n')

    simple_upper.generate_c(out_dir / "gen_casemap.c", append=True)
    simple_lower.generate_c(out_dir / "gen_casemap.c", append=True)
    simple_title.generate_c(out_dir / "gen_casemap.c", append=True)
    full_upper.generate_c(out_dir / "gen_casemap.c", append=True)
    full_lower.generate_c(out_dir / "gen_casemap.c", append=True)
    full_title.generate_c(out_dir / "gen_casemap.c", append=True)
    simple_fold.generate_c(out_dir / "gen_casemap.c", append=True)
    full_fold.generate_c(out_dir / "gen_casemap.c", append=True)


def gen_emoji(cache_dir, out_dir):
    """Generate Emoji properties + RGI sequences."""
    print("Generating gen_emoji.c ...")
    # Emoji binary properties are already in gen_proplist.c
    # Here we generate any additional emoji sequence data

    # For now, just generate an empty file that confirms emoji data is loaded
    with open(out_dir / "gen_emoji.c", "w", encoding="utf-8") as f:
        f.write("// Auto-generated by gen_tables.py — do not edit\n")
        f.write('#include "text/unicode/types.h"\n\n')
        f.write("// Emoji binary properties are in gen_proplist.c\n")
        f.write("// RGI emoji sequences would go here for a full implementation\n")

    print("  emoji: properties in gen_proplist.c")


def gen_confusables(cache_dir, out_dir):
    """Generate confusable mappings for skeleton algorithm."""
    print("Generating gen_confusables.c ...")

    confusables = SparseMapping("unicode_confusable")

    path = cache_dir / "confusables.txt"
    require_nonempty_file(path, "Unicode input file")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 3:
                continue
            # Format: source ; target ; type
            src_cps = [int(x, 16) for x in parts[0].split()]
            tgt_cps = [int(x, 16) for x in parts[1].split()]

            if len(src_cps) == 1:
                confusables.add(src_cps[0], tgt_cps)

    confusables.generate_c(out_dir / "gen_confusables.c")


def gen_identifiers(cache_dir, out_dir):
    """Generate Identifier_Status/Type tables."""
    print("Generating gen_identifiers.c ...")

    # Identifier_Status: Allowed=1, Restricted=0
    table = TwoStageTable("unicode_id_status", "uint8_t", 0)

    for (start, end), fields in parse_semicolon_file(
            cache_dir / "IdentifierStatus.txt"):
        if fields:
            val = 1 if fields[0] == "Allowed" else 0
            table.set_range(start, end, val)

    table.generate_c(out_dir / "gen_identifiers.c")


def gen_idna(cache_dir, out_dir):
    """Generate IDNA mapping table."""
    print("Generating gen_idna.c ...")

    # IDNA statuses: valid=0, ignored=1, mapped=2, deviation=3, disallowed=4,
    #                disallowed_STD3_valid=5, disallowed_STD3_mapped=6
    idna_status_map = {
        "valid": 0, "ignored": 1, "mapped": 2, "deviation": 3,
        "disallowed": 4, "disallowed_STD3_valid": 5,
        "disallowed_STD3_mapped": 6,
    }

    status_table = TwoStageTable("unicode_idna_status", "uint8_t", 4)  # default: disallowed
    mapping = SparseMapping("unicode_idna_map")

    path = cache_dir / "IdnaMappingTable.txt"
    for (start, end), fields in parse_semicolon_file(path):
        if not fields:
            continue
        status = fields[0]
        if status in idna_status_map:
            status_table.set_range(start, end, idna_status_map[status])

            # If there's a mapping
            if len(fields) > 1 and fields[1].strip():
                map_cps = [int(x, 16) for x in fields[1].split()]
                for cp in range(start, end + 1):
                    mapping.add(cp, map_cps)

    status_table.generate_c(out_dir / "gen_idna.c")
    mapping.generate_c(out_dir / "gen_idna.c", append=True)


def gen_names(cache_dir, out_dir):
    """Generate Unicode codepoint→name and name→codepoint tables from
    UnicodeData.txt.

    Skips range placeholders (`<CJK Ideograph>`, `<Hangul Syllable>`,
    etc.) — those codepoints have algorithmically-computed names that
    a future revision can layer on top.  Explicit-name codepoints
    (ASCII, Latin, Cyrillic, Greek, symbols, emoji-style names, etc.)
    are emitted into a sorted array of (cp, name-offset) records plus
    a packed string pool of NUL-terminated names.
    """
    print(f"Generating {out_dir}/gen_names.c")
    ud = parse_unicode_data(cache_dir / "UnicodeData.txt")

    # Filter to explicit names (skip <...> placeholders, control char
    # entries with empty names, etc.).
    entries = []
    for cp in sorted(ud.keys()):
        name = ud[cp][1]
        if not name or name.startswith("<"):
            continue
        entries.append((cp, name))

    # Build a string pool with offsets.  Names share no prefixes
    # in UnicodeData so a simple concat is fine.
    pool = bytearray()
    offsets = []
    for cp, name in entries:
        offsets.append(len(pool))
        pool.extend(name.encode("ascii"))
        pool.append(0)

    out_path = out_dir / "gen_names.c"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write('// Auto-generated by gen_tables.py — do not edit.\n')
        f.write('#include <stdint.h>\n')
        f.write('#include <stddef.h>\n')
        f.write('#include <string.h>\n\n')

        f.write(f'static const char n00b_unicode_name_pool[] = {{\n')
        # Emit string pool as a comma-separated byte array.
        for i in range(0, len(pool), 24):
            chunk = pool[i:i + 24]
            line = ", ".join(str(b) for b in chunk)
            f.write(f'    {line},\n')
        f.write('};\n\n')

        f.write('typedef struct { uint32_t cp; uint32_t off; }\n')
        f.write('    n00b_unicode_name_entry_t;\n\n')
        f.write(f'static const n00b_unicode_name_entry_t '
                f'n00b_unicode_name_table[] = {{\n')
        for (cp, _name), off in zip(entries, offsets):
            f.write(f'    {{ 0x{cp:06X}, {off}u }},\n')
        f.write('};\n\n')

        f.write(f'#define N00B_UNICODE_NAME_COUNT '
                f'{len(entries)}\n\n')

        # cp→name via binary search on sorted-by-cp table.
        f.write('const char *\n')
        f.write('_n00b_gen_unicode_cp_name(uint32_t cp)\n')
        f.write('{\n')
        f.write('    size_t lo = 0;\n')
        f.write('    size_t hi = N00B_UNICODE_NAME_COUNT;\n')
        f.write('    while (lo < hi) {\n')
        f.write('        size_t mid = (lo + hi) / 2;\n')
        f.write('        uint32_t mcp = n00b_unicode_name_table[mid].cp;\n')
        f.write('        if (mcp == cp) {\n')
        f.write('            return n00b_unicode_name_pool +\n')
        f.write('                   n00b_unicode_name_table[mid].off;\n')
        f.write('        }\n')
        f.write('        if (mcp < cp) lo = mid + 1; else hi = mid;\n')
        f.write('    }\n')
        f.write('    return 0;\n')
        f.write('}\n\n')

        # name→cp via linear scan — small enough at ~17K entries that
        # a sorted-name table + binary search is overkill for v1.
        # (The pool isn't sorted by name; a follow-up could emit a
        # parallel sorted-name index.)
        f.write('int\n')
        f.write('_n00b_gen_unicode_name_lookup(const char *name,\n')
        f.write('                              uint32_t   *out_cp)\n')
        f.write('{\n')
        f.write('    if (!name || !out_cp) return 0;\n')
        f.write('    for (size_t i = 0; i < N00B_UNICODE_NAME_COUNT; i++) {\n')
        f.write('        const char *n = n00b_unicode_name_pool +\n')
        f.write('                        n00b_unicode_name_table[i].off;\n')
        f.write('        if (strcmp(n, name) == 0) {\n')
        f.write('            *out_cp = n00b_unicode_name_table[i].cp;\n')
        f.write('            return 1;\n')
        f.write('        }\n')
        f.write('    }\n')
        f.write('    return 0;\n')
        f.write('}\n')


def gen_collation(cache_dir, out_dir):
    """Generate DUCET collation data from allkeys.txt."""
    print("Generating gen_collation.c ...")

    # Parse allkeys.txt format:
    # codepoint(s) ; [.primary.secondary.tertiary] [.p.s.t] ...
    # or: @implicitweights ranges

    single_ces = {}    # cp → list of (primary, secondary, tertiary)
    contractions = {}  # tuple of cps → list of (p, s, t)

    path = cache_dir / "allkeys.txt"
    if not is_nonempty_file(path):
        print("  WARNING: allkeys.txt not found, skipping collation")
        table = TwoStageTable("unicode_ducet", "uint32_t", 0xFFFFFFFF)
        table.generate_c(out_dir / "gen_collation.c")
        with open(out_dir / "gen_collation.c", "a", encoding="utf-8") as f:
            f.write("\nconst uint16_t n00b_unicode_ce_data[1] = { 0 };\n")
            f.write("const uint32_t n00b_unicode_ce_data_len = 1;\n")
            f.write("const uint32_t n00b_unicode_contraction_count = 0;\n")
            f.write("const uint32_t n00b_unicode_contr_keys[1][4] = { { 0, 0, 0, 0 } };\n")
            f.write("const uint32_t n00b_unicode_contr_key_lens[1] = { 0 };\n")
            f.write("const uint32_t n00b_unicode_contr_ce_offsets[1] = { 0 };\n")
            f.write("const uint16_t n00b_unicode_contr_ce_data[1] = { 0 };\n")
            f.write("const uint32_t n00b_unicode_ducet_count = 0;\n")
        return

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line or line.startswith("@"):
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 2:
                continue

            cp_strs = parts[0].split()
            cps = [int(x, 16) for x in cp_strs]

            # Parse CE weights
            ce_str = parts[1]
            ces = []
            # Find all [.XXXX.XXXX.XXXX] or [*XXXX.XXXX.XXXX] patterns
            i = 0
            while i < len(ce_str):
                if ce_str[i] == '[':
                    end = ce_str.index(']', i)
                    inner = ce_str[i + 1:end]
                    # Replace * with . for splitting (variable weight marker)
                    inner = inner.replace("*", ".")
                    ce_parts = [x for x in inner.split(".") if x]
                    if len(ce_parts) >= 3:
                        ce_vals = [int(x, 16) for x in ce_parts[:3]]
                        ces.append((ce_vals[0], ce_vals[1], ce_vals[2]))
                    i = end + 1
                else:
                    i += 1

            if len(cps) == 1:
                single_ces[cps[0]] = ces
            else:
                contractions[tuple(cps)] = ces

    # Build two-stage table for single-codepoint → CE offset
    # CE data array stores: [count, p1, s1, t1, p2, s2, t2, ...]
    ce_data = []
    ce_offsets = {}

    # Deduplicate CE sequences
    ce_seq_map = {}
    for cp in sorted(single_ces.keys()):
        ces = single_ces[cp]
        key = tuple((p, s, t) for p, s, t in ces)
        if key not in ce_seq_map:
            ce_seq_map[key] = len(ce_data)
            ce_data.append(len(ces))
            for p, s, t in ces:
                ce_data.extend([p, s, t])
        ce_offsets[cp] = ce_seq_map[key]

    # Two-stage table mapping cp → offset into ce_data
    table = TwoStageTable("unicode_ducet", "uint32_t", 0xFFFFFFFF)
    for cp, offset in ce_offsets.items():
        table.set(cp, offset)

    table.generate_c(out_dir / "gen_collation.c")

    with open(out_dir / "gen_collation.c", "a", encoding="utf-8") as f:
        # CE data array
        f.write(f"\nconst uint16_t n00b_unicode_ce_data[{len(ce_data)}] = {{\n")
        for i in range(0, len(ce_data), 16):
            vals = ce_data[i:i + 16]
            f.write("    " + ", ".join(f"0x{v:04X}" for v in vals) + ",\n")
        f.write("};\n")
        f.write(f"const uint32_t n00b_unicode_ce_data_len = {len(ce_data)};\n\n")

        # Contraction table (sorted by first codepoint for binary search)
        sorted_contr = sorted(contractions.items())
        f.write(f"const uint32_t n00b_unicode_contraction_count = {len(sorted_contr)};\n\n")

        if sorted_contr:
            # Contraction index: {cp1, cp2, ..., 0, ce_offset}
            # For simplicity, store as flat array with sentinel
            contr_data = []
            contr_index = []
            for cps, ces in sorted_contr:
                offset = len(contr_data)
                contr_index.append((cps, offset))
                contr_data.append(len(ces))
                for p, s, t in ces:
                    contr_data.extend([p, s, t])

            f.write(f"const uint32_t n00b_unicode_contr_keys[][4] = {{\n")
            for cps, offset in contr_index:
                padded = list(cps) + [0] * (4 - len(cps))
                padded = padded[:4]
                f.write("    {{ {} }},\n".format(
                    ", ".join(f"0x{v:06X}" for v in padded)))
            f.write("};\n\n")

            f.write(f"const uint32_t n00b_unicode_contr_key_lens[] = {{\n")
            for cps, offset in contr_index:
                f.write(f"    {len(cps)},\n")
            f.write("};\n\n")

            f.write(f"const uint32_t n00b_unicode_contr_ce_offsets[] = {{\n")
            for cps, offset in contr_index:
                f.write(f"    {offset},\n")
            f.write("};\n\n")

            f.write(f"const uint16_t n00b_unicode_contr_ce_data[{len(contr_data)}] = {{\n")
            for i in range(0, len(contr_data), 16):
                vals = contr_data[i:i + 16]
                f.write("    " + ", ".join(f"0x{v:04X}" for v in vals) + ",\n")
            f.write("};\n")

    print(f"  collation: {len(single_ces)} single entries, "
          f"{len(contractions)} contractions, "
          f"{len(ce_data)} CE data words")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate UCD tables")
    parser.add_argument("--version", default="16.0.0",
                        help="Unicode version (default: 16.0.0)")
    parser.add_argument("--cache-dir", default=".unicode_cache",
                        help="Cache directory for downloaded files")
    parser.add_argument("--out-dir", default="src/unicode/generated",
                        help="Output directory for generated C files")
    parser.add_argument("--test-data-dir", default="test/data",
                        help="Output directory for test data files")
    parser.add_argument("--allow-downloads", action="store_true",
                        help="Allow network downloads for missing unicode cache/test files")
    parser.add_argument("--strict", dest="strict", action="store_true",
                        help="Fail when unicode test data files are missing; required cache files are always fatal")
    parser.add_argument("--no-strict", dest="strict", action="store_false",
                        help="Warn instead of failing when unicode test data files are missing")
    parser.add_argument("--check-inputs", action="store_true",
                        help="Populate/validate unicode cache and test data, then exit")
    parser.set_defaults(strict=True)
    args = parser.parse_args()

    # Resolve paths relative to CWD (works both standalone and from meson)
    cache_dir = Path(args.cache_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    test_data_dir = Path(args.test_data_dir).resolve()

    cache_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    test_data_dir.mkdir(parents=True, exist_ok=True)

    print(f"Unicode cache dir: {cache_dir}")
    print(f"Unicode test-data dir: {test_data_dir}")
    print(f"Allow downloads: {'yes' if args.allow_downloads else 'no'}")
    print(f"Strict input checks: {'yes' if args.strict else 'no'}")

    missing_required, missing_test_data = download_all(args.version,
                                                       cache_dir,
                                                       test_data_dir,
                                                       args.allow_downloads)
    print()

    if missing_required:
        print("ERROR: required unicode cache files are missing:")
        for name in missing_required:
            print(f"  - {name}")

        if args.allow_downloads:
            print("Downloads were enabled, but one or more required files could not be fetched.")
            print("Check network/DNS access and rerun.")
        else:
            print("Downloads are disabled. Pre-populate the cache directory above,")
            print("or rerun with --allow-downloads.")

        return 2

    validate_cache_inputs(cache_dir)

    if missing_test_data:
        label = "ERROR" if args.strict else "WARNING"
        print(f"{label}: unicode test-data files are missing:")
        for name in missing_test_data:
            print(f"  - {name}")
        if args.strict:
            print("Pre-populate the test-data directory above, or rerun with --allow-downloads.")
            return 2
        print("Some unicode conformance tests may be unavailable.")
        print()
    else:
        validate_test_data_inputs(test_data_dir)

    if args.check_inputs:
        print("Unicode inputs are ready.")
        return 0

    # Generate all tables
    gen_categories(cache_dir, out_dir)
    gen_combining(cache_dir, out_dir)
    gen_bidi_class(cache_dir, out_dir)
    gen_bidi_brackets(cache_dir, out_dir)
    gen_scripts(cache_dir, out_dir)
    gen_script_extensions(cache_dir, out_dir)
    gen_blocks(cache_dir, out_dir)
    gen_eaw(cache_dir, out_dir)
    gen_linebreak(cache_dir, out_dir)
    gen_grapheme(cache_dir, out_dir)
    gen_wordbreak(cache_dir, out_dir)
    gen_sentbreak(cache_dir, out_dir)
    gen_joining(cache_dir, out_dir)
    gen_numeric(cache_dir, out_dir)
    gen_age(cache_dir, out_dir)
    gen_proplist(cache_dir, out_dir)
    gen_decomposition(cache_dir, out_dir)
    gen_composition(cache_dir, out_dir)
    gen_normprops(cache_dir, out_dir)
    gen_casemap(cache_dir, out_dir)
    gen_emoji(cache_dir, out_dir)
    gen_confusables(cache_dir, out_dir)
    gen_identifiers(cache_dir, out_dir)
    gen_idna(cache_dir, out_dir)
    gen_names(cache_dir, out_dir)
    gen_collation(cache_dir, out_dir)

    validate_generated_outputs(out_dir)

    print("\nAll tables generated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
