/**
 * @file objfile_macho_casegen.c
 * @brief Standalone compile of the Mach-O fixture generators.
 *
 * The Mach-O fixture builders and `n00b_test_macho_build_case` dispatch
 * live header-only in `objfile_macho_casegen.h`, mirroring the
 * header-only `objfile_elf_casegen.h` precedent: the always-run harness
 * consumes them via `#include` and rides the existing `'macho'` test
 * target without editing the `objfile_test_names` foreach. This thin
 * translation unit `#include`s the header so the builder implementation
 * is also compiled standalone (and linked into the gated Mach-O oracle
 * target, which lists this source explicitly).
 *
 * Per n00b-api-guidelines § 1 / macwrap DECISIONS.md D-018, the header's
 * raw-byte scaffolding may use header-only libc; see the header for the
 * full rationale and the §6.3 build-API findings (no signature emitter;
 * __LINKEDIT always emitted last).
 */

#include "objfile_macho_casegen.h"
