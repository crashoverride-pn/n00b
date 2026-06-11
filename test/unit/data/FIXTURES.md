# Mach-O test fixtures (test/unit/data)

All compiled from `hello.c` (`int main(void){return 0;}`) for arm64.

| Fixture | How it was made | Properties used by tests |
|---|---|---|
| `hello.macho` | configure-time build (ELF/Mach-O/PE host fixture) | ad-hoc signed arm64 `MH_EXECUTE`; `sizeofcmds=744`; 32 B LC slack. |
| `hello_signed_arm64.macho` | ad-hoc signed arm64 build | signed; used by codesig-present-no-resign tests. |
| `hello_unsigned_arm64.macho` | `xcrun clang -arch arm64 -Wl,-headerpad,0x100 -Wl,-no_adhoc_codesign -o hello_unsigned_arm64.macho hello.c` | **unsigned** arm64 `MH_EXECUTE`; **256 B LC slack** (≥ the 40 B `LC_NOTE` command); `LC_MAIN`; `__LINKEDIT` last; file ends at `__LINKEDIT` end. The clean **accept** + reserved-name fixture for `objfile_macho_rewrite_admit` (WP-004 DF-004-01). |
| `hello_lowslack_arm64.macho` | `xcrun clang -arch arm64 -Wl,-headerpad,0 -Wl,-no_adhoc_codesign -o hello_lowslack_arm64.macho hello.c` | **unsigned** arm64 `MH_EXECUTE`; **32 B LC slack** (< 40 B; the linker's enforced minimum) so metadata-insert admission rejects with `LC_HEADER_SLACK`; otherwise clean. The `LC_HEADER_SLACK` **reject** fixture (WP-004 DF-004-01). |
| `hello_x86_64.macho` | `xcrun clang -arch x86_64 -Wl,-no_adhoc_codesign -o hello_x86_64.macho hello.c` | **unsigned** x86_64 `MH_EXECUTE`. The non-arm64 fixture for the host-entrypoint `UNSUPPORTED_CPUTYPE` reject (WP-004 Phase 2). |

> **Not vendorable: an arm64 binary without `LC_MAIN`.** Modern `ld` always emits
> `LC_MAIN` for arm64 (`-no_new_main` is obsolete and ignored), and `n00b_macho_build`
> also always emits `LC_MAIN`, so the `NO_LC_MAIN` host-entrypoint reject cannot be
> exercised by a compiled or built artifact. See the WP-004 Phase-2 log for how that one
> case is handled.

`-Wl,-no_adhoc_codesign` yields a binary with no `LC_CODE_SIGNATURE` (parseable as a
fixture; not for execution). `-Wl,-headerpad,N` controls the byte gap between the load
commands and the first section (the LC header slack the admission layer measures).
