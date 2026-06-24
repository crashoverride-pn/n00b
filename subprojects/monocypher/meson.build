# meson.build — Monocypher (Ed25519 + SHA-512) shim for n00b.
#
# This shim is **n00b-authored**, not from upstream. Upstream Monocypher
# ships a Makefile (and an optional CMake hand-off); we provide a meson
# wrapper so the build can be driven through meson the same way as any
# other vendored subproject (mirrors the precedent set by
# subprojects/picotls/meson.build).
#
# What we build:
#
#   monocypher  (src/monocypher.c, src/monocypher-ed25519.c)
#
# Why both:
#
# - monocypher.c provides crypto_eddsa_* (BLAKE2b-based EdDSA, the
#   core-Monocypher signature primitive), shared field/group code, and
#   the low-level scalar ops the Ed25519 module reuses.
# - monocypher-ed25519.c provides the RFC 8032 SHA-512 Ed25519 variant
#   (crypto_ed25519_* and crypto_sha512_*) — the standards-compliant
#   form used for DSSE signing.
#
# We expose a single dependency (monocypher_dep) so consumers can
# pull both APIs in with one #include / one link edge.
#
# Upstream version: v4.0.2 (https://github.com/LoupVaillant/Monocypher).
# License: CC0 / BSD-2 dual (see LICENCE.md alongside this file).

project('monocypher', 'c',
  version: '4.0.2',
  license: 'CC0-1.0 OR BSD-2-Clause',
  default_options: [
    'c_std=c99',
    'warning_level=1',
    'default_library=static',
  ],
)

# Vendored upstream headers: exported as `is_system` so ncc treats them like
# system headers and never flags their unions in any TU that includes them.
monocypher_inc = [
  include_directories('include', is_system: true),
]

# Quiet upstream-internal warnings that aren't ours to fix.
# Monocypher is mature, Cure53-audited code; we trust its style.
monocypher_c_args = [
  '-Wno-unused-parameter',
  '-Wno-unused-function',
  '-Wno-unused-variable',
  '-Wno-sign-compare',
  '-Wno-implicit-fallthrough',
]
# Vendored upstream code: opt out of ncc's traditional-union deprecation
# (won't migrate to n00b_variant_t). has_argument-guarded so a standalone clang
# build is unaffected (ncc's compiler id reads as "clang").
if meson.get_compiler('c').has_argument('--ncc-allow-unions')
  monocypher_c_args += '--ncc-allow-unions'
endif

monocypher_sources = [
  'src/monocypher.c',
  'src/monocypher-ed25519.c',
]

monocypher_lib = static_library('monocypher',
  monocypher_sources,
  include_directories: monocypher_inc,
  c_args: monocypher_c_args,
)

monocypher_dep = declare_dependency(
  link_with: monocypher_lib,
  include_directories: monocypher_inc,
)
