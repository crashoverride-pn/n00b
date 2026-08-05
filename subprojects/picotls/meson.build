# meson.build — picotls (TLS 1.3 + QUIC keyschedule) shim for n00b.
#
# This shim is **n00b-authored**, not from upstream.  Upstream picotls
# ships CMake; we provide a meson wrapper that produces two static
# libraries:
#
#   picotls-core         (lib/picotls.c, lib/hpke.c, lib/pembase64.c)
#   picotls-minicrypto   (cifra + micro-ecc + picotls minicrypto bindings)
#
# We deliberately do **not** build:
#
#   - picotls-openssl (would add an OpenSSL runtime dep we don't want
#     for Phase 1 — see docs/quic/vendored.md)
#   - picotls-fusion  (AES-NI fast path — useful, but Phase 1 favors
#     a tighter dep closure)
#   - picotls-mbedtls
#   - picotls-bcrypt  (Windows; out of Phase 1 scope)
#   - certificate_compression.c (requires libbrotli)
#   - The ptlsbench / test binaries.
#
# Both choices match what `~/dd/quic_1.md` and the design discussion
# committed to.  Adding a backend later is a one-line `if get_option(...)`
# extension here, not a redesign.

project('picotls', 'c',
  version: '0.0.0+ptls-cfe2ea97',  # tracks upstream commit; see docs/quic/vendored.md
  license: 'MIT',
  default_options: [
    'c_std=c11',
    'warning_level=1',
    'default_library=static',
  ],
)

cc = meson.get_compiler('c')

# Vendored upstream headers: exported as `is_system` so the preprocessor marks
# their tokens as system-header. ncc's GC/union passes already skip system
# headers, so picotls's traditional unions are not flagged in this subproject
# nor in any first-party TU that includes them. (picotls won't migrate to
# n00b_variant_t.)
picotls_inc = [
  include_directories('include', is_system: true),
  include_directories('deps/cifra/src/ext', is_system: true),
  include_directories('deps/cifra/src', is_system: true),
  include_directories('deps/micro-ecc', is_system: true),
]

# Quiet picotls-internal warnings that aren't ours to fix.  The upstream
# code is mature and exercised against IETF interop runners; we trust
# its style choices.
ptls_c_args = [
  '-Wno-unused-parameter',
  '-Wno-unused-function',
  '-Wno-unused-variable',
  '-Wno-unused-but-set-variable',
  '-Wno-sign-compare',
  '-Wno-implicit-fallthrough',
  '-Wno-deprecated-declarations',  # Cifra uses some functions that newer libcs deprecate
  '-Wno-unknown-pragmas',
  '-Wno-pointer-sign',
  '-Wno-missing-braces',
  # Linux glibc is stricter about implicit decls than macOS libc.
  # picotls's vendored sources use strdup/syscall without including
  # the right headers in some files; downgrading to warnings keeps
  # vendored-as-is upstream sources building cleanly across platforms.
  '-Wno-error=implicit-function-declaration',
  '-Wno-error=int-conversion',
  '-Wno-error=incompatible-pointer-types',
  '-Wno-implicit-function-declaration',
  '-Wno-int-conversion',
  '-Wno-incompatible-pointer-types',
]
picotls_public_c_args = []
picotls_minicrypto_deps = []

# Vendored upstream code: opt out of ncc's traditional-union deprecation for
# picotls's own .c files (the is_system include path above already covers its
# headers; this covers any union defined directly in a .c). has_argument-guarded
# so a standalone clang build is unaffected (ncc's compiler id reads as "clang").
if cc.has_argument('--ncc-allow-unions')
  ptls_c_args += '--ncc-allow-unions'
endif

if host_machine.system() == 'windows'
  picotls_inc += include_directories('picotlsvs/picotls')
  picotls_public_c_args += ['-D_WINDOWS', '-D_WINDOWS64']
  ptls_c_args += picotls_public_c_args
  if cc.get_id() == 'clang'
    ptls_c_args += ['-fgnuc-version=4.2.1']
  endif
  picotls_minicrypto_deps += cc.find_library('bcrypt')
endif

# Force-include n00b's libc-malloc interposition shim so picotls's libc
# malloc-family calls route into n00b's user pool — required because picotls
# runs on n00b off-libc worker threads where libc malloc traps. See
# include/core/alloc_interpose_shim.h.
ptls_c_args += [
  '-include',
  # libn00b's own source root, computed as ../.. from this vendored picotls
  # subproject. Do NOT use meson.global_source_root(): that resolves to the
  # TOP-LEVEL project's root, which is correct only when libn00b is built
  # standalone. When libn00b is consumed as a subproject (wax, libchalk, etc.),
  # global_source_root is the consumer's root and the shim header is not there.
  meson.current_source_dir() / '..' / '..' / 'include' / 'core' / 'alloc_interpose_shim.h',
]

# ----------------------------------------------------------------------------
# picotls-core
# ----------------------------------------------------------------------------

picotls_core_sources = [
  'lib/picotls.c',
  'lib/hpke.c',
  'lib/pembase64.c',
]

if host_machine.system() == 'windows'
  picotls_core_sources += 'picotlsvs/picotls/wintimeofday.c'
endif

picotls_core_lib = static_library('picotls-core',
  picotls_core_sources,
  include_directories: picotls_inc,
  c_args: ptls_c_args,
)

picotls_core_dep = declare_dependency(
  link_with: picotls_core_lib,
  include_directories: picotls_inc,
  compile_args: picotls_public_c_args,
)

# ----------------------------------------------------------------------------
# picotls-minicrypto
#
# This pulls in cifra (sha256/512, aes, chacha20, gcm, drbg, ...) and
# micro-ecc (uECC for ECDSA / ECDH).  Together they cover everything the
# QUIC keyschedule and TLS 1.3 handshake need.  No OpenSSL, no system
# crypto.
# ----------------------------------------------------------------------------

minicrypto_sources = [
  # micro-ecc
  'deps/micro-ecc/uECC.c',

  # cifra primitives
  'deps/cifra/src/aes.c',
  'deps/cifra/src/blockwise.c',
  'deps/cifra/src/chacha20.c',
  'deps/cifra/src/chash.c',
  'deps/cifra/src/curve25519.c',
  'deps/cifra/src/drbg.c',
  'deps/cifra/src/hmac.c',
  'deps/cifra/src/gcm.c',
  'deps/cifra/src/gf128.c',
  'deps/cifra/src/modes.c',
  'deps/cifra/src/poly1305.c',
  'deps/cifra/src/sha256.c',
  'deps/cifra/src/sha512.c',

  # picotls minicrypto bindings
  'lib/cifra.c',
  'lib/cifra/x25519.c',
  'lib/cifra/chacha20.c',
  'lib/cifra/aes128.c',
  'lib/cifra/aes256.c',
  'lib/cifra/random.c',
  'lib/minicrypto-pem.c',
  'lib/uecc.c',
  'lib/asn1.c',
  'lib/ffx.c',
]

picotls_minicrypto_lib = static_library('picotls-minicrypto',
  minicrypto_sources,
  include_directories: picotls_inc,
  c_args: ptls_c_args,
  link_with: picotls_core_lib,
)

picotls_minicrypto_dep = declare_dependency(
  link_with: [picotls_minicrypto_lib, picotls_core_lib],
  include_directories: picotls_inc,
  compile_args: picotls_public_c_args,
  dependencies: picotls_minicrypto_deps,
)
