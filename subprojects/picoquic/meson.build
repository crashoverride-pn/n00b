# meson.build — picoquic (QUIC transport state machine) shim for n00b.
#
# This shim is **n00b-authored**, not from upstream.  Upstream picoquic
# ships CMake; this provides a meson wrapper.
#
# Backend selection (see docs/quic/vendored.md): minicrypto only.
# - picoquic_ptls_minicrypto.c is included.
# - picoquic_ptls_openssl.c, picoquic_ptls_fusion.c, and
#   picoquic_mbedtls.c are excluded.  Adding any of them is a one-line
#   extension here, but Phase 1 favors a tighter dep closure.
#
# Other deliberate exclusions:
# - loglib (qlog writers) ships separately; we'll wrap it when the qlog
#   module lands.
# - picohttp / picoquicfirst / pqbench / picoquicdemo / tests are
#   binaries/tests we do not need from this shim.

project('picoquic', 'c',
  version: '1.1.48.0+pq-f54239a3',  # tracks upstream commit; see docs/quic/vendored.md
  license: 'BSD-3-Clause',
  default_options: [
    'c_std=c11',
    'warning_level=1',
    'default_library=static',
  ],
)

cc = meson.get_compiler('c')

picotls_proj = subproject('picotls')
picotls_minicrypto_dep = picotls_proj.get_variable('picotls_minicrypto_dep')
picotls_core_dep       = picotls_proj.get_variable('picotls_core_dep')

# picoquic itself
# Vendored upstream headers: exported as `is_system` so ncc treats them like
# system headers and never flags their traditional unions (in this subproject
# or in first-party TUs that include them). picoquic won't migrate to
# n00b_variant_t.
picoquic_inc = [
  include_directories('picoquic', is_system: true),
  include_directories('loglib', is_system: true),
]

# loglib — qlog writers + supporting plumbing.  Required because
# picoquic_config.c and picoquic_sockloop.c reference picoquic_set_qlog,
# which lives in qlog_fns.c.
picoquic_loglib_files = [
  'loglib/autoqlog.c',
  'loglib/cidset.c',
  'loglib/csv.c',
  'loglib/logconvert.c',
  'loglib/logreader.c',
  'loglib/memory_log.c',
  'loglib/qlog.c',
  'loglib/qlog_frames.c',
  'loglib/qlog_fns.c',
  'loglib/svg.c',
]

picoquic_library_files = [
  'picoquic/bbr.c',
  'picoquic/bbr1.c',
  'picoquic/bytestream.c',
  'picoquic/cc_common.c',
  'picoquic/config.c',
  'picoquic/cubic.c',
  'picoquic/c4.c',
  'picoquic/ech.c',
  'picoquic/error_names.c',
  'picoquic/fastcc.c',
  'picoquic/frames.c',
  'picoquic/frame_names.c',
  'picoquic/intformat.c',
  'picoquic/logger.c',
  'picoquic/logwriter.c',
  'picoquic/loss_recovery.c',
  'picoquic/newreno.c',
  'picoquic/pacing.c',
  'picoquic/packet.c',
  'picoquic/packet_names.c',
  'picoquic/paths.c',
  'picoquic/performance_log.c',
  'picoquic/picohash.c',
  'picoquic/picoquic_lb.c',
  # Backend selection: minicrypto only.
  'picoquic/picoquic_ptls_minicrypto.c',
  'picoquic/picosocks.c',
  'picoquic/picosplay.c',
  'picoquic/port_blocking.c',
  'picoquic/prague.c',
  'picoquic/quicctx.c',
  'picoquic/register_all_cc_algorithms.c',
  'picoquic/sacks.c',
  'picoquic/sender.c',
  'picoquic/sim_link.c',
  'picoquic/dualq_aqm.c',
  'picoquic/siphash.c',
  'picoquic/sockloop.c',
  'picoquic/spinbit.c',
  'picoquic/ticket_store.c',
  'picoquic/timing.c',
  'picoquic/token_store.c',
  'picoquic/tls_api.c',
  'picoquic/tp_names.c',
  'picoquic/transport.c',
  'picoquic/unified_log.c',
  'picoquic/util.c',
]

# Backend selection flags — explicit opt-out for OpenSSL and Fusion;
# mbedtls is opt-in via PICOQUIC_WITH_MBEDTLS so leaving it undefined
# is the right choice.
picoquic_backend_defs = [
  '-DPTLS_WITHOUT_OPENSSL',
  '-DPTLS_WITHOUT_FUSION',
]
picoquic_public_c_args = []

# Quiet picoquic-internal warnings.  Upstream is mature; we don't fix style.
picoquic_c_args = picoquic_backend_defs + [
  '-Wno-unused-parameter',
  '-Wno-unused-function',
  '-Wno-unused-variable',
  '-Wno-unused-but-set-variable',
  '-Wno-sign-compare',
  '-Wno-implicit-fallthrough',
  '-Wno-deprecated-declarations',
  '-Wno-unknown-pragmas',
  '-Wno-pointer-sign',
  '-Wno-missing-braces',
  '-Wno-missing-field-initializers',
  '-Wno-cast-function-type',
  '-Wno-strict-prototypes',
]
# Vendored upstream code: opt out of ncc's traditional-union deprecation for
# picoquic's own .c files (the is_system include path above already covers its
# headers). has_argument-guarded so a standalone clang build is unaffected
# (ncc's compiler id reads as "clang").
if cc.has_argument('--ncc-allow-unions')
  picoquic_c_args += '--ncc-allow-unions'
endif
# On Linux, picoquic's picosocks.c uses `struct in_pktinfo` and
# `pthread_rwlockattr_t` / `pthread_spinlock_t` which are gated behind
# `_GNU_SOURCE` in glibc.  Macs default to having these visible without
# the feature-test macro; Linux doesn't.  Add the macro globally to the
# picoquic compile so the vendored-as-is sources build cross-platform.
if host_machine.system() == 'linux'
  picoquic_c_args += ['-D_GNU_SOURCE']
endif
if host_machine.system() == 'windows'
  picoquic_public_c_args += ['-D_WINDOWS', '-D_WINDOWS64']
  picoquic_c_args += picoquic_public_c_args
endif

# Force-include n00b's libc-malloc interposition shim so picoquic's libc
# malloc-family calls route into n00b's user pool — required because picoquic
# runs on n00b off-libc worker threads where libc malloc traps (this is the
# sender.c:271 SIGTRAP). See include/core/alloc_interpose_shim.h.
picoquic_c_args += [
  '-include',
  # libn00b's own source root, computed as ../.. from this vendored picoquic
  # subproject. Do NOT use meson.global_source_root(): that resolves to the
  # TOP-LEVEL project's root, which is correct only when libn00b is built
  # standalone. When libn00b is consumed as a subproject (wax, libchalk, etc.),
  # global_source_root is the consumer's root and the shim header is not there.
  meson.current_source_dir() / '..' / '..' / 'include' / 'core' / 'alloc_interpose_shim.h',
]

threads_dep = dependency('threads')

picoquic_core_lib = static_library('picoquic-core',
  picoquic_library_files + picoquic_loglib_files,
  include_directories: picoquic_inc,
  c_args: picoquic_c_args,
  dependencies: [picotls_minicrypto_dep, picotls_core_dep, threads_dep],
)

picoquic_core_dep = declare_dependency(
  link_with: picoquic_core_lib,
  include_directories: picoquic_inc,
  compile_args: picoquic_public_c_args,
  dependencies: [picotls_minicrypto_dep, picotls_core_dep, threads_dep],
)
