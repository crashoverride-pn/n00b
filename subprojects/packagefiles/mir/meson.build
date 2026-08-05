project('mir', 'c',
  version: '0.0.0',
  meson_version: '>=1.1.0',
  default_options: ['warning_level=0', 'werror=false'],
)

# n00b's CC is `ncc` (a clang wrapper that performs source-to-source
# transforms). ncc's tokenizer cannot parse the libgcc/clang intrinsic
# headers MIR pulls in transitively on some platforms — notably the
# `__extension__ ((__m64)(__v2si){…})` compound-literal vector casts in
# mmintrin.h when targeting x86_64-w64-windows-gnu. Build MIR with the
# raw clang driver directly, regardless of host, so the project's CC
# does not need to be involved.

python = import('python').find_installation(required: true)
llvm_mingw = run_command(
  python,
  '-c',
  'import os, sys; sys.stdout.write(os.environ.get("LLVM_MINGW") or os.environ.get("N00B_LLVM_MINGW") or "")',
  check: true,
).stdout().strip()

if llvm_mingw != ''
  # Cross-build to Windows (or any time the user has explicitly pointed
  # at an llvm-mingw root): use that clang directly.
  c_cmd = llvm_mingw / 'bin' / 'x86_64-w64-mingw32-clang'
else
  # Native build: use whichever clang is on PATH.
  c_cmd = find_program('clang', required: true).full_path()
endif

mir_c_args = ['-c', '-O2', '-DMIR_PARALLEL_GEN=0', '-w']
if host_machine.system() != 'windows'
  mir_c_args += '-fPIC'
endif

# mir.c and mir-gen.c #include the per-target backend .c files directly (e.g.
# mir-gen.c #includes mir-gen-aarch64.c). custom_target dependency tracking only
# follows the declared `input`, so without listing the #included sources as
# depend_files an edit to a backend file would NOT rebuild the object on an
# incremental build — silently shipping a stale .o. List them all.
mir_internal_deps = files(
  'mir-aarch64.c', 'mir-ppc64.c', 'mir-s390x.c', 'mir-riscv64.c',
  'mir-x86_64.c', 'mir-interp.c',
  'mir-gen-aarch64.c', 'mir-gen-ppc64.c', 'mir-gen-s390x.c',
  'mir-gen-riscv64.c', 'mir-gen-x86_64.c', 'mir-gen-stub.c',
  'mir.h', 'mir-gen.h', 'mir-aarch64.h', 'mir-ppc64.h', 'mir-s390x.h',
  'mir-riscv64.h', 'mir-x86_64.h', 'mir-alloc.h', 'mir-code-alloc.h',
  'mir-bitmap.h', 'mir-dlist.h', 'mir-hash.h', 'mir-htab.h', 'mir-reduce.h',
  'mir-varr.h',
)

mir_o = custom_target('mir_o',
  input: 'mir.c',
  output: 'mir.c.o',
  depend_files: mir_internal_deps,
  command: [c_cmd, mir_c_args, '-o', '@OUTPUT@', '@INPUT@'],
)

mir_gen_o = custom_target('mir_gen_o',
  input: 'mir-gen.c',
  output: 'mir-gen.c.o',
  depend_files: mir_internal_deps,
  command: [c_cmd, mir_c_args, '-o', '@OUTPUT@', '@INPUT@'],
)

mir_lib = static_library('mir', objects: [mir_o, mir_gen_o])

mir_dep = declare_dependency(
  link_with: mir_lib,
  # Vendored upstream header (mir.h): exported as `is_system` so ncc treats it
  # like a system header and never flags its unions in first-party TUs that
  # include it (e.g. src/slay/codegen.c). mir compiles with clang via a custom
  # command, so it never runs ncc's union pass itself.
  include_directories: include_directories('.', is_system: true),
)
