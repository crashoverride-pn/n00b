# src/aws/meson.build — libn00b_aws C wrap over the aws-sdk-rust
# `n00b-aws-shim` cdylib. See [[project_n00b_aws_via_rust_shim]] in
# the SKP auto-memory for the why.
#
# Build flow (Rust-shim path):
#   1. Run `cbindgen --config cbindgen.toml --crate n00b_aws_shim`
#      against the shim source. cbindgen reads `src/lib.rs` + its
#      submodules and emits `n00b_aws_shim_generated.h` with typed
#      `extern` declarations using `<stdint.h>` types.
#   2. Compile the per-service C wrap (`n00b_aws_<service>.c`),
#      including the generated header.
#   3. Link the resulting static library against the shim cdylib via
#      `aws_shim_lib_dep`.
#
# The shim cdylib is the runtime + link-time dependency. demangle is
# NOT in the loop for this path (it segfaults on aws-sdk-rust's
# DWARF; cbindgen reads source directly).

# cbindgen needs to re-run when any Rust source under the shim crate
# changes. meson's `depend_files` walks the listed paths and adds
# them to ninja's dependency graph without going through `files()`
# (which is sandbox-restricted to the current subproject).
aws_generated_header = custom_target(
  'n00b_aws_shim_generated.h',
  output:  'n00b_aws_shim_generated.h',
  command: [
    cbindgen_bin,
    '--config', aws_shim_crate_root / 'cbindgen.toml',
    '--crate',  'n00b_aws_shim',
    '--output', '@OUTPUT@',
    aws_shim_crate_root,
  ],
  depend_files: [
    aws_shim_crate_root / 'Cargo.toml',
    aws_shim_crate_root / 'cbindgen.toml',
    aws_shim_crate_root / 'src' / 'lib.rs',
    aws_shim_crate_root / 'src' / 'runtime.rs',
    aws_shim_crate_root / 'src' / 'config.rs',
    aws_shim_crate_root / 'src' / 'sts.rs',
    aws_shim_crate_root / 'src' / 'sqs.rs',
    aws_shim_crate_root / 'src' / 'sns.rs',
    aws_shim_crate_root / 'src' / 's3.rs',
  ],
  build_by_default: true,
)

n00b_aws_src = []  # services added per-service below; first is STS.

# Service wrap files are listed individually so per-service builds
# stay legible. Each one consumes `aws_generated_header` for the
# typed extern declarations and the n00b umbrella for n00b types.
if fs.exists(meson.current_source_dir() / 'n00b_aws_sts.c')
  n00b_aws_src += files('n00b_aws_sts.c')
endif
if fs.exists(meson.current_source_dir() / 'n00b_aws_sqs.c')
  n00b_aws_src += files('n00b_aws_sqs.c')
endif
if fs.exists(meson.current_source_dir() / 'n00b_aws_sns.c')
  n00b_aws_src += files('n00b_aws_sns.c')
endif
if fs.exists(meson.current_source_dir() / 'n00b_aws_s3.c')
  n00b_aws_src += files('n00b_aws_s3.c')
endif

if n00b_aws_src.length() > 0
  n00b_aws_lib = static_library(
    'n00b_aws',
    n00b_aws_src,
    [aws_generated_header],
    include_directories: incdir,
    c_args:   exe_c_args,
    link_args: link_args,
    install:  true,
  )

  n00b_aws_dep = declare_dependency(
    sources:             [aws_generated_header],
    include_directories: incdir,
    link_with:           [n00b_aws_lib],
    dependencies:        [aws_shim_lib_dep],
  )
else
  # Header generation still runs (build_by_default: true above) so the
  # generated header lives in the build dir for any consumer that wants
  # to peek at the available shim symbols, but the library doesn't
  # exist until the first wrap source file lands.
  n00b_aws_dep = declare_dependency(
    sources:             [aws_generated_header],
    include_directories: incdir,
    dependencies:        [aws_shim_lib_dep],
  )
endif
