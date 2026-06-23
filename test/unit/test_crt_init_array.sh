#!/bin/sh
set -eu

script=$0
src_root=$1
build_root=$2
target_os=$3
target_arch=$4

case "${target_os}:${target_arch}" in
    darwin:aarch64|darwin:arm64)
        stub=${src_root}/src/crt/n00b_start_macos_arm64.S
        entry_flag=-Wl,-e,_n00b_start
        ;;
    darwin:x86_64)
        stub=${src_root}/src/crt/n00b_start_macos_x64.S
        entry_flag=-Wl,-e,_n00b_start
        ;;
    linux:aarch64|linux:arm64)
        stub=${src_root}/src/crt/n00b_start_linux_arm64.S
        entry_flag=-Wl,-e,n00b_start
        ;;
    linux:x86_64)
        stub=${src_root}/src/crt/n00b_start_linux_x64.S
        entry_flag=-Wl,-e,n00b_start
        ;;
    *)
        echo "unsupported CRT init-array host: ${target_os}:${target_arch}" >&2
        exit 77
        ;;
esac

cc=${N00B_CRT_TEST_CC:-clang}
sdk_args=
if [ "${target_os}" = darwin ] && command -v xcrun >/dev/null 2>&1; then
    cc=$(xcrun --find clang)
    sdk_args="-isysroot $(xcrun --sdk macosx --show-sdk-path)"
fi

out=${build_root}/test_crt_init_array.bin
"${cc}" \
    -std=c23 \
    ${sdk_args} \
    -DN00B_CRT_INIT_ARRAY_ONLY \
    -I"${src_root}/include" \
    -I"${src_root}/src/crt" \
    -nostartfiles \
    "${entry_flag}" \
    "${script%.sh}.c" \
    "${src_root}/src/crt/n00b_crt.c" \
    "${stub}" \
    -o "${out}"

"${out}"
