#!/usr/bin/env bash
# Build and optionally test n00b inside a Linux Docker container.
#
# MOUNT-BASED + INCREMENTAL (WP-001 Phase 0).  The project tree is mounted
# READ-WRITE at /src (NOT copied), and the Linux artifacts persist on the host
# across container runs so repeat builds are incremental:
#
#   build_linux/                       — the Linux n00b build dir
#   subprojects/ncc/build_linux/       — the Linux ncc build dir
#
# Both are gitignored (`**/build*/`, `/subprojects/ncc/`).  macOS `build.sh`
# uses build_debug/build_release and never touches build_linux, so the macOS
# and Linux trees coexist in one checkout.  The tree is mounted rw because the
# unicode build step writes a cache into the source tree
# (src/text/unicode/.unicode_cache, gitignored and shared with macOS builds).
#
# Usage:
#   bash docker/linux-build.sh                          # incremental build
#   N00B_TEST=1 bash docker/linux-build.sh              # build + test
#   N00B_TEST=1 N00B_TEST_FAIL_FAST=1 bash docker/linux-build.sh
#   N00B_TEST=1 N00B_TEST_SUITES="n00b:unit" bash docker/linux-build.sh
#   N00B_TEST=1 N00B_TESTS="n00b:parquet_flat n00b:http_service" bash docker/linux-build.sh
#   N00B_BUILD_TARGETS="test_parquet_flat" N00B_TEST=1 N00B_TESTS="n00b:parquet_flat" bash docker/linux-build.sh
#   N00B_CLEAN=1 N00B_TEST=1 bash docker/linux-build.sh # force clean rebuild + test
#   N00B_JOBS=4 bash docker/linux-build.sh              # limit parallelism (default: 2)
#   NCC_REV=<commit|bookmark> bash docker/linux-build.sh # pin ncc (default: upstream main)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="n00b-linux"

# NOTE: ncc is NOT required in subprojects/ here.  The container clones and
# tracks crashappsec/ncc upstream `main` itself (via jj) into the persistent
# docker/_linux_ncc/ dir and builds it there — independent of the host's
# (out-of-tree) ncc.  See docker/linux-container-build.sh.

echo "=== Building Docker image ($IMAGE_NAME) ==="
# Ensure sdk/ dir exists (Dockerfile COPY requires it, even when empty)
mkdir -p "$SCRIPT_DIR/sdk"
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

DOCKER_MEM="${N00B_DOCKER_MEM:-8g}"

echo "=== Running build inside container (mount-based, incremental) ==="
# Tree mounted READ-WRITE so build_linux/, subprojects/ncc/build_linux/, and the
# in-tree unicode cache persist on the host between runs.  N00B_CLEAN is passed
# through (default 0) so a normal run is incremental; set N00B_CLEAN=1 to force a
# clean rebuild.
docker run --rm \
    --memory="${DOCKER_MEM}" \
    --memory-swap="${DOCKER_MEM}" \
    -v "$PROJECT_ROOT:/src" \
    -e N00B_TEST="${N00B_TEST:-0}" \
    -e N00B_TEST_FAIL_FAST="${N00B_TEST_FAIL_FAST:-0}" \
    -e N00B_TEST_SUITES="${N00B_TEST_SUITES:-}" \
    -e N00B_TEST_NO_SUITES="${N00B_TEST_NO_SUITES:-}" \
    -e N00B_TESTS="${N00B_TESTS:-}" \
    -e N00B_BUILD_TARGETS="${N00B_BUILD_TARGETS:-}" \
    -e N00B_CLEAN="${N00B_CLEAN:-0}" \
    -e NCC_REV="${NCC_REV:-}" \
    -e N00B_NATIVE=1 \
    -e N00B_SKIP_VCS_CHECK=1 \
    -e N00B_KEEP_GOING="${N00B_KEEP_GOING:-0}" \
    -e N00B_BUILD_TYPE="${N00B_BUILD_TYPE:-debug}" \
    -e N00B_JOBS="${N00B_JOBS:-2}" \
    -e CC=clang \
    "$IMAGE_NAME" \
    bash /src/docker/linux-container-build.sh
