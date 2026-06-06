#!/bin/sh

set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 <display_baseline_capture> <display_scene_inspect> <display_backend_selection_report> <display_gui_parity_report> <display_m6_cutover_report> <source_root>" >&2
    exit 1
fi

capture_tool=$1
inspect_tool=$2
selection_tool=$3
parity_tool=$4
cutover_tool=$5
source_root=$6
fixture_root="$source_root/test/fixtures/display/baselines"
tmpdir="${TMPDIR:-/tmp}/n00b-display-m6-artifacts.$$"

cleanup() {
    rm -rf "$tmpdir"
}

check_no_whitespace_errors() {
    status=0
    output=$(git diff --no-index --check -- /dev/null "$1" 2>&1) || status=$?
    if [ "$status" -gt 1 ]; then
        printf '%s\n' "$output" >&2
        return "$status"
    fi
}

baseline_for_artifact() {
    artifact=$1
    platform=$(uname -s | tr '[:upper:]' '[:lower:]')
    platform_path="$fixture_root/m6/$platform/$artifact"

    if [ -f "$platform_path" ]; then
        printf '%s\n' "$platform_path"
    else
        printf '%s\n' "$fixture_root/m6/$artifact"
    fi
}

trap cleanup EXIT HUP INT TERM

rm -rf "$tmpdir"
mkdir -p "$tmpdir"

"$capture_tool" --out-dir "$tmpdir"
"$inspect_tool" --out "$tmpdir/scene_inspect.txt"
"$selection_tool" --out-dir "$tmpdir"
"$parity_tool" --out-dir "$tmpdir"
# Keep the cutover fixture independent of host GUI availability.
env TERM=xterm-256color DISPLAY=:65534 WAYLAND_DISPLAY= "$cutover_tool" --out-dir "$tmpdir"

for artifact in \
    scene_stream.txt \
    table_stream.txt \
    metadata.txt \
    scene_inspect.txt \
    selection_report.txt \
    selection_metadata.txt \
    parity_report.txt \
    parity_metadata.txt \
    cutover_report.txt \
    cutover_metadata.txt
do
    diff -u "$(baseline_for_artifact "$artifact")" \
        "$tmpdir/$artifact"
    check_no_whitespace_errors "$tmpdir/$artifact"
done
