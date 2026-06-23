#!/bin/sh

set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <display_baseline_capture> <display_scene_inspect> <display_m4_showcase> <n00b_table> <source_root>" >&2
    exit 1
fi

capture_tool=$1
inspect_tool=$2
showcase_tool=$3
table_tool=$4
source_root=$5
fixture_root="$source_root/test/fixtures/display/baselines"
tmpdir="${TMPDIR:-/tmp}/n00b-display-m4-artifacts.$$"

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

trap cleanup EXIT HUP INT TERM

rm -rf "$tmpdir"
mkdir -p "$tmpdir"

"$capture_tool" --out-dir "$tmpdir"
"$inspect_tool" --out "$tmpdir/scene_inspect.txt"
"$showcase_tool" --out-dir "$tmpdir"
printf 'Component,State\nwidget,ready\nhexdump,formatted\n' | \
    env -u NO_COLOR "$table_tool" --style simple > "$tmpdir/table_cli.txt"

for artifact in \
    scene_stream.txt \
    table_stream.txt \
    metadata.txt \
    scene_inspect.txt \
    showcase_stream.txt \
    hexdump_stream.txt \
    showcase_metadata.txt \
    table_cli.txt
do
    diff -u "$fixture_root/m4/$artifact" \
        "$tmpdir/$artifact"
    check_no_whitespace_errors "$tmpdir/$artifact"
done
