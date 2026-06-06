#!/bin/sh

set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <display_baseline_capture> <display_scene_inspect> <display_backend_selection_report> <widget_demo> <source_root>" >&2
    exit 1
fi

capture_tool=$1
inspect_tool=$2
selection_tool=$3
widget_demo=$4
source_root=$5
fixture_root="$source_root/test/fixtures/display/baselines"
tmpdir="${TMPDIR:-/tmp}/n00b-display-m5-artifacts.$$"

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
"$selection_tool" --out-dir "$tmpdir"

for artifact in \
    scene_stream.txt \
    table_stream.txt \
    metadata.txt \
    scene_inspect.txt \
    selection_report.txt \
    selection_metadata.txt
do
    diff -u "$fixture_root/m5/$artifact" \
        "$tmpdir/$artifact"
    check_no_whitespace_errors "$tmpdir/$artifact"
done

env N00B_RENDERER_BACKEND=stream \
    "$widget_demo" --widget label --backend ansi \
    >"$tmpdir/widget_explicit.out" 2>"$tmpdir/widget_explicit.err"
grep -Fx "Backend request 'ansi' selected 'ansi'" "$tmpdir/widget_explicit.err"

env N00B_RENDERER_BACKEND=stream \
    "$widget_demo" --widget label --backend auto \
    >"$tmpdir/widget_auto.out" 2>"$tmpdir/widget_auto.err"
grep -Fx "Backend request 'auto' selected 'stream'" "$tmpdir/widget_auto.err"

"$widget_demo" --widget label --backend stream \
    >"$tmpdir/widget_stream.out" 2>"$tmpdir/widget_stream.err"
[ -s "$tmpdir/widget_stream.out" ]

"$widget_demo" --widget label --backend dumb \
    >"$tmpdir/widget_dumb.out" 2>"$tmpdir/widget_dumb.err"
[ -s "$tmpdir/widget_dumb.out" ]
