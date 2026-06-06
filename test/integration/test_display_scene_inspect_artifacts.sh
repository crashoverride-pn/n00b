#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <display_scene_inspect> <source_root>" >&2
    exit 1
fi

inspect_tool=$1
source_root=$2
fixture_root="$source_root/test/fixtures/display/baselines"
tmpdir="${TMPDIR:-/tmp}/n00b-display-scene-inspect.$$"
outfile="$tmpdir/scene_inspect.txt"

cleanup() {
    rm -rf "$tmpdir"
}

trap cleanup EXIT HUP INT TERM

rm -rf "$tmpdir"
mkdir -p "$tmpdir"

if "$inspect_tool" >/dev/null 2>&1; then
    echo "expected $inspect_tool to require --out" >&2
    exit 1
fi

"$inspect_tool" --out "$outfile"

diff -u "$fixture_root/m1/scene_inspect.txt" \
    "$outfile"
