#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <display_baseline_capture> <display_terminal_replay> <source_root>" >&2
    exit 1
fi

capture_tool=$1
replay_tool=$2
source_root=$3
fixture_root="$source_root/test/fixtures/display/baselines"
tmpdir="${TMPDIR:-/tmp}/n00b-display-terminal-replay.$$"

cleanup() {
    rm -rf "$tmpdir"
}

trap cleanup EXIT HUP INT TERM

rm -rf "$tmpdir"
mkdir -p "$tmpdir"

if "$replay_tool" >/dev/null 2>&1; then
    echo "expected $replay_tool to require --out-dir" >&2
    exit 1
fi

"$capture_tool" --out-dir "$tmpdir"
cp "$tmpdir/metadata.txt" "$tmpdir/metadata.before-replay.txt"

"$replay_tool" --out-dir "$tmpdir"

diff -u "$tmpdir/metadata.before-replay.txt" "$tmpdir/metadata.txt"
diff -u "$fixture_root/m2/scene_stream.txt" \
    "$tmpdir/scene_stream.txt"
diff -u "$fixture_root/m2/table_stream.txt" \
    "$tmpdir/table_stream.txt"
diff -u "$fixture_root/m2/metadata.txt" \
    "$tmpdir/metadata.txt"
diff -u "$fixture_root/m2/terminal_replay.txt" \
    "$tmpdir/terminal_replay.txt"
diff -u "$fixture_root/m2/terminal_replay_metadata.txt" \
    "$tmpdir/terminal_replay_metadata.txt"
