# rocs wax cache demo

WP-013 packages the wax event cache as a local rocs demo. The normal entrypoint
is the `wax` command:

```sh
wax ingest /path/to/wax-normalized-capture.ndjson
wax search codex --format table
wax search --kind file.modify --format jsonl
wax status
wax stop
```

`wax ingest` and `wax search` start the local rocs daemon automatically when it
is not already ready. By default that daemon listens on
`http://127.0.0.1:8080`, uses the `wax.normalized.v1` schema, stores rocs data
under `$XDG_CACHE_HOME/n00b/wax/rocs`, and writes daemon state under
`$XDG_STATE_HOME/n00b/wax`.

If you already have a compatible local service running, `wax` uses it directly.
Point at a non-default local service with:

```sh
wax search codex --server-url http://127.0.0.1:9090 --format table
```

For an isolated local daemon on a non-default port, also pass the listen
address and optional scratch directories:

```sh
wax search codex \
  --server-url http://127.0.0.1:9090 \
  --http-addr 127.0.0.1:9090 \
  --cache-dir /private/tmp/wax-rocs \
  --state-dir /private/tmp/wax-state
```

`wax` reads an optional TOML config file at `$XDG_CONFIG_HOME/n00b/wax.toml`.
The parser expects flat keys:

```toml
server_url = "http://127.0.0.1:8080"
http_addr = "127.0.0.1:8080"
cache_dir = "/private/tmp/wax-rocs"
state_dir = "/private/tmp/wax-state"
store_name = "wax"
```

Command-line flags override TOML. The most common overrides are `--config`,
`--server-url`, `--http-addr`, `--cache-dir`, `--state-dir`, `--service-bin`,
and `--cache-bin`.

## Build and smoke

From the repository root:

```sh
NCC_PATH=/usr/local/bin/ncc N00B_TEST=1 N00B_SKIP_VCS_CHECK=1 \
N00B_BUILD_TARGETS='test_rocs_wax_demo_smoke test_rocs_wax_live test_rocs_wax_cli test_rocs_wax_daemon test_rocs_wax_schema test_rocs_service_smoke n00b-rocs-wax-cache n00b-rocs-service wax' \
N00B_TESTS='rocs_wax_demo_smoke rocs_wax_gateway_optional rocs_wax_live rocs_wax_cli rocs_wax_daemon rocs_wax_schema rocs_service_smoke wax_tool_help' \
bash ./build.sh /private/tmp/n00b_rocs_wax_demo
```

`rocs_wax_demo_smoke` runs the end-to-end fixture demo. It creates a temporary
service-local rocs cache, replays checked-in wax events, runs finite searches,
runs fixture-backed live search, and cleans up its temporary cache directory.

`rocs_wax_gateway_optional` exits with Meson skip status when
`ROCS_WAX_GATEWAY_NDJSON` is unset. When set, it treats the value as a
line-oriented `wax.normalized.v1` capture and replays it through the same cache
command. The optional path is for local gateway captures only; it is not a
mandatory validation gate.

## Lower-level cache command

The `wax` command is the normal interactive path. The cache command also
supports direct local-store mode for tests and one-shot demos.

Local-store mode uses normal rocs service-local store configuration:

```sh
export ROCS_PROFILE=service_local
export ROCS_NAME=rocs-wax-demo
export ROCS_CACHE_DIR=/private/tmp/rocs-wax-demo-cache
```

Replay the repository fixture into a durable local cache:

```sh
/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --run-fixture test/unit/data/rocs_wax/daemon_events.ndjson \
  /private/tmp/rocs-wax-demo-cache/checkpoint.txt
```

The command reports accepted, rejected, and checkpointed lines. Valid records
are written through rocs store ingest and flushed before accepted-line
checkpoint advancement. Malformed or unsupported lines are counted and
checkpointed without mutating the store so a replay cannot loop forever on the
same poison input.

## Finite search

Search the existing cache with documented flags:

```sh
/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --search --contains codex --format jsonl

/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --search --kind file.modify --format table

/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --search --field-eq quality=degraded --limit 10 --format text
```

Supported filters are `--kind`, `--class`, `--family`, `--event-id`,
`--contains`, `--field-eq FIELD=VALUE`, `--time-from`, and `--time-to`.
Ordering is `--order durable` by default, with `--order ranked` available for
finite search. Output formats are `text`, `table`, and `jsonl`.

## Live fixture mode

Live mode opens a rocs live query view before replaying the live fixture, then
emits historical matches followed by newly cached matching events:

```sh
/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --search --live \
  --live-fixture test/unit/data/rocs_wax/live_events.ndjson \
  --contains codex \
  --format jsonl
```

The live command reports source lines, accepted events, rejected lines,
delivered rows, dropped-output accounting, and the next resume token on stderr.
Use that token to suppress duplicate delivery on the next run:

```sh
/private/tmp/n00b_rocs_wax_demo/n00b-rocs-wax-cache \
  --search --live --resume "$ROCS_WAX_RESUME" --contains codex
```

Live search is durable-ordered. Ranked live output is rejected because ranked
scoring remains a finite snapshot behavior. Server mode currently supports
finite replay and finite search through `/v1/records` and `/v1/query`; live
HTTP streaming is not part of this demo surface, so `--server --search --live`
is rejected.

## Optional gateway capture

The rocs demo does not start or manage the privileged wax gateway. For a local
gateway experiment, use the wax tree under `/Users/viega/wax` to produce a
line-oriented normalized event capture, then replay that capture through the
same command:

```sh
export ROCS_WAX_GATEWAY_NDJSON=/path/to/wax-normalized-capture.ndjson
NCC_PATH=/usr/local/bin/ncc N00B_TEST=1 N00B_SKIP_VCS_CHECK=1 \
N00B_BUILD_TARGETS='test_rocs_wax_demo_smoke n00b-rocs-wax-cache' \
N00B_TESTS='rocs_wax_gateway_optional' \
bash ./build.sh /private/tmp/n00b_rocs_wax_gateway_optional
```

If the capture is absent, unreadable, or contains no accepted normalized
events, the optional smoke skips or fails without affecting mandatory
fixture-backed validation.

## Failure modes

- Missing or invalid store config returns a deterministic command error before
  ingest starts.
- Missing fixture or checkpoint read/write failure is surfaced as a wax source
  or checkpoint error.
- Unsupported schema lines and malformed JSON are counted as rejected events and
  do not mutate the store.
- Server mode reports a connection or non-2xx HTTP response as a deterministic
  command error.
- Store flush or close failure stops the command with a non-zero exit.
- Live mode terminates after fixture EOF in tests; a resume token reports the
  last delivered durable position.
- Temporary cache directories created by the smoke are removed after the test.
