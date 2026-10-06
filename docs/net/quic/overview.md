# QUIC module — overview

n00b's QUIC module (`include/net/quic/`, `src/net/quic/`) is an opinionated
transport library targeting the use case described in
`~/dd/quic-libs-design.md`: an authenticated, multiplexed QUIC
transport on top of which higher-level protocols (HTTP/3, RPC) ride.

The full design is in `~/dd/quic_1.md`.  This file is the in-tree
overview — what's currently shipped, how the pieces fit together,
how to use what's there today.

## Layered architecture

```
+------------------------------------------------------------+
|  H3 (Phase 4)              |  RPC (Phase 4)                |
+----------------------------+-------------------------------+
|  Transport: endpoint, conn, channels  ✓                    |
|    accept-topic, recv path, qlog, stats  ✓                 |
|  Wire framer (varint + 1-byte type tag)  ✓                 |
+------------------------------------------------------------+
|  picoquic + picotls (vendored, minicrypto-only)  ✓         |
+------------------------------------------------------------+
|  conduit IO loop + UDP datagram socket  ✓                  |
|  conduit_pool allocator                                    |
+------------------------------------------------------------+
|  n00b runtime: arenas, GC, futexes, rwlocks                |
+------------------------------------------------------------+
```

H3 and RPC are **siblings**, not stacked: a build can ship one
without the other.  Both ride the same transport.

## What's currently in tree

### Wire framer — `include/net/quic/framer.h`

Length-prefixed, type-tagged byte frames:

```
+-----------------+----------+-----------+
| varint(len)     | u8 type  | payload[] |
+-----------------+----------+-----------+
```

- `varint(len)` is RFC 9000 §16; encodes payload length only.
- `type` partitions: `0x00–0x3f` transport, `0x40–0x7f` H3,
  `0x80–0xbf` RPC, `0xc0–0xff` unassigned.
- `max_size` cap (default 16 MiB) on total encoded frame.

Public entries: `n00b_quic_varint_size`, `_encode`, `_decode`,
`n00b_quic_frame_emit`, `n00b_quic_frame_parse`.  17 unit tests
across `test_quic_framer.c` and `test_quic_framer_fuzz.c` cover
roundtrip, varint class boundaries, oversize rejection, truncated
input, multi-frame back-to-back, max_size on emit + parse,
null-arg, plus 2000+ random-fuzzing iterations and adversarial
truncation/length-overflow strategies.

### UDP datagram conduit — `include/conduit/socket_udp.h`

Net-new IO primitive in the conduit module:

- `n00b_conduit_udp_bind(c, io, host, port)` — bind, register with
  IO backend, set up a typed recv topic.
- Recv topic carries `n00b_conduit_udp_datagram_t` (peer addr +
  payload bytes + timestamp).
- `n00b_conduit_udp_send(u, peer, peer_len, bytes, len)` —
  non-blocking sendto.  Required extending the IO target variant
  from 2-tag (fd_owner / listener) to 3-tag (+ udp).

### Common types — `include/net/quic/quic_types.h`

Opaque public handles for endpoint / conn / chan / trust / secret.
Channel kind / state enums.  CC algorithm enum.  Error codes
(`n00b_quic_err_t`) + `n00b_quic_err_str`.  Frame namespace
constants.  Stream budget defaults (100/100, validated by perf
harness — see `stream_budgets.md`).

### Endpoint — `include/net/quic/endpoint.h`

A UDP socket plus a picoquic context.

- `n00b_quic_endpoint_new(c, io, .listen, .bind_host, .bind_port,
  .alpn, .trust, .cert, .key, .qlog_dir, .cert_der_bytes,
  .cert_der_len, .key_pem_path)` — kwargs-driven constructor.
- `n00b_quic_endpoint_run_once(ep, timeout_ms)` — drive one IO
  iteration: poll the conduit, drain UDP recv into picoquic, drain
  picoquic outbound, send.
- `n00b_quic_endpoint_accept_topic(ep)` — server-side accept
  events.  Each new picoquic-accepted cnx is wrapped as
  `n00b_quic_conn_t` and published once with payload
  `n00b_quic_accept_event_t`.
- `n00b_quic_endpoint_close`: idempotent. Handles live in
  `conduit_pool`, which the collector does not reclaim per object, so a
  handle dropped without closing keeps its socket and picoquic state.
- `n00b_quic_endpoint_stats` — per-endpoint packet counters.
- `n00b_quic_endpoint_local_port` — bound port (useful when port=0
  selected an ephemeral port).

### Connection — `include/net/quic/conn.h`

One QUIC connection = one peer = one TLS session.

- `n00b_quic_connect(ep, remote_addr, sni, .timeout_ms,
  .alpn_pref, .zero_rtt)` — outbound.
- Server-side: created automatically by the endpoint's
  accept-default callback when picoquic accepts an Initial.
  Surfaces via the accept topic.
- `n00b_quic_close(conn, app_err, .reason)` — ordered close.
- `n00b_quic_conn_state(conn)` — coarse-grained
  CONNECTING / CONNECTED / CLOSING / CLOSED / FAILED projection
  over picoquic's 17 fine-grained states.
- `n00b_quic_conn_stats(conn)` — RTT, RTT variance, cwnd,
  bytes_in_flight, packets_sent / lost, channels_open / total,
  bytes_sent / received, CC algo.
- `n00b_quic_conn_first_chan(conn)` — head of intrusive channel
  list (use with `n00b_quic_chan_next_in_conn` to walk).
- Server conns auto-unlinked from `endpoint->accepted` on
  `picoquic_callback_close` so long-lived servers don't leak.
- Released only by `n00b_quic_close`; a dropped handle is not reclaimed.

### Channel — `include/net/quic/chan.h`

One channel = one QUIC stream + n00b's framing semantics.

- `n00b_quic_chan_open(conn, .kind, .bidi, .zero_rtt)` —
  outbound; client picks the stream ID via picoquic.
- Server-side channels auto-created by `_n00b_quic_conn_default_callback`
  when peer-initiated streams arrive; bidi/uni inferred from
  RFC 9000 §2.1 stream-ID parity.
- `n00b_quic_chan_send(chan, bytes, len, .fin)` — bounded, never
  blocks.
- `n00b_quic_chan_recv(chan, out, max)` — pull-style; returns
  what's currently in the per-channel recv buffer.
  `n00b_quic_chan_has_data` and `n00b_quic_chan_recv_fin` for
  predicates.
- `n00b_quic_chan_reset(chan, app_err)`,
  `n00b_quic_chan_stop_sending(chan, app_err)`,
  `n00b_quic_chan_close(chan)` — terminal state primitives.
- `n00b_quic_chan_state(chan)` — observable state:
  OPEN → SEND_HALF_CLOSED / RECV_HALF_CLOSED → CLOSED, with
  LOCAL_RESET / PEER_RESET as alternates.
- `n00b_quic_chan_stats(chan)` — bytes_sent / bytes_received /
  state / kind / bidi / app_err codes / last_activity_ns.
- Recv events come from picoquic's per-cnx callback; STREAM_DATA
  bytes accumulate in a per-channel recv buffer (geometric grow,
  conduit-pool no_scan).
- Released only by `n00b_quic_chan_close`; a dropped handle is not
  reclaimed.

### Trust — `include/net/quic/trust.h`

OS-native cert verification, plus a test-only pinned-fingerprint
backend.

- `n00b_quic_trust_pinned(fingerprint)` — ships, test-only.
- `n00b_quic_trust_system()` — declared, returns NOT_IMPLEMENTED
  pending the picotls verify-callback bridge (Phase 3).
- `n00b_quic_trust_with_extra` — same.
- **No `n00b_quic_trust_disabled()` and no `--insecure`.**
  Connections that can't verify don't come up — except via the
  test-only `picoquic_set_null_verifier(client->quic)` in the test
  + example, which goes away when the bridge ships.

### Secret — `include/net/quic/secret.h`

Handle-based secret API.

- `n00b_quic_secret_open(uri)` — provider routing on URI scheme.
- `ephemeral:<label>` — in-memory test-only provider; ships.
- `keychain:`, `libsecret:`, `pkcs11:`, `tpm:`, etc. — stubbed
  with NOT_IMPLEMENTED pending Phase 1.5 / Phase 3 work.
- `env:` and `file:` are explicitly **refused** per the design.
- `n00b_quic_secret_format(s)` — opaque tag string; never
  stringifies the underlying material.

### qlog — kwarg on endpoint

`n00b_quic_endpoint_new(.qlog_dir = "/tmp/qlog")` calls picoquic's
qlog writer and produces one .qlog file per accepted/initiated
cnx.  Use with `qvis` (https://qvis.quictools.info/) for visual
handshake / loss analysis.

## Test coverage

| File | Sub-tests | What |
|---|---:|---|
| `test_quic_framer.c` | 12 | Round-trip, boundaries, max_size, multi-frame, null-arg |
| `test_quic_framer_fuzz.c` | 5 | 2000 random + 200 truncated + 17 boundary + oversize-advert + offset-OOB |
| `test_conduit_udp.c` | 3 | UDP bind / loopback recv / send error paths |
| `test_quic_trust.c` | 3 | Pinned accept/reject, NOT_IMPLEMENTED stubs, null-args |
| `test_quic_secret.c` | 3 | Ephemeral lifecycle, URI refusals (env: / file:), sign |
| `test_quic_endpoint.c` | 5 | Create+close, listen NOT_IMPL, null-arg, idle run, Client Hello to server |
| `test_quic_conn.c` | 3 | Connect+state, null-arg, loopback handshake drive |
| `test_quic_chan.c` | 5 | Open+close, send+FIN, reset, stats, null-arg |
| `test_quic_chan_recv.c` | 5 | Find_chan, append+pull, geometric grow, FIN state, null/zero |
| `test_quic_handshake.c` | 1 | Full TLS 1.3 handshake reaches CONNECTED |
| `test_quic_accept.c` | 2 | Accept topic exists, multi-conn + unlink-on-close |
| `test_quic_qlog.c` | 1 | qlog files created, contain qlog format marker |
| `perf_quic_stream_scaling.c` | — (perf) | Sweep N ∈ {10..1000} concurrent channels |

Plus `examples/quic_echo` — three-mode demo (loopback / server /
client) exercising the full surface.

## How to use what's shipped

### Loopback echo
```bash
./build_debug/quic_echo
# → [loopback OK] hello, n00b/quic! -> hello, n00b/quic!
```

### Server + many clients
```bash
./build_debug/quic_echo server 4433 &
for i in 1 2 3; do
    ./build_debug/quic_echo client 127.0.0.1 4433 "msg $i" &
done; wait
```

### Server with real PKI + qlog
```bash
./examples/quic_echo/setup_dev_pki.sh    # one-time, sudo for trust install
./build_debug/quic_echo server 4433 \
    --cert-pem=$HOME/.n00b-dev-pki/server.crt.pem \
    --key-pem=$HOME/.n00b-dev-pki/server.key.pem \
    --qlog=/tmp/n00b-qlog &
./build_debug/quic_echo client 127.0.0.1 4433 "real cert" --qlog=/tmp/n00b-qlog
```

### Multi-message duplex (handshake amortizes)
```bash
./build_debug/quic_echo client 127.0.0.1 4433 "ping" --multi=10
# → 10 messages on ONE channel, ONE TLS handshake, server echoes each
```

## Memory + threading discipline

Per `docs/net/quic/allocator.md` (mandatory):

1. All long-lived QUIC state (endpoints, conns, channels, recv
   buffers, accept topic) allocated from `conduit_pool`, not the
   default GC arena.
2. GC roots: any file-scope global holding QUIC state must call
   `n00b_gc_register_root(var)` after `n00b_init`.  (No such
   globals in the QUIC module itself today.)
3. Endpoints, conns, and channels are released only by their close
   calls; nothing reclaims a dropped handle.

Cross-thread: picoquic is single-threaded.  Call `run_once` from
one thread.  Multi-threaded `run_once` is future work.

## What's deferred to later phases

- **`n00b_quic_chan_writable_bytes`** — picoquic doesn't expose a
  public per-stream send-window accessor.  Either reach into
  picoquic_internal.h (fragile across upstream versions) or wait
  for an upstream feature.
- **Datagram channels (RFC 9221, `N00B_QUIC_CHAN_DGRAM`)** —
  conceptual model needs work: datagrams are per-connection, not
  per-stream.  Worth a real design pass.
- **Trust-store → picotls verify-callback bridge** — picotls's
  verify cb requires a verify-sign function that wants the cert's
  public key, which means X.509 ASN.1 parsing.  Phase 3 (auth)
  work.
- **Real Keychain / libsecret secret providers** — the URI scheme
  and vtable shape are in tree; provider implementations land
  with the trust bridge.
- **ACME provisioning library inside libn00b** — currently the
  dev workflow shells out to `step ca certificate`.  Phase 2
  bundles a uacme-derived provisioner.
- **Hot-reload + SNI atomic swap** — Phase 2.
- **Stateless-reset + address-validation token rotation** —
  Phase 2.
- **draft-ietf-quic-load-balancers CID encoding** — Phase 2.

## Cross-references

- `~/dd/quic_1.md` — Phase 1 design / source of truth.
- `~/dd/quic_1_runbook.md` — implementation runbook.
- `~/dd/quic_1_progress.md` — running log.
- `docs/net/quic/vendored.md` — picotls / picoquic upstream pins.
- `docs/net/quic/allocator.md` — the conduit_pool allocator-discipline
  rule (mandatory).
- `docs/net/quic/dev_pki.md` — local step-ca workflow.
- `docs/net/quic/stream_budgets.md` — perf-harness methodology +
  measured numbers.
- `docs/net/quic/example.md` — walkthrough of the `quic_echo` example.
