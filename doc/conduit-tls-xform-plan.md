# Work plan: conduit-native TLS transport (two xforms / one `ptls_t`)

## Motivation

TLS today is `src/crypto/acme_tls.c` — a raw, blocking `connect` + `ptls_send`
+ `poll(2)` loop that lives **outside** the conduit. Because it sits outside,
it has to own buffers by hand (it hands a caller's GC-managed `n00b_buffer_t`
straight to `ptls_send`, which on a worker thread let the moving collector
relocate the plaintext mid-encrypt → SIGSEGV in cifra `xor_bb`; the merged
stopgap copies into a local picotls buffer). It also can't ride
`n00b_write` / `n00b_read`, so every HTTPS caller is special-cased.

Goal: make TLS a normal **conduit pipeline stage** so plaintext rides
`n00b_write` / `n00b_read` and TLS happens transparently, with the conduit
owning every buffer across the encrypt/decrypt boundary. Then the crash class
is gone *by construction*, and HTTPS is just:

```
inbound:   tcp-conn → [tls-decrypt] → [http-parse] → consumer
outbound:  producer → [tls-encrypt] → tcp-conn
```

## Decided design

- **Two transforms sharing one `ptls_t`** (not a new bidirectional conduit
  primitive):
  - **encrypt xform** (outbound), `N00B_CONDUIT_XFORM_IMPL(n00b_buffer_t*, n00b_buffer_t*)`:
    plaintext → `ptls_send` → ciphertext → the TCP fd writer.
  - **decrypt xform** (inbound), `N00B_CONDUIT_XFORM_IMPL(n00b_buffer_t*, n00b_buffer_t*)`:
    TCP fd bytes → `ptls_receive` → plaintext → downstream.
- A small **shared TLS-session handle** both xforms reference: the `ptls_t`,
  the picotls send/recv buffers, handshake state, and the trust handle.
- **Handshake driven over the conduit IO** before any app data flows; the
  plaintext topics stay gated until `ptls_handshake` reports done.
- **Trust** via the existing, worker-safe `n00b_quic_trust_native()` — no new
  trust code.
- Built **alongside** `acme_tls.c`; nothing is removed until Phase 3.

## Substrate that already exists (no new work)

- Conduit transform pipeline: `include/conduit/xform.h` +
  `xform_http/json/marshal/linebuf/...`. Transforms chain from spec arrays.
- TCP transport: `n00b_conduit_conn_tcp` (`include/conduit/socket.h`);
  fd-managed write copies into a conduit-owned buffer
  (`n00b_conduit_fd_write_submit`).
- `n00b_write` / `n00b_read` typed topic surface (`conduit/write.h`, `read.h`).
- Native trust: `n00b_quic_trust_native()` (merged in #137).
- picotls (vendored): `ptls_handshake`, `ptls_send`, `ptls_receive`,
  `ptls_buffer_*`.
- Precedent: the **unix-socket** HTTP path is already conduit-native
  (`xform_http` over the fd transport). Only the HTTPS path detours into
  `acme_tls`.

## Phase 1 — Build the conduit TLS transport (libn00b)

1. **TLS-session handle** — struct holding `ptls_t *`, the picotls encrypt/recv
   `ptls_buffer_t`s, handshake-complete flag, peer-eof/close-notify state, and
   the `n00b_quic_trust_t *` trust handle. Allocated from the conduit pool
   (non-moving), so picotls never sees a movable pointer.
2. **TCP wiring** — open `n00b_conduit_conn_tcp(c, io, host, port)`, obtain its
   raw-byte read/write topics (the fd writer + fd read topic).
3. **Handshake driver** — pump handshake records both directions through the
   conduit IO until `ptls_handshake` is done; verify via the trust hook; only
   then publish/enable the plaintext read+write topics. *(Main design
   challenge: the xform model is unidirectional `T_in→T_out`, but the handshake
   is bidirectional + stateful over one `ptls_t`. Resolve in the connect setup
   — drive the handshake before installing the two app-data xforms.)*
4. **Outbound encrypt xform** — plaintext `n00b_buffer_t` → `ptls_send` into the
   session's encrypt buffer → emit ciphertext `n00b_buffer_t` to the TCP fd
   writer. Conduit owns the bytes end to end.
5. **Inbound decrypt xform** — TCP fd ciphertext → `ptls_receive` →
   emit plaintext `n00b_buffer_t` downstream. Handle partial records,
   multiple records per read, and `close_notify`.
6. **Connect API + teardown** — e.g.
   `n00b_conduit_tls_connect(c, host, port, .trust=…, .allocator=…)` returning
   the plaintext read/write topics; teardown sends `close_notify`, frees the
   `ptls_t`, drops the trust handle.
- **Files**: new `include/conduit/xform_tls.h` + `src/conduit/xform_tls.c`
  (or `src/crypto/conduit_tls.c`); reuses `socket.h`, `xform.h`,
  `crypto/trust.h`, `picotls.h`.
- **Tests**: loopback TLS server round-trip (handshake + echo); a
  **worker-thread test under forced GC** asserting no dangle (the regression
  the stopgap covered); compare results against `acme_tls`.
- **Risks**: handshake/IO coordination; partial-record buffering; backpressure
  across the boundary; half-close semantics.

## Phase 2 — Migrate Wax to the new transport

1. Rewire the n00b HTTP client's **HTTPS** path (`src/net/http/http_h1.c`
   around the `n00b_acme_tls_connect_ex`/`n00b_acme_tls_send` calls) to use the
   conduit TLS transport; keep `acme_tls` reachable.
2. Egress (`wax`) then flows over it (egress already uses the HTTP client).
3. **Re-land the unmerged wax egress/health work** here (`ymzxxowz`: diagnostics,
   byte-bound batching, English `crayon health`) — it was deployed/tested but
   never merged; PR it on top of the migrated path (or fold in).
4. **Verify**: `crayon login` + egress over conduit TLS; no crash; the
   `crayon health` HTTP-status surfacing still works.

## Phase 3 — Migrate the rest of libn00b off `acme_tls`; remove it

1. Enumerate all `acme_tls` callers (HTTP client, ACME cert issuance, the
   `n00b_quic_trust_native` consumers, any h1/h3 bridges).
2. Migrate each to the conduit TLS transport.
3. **Remove `src/crypto/acme_tls.c`** + dead helpers once nothing references it.
- **Tests**: full TLS suite, ACME issuance, HTTPS round-trips.

## Acceptance

- All TLS traffic rides the conduit; no raw `ptls_send` on a caller-owned
  buffer anywhere.
- The GC-buffer-to-encryptor crash class is structurally impossible.
- `acme_tls.c` deleted.

## Open questions

- Handshake-over-conduit shape: drive it in the connect call (before installing
  the xforms) vs. a tiny handshake xform. Leaning: drive in connect setup.
- Flow control / backpressure across encrypt↔decrypt.
- `close_notify` / half-close mapping onto conduit `TOPIC_CLOSED`.
