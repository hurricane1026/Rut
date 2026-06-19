# io_uring TLS: owned ciphertext output buffer + watermark backpressure

**Status:** design / proposal (supersedes PR #130's depth-1 send queue)

## 1. Problem

When reverse-proxying a body over TLS on the io_uring backend, the gateway issues
one client send per upstream chunk. The current model is:

- The proxy (`on_response_body_recvd`) sets a single `conn.upstream_send_len`,
  then `client_send(conn, conn.upstream_recv_buf.data(), send_len)` — i.e. it
  always sends from **buffer offset 0**.
- `upstream_recv_buf` is only consumed/shifted in `on_response_body_sent`
  (`consume_upstream_sent`) **after** that send completes.
- The io_uring TLS send path (`submit_send_impl` → `tls_pump_send`) encrypts the
  plaintext **lazily**: it holds a pointer `tls_send_src = upstream_recv_buf.data()`
  and `SSL_write`s a record at a time into `tls_out_slice`, flushing each, until
  the whole chunk has drained — only then firing the upper-layer continuation.

This is a strictly **serialized single-send model**: the proxy assumes exactly
one outstanding client send, tracked by one `upstream_send_len`, sent from
offset 0, consumed on completion.

PR #129 fail-safe-closed the connection if a second send arrived mid-flight.
PR #130 tried a **depth-1 send queue** to avoid the close, but it is
fundamentally incompatible with the proxy model and the code review (codex)
surfaced it as 2×P1 + 1×P2:

1. **P1** — the queue branch doesn't restore `on_send = tls_on_out_sent`, so the
   in-flight ciphertext Send CQE is mis-dispatched to the upper-layer callback;
   `tls_out_inflight` is never cleared and the queued send never pumps.
2. **P1** — the queued send reuses the *completed* send's continuation and fires
   it with the *queued* send's length/state, corrupting the streaming accounting.
3. **P2** — the e2e test never actually forces the queue path (it passes even
   with the bugs).

The deeper root cause behind 1 & 2: the lazy-encrypt model **aliases**
`upstream_recv_buf` across a send completion, and issuing a second send
overwrites the single `upstream_send_len` and re-reads from offset 0 (A's
unconsumed bytes). Two concurrent sends simply cannot coexist with this model.

## 2. Industry baseline

Production reverse proxies do **not** use a depth-1 pointer queue, and do **not**
strictly serialize. They use an **owned output buffer + high/low watermark
backpressure**:

- **nginx** — `ngx_chain_t` buffer chains + `proxy_buffering`/`proxy_buffers`;
  data is copied into owned buffers, written via `ngx_ssl_send_chain`; stops
  reading upstream when buffers fill.
- **Envoy** — per-connection **watermark buffers**; the write path appends to the
  connection write buffer; above `per_connection_buffer_limit_bytes` (~1 MiB
  default) it `readDisable(true)`s the upstream, re-enables below low watermark.
  TLS is a transport socket whose `doWrite` feeds the write buffer to `SSL_write`.
- **HAProxy** — per-stream `channel` buffers; backpressure via buffer fullness.

Three invariants common to all:

1. **Own the unsent bytes** — never alias the upstream recv buffer across a send.
2. **One in-flight send draining an owned buffer** — "depth" is the buffer
   capacity, not a fixed `1`.
3. **Watermark backpressure** — pause upstream reads above high watermark, resume
   below low watermark. Bounds memory and propagates TCP backpressure to the
   backend.

## 3. Design for Rut

Apply the same pattern, bounded to fit Rut's C1000K / zero-idle-overhead
philosophy. **The single behavioral change is encrypt-timing: eager instead of
lazy.** Everything else is the backpressure + continuation timing around it.

> `client_send` over io_uring TLS **synchronously `SSL_write`s the whole chunk
> into an owned, bounded ciphertext output buffer at submit time.** The plaintext
> is consumed into owned ciphertext immediately, so `upstream_recv_buf` is no
> longer aliased across the Send CQE. One in-flight raw send drains the ciphertext
> buffer; upstream reads pause above a high watermark and resume below a low one.

This removes the depth-1 queue entirely and dissolves the root cause of all three
findings.

### 3.1 Data structures (`connection_base.h`)

Remove (depth-1 queue): `tls_send_q_src`, `tls_send_q_len`.

Change `tls_out` from a single 16 KiB slice into a bounded owned ciphertext buffer:

```cpp
Buffer  tls_out_buf;        // owned ciphertext output (Buffer has consume()/compact())
                            // backed by an mmap region of kTlsOutBufCap, like tls_in
bool    tls_out_inflight;   // keep: one raw send drains tls_out_buf at a time
```

Add backpressure / deferred-continuation state:

```cpp
Callback tls_deferred_on_send;  // upper-layer continuation deferred at high watermark
bool     tls_recv_paused_hw;    // upstream recv paused for backpressure (resume at low)
```

Keep `tls_send_src/len/off` but **narrow their meaning**: used only by the
fallback branch where a single chunk's ciphertext exceeds the buffer's free space
and `SSL_write` returns `WantWrite` mid-chunk (see §3.4). Normal path no longer
holds plaintext across calls.

Constants (`iouring_event_loop.h`):

```cpp
kTlsOutBufCap = 4 * SlicePool::kSliceSize;  // 64 KiB — bounded; throughput/memory knob
kTlsOutHigh   = 3 * SlicePool::kSliceSize;  // pause upstream recv above this
kTlsOutLow    = 1 * SlicePool::kSliceSize;  // resume below this
```

Invariant: `kTlsOutBufCap − kTlsOutHigh ≥ one upstream chunk's worst-case
ciphertext` (~16 KiB + record/AEAD overhead) so a chunk we're allowed to accept
always encrypts fully in one shot (avoids the mid-chunk `WantWrite` fallback in
the common case). `tls_setup` allocates the `kTlsOutBufCap` mmap; `tls_teardown`
/`reset` clean it up.

### 3.2 Submit — `submit_send_impl` TLS branch (`iouring_event_loop.h`)

```text
submit_send_tls(conn, src, len, cont = conn.on_send):
  # 1) synchronously encrypt the whole chunk into the owned ciphertext buffer
  set_output(engine, tls_out_buf.write_ptr, tls_out_buf.write_avail)
  SSL_write(engine, src, len)             # expected to consume the whole chunk
    if WantWrite (not enough room) -> §3.4 fallback (hold remainder + pause); return true
  tls_out_buf.commit(produced ciphertext)

  # 2) ensure one raw send is draining the buffer
  if !tls_out_inflight and tls_out_buf.len() > 0:
     submit_send_raw(conn, tls_out_buf.data(), tls_out_buf.len())
     tls_out_inflight = true
     conn.on_send = tls_on_out_drain       # always the TLS drain hook  (fixes P1-a)

  # 3) signal the upper layer it may advance — gated by the high watermark
  if tls_out_buf.len() < kTlsOutHigh:
     fire(cont, result = len)              # fire on_response_body_sent with THIS chunk's len (fixes P1-b)
  else:
     tls_deferred_on_send = cont           # high watermark: defer until drained to low
     pause_upstream_recv(conn); tls_recv_paused_hw = true
  return true
```

The shared proxy code (`on_response_body_recvd`) is **unchanged**: it still sets
`upstream_send_len = send_len; transition_to_sending(on_response_body_sent);
client_send(...)`. The only difference is that `client_send` now encrypts
synchronously and (when below the high watermark) fires `on_response_body_sent`
synchronously — at which point `consume_upstream_sent` consumes exactly this
chunk (`upstream_send_len` is still this chunk's length → correct accounting).

### 3.3 Drain — `tls_on_out_drain` (renamed `tls_on_out_sent`, `tls_iouring.h`)

```text
tls_on_out_drain(conn, ev):
  tls_out_inflight = false
  if ev.result < 0: close; return
  partial-send aware: advance by ev.result; tls_out_buf.consume(ev.result); compact

  if tls_out_buf.len() > 0:                # more ciphertext queued — submit next send
     submit_send_raw(...); tls_out_inflight = true; conn.on_send = tls_on_out_drain; return

  # buffer drained (or this was a handshake/control flight with no continuation)
  if tls_deferred_on_send and tls_out_buf.len() <= kTlsOutLow:
     cont = tls_deferred_on_send; tls_deferred_on_send = null
     if tls_recv_paused_hw: resume_upstream_recv(conn); tls_recv_paused_hw = false
     fire(cont, result = ...)              # low-watermark callback: proxy advances
  else:
     # existing tail preserved: handshake continuation / pending_handler_fn / submit_recv
```

`on_send` is `tls_on_out_drain` for the whole in-flight period (reset on every
`submit_send_raw`), so `transition_to_sending` can't clobber it. The proxy
continuation is invoked directly by the TLS layer, never via a raw Send CQE.

### 3.4 Edge cases

1. **Single chunk's ciphertext > buffer free space (`WantWrite` mid-chunk).**
   The §3.1 capacity invariant avoids it normally; the fallback holds the
   un-encrypted remainder in `tls_send_src/off/len` (pointing into
   `upstream_recv_buf`, valid because **we pause upstream recv**, keeping it
   stable) and resumes encryption at the low watermark.
2. **Handshake / control flights (NewSessionTicket, KeyUpdate).** Also flow
   through `tls_out_buf` but with **no upper-layer continuation** (`cont = null`);
   `tls_deferred_on_send` stays null and the existing handshake tail runs.
3. **`SSL_write` returns `WANT_READ`** (e.g. a KeyUpdate must be read first).
   Preserve #129's `tls_resume_pending_send_recv` path: `submit_recv` first, then
   continue encrypting after the control message is consumed.
4. **Partial socket send.** `submit_send_raw` completion may be `< len`; the
   drain handler must advance by `send_progress` (mirror `on_h2_sent`), not
   assume the buffer is fully drained.
5. **Close / teardown.** Discard unsent ciphertext on `close_conn`; `reset()`
   clears `tls_deferred_on_send`/`tls_recv_paused_hw`; `tls_teardown` frees the
   `tls_out` mmap.
6. **epoll unaffected.** All changes live in `tls_iouring.h` and the io_uring TLS
   branch of `submit_send_impl`. The shared `on_response_body_recvd/sent`,
   `consume_upstream_sent` keep the same signature and semantics ("consume one
   `upstream_send_len` chunk") — only *when* the continuation fires differs, and
   only on the io_uring TLS path. epoll TLS (terminated in-backend) and plaintext
   keep firing from the real send completion.

### 3.5 How this resolves the review

| Finding | Resolution |
|---|---|
| P1-a (`on_send` not restored) | No queued-pointer juggling; `on_send` is always `tls_on_out_drain` while in flight; continuation fired directly, not via CQE. |
| P1-b (wrong continuation/length) | Each chunk fires its continuation at its own accept time with its own `upstream_send_len`. |
| Root cause (alias / accounting) | Eager encrypt → `upstream_recv_buf` is free to reuse after submit; accounting consumes exactly the submitted chunk. |
| P2 (test doesn't exercise queue) | New test forces the high/low watermark path (§5). |

## 4. Memory / throughput tradeoff

`kTlsOutBufCap` is the knob: larger → the proxy runs further ahead of the socket
(higher throughput), at the cost of up to `kTlsOutBufCap` ciphertext bytes per
connection. 64 KiB/conn is a "enough for streaming, still C1000K-affordable"
midpoint (vs Envoy's ~1 MiB default). Idle connections allocate nothing — the
mmap happens in `tls_setup`, matching Rut's zero-idle-overhead model. The knob
can be a compile-time constant or per-shard config.

## 5. Test strategy

**Local (unit, `test_network.cc`, drives the functions directly):**

- `tls_out_buf` append/drain/compact + offset correctness.
- Watermark: fill to ≥ high → `pause` set + continuation deferred; drain to ≤ low
  → `resume` + deferred continuation fired.
- Per-chunk continuation fires with the correct length (two chunks → assert
  `consume_upstream_sent` called twice, each with its own length).
- Fallback: a chunk whose ciphertext overflows → remainder held + pause, resumes.
- Handshake flight (no continuation) doesn't spuriously fire a continuation;
  partial socket send continues.

**CI-only (integration, `test_integration.cc`, real io_uring + TLS sockets):**

- Rewrite `streams_large_body_over_tls_iouring` to **deterministically** trigger
  backpressure: upstream `send_all`s a body **much larger than `kTlsOutBufCap`**
  (e.g. 256 KiB) and the client reads **slowly** (read-a-bit / pause), forcing
  several high→pause→low→resume cycles. Assert the full body arrives byte-intact,
  **and** assert (via a counter/metric) that the pause/resume path was actually
  taken — otherwise the test proves nothing (this is exactly the P2 gap).
- ⚠️ Not runnable in the sandbox (no io_uring + TLS sockets); CI must validate.

## 6. Phasing & rollback

0. Add fields + `tls_out_buf` alloc/free + constants (pure addition, no behavior
   change). Compiles.
1. `submit_send_impl` TLS branch → eager encrypt into the buffer + fire
   continuation (no watermark yet; buffer large enough not to fill). Unit tests.
2. `tls_on_out_drain` → drain the buffer + continuation/resume. Delete
   `tls_send_q_*`. Unit tests.
3. Add high/low watermark backpressure + pause/resume + deferred continuation.
   Unit tests.
4. Rewrite the integration test to force backpressure. CI validates.

**Rollback:** each phase is an independent commit. If CI surfaces a problem, fall
back to phase 2 (no watermark, buffer sized large) — still correct, just less
aggressive on throughput than the full watermark version.

**Risks:** the io_uring TLS path is the most delicate state machine here and is
**not locally runtime-validatable** (sandbox limitation); the eager-encrypt
continuation is invoked synchronously, so the recursion depth (proxy pump →
client_send → fire continuation → proxy pump …) must be confirmed bounded
(≈ `kTlsOutBufCap / chunk` ≈ 4 levels; the codebase already has a similar bounded
recursion in the `kRemaining > 0` proxy path). CI is the backstop for both.
