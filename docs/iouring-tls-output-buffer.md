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

> `client_send` over io_uring TLS **encrypts plaintext into an owned, bounded
> ciphertext output buffer**, with one in-flight raw send draining it. Plaintext is
> consumed into owned ciphertext as it is encrypted, so `upstream_recv_buf` is no
> longer aliased across the Send CQE. The proxy keeps reading and encrypting ahead
> of the socket, bounded by a high/low watermark that pauses/resumes upstream
> reads — that read-side read-ahead (not any early continuation) is where the
> throughput comes from. **No continuation is ever fired synchronously at submit;
> all completions fire on the real drain CQE** (see §3.0), which is what keeps the
> shared callers' ordering intact.

This removes the depth-1 queue entirely and dissolves the root cause of all three
findings.

This design also splits cleanly into two layers, which matters for future TLS
hardware/kernel offload (see §7):

- **Generic transport layer** — owned output buffer, one in-flight (chunked)
  send, high/low watermark backpressure. Single-shot sends carry a continuation
  fired on the real drain CQE; proxy streaming carries **none** (it completes on
  fully-buffered + drained, per §3.0). Independent of how the bytes are produced.
- **Output provider** — the "plaintext → sendable bytes" step. Today there is one
  provider (userspace records: BoringSSL `SSL_write` → ciphertext). kTLS / NIC
  inline offload is a second provider that swaps only this step (write plaintext;
  kernel/NIC encrypts), reusing the generic layer unchanged.

To keep that seam open, the buffer and the fill step are named neutrally rather
than baked to "ciphertext / SSL_write":

```cpp
enum class TlsOutputMode : u8 { UserspaceRecord, Ktls };  // per-connection, set at handshake
// fill_output(conn, plaintext, len) -> consumed
//   UserspaceRecord: SSL_write the plaintext into out_buf (produces ciphertext)
//   Ktls:            copy/zero-copy the plaintext into out_buf; kernel/NIC encrypts on send
```

### 3.0 Two send shapes — never fire a continuation early

The design review (codex on this doc) showed that firing the upper-layer
continuation **synchronously at submit** is unsafe: it runs while a raw send is
in flight (so the next Send CQE no longer reaches `tls_on_out_drain`), and it
breaks callers that rely on async ordering — e.g. JIT `wait(send)`
(`handle_jit_outcome` calls `client_send(...)` then `pause_recv(...)`), and
`on_response_sent`/`on_jit_wait_send_sent` which validate via `ev.result`. So the
revised rule is **no continuation is ever fired synchronously; every completion
fires on the real drain CQE.** Two send shapes share the owned buffer:

- **Single-shot send** (a JIT/static response, `wait(send)`, a handshake flight):
  one logical `client_send`. Keep #129's model: save the upper-layer continuation
  in `tls_pending_on_send`, encrypt into the buffer, and fire that continuation
  **on the real full-drain CQE** with the sent length — exactly the existing
  async ordering. Unchanged semantics; only the staging buffer grows from one
  slice to `tls_out_buf`.
- **Proxy streaming body** (the only path that issues many sends back-to-back):
  decouple **read-side** (encrypt upstream chunks into `tls_out_buf`, driven by
  upstream-recv CQEs, bounded by the watermark) from **write-side** (one send
  drains the buffer). There is **no per-chunk continuation** — the throughput
  comes from reading/encrypting ahead of the socket, and the request completes
  when the body is fully buffered *and* the buffer fully drained.

This roots out the "fire while in flight" / "wait(send) reentrancy" / "deferred
length" findings: generic continuations are never deferred or early-fired.

### 3.1 Data structures (`connection_base.h`)

Remove (depth-1 queue): `tls_send_q_src`, `tls_send_q_len`.

Change `tls_out` from a single 16 KiB slice into a bounded owned output buffer:

```cpp
Buffer  tls_out_buf;          // owned ciphertext output (Buffer has consume()/compact())
                              // backed by an mmap region of kTlsOutBufCap, like tls_in
bool    tls_out_inflight;     // one raw send drains tls_out_buf at a time
u32     tls_out_inflight_len; // bytes the in-flight raw send covers (codex P1: read-ahead
                              // may append more ciphertext after the SQE captured len)
```

`tls_out_inflight_len` is essential because, with proxy read-ahead, `fill_output`
can append ciphertext to `tls_out_buf` *after* `ensure_draining` already submitted
a send for the then-current length. The SQE only covers the bytes captured at
submit; the drain handler must consume/partial-detect against
`tls_out_inflight_len`, not the (now larger) `tls_out_buf.len()`.

Keep, unchanged, the single-shot continuation: `tls_pending_on_send`,
`tls_send_src/len/off` (now: plaintext not yet encrypted because the buffer
filled — both for a single-shot send larger than the buffer *and* the proxy
`WantWrite`/`WantRead` fallback). Add proxy-streaming state:

```cpp
bool tls_recv_paused_hw;   // upstream recv paused for backpressure (resume at low watermark)
bool resp_fully_buffered;  // whole proxy body has been read+encrypted into tls_out_buf
bool tls_proxy_stream;     // this connection is mid proxy-over-TLS body (vs single-shot/handshake)
```

No `tls_deferred_on_send` / no early-fire (removed — see §3.0).

Constants (`iouring_event_loop.h`):

```cpp
kTlsRecordMax  = SlicePool::kSliceSize + 256;  // worst-case ciphertext for one ≤16 KiB chunk
kTlsOutBufCap  = 4 * SlicePool::kSliceSize;     // 64 KiB — bounded; throughput/memory knob
kTlsOutHigh    = kTlsOutBufCap - kTlsRecordMax; // pause upstream recv above this …
kTlsOutLow     = kTlsOutBufCap / 4;             // … resume below this
kTlsDrainChunk = SlicePool::kSliceSize;         // raw send submits at most this much at once
```

**Why chunk the drain (codex P2):** the io_uring backend enforces *full-send*
proactor semantics — a partial `IORING_OP_SEND` is re-submitted **inside** the
backend, and a Send event is emitted only once the entire submitted length has
drained. So if `ensure_draining` submitted the whole `tls_out_buf` (up to 64 KiB),
the drain handler would only run once the buffer is *empty* — the low watermark
would never be observed and backpressure would degrade to "resume only when
fully drained". Submitting at most `kTlsDrainChunk` per raw send makes the drain
handler run at slice granularity, so the `≤ kTlsOutLow` resume check actually
fires near the low watermark. (One TLS record ≈ one slice, so this adds no
record-level overhead.)

**Invariant (codex P2):** `kTlsOutBufCap − kTlsOutHigh ≥ kTlsRecordMax`, i.e. the
guaranteed free space above the high watermark must cover one full upstream chunk
**plus TLS record/AEAD expansion** — otherwise a normal full chunk just below the
high watermark hits the `WantWrite` fallback every time. Deriving `kTlsOutHigh`
from `kTlsRecordMax` (not "cap − one slice") enforces it. `tls_setup` allocates
the `kTlsOutBufCap` mmap; `tls_teardown`/`reset` clean it up.

### 3.2 `fill_output` — encrypt into the buffer (`tls_iouring.h`)

The one primitive both send shapes use. It must **loop on partial writes** and
**commit produced ciphertext every iteration** (codex P1 ×2):

```text
fill_output(conn, src, len) -> (consumed, status):    # status ∈ {Done, NeedRoom, NeedRead, Fatal}
  off = 0
  while off < len:
     set_output(engine, tls_out_buf.write_ptr, tls_out_buf.write_avail)
     w, st = SSL_write(engine, src+off, len-off)
     # The custom BIO writes ciphertext into the output region BEFORE SSL_write
     # returns (incl. on WantWrite), so commit whatever it produced EVERY pass —
     # else those bytes never drain and the low watermark never arrives.
     tls_out_buf.commit(tls_engine_output_len(engine))
     if !ensure_draining(conn): return (off, Fatal)        # submit_send_raw failure → close
     if w > 0: off += w; continue                          # PARTIAL_WRITE: positive < len is legal
     if st == WantWrite: return (off, NeedRoom)            # buffer full mid-chunk
     if st == WantRead:  return (off, NeedRead)            # post-handshake control needs a read
     return (off, Fatal)
  return (len, Done)

ensure_draining(conn):                                      # one in-flight send draining the buffer
  if !tls_out_inflight and tls_out_buf.len() > 0:
     n = min(tls_out_buf.len(), kTlsDrainChunk)            # chunk the drain (codex P2) — slice-granular
     if !submit_send_raw(conn, tls_out_buf.data(), n): return false   # codex P2: fail closed
     tls_out_inflight = true
     tls_out_inflight_len = n                              # SQE covers exactly n; full-send → CQE result == n
     conn.on_send = tls_on_out_drain
  return true
```

### 3.3 Submit paths (`submit_send_impl` / proxy read path)

**Single-shot** (`submit_send_impl` TLS branch) — same shape as #129, async
completion:
```text
tls_pending_on_send  = conn.on_send         # the upper-layer continuation
conn.on_send         = tls_on_out_drain
tls_send_src/len/off = src/len/0
(consumed, status) = fill_output(conn, src, len)
on Fatal: return false (caller closes)
tls_send_off = consumed
if status == NeedRead:                       # codex P1: WANT_READ for single-shot too
   tls_pending_on_recv = tls_resume_pending_send_recv; submit_recv(conn)
# NeedRoom: nothing to do — the drain handler resumes encryption when room frees
# the continuation fires later, from tls_on_out_drain, on full drain — NOT here
return true
```
`tls_resume_pending_send_recv` re-drives `fill_output(tls_send_src+off, len-off)`
after the read, for both shapes.

**Proxy streaming body** — the io_uring-TLS branch of `on_response_body_recvd`
calls `fill_output` directly instead of the generic `client_send`. It must
**preserve every bit of bookkeeping the existing path does** (codex), not just
encrypt:
```text
# --- close-delimited EOF: complete via the drain, don't discard the buffer ---
if ev.result <= 0:                           # codex P1 (UntilClose / EOF)
   if BodyMode::UntilClose and ev is clean EOF:
      tls_proxy_stream = true; resp_fully_buffered = true
      if !tls_out_inflight and tls_out_buf.len()==0: proxy_stream_complete(conn)  # nothing pending
      return                                 # else tls_on_out_drain finishes + completes
   handle -ENOBUFS / error exactly as today; return

tls_proxy_stream = true
(consumed, status) = fill_output(conn, upstream_recv_buf.data(), send_len)
on Fatal: close; return
consume_upstream(conn, consumed)             # drop the bytes we actually encrypted; compact
advance resp_body_remaining / chunked state by consumed
resp_body_sent += consumed                   # codex P2: access-log/capture size
throttle_advance(conn, consumed)             # codex P1: mirror client_send's throttle_tat_ns bump

if status == NeedRoom or status == NeedRead: # codex P1: park remainder for BOTH
   tls_send_src = upstream_recv_buf.data(); tls_send_len = remainder; tls_send_off = 0
   pause_upstream_recv(conn); tls_recv_paused_hw = true   # keep upstream_recv_buf stable
   if status == NeedRead: tls_pending_on_recv = tls_resume_pending_send_recv; submit_recv(conn)
   return

# chunk fully encrypted:
if whole body read+encrypted: resp_fully_buffered = true; return   # completion happens at drain
# re-arm upstream recv, honoring @throttle and the high watermark:
if throttle_pause_before_pump(conn): return                 # codex P1: byte-rate pacing
if tls_out_buf.len() >= kTlsOutHigh: pause_upstream_recv(conn); tls_recv_paused_hw = true
else: re-arm upstream recv
```

> The proxy branch is best implemented as a variant of the existing
> `on_response_body_recvd` that swaps `client_send` for `fill_output` and
> `consume_upstream_sent`-on-completion for `consume_upstream`-at-encrypt — keeping
> the body-mode dispatch (ContentLength / Chunked / UntilClose), `resp_body_sent`,
> `@throttle`, capture, and the `proxy_stream_complete` tail intact.

### 3.4 Drain — `tls_on_out_drain` (renamed `tls_on_out_sent`, `tls_iouring.h`)

```text
tls_on_out_drain(conn, ev):
  if ev.result <= 0: close; return
  # The backend has full-send semantics: it re-submits partial IORING_OP_SEND
  # internally and only delivers this event once the whole submitted chunk drained.
  # So ev.result == tls_out_inflight_len; no partial-send handling here.
  tls_out_buf.consume(tls_out_inflight_len); compact
  tls_out_inflight = false; tls_out_inflight_len = 0

  # (a) finish a parked plaintext remainder FIRST, before any completion (codex P1)
  if tls_send_src and tls_send_off < tls_send_len:
     (consumed, status) = fill_output(conn, tls_send_src + tls_send_off, tls_send_len - tls_send_off)
     on Fatal: close; return
     tls_send_off += consumed
     if tls_proxy_stream:
        consume_upstream(conn, consumed); advance body state; resp_body_sent += consumed
        throttle_advance(conn, consumed)
     if status == NeedRoom: return                          # still full — wait for the next drain
     if status == NeedRead: tls_pending_on_recv = tls_resume_pending_send_recv; submit_recv(conn); return
     tls_send_src = null                                     # remainder fully encrypted
     if tls_proxy_stream and whole body read+encrypted: resp_fully_buffered = true  # codex P1: final parked bytes

  # (b) relieve backpressure at the LOW watermark — BEFORE deciding to resubmit,
  #     so a paused stream resumes at kTlsOutLow, not only when fully empty (codex P2)
  if tls_proxy_stream and tls_recv_paused_hw and tls_out_buf.len() <= kTlsOutLow and not resp_fully_buffered:
     resume_upstream_recv(conn); tls_recv_paused_hw = false   # (still drain below if bytes remain)

  if tls_out_buf.len() > 0:                     # more ciphertext to push (next chunk)
     if !ensure_draining(conn): close; return   # codex P2: SQ-full here must fail closed too
     return

  # (c) buffer empty
  if tls_pending_on_send:                      # single-shot: fire continuation NOW (async, real len)
     fire(tls_pending_on_send, result = total_plaintext_sent); tls_pending_on_send = null; return
  if tls_proxy_stream:
     if resp_fully_buffered:                   # body fully buffered AND drained
        tls_proxy_stream = false; resp_fully_buffered = false   # codex P1: per-request, not just on close
        proxy_stream_complete(conn); return
     return                                    # codex P1: proxy active & idle — wait for the next
                                               # upstream recv; do NOT fall into the handshake tail
  # else: handshake/control flight tail (existing tls_process / pending_handler_fn / submit_recv)
```

`on_send` is `tls_on_out_drain` for the whole in-flight period (re-set on every
`ensure_draining`), so `transition_to_sending` can't clobber it. The explicit
`tls_proxy_stream` idle case (c) stops a mid-body proxy drain from entering the
handshake/`submit_recv` tail, which would clear `on_send` and read pipelined
client bytes out of order (codex P1).

### 3.5 Edge cases

1. **Buffer fills mid-chunk (`WantWrite`).** The §3.1 invariant prevents it for a
   normal chunk below the high watermark; the fallback parks the un-encrypted
   remainder in `tls_send_src/off/len` (pointing into `upstream_recv_buf`, stable
   because upstream recv is paused) and the drain handler §3.4(a) **finishes
   encrypting it before** any completion fires (codex P1) — so a chunk's tail is
   never lost and the continuation never runs against shifted data.
2. **Handshake / control flights (NewSessionTicket, KeyUpdate).** Flow through
   `tls_out_buf` with no upper-layer continuation (`tls_pending_on_send == null`);
   §3.4's handshake tail runs.
3. **`SSL_write` returns `WANT_READ`.** Preserve #129's
   `tls_resume_pending_send_recv` path: `submit_recv` first, resume encryption
   after the control message is consumed.
4. **Partial socket send.** Handled by the backend's full-send proactor
   semantics — a partial `IORING_OP_SEND` is re-submitted inside the backend, so
   `tls_on_out_drain` only sees full-chunk completions (`ev.result ==
   tls_out_inflight_len`). No partial handling in the drain path.
5. **`submit_send_raw` failure (SQ pressure).** `ensure_draining` returns false at
   **every** call site — the submit path *and* the drain path (next-chunk
   resubmit) — and both fail closed, so ciphertext is never left queued with no
   drain event (codex P2).
6. **Close-delimited body (`BodyMode::UntilClose`).** Upstream EOF marks the
   response complete, but ciphertext may still be undrained. The EOF path sets
   `resp_fully_buffered` and returns; `tls_on_out_drain` completes via
   `proxy_stream_complete` once the buffer empties — never close+discard the
   buffered tail (codex P1).
7. **Per-request state.** `tls_proxy_stream`/`resp_fully_buffered` are
   per-response, not per-connection: they're cleared in `proxy_stream_complete`
   (the keep-alive request boundary), not only in `reset()` — otherwise a later
   proxy response on the same connection could complete early when its buffer
   happens to empty mid-body (codex P1). `reset()` still clears them defensively
   along with `tls_recv_paused_hw`/`tls_out_inflight_len`/`tls_send_*`.
8. **Close / teardown.** Discard unsent ciphertext on `close_conn`; `tls_teardown`
   frees the `tls_out` mmap.
9. **epoll unaffected.** Changes live in `tls_iouring.h` and the io_uring TLS
   branches of `submit_send_impl` / `on_response_body_recvd`. The proxy-stream
   completion tail (`proxy_stream_complete`) is the body-done logic factored out
   of `on_response_body_sent`; epoll TLS (in-backend) and plaintext keep the
   existing synchronous send-completion flow.

### 3.6 How this resolves the design review (codex on this doc)

**Round 1** (on the first draft — the synchronous-fire model):

| Finding | Resolution |
|---|---|
| P1 — preserve the TLS drain hook before firing continuations | No continuation is fired at submit; `on_send` stays `tls_on_out_drain` for the whole in-flight period (§3.0, §3.4). |
| P1 — resume fallback encryption before firing the continuation | §3.4(a) finishes the parked remainder before any completion. |
| P1 — avoid inline completion for `wait(send)` sends | Single-shot continuations fire only on the real drain CQE (§3.0/§3.3), preserving the `client_send` → `pause_recv` ordering. |
| P1 — commit ciphertext before entering `WantWrite` fallback | `fill_output` commits `tls_engine_output_len()` and ensures a drain **every** iteration (§3.2). |
| P1 — loop until `SSL_write` consumes the whole chunk | `fill_output` loops on positive partial writes (`SSL_MODE_ENABLE_PARTIAL_WRITE`) until `Done`/retry (§3.2). |
| P2 — leave TLS overhead room above the high watermark | `kTlsOutHigh = kTlsOutBufCap − kTlsRecordMax` (§3.1). |
| P2 — store the deferred send result length | No deferred generic continuation exists anymore; single-shot fires with the real sent length (§3.4). |
| P2 — handle raw send submission failure | `ensure_draining` checks `submit_send_raw` and fails closed (§3.2/§3.5). |
| (original #130) root cause: alias / accounting | Encrypt-into-owned-buffer → `upstream_recv_buf` consumed at encrypt time, never aliased across a CQE. |

**Round 2** (on the decoupled read/drain model — proxy path must preserve the
existing path's bookkeeping, plus precise drain mechanics):

| Finding | Resolution |
|---|---|
| P1 — store the in-flight raw-send length | `tls_out_inflight_len` records the SQE-captured length; drain consumes/partial-detects against it, not the read-ahead-grown `tls_out_buf.len()` (§3.1, §3.2, §3.4). |
| P1 — preserve `@throttle` accounting in the TLS fill path | The proxy fill path calls `throttle_advance` per encrypted chunk and gates the upstream re-arm through `throttle_pause_before_pump` (§3.3). |
| P1 — wait for drain after close-delimited EOF (`UntilClose`) | EOF sets `resp_fully_buffered` and lets the drain complete via `proxy_stream_complete` (§3.3, §3.5(6)). |
| P1 — park the proxy remainder before `WANT_READ` | The proxy `NeedRead` branch parks `tls_send_src/len/off` + pauses recv, same as `NeedRoom` (§3.3). |
| P1 — handle `WANT_READ` for single-shot sends | Single-shot `NeedRead` installs `tls_resume_pending_send_recv` + `submit_recv` (§3.3). |
| P1 — keep proxy drains out of the handshake tail | Explicit `tls_proxy_stream` idle case in §3.4(c) returns and waits for the next upstream recv. |
| P2 — keep `resp_body_sent` in the direct TLS path | Incremented by the plaintext bytes accepted per chunk (§3.3, §3.4(a)). |
| P2 — resume upstream at the low watermark | Resume check moved **before** the resubmit return, gated on `tls_out_buf.len() ≤ kTlsOutLow` (§3.4(b)). |

**Round 3** (consistency leftovers + backend full-send semantics):

| Finding | Resolution |
|---|---|
| P1 — mark completion after parked final bytes | §3.4(a) sets `resp_fully_buffered` when the parked remainder is the last of the body, so completion isn't lost. |
| P1 — reset proxy-stream flags per request | `proxy_stream_complete` clears `tls_proxy_stream`/`resp_fully_buffered` at the keep-alive boundary, not only `reset()` (§3.4(c), §3.5(7)). |
| P2 — account for full-send io_uring completions | The backend re-submits partial sends internally, so the drain runs only at chunk boundaries; `ensure_draining` submits `≤ kTlsDrainChunk` so the low watermark is actually observed (§3.1, §3.2). |
| P2 — check drain resubmission failures | The drain-path next-chunk `ensure_draining` now fails closed too (§3.4). |
| P2 — saturate the socket buffer in the backpressure test | Shrink `SO_RCVBUF`/`SO_SNDBUF` below `kTlsOutBufCap` + a many-×-cap body to force the kernel send buffer to fill (§5). |
| P2 — remove the per-chunk continuation invariant | §3 transport-layer description now distinguishes single-shot (continuation) from continuation-free proxy streaming. |
| P2 — remove the synchronous-continuation guidance | §6 risk note corrected to the async-drain invariant. |

## 4. Memory / throughput tradeoff

`kTlsOutBufCap` is the knob: larger → the proxy runs further ahead of the socket
(higher throughput), at the cost of up to `kTlsOutBufCap` ciphertext bytes per
connection. 64 KiB/conn is a "enough for streaming, still C1000K-affordable"
midpoint (vs Envoy's ~1 MiB default). Idle connections allocate nothing — the
mmap happens in `tls_setup`, matching Rut's zero-idle-overhead model. The knob
can be a compile-time constant or per-shard config.

## 5. Test strategy

**Local (unit, `test_network.cc`, drives the functions directly):**

- `fill_output`: loops on partial `SSL_write` until the whole chunk is consumed;
  commits produced ciphertext every pass; `WantWrite` → `NeedRoom` with the
  already-produced bytes committed and a drain ensured; `submit_send_raw` failure
  → `Fatal`/close.
- Single-shot: continuation fires **only** on the real full-drain CQE, with the
  total sent length — never synchronously at submit (guards the `wait(send)` /
  `on_response_sent` ordering).
- Watermark: read-side fills to ≥ high → upstream recv paused; drain to ≤ low →
  resumed. No generic continuation is deferred or early-fired.
- Proxy stream accounting: two chunks → `upstream_recv_buf` consumed by the
  encrypted byte count at each fill; request completes only when
  `resp_fully_buffered` **and** the buffer is empty.
- Fallback: a chunk whose ciphertext overflows the free space → remainder parked
  + pause; drain handler finishes encrypting it **before** completing the chunk.
- Watermark headroom: a full chunk just below the high watermark encrypts in one
  shot (no `WantWrite`) — guards `kTlsOutHigh = cap − kTlsRecordMax`.
- Handshake flight (no `tls_pending_on_send`) doesn't spuriously fire a
  continuation.
- In-flight length: read-ahead appends ciphertext after `ensure_draining`; the
  drain consumes only `ev.result` and partial-detects against
  `tls_out_inflight_len`, never the grown buffer length (no dup/drop).
- Low-watermark resume: with `kTlsDrainChunk`-granular drains, a stream paused at
  the high watermark resumes when the buffer falls to `kTlsOutLow`, not only when
  fully empty (drive `tls_on_out_drain` chunk-by-chunk and assert the resume fires
  at the right point).
- Final parked bytes: a chunk that hits `NeedRoom`/`NeedRead` as the **last** bytes
  of the body sets `resp_fully_buffered` when it finishes, so completion happens
  (no hang waiting for an upstream recv that never comes).
- Per-request reset: a second proxy response on a keep-alive connection does not
  complete early from stale `tls_proxy_stream`/`resp_fully_buffered`.
- `@throttle`: a throttled route's TLS proxy body advances `throttle_tat_ns` and
  pauses the upstream read at the configured byte rate (not just on memory).
- `resp_body_sent` equals the forwarded body size at completion (access
  log/capture).
- `UntilClose`: upstream EOF with ciphertext still queued completes via the drain
  (`proxy_stream_complete`), not an immediate close that drops the tail.
- Proxy idle: buffer empties mid-body → no `submit_recv`/`on_send` clobber; waits
  for the next upstream recv.
- `WANT_READ` mid-send (both shapes): parks the remainder + arms a recv; the
  resume re-drives `fill_output` and the response finishes.
- `ensure_draining` failure at the drain-path next-chunk resubmit closes the conn.

**CI-only (integration, `test_integration.cc`, real io_uring + TLS sockets):**

- Rewrite `streams_large_body_over_tls_iouring` to **deterministically** trigger
  backpressure. A slow-reading client alone is **not** enough (codex P2): an
  io_uring send completes once bytes reach the kernel socket buffer, and on
  loopback the kernel can absorb far more than `kTlsOutBufCap` before the client's
  read rate matters — so the watermark path may never run and the metric assert
  goes flaky. Force it by **shrinking the client/socket buffers** (`SO_RCVBUF` on
  the client, `SO_SNDBUF` on the accepted fd) below `kTlsOutBufCap` *and* using a
  body many times `kTlsOutBufCap`, so the kernel send buffer fills and the
  user-space high→pause→low→resume cycles are forced. Assert the body arrives
  byte-intact **and** (via a counter/metric) that the pause/resume path was taken.
- ⚠️ Not runnable in the sandbox (no io_uring + TLS sockets); CI must validate.

## 6. Phasing & rollback

0. Add fields + `tls_out_buf` mmap alloc/free + constants; delete the depth-1
   queue (`tls_send_q_*`). Pure plumbing, no behavior change. Compiles.
1. `fill_output` + `ensure_draining` (loop on partial writes, commit-every-pass,
   submit-failure → close). Unit tests for the primitive in isolation.
2. **Single-shot** path on the buffer: `submit_send_impl` stages into
   `tls_out_buf`, `tls_on_out_drain` fires `tls_pending_on_send` on full drain
   (async — same semantics as #129). Unit tests. *This alone already supersedes
   #129/#130 for single-shot; the proxy still serializes.*
3. **Proxy streaming** read/drain decoupling: `on_response_body_recvd` io_uring-
   TLS branch calls `fill_output`; `resp_fully_buffered` + `proxy_stream_complete`
   in the drain handler. No watermark yet (buffer sized so it won't fill under
   test). Unit tests.
4. High/low watermark backpressure: pause/resume upstream recv; the `WantWrite`
   fallback + §3.4(a) remainder-finish. Unit tests.
5. Rewrite the integration test to deterministically force backpressure. CI.

**Rollback:** each phase is an independent commit. If CI surfaces a problem after
phase 3/4, fall back to phase 2 (single-shot on the buffer; proxy stays
serialized like #129 but without the spurious close) — still correct, just
without the streaming throughput win.

**Risks:** the io_uring TLS path is the most delicate state machine here and is
**not locally runtime-validatable** (sandbox limitation). No continuation is fired
synchronously (the core invariant, §3.0): single-shot continuations fire only on
the drain CQE, and the proxy stream has none — so the `wait(send)` reentrancy and
`on_send` clobber are avoided by construction. The remaining recursion to confirm
bounded is the **read side** — `on_response_body_recvd` consuming
`upstream_recv_buf` and re-pumping the next buffered chunk — which is the existing
`kRemaining > 0` pattern, already bounded by the recv buffer draining. CI is the
backstop.

## 7. Forward compatibility: kTLS / NIC inline TLS offload

This design is intentionally a stepping stone toward offloading the data-path
crypto to the kernel (kTLS) or the NIC (kTLS + hardware inline offload), which
Rut lists as a follow-up. The key is the §3 split:

- **Generic transport layer** (owned buffer + one in-flight chunked send +
  watermark backpressure; single-shot continuation on drain, continuation-free
  streaming) is **provider-agnostic** — keep as-is.
- **Output provider** is the only thing offload swaps.

So userspace records and kTLS are two providers of one seam, not two code paths:

| Provider | Handshake | Data path | `out_buf` holds |
|---|---|---|---|
| `UserspaceRecord` (today) | BoringSSL in userspace | `SSL_write` → ciphertext | ciphertext |
| `Ktls` | BoringSSL in userspace, then keys installed into the socket | write **plaintext** to the fd; kernel (or NIC) frames + AES-GCM encrypts inline | plaintext |

What carries over **unchanged** to kTLS: own-the-bytes (no aliasing
`upstream_recv_buf` across a send), one in-flight chunked send draining `out_buf`,
high/low watermark pause/resume, the single-shot-continuation-on-drain /
continuation-free-streaming split. kTLS is in fact **simpler** — no ciphertext
expansion, no `SSL_write` `WANT_WRITE`/`WANT_READ` handling, and the §3.5(1)
"ciphertext overflow" fallback disappears.

Mechanics to wire when adding the `Ktls` provider (out of scope for this PR, but
the seam is reserved now):

1. **Mode switch at handshake completion.** After BoringSSL finishes the
   handshake, install the negotiated keys into the socket
   (`setsockopt(TCP_ULP, "tls")` + `TLS_TX`/`TLS_RX`) and set
   `conn.tls_output_mode = Ktls`. The generic layer then routes `fill_output`
   to a plaintext copy instead of `SSL_write`.
2. **io_uring transport.** kTLS works with `IORING_OP_SEND`/`SENDMSG`. True
   zero-copy (`IORING_OP_SEND_ZC`) + NIC inline offload has kernel-version / NIC
   dependencies; its "buffer stays pinned until the zero-copy completion
   notification" requirement maps directly onto this design's "one in-flight
   send, don't reuse until completion" discipline — so SEND_ZC can later let the
   `Ktls` provider send plaintext **directly from `upstream_recv_buf`** (no copy)
   by holding it until the ZC completion.
3. **Post-handshake control records (KeyUpdate, etc.).** Under kTLS some are
   handled by the kernel and some surface to userspace via control messages
   (`cmsg` / `TLS_GET_RECORD_TYPE`). Handled inside the provider; orthogonal to
   the buffering/backpressure logic.
4. **Capability probe + fallback.** Not every kernel/NIC supports the offload.
   Probe at startup (or per connection) and fall back to `UserspaceRecord` —
   the same pattern as the existing io_uring→epoll backend fallback.

Naming consequence for this PR (Phase 0): name the buffer `tls_out_buf` and the
fill step neutrally (a `fill_output`/provider indirection) rather than hard-wiring
"ciphertext"/`SSL_write`, and reserve `TlsOutputMode` even though only
`UserspaceRecord` is implemented now. That keeps kTLS a drop-in provider later
instead of a rewrite.

> External **TLS-terminating appliance** (a separate box doing TLS, Rut speaking
> plaintext to it) is a different thing entirely: there Rut isn't doing TLS, so
> this whole path is bypassed and the plaintext send path applies — trivially
> "supported" because there is no TLS in Rut's data path.
