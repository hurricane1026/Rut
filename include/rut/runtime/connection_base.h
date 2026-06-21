#pragma once

#include "rut/common/buffer.h"
#include "rut/common/types.h"
#include "rut/common/wait_limits.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/tls_engine.h"
#include "rut/runtime/ws_terminate.h"

#include <linux/time_types.h>
#include <openssl/base.h>

namespace rut {

struct RouteConfig;  // forward for per-request config pin below
struct Http2Conn;    // forward: per-connection HTTP/2 engine, pool-allocated

enum class BodyMode : u8 {
    None,           // No body
    ContentLength,  // Known size via Content-Length
    Chunked,        // Transfer-Encoding: chunked
    UntilClose,     // Read until EOF (HTTP/1.0)
};

// Active wire protocol on a connection, fixed after the TLS handshake from the
// ALPN result (plaintext connections stay Http11). Drives parse/serialize path.
enum class ConnProtocol : u8 {
    Http11,
    Http2,
};

enum class ConnState : u8 {
    Idle,
    ReadingHeader,
    ReadingBody,
    ExecHandler,
    Proxying,
    Sending,
    Count,
};

static_assert(static_cast<u8>(ConnState::Count) == 6u,
              "ConnState count is part of the static network state contract");

struct ConnectionBase {
    static constexpr u32 kMaxReqPathLen = 64;
    static constexpr u32 kMaxUpstreamNameLen = 24;
    static constexpr u16 kMaxPipelineDepth = 16;
    // Keep persistent wait fields coupled to the shared route wait limit:
    // every wait stores kind/result in two i64 slots.
    static constexpr u32 kMaxJitHandlerSlots = rut::kMaxJitHandlerSlots;
    static_assert(kMaxJitHandlerSlots >= 2u, "JIT wait frame must hold at least one wait result");
    // Event callback type — void* loop to avoid circular dependency.
    using Callback = void (*)(void* loop, ConnectionBase& conn, IoEvent ev);

    // Per-event-type callback slots (Seastar-inspired).
    // Each slot receives ONLY its designated event type. The dispatch
    // layer routes events to the correct slot and handles null slots
    // centrally (drain/ignore/close). No event-type guard code needed
    // inside callbacks.
    Callback on_recv;           // IoEventType::Recv only
    Callback on_send;           // IoEventType::Send only
    Callback on_upstream_recv;  // IoEventType::UpstreamRecv only
    Callback on_upstream_send;  // IoEventType::UpstreamSend + UpstreamConnect

    // Set all 4 slots atomically. Full state transitions MUST use this
    // to prevent stale callbacks in slots that aren't explicitly changed.
    void set_slots(Callback recv, Callback send, Callback up_recv, Callback up_send) {
        if (uses_iouring_tls()) {
            tls_pending_on_recv = recv;
        } else {
            on_recv = recv;
        }
        on_send = send;
        on_upstream_recv = up_recv;
        on_upstream_send = up_send;
    }

    void clear_slots() { set_slots(nullptr, nullptr, nullptr, nullptr); }

    void transition_to_reading_header(Callback recv) {
        state = ConnState::ReadingHeader;
        set_slots(recv, nullptr, nullptr, nullptr);
    }

    void transition_to_reading_body(Callback recv) {
        state = ConnState::ReadingBody;
        set_slots(recv, nullptr, nullptr, nullptr);
    }

    void transition_to_sending(Callback send) {
        state = ConnState::Sending;
        set_slots(nullptr, send, nullptr, nullptr);
    }

    void transition_to_exec_handler_wait() {
        state = ConnState::ExecHandler;
        clear_slots();
    }

    bool uses_iouring_tls() const { return tls_active && tls_engine.ssl != nullptr; }

    // Check if any slot is active (for dispatch guard).
    bool has_active_slot() const {
        return on_recv || on_send || on_upstream_recv || on_upstream_send;
    }

    i32 fd;
    u32 id;
    ConnState state;  // for debugging/metrics only
    u8 shard_id;
    u16 flags;
    u32 timer_slot;
    ListNode timer_node;
    ListNode idle_node;

    // Upstream (only when proxying)
    i32 upstream_fd;
    u16 upstream_idx;
    u8 upstream_attempts;     // connect attempts so far (initial + retries) this request
    u8 upstream_backend_idx;  // which backend endpoint the current connect targets
    bool proxy_resp_started;  // true once upstream response bytes were sent to the client
    bool upstream_abandoned;  // gave up on the upstream (timeout); ignore late upstream CQEs
    // forward(set_path:) request mutation: a JIT handler may rewrite the request
    // path before proxying. The runtime helper records the new path (a view into
    // stable JIT constant memory); on_upstream_connected rewrites the request
    // line in recv_buf before forwarding. Reset per request.
    bool req_path_overridden;
    Str req_path_override;
    // Upstream concurrency slot: set true between try_acquire and release so the
    // slot is freed exactly once, on whatever exit path runs (completion, failure,
    // or close). `upstream_slot_uid` records which backend's gauge to decrement.
    bool upstream_slot_held;
    u16 upstream_slot_uid;

    // @throttle downstream pacing — per-connection token bucket (virtual-time /
    // GCRA) for sends to the client. Set per request from the matched route. The
    // proxy body pump advances `throttle_tat_ns` by sent_bytes × 1e9 / bps (full
    // precision; see client_send); when it runs ahead of real time the pump parks
    // for the exact deficit on the
    // per-shard precise timer, resumed by throttle_resume (see callbacks_impl.h).
    u32 throttle_down_bps;     // bytes/sec cap (0 = unthrottled); also the "enabled" flag
    u64 throttle_tat_ns;       // GCRA theoretical arrival time (monotonic ns)
    bool throttle_paused;      // pump parked waiting for byte-budget to recover
    u32 throttle_pending_len;  // buffered upstream bytes to replay on resume
    // After a 101 Switching Protocols response the connection becomes a
    // transparent full-duplex byte tunnel (WebSocket passthrough): the 4 slots
    // splice client↔upstream and the keepalive timeout no longer closes it.
    bool is_ws_tunnel;
    // WebSocket tunnel send state tracks the submitted prefix in each direction
    // so raced recv completions can leave later bytes buffered for the next send.
    bool ws_client_send_pending;
    bool ws_upstream_send_pending;
    // Bytes submitted for the current tunnel send. A best-effort recv pause can
    // still race with already-harvested CQEs, so completion must consume only
    // the submitted prefix and preserve later buffered bytes.
    u32 ws_client_send_len;
    u32 ws_upstream_send_len;
    // Bytes of the 101 Switching Protocols response sent before entering
    // tunnel mode (HTTP headers only, excluding any early upstream bytes).
    u32 ws_upgrade_response_len;
    // Upstream closed during pre-tunnel 101 handling and should be closed once
    // tunnel mode is fully entered (after preserving buffered early bytes).
    bool ws_pre_tunnel_upstream_closed;
    // A tunnel peer half-closed (FIN/EOF) while its paired send was still
    // draining. Tear down only after the in-flight frame finishes flushing so
    // the last frame is not truncated: ws_client_eof gates the client→upstream
    // drain (on_ws_client_to_upstream_sent), ws_upstream_eof the upstream→client
    // drain (on_ws_upstream_to_client_sent).
    bool ws_client_eof;
    bool ws_upstream_eof;

    // WebSocket TERMINATE mode (vs the passthrough tunnel above). Set from the matched
    // route at request time; `is_ws_terminate` is armed at the 101 transition once the
    // per-direction inspection buffers are acquired. In terminate mode the data phase is
    // parsed/inspected/re-framed per message (ws_inspect) instead of spliced raw.
    bool is_ws_terminate_route;     // matched route requested terminate (vs passthrough)
    bool is_ws_terminate;           // active: 101 seen + inspection buffers acquired
    WsMessageHandlerFn ws_handler;  // per-message decision callback (route-supplied)
    u32 ws_max_message_size;        // reassembly cap; bounded to one slice (<=16KB-14)
    WsInspector ws_c2u;             // client->upstream inspection state (masked)
    WsInspector ws_u2c;             // upstream->client inspection state (unmasked)
    // Reassembly scratch, one per direction (pure CPU — never kernel-referenced, so freed
    // immediately on close). The re-framed output is written IN PLACE over the recv buffer
    // (ws_inspect's output is always <= its consumed input), so no separate output slice is
    // needed. ws_*_consumed remembers the unconsumed-tail start across an in-flight send so
    // the sent callback can compact the partial trailing frame to the front.
    u8* ws_c2u_msg = nullptr;  // client->upstream reassembly slice
    u8* ws_u2c_msg = nullptr;  // upstream->client reassembly slice
    u32 ws_c2u_consumed;       // recv_buf bytes consumed by the in-flight c->u send
    u32 ws_u2c_consumed;       // upstream_recv_buf bytes consumed by the in-flight u->c send

    // JIT handler state.
    //   handler_state: current state-machine index; handler reads this at
    //     entry and dispatches. On yield the runtime stores next_state here.
    //   handler_ctx:   points at handler_ctx_storage while a JIT handler is
    //     running. The first slots store wait result kind/result pairs across
    //     resume boundaries.
    //   pending_handler_fn: non-null while the handler has yielded and is
    //     waiting for its timer/io completion. The tick callback uses this
    //     to distinguish "resume JIT handler" from "keepalive expired,
    //     close connection". Reset to null on terminal outcome.
    u16 handler_state;
    jit::YieldKind pending_yield_kind;
    jit::YieldKind resume_event_kind;
    i32 resume_event_result;
    void* handler_ctx;
    jit::HandlerFn pending_handler_fn;
    alignas(alignof(u64)) u8 handler_ctx_storage[sizeof(jit::HandlerCtx) +
                                                 static_cast<size_t>(kMaxJitHandlerSlots) * 8]{};

    jit::HandlerCtx* reset_jit_ctx() {
        __builtin_memset(handler_ctx_storage, 0, sizeof(handler_ctx_storage));
        auto* ctx = reinterpret_cast<jit::HandlerCtx*>(handler_ctx_storage);
        ctx->slot_count = kMaxJitHandlerSlots;
        handler_ctx = ctx;
        return ctx;
    }

    jit::HandlerCtx* jit_ctx() {
        if (handler_ctx == nullptr) return reset_jit_ctx();
        return reinterpret_cast<jit::HandlerCtx*>(handler_ctx);
    }

    // Per-request generation counter. Incremented on every new request
    // (in on_header_received) so the epoll YieldHeap can filter out
    // stale entries left behind by a close+reuse that lands in the same
    // microsecond as the new request — req_start_us alone is not
    // strictly unique at μs granularity under close-during-yield churn.
    //
    // Default-initialized and deliberately NOT reset in reset(): the
    // counter must persist across slot reuse so every generation on a
    // given slot is distinct (first use: 0 → 1; reuse: N → N+1; …).
    u32 handler_gen = 0;

    // Route config pinned for the lifetime of the current request. Set
    // in on_header_received from the loop's config pointer; referenced
    // by handle_jit_outcome (e.g., Forward upstream resolution) so a
    // config hot-swap during wait(ms) can't resolve an upstream_id
    // against the post-swap config. Cleared by reset().
    const RouteConfig* request_config;

    // Per-connection timespec storage for IORING_OP_TIMEOUT yields. The
    // kernel reads this asynchronously after SQE submission, so it must
    // outlive the submit call — on-connection storage is the simplest
    // stable lifetime. Unused by the epoll backend (which uses a shared
    // yield_timer_fd + min-heap).
    __kernel_timespec yield_timespec;
    u32 yield_timer_gen = 0;

    bool keep_alive;
    bool tls_active;
    bool tls_handshake_complete;
    // Active wire protocol. Defaults to Http11; set from the ALPN result once
    // the TLS handshake completes, or on detecting the cleartext h2c preface.
    ConnProtocol protocol;
    // Per-connection HTTP/2 engine, lazily allocated from a per-shard pool when
    // the connection switches to Http2; returned to the pool on close. Null for
    // HTTP/1 connections (they pay nothing).
    Http2Conn* h2;
    SSL* tls;

    // --- io_uring TLS termination (event-loop-layer) ---
    // The epoll backend terminates TLS with a socket BIO inside the backend
    // (SSL does its own recv/send on readiness). io_uring can't — SSL must never
    // touch the fd — so it drives a TlsEngine over the custom zero-copy BIO from
    // the event-loop layer. These fields are unused by the epoll path (it uses
    // `tls` above); io_uring leaves `tls` null and uses `tls_engine`.
    TlsEngine tls_engine;
    u8* tls_in_slice;  // ciphertext arriving from the network (recv lands here)
    Buffer tls_in_buf;
    u8* tls_out_slice;  // ciphertext to send: handshake flights + encrypted app data
    Buffer tls_out_buf;
    // A tls_out_buf send is in flight; the buffer cannot be reused until its CQE.
    bool tls_out_inflight;
    // Bytes the in-flight raw send covers. Read-ahead may append more ciphertext
    // to tls_out_buf after the SQE captured its length, so the drain handler must
    // consume against this, not the (possibly grown) tls_out_buf.len(). See
    // docs/iouring-tls-output-buffer.md §3.1.
    u32 tls_out_inflight_len;
    // Proxy-over-TLS streaming backpressure state (io_uring). Per-response, not
    // per-connection — cleared at the keep-alive request boundary, not only reset().
    bool tls_recv_paused_hw;   // upstream recv paused at the high watermark
    bool resp_fully_buffered;  // whole proxy body read+encrypted into tls_out_buf
    bool tls_proxy_stream;     // mid proxy-over-TLS body (vs single-shot / handshake)
    // Plaintext awaiting encryption for an app-data send. Encryption may need
    // several rounds when the ciphertext doesn't fit tls_out_buf in one shot; the
    // send-completion handler resumes from tls_send_off and only fires the real
    // continuation (tls_pending_on_send) once all plaintext is encrypted+sent.
    const u8* tls_send_src;
    u32 tls_send_len;
    u32 tls_send_off;
    Callback tls_pending_on_recv;
    Callback tls_pending_on_send;

    // HTTP pipelining state
    u16 pipeline_depth;      // pipelined requests processed on this connection
    u16 pipeline_stash_len;  // bytes of next request stashed in send_buf (proxy)

    // Body streaming state (proxy large body support)
    u32 req_header_end;        // offset past request headers (\r\n\r\n)
    u32 req_content_length;    // original Content-Length value (for send capping)
    u32 req_initial_send_len;  // max bytes to send in initial upstream forward
    bool req_malformed;        // true if request body is malformed (reject)
    bool req_wants_upgrade;    // client sent Connection: upgrade (gates 101 tunnel)
    BodyMode req_body_mode;
    u32 req_body_remaining;          // bytes left for request body (Content-Length)
    ChunkedParser req_chunk_parser;  // for chunked request body end detection
    BodyMode resp_body_mode;
    u32 resp_body_remaining;          // bytes left for Content-Length mode
    ChunkedParser resp_chunk_parser;  // for chunked mode end detection
    u32 resp_body_sent;               // total response body bytes sent (for access log)
    u32 upstream_send_len;            // bytes from upstream_recv_buf in current client send

    // io_uring multishot recv tracking: true while the multishot SQE is
    // armed in the kernel (set on submit, cleared on final CQE without
    // IORING_CQE_F_MORE). Separate flags for client and upstream to avoid
    // an upstream recv CQE clearing the client's armed state.
    bool recv_armed;
    bool send_armed;
    bool upstream_recv_armed;
    bool upstream_send_armed;
    bool recv_paused_for_send;
    bool recv_pause_cancel_pending;
    // True when code asked to recv during a send-wait pause window and the
    // read should be re-armed after the cancel CQE drains.
    bool recv_pause_rearm_pending;
    bool upstream_recv_paused_for_send;
    bool upstream_recv_pause_cancel_pending;
    bool upstream_recv_pause_rearm_pending;
    // True from when a pause cancel is issued until the CANCELLED recv's own terminal
    // CQE (-ECANCELED, or a normal completion that beat the cancel) has drained. Unlike
    // upstream_recv_armed — which proxy_stream_complete clears at the keep-alive
    // boundary while the old recv is still in flight — this is cleared ONLY by that
    // terminal CQE, so it is the reliable "the cancelled recv has not yet drained"
    // signal that gates re-arm (alongside upstream_recv_pause_cancel_pending).
    bool upstream_recv_cancel_inflight;
    // Captures resp_fully_buffered AT PAUSE TIME: true if the pause fired at the keep-
    // alive boundary (body already complete) rather than mid-stream backpressure. The
    // cancelled recv's terminal CQE is then stale post-body data and must be suppressed,
    // not delivered to the next pipelined request's slots. Captured here because
    // proxy_stream_complete clears resp_fully_buffered before that terminal drains, so
    // the live flag is unreliable. Cleared with upstream_recv_cancel_inflight.
    bool upstream_recv_terminal_stale;
    // True while a handler yield timer is logically armed. For io_uring,
    // the timer may be backed either by an IORING_OP_TIMEOUT SQE or by the
    // coarse timer wheel fallback.
    bool yield_armed;
    // True only when an IORING_OP_TIMEOUT SQE is in flight for the yield.
    // Used to avoid cancel SQEs for wheel-backed yields.
    bool yield_timeout_armed;

    // Response status (set by handler/proxy, used by access log)
    u16 resp_status;

    // Access-log metadata captured from the request/peer.
    u8 req_method;
    u32 req_size;
    u32 peer_addr;
    u16 peer_port;
    char req_path[kMaxReqPathLen];
    // View into req_path covering the canonical-for-routing path slice
    // (leading '/' stripped, trailing '/' run trimmed, bytes after first
    // '?' or '#' excluded). Populated by capture_request_metadata as a
    // free byproduct of the URI SIMD scan; read by dispatch via
    // RouteConfig::match_canonical to avoid a redundant canon pass on
    // the hot path. Valid only for the current request — reset() clears.
    Str req_path_canon;

    // Proxy timing/name for access log.
    u32 upstream_us;
    char upstream_name[kMaxUpstreamNameLen];
    u64 upstream_start_us;

    // Traffic capture: raw headers staged at on_header_received,
    // written to CaptureRing at on_request_complete. Null when capture disabled.
    u8* capture_buf;
    u16 capture_header_len;

    // Request timing (for access log)
    u64 req_start_us;

    // Outstanding I/O ops submitted to the backend. Incremented on
    // submit_recv/submit_send/etc., decremented when the final CQE
    // arrives in dispatch() (multishot CQEs with IORING_CQE_F_MORE
    // don't decrement). Used to drive CQE-based slice reclamation:
    // a closed connection's pooled slices are only returned to the pool
    // after all in-flight ops have completed (pending_ops reaches 0).
    //
    // u32: multishot recv stays armed across keep-alive cycles, but
    // on_response_sent re-submits submit_recv each cycle, growing the
    // counter by ~1 per request. u32 avoids wraparound (~4B requests).
    // The proper fix is to not re-arm multishot recv on keep-alive.
    u32 pending_ops;

    // Recv/send buffers — backed by SlicePool slices (16KB each).
    // Slices are allocated in EventLoop::alloc_conn_impl() and freed in free_conn_impl().
    // Idle/free connections hold nullptr (zero buffer memory).
    u8* recv_slice;
    u8* send_slice;
    Buffer recv_buf;
    Buffer send_buf;
    u32 send_progress;

    // Upstream recv buffer — separate from client recv_buf to prevent:
    // 1. Client pipelined data being parsed as upstream response
    // 2. Stale UpstreamRecv CQEs corrupting client request parsing
    // 3. Client Recv during response streaming polluting upstream body data
    // Lazy-allocated: only proxy connections pay the cost.
    u8* upstream_recv_slice;
    Buffer upstream_recv_buf;

    void reset() {
        on_recv = nullptr;
        on_send = nullptr;
        on_upstream_recv = nullptr;
        on_upstream_send = nullptr;
        fd = -1;
        id = 0;
        state = ConnState::Idle;
        shard_id = 0;
        flags = 0;
        timer_slot = 0;
        timer_node.init();
        idle_node.init();
        upstream_fd = -1;
        upstream_idx = 0;
        upstream_attempts = 0;
        upstream_backend_idx = 0;
        proxy_resp_started = false;
        upstream_abandoned = false;
        req_path_overridden = false;
        req_path_override = {nullptr, 0};
        upstream_slot_held = false;
        upstream_slot_uid = 0;
        throttle_down_bps = 0;
        throttle_tat_ns = 0;
        throttle_paused = false;
        throttle_pending_len = 0;
        is_ws_tunnel = false;
        ws_client_send_pending = false;
        ws_upstream_send_pending = false;
        ws_client_send_len = 0;
        ws_upstream_send_len = 0;
        ws_upgrade_response_len = 0;
        ws_pre_tunnel_upstream_closed = false;
        ws_client_eof = false;
        ws_upstream_eof = false;
        is_ws_terminate_route = false;
        is_ws_terminate = false;
        ws_handler = nullptr;
        ws_max_message_size = 0;
        ws_c2u.reset();
        ws_u2c.reset();
        ws_c2u.message_len = 0;
        ws_u2c.message_len = 0;
        ws_c2u_msg = nullptr;
        ws_u2c_msg = nullptr;
        ws_c2u_consumed = 0;
        ws_u2c_consumed = 0;
        handler_state = 0;
        pending_yield_kind = jit::YieldKind::Timer;
        resume_event_kind = jit::YieldKind::Timer;
        resume_event_result = 0;
        handler_ctx = nullptr;
        // Deliberately NOT reset here: handler_gen persists across
        // reset() so a stale YieldHeap entry whose target slot was
        // recycled reliably fails the generation match. It's
        // initialized at accept-time via EventLoop::alloc_conn_impl.
        request_config = nullptr;
        pending_handler_fn = nullptr;
        yield_timespec.tv_sec = 0;
        yield_timespec.tv_nsec = 0;
        yield_timer_gen = 0;
        keep_alive = false;
        tls_active = false;
        tls_handshake_complete = false;
        protocol = ConnProtocol::Http11;
        h2 = nullptr;  // pool slot is released by free_conn_impl, not reset()
        tls = nullptr;
        // tls_engine.ssl is SSL_free'd by close_conn_impl before reset(); null
        // here purely for hygiene on slot reuse (no double-free).
        tls_engine.ssl = nullptr;
        tls_engine.handshake_done = false;
        tls_in_slice = nullptr;
        tls_in_buf.bind(nullptr, 0);
        tls_out_slice = nullptr;
        tls_out_buf.bind(nullptr, 0);
        tls_out_inflight = false;
        tls_out_inflight_len = 0;
        tls_recv_paused_hw = false;
        resp_fully_buffered = false;
        tls_proxy_stream = false;
        tls_send_src = nullptr;
        tls_send_len = 0;
        tls_send_off = 0;
        tls_pending_on_recv = nullptr;
        tls_pending_on_send = nullptr;
        pipeline_depth = 0;
        pipeline_stash_len = 0;
        req_header_end = 0;
        req_content_length = 0;
        req_initial_send_len = 0;
        req_malformed = false;
        req_wants_upgrade = false;
        req_body_mode = BodyMode::None;
        req_body_remaining = 0;
        req_chunk_parser.reset();
        resp_body_mode = BodyMode::None;
        resp_body_remaining = 0;
        resp_chunk_parser.reset();
        resp_body_sent = 0;
        upstream_send_len = 0;
        recv_armed = false;
        send_armed = false;
        upstream_recv_armed = false;
        upstream_send_armed = false;
        recv_paused_for_send = false;
        recv_pause_cancel_pending = false;
        recv_pause_rearm_pending = false;
        upstream_recv_paused_for_send = false;
        upstream_recv_pause_cancel_pending = false;
        upstream_recv_pause_rearm_pending = false;
        upstream_recv_cancel_inflight = false;
        upstream_recv_terminal_stale = false;
        yield_armed = false;
        yield_timeout_armed = false;
        resp_status = 0;
        req_method = 0;
        req_size = 0;
        peer_addr = 0;
        peer_port = 0;
        req_path[0] = '\0';
        req_path_canon = {nullptr, 0};
        upstream_us = 0;
        upstream_name[0] = '\0';
        upstream_start_us = 0;
        capture_buf = nullptr;
        capture_header_len = 0;
        req_start_us = 0;
        pending_ops = 0;
        recv_slice = nullptr;
        send_slice = nullptr;
        recv_buf.bind(nullptr, 0);
        send_buf.bind(nullptr, 0);
        send_progress = 0;
        upstream_recv_slice = nullptr;
        upstream_recv_buf.bind(nullptr, 0);
    }
};

}  // namespace rut
