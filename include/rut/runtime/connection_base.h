#pragma once

#include "rut/common/buffer.h"
#include "rut/common/types.h"
#include "rut/compiler/mir.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/io_event.h"

#include <linux/time_types.h>
#include <openssl/base.h>

namespace rut {

struct RouteConfig;  // forward for per-request config pin below

enum class BodyMode : u8 {
    None,           // No body
    ContentLength,  // Known size via Content-Length
    Chunked,        // Transfer-Encoding: chunked
    UntilClose,     // Read until EOF (HTTP/1.0)
};

enum class ConnState : u8 {
    Idle,
    ReadingHeader,
    ReadingBody,
    ExecHandler,
    Proxying,
    Sending,
};

struct ConnectionBase {
    static constexpr u32 kMaxReqPathLen = 64;
    static constexpr u32 kMaxUpstreamNameLen = 24;
    static constexpr u16 kMaxPipelineDepth = 16;
    // Keep persistent wait fields coupled to compiler wait limit: every wait
    // stores kind/result in two i64 slots.
    static constexpr u32 kMaxJitHandlerSlots = MirFunction::kMaxWaits * 2u;
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
        on_recv = recv;
        on_send = send;
        on_upstream_recv = up_recv;
        on_upstream_send = up_send;
    }

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
    alignas(alignof(jit::HandlerCtx)) u8
        handler_ctx_storage[sizeof(jit::HandlerCtx) +
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
    SSL* tls;

    // HTTP pipelining state
    u16 pipeline_depth;      // pipelined requests processed on this connection
    u16 pipeline_stash_len;  // bytes of next request stashed in send_buf (proxy)

    // Body streaming state (proxy large body support)
    u32 req_header_end;        // offset past request headers (\r\n\r\n)
    u32 req_content_length;    // original Content-Length value (for send capping)
    u32 req_initial_send_len;  // max bytes to send in initial upstream forward
    bool req_malformed;        // true if request body is malformed (reject)
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
        tls = nullptr;
        pipeline_depth = 0;
        pipeline_stash_len = 0;
        req_header_end = 0;
        req_content_length = 0;
        req_initial_send_len = 0;
        req_malformed = false;
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
        yield_armed = false;
        yield_timeout_armed = false;
        resp_status = 0;
        req_method = 0;
        req_size = 0;
        peer_addr = 0;
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
        upstream_recv_slice = nullptr;
        upstream_recv_buf.bind(nullptr, 0);
    }
};

}  // namespace rut
