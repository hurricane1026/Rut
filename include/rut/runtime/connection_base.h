#pragma once

#include "rut/common/buffer.h"
#include "rut/common/failure_policy.h"
#include "rut/common/forward_target_transform.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/request_policy.h"
#include "rut/common/types.h"
#include "rut/common/wait_limits.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/listener_context.h"
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

enum class ResponseReadDeadlineState : u8 {
    None,
    Preflight,
    Validated,
    Armed,
    ExpiryPending,
    BatchPending,
    RefreshPending,
    BodyComplete,
};

enum class ResponseReadDeadlinePostCommitPhase : u8 {
    None,
    // The strict response header is pinned, but no downstream byte has been
    // published.  Positive Content-Length bytes remain behind the header in
    // upstream_recv_buf until a terminal buffering disposition is selected.
    Buffering,
    HeaderSend,
    BodySend,
    WaitingBody,
    OriginComplete,
};

enum class ResponseReadDeadlineSendKind : u8 {
    None,
    Header,
    Body,
};

// Immutable request/response contract selected before the JIT handler runs.
// The profile is part of every explicit-deadline ownership proof; method tests
// outside the centralized classifier must never widen this domain.
enum class ResponseReadDeadlineProfile : u8 {
    None,
    HeaderOnlyHead,
    BodylessNonHeadContentLengthZero,
    FixedContentLengthUploadNonHeadContentLengthZero,
};

// Immutable request-upload identity for the bounded fixed-Content-Length
// explicit-deadline profile. The active, first-response-batch, and D1/D2
// copies are compared byte-for-byte by field so no transition can manufacture
// a body/upload proof after the original request bytes have been released.
struct ResponseReadDeadlineUploadProof {
    u32 handler_generation = 0;
    u32 raw_header_end = 0;
    u32 raw_content_length = 0;
    u32 raw_total_length = 0;
    u32 rewritten_header_end = 0;
    u32 rewritten_total_length = 0;
    u32 upload_episode = 0;
    u32 expected_upload_length = 0;
    u16 route_index = 0xffffu;
    u16 upstream_id = 0xffffu;
    u16 request_policy_id = 0;
    jit::HandlerFn route_fn = nullptr;
};

enum class Http1PrebuiltResponseLayout : u8 {
    None,
    HeaderOnlyHead,
    FullContentLengthNonHead,
};

enum class Http1PrebuiltResponsePurpose : u8 {
    None,
    StrictHeadHeaderOnly,
    StrictNonHeadCl0Success,
    ResponseReadTimeout,
};

// Request-buffer ownership captured by the internal HTTP/1 prebuilt-response
// rendezvous.  The value describes where request 1 still lives while an old
// upstream episode and the downstream header send drain independently.
enum class Http1RequestBufferDisposition : u8 {
    None,
    PrefixInRecv,
    RetrySendBuf,
    ExistingPipeline,
};

static constexpr u8 kHttp1WaitHeaderSend = 1u << 0;
static constexpr u8 kHttp1WaitUpstreamRetirement = 1u << 1;

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
    // HTTP/1 idle upstream reuse: `upstream_keep_alive` is set when the upstream
    // response is parsed iff its connection may be reused (keep-alive, not
    // close-delimited) — the completion path then returns the fd to the per-shard
    // idle pool instead of closing it. `upstream_reused` marks a request whose
    // upstream socket came from that pool, so a send/recv failure before any
    // response byte can fall back to a fresh connect (idempotent methods only).
    bool upstream_keep_alive;
    bool upstream_reused;
    // Set when a request-body write to the upstream FAILS (initial forward or a
    // streamed chunk) so the upload was not fully delivered. The body counters
    // (req_body_remaining / req_chunk_parser) are advanced before the send is
    // submitted, so they can read "complete" even though those bytes never landed;
    // this flag is the authoritative "upload finished cleanly" signal that
    // proxy_upstream_reusable consults before pooling — a socket whose upload
    // desynced must never be reused (the next request would be parsed as leftover
    // body). Reset at the per-request boundary like the other reuse flags.
    bool upstream_request_incomplete;
    // io_uring-only deferred idle-pool return: an upstream fd to park in the pool
    // once its cancelled multishot recv terminal drains (handing the fd out while a
    // recv is still draining on it would let two recvs race the same socket). -1 =
    // none. epoll detaches synchronously and never uses this. See
    // IoUringEventLoop::return_idle_upstream / try_deferred_upstream_rearm.
    i32 idle_return_fd;
    u16 idle_return_uid;
    u8 idle_return_bidx;
    // Active RouteConfig pinned when idle_return_fd was parked (return_idle_upstream).
    // A hot reload can land while the cancelled recv is still draining; poll_command
    // only drains sockets ALREADY in the pool, so the deferred fd would escape that
    // drain and later be put_idle'd into the freshly-drained pool under a now-stale
    // (upstream_id, backend_idx). try_deferred_upstream_rearm compares this against the
    // live config and CLOSES instead of pooling on mismatch. request_config can't be
    // reused: the keep-alive client repoints it on its next request while this drains.
    const RouteConfig* idle_return_config;
    // io_uring-only deferred close: close_conn was called on a conn whose deferred
    // idle-pool return (idle_return_fd) had not yet drained its cancelled recv. Rather
    // than discard the still-reusable upstream fd (and free the slot), the conn is kept
    // allocated with this set; once the recv drains, try_deferred_upstream_rearm parks
    // the fd in the pool AND performs the slot-free close_conn deferred. See
    // IoUringEventLoop::close_conn_impl / try_deferred_upstream_rearm.
    bool close_after_idle_return;
    // Active health-check probe (slice 2, epoll only): this Connection is not a
    // real client request but a built-in periodic HTTP probe to one upstream
    // backend (fd == -1, no downstream; upstream_fd is the probe socket). Gates
    // close_conn to the minimal probe teardown (no metrics/epoch/access-log).
    bool is_health_probe;
    // io_uring h2-proxy reuse guards (epoll is synchronous → both stay false there).
    // h2_proxy_recv_draining: a multishot upstream recv from a torn-down h2 proxy
    // episode may still deliver a terminal CQE; the next episode must not arm its
    // own recv (which shares the conn_id/type user_data) until that terminal drains,
    // or the stale CQE would be misrouted to the new stream. Cleared when the
    // terminal is accounted in dispatch.
    bool h2_proxy_recv_draining;
    // h2_proxy_synth_quarantined: an upstream request send was still in flight when
    // an h2 proxy episode was torn down (timeout). The send SQE still sources
    // pending_synth, so a subsequent request must not overwrite it until that send
    // CQE drains. Cleared when the stale UpstreamSend terminal is accounted.
    bool h2_proxy_synth_quarantined;
    // forward(set_path:) request mutation: a JIT handler may rewrite the request
    // path before proxying. The runtime helper records the new path (a view into
    // stable JIT constant memory); on_upstream_connected rewrites the request
    // line in recv_buf before forwarding. Reset per request.
    bool req_path_overridden;
    Str req_path_override;
    // Foundation-only target-transform effect. The recorded flag distinguishes
    // no effect from a forged zero/sentinel ID; every recorded effect is rejected
    // before upstream selection until target materialization exists.
    u16 target_transform_id;
    bool target_transform_recorded;
    // forward(set_header:) request mutation: rut_helper_req_set_header records
    // (name, value) overrides (views into stable JIT constant memory);
    // on_upstream_connected injects/replaces those header lines in recv_buf before
    // forwarding. Bounded; reset per request. No default member initializers, so
    // the struct stays trivially constructible for the SlabPool.
    static constexpr u32 kMaxReqHeaderOverrides = 16;
    struct ReqHeaderOverride {
        Str name;
        Str value;
    };
    ReqHeaderOverride req_header_overrides[kMaxReqHeaderOverrides];
    u8 req_header_override_count;
    // Bit i selects append semantics (`req.add`) for override slot i; clear
    // means replace/dedupe (`req.set`).
    u16 req_header_append_mask;
    // Set when rut_helper_req_set_header is called past kMaxReqHeaderOverrides
    // (reachable only via direct RIR — the DSL caps + dedupes entries). The apply
    // path fails the request closed so a dropped override can't be forwarded as a
    // silent no-op. Reset per request alongside the count.
    bool req_header_override_overflow;
    // Ordered response-header mutations recorded by compiled Response builders.
    // Forward paths re-anchor request-backed values into a stable request snapshot
    // before recv_buf is released.
    static constexpr u32 kMaxRespHeaderMutations = 16;
    enum class RespHeaderMutationMode : u8 { Set, Add, Remove };
    struct RespHeaderMutation {
        Str name;
        Str value;
        RespHeaderMutationMode mode;
    };
    RespHeaderMutation resp_header_mutations[kMaxRespHeaderMutations];
    // Helpers append to the pending builder-local prefix so resp.header() can
    // observe source order. Only return of that builder publishes it.
    u8 resp_header_mutation_pending_count;
    bool resp_header_mutation_pending_overflow;
    u8 resp_header_mutation_count;
    bool resp_header_mutation_overflow;
    // Lazy slice used to serialize mutated forwarded response headers separately
    // from upstream_recv_buf. Keeping the header block independent lets a full
    // upstream body buffer stream normally even when mutations grow the headers.
    u8* response_header_slice;
    Buffer response_header_buf;

    void reanchor_request_overrides(const u8* old_base, u32 old_len, const u8* new_base) {
        auto reanchor = [&](Str& value) {
            if (value.ptr == nullptr) return;
            const auto* ptr = reinterpret_cast<const u8*>(value.ptr);
            if (ptr < old_base || ptr + value.len > old_base + old_len) return;
            value.ptr = reinterpret_cast<const char*>(new_base + (ptr - old_base));
        };
        reanchor(req_path_override);
        for (u32 i = 0; i < req_header_override_count; i++) {
            reanchor(req_header_overrides[i].name);
            reanchor(req_header_overrides[i].value);
        }
    }

    void reanchor_response_mutations(const u8* old_base, u32 old_len, const u8* new_base) {
        for (u32 i = 0; i < resp_header_mutation_count; i++) {
            auto& value = resp_header_mutations[i].value;
            if (value.ptr == nullptr) continue;
            const auto* ptr = reinterpret_cast<const u8*>(value.ptr);
            if (ptr < old_base || ptr + value.len > old_base + old_len) continue;
            value.ptr = reinterpret_cast<const char*>(new_base + (ptr - old_base));
        }
    }

    // Copy request-backed mutation values out of a synthesized request before
    // HTTP/2 reuses its request scratch for the encoded response. Literal values
    // already live in JIT-owned storage and do not need copying.
    bool stabilize_response_mutations(const u8* source, u32 source_len) {
        auto survives_folding = [&](u32 index) {
            const auto& current = resp_header_mutations[index];
            if (current.mode == RespHeaderMutationMode::Remove) return false;
            for (u32 later_index = index + 1; later_index < resp_header_mutation_count;
                 later_index++) {
                const auto& later = resp_header_mutations[later_index];
                if (later.mode != RespHeaderMutationMode::Add &&
                    http_header_name_eq_ci(
                        current.name.ptr, current.name.len, later.name.ptr, later.name.len))
                    return false;
            }
            return true;
        };
        u32 needed = 0;
        for (u32 i = 0; i < resp_header_mutation_count; i++) {
            if (!survives_folding(i)) continue;
            const auto& value = resp_header_mutations[i].value;
            if (value.ptr == nullptr) continue;
            const auto* ptr = reinterpret_cast<const u8*>(value.ptr);
            if (ptr >= source && ptr + value.len <= source + source_len) needed += value.len;
        }
        if (needed > response_header_buf.capacity()) return false;
        response_header_buf.reset();
        for (u32 i = 0; i < resp_header_mutation_count; i++) {
            if (!survives_folding(i)) continue;
            auto& value = resp_header_mutations[i].value;
            if (value.ptr == nullptr) continue;
            const auto* ptr = reinterpret_cast<const u8*>(value.ptr);
            if (ptr < source || ptr + value.len > source + source_len) continue;
            const u32 offset = response_header_buf.len();
            if (response_header_buf.write(ptr, value.len) != value.len) return false;
            value.ptr = reinterpret_cast<const char*>(response_header_buf.data() + offset);
        }
        return true;
    }
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
    // Bytes in the upstream's original 101 header block. This is the prefix
    // consumed from upstream_recv_buf after the (possibly rewritten) response
    // reaches the client.
    u32 ws_upgrade_response_len;
    // Bytes actually sent for the 101 header block after response mutations.
    // Access logging and capture account this length, not the upstream prefix.
    u32 ws_upgrade_sent_len;
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
    u16 ws_close_code;              // route's frame.close(code) status (seeds both inspectors)
    u16 ws_echo_close_code;         // code for the echo Close (set from the inspector on close)
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
    // Bidirectional Close handshake (RFC 6455 §5.5.1). When a Close is determined (a peer
    // sent Close, or the handler returned Close), terminate sends a Close frame to BOTH
    // peers and tears the connection down only once both Close sends have drained — so a
    // policy/peer close is graceful (the initiating client sees a Close, not EOF/1006). Per
    // send slot: `_need` = a Close still to submit on this slot, `_inflight` = a Close is
    // draining on it. close_conn fires when ws_closing and neither need nor inflight is set
    // on either slot. The forward Close (emitted by ws_inspect) starts its slot _inflight;
    // the echo Close (built into ws_close_frame_*) is submitted on the opposite slot.
    bool ws_closing;
    bool ws_close_client_need;        // Close still to send on the client slot (u->c)
    bool ws_close_client_inflight;    // a Close is draining on the client slot
    bool ws_close_upstream_need;      // Close still to send on the upstream slot (c->u)
    bool ws_close_upstream_inflight;  // a Close is draining on the upstream slot
    u8 ws_close_frame_client[12];     // echo Close frame to the client (unmasked, persists during
                                      // send)
    u8 ws_close_frame_upstream[12];   // echo Close frame to the upstream (masked)

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

    // Reserved for upstream I/O episode fencing. Deliberately preserved by
    // reset()/slot reuse; the transport slices will advance it before each
    // upstream episode so stale completions cannot match a later episode.
    u32 upstream_episode = 1;

    // Fail-closed terminal state for an exhausted io_uring episode token. Like
    // upstream_episode, this deliberately survives reset(): a quarantined slot
    // must never return to the allocator or wrap back to an old kernel token.
    bool upstream_episode_quarantined = false;

    // Persistent generation plus current-owner metadata for the bounded
    // explicit first-response deadline.  The generation deliberately survives
    // reset()/slot reuse; active ownership does not.
    u32 response_read_deadline_generation = 0;
    u32 response_read_deadline_owner_generation;
    u32 response_read_deadline_upstream_episode;
    u16 response_read_deadline_bundle_id;
    u8 response_read_deadline_seconds;
    ForwardResponseBufferingMode response_read_deadline_buffering;
    ResponseReadDeadlineProfile response_read_deadline_profile;
    u8 response_read_deadline_method;
    u8 response_read_deadline_route_method;
    ResponseReadDeadlineState response_read_deadline_state;
    bool response_read_deadline_first_batch;
    ResponseReadDeadlineProfile response_read_deadline_first_batch_profile;
    u8 response_read_deadline_first_batch_method;
    u8 response_read_deadline_first_batch_route_method;
    u32 response_read_deadline_first_batch_generation;
    u16 response_read_deadline_first_batch_bundle_id;
    ForwardResponseBufferingMode response_read_deadline_first_batch_buffering;
    ResponseReadDeadlineUploadProof response_read_deadline_upload;
    ResponseReadDeadlineUploadProof response_read_deadline_first_batch_upload;
    // Exact cumulative positive-copy proof for the current deadline owner.
    // Set only after whole-batch witness validation and preserved across
    // incomplete-header re-arms; cleared with active deadline ownership.
    u32 response_read_deadline_progress_generation;
    u32 response_read_deadline_progress_episode;
    u32 response_read_deadline_progress_bytes;
    // Bounded positive-Content-Length response owner.  This is selected only
    // after the strict GET response header is fully validated.  The counters
    // are monotonic across recv-buffer compaction and downstream send gaps.
    ResponseReadDeadlinePostCommitPhase response_read_deadline_post_commit_phase;
    u32 response_read_deadline_post_commit_generation;
    u32 response_read_deadline_post_commit_episode;
    u32 response_read_deadline_post_commit_raw_header_end;
    u32 response_read_deadline_post_commit_declared_body;
    u32 response_read_deadline_post_commit_origin_received;
    u32 response_read_deadline_post_commit_downstream_submitted;
    u32 response_read_deadline_post_commit_downstream_completed;
    u32 response_read_deadline_post_commit_inflight_body;
    // For the complete-Content-Length barrier this is the exact body prefix
    // selected for publication.  It equals declared_body on success, zero on
    // inactivity, and origin_received on a clean premature EOF.
    u32 response_read_deadline_post_commit_send_body;
    bool response_read_deadline_post_commit_close_after_drain;
    bool response_read_deadline_post_commit_pump_pending;
    // Exact downstream Send CQE ownership for the post-commit stream.  The
    // monotonically increasing token is encoded in io_uring user_data; the
    // tombstone survives retirement/request-boundary handoff so late CQEs
    // cannot steal a successor request's accounting.
    u32 response_read_deadline_send_generation = 0;
    u32 response_read_deadline_send_owner_generation;
    u32 response_read_deadline_send_tombstone_generation = 0;
    u32 response_read_deadline_send_deadline_generation;
    u32 response_read_deadline_send_upstream_episode;
    const u8* response_read_deadline_send_src;
    u32 response_read_deadline_send_len;
    i32 response_read_deadline_send_fd;
    ResponseReadDeadlineSendKind response_read_deadline_send_kind;
    bool response_read_deadline_send_owner_active;
    u32 response_read_deadline_send_close_generation = 0;
    bool response_read_deadline_send_close_target_owned = false;
    bool response_read_deadline_send_close_cancel_owned = false;

    bool next_response_read_deadline_send_generation() {
        if (response_read_deadline_send_generation == kNonUpstreamSendGenerationMask) return false;
        ++response_read_deadline_send_generation;
        response_read_deadline_send_owner_generation = response_read_deadline_send_generation;
        return true;
    }

    void clear_response_read_deadline_send_owner() {
        response_read_deadline_send_owner_generation = 0;
        response_read_deadline_send_deadline_generation = 0;
        response_read_deadline_send_upstream_episode = 0;
        response_read_deadline_send_src = nullptr;
        response_read_deadline_send_len = 0;
        response_read_deadline_send_fd = -1;
        response_read_deadline_send_kind = ResponseReadDeadlineSendKind::None;
        response_read_deadline_send_owner_active = false;
    }

    bool next_response_read_deadline_generation() {
        if (response_read_deadline_generation == 0xFFFFFFFFu) return false;
        ++response_read_deadline_generation;
        response_read_deadline_owner_generation = response_read_deadline_generation;
        return true;
    }

    void clear_response_read_deadline() {
        response_read_deadline_owner_generation = 0;
        response_read_deadline_upstream_episode = 0;
        response_read_deadline_bundle_id = 0;
        response_read_deadline_seconds = 0;
        response_read_deadline_buffering = ForwardResponseBufferingMode::None;
        response_read_deadline_profile = ResponseReadDeadlineProfile::None;
        response_read_deadline_method = 0xffu;
        response_read_deadline_route_method = 0xffu;
        response_read_deadline_state = ResponseReadDeadlineState::None;
        response_read_deadline_progress_generation = 0;
        response_read_deadline_progress_episode = 0;
        response_read_deadline_progress_bytes = 0;
        response_read_deadline_post_commit_phase = ResponseReadDeadlinePostCommitPhase::None;
        response_read_deadline_post_commit_generation = 0;
        response_read_deadline_post_commit_episode = 0;
        response_read_deadline_post_commit_raw_header_end = 0;
        response_read_deadline_post_commit_declared_body = 0;
        response_read_deadline_post_commit_origin_received = 0;
        response_read_deadline_post_commit_downstream_submitted = 0;
        response_read_deadline_post_commit_downstream_completed = 0;
        response_read_deadline_post_commit_inflight_body = 0;
        response_read_deadline_post_commit_send_body = 0;
        response_read_deadline_post_commit_close_after_drain = false;
        response_read_deadline_post_commit_pump_pending = false;
        clear_response_read_deadline_send_owner();
        response_read_deadline_first_batch = false;
        response_read_deadline_first_batch_profile = ResponseReadDeadlineProfile::None;
        response_read_deadline_first_batch_method = 0xffu;
        response_read_deadline_first_batch_route_method = 0xffu;
        response_read_deadline_first_batch_generation = 0;
        response_read_deadline_first_batch_bundle_id = 0;
        response_read_deadline_first_batch_buffering = ForwardResponseBufferingMode::None;
        response_read_deadline_upload = ResponseReadDeadlineUploadProof{};
        response_read_deadline_first_batch_upload = ResponseReadDeadlineUploadProof{};
    }

    void clear_http1_prebuilt_response_proof() {
        http1_prebuilt_response_layout = Http1PrebuiltResponseLayout::None;
        http1_prebuilt_response_purpose = Http1PrebuiltResponsePurpose::None;
        http1_prebuilt_deadline_profile = ResponseReadDeadlineProfile::None;
        http1_prebuilt_deadline_method = 0xffu;
        http1_prebuilt_deadline_route_method = 0xffu;
        http1_prebuilt_deadline_generation = 0;
        http1_prebuilt_deadline_bundle_id = 0;
        http1_prebuilt_deadline_config = nullptr;
        http1_prebuilt_deadline_upload = ResponseReadDeadlineUploadProof{};
        http1_prebuilt_header_end = 0;
        http1_prebuilt_total_len = 0;
        http1_prebuilt_body_len = 0;
        http1_prebuilt_status = 0;
    }

    // Advance the token without wrapping. Zero is the invalid sentinel and
    // max is the final representable token; callers must quarantine the
    // episode owner when this returns false rather than reusing an old token.
    bool next_upstream_episode() {
        if (!valid_upstream_episode(upstream_episode) ||
            upstream_episode == kIoUserDataMaxUpstreamEpisode)
            return false;
        ++upstream_episode;
        return true;
    }

    // Route config pinned for the lifetime of the current request. Set
    // in on_header_received from the loop's config pointer; referenced
    // by handle_jit_outcome (e.g., Forward upstream resolution) so a
    // config hot-swap during wait(ms) can't resolve an upstream_id
    // against the post-swap config. Cleared by reset().
    const RouteConfig* request_config;

    // Immutable process/listener identity copied at accept-time. Unlike
    // request_config this survives keep-alive request boundaries and is
    // cleared only when the connection slot is reset.
    ListenerContext listener_context;

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
    // Idle-reuse retry snapshot length. When a request is forwarded to a REUSED
    // pooled upstream socket, recv_buf is reset at request-sent (so pipelined
    // downstream bytes read during the wait flow through pipeline_recover, and the
    // just-sent request can't leak into the next request). To still allow the rare
    // post-send dead-socket fallback (origin FIN landing just after take_idle's
    // MSG_PEEK probe), the exact request bytes are snapshotted into the front of
    // send_buf. If the same client read also carried pipelined surplus, pipeline_stash
    // appends that suffix after this snapshot; pipeline_stash_len describes the suffix.
    // >0 means "a replayable copy lives in send_buf" and on_upstream_connected replays
    // [0, retry_req_send_len) instead of recv_buf. Reset at the per-request boundary
    // like the reuse flags.
    u32 retry_req_send_len;
    // A response mutation may pin the pre-override request in send_buf. Such a
    // snapshot still reserves the retry prefix for pipeline_stash layout, but it
    // is not replayable when the upstream received rewritten request bytes.
    bool retry_req_snapshot_replayable;
    bool response_mutations_snapshotted;
    bool req_malformed;  // true if request body is malformed (reject)
    // Non-zero when the explicit source request policy has rewritten recv_buf.
    // This is reset at the request boundary and is deliberately separate from
    // the route/config lifetime: the bytes are owned by this connection slice.
    u16 request_policy_id;
    // A policy Forward whose fixed Content-Length body has not arrived yet.
    // The JIT handler is invoked once; these compact fields retain its immutable
    // Forward outcome while the pinned request_config/epoch waits for the body.
    bool request_policy_body_pending;
    u16 pending_forward_upstream_id;
    u16 pending_forward_request_policy_id;
    u16 pending_forward_response_policy_id;
    u16 pending_forward_failure_policy_id;
    u16 pending_forward_timeout_failure_policy_id;
    // Semantic request facts kept separate from the transport's counters:
    // buffered means the complete fixed-CL request is staged, while upload
    // complete is published only after the upstream send finishes.
    bool request_body_fully_buffered;
    bool request_upload_complete;
    // Non-zero selects the strict H1 response serializer for this request.
    u16 response_policy_id;
    // Strict HEAD responses preserve the upstream representation length in the
    // downstream headers but never forward representation bytes.
    bool response_policy_suppress_body;
    // Non-zero selects the bounded H1 failure serializer for connect failures.
    u16 failure_policy_id;
    // Optional cause-specific timeout response selected with this request.
    // Foundation metadata only until #267 runtime wiring consumes it.
    u16 timeout_failure_policy_id;
    // Pinned per-request failure disposition.  This is deliberately separate
    // from the policy table so later request rewrites or config swaps cannot
    // change how an already selected connect failure is serialized.
    bool failure_policy_suppress_body;
    // Exact parsed request HTTP version (HttpVersion underlying value).
    u8 req_http_version;  // HttpVersion::Http10/Http11, 255 when unknown.
    // Request-side keep-alive intent of the CURRENT request, as parsed from its
    // request line + Connection header (HTTP/1.1 default true, HTTP/1.0 default
    // false, "Connection: close" → false). The proxy forwards the client's
    // request bytes (incl. its Connection header / version) verbatim upstream, so
    // this is what told the origin whether it may close after responding. Gate
    // upstream idle-pooling on THIS, not on conn.keep_alive (which is derived from
    // drain state, not the request). Recorded by capture_request_metadata.
    bool req_keep_alive;
    // Parsed downstream intent preserved across request-policy materialisation,
    // which rewrites req_keep_alive for the upstream request.
    bool req_client_keep_alive;
    bool req_client_connection_close;
    bool req_client_connection_close_exact;
    bool req_client_has_content_length;
    // Original request framing/upgrade facts captured before any request-policy
    // rewrite. SuppressBody HEAD admission must not lose these when rewritten
    // requests strip hop-by-hop fields.
    bool req_client_has_transfer_encoding;
    bool req_client_has_te;
    bool req_client_has_expect;
    bool req_client_has_upgrade_header;
    u8 req_client_connection_count;
    bool req_wants_upgrade;          // client sent Connection: upgrade (gates 101 tunnel)
    bool req_upgrade_is_websocket;   // the request Upgrade list offered "websocket"
    bool resp_upgrade_is_websocket;  // the backend 101 selected "websocket" (gates terminate)
    BodyMode req_body_mode;
    u32 req_body_remaining;          // bytes left for request body (Content-Length)
    ChunkedParser req_chunk_parser;  // for chunked request body end detection
    // True once any request-body byte has started streaming upstream (recv_buf is
    // reset + refilled with body chunks, so the original headers+body are gone).
    // Once set, the request can no longer be replayed from recv_buf, so the
    // reused-socket retry predicate refuses it. Reset at the per-request boundary.
    bool req_body_streamed;
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
    bool upstream_connect_armed;
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
    // Bounded io_uring strict-abandonment retirement state. The latest retiring
    // token remains as a tombstone after both owned finals drain and across
    // ordinary reset()/slot reuse, so an old final cannot fall into generic
    // stale-CQE accounting. A later proven retirement atomically replaces it
    // with the then-current token; it is initialized exactly once
    // here rather than being cleared by reset(). Active ownership/retry fields
    // are still reset normally and preserved explicitly by io_uring's deferred-
    // free path while kernel work pins the connection storage.
    u32 upstream_retiring_episode = 0;
    bool upstream_retirement_active;
    u8 upstream_retirement_target_owned;
    u8 upstream_retirement_cancel_owned;
    u8 upstream_retirement_cancel_retry;
    // A close may land after C2 admitted the successor episode while its
    // connect/send/recv is still in flight. Preserve exact target/cancel
    // ownership through reset so only matching successor CQEs drain accounting.
    // The episode remains as a tombstone after the masks reach zero.
    u32 upstream_close_episode;
    u8 upstream_close_target_owned;
    u8 upstream_close_cancel_owned;
    bool upstream_close_pause_cancel_owned;
    // Generic HTTP/1 request-boundary rendezvous used by io_uring while the
    // strict upstream recv episode above drains. Request-completion bookkeeping
    // has already run when deferred is set; buffered downstream bytes must not
    // enter the next request until the loop consumes ready at batch end. The
    // successor episode binds the marker to this exact live slot generation.
    bool http1_boundary_deferred;
    bool http1_boundary_ready;
    u32 http1_boundary_successor_episode;
    // Internal, policy-agnostic prebuilt-header rendezvous. HeaderSend and
    // UpstreamRetirement are independently owned wait bits; request 2 is
    // admitted only after both clear and the batch-end scan consumes readiness.
    // A non-None disposition is the active marker even after the wait mask is
    // zero. The exact prefix remains pinned until retirement and header send no
    // longer reference recv/send slices.
    u8 http1_prebuilt_wait;
    Http1RequestBufferDisposition http1_prebuilt_disposition;
    u32 http1_prebuilt_request_prefix_len;
    Http1PrebuiltResponseLayout http1_prebuilt_response_layout;
    Http1PrebuiltResponsePurpose http1_prebuilt_response_purpose;
    ResponseReadDeadlineProfile http1_prebuilt_deadline_profile;
    u8 http1_prebuilt_deadline_method;
    u8 http1_prebuilt_deadline_route_method;
    u32 http1_prebuilt_deadline_generation;
    u16 http1_prebuilt_deadline_bundle_id;
    const RouteConfig* http1_prebuilt_deadline_config;
    ResponseReadDeadlineUploadProof http1_prebuilt_deadline_upload;
    u32 http1_prebuilt_header_end;
    u32 http1_prebuilt_total_len;
    u32 http1_prebuilt_body_len;
    u16 http1_prebuilt_status;
    // True when an idle-return stale upstream recv CQE carried bytes. The stale branch
    // rolls those bytes back out of upstream_recv_buf, so the deferred pool-return path
    // needs this separate marker to close rather than reuse a desynced fd.
    bool upstream_recv_idle_stale_bytes;
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

    // Ownership transferred from request timing after completion bookkeeping
    // but before a deferred continuation releases the RCU config epoch. HTTP/2
    // async streams use it while parked without h1-style request metrics; the
    // internal HTTP/1 prebuilt-response rendezvous uses it after req_start_us is
    // cleared and before batch-end request-boundary admission.
    bool epoch_held;

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
        upstream_keep_alive = false;
        upstream_reused = false;
        upstream_request_incomplete = false;
        idle_return_fd = -1;
        idle_return_uid = 0;
        idle_return_bidx = 0;
        idle_return_config = nullptr;
        close_after_idle_return = false;
        is_health_probe = false;
        h2_proxy_recv_draining = false;
        h2_proxy_synth_quarantined = false;
        req_path_overridden = false;
        req_path_override = {nullptr, 0};
        target_transform_id = 0;
        target_transform_recorded = false;
        req_header_override_count = 0;
        req_header_append_mask = 0;
        req_header_override_overflow = false;
        resp_header_mutation_pending_count = 0;
        resp_header_mutation_pending_overflow = false;
        resp_header_mutation_count = 0;
        resp_header_mutation_overflow = false;
        response_header_slice = nullptr;
        response_header_buf.bind(nullptr, 0);
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
        ws_upgrade_sent_len = 0;
        ws_pre_tunnel_upstream_closed = false;
        ws_client_eof = false;
        ws_upstream_eof = false;
        is_ws_terminate_route = false;
        is_ws_terminate = false;
        ws_handler = nullptr;
        ws_max_message_size = 0;
        ws_close_code = 1000;
        ws_echo_close_code = 1000;
        ws_c2u.reset();
        ws_u2c.reset();
        ws_c2u.message_len = 0;
        ws_u2c.message_len = 0;
        ws_c2u_msg = nullptr;
        ws_u2c_msg = nullptr;
        ws_c2u_consumed = 0;
        ws_u2c_consumed = 0;
        ws_closing = false;
        ws_close_client_need = false;
        ws_close_client_inflight = false;
        ws_close_upstream_need = false;
        ws_close_upstream_inflight = false;
        handler_state = 0;
        pending_yield_kind = jit::YieldKind::Timer;
        resume_event_kind = jit::YieldKind::Timer;
        resume_event_result = 0;
        handler_ctx = nullptr;
        // Deliberately NOT reset here: handler_gen persists across
        // reset() so a stale YieldHeap entry whose target slot was
        // recycled reliably fails the generation match. It's
        // initialized at accept-time via EventLoop::alloc_conn_impl.
        // upstream_episode follows the same persistence rule for the future
        // upstream-event token contract and is intentionally not reset here.
        // response_read_deadline_generation follows that persistence rule too;
        // only the live owner is cleared.
        clear_response_read_deadline();
        response_read_deadline_send_close_generation = 0;
        response_read_deadline_send_close_target_owned = false;
        response_read_deadline_send_close_cancel_owned = false;
        request_config = nullptr;
        listener_context = {};
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
        retry_req_send_len = 0;
        retry_req_snapshot_replayable = true;
        response_mutations_snapshotted = false;
        req_malformed = false;
        request_policy_id = 0;
        request_policy_body_pending = false;
        pending_forward_upstream_id = 0;
        pending_forward_request_policy_id = 0;
        pending_forward_response_policy_id = 0;
        pending_forward_failure_policy_id = 0;
        pending_forward_timeout_failure_policy_id = 0;
        request_body_fully_buffered = false;
        request_upload_complete = false;
        response_policy_id = 0;
        response_policy_suppress_body = false;
        failure_policy_id = 0;
        timeout_failure_policy_id = 0;
        failure_policy_suppress_body = false;
        req_http_version = 255;
        req_keep_alive = false;
        req_client_keep_alive = false;
        req_client_connection_close = false;
        req_client_connection_close_exact = false;
        req_client_has_content_length = false;
        req_client_has_transfer_encoding = false;
        req_client_has_te = false;
        req_client_has_expect = false;
        req_client_has_upgrade_header = false;
        req_client_connection_count = 0;
        req_wants_upgrade = false;
        req_upgrade_is_websocket = false;
        resp_upgrade_is_websocket = false;
        req_body_mode = BodyMode::None;
        req_body_remaining = 0;
        req_chunk_parser.reset();
        req_body_streamed = false;
        resp_body_mode = BodyMode::None;
        resp_body_remaining = 0;
        resp_chunk_parser.reset();
        resp_body_sent = 0;
        upstream_send_len = 0;
        recv_armed = false;
        send_armed = false;
        upstream_connect_armed = false;
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
        // upstream_retiring_episode deliberately persists across reset()/reuse;
        // see its declaration. Active ownership never does.
        upstream_retirement_active = false;
        upstream_retirement_target_owned = 0;
        upstream_retirement_cancel_owned = 0;
        upstream_retirement_cancel_retry = 0;
        upstream_close_episode = 0;
        upstream_close_target_owned = 0;
        upstream_close_cancel_owned = 0;
        upstream_close_pause_cancel_owned = false;
        http1_boundary_deferred = false;
        http1_boundary_ready = false;
        http1_boundary_successor_episode = 0;
        http1_prebuilt_wait = 0;
        http1_prebuilt_disposition = Http1RequestBufferDisposition::None;
        http1_prebuilt_request_prefix_len = 0;
        clear_http1_prebuilt_response_proof();
        upstream_recv_idle_stale_bytes = false;
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
        epoch_held = false;
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
