#pragma once

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/upstream_pool.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut {

// Per-shard round-robin cursor for upstream backend (load-balancing)
// selection. Shards are share-nothing — one OS thread each — so a thread_local
// table is naturally per-shard: no atomics, no cross-shard contention (same
// rationale as the thread_local parse cache). Returns the index into
// UpstreamTarget::addrs[] to use for the next connect to `upstream_id`.
// A single-backend upstream (count <= 1) always returns 0.
inline u32 next_backend_index(u16 upstream_id, u32 backend_count) {
    static thread_local u16 rr_cursor[RouteConfig::kMaxUpstreams] = {};
    if (backend_count <= 1 || upstream_id >= RouteConfig::kMaxUpstreams) return 0;
    const u32 kIdx = rr_cursor[upstream_id] % backend_count;
    rr_cursor[upstream_id] = static_cast<u16>(rr_cursor[upstream_id] + 1);
    return kIdx;
}

u8 map_log_method(HttpMethod method);
u8 parse_log_method_fallback(const u8* data, u32 len, u32* method_len);
void capture_request_metadata(Connection& conn);
u32 pipeline_leftover(const Connection& conn);
bool pipeline_shift(Connection& conn);
void pipeline_stash(Connection& conn);
bool pipeline_recover(Connection& conn);
void capture_stage_headers(Connection& conn);
const char* status_reason(u16 code);
void format_static_response(Connection& conn, u16 code, bool keep_alive);
// Custom-body variant: writes status line + Content-Length matching
// body_len + default Content-Type (text/plain; charset=utf-8) + body
// bytes. For codes that must have no body (1xx / 204 / 304) falls
// back to format_static_response.
void format_response_with_body(
    Connection& conn, u16 code, const char* body_data, u32 body_len, bool keep_alive);

// Custom-headers variant: emits each `headers[i]` pair (indexed
// [0, header_count)) before the blank line. If any user-supplied key
// case-insensitively matches "Content-Type", the default text/plain
// Content-Type is suppressed so the user's value wins. User-supplied
// "Content-Length" is skipped — the formatter recomputes it from
// `body_len` to keep the framing honest. For codes that must have no
// body (1xx / 204 / 304), headers are still emitted (they can be
// meaningful on 204/304, e.g. Cache-Control) but the body is omitted
// per spec. If the precomputed response size won't fit in the
// connection's send_buf, fails closed with a 500 + Connection: close.
//
// `body_is_fallback_reason_phrase` tells the formatter the body bytes
// are a system-generated status-reason phrase (e.g. "OK" after an
// invalid body_idx config mismatch), not user content. In that case
// the default Content-Type is suppressed even when body_len > 0 —
// matches format_static_response's wire shape so the "fallback"
// semantic is consistent regardless of whether custom headers were
// present.
struct ResponseHeaderKV {
    const char* key_data;
    u32 key_len;
    const char* value_data;
    u32 value_len;
};
void format_response_with_body_and_headers(Connection& conn,
                                           u16 code,
                                           const char* body_data,
                                           u32 body_len,
                                           const ResponseHeaderKV* headers,
                                           u32 header_count,
                                           bool keep_alive,
                                           bool body_is_fallback_reason_phrase = false);
void prepare_early_response_state(Connection& conn);
u32 consume_upstream_sent(Connection& conn);

extern const char kResponse200[];
extern const char kResponse200Close[];

template <typename Loop>
void on_request_complete(Loop* loop, Connection& conn, u16 status, u32 resp_size);

// ── JIT handler dispatch ───────────────────────────────────────────
// Route-matched JitHandler action → invoke the compiled handler and
// translate JitDispatchOutcome into event-loop operations (send, forward,
// register timer for resume, or 500). Shared between the initial call
// (on_header_received) and timer-driven resumes.
template <typename Loop>
void handle_jit_outcome(Loop* loop,
                        Connection& conn,
                        const JitDispatchOutcome& outcome,
                        jit::HandlerFn fn,
                        bool keep_alive);

// Called from timer.tick when the timer firing was a JIT handler yield
// (conn.pending_handler_fn != nullptr). Re-enters the handler with
// ctx.state = conn.handler_state, then re-dispatches on the outcome.
template <typename Loop>
void resume_jit_handler(Loop* loop, Connection& conn);

template <typename Loop>
void pipeline_dispatch(Loop* loop, Connection& conn);

template <typename Loop>
void handle_early_upstream_recv(Loop* loop, Connection& conn, IoEvent ev, bool send_in_flight);

template <typename Loop>
void on_request_complete(Loop* loop, Connection& conn, u16 status, u32 resp_size) {
    const u32 kDurationUs = static_cast<u32>(monotonic_us() - conn.req_start_us);

    // Clear req_start_us so close_conn_impl knows no request is in flight.
    conn.req_start_us = 0;

    if (loop->metrics) {
        loop->metrics->on_request_complete(kDurationUs);
    }

    if (loop->access_log) {
        AccessLogEntry entry{};
        entry.timestamp_us = realtime_us();
        entry.duration_us = kDurationUs;
        entry.status = status;
        entry.method = conn.req_method;
        entry.shard_id = conn.shard_id;
        entry.resp_size = resp_size;
        entry.req_size = conn.req_size;
        entry.addr = conn.peer_addr;
        entry.upstream_us = conn.upstream_us;
        for (u32 i = 0; i < sizeof(entry.path); i++) {
            entry.path[i] = conn.req_path[i];
            if (conn.req_path[i] == '\0') break;
        }
        for (u32 i = 0; i < sizeof(entry.upstream); i++) {
            entry.upstream[i] = conn.upstream_name[i];
            if (conn.upstream_name[i] == '\0') break;
        }
        loop->access_log->push(entry);
    }

    if (loop->capture_ring && conn.capture_buf && conn.capture_header_len > 0) {
        CaptureEntry* cap_entry = nullptr;
        u32 expected_wp = 0;
        if (!loop->capture_ring->begin_push(&cap_entry, &expected_wp)) {
            return;
        }
        auto* cap = cap_entry;
        __builtin_memset(cap, 0, sizeof(*cap));
        cap->timestamp_us = realtime_us();
        cap->req_content_length = conn.req_content_length;
        cap->resp_content_length = resp_size;
        cap->resp_status = status;
        cap->raw_header_len = conn.capture_header_len;
        cap->peer_port = conn.peer_port;
        cap->method = conn.req_method;
        cap->shard_id = conn.shard_id;
        cap->flags =
            (conn.capture_header_len == CaptureEntry::kMaxHeaderLen) ? kCaptureFlagTruncated : 0;
        constexpr u32 kCopyLen = sizeof(conn.upstream_name) < sizeof(cap->upstream_name)
                                     ? sizeof(conn.upstream_name)
                                     : sizeof(cap->upstream_name);
        for (u32 i = 0; i < kCopyLen; i++) {
            cap->upstream_name[i] = conn.upstream_name[i];
            if (conn.upstream_name[i] == '\0') break;
        }
        __builtin_memcpy(cap->raw_headers, conn.capture_buf, conn.capture_header_len);
        loop->capture_ring->commit_push(expected_wp);
    }
}

template <typename Loop>
void pipeline_dispatch(Loop* loop, Connection& conn) {
    conn.transition_to_reading_header(&on_header_received<Loop>);
    // Refresh keepalive timer — synthetic dispatch skips the normal
    // EventLoop::dispatch() which calls timer.refresh().
    loop->timer.refresh(&conn, loop->keepalive_timeout);
    const IoEvent kSynth = {
        conn.id, static_cast<i32>(conn.recv_buf.len()), 0, 0, IoEventType::Recv, 0};
    on_header_received<Loop>(static_cast<void*>(loop), conn, kSynth);
}

template <typename Loop>
void on_header_received(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    // Slot: on_recv. dispatch_event guarantees ev.type == Recv.
    conn.send_progress = 0;

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    // HTTP/2 entry: either ALPN negotiated h2 (TLS), or the cleartext h2c
    // connection preface appears on the wire. A real HTTP/1 request never
    // starts with the preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), so the
    // prefix check can't misfire on HTTP/1 traffic.
    if (conn.protocol == ConnProtocol::Http2) {
        enter_h2<Loop>(loop, conn, ev);
        return;
    }
    if (!conn.tls_active && conn.pipeline_depth == 0) {
        const ParseStatus kPf = match_client_preface(conn.recv_buf.data(), conn.recv_buf.len());
        if (kPf == ParseStatus::Complete) {
            conn.protocol = ConnProtocol::Http2;
            enter_h2<Loop>(loop, conn, ev);
            return;
        }
        if (kPf == ParseStatus::Incomplete) {
            // A strict prefix of the preface so far — wait for the full 24 bytes
            // before committing to h2c.
            conn.transition_to_reading_header(&on_header_received<Loop>);
            loop->submit_recv(conn);
            return;
        }
    }

    // NOTE: recv_buf is NOT reset here — proxy flow needs recv_buf.data()
    // for upstream forwarding. Reset happens in on_response_sent / on_proxy_response_sent
    // when the cycle completes and we're about to read the next request.

    // Check if the buffer contains a complete request before proceeding.
    // For pipelined re-entries, an incomplete request should wait for more
    // data instead of getting a spurious default response.
    if (conn.pipeline_depth > 0) {
        HttpParser pre_parser;
        ParsedRequest pre_req;
        pre_parser.reset();
        if (pre_parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &pre_req) ==
            ParseStatus::Incomplete) {
            // Keep pipeline_depth > 0 so subsequent recvs also check for
            // Incomplete (multi-packet reassembly of the pipelined request).
            conn.transition_to_reading_header(&on_header_received<Loop>);
            loop->submit_recv(conn);
            return;
        }
    }

    capture_request_metadata(conn);

    // Tag the request with a fresh generation so the yield-heap stale
    // filter can reliably reject entries left by a close+reuse even if
    // the new request's req_start_us lands in the same microsecond.
    conn.handler_gen++;
    conn.req_start_us = monotonic_us();
    if (loop->capture_ring) capture_stage_headers(conn);
    loop->epoch_enter();
    if (loop->metrics) loop->metrics->on_request_start();

    const bool kKeepAlive = !loop->is_draining();
    conn.keep_alive = kKeepAlive;

    // Route matching: config_ptr → active RouteConfig (may be null in tests).
    // Pin on the connection so handle_jit_outcome resumes (post-wait) see
    // the same config the route was matched against — hot-swap during a
    // long wait(ms) could otherwise resolve upstream_id against a
    // different upstream table.
    const RouteConfig* config = loop->config_ptr ? *loop->config_ptr : nullptr;
    conn.request_config = config;
    if (config && !config->firewall_allows_peer(conn.peer_addr, conn.peer_port)) {
        conn.resp_status = 403;
        format_static_response(conn, 403, /*keep_alive=*/false);
        conn.keep_alive = false;
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }
    const RouteEntry* route = nullptr;
    RouteParam route_params[kMaxRouteParams]{};
    u32 route_param_count = 0;
    if (config) {
        const u8 kMethodKey = route_method_key(static_cast<LogHttpMethod>(conn.req_method));
        // Use the parser-supplied canonical view (PR #50 round 7 path A)
        // to skip the redundant canon scan and the strlen-style scan
        // over conn.req_path. The parser only populates path_canon for
        // origin-form request-targets; non-origin-form (asterisk-form
        // "*", authority-form "host:port") leaves req_path_canon as
        // {nullptr, 0}, and match_canonical's null-ptr guard returns
        // nullptr (miss) so those targets cannot fall into a "/" catchall.
        // {non-null ptr, len=0} remains a legitimate canonical view of
        // the origin-form root "/" and dispatches normally.
        route = config->match_canonical(
            conn.req_path_canon, kMethodKey, route_params, &route_param_count, kMaxRouteParams);
    }

    if (route && route->action == RouteAction::Proxy) {
        conn.state = ConnState::Proxying;
        auto& target = config->upstreams[route->upstream_id];
        for (u32 i = 0; i < sizeof(conn.upstream_name) && i < target.name_len; i++)
            conn.upstream_name[i] = target.name[i];
        if (target.name_len < sizeof(conn.upstream_name))
            conn.upstream_name[target.name_len] = '\0';
        else
            conn.upstream_name[sizeof(conn.upstream_name) - 1] = '\0';
        const i32 kUpstreamFd = UpstreamPool::create_socket();
        if (kUpstreamFd < 0) {
            conn.resp_status = kStatusBadGateway;
            format_static_response(conn, 502, false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        conn.upstream_fd = kUpstreamFd;
        conn.upstream_idx = route->upstream_id;
        conn.upstream_start_us = monotonic_us();
        conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
        const u32 kBackend = next_backend_index(route->upstream_id, target.addr_count);
        if (!loop->submit_connect(conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
            ::close(conn.upstream_fd);
            conn.upstream_fd = -1;
            conn.upstream_idx = 0;
            loop->clear_upstream_fd(conn.id);
            conn.resp_status = kStatusBadGateway;
            format_static_response(conn, 502, false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
    } else if (route && route->action == RouteAction::Static) {
        conn.resp_status = route->status_code;
        format_static_response(conn, route->status_code, kKeepAlive);
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
    } else if (route && route->action == RouteAction::JitHandler && route->fn) {
        if (route->needs_req_body) {
            if (conn.req_body_mode == BodyMode::Chunked) {
                conn.resp_status = 400;
                format_static_response(conn, 400, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            if (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) {
                conn.transition_to_reading_body(&on_jit_request_body_recvd<Loop>);
                loop->submit_recv(conn);
                return;
            }
        }
        conn.handler_state = 0;  // entry state
        conn.transition_to_exec_handler_wait();
        auto* ctx = conn.reset_jit_ctx();
        ctx->state = 0;
        ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
        ctx->resume_event_result = 0;
        ctx->route_param_count = route_param_count;
        for (u32 i = 0; i < route_param_count; i++) ctx->route_params[i] = route_params[i];
        conn.send_buf.reset();
        auto outcome = invoke_jit_handler(route->fn,
                                          static_cast<void*>(&conn),
                                          *ctx,
                                          conn.recv_buf.data(),
                                          conn.recv_buf.len(),
                                          /*arena=*/nullptr);
        handle_jit_outcome<Loop>(loop, conn, outcome, route->fn, kKeepAlive);
    } else {
        conn.resp_status = kStatusOK;
        conn.send_buf.reset();
        if (kKeepAlive)
            conn.send_buf.write(reinterpret_cast<const u8*>(kResponse200), kResponse200Len);
        else
            conn.send_buf.write(reinterpret_cast<const u8*>(kResponse200Close),
                                kResponse200CloseLen);
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
    }
}

template <typename Loop>
void on_jit_request_body_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    if (conn.req_body_mode != BodyMode::ContentLength || conn.req_body_remaining == 0) {
        loop->close_conn(conn);
        return;
    }

    u32 consume = static_cast<u32>(ev.result);
    if (consume > conn.req_body_remaining) consume = conn.req_body_remaining;
    conn.req_body_remaining -= consume;
    conn.req_size += consume;
    conn.req_initial_send_len =
        conn.req_header_end + (conn.req_content_length - conn.req_body_remaining);

    if (conn.req_body_remaining > 0) {
        conn.transition_to_reading_body(&on_jit_request_body_recvd<Loop>);
        loop->submit_recv(conn);
        return;
    }

    const RouteConfig* config = conn.request_config;
    const RouteEntry* route = nullptr;
    RouteParam route_params[kMaxRouteParams]{};
    u32 route_param_count = 0;
    if (config) {
        const u8 kMethodKey = route_method_key(static_cast<LogHttpMethod>(conn.req_method));
        route = config->match_canonical(
            conn.req_path_canon, kMethodKey, route_params, &route_param_count, kMaxRouteParams);
    }
    if (!route || route->action != RouteAction::JitHandler || !route->fn) {
        loop->close_conn(conn);
        return;
    }

    conn.handler_state = 0;
    conn.transition_to_exec_handler_wait();
    auto* ctx = conn.reset_jit_ctx();
    ctx->state = 0;
    ctx->resume_event_kind = static_cast<u32>(jit::YieldKind::Timer);
    ctx->resume_event_result = 0;
    ctx->route_param_count = route_param_count;
    for (u32 i = 0; i < route_param_count; i++) ctx->route_params[i] = route_params[i];
    conn.send_buf.reset();
    auto outcome = invoke_jit_handler(route->fn,
                                      static_cast<void*>(&conn),
                                      *ctx,
                                      conn.recv_buf.data(),
                                      conn.recv_buf.len(),
                                      /*arena=*/nullptr);
    handle_jit_outcome<Loop>(loop, conn, outcome, route->fn, conn.keep_alive);
}

template <typename Loop>
void on_response_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const u32 kSendLen = conn.send_buf.len();
    const u32 kResult = static_cast<u32>(ev.result);

    if (ev.result < 0) {
        loop->close_conn(conn);
        return;
    }

    if (conn.send_progress > kSendLen) {
        loop->close_conn(conn);
        return;
    }
    if (kResult > (kSendLen - conn.send_progress)) {
        loop->close_conn(conn);
        return;
    }
    conn.send_progress += kResult;

    if (conn.send_progress < kSendLen) {
        if (kResult == 0u) {
            // No progress cannot guarantee eventual completion.
            loop->close_conn(conn);
            return;
        }

        const u32 kRemaining = kSendLen - conn.send_progress;
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data() + conn.send_progress, kRemaining);
        return;
    }

    // Send complete — clear all slots (will set on_recv for keep-alive below).
    conn.send_progress = 0;
    conn.clear_slots();

    on_request_complete(loop, conn, conn.resp_status, conn.send_buf.len());
    conn.send_buf.reset();
    loop->epoch_leave();

    if (conn.upstream_fd >= 0) {
        ::close(conn.upstream_fd);
        conn.upstream_fd = -1;
    }
    conn.upstream_idx = 0;
    loop->clear_upstream_fd(conn.id);
    conn.upstream_recv_armed = false;
    conn.upstream_send_armed = false;

    if (!conn.keep_alive) {
        loop->close_conn(conn);
        return;
    }

    if (pipeline_shift(conn)) {
        pipeline_dispatch<Loop>(loop, conn);
        return;
    }
    conn.pipeline_depth = 0;
    conn.recv_buf.reset();
    conn.transition_to_reading_header(&on_header_received<Loop>);
    loop->submit_recv(conn);
}

template <typename Loop>
void on_jit_wait_send_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const u32 kSendLen = conn.send_buf.len();
    const u32 kResult = ev.result < 0 ? 0u : static_cast<u32>(ev.result);

    if (ev.result < 0) {
        loop->close_conn(conn);
        return;
    }

    if (conn.send_progress > kSendLen) {
        loop->close_conn(conn);
        return;
    }
    if (kResult > (kSendLen - conn.send_progress)) {
        loop->close_conn(conn);
        return;
    }
    conn.send_progress += kResult;

    if (conn.send_progress < kSendLen) {
        if (kResult == 0u) {
            loop->close_conn(conn);
            return;
        }

        const u32 kRemaining = kSendLen - conn.send_progress;
        conn.transition_to_sending(&on_jit_wait_send_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data() + conn.send_progress, kRemaining);
        return;
    }

    conn.send_progress = 0;
    conn.send_buf.reset();
    conn.transition_to_exec_handler_wait();
    conn.recv_paused_for_send = false;
    conn.resume_event_kind = jit::YieldKind::Send;
    conn.resume_event_result = static_cast<i32>(kSendLen);
    resume_jit_handler<Loop>(loop, conn);
}

template <typename Loop>
void handle_jit_outcome(Loop* loop,
                        Connection& conn,
                        const JitDispatchOutcome& outcome,
                        jit::HandlerFn fn,
                        bool keep_alive) {
    switch (outcome.kind) {
        case JitDispatchOutcome::Kind::ReturnStatus: {
            conn.pending_handler_fn = nullptr;
            conn.resp_status = outcome.status_code;
            // ABI: upstream_id is a 1-based index into the pinned
            // route config's response_bodies table (0 = use default
            // status-reason body). Out-of-range indices fall back to
            // the default rather than rendering garbage.
            const RouteConfig* cfg = conn.request_config;
            const bool has_body = outcome.response_body_idx != 0 && cfg != nullptr &&
                                  outcome.response_body_idx <= cfg->response_body_count;
            const bool has_headers = outcome.response_headers_idx != 0 && cfg != nullptr &&
                                     outcome.response_headers_idx <= cfg->response_header_set_count;
            // Distinguish "user didn't supply a body" (body_idx == 0)
            // from "user supplied one but it's out of range" (a config
            // mismatch). The latter falls back to the reason-phrase
            // default so the response still has a representative body
            // — matches the no-headers path's documented behavior of
            // falling back rather than rendering garbage.
            const bool body_idx_invalid = outcome.response_body_idx != 0 && !has_body;
            if (has_headers) {
                // Materialise the header set into a stack-local KV
                // array so the formatter takes a uniform view.
                // RouteConfig::kMaxHeadersPerSet is enforced at
                // add_response_header_set time, so ref.count can
                // never exceed our buffer size — no silent truncation.
                const auto& ref = cfg->response_header_sets[outcome.response_headers_idx - 1];
                ResponseHeaderKV kvs[RouteConfig::kMaxHeadersPerSet];
                for (u16 i = 0; i < ref.count; i++) {
                    kvs[i].key_data = cfg->header_keys[ref.offset + i].data;
                    kvs[i].key_len = cfg->header_keys[ref.offset + i].len;
                    kvs[i].value_data = cfg->header_values[ref.offset + i].data;
                    kvs[i].value_len = cfg->header_values[ref.offset + i].len;
                }
                const char* body_data = nullptr;
                u32 body_len = 0;
                bool body_is_fallback = false;
                if (has_body) {
                    const auto& body = cfg->response_bodies[outcome.response_body_idx - 1];
                    body_data = body.data;
                    body_len = body.len;
                } else if (body_idx_invalid) {
                    // Out-of-range body_idx + headers present: render
                    // the default reason-phrase as body so the
                    // fallback matches the no-headers path's "fall
                    // back rather than render garbage" rule. Flag it
                    // so the formatter suppresses the default
                    // Content-Type (format_static_response doesn't
                    // advertise one for reason-phrase bodies either).
                    const char* reason = status_reason(outcome.status_code);
                    u32 reason_len = 0;
                    while (reason[reason_len]) reason_len++;
                    body_data = reason;
                    body_len = reason_len;
                    body_is_fallback = true;
                }
                format_response_with_body_and_headers(conn,
                                                      outcome.status_code,
                                                      body_data,
                                                      body_len,
                                                      kvs,
                                                      ref.count,
                                                      keep_alive,
                                                      body_is_fallback);
            } else if (has_body) {
                const auto& body = cfg->response_bodies[outcome.response_body_idx - 1];
                format_response_with_body(
                    conn, outcome.status_code, body.data, body.len, keep_alive);
            } else {
                format_static_response(conn, outcome.status_code, keep_alive);
            }
            conn.transition_to_sending(&on_response_sent<Loop>);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        case JitDispatchOutcome::Kind::TimerYield: {
            // Stash fn + next_state so the resume path can re-enter the
            // handler with ctx.state = handler_state. Slots stay clear —
            // no recv/send in flight while sleeping. Delegates to the
            // loop's schedule_yield_timer: ms precision on both backends
            // (IORING_OP_TIMEOUT on io_uring, one-shot timerfd + min-heap
            // on epoll).
            conn.pending_handler_fn = fn;
            conn.handler_state = outcome.next_state;
            conn.pending_yield_kind = jit::YieldKind::Timer;
            conn.transition_to_exec_handler_wait();
            if (loop->schedule_yield_timer(conn, outcome.timer_ms)) return;
            // Couldn't schedule faithfully (SQ / heap catastrophically
            // pressured AND wait too long for the wheel fallback). Fail
            // the request rather than resume early and silently violate
            // wait(ms) semantics.
            conn.pending_handler_fn = nullptr;
            conn.resp_status = 500;
            format_static_response(conn, 500, /*keep_alive=*/false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            // schedule_yield_timer already called timer.remove(&conn);
            // re-arm keepalive before the send so a stalled response
            // (client backpressure) can't leak the slot indefinitely.
            // on_response_sent's normal dispatch refresh would eventually
            // cover it, but only if the Send CQE arrives.
            loop->timer.add(&conn, loop->keepalive_timeout);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        case JitDispatchOutcome::Kind::EventYield: {
            conn.pending_handler_fn = fn;
            conn.handler_state = outcome.next_state;
            conn.pending_yield_kind = outcome.yield_kind;
            conn.transition_to_exec_handler_wait();
            auto send_bad_gateway = [&]() {
                conn.pending_handler_fn = nullptr;
                conn.resp_status = kStatusBadGateway;
                format_static_response(conn, 502, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            };
            auto send_internal_error = [&]() {
                conn.pending_handler_fn = nullptr;
                conn.resp_status = 500;
                format_static_response(conn, 500, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            };
            auto upstream_target_matches = [&]() {
                if (conn.upstream_fd < 0) return false;
                if (outcome.timer_ms == 0) return true;
                return conn.upstream_idx == static_cast<u16>(outcome.timer_ms - 1);
            };
            if constexpr (requires { Loop::kSupportsEventYieldResume; }) {
                if (!Loop::kSupportsEventYieldResume) {
                    send_internal_error();
                    return;
                }
            }
            if (outcome.yield_kind == jit::YieldKind::Send) {
                if (conn.send_buf.len() == 0) {
                    conn.transition_to_exec_handler_wait();
                    conn.resume_event_kind = jit::YieldKind::Send;
                    conn.resume_event_result = 0;
                    resume_jit_handler<Loop>(loop, conn);
                    return;
                }
                conn.transition_to_sending(&on_jit_wait_send_sent<Loop>);
                if (!loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len())) {
                    // The send couldn't be queued (io_uring add_send returns
                    // false under SQ pressure), so no Send completion will ever
                    // arrive to call on_jit_wait_send_sent and resume the
                    // handler. Fail closed like the other event-yield arms whose
                    // submit_* couldn't be started, rather than leaving
                    // pending_handler_fn parked until keepalive.
                    send_internal_error();
                    return;
                }
                if constexpr (requires(Loop* lp, Connection& c) { lp->pause_recv(c); }) {
                    if (!loop->pause_recv(conn)) {
                        loop->close_conn(conn);
                        return;
                    }
                } else if constexpr (requires(Loop* lp, u32 conn_id) {
                                         lp->backend.pause_recv(conn_id, true);
                                     }) {
                    loop->backend.pause_recv(conn.id, true);
                } else if constexpr (requires(Loop* lp, u32 conn_id) {
                                         lp->backend.pause_recv(conn_id);
                                     }) {
                    loop->backend.pause_recv(conn.id);
                }
                return;
            } else if (outcome.yield_kind == jit::YieldKind::UpstreamConnect &&
                       outcome.timer_ms != 0) {
                const RouteConfig* config = conn.request_config;
                const u32 upstream_id = outcome.timer_ms - 1;
                if (!config || upstream_id >= config->upstream_count) {
                    conn.pending_handler_fn = nullptr;
                    conn.resp_status = kStatusBadGateway;
                    format_static_response(conn, 502, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                auto& target = config->upstreams[upstream_id];
                const i32 kUpstreamFd = UpstreamPool::create_socket();
                if (kUpstreamFd < 0) {
                    conn.pending_handler_fn = nullptr;
                    conn.resp_status = kStatusBadGateway;
                    format_static_response(conn, 502, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                if (conn.upstream_fd >= 0) {
                    ::close(conn.upstream_fd);
                    conn.upstream_fd = -1;
                    conn.upstream_idx = 0;
                    loop->clear_upstream_fd(conn.id);
                    conn.upstream_recv_armed = false;
                    conn.upstream_send_armed = false;
                }
                conn.upstream_fd = kUpstreamFd;
                conn.upstream_idx = static_cast<u16>(upstream_id);
                conn.upstream_start_us = monotonic_us();
                const u32 kBackend =
                    next_backend_index(static_cast<u16>(upstream_id), target.addr_count);
                if (!loop->submit_connect(
                        conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
                    ::close(conn.upstream_fd);
                    conn.upstream_fd = -1;
                    conn.upstream_idx = 0;
                    loop->clear_upstream_fd(conn.id);
                    send_bad_gateway();
                    return;
                }
            } else if (outcome.yield_kind == jit::YieldKind::UpstreamSend) {
                if (upstream_target_matches()) {
                    if (!loop->submit_send_upstream(
                            conn, conn.recv_buf.data(), conn.recv_buf.len())) {
                        send_bad_gateway();
                        return;
                    }
                } else {
                    send_bad_gateway();
                    return;
                }
            } else if (outcome.yield_kind == jit::YieldKind::UpstreamRecv) {
                if (upstream_target_matches()) {
                    if (!loop->submit_recv_upstream(conn)) {
                        send_bad_gateway();
                        return;
                    }
                } else {
                    send_bad_gateway();
                    return;
                }
            }
            const bool waits_downstream_recv = outcome.yield_kind == jit::YieldKind::Any ||
                                               outcome.yield_kind == jit::YieldKind::Recv;
            if (!waits_downstream_recv) {
                if constexpr (requires(Loop* lp, u32 conn_id) {
                                  lp->backend.pause_recv(conn_id);
                              }) {
                    loop->backend.pause_recv(conn.id);
                }
            }
            if (outcome.yield_kind == jit::YieldKind::Any && outcome.timer_ms != 0 &&
                !loop->schedule_yield_timer(conn, outcome.timer_ms)) {
                send_internal_error();
                loop->timer.refresh(&conn, loop->keepalive_timeout);
                return;
            }
            auto disarm_yield_timer = [&]() {
                if constexpr (requires(Loop* lp, Connection& c) { lp->disarm_yield_timer(c); }) {
                    loop->disarm_yield_timer(conn);
                } else {
                    conn.yield_armed = false;
                }
            };
            if ((outcome.yield_kind == jit::YieldKind::Any ||
                 outcome.yield_kind == jit::YieldKind::Recv) &&
                conn.recv_pause_cancel_pending) {
                conn.recv_pause_rearm_pending = true;
            }
            if ((outcome.yield_kind == jit::YieldKind::Any ||
                 outcome.yield_kind == jit::YieldKind::Recv) &&
                conn.fd >= 0 && !conn.recv_armed) {
                if (!loop->submit_recv(conn)) {
                    if (conn.yield_armed) {
                        disarm_yield_timer();
                        loop->timer.refresh(&conn, loop->keepalive_timeout);
                    }
                    send_internal_error();
                    return;
                }
            }
            // io_uring keeps the multishot downstream recv armed across upstream
            // waits so client FINs / pipelined bytes still surface a Recv CQE
            // (handled by the mid-yield dispatch branch). A preceding non-empty
            // wait(downstream.send()) cancels that recv via pause_recv; calling
            // submit_recv here re-arms it when the cancel has already drained,
            // or marks recv_pause_rearm_pending so the in-flight cancel
            // completion re-arms — covering both Send/cancel CQE orderings. It
            // is a no-op when recv is still armed (the normal upstream-wait
            // case). Gated to the io_uring loop via the pause_recv(conn)
            // member; epoll deliberately masks EPOLLIN for these waits above.
            if constexpr (requires(Loop* lp, Connection& c) { lp->pause_recv(c); }) {
                const bool kWaitsUpstream = outcome.yield_kind == jit::YieldKind::UpstreamConnect ||
                                            outcome.yield_kind == jit::YieldKind::UpstreamRecv ||
                                            outcome.yield_kind == jit::YieldKind::UpstreamSend;
                if (kWaitsUpstream && conn.fd >= 0 && !conn.recv_paused_for_send) {
                    // Best-effort: under SQ pressure the upstream op or
                    // keepalive still bounds the wait, so a missed FIN detector
                    // must not fail the in-flight upstream request.
                    (void)loop->submit_recv(conn);
                }
            }
            return;
        }
        case JitDispatchOutcome::Kind::Forward: {
            conn.pending_handler_fn = nullptr;
            // Resolve upstream by id against the config pinned at
            // on_header_received. Reading loop->config_ptr here would
            // pick up a post-swap config whose upstream table doesn't
            // match the indexing the handler compiled against.
            const RouteConfig* config = conn.request_config;
            if (!config || outcome.upstream_id >= config->upstream_count) {
                // Unresolvable upstream id — handler returned a value
                // the config doesn't know. Fail closed with 502 rather
                // than hanging or silently discarding the request.
                conn.resp_status = kStatusBadGateway;
                format_static_response(conn, 502, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            conn.state = ConnState::Proxying;
            auto& target = config->upstreams[outcome.upstream_id];
            for (u32 i = 0; i < sizeof(conn.upstream_name) && i < target.name_len; i++)
                conn.upstream_name[i] = target.name[i];
            if (target.name_len < sizeof(conn.upstream_name))
                conn.upstream_name[target.name_len] = '\0';
            else
                conn.upstream_name[sizeof(conn.upstream_name) - 1] = '\0';
            if (conn.upstream_fd >= 0) {
                ::close(conn.upstream_fd);
                conn.upstream_fd = -1;
                conn.upstream_idx = 0;
                loop->clear_upstream_fd(conn.id);
                conn.upstream_recv_armed = false;
                conn.upstream_send_armed = false;
            }
            const i32 kUpstreamFd = UpstreamPool::create_socket();
            if (kUpstreamFd < 0) {
                conn.resp_status = kStatusBadGateway;
                format_static_response(conn, 502, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            conn.upstream_fd = kUpstreamFd;
            conn.upstream_start_us = monotonic_us();
            conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
            const u32 kBackend =
                next_backend_index(static_cast<u16>(outcome.upstream_id), target.addr_count);
            loop->submit_connect(conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]));
            return;
        }
        case JitDispatchOutcome::Kind::Error:
        default:
            // Handler returned an unsupported action kind (or nullptr fn);
            // fail closed with 500 rather than hang.
            conn.pending_handler_fn = nullptr;
            conn.resp_status = 500;
            format_static_response(conn, 500, /*keep_alive=*/false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
    }
}

template <typename Loop>
void resume_jit_handler(Loop* loop, Connection& conn) {
    // A yielded handler can resume while still on the keepalive wheel
    // (pure event waits) or after schedule_yield_timer removed it.
    // refresh handles both without double-inserting the intrusive node.
    loop->timer.refresh(&conn, loop->keepalive_timeout);
    auto* fn = conn.pending_handler_fn;
    auto* ctx = conn.jit_ctx();
    ctx->state = conn.handler_state;
    ctx->resume_event_kind = static_cast<u32>(conn.resume_event_kind);
    ctx->resume_event_result = conn.resume_event_result;
    auto outcome = invoke_jit_handler(fn,
                                      static_cast<void*>(&conn),
                                      *ctx,
                                      conn.recv_buf.data(),
                                      conn.recv_buf.len(),
                                      /*arena=*/nullptr);
    handle_jit_outcome<Loop>(loop, conn, outcome, fn, conn.keep_alive);
}

template <typename Loop>
void on_upstream_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result < 0) {
        static const char k502[] =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Length: 11\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Gateway";
        conn.send_buf.reset();
        conn.send_buf.write(reinterpret_cast<const u8*>(k502), sizeof(k502) - 1);
        conn.keep_alive = false;
        conn.resp_status = kStatusBadGateway;
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    if (conn.req_malformed) {
        loop->close_conn(conn);
        return;
    }

    if (!loop->alloc_upstream_buf(conn)) {
        loop->close_conn(conn);
        return;
    }

    conn.state = ConnState::Proxying;
    u32 req_send_len =
        conn.req_initial_send_len > 0 ? conn.req_initial_send_len : conn.recv_buf.len();
    if (req_send_len > conn.recv_buf.len()) req_send_len = conn.recv_buf.len();
    conn.set_slots(nullptr,
                   nullptr,
                   &on_early_upstream_recvd_send_inflight<Loop>,
                   &on_upstream_request_sent<Loop>);
    loop->submit_send_upstream(conn, conn.recv_buf.data(), req_send_len);
}

template <typename Loop>
void on_upstream_request_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result < 0) {
        if (conn.upstream_recv_buf.len() > 0) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            IoEvent synth = {conn.id,
                             static_cast<i32>(conn.upstream_recv_buf.len()),
                             0,
                             0,
                             IoEventType::UpstreamRecv,
                             0};
            on_upstream_response<Loop>(lp, conn, synth);
            return;
        }
        if (conn.upstream_recv_armed) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            loop->submit_recv_upstream(conn);
            return;
        }
        if (conn.upstream_fd >= 0) {
            const u32 kAvail = conn.upstream_recv_buf.write_avail();
            if (kAvail > 0) {
                ssize_t nr;
                do {
                    nr = recv(conn.upstream_fd, conn.upstream_recv_buf.write_ptr(), kAvail, 0);
                } while (nr < 0 && errno == EINTR);
                if (nr > 0) {
                    conn.upstream_recv_buf.commit(static_cast<u32>(nr));
                    prepare_early_response_state(conn);
                    conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
                    IoEvent synth = {
                        conn.id, static_cast<i32>(nr), 0, 0, IoEventType::UpstreamRecv, 0};
                    on_upstream_response<Loop>(lp, conn, synth);
                    return;
                }
            }
        }
        loop->close_conn(conn);
        return;
    }

    const bool kMoreReqBody =
        (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) ||
        (conn.req_body_mode == BodyMode::Chunked &&
         conn.req_chunk_parser.state != ChunkedParser::State::Complete);
    if (kMoreReqBody) {
        conn.recv_buf.reset();
        conn.set_slots(
            &on_request_body_recvd<Loop>, nullptr, &on_early_upstream_recvd<Loop>, nullptr);
        loop->submit_recv(conn);
        loop->submit_recv_upstream(conn);
        return;
    }

    pipeline_stash(conn);
    conn.recv_buf.reset();
    conn.upstream_start_us = monotonic_us();
    conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
    if (conn.upstream_recv_buf.len() > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(conn.upstream_recv_buf.len()),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0};
        on_upstream_response<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

template <typename Loop>
void on_response_header_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    conn.set_slots(nullptr, nullptr, &on_response_body_recvd<Loop>, nullptr);
    const u32 kRemaining = consume_upstream_sent(conn);
    if (kRemaining > 0) {
        IoEvent synth = {conn.id, static_cast<i32>(kRemaining), 0, 0, IoEventType::UpstreamRecv, 0};
        on_response_body_recvd<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

template <typename Loop>
void on_response_body_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        if (conn.resp_body_mode == BodyMode::UntilClose) {
            on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
            loop->epoch_leave();
            loop->close_conn(conn);
            return;
        }
        loop->close_conn(conn);
        return;
    }

    const u32 kDataLen = conn.upstream_recv_buf.len();
    u32 send_len = kDataLen;

    if (conn.resp_body_mode == BodyMode::ContentLength) {
        u32 consume = kDataLen;
        if (consume > conn.resp_body_remaining) consume = conn.resp_body_remaining;
        conn.resp_body_remaining -= consume;
        send_len = consume;
    } else if (conn.resp_body_mode == BodyMode::Chunked) {
        const u8* body_data = conn.upstream_recv_buf.data();
        u32 pos = 0;
        while (pos < kDataLen) {
            u32 consumed = 0, out_start = 0, out_len = 0;
            const ChunkStatus kChunkStatus = conn.resp_chunk_parser.feed(
                body_data + pos, kDataLen - pos, &consumed, &out_start, &out_len);
            pos += consumed;
            if (kChunkStatus == ChunkStatus::Done) break;
            if (kChunkStatus == ChunkStatus::Error) {
                loop->close_conn(conn);
                return;
            }
            if (kChunkStatus == ChunkStatus::NeedMore) break;
        }
        send_len = pos;
    }

    conn.resp_body_sent += send_len;
    conn.upstream_send_len = send_len;
    conn.transition_to_sending(&on_response_body_sent<Loop>);
    loop->submit_send(conn, conn.upstream_recv_buf.data(), send_len);
}

template <typename Loop>
void on_response_body_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    conn.clear_slots();
    const u32 kRemaining = consume_upstream_sent(conn);

    bool body_done = false;
    if (conn.resp_body_mode == BodyMode::ContentLength) {
        body_done = (conn.resp_body_remaining == 0);
    } else if (conn.resp_body_mode == BodyMode::Chunked) {
        body_done = (conn.resp_chunk_parser.state == ChunkedParser::State::Complete);
    }

    if (body_done) {
        conn.upstream_recv_buf.reset();

        on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
        loop->epoch_leave();

        if (conn.upstream_fd >= 0) {
            ::close(conn.upstream_fd);
            conn.upstream_fd = -1;
        }
        loop->clear_upstream_fd(conn.id);
        conn.upstream_recv_armed = false;
        conn.upstream_send_armed = false;

        if (!conn.keep_alive || loop->is_draining()) {
            loop->close_conn(conn);
            return;
        }

        if (conn.pipeline_stash_len > 0 && conn.recv_buf.len() > 0) {
            const u16 kStashLen = conn.pipeline_stash_len;
            const u32 kLateLen = conn.recv_buf.len();
            if (static_cast<u32>(kStashLen) + kLateLen > conn.recv_buf.capacity()) {
                conn.pipeline_stash_len = 0;
                conn.send_buf.reset();
                loop->close_conn(conn);
                return;
            }
            conn.pipeline_stash_len = 0;
            conn.upstream_recv_buf.reset();
            conn.upstream_recv_buf.write(conn.recv_buf.data(), kLateLen);
            conn.recv_buf.reset();
            conn.recv_buf.write(conn.send_buf.data(), kStashLen);
            conn.recv_buf.write(conn.upstream_recv_buf.data(), kLateLen);
            conn.upstream_recv_buf.reset();
            conn.send_buf.reset();
            conn.pipeline_depth++;
            pipeline_dispatch<Loop>(loop, conn);
            return;
        }
        if (pipeline_recover(conn)) {
            pipeline_dispatch<Loop>(loop, conn);
            return;
        }
        if (conn.recv_buf.len() > 0) {
            conn.pipeline_depth++;
            pipeline_dispatch<Loop>(loop, conn);
            return;
        }
        conn.pipeline_depth = 0;
        conn.recv_buf.reset();
        conn.transition_to_reading_header(&on_header_received<Loop>);
        loop->submit_recv(conn);
        return;
    }

    conn.set_slots(nullptr, nullptr, &on_response_body_recvd<Loop>, nullptr);
    if (kRemaining > 0) {
        IoEvent synth = {conn.id, static_cast<i32>(kRemaining), 0, 0, IoEventType::UpstreamRecv, 0};
        on_response_body_recvd<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

template <typename Loop>
void handle_early_upstream_recv(Loop* loop, Connection& conn, IoEvent ev, bool send_in_flight) {
    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        loop->close_conn(conn);
        return;
    }
    if (ev.result <= 0) {
        conn.on_upstream_send = &on_body_send_with_early_response<Loop>;
        conn.on_upstream_recv = nullptr;
        return;
    }
    HttpResponseParser resp_parser;
    ParsedResponse resp;
    resp.reset();
    resp_parser.reset();
    const ParseStatus kParseStatus =
        resp_parser.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &resp);
    const bool kCanRearm = !conn.upstream_recv_armed && !send_in_flight;
    if (kParseStatus == ParseStatus::Incomplete) {
        if (kCanRearm) loop->submit_recv_upstream(conn);
        return;
    }
    if (kParseStatus == ParseStatus::Complete && resp.status_code >= 100 &&
        resp.status_code < 200 && resp.status_code != 101) {
        const u32 kInterimEnd = resp_parser.header_end;
        const u32 kTotal = conn.upstream_recv_buf.len();
        if (kInterimEnd < kTotal) {
            const u32 kRemaining = kTotal - kInterimEnd;
            const u8* src = conn.upstream_recv_buf.data() + kInterimEnd;
            conn.upstream_recv_buf.reset();
            u8* dst = conn.upstream_recv_buf.write_ptr();
            __builtin_memmove(dst, src, kRemaining);
            conn.upstream_recv_buf.commit(kRemaining);
            handle_early_upstream_recv<Loop>(loop, conn, ev, send_in_flight);
            return;
        }
        conn.upstream_recv_buf.reset();
        if (kCanRearm) loop->submit_recv_upstream(conn);
        return;
    }
    conn.on_upstream_send = &on_body_send_with_early_response<Loop>;
    conn.on_upstream_recv = nullptr;
}

template <typename Loop>
void on_body_send_with_early_response(void* lp, Connection& conn, IoEvent ev) {
    (void)ev;

    prepare_early_response_state(conn);
    conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);

    HttpResponseParser probe;
    ParsedResponse probe_resp;
    probe_resp.reset();
    probe.reset();
    const ParseStatus kParseStatus =
        probe.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &probe_resp);
    const i32 kSynthResult = (kParseStatus == ParseStatus::Incomplete)
                                 ? 0
                                 : static_cast<i32>(conn.upstream_recv_buf.len());
    IoEvent synth = {conn.id, kSynthResult, 0, 0, IoEventType::UpstreamRecv, 0};
    on_upstream_response<Loop>(lp, conn, synth);
}

template <typename Loop>
void on_request_body_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        if (conn.upstream_recv_buf.len() > 0) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            IoEvent synth = {conn.id,
                             static_cast<i32>(conn.upstream_recv_buf.len()),
                             0,
                             0,
                             IoEventType::UpstreamRecv,
                             0};
            on_upstream_response<Loop>(lp, conn, synth);
            return;
        }
        if (conn.upstream_recv_armed) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            loop->submit_recv_upstream(conn);
            return;
        }
        if (conn.upstream_fd >= 0) {
            const u32 kAvail = conn.upstream_recv_buf.write_avail();
            if (kAvail > 0) {
                ssize_t nr;
                do {
                    nr = recv(conn.upstream_fd, conn.upstream_recv_buf.write_ptr(), kAvail, 0);
                } while (nr < 0 && errno == EINTR);
                if (nr > 0) {
                    conn.upstream_recv_buf.commit(static_cast<u32>(nr));
                    prepare_early_response_state(conn);
                    conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
                    IoEvent synth = {
                        conn.id, static_cast<i32>(nr), 0, 0, IoEventType::UpstreamRecv, 0};
                    on_upstream_response<Loop>(lp, conn, synth);
                    return;
                }
            }
        }
        loop->close_conn(conn);
        return;
    }

    bool body_done = false;
    if (conn.req_body_mode == BodyMode::ContentLength) {
        body_done = (conn.req_body_remaining == 0);
    } else if (conn.req_body_mode == BodyMode::Chunked) {
        body_done = (conn.req_chunk_parser.state == ChunkedParser::State::Complete);
    }

    if (body_done) {
        pipeline_stash(conn);
        conn.recv_buf.reset();
        conn.upstream_start_us = monotonic_us();
        if (conn.upstream_recv_buf.len() == 0) conn.upstream_recv_buf.reset();
        conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
        if (conn.upstream_recv_buf.len() > 0) {
            IoEvent synth = {conn.id,
                             static_cast<i32>(conn.upstream_recv_buf.len()),
                             0,
                             0,
                             IoEventType::UpstreamRecv,
                             0};
            on_upstream_response<Loop>(lp, conn, synth);
        } else {
            loop->submit_recv_upstream(conn);
        }
        return;
    }

    conn.recv_buf.reset();
    conn.set_slots(&on_request_body_recvd<Loop>, nullptr, &on_early_upstream_recvd<Loop>, nullptr);
    loop->submit_recv(conn);
    loop->submit_recv_upstream(conn);
}

template <typename Loop>
void on_early_upstream_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    handle_early_upstream_recv<Loop>(loop, conn, ev, false);
    if (conn.on_upstream_send == &on_body_send_with_early_response<Loop>) {
        on_body_send_with_early_response<Loop>(lp, conn, ev);
    }
}

template <typename Loop>
void on_early_upstream_recvd_send_inflight(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    handle_early_upstream_recv<Loop>(loop, conn, ev, true);
}

template <typename Loop>
void on_request_body_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    const u32 kDataLen = conn.recv_buf.len();
    u32 send_len = kDataLen;
    if (conn.req_body_mode == BodyMode::ContentLength) {
        u32 consume = kDataLen;
        if (consume > conn.req_body_remaining) consume = conn.req_body_remaining;
        conn.req_body_remaining -= consume;
        send_len = consume;
    } else if (conn.req_body_mode == BodyMode::Chunked) {
        const u8* body_data = conn.recv_buf.data();
        u32 pos = 0;
        while (pos < kDataLen) {
            u32 consumed = 0, out_start = 0, out_len = 0;
            const ChunkStatus kChunkStatus = conn.req_chunk_parser.feed(
                body_data + pos, kDataLen - pos, &consumed, &out_start, &out_len);
            pos += consumed;
            if (kChunkStatus == ChunkStatus::Done) break;
            if (kChunkStatus == ChunkStatus::Error) {
                loop->close_conn(conn);
                return;
            }
            if (kChunkStatus == ChunkStatus::NeedMore) break;
        }
        send_len = pos;
    }

    conn.req_size += send_len;
    conn.req_initial_send_len = send_len;
    conn.set_slots(nullptr,
                   nullptr,
                   &on_early_upstream_recvd_send_inflight<Loop>,
                   &on_request_body_sent<Loop>);
    loop->submit_send_upstream(conn, conn.recv_buf.data(), send_len);
}

template <typename Loop>
void on_upstream_response(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (conn.upstream_start_us != 0) {
        conn.upstream_us = static_cast<u32>(monotonic_us() - conn.upstream_start_us);
        conn.upstream_start_us = 0;
    }

    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        loop->close_conn(conn);
        return;
    }

    HttpResponseParser resp_parser;
    ParsedResponse resp;
    resp.reset();
    resp_parser.reset();
    ParseStatus ps =
        resp_parser.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &resp);
    if (ps == ParseStatus::Incomplete) {
        if (ev.result <= 0)
            ps = ParseStatus::Error;
        else {
            loop->submit_recv_upstream(conn);
            return;
        }
    }
    if (ps == ParseStatus::Error) {
        if (conn.upstream_fd >= 0) {
            ::close(conn.upstream_fd);
            conn.upstream_fd = -1;
        }
        static const char k502[] =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Length: 11\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Gateway";
        conn.send_buf.reset();
        conn.send_buf.write(reinterpret_cast<const u8*>(k502), sizeof(k502) - 1);
        conn.keep_alive = false;
        conn.resp_status = kStatusBadGateway;
        conn.transition_to_sending(&on_response_sent<Loop>);
        loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }
    conn.resp_status = resp.status_code;

    if (resp.status_code >= 100 && resp.status_code < 200 && resp.status_code != 101) {
        const u32 kInterimEnd = resp_parser.header_end;
        const u32 kTotal = conn.upstream_recv_buf.len();
        if (kInterimEnd < kTotal) {
            const u32 kRemaining = kTotal - kInterimEnd;
            const u8* src = conn.upstream_recv_buf.data() + kInterimEnd;
            conn.upstream_recv_buf.reset();
            u8* dst = conn.upstream_recv_buf.write_ptr();
            __builtin_memmove(dst, src, kRemaining);
            conn.upstream_recv_buf.commit(kRemaining);
            on_upstream_response<Loop>(lp, conn, ev);
            return;
        }
        conn.upstream_recv_buf.reset();
        loop->submit_recv_upstream(conn);
        return;
    }

    const bool kIsHead = (conn.req_method == static_cast<u8>(LogHttpMethod::Head));
    const bool kNoBodyStatus =
        resp.status_code == 204 || resp.status_code == 205 || resp.status_code == 304;

    if (kIsHead || kNoBodyStatus) {
        conn.resp_body_mode = BodyMode::None;
        conn.resp_body_remaining = 0;
    } else if (resp.chunked) {
        conn.resp_body_mode = BodyMode::Chunked;
        conn.resp_chunk_parser.reset();
        conn.resp_body_remaining = 0;
    } else if (resp.has_content_length) {
        conn.resp_body_mode = BodyMode::ContentLength;
        conn.resp_body_remaining = resp.content_length;
    } else {
        conn.resp_body_mode = BodyMode::UntilClose;
        conn.resp_body_remaining = 0;
    }

    const u32 kHeaderLen = resp_parser.header_end;
    const u32 kTotalLen = conn.upstream_recv_buf.len();
    const u32 kInitialBodyLen = (kTotalLen > kHeaderLen) ? kTotalLen - kHeaderLen : 0;

    if (conn.resp_body_mode == BodyMode::ContentLength && kInitialBodyLen > 0) {
        u32 consume = kInitialBodyLen;
        if (consume > conn.resp_body_remaining) consume = conn.resp_body_remaining;
        conn.resp_body_remaining -= consume;
    }

    bool chunked_done = false;
    u32 chunked_consumed = kInitialBodyLen;
    if (conn.resp_body_mode == BodyMode::Chunked && kInitialBodyLen > 0) {
        const u8* body_start = conn.upstream_recv_buf.data() + kHeaderLen;
        u32 pos = 0;
        while (pos < kInitialBodyLen) {
            u32 consumed = 0, out_start = 0, out_len = 0;
            const ChunkStatus kChunkStatus = conn.resp_chunk_parser.feed(
                body_start + pos, kInitialBodyLen - pos, &consumed, &out_start, &out_len);
            pos += consumed;
            if (kChunkStatus == ChunkStatus::Done) {
                chunked_done = true;
                break;
            }
            if (kChunkStatus == ChunkStatus::Error) {
                if (conn.upstream_fd >= 0) {
                    ::close(conn.upstream_fd);
                    conn.upstream_fd = -1;
                }
                static const char k502[] =
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Length: 11\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "Bad Gateway";
                conn.send_buf.reset();
                conn.send_buf.write(reinterpret_cast<const u8*>(k502), sizeof(k502) - 1);
                conn.keep_alive = false;
                conn.resp_status = kStatusBadGateway;
                conn.transition_to_sending(&on_response_sent<Loop>);
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            if (kChunkStatus == ChunkStatus::NeedMore) break;
        }
        chunked_consumed = pos;
    }

    if (loop->is_draining()) {
        u8* d = const_cast<u8*>(conn.upstream_recv_buf.data());
        const u32 kLen = conn.upstream_recv_buf.len();
        const u32 kHdrEnd =
            (resp_parser.header_end >= kHeaderEndLen) ? resp_parser.header_end - kHeaderEndLen : 0;

        bool rewritten = false;
        if (kHdrEnd > 0) {
            for (u32 j = 0; j + 14 <= kHdrEnd; j++) {
                if (d[j] == '\r' && d[j + 1] == '\n' && ascii_ci_eq(d + j + 2, "connection", 10) &&
                    d[j + 12] == ':') {
                    u32 val_start = j + 13;
                    while (val_start < kHdrEnd && d[val_start] == ' ') val_start++;
                    u32 val_end = val_start;
                    while (val_end + 1 < kHdrEnd && (d[val_end] != '\r' || d[val_end + 1] != '\n'))
                        val_end++;
                    const u32 kValLen = val_end - val_start;
                    if (kValLen >= 5) {
                        d[val_start] = 'c';
                        d[val_start + 1] = 'l';
                        d[val_start + 2] = 'o';
                        d[val_start + 3] = 's';
                        d[val_start + 4] = 'e';
                        for (u32 k = val_start + 5; k < val_end; k++) d[k] = ' ';
                        rewritten = true;
                    }
                    break;
                }
            }
        }

        if (!rewritten && kHdrEnd > 0) {
            const u32 kBodyStart = kHdrEnd + kHeaderEndLen;
            const u32 kRawBodyLen = (kLen > kBodyStart) ? kLen - kBodyStart : 0;
            u32 body_len = kRawBodyLen;
            if (conn.resp_body_mode == BodyMode::None)
                body_len = 0;
            else if (conn.resp_body_mode == BodyMode::ContentLength &&
                     body_len > resp.content_length)
                body_len = resp.content_length;
            static const char kConnClose[] = "Connection: close\r\n";
            if (kHdrEnd + kConnCloseLen + kHeaderEndLen + body_len <= conn.send_buf.capacity()) {
                conn.send_buf.reset();
                conn.send_buf.write(d, kHdrEnd + 2);
                conn.send_buf.write(reinterpret_cast<const u8*>(kConnClose), kConnCloseLen);
                conn.send_buf.write(d + kHdrEnd + 2, 2 + body_len);
                conn.keep_alive = false;
                conn.resp_body_sent = conn.send_buf.len();
                const bool kDrainBodyDone =
                    (conn.resp_body_mode == BodyMode::None) ||
                    (conn.resp_body_mode == BodyMode::ContentLength &&
                     conn.resp_body_remaining == 0) ||
                    (conn.resp_body_mode == BodyMode::Chunked && chunked_done);
                if (!kDrainBodyDone) {
                    conn.transition_to_sending(&on_response_header_sent<Loop>);
                } else {
                    conn.transition_to_sending(&on_response_sent<Loop>);
                }
                conn.upstream_send_len = conn.upstream_recv_buf.len();
                loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
        }
    }

    bool body_complete = false;
    if (conn.resp_body_mode == BodyMode::None) {
        body_complete = true;
    } else if (conn.resp_body_mode == BodyMode::ContentLength) {
        body_complete = (conn.resp_body_remaining == 0);
    } else if (conn.resp_body_mode == BodyMode::Chunked) {
        body_complete = chunked_done;
    }

    u32 actual_body = kInitialBodyLen;
    if (conn.resp_body_mode == BodyMode::None)
        actual_body = 0;
    else if (conn.resp_body_mode == BodyMode::ContentLength &&
             kInitialBodyLen > resp.content_length)
        actual_body = resp.content_length;
    else if (conn.resp_body_mode == BodyMode::Chunked)
        actual_body = chunked_consumed;
    u32 initial_send_len = kHeaderLen + actual_body;

    conn.resp_body_sent = initial_send_len;
    conn.upstream_send_len = initial_send_len;

    if (body_complete) {
        conn.transition_to_sending(&on_proxy_response_sent<Loop>);
        loop->submit_send(conn, conn.upstream_recv_buf.data(), initial_send_len);
    } else {
        conn.transition_to_sending(&on_response_header_sent<Loop>);
        loop->submit_send(conn, conn.upstream_recv_buf.data(), initial_send_len);
    }
}

template <typename Loop>
void on_proxy_response_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    conn.clear_slots();

    if (ev.result < 0) {
        loop->close_conn(conn);
        return;
    }

    on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
    loop->epoch_leave();

    if (loop->is_draining()) {
        loop->close_conn(conn);
        return;
    }

    conn.upstream_recv_buf.reset();

    if (conn.upstream_fd >= 0) {
        ::close(conn.upstream_fd);
        conn.upstream_fd = -1;
    }
    loop->clear_upstream_fd(conn.id);
    conn.upstream_recv_armed = false;
    conn.upstream_send_armed = false;

    if (conn.pipeline_stash_len > 0 && conn.recv_buf.len() > 0) {
        const u16 kStashLen = conn.pipeline_stash_len;
        const u32 kLateLen = conn.recv_buf.len();
        if (static_cast<u32>(kStashLen) + kLateLen > conn.recv_buf.capacity()) {
            conn.pipeline_stash_len = 0;
            conn.send_buf.reset();
            loop->close_conn(conn);
            return;
        }
        conn.pipeline_stash_len = 0;
        conn.upstream_recv_buf.reset();
        conn.upstream_recv_buf.write(conn.recv_buf.data(), kLateLen);
        conn.recv_buf.reset();
        conn.recv_buf.write(conn.send_buf.data(), kStashLen);
        conn.recv_buf.write(conn.upstream_recv_buf.data(), kLateLen);
        conn.upstream_recv_buf.reset();
        conn.send_buf.reset();
        conn.pipeline_depth++;
        pipeline_dispatch<Loop>(loop, conn);
        return;
    }
    if (pipeline_recover(conn)) {
        pipeline_dispatch<Loop>(loop, conn);
        return;
    }
    if (conn.recv_buf.len() > 0) {
        conn.pipeline_depth++;
        pipeline_dispatch<Loop>(loop, conn);
        return;
    }
    conn.pipeline_depth = 0;
    conn.recv_buf.reset();
    conn.transition_to_reading_header(&on_header_received<Loop>);
    loop->submit_recv(conn);
}

}  // namespace rut
