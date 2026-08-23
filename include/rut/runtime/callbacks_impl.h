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
#include "rut/runtime/prometheus.h"
#include "rut/runtime/rate_limit.h"
#include "rut/runtime/rate_limit_enforce.h"
#include "rut/runtime/response_read_deadline.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/slice_pool.h"  // SlicePool::kSliceSize (terminate reassembly cap)
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/tls_iouring.h"  // tls_fill_output / TlsFill for the io_uring-TLS proxy path
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/upstream_pool.h"
#include "rut/runtime/ws_terminate.h"  // ws_inspect for terminate-mode tunnels
#include <ctime>

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/rand.h>  // RAND_bytes — fresh outbound mask-key seed (terminate mode)
#include <sys/socket.h>
#include <unistd.h>

namespace rut {

// --- Upstream backend selection + passive health (circuit breaking) ---
//
// Shards are share-nothing — one OS thread each — so per-shard state lives in
// thread_local tables: no atomics, no cross-shard contention (same rationale as
// the thread_local parse cache). Two tables, indexed by upstream_id (and backend
// index): a round-robin cursor, and a passive-health record per backend.
//
// Passive circuit breaking: after kBackendFailThreshold consecutive connect
// failures a backend is ejected for kBackendEjectCooldownUs; selection skips
// ejected backends. A successful connect clears the record.
inline constexpr u16 kBackendFailThreshold = 3;
inline constexpr u64 kBackendEjectCooldownUs = 5'000'000;  // 5s

struct BackendHealth {
    u16 fails;           // consecutive connect failures
    u64 eject_until_us;  // passively ejected while now < this (0 = healthy)
    bool active_down;    // active-probe failure: down until a probe SUCCEEDS (no timed expiry)
};

// thread_local health table. Returns a mutable ref, or nullptr if indices are
// out of range (caller then treats the backend as always-healthy).
inline BackendHealth* backend_health(u16 upstream_id, u32 backend_idx) {
    static thread_local BackendHealth health[RouteConfig::kMaxUpstreams]
                                            [UpstreamTarget::kMaxBackends] = {};
    if (upstream_id >= RouteConfig::kMaxUpstreams || backend_idx >= UpstreamTarget::kMaxBackends)
        return nullptr;
    return &health[upstream_id][backend_idx];
}

inline bool backend_ejected(u16 upstream_id, u32 backend_idx, u64 now_us) {
    const BackendHealth* h = backend_health(upstream_id, backend_idx);
    if (h == nullptr) return false;
    // `active_down` (an active-probe failure) has no timed expiry — only a
    // successful probe clears it, so it suppresses the backend independent of the
    // passive 5s cooldown (which would otherwise resume routing to a dead backend
    // between probes when the health-check interval exceeds the cooldown).
    return h->active_down || now_us < h->eject_until_us;
}

// Record the outcome of a connect attempt to (upstream_id, backend_idx).
// On success: clear the record. On failure: bump the consecutive-failure count
// and eject the backend once it crosses the threshold.
inline void record_backend_result(u16 upstream_id, u32 backend_idx, bool success, u64 now_us) {
    BackendHealth* h = backend_health(upstream_id, backend_idx);
    if (h == nullptr) return;
    if (success) {
        h->fails = 0;
        h->eject_until_us = 0;
        return;
    }
    if (h->fails < 0xffff) h->fails++;
    if (h->fails >= kBackendFailThreshold) h->eject_until_us = now_us + kBackendEjectCooldownUs;
}

// Record the outcome of an ACTIVE health probe to (upstream_id, backend_idx).
// Unlike passive ejection — a fixed 5s cooldown — an active failure keeps the
// backend out of rotation until a probe SUCCEEDS: `active_down` is the authority
// and has no timed expiry. This closes the gap where, with health_check.interval
// > kBackendEjectCooldownUs, the passive cooldown would lapse between probes and
// select_backend would resume routing to a still-dead backend. On success the
// backend is fully healthy again: clear active_down AND the passive fail/eject
// record. (`fails` is still bumped on failure for observability; active_down is
// what select_backend honors.)
inline void record_active_probe_result(u16 upstream_id, u32 backend_idx, bool healthy, u64 now_us) {
    (void)now_us;  // active suppression is success-gated, not time-gated
    BackendHealth* h = backend_health(upstream_id, backend_idx);
    if (h == nullptr) return;
    if (healthy) {
        h->active_down = false;
        h->fails = 0;
        h->eject_until_us = 0;
        return;
    }
    h->active_down = true;
    if (h->fails < 0xffff) h->fails++;
}

// In-flight guard for active probes: at most one outstanding probe per
// (upstream, backend). A health endpoint that accepts but never responds keeps
// its probe Connection alive until keepalive_timeout; without this guard every
// due sweep would launch ANOTHER probe for the same backend, accumulating probe
// Connection slots without bound and eventually starving real client accepts.
// Per-shard thread_local — same rationale as BackendHealth / rr_cursor.
inline bool* probe_in_flight_slot(u16 upstream_id, u32 backend_idx) {
    static thread_local bool in_flight[RouteConfig::kMaxUpstreams][UpstreamTarget::kMaxBackends] =
        {};
    if (upstream_id >= RouteConfig::kMaxUpstreams || backend_idx >= UpstreamTarget::kMaxBackends)
        return nullptr;
    return &in_flight[upstream_id][backend_idx];
}

bool probe_in_flight(u16 upstream_id, u32 backend_idx);

inline void set_probe_in_flight(u16 upstream_id, u32 backend_idx, bool v) {
    bool* s = probe_in_flight_slot(upstream_id, backend_idx);
    if (s != nullptr) *s = v;
}

// Clear ALL per-(upstream, backend) health verdicts. Called from
// sweep_health_probes on a config change (hot reload). The BackendHealth table is
// thread_local and keyed only by NUMERIC (upstream_idx, backend_idx) — it carries
// no config pin and active_down has no timed expiry — so after a reload a verdict
// recorded under the OLD config would wrongly suppress (or pass) a DIFFERENT
// endpoint that now occupies the same numeric slot, and if the new config
// disables health checks there is no future probe to clear it. Reset all three
// fields (active_down + the passive fails/eject, since indices may now mean a
// different backend). O(kMaxUpstreams * kMaxBackends); runs only on reload.
//
// probe_in_flight is deliberately NOT reset. A probe launched under the old config
// may still be in flight via a live Connection that owns its slot's flag; every
// probe now carries a bounded timer (see start_health_probe), so the flag always
// self-clears within upstream_timeout on the probe's teardown. Clearing it here
// would let the next sweep launch a SECOND probe for the same backend while the
// old one is still live, defeating the in-flight overlap guard.
//
// Defined out-of-line in callbacks.cc (not inline here): it is odr-used from
// sweep_health_probes — instantiated in main.cc and the test TUs — and a single
// strong symbol avoids multiple-definition across TUs that include this header.

// Pick the next backend index for `upstream_id` via round-robin, skipping
// ejected backends. If every backend is ejected, falls back to plain
// round-robin (serving through a possibly-down backend beats refusing). A
// single-backend upstream (count <= 1) always returns 0.
inline u32 select_backend(u16 upstream_id, u32 backend_count, u64 now_us) {
    static thread_local u16 rr_cursor[RouteConfig::kMaxUpstreams] = {};
    if (backend_count <= 1 || upstream_id >= RouteConfig::kMaxUpstreams) return 0;
    for (u32 step = 0; step < backend_count; step++) {
        const u32 idx = (rr_cursor[upstream_id] + step) % backend_count;
        if (!backend_ejected(upstream_id, idx, now_us)) {
            rr_cursor[upstream_id] = static_cast<u16>((idx + 1) % backend_count);
            return idx;
        }
    }
    const u32 idx = rr_cursor[upstream_id] % backend_count;
    rr_cursor[upstream_id] = static_cast<u16>((rr_cursor[upstream_id] + 1) % backend_count);
    return idx;
}

// --- Active health-check probes (Phase 5 slice 2) — EPOLL ONLY ---
//
// A probe is a Connection with fd == -1 (no downstream client) whose upstream_fd
// is a fresh socket to ONE backend of an hc_enabled upstream. The 1s sweep
// (EventLoopCRTP::sweep_health_probes) calls start_health_probe per backend; the
// probe connects, sends `GET <hc_path> HTTP/1.1`, parses the response status, and
// feeds the result into the SAME per-shard BackendHealth used by passive
// ejection (record_backend_result), so select_backend honors both signals — no
// parallel health state. Teardown goes through free_probe_conn (never the full
// close_conn, which moves per-request metrics/epoch/access-log counters).
//
// Format "<ipv4>:<port>" (network-order sockaddr_in) for the probe Host header.
// out must hold >= 22 bytes ("255.255.255.255:65535"). Returns bytes written.
inline u32 format_probe_host(char* out, const struct sockaddr_in& addr) {
    u32 w = 0;
    const auto* bytes = reinterpret_cast<const u8*>(&addr.sin_addr.s_addr);
    for (u32 i = 0; i < 4; i++) {
        if (i > 0) out[w++] = '.';
        const u8 kOctet = bytes[i];
        if (kOctet >= 100) out[w++] = static_cast<char>('0' + kOctet / 100);
        if (kOctet >= 10) out[w++] = static_cast<char>('0' + (kOctet / 10) % 10);
        out[w++] = static_cast<char>('0' + kOctet % 10);
    }
    out[w++] = ':';
    u16 port = ntohs(addr.sin_port);
    char tmp[5];
    u32 t = 0;
    if (port == 0) tmp[t++] = '0';
    while (port > 0) {
        tmp[t++] = static_cast<char>('0' + port % 10);
        port = static_cast<u16>(port / 10);
    }
    for (u32 i = 0; i < t; i++) out[w++] = tmp[t - 1 - i];
    return w;
}

// Build `GET <hc_path> HTTP/1.1\r\nHost: <ip:port>\r\nConnection: close\r\n
// User-Agent: rut-healthcheck\r\n\r\n` into the connection-owned recv_buf (a
// probe never receives client bytes, so recv_buf is free for the request).
inline void build_probe_request(Connection& conn, const UpstreamTarget& target, u32 backend_idx) {
    Buffer& buf = conn.recv_buf;
    static const char kGet[] = "GET ";
    buf.write(reinterpret_cast<const u8*>(kGet), 4);
    if (target.hc_path_len > 0)
        buf.write(reinterpret_cast<const u8*>(target.hc_path), target.hc_path_len);
    else
        buf.write(reinterpret_cast<const u8*>("/"), 1);
    static const char kProto[] = " HTTP/1.1\r\nHost: ";
    buf.write(reinterpret_cast<const u8*>(kProto), sizeof(kProto) - 1);
    char host[24];
    const u32 kHostLen = format_probe_host(host, target.addrs[backend_idx]);
    buf.write(reinterpret_cast<const u8*>(host), kHostLen);
    static const char kTail[] = "\r\nConnection: close\r\nUser-Agent: rut-healthcheck\r\n\r\n";
    buf.write(reinterpret_cast<const u8*>(kTail), sizeof(kTail) - 1);
}

template <typename Loop>
void free_probe_conn(Loop* loop, Connection& conn) {
    // Minimal teardown — close the probe socket (EPOLL_CTL_DEL first) and return
    // the slot. Never touches metrics/epoch/access-log/keepalive (the probe is
    // not a real request). free_health_probe is epoll-only; probes never run on
    // io_uring this slice, so this is only instantiated for the epoll loop.
    //
    // Clearing the in-flight guard here covers every connected/sent/response
    // teardown path (success and error). The probe carries the SAME
    // (upstream_idx, backend_idx) it was launched against, so the flag is cleared
    // at exactly the slot that was marked. The one mark-then-exit path that does
    // NOT route through here — the create_socket-failure branch in
    // start_health_probe (which calls free_conn directly) — clears it inline.
    set_probe_in_flight(conn.upstream_idx, conn.upstream_backend_idx, false);
    loop->free_health_probe(conn);
}

// Record an active-probe outcome, but only if the config that LAUNCHED the probe
// is still current. A hot reload (*config_ptr swap) mid-probe can repoint the
// numeric upstream_idx at a different upstream/backend; a stale result recorded
// against that index would wrongly suppress or clear the new backend. After a
// swap the result is meaningless, so drop it.
template <typename Loop>
inline void record_probe_if_current(Loop* loop, Connection& conn, bool healthy, u64 now_us) {
    const RouteConfig* cur = loop->config_ptr ? *loop->config_ptr : nullptr;
    if (cur == conn.request_config)
        record_active_probe_result(conn.upstream_idx, conn.upstream_backend_idx, healthy, now_us);
}

template <typename Loop>
void on_probe_response(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void on_probe_sent(void* lp, Connection& conn, IoEvent ev);
template <typename Loop>
void on_probe_connected(void* lp, Connection& conn, IoEvent ev);

// Returns true iff a probe socket was actually submitted (a connect that may
// queue one synchronous completion into the epoll pending ring). Returns false
// when the probe was skipped (already in-flight) or aborted before submit
// (invalid index / local resource failure) — i.e. when no pending-ring slot was
// consumed. sweep_health_probes uses this to budget probes against the ring.
template <typename Loop>
bool start_health_probe(Loop* loop, u16 upstream_idx, u32 backend_idx) {
    const RouteConfig* config = loop->config_ptr ? *loop->config_ptr : nullptr;
    if (config == nullptr || upstream_idx >= config->upstream_count) return false;
    const UpstreamTarget& target = config->upstreams[upstream_idx];
    if (backend_idx >= target.addr_count) return false;

    // Reserve a margin of Connection slots for real client traffic. Near
    // kMaxConns a due sweep can launch up to kMaxProbesPerSweep (32) probes,
    // and a stalled health endpoint pins each probe slot until upstream_timeout
    // (~30s). Without a floor those probes could consume the last free slots
    // and real accepts would be refused for that whole window. Refuse to
    // allocate a probe when free slots are below the reserve; the deferred
    // probe simply retries on the next sweep (probe_in_flight is left unset, so
    // the retry is idempotent). The reserve (64) comfortably exceeds a full
    // 32-probe sweep burst yet is negligible against kMaxConns (16384), so it
    // never meaningfully reduces real-traffic capacity. Checked before
    // set_probe_in_flight so a deferral leaves no guard to clear.
    static constexpr u32 kHealthProbeSlotReserve = 64;
    if (loop->free_conn_slots() < kHealthProbeSlotReserve) return false;

    // At most one outstanding probe per backend (see probe_in_flight). A backend
    // that accepts but never responds otherwise accumulates a probe Connection per
    // due sweep until each times out. Mark BEFORE alloc_conn and clear on EVERY
    // exit-after-mark path below (alloc/create-socket failure here, every other
    // path through free_probe_conn).
    if (probe_in_flight(upstream_idx, backend_idx)) return false;
    set_probe_in_flight(upstream_idx, backend_idx, true);

    Connection* cptr = loop->alloc_conn();
    if (cptr == nullptr) {  // slot exhaustion: never starve real traffic
        set_probe_in_flight(upstream_idx, backend_idx, false);
        return false;
    }
    Connection& conn = *cptr;
    conn.is_health_probe = true;
    conn.fd = -1;
    conn.upstream_idx = upstream_idx;
    conn.upstream_backend_idx = static_cast<u8>(backend_idx);
    // Pin the launching config so on_probe_* drops results after a hot swap.
    conn.request_config = config;

    // Probe-SETUP failures below (create_socket / alloc_buf / submit_connect) are
    // LOCAL resource or kernel-submission failures, not backend health signals —
    // they must NOT mark the backend down (else local fd/slice pressure would
    // eject healthy backends, and active_down is success-gated so it would stay
    // ejected). Just free and skip this probe; the next sweep retries. Only
    // genuine on-wire outcomes (connect refused/reset, send/recv result, response)
    // feed record_active_probe_result.
    const i32 kProbeFd = UpstreamPool::create_socket();
    if (kProbeFd < 0) {
        // The one mark-then-exit path that bypasses free_probe_conn, so clear the
        // in-flight guard inline.
        set_probe_in_flight(upstream_idx, backend_idx, false);
        loop->free_conn(conn);
        return false;
    }
    conn.upstream_fd = kProbeFd;
    // The response lands in upstream_recv_buf (recv_buf holds the request).
    if (!loop->alloc_upstream_buf(conn)) {
        free_probe_conn(loop, conn);
        return false;
    }

    conn.recv_buf.reset();
    build_probe_request(conn, target, backend_idx);

    conn.set_slots(nullptr, nullptr, nullptr, &on_probe_connected<Loop>);
    if (!loop->submit_connect(
            conn, &target.addrs[backend_idx], sizeof(target.addrs[backend_idx]))) {
        free_probe_conn(loop, conn);
        return false;
    }
    // Bound the probe's lifetime. A probe Connection is not a client accept, so
    // nothing else puts it on the keepalive wheel; a backend that completes the
    // connect but never responds (or a connect that stays pending) would otherwise
    // keep this Connection alive forever with upstream I/O armed and
    // probe_in_flight set — permanently suppressing all future probes for the
    // backend and leaking the slot. Arm it on the 1s timer wheel with the same
    // bound a real proxied upstream response gets (upstream_timeout, default 30s,
    // already < TimerWheel::kSlots): the Timeout tick reaps a stalled probe as a
    // health FAILURE and frees it (clearing probe_in_flight so the next sweep
    // re-probes). Every fast completion path frees via free_probe_conn ->
    // free_health_probe -> free_conn, which removes the wheel entry, so a completed
    // probe can never leave a stale entry to fire later against a reused slot.
    loop->timer.add(&conn, loop->upstream_timeout);
    return true;
}

template <typename Loop>
void on_probe_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result < 0) {
        record_probe_if_current(loop, conn, /*healthy=*/false, monotonic_us());
        free_probe_conn(loop, conn);
        return;
    }
    conn.set_slots(nullptr, nullptr, nullptr, &on_probe_sent<Loop>);
    // submit failure is local (kernel submission), not a backend signal — skip.
    if (!loop->submit_send_upstream(conn, conn.recv_buf.data(), conn.recv_buf.len())) {
        free_probe_conn(loop, conn);
    }
}

template <typename Loop>
void on_probe_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    // A local epoll submission failure is not evidence that the backend is
    // unhealthy.  The queued completion still owns normal probe teardown, but
    // must not enter the health failure accounting below.
    if (ev.aux == kLocalSubmitFailureAux) {
        free_probe_conn(loop, conn);
        return;
    }
    if (ev.result < 0) {
        record_probe_if_current(loop, conn, /*healthy=*/false, monotonic_us());
        free_probe_conn(loop, conn);
        return;
    }
    conn.set_slots(nullptr, nullptr, &on_probe_response<Loop>, nullptr);
    if (conn.upstream_recv_buf.len() > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(conn.upstream_recv_buf.len()),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
        on_probe_response<Loop>(lp, conn, synth);
        return;
    }
    // submit failure is local (kernel submission), not a backend signal — skip.
    if (!loop->submit_recv_upstream(conn)) {
        free_probe_conn(loop, conn);
    }
}

template <typename Loop>
void on_probe_response(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const u64 kNowUs = monotonic_us();
    if (ev.aux == kLocalSubmitFailureAux) {
        free_probe_conn(loop, conn);
        return;
    }
    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        record_probe_if_current(loop, conn, /*healthy=*/false, kNowUs);
        free_probe_conn(loop, conn);
        return;
    }
    HttpResponseParser parser;
    ParsedResponse resp;
    resp.reset();
    parser.reset();
    const ParseStatus kStatus =
        parser.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &resp);
    // Headers split across packets: keep reading while bytes arrive and buffer space
    // remains. The probe's upstream_timeout bounds stalled/trickling responses.
    if (kStatus == ParseStatus::Incomplete && ev.result > 0 &&
        conn.upstream_recv_buf.write_avail() > 0) {
        if (!loop->submit_recv_upstream(conn)) {
            free_probe_conn(loop, conn);
        }
        return;
    }
    // Pin to the launching config: a hot reload mid-probe can repoint the numeric
    // upstream_idx at a different upstream. Guard BEFORE the expected-status
    // comparison — after a swap the response is meaningless, so free without
    // recording (the stale result must not touch the new backend at this index).
    const RouteConfig* config = loop->config_ptr ? *loop->config_ptr : nullptr;
    if (config != conn.request_config) {
        free_probe_conn(loop, conn);
        return;
    }
    // Complete + expected status → healthy; anything else (Error, Incomplete with
    // no more data, unexpected status) → failure.
    bool healthy = false;
    if (kStatus == ParseStatus::Complete && config != nullptr &&
        conn.upstream_idx < config->upstream_count) {
        healthy = (resp.status_code == config->upstreams[conn.upstream_idx].hc_expected_status);
    }
    record_active_probe_result(conn.upstream_idx, conn.upstream_backend_idx, healthy, kNowUs);
    free_probe_conn(loop, conn);
}

u8 map_log_method(HttpMethod method);
u8 parse_log_method_fallback(const u8* data, u32 len, u32* method_len);
void capture_request_metadata(Connection& conn);
u32 pipeline_leftover(const Connection& conn);
bool pipeline_shift(Connection& conn);
bool pipeline_stash(Connection& conn);
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
// `suppress_default_content_type` is a tombstone from a committed
// Content-Type removal. It preserves an intentional absence even when
// no effective header remains to suppress the normal text/plain default.
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
                                           bool body_is_fallback_reason_phrase = false,
                                           bool suppress_default_content_type = false);
inline bool apply_request_policy(Connection& conn, const sockaddr_in& endpoint, u16 policy_id);
inline bool materialize_request_target_transform(Connection& conn, const RouteConfig& config);
inline bool build_redirect_response(const Connection& conn,
                                    const RouteConfig& config,
                                    u16 policy_id,
                                    u8* out,
                                    u32 out_cap,
                                    u32* out_len);
inline bool stage_redirect_response(Connection& conn, const RouteConfig& config, u16 policy_id);
enum class RequestPolicyBodyState : u8 { Invalid, Complete, Waiting };
RequestPolicyBodyState inspect_request_policy_body(const Connection& conn, u16 policy_id);
inline bool request_policy_body_response_domain(const Connection& conn);
inline bool request_policy_body_response_admitted(const Connection& conn);
inline bool strict_response_upload_ready(const Connection& conn);
inline bool response_policy_runtime_supported(const ForwardResponsePolicySpec& policy);
inline bool failure_policy_runtime_supported(const ForwardFailurePolicySpec& policy);
inline bool forward_policy_head_modes_compatible(const RouteConfig& config,
                                                 u16 response_policy_id,
                                                 u16 failure_policy_id,
                                                 u16 timeout_failure_policy_id = 0);
inline bool response_policy_suppress_head_admitted(const Connection& conn,
                                                   const ForwardResponsePolicySpec& policy,
                                                   bool paired_failure);
inline ResponseReadDeadlineProfile classify_response_read_deadline_profile(
    const Connection& conn,
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout);
inline bool build_timeout_failure_policy_response(const Connection& conn,
                                                  const RouteConfig& config,
                                                  bool suppress_body,
                                                  u8* out,
                                                  u32 out_cap,
                                                  u32* out_len);
template <typename Loop>
inline void reject_request_policy(Loop* loop, Connection& conn);
template <typename Loop>
inline void reject_response_policy(Loop* loop, Connection& conn);
template <typename Loop>
inline void respond_upstream_connect_failure(Loop* loop, Connection& conn);
void prepare_early_response_state(Connection& conn);
u32 consume_upstream_sent(Connection& conn);

extern const char kResponse200[];
extern const char kResponse200Close[];

struct ResponseReadDeadlineFixedUploadRequest {
    u32 header_end = 0;
    u32 content_length = 0;
    u32 total_length = 0;
};

inline bool inspect_response_read_deadline_fixed_upload_request(
    const Connection& conn, ResponseReadDeadlineFixedUploadRequest* out) {
    if (out == nullptr || conn.recv_buf.data() == nullptr || conn.recv_buf.len() == 0 ||
        !response_read_deadline_fixed_upload_method_admitted(conn.req_method))
        return false;
    HttpParser parser;
    ParsedRequest request;
    parser.reset();
    request.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &request) !=
            ParseStatus::Complete ||
        route_method_key(request.method) !=
            route_method_key(static_cast<LogHttpMethod>(conn.req_method)) ||
        request.version != HttpVersion::Http11 || request.path.ptr == nullptr ||
        request.path.len == 0 || request.path.ptr[0] != '/' || !request.has_content_length ||
        request.content_length == 0 || request.chunked || request.upgrade ||
        request.has_upgrade_header)
        return false;
    u32 host_count = 0;
    u32 content_length_count = 0;
    for (u32 i = 0; i < request.header_count; ++i) {
        const Header& header = request.headers[i];
        const Str name = header.name;
        if (http_header_name_eq_ci(name.ptr, name.len, "host", 4)) {
            if (++host_count > 1 || header.value.len == 0) return false;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "content-length", 14)) {
            if (++content_length_count > 1) return false;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "connection", 10) ||
                   http_header_name_eq_ci(name.ptr, name.len, "transfer-encoding", 17) ||
                   http_header_name_eq_ci(name.ptr, name.len, "te", 2) ||
                   http_header_name_eq_ci(name.ptr, name.len, "expect", 6) ||
                   http_header_name_eq_ci(name.ptr, name.len, "upgrade", 7)) {
            return false;
        }
    }
    const u64 total = static_cast<u64>(parser.header_end) + request.content_length;
    if (host_count != 1 || content_length_count != 1 || total > conn.recv_buf.capacity() ||
        conn.recv_buf.len() > total)
        return false;
    out->header_end = parser.header_end;
    out->content_length = request.content_length;
    out->total_length = static_cast<u32>(total);
    return true;
}

inline bool response_read_deadline_route_index(const RouteConfig& config,
                                               const RouteEntry* route,
                                               u16* out) {
    if (route == nullptr || out == nullptr) return false;
    for (u32 i = 0; i < config.route_count; ++i) {
        if (&config.routes[i] != route) continue;
        *out = static_cast<u16>(i);
        return true;
    }
    return false;
}

inline bool response_read_deadline_fixed_upload_route_stable(const Connection& conn,
                                                             bool require_complete) {
    const RouteConfig* config = conn.request_config;
    const auto& proof = conn.response_read_deadline_upload;
    if (config == nullptr || proof.route_index >= config->route_count ||
        proof.handler_generation == 0 || proof.handler_generation != conn.handler_gen ||
        proof.route_fn == nullptr)
        return false;
    const RouteEntry& pinned = config->routes[proof.route_index];
    if (pinned.action != RouteAction::JitHandler || pinned.fn != proof.route_fn ||
        pinned.needs_req_body || pinned.rate_limit.count != 0 || pinned.throttle_down_bps != 0 ||
        pinned.ws_terminate ||
        pinned.preflight_forward_policy_bundle_id != conn.response_read_deadline_bundle_id ||
        pinned.method != conn.response_read_deadline_route_method ||
        !response_read_deadline_route_method_matches(conn.req_method, pinned.method))
        return false;
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    const u8 method_key = route_method_key(static_cast<LogHttpMethod>(conn.req_method));
    const RouteEntry* matched = config->match_canonical(
        conn.req_path_canon, method_key, params, &param_count, kMaxRouteParams);
    if (matched != &pinned) return false;
    ResponseReadDeadlineFixedUploadRequest request{};
    if (!inspect_response_read_deadline_fixed_upload_request(conn, &request) ||
        request.header_end != proof.raw_header_end ||
        request.content_length != proof.raw_content_length ||
        request.total_length != proof.raw_total_length ||
        conn.req_header_end != proof.raw_header_end ||
        conn.req_content_length != proof.raw_content_length ||
        conn.req_initial_send_len != conn.recv_buf.len() ||
        conn.req_body_mode != BodyMode::ContentLength || conn.req_client_connection_count != 0 ||
        !conn.req_client_has_content_length || conn.req_client_has_transfer_encoding ||
        conn.req_client_has_te || conn.req_client_has_expect ||
        conn.req_client_has_upgrade_header || conn.req_malformed || conn.req_wants_upgrade ||
        conn.pipeline_depth != 0 || conn.pipeline_stash_len != 0 ||
        conn.request_body_fully_buffered || conn.req_body_streamed)
        return false;
    const u32 buffered_body = conn.recv_buf.len() - proof.raw_header_end;
    if (buffered_body > proof.raw_content_length ||
        conn.req_body_remaining != proof.raw_content_length - buffered_body)
        return false;
    return !require_complete ||
           (conn.recv_buf.len() == proof.raw_total_length && conn.req_body_remaining == 0);
}

template <typename Loop>
bool prepare_response_read_deadline_preflight(Loop* loop,
                                              Connection& conn,
                                              const RouteEntry* route,
                                              const RouteConfig* config) {
    if (route == nullptr || route->preflight_forward_policy_bundle_id == 0) return true;
    constexpr bool supports_explicit_deadline = [] {
        if constexpr (requires { Loop::kSupportsExplicitFirstResponseDeadline; })
            return Loop::kSupportsExplicitFirstResponseDeadline;
        else
            return false;
    }();
    if constexpr (!supports_explicit_deadline) {
        loop->close_conn(conn);
        return false;
    } else {
        const u16 id = route->preflight_forward_policy_bundle_id;
        if (config == nullptr || conn.request_config != config ||
            !config->policy_bundle_id_is_valid(id) || route->action != RouteAction::JitHandler ||
            route->fn == nullptr || route->needs_req_body || route->rate_limit.count != 0 ||
            route->throttle_down_bps != 0 || route->ws_terminate ||
            conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
            loop->close_conn(conn);
            return false;
        }
        const auto& bundle = config->policy_bundles[id - 1];
        const bool complete_buffering =
            bundle.response_buffering == ForwardResponseBufferingMode::CompleteContentLength;
        if (!forward_response_buffering_mode_valid(bundle.response_buffering)) {
            loop->close_conn(conn);
            return false;
        }
        if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
            bundle.response_policy_id == 0 || bundle.failure_policy_id == 0 ||
            bundle.timeout_failure_policy_id == 0 ||
            !config->response_policy_id_is_valid(bundle.response_policy_id) ||
            !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
            !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id) ||
            !forward_policy_head_modes_compatible(*config,
                                                  bundle.response_policy_id,
                                                  bundle.failure_policy_id,
                                                  bundle.timeout_failure_policy_id)) {
            loop->close_conn(conn);
            return false;
        }
        const auto& response = config->response_policies[bundle.response_policy_id - 1];
        const auto& failure = config->failure_policies[bundle.failure_policy_id - 1];
        const auto& timeout = config->failure_policies[bundle.timeout_failure_policy_id - 1];
        const ResponseReadDeadlineProfile profile =
            classify_response_read_deadline_profile(conn, response, failure, timeout);
        const bool fixed_upload =
            profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
        ResponseReadDeadlineFixedUploadRequest upload_request{};
        u16 route_index = 0xffffu;
        if (response.version != ResponsePolicyVersion::Http11 ||
            response.framing != ResponsePolicyFraming::ContentLength ||
            response.connection != ResponsePolicyConnection::Request ||
            failure.version != ForwardFailurePolicyVersion::Http11 ||
            failure.status_code != kStatusBadGateway ||
            failure.connection != ForwardFailurePolicyConnection::Request ||
            timeout.version != ForwardFailurePolicyVersion::Http11 ||
            timeout.connection != ForwardFailurePolicyConnection::Request ||
            conn.protocol != ConnProtocol::Http11 || conn.tls_active || conn.req_malformed ||
            (!fixed_upload && (conn.req_body_mode != BodyMode::None ||
                               conn.req_body_remaining != 0 || conn.request_body_fully_buffered)) ||
            conn.req_client_has_transfer_encoding || conn.req_client_has_te ||
            conn.req_client_has_expect || conn.req_client_has_upgrade_header ||
            conn.req_client_connection_count != 0 || conn.req_wants_upgrade ||
            profile == ResponseReadDeadlineProfile::None ||
            (complete_buffering &&
             ((profile != ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
               profile !=
                   ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero) ||
              !response_read_deadline_non_head_method_admitted(conn.req_method) ||
              !complete_content_length_route_method_is_admitted(route->method) ||
              !response_read_deadline_route_method_matches(conn.req_method, route->method) ||
              conn.request_policy_id != 0 || conn.request_policy_body_pending ||
              conn.pending_forward_request_policy_id != 0 ||
              !complete_content_length_buffering_policies_valid(response, failure, timeout))) ||
            !response_read_deadline_route_method_matches(conn.req_method, route->method) ||
            conn.pipeline_depth != 0 || conn.recv_buf.len() != conn.req_initial_send_len ||
            (fixed_upload &&
             (!inspect_response_read_deadline_fixed_upload_request(conn, &upload_request) ||
              !response_read_deadline_route_index(*config, route, &route_index)))) {
            loop->close_conn(conn);
            return false;
        }
        if (!conn.next_response_read_deadline_generation()) {
            loop->close_conn(conn);
            return false;
        }
        conn.response_read_deadline_bundle_id = id;
        conn.response_read_deadline_seconds = bundle.response_read_timeout_seconds;
        conn.response_read_deadline_buffering = bundle.response_buffering;
        conn.response_read_deadline_profile = profile;
        conn.response_read_deadline_method = conn.req_method;
        conn.response_read_deadline_route_method = route->method;
        conn.response_read_deadline_state = ResponseReadDeadlineState::Preflight;
        if (fixed_upload) {
            auto& proof = conn.response_read_deadline_upload;
            proof.handler_generation = conn.handler_gen;
            proof.raw_header_end = upload_request.header_end;
            proof.raw_content_length = upload_request.content_length;
            proof.raw_total_length = upload_request.total_length;
            proof.route_index = route_index;
            proof.route_fn = route->fn;
        }
        return true;
    }
}

template <typename Loop>
void on_request_complete(Loop* loop, Connection& conn, u16 status, u32 resp_size);

#if RUT_ENABLE_WEBSOCKET
template <typename Loop>
void on_ws_upstream_recv(void* lp, Connection& conn, IoEvent ev);
#endif

// ── JIT handler dispatch ───────────────────────────────────────────
// Route-matched JitHandler action → invoke the compiled handler and
// translate JitDispatchOutcome into event-loop operations (send, forward,
// register timer for resume, or 500). Shared between the initial call
// (on_header_received) and timer-driven resumes.
template <typename Loop>
void handle_jit_outcome(
    Loop* loop, Connection& conn, JitDispatchOutcome outcome, jit::HandlerFn fn, bool keep_alive);

template <typename Loop>
void on_request_policy_body_recvd(void* lp, Connection& conn, IoEvent ev);

// Called from timer.tick when the timer firing was a JIT handler yield
// (conn.pending_handler_fn != nullptr). Re-enters the handler with
// ctx.state = conn.handler_state, then re-dispatches on the outcome.
template <typename Loop>
void resume_jit_handler(Loop* loop, Connection& conn);

// Handle a proxying connection whose upstream deadline expired. Explicit
// timeout policy is selected only in the bounded D2 domain below; policy-free
// requests retain the legacy close-only 504.
template <typename Loop>
void respond_upstream_timeout(Loop* loop, Connection& conn);
template <typename Loop>
inline bool try_prebuilt_strict_read_timeout(Loop* loop, Connection& conn);

template <typename Loop>
void pipeline_dispatch(Loop* loop, Connection& conn);
template <typename Loop>
void proxy_stream_complete(Loop* loop, Connection& conn);

// Client send with @throttle token-bucket accounting. With no per-route throttle
// (bps == 0) this is just loop->submit_send. Otherwise it advances the
// connection's virtual-time bucket `throttle_tat_ns` by len × ns_per_byte
// (anchored to now so an idle bucket doesn't bank credit). The actual pacing
// happens on the proxy *read* side (throttle_pause_before_pump): pacing the
// upstream read lets TCP flow control backpressure the backend, and sending whole
// buffers as produced keeps the downstream path simple and never splits a send.
// Single-writer per shard, so the bucket needs no atomics.
// Advance the @throttle virtual-time bucket by `len` bytes (no-op when the route
// has no throttle). Factored out so the io_uring-TLS proxy path, which encrypts
// directly into tls_out_buf instead of calling client_send, keeps the same
// byte-rate accounting (otherwise watermark backpressure would bound memory but
// not enforce the configured rate).
inline void throttle_advance(Connection& conn, u32 len) {
    if (conn.throttle_down_bps == 0) return;
    const u64 kNowNs = monotonic_ns();
    const u64 kBase = (kNowNs > conn.throttle_tat_ns) ? kNowNs : conn.throttle_tat_ns;
    // len*1e9/bps at full precision per chunk (a precomputed ns-per-byte would
    // truncate to 0 above ~1 GB/s). len*1e9 <= ~4.3e18 for u32 len, within u64.
    conn.throttle_tat_ns =
        kBase + static_cast<u64>(len) * 1'000'000'000ull / conn.throttle_down_bps;
}

// True once the whole proxied response body has been read from the upstream
// (Content-Length exhausted / chunked trailer seen). UntilClose ends at EOF, not
// here.
inline bool proxy_body_complete(const Connection& conn) {
    return (conn.resp_body_mode == BodyMode::ContentLength && conn.resp_body_remaining == 0) ||
           (conn.resp_body_mode == BodyMode::Chunked &&
            conn.resp_chunk_parser.state == ChunkedParser::State::Complete);
}

// Drain-side accounting for a parked proxy-body remainder: the io_uring-TLS read
// side parks the unencrypted tail in tls_send_src when tls_fill_output returns
// NeedRoom/NeedRead, and pauses the upstream read. tls_on_out_drain /
// tls_resume_pending_send_recv re-encrypt it; `newly` is the plaintext encrypted
// this pass. Once the whole remainder is in, shift the upstream buffer past it,
// finalize the body state, and either complete-on-drain or resume the read
// (honoring the watermark and @throttle). Defined here (not in tls_iouring.h) so
// it can reach consume_upstream_sent / on_response_body_recvd / the body state;
// forward-declared there. May close the connection — callers must re-check
// tls_active before touching conn again.
template <typename Loop>
void proxy_tls_parked_drained(Loop* loop, Connection& conn, u32 newly) {
    conn.resp_body_sent += newly;
    throttle_advance(conn, newly);
    if (conn.tls_send_off < conn.tls_send_len) return;  // remainder still partial
    conn.upstream_send_len = conn.tls_send_len;
    // The multishot recv may have raced more body into upstream_recv_buf behind the
    // parked tail before the pause took effect; consume_upstream_sent returns it.
    const u32 kRemaining = consume_upstream_sent(conn);
    conn.tls_send_src = nullptr;
    conn.tls_send_len = 0;
    conn.tls_send_off = 0;
    if (proxy_body_complete(conn)) {
        conn.resp_fully_buffered = true;  // completes when tls_out_buf drains
        if (!loop->pause_upstream_recv(conn)) loop->close_conn(conn);
        return;
    }
    if (kRemaining > 0) {
        // Bytes already buffered (the multishot raced them in behind the tail).
        // Honor @throttle before replaying them (same as the main read path), so
        // raced body data parks for the byte budget instead of bursting past the
        // configured rate; they stay in upstream_recv_buf and replay on the timer.
        if (throttle_pause_before_pump<Loop>(loop, conn, kRemaining)) return;
        IoEvent synth = {conn.id,
                         static_cast<i32>(kRemaining),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
        on_response_body_recvd<Loop>(loop, conn, synth);
        return;
    }
    // More body expected, buffer drained: honor the high watermark, then @throttle,
    // before re-arming the (paused) upstream read.
    if (conn.tls_out_buf.len() >= Loop::kTlsOutHigh) {
        conn.tls_recv_paused_hw = true;  // drain's low-watermark logic re-arms
        return;
    }
    if (throttle_pause_before_pump<Loop>(loop, conn, 0)) return;
    // Unconditional (see tls_on_out_drain): submit_recv_upstream self-guards the
    // armed/cancel-pending race and only fails on a real add_recv error.
    if (!loop->submit_recv_upstream(conn)) loop->close_conn(conn);
}

template <typename Loop>
bool client_send(Loop* loop, Connection& conn, const u8* buf, u32 len) {
    throttle_advance(conn, len);
    return loop->submit_send(conn, buf, len);
}

// @throttle read-side gate for the proxy body pump. Called at each point where
// the proxy would read the next upstream chunk. If the token bucket has run ahead
// of real time (the bytes sent so far "should" take until throttle_tat_ns at the
// configured rate), disarm the upstream recv — so level-triggered epoll readiness
// can't drive the pipeline past the pause — park the connection on the per-shard
// *precise* timer for exactly the deficit, and return true so the caller returns
// without pumping. throttle_resume re-checks and re-arms when the budget recovers.
template <typename Loop>
bool throttle_pause_before_pump(Loop* loop, Connection& conn, u32 pending_remaining) {
    if (conn.throttle_down_bps == 0) return false;
    const u64 kNowNs = monotonic_ns();
    if (conn.throttle_tat_ns <= kNowNs) return false;  // not ahead → budget available
    const u64 kDelayNs = conn.throttle_tat_ns - kNowNs;
    conn.throttle_paused = true;
    conn.throttle_pending_len = pending_remaining;  // stash for resume
    if constexpr (requires { loop->pause_upstream_recv(conn); }) {
        // On io_uring the pause is a cancel SQE that can fail to queue under SQ
        // pressure, leaving the multishot recv live. For io_uring TLS that lets the
        // live recv keep encrypting body bytes (a parked tail can even corrupt on
        // overflow), so fail closed like the watermark/body-done pause paths. The
        // plaintext path self-heals (its -ENOBUFS handling pauses on overflow), so
        // leave it unchanged. (epoll's pause can't fail.)
        if (!loop->pause_upstream_recv(conn) && conn.uses_iouring_tls()) {
            loop->close_conn(conn);
            return true;  // caller returns; conn is closed
        }
    }
    // Arm the per-shard precise (sub-second) timer for the exact deficit. If the
    // loop can't (heap full / no support), fall back to the 1-second keepalive
    // wheel — throttle_resume re-checks the budget, so a coarse/early wake is safe.
    bool armed = false;
    if constexpr (requires { loop->arm_throttle_timer(conn, kDelayNs); }) {
        armed = loop->arm_throttle_timer(conn, kDelayNs);
    }
    if (!armed) {
        if constexpr (requires { loop->timer.refresh(&conn, 1u); }) {
            loop->timer.refresh(&conn, 1u);
        }
    }
    return true;
}

// Resume the proxy body pump parked by throttle_pause_before_pump (invoked from
// the per-shard precise timer or the keepalive wheel). Re-check the bucket: if it
// is still ahead of real time (the timer fired early, or a coarse wheel tick), the
// budget hasn't recovered yet — re-park for the remaining deficit. Otherwise
// replay the buffered upstream bytes or re-arm the upstream recv.
template <typename Loop>
void throttle_resume(Loop* loop, Connection& conn) {
    if (conn.throttle_down_bps != 0) {
        const u64 kNowNs = monotonic_ns();
        if (conn.throttle_tat_ns > kNowNs) {
            // Budget not recovered yet — re-park for the remaining deficit.
            const u64 kDelayNs = conn.throttle_tat_ns - kNowNs;
            bool armed = false;
            if constexpr (requires { loop->arm_throttle_timer(conn, kDelayNs); }) {
                armed = loop->arm_throttle_timer(conn, kDelayNs);
            }
            if (!armed) {
                if constexpr (requires { loop->timer.refresh(&conn, 1u); }) {
                    loop->timer.refresh(&conn, 1u);
                }
            }
            return;  // stay paused
        }
    }
    conn.throttle_paused = false;
    const u32 kRemaining = conn.throttle_pending_len;
    conn.throttle_pending_len = 0;
    if (kRemaining > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(kRemaining),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
#if RUT_ENABLE_WEBSOCKET
        if (conn.is_ws_tunnel) {
            on_ws_upstream_recv<Loop>(static_cast<void*>(loop), conn, synth);
        } else {
            on_response_body_recvd<Loop>(static_cast<void*>(loop), conn, synth);
        }
#else
        on_response_body_recvd<Loop>(static_cast<void*>(loop), conn, synth);
#endif
    } else if (!loop->submit_recv_upstream(conn)) {
        // Deferred re-arm: the low-watermark watermark resume cleared
        // tls_recv_paused_hw and left the retry to throttle_resume.
        // submit_recv_upstream can fail under io_uring SQ pressure; with the
        // watermark flag already gone there is nothing left to retry and no CQE is
        // guaranteed, so fail closed rather than stall the response until timeout.
        loop->close_conn(conn);
    }
}

// Release the upstream concurrency slot taken at proxy dispatch, exactly once.
// Called on clean completion (promptly, so keep-alive connections free the slot
// without waiting for close) and from close_conn (the catch-all for failures and
// non-keep-alive completion) — the held flag makes the second call a no-op.
template <typename Loop>
void release_upstream_slot(Loop* loop, Connection& conn) {
    if (!conn.upstream_slot_held) return;
    conn.upstream_slot_held = false;
    if constexpr (requires { loop->upstream_release(conn.upstream_slot_uid); }) {
        loop->upstream_release(conn.upstream_slot_uid);
    }
}

// Release conn.upstream_fd at proxy completion: hand it to the per-shard idle pool
// for reuse when the upstream connection is keep-alive + self-framed (and wasn't
// abandoned on timeout), otherwise close it. Either way conn.upstream_fd ends as -1
// and the fd↔conn routing / armed flags are cleared. The loop's return_idle_upstream
// (epoll today; io_uring via the deferred-drain path) detaches the fd from the I/O
// backend before parking it; loops without that method just close (no reuse).
template <typename Loop>
bool proxy_upstream_reusable(Loop* loop, Connection& conn) {
    // The upstream must have signalled keep-alive + a self-framed body, and the
    // episode must not have been abandoned on timeout.
    if (!conn.upstream_keep_alive || conn.upstream_abandoned) return false;
    // The client→upstream upload must have been fully DELIVERED. A failed body
    // write (initial forward or a streamed chunk) leaves the backend mid-read of a
    // truncated request even though the body counters below may read "complete"
    // (they advance before the send is submitted) — pooling such a socket would let
    // the next request's bytes be parsed as the unfinished body. See
    // upstream_request_incomplete.
    if (conn.upstream_request_incomplete) return false;
    // The client→upstream request upload must have finished. An early upstream
    // response (e.g. a 413 before the POST body drained) stops forwarding the body,
    // leaving the backend still reading the previous request — a pooled fd would
    // then have the next request's bytes parsed as that leftover body.
    if ((conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) ||
        (conn.req_body_mode == BodyMode::Chunked &&
         conn.req_chunk_parser.state != ChunkedParser::State::Complete))
        return false;
    // The request must have run on the still-current config. A hot reload can
    // repoint this (upstream_idx, backend_idx) to a different backend while the
    // request is in flight; poll_command's drain only flushes sockets idle at the
    // swap instant, so an in-flight old-config request completing afterward must not
    // park its fd under the now-reused numeric key.
    if constexpr (requires { loop->config_ptr; }) {
        const RouteConfig* kCur = loop->config_ptr ? *loop->config_ptr : nullptr;
        if (conn.request_config != kCur) return false;
    }
    return true;
}

// Shared upstream teardown hook. Epoll owns the synchronous DEL/map/send-state
// detach and strict episode retirement; io_uring, legacy, and test loops retain
// their existing close/accounting behavior through the fallback below.
template <typename Loop>
bool detach_upstream_close(Loop* loop, Connection& conn) {
    if constexpr (requires { loop->detach_upstream_close(conn); }) {
        return loop->detach_upstream_close(conn);
    } else {
        if (conn.upstream_fd >= 0) {
            ::close(conn.upstream_fd);
            conn.upstream_fd = -1;
        }
        loop->clear_upstream_fd(conn.id);
        conn.upstream_recv_armed = false;
        conn.upstream_send_armed = false;
        return true;
    }
}

// Close-only fallback for malformed response paths that can run while an
// asynchronous upstream recv is still armed. Epoll has synchronous ownership
// and must use its full detach/retire hook; io_uring, legacy, and mock loops
// retain the fd/armed state until their normal close/cancel accounting drains.
template <typename Loop>
bool detach_upstream_close_only(Loop* loop, Connection& conn) {
    if constexpr (requires { loop->detach_upstream_close(conn); }) {
        return loop->detach_upstream_close(conn);
    } else {
        if (conn.upstream_fd >= 0) {
            ::close(conn.upstream_fd);
            conn.upstream_fd = -1;
        }
        return true;
    }
}

template <typename Loop>
void release_upstream_conn(Loop* loop, Connection& conn) {
    if (conn.upstream_fd >= 0 && proxy_upstream_reusable(loop, conn)) {
        if constexpr (requires {
                          loop->return_idle_upstream(
                              conn, conn.upstream_idx, conn.upstream_backend_idx);
                      }) {
            loop->return_idle_upstream(conn, conn.upstream_idx, conn.upstream_backend_idx);
            if (conn.upstream_fd < 0) return;  // parked (or closed) + cleared by the loop
        }
    }
    (void)detach_upstream_close(loop, conn);
}

// Body-state half of resendability: the request body must be fully delivered and
// nothing may have begun streaming (once a body byte streams, recv_buf is reset +
// refilled with chunks, so the original headers+body are gone). Shared by both
// resendability predicates below.
inline bool request_body_replayable(const Connection& conn) {
    if (conn.req_body_streamed) return false;
    if (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) return false;
    if (conn.req_body_mode == BodyMode::Chunked &&
        conn.req_chunk_parser.state != ChunkedParser::State::Complete)
        return false;
    return true;
}

// True iff the COMPLETE original request is still byte-for-byte at the front of
// recv_buf. recv_buf may also contain pipelined surplus after that prefix; the
// retry snapshot copies only the first req_initial_send_len bytes, while
// pipeline_stash keeps the surplus separately in send_buf after the snapshot.
inline bool request_resendable_from_recv_buf(const Connection& conn) {
    if (!request_body_replayable(conn)) return false;
    return conn.req_initial_send_len > 0 && conn.recv_buf.len() >= conn.req_initial_send_len;
}

// True iff a reused-socket retry can re-send the COMPLETE original request. There
// are two replay sources, checked in order:
//   1. retry_req_send_len > 0 — the request was snapshotted into send_buf at
//      request-sent (after recv_buf was reset). This is the post-send dead-socket
//      site (on_upstream_response); recv_buf may now hold a pipelined next request,
//      which is preserved while the snapshot is replayed from send_buf.
//   2. recv_buf still has the request as its prefix — the pre-reset sites (failed
//      send / EOF before the send completed), where no snapshot was taken yet.
//      Any surplus bytes are pipelined next-request data and are preserved by the
//      normal stash path after the retry send succeeds.
// Used to gate BOTH reused-socket retry sites so they cannot drift.
inline bool request_fully_resendable(const Connection& conn) {
    if (!request_body_replayable(conn)) return false;
    if (conn.retry_req_send_len > 0) return conn.retry_req_snapshot_replayable;
    return conn.req_initial_send_len > 0 && conn.recv_buf.len() >= conn.req_initial_send_len;
}

// A reused (pooled) upstream socket failed before any response byte — the backend
// closed it between take_idle's liveness probe and our request. Fall back to a
// fresh connect + resend, but ONLY for idempotent methods: a non-idempotent
// request could have been received by the backend before the reset, so resending
// risks executing it twice. Returns true (a fresh connect was started → caller
// returns) or false (caller runs its normal failure handling, e.g. 502/close).
// One-shot: clears upstream_reused so a fresh-connect failure isn't retried again.
template <typename Loop>
bool retry_reused_upstream(Loop* loop, Connection& conn) {
    if (!conn.upstream_reused) return false;
    // Paired strict HEAD failures are a one-shot connect-establishment
    // contract; never replay a request from a pooled socket under that policy.
    if (conn.failure_policy_suppress_body) {
        conn.upstream_reused = false;
        return false;
    }
    conn.upstream_reused = false;
    // An upgrade request (WebSocket/HTTP Upgrade) is a GET but can open backend
    // session state, so replaying it could create a duplicate session — never retry.
    if (conn.req_wants_upgrade) return false;
    const u8 m = conn.req_method;
    const bool kIdempotent =
        m == static_cast<u8>(LogHttpMethod::Get) || m == static_cast<u8>(LogHttpMethod::Head) ||
        m == static_cast<u8>(LogHttpMethod::Put) || m == static_cast<u8>(LogHttpMethod::Delete) ||
        m == static_cast<u8>(LogHttpMethod::Options) || m == static_cast<u8>(LogHttpMethod::Trace);
    if (!kIdempotent) return false;
    // The full request must still be resendable from recv_buf: a body upload that
    // began streaming has already overwritten recv_buf with body chunks, so
    // reconnecting would resend a truncated/garbage request (bodyless idempotent
    // methods and fully-buffered-unsent bodies stay retryable). This same gate runs
    // at every retry site, so a partially-or-fully-streamed body is never replayed.
    if (!request_fully_resendable(conn)) return false;
    // A retry re-sends the request from scratch, so any prior failed-send marker
    // from this episode is stale; the fresh attempt decides delivery anew.
    conn.upstream_request_incomplete = false;
    conn.request_upload_complete = false;
    const RouteConfig* cfg = conn.request_config;
    if (!cfg) return false;
    const auto& target = cfg->upstreams[conn.upstream_idx];
    if (conn.upstream_backend_idx >= target.addr_count) return false;

    (void)detach_upstream_close(loop, conn);
    // Clear any epoll partial-send bookkeeping for the dead fd before reconnecting:
    // a request send parked on EPOLLOUT leaves upstream_send_state set, which the
    // fresh connect's EPOLLOUT would otherwise resume / misread as the connect
    // result (the swapped on_upstream_connected slot). io_uring has no such state
    // — its retry is gated on upstream_send_armed instead.
    if constexpr (requires { loop->clear_upstream_send_state(conn.id); })
        loop->clear_upstream_send_state(conn.id);
    conn.upstream_recv_buf.reset();
    const i32 fd = UpstreamPool::create_socket();
    if (fd < 0) return false;
    conn.upstream_fd = fd;
    conn.upstream_start_us = monotonic_us();
    conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
    if (!loop->submit_connect(conn,
                              &target.addrs[conn.upstream_backend_idx],
                              sizeof(target.addrs[conn.upstream_backend_idx]))) {
        (void)detach_upstream_close(loop, conn);
        return false;
    }
    return true;
}

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
    // Per-request proxy state must start clean on EVERY request. reset() runs
    // only at connection alloc, so on a keep-alive-reused connection these flags
    // would otherwise leak from the previous request: a prior forward(set_path:)
    // would re-rewrite this request's path, and a stale proxy_resp_started /
    // upstream_abandoned would skew the 504 timeout logic. This is the canonical
    // new-request boundary (past the incomplete/pipeline-wait returns above), hit
    // exactly once per complete request, before route matching / handler dispatch.
    conn.req_path_overridden = false;
    conn.req_path_override = {nullptr, 0};
    conn.target_transform_id = 0;
    conn.target_transform_recorded = false;
    conn.req_header_override_count = 0;  // forward(set_header:) — same leak risk
    conn.req_header_append_mask = 0;
    conn.req_header_override_overflow = false;
    conn.request_policy_id = 0;
    conn.request_policy_body_pending = false;
    conn.pending_forward_upstream_id = 0;
    conn.pending_forward_request_policy_id = 0;
    conn.pending_forward_response_policy_id = 0;
    conn.pending_forward_failure_policy_id = 0;
    conn.pending_forward_timeout_failure_policy_id = 0;
    if constexpr (requires(Loop* candidate, Connection& c) {
                      candidate->disarm_response_read_deadline(c);
                  }) {
        loop->disarm_response_read_deadline(conn);
    } else {
        conn.clear_response_read_deadline();
        conn.response_read_deadline_first_batch = false;
    }
    conn.request_body_fully_buffered = false;
    conn.request_upload_complete = false;
    conn.response_policy_id = 0;
    conn.response_policy_suppress_body = false;
    conn.failure_policy_id = 0;
    conn.timeout_failure_policy_id = 0;
    conn.failure_policy_suppress_body = false;
    conn.resp_header_mutation_pending_count = 0;
    conn.resp_header_mutation_pending_overflow = false;
    conn.resp_header_mutation_count = 0;
    conn.resp_header_mutation_overflow = false;
    if (conn.response_header_buf.valid()) conn.response_header_buf.reset();
    conn.proxy_resp_started = false;
    conn.upstream_abandoned = false;
    conn.upstream_keep_alive = false;
    conn.upstream_reused = false;
    conn.upstream_request_incomplete = false;
    conn.retry_req_send_len = 0;
    conn.retry_req_snapshot_replayable = true;
    conn.response_mutations_snapshotted = false;
    conn.req_body_streamed = false;
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
        client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    // Built-in Prometheus endpoint. Opt-in: only when the loop carries the
    // cross-shard metrics registry (main wires it under --metrics). Served on
    // the data listener at GET /metrics, ahead of route matching, and works
    // even with no RouteConfig. `if constexpr` keeps it out of loops/mocks that
    // don't expose the registry.
    //
    // RESERVED PATH: when --metrics is enabled, GET /metrics is a built-in
    // endpoint that intentionally shadows any user route on that path.
    // req_path_canon is the canonical-for-routing slice (leading/trailing '/'
    // stripped, query removed), so /metrics, /metrics/ and /metrics?x all match.
    // Only GET is intercepted — POST/PUT/DELETE/… /metrics fall through to
    // normal routing (they are not the scrape endpoint and must not return the
    // metrics body, keeping the behavior consistent with "Prometheus endpoint").
    if constexpr (requires { loop->all_shard_metrics; }) {
        if (loop->all_shard_metrics != nullptr &&
            conn.req_method == static_cast<u8>(LogHttpMethod::Get) &&
            conn.req_path_canon.eq(Str{"metrics", 7})) {
            // Fixed 8 KiB exposition buffer. The current metric set (counters +
            // gauges + the 11-bucket latency histogram + _sum/_count) renders in
            // a few hundred bytes, so this has ample headroom. format_prometheus
            // is fail-closed: if the output would NOT fit it returns 0 (never a
            // truncated/invalid body) and we respond 500 instead of emitting
            // malformed Prometheus text. If the metric set ever outgrows 8 KiB,
            // bump this buffer — the 500 is the signal, not silent truncation.
            char mbuf[8192];
            const ShardMetrics kAgg =
                aggregate_metrics(loop->all_shard_metrics, loop->shard_metrics_count);
            const u32 kLen = format_prometheus(kAgg, mbuf, sizeof(mbuf));
            if (kLen > 0) {
                format_response_with_body(conn, 200, mbuf, kLen, conn.keep_alive);
            } else {
                format_static_response(conn, 500, /*keep_alive=*/false);
                conn.keep_alive = false;
            }
            conn.resp_status = kLen > 0 ? 200 : 500;
            conn.transition_to_sending(&on_response_sent<Loop>);
            loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
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

    if (!prepare_response_read_deadline_preflight(loop, conn, route, config)) return;

    // Per-route rate limit (fixed window). Enforced after route match, before
    // dispatch. A route may stack several rules; a request must pass every one,
    // each metered by its own key tuple (IP / header / query / cookie / param;
    // empty = per-client-IP). The limiter is per-shard (one thread each), so a
    // thread_local table needs no atomics — same rationale as the parse cache.
    if (route && route->rate_limit.count > 0 && config) {
        u32 path_len = 0;
        while (path_len < Connection::kMaxReqPathLen && conn.req_path[path_len] != '\0') path_len++;
        RateLimitKeyInput key_in;
        key_in.peer_addr = conn.peer_addr;
        key_in.req_buf = conn.recv_buf.data();
        key_in.req_header_end = conn.req_header_end;
        key_in.path = conn.req_path;
        key_in.path_len = path_len;
        key_in.params = route_params;
        key_in.param_count = route_param_count;
        const u32 kRouteIdx = static_cast<u32>(route - config->routes);
        if (rate_limit_exceeded(loop, route->rate_limit, kRouteIdx, key_in, monotonic_us())) {
            conn.resp_status = 429;
            format_static_response(conn, 429, /*keep_alive=*/false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
    }

    // @throttle: arm per-connection downstream pacing for this request's response
    // (0 = unthrottled). The token bucket starts empty (tat = 0 ⇒ the first chunk
    // goes immediately, then paced). client_send advances tat by len*1e9/bps at
    // full precision (see there) — there is no precomputed ns-per-byte, which
    // would round to 0 and silently disable throttling for rates >= ~1 GB/s.
    conn.throttle_down_bps = route ? route->throttle_down_bps : 0;
    conn.throttle_tat_ns = 0;
#if RUT_ENABLE_WEBSOCKET
    // Per-request terminate config from the matched route, set for EVERY request (not just
    // the Proxy branch) so stale state from a prior keep-alive request — e.g. a terminate
    // route that returned a normal response, followed by a JIT websocket()/forward() — can
    // never mis-arm a later 101 as terminate.
    const bool ws_term = route && route->action == RouteAction::Proxy && route->ws_terminate;
    conn.is_ws_terminate_route = ws_term;
    conn.ws_handler = ws_term ? route->ws_frame_handler : nullptr;
    conn.ws_max_message_size = ws_term ? route->ws_max_message_size : 0;
    conn.ws_close_code = ws_term ? route->ws_close_code : 1000;
#endif

    if (route && route->action == RouteAction::Proxy) {
        conn.state = ConnState::Proxying;
        auto& target = config->upstreams[route->upstream_id];
        // Upstream concurrency cap: if the backend is already at its in-flight
        // limit, shed this request with 503 before opening a connection to it.
        // Otherwise take a slot, released on every exit path (completion via
        // release_upstream_slot at body-done; failure/close via close_conn).
        if (target.max_inflight != 0) {
            bool acquired = true;
            if constexpr (requires { loop->upstream_acquire(route->upstream_id, 1u); }) {
                acquired = loop->upstream_acquire(route->upstream_id, target.max_inflight);
            }
            if (!acquired) {
                conn.resp_status = 503;
                format_static_response(conn, 503, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            conn.upstream_slot_held = true;
            conn.upstream_slot_uid = route->upstream_id;
        }
        for (u32 i = 0; i < sizeof(conn.upstream_name) && i < target.name_len; i++)
            conn.upstream_name[i] = target.name[i];
        if (target.name_len < sizeof(conn.upstream_name))
            conn.upstream_name[target.name_len] = '\0';
        else
            conn.upstream_name[sizeof(conn.upstream_name) - 1] = '\0';
        conn.upstream_idx = route->upstream_id;
        // (terminate-mode config is set unconditionally above, for every request)
        conn.upstream_attempts = 1;  // initial attempt; on_upstream_connected retries
        conn.upstream_start_us = monotonic_us();
        const u32 kBackend =
            select_backend(route->upstream_id, target.addr_count, conn.upstream_start_us);
        conn.upstream_backend_idx = static_cast<u8>(kBackend);

        // Idle reuse: borrow a live keep-alive socket to this endpoint from the
        // per-shard pool and skip the TCP connect, driving the post-connect path
        // directly with a synthetic success. On a miss, fall through to a fresh
        // connect. `upstream_reused` lets a send/recv failure before any response
        // byte fall back to a fresh connect (idempotent methods only).
        if constexpr (requires {
                          loop->reuse_idle_upstream(
                              conn, route->upstream_id, static_cast<u8>(kBackend));
                      }) {
            if (loop->reuse_idle_upstream(conn, route->upstream_id, static_cast<u8>(kBackend))) {
                conn.upstream_reused = true;
                // Driving on_upstream_connected inline skips the UpstreamConnect
                // dispatch that refreshes the wheel to upstream_timeout, so refresh
                // here — else a reused send that parks (EPOLLOUT) or a stalled
                // backend would wait the longer keepalive deadline.
                if constexpr (requires { loop->timer.refresh(&conn, loop->upstream_timeout); }) {
                    loop->timer.refresh(&conn, loop->upstream_timeout);
                }
                on_upstream_connected<Loop>(static_cast<void*>(loop),
                                            conn,
                                            IoEvent{conn.id,
                                                    0,
                                                    0,
                                                    0,
                                                    IoEventType::UpstreamConnect,
                                                    0,
                                                    0,
                                                    conn.upstream_episode});
                return;
            }
        }

        const i32 kUpstreamFd = UpstreamPool::create_socket();
        if (kUpstreamFd < 0) {
            conn.resp_status = kStatusBadGateway;
            format_static_response(conn, 502, false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        conn.upstream_fd = kUpstreamFd;
        conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
        if (!loop->submit_connect(conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
            (void)detach_upstream_close(loop, conn);
            conn.upstream_idx = 0;
            conn.resp_status = kStatusBadGateway;
            format_static_response(conn, 502, false);
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
    } else if (route && route->action == RouteAction::Static) {
        conn.resp_status = route->status_code;
        format_static_response(conn, route->status_code, kKeepAlive);
        conn.transition_to_sending(&on_response_sent<Loop>);
        client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
    } else if (route && route->action == RouteAction::JitHandler && route->fn) {
        if (route->needs_req_body) {
            if (conn.req_body_mode == BodyMode::Chunked) {
                conn.resp_status = 400;
                format_static_response(conn, 400, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
        client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
    if (!prepare_response_read_deadline_preflight(loop, conn, route, config)) return;
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
void on_request_policy_body_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const bool fixed_upload =
        conn.response_read_deadline_state == ResponseReadDeadlineState::Validated &&
        conn.response_read_deadline_profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
    if (ev.result <= 0 || !conn.request_policy_body_pending ||
        conn.req_body_mode != BodyMode::ContentLength || conn.req_body_remaining == 0) {
        loop->close_conn(conn);
        return;
    }

    u32 consume = static_cast<u32>(ev.result);
    if (fixed_upload) {
        const auto& proof = conn.response_read_deadline_upload;
        const RouteConfig* config = conn.request_config;
        if (config == nullptr || proof.route_index >= config->route_count ||
            proof.handler_generation != conn.handler_gen ||
            config->routes[proof.route_index].fn != proof.route_fn ||
            conn.recv_buf.len() < conn.req_initial_send_len ||
            conn.recv_buf.len() > proof.raw_total_length) {
            loop->close_conn(conn);
            return;
        }
        // wait() may harvest and append multiple multishot Recv CQEs before
        // dispatching the first callback. Account the authoritative cumulative
        // buffer delta exactly once; later records either find the body slot
        // cleared at completion or observe a zero delta while the same live recv
        // remains armed. Never clamp bytes past the promised request boundary.
        consume = conn.recv_buf.len() - conn.req_initial_send_len;
        if (consume > conn.req_body_remaining) {
            loop->close_conn(conn);
            return;
        }
    } else if (consume > conn.req_body_remaining) {
        consume = conn.req_body_remaining;
    }
    conn.req_body_remaining -= consume;
    conn.req_size += consume;
    conn.req_initial_send_len =
        conn.req_header_end + (conn.req_content_length - conn.req_body_remaining);
    if (conn.req_body_remaining > 0) {
        if (fixed_upload && !response_read_deadline_fixed_upload_route_stable(conn, false)) {
            loop->close_conn(conn);
            return;
        }
        conn.transition_to_reading_body(&on_request_policy_body_recvd<Loop>);
        if (!loop->submit_recv(conn)) loop->close_conn(conn);
        return;
    }

    JitDispatchOutcome outcome{};
    outcome.kind = JitDispatchOutcome::Kind::Forward;
    outcome.upstream_id = conn.pending_forward_upstream_id;
    outcome.request_policy_id = conn.pending_forward_request_policy_id;
    outcome.response_policy_id = conn.pending_forward_response_policy_id;
    outcome.failure_policy_id = conn.pending_forward_failure_policy_id;
    outcome.timeout_failure_policy_id = conn.pending_forward_timeout_failure_policy_id;
    if (fixed_upload) {
        if (!response_read_deadline_fixed_upload_route_stable(conn, true)) {
            loop->close_conn(conn);
            return;
        }
        outcome.policy_bundle_id = conn.response_read_deadline_bundle_id;
        outcome.response_read_timeout_seconds = conn.response_read_deadline_seconds;
    }
    conn.request_policy_body_pending = false;
    conn.pending_forward_upstream_id = 0;
    conn.pending_forward_request_policy_id = 0;
    conn.pending_forward_response_policy_id = 0;
    conn.pending_forward_failure_policy_id = 0;
    conn.pending_forward_timeout_failure_policy_id = 0;
    // No handler is re-entered: the Forward outcome and pinned request config
    // are sufficient for the normal dispatch path to validate/rebuild once.
    handle_jit_outcome<Loop>(loop, conn, outcome, nullptr, conn.keep_alive);
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
        client_send(loop, conn, conn.send_buf.data() + conn.send_progress, kRemaining);
        return;
    }

    // Send complete — clear all slots (will set on_recv for keep-alive below).
    conn.send_progress = 0;
    conn.clear_slots();

    on_request_complete(loop, conn, conn.resp_status, conn.send_buf.len());
    conn.send_buf.reset();
    loop->epoch_leave();

    (void)detach_upstream_close(loop, conn);
    conn.upstream_idx = 0;

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
        client_send(loop, conn, conn.send_buf.data() + conn.send_progress, kRemaining);
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

inline bool collect_effective_response_headers(const Connection& conn,
                                               const RouteConfig* cfg,
                                               u16 static_set_index,
                                               ResponseHeaderKV* out,
                                               u32 capacity,
                                               u32* out_count,
                                               bool* out_suppress_default_content_type = nullptr) {
    *out_count = 0;
    if (out_suppress_default_content_type != nullptr) *out_suppress_default_content_type = false;
    if (conn.resp_header_mutation_overflow) return false;
    if (static_set_index != 0 && cfg != nullptr &&
        static_set_index <= cfg->response_header_set_count) {
        const auto& ref = cfg->response_header_sets[static_set_index - 1];
        if (ref.count > capacity) return false;
        for (u16 i = 0; i < ref.count; i++) {
            out[*out_count] = {cfg->header_keys[ref.offset + i].data,
                               cfg->header_keys[ref.offset + i].len,
                               cfg->header_values[ref.offset + i].data,
                               cfg->header_values[ref.offset + i].len};
            (*out_count)++;
        }
    }
    for (u32 mi = 0; mi < conn.resp_header_mutation_count; mi++) {
        const auto& mutation = conn.resp_header_mutations[mi];
        const bool remove = mutation.mode == Connection::RespHeaderMutationMode::Remove;
        if (validate_response_header(mutation.name.ptr,
                                     mutation.name.len,
                                     remove ? "" : mutation.value.ptr,
                                     remove ? 0 : mutation.value.len) != HttpHeaderValidation::Ok)
            return false;
        if (out_suppress_default_content_type != nullptr &&
            http_header_name_eq_ci(mutation.name.ptr, mutation.name.len, "content-type", 12))
            *out_suppress_default_content_type = remove;
        if (mutation.mode != Connection::RespHeaderMutationMode::Add) {
            for (u32 i = 0; i < *out_count;) {
                if (!http_header_name_eq_ci(
                        out[i].key_data, out[i].key_len, mutation.name.ptr, mutation.name.len)) {
                    i++;
                    continue;
                }
                for (u32 move = i + 1; move < *out_count; move++) out[move - 1] = out[move];
                (*out_count)--;
            }
        }
        if (!remove) {
            if (*out_count >= capacity) return false;
            out[(*out_count)++] = {
                mutation.name.ptr, mutation.name.len, mutation.value.ptr, mutation.value.len};
        }
    }
    return true;
}

inline bool response_mutation_survives(const Connection& conn, u32 index) {
    const auto& current = conn.resp_header_mutations[index];
    if (current.mode == Connection::RespHeaderMutationMode::Remove) return false;
    for (u32 i = index + 1; i < conn.resp_header_mutation_count; i++) {
        const auto& later = conn.resp_header_mutations[i];
        if (later.mode != Connection::RespHeaderMutationMode::Add &&
            http_header_name_eq_ci(
                current.name.ptr, current.name.len, later.name.ptr, later.name.len))
            return false;
    }
    return true;
}

// Serialize only the rewritten upstream HTTP/1 header block into dedicated,
// response-lifetime storage. The original upstream buffer (including its body)
// stays untouched and is streamed after this header send completes.
inline bool build_h1_forward_response_headers(Connection& conn, u32 header_len, bool draining) {
    if (conn.resp_header_mutation_count == 0 || conn.resp_header_mutation_overflow ||
        !conn.response_header_buf.valid() || header_len < 4 ||
        header_len > conn.upstream_recv_buf.len())
        return false;

    // Compile-time validation cannot see request-derived values. Validate the
    // committed runtime log before writing any bytes so malformed values fail
    // closed without leaving a partially serialized header block.
    for (u32 i = 0; i < conn.resp_header_mutation_count; i++) {
        const auto& mutation = conn.resp_header_mutations[i];
        const bool remove = mutation.mode == Connection::RespHeaderMutationMode::Remove;
        // ReservedKey includes Content-Length and Transfer-Encoding. Reject
        // those mutations before serialization so the upstream framing parsed
        // into resp_body_mode remains the sole downstream framing authority.
        // Once a 101 is accepted the runtime will enter the raw upgrade
        // tunnel. Do not allow mutations to rewrite its required Connection
        // nomination or negotiated upgrade/WebSocket handshake fields after
        // tunnel mode was chosen from the original upstream response.
        if (conn.resp_status == 101 &&
            (http_header_name_eq_ci(mutation.name.ptr, mutation.name.len, "connection", 10) ||
             http_header_name_eq_ci(mutation.name.ptr, mutation.name.len, "upgrade", 7) ||
             http_header_name_eq_ci(
                 mutation.name.ptr, mutation.name.len, "sec-websocket-protocol", 22) ||
             http_header_name_eq_ci(
                 mutation.name.ptr, mutation.name.len, "sec-websocket-extensions", 24) ||
             http_header_name_eq_ci(
                 mutation.name.ptr, mutation.name.len, "sec-websocket-accept", 20)))
            return false;
        if (validate_response_header(mutation.name.ptr,
                                     mutation.name.len,
                                     remove ? "" : mutation.value.ptr,
                                     remove ? 0 : mutation.value.len) != HttpHeaderValidation::Ok)
            return false;
    }

    const u8* data = conn.upstream_recv_buf.data();
    auto write = [&](const void* src, u32 len) {
        return conn.response_header_buf.write(static_cast<const u8*>(src), len) == len;
    };
    auto connection_value_nominates =
        [&](const u8* value, u32 value_len, const char* name, u32 name_len) {
            u32 pos = 0;
            while (pos < value_len) {
                while (pos < value_len &&
                       (value[pos] == ',' || value[pos] == ' ' || value[pos] == '\t'))
                    pos++;
                const u32 start = pos;
                while (pos < value_len && value[pos] != ',') pos++;
                u32 end = pos;
                while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) end--;
                if (end > start &&
                    http_header_name_eq_ci(
                        reinterpret_cast<const char*>(value + start), end - start, name, name_len))
                    return true;
            }
            return false;
        };
    auto upstream_connection_nominates = [&](const char* name, u32 name_len) {
        // A successful 101 switches to a raw tunnel, whose Connection/Upgrade
        // handshake must remain byte-compatible with the upstream response.
        if (conn.resp_status == 101) return false;
        u32 line_start = 0;
        while (line_start + 1 < header_len &&
               (data[line_start] != '\r' || data[line_start + 1] != '\n'))
            line_start++;
        line_start += 2;
        while (line_start + 1 < header_len &&
               (data[line_start] != '\r' || data[line_start + 1] != '\n')) {
            u32 line_end = line_start;
            while (line_end + 1 < header_len &&
                   (data[line_end] != '\r' || data[line_end + 1] != '\n'))
                line_end++;
            if (line_end + 1 >= header_len) return false;
            u32 colon = line_start;
            while (colon < line_end && data[colon] != ':') colon++;
            if (colon == line_end) return false;
            u32 field_name_end = colon;
            while (field_name_end > line_start &&
                   (data[field_name_end - 1] == ' ' || data[field_name_end - 1] == '\t'))
                field_name_end--;
            if (http_header_name_eq_ci(reinterpret_cast<const char*>(data + line_start),
                                       field_name_end - line_start,
                                       "connection",
                                       10) &&
                connection_value_nominates(data + colon + 1, line_end - colon - 1, name, name_len))
                return true;
            line_start = line_end + 2;
        }
        return false;
    };
    const bool nominated_framing = upstream_connection_nominates("content-length", 14) ||
                                   upstream_connection_nominates("transfer-encoding", 17);
    auto base_suppressed = [&](const char* name, u32 name_len) {
        const bool framing = http_header_name_eq_ci(name, name_len, "content-length", 14) ||
                             http_header_name_eq_ci(name, name_len, "transfer-encoding", 17);
        // Even a malformed upstream Connection nomination must not strip the
        // field that frames the already-parsed body. Preserve that field and
        // force downstream close below so the message stays self-delimiting.
        if (framing) return false;
        if ((draining || nominated_framing) &&
            http_header_name_eq_ci(name, name_len, "connection", 10))
            return true;
        if (upstream_connection_nominates(name, name_len)) return true;
        for (u32 i = 0; i < conn.resp_header_mutation_count; i++) {
            const auto& mutation = conn.resp_header_mutations[i];
            if (mutation.mode != Connection::RespHeaderMutationMode::Add &&
                http_header_name_eq_ci(name, name_len, mutation.name.ptr, mutation.name.len))
                return true;
        }
        return false;
    };
    auto nominated_mutation = [&](const u8* token, u32 token_len) {
        for (u32 i = 0; i < conn.resp_header_mutation_count; i++) {
            const auto& mutation = conn.resp_header_mutations[i];
            // A final Remove has no emitted mutation, but it still removes the
            // upstream field named by this Connection option. Strip that stale
            // nomination along with nominations for surviving Set/Add entries.
            if (mutation.mode != Connection::RespHeaderMutationMode::Remove &&
                !response_mutation_survives(conn, i))
                continue;
            if (http_header_name_eq_ci(reinterpret_cast<const char*>(token),
                                       token_len,
                                       mutation.name.ptr,
                                       mutation.name.len))
                return true;
        }
        return false;
    };
    auto connection_nominates_mutation = [&](const u8* value, u32 value_len) {
        u32 pos = 0;
        while (pos < value_len) {
            while (pos < value_len &&
                   (value[pos] == ',' || value[pos] == ' ' || value[pos] == '\t'))
                pos++;
            const u32 start = pos;
            while (pos < value_len && value[pos] != ',') pos++;
            u32 end = pos;
            while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) end--;
            if (end > start && nominated_mutation(value + start, end - start)) return true;
        }
        return false;
    };
    auto write_filtered_connection = [&](const u8* value, u32 value_len) {
        static constexpr char kConnection[] = "Connection: ";
        static constexpr char kCommaSpace[] = ", ";
        static constexpr char kCrLf[] = "\r\n";
        bool wrote_header = false;
        u32 pos = 0;
        while (pos < value_len) {
            while (pos < value_len &&
                   (value[pos] == ',' || value[pos] == ' ' || value[pos] == '\t'))
                pos++;
            const u32 start = pos;
            while (pos < value_len && value[pos] != ',') pos++;
            u32 end = pos;
            while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t')) end--;
            if (end == start || nominated_mutation(value + start, end - start)) continue;
            if (!wrote_header) {
                if (!write(kConnection, sizeof(kConnection) - 1)) return false;
                wrote_header = true;
            } else if (!write(kCommaSpace, sizeof(kCommaSpace) - 1)) {
                return false;
            }
            if (!write(value + start, end - start)) return false;
        }
        return !wrote_header || write(kCrLf, sizeof(kCrLf) - 1);
    };

    conn.response_header_buf.reset();
    u32 line_start = 0;
    u32 line_end = 0;
    while (line_end + 1 < header_len && (data[line_end] != '\r' || data[line_end + 1] != '\n'))
        line_end++;
    if (line_end + 1 >= header_len || !write(data, line_end + 2)) return false;
    line_start = line_end + 2;
    while (line_start + 1 < header_len &&
           (data[line_start] != '\r' || data[line_start + 1] != '\n')) {
        line_end = line_start;
        while (line_end + 1 < header_len && (data[line_end] != '\r' || data[line_end + 1] != '\n'))
            line_end++;
        if (line_end + 1 >= header_len) return false;
        u32 colon = line_start;
        while (colon < line_end && data[colon] != ':') colon++;
        if (colon == line_end) return false;
        u32 name_end = colon;
        while (name_end > line_start && (data[name_end - 1] == ' ' || data[name_end - 1] == '\t'))
            name_end--;
        const bool is_connection =
            http_header_name_eq_ci(reinterpret_cast<const char*>(data + line_start),
                                   name_end - line_start,
                                   "connection",
                                   10);
        if (!base_suppressed(reinterpret_cast<const char*>(data + line_start),
                             name_end - line_start)) {
            const u8* value = data + colon + 1;
            const u32 value_len = line_end - colon - 1;
            if (is_connection && connection_nominates_mutation(value, value_len)) {
                if (!write_filtered_connection(value, value_len)) return false;
            } else if (!write(data + line_start, line_end + 2 - line_start)) {
                return false;
            }
        }
        line_start = line_end + 2;
    }

    static const char kColonSpace[] = ": ";
    static const char kCrLf[] = "\r\n";
    for (u32 i = 0; i < conn.resp_header_mutation_count; i++) {
        if (!response_mutation_survives(conn, i)) continue;
        const auto& mutation = conn.resp_header_mutations[i];
        if (!write(mutation.name.ptr, mutation.name.len) || !write(kColonSpace, 2) ||
            !write(mutation.value.ptr, mutation.value.len) || !write(kCrLf, 2))
            return false;
    }
    static const char kConnectionClose[] = "Connection: close\r\n";
    if (nominated_framing) conn.keep_alive = false;
    if ((draining || nominated_framing) && !write(kConnectionClose, sizeof(kConnectionClose) - 1))
        return false;
    return write(kCrLf, 2);
}

template <typename Loop>
void handle_jit_outcome(
    Loop* loop, Connection& conn, JitDispatchOutcome outcome, jit::HandlerFn fn, bool keep_alive) {
    if (conn.response_read_deadline_state == ResponseReadDeadlineState::Preflight &&
        outcome.kind != JitDispatchOutcome::Kind::Forward) {
        loop->close_conn(conn);
        return;
    }
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
            const bool has_header_set =
                outcome.response_headers_idx != 0 && cfg != nullptr &&
                outcome.response_headers_idx <= cfg->response_header_set_count;
            constexpr u32 kMaxEffectiveHeaders =
                RouteConfig::kMaxHeadersPerSet + Connection::kMaxRespHeaderMutations;
            ResponseHeaderKV kvs[kMaxEffectiveHeaders];
            u32 header_count = 0;
            bool suppress_default_content_type = false;
            if (!collect_effective_response_headers(conn,
                                                    cfg,
                                                    outcome.response_headers_idx,
                                                    kvs,
                                                    kMaxEffectiveHeaders,
                                                    &header_count,
                                                    &suppress_default_content_type)) {
                conn.resp_status = 500;
                conn.keep_alive = false;
                format_static_response(conn, 500, false);
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            // Distinguish "user didn't supply a body" (body_idx == 0)
            // from "user supplied one but it's out of range" (a config
            // mismatch). The latter falls back to the reason-phrase
            // default so the response still has a representative body
            // — matches the no-headers path's documented behavior of
            // falling back rather than rendering garbage.
            const bool body_idx_invalid = outcome.response_body_idx != 0 && !has_body;
            if (has_header_set || header_count != 0 || suppress_default_content_type) {
                const char* body_data = nullptr;
                u32 body_len = 0;
                bool body_is_fallback = false;
                if (has_body) {
                    const auto& body = cfg->response_bodies[outcome.response_body_idx - 1];
                    body_data = body.data;
                    body_len = body.len;
                } else if (body_idx_invalid || !has_header_set) {
                    // A status-only response that gained runtime headers, or
                    // an out-of-range body_idx, still uses the default
                    // reason-phrase body just like the no-headers path. Flag it
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
                                                      header_count,
                                                      keep_alive,
                                                      body_is_fallback,
                                                      suppress_default_content_type);
            } else if (has_body) {
                const auto& body = cfg->response_bodies[outcome.response_body_idx - 1];
                format_response_with_body(
                    conn, outcome.status_code, body.data, body.len, keep_alive);
            } else {
                format_static_response(conn, outcome.status_code, keep_alive);
            }
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
        case JitDispatchOutcome::Kind::Redirect: {
            // Redirects are local responses: resolve only against the pinned
            // request config and publish a complete response before any
            // request-policy or upstream path can run. Unsupported input uses
            // the existing exact 400/close fallback.
            conn.pending_handler_fn = nullptr;
            const RouteConfig* config = conn.request_config;
            if (config == nullptr ||
                !config->redirect_policy_id_is_valid(outcome.redirect_policy_id)) {
                reject_response_policy(loop, conn);
                return;
            }
            if (!stage_redirect_response(conn, *config, outcome.redirect_policy_id)) {
                reject_response_policy(loop, conn);
                return;
            }
            conn.resp_status =
                config->redirect_policies[outcome.redirect_policy_id - 1].status_code;
            conn.keep_alive = false;
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            };
            auto send_internal_error = [&]() {
                conn.pending_handler_fn = nullptr;
                conn.resp_status = 500;
                format_static_response(conn, 500, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
                if (!client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len())) {
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
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                if (conn.upstream_fd >= 0) {
                    (void)detach_upstream_close(loop, conn);
                    conn.upstream_idx = 0;
                }
                conn.upstream_fd = kUpstreamFd;
                conn.upstream_idx = static_cast<u16>(upstream_id);
                conn.upstream_start_us = monotonic_us();
                const u32 kBackend = select_backend(
                    static_cast<u16>(upstream_id), target.addr_count, conn.upstream_start_us);
                conn.upstream_backend_idx = static_cast<u8>(kBackend);
                if (!loop->submit_connect(
                        conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
                    (void)detach_upstream_close(loop, conn);
                    conn.upstream_idx = 0;
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
            u16 forward_response_policy_id = outcome.response_policy_id;
            u16 forward_failure_policy_id = outcome.failure_policy_id;
            u16 forward_timeout_failure_policy_id = outcome.timeout_failure_policy_id;
            ForwardResponseBufferingMode forward_response_buffering =
                ForwardResponseBufferingMode::None;
            if (outcome.policy_bundle_id != 0) {
                if (config == nullptr ||
                    !config->policy_bundle_id_is_valid(outcome.policy_bundle_id)) {
                    loop->close_conn(conn);
                    return;
                }
                const auto& bundle = config->policy_bundles[outcome.policy_bundle_id - 1];
                forward_response_policy_id = bundle.response_policy_id;
                forward_failure_policy_id = bundle.failure_policy_id;
                forward_timeout_failure_policy_id = bundle.timeout_failure_policy_id;
                outcome.response_read_timeout_seconds = bundle.response_read_timeout_seconds;
                forward_response_buffering = bundle.response_buffering;
            }
            const bool complete_content_length_buffering =
                forward_response_buffering == ForwardResponseBufferingMode::CompleteContentLength;
            if (outcome.response_read_timeout_seconds != 0) {
                const bool loop_supports_deadline = [] {
                    if constexpr (requires { Loop::kSupportsExplicitFirstResponseDeadline; })
                        return Loop::kSupportsExplicitFirstResponseDeadline;
                    return false;
                }();
                const bool target_valid =
                    config != nullptr && outcome.upstream_id < config->upstream_count &&
                    config->upstreams[outcome.upstream_id].addr_count == 1 &&
                    config->upstreams[outcome.upstream_id].addrs[0].sin_family == AF_INET &&
                    config->upstreams[outcome.upstream_id].max_inflight == 0;
                const RequestPolicyBodyState request_body_state =
                    outcome.request_policy_id == 0
                        ? RequestPolicyBodyState::Complete
                        : inspect_request_policy_body(conn, outcome.request_policy_id);
                ResponseReadDeadlineProfile outcome_profile = ResponseReadDeadlineProfile::None;
                if (config != nullptr &&
                    config->response_policy_id_is_valid(forward_response_policy_id) &&
                    config->failure_policy_id_is_valid(forward_failure_policy_id) &&
                    config->timeout_failure_policy_id_is_valid(forward_timeout_failure_policy_id)) {
                    outcome_profile = classify_response_read_deadline_profile(
                        conn,
                        config->response_policies[forward_response_policy_id - 1],
                        config->failure_policies[forward_failure_policy_id - 1],
                        config->failure_policies[forward_timeout_failure_policy_id - 1]);
                }
                const bool fixed_upload =
                    outcome_profile ==
                    ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
                const bool deadline_phase_valid =
                    (conn.response_read_deadline_state == ResponseReadDeadlineState::Preflight &&
                     (!fixed_upload ||
                      (fn != nullptr && fn == conn.response_read_deadline_upload.route_fn))) ||
                    (fixed_upload &&
                     conn.response_read_deadline_state == ResponseReadDeadlineState::Validated &&
                     fn == nullptr && !conn.request_policy_body_pending &&
                     request_body_state == RequestPolicyBodyState::Complete);
                const bool request_policy_valid =
                    fixed_upload ? outcome.request_policy_id ==
                                           static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
                                       request_body_state != RequestPolicyBodyState::Invalid
                    : complete_content_length_buffering
                        ? complete_content_length_request_policy_is_admitted(
                              outcome.request_policy_id) &&
                              request_body_state == RequestPolicyBodyState::Complete
                        : outcome.request_policy_id == 0 ||
                              (request_policy_is_supported(outcome.request_policy_id) &&
                               request_body_state == RequestPolicyBodyState::Complete);
                if (!loop_supports_deadline || !deadline_phase_valid ||
                    conn.response_read_deadline_owner_generation == 0 ||
                    conn.response_read_deadline_owner_generation !=
                        conn.response_read_deadline_generation ||
                    outcome.policy_bundle_id == 0 ||
                    outcome.policy_bundle_id != conn.response_read_deadline_bundle_id ||
                    outcome.response_read_timeout_seconds != conn.response_read_deadline_seconds ||
                    forward_response_buffering != conn.response_read_deadline_buffering ||
                    outcome_profile == ResponseReadDeadlineProfile::None ||
                    outcome_profile != conn.response_read_deadline_profile ||
                    conn.response_read_deadline_method != conn.req_method ||
                    !response_read_deadline_route_method_matches(
                        conn.response_read_deadline_method,
                        conn.response_read_deadline_route_method) ||
                    !target_valid || !request_policy_valid || conn.target_transform_recorded ||
                    conn.req_path_overridden || conn.req_header_override_count != 0 ||
                    conn.req_header_override_overflow || conn.resp_header_mutation_count != 0 ||
                    conn.resp_header_mutation_pending_count != 0 ||
                    conn.resp_header_mutation_pending_overflow ||
                    conn.resp_header_mutation_overflow || conn.protocol != ConnProtocol::Http11 ||
                    conn.tls_active || conn.pipeline_depth != 0 ||
                    (!fixed_upload &&
                     (conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
                      conn.request_body_fully_buffered ||
                      conn.recv_buf.len() != conn.req_initial_send_len)) ||
                    (fixed_upload &&
                     !response_read_deadline_fixed_upload_route_stable(
                         conn, request_body_state == RequestPolicyBodyState::Complete))) {
                    loop->close_conn(conn);
                    return;
                }
                if (fixed_upload) {
                    auto& proof = conn.response_read_deadline_upload;
                    if ((proof.upstream_id != 0xffffu &&
                         proof.upstream_id != outcome.upstream_id) ||
                        (proof.request_policy_id != 0 &&
                         proof.request_policy_id != outcome.request_policy_id)) {
                        loop->close_conn(conn);
                        return;
                    }
                    proof.upstream_id = outcome.upstream_id;
                    proof.request_policy_id = outcome.request_policy_id;
                } else if (complete_content_length_buffering) {
                    auto& proof = conn.response_read_deadline_upload;
                    if (proof.request_policy_id != 0) {
                        loop->close_conn(conn);
                        return;
                    }
                    proof.request_policy_id = outcome.request_policy_id;
                }
                conn.response_read_deadline_state = ResponseReadDeadlineState::Validated;
            } else if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
                // A preflight-marked route must return the same immutable bundle;
                // absence or a mismatched outcome cannot silently shed timing.
                loop->close_conn(conn);
                return;
            }
            if (conn.target_transform_recorded) {
                // Validate every deterministic Forward reference and the bounded
                // transform domain before touching recv_buf. The transform is
                // deliberately last: policy rebuilding and response snapshots
                // must never observe a partially or incorrectly validated target.
                if (config == nullptr || outcome.upstream_id >= config->upstream_count) {
                    reject_request_policy(loop, conn);
                    return;
                }
                const u16 target_response_policy_id = forward_response_policy_id;
                const u16 target_failure_policy_id = forward_failure_policy_id;
                const u16 target_timeout_failure_policy_id = forward_timeout_failure_policy_id;
                if ((target_response_policy_id != 0 &&
                     !config->response_policy_id_is_valid(target_response_policy_id)) ||
                    (target_failure_policy_id != 0 &&
                     !config->failure_policy_id_is_valid(target_failure_policy_id)) ||
                    (target_timeout_failure_policy_id != 0 &&
                     !config->timeout_failure_policy_id_is_valid(
                         target_timeout_failure_policy_id)) ||
                    (target_failure_policy_id != 0 &&
                     !failure_policy_runtime_supported(
                         config->failure_policies[target_failure_policy_id - 1])) ||
                    (target_timeout_failure_policy_id != 0 &&
                     !failure_policy_runtime_supported(
                         config->failure_policies[target_timeout_failure_policy_id - 1])) ||
                    !forward_policy_head_modes_compatible(*config,
                                                          target_response_policy_id,
                                                          target_failure_policy_id,
                                                          target_timeout_failure_policy_id) ||
                    (outcome.request_policy_id != 0 &&
                     (!request_policy_is_supported(outcome.request_policy_id) ||
                      inspect_request_policy_body(conn, outcome.request_policy_id) !=
                          RequestPolicyBodyState::Complete))) {
                    reject_response_policy(loop, conn);
                    return;
                }
                if (target_response_policy_id != 0 &&
                    !response_policy_runtime_supported(
                        config->response_policies[target_response_policy_id - 1])) {
                    reject_response_policy(loop, conn);
                    return;
                }
                const auto& target = config->upstreams[outcome.upstream_id];
                bool response_policy_request_connection = false;
                if (target_response_policy_id != 0) {
                    response_policy_request_connection =
                        config->response_policies[target_response_policy_id - 1].connection ==
                        ResponsePolicyConnection::Request;
                }
                if (target.addr_count != 1 || target.addrs[0].sin_family != AF_INET ||
                    conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
                    conn.req_method == static_cast<u8>(LogHttpMethod::Head) || conn.tls_active ||
                    conn.req_path_canon.ptr == nullptr || conn.req_wants_upgrade ||
                    conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
                    conn.request_body_fully_buffered ||
                    (target_response_policy_id != 0 && !response_policy_request_connection &&
                     !conn.req_keep_alive) ||
                    conn.req_header_override_count != 0 || conn.req_header_override_overflow ||
                    conn.resp_header_mutation_count != 0 ||
                    conn.resp_header_mutation_pending_count != 0 ||
                    conn.resp_header_mutation_pending_overflow ||
                    conn.resp_header_mutation_overflow) {
                    reject_request_policy(loop, conn);
                    return;
                }
                // Resolve and materialize against the pinned table only after all
                // references and domain guards have passed. Forged IDs and inputs
                // outside the bounded clean H1 domain remain fail-closed.
                if (config == nullptr || !materialize_request_target_transform(conn, *config)) {
                    reject_request_policy(loop, conn);
                    return;
                }
            }
            if (!config || outcome.upstream_id >= config->upstream_count) {
                // Unresolvable upstream id — handler returned a value
                // the config doesn't know. Fail closed with 502 rather
                // than hanging or silently discarding the request.
                conn.resp_status = kStatusBadGateway;
                format_static_response(conn, 502, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            if (outcome.policy_bundle_id == 0) {
                if ((forward_failure_policy_id != 0 &&
                     !config->failure_policy_id_is_valid(forward_failure_policy_id)) ||
                    (forward_timeout_failure_policy_id != 0 &&
                     (forward_response_policy_id == 0 || forward_failure_policy_id == 0 ||
                      !config->timeout_failure_policy_id_is_valid(
                          forward_timeout_failure_policy_id)))) {
                    reject_response_policy(loop, conn);
                    return;
                }
            }
            if (forward_response_policy_id != 0 &&
                !config->response_policy_id_is_valid(forward_response_policy_id)) {
                // Validate direct response IDs at the same pre-body boundary
                // as failure IDs; a malformed ID must not be parked in a
                // request-policy body wait and resolved later.
                reject_response_policy(loop, conn);
                return;
            }
            if (!forward_policy_head_modes_compatible(*config,
                                                      forward_response_policy_id,
                                                      forward_failure_policy_id,
                                                      forward_timeout_failure_policy_id)) {
                // A failure SuppressBody policy is meaningful only when the
                // success policy carries the same disposition.  Response-only
                // SuppressBody remains valid for the existing HEAD success
                // path, but mismatched pairs fail before any body wait.
                reject_response_policy(loop, conn);
                return;
            }
            bool suppress_body_head =
                forward_response_policy_id != 0 &&
                config->response_policies[forward_response_policy_id - 1].head_mode ==
                    ResponsePolicyHeadMode::SuppressBody &&
                response_policy_suppress_head_admitted(
                    conn,
                    config->response_policies[forward_response_policy_id - 1],
                    forward_failure_policy_id != 0);
            const bool suppress_failure_head =
                forward_response_policy_id != 0 && forward_failure_policy_id != 0 &&
                config->response_policies[forward_response_policy_id - 1].head_mode ==
                    ResponsePolicyHeadMode::SuppressBody &&
                config->failure_policies[forward_failure_policy_id - 1].head_mode ==
                    FailurePolicyHeadMode::SuppressBody &&
                suppress_body_head;
            // Validate the selected failure disposition before request-body
            // waiting, policy rewriting, target materialisation, or any
            // upstream resource can be touched. Only the paired SuppressBody
            // contract below is executable in this increment.
            if (forward_failure_policy_id != 0 &&
                !failure_policy_runtime_supported(
                    config->failure_policies[forward_failure_policy_id - 1]) &&
                !suppress_failure_head) {
                reject_response_policy(loop, conn);
                return;
            }
            if (forward_timeout_failure_policy_id != 0 &&
                (!config->timeout_failure_policy_id_is_valid(forward_timeout_failure_policy_id) ||
                 (!failure_policy_runtime_supported(
                      config->failure_policies[forward_timeout_failure_policy_id - 1]) &&
                  !suppress_failure_head))) {
                reject_response_policy(loop, conn);
                return;
            }
            // A paired SuppressBody contract is deliberately narrower than
            // ordinary response-only policy handling: it must prove the full
            // explicit-close HEAD domain before request-policy body waiting,
            // rewriting, or any upstream resource is touched.
            if (forward_failure_policy_id != 0 &&
                config->failure_policies[forward_failure_policy_id - 1].head_mode ==
                    FailurePolicyHeadMode::SuppressBody &&
                !suppress_failure_head) {
                reject_response_policy(loop, conn);
                return;
            }
            auto& target = config->upstreams[outcome.upstream_id];
            // Policy rewriting uses the request buffers before the response
            // mutation snapshot is established. Reject combinations and
            // multi-endpoint targets before allocating slots or selecting an
            // endpoint; never emit a Host for an endpoint that may differ on
            // retry.
            if (outcome.request_policy_id != 0 &&
                (!(complete_content_length_buffering
                       ? complete_content_length_request_policy_is_admitted(
                             outcome.request_policy_id)
                       : request_policy_is_supported(outcome.request_policy_id)) ||
                 target.addr_count != 1 || conn.resp_header_mutation_count != 0 ||
                 conn.resp_header_mutation_pending_count != 0 ||
                 conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow ||
                 conn.req_path_overridden || conn.req_header_override_count != 0 ||
                 conn.req_header_override_overflow)) {
                reject_request_policy(loop, conn);
                return;
            }
            const u32 kBackend = select_backend(
                static_cast<u16>(outcome.upstream_id), target.addr_count, monotonic_us());
            bool request_policy_prepared = false;
            if (outcome.request_policy_id != 0) {
                const RequestPolicyBodyState body_state =
                    inspect_request_policy_body(conn, outcome.request_policy_id);
                if (body_state == RequestPolicyBodyState::Invalid) {
                    reject_request_policy(loop, conn);
                    return;
                }
                if (body_state == RequestPolicyBodyState::Waiting) {
                    // The handler has already run and request_config remains pinned
                    // for the epoch. Retain only the compact Forward outcome; no
                    // slot, upstream fd, or policy rewrite is created yet.
                    conn.request_policy_body_pending = true;
                    conn.pending_forward_upstream_id = outcome.upstream_id;
                    conn.pending_forward_request_policy_id = outcome.request_policy_id;
                    conn.pending_forward_response_policy_id = forward_response_policy_id;
                    conn.pending_forward_failure_policy_id = forward_failure_policy_id;
                    conn.pending_forward_timeout_failure_policy_id =
                        forward_timeout_failure_policy_id;
                    conn.request_policy_id = outcome.request_policy_id;
                    conn.transition_to_reading_body(&on_request_policy_body_recvd<Loop>);
                    if (!loop->submit_recv(conn)) loop->close_conn(conn);
                    return;
                }
                if (!apply_request_policy(
                        conn, target.addrs[kBackend], outcome.request_policy_id)) {
                    if (conn.response_read_deadline_state == ResponseReadDeadlineState::Validated)
                        loop->close_conn(conn);
                    else
                        reject_request_policy(loop, conn);
                    return;
                }
                if (conn.response_read_deadline_profile ==
                    ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero) {
                    ResponseReadDeadlineFixedUploadRequest rewritten{};
                    auto& proof = conn.response_read_deadline_upload;
                    if (!inspect_response_read_deadline_fixed_upload_request(conn, &rewritten) ||
                        rewritten.content_length != proof.raw_content_length ||
                        rewritten.total_length != conn.recv_buf.len() ||
                        conn.req_initial_send_len != rewritten.total_length ||
                        conn.req_header_end != rewritten.header_end ||
                        conn.req_body_remaining != 0 || !conn.request_body_fully_buffered ||
                        conn.req_body_streamed) {
                        loop->close_conn(conn);
                        return;
                    }
                    proof.rewritten_header_end = rewritten.header_end;
                    proof.rewritten_total_length = rewritten.total_length;
                    proof.expected_upload_length = rewritten.total_length;
                }
                request_policy_prepared = true;
            }
            // Response-policy metadata is carried independently from the request
            // policy. The strict serializer owns the response header bytes, so
            // reserve its slice before allocating a slot or connecting.
            const bool has_failure_policy = forward_failure_policy_id != 0;
            const bool has_timeout_failure_policy = forward_timeout_failure_policy_id != 0;
            bool response_policy_request_connection = false;
            if (forward_response_policy_id != 0 &&
                config->response_policy_id_is_valid(forward_response_policy_id)) {
                response_policy_request_connection =
                    config->response_policies[forward_response_policy_id - 1].connection ==
                    ResponsePolicyConnection::Request;
            }
            if ((forward_response_policy_id != 0 || has_failure_policy) &&
                ((forward_response_policy_id != 0 &&
                  !config->response_policy_id_is_valid(forward_response_policy_id)) ||
                 (has_failure_policy &&
                  !config->failure_policy_id_is_valid(forward_failure_policy_id)) ||
                 (has_timeout_failure_policy &&
                  !config->timeout_failure_policy_id_is_valid(forward_timeout_failure_policy_id)) ||
                 conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
                 (forward_response_policy_id != 0 && !response_policy_request_connection &&
                  !conn.req_keep_alive) ||
                 (!suppress_body_head && conn.req_method == static_cast<u8>(LogHttpMethod::Head)) ||
                 conn.tls_active || conn.req_path_canon.ptr == nullptr || conn.req_wants_upgrade ||
                 ((conn.req_body_mode != BodyMode::None || conn.request_body_fully_buffered) &&
                  !request_policy_body_response_admitted(conn)) ||
                 target.addr_count != 1 || target.addrs[0].sin_family != AF_INET ||
                 conn.resp_header_mutation_count != 0 ||
                 conn.resp_header_mutation_pending_count != 0 ||
                 conn.resp_header_mutation_pending_overflow ||
                 conn.resp_header_mutation_overflow)) {
                reject_response_policy(loop, conn);
                return;
            }
            if (forward_response_policy_id != 0 &&
                !response_policy_runtime_supported(
                    config->response_policies[forward_response_policy_id - 1]) &&
                !suppress_body_head) {
                reject_response_policy(loop, conn);
                return;
            }
            if (forward_response_policy_id != 0) {
                if (!loop->alloc_response_header_buf(conn)) {
                    if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
                        loop->close_conn(conn);
                        return;
                    }
                    conn.resp_status = kStatusBadGateway;
                    format_static_response(conn, 502, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                conn.response_policy_id = forward_response_policy_id;
                conn.response_policy_suppress_body = suppress_body_head;
            }
            conn.failure_policy_id = forward_failure_policy_id;
            conn.timeout_failure_policy_id = forward_timeout_failure_policy_id;
            conn.failure_policy_suppress_body = suppress_failure_head;
            if (conn.resp_header_mutation_count != 0 && !loop->alloc_response_header_buf(conn)) {
                if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
                    loop->close_conn(conn);
                    return;
                }
                conn.resp_status = kStatusInternalServerError;
                format_static_response(conn, 500, /*keep_alive=*/false);
                conn.keep_alive = false;
                conn.transition_to_sending(&on_response_sent<Loop>);
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            conn.state = ConnState::Proxying;
            // Upstream concurrency cap — same as the direct RouteAction::Proxy
            // path (a `return forward(...)` JIT route must honor max_inflight too,
            // or JIT-implemented routes could exceed the backend's in-flight cap).
            // Shed with 503 before connecting; slot released on every exit via
            // close_conn's catch-all (or release_upstream_slot at body-done).
            if (target.max_inflight != 0) {
                bool acquired = true;
                if constexpr (requires { loop->upstream_acquire(outcome.upstream_id, 1u); }) {
                    acquired = loop->upstream_acquire(outcome.upstream_id, target.max_inflight);
                }
                if (!acquired) {
                    if (conn.failure_policy_suppress_body) {
                        loop->close_conn(conn);
                        return;
                    }
                    conn.resp_status = 503;
                    format_static_response(conn, 503, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                conn.upstream_slot_held = true;
                conn.upstream_slot_uid = outcome.upstream_id;
            }
            for (u32 i = 0; i < sizeof(conn.upstream_name) && i < target.name_len; i++)
                conn.upstream_name[i] = target.name[i];
            if (target.name_len < sizeof(conn.upstream_name))
                conn.upstream_name[target.name_len] = '\0';
            else
                conn.upstream_name[sizeof(conn.upstream_name) - 1] = '\0';
            if (conn.upstream_fd >= 0) {
                (void)detach_upstream_close(loop, conn);
                conn.upstream_idx = 0;
            }
            conn.upstream_idx = static_cast<u16>(outcome.upstream_id);
            conn.upstream_attempts = 1;  // initial attempt; on_upstream_connected retries
            conn.upstream_start_us = monotonic_us();
            conn.upstream_backend_idx = static_cast<u8>(kBackend);

            conn.request_policy_id = outcome.request_policy_id;
            if (conn.request_policy_id != 0 && !request_policy_prepared) {
                // The source compiler rejects these combinations. Keep the
                // runtime guard for direct-RIR/JIT callers so policy never
                // silently loses precedence against an in-place mutation.
                if (conn.req_path_overridden || conn.req_header_override_count != 0 ||
                    conn.req_header_override_overflow ||
                    !apply_request_policy(conn, target.addrs[kBackend], conn.request_policy_id)) {
                    reject_request_policy(loop, conn);
                    return;
                }
            }

            // Idle reuse (mirrors the direct RouteAction::Proxy path): borrow a live
            // pooled socket to this endpoint and skip the connect. Without this take
            // path, JIT forward(...) completions would deposit idle fds the pool never
            // hands back. On a miss, connect fresh.
            if constexpr (requires {
                              loop->reuse_idle_upstream(conn,
                                                        static_cast<u16>(outcome.upstream_id),
                                                        static_cast<u8>(kBackend));
                          }) {
                if (conn.response_read_deadline_state == ResponseReadDeadlineState::None &&
                    !conn.failure_policy_suppress_body &&
                    loop->reuse_idle_upstream(
                        conn, static_cast<u16>(outcome.upstream_id), static_cast<u8>(kBackend))) {
                    conn.upstream_reused = true;
                    if constexpr (requires {
                                      loop->timer.refresh(&conn, loop->upstream_timeout);
                                  }) {
                        loop->timer.refresh(&conn, loop->upstream_timeout);
                    }
                    on_upstream_connected<Loop>(static_cast<void*>(loop),
                                                conn,
                                                IoEvent{conn.id,
                                                        0,
                                                        0,
                                                        0,
                                                        IoEventType::UpstreamConnect,
                                                        0,
                                                        0,
                                                        conn.upstream_episode});
                    return;
                }
            }

            const i32 kUpstreamFd = UpstreamPool::create_socket();
            if (kUpstreamFd < 0) {
                if (conn.response_read_deadline_state == ResponseReadDeadlineState::Validated) {
                    loop->close_conn(conn);
                } else if (conn.failure_policy_id != 0) {
                    respond_upstream_connect_failure(loop, conn);
                } else {
                    conn.resp_status = kStatusBadGateway;
                    format_static_response(conn, 502, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                }
                return;
            }
            conn.upstream_fd = kUpstreamFd;
            conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
            if (!loop->submit_connect(
                    conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
                if (conn.response_read_deadline_state == ResponseReadDeadlineState::Validated) {
                    loop->close_conn(conn);
                } else if (conn.failure_policy_id != 0) {
                    respond_upstream_connect_failure(loop, conn);
                } else {
                    (void)detach_upstream_close(loop, conn);
                    conn.upstream_idx = 0;
                    conn.resp_status = kStatusBadGateway;
                    format_static_response(conn, 502, /*keep_alive=*/false);
                    conn.keep_alive = false;
                    conn.transition_to_sending(&on_response_sent<Loop>);
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                }
                return;
            }
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
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
    }
}

template <typename Loop>
void resume_jit_handler(Loop* loop, Connection& conn) {
    // HTTP/2 streams suspend/resume through their own path: the response is
    // serialized as frames (not an HTTP/1 byte stream) and the request bytes live
    // in the engine's pending_synth, not recv_buf. The connection-scoped timer
    // machinery is shared (a connection is either h1 or h2), so the drains funnel
    // both here; branch on protocol.
    if (conn.protocol == ConnProtocol::Http2) {
        h2_resume_jit_handler<Loop>(loop, conn);
        return;
    }
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
void on_upstream_connected(void* lp, Connection& conn, IoEvent ev);

// Maximum upstream connect attempts per request (initial + retries), capped by
// the upstream's backend count. Retrying here is safe regardless of HTTP method:
// the connect failed before any request bytes were sent upstream, so no
// non-idempotent side effect can have occurred.
inline constexpr u32 kMaxConnectAttempts = 3;

// On a failed upstream connect, try the next backend (round-robin) if the retry
// budget isn't exhausted. Closes the dead fd, opens a fresh socket, and submits
// a new connect routed back to on_upstream_connected. Returns true if a retry
// was submitted; false (budget/socket/submit exhausted) → caller answers 502.
template <typename Loop>
bool try_connect_next_backend(Loop* loop, Connection& conn) {
    const RouteConfig* config = conn.request_config;
    if (!config || conn.upstream_idx >= config->upstream_count) return false;
    const UpstreamTarget& target = config->upstreams[conn.upstream_idx];
    const u32 kBudget =
        target.addr_count < kMaxConnectAttempts ? target.addr_count : kMaxConnectAttempts;
    if (conn.upstream_attempts >= kBudget) return false;  // budget exhausted

    (void)detach_upstream_close(loop, conn);
    const i32 kFd = UpstreamPool::create_socket();
    if (kFd < 0) return false;
    conn.upstream_fd = kFd;
    conn.upstream_attempts++;
    conn.upstream_start_us = monotonic_us();
    conn.set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
    const u32 kBackend =
        select_backend(conn.upstream_idx, target.addr_count, conn.upstream_start_us);
    conn.upstream_backend_idx = static_cast<u8>(kBackend);
    if (loop->submit_connect(conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend])))
        return true;
    (void)detach_upstream_close(loop, conn);
    return false;
}

// Admit only the first bounded timeout-policy runtime slice: a complete,
// bodyless paired HEAD request has reached the strict upstream-header read and
// the one exact live upstream Recv has produced either no byte or only an
// authoritative retained incomplete prefix. Everything else keeps the
// explicit-policy zero-byte fail-close contract.
template <typename Loop>
inline bool try_prebuilt_strict_read_timeout(Loop* loop, Connection& conn) {
    if constexpr (!requires(Loop* candidate, Connection& c) {
                      candidate->begin_prebuilt_http1_response(
                          c, u8{}, Http1RequestBufferDisposition::ExistingPipeline, u32{});
                  }) {
        return false;
    } else {
        // Ordinary proxy timeout admission is strictly a zero-progress state.
        // The io_uring explicit-deadline extension may additionally consume a
        // private incomplete prefix, but only while this helper can prove the
        // authoritative retained owner itself.  There is deliberately no
        // caller-supplied flag capable of bypassing either proof.
        bool explicit_deadline_expiry = false;
        bool retained_positive_progress = false;
        if constexpr (requires(Loop* candidate, const Connection& c) {
                          Loop::kMaxConns;
                          candidate->conns[0];
                          candidate->response_read_deadline_identity_is_stable(c);
                          candidate->disarm_response_read_deadline(candidate->conns[0]);
                      }) {
            if (conn.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending &&
                conn.id < Loop::kMaxConns && &loop->conns[conn.id] == &conn &&
                conn.upstream_recv_armed && loop->response_read_deadline_identity_is_stable(conn)) {
                const bool no_progress = conn.upstream_recv_buf.len() == 0 &&
                                         conn.response_read_deadline_progress_generation == 0 &&
                                         conn.response_read_deadline_progress_episode == 0 &&
                                         conn.response_read_deadline_progress_bytes == 0 &&
                                         conn.upstream_start_us != 0;
                retained_positive_progress =
                    conn.upstream_recv_buf.len() != 0 &&
                    conn.response_read_deadline_progress_generation ==
                        conn.response_read_deadline_generation &&
                    conn.response_read_deadline_progress_episode == conn.upstream_episode &&
                    conn.response_read_deadline_progress_bytes == conn.upstream_recv_buf.len() &&
                    conn.upstream_start_us == 0;
                explicit_deadline_expiry = no_progress || retained_positive_progress;
            }
        }
        const bool ordinary_zero_progress =
            conn.response_read_deadline_state == ResponseReadDeadlineState::None &&
            conn.upstream_recv_buf.len() == 0 &&
            conn.response_read_deadline_progress_generation == 0 &&
            conn.response_read_deadline_progress_episode == 0 &&
            conn.response_read_deadline_progress_bytes == 0 && conn.upstream_start_us != 0;
        if (!explicit_deadline_expiry && !ordinary_zero_progress) return false;

        const RouteConfig* config = conn.request_config;
        if (config == nullptr || conn.response_policy_id == 0 || conn.failure_policy_id == 0 ||
            conn.timeout_failure_policy_id == 0 ||
            !config->response_policy_id_is_valid(conn.response_policy_id) ||
            !config->failure_policy_id_is_valid(conn.failure_policy_id) ||
            !config->timeout_failure_policy_id_is_valid(conn.timeout_failure_policy_id))
            return false;

        const auto& response = config->response_policies[conn.response_policy_id - 1];
        const auto& failure = config->failure_policies[conn.failure_policy_id - 1];
        const auto& timeout = config->failure_policies[conn.timeout_failure_policy_id - 1];
        const ResponseReadDeadlineProfile profile =
            explicit_deadline_expiry ? conn.response_read_deadline_profile
                                     : ResponseReadDeadlineProfile::HeaderOnlyHead;
        const bool suppress_body = profile == ResponseReadDeadlineProfile::HeaderOnlyHead;
        const bool profile_modes_match =
            suppress_body
                ? response.head_mode == ResponsePolicyHeadMode::SuppressBody &&
                      failure.head_mode == FailurePolicyHeadMode::SuppressBody &&
                      timeout.head_mode == FailurePolicyHeadMode::SuppressBody &&
                      conn.response_policy_suppress_body && conn.failure_policy_suppress_body
                : (profile == ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
                   profile == ResponseReadDeadlineProfile::
                                  FixedContentLengthUploadNonHeadContentLengthZero) &&
                      response.head_mode == ResponsePolicyHeadMode::Reject &&
                      failure.head_mode == FailurePolicyHeadMode::Reject &&
                      timeout.head_mode == FailurePolicyHeadMode::Reject &&
                      !conn.response_policy_suppress_body && !conn.failure_policy_suppress_body;
        if (response.version != ResponsePolicyVersion::Http11 ||
            response.framing != ResponsePolicyFraming::ContentLength ||
            response.connection != ResponsePolicyConnection::Request ||
            failure.version != ForwardFailurePolicyVersion::Http11 ||
            failure.status_code != kStatusBadGateway ||
            failure.connection != ForwardFailurePolicyConnection::Request ||
            timeout.version != ForwardFailurePolicyVersion::Http11 ||
            timeout.connection != ForwardFailurePolicyConnection::Request || !profile_modes_match)
            return false;

        // The original request bytes were removed after the complete upload, so
        // use the pinned admission latch plus captured request facts instead of
        // re-running response_policy_suppress_head_admitted against recv_buf.
        const bool fixed_upload =
            profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
        if (conn.protocol != ConnProtocol::Http11 || conn.tls_active ||
            conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
            ((profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
              conn.req_method != static_cast<u8>(LogHttpMethod::Head)) ||
             (profile == ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
              (!response_read_deadline_non_head_method_admitted(conn.req_method) ||
               conn.response_read_deadline_method != conn.req_method ||
               !response_read_deadline_route_method_matches(
                   conn.response_read_deadline_method,
                   conn.response_read_deadline_route_method))) ||
             (fixed_upload &&
              (!response_read_deadline_fixed_upload_method_admitted(conn.req_method) ||
               conn.response_read_deadline_method != conn.req_method ||
               !response_read_deadline_fixed_upload_proof_is_stable(
                   conn, conn.response_read_deadline_upload)))) ||
            !conn.keep_alive || !conn.req_keep_alive || !conn.req_client_keep_alive ||
            conn.req_client_connection_close || conn.req_client_connection_close_exact ||
            conn.req_client_connection_count != 0 ||
            (!fixed_upload && conn.req_client_has_content_length) ||
            conn.req_client_has_transfer_encoding || conn.req_client_has_te ||
            conn.req_client_has_expect || conn.req_client_has_upgrade_header ||
            conn.req_malformed || conn.req_wants_upgrade || conn.req_path_canon.ptr == nullptr ||
            (fixed_upload ? conn.req_body_mode != BodyMode::ContentLength ||
                                conn.req_body_remaining != 0 || !conn.request_body_fully_buffered
                          : conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
                                conn.request_body_fully_buffered) ||
            conn.req_body_streamed || conn.req_header_override_count != 0 ||
            conn.req_header_override_overflow || conn.resp_header_mutation_count != 0 ||
            conn.resp_header_mutation_pending_count != 0 ||
            conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow)
            return false;

        if (conn.state != ConnState::Proxying || conn.req_start_us == 0 || conn.epoch_held ||
            loop->is_draining() || conn.is_health_probe || conn.pending_handler_fn != nullptr ||
            conn.yield_armed || conn.yield_timeout_armed || conn.throttle_paused ||
            conn.upstream_abandoned || conn.upstream_reused || !conn.request_upload_complete ||
            conn.upstream_request_incomplete || conn.proxy_resp_started || conn.resp_status != 0 ||
            conn.resp_body_mode != BodyMode::None || conn.resp_body_remaining != 0 ||
            conn.resp_body_sent != 0 || conn.upstream_send_len != 0 || conn.send_progress != 0 ||
            conn.send_armed || conn.on_send != nullptr || conn.on_recv != nullptr ||
            conn.response_header_buf.is_released() || !conn.response_header_buf.valid() ||
            conn.response_header_buf.len() != 0 || conn.upstream_fd < 0 ||
            !valid_upstream_episode(conn.upstream_episode) || conn.upstream_episode_quarantined ||
            !conn.upstream_recv_armed || conn.on_upstream_recv != &on_upstream_response<Loop> ||
            conn.upstream_connect_armed || conn.upstream_send_armed ||
            conn.on_upstream_send != nullptr || conn.retry_req_send_len != 0 ||
            (!fixed_upload && conn.response_mutations_snapshotted) || conn.pipeline_depth != 0 ||
            conn.recv_paused_for_send || conn.recv_pause_cancel_pending ||
            conn.recv_pause_rearm_pending || conn.upstream_recv_paused_for_send ||
            conn.upstream_recv_pause_cancel_pending || conn.upstream_recv_pause_rearm_pending ||
            conn.upstream_recv_cancel_inflight || conn.upstream_recv_terminal_stale ||
            conn.upstream_retirement_active || conn.upstream_retirement_target_owned != 0 ||
            conn.upstream_retirement_cancel_owned != 0 ||
            conn.upstream_retirement_cancel_retry != 0 || conn.upstream_close_episode != 0 ||
            conn.upstream_close_target_owned != 0 || conn.upstream_close_cancel_owned != 0 ||
            conn.upstream_close_pause_cancel_owned || conn.http1_boundary_deferred ||
            conn.http1_boundary_ready || conn.http1_boundary_successor_episode != 0 ||
            conn.http1_prebuilt_wait != 0 ||
            conn.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            conn.http1_prebuilt_request_prefix_len != 0 ||
            conn.pending_ops != static_cast<u32>(conn.recv_armed) + 1u ||
            loop->keepalive_timeout == 0 || loop->keepalive_timeout >= TimerWheel::kSlots)
            return false;

        if (conn.upstream_idx >= config->upstream_count) return false;
        const auto& target = config->upstreams[conn.upstream_idx];
        const bool exact_slot =
            target.max_inflight == 0
                ? !conn.upstream_slot_held
                : conn.upstream_slot_held && conn.upstream_slot_uid == conn.upstream_idx;
        if (!exact_slot) return false;

        u8 scratch[SlicePool::kSliceSize];
        u32 response_len = 0;
        if (!build_timeout_failure_policy_response(
                conn, *config, suppress_body, scratch, sizeof(scratch), &response_len) ||
            response_len == 0 || response_len > conn.response_header_buf.capacity())
            return false;

        HttpResponseParser timeout_parser;
        ParsedResponse timeout_response;
        timeout_parser.reset();
        timeout_response.reset();
        if (timeout_parser.parse(scratch, response_len, &timeout_response) !=
                ParseStatus::Complete ||
            timeout_response.version != HttpVersion::Http11 ||
            timeout_response.status_code != timeout.status_code ||
            timeout_response.content_length_count != 1 || timeout_response.chunked ||
            timeout_parser.header_end > response_len ||
            (suppress_body
                 ? timeout_parser.header_end != response_len
                 : timeout_response.content_length != response_len - timeout_parser.header_end))
            return false;

        // Capture the complete immutable response owner before removing the
        // live deadline.  D2 validates these fields again before publishing a
        // byte, independently of the header parser's transient views.
        if (explicit_deadline_expiry) {
            conn.http1_prebuilt_response_layout =
                suppress_body ? Http1PrebuiltResponseLayout::HeaderOnlyHead
                              : Http1PrebuiltResponseLayout::FullContentLengthNonHead;
            conn.http1_prebuilt_response_purpose =
                Http1PrebuiltResponsePurpose::ResponseReadTimeout;
            conn.http1_prebuilt_deadline_profile = profile;
            conn.http1_prebuilt_deadline_method = conn.response_read_deadline_method;
            conn.http1_prebuilt_deadline_route_method = conn.response_read_deadline_route_method;
            conn.http1_prebuilt_deadline_generation = conn.response_read_deadline_generation;
            conn.http1_prebuilt_deadline_bundle_id = conn.response_read_deadline_bundle_id;
            conn.http1_prebuilt_deadline_config = config;
            conn.http1_prebuilt_deadline_upload = conn.response_read_deadline_upload;
            conn.http1_prebuilt_header_end = timeout_parser.header_end;
            conn.http1_prebuilt_total_len = response_len;
            conn.http1_prebuilt_body_len = response_len - timeout_parser.header_end;
            conn.http1_prebuilt_status = timeout.status_code;
        }

        // All admission and response construction checks above are read-only.
        // Only now may an explicit-deadline expiry consume its private prefix
        // and retained proof before entering the existing D1/D2 path.
        if (explicit_deadline_expiry) {
            if (retained_positive_progress) conn.upstream_recv_buf.reset();
            loop->disarm_response_read_deadline(conn);
        }

        conn.response_header_buf.reset();
        if (conn.response_header_buf.write(scratch, response_len) != response_len) {
            loop->close_conn(conn);
            return true;
        }
        conn.resp_status = timeout.status_code;
        conn.resp_body_mode = BodyMode::None;
        conn.resp_body_remaining = 0;
        conn.resp_body_sent = suppress_body ? 0 : conn.http1_prebuilt_body_len;
        conn.upstream_send_len = 0;
        if (!loop->begin_prebuilt_http1_response(conn,
                                                 kUpstreamOpRecv,
                                                 Http1RequestBufferDisposition::ExistingPipeline,
                                                 conn.retry_req_send_len)) {
            if (conn.fd >= 0) loop->close_conn(conn);
            return true;
        }

        // This D2 originates from the wheel expiry itself, whose tick removed
        // the node before entering this helper. Bound a stuck HeaderSend or
        // retirement without changing the generic parser-error D2 timer policy.
        loop->timer.refresh(&conn, loop->keepalive_timeout);
        return true;
    }
}

// Handle a proxying connection past its upstream deadline (only while
// proxy_resp_started is false). Explicit timeout policy uses the bounded
// Recv-only D1/D2 path above; policy-free traffic retains the legacy 504.
template <typename Loop>
void respond_upstream_timeout(Loop* loop, Connection& conn) {
    // The additive timeout-policy metadata now has one bounded runtime caller:
    // Recv-only, read-before-bytes paired HEAD through D1/D2. Never silently
    // substitute the legacy hard-coded 504 (or the default 502) outside it:
    // unsupported explicit-policy phases close with zero downstream bytes.
    if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
        if (conn.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending &&
            conn.timeout_failure_policy_id != 0 && try_prebuilt_strict_read_timeout(loop, conn))
            return;
        if (conn.fd >= 0) loop->close_conn(conn);
        return;
    }
    if (conn.timeout_failure_policy_id != 0) {
        if (!try_prebuilt_strict_read_timeout(loop, conn) && conn.fd >= 0) loop->close_conn(conn);
        return;
    }
    // Paired timeout states outside the exact configured Recv-only slice can
    // still own connect/send or other unsupported transport phases. Let
    // close_conn's exact ledger drain them without publishing bytes.
    if (conn.failure_policy_suppress_body) {
        loop->close_conn(conn);
        return;
    }
    (void)detach_upstream_close(loop, conn);
    conn.upstream_abandoned = true;
    static const char k504[] =
        "HTTP/1.1 504 Gateway Timeout\r\n"
        "Content-Length: 15\r\n"
        "Connection: close\r\n"
        "\r\n"
        "Gateway Timeout";
    conn.send_buf.reset();
    conn.send_buf.write(reinterpret_cast<const u8*>(k504), sizeof(k504) - 1);
    conn.keep_alive = false;
    conn.resp_status = 504;
    conn.transition_to_sending(&on_response_sent<Loop>);
    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
}

// forward(set_path:) — rewrite the request-line path in recv_buf in place from
// conn.req_path_override before forwarding upstream. The path lives at the front
// of the request (inside the initial-forward chunk), so the buffered bytes after
// it (remaining headers + any buffered body) shift by the length delta, and both
// recv_buf's length and req_initial_send_len are adjusted to match. No-ops on a
// malformed request line or if the rewritten request would exceed the buffer.
inline bool rewrite_request_line_path(Connection& conn) {
    if (!conn.req_path_overridden || conn.req_path_override.ptr == nullptr) return true;
    u8* buf = conn.recv_slice;
    const u32 total = conn.recv_buf.len();
    if (buf == nullptr || total == 0) return false;
    // Request line: METHOD SP PATH SP VERSION CRLF — locate the two spaces.
    u32 i = 0;
    while (i < total && buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\n') i++;
    if (i >= total || buf[i] != ' ') return false;
    const u32 path_start = i + 1;
    u32 j = path_start;
    while (j < total && buf[j] != ' ' && buf[j] != '\r' && buf[j] != '\n') j++;
    if (j >= total || buf[j] != ' ') return false;
    const u32 old_len = j - path_start;
    const u32 new_len = conn.req_path_override.len;
    if (new_len == 0) return false;
    const i64 delta = static_cast<i64>(new_len) - static_cast<i64>(old_len);
    if (delta > 0 && total + static_cast<u32>(delta) > conn.recv_buf.capacity()) return false;
    if (delta != 0) {
        __builtin_memmove(
            buf + (static_cast<i64>(j) + delta), buf + j, static_cast<size_t>(total - j));
    }
    __builtin_memcpy(buf + path_start, conn.req_path_override.ptr, new_len);
    conn.recv_buf.set_len(static_cast<u32>(static_cast<i64>(total) + delta));
    // The path sits at the front of the request, so every absolute offset past
    // it shifts by delta: the initial-forward length AND req_header_end (which
    // the ContentLength body-streaming path uses to locate later body bytes in
    // recv_buf — see on_*_request_body_recvd). Leaving req_header_end stale
    // would mis-frame a streaming POST body. req_path/req_path_canon become
    // stale views here but are not read after routing.
    if (delta != 0) {
        if (conn.req_initial_send_len > 0) {
            const i64 adj = static_cast<i64>(conn.req_initial_send_len) + delta;
            conn.req_initial_send_len = adj > 0 ? static_cast<u32>(adj) : 0;
        }
        const i64 he = static_cast<i64>(conn.req_header_end) + delta;
        conn.req_header_end = he > 0 ? static_cast<u32>(he) : 0;
    }
    return true;
}

// Apply forward(set_header:) overrides to the buffered request before forwarding.
// For each (name, value): replace the FIRST existing header line (case-insensitive)
// in place — or insert "Name: Value\r\n" before the blank-line terminator — then
// delete every further field with the same name, so a client that sent the header
// more than once can't smuggle its own value past the override. The header line is
// written directly into recv_buf (no fixed scratch limit), and recv_buf's length,
// req_header_end, and req_initial_send_len are adjusted by each edit's delta — the
// same in-place mechanics as rewrite_request_line_path. Returns false if any
// override can't fit recv_buf (so the caller fails the request closed rather than
// forwarding it with a security-sensitive override silently dropped); true on a
// no-op or full success.
inline bool apply_request_header_overrides(Connection& conn) {
    if (conn.req_header_override_count == 0 && !conn.req_header_override_overflow) return true;
    // More overrides were requested than the table holds (direct-RIR only): a
    // dropped override must not be forwarded as a silent no-op — fail closed.
    if (conn.req_header_override_overflow) return false;
    u8* buf = conn.recv_slice;
    if (buf == nullptr) return false;  // overrides recorded but no buffer → fail closed

    // In-place splice: replace buf[pos, pos+old_span) with "Name: Value\r\n"
    // (write_line) or with nothing (deletion of a duplicate). Adjusts the buffer
    // length, req_header_end and req_initial_send_len by the delta. Returns false
    // — leaving the buffer untouched — only when a grow would exceed capacity.
    auto splice =
        [&](u32 pos, u32 old_span, const Str& name, const Str& val, bool write_line) -> bool {
        const u32 total = conn.recv_buf.len();
        const u32 ins_len = write_line ? name.len + 2 + val.len + 2 : 0;  // ": " + CRLF
        const i64 delta = static_cast<i64>(ins_len) - static_cast<i64>(old_span);
        if (delta > 0 && total + static_cast<u32>(delta) > conn.recv_buf.capacity()) return false;
        const u32 tail_src = pos + old_span;
        if (delta != 0)
            __builtin_memmove(buf + (static_cast<i64>(tail_src) + delta),
                              buf + tail_src,
                              static_cast<size_t>(total - tail_src));
        if (write_line) {
            u32 p = pos;
            for (u32 i = 0; i < name.len; i++) buf[p++] = static_cast<u8>(name.ptr[i]);
            buf[p++] = ':';
            buf[p++] = ' ';
            for (u32 i = 0; i < val.len; i++) buf[p++] = static_cast<u8>(val.ptr[i]);
            buf[p++] = '\r';
            buf[p++] = '\n';
        }
        conn.recv_buf.set_len(static_cast<u32>(static_cast<i64>(total) + delta));
        if (delta != 0) {
            const i64 he = static_cast<i64>(conn.req_header_end) + delta;
            conn.req_header_end = he > 0 ? static_cast<u32>(he) : 0;
            if (conn.req_initial_send_len > pos) {
                const i64 adj = static_cast<i64>(conn.req_initial_send_len) + delta;
                conn.req_initial_send_len = adj > 0 ? static_cast<u32>(adj) : 0;
            }
        }
        return true;
    };

    // Find the first header field named `name` (case-insensitive) at or after `from`
    // within the live header block; on success sets [*fs,*fe) (fe just past its LF).
    auto find_field = [&](const Str& name, u32 from, u32* fs, u32* fe) -> bool {
        const u32 total = conn.recv_buf.len();
        const u32 hend = conn.req_header_end;
        if (hend < 4 || hend > total) return false;
        u32 hstart = 0;
        while (hstart < hend && buf[hstart] != '\n') hstart++;  // past the request line
        if (hstart >= hend) return false;
        hstart++;
        const u32 hbody = hend - 2;  // header fields occupy [hstart, hbody)
        for (u32 i = from < hstart ? hstart : from; i < hbody;) {
            const u32 ls = i;
            u32 colon = ls;
            while (colon < hbody && buf[colon] != ':' && buf[colon] != '\n') colon++;
            u32 le = ls;
            while (le < hbody && buf[le] != '\n') le++;
            le = le < hbody ? le + 1 : hbody;  // include LF
            if (colon < hbody && buf[colon] == ':' &&
                http_header_name_eq_ci(
                    reinterpret_cast<const char*>(buf + ls), colon - ls, name.ptr, name.len)) {
                *fs = ls;
                *fe = le;
                return true;
            }
            i = le;
        }
        return false;
    };

    // Bytes that lie inside recv_buf's storage. A recorded value (or name) pointing
    // here — e.g. a request-derived value recorded straight through RIR — would be
    // shifted/overwritten by the in-place rewrite below before it's serialized, so
    // we can't apply it safely and must fail closed rather than forward a corrupted
    // header. (DSL set_header values are string literals in stable JIT constant
    // memory, so they never alias recv_buf and this never trips for compiled .rut.)
    const uintptr_t kBufLo = reinterpret_cast<uintptr_t>(buf);
    const uintptr_t kBufHi = kBufLo + conn.recv_buf.capacity();
    auto aliases_recv_buf = [&](const Str& s) {
        if (s.ptr == nullptr) return false;
        const uintptr_t p = reinterpret_cast<uintptr_t>(s.ptr);
        return p < kBufHi && p + s.len > kBufLo;
    };

    for (u32 oi = 0; oi < conn.req_header_override_count; oi++) {
        const Str name = conn.req_header_overrides[oi].name;
        const Str val = conn.req_header_overrides[oi].value;
        const bool append = (conn.req_header_append_mask & (1u << oi)) != 0;
        // Validate at the choke point before any byte reaches the wire. The DSL
        // parser already validates literals at compile time, but overrides recorded
        // directly through RIR are otherwise unchecked — an empty/non-tchar name, a
        // value carrying CR/LF or other control bytes (header injection), or a
        // reserved framing name (Content-Length/Transfer-Encoding/Connection) must
        // fail the request closed, never be forwarded.
        if (validate_response_header(name.ptr, name.len, val.ptr, val.len) !=
            HttpHeaderValidation::Ok)
            return false;
        if (aliases_recv_buf(name) || aliases_recv_buf(val)) return false;

        const u32 total = conn.recv_buf.len();
        const u32 hend = conn.req_header_end;
        // A configured override must be applied; if the request has no usable parsed
        // header block (e.g. a lenient request line that set no req_header_end) we
        // can't place it, so fail closed instead of forwarding without it.
        if (hend < 4 || hend > total) return false;

        const u32 line_len = name.len + 2 + val.len + 2;
        u32 fs = 0, fe = 0, search_from = 0;
        if (append) {
            const u32 hbody = conn.req_header_end - 2;
            if (!splice(hbody, 0, name, val, /*write_line=*/true)) return false;
            continue;
        }
        if (find_field(name, 0, &fs, &fe)) {
            if (!splice(fs, fe - fs, name, val, /*write_line=*/true)) return false;
            search_from = fs + line_len;  // skip the line we just wrote
        } else {
            const u32 hbody = conn.req_header_end - 2;  // insert before the blank line
            if (!splice(hbody, 0, name, val, /*write_line=*/true)) return false;
            search_from = hbody + line_len;
        }
        // Drop any remaining same-named fields (deletion never grows → never fails).
        while (find_field(name, search_from, &fs, &fe)) splice(fs, fe - fs, name, val, false);
    }
    return true;
}

#if RUT_ENABLE_WEBSOCKET
// Remove the `Sec-WebSocket-Extensions` request header (in place) before forwarding a
// terminate-route upgrade, so client and backend can't negotiate a per-message extension
// (permessage-deflate) the inspection engine can't read — its frames would carry RSV1 and
// be failed. Same in-place mechanics as rewrite_request_line_path: the header sits in the
// buffered request, so trailing bytes shift up and the forward length / header_end shrink.
inline void strip_ws_extensions(Connection& conn) {
    u8* buf = conn.recv_slice;
    if (buf == nullptr) return;
    static constexpr char kHdr[] = "sec-websocket-extensions:";
    static constexpr u32 kHdrLen = sizeof(kHdr) - 1;
    // Scan ONLY the parsed header block — never the coalesced post-upgrade frame bytes a
    // client may have packed after the request, and remove EVERY matching field (repeated
    // HTTP header fields are legal), so the backend can't still negotiate an extension.
    u32 limit = conn.req_header_end > 0 ? conn.req_header_end : conn.recv_buf.len();
    if (limit > conn.recv_buf.len()) limit = conn.recv_buf.len();
    u32 i = 0;
    while (i + kHdrLen <= limit) {  // i is always at a line start
        bool match = true;
        for (u32 j = 0; j < kHdrLen; j++) {
            u8 c = buf[i + j];
            if (c >= 'A' && c <= 'Z') c = static_cast<u8>(c - 'A' + 'a');
            if (c != static_cast<u8>(kHdr[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            const u32 total = conn.recv_buf.len();
            u32 line_end = i;
            while (line_end < total && buf[line_end] != '\n') line_end++;
            if (line_end < total) line_end++;  // include the LF
            const u32 removed = line_end - i;
            __builtin_memmove(buf + i, buf + line_end, static_cast<size_t>(total - line_end));
            conn.recv_buf.set_len(total - removed);
            limit -= removed;  // the header block shrank; the next line is now at i
            if (conn.req_initial_send_len > i) {
                conn.req_initial_send_len =
                    conn.req_initial_send_len > removed ? conn.req_initial_send_len - removed : 0;
            }
            if (conn.req_header_end > i) {
                conn.req_header_end =
                    conn.req_header_end > removed ? conn.req_header_end - removed : 0;
            }
            continue;  // re-check at i (the next field) for duplicates
        }
        while (i < limit && buf[i] != '\n') i++;  // skip to next line
        i++;
    }
}
#endif

// Preserve request-backed after-mutation values before forward(set_path:) and
// forward(set_header:) rewrite recv_buf in place. send_buf remains pinned until
// the response completes; on_upstream_request_sent later reserves this snapshot
// as the prefix used by pipeline_stash.
inline bool snapshot_response_mutations_before_request_rewrite(Connection& conn) {
    if (conn.resp_header_mutation_count == 0 || conn.retry_req_send_len != 0 ||
        conn.response_mutations_snapshotted)
        return true;
    if (conn.req_initial_send_len == 0 || conn.req_initial_send_len > conn.recv_buf.len() ||
        conn.req_initial_send_len > conn.send_buf.capacity())
        return false;
    const u8* old_base = conn.recv_buf.data();
    conn.send_buf.reset();
    if (conn.send_buf.write(old_base, conn.req_initial_send_len) != conn.req_initial_send_len)
        return false;
    conn.reanchor_response_mutations(old_base, conn.req_initial_send_len, conn.send_buf.data());
    conn.response_mutations_snapshotted = true;
    conn.retry_req_snapshot_replayable =
        !conn.req_path_overridden && conn.req_header_override_count == 0;
    return true;
}

// Materialize the foundation target-transform effect for the first supported
// domain.  This deliberately runs before target selection, policy materializa-
// tion, slot acquisition, idle reuse, and socket/connect side effects.  Every
// validation and size check happens before the first recv_buf mutation.
inline bool materialize_request_target_transform(Connection& conn, const RouteConfig& config) {
    if (!conn.target_transform_recorded) return true;
    if (!config.target_transform_id_is_valid(conn.target_transform_id) ||
        conn.protocol == ConnProtocol::Http2 || conn.tls_active || conn.req_path_overridden ||
        conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
        conn.req_method == static_cast<u8>(LogHttpMethod::Head) ||
        conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
        conn.request_body_fully_buffered || conn.req_malformed || conn.req_wants_upgrade ||
        conn.req_header_override_count != 0 || conn.req_header_override_overflow ||
        conn.resp_header_mutation_count != 0 || conn.resp_header_mutation_pending_count != 0 ||
        conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow)
        return false;

    u8* data = conn.recv_slice;
    const u32 total = conn.recv_buf.len();
    if (data == nullptr || conn.recv_buf.data() != data || total == 0) return false;

    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    if (parser.parse(data, total, &req) != ParseStatus::Complete ||
        req.version == HttpVersion::Unknown || req.has_content_length || req.chunked ||
        req.upgrade || req.has_upgrade_header || parser.header_end != conn.req_header_end ||
        conn.req_initial_send_len != parser.header_end)
        return false;
    auto header_name_eq = [](const Str& name, const char* literal, u32 literal_len) {
        if (name.len != literal_len) return false;
        for (u32 i = 0; i < name.len; i++) {
            u8 a = static_cast<u8>(name.ptr[i]);
            u8 b = static_cast<u8>(literal[i]);
            if (a >= 'A' && a <= 'Z') a = static_cast<u8>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = static_cast<u8>(b + ('a' - 'A'));
            if (a != b) return false;
        }
        return true;
    };
    for (u32 i = 0; i < req.header_count; i++) {
        const Str name = req.headers[i].name;
        if (header_name_eq(name, "transfer-encoding", 17) || header_name_eq(name, "te", 2) ||
            header_name_eq(name, "expect", 6))
            return false;
    }
    if (req.version != HttpVersion::Http11) return false;

    const uintptr_t base = reinterpret_cast<uintptr_t>(data);
    const uintptr_t limit = base + total;
    const uintptr_t path_addr = reinterpret_cast<uintptr_t>(req.path.ptr);
    if (path_addr < base || path_addr > limit || req.path.len > limit - path_addr) return false;
    const u32 target_start = static_cast<u32>(path_addr - base);
    const u32 target_len = req.path.len;
    if (target_len == 0 || data[target_start] != '/') return false;

    for (u32 i = 0; i < target_len; i++) {
        if (data[target_start + i] == '#') return false;
    }

    u32 path_len = target_len;
    for (u32 i = 0; i < target_len; i++) {
        if (data[target_start + i] == '?') {
            path_len = i;
            break;
        }
    }
    if (path_len == 0) return false;

    const u8* path = data + target_start;
    for (u32 i = 0; i < path_len; i++) {
        const u8 c = path[i];
        if (c < 0x21 || c == 0x7f || c == '%' || c == '#') return false;
        if (i > 0 && c == '/' && path[i - 1] == '/') return false;
    }
    u32 segment_start = 1;
    for (u32 i = 1; i <= path_len; i++) {
        if (i != path_len && path[i] != '/') continue;
        const u32 segment_len = i - segment_start;
        if ((segment_len == 1 && path[segment_start] == '.') ||
            (segment_len == 2 && path[segment_start] == '.' && path[segment_start + 1] == '.'))
            return false;
        segment_start = i + 1;
    }

    const auto& spec = config.target_transforms[conn.target_transform_id - 1];
    if (!forward_target_transform_spec_valid(spec) || path_len < spec.strip_prefix.len ||
        __builtin_memcmp(path, spec.strip_prefix.ptr, spec.strip_prefix.len) != 0)
        return false;

    const u32 suffix_len = path_len - spec.strip_prefix.len;
    const u32 query_len = target_len - path_len;
    const u64 new_target_len = static_cast<u64>(spec.replace_prefix.len) + suffix_len + query_len;
    const i64 delta = static_cast<i64>(new_target_len) - static_cast<i64>(target_len);
    const i64 final_total = static_cast<i64>(total) + delta;
    if (new_target_len > 0xffffffffu || final_total < 0 ||
        static_cast<u64>(final_total) > conn.recv_buf.capacity())
        return false;

    const u32 target_end = target_start + target_len;
    const u32 new_target_end = target_start + static_cast<u32>(new_target_len);
    const u32 suffix_start = target_start + spec.strip_prefix.len;
    const u32 suffix_dest = target_start + spec.replace_prefix.len;
    if (delta < 0) {
        __builtin_memmove(data + suffix_dest, data + suffix_start, suffix_len + query_len);
        __builtin_memmove(
            data + new_target_end, data + target_end, static_cast<size_t>(total - target_end));
    } else {
        __builtin_memmove(
            data + target_end + delta, data + target_end, static_cast<size_t>(total - target_end));
        __builtin_memmove(data + suffix_dest, data + suffix_start, suffix_len + query_len);
    }
    __builtin_memcpy(data + target_start, spec.replace_prefix.ptr, spec.replace_prefix.len);
    conn.recv_buf.set_len(static_cast<u32>(final_total));
    conn.req_header_end = static_cast<u32>(static_cast<i64>(conn.req_header_end) + delta);
    conn.req_initial_send_len =
        static_cast<u32>(static_cast<i64>(conn.req_initial_send_len) + delta);
    if (conn.response_mutations_snapshotted) conn.retry_req_snapshot_replayable = false;
    conn.target_transform_recorded = false;
    conn.target_transform_id = 0;
    return true;
}

inline bool request_policy_name_eq(const u8* p, u32 n, const char* q, u32 qn) {
    if (n != qn) return false;
    for (u32 i = 0; i < n; i++) {
        u8 a = p[i];
        u8 b = static_cast<u8>(q[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<u8>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<u8>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

// Parse and validate the policy's framing before it can acquire an upstream
// slot. The existing HTTP parser intentionally accepts identical duplicate
// Content-Length fields; nginx's fixed policy does not, so count the raw fields
// here and fail closed. The request buffer remains untouched by this function.
inline RequestPolicyBodyState inspect_request_policy_body(const Connection& conn, u16 policy_id) {
    if (policy_id == 0 || !request_policy_is_supported(policy_id) ||
        conn.protocol == ConnProtocol::Http2 ||
        conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
        conn.recv_slice == nullptr || conn.send_slice == nullptr)
        return RequestPolicyBodyState::Invalid;
    const u8* data = conn.recv_buf.data();
    const u32 len = conn.recv_buf.len();
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    if (parser.parse(data, len, &req) != ParseStatus::Complete || req.path.ptr == nullptr ||
        req.path.len == 0 || req.path.ptr[0] != '/')
        return RequestPolicyBodyState::Invalid;

    const u8* end = data + parser.header_end;
    const u8* line_end = data;
    while (line_end + 1 < end && !(line_end[0] == '\r' && line_end[1] == '\n')) line_end++;
    if (line_end + 1 >= end) return RequestPolicyBodyState::Invalid;

    u32 cl_count = 0;
    bool has_te = false;
    bool has_expect = false;
    bool has_upgrade = false;
    const u8* hs = line_end + 2;
    const u8* header_end = end - 2;
    while (hs < header_end) {
        const u8* le = hs;
        while (le + 1 < end && !(le[0] == '\r' && le[1] == '\n')) le++;
        if (le + 1 >= end || le <= hs) return RequestPolicyBodyState::Invalid;
        const u8* colon = hs;
        while (colon < le && *colon != ':') colon++;
        if (colon == hs || colon == le) return RequestPolicyBodyState::Invalid;
        const u32 name_len = static_cast<u32>(colon - hs);
        if (request_policy_name_eq(hs, name_len, "content-length", 14)) cl_count++;
        if (request_policy_name_eq(hs, name_len, "transfer-encoding", 17))
            return RequestPolicyBodyState::Invalid;
        has_te |= request_policy_name_eq(hs, name_len, "te", 2);
        has_expect |= request_policy_name_eq(hs, name_len, "expect", 6);
        has_upgrade |= request_policy_name_eq(hs, name_len, "upgrade", 7);
        hs = le + 2;
    }
    if (conn.req_wants_upgrade || cl_count > 1) return RequestPolicyBodyState::Invalid;
    if (cl_count == 0) {
        if (conn.req_body_mode != BodyMode::None) return RequestPolicyBodyState::Invalid;
        return RequestPolicyBodyState::Complete;
    }
    if (has_te || has_expect || has_upgrade) return RequestPolicyBodyState::Invalid;
    if (!req.has_content_length ||
        req.content_length > conn.recv_buf.capacity() - parser.header_end)
        return RequestPolicyBodyState::Invalid;
    const u64 required = static_cast<u64>(parser.header_end) + req.content_length;
    if (required > conn.recv_buf.capacity()) return RequestPolicyBodyState::Invalid;
    if (conn.recv_buf.len() < required) return RequestPolicyBodyState::Waiting;
    if (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining != 0)
        return RequestPolicyBodyState::Waiting;
    if (conn.req_body_mode != BodyMode::ContentLength && req.content_length != 0)
        return RequestPolicyBodyState::Invalid;
    return RequestPolicyBodyState::Complete;
}

// Validate and materialise the first explicit upstream request policy. This runs
// before slot acquisition and before a TCP connect, so unsupported input cannot
// accidentally fall back to transparent forwarding or touch the upstream.
inline bool apply_request_policy(Connection& conn, const sockaddr_in& endpoint, u16 policy_id) {
    if (policy_id == 0) return true;
    if (inspect_request_policy_body(conn, policy_id) != RequestPolicyBodyState::Complete)
        return false;

    const u8* data = conn.recv_buf.data();
    const u32 len = conn.recv_buf.len();
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    if (parser.parse(data, len, &req) != ParseStatus::Complete) return false;
    const u32 body_len = req.has_content_length ? req.content_length : 0;
    const u8* end = data + parser.header_end;
    const u8* line_end = data;
    while (line_end + 1 < end && !(line_end[0] == '\r' && line_end[1] == '\n')) line_end++;
    const u8* path_ptr = reinterpret_cast<const u8*>(req.path.ptr);
    if (line_end + 1 >= end || path_ptr < data || path_ptr + req.path.len > line_end) return false;

    auto append = [&](const u8* p, u32 n) {
        return n <= conn.send_buf.capacity() - conn.send_buf.len() &&
               conn.send_buf.write(p, n) == n;
    };
    auto append_lit = [&](const char* p, u32 n) {
        return append(reinterpret_cast<const u8*>(p), n);
    };
    auto append_dec = [&](u32 value) {
        char digits[10];
        u32 n = 0;
        do {
            digits[n++] = static_cast<char>('0' + value % 10);
            value /= 10;
        } while (value != 0);
        for (u32 i = n; i > 0; i--) {
            if (!append(reinterpret_cast<const u8*>(&digits[i - 1]), 1)) return false;
        }
        return true;
    };

    conn.send_buf.reset();
    const u32 method_prefix = static_cast<u32>(path_ptr - data);
    if (!append(data, method_prefix) || !append(path_ptr, req.path.len) || !append_lit(" ", 1) ||
        !append_lit(request_policy_version(policy_id), 8) || !append_lit("\r\n", 2))
        return false;

    char authority[32];
    u32 authority_len = 0;
    const u32 ip = ntohl(endpoint.sin_addr.s_addr);
    const u8 octets[4] = {static_cast<u8>(ip >> 24),
                          static_cast<u8>(ip >> 16),
                          static_cast<u8>(ip >> 8),
                          static_cast<u8>(ip)};
    for (u32 oi = 0; oi < 4; oi++) {
        if (oi != 0) authority[authority_len++] = '.';
        u32 v = octets[oi];
        char digits[3];
        u32 dn = 0;
        do {
            digits[dn++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        } while (v != 0);
        while (dn > 0) authority[authority_len++] = digits[--dn];
    }
    const u16 port = ntohs(endpoint.sin_port);
    if (port != 80) {
        authority[authority_len++] = ':';
        char digits[5];
        u32 dn = 0, v = port;
        do {
            digits[dn++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        } while (v != 0);
        while (dn > 0) authority[authority_len++] = digits[--dn];
    }
    if (!append_lit("Host: ", 6) ||
        !append(reinterpret_cast<const u8*>(authority), authority_len) || !append_lit("\r\n", 2))
        return false;

    const u8* hs = line_end + 2;
    const u8* header_end = end - 2;
    while (hs < header_end) {
        const u8* le = hs;
        while (le + 1 < end && !(le[0] == '\r' && le[1] == '\n')) le++;
        const u8* colon = hs;
        while (colon < le && *colon != ':') colon++;
        const u32 name_len = static_cast<u32>(colon - hs);
        const bool is_cl = request_policy_name_eq(hs, name_len, "content-length", 14);
        const bool drop = is_cl || request_policy_name_eq(hs, name_len, "host", 4) ||
                          request_policy_name_eq(hs, name_len, "connection", 10) ||
                          request_policy_name_eq(hs, name_len, "keep-alive", 10) ||
                          request_policy_name_eq(hs, name_len, "te", 2) ||
                          request_policy_name_eq(hs, name_len, "expect", 6) ||
                          request_policy_name_eq(hs, name_len, "upgrade", 7) ||
                          request_policy_name_eq(hs, name_len, "transfer-encoding", 17);
        if (is_cl) {
            if (!append_lit("Content-Length: ", 16) || !append_dec(body_len) ||
                !append_lit("\r\n", 2))
                return false;
        } else if (!drop) {
            const u8* value_start = colon + 1;
            while (value_start < le && (*value_start == ' ' || *value_start == '\t')) value_start++;
            const u8* value_end = le;
            while (value_end > value_start && (value_end[-1] == ' ' || value_end[-1] == '\t'))
                value_end--;
            if (!append(hs, name_len) || !append_lit(": ", 2) ||
                !append(value_start, static_cast<u32>(value_end - value_start)) ||
                !append_lit("\r\n", 2))
                return false;
        }
        hs = le + 2;
    }
    if (!append_lit("\r\n", 2)) return false;
    const u32 new_header_len = conn.send_buf.len();
    const u32 body_start = parser.header_end;
    const u64 request_end64 = static_cast<u64>(body_start) + body_len;
    if (request_end64 > len) return false;
    const u32 request_end = static_cast<u32>(request_end64);
    if (!append(data + body_start, body_len) || !append(data + request_end, len - request_end))
        return false;
    if (conn.send_buf.len() > conn.recv_buf.capacity()) return false;
    conn.recv_buf.reset();
    if (conn.recv_buf.write(conn.send_buf.data(), conn.send_buf.len()) != conn.send_buf.len())
        return false;
    conn.req_header_end = new_header_len;
    conn.req_initial_send_len = new_header_len + body_len;
    conn.req_size = conn.req_initial_send_len;
    conn.req_keep_alive = true;
    conn.request_policy_id = policy_id;
    conn.request_body_fully_buffered = req.has_content_length;
    conn.request_upload_complete = false;
    return true;
}

template <typename Loop>
inline void reject_request_policy(Loop* loop, Connection& conn) {
    release_upstream_slot(loop, conn);
    if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
        loop->close_conn(conn);
        return;
    }
    conn.resp_status = 400;
    format_static_response(conn, 400, /*keep_alive=*/false);
    conn.keep_alive = false;
    conn.transition_to_sending(&on_response_sent<Loop>);
    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
}

template <typename Loop>
inline void reject_response_policy(Loop* loop, Connection& conn) {
    release_upstream_slot(loop, conn);
    if (conn.response_read_deadline_state != ResponseReadDeadlineState::None) {
        loop->close_conn(conn);
        return;
    }
    conn.resp_status = 400;
    format_static_response(conn, 400, /*keep_alive=*/false);
    conn.keep_alive = false;
    conn.transition_to_sending(&on_response_sent<Loop>);
    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
}

// Keep a snapshotted request prefix pinned while pipeline_stash appends later
// downstream bytes. This is also required for streamed request bodies: their
// final chunk can contain the beginning of the next pipelined request.
inline void reserve_response_mutation_snapshot(Connection& conn) {
    if (conn.response_mutations_snapshotted && conn.retry_req_send_len == 0)
        conn.retry_req_send_len = conn.send_buf.len();
}

template <typename Loop>
void on_upstream_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    // Stale same-batch UpstreamSend guard (epoll). A dead reused upstream fd with a
    // partial send parked on EPOLLOUT can surface BOTH an UpstreamRecv EOF and an
    // UpstreamSend completion in ONE EpollBackend::wait() batch. The EOF dispatches
    // first and runs retry_reused_upstream, which closes the fd, clears
    // upstream_send_state, and swaps this slot to on_upstream_connected — but the
    // UpstreamSend was already emitted into that batch and dispatches AFTER, landing
    // in this (now-swapped) slot (UpstreamSend + UpstreamConnect share on_upstream_send).
    // on_upstream_connected only ever handles connect results — a request send is
    // submitted only AFTER the slot moves on to on_upstream_request_sent — so any
    // UpstreamSend reaching here is that stale pre-retry completion for the old fd.
    // Drop it. The real connect for the fresh fd arrives as an UpstreamConnect in a
    // later batch (EINPROGRESS) or via pending_completions (immediate connect), so a
    // genuine connect result is never swallowed.
    if (ev.type == IoEventType::UpstreamSend) return;

    // A paired strict HEAD connect failure owns the downstream response after
    // abandoning and clearing the upstream episode.  Ignore only a late
    // connect event from that fully-cleared episode; fresh connects still have
    // a live fd or callback slot, and other protocols do not set this mode.
    if (ev.type == IoEventType::UpstreamConnect && conn.failure_policy_suppress_body &&
        conn.upstream_abandoned && conn.upstream_fd < 0 && conn.on_upstream_recv == nullptr &&
        conn.on_upstream_send == nullptr)
        return;

    if (ev.result < 0) {
        // Connect failed (e.g. ECONNREFUSED). Record the failure against this
        // backend (passive health → ejection past the threshold), then try the
        // next backend within the retry budget; only answer 502 once all
        // candidates are exhausted.
        record_backend_result(
            conn.upstream_idx, conn.upstream_backend_idx, /*success=*/false, monotonic_us());
        if (conn.response_read_deadline_state == ResponseReadDeadlineState::Validated) {
            loop->close_conn(conn);
            return;
        }
        if (try_connect_next_backend(loop, conn)) return;
        if (conn.failure_policy_id != 0) {
            respond_upstream_connect_failure(loop, conn);
        } else {
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
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
        }
        return;
    }

    // A fresh TCP connect succeeded — clear this backend's passive-health record.
    // Reused pooled sockets only prove health once they return a response.
    if (!conn.upstream_reused) {
        record_backend_result(
            conn.upstream_idx, conn.upstream_backend_idx, /*success=*/true, monotonic_us());
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
    // forward(set_path:) and forward(set_header:) mutate recv_buf in place. On
    // retry replay the request bytes live in send_buf, while recv_buf may already
    // hold the next pipelined request, so only rewrite the initial forward buffer.
    if (conn.retry_req_send_len == 0) {
        const bool mutations_snapshotted = snapshot_response_mutations_before_request_rewrite(conn);
        const bool path_rewritten = mutations_snapshotted && rewrite_request_line_path(conn);
        // forward(set_header:) — inject/replace request header lines (no-op unless
        // overrides were recorded). After the path rewrite so it reads the updated
        // req_header_end. Fail closed (500) if a configured override can't be applied
        // (oversized / no headroom) rather than forwarding the request with a
        // security-sensitive header silently dropped.
        if (!path_rewritten || !apply_request_header_overrides(conn)) {
            if (conn.failure_policy_suppress_body) {
                loop->close_conn(conn);
                return;
            }
            // The upstream connected but no request will be sent. Release it now so a
            // client that stalls reading the 500 can't pin an idle upstream fd /
            // concurrency slot until keepalive/timeout (close_conn would otherwise only
            // reap it once the downstream connection finally goes away).
            (void)detach_upstream_close(loop, conn);
            release_upstream_slot(loop, conn);
            static const char k500[] =
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Length: 21\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Internal Server Error";
            conn.send_buf.reset();
            conn.send_buf.write(reinterpret_cast<const u8*>(k500), sizeof(k500) - 1);
            conn.keep_alive = false;
            conn.resp_status = kStatusInternalServerError;
            conn.transition_to_sending(&on_response_sent<Loop>);
            client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
            return;
        }
    }
#if RUT_ENABLE_WEBSOCKET
    // Terminate routes must not let the backend negotiate a per-message extension.
    if (conn.is_ws_terminate_route && conn.req_wants_upgrade) strip_ws_extensions(conn);
#endif
    // Pick the request source. A retried fresh connect (after a reused socket died
    // post-send) has retry_req_send_len > 0: recv_buf was reset at request-sent, so
    // replay the snapshot stashed in send_buf. Otherwise this is the initial connect
    // and recv_buf still holds the request.
    const u8* req_src;
    u32 req_send_len;
    if (conn.retry_req_send_len > 0) {
        req_src = conn.send_buf.data();
        req_send_len = conn.retry_req_send_len;
    } else {
        req_src = conn.recv_buf.data();
        req_send_len =
            conn.req_initial_send_len > 0 ? conn.req_initial_send_len : conn.recv_buf.len();
        if (req_send_len > conn.recv_buf.len()) req_send_len = conn.recv_buf.len();
    }
    if (conn.response_read_deadline_profile ==
        ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero) {
        auto& proof = conn.response_read_deadline_upload;
        proof.upload_episode = conn.upstream_episode;
        if (conn.response_read_deadline_state != ResponseReadDeadlineState::Validated ||
            !valid_upstream_episode(proof.upload_episode) || conn.upstream_reused ||
            conn.upstream_attempts != 1 || conn.upstream_recv_buf.len() != 0 ||
            conn.upstream_recv_armed || conn.request_upload_complete ||
            req_src != conn.recv_buf.data() || req_send_len != proof.expected_upload_length ||
            req_send_len != conn.recv_buf.len() ||
            !response_read_deadline_fixed_upload_materialization_is_stable(
                conn, proof, /*require_upload_complete=*/false)) {
            loop->close_conn(conn);
            return;
        }
    }
    conn.set_slots(nullptr,
                   nullptr,
                   &on_early_upstream_recvd_send_inflight<Loop>,
                   &on_upstream_request_sent<Loop>);
    if (!loop->submit_send_upstream(conn, req_src, req_send_len)) {
        IoEvent synth = {
            conn.id, -EIO, 0, 0, IoEventType::UpstreamSend, 0, 0, conn.upstream_episode};
        on_upstream_request_sent<Loop>(lp, conn, synth);
    }
}

template <typename Loop>
void on_upstream_request_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const bool fixed_upload =
        conn.response_read_deadline_state == ResponseReadDeadlineState::Validated &&
        conn.response_read_deadline_profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
    if (fixed_upload) {
        const auto& proof = conn.response_read_deadline_upload;
        bool send_owner_stable = false;
        if constexpr (requires(Loop* candidate) { candidate->backend.upstream_send_state[0]; }) {
            const auto& send = loop->backend.upstream_send_state[conn.id];
            send_owner_stable = send.src == conn.recv_buf.data() && send.fd == conn.upstream_fd &&
                                send.offset == proof.expected_upload_length &&
                                send.remaining == 0 && send.type == IoEventType::UpstreamSend &&
                                send.upstream_episode == proof.upload_episode;
        }
        if (ev.type != IoEventType::UpstreamSend || ev.aux != 0 || ev.more != 0 ||
            ev.upstream_episode != proof.upload_episode ||
            ev.result != static_cast<i32>(proof.expected_upload_length) || !send_owner_stable ||
            conn.upstream_send_armed || conn.on_upstream_send != &on_upstream_request_sent<Loop> ||
            conn.request_upload_complete || conn.upstream_recv_buf.len() != 0 ||
            conn.upstream_recv_armed ||
            !response_read_deadline_fixed_upload_materialization_is_stable(
                conn, proof, /*require_upload_complete=*/false)) {
            conn.upstream_request_incomplete = true;
            loop->close_conn(conn);
            return;
        }
    }

    if (ev.result < 0) {
        // The request forward failed mid-write: the backend never received the
        // complete request. If an early response was buffered (below) and the
        // socket gets considered for pooling, this marks the upload as not
        // delivered so proxy_upstream_reusable refuses it. A successful retry
        // clears it again (the fresh attempt re-sends from scratch).
        conn.upstream_request_incomplete = true;
        conn.request_upload_complete = false;
        // The initial request snapshot may still have a zero-length reservation:
        // on the successful path that reservation is normally established below,
        // after the send completes. Every early-response recovery branch calls
        // prepare_early_response_state, which can pipeline-stash and reset send_buf,
        // so pin the snapshot prefix before entering any of those branches.
        reserve_response_mutation_snapshot(conn);
        if (conn.upstream_recv_buf.len() > 0) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            IoEvent synth = {conn.id,
                             static_cast<i32>(conn.upstream_recv_buf.len()),
                             0,
                             0,
                             IoEventType::UpstreamRecv,
                             0,
                             0,
                             conn.upstream_episode};
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
                    IoEvent synth = {conn.id,
                                     static_cast<i32>(nr),
                                     0,
                                     0,
                                     IoEventType::UpstreamRecv,
                                     0,
                                     0,
                                     conn.upstream_episode};
                    on_upstream_response<Loop>(lp, conn, synth);
                    return;
                }
            }
        }
        // No early upstream response was buffered or recoverable. A reused pooled
        // socket the backend reset before responding can retry on a fresh connect
        // (idempotent only) — checked here, after every early-response path, so a
        // buffered/in-flight response is never dropped in favor of a retry.
        if (retry_reused_upstream(loop, conn)) return;
        loop->close_conn(conn);
        return;
    }

    const bool kMoreReqBody =
        (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) ||
        (conn.req_body_mode == BodyMode::Chunked &&
         conn.req_chunk_parser.state != ChunkedParser::State::Complete);
    // Normal forwarding snapshots in on_upstream_connected, before overrides.
    // Keep this fallback for callers that submit an already-prepared request
    // directly (and fail closed if their request-backed values cannot be pinned).
    if (!snapshot_response_mutations_before_request_rewrite(conn)) {
        loop->close_conn(conn);
        return;
    }
    const bool response_mutation_snapshot = conn.response_mutations_snapshotted;
    if (kMoreReqBody) {
        // Body streaming begins here: recv_buf is reset and refilled with body
        // chunks, so the original headers+body are no longer replayable. Mark it so
        // request_fully_resendable refuses any later reused-socket retry.
        conn.req_body_streamed = true;
        conn.request_upload_complete = false;
        reserve_response_mutation_snapshot(conn);
        conn.recv_buf.reset();
        conn.set_slots(
            &on_request_body_recvd<Loop>, nullptr, &on_early_upstream_recvd<Loop>, nullptr);
        loop->submit_recv(conn);
        loop->submit_recv_upstream(conn);
        return;
    }

    // This callback represents completion of the entire initial upstream send
    // (header plus any already-buffered fixed body). Do not infer this from
    // req_body_remaining: that counter is advanced before asynchronous writes.
    conn.request_upload_complete = true;

    // FRESH (non-retry) send path: recv_buf still holds exactly the just-sent request
    // (plus any pipelined surplus after it). Stash that surplus, optionally snapshot
    // the request for a reused-socket retry, then release recv_buf.
    //
    // RETRY path (retry_req_send_len > 0): the request was just replayed from the
    // send_buf snapshot, so recv_buf did NOT hold it — recv_buf was empty when the
    // retry began. Any bytes in recv_buf now are the next request(s) the client
    // PIPELINED during the in-flight fresh connect/send, sitting at offset 0 (a clean
    // request boundary).
    // Running pipeline_stash here would mis-slice them at req_initial_send_len (the
    // ORIGINAL request's length, not a boundary in this buffer), and recv_buf.reset()
    // would drop them. So on the retry path we do NEITHER and preserve recv_buf intact:
    // pipeline_stash_len is already 0 (a snapshot is taken only when the original send
    // had no pipelined surplus), so the completion path dispatches recv_buf as the next
    // request (Case C: stash_len==0 && recv_buf.len()>0). This matches on_upstream_-
    // response's "recv_buf is NOT touched here" handling once a response byte arrives.
    if (conn.retry_req_send_len == 0) {
        // Snapshot the request for a reused pooled socket so the rare post-send dead-
        // socket case (origin FIN landing just after take_idle's MSG_PEEK probe) can
        // replay it on a fresh connect even after recv_buf is reset below. Do this
        // BEFORE pipeline_stash: when the client sent GET1+GET2 in the same read,
        // pipeline_stash needs send_buf for GET2, so send_buf is laid out as:
        //   [0, retry_req_send_len)                         retry copy of GET1
        //   [retry_req_send_len, + pipeline_stash_len)       pipelined suffix
        // Guarded on upstream_reused so a fresh non-reused connect doesn't re-copy.
        if (response_mutation_snapshot) {
            reserve_response_mutation_snapshot(conn);
        } else if (conn.upstream_reused && request_resendable_from_recv_buf(conn) &&
                   conn.recv_buf.len() <= conn.send_buf.capacity()) {
            conn.send_buf.reset();
            conn.send_buf.write(conn.recv_buf.data(), conn.req_initial_send_len);
            conn.retry_req_send_len = conn.req_initial_send_len;
            conn.retry_req_snapshot_replayable = true;
        }
        if (!pipeline_stash(conn)) {
            loop->close_conn(conn);
            return;
        }
        // recv_buf is released: pipelined downstream bytes read during the upstream wait
        // then land at offset 0 and flow through pipeline_recover, and the just-sent
        // request can never leak into the next request's parse.
        conn.recv_buf.reset();
    }
    conn.upstream_start_us = monotonic_us();
    conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
    if (conn.response_read_deadline_state == ResponseReadDeadlineState::Validated) {
        if (conn.upstream_recv_buf.len() != 0) {
            loop->close_conn(conn);
            return;
        }
        if constexpr (requires(Loop* candidate, Connection& c) {
                          candidate->arm_first_response_read_deadline(c);
                      }) {
            if (!loop->arm_first_response_read_deadline(conn)) loop->close_conn(conn);
        } else {
            loop->close_conn(conn);
        }
        return;
    }
    if (conn.upstream_recv_buf.len() > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(conn.upstream_recv_buf.len()),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
        on_upstream_response<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

// === HTTP/2 reverse proxy (buffered, one stream at a time) ===
//
// An h2 proxy stream is parked on the engine's async slot (h2_suspend_proxy),
// then driven here: connect upstream → send the synthesized h1 request (stashed
// in pending_synth) → accumulate the whole h1 response in upstream_recv_buf →
// re-encode it as h2 HEADERS+DATA on the stream. The h1 proxy streams response
// bytes raw; an h2 client needs frames, so we must buffer + re-frame. Bounded by
// the 16KB upstream_recv_buf (over-cap → 502). Deferred: chunked de-framing,
// streaming/large bodies with flow control, request bodies, backend failover.

// h2 response headers we must NOT forward: hop-by-hop / connection-specific
// (RFC 7540 §8.1.2.2) and content-length (http2_write_response re-derives it).
inline bool h2_drop_response_header(Str name) {
    const char* const kName = name.ptr;
    const u32 kLen = name.len;
    return http_header_name_eq_ci(kName, kLen, "connection", 10) ||
           http_header_name_eq_ci(kName, kLen, "keep-alive", 10) ||
           http_header_name_eq_ci(kName, kLen, "proxy-connection", 16) ||
           http_header_name_eq_ci(kName, kLen, "transfer-encoding", 17) ||
           http_header_name_eq_ci(kName, kLen, "te", 2) ||
           http_header_name_eq_ci(kName, kLen, "upgrade", 7) ||
           http_header_name_eq_ci(kName, kLen, "content-length", 14);
}

// Is `name` listed as a token in an upstream `Connection: a, b, c` header value?
// Such fields are connection-specific (hop-by-hop) and must not be forwarded to
// the HTTP/2 client (RFC 7230 §6.1 / RFC 7540 §8.1.2.2). Tokens are comma
// separated, case-insensitive, with optional surrounding whitespace.
inline bool h2_name_in_connection_tokens(Str connection_value, Str name) {
    const char* const kV = connection_value.ptr;
    const u32 kN = connection_value.len;
    u32 i = 0;
    while (i < kN) {
        while (i < kN && (kV[i] == ' ' || kV[i] == '\t' || kV[i] == ',')) i++;
        const u32 kStart = i;
        while (i < kN && kV[i] != ',') i++;
        u32 end = i;  // trim trailing whitespace
        while (end > kStart && (kV[end - 1] == ' ' || kV[end - 1] == '\t')) end--;
        if (end > kStart && http_header_name_eq_ci(kV + kStart, end - kStart, name.ptr, name.len))
            return true;
    }
    return false;
}

// Close the upstream side and release its resources (fd, concurrency slot,
// response buffer). Shared by the success and failure paths.
template <typename Loop>
void h2_proxy_teardown_upstream(Loop* loop, Connection& conn) {
    // Detach the upstream slots BEFORE closing: on io_uring a multishot recv may
    // still have an in-flight terminal CQE after close(). With on_upstream_recv
    // null + upstream_abandoned set, the dispatch's stale-CQE guard ignores it
    // (won't re-enter h2_on_upstream_response on the next stream, won't close the
    // now-reused connection on a negative terminal). See EventLoopCRTP::dispatch.
    conn.on_upstream_recv = nullptr;
    conn.on_upstream_send = nullptr;
    conn.upstream_abandoned = true;
    // Record which in-flight upstream SQEs still reference connection state, so the
    // NEXT episode waits for their CQEs to drain before reusing that state. The
    // multishot recv shares the (conn_id, UpstreamRecv) user_data with the next
    // episode's recv; the in-flight send still sources pending_synth. (Both are
    // io_uring-only: epoll's recv/send complete synchronously, so neither flag is
    // ever armed there.) close() doesn't cancel these SQEs — their CQEs still come.
    if (conn.upstream_recv_armed) conn.h2_proxy_recv_draining = true;
    if (conn.upstream_send_armed) conn.h2_proxy_synth_quarantined = true;
    (void)detach_upstream_close(loop, conn);
    // epoll-only: drop any partial upstream send still referencing pending_synth so
    // a later EPOLLOUT on a reused upstream fd can't ship overwritten bytes to the
    // next backend (io_uring uses the h2_proxy_synth_quarantined SQE-drain path).
    if constexpr (requires { loop->discard_upstream_send(conn); })
        loop->discard_upstream_send(conn);
    conn.upstream_recv_armed = false;
    conn.upstream_send_armed = false;
    release_upstream_slot(loop, conn);
    conn.upstream_recv_buf.reset();
}

// Flush a fully-serialized response (in `src`, length resp_len) for the suspended
// stream, clear the async slot, and resume reading frames once it drains
// (on_h2_sent sees async_stream == 0). `src` is copied into send_buf synchronously,
// so a caller-owned stack buffer is fine.
template <typename Loop>
void h2_proxy_flush(Loop* loop, Connection& conn, const u8* src, u32 resp_len) {
    h2_clear_async(*conn.h2);
    h2_async_epoch_leave(loop, conn);  // proxy episode done — release the config epoch
    if (resp_len == 0) {
        loop->close_conn(conn);
        return;
    }
    // The proxy left the connection idle on the keepalive wheel while upstream
    // I/O ran; refresh it so a client that stops reading the response can't strand
    // the connection with no timer to reap it.
    loop->timer.refresh(&conn, loop->keepalive_timeout);
    conn.send_progress = 0;
    conn.send_buf.reset();
    conn.send_buf.write(src, resp_len);
    conn.keep_alive = true;
    conn.transition_to_sending(&on_h2_sent<Loop>);
    loop->submit_send(conn, conn.send_buf.data(), conn.send_buf.len());
}

// Answer the suspended proxy stream with a synthetic status (502 upstream
// failure, 503 inflight cap) and tear down the upstream side.
template <typename Loop>
void h2_proxy_fail(Loop* loop, Connection& conn, u16 status) {
    Http2Conn* h2 = conn.h2;
    const u32 kStreamId = h2->async_stream;
    h2_proxy_teardown_upstream(loop, conn);
    // Serialize the status-only response into a local scratch, NOT pending_synth:
    // on io_uring a timeout can fire while the upstream request send is still in
    // flight, and that SQE still sources pending_synth — overwriting it here would
    // corrupt the bytes the backend is reading. A status-only HEADERS frame is
    // tiny, so a small stack buffer is ample.
    u8 scratch[256];
    H2Dispatch<Loop> d{loop, &conn, scratch, sizeof(scratch), 0, false};
    h2_emit_status(d, kStreamId, status);
    h2_proxy_flush(loop, conn, scratch, d.resp_len);
}

// The full h1 upstream response is buffered in upstream_recv_buf. Re-encode it as
// h2 (:status + forwarded headers as HEADERS, body as DATA) for the stream.
template <typename Loop>
void h2_proxy_finish(Loop* loop,
                     Connection& conn,
                     const ParsedResponse& resp,
                     u32 hdr_end,
                     u32 body_len,
                     bool is_head) {
    Http2Conn* h2 = conn.h2;
    const u32 kStreamId = h2->async_stream;
    // If the upstream sent MORE headers than HttpResponseParser can hold, a later
    // Connection field naming an earlier (dropped) header is invisible to the
    // hop-by-hop filter below — we can't safely strip connection-specific headers,
    // so fail the stream. Keyed off headers_truncated (not header_count, which
    // saturates at kMaxHeaders): an exactly-full 64-header response is fully stored
    // and forwarded normally. kMaxHeaders is generous, so truncation is rare.
    if (resp.headers_truncated) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    constexpr u32 kMaxForwardHeaders = kMaxHeaders + Connection::kMaxRespHeaderMutations;
    hpack::Header hdrs[kMaxForwardHeaders];
    u32 nhdrs = 0;
    for (u32 i = 0; i < resp.header_count && nhdrs < kMaxHeaders; i++) {
        const Str kName = resp.headers[i].name;
        // content-length is normally dropped (http2_write_response re-derives it
        // from the DATA body), but a HEAD response carries no DATA, so keep the
        // upstream's so the client learns the corresponding GET body size.
        if (http_header_name_eq_ci(kName.ptr, kName.len, "content-length", 14)) {
            if (!is_head) continue;
        } else if (h2_drop_response_header(kName)) {
            continue;
        }
        // Fields named by ANY upstream Connection header are hop-by-hop (RFC 7230
        // §6.1) — scan every Connection field, not just the first.
        bool nominated = false;
        for (u32 j = 0; j < resp.header_count && !nominated; j++) {
            if (http_header_name_eq_ci(
                    resp.headers[j].name.ptr, resp.headers[j].name.len, "connection", 10))
                nominated = h2_name_in_connection_tokens(resp.headers[j].value, kName);
        }
        if (nominated) continue;
        hdrs[nhdrs].name = kName;
        hdrs[nhdrs].value = resp.headers[i].value;
        nhdrs++;
    }
    if (conn.resp_header_mutation_overflow) {
        h2_proxy_fail(loop, conn, 500);
        return;
    }
    for (u32 mi = 0; mi < conn.resp_header_mutation_count; mi++) {
        // Superseded value-bearing entries may intentionally retain request-backed
        // views that were not stabilized. Do not dereference them after suspension;
        // Remove carries no value and must still be applied to the upstream fields.
        const auto& mutation = conn.resp_header_mutations[mi];
        if (mutation.mode != Connection::RespHeaderMutationMode::Remove &&
            !response_mutation_survives(conn, mi))
            continue;
        const bool remove = mutation.mode == Connection::RespHeaderMutationMode::Remove;
        if (validate_response_header(mutation.name.ptr,
                                     mutation.name.len,
                                     remove ? "" : mutation.value.ptr,
                                     remove ? 0 : mutation.value.len) != HttpHeaderValidation::Ok) {
            h2_proxy_fail(loop, conn, 500);
            return;
        }
        if (mutation.mode != Connection::RespHeaderMutationMode::Add) {
            for (u32 i = 0; i < nhdrs;) {
                if (!http_header_name_eq_ci(
                        hdrs[i].name.ptr, hdrs[i].name.len, mutation.name.ptr, mutation.name.len)) {
                    i++;
                    continue;
                }
                for (u32 move = i + 1; move < nhdrs; move++) hdrs[move - 1] = hdrs[move];
                nhdrs--;
            }
        }
        if (!remove && !h2_drop_response_header(mutation.name)) {
            if (nhdrs >= kMaxForwardHeaders) {
                h2_proxy_fail(loop, conn, 500);
                return;
            }
            hdrs[nhdrs].name = mutation.name;
            hdrs[nhdrs].value = mutation.value;
            nhdrs++;
        }
    }
    // body points into upstream_recv_buf, which h2_emit_response copies into the
    // DATA frame in pending_synth scratch — so serialize BEFORE teardown.
    const u8* body = conn.upstream_recv_buf.data() + hdr_end;
    H2Dispatch<Loop> d{loop, &conn, h2->pending_synth, Http2Conn::kBodySynthCap, 0, false};
    // A re-framed response too large for the scratch buffer (large body OR large
    // header block) must NOT close the whole connection (dropping unrelated
    // streams), nor be reported as a generic 500. Disable the 500 fallback and, on
    // overflow, answer just this stream with 502 Bad Gateway.
    h2_emit_response(
        d, kStreamId, resp.status_code, hdrs, nhdrs, body, body_len, /*allow_fallback=*/false);
    if (d.overflow || d.resp_len == 0) {
        d.resp_len = 0;
        d.overflow = false;
        h2_emit_status(d, kStreamId, 502);
    }
    h2_proxy_teardown_upstream(loop, conn);
    // Success path: the full upstream response already arrived, so the request
    // send long completed and pending_synth (d's buffer) is free to source from.
    h2_proxy_flush(loop, conn, h2->pending_synth, d.resp_len);
}

// Upstream response recv completion: accumulate in upstream_recv_buf until the
// full response is present (headers + content-length body, or close-delimited),
// then re-frame. Chunked and over-buffer responses fail closed (502).
template <typename Loop>
void h2_on_upstream_response(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    HttpResponseParser parser;
    ParsedResponse resp;
    resp.reset();
    parser.reset();
    ParseStatus ps =
        parser.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &resp);
    if (ps == ParseStatus::Error) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    if (ps == ParseStatus::Incomplete) {
        // Headers not complete yet: need more bytes, unless the peer closed or the
        // buffer is full (header block larger than we will buffer).
        if (ev.result <= 0 || conn.upstream_recv_buf.write_avail() == 0) {
            h2_proxy_fail(loop, conn, 502);
            return;
        }
        if (!loop->submit_recv_upstream(conn)) h2_proxy_fail(loop, conn, 502);
        return;
    }
    // Headers complete.
    const u32 kHdrEnd = parser.header_end;

    // 101 Switching Protocols means the backend upgraded — no final HTTP response
    // follows, and the h2 proxy can't tunnel an upgrade. Fail now (502) instead of
    // stalling until the upstream timeout (504).
    if (resp.status_code == 101) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    // Discard other 1xx informational responses (100 Continue, 103 Early Hints):
    // they carry no body and precede the final response. Drop the 1xx block and
    // re-parse the remainder (it may already be buffered), else the final response
    // would be reframed as the body of a :status 1xx (or stall waiting on it).
    // (101 is handled above; this range covers 100/102/103/...)
    if (resp.status_code >= 100 && resp.status_code < 200) {
        const u32 kRem = conn.upstream_recv_buf.len() - kHdrEnd;
        if (kRem > 0 && conn.upstream_recv_slice)
            __builtin_memmove(conn.upstream_recv_slice, conn.upstream_recv_slice + kHdrEnd, kRem);
        conn.upstream_recv_buf.reset();
        if (kRem > 0) {
            conn.upstream_recv_buf.commit(kRem);
            IoEvent synth{conn.id,
                          static_cast<i32>(kRem),
                          0,
                          0,
                          IoEventType::UpstreamRecv,
                          0,
                          0,
                          conn.upstream_episode};
            h2_on_upstream_response<Loop>(lp, conn, synth);
        } else if (!loop->submit_recv_upstream(conn)) {
            h2_proxy_fail(loop, conn, 502);
        }
        return;
    }

    // No-body responses carry no body regardless of content-length: 204/205/304,
    // and any response to a HEAD request (the synthesized request is in
    // pending_synth, still intact here). Reframe immediately instead of waiting on
    // a body a keep-alive upstream will never send.
    const bool kHeadReq = conn.h2->async_synth_len >= 4 && conn.h2->pending_synth[0] == 'H' &&
                          conn.h2->pending_synth[1] == 'E' && conn.h2->pending_synth[2] == 'A' &&
                          conn.h2->pending_synth[3] == 'D';
    if (resp.status_code == 204 || resp.status_code == 205 || resp.status_code == 304 || kHeadReq) {
        h2_proxy_finish(loop, conn, resp, kHdrEnd, 0, /*is_head=*/kHeadReq);
        return;
    }

    // Is the body fully buffered?
    const u32 kHaveBody = conn.upstream_recv_buf.len() - kHdrEnd;
    u32 body_len = 0;
    bool complete = false;
    if (resp.chunked) {
        h2_proxy_fail(loop, conn, 502);  // chunked de-framing: follow-up
        return;
    }
    if (resp.has_content_length) {
        if (kHaveBody >= resp.content_length) {
            body_len = resp.content_length;
            complete = true;
        } else if (ev.result <= 0) {
            h2_proxy_fail(loop, conn, 502);  // closed/errored before the declared body → truncated
            return;
        }
    } else if (ev.result == 0) {
        body_len = kHaveBody;  // close-delimited body, clean EOF
        complete = true;
    } else if (ev.result < 0) {
        // A reset / -ENOBUFS overflow must not be reframed as a successful partial
        // body (only a clean EOF terminates an until-close body).
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    if (!complete) {
        if (conn.upstream_recv_buf.write_avail() == 0) {
            h2_proxy_fail(loop, conn, 502);  // response exceeds buffer
            return;
        }
        if (!loop->submit_recv_upstream(conn)) h2_proxy_fail(loop, conn, 502);
        return;
    }
    h2_proxy_finish(loop, conn, resp, kHdrEnd, body_len, /*is_head=*/false);
}

// Upstream request fully sent → start reading the response.
template <typename Loop>
void h2_on_upstream_request_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result < 0) {
        // On epoll the backend can reply early (e.g. an error response) and close
        // before our request finishes draining, so the send completes negative even
        // though a complete response is already buffered. Reframe it — as the HTTP/1
        // proxy does — rather than masking it with a synthetic 502. An EOF-signalling
        // event (result 0) makes h2_on_upstream_response serve a complete response or
        // 502 a truncated one; it never re-arms a recv on the now-dead fd.
        if (conn.upstream_recv_buf.len() > 0) {
            conn.set_slots(nullptr, nullptr, &h2_on_upstream_response<Loop>, nullptr);
            IoEvent eof{conn.id, 0, 0, 0, IoEventType::UpstreamRecv, 0, 0, conn.upstream_episode};
            h2_on_upstream_response<Loop>(lp, conn, eof);
            return;
        }
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    // io_uring sends can complete short (full socket send buffer, large synthesized
    // header block). Treating a prefix as the whole request makes the backend stall
    // or parse a truncated request → the stream times out. Resubmit the remainder
    // until the full request is written, then read the response.
    Http2Conn* h2 = conn.h2;
    h2->async_synth_sent += static_cast<u32>(ev.result);
    if (h2->async_synth_sent < h2->async_synth_len) {
        // Slot is still h2_on_upstream_request_sent, so the next send CQE re-enters.
        if (!loop->submit_send_upstream(conn,
                                        h2->pending_synth + h2->async_synth_sent,
                                        h2->async_synth_len - h2->async_synth_sent))
            h2_proxy_fail(loop, conn, 502);
        return;
    }
    // Don't arm this episode's recv while a previous torn-down episode's multishot
    // recv terminal is still in flight: it shares the (conn_id, UpstreamRecv)
    // user_data, so installing on_upstream_response now would let that stale CQE be
    // delivered to this stream. The terminal almost always drained during the
    // connect+send above (it's accounted in dispatch, which clears the flag); if it
    // somehow hasn't, fail this stream rather than risk misrouting (502, very rare).
    if (conn.h2_proxy_recv_draining) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    conn.set_slots(nullptr, nullptr, &h2_on_upstream_response<Loop>, nullptr);
    // On epoll, EPOLLIN stayed armed while a partial request send drained, so an
    // upstream that replied early may already have bytes in upstream_recv_buf.
    // Process them now rather than only arming another recv (which could stall if
    // the backend sends nothing further).
    if (conn.upstream_recv_buf.len() > 0) {
        IoEvent synth{conn.id,
                      static_cast<i32>(conn.upstream_recv_buf.len()),
                      0,
                      0,
                      IoEventType::UpstreamRecv,
                      0,
                      0,
                      conn.upstream_episode};
        h2_on_upstream_response<Loop>(lp, conn, synth);
        return;
    }
    if (!loop->submit_recv_upstream(conn)) h2_proxy_fail(loop, conn, 502);
}

// Upstream TCP connect completion → send the synthesized h1 request.
template <typename Loop>
void h2_on_upstream_connected(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    Http2Conn* h2 = conn.h2;
    if (ev.result < 0) {
        record_backend_result(
            conn.upstream_idx, conn.upstream_backend_idx, /*success=*/false, monotonic_us());
        h2_proxy_fail(loop, conn, 502);  // backend failover over h2: follow-up
        return;
    }
    record_backend_result(
        conn.upstream_idx, conn.upstream_backend_idx, /*success=*/true, monotonic_us());
    if (!loop->alloc_upstream_buf(conn)) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    // Start the response buffer clean. A previous proxy on this connection may
    // have left stale bytes from a positive multishot recv CQE that landed after
    // its teardown reset; without this, the early-response path below would parse
    // them as this upstream's response. The old fd is long closed, so its CQEs
    // have drained by the time this fresh connect completes.
    conn.upstream_recv_buf.reset();
    // upstream_abandoned stays set: the new episode's recv carries its own handler,
    // so its CQEs are delivered regardless of the flag — the flag only suppresses
    // NULL-handler (stale) terminals, which is always what we want for an h2 proxy.
    // The h2_proxy_recv_draining guard (checked before arming the new recv in
    // h2_on_upstream_request_sent) is what prevents a stale terminal from being
    // misrouted to the new stream once its handler is installed.
    conn.set_slots(nullptr, nullptr, nullptr, &h2_on_upstream_request_sent<Loop>);
    h2->async_synth_sent = 0;  // track partial sends (h2_on_upstream_request_sent)
    // submit_send_upstream can fail to queue (io_uring SQE exhaustion); without a
    // completion the stream would park forever, so fail closed like a bad connect.
    if (!loop->submit_send_upstream(conn, h2->pending_synth, h2->async_synth_len))
        h2_proxy_fail(loop, conn, 502);
}

// Open the upstream connection for a proxy-suspended stream (called after the
// suspending batch flushes). Acquires an inflight slot, opens a socket, and
// connects; any failure answers the stream (502/503) instead of stalling.
template <typename Loop>
void h2_proxy_begin(Loop* loop, Connection& conn) {
    Http2Conn* h2 = conn.h2;
    const RouteConfig* cfg = h2->async_cfg;
    const u16 upstream_id = h2->async_upstream_id;
    if (cfg == nullptr || upstream_id >= cfg->upstream_count) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    // NOTE: upstream_abandoned stays true (set by the prior episode's teardown)
    // through the connect window — cleared only once the fresh upstream connects
    // (h2_on_upstream_connected). On io_uring a late negative terminal CQE from the
    // PREVIOUS upstream's multishot recv can still be in flight here; with the guard
    // up, the dispatch ignores it instead of spuriously closing this connection
    // before the new upstream has even connected. By the time the fresh connect
    // completes, the old fd's CQEs have drained (same reasoning as the recv-buf
    // reset in h2_on_upstream_connected).
    // Enter Proxying so the timer wheel uses the (shorter) upstream_timeout, not
    // keepalive: a backend that accepts then stalls is reaped on the configured
    // upstream deadline (the tick routes h2 conns to h2_proxy_fail(504)) instead
    // of holding the stream + inflight slot until keepalive. proxy_resp_started
    // stays false (h2 buffers the whole response before sending to the client).
    conn.state = ConnState::Proxying;
    conn.proxy_resp_started = false;
    // Refresh the wheel now so a CONNECT that hangs (never producing an
    // UpstreamConnect event to refresh it) is still reaped on upstream_timeout
    // rather than the much longer keepalive deadline it was last scheduled at.
    if constexpr (requires { loop->upstream_timeout; }) {
        loop->timer.refresh(&conn, loop->upstream_timeout);
    }
    const UpstreamTarget& target = cfg->upstreams[upstream_id];
    if (target.max_inflight != 0) {
        bool acquired = true;
        if constexpr (requires { loop->upstream_acquire(upstream_id, 1u); }) {
            acquired = loop->upstream_acquire(upstream_id, target.max_inflight);
        }
        if (!acquired) {
            h2_proxy_fail(loop, conn, 503);
            return;
        }
        conn.upstream_slot_held = true;
        conn.upstream_slot_uid = upstream_id;
    }
    const i32 kFd = UpstreamPool::create_socket();
    if (kFd < 0) {
        h2_proxy_fail(loop, conn, 502);
        return;
    }
    conn.upstream_fd = kFd;
    conn.upstream_idx = upstream_id;
    conn.upstream_attempts = 1;
    conn.upstream_start_us = monotonic_us();
    conn.set_slots(nullptr, nullptr, nullptr, &h2_on_upstream_connected<Loop>);
    const u32 kBackend = select_backend(upstream_id, target.addr_count, conn.upstream_start_us);
    conn.upstream_backend_idx = static_cast<u8>(kBackend);
    if (!loop->submit_connect(conn, &target.addrs[kBackend], sizeof(target.addrs[kBackend]))) {
        h2_proxy_fail(loop, conn, 502);  // h2_proxy_fail closes the fd we just opened
    }
}

template <typename Loop>
void on_response_header_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (conn.response_read_deadline_post_commit_phase !=
        ResponseReadDeadlinePostCommitPhase::None) {
        const bool send_owner_valid = [&]() {
            if constexpr (requires(
                              const Loop* candidate, const Connection& c, const IoEvent& event) {
                              candidate->response_read_deadline_send_completion_is_valid(
                                  c, event, ResponseReadDeadlineSendKind::Header);
                          }) {
                return loop->response_read_deadline_send_completion_is_valid(
                    conn, ev, ResponseReadDeadlineSendKind::Header);
            }
            return false;
        }();
        if (!send_owner_valid || ev.result <= 0 ||
            static_cast<u32>(ev.result) != conn.response_header_buf.len() ||
            conn.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::HeaderSend ||
            !response_read_deadline_post_commit_is_stable(conn) ||
            conn.response_read_deadline_post_commit_inflight_body != 0 ||
            conn.upstream_send_len != conn.response_read_deadline_post_commit_raw_header_end ||
            conn.upstream_recv_buf.len() < conn.upstream_send_len) {
            loop->close_conn(conn);
            return;
        }
        conn.clear_response_read_deadline_send_owner();
        (void)consume_upstream_sent(conn);
        conn.response_read_deadline_post_commit_phase =
            ResponseReadDeadlinePostCommitPhase::WaitingBody;
        if (conn.response_read_deadline_buffering ==
                ForwardResponseBufferingMode::CompleteContentLength &&
            conn.response_read_deadline_post_commit_close_after_drain &&
            conn.response_read_deadline_post_commit_send_body == 0) {
            loop->close_conn(conn);
            return;
        }
        if constexpr (requires(Loop* candidate, Connection& c) {
                          candidate->defer_response_read_deadline_body_pump(c);
                      }) {
            loop->defer_response_read_deadline_body_pump(conn);
        } else {
            loop->close_conn(conn);
        }
        return;
    }

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }
    if (conn.response_policy_id != 0 && !strict_response_upload_ready(conn)) {
        loop->close_conn(conn);
        return;
    }

    conn.set_slots(nullptr, nullptr, &on_response_body_recvd<Loop>, nullptr);
    const u32 kRemaining = consume_upstream_sent(conn);
    if (throttle_pause_before_pump(loop, conn, kRemaining)) return;
    if (kRemaining > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(kRemaining),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
        on_response_body_recvd<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

template <typename Loop>
void pump_response_read_deadline_body(Loop* loop, Connection& conn) {
    if (!response_read_deadline_post_commit_is_stable(conn) ||
        conn.response_read_deadline_post_commit_phase !=
            ResponseReadDeadlinePostCommitPhase::WaitingBody ||
        conn.response_read_deadline_post_commit_inflight_body != 0 || conn.send_armed) {
        loop->close_conn(conn);
        return;
    }
    const u32 received = conn.response_read_deadline_post_commit_origin_received;
    const u32 completed = conn.response_read_deadline_post_commit_downstream_completed;
    if (completed > received || conn.upstream_recv_buf.len() != received - completed) {
        loop->close_conn(conn);
        return;
    }
    const bool complete_buffering = conn.response_read_deadline_buffering ==
                                    ForwardResponseBufferingMode::CompleteContentLength;
    const u32 publish_body =
        complete_buffering ? conn.response_read_deadline_post_commit_send_body : received;
    if (publish_body > received || completed > publish_body) {
        loop->close_conn(conn);
        return;
    }
    const u32 available = publish_body - completed;
    if (available == 0) {
        if (complete_buffering && conn.response_read_deadline_post_commit_close_after_drain) {
            loop->close_conn(conn);
            return;
        }
        if (received == conn.response_read_deadline_post_commit_declared_body) {
            if constexpr (requires(Loop* candidate, Connection& c) {
                              candidate->retire_response_read_deadline_origin(c);
                          }) {
                if (!loop->retire_response_read_deadline_origin(conn)) {
                    loop->close_conn(conn);
                    return;
                }
            } else {
                loop->close_conn(conn);
                return;
            }
            // The post-commit Send owner is already tombstoned and the exact
            // origin episode is under strict retirement.  Detach the completed
            // Header/Body callbacks before proxy_stream_complete parks request
            // 2; otherwise the rendezvous correctly refuses to hand a fresh
            // request to a connection that still advertises an old Send owner.
            conn.clear_slots();
            proxy_stream_complete<Loop>(loop, conn);
        }
        return;
    }
    if (conn.response_read_deadline_post_commit_downstream_submitted != completed ||
        available > conn.resp_body_remaining) {
        loop->close_conn(conn);
        return;
    }
    conn.response_read_deadline_post_commit_downstream_submitted += available;
    conn.response_read_deadline_post_commit_inflight_body = available;
    conn.resp_body_remaining -= available;
    conn.resp_body_sent += available;
    conn.upstream_send_len = available;
    conn.response_read_deadline_post_commit_phase = ResponseReadDeadlinePostCommitPhase::BodySend;
    conn.transition_to_sending(&on_response_body_sent<Loop>);
    if (!client_send(loop, conn, conn.upstream_recv_buf.data(), available)) loop->close_conn(conn);
}

template <typename Loop>
void on_response_body_recvd(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        // -ENOBUFS is the backend's "recv buffer full, couldn't read" signal, not
        // a terminal error: it surfaces when a downstream send is still draining
        // the buffer (e.g. a throttled burst the client hasn't consumed yet) while
        // the level-triggered upstream fd reports more data. The event is built at
        // backend-recv time and may be processed after the buffer state changed, so
        // act on the *current* state: if the buffer is still full a downstream send
        // is draining it and on_response_body_sent is guaranteed to re-arm the
        // upstream recv — disarm now to avoid spinning on the level-triggered fd.
        // If the buffer already has space the event is stale (the send completed
        // and the pump already re-armed or @throttle-paused); leave that state
        // untouched so we neither undo a re-arm nor undo a pause.
        if (ev.result == -ENOBUFS) {
            // For an io_uring TLS proxy stream, -ENOBUFS means the backend already
            // discarded the uncopied suffix of an overflowing multishot CQE (it
            // copies min(nbytes, avail) and reports -ENOBUFS — see io_uring_backend).
            // Those upstream body bytes are gone and can never be replayed, so any
            // tls_proxy_stream overflow must fail closed — not only the parked-tail
            // case. A single wait() batch harvests the whole CQE burst before the
            // first callback drains the buffer, so the 16 KiB upstream_recv_buf can
            // overflow even when no tail is parked (tls_send_src == nullptr).
            if (conn.tls_proxy_stream) {
                loop->close_conn(conn);
                return;
            }
            // Plaintext path. On epoll the bytes remain on the level-triggered fd
            // and are re-read after the pause, which can't fail (returns true), so
            // this is a benign pause-on-full. On io_uring the pause is an async
            // cancel that can fail under SQ pressure — and a still-live provided-
            // buffer multishot keeps discarding overflow bytes (truncation), so fail
            // closed there. (uses_iouring_tls is false here; the gate is io_uring-vs-
            // epoll, expressed via the nodiscard'd pause returning false only on io_uring.)
            if (conn.upstream_recv_buf.write_avail() == 0 && !loop->pause_upstream_recv(conn))
                loop->close_conn(conn);
            return;
        }
        // io_uring TLS: the body may be fully buffered and still draining to the
        // client (the multishot upstream recv was cancelled, but an EOF CQE can
        // already be queued, or the backend closes right after the response).
        // Closing now would truncate ciphertext still in tls_out_buf — let the
        // drain complete the request.
        if (conn.resp_fully_buffered) return;
        if (conn.resp_body_mode == BodyMode::UntilClose) {
            if (conn.uses_iouring_tls()) {
                // Close-delimited: EOF is the body terminator, so the downstream
                // HTTP/1.1 response must also end by closing — force a
                // non-keepalive completion. Any ciphertext still in tls_out_buf
                // must flush first, so mark complete-on-drain (complete now only if
                // nothing is buffered).
                conn.keep_alive = false;
                conn.tls_proxy_stream = true;
                conn.resp_fully_buffered = true;
                if (!conn.tls_out_inflight && conn.tls_out_buf.len() == 0)
                    proxy_stream_complete<Loop>(loop, conn);
                return;
            }
            on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
            loop->epoch_leave();
            loop->close_conn(conn);
            return;
        }
        // A parked TLS proxy tail still owns the final body bytes: the body parser
        // already completed (resp_body_remaining hit 0 / chunk parser Complete
        // before tls_fill_output parked the unencrypted remainder), but
        // resp_fully_buffered isn't set until proxy_tls_parked_drained finishes it.
        // A racing upstream EOF in that window must not drop the draining
        // ciphertext — it is complete-on-drain, so ignore it. (A tail parked
        // mid-body — body NOT complete — is a genuine upstream truncation, so fall
        // through to close.)
        if (conn.tls_proxy_stream && conn.tls_send_src && proxy_body_complete(conn)) return;
        loop->close_conn(conn);
        return;
    }

    // A TLS proxy tail is parked at the front of upstream_recv_buf (tls_send_src),
    // and the multishot recv may have raced a positive CQE in behind it before
    // pause_upstream_recv's cancel landed. Defer: re-running tls_fill_output over
    // upstream_recv_buf.data() now would re-encrypt the parked tail (the drain path
    // still owns it via tls_send_src/off) and double-count the body. The parked
    // drain replays these appended bytes once the remainder finishes
    // (proxy_tls_parked_drained → consume_upstream_sent → synthetic recv).
    if (conn.tls_proxy_stream && conn.tls_send_src) return;

    const u32 kDataLen = conn.upstream_recv_buf.len();
    if (conn.response_policy_id != 0 && conn.resp_body_mode == BodyMode::ContentLength &&
        kDataLen > conn.resp_body_remaining) {
        // The strict profile cannot safely recover from bytes beyond its exact
        // framing. Once headers are committed, close both legs rather than pool
        // or expose a desynchronized downstream stream.
        loop->close_conn(conn);
        return;
    }
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

    // Proxy-over-TLS on io_uring: encrypt this body chunk straight into the owned
    // tls_out_buf (read/drain decoupled — no client_send / on_response_body_sent
    // round-trip). The request completes from tls_on_out_drain once the buffer
    // empties with resp_fully_buffered set. The `if constexpr` compiles this only
    // for loops with the io_uring-TLS send interface (Epoll terminates TLS inside
    // the backend and never reaches here with uses_iouring_tls()).
    if constexpr (requires(Loop* l, Connection& cc) {
                      l->submit_send_raw(cc, static_cast<const u8*>(nullptr), 0u);
                      Loop::kTlsDrainChunk;
                  }) {
        if (conn.uses_iouring_tls()) {
            conn.tls_proxy_stream = true;
            u32 enc = 0;
            const TlsFill kFill =
                tls_fill_output<Loop>(loop, conn, conn.upstream_recv_buf.data(), send_len, enc);
            if (kFill == TlsFill::Fatal) {
                loop->close_conn(conn);
                return;
            }
            if (kFill != TlsFill::Done) {
                // NeedRoom (buffer filled mid-chunk) or NeedRead (SSL_write needs
                // peer input, e.g. a TLS 1.3 KeyUpdate during the response). Park
                // the unencrypted tail and pause the upstream read; the drain (and,
                // for NeedRead, the next client recv) re-encrypt it via
                // proxy_tls_parked_drained rather than truncating the download.
                conn.resp_body_sent += enc;
                throttle_advance(conn, enc);
                conn.upstream_send_len = enc;
                consume_upstream_sent(conn);  // shift past encrypted; tail now at front
                conn.tls_send_src = conn.upstream_recv_buf.data();
                conn.tls_send_len = send_len - enc;
                conn.tls_send_off = 0;
                // Cancel the multishot recv; the cancel SQE can fail to queue under
                // SQ pressure, leaving it live — fail closed rather than overflow.
                if (!loop->pause_upstream_recv(conn)) {
                    loop->close_conn(conn);
                    return;
                }
                if (kFill == TlsFill::NeedRead) {
                    conn.tls_pending_on_recv = &tls_resume_pending_send_recv<Loop>;
                    if (!conn.recv_armed && !loop->submit_recv(conn)) loop->close_conn(conn);
                }
                return;
            }
            conn.resp_body_sent += enc;  // enc == send_len on Done
            throttle_advance(conn, enc);
            const bool kBodyDone = proxy_body_complete(conn);
            conn.upstream_send_len = enc;
            const u32 kRemaining = consume_upstream_sent(conn);  // shift past encrypted chunk
            if (kBodyDone) {
                conn.resp_fully_buffered = true;  // completes when tls_out_buf drains
                if (!loop->pause_upstream_recv(conn)) loop->close_conn(conn);  // stop multishot
                return;
            }
            if (kRemaining > 0) {
                // Bytes already in upstream_recv_buf (the multishot raced them in).
                // Honor @throttle before replaying them, like the plaintext path:
                // throttle_advance above may have pushed throttle_tat_ns into the
                // future, so park the buffered remainder for the byte budget (it
                // stays in upstream_recv_buf — no memory growth — and replays on the
                // throttle timer) rather than bursting past the configured rate.
                if (throttle_pause_before_pump(loop, conn, kRemaining)) return;
                // Not throttled: encrypt now (memory safety — the watermark only
                // gates *new* reads; one recv's worth fits under kTlsRecordMax).
                IoEvent synth = {conn.id,
                                 static_cast<i32>(kRemaining),
                                 0,
                                 0,
                                 IoEventType::UpstreamRecv,
                                 0,
                                 0,
                                 conn.upstream_episode};
                on_response_body_recvd<Loop>(lp, conn, synth);  // drain the rest of this recv
                return;
            }
            // The high watermark is the hard (memory-safety) stop and is checked
            // BEFORE throttle so the throttle timer's resume never re-arms a read
            // while the buffer is still full. Below the high watermark the buffer
            // only drains, so a throttle pause/resume here can't overflow it.
            if (conn.tls_out_buf.len() >= Loop::kTlsOutHigh) {
                conn.tls_recv_paused_hw = true;
                // Cancel may fail to queue (SQ full) — close rather than let the
                // multishot keep filling above the stop line.
                if (!loop->pause_upstream_recv(conn)) loop->close_conn(conn);
                return;
            }
            if (throttle_pause_before_pump(loop, conn, kRemaining)) return;
            // Unconditional (see tls_on_out_drain): submit_recv_upstream self-guards
            // the armed/cancel-pending race and fails only on a real add_recv error.
            if (!loop->submit_recv_upstream(conn)) {
                loop->close_conn(conn);
            }
            return;
        }
    }

    conn.resp_body_sent += send_len;
    conn.upstream_send_len = send_len;
    conn.transition_to_sending(&on_response_body_sent<Loop>);
    client_send(loop, conn, conn.upstream_recv_buf.data(), send_len);
}

// The proxy response body is fully forwarded: release the upstream slot,
// complete the request, close upstream, and continue the connection (keep-alive
// pipeline / next request). Factored out of on_response_body_sent so the
// io_uring-TLS owned-buffer path (tls_on_out_drain, see docs/iouring-tls-output-
// buffer.md) shares the exact completion logic. tls_proxy_stream /
// resp_fully_buffered are per-response — cleared here, the keep-alive boundary.
template <typename Loop>
void proxy_stream_complete(Loop* loop, Connection& conn) {
    if (conn.response_policy_id != 0 && !strict_response_upload_ready(conn)) {
        loop->close_conn(conn);
        return;
    }
    conn.tls_proxy_stream = false;
    conn.resp_fully_buffered = false;
    conn.tls_recv_paused_hw = false;  // per-response; must not leak into the next request
    // A throttle pause + armed throttle timer are also per-response. If the body
    // completes (parked/raced tail) before the timer fires, clear the pause so a
    // leaked tick is a no-op — both backends dispatch throttle_resume only while
    // throttle_paused — instead of resuming a pump against the next request's state.
    const bool kWasThrottled = conn.throttle_paused;
    conn.throttle_paused = false;
    conn.throttle_pending_len = 0;
    // Surplus upstream bytes after the self-framed body — left in the buffer by the
    // body pump (already consumed from the socket, so take_idle's MSG_PEEK can't see
    // them) — mean a desynced/overlong backend; don't pool such a connection. (A
    // TLS-proxied stream parks its tail in this buffer legitimately, so skip the
    // check there to avoid needlessly dropping a reusable connection.)
    if (!conn.tls_proxy_stream && conn.upstream_recv_buf.len() > 0)
        conn.upstream_keep_alive = false;
    // The strict response profile deliberately never parks an upstream socket:
    // nginx's literal proxy_pass opens a fresh backend connection for each
    // request in the pinned compatibility experiment.  Any bytes beyond the
    // declared body are discarded after the downstream response completed;
    // bytes observed before completion are still rejected by the body pump.
    if (conn.response_policy_id != 0) conn.upstream_keep_alive = false;
    conn.upstream_recv_buf.reset();
    release_upstream_slot(loop, conn);  // free the backend slot promptly

    on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
    loop->epoch_leave();

    // Mirror on_proxy_response_sent: during graceful drain, close the upstream
    // (close_conn closes upstream_fd) rather than parking it in the idle pool.
    // No further request should reuse a draining shard's backend sockets, and a
    // pooled fd would otherwise survive until sweep/shutdown. This is-draining
    // check therefore precedes release_upstream_conn (which would pool a
    // reusable fd). A normal (non-draining) completion still pools as before.
    if (loop->is_draining()) {
        loop->close_conn(conn);
        return;
    }

    release_upstream_conn(loop, conn);  // pool for reuse if keep-alive, else close

    if (!conn.keep_alive) {
        loop->close_conn(conn);
        return;
    }

    if constexpr (requires(Loop* candidate, Connection& c) {
                      candidate->defer_http1_request_boundary(c);
                  }) {
        if (conn.upstream_retirement_active && loop->defer_http1_request_boundary(conn)) return;
    }

    // If this response was throttled, arm_throttle_timer pulled the connection off
    // the keepalive wheel (the precise timer owned its wakeup). Now that the
    // throttle pause is cleared (its timer tick is a no-op), restore the normal
    // keepalive deadline — otherwise an idle keep-alive client could hold the slot
    // open indefinitely (precise-timer path) or be closed at the short throttle
    // delay (wheel fallback) instead of keepalive_timeout. The pipeline paths below
    // dispatch a buffered request immediately (which re-refreshes), but the idle
    // header-read path has no other wakeup to re-arm it.
    if constexpr (requires { loop->timer.refresh(&conn, loop->keepalive_timeout); }) {
        if (kWasThrottled) loop->timer.refresh(&conn, loop->keepalive_timeout);
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
        conn.recv_buf.write(conn.send_buf.data() + conn.retry_req_send_len, kStashLen);
        conn.retry_req_send_len = 0;
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

template <typename Loop>
void on_response_body_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (conn.response_read_deadline_post_commit_phase !=
        ResponseReadDeadlinePostCommitPhase::None) {
        const u32 inflight = conn.response_read_deadline_post_commit_inflight_body;
        const bool send_owner_valid = [&]() {
            if constexpr (requires(
                              const Loop* candidate, const Connection& c, const IoEvent& event) {
                              candidate->response_read_deadline_send_completion_is_valid(
                                  c, event, ResponseReadDeadlineSendKind::Body);
                          }) {
                return loop->response_read_deadline_send_completion_is_valid(
                    conn, ev, ResponseReadDeadlineSendKind::Body);
            }
            return false;
        }();
        if (!send_owner_valid || ev.result <= 0 || static_cast<u32>(ev.result) != inflight ||
            inflight == 0 ||
            conn.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::BodySend ||
            !response_read_deadline_post_commit_is_stable(conn) ||
            conn.upstream_send_len != inflight || conn.upstream_recv_buf.len() < inflight ||
            conn.response_read_deadline_post_commit_downstream_completed > 0xFFFFFFFFu - inflight) {
            loop->close_conn(conn);
            return;
        }
        conn.clear_response_read_deadline_send_owner();
        conn.response_read_deadline_post_commit_downstream_completed += inflight;
        conn.response_read_deadline_post_commit_inflight_body = 0;
        (void)consume_upstream_sent(conn);
        conn.response_read_deadline_post_commit_phase =
            ResponseReadDeadlinePostCommitPhase::WaitingBody;
        if constexpr (requires(Loop* candidate, Connection& c) {
                          candidate->defer_response_read_deadline_body_pump(c);
                      }) {
            loop->defer_response_read_deadline_body_pump(conn);
        } else {
            loop->close_conn(conn);
        }
        return;
    }

    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }

    if (conn.response_policy_id != 0 && !strict_response_upload_ready(conn)) {
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
        proxy_stream_complete<Loop>(loop, conn);
        return;
    }

    conn.set_slots(nullptr, nullptr, &on_response_body_recvd<Loop>, nullptr);
    if (throttle_pause_before_pump(loop, conn, kRemaining)) return;
    if (kRemaining > 0) {
        IoEvent synth = {conn.id,
                         static_cast<i32>(kRemaining),
                         0,
                         0,
                         IoEventType::UpstreamRecv,
                         0,
                         0,
                         conn.upstream_episode};
        on_response_body_recvd<Loop>(lp, conn, synth);
    } else {
        loop->submit_recv_upstream(conn);
    }
}

template <typename Loop>
void handle_early_upstream_recv(Loop* loop, Connection& conn, IoEvent ev, bool send_in_flight) {
    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        // EOF/error before any response, possibly before the request send even
        // completed (epoll can deliver a reused socket's FIN/RST while the send is
        // still parked on EPOLLOUT). The request is still in recv_buf, so retry on a
        // fresh connect for idempotent reused requests. Gated on !upstream_send_armed
        // so we never abandon an in-flight io_uring send SQE (its later CQE would be
        // misrouted to the retried connection).
        if (!conn.upstream_send_armed && retry_reused_upstream(loop, conn)) return;
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
    // The body upload is still draining while an early upstream response is buffered;
    // this slot completes the final body chunk send. If that send FAILED the upload
    // is truncated even though the body counters (advanced before submit) may read
    // "complete" — mark it so proxy_upstream_reusable refuses to pool a socket whose
    // request desynced (otherwise the next request would be parsed as leftover body).
    if (ev.result < 0) {
        conn.upstream_request_incomplete = true;
        conn.request_upload_complete = false;
    } else if (request_policy_body_response_domain(conn) && conn.req_initial_send_len > 0 &&
               static_cast<u32>(ev.result) == conn.req_initial_send_len &&
               (conn.req_body_mode == BodyMode::None ||
                conn.req_body_mode == BodyMode::ContentLength) &&
               conn.req_body_remaining == 0 && !conn.req_body_streamed) {
        // The send callback is emitted only after the backend has accepted the
        // complete submitted request (both epoll and io_uring enforce full-send
        // semantics). A response CQE may have arrived first, so publish the
        // successful upload here before strict response admission. A partial
        // positive result remains an early response and stays fail-closed.
        conn.request_upload_complete = true;
    }

    reserve_response_mutation_snapshot(conn);
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
    IoEvent synth = {
        conn.id, kSynthResult, 0, 0, IoEventType::UpstreamRecv, 0, 0, conn.upstream_episode};
    on_upstream_response<Loop>(lp, conn, synth);
}

template <typename Loop>
void on_request_body_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);

    if (ev.result <= 0) {
        // A streamed body chunk failed to send: the upload is now truncated even
        // though req_body_remaining / the chunk parser were advanced (before this
        // submit) and may read "complete". Mark the upload incomplete so that if an
        // early response was buffered and the socket reaches release_upstream_conn,
        // proxy_upstream_reusable refuses to pool this desynced stream.
        conn.upstream_request_incomplete = true;
        conn.request_upload_complete = false;
        if (conn.upstream_recv_buf.len() > 0) {
            prepare_early_response_state(conn);
            conn.set_slots(nullptr, nullptr, &on_upstream_response<Loop>, nullptr);
            IoEvent synth = {conn.id,
                             static_cast<i32>(conn.upstream_recv_buf.len()),
                             0,
                             0,
                             IoEventType::UpstreamRecv,
                             0,
                             0,
                             conn.upstream_episode};
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
                    IoEvent synth = {conn.id,
                                     static_cast<i32>(nr),
                                     0,
                                     0,
                                     IoEventType::UpstreamRecv,
                                     0,
                                     0,
                                     conn.upstream_episode};
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
        conn.request_upload_complete = true;
        if (!pipeline_stash(conn)) {
            loop->close_conn(conn);
            return;
        }
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
                             0,
                             0,
                             conn.upstream_episode};
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
    if (!loop->submit_send_upstream(conn, conn.recv_buf.data(), send_len)) {
        conn.upstream_request_incomplete = true;
        conn.request_upload_complete = false;
        loop->close_conn(conn);
    }
}

#if RUT_ENABLE_WEBSOCKET
// === WebSocket / Upgrade passthrough: full-duplex byte tunnel ================
// After a 101 the connection runs as a transparent splice with four fixed slots,
// two independent ping-pong loops (read one side → send to the other → re-read):
//   on_recv          = on_ws_client_recv          (client bytes → upstream)
//   on_upstream_send = on_ws_client_to_upstream_sent
//   on_upstream_recv = on_ws_upstream_recv         (upstream bytes → client)
//   on_send          = on_ws_upstream_to_client_sent
// Either side closing tears down both. A stale -ENOBUFS (recv buffer full while
// the paired send drains it) is ignored rather than treated as a close.

#if RUT_ENABLE_WEBSOCKET
// Arm terminate mode at the 101: acquire the two reassembly slices, initialize both
// per-direction inspectors (client->upstream masked, upstream->client unmasked), bound the
// message cap to one slice, and seed the outbound mask PRNG with real entropy. Returns
// false if the slice pool is exhausted (or the loop has no pool) — the caller closes.
template <typename Loop>
bool ws_arm_terminate(Loop* loop, Connection& conn) {
    if constexpr (requires(Loop* lp, Connection& c) { lp->alloc_ws_terminate_bufs(c); }) {
        if (!loop->alloc_ws_terminate_bufs(conn)) return false;
        u32 cap = conn.ws_max_message_size;
        const u32 kCap = SlicePool::kSliceSize - kWsMaxHeaderSize;
        if (cap == 0 || cap > kCap) cap = kCap;
        conn.ws_c2u.reset();
        conn.ws_c2u.masked = true;       // client->upstream is client-role on both ends → masked
        conn.ws_c2u.from_client = true;  // this leg is the client→upstream direction
        conn.ws_c2u.max_message_size = cap;
        conn.ws_c2u.close_code = conn.ws_close_code;  // frame.close(code) status for this route
        conn.ws_c2u.reject_fragmented = true;  // in-place re-frame: single-frame messages only
        conn.ws_u2c.reset();
        conn.ws_u2c.masked = false;       // upstream->client is server-role on both ends → unmasked
        conn.ws_u2c.from_client = false;  // this leg is the upstream→client direction
        conn.ws_u2c.max_message_size = cap;
        conn.ws_u2c.close_code = conn.ws_close_code;
        conn.ws_u2c.reject_fragmented = true;
        u64 seed = 0;
        // Fail closed on an RNG failure rather than emit predictable mask keys (§5.3).
        if (RAND_bytes(reinterpret_cast<u8*>(&seed), sizeof(seed)) != 1) return false;
        conn.ws_c2u.mask_rng = seed;  // only the masked direction emits fresh mask keys
        conn.is_ws_terminate = true;
        return true;
    } else {
        return false;
    }
}
#endif

template <typename Loop>
bool ws_pause_client_recv(Loop* loop, Connection& conn) {
    // Prefer the loop-level pause_recv(Connection&): the io_uring loop needs it
    // to set recv_paused_for_send / recv_pause_cancel_pending and cancel the
    // multishot recv on the correct fd. It must be checked BEFORE the backend
    // 2-arg form, because IoUringBackend::pause_recv(i32 fd, u32 conn_id) also
    // binds to `backend.pause_recv(conn.id, true)` via implicit conversions
    // (true→u32), which would pause the wrong conn_id and skip the loop flags.
    // The epoll loop has no pause_recv(Connection&), so it falls through to the
    // backend form with preserve_send_interest=true (unchanged behavior).
    if constexpr (requires(Loop* lp, Connection& c) { lp->pause_recv(c); }) {
        const bool ok = loop->pause_recv(conn);
        if (ok && !conn.recv_armed) conn.recv_pause_cancel_pending = false;
        return ok;
    } else if constexpr (requires(Loop* lp, u32 conn_id) {
                             lp->backend.pause_recv(conn_id, true);
                             lp->backend.pause_recv(conn_id);
                         }) {
        // epoll-style backend: pause_recv(u32 conn_id, bool preserve=false). The
        // extra 1-arg requirement excludes io_uring's pause_recv(i32 fd, u32
        // conn_id) — which would otherwise bind conn.id as the fd and `true` as
        // conn_id, cancelling the wrong recv (the io_uring loop uses the
        // pause_recv(Connection&) branch above).
        loop->backend.pause_recv(conn.id, true);
    } else if constexpr (requires(Loop* lp, u32 cid) { lp->backend.pause_recv(cid); }) {
        loop->backend.pause_recv(conn.id);
    }
    return true;
}

template <typename Loop>
[[nodiscard]] bool ws_pause_upstream_recv(Loop* loop, Connection& conn) {
    if constexpr (requires(Loop* lp, Connection& c) { lp->pause_upstream_recv_for_send(c); }) {
        return loop->pause_upstream_recv_for_send(conn);
    } else if constexpr (requires(Loop* lp, Connection& c) { lp->pause_upstream_recv(c); }) {
        return loop->pause_upstream_recv(conn);
    } else if constexpr (requires(Loop* lp, u32 cid) { lp->backend.pause_upstream_recv(cid); }) {
        loop->backend.pause_upstream_recv(conn.id);
    }
    return true;
}

template <typename Loop>
bool ws_resume_client_recv(Loop* loop, Connection& conn) {
    conn.recv_paused_for_send = false;
    return loop->submit_recv(conn);
}

// Stop reading from the upstream fd while a close is deferred behind a draining
// send. epoll: drop the read interest (keep a pending send's EPOLLOUT) so a
// level-triggered FIN can't spin. io_uring: cancel the multishot recv so no NEW
// bytes are read after the FIN — otherwise the drain-then-close contract (stop
// reading new data) would be violated and the tunnel would keep relaying.
template <typename Loop>
void ws_stop_upstream_poll(Loop* loop, Connection& conn) {
    if constexpr (requires(Loop* lp, Connection& c) { lp->ws_unpoll_upstream(c); }) {
        loop->ws_unpoll_upstream(conn);
    } else if constexpr (requires(Loop* lp, Connection& c) { lp->pause_upstream_recv(c); }) {
        (void)loop->pause_upstream_recv(conn);  // async: cancel the multishot recv
    }
}

// Symmetric to ws_stop_upstream_poll for the client fd.
template <typename Loop>
void ws_stop_client_poll(Loop* loop, Connection& conn) {
    if constexpr (requires(Loop* lp, Connection& c) { lp->ws_unpoll_client(c); }) {
        loop->ws_unpoll_client(conn);
    } else if constexpr (requires(Loop* lp, Connection& c) { lp->pause_recv(c); }) {
        (void)loop->pause_recv(conn);  // async: cancel the multishot recv
    }
}

// True for backends whose recv eagerly consumes socket data into a provided
// buffer (io_uring): a -ENOBUFS there means the overflow bytes were already read
// from the socket and discarded, so the tunnel cannot recover them by pausing.
// Sync backends (epoll) leave the bytes in the socket, so pausing is safe.
template <typename Loop>
constexpr bool ws_loop_async() {
    if constexpr (requires { decltype(Loop::backend)::kAsyncIo; }) {
        return decltype(Loop::backend)::kAsyncIo;
    } else {
        return false;
    }
}

// Drive the bidirectional Close handshake: submit a Close frame on each peer's send slot
// when it's idle (deferring on a busy slot), skip a peer that already half-closed, and
// close once both slots' Close frames have drained. Idempotent — safe to call from the
// trigger and from both sent callbacks. Returns false on a submit failure (caller closes).
template <typename Loop>
bool ws_drive_close(Loop* loop, Connection& conn) {
    // A peer that already FIN'd can't receive a Close — treat its slot as satisfied.
    if (conn.ws_client_eof) conn.ws_close_client_need = false;
    if (conn.ws_upstream_eof) conn.ws_close_upstream_need = false;
    // Client slot (upstream->client, unmasked): send the echo Close if idle.
    if (conn.ws_close_client_need && !conn.ws_upstream_send_pending) {
        const u32 n = ws_emit_close_frame(conn.ws_close_frame_client,
                                          sizeof(conn.ws_close_frame_client),
                                          /*masked=*/false,
                                          conn.ws_u2c.mask_rng,
                                          conn.ws_echo_close_code);
        if (n == 0 || !client_send(loop, conn, conn.ws_close_frame_client, n)) return false;
        conn.ws_upstream_send_pending = true;
        conn.ws_close_client_need = false;
        conn.ws_close_client_inflight = true;
    }
    // Upstream slot (client->upstream, masked): send the echo Close if idle.
    if (conn.ws_close_upstream_need && !conn.ws_client_send_pending) {
        const u32 n = ws_emit_close_frame(conn.ws_close_frame_upstream,
                                          sizeof(conn.ws_close_frame_upstream),
                                          /*masked=*/true,
                                          conn.ws_c2u.mask_rng,
                                          conn.ws_echo_close_code);
        if (n == 0 || !loop->submit_send_upstream(conn, conn.ws_close_frame_upstream, n))
            return false;
        conn.ws_client_send_pending = true;
        conn.ws_close_upstream_need = false;
        conn.ws_close_upstream_inflight = true;
    }
    // Both slots have finished their Close (none pending, none draining) → tear down.
    if (!conn.ws_close_client_need && !conn.ws_close_client_inflight &&
        !conn.ws_close_upstream_need && !conn.ws_close_upstream_inflight) {
        loop->close_conn(conn);
    }
    return true;
}

template <typename Loop>
bool ws_try_send_client_to_upstream(Loop* loop, Connection& conn) {
    // Once a Close handshake is under way, no more data is forwarded — ignore further bytes
    // (the handshake drives teardown). Prevents relaying frames after the Close.
    if (conn.ws_closing) return true;
    if (conn.recv_buf.len() == 0) return true;
    if (conn.ws_client_send_pending) return ws_pause_client_recv(loop, conn);
#if RUT_ENABLE_WEBSOCKET
    if (conn.is_ws_terminate) {
        // Terminate: parse/reassemble/inspect the client frames and re-frame the result
        // IN PLACE over recv_buf (output is always <= consumed input). Send the produced
        // prefix; the unconsumed (partial trailing) bytes are dropped via consume() in the
        // sent callback once the send drains.
        u32 consumed = 0, produced = 0;
        const WsInspectStatus st = ws_inspect(conn.ws_c2u,
                                              conn.recv_buf.data(),
                                              conn.recv_buf.len(),
                                              const_cast<u8*>(conn.recv_buf.data()),
                                              conn.recv_buf.len(),
                                              conn.ws_c2u_msg,
                                              conn.ws_max_message_size,
                                              conn.ws_handler,
                                              &conn,
                                              &consumed,
                                              &produced);
        if (st == WsInspectStatus::Error) return false;  // caller closes
        if (produced > 0) {
            conn.ws_c2u_consumed = consumed;
            if (st == WsInspectStatus::Close) {
                // The produced send carries the Close to the upstream; the client must get a
                // Close back too (handshake). Start the upstream slot in-flight + queue the
                // client echo, then close once both drain. The echo carries the code the
                // inspector resolved (handler frame.close(code), or 1000 for a peer close).
                conn.ws_closing = true;
                conn.ws_close_upstream_inflight = true;
                conn.ws_close_client_need = true;
                conn.ws_echo_close_code = conn.ws_c2u.echo_close_code;
            }
            if (!loop->submit_send_upstream(conn, conn.recv_buf.data(), produced)) return false;
            conn.ws_client_send_pending = true;
            conn.ws_client_send_len = produced;
            if (conn.ws_closing)
                return ws_drive_close(loop, conn);  // send the client echo now if idle
            return ws_pause_client_recv(loop, conn);
        }
        // Nothing to forward yet (partial frame) or every message was dropped: discard the
        // consumed bytes and keep receiving the rest of the next frame. We didn't pause, so
        // a sync (epoll, one-shot) recv must be re-armed; an async multishot recv stays
        // armed UNLESS this was its terminal completion (recv_armed cleared) — re-arm then.
        if (consumed > 0) conn.recv_buf.consume(consumed);
        if (st == WsInspectStatus::Close) return false;  // caller closes
        if ((conn.ws_client_eof || conn.ws_upstream_eof)) {
            // Peer FIN'd and the drain stops new reads, so a leftover partial frame can
            // never complete — drop it so ws_close_if_drained (which needs an empty buffer)
            // can tear down, instead of a partial-frame-then-FIN wedging the tunnel open.
            conn.recv_buf.consume(conn.recv_buf.len());
            return true;
        }
        if constexpr (ws_loop_async<Loop>()) {
            // If a pre-tunnel recv cancel is still in flight, recv_armed is still true but
            // the cancel will clear it — mark a deferred re-arm so its completion re-arms,
            // otherwise a zero-output (dropped/partial) first frame strands the client recv.
            if (conn.recv_pause_cancel_pending) conn.recv_pause_rearm_pending = true;
            if (!conn.recv_armed) return ws_resume_client_recv(loop, conn);
        } else {
            return ws_resume_client_recv(loop, conn);
        }
        return true;
    }
#endif
    const u32 kSendLen = conn.recv_buf.len();
    if (!loop->submit_send_upstream(conn, conn.recv_buf.data(), kSendLen)) return false;
    conn.ws_client_send_pending = true;
    conn.ws_client_send_len = kSendLen;
    return ws_pause_client_recv(loop, conn);
}

template <typename Loop>
bool ws_try_send_upstream_to_client(Loop* loop, Connection& conn) {
    if (conn.ws_closing) return true;  // close handshake under way — stop forwarding data
    if (conn.upstream_recv_buf.len() == 0) return true;
    if (conn.ws_upstream_send_pending) {
        return ws_pause_upstream_recv(loop, conn);
    }
#if RUT_ENABLE_WEBSOCKET
    if (conn.is_ws_terminate) {
        // Mirror of the client->upstream terminate path, on upstream_recv_buf. Frames here
        // are unmasked (server role). @throttle pacing is intentionally bypassed in
        // terminate mode: a throttle park would re-enter this function and re-inspect the
        // same (already advanced) reassembler state — terminate + @throttle is a later
        // combination.
        u32 consumed = 0, produced = 0;
        const WsInspectStatus st = ws_inspect(conn.ws_u2c,
                                              conn.upstream_recv_buf.data(),
                                              conn.upstream_recv_buf.len(),
                                              const_cast<u8*>(conn.upstream_recv_buf.data()),
                                              conn.upstream_recv_buf.len(),
                                              conn.ws_u2c_msg,
                                              conn.ws_max_message_size,
                                              conn.ws_handler,
                                              &conn,
                                              &consumed,
                                              &produced);
        if (st == WsInspectStatus::Error) return false;
        if (produced > 0) {
            conn.ws_u2c_consumed = consumed;
            if (st == WsInspectStatus::Close) {
                // The produced send carries the Close to the client; the upstream must get a
                // Close back too. Start the client slot in-flight + queue the upstream echo,
                // carrying the code the inspector resolved (frame.close(code), or 1000).
                conn.ws_closing = true;
                conn.ws_close_client_inflight = true;
                conn.ws_close_upstream_need = true;
                conn.ws_echo_close_code = conn.ws_u2c.echo_close_code;
            }
            if (!client_send(loop, conn, conn.upstream_recv_buf.data(), produced)) return false;
            conn.ws_upstream_send_pending = true;
            conn.ws_upstream_send_len = produced;
            if (conn.ws_closing)
                return ws_drive_close(loop, conn);  // send the upstream echo now if idle
            return ws_pause_upstream_recv(loop, conn);
        }
        if (consumed > 0) conn.upstream_recv_buf.consume(consumed);
        if (st == WsInspectStatus::Close) return false;
        if ((conn.ws_client_eof ||
             conn.ws_upstream_eof)) {  // drain can't complete a partial frame — drop it so we close
            conn.upstream_recv_buf.consume(conn.upstream_recv_buf.len());
            return true;
        }
        // Sync (epoll): re-arm the one-shot upstream recv. Async: re-arm only if the
        // terminal multishot completion cleared upstream_recv_armed.
        if constexpr (ws_loop_async<Loop>()) {
            // A pre-tunnel upstream recv cancel in flight will clear upstream_recv_armed —
            // mark a deferred re-arm so its completion re-arms (a zero-output early backend
            // frame coalesced with the 101 would otherwise stop further backend reads).
            if (conn.upstream_recv_pause_cancel_pending)
                conn.upstream_recv_pause_rearm_pending = true;
            if (!conn.upstream_recv_armed) {
                conn.upstream_recv_paused_for_send = false;
                return loop->submit_recv_upstream(conn);
            }
        } else {
            conn.upstream_recv_paused_for_send = false;
            return loop->submit_recv_upstream(conn);
        }
        return true;
    }
#endif
    const u32 kSendLen = conn.upstream_recv_buf.len();
    if (throttle_pause_before_pump(loop, conn, kSendLen)) return true;
    if (!client_send(loop, conn, conn.upstream_recv_buf.data(), kSendLen)) return false;
    conn.ws_upstream_send_pending = true;
    conn.ws_upstream_send_len = kSendLen;
    return ws_pause_upstream_recv(loop, conn);
}

// nginx-style drain-then-close. Once either peer half-closes (TCP FIN), the
// tunnel stops reading NEW data but flushes all in-flight/buffered bytes in BOTH
// directions before tearing down — never truncating data, and never relaying
// new data after the FIN (WebSocket shutdown is an application-level Close-frame
// handshake, not a TCP half-close). See DESIGN.md §"WebSocket tunnel teardown".
inline bool ws_draining(const Connection& conn) {
    return conn.ws_client_eof || conn.ws_upstream_eof;
}

template <typename Loop>
void ws_close_if_drained(Loop* loop, Connection& conn) {
    if (!conn.ws_client_send_pending && !conn.ws_upstream_send_pending &&
        conn.recv_buf.len() == 0 && conn.upstream_recv_buf.len() == 0) {
        loop->close_conn(conn);
    }
}

// Flush both directions: kick a send wherever bytes are buffered but no send is
// in flight, then quiesce both fds — stop new reads (so a level-triggered FIN
// can't spin) while preserving any pending send's EPOLLOUT so it still drains.
template <typename Loop>
bool ws_drain_pump(Loop* loop, Connection& conn) {
    if (!conn.ws_client_send_pending && conn.recv_buf.len() > 0)
        if (!ws_try_send_client_to_upstream(loop, conn)) return false;
    if (!conn.ws_upstream_send_pending && conn.upstream_recv_buf.len() > 0)
        if (!ws_try_send_upstream_to_client(loop, conn)) return false;
    ws_stop_client_poll(loop, conn);
    ws_stop_upstream_poll(loop, conn);
    return true;
}

template <typename Loop>
void on_ws_client_recv(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result == -ENOBUFS) {
        if constexpr (ws_loop_async<Loop>()) {
            // io_uring already consumed the socket data into its provided buffer
            // and discarded what didn't fit (IoUringBackend::wait), so pausing
            // would forward a corrupted stream. Fail closed instead.
            loop->close_conn(conn);
            return;
        }
        // recv_buf full while the paired client→upstream send drains it. On
        // level-triggered epoll the client fd stays readable, so a bare return
        // busy-loops; pause this direction (resumed by the send callback's
        // reset + submit_recv). State-aware like on_response_body_recvd: only
        // pause when truly full — a non-full -ENOBUFS is a stale completion.
        if (conn.recv_buf.write_avail() == 0) {
            if (!ws_pause_client_recv(loop, conn)) loop->close_conn(conn);
        }
        return;
    }
    if (ev.result < 0) {
        loop->close_conn(conn);  // hard error (e.g. ECONNRESET): not a clean FIN
        return;
    }
    if (ev.result == 0) {
        // Client half-closed (clean FIN). Enter drain mode: flush both directions'
        // buffered/in-flight bytes, then tear down once everything has drained.
        conn.ws_client_eof = true;
        if (!ws_drain_pump(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        ws_close_if_drained(loop, conn);
        return;
    }
    if (!ws_try_send_client_to_upstream(loop, conn)) loop->close_conn(conn);
}

template <typename Loop>
void on_ws_client_to_upstream_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    conn.ws_client_send_pending = false;
    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }
#if RUT_ENABLE_WEBSOCKET
    if (conn.is_ws_terminate) {
        // Drop the consumed prefix (the re-framed output we just sent + any dropped
        // frames), keeping the partial trailing frame at the front for the next read.
        conn.recv_buf.consume(conn.ws_c2u_consumed);
        conn.ws_c2u_consumed = 0;
        conn.ws_client_send_len = 0;
        if (conn.ws_closing) {  // a Close drained on the upstream slot — advance the handshake
            conn.ws_close_upstream_inflight = false;
            if (!ws_drive_close(loop, conn)) loop->close_conn(conn);
            return;
        }
        if (ws_draining(conn)) {
            if (!ws_drain_pump(loop, conn)) {
                loop->close_conn(conn);
                return;
            }
            ws_close_if_drained(loop, conn);
            return;
        }
        // Bytes can race into recv_buf while the send was in flight (the recv pause is
        // best-effort): re-inspect them now so an already-complete frame isn't stranded
        // until the client sends more. The send is done, so clear the pause first — if the
        // re-inspection produces nothing (a dropped/partial frame) it re-arms rather than
        // sending, and a stale recv_paused_for_send would mis-handle the next completion;
        // ws_try_send re-sets it via ws_pause_client_recv if it does send.
        conn.recv_paused_for_send = false;
        if (conn.recv_buf.len() > 0) {
            if (!ws_try_send_client_to_upstream(loop, conn)) loop->close_conn(conn);
            return;
        }
        // Resume client recv (paused for this send), and pump the opposite direction.
        if (!ws_resume_client_recv(loop, conn) || !ws_try_send_upstream_to_client(loop, conn)) {
            loop->close_conn(conn);
        }
        return;
    }
#endif
    conn.recv_buf.consume(conn.ws_client_send_len);
    conn.ws_client_send_len = 0;
    if (ws_draining(conn)) {
        // Keep flushing both directions; close once everything has drained.
        if (!ws_drain_pump(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        ws_close_if_drained(loop, conn);
        return;
    }
    if (conn.recv_buf.len() > 0) {
        if (!ws_try_send_client_to_upstream(loop, conn)) loop->close_conn(conn);
        return;
    }
    if (!ws_resume_client_recv(loop, conn) || !ws_try_send_upstream_to_client(loop, conn))
        loop->close_conn(conn);
}

template <typename Loop>
void on_ws_upstream_recv(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result == -ENOBUFS) {
        if constexpr (ws_loop_async<Loop>()) {
            loop->close_conn(conn);  // overflow discarded by io_uring (see above)
            return;
        }
        // upstream_recv_buf full while the paired upstream→client send drains it
        // (see on_ws_client_recv). Pause the upstream direction when truly full.
        if (conn.upstream_recv_buf.write_avail() == 0) {
            if (!ws_pause_upstream_recv(loop, conn)) loop->close_conn(conn);
        }
        return;
    }
    if (ev.result < 0) {
        loop->close_conn(conn);  // hard error (e.g. ECONNRESET): not a clean FIN
        return;
    }
    if (ev.result == 0) {
        // Backend half-closed (clean FIN). Mirror on_ws_client_recv: drain both
        // directions, then tear down once everything has flushed.
        conn.ws_upstream_eof = true;
        if (!ws_drain_pump(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        ws_close_if_drained(loop, conn);
        return;
    }
    if (!ws_try_send_upstream_to_client(loop, conn)) loop->close_conn(conn);
}

template <typename Loop>
void on_ws_upstream_to_client_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    conn.ws_upstream_send_pending = false;
    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }
#if RUT_ENABLE_WEBSOCKET
    if (conn.is_ws_terminate) {
        conn.upstream_recv_buf.consume(conn.ws_u2c_consumed);
        conn.ws_u2c_consumed = 0;
        conn.ws_upstream_send_len = 0;
        if (conn.ws_closing) {  // a Close drained on the client slot — advance the handshake
            conn.ws_close_client_inflight = false;
            if (!ws_drive_close(loop, conn)) loop->close_conn(conn);
            return;
        }
        if (conn.ws_pre_tunnel_upstream_closed) conn.ws_upstream_eof = true;
        if (ws_draining(conn)) {
            if (!ws_drain_pump(loop, conn)) {
                loop->close_conn(conn);
                return;
            }
            ws_close_if_drained(loop, conn);
            return;
        }
        // Re-inspect bytes that raced into upstream_recv_buf during the send before
        // re-arming (a complete frame mustn't wait for the next backend read). Clear the
        // pause first so a zero-output re-inspection that re-arms doesn't leave it stale.
        conn.upstream_recv_paused_for_send = false;
        if (conn.upstream_recv_buf.len() > 0) {
            if (!ws_try_send_upstream_to_client(loop, conn)) loop->close_conn(conn);
            return;
        }
        if (!loop->submit_recv_upstream(conn)) {  // re-arm upstream->client direction
            loop->close_conn(conn);
            return;
        }
        if (!ws_try_send_client_to_upstream(loop, conn)) loop->close_conn(conn);
        return;
    }
#endif
    conn.upstream_recv_buf.consume(conn.ws_upstream_send_len);
    conn.ws_upstream_send_len = 0;
    if (conn.ws_pre_tunnel_upstream_closed) {
        // Backend closed during the 101 drain: enter drain mode so a still-pending
        // or buffered client→upstream send (post-upgrade bytes) flushes before the
        // tunnel tears down, instead of being truncated.
        conn.ws_upstream_eof = true;
    }
    if (ws_draining(conn)) {
        if (!ws_drain_pump(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        ws_close_if_drained(loop, conn);
        return;
    }
    if (conn.upstream_recv_buf.len() > 0) {
        if (!ws_try_send_upstream_to_client(loop, conn)) loop->close_conn(conn);
        return;
    }
    conn.upstream_recv_paused_for_send = false;
    if (!loop->submit_recv_upstream(conn)) {  // re-arm upstream→client direction
        loop->close_conn(conn);
        return;
    }
    if (!ws_try_send_client_to_upstream(loop, conn)) loop->close_conn(conn);
}

template <typename Loop>
void on_ws_pre_tunnel_upstream_recv(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result == -ENOBUFS) {
        if constexpr (ws_loop_async<Loop>()) {
            loop->close_conn(conn);  // overflow discarded by io_uring
            return;
        }
        if (conn.upstream_recv_buf.write_avail() == 0) {
            if (!ws_pause_upstream_recv(loop, conn)) loop->close_conn(conn);
        }
        return;
    }
    if (ev.result < 0) {
        // Hard error (e.g. ECONNRESET): the stream is not cleanly half-closed —
        // don't advertise a successful upgrade. Close immediately.
        loop->close_conn(conn);
        return;
    }
    if (ev.result == 0) {
        conn.ws_pre_tunnel_upstream_closed = true;
        // Stop polling the hung-up upstream fd so a slow 101 drain to the client
        // doesn't spin the level-triggered loop on redelivered EPOLLHUP. The fd
        // is still ::closed by close_conn once the tunnel is entered/torn down.
        ws_stop_upstream_poll(loop, conn);
        return;
    }
    if (!ws_pause_upstream_recv(loop, conn)) loop->close_conn(conn);
}

// The 101 (and any bytes the backend already sent) has been forwarded to the
// client; switch into tunnel mode and arm both directions.
template <typename Loop>
void on_ws_101_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if (ev.result <= 0) {
        loop->close_conn(conn);
        return;
    }
    conn.is_ws_tunnel = true;
    conn.ws_client_send_pending = false;
    conn.ws_upstream_send_pending = false;
    conn.ws_client_send_len = 0;
    conn.ws_upstream_send_len = 0;
#if RUT_ENABLE_WEBSOCKET
    // Arm terminate-mode inspection before any early upstream frames are flushed, so they
    // flow through ws_inspect like the rest of the data phase. Only arm for a genuine
    // WebSocket handshake: the client must have offered "websocket" AND the backend's 101
    // must have SELECTED it (the response is authoritative). A 101 negotiating another
    // offered protocol (e.g. h2c from "Upgrade: websocket, h2c") falls through to the opaque
    // passthrough tunnel, which relays bytes correctly, rather than mis-parsing them.
    if (conn.is_ws_terminate_route && conn.req_upgrade_is_websocket &&
        conn.resp_upgrade_is_websocket && !ws_arm_terminate(loop, conn)) {
        loop->close_conn(conn);
        return;
    }
#endif
    if (conn.pipeline_stash_len > 0) {
        // Recover the stashed post-upgrade bytes into recv_buf. If they (plus any
        // bytes already read) don't fit, fail closed rather than truncate the
        // tunnel stream.
        if (!pipeline_recover(conn)) {
            loop->close_conn(conn);
            return;
        }
    }
    // Log only the upgrade request itself: if the client coalesced its first
    // WebSocket bytes with the request, req_size captured the whole recv_buf, so
    // the access-log request size would depend on packet framing. Trim to the
    // parsed header length (an upgrade request has no body).
    if (conn.req_header_end > 0) conn.req_size = conn.req_header_end;
    on_request_complete(loop, conn, conn.resp_status, conn.ws_upgrade_sent_len);
    // The HTTP request is complete at the 101: release the upstream max_inflight
    // slot now so a long-lived tunnel doesn't hold an in-flight request slot for
    // its whole lifetime and shed later requests with 503.
    release_upstream_slot(loop, conn);
    loop->epoch_leave();
    u32 kRemaining = conn.upstream_recv_buf.len();
    if (kRemaining >= conn.ws_upgrade_response_len) {
        conn.upstream_send_len = conn.ws_upgrade_response_len;
        kRemaining = consume_upstream_sent(conn);
    } else {
        conn.upstream_send_len = 0;
    }
    conn.set_slots(&on_ws_client_recv<Loop>,
                   &on_ws_upstream_to_client_sent<Loop>,
                   &on_ws_upstream_recv<Loop>,
                   &on_ws_client_to_upstream_sent<Loop>);
    conn.upstream_recv_paused_for_send = false;
    if (conn.ws_pre_tunnel_upstream_closed) {
        // Backend already half-closed during the 101 drain: enter drain mode
        // immediately rather than arming new client reads. Flush any buffered
        // bytes both ways (early upstream→client frames + buffered post-upgrade
        // client→upstream bytes), then tear down once everything has drained.
        conn.ws_upstream_eof = true;
        if (!ws_drain_pump(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        ws_close_if_drained(loop, conn);
        return;
    }
    (void)kRemaining;
    if (conn.recv_buf.len() > 0) {
        // Buffered post-upgrade client bytes: send them upstream. recv stays paused while that
        // send is in flight (correct backpressure); on_ws_client_to_upstream_sent resumes via
        // ws_resume_client_recv, which clears recv_paused_for_send.
        if (!ws_try_send_client_to_upstream(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
    } else {
        // No buffered bytes: re-arm the client recv via ws_resume_client_recv, NOT a bare
        // submit_recv. ws_stop_client_poll paused this recv on the 101 path (io_uring:
        // recv_paused_for_send = true), and a bare submit_recv no-ops while that flag is set
        // (it only marks recv_pause_rearm_pending) — so with no client send ever in flight to
        // clear it, the tunnel would stall and never read further client frames.
        if (!ws_resume_client_recv(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
    }
    if (conn.upstream_recv_buf.len() > 0) {
        if (!ws_try_send_upstream_to_client(loop, conn)) loop->close_conn(conn);
    } else {
        if (!loop->submit_recv_upstream(conn)) loop->close_conn(conn);
    }
}
// Case-insensitive scan of a comma/whitespace-separated header value for an exact token
// (optionally carrying a "/version" suffix), e.g. "websocket" in "h2c, websocket".
inline bool ws_value_has_token(const char* v, u32 vlen, const char* tok, u32 tlen) {
    auto lc = [](char ch) {
        return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
    };
    u32 i = 0;
    while (i < vlen) {
        while (i < vlen && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
        if (i >= vlen) break;
        const u32 ts = i;
        while (i < vlen && v[i] != ',' && v[i] != ' ' && v[i] != '\t') i++;
        const u32 n = i - ts;
        if (n >= tlen && (n == tlen || v[ts + tlen] == '/')) {
            bool eq = true;
            for (u32 k = 0; k < tlen; k++) {
                if (lc(v[ts + k]) != lc(tok[k])) {
                    eq = false;
                    break;
                }
            }
            if (eq) return true;
        }
    }
    return false;
}
#endif  // RUT_ENABLE_WEBSOCKET

inline bool response_policy_name_eq(Str name, const char* literal, u32 len) {
    return name.len == len && http_header_name_eq_ci(name.ptr, name.len, literal, len);
}

// The #252 body slice is eligible for the strict #253 response profile only
// after request-policy materialisation has proved a fixed Content-Length request
// is complete and no client pipeline suffix was included in that request. A
// header-only request remains outside this predicate and keeps the original
// response-policy admission path.
inline bool request_policy_body_response_domain(const Connection& conn) {
    return conn.request_policy_id != 0 && conn.request_body_fully_buffered;
}

inline bool request_policy_body_response_admitted(const Connection& conn) {
    if (!request_policy_body_response_domain(conn) || conn.request_policy_body_pending ||
        conn.req_body_streamed || conn.req_body_remaining != 0 ||
        (conn.req_body_mode != BodyMode::None && conn.req_body_mode != BodyMode::ContentLength) ||
        conn.recv_buf.len() != conn.req_initial_send_len)
        return false;
    return request_policy_is_supported(conn.request_policy_id);
}

// Check immediately before strict response headers are committed. The body
// counters are advanced before asynchronous upstream writes, so they cannot
// by themselves prove that the complete buffered request was uploaded.
inline bool strict_response_upload_ready(const Connection& conn) {
    // A reusable paired HEAD may publish request 2 after the strict response
    // boundary. Do not publish request 1's headers until its complete request
    // write has actually retired; body counters alone are not ownership
    // evidence for an asynchronous send.
    if (conn.failure_policy_suppress_body && conn.req_client_keep_alive &&
        (!conn.request_upload_complete || conn.upstream_request_incomplete))
        return false;
    if (!request_policy_body_response_domain(conn)) return true;
    return !conn.request_policy_body_pending && conn.req_body_remaining == 0 &&
           (conn.req_body_mode == BodyMode::None ||
            conn.req_body_mode == BodyMode::ContentLength) &&
           conn.request_upload_complete && !conn.upstream_request_incomplete &&
           !conn.req_body_streamed && conn.pipeline_stash_len == 0 &&
           conn.retry_req_send_len == 0 && conn.recv_buf.len() == 0 && !conn.upstream_reused;
}

// SuppressBody is supported only in the bounded cleartext H1 HEAD/explicit-
// close domain below. Every other execution path remains fail-closed.
inline bool response_policy_runtime_supported(const ForwardResponsePolicySpec& policy) {
    return policy.head_mode == ResponsePolicyHeadMode::Reject;
}

inline bool failure_policy_runtime_supported(const ForwardFailurePolicySpec& policy) {
    return policy.head_mode == FailurePolicyHeadMode::Reject;
}

// A HEAD suppression disposition is meaningful for the success and failure
// serializers only as the same per-request contract.  Response-only
// suppression remains valid for the already supported success path; a failure
// suppression disposition requires the matching response disposition so a
// connect failure can never silently fall back to a normal-body policy.
inline bool forward_policy_head_modes_compatible(const RouteConfig& config,
                                                 u16 response_policy_id,
                                                 u16 failure_policy_id,
                                                 u16 timeout_failure_policy_id) {
    const bool response_suppress =
        response_policy_id != 0 && config.response_policies[response_policy_id - 1].head_mode ==
                                       ResponsePolicyHeadMode::SuppressBody;
    const bool failure_suppress =
        failure_policy_id != 0 && config.failure_policies[failure_policy_id - 1].head_mode ==
                                      FailurePolicyHeadMode::SuppressBody;
    const bool timeout_failure_suppress =
        timeout_failure_policy_id != 0 &&
        config.failure_policies[timeout_failure_policy_id - 1].head_mode ==
            FailurePolicyHeadMode::SuppressBody;
    if (timeout_failure_policy_id != 0 && (response_policy_id == 0 || failure_policy_id == 0 ||
                                           timeout_failure_suppress != failure_suppress))
        return false;
    if (failure_suppress && !response_suppress) return false;
    // Response-only SuppressBody is an existing success-only capability; once
    // a failure policy is present it must carry the same disposition rather
    // than silently falling back to a body-bearing failure serializer.
    if (response_suppress && failure_policy_id != 0 && !failure_suppress) return false;
    if (timeout_failure_policy_id != 0 && response_suppress != timeout_failure_suppress)
        return false;
    return true;
}

inline bool response_policy_suppress_head_admitted(const Connection& conn,
                                                   const ForwardResponsePolicySpec& policy,
                                                   bool paired_failure) {
    // This is intentionally the complete bounded HEAD domain. Response-only
    // suppression keeps its original explicit-close shape. A paired failure
    // policy additionally admits the ordinary HTTP/1.1 default keep-alive
    // shape (no Connection field); every explicit keep-alive/token-list shape
    // still fails below.
    if (policy.head_mode != ResponsePolicyHeadMode::SuppressBody ||
        policy.connection != ResponsePolicyConnection::Request)
        return false;
    if (conn.recv_buf.data() == nullptr || conn.recv_buf.len() == 0) return false;
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) != ParseStatus::Complete ||
        req.method != HttpMethod::HEAD || req.version != HttpVersion::Http11 ||
        req.path.ptr == nullptr || req.path.len == 0 || req.path.ptr[0] != '/' ||
        req.has_content_length || req.chunked || req.upgrade || req.has_upgrade_header)
        return false;
    u32 host_count = 0;
    u32 connection_count = 0;
    const Header* host = nullptr;
    for (u32 i = 0; i < req.header_count; i++) {
        const Header& header = req.headers[i];
        const Str name = header.name;
        if (http_header_name_eq_ci(name.ptr, name.len, "host", 4)) {
            if (++host_count > 1) return false;
            host = &header;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "connection", 10)) {
            if (++connection_count > 1 || header.value.len != 5 ||
                !http_header_name_eq_ci(header.value.ptr, header.value.len, "close", 5))
                return false;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "content-length", 14) ||
                   http_header_name_eq_ci(name.ptr, name.len, "transfer-encoding", 17) ||
                   http_header_name_eq_ci(name.ptr, name.len, "te", 2) ||
                   http_header_name_eq_ci(name.ptr, name.len, "expect", 6) ||
                   http_header_name_eq_ci(name.ptr, name.len, "upgrade", 7)) {
            if (!conn.request_policy_id || paired_failure) return false;
        }
    }
    auto valid_authority = [](Str value) {
        if (value.ptr == nullptr || value.len == 0 || value.len > 255) return false;
        u32 colon = value.len;
        for (u32 i = 0; i < value.len; i++) {
            const u8 c = static_cast<u8>(value.ptr[i]);
            if (c <= 0x20 || c == 0x7f || c == '/' || c == '?' || c == '#' || c == '@' ||
                c == '[' || c == ']' || c == ',' || c == '\\')
                return false;
            if (c == ':') {
                if (colon != value.len) return false;
                colon = i;
            }
        }
        if (colon == 0) return false;
        const bool has_port = colon != value.len;
        if (has_port) {
            if (colon + 1 == value.len) return false;
            u32 port = 0;
            for (u32 i = colon + 1; i < value.len; i++) {
                const u8 c = static_cast<u8>(value.ptr[i]);
                if (c < '0' || c > '9' || port > 6553u || (port == 6553u && c > '5')) return false;
                port = port * 10u + static_cast<u32>(c - '0');
            }
            if (port == 0) return false;
        }
        const u32 host_len = has_port ? colon : value.len;
        for (u32 i = 0; i < host_len; i++) {
            const u8 c = static_cast<u8>(value.ptr[i]);
            const bool alpha_num =
                (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alpha_num && c != '.' && c != '-' && c != '_') return false;
        }
        return true;
    };
    if (paired_failure && (host_count != 1 || connection_count > 1 || host == nullptr ||
                           !valid_authority(host->value)))
        return false;
    const bool explicit_close_shape =
        !conn.req_client_keep_alive && conn.req_client_connection_close &&
        conn.req_client_connection_close_exact && conn.req_client_connection_count == 1;
    const bool default_keep_alive_shape =
        paired_failure && conn.req_client_keep_alive && !conn.req_client_connection_close &&
        !conn.req_client_connection_close_exact && conn.req_client_connection_count == 0;
    return policy.connection == ResponsePolicyConnection::Request &&
           conn.req_method == static_cast<u8>(LogHttpMethod::Head) &&
           conn.req_http_version == static_cast<u8>(HttpVersion::Http11) &&
           (explicit_close_shape || default_keep_alive_shape) &&
           !conn.req_client_has_content_length && !conn.tls_active &&
           !conn.req_client_has_transfer_encoding && !conn.req_client_has_te &&
           !conn.req_client_has_expect && !conn.req_client_has_upgrade_header &&
           conn.protocol == ConnProtocol::Http11 && conn.req_path_canon.ptr != nullptr &&
           conn.req_body_mode == BodyMode::None && conn.req_body_remaining == 0 &&
           !conn.request_body_fully_buffered && !conn.req_malformed && !conn.req_wants_upgrade &&
           conn.req_header_override_count == 0 && !conn.req_header_override_overflow &&
           conn.resp_header_mutation_count == 0 && conn.resp_header_mutation_pending_count == 0 &&
           !conn.resp_header_mutation_pending_overflow && !conn.resp_header_mutation_overflow &&
           conn.pipeline_stash_len == 0 && conn.req_initial_send_len != 0 &&
           conn.recv_buf.len() == conn.req_initial_send_len;
}

inline ResponseReadDeadlineProfile classify_response_read_deadline_profile(
    const Connection& conn,
    const ForwardResponsePolicySpec& response,
    const ForwardFailurePolicySpec& failure,
    const ForwardFailurePolicySpec& timeout) {
    const bool common = response.version == ResponsePolicyVersion::Http11 &&
                        response.framing == ResponsePolicyFraming::ContentLength &&
                        response.connection == ResponsePolicyConnection::Request &&
                        failure.version == ForwardFailurePolicyVersion::Http11 &&
                        failure.status_code == kStatusBadGateway &&
                        failure.connection == ForwardFailurePolicyConnection::Request &&
                        timeout.version == ForwardFailurePolicyVersion::Http11 &&
                        timeout.connection == ForwardFailurePolicyConnection::Request;
    if (!common) return ResponseReadDeadlineProfile::None;

    if (response.head_mode == ResponsePolicyHeadMode::SuppressBody &&
        failure.head_mode == FailurePolicyHeadMode::SuppressBody &&
        timeout.head_mode == FailurePolicyHeadMode::SuppressBody &&
        response_policy_suppress_head_admitted(conn, response, /*paired_failure=*/true))
        return ResponseReadDeadlineProfile::HeaderOnlyHead;

    // A bounded fixed-upload profile keeps the complete request private until
    // the request policy has rebuilt it and the exact bytes have been sent on a
    // fresh upstream connection.  It deliberately shares the non-HEAD CL0
    // response contract, but has a distinct identity so no bodyless predicate
    // can manufacture upload completion.
    ResponseReadDeadlineFixedUploadRequest fixed_upload{};
    if (response.head_mode == ResponsePolicyHeadMode::Reject &&
        failure.head_mode == FailurePolicyHeadMode::Reject &&
        timeout.head_mode == FailurePolicyHeadMode::Reject &&
        response_read_deadline_fixed_upload_method_admitted(conn.req_method) &&
        conn.req_http_version == static_cast<u8>(HttpVersion::Http11) && conn.keep_alive &&
        conn.req_client_keep_alive && !conn.req_client_connection_close &&
        !conn.req_client_connection_close_exact && conn.req_client_connection_count == 0 &&
        conn.req_client_has_content_length && !conn.req_client_has_transfer_encoding &&
        !conn.req_client_has_te && !conn.req_client_has_expect &&
        !conn.req_client_has_upgrade_header && !conn.req_malformed && !conn.req_wants_upgrade &&
        conn.req_path_canon.ptr != nullptr && conn.req_body_mode == BodyMode::ContentLength &&
        !conn.request_body_fully_buffered && !conn.req_body_streamed &&
        conn.req_header_override_count == 0 && !conn.req_header_override_overflow &&
        conn.resp_header_mutation_count == 0 && conn.resp_header_mutation_pending_count == 0 &&
        !conn.resp_header_mutation_pending_overflow && !conn.resp_header_mutation_overflow &&
        conn.pipeline_depth == 0 && conn.pipeline_stash_len == 0 &&
        conn.protocol == ConnProtocol::Http11 && !conn.tls_active &&
        inspect_response_read_deadline_fixed_upload_request(conn, &fixed_upload) &&
        fixed_upload.header_end == conn.req_header_end &&
        fixed_upload.content_length == conn.req_content_length &&
        conn.req_initial_send_len == conn.recv_buf.len() &&
        conn.req_body_remaining == fixed_upload.total_length - conn.recv_buf.len())
        return ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;

    // The second admitted profile is deliberately a raw, bodyless HTTP/1.1
    // origin-form non-HEAD request with default persistence. Captured request
    // facts are authoritative after upload, so this same predicate can be
    // re-run without retaining a parser view into recv_buf.
    if (response.head_mode != ResponsePolicyHeadMode::Reject ||
        failure.head_mode != FailurePolicyHeadMode::Reject ||
        timeout.head_mode != FailurePolicyHeadMode::Reject ||
        !response_read_deadline_non_head_method_admitted(conn.req_method) ||
        conn.req_http_version != static_cast<u8>(HttpVersion::Http11) || !conn.keep_alive ||
        !conn.req_client_keep_alive || conn.req_client_connection_close ||
        conn.req_client_connection_close_exact || conn.req_client_connection_count != 0 ||
        conn.req_client_has_content_length || conn.req_client_has_transfer_encoding ||
        conn.req_client_has_te || conn.req_client_has_expect ||
        conn.req_client_has_upgrade_header || conn.req_malformed || conn.req_wants_upgrade ||
        conn.req_path_canon.ptr == nullptr || conn.req_body_mode != BodyMode::None ||
        conn.req_body_remaining != 0 || conn.request_body_fully_buffered ||
        conn.req_body_streamed || conn.req_header_override_count != 0 ||
        conn.req_header_override_overflow || conn.resp_header_mutation_count != 0 ||
        conn.resp_header_mutation_pending_count != 0 ||
        conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow ||
        conn.pipeline_stash_len != 0 || conn.protocol != ConnProtocol::Http11 || conn.tls_active)
        return ResponseReadDeadlineProfile::None;
    if (conn.recv_buf.data() == nullptr || conn.recv_buf.len() == 0)
        return ResponseReadDeadlineProfile::None;
    HttpParser parser;
    ParsedRequest request;
    parser.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &request) !=
            ParseStatus::Complete ||
        parser.header_end != conn.recv_buf.len() ||
        route_method_key(request.method) !=
            route_method_key(static_cast<LogHttpMethod>(conn.req_method)) ||
        request.version != HttpVersion::Http11 || request.path.ptr == nullptr ||
        request.path.len == 0 || request.path.ptr[0] != '/')
        return ResponseReadDeadlineProfile::None;
    u32 host_count = 0;
    for (u32 i = 0; i < request.header_count; ++i) {
        const Str name = request.headers[i].name;
        if (http_header_name_eq_ci(name.ptr, name.len, "host", 4)) {
            if (++host_count > 1 || request.headers[i].value.len == 0)
                return ResponseReadDeadlineProfile::None;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "connection", 10) ||
                   http_header_name_eq_ci(name.ptr, name.len, "content-length", 14) ||
                   http_header_name_eq_ci(name.ptr, name.len, "transfer-encoding", 17) ||
                   http_header_name_eq_ci(name.ptr, name.len, "te", 2) ||
                   http_header_name_eq_ci(name.ptr, name.len, "expect", 6) ||
                   http_header_name_eq_ci(name.ptr, name.len, "upgrade", 7)) {
            return ResponseReadDeadlineProfile::None;
        }
    }
    if (host_count != 1) return ResponseReadDeadlineProfile::None;
    return ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero;
}

inline u32 strict_response_dec(char* out, u32 value);
inline u32 strict_response_date(char* out, u64 now_us);

inline bool build_failure_policy_response_from_spec(const Connection& conn,
                                                    const ForwardFailurePolicySpec& policy,
                                                    bool suppress_body,
                                                    u8* out,
                                                    u32 out_cap,
                                                    u32* out_len) {
    if (out_len == nullptr) return false;
    *out_len = 0;
    if (out == nullptr) return false;
    u32 pos = 0;
    auto put = [&](const u8* data, u32 len) {
        if ((data == nullptr && len != 0) || len > out_cap - (pos <= out_cap ? pos : out_cap))
            return false;
        for (u32 i = 0; i < len; i++) out[pos + i] = data[i];
        pos += len;
        return true;
    };
    auto put_lit = [&](const char* text) {
        return put(reinterpret_cast<const u8*>(text), static_cast<u32>(__builtin_strlen(text)));
    };
    char status[3] = {static_cast<char>('0' + policy.status_code / 100),
                      static_cast<char>('0' + (policy.status_code / 10) % 10),
                      static_cast<char>('0' + policy.status_code % 10)};
    char date[32];
    char length[10];
    const u32 date_len = strict_response_date(date, realtime_us());
    const u32 length_len = strict_response_dec(length, policy.body.len);
    if (date_len == 0 || !put_lit("HTTP/1.1 ") || !put(reinterpret_cast<const u8*>(status), 3) ||
        !put_lit(" ") || !put(reinterpret_cast<const u8*>(policy.reason.ptr), policy.reason.len) ||
        !put_lit("\r\nServer: ") ||
        !put(reinterpret_cast<const u8*>(policy.server.ptr), policy.server.len) ||
        !put_lit("\r\nDate: ") || !put(reinterpret_cast<const u8*>(date), date_len) ||
        !put_lit("\r\nContent-Type: ") ||
        !put(reinterpret_cast<const u8*>(policy.content_type.ptr), policy.content_type.len) ||
        !put_lit("\r\nContent-Length: ") || !put(reinterpret_cast<const u8*>(length), length_len) ||
        !put_lit("\r\nConnection: "))
        return false;
    // Body disposition and downstream persistence are orthogonal: paired HEAD
    // suppresses configured representation bytes, while connection: request
    // still follows the parsed client request's lifetime.
    const bool keep_alive = conn.keep_alive && conn.req_client_keep_alive;
    if (!put_lit(keep_alive ? "keep-alive\r\n\r\n" : "close\r\n\r\n") ||
        (!suppress_body && !put(reinterpret_cast<const u8*>(policy.body.ptr), policy.body.len)))
        return false;
    *out_len = pos;
    return true;
}

inline bool build_failure_policy_response(const Connection& conn,
                                          const RouteConfig& config,
                                          bool suppress_body,
                                          u8* out,
                                          u32 out_cap,
                                          u32* out_len) {
    if (out_len != nullptr) *out_len = 0;
    if (conn.failure_policy_id == 0 || !config.failure_policy_id_is_valid(conn.failure_policy_id))
        return false;
    return build_failure_policy_response_from_spec(
        conn,
        config.failure_policies[conn.failure_policy_id - 1],
        suppress_body,
        out,
        out_cap,
        out_len);
}

inline bool build_timeout_failure_policy_response(const Connection& conn,
                                                  const RouteConfig& config,
                                                  bool suppress_body,
                                                  u8* out,
                                                  u32 out_cap,
                                                  u32* out_len) {
    if (out_len != nullptr) *out_len = 0;
    if (conn.timeout_failure_policy_id == 0 ||
        !config.timeout_failure_policy_id_is_valid(conn.timeout_failure_policy_id))
        return false;
    return build_failure_policy_response_from_spec(
        conn,
        config.failure_policies[conn.timeout_failure_policy_id - 1],
        suppress_body,
        out,
        out_cap,
        out_len);
}

template <typename Loop>
inline void respond_upstream_connect_failure(Loop* loop, Connection& conn) {
    if constexpr (requires(Loop* candidate, Connection& c) {
                      candidate->disarm_response_read_deadline(c);
                  }) {
        loop->disarm_response_read_deadline(conn);
    } else {
        conn.clear_response_read_deadline();
        conn.response_read_deadline_first_batch = false;
    }
    conn.upstream_abandoned = true;
    conn.upstream_keep_alive = false;
    conn.upstream_start_us = 0;
    conn.set_slots(nullptr, nullptr, nullptr, nullptr);
    if constexpr (requires { loop->discard_upstream_send(conn); }) {
        loop->discard_upstream_send(conn);
    }
    (void)detach_upstream_close(loop, conn);
    release_upstream_slot(loop, conn);

    bool serialized = false;
    if (conn.failure_policy_id != 0 && conn.request_config != nullptr) {
        // Build off-buffer so a capacity/date failure cannot publish a partial
        // policy response or accidentally fall through to the legacy body.
        u8 scratch[SlicePool::kSliceSize];
        u32 serialized_len = 0;
        if (build_failure_policy_response(conn,
                                          *conn.request_config,
                                          conn.failure_policy_suppress_body,
                                          scratch,
                                          sizeof(scratch),
                                          &serialized_len) &&
            serialized_len <= conn.send_buf.capacity()) {
            conn.send_buf.reset();
            serialized = conn.send_buf.write(scratch, serialized_len) == serialized_len;
        }
        if (serialized) conn.keep_alive = conn.keep_alive && conn.req_client_keep_alive;
    }
    if (!serialized) {
        // A selected policy is never silently approximated by the legacy
        // 11-byte response.  The fallback remains for policy-free Forward.
        if (conn.failure_policy_id != 0) {
            loop->close_conn(conn);
            return;
        }
        static constexpr char k502[] =
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Length: 11\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Bad Gateway";
        conn.send_buf.reset();
        if (conn.send_buf.write(reinterpret_cast<const u8*>(k502), sizeof(k502) - 1) !=
            sizeof(k502) - 1) {
            loop->close_conn(conn);
            return;
        }
        conn.keep_alive = false;
    }
    conn.resp_status = kStatusBadGateway;
    conn.transition_to_sending(&on_response_sent<Loop>);
    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
}

inline bool strict_response_forbidden(Str name) {
    if (response_policy_name_eq(name, "keep-alive", 10) || response_policy_name_eq(name, "te", 2) ||
        response_policy_name_eq(name, "trailer", 7) ||
        response_policy_name_eq(name, "transfer-encoding", 17) ||
        response_policy_name_eq(name, "upgrade", 7) ||
        response_policy_name_eq(name, "proxy-connection", 16) ||
        response_policy_name_eq(name, "location", 8) ||
        response_policy_name_eq(name, "refresh", 7) ||
        response_policy_name_eq(name, "content-type", 12) ||
        response_policy_name_eq(name, "last-modified", 13))
        return true;
    if (name.len >= 8 && http_header_name_eq_ci(name.ptr, 8, "x-accel-", 8)) return true;
    return false;
}

inline bool response_policy_hides(const ForwardResponsePolicySpec& policy, Str name) {
    for (u32 i = 0; i < policy.hide_header_count; i++) {
        const Str hidden = policy.hide_headers[i];
        if (hidden.len == name.len &&
            http_header_name_eq_ci(hidden.ptr, hidden.len, name.ptr, name.len))
            return true;
    }
    return false;
}

inline u32 strict_response_dec(char* out, u32 value) {
    char tmp[10];
    u32 n = 0;
    do {
        tmp[n++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    } while (value != 0);
    for (u32 i = 0; i < n; i++) out[i] = tmp[n - i - 1];
    return n;
}

inline u32 strict_response_date(char* out, u64 now_us) {
    static constexpr const char* kWeek[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr const char* kMonth[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    time_t t = static_cast<time_t>(now_us / 1000000ULL);
    struct tm tm;
    if (gmtime_r(&t, &tm) == nullptr) return 0;
    char* p = out;
    auto two = [&](int v) {
        *p++ = static_cast<char>('0' + v / 10);
        *p++ = static_cast<char>('0' + v % 10);
    };
    for (const char* s = kWeek[tm.tm_wday]; *s; ++s) *p++ = *s;
    *p++ = ',';
    *p++ = ' ';
    two(tm.tm_mday);
    *p++ = ' ';
    for (const char* s = kMonth[tm.tm_mon]; *s; ++s) *p++ = *s;
    *p++ = ' ';
    int year = tm.tm_year + 1900;
    *p++ = static_cast<char>('0' + year / 1000);
    *p++ = static_cast<char>('0' + (year / 100) % 10);
    *p++ = static_cast<char>('0' + (year / 10) % 10);
    *p++ = static_cast<char>('0' + year % 10);
    *p++ = ' ';
    two(tm.tm_hour);
    *p++ = ':';
    two(tm.tm_min);
    *p++ = ':';
    two(tm.tm_sec);
    *p++ = ' ';
    *p++ = 'G';
    *p++ = 'M';
    *p++ = 'T';
    return static_cast<u32>(p - out);
}

struct RedirectAuthorityView {
    Str value{};
    bool has_port = false;
};

inline bool redirect_name_eq(Str name, const char* literal, u32 literal_len) {
    return name.len == literal_len &&
           http_header_name_eq_ci(name.ptr, name.len, literal, literal_len);
}

inline bool redirect_connection_close(Str value) {
    u32 start = 0;
    while (start < value.len && (value.ptr[start] == ' ' || value.ptr[start] == '\t')) start++;
    u32 end = value.len;
    while (end > start && (value.ptr[end - 1] == ' ' || value.ptr[end - 1] == '\t')) end--;
    return end - start == 5 && http_header_name_eq_ci(value.ptr + start, 5, "close", 5);
}

inline bool redirect_authority_valid(Str value, u16 actual_port, RedirectAuthorityView* out) {
    if (out == nullptr || value.ptr == nullptr || value.len == 0 || value.len > 255 ||
        actual_port == 0)
        return false;
    u32 colon = value.len;
    for (u32 i = 0; i < value.len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        if (c <= 0x20 || c == 0x7f || c == '/' || c == '?' || c == '#' || c == '@' || c == '[' ||
            c == ']' || c == ',' || c == '\\')
            return false;
        if (c == ':') {
            if (colon != value.len) return false;
            colon = i;
        }
    }
    if (colon == 0) return false;
    const bool has_port = colon != value.len;
    if (has_port) {
        if (colon + 1 == value.len) return false;
        u32 parsed = 0;
        for (u32 i = colon + 1; i < value.len; i++) {
            const u8 c = static_cast<u8>(value.ptr[i]);
            if (c < '0' || c > '9') return false;
            if (parsed > 6553u || (parsed == 6553u && c > '5')) return false;
            parsed = parsed * 10u + static_cast<u32>(c - '0');
        }
        if (parsed == 0 || parsed != actual_port) return false;
    }
    const u32 host_len = has_port ? colon : value.len;
    for (u32 i = 0; i < host_len; i++) {
        const u8 c = static_cast<u8>(value.ptr[i]);
        const bool alpha_num =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!alpha_num && c != '.' && c != '-' && c != '_') return false;
    }
    out->value = value;
    out->has_port = has_port;
    return true;
}

inline bool redirect_origin_request_valid(const Connection& conn,
                                          ParsedRequest* out_req,
                                          u32* out_target_start,
                                          u32* out_path_len,
                                          u32* out_query_len,
                                          RedirectAuthorityView* out_authority) {
    if (out_req == nullptr || out_target_start == nullptr || out_path_len == nullptr ||
        out_query_len == nullptr || out_authority == nullptr || conn.recv_slice == nullptr ||
        conn.recv_buf.data() != conn.recv_slice || conn.recv_buf.len() == 0 ||
        conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
        conn.req_header_end == 0 || conn.recv_buf.len() != conn.req_header_end)
        return false;
    HttpParser parser;
    parser.reset();
    if (parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), out_req) != ParseStatus::Complete ||
        parser.header_end != conn.req_header_end || out_req->method != HttpMethod::GET ||
        out_req->version != HttpVersion::Http11 || out_req->has_content_length ||
        out_req->chunked || out_req->upgrade || out_req->has_upgrade_header)
        return false;
    const uintptr_t base = reinterpret_cast<uintptr_t>(conn.recv_buf.data());
    const uintptr_t path_addr = reinterpret_cast<uintptr_t>(out_req->path.ptr);
    if (path_addr < base || path_addr - base > conn.recv_buf.len() ||
        out_req->path.len > conn.recv_buf.len() - static_cast<u32>(path_addr - base))
        return false;
    const u32 target_start = static_cast<u32>(path_addr - base);
    const u32 target_len = out_req->path.len;
    if (target_len == 0 || out_req->path.ptr[0] != '/') return false;

    u32 host_count = 0;
    u32 connection_count = 0;
    const Header* host = nullptr;
    for (u32 i = 0; i < out_req->header_count; i++) {
        const Header& header = out_req->headers[i];
        if (redirect_name_eq(header.name, "host", 4)) {
            if (++host_count > 1) return false;
            host = &header;
        } else if (redirect_name_eq(header.name, "connection", 10)) {
            if (++connection_count > 1 || !redirect_connection_close(header.value)) return false;
        } else if (redirect_name_eq(header.name, "content-length", 14) ||
                   redirect_name_eq(header.name, "transfer-encoding", 17) ||
                   redirect_name_eq(header.name, "te", 2) ||
                   redirect_name_eq(header.name, "expect", 6) ||
                   redirect_name_eq(header.name, "upgrade", 7)) {
            return false;
        }
    }
    if (host_count != 1 || connection_count != 1 || host == nullptr ||
        !redirect_authority_valid(host->value, conn.listener_context.port, out_authority))
        return false;

    u32 path_len = target_len;
    for (u32 i = 0; i < target_len; i++) {
        const u8 c = static_cast<u8>(out_req->path.ptr[i]);
        if (c == '?') {
            path_len = i;
            break;
        }
        if (c == '#' || c < 0x21 || c == 0x7f) return false;
    }
    for (u32 i = path_len; i < target_len; i++) {
        const u8 c = static_cast<u8>(out_req->path.ptr[i]);
        if (c == '#' || c < 0x21 || c == 0x7f) return false;
    }
    if (path_len == 0) return false;
    *out_target_start = target_start;
    *out_path_len = path_len;
    *out_query_len = target_len - path_len;
    return true;
}

inline bool build_redirect_response(const Connection& conn,
                                    const RouteConfig& config,
                                    u16 policy_id,
                                    u8* out,
                                    u32 out_cap,
                                    u32* out_len) {
    if (out_len == nullptr) return false;
    *out_len = 0;
    if (out == nullptr || conn.tls_active || !conn.listener_context.valid() ||
        conn.listener_context.transport != ListenerTransport::Cleartext ||
        !config.redirect_policy_id_is_valid(policy_id))
        return false;
    const auto& policy = config.redirect_policies[policy_id - 1];
    if (!redirect_policy_spec_valid(policy)) return false;

    ParsedRequest req{};
    u32 target_start = 0, path_len = 0, query_len = 0;
    RedirectAuthorityView authority{};
    if (!redirect_origin_request_valid(
            conn, &req, &target_start, &path_len, &query_len, &authority))
        return false;

    char status[3] = {static_cast<char>('0' + policy.status_code / 100),
                      static_cast<char>('0' + (policy.status_code / 10) % 10),
                      static_cast<char>('0' + policy.status_code % 10)};
    char date[32];
    char body_len[10];
    char actual_port[10];
    const u32 date_len = strict_response_date(date, realtime_us());
    const u32 body_len_digits = strict_response_dec(body_len, policy.body.len);
    const u32 actual_port_digits = strict_response_dec(actual_port, conn.listener_context.port);
    if (date_len == 0 || actual_port_digits == 0) return false;

    const u32 authority_len =
        authority.value.len + (authority.has_port ? 0u : 1u + actual_port_digits);
    u64 required = 0;
    auto add = [&](u64 n) {
        if (n > 0xffffffffu - required) return false;
        required += n;
        return true;
    };
    static constexpr char kLocationPrefix[] = "\r\nLocation: http://";
    static constexpr char kTail[] = "\r\nConnection: close\r\n\r\n";
    if (!add(9 + 3 + 1 + policy.reason.len + 2) || !add(10 + policy.server.len) ||
        !add(8 + date_len) || !add(16 + policy.content_type.len) || !add(18 + body_len_digits) ||
        !add(sizeof(kLocationPrefix) - 1 + authority_len) ||
        !add(policy.target_path.len + query_len) || !add(sizeof(kTail) - 1) ||
        !add(policy.body.len) || required > out_cap)
        return false;

    u32 pos = 0;
    auto put = [&](const void* data, u32 len) {
        if (len > out_cap - pos) return false;
        if (len != 0) __builtin_memcpy(out + pos, data, len);
        pos += len;
        return true;
    };
    auto put_lit = [&](const char* value) {
        return put(value, static_cast<u32>(__builtin_strlen(value)));
    };
    if (!put_lit("HTTP/1.1 ") || !put(status, 3) || !put_lit(" ") ||
        !put(policy.reason.ptr, policy.reason.len) || !put_lit("\r\nServer: ") ||
        !put(policy.server.ptr, policy.server.len) || !put_lit("\r\nDate: ") ||
        !put(date, date_len) || !put_lit("\r\nContent-Type: ") ||
        !put(policy.content_type.ptr, policy.content_type.len) ||
        !put_lit("\r\nContent-Length: ") || !put(body_len, body_len_digits) ||
        !put(kLocationPrefix, sizeof(kLocationPrefix) - 1) ||
        !put(authority.value.ptr, authority.value.len) ||
        (!authority.has_port && (!put_lit(":") || !put(actual_port, actual_port_digits))) ||
        !put(policy.target_path.ptr, policy.target_path.len) ||
        !put(conn.recv_buf.data() + target_start + path_len, query_len) ||
        !put(kTail, sizeof(kTail) - 1) || !put(policy.body.ptr, policy.body.len))
        return false;
    *out_len = pos;
    return true;
}

inline bool stage_redirect_response(Connection& conn, const RouteConfig& config, u16 policy_id) {
    u8 scratch[SlicePool::kSliceSize];
    const u32 cap =
        conn.send_buf.capacity() < sizeof(scratch) ? conn.send_buf.capacity() : sizeof(scratch);
    u32 len = 0;
    if (!build_redirect_response(conn, config, policy_id, scratch, cap, &len)) return false;
    conn.send_buf.reset();
    return conn.send_buf.write(scratch, len) == len;
}

inline bool build_strict_response_headers(Connection& conn,
                                          const RouteConfig& config,
                                          const ParsedResponse& resp) {
    if (conn.response_policy_id == 0 || conn.response_policy_id > config.response_policy_count)
        return false;
    const auto& policy = config.response_policies[conn.response_policy_id - 1];
    if (!response_policy_spec_valid(policy) || resp.version != HttpVersion::Http11 ||
        resp.status_code < 200 || resp.status_code > 599 || resp.status_code == 204 ||
        resp.status_code == 205 || resp.status_code == 304 || resp.headers_truncated ||
        resp.content_length_count != 1 || !resp.has_content_length || resp.chunked ||
        resp.reason.len == 0)
        return false;
    for (u32 i = 0; i < resp.reason.len; i++) {
        const u8 c = static_cast<u8>(resp.reason.ptr[i]);
        if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
    }
    u32 connection_count = 0;
    for (u32 i = 0; i < resp.header_count; i++) {
        const Str name = resp.headers[i].name;
        if (response_policy_name_eq(name, "connection", 10)) {
            // The policy always synthesizes the sole downstream Connection
            // field. Consume at most one upstream field; duplicate hop-by-hop
            // metadata is ambiguous and remains fail-closed.
            if (++connection_count > 1) return false;
        } else if (strict_response_forbidden(name)) {
            return false;
        }
    }
    conn.response_header_buf.reset();
    auto put = [&](const char* p, u32 n) {
        return conn.response_header_buf.write(reinterpret_cast<const u8*>(p), n) == n;
    };
    auto put_lit = [&](const char* p) { return put(p, static_cast<u32>(__builtin_strlen(p))); };
    char num[10];
    char line[32];
    line[0] = static_cast<char>('0' + resp.status_code / 100);
    line[1] = static_cast<char>('0' + (resp.status_code / 10) % 10);
    line[2] = static_cast<char>('0' + resp.status_code % 10);
    if (!put_lit("HTTP/1.1 ") || !put(line, 3) || !put_lit(" ") ||
        !put(resp.reason.ptr, resp.reason.len) || !put_lit("\r\nServer: ") ||
        !put(policy.server.ptr, policy.server.len) || !put_lit("\r\nDate: "))
        return false;
    char date[32];
    const u32 date_len = strict_response_date(date, realtime_us());
    if (date_len == 0 || !put(date, date_len) || !put_lit("\r\nContent-Length: ")) return false;
    const u32 num_len = strict_response_dec(num, resp.content_length);
    if (!put(num, num_len) || !put_lit("\r\nConnection: ")) return false;
    const bool policy_keep_alive =
        policy.connection == ResponsePolicyConnection::KeepAlive ||
        (policy.connection == ResponsePolicyConnection::Request && conn.req_client_keep_alive);
    // Preserve the server lifecycle gate set at the request boundary: a
    // draining connection must not be reopened by a response policy intent.
    const bool effective_keep_alive = conn.keep_alive && policy_keep_alive;
    conn.keep_alive = effective_keep_alive;
    if (!put_lit(effective_keep_alive ? "keep-alive\r\n" : "close\r\n")) return false;
    for (u32 i = 0; i < resp.header_count; i++) {
        const Header& h = resp.headers[i];
        if (response_policy_name_eq(h.name, "connection", 10) ||
            response_policy_name_eq(h.name, "date", 4) ||
            response_policy_name_eq(h.name, "server", 6) ||
            response_policy_name_eq(h.name, "content-length", 14) ||
            response_policy_hides(policy, h.name))
            continue;
        if (!put(h.name.ptr, h.name.len) || !put_lit(": ")) return false;
        u32 start = 0;
        while (start < h.raw_value.len &&
               (h.raw_value.ptr[start] == ' ' || h.raw_value.ptr[start] == '\t'))
            start++;
        if (!put(h.raw_value.ptr + start, h.raw_value.len - start) || !put_lit("\r\n"))
            return false;
    }
    return put_lit("\r\n");
}

template <typename Loop>
inline bool abandon_strict_upstream(Loop* loop, Connection& conn) {
    // Publish abandonment before closing the fd so late CQEs cannot dispatch
    // into the old upstream callback. Detach every callback/epoll state before
    // the downstream response is sent, and release the slot exactly once.
    conn.upstream_abandoned = true;
    conn.upstream_keep_alive = false;
    conn.set_slots(nullptr, nullptr, nullptr, nullptr);
    if constexpr (requires { loop->begin_strict_upstream_retirement(conn); }) {
        // io_uring's strict path must establish its recv-only drain ownership
        // before close clears the old armed state. Failure means the bounded C1
        // preconditions were not proven: close the entire request rather than
        // publish a response over an unsafe retirement.
        if (!loop->begin_strict_upstream_retirement(conn)) {
            loop->close_conn(conn);
            return false;
        }
    }
    if constexpr (requires { loop->discard_upstream_send(conn); }) {
        loop->discard_upstream_send(conn);
    }
    (void)detach_upstream_close(loop, conn);
    release_upstream_slot(loop, conn);
    return true;
}

enum class StrictResponseRejectionCause : u8 {
    Default = 0,
    UpstreamParse,
};

template <typename Loop>
inline bool try_prebuilt_strict_parse_failure(Loop* loop, Connection& conn) {
    if constexpr (!requires(Loop* candidate, Connection& c) {
                      candidate->begin_prebuilt_http1_response(
                          c, u8{}, Http1RequestBufferDisposition::ExistingPipeline, u32{});
                  }) {
        return false;
    } else {
        // This is deliberately narrower than the general strict rejection
        // path.  Only the paired, reusable, bodyless HEAD contract may publish
        // its configured 502 while an old recv episode drains through D2.
        // Every check before scratch serialization is mutation-free.
        if (conn.upstream_recv_buf.len() == 0 || conn.request_config == nullptr ||
            conn.response_policy_id == 0 || conn.failure_policy_id == 0 ||
            !conn.request_config->response_policy_id_is_valid(conn.response_policy_id) ||
            !conn.request_config->failure_policy_id_is_valid(conn.failure_policy_id) ||
            !conn.response_policy_suppress_body || !conn.failure_policy_suppress_body ||
            conn.protocol != ConnProtocol::Http11 || conn.tls_active ||
            conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
            conn.req_method != static_cast<u8>(LogHttpMethod::Head) || !conn.keep_alive ||
            !conn.req_client_keep_alive || conn.req_client_connection_close ||
            conn.req_client_connection_close_exact || conn.req_client_connection_count != 0 ||
            conn.req_client_has_content_length || conn.req_client_has_transfer_encoding ||
            conn.req_client_has_te || conn.req_client_has_expect ||
            conn.req_client_has_upgrade_header || conn.req_malformed || conn.req_wants_upgrade ||
            conn.req_header_override_count != 0 || conn.req_header_override_overflow ||
            conn.resp_header_mutation_count != 0 || conn.resp_header_mutation_pending_count != 0 ||
            conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow ||
            conn.req_body_mode != BodyMode::None || conn.req_body_remaining != 0 ||
            conn.req_body_streamed || conn.state != ConnState::Proxying || conn.req_start_us == 0 ||
            conn.proxy_resp_started || conn.resp_body_sent != 0 || conn.send_progress != 0 ||
            conn.send_armed || conn.on_send != nullptr || !conn.request_upload_complete ||
            conn.upstream_request_incomplete || conn.upstream_connect_armed ||
            conn.upstream_send_armed || conn.response_header_buf.is_released() ||
            !conn.response_header_buf.valid())
            return false;

        const auto& response = conn.request_config->response_policies[conn.response_policy_id - 1];
        const auto& failure = conn.request_config->failure_policies[conn.failure_policy_id - 1];
        if (response.version != ResponsePolicyVersion::Http11 ||
            response.framing != ResponsePolicyFraming::ContentLength ||
            response.connection != ResponsePolicyConnection::Request ||
            response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
            failure.version != ForwardFailurePolicyVersion::Http11 ||
            failure.status_code != kStatusBadGateway ||
            failure.connection != ForwardFailurePolicyConnection::Request ||
            failure.head_mode != FailurePolicyHeadMode::SuppressBody)
            return false;

        u8 scratch[SlicePool::kSliceSize];
        u32 header_len = 0;
        if (!build_failure_policy_response(conn,
                                           *conn.request_config,
                                           /*suppress_body=*/true,
                                           scratch,
                                           sizeof(scratch),
                                           &header_len) ||
            header_len == 0 || header_len > conn.response_header_buf.capacity())
            return false;

        // Serialization and capacity are now proven.  Publish the exact
        // header-only failure state before transferring ownership to D2.
        conn.response_header_buf.reset();
        if (conn.response_header_buf.write(scratch, header_len) != header_len) {
            loop->close_conn(conn);
            return true;
        }
        conn.resp_status = kStatusBadGateway;
        conn.resp_body_mode = BodyMode::None;
        conn.resp_body_remaining = 0;
        conn.resp_body_sent = 0;
        conn.upstream_send_len = 0;

        const u8 selected_targets = conn.upstream_recv_armed ? kUpstreamOpRecv : static_cast<u8>(0);
        if (!loop->begin_prebuilt_http1_response(conn,
                                                 selected_targets,
                                                 Http1RequestBufferDisposition::ExistingPipeline,
                                                 conn.retry_req_send_len)) {
            // D2 may already have closed on an episode-exhaustion or submit
            // failure.  Do not run close bookkeeping twice.
            if (conn.fd >= 0) loop->close_conn(conn);
            return true;
        }
        // Invalid origin bytes are no longer authoritative after D2 owns the
        // complete downstream header and the old upstream episode.
        conn.upstream_recv_buf.reset();
        return true;
    }
}

template <typename Loop>
inline void reject_strict_response(
    Loop* loop,
    Connection& conn,
    StrictResponseRejectionCause cause = StrictResponseRejectionCause::Default) {
    // Only a non-empty parser error has the bounded D2 admission below. Every
    // other reusable paired HEAD rejection still closes before detaching,
    // clearing callbacks, or staging downstream bytes.
    if (conn.failure_policy_suppress_body) {
        if (cause == StrictResponseRejectionCause::UpstreamParse &&
            try_prebuilt_strict_parse_failure(loop, conn))
            return;
        loop->close_conn(conn);
        return;
    }
    if (!abandon_strict_upstream(loop, conn)) return;
    static const char k502[] =
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n"
        "Connection: close\r\n\r\nBad Gateway";
    conn.send_buf.reset();
    conn.send_buf.write(reinterpret_cast<const u8*>(k502), sizeof(k502) - 1);
    conn.keep_alive = false;
    conn.resp_status = kStatusBadGateway;
    conn.upstream_keep_alive = false;
    conn.transition_to_sending(&on_response_sent<Loop>);
    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
}

template <typename Loop>
void on_upstream_response(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    const bool explicit_first_batch = conn.response_read_deadline_first_batch;
    const bool explicit_progress_batch =
        conn.response_read_deadline_state == ResponseReadDeadlineState::BatchPending;
    const ResponseReadDeadlineProfile explicit_profile =
        explicit_progress_batch ? conn.response_read_deadline_profile
                                : conn.response_read_deadline_first_batch_profile;
    const u32 explicit_generation = explicit_progress_batch
                                        ? conn.response_read_deadline_generation
                                        : conn.response_read_deadline_first_batch_generation;
    const u16 explicit_bundle_id = explicit_progress_batch
                                       ? conn.response_read_deadline_bundle_id
                                       : conn.response_read_deadline_first_batch_bundle_id;
    const ForwardResponseBufferingMode explicit_buffering =
        explicit_progress_batch ? conn.response_read_deadline_buffering
                                : conn.response_read_deadline_first_batch_buffering;
    const u8 explicit_method = explicit_progress_batch
                                   ? conn.response_read_deadline_method
                                   : conn.response_read_deadline_first_batch_method;
    const u8 explicit_route_method = explicit_progress_batch
                                         ? conn.response_read_deadline_route_method
                                         : conn.response_read_deadline_first_batch_route_method;
    const ResponseReadDeadlineUploadProof explicit_upload =
        explicit_progress_batch ? conn.response_read_deadline_upload
                                : conn.response_read_deadline_first_batch_upload;
    auto disarm_explicit_deadline = [&]() {
        if constexpr (requires(Loop* candidate, Connection& c) {
                          candidate->disarm_response_read_deadline(c);
                      }) {
            loop->disarm_response_read_deadline(conn);
        } else {
            conn.clear_response_read_deadline();
            conn.response_read_deadline_first_batch = false;
        }
    };

    // An old upstream CQE may still be delivered after strict HEAD has
    // abandoned and closed the backend. Never let a direct or backend-routed
    // late event re-enter parsing, release state twice, or append bytes.
    if (conn.upstream_abandoned) return;

    if (conn.upstream_start_us != 0) {
        conn.upstream_us = static_cast<u32>(monotonic_us() - conn.upstream_start_us);
        conn.upstream_start_us = 0;
    }

    if (ev.result <= 0 && conn.upstream_recv_buf.len() == 0) {
        if (explicit_first_batch || explicit_progress_batch) disarm_explicit_deadline();
        // Post-send first-recv EOF/RST with no response byte. For a reused pooled
        // socket whose origin FIN/RST landed just after take_idle's MSG_PEEK probe,
        // the request write completed locally and the dead socket only surfaces
        // here. on_upstream_request_sent kept recv_buf for the reused case, so an
        // idempotent request whose full bytes are still buffered can fall back to a
        // fresh connect (request_fully_resendable inside the helper enforces this, so
        // a streamed body upload is never replayed). Otherwise fail closed.
        if (retry_reused_upstream(loop, conn)) return;
        loop->close_conn(conn);
        return;
    }

    // A reused pooled socket proved healthy once it returned response bytes; record
    // success here rather than at synthetic connect time.
    if (conn.upstream_reused) {
        record_backend_result(
            conn.upstream_idx, conn.upstream_backend_idx, /*success=*/true, monotonic_us());
        conn.upstream_reused = false;
    }

    // A response byte is now in hand, so the request will not be replayed. Drop the
    // snapshot marker only when it is not also the offset to a stashed pipelined
    // suffix; pipeline_recover / the merged stash+late path clear it after copying
    // from that offset.
    // recv_buf is NOT touched here — it was already reset at request-sent, so any
    // bytes in it now are a genuine pipelined downstream request that must survive to
    // flow through pipeline_recover / pipeline_dispatch on the completion path.
    if (conn.pipeline_stash_len == 0) conn.retry_req_send_len = 0;

    HttpResponseParser resp_parser;
    ParsedResponse resp;
    resp.reset();
    resp_parser.reset();
    ParseStatus ps =
        resp_parser.parse(conn.upstream_recv_buf.data(), conn.upstream_recv_buf.len(), &resp);
    if (ps == ParseStatus::Incomplete) {
        if (ev.result <= 0)
            ps = ParseStatus::Error;
        else if (explicit_progress_batch) {
            if constexpr (requires(Loop* candidate, Connection& c, const IoEvent& event) {
                              candidate->continue_response_read_deadline_after_incomplete(c, event);
                          }) {
                if (!loop->continue_response_read_deadline_after_incomplete(conn, ev))
                    loop->close_conn(conn);
            } else {
                loop->close_conn(conn);
            }
            return;
        } else if (explicit_first_batch) {
            disarm_explicit_deadline();
            loop->close_conn(conn);
            return;
        } else {
            loop->submit_recv_upstream(conn);
            return;
        }
    }
    if (ps == ParseStatus::Error) {
        if (explicit_first_batch || explicit_progress_batch) disarm_explicit_deadline();
        if ((explicit_first_batch || explicit_progress_batch) &&
            (explicit_profile == ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
             explicit_profile ==
                 ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero)) {
            loop->close_conn(conn);
            return;
        }
        if (conn.response_policy_id != 0) {
            reject_strict_response(loop, conn, StrictResponseRejectionCause::UpstreamParse);
            return;
        }
        (void)detach_upstream_close_only(loop, conn);
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
        client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
        return;
    }

    if ((explicit_first_batch || explicit_progress_batch) &&
        (explicit_profile == ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
         explicit_profile ==
             ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero)) {
        const bool fixed_upload =
            explicit_profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
        const RouteConfig* config = conn.request_config;
        const bool owner_exact =
            explicit_generation != 0 &&
            explicit_generation == conn.response_read_deadline_generation &&
            explicit_bundle_id != 0 && config != nullptr &&
            config->policy_bundle_id_is_valid(explicit_bundle_id) &&
            config->response_policy_id_is_valid(conn.response_policy_id) &&
            config->failure_policy_id_is_valid(conn.failure_policy_id) &&
            config->timeout_failure_policy_id_is_valid(conn.timeout_failure_policy_id) &&
            config->policy_bundles[explicit_bundle_id - 1].response_policy_id ==
                conn.response_policy_id &&
            config->policy_bundles[explicit_bundle_id - 1].failure_policy_id ==
                conn.failure_policy_id &&
            config->policy_bundles[explicit_bundle_id - 1].timeout_failure_policy_id ==
                conn.timeout_failure_policy_id &&
            config->policy_bundles[explicit_bundle_id - 1].response_buffering ==
                explicit_buffering &&
            (explicit_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
             (complete_content_length_route_method_is_admitted(explicit_route_method) &&
              complete_content_length_request_policy_is_admitted(conn.request_policy_id) &&
              explicit_upload.request_policy_id == conn.request_policy_id)) &&
            response_read_timeout_seconds_valid(
                config->policy_bundles[explicit_bundle_id - 1].response_read_timeout_seconds) &&
            explicit_method == conn.req_method &&
            (fixed_upload ? response_read_deadline_fixed_upload_method_admitted(explicit_method) &&
                                response_read_deadline_fixed_upload_materialization_is_stable(
                                    conn,
                                    explicit_upload,
                                    /*require_upload_complete=*/true,
                                    explicit_bundle_id,
                                    explicit_route_method)
                          : response_read_deadline_non_head_method_admitted(explicit_method)) &&
            response_read_deadline_route_method_matches(explicit_method, explicit_route_method) &&
            config->response_policies[conn.response_policy_id - 1].head_mode ==
                ResponsePolicyHeadMode::Reject &&
            config->failure_policies[conn.failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::Reject &&
            config->failure_policies[conn.timeout_failure_policy_id - 1].head_mode ==
                FailurePolicyHeadMode::Reject;
        const bool strict_common =
            owner_exact && resp.version == HttpVersion::Http11 && resp.status_code == 200 &&
            resp.content_length_count == 1 && resp.has_content_length && !resp.chunked &&
            !resp.headers_truncated && resp_parser.header_end <= conn.upstream_recv_buf.len() &&
            conn.req_http_version == static_cast<u8>(HttpVersion::Http11) &&
            (fixed_upload ? conn.req_body_mode == BodyMode::ContentLength &&
                                conn.req_body_remaining == 0 && conn.request_body_fully_buffered
                          : conn.req_body_mode == BodyMode::None && conn.req_body_remaining == 0 &&
                                !conn.request_body_fully_buffered) &&
            !conn.req_body_streamed && !conn.response_policy_suppress_body &&
            !conn.failure_policy_suppress_body && conn.resp_header_mutation_count == 0 &&
            conn.resp_header_mutation_pending_count == 0 &&
            !conn.resp_header_mutation_pending_overflow && !conn.resp_header_mutation_overflow &&
            !conn.target_transform_recorded && !conn.req_path_overridden &&
            conn.req_header_override_count == 0 && !conn.req_header_override_overflow &&
            strict_response_upload_ready(conn);
        const u32 raw_header_end = resp_parser.header_end;
        const u32 raw_total = conn.upstream_recv_buf.len();
        const bool strict_cl0 =
            strict_common && resp.content_length == 0 && raw_header_end == raw_total;
        const bool strict_positive_complete_buffering =
            strict_common &&
            explicit_buffering == ForwardResponseBufferingMode::CompleteContentLength &&
            (fixed_upload
                 ? complete_content_length_fixed_upload_materialization_is_stable(
                       conn,
                       explicit_upload,
                       /*require_upload_complete=*/true,
                       explicit_bundle_id,
                       explicit_route_method)
                 : response_read_deadline_non_head_method_admitted(explicit_method) &&
                       complete_content_length_route_method_is_admitted(explicit_route_method) &&
                       response_read_deadline_route_method_matches(explicit_method,
                                                                   explicit_route_method)) &&
            resp.content_length > 0 && raw_header_end <= conn.upstream_recv_buf.capacity() &&
            resp.content_length <= conn.upstream_recv_buf.capacity() - raw_header_end &&
            raw_total - raw_header_end <= resp.content_length;
        const bool strict_positive_streaming_get =
            strict_common && !fixed_upload &&
            explicit_buffering == ForwardResponseBufferingMode::None &&
            explicit_method == static_cast<u8>(LogHttpMethod::Get) && resp.content_length > 0 &&
            raw_header_end <= conn.upstream_recv_buf.capacity() &&
            resp.content_length <= conn.upstream_recv_buf.capacity() - raw_header_end &&
            raw_total - raw_header_end <= resp.content_length;
        if (!strict_cl0 && !strict_positive_complete_buffering && !strict_positive_streaming_get) {
            disarm_explicit_deadline();
            loop->close_conn(conn);
            return;
        }

        // The origin frame is fully proven before any downstream response
        // status/header/persistence byte is materialized.
        conn.resp_status = 200;
        if (!build_strict_response_headers(conn, *config, resp)) {
            disarm_explicit_deadline();
            loop->close_conn(conn);
            return;
        }
        HttpResponseParser output_parser;
        ParsedResponse output_response;
        output_parser.reset();
        output_response.reset();
        const u32 output_len = conn.response_header_buf.len();
        if (output_parser.parse(conn.response_header_buf.data(), output_len, &output_response) !=
                ParseStatus::Complete ||
            output_response.version != HttpVersion::Http11 || output_response.status_code != 200 ||
            output_response.content_length_count != 1 ||
            output_response.content_length != resp.content_length || output_response.chunked ||
            output_parser.header_end != output_len) {
            disarm_explicit_deadline();
            loop->close_conn(conn);
            return;
        }

        if (strict_positive_complete_buffering || strict_positive_streaming_get) {
            if (strict_positive_complete_buffering) {
                if constexpr (requires(Loop* candidate,
                                       Connection& c,
                                       const IoEvent& event,
                                       u32 header_end,
                                       u32 declared) {
                                  candidate->begin_complete_content_length_buffering(
                                      c, event, header_end, declared);
                              }) {
                    if (!loop->begin_complete_content_length_buffering(
                            conn, ev, raw_header_end, resp.content_length)) {
                        loop->close_conn(conn);
                    }
                } else {
                    loop->close_conn(conn);
                }
                return;
            }
            if constexpr (requires(Loop* candidate,
                                   Connection& c,
                                   const IoEvent& event,
                                   u32 header_end,
                                   u32 declared) {
                              candidate->begin_response_read_deadline_body_stream(
                                  c, event, header_end, declared);
                          }) {
                if (!loop->begin_response_read_deadline_body_stream(
                        conn, ev, raw_header_end, resp.content_length)) {
                    loop->close_conn(conn);
                    return;
                }
            } else {
                loop->close_conn(conn);
                return;
            }
            conn.resp_status = 200;
            conn.resp_body_mode = BodyMode::ContentLength;
            conn.resp_body_remaining = resp.content_length;
            conn.resp_body_sent = conn.response_header_buf.len();
            conn.upstream_send_len = raw_header_end;
            conn.upstream_keep_alive = false;
            conn.proxy_resp_started = true;
            conn.transition_to_sending(&on_response_header_sent<Loop>);
            if (!client_send(
                    loop, conn, conn.response_header_buf.data(), conn.response_header_buf.len()))
                loop->close_conn(conn);
            return;
        }

        conn.http1_prebuilt_response_layout = Http1PrebuiltResponseLayout::FullContentLengthNonHead;
        conn.http1_prebuilt_response_purpose =
            Http1PrebuiltResponsePurpose::StrictNonHeadCl0Success;
        conn.http1_prebuilt_deadline_profile = explicit_profile;
        conn.http1_prebuilt_deadline_method = explicit_method;
        conn.http1_prebuilt_deadline_route_method = explicit_route_method;
        conn.http1_prebuilt_deadline_generation = explicit_generation;
        conn.http1_prebuilt_deadline_bundle_id = explicit_bundle_id;
        conn.http1_prebuilt_deadline_config = config;
        conn.http1_prebuilt_deadline_upload = explicit_upload;
        conn.http1_prebuilt_header_end = output_parser.header_end;
        conn.http1_prebuilt_total_len = output_len;
        conn.http1_prebuilt_body_len = 0;
        conn.http1_prebuilt_status = 200;
        conn.resp_body_mode = BodyMode::None;
        conn.resp_body_remaining = 0;
        conn.resp_body_sent = 0;
        conn.upstream_send_len = 0;
        disarm_explicit_deadline();
        const u8 selected_targets = conn.upstream_recv_armed ? kUpstreamOpRecv : static_cast<u8>(0);
        if constexpr (requires(Loop* candidate, Connection& c) {
                          candidate->begin_prebuilt_http1_response(
                              c, u8{}, Http1RequestBufferDisposition::ExistingPipeline, u32{});
                      }) {
            if (!loop->begin_prebuilt_http1_response(
                    conn,
                    selected_targets,
                    Http1RequestBufferDisposition::ExistingPipeline,
                    conn.retry_req_send_len)) {
                if (conn.fd >= 0) loop->close_conn(conn);
                return;
            }
        } else {
            loop->close_conn(conn);
            return;
        }
        conn.upstream_recv_buf.reset();
        return;
    }
    if (explicit_first_batch || explicit_progress_batch) disarm_explicit_deadline();
    conn.resp_status = resp.status_code;

    // A strict policy has no interim-response or Upgrade domain.  Reject all
    // 1xx statuses before the transparent interim-discard/WebSocket branches;
    // otherwise a 103/100 could be consumed and a later final response would
    // incorrectly make the policy appear successful.
    if (conn.response_policy_id != 0 && resp.status_code >= 100 && resp.status_code < 200) {
        reject_strict_response(loop, conn);
        return;
    }

#if RUT_ENABLE_WEBSOCKET
    // 101 Switching Protocols → WebSocket/Upgrade passthrough. Forward the 101
    // response plus any bytes the backend already sent (early frames) to the
    // client, then run the connection as a transparent full-duplex tunnel.
    if (resp.status_code == 101) {
        // The client→upstream request upload must be fully drained before we can
        // pivot the upstream send slot to the tunnel: otherwise a still-pending
        // request body send completion would be misread as a tunnel send (or
        // strand the upload). A gated upgrade (GET, no body) has nothing pending.
        const bool kReqUploadPending =
            (conn.req_body_mode == BodyMode::ContentLength && conn.req_body_remaining > 0) ||
            (conn.req_body_mode == BodyMode::Chunked &&
             conn.req_chunk_parser.state != ChunkedParser::State::Complete);
        if (!conn.req_wants_upgrade || kReqUploadPending) {
            // No client upgrade intent (a misbehaving/hostile backend trying to
            // hijack the connection — installing a tunnel would forward pipelined
            // bytes raw upstream), or the request upload is not finished. Refuse.
            loop->close_conn(conn);
            return;
        }
        // The 101 is authoritative for what was actually negotiated (the request's offer
        // is only a proposal). Record whether the backend selected WebSocket — terminate
        // arms on THIS, not the request — and refuse a response extension terminate can't
        // honor (ws_inspect rejects RSV1 compressed frames), so we never send the client a
        // 101 advertising an extension that would break the first compressed frame.
        conn.resp_upgrade_is_websocket = false;
        bool resp_has_ws_ext = false;
        for (u32 i = 0; i < resp.header_count; i++) {
            const Str nm = resp.headers[i].name;
            const Str vl = resp.headers[i].value;
            if (ws_value_has_token(nm.ptr, nm.len, "upgrade", 7)) {
                if (ws_value_has_token(vl.ptr, vl.len, "websocket", 9))
                    conn.resp_upgrade_is_websocket = true;
            } else if (ws_value_has_token(nm.ptr, nm.len, "sec-websocket-extensions", 24)) {
                if (vl.len > 0) resp_has_ws_ext = true;
            }
        }
        if (conn.is_ws_terminate_route && resp_has_ws_ext) {
            loop->close_conn(conn);  // backend negotiated an extension terminate can't process
            return;
        }
        conn.ws_upgrade_response_len = resp_parser.header_end;
        const u8* upgrade_response = conn.upstream_recv_buf.data();
        u32 upgrade_response_len = conn.ws_upgrade_response_len;
        if (conn.resp_header_mutation_count != 0) {
            if (!build_h1_forward_response_headers(
                    conn, conn.ws_upgrade_response_len, /*draining=*/false)) {
                loop->close_conn(conn);
                return;
            }
            upgrade_response = conn.response_header_buf.data();
            upgrade_response_len = conn.response_header_buf.len();
        }
        conn.ws_upgrade_sent_len = upgrade_response_len;
        conn.ws_pre_tunnel_upstream_closed = false;
        if (!ws_pause_upstream_recv(loop, conn)) {
            loop->close_conn(conn);
            return;
        }
        conn.transition_to_sending(&on_ws_101_sent<Loop>);
        conn.on_upstream_recv = &on_ws_pre_tunnel_upstream_recv<Loop>;
        if (!loop->submit_send(conn, upgrade_response, upgrade_response_len)) {
            loop->close_conn(conn);
            return;
        }
        // Stop reading from the client until the tunnel slots are installed: a
        // partial 101 send arms the client fd EPOLLIN|EPOLLOUT (and an io_uring
        // multishot recv may still be live), so client bytes arriving mid-drain
        // would dispatch with on_recv == nullptr. Use ws_stop_client_poll (not
        // ws_pause_client_recv) so epoll also drops EPOLLRDHUP — otherwise a
        // client FIN during a backpressured 101 send would spin the loop on
        // redelivered Recv/0. It preserves the 101 send's EPOLLOUT and cancels
        // the io_uring recv; on_ws_101_sent re-arms once the tunnel is up.
        ws_stop_client_poll(loop, conn);
        return;
    }
#endif

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

    if (conn.response_policy_id != 0) {
        // This profile is deliberately narrower than transparent forwarding:
        // only an origin-form HTTP/1.1 request may select it, and the final
        // response must be a strict self-framed HTTP/1.1 response. SuppressBody
        // is the one bounded HEAD exception; it commits headers only and
        // abandons the representation stream immediately after validation.
        if (conn.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
            (!conn.response_policy_suppress_body &&
             conn.req_method == static_cast<u8>(LogHttpMethod::Head)) ||
            (conn.response_policy_suppress_body &&
             conn.req_method != static_cast<u8>(LogHttpMethod::Head)) ||
            resp.status_code == 101 || (resp.status_code >= 100 && resp.status_code < 200) ||
            conn.resp_header_mutation_count != 0 || conn.resp_header_mutation_pending_count != 0 ||
            conn.resp_header_mutation_pending_overflow || conn.resp_header_mutation_overflow ||
            !conn.request_config || !strict_response_upload_ready(conn) ||
            (conn.upstream_recv_buf.len() > resp_parser.header_end &&
             conn.upstream_recv_buf.len() - resp_parser.header_end > resp.content_length) ||
            !build_strict_response_headers(conn, *conn.request_config, resp)) {
            reject_strict_response(loop, conn);
            return;
        }
        if (conn.response_policy_suppress_body &&
            (conn.upstream_recv_buf.len() < resp_parser.header_end ||
             conn.upstream_recv_buf.len() - resp_parser.header_end > resp.content_length)) {
            // A coalesced body may be absent or shorter than the advertised
            // representation; it is discarded below. Bytes beyond the exact
            // Content-Length are ambiguous and must fail before any header is
            // published downstream.
            reject_strict_response(loop, conn);
            return;
        }
        conn.resp_body_mode = BodyMode::ContentLength;
        conn.resp_body_remaining = resp.content_length;
        conn.upstream_keep_alive = conn.response_policy_suppress_body ? false : conn.req_keep_alive;
        const u32 header_len = resp_parser.header_end;
        conn.upstream_send_len = header_len;
        conn.resp_body_sent = conn.response_header_buf.len();
        conn.proxy_resp_started = true;
        if (conn.response_policy_suppress_body) {
            // The representation length remains in the synthesized headers,
            // but HEAD sends no representation bytes. Close and detach the
            // upstream before publishing those headers; a delayed body or
            // late CQE therefore cannot append bytes or release the slot twice.
            conn.upstream_recv_buf.reset();
            if (!abandon_strict_upstream(loop, conn)) return;
            conn.transition_to_sending(&on_proxy_response_sent<Loop>);
            client_send(
                loop, conn, conn.response_header_buf.data(), conn.response_header_buf.len());
            return;
        }
        const bool complete = conn.resp_body_remaining == 0;
        conn.transition_to_sending(complete ? &on_proxy_response_sent<Loop>
                                            : &on_response_header_sent<Loop>);
        client_send(loop, conn, conn.response_header_buf.data(), conn.response_header_buf.len());
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

    // Decide upstream idle-reuse eligibility now, while the parsed response is in
    // hand: reusable iff the upstream wants keep-alive and the body is self-framed
    // (None / Content-Length / chunked). A close-delimited (UntilClose) body ends
    // by the upstream closing the socket, so its fd is never reusable. The
    // completion path reads this flag to pool the fd vs. close it.
    // conn.req_keep_alive guards the REQUEST side: the proxy forwards the client's
    // request bytes (incl. its Connection header / HTTP version) verbatim upstream,
    // so a client Connection: close (or an HTTP/1.0 request) told the origin it may
    // close after responding — even if the response itself is self-framed HTTP/1.1
    // keep-alive. Pooling such an fd would race the origin's close, so refuse it.
    // NOTE: this must NOT be conn.keep_alive — that is derived from drain state
    // (set to !is_draining() in on_header_received), not the parsed request, so a
    // Connection: close request on a live shard still has conn.keep_alive == true.
    conn.upstream_keep_alive = resp.keep_alive && !resp.connection_close &&
                               conn.resp_body_mode != BodyMode::UntilClose && conn.req_keep_alive;

    const u32 kHeaderLen = resp_parser.header_end;
    const u32 kTotalLen = conn.upstream_recv_buf.len();
    const u32 kInitialBodyLen = (kTotalLen > kHeaderLen) ? kTotalLen - kHeaderLen : 0;

    if (conn.resp_header_mutation_count != 0) {
        // Keep the body in upstream_recv_buf while rewritten headers drain, but
        // validate any chunk bytes already received before committing a success
        // response downstream. The streaming callback will parse the same bytes
        // with the connection-owned parser after the header send completes.
        if (conn.resp_body_mode == BodyMode::Chunked && kInitialBodyLen > 0) {
            ChunkedParser probe = conn.resp_chunk_parser;
            const u8* body_start = conn.upstream_recv_buf.data() + kHeaderLen;
            u32 pos = 0;
            while (pos < kInitialBodyLen) {
                u32 consumed = 0, out_start = 0, out_len = 0;
                const ChunkStatus kChunkStatus = probe.feed(
                    body_start + pos, kInitialBodyLen - pos, &consumed, &out_start, &out_len);
                pos += consumed;
                if (kChunkStatus == ChunkStatus::Error) {
                    (void)detach_upstream_close_only(loop, conn);
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
                    client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                    return;
                }
                if (kChunkStatus == ChunkStatus::NeedMore || kChunkStatus == ChunkStatus::Done)
                    break;
            }
        }
        if (!build_h1_forward_response_headers(conn, kHeaderLen, loop->is_draining())) {
            loop->close_conn(conn);
            return;
        }
        conn.resp_body_sent = conn.response_header_buf.len();
        // Once the rewritten header send drains, consume only the ORIGINAL
        // upstream header. The body remains in upstream_recv_buf and enters the
        // normal streaming parser without needing header-growth headroom.
        conn.upstream_send_len = kHeaderLen;
        conn.proxy_resp_started = true;
        const bool no_body =
            conn.resp_body_mode == BodyMode::None ||
            (conn.resp_body_mode == BodyMode::ContentLength && conn.resp_body_remaining == 0);
        if (no_body)
            conn.transition_to_sending(&on_proxy_response_sent<Loop>);
        else
            conn.transition_to_sending(&on_response_header_sent<Loop>);
        client_send(loop, conn, conn.response_header_buf.data(), conn.response_header_buf.len());
        return;
    }

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
                (void)detach_upstream_close_only(loop, conn);
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
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
                return;
            }
            if (kChunkStatus == ChunkStatus::NeedMore) break;
        }
        chunked_consumed = pos;
    }

    // Refuse reuse if the upstream sent bytes beyond its self-framed body in this
    // initial buffer — an overlong/malformed response. We discard those extra bytes
    // at completion, so pooling the socket would mask the protocol violation and
    // risk desync. (On-wire leftover the backend sends later is separately caught by
    // take_idle's MSG_PEEK probe before any request goes out.)
    const bool kContentLenOverlong =
        conn.resp_body_mode == BodyMode::ContentLength && kInitialBodyLen > resp.content_length;
    const bool kChunkedOverlong = conn.resp_body_mode == BodyMode::Chunked && chunked_done &&
                                  chunked_consumed < kInitialBodyLen;
    // No-body responses (HEAD / 204 / 205 / 304) must have nothing after the
    // headers; any trailing bytes mean a desynced/malformed keep-alive backend.
    const bool kNoBodyOverlong = conn.resp_body_mode == BodyMode::None && kInitialBodyLen > 0;
    if (conn.upstream_keep_alive && (kContentLenOverlong || kChunkedOverlong || kNoBodyOverlong))
        conn.upstream_keep_alive = false;

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
                client_send(loop, conn, conn.send_buf.data(), conn.send_buf.len());
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

    // Response bytes are now headed to the client — past this point a timeout
    // cannot inject a 504 (the tick will close instead).
    conn.proxy_resp_started = true;

    if (body_complete) {
        conn.transition_to_sending(&on_proxy_response_sent<Loop>);
        client_send(loop, conn, conn.upstream_recv_buf.data(), initial_send_len);
    } else {
        conn.transition_to_sending(&on_response_header_sent<Loop>);
        client_send(loop, conn, conn.upstream_recv_buf.data(), initial_send_len);
    }
}

template <typename Loop>
void on_prebuilt_http1_header_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    if constexpr (requires {
                      loop->prebuilt_http1_header_send_completion_is_valid(conn, ev);
                      loop->complete_prebuilt_http1_header_send(conn);
                  }) {
        // io_uring's send proactor emits one completion only after the complete
        // header block drains. Validate the exact source/length before claiming
        // request completion; a stale, short, duplicate, or error event closes
        // with req_start_us still live.
        if (!loop->prebuilt_http1_header_send_completion_is_valid(conn, ev)) {
            loop->close_conn(conn);
            return;
        }
        conn.clear_slots();
        // Transfer the old request's epoch ownership before on_request_complete
        // clears req_start_us. Batch-end request-boundary admission releases it.
        conn.epoch_held = true;
        on_request_complete(loop, conn, conn.resp_status, conn.response_header_buf.len());
        if (!loop->complete_prebuilt_http1_header_send(conn)) {
            loop->close_conn(conn);
            return;
        }
    } else {
        // D2 is an internal io_uring seam only. Any accidental installation on
        // another loop fails closed rather than acquiring different semantics.
        loop->close_conn(conn);
    }
}

template <typename Loop>
void continue_http1_request_boundary(Loop* loop, Connection& conn) {
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
        conn.recv_buf.write(conn.send_buf.data() + conn.retry_req_send_len, kStashLen);
        conn.retry_req_send_len = 0;
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

template <typename Loop>
void on_proxy_response_sent(void* lp, Connection& conn, IoEvent ev) {
    auto* loop = static_cast<Loop*>(lp);
    conn.clear_slots();

    if (ev.result < 0) {
        loop->close_conn(conn);
        return;
    }

    if (conn.response_policy_id != 0 && !strict_response_upload_ready(conn)) {
        loop->close_conn(conn);
        return;
    }

    // One-shot proxy response complete (header-only / small Content-Length that
    // finished in the first read). Release the backend concurrency slot promptly
    // — like on_response_body_sent — so keep-alive clients don't pin the slot
    // until the downstream connection closes (which would make max_inflight=1
    // shed every subsequent request even with an idle backend).
    release_upstream_slot(loop, conn);

    on_request_complete(loop, conn, conn.resp_status, conn.resp_body_sent);
    loop->epoch_leave();

    if (loop->is_draining()) {
        loop->close_conn(conn);
        return;
    }

    // Strict response-policy upstreams are intentionally never pooled.  The
    // downstream HTTP/1.1 connection may remain keep-alive; only the backend
    // socket is closed by release_upstream_conn below.
    if (conn.response_policy_id != 0) conn.upstream_keep_alive = false;

    // Surplus upstream bytes beyond the one-shot response we sent
    // (upstream_send_len) mean a desynced stream — refuse reuse, mirroring
    // proxy_stream_complete. This covers bytes the backend wrote past its
    // self-framed body that wait() appended to upstream_recv_buf while the
    // downstream send was still draining (on_upstream_recv is null on this path,
    // so they'd otherwise be silently discarded by the reset below and the fd
    // pooled as reusable). A TLS proxy tail legitimately parks in this buffer.
    if (conn.upstream_recv_buf.len() > conn.upstream_send_len && !conn.tls_proxy_stream)
        conn.upstream_keep_alive = false;
    conn.upstream_recv_buf.reset();

    release_upstream_conn(loop, conn);  // pool for reuse if keep-alive, else close

    if (!conn.keep_alive) {
        loop->close_conn(conn);
        return;
    }

    // io_uring may still own the exact old upstream recv target plus its cancel.
    // Request 1 is fully accounted and detached above; park only the request-2
    // boundary tail until the loop publishes and consumes retirement readiness.
    if constexpr (requires { loop->defer_http1_request_boundary(conn); }) {
        if (loop->defer_http1_request_boundary(conn)) return;
    }

    continue_http1_request_boundary(loop, conn);
}

}  // namespace rut
