#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/access_log_live_producer.h"
#include "rut/runtime/callbacks.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_capacity.h"
#include "rut/runtime/drain.h"
#include "rut/runtime/error.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/io_uring_backend.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/mapped_array.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/rate_limit.h"
#include "rut/runtime/response_read_deadline.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/slab_pool.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/timer_wheel.h"
#include "rut/runtime/tls.h"
#include "rut/runtime/tls_iouring.h"
#include "rut/runtime/upstream_concurrency.h"
#include "rut/runtime/upstream_pool.h"
#include "rut/runtime/ws_splice_experiment.h"
#include <atomic>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <unistd.h>

namespace rut {

// A bounded one-shot upstream recv may fill the whole upstream receive slice
// from one dedicated provided buffer. A bulk-sized target instead recvs
// directly (add_recv_upstream_direct) — no ring, so no matching size assert.
static_assert(kLargeProvidedBufSize == SlicePool::kSliceSize);

namespace detail {

// Optional test-binary hook. Production binaries leave this weak symbol
// unresolved, so it cannot publish an owner or alter the event-loop layout.
[[gnu::weak]] bool test_fail_iouring_submit(u8 operation) noexcept;

inline bool injected_iouring_submit_failure(u8 operation) noexcept {
    return test_fail_iouring_submit != nullptr && test_fail_iouring_submit(operation);
}

// Optional test-binary hook for the idle-trim page release (see
// IoUringEventLoop::sweep_idle_trim). Production binaries leave it unresolved.
// Returns -1 to leave the step alone; any value >= 0 injects a fault:
//   IdleTrimPidfdOpen / IdleTrimProbeAdvise: the probe step fails;
//   IdleTrimBatchAdvise (arg = ranges in the chunk): only that many ranges are
//     submitted to process_madvise, so the return is short exactly as if an iovec
//     further in were bad; 0 makes the call fail hard (-1, EPERM), -2 makes it
//     fail softly (-1, EAGAIN);
//   IdleTrimSliceAdvise (arg = slice address): that per-slice madvise fails.
enum IdleTrimPoint : u8 {
    IdleTrimPidfdOpen = 1,
    IdleTrimProbeAdvise = 2,
    IdleTrimBatchAdvise = 3,
    IdleTrimSliceAdvise = 4,
};
[[gnu::weak]] i64 test_idle_trim_inject(u8 point, u64 arg) noexcept;

inline i64 idle_trim_inject(IdleTrimPoint point, u64 arg) noexcept {
    return test_idle_trim_inject != nullptr ? test_idle_trim_inject(point, arg) : -1;
}

inline constexpr u8 kTestIoUringConnectSubmit = 1;
inline constexpr u8 kTestIoUringStagedSendSubmit = 2;

}  // namespace detail

// Outcome of IoUringEventLoop::submit_send_file. Failed: the caller falls
// back to a memory send. Armed: an SQE is outstanding; the completion
// arrives through the proactor as usual. CompletedSync: a keep-alive body
// that finished in one sendfile(2) call — no SQE was queued (see
// IoUringBackend::add_send_file), so the caller must account the send
// itself, synchronously, instead of waiting on an event.
enum class SendFileOutcome : u8 { Failed, Armed, CompletedSync };

// Guard for IoUringEventLoop::in_sync_send_completion. Behaves as a plain
// bool (implicit conversion + bool assignment) everywhere it's used, but
// also counts nesting depth so tests can assert the recursion bound
// directly instead of by stack size: depth is the current nesting level,
// max_depth the deepest it ever reached. Production code only ever does
// `loop->in_sync_send_completion = true;` ... `= false;` in matched pairs
// (see on_response_sent), so depth returns to 0 once the outermost pair
// unwinds and max_depth is the true peak nesting reached.
struct SyncSendCompletionGuard {
    u32 depth = 0;
    u32 max_depth = 0;

    operator bool() const { return depth != 0; }
    SyncSendCompletionGuard& operator=(bool active) {
        if (active) {
            depth++;
            if (depth > max_depth) max_depth = depth;
        } else if (depth != 0) {
            depth--;
        }
        return *this;
    }
};

// IoUringEventLoop — concrete, non-template event loop for io_uring backend.
//
// io_uring is asynchronous: the kernel may still reference user buffers
// between SQE submission and CQE completion. This loop tracks pending_ops
// per connection and defers slice reclamation until all in-flight CQEs
// have been harvested. Includes armed flag management, cancel SQE tracking,
// deferred accepts, and reclaim_pending/reclaim_slot machinery.
struct IoUringEventLoop : EventLoopCRTP<IoUringEventLoop> {
    u64 study_direct_body_attempts = 0;
    u64 study_direct_body_progress = 0;
    u64 study_direct_body_full = 0;
    u64 study_completed_responses = 0;
    u64 study_body_sends = 0;
    struct StudyRequestPhaseSlot {
        u32 conn_id = 0;
        u64 req_us = 0;
        u64 first_us = 0;
        u32 upstream_us = 0;
        u32 payload_len = 0;
    };
    StudyRequestPhaseSlot study_request_slots[128]{};
    u32 study_phase_rng = 0x6d2b79f5u;
    u64 study_small_phase_samples = 0;
    u64 study_small_phase_drops = 0;
    u64 study_small_phase_hist[4][32]{};
    u64 study_small_phase_sum_us[4]{};
    u64 study_small_phase_max_us[4]{};

    void study_note_first_response(const Connection& c, u64 now_us) {
        if (c.req_start_us == 0 || now_us < c.req_start_us ||
            now_us - c.req_start_us > 60ull * 1000000u)
            return;
        u32 rng = study_phase_rng;
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        study_phase_rng = rng;
        if ((rng & 63u) != 0) return;
        auto& slot = study_request_slots[c.id & 127u];
        if (slot.req_us != 0 && slot.conn_id != c.id && now_us >= slot.req_us &&
            now_us - slot.req_us < 1000000u) {
            ++study_small_phase_drops;
            return;
        }
        slot.conn_id = c.id;
        slot.req_us = c.req_start_us;
        slot.first_us = now_us;
        slot.upstream_us = c.upstream_us;
        slot.payload_len = 0;
    }

    void study_note_response_size(const Connection& c, u32 payload_len) {
        auto& slot = study_request_slots[c.id & 127u];
        if (slot.req_us != 0 && slot.conn_id == c.id && slot.req_us == c.req_start_us)
            slot.payload_len = payload_len;
    }

    void study_note_proxy_complete(const Connection& c) {
        auto& slot = study_request_slots[c.id & 127u];
        if (slot.req_us == 0 || slot.conn_id != c.id || slot.req_us != c.req_start_us) return;
        const StudyRequestPhaseSlot snapshot = slot;
        slot.req_us = 0;
        // Filter by actual completed payload, never by a predicted URL size.
        if (snapshot.payload_len != 4096 || c.resp_body_mode != BodyMode::ContentLength) return;
        const u64 now = monotonic_us();
        if (now < snapshot.first_us || snapshot.first_us < snapshot.req_us ||
            snapshot.first_us - snapshot.req_us < snapshot.upstream_us)
            return;
        const u64 phases[4] = {now - snapshot.req_us,
                               snapshot.first_us - snapshot.req_us - snapshot.upstream_us,
                               snapshot.upstream_us,
                               now - snapshot.first_us};
        ++study_small_phase_samples;
        for (u32 k = 0; k < 4; ++k) {
            u64 value = phases[k];
            u32 bin = 0;
            while (value > 1 && bin < 31) {
                value >>= 1;
                ++bin;
            }
            ++study_small_phase_hist[k][bin];
            study_small_phase_sum_us[k] += phases[k];
            if (phases[k] > study_small_phase_max_us[k]) study_small_phase_max_us[k] = phases[k];
        }
    }

    bool study_inside_cq = false;
    u64 study_turn_started_ns = 0;
    u64 study_cq_splice_calls = 0;
    u64 study_cq_splice_bytes = 0;
    u64 study_cq_phase_ns = 0;
    u64 study_flush_phase_ns = 0;
    static constexpr u32 kResponseSpliceChunkSize = 128 * 1024;
    u64 study_large_pipes = 0;
    u64 study_small_pipes = 0;
    u64 study_splice_calls[2]{};
    u64 study_splice_eagain[2]{};
    u64 study_splice_short[2]{};
    u64 study_write_budget_polls = 0;
    u64 study_poll_started[2][kDefaultConnectionCapacity]{};
    u64 study_queue_started[kDefaultConnectionCapacity]{};
    u64 study_wait_hist[3][32]{};
    u64 study_wait_sum_ns[3]{};
    u64 study_wait_max_ns[3]{};
    u64 study_syscall_hist[2][32]{};
    void study_record_wait(u32 kind, u64 ns) {
        u64 us = ns / 1000;
        u32 bin = 0;
        while (us > 1 && bin < 31) {
            us >>= 1;
            ++bin;
        }
        ++study_wait_hist[kind][bin];
        study_wait_sum_ns[kind] += ns;
        if (ns > study_wait_max_ns[kind]) study_wait_max_ns[kind] = ns;
    }
    void study_record_syscall(u32 kind, u64 ns) {
        u64 us = ns / 1000;
        u32 bin = 0;
        while (us > 1 && bin < 31) {
            us >>= 1;
            ++bin;
        }
        ++study_syscall_hist[kind][bin];
    }

    bool study_yield_enabled = true;
    u64 ordinary_cq_wait_limit_ns = 80ull * 1000;
    u64 study_relay_turns = 0;
    u64 study_relay_yields = 0;
    u64 study_relay_calls = 0;
    u64 study_cq_probes = 0;
    u64 study_cq_entries = 0;
    u64 study_yield_types[static_cast<u32>(IoEventType::Count) + 1]{};
    IoUringBackend backend;
    TimerWheel timer;
    u32 shard_id = 0;
    // Set for the duration of the synthetic dispatch_event() call that
    // accounts a SendFileOutcome::CompletedSync completion (see
    // on_response_sent). That dispatch can synchronously complete a whole
    // response and pipeline_dispatch the next pipelined request, whose own
    // handler may again try to sendfile-complete synchronously — recursing
    // into dispatch_event with no bound on pipeline depth. While this flag is
    // set, submit_send_file refuses another synchronous completion (it arms
    // an ordinary SQE instead), so the recursion is provably one level deep:
    // the outer dispatch_event call sets it, the (at most one) nested
    // completion sees it set and falls back to async, and nothing set it
    // again before that nested call returns.
    SyncSendCompletionGuard in_sync_send_completion{};
    // Shared fairness budget for synchronous relay progress within one wait turn.
    static constexpr u32 kRelayTurnMaxCalls = 16;
    static constexpr u32 kRelayTurnMaxBytes = 1024 * 1024;
    u32 study_event_batch_limit = kMaxEventsPerWait;
    u32 study_relay_chunk_size = kResponseSpliceChunkSize;
    u32 study_relay_turn_call_limit = kRelayTurnMaxCalls;
    u32 study_relay_turn_byte_limit = kRelayTurnMaxBytes;
    u32 relay_budget_calls = kRelayTurnMaxCalls;
    u32 relay_budget_bytes = kRelayTurnMaxBytes;
    u32 relay_cancel_retry_count = 0;
    static constexpr u32 kDeferredRelayReadLimit = kMaxEventsPerWait;
    u32 deferred_relay_read_count = 0;
    u32 deferred_relay_read_ids[kDeferredRelayReadLimit]{};
    u32 deferred_relay_read_episodes[kDeferredRelayReadLimit]{};
    // Read-only diagnostics for focused validation and post-run evidence.
    WsSpliceExperiment ws_splice;
    // Conservative negative cache: only the terminal-pending publisher can
    // introduce an owner. Normal/mixed batches still scan unconditionally.
    bool response_read_terminal_scan_needed = true;
    bool study_ws_poll_first = false;
    u64 study_ws_poll_first_arms = 0;
    u32 study_ws_direct_recv_limit = 0;
    u64 study_ws_direct_recv_arms = 0;
    bool study_ws_sync_send = false;
    u64 study_ws_sync_attempts = 0, study_ws_sync_full = 0, study_ws_sync_partial = 0;
    u64 study_ws_sync_blocked = 0, study_ws_sync_errors = 0, study_ws_sync_bytes = 0;
    u64 study_ws_sync_cached = 0;
    u64 relay_admissions = 0;
    u64 relay_pulled_bytes = 0;
    u64 relay_written_bytes = 0;
    bool test_fail_next_relay_poll = false;
    bool test_fail_next_ws_splice_cancel = false;
    // Shared cross-shard limiter for @rateLimit(scope: global) rules. Null ->
    // global rules degrade to per-shard. main.cc points every shard at one
    // shared instance.
    GlobalRateLimiter* global_rl = nullptr;
    // Shared per-upstream concurrency gauge for max-inflight limiting (null =
    // unlimited). main.cc points every shard at one shared instance.
    UpstreamConcurrency* upstream_cc = nullptr;
    bool upstream_acquire(u16 uid, u32 max) {
        return upstream_cc ? upstream_cc->try_acquire(uid, max) : true;
    }
    void upstream_release(u16 uid) {
        if (upstream_cc) upstream_cc->release(uid);
    }

private:
    std::atomic<bool> running_;
    std::atomic<bool> draining_;
    std::atomic<u64> drain_start_;
    std::atomic<u32> drain_period_;

private:
    template <typename Submit>
    [[nodiscard]] bool submit_staged_tls_local_response_impl(Connection& c,
                                                             const u8* src,
                                                             u32 len,
                                                             Submit&& submit) {
        const bool staged_in_response_header_buf =
            src == c.response_header_buf.data() && len == c.response_header_buf.len() && len != 0;
        if (c.id >= connection_capacity || c.fd < 0 || src == nullptr ||
            !staged_in_response_header_buf || !c.uses_iouring_tls() || !c.tls_handshake_complete ||
            !c.tls_engine.handshake_done || c.protocol != ConnProtocol::Http11 || c.h2 != nullptr ||
            c.state != ConnState::Sending ||
            c.on_send != &on_validated_preconnect_failure_sent<IoUringEventLoop> ||
            c.resp_status != kStatusBadGateway || c.resp_body_mode != BodyMode::None ||
            c.resp_body_remaining != 0 || c.upstream_fd >= 0 || !c.upstream_abandoned ||
            c.send_armed || backend.send_state[c.id].remaining != 0 ||
            !c.response_read_deadline_owner_is_neutral() ||
            !c.http1_prebuilt_response_proof_is_neutral() ||
            !c.tls_single_shot_send_owner_is_neutral() || !c.tls_raw_send_owner_is_neutral() ||
            c.tls_in_buf.len() != 0 || c.tls_out_buf.len() != 0 || c.tls_proxy_stream ||
            c.upstream_send_len != 0 || c.upstream_send_armed || c.on_upstream_send != nullptr ||
            backend.upstream_send_state[c.id].remaining != 0 || c.retry_req_send_len != 0 ||
            c.pipeline_stash_len != 0 || c.response_mutations_snapshotted ||
            c.upstream_request_incomplete || backend.failure_code() != 0)
            return false;

        // SSL_write consumes the staged plaintext before the ciphertext SQE
        // can be rejected. Make one submission attempt only; its failure is
        // terminal and must be observed by the caller without a second close.
        return submit();
    }

    template <typename Submit, typename FlushResult>
    [[nodiscard]] bool submit_staged_local_response_impl(
        Connection& c, const u8* src, u32 len, Submit&& submit, FlushResult&& flush_result) {
        const bool staged_in_response_header_buf =
            src == c.response_header_buf.data() && len == c.response_header_buf.len() && len != 0;
        if (c.id >= connection_capacity || c.fd < 0 || src == nullptr || len == 0 || c.tls_active ||
            !staged_in_response_header_buf || c.send_armed ||
            backend.send_state[c.id].remaining != 0 ||
            !c.response_read_deadline_owner_is_neutral() || c.upstream_send_armed ||
            c.on_upstream_send != nullptr || c.upstream_send_len != 0 ||
            backend.upstream_send_state[c.id].remaining != 0 || c.retry_req_send_len != 0 ||
            c.pipeline_stash_len != 0 || c.response_mutations_snapshotted ||
            c.upstream_request_incomplete || backend.failure_code() != 0)
            return false;

        const u32 pending_ops_before = c.pending_ops;
        const auto send_state_before = backend.send_state[c.id];
        const auto attempt_left_no_owner = [&]() {
            const auto& send = backend.send_state[c.id];
            return c.pending_ops == pending_ops_before && !c.send_armed &&
                   send.src == send_state_before.src && send.fd == send_state_before.fd &&
                   send.offset == send_state_before.offset &&
                   send.remaining == send_state_before.remaining &&
                   send.type == send_state_before.type &&
                   send.upstream_episode == send_state_before.upstream_episode &&
                   send.generation == send_state_before.generation;
        };

        if (submit()) return true;
        if (!attempt_left_no_owner()) {
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            return false;
        }
        if (!flush_result()) return false;
        if (submit()) return true;
        if (!attempt_left_no_owner()) backend.fatal_error.store(EPROTO, std::memory_order_release);
        return false;
    }

public:
    static constexpr u32 kMaxConns = kDefaultConnectionCapacity;
    u32 connection_capacity = 0;
    // Active health-check probing requires synchronous probe teardown; the
    // io_uring loop doesn't support that yet, so sweep_health_probes only re-arms
    // deadlines here and issues no connects (epoll-only this slice).
    static constexpr bool kSupportsHealthProbe = false;
    static constexpr bool kSupportsExplicitFirstResponseDeadline = true;
    static constexpr u32 kTlsInputSize = SlicePool::kSliceSize + 1024;
    // Owned ciphertext output buffer + watermark backpressure for proxy-over-TLS
    // streaming on io_uring. See docs/iouring-tls-output-buffer.md.
    static constexpr u32 kTlsRecordMax =
        SlicePool::kSliceSize + 256;  // 1 chunk's worst-case ciphertext
    static constexpr u32 kTlsOutBufCap =
        4 * SlicePool::kSliceSize;  // 64 KiB — bounded throughput knob
    static constexpr u32 kTlsOutHigh =
        kTlsOutBufCap - kTlsRecordMax;                    // pause upstream recv above this
    static constexpr u32 kTlsOutLow = kTlsOutBufCap / 4;  // resume below this
    static constexpr u32 kTlsDrainChunk = kTlsRecordMax;  // keep one TLS record within a raw send
    static constexpr u32 kDefaultKeepaliveTimeout = 60;
    // Deadline (seconds; coarse 1s timer-wheel resolution) for a connection in
    // the Proxying state. SCOPE: the post-connect phase only — from the upstream
    // connect completing, through request-send, until the upstream's first
    // response bytes. Firing before any response reached the client
    // (!proxy_resp_started) → 504; after streaming started → close (truncate).
    // Does NOT bound TCP connect establishment: the timer flips to this value
    // only on the first upstream I/O event (connect completion), so a *hung
    // connect* is still bounded by keepalive_timeout (ECONNREFUSED is immediate,
    // so this rarely matters). Idle keep-alive uses keepalive_timeout — a
    // separate knob. TODO: a dedicated connect-timeout if hung connects matter.
    static constexpr u32 kDefaultUpstreamTimeout = 30;
    SlicePool pool;
    // TLS server context (cert/key/ALPN). When set, accepted connections
    // terminate TLS via the event-loop TlsEngine (see tls_iouring.h). Null =
    // plaintext. Mirrors EpollEventLoop::tls_server.
    TlsServerContext* tls_server = nullptr;
    // Per-shard HTTP/2 engine pool (see EpollEventLoop). Lazily handed out on
    // h2 upgrade; bounded, over-cap upgrades close the connection.
    static constexpr u32 kH2PoolCap = 2048;
    SlabPool<Http2Conn, kH2PoolCap> h2_pool;
    MappedArray<Connection> conns;
    MappedArray<u32> free_stack;
    u32 free_top = 0;
    // Initialised-prefix watermark for `conns`. Slots [0, slots_initialized)
    // have each been constructed and reset() (id/shard_id set) and are valid to
    // read; slots at or above it are untouched anonymous zero pages (conns is
    // mapped with MappedArray::init_lazy). A zeroed slot is NOT a valid free
    // slot: fds are -1 after reset() but 0 when zeroed, so it must never be read.
    // free_stack is seeded so fresh ids pop in ascending order, which keeps the
    // never-used slots a suffix; initialize_slots_to() keeps the prefix property
    // regardless of hand-out order.
    // Bounded by the watermark: any index that can arrive without a live
    // allocation behind it (CQE/event conn_ids, response-read batch owners and
    // pins, the body-pump ready set, reclaim_slot arguments) and every walk over
    // all slots. Allocated by construction (not bounded): Connection& c handed
    // out by alloc_conn and the pending_free ids, which are only ever pushed from
    // closed live slots.
    u32 slots_initialized = 0;

    // Pending-free list: slots closed during the current dispatch batch.
    MappedArray<u32> pending_free;
    u32 pending_free_count = 0;
    // Normally zero. A strict retirement cancel that could not acquire an SQE
    // is retried before the next blocking wait; the count avoids scanning the
    // full connection table on the ordinary hot path.
    u32 upstream_retirement_retry_count;
    // Set only when exact rendezvous owners make at least one parked HTTP/1
    // boundary eligible. The ordinary hot path avoids a connection-table scan;
    // the run loop consumes this after the complete wait batch.
    bool http1_boundary_ready_pending;
    bool response_read_deadline_expiry_pending;
    bool response_read_deadline_body_pump_pending = false;
    MappedArray<u64> body_pump_ready_words;
    // Downstream recvs that completed -ENOBUFS (provided ring empty): one bit
    // per slot, re-armed by rearm_deferred_recvs() once buffers are back. The
    // count keeps the ordinary hot path from touching the bitmap.
    MappedArray<u64> recv_rearm_words;
    u32 recv_rearm_count = 0;
    u32 recv_rearm_cursor = 0;  // word where the next capped pass resumes
    u32 recv_rearm_slot_cursor = 0;
    u32 ws_cache_rearm_cursor = 0;  // connection where the upstream pass resumes
    u32 ws_cache_rearm_budget = 0;
    bool ws_cache_rearm_upstream_turn = true;

    enum class CompleteContentLengthTerminalDisposition : u8 {
        CompleteBody,
        CleanUpstreamEof,
        InactivityExpiry,
    };

    struct ResponseReadBatchOwner {
        u32 conn_id = 0;
        u32 deadline_generation = 0;
        u32 upstream_episode = 0;
        ResponseReadDeadlineProfile profile = ResponseReadDeadlineProfile::None;
        u8 method = 0xffu;
        u32 last_relevant = 0;
        u32 last_positive = 0;
        u32 first_copy_begin = 0;
        u32 expected_copy_end = 0;
        u32 positive_bytes = 0;
        bool valid = false;
        bool saw_relevant = false;
        bool saw_positive = false;
        bool saw_terminal = false;
        bool post_commit_at_start = false;
        bool terminal_fault = false;
        bool clean_eof = false;
        bool terminal_error = false;
        bool positive_terminal = false;
        bool body_complete_at_start = false;
        bool saw_precise_timer = false;
        bool precise_timer_valid = false;
        u32 precise_timer_generation = 0;
        bool precise_timer_target_seen = false;
        bool precise_timer_cancel_seen = false;
        bool precise_timer_semantic = false;
        bool bounded_terminal_custody = false;
        bool bounded_terminal_prospective = false;
        bool bounded_terminal_timer_seen = false;
        u32 bounded_terminal_buffer_begin = 0;
        bool bounded_terminal_recv_seen = false;
        bool bounded_terminal_cancel_seen = false;
        bool bounded_terminal_custody_invalid = false;
    };
    ResponseReadBatchOwner response_read_batch_owners[kMaxEventsPerWait];
    u16 response_read_batch_event_owner[kMaxEventsPerWait];
    // Batch-local owner index: at most 256 owners in 512 slots. No Connection
    // state or allocation is retained across dispatch/reclamation boundaries.
    static constexpr u32 kResponseReadOwnerIndexSize = 2u * kMaxEventsPerWait;
    static_assert((kResponseReadOwnerIndexSize & (kResponseReadOwnerIndexSize - 1u)) == 0);
    u16 response_read_batch_owner_index[kResponseReadOwnerIndexSize]{};
    bool response_read_batch_owner_index_active = false;
    // Counters default to empty so a loop whose slots are used before init()
    // (e.g. storage-only setup) never scans indeterminate batch state.
    u32 response_read_batch_owner_count = 0;
    u32 response_read_batch_event_count = 0;
    u32 response_read_batch_event_index = 0;
    const IoEvent* response_read_batch_events = nullptr;
    u32 response_read_batch_pins[kMaxEventsPerWait];
    u32 response_read_batch_pin_count = 0;

    // Deferred accepts: accepted fds that couldn't be allocated during
    // dispatch because all slots were in pending_free.
    static constexpr u32 kMaxDeferredAccepts = 64;
    i32 deferred_accepts[kMaxDeferredAccepts];
    u32 deferred_accept_count = 0;

    u32 keepalive_timeout = kDefaultKeepaliveTimeout;
    u32 upstream_timeout = kDefaultUpstreamTimeout;
    i32 listen_fd = -1;
    // Multishot accept needs a deferred re-arm (resource exhaustion or no SQE);
    // retried on the next 1s timer tick.
    bool accept_rearm_pending = false;

    AccessLogRing* access_log = nullptr;
    SourceLiveAccessLogProducer* live_access_log = nullptr;

    struct CaptureRing* capture_ring = nullptr;
    static constexpr u32 kCaptureSliceSize = 8192;
    u8* capture_region_ = nullptr;

    core::Expected<void, Error> init_slot_storage(u32 capacity) {
        if (!validate_connection_capacity(capacity))
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        if (connection_capacity != 0)
            return connection_capacity == capacity
                       ? core::Expected<void, Error>{}
                       : core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        response_read_deadline_body_pump_pending = false;
        auto c = conns.init_lazy(capacity);
        if (!c) return core::make_unexpected(c.error());
        auto f = free_stack.init(capacity);
        if (!f) {
            conns.destroy();
            return core::make_unexpected(f.error());
        }
        auto p = pending_free.init(capacity);
        if (!p) {
            free_stack.destroy();
            conns.destroy();
            return core::make_unexpected(p.error());
        }
        auto b = backend.init_send_state_storage(capacity);
        if (!b) {
            pending_free.destroy();
            free_stack.destroy();
            conns.destroy();
            return core::make_unexpected(b.error());
        }
        auto ready_words = body_pump_ready_words.init((capacity + 63u) / 64u);
        if (!ready_words) {
            backend.destroy_send_state_storage();
            pending_free.destroy();
            free_stack.destroy();
            conns.destroy();
            return core::make_unexpected(ready_words.error());
        }
        auto rearm_words = recv_rearm_words.init((capacity + 63u) / 64u);
        if (!rearm_words) {
            body_pump_ready_words.destroy();
            backend.destroy_send_state_storage();
            pending_free.destroy();
            free_stack.destroy();
            conns.destroy();
            return core::make_unexpected(rearm_words.error());
        }
        recv_rearm_count = 0;
        recv_rearm_cursor = 0;
        ws_cache_rearm_cursor = 0;
        recv_rearm_slot_cursor = 0;
        ws_cache_rearm_upstream_turn = true;
        // conns[] is mapped but neither constructed nor reset (lazy pages);
        // alloc_conn_impl constructs and resets a slot on first hand-out. Seed
        // the stack so pops ascend.
        for (u32 i = 0; i < capacity; i++) {
            free_stack[i] = capacity - 1 - i;
            pending_free[i] = 0;
        }
        free_top = capacity;
        slots_initialized = 0;
        pending_free_count = 0;
        response_read_deadline_body_pump_pending = false;
        connection_capacity = capacity;
        return {};
    }

    void destroy_slot_storage() {
        connection_capacity = 0;
        slots_initialized = 0;
        pending_free_count = 0;
        deferred_relay_read_count = 0;
        free_top = 0;
        response_read_deadline_body_pump_pending = false;
        body_pump_ready_words.destroy();
        recv_rearm_words.destroy();
        recv_rearm_count = 0;
        backend.destroy_send_state_storage();
        pending_free.destroy();
        free_stack.destroy();
        conns.destroy();
    }

    bool set_capture(CaptureRing* ring) {
        capture_ring = ring;
        if (!ring) return true;
        if (connection_capacity == 0 || static_cast<u64>(connection_capacity) >
                                            static_cast<u64>(SIZE_MAX) / kCaptureSliceSize) {
            capture_ring = nullptr;
            return false;
        }
        if (!capture_region_) {
            void* region = mmap(nullptr,
                                static_cast<size_t>(connection_capacity) * kCaptureSliceSize,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1,
                                0);
            if (region == MAP_FAILED) {
                capture_ring = nullptr;
                return false;
            }
            capture_region_ = static_cast<u8*>(region);
        }
        for (u32 i = 0; i < slots_initialized; i++) {
            if (conns[i].fd >= 0 && !conns[i].capture_buf)
                conns[i].capture_buf = capture_region_ + static_cast<u64>(i) * kCaptureSliceSize;
        }
        return true;
    }

    ShardMetrics* metrics = nullptr;
    // Registry of every shard's metrics, for the built-in /metrics endpoint to
    // aggregate across shards. Null → endpoint disabled (the default).
    ShardMetrics* const* all_shard_metrics = nullptr;
    u32 shard_metrics_count = 0;
    // Per-shard idle upstream connection pool (HTTP/1 keep-alive reuse). Wired by
    // the shard; null in tests/mocks that don't exercise reuse.
    UpstreamPool* upstream = nullptr;

    const RouteConfig** config_ptr = nullptr;
    ShardControlBlock* control = nullptr;
    ShardEpoch* epoch = nullptr;
    void** jit_code_ptr = nullptr;

    core::Expected<void, Error> init(u32 id,
                                     i32 lfd,
                                     u32 pool_prealloc = 0,
                                     u32 capacity = kDefaultConnectionCapacity) {
        if (connection_capacity != 0)
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        auto slots = init_slot_storage(capacity);
        if (!slots) return core::make_unexpected(slots.error());
        shard_id = id;
        listen_fd = lfd;
        this->listener_context = {};
        running_.store(true, std::memory_order_relaxed);
        draining_.store(false, std::memory_order_relaxed);
        drain_start_.store(0, std::memory_order_relaxed);
        drain_period_.store(0, std::memory_order_relaxed);
        keepalive_timeout = kDefaultKeepaliveTimeout;
        upstream_timeout = kDefaultUpstreamTimeout;
        live_access_log = nullptr;
        capture_ring = nullptr;
        capture_region_ = nullptr;
        config_ptr = nullptr;
        control = nullptr;
        epoch = nullptr;
        jit_code_ptr = nullptr;
        upstream_retirement_retry_count = 0;
        deferred_relay_read_count = 0;
        http1_boundary_ready_pending = false;
        response_read_deadline_expiry_pending = false;
        response_read_deadline_body_pump_pending = false;
        response_read_batch_owner_count = 0;
        response_read_batch_owner_index_active = false;
        response_read_batch_event_count = 0;
        response_read_batch_event_index = 0;
        response_read_batch_events = nullptr;
        response_read_batch_pin_count = 0;
        deferred_accept_count = 0;
        timer.init();
        // Reserve six ordinary slices and one complete bounded response chain
        // per admitted connection. TLS input remains separately mmap-backed.
        // Bulk relay buffers (Part D) are reserved per connection too, bounded
        // by SlicePool::kMaxBulkSlices — only io_uring ever borrows one.
        auto pooled = pool.init(SlicePool::capacity_for_connections(connection_capacity),
                                pool_prealloc,
                                SlicePool::kMaxCachedSlices,
                                SlicePool::bulk_capacity_for_connections(connection_capacity));
        if (!pooled) {
            backend.shutdown();
            destroy_slot_storage();
            return core::make_unexpected(pooled.error());
        }
        backend.response_pool = &pool;
        auto h2p = h2_pool.init();
        if (!h2p) {
            pool.destroy();
            backend.shutdown();
            destroy_slot_storage();
            return core::make_unexpected(h2p.error());
        }
        auto be = backend.init(id, lfd, connection_capacity);
        if (!be) {
            h2_pool.destroy();
            pool.destroy();
            destroy_slot_storage();
            return core::make_unexpected(be.error());
        }
        probe_idle_trim();  // idle-buffer trim is on only if this succeeds
        return {};
    }

    void run() {
        struct rusage study_usage_begin{};
        const bool kStudyUsageValid =
            backend.study_io_stats && ::getrusage(RUSAGE_THREAD, &study_usage_begin) == 0;
        rearm_accept();
        // Arm timer deadlines from activation (config is installed before run()),
        // so `every: D` measures from here rather than from the first 1s tick.
        this->fire_due_timers();
        // Reset/arm active-health state at activation (#161 F4). io_uring issues
        // no probes this slice, but the reset still clears stale numeric-slot
        // verdicts that routing reads.
        this->arm_health_on_config_change();
        IoEvent events[kMaxEventsPerWait];

        while (is_running()) {
            retry_strict_upstream_retirement_cancels();
            retry_response_splice_cancels();
            ws_splice.progress(*this);
            const u32 kEventCount = backend.wait(events,
                                                 study_event_batch_limit,
                                                 conns,
                                                 slots_initialized,
                                                 deferred_relay_read_count == 0);
            if (backend.failure_code() != 0) {
                // A zero-event wait is valid; a sticky backend error is not. Stop
                // this shard so an io_uring_enter failure cannot become a silent
                // request stall or an endless busy loop.
                running_.store(false, std::memory_order_release);
                break;
            }
            relay_budget_calls = study_relay_turn_call_limit;
            relay_budget_bytes = study_relay_turn_byte_limit;
            dispatch_batch(events, kEventCount);
            if (backend.ws_recv_cache_enabled) {
                ws_cache_rearm_budget = cache_rearm_budget(backend.cq_unharvested());
            }
            rearm_deferred_cache_passes(/*force=*/false);
            retry_deferred_accepts();
            poll_command();
            // Re-arm timers after a possible hot reload (see EpollEventLoop::run).
            this->fire_due_timers();
            // Reset/arm active-health state on hot reload (#161 F4). No-op when
            // unchanged; advances health_armed_config so the later sweep doesn't
            // double-reset.
            this->arm_health_on_config_change();
            if (draining_.load(std::memory_order_acquire)) {
                close_listen();
                // Drain the idle upstream pool on the shard thread (NOT in drain(),
                // which runs on the control thread and would race pool access here).
                // Idempotent (no-op once empty); drain-time completions close-not-pool,
                // so the pool stays empty and the shard exits with no open pooled fds.
                if (upstream) upstream->drain();
                u64 start = drain_start_.load(std::memory_order_relaxed);
                u32 period = drain_period_.load(std::memory_order_relaxed);
                if (active_count() == 0) {
                    running_.store(false, std::memory_order_relaxed);
                } else if (monotonic_secs() >= start + period) {
                    force_close_all();
                    running_.store(false, std::memory_order_relaxed);
                }
            }
        }
        if (kStudyUsageValid) {
            struct rusage usage{};
            if (::getrusage(RUSAGE_THREAD, &usage) == 0)
                ::fprintf(stderr,
                          "RUT_WS_THREAD voluntary=%ld involuntary=%ld\n",
                          usage.ru_nvcsw - study_usage_begin.ru_nvcsw,
                          usage.ru_nivcsw - study_usage_begin.ru_nivcsw);
        }
    }

    // A close-path relay cancel can fail transiently when the SQ is full.  Keep
    // the ownership bit and retry before the next wait; reclaim must never
    // infer that an armed poll is gone merely because submission was refused.
    void retry_response_splice_cancels() {
        if (relay_cancel_retry_count == 0) return;
        for (u32 i = 0; i < slots_initialized; ++i) {
            Connection& c = conns[i];
            RelayOwner& r = c.relay_owner;
            if (!r.close_pending || !r.active()) continue;
            if (r.read_cancel_retry && r.read_armed && !r.read_cancel_owned) {
                if (backend.cancel_retiring_upstream(
                        c.id, IoEventType::RelayRead, r.upstream_episode)) {
                    r.read_cancel_owned = true;
                    r.read_cancel_retry = false;
                    if (relay_cancel_retry_count == 0) {
                        c.upstream_episode = kInvalidUpstreamEventEpisode;
                        c.upstream_episode_quarantined = true;
                        backend.fatal_error.store(EPROTO, std::memory_order_release);
                        running_.store(false, std::memory_order_release);
                        continue;
                    }
                    --relay_cancel_retry_count;
                    ++c.pending_ops;
                }
            }
            if (r.write_cancel_retry && r.write_armed && !r.write_cancel_owned) {
                if (backend.cancel_retiring_upstream(
                        c.id, IoEventType::RelayWrite, r.upstream_episode)) {
                    r.write_cancel_owned = true;
                    r.write_cancel_retry = false;
                    if (relay_cancel_retry_count == 0) {
                        c.upstream_episode = kInvalidUpstreamEventEpisode;
                        c.upstream_episode_quarantined = true;
                        backend.fatal_error.store(EPROTO, std::memory_order_release);
                        running_.store(false, std::memory_order_release);
                        continue;
                    }
                    --relay_cancel_retry_count;
                    ++c.pending_ops;
                }
            }
        }
    }

    void stop() { running_.store(false, std::memory_order_release); }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    bool is_draining() const { return draining_.load(std::memory_order_acquire); }

    void poll_command() {
        if (!control) return;
        auto* cfg = control->pending_config.exchange(nullptr, std::memory_order_acq_rel);
        if (cfg && config_ptr) {
            *config_ptr = cfg;
            // A reload may repoint an upstream endpoint under the same
            // (upstream_id, backend_idx); drop idle sockets parked under the old
            // config so post-reload requests don't reuse a stale connection.
            if (upstream) upstream->drain();
        }
        auto* jit = control->pending_jit.exchange(nullptr, std::memory_order_acq_rel);
        if (jit && jit_code_ptr) *jit_code_ptr = jit;
        auto* cap = control->pending_capture.exchange(nullptr, std::memory_order_acq_rel);
        if (cap == kCaptureDisable) {
            set_capture(nullptr);
        } else if (cap) {
            if (!set_capture(cap)) control->pending_capture.store(cap, std::memory_order_release);
        }
    }

    void epoch_enter() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }
    void epoch_leave() {
        if (epoch)
            epoch->epoch.store(epoch->epoch.load(std::memory_order_relaxed) + 1,
                               std::memory_order_release);
    }

    void shutdown() {
        close_deferred_idle_return_fds();
        reclaim_pending();
        if (idle_trim_pidfd >= 0) {
            ::close(idle_trim_pidfd);
            idle_trim_pidfd = -1;
        }
        if (backend.ws_recv_cache_enabled)
            ::fprintf(stderr,
                      "RUT_WS_CACHE deferred=%llu peak=%llu live=%u\n",
                      static_cast<unsigned long long>(backend.ws_recv_cache_deferred),
                      static_cast<unsigned long long>(backend.ws_recv_cache_peak),
                      backend.ws_recv_cache_count);
        backend.shutdown();
        if (ws_splice.enabled)
            ::fprintf(stderr,
                      "RUT_WS_SPLICE admissions=%llu client_bytes=%llu upstream_bytes=%llu "
                      "calls=%llu polls=%llu read_eagain=%llu write_eagain=%llu "
                      "pipe_grow_failures=%llu min_pipe_capacity=%u\n",
                      static_cast<unsigned long long>(ws_splice.admissions),
                      static_cast<unsigned long long>(ws_splice.transferred[0]),
                      static_cast<unsigned long long>(ws_splice.transferred[1]),
                      static_cast<unsigned long long>(ws_splice.calls),
                      static_cast<unsigned long long>(ws_splice.polls),
                      static_cast<unsigned long long>(ws_splice.eagain[0]),
                      static_cast<unsigned long long>(ws_splice.eagain[1]),
                      static_cast<unsigned long long>(ws_splice.pipe_grow_failures),
                      ws_splice.minimum_pipe_capacity);
        if (study_ws_poll_first)
            ::fprintf(stderr,
                      "RUT_WS_POLL_FIRST arms=%llu\n",
                      static_cast<unsigned long long>(study_ws_poll_first_arms));
        if (study_ws_direct_recv_limit != 0)
            ::fprintf(stderr,
                      "RUT_WS_DIRECT arms=%llu limit=%u\n",
                      static_cast<unsigned long long>(study_ws_direct_recv_arms),
                      study_ws_direct_recv_limit);
        if (study_ws_sync_send)
            ::fprintf(stderr,
                      "RUT_WS_SYNC attempts=%llu full=%llu partial=%llu blocked=%llu "
                      "errors=%llu bytes=%llu cached=%llu\n",
                      static_cast<unsigned long long>(study_ws_sync_attempts),
                      static_cast<unsigned long long>(study_ws_sync_full),
                      static_cast<unsigned long long>(study_ws_sync_partial),
                      static_cast<unsigned long long>(study_ws_sync_blocked),
                      static_cast<unsigned long long>(study_ws_sync_errors),
                      static_cast<unsigned long long>(study_ws_sync_bytes),
                      static_cast<unsigned long long>(study_ws_sync_cached));
        if (backend.study_io_stats)
            ::fprintf(stderr,
                      "RUT_IO_WAIT calls=%llu enters=%llu submitted=%llu events=%llu "
                      "empty=%llu max_events=%u\n",
                      static_cast<unsigned long long>(backend.study_wait_calls),
                      static_cast<unsigned long long>(backend.study_wait_enter_calls),
                      static_cast<unsigned long long>(backend.study_wait_submitted),
                      static_cast<unsigned long long>(backend.study_wait_events),
                      static_cast<unsigned long long>(backend.study_wait_empty),
                      backend.study_wait_max_events);
        if (ws_splice.enabled)
            ::fprintf(stderr,
                      "RUT_WS_NODELAY changes=%llu failures=%llu\n",
                      static_cast<unsigned long long>(ws_splice.nodelay_changes),
                      static_cast<unsigned long long>(ws_splice.nodelay_failures));
        ws_splice.shutdown();
        // No further CQE can retire relay polls after the backend has stopped.
        // Close every connection-owned pipe explicitly before destroying the
        // mmap-backed slots; integer pipe descriptors are not owned by reset().
        for (u32 i = 0; i < slots_initialized; ++i) close_response_splice_pipe(conns[i]);
        relay_cancel_retry_count = 0;
        // No CQE can arrive after the backend is stopped.  Release any
        // deferred config epochs now so shutdown does not leave a shard pinned
        // forever when the kernel never returned a cancelled Send.
        for (u32 i = 0; i < pending_free_count; i++) release_deferred_epoch(conns[pending_free[i]]);
        h2_pool.destroy();
        if (::getenv("RUT_STUDY_BODY_POOL_LOG"))
            ::fprintf(
                stderr,
                "RUT_DIRECT_BODY_STUDY completed=%llu attempts=%llu progress=%llu full=%llu\n",
                static_cast<unsigned long long>(study_completed_responses),
                static_cast<unsigned long long>(study_direct_body_attempts),
                static_cast<unsigned long long>(study_direct_body_progress),
                static_cast<unsigned long long>(study_direct_body_full));
        if (::getenv("RUT_STUDY_BODY_POOL_LOG"))
            ::fprintf(stderr,
                      "RUT_BULK_CACHE_STUDY enabled=%u peak_borrowed=%u peak_cached=%u borrowed=%u "
                      "cached=%u\n",
                      pool.study_adaptive_cache,
                      pool.study_bulk_peak_borrowed,
                      pool.study_bulk_peak_cached,
                      pool.study_bulk_borrowed,
                      pool.bulk_cached_count);
        pool.destroy();
        if (capture_region_) {
            munmap(capture_region_, static_cast<u64>(connection_capacity) * kCaptureSliceSize);
            capture_region_ = nullptr;
        }
        destroy_slot_storage();
    }

    void drain(u32 period_secs) {
        drain_period_.store(period_secs, std::memory_order_relaxed);
        drain_start_.store(monotonic_secs(), std::memory_order_relaxed);
        draining_.store(true, std::memory_order_release);
        // NOTE: do NOT drain the share-nothing UpstreamPool here — drain() runs on the
        // control thread (Shard::drain) while the shard's event-loop thread may be in
        // take_idle/put_idle/sweep. The pool is drained on the shard thread instead,
        // the first time run() observes draining_ (the timerfd kick below wakes it).
        if (backend.timer_fd >= 0) {
            struct itimerspec wake = {};
            wake.it_value.tv_nsec = 1;
            wake.it_interval.tv_sec = 1;
            timerfd_settime(backend.timer_fd, 0, &wake, nullptr);
        }
    }

    u32 active_count() const { return connection_capacity - free_top; }

    // Lazy-allocate upstream recv buffer for proxy connections.
    // Only called when a connection starts proxying — non-proxy connections
    // No-op for io_uring (no fd_map to clear).
    void clear_upstream_fd(u32 /*conn_id*/) {}

    static bool strict_upstream_retirement_blocks_reclaim(const Connection& c) {
        return c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
               c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
               c.upstream_close_target_owned != 0 || c.upstream_close_cancel_owned != 0 ||
               c.upstream_close_pause_cancel_owned;
    }

    // A deferred idle-pool return (return_idle_upstream) whose cancelled multishot
    // recv has not drained yet. Usually idle_return_fd/config are still pinned, but
    // cancel submission can fail after upstream_fd is closed and leave only the
    // cancel-inflight ownership marker. Either form must reject request 2 until the
    // old recv terminal drains; try_deferred_upstream_rearm publishes readiness then.
    static bool idle_return_drain_blocks_boundary(const Connection& c) {
        return c.upstream_recv_cancel_inflight ||
               (c.idle_return_fd >= 0 &&
                (c.upstream_recv_armed || c.upstream_recv_pause_cancel_pending));
    }

    void maybe_publish_http1_boundary_ready(Connection& c) {
        if (c.id >= connection_capacity || conns.data() == nullptr || &conns[c.id] != &c ||
            c.fd < 0 || !c.http1_boundary_deferred || c.http1_boundary_ready ||
            (c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None &&
             c.http1_prebuilt_wait != 0) ||
            strict_upstream_retirement_blocks_reclaim(c) || idle_return_drain_blocks_boundary(c) ||
            !c.response_read_timer_owner_is_neutral())
            return;
        c.http1_boundary_ready = true;
        http1_boundary_ready_pending = true;
    }

    static constexpr u8 upstream_op_for_event(IoEventType type) {
        if (type == IoEventType::UpstreamConnect) return kUpstreamOpConnect;
        if (type == IoEventType::UpstreamRecv) return kUpstreamOpRecv;
        if (type == IoEventType::UpstreamSend) return kUpstreamOpSend;
        return 0;
    }

    static constexpr IoEventType upstream_event_for_op(u8 op) {
        if (op == kUpstreamOpConnect) return IoEventType::UpstreamConnect;
        if (op == kUpstreamOpRecv) return IoEventType::UpstreamRecv;
        if (op == kUpstreamOpSend) return IoEventType::UpstreamSend;
        return IoEventType::Count;
    }

    static constexpr u32 upstream_op_count(u8 mask) {
        return static_cast<u32>((mask & kUpstreamOpConnect) != 0) +
               static_cast<u32>((mask & kUpstreamOpRecv) != 0) +
               static_cast<u32>((mask & kUpstreamOpSend) != 0);
    }

    // Park only the post-response request-boundary tail. Every request-1 side
    // effect (metrics/log/epoch/upstream release) has already completed before
    // this hook is called from on_proxy_response_sent. Origin retirement and
    // the precise response timer are independent owners; neither may be reused
    // as request-2 readiness until both have settled.
    [[nodiscard]] bool defer_http1_request_boundary(Connection& c) {
        // Exhausting the episode space quarantines the slot even when C1 had
        // no recv owner to drain. Never admit request 2 under an invalid token.
        if (c.upstream_episode_quarantined || !valid_upstream_episode(c.upstream_episode)) {
            close_conn(c);
            return true;
        }
        if (!strict_upstream_retirement_blocks_reclaim(c) &&
            !idle_return_drain_blocks_boundary(c) && c.response_read_timer_owner_is_neutral())
            return false;
        if (c.http1_boundary_deferred || c.http1_boundary_ready) {
            // A duplicate rendezvous cannot be resumed safely. Keep it parked;
            // the normal close path will clear it.
            close_conn(c);
            return true;
        }
        // Request 1's callbacks are spent, and the resume validity check refuses a
        // connection that still advertises one. The io_uring TLS completion
        // (tls_on_out_drain -> proxy_stream_complete) reaches here with them set.
        // For TLS this also nulls tls_pending_on_recv, so the tail tls_process in
        // tls_on_out_drain cannot dispatch request 2 while parked; its ciphertext
        // stays in tls_in_buf and is decrypted on resume.
        c.clear_slots();
        c.http1_boundary_deferred = true;
        c.http1_boundary_ready = false;
        c.http1_boundary_successor_episode = c.upstream_episode;
        return true;
    }

    static bool current_successor_event_is_valid(const Connection& c, const IoEvent& ev) {
        if (!io_event_is_upstream(ev.type) || !valid_upstream_episode(ev.upstream_episode) ||
            ev.upstream_episode != c.upstream_episode)
            return false;
        if (ev.aux == kPauseCancelAux)
            return ev.type == IoEventType::UpstreamRecv && c.upstream_recv_pause_cancel_pending &&
                   c.pending_ops > 0;
        if (ev.aux == kLocalSubmitFailureAux) {
            if (c.pending_ops == 0) return false;
            if (ev.type == IoEventType::UpstreamConnect)
                return c.on_upstream_send != nullptr && c.upstream_connect_armed;
            if (ev.type == IoEventType::UpstreamSend)
                return c.on_upstream_send != nullptr && c.upstream_send_armed;
            // A local recv-registration failure is the completion of the new
            // submitted target itself; unlike an old terminal racing a pause,
            // cancel_inflight alone is not ownership of this synthetic record.
            return ev.type == IoEventType::UpstreamRecv && c.on_upstream_recv != nullptr &&
                   c.upstream_recv_armed;
        }
        if (ev.aux != 0 || c.pending_ops == 0) return false;
        if (ev.type == IoEventType::UpstreamConnect)
            return c.on_upstream_send != nullptr && c.upstream_connect_armed;
        if (ev.type == IoEventType::UpstreamSend)
            return c.on_upstream_send != nullptr && c.upstream_send_armed;
        // A pause/body-completion path may clear armed before the old recv
        // target terminal drains, but cancel_inflight still proves its exact
        // current ownership and must reach the stale-data branch.
        return ev.type == IoEventType::UpstreamRecv &&
               (c.upstream_recv_armed || c.upstream_recv_cancel_inflight);
    }

private:
    static bool prebuilt_http1_header_is_complete(const Connection& c) {
        const u32 len = c.response_header_buf.len();
        const u8* data = c.response_header_buf.data();
        if (data == nullptr || len < 16u || __builtin_memcmp(data, "HTTP/1.1 ", 9) != 0 ||
            data[9] < '1' || data[9] > '5' || data[10] < '0' || data[10] > '9' || data[11] < '0' ||
            data[11] > '9' || data[12] != ' ' || data[len - 4] != '\r' || data[len - 3] != '\n' ||
            data[len - 2] != '\r' || data[len - 1] != '\n')
            return false;
        const u16 status =
            static_cast<u16>((data[9] - '0') * 100u + (data[10] - '0') * 10u + (data[11] - '0'));
        return status == c.resp_status;
    }

    static bool prebuilt_http1_response_is_complete(const Connection& c,
                                                    bool allow_consumed_terminal_episode = false) {
        // A generic pipeline generation token is not a strict activation bit.
        // Preserve the legacy layout shortcut only while every copied owner
        // field is at its canonical reset value.  Once any copied field is
        // published, a non-legacy request must prove the complete strict
        // identity before layout-None or header-only can return.
        const bool header_only_head_timeout =
            c.http1_prebuilt_response_layout == Http1PrebuiltResponseLayout::HeaderOnlyHead &&
            response_read_timeout_header_only_head_is_stable(
                c, c.http1_prebuilt_deadline_config, c.http1_prebuilt_deadline_bundle_id);
        const auto response_phase =
            c.state == ConnState::Sending &&
                    c.http1_prebuilt_disposition == Http1RequestBufferDisposition::ExistingPipeline
                ? ResponseReadTimeoutHeaderOnlyHeadPhase::SendingRetired
                : ResponseReadTimeoutHeaderOnlyHeadPhase::PreBegin;
        if (!c.http1_prebuilt_response_proof_is_neutral() && !http1_pipeline_request_is_legacy(c)) {
            if (header_only_head_timeout) {
                if (!response_read_timeout_header_only_head_response_is_stable(
                        c,
                        c.http1_prebuilt_deadline_upload,
                        c.http1_prebuilt_deadline_config,
                        c.http1_prebuilt_deadline_bundle_id,
                        c.http1_prebuilt_deadline_generation,
                        response_phase))
                    return false;
            } else {
                ForwardResponseBufferingMode copied_buffering = ForwardResponseBufferingMode::None;
                if (c.http1_prebuilt_deadline_config != nullptr &&
                    c.http1_prebuilt_deadline_config->policy_bundle_id_is_valid(
                        c.http1_prebuilt_deadline_bundle_id)) {
                    copied_buffering = c.http1_prebuilt_deadline_config
                                           ->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1]
                                           .response_buffering;
                }
                if (!http1_pipeline_request_generation_prebuilt_is_stable(
                        c,
                        c.http1_prebuilt_deadline_upload,
                        c.http1_prebuilt_deadline_config,
                        c.http1_prebuilt_deadline_bundle_id,
                        c.http1_prebuilt_deadline_profile,
                        copied_buffering,
                        c.http1_prebuilt_deadline_method,
                        c.http1_prebuilt_deadline_route_method,
                        c.http1_prebuilt_response_layout,
                        c.http1_prebuilt_response_purpose))
                    return false;
            }
        }
        if (c.http1_prebuilt_response_layout == Http1PrebuiltResponseLayout::None)
            return prebuilt_http1_header_is_complete(c);
        const bool fixed_upload_head_timeout =
            c.http1_prebuilt_deadline_profile ==
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead &&
            c.http1_prebuilt_response_purpose == Http1PrebuiltResponsePurpose::ResponseReadTimeout;
        const bool header_only_representation =
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::StrictHeadHeaderOnly ||
            (c.http1_prebuilt_response_layout ==
                 Http1PrebuiltResponseLayout::HeaderOnlyNoBodyStatus &&
             c.http1_prebuilt_response_purpose ==
                 Http1PrebuiltResponsePurpose::StrictNoBodyMetadataSuccess) ||
            fixed_upload_head_timeout || header_only_head_timeout;
        if (c.http1_prebuilt_deadline_profile == ResponseReadDeadlineProfile::None ||
            c.http1_prebuilt_deadline_method != c.req_method ||
            !response_read_deadline_route_method_matches(c.http1_prebuilt_deadline_method,
                                                         c.http1_prebuilt_deadline_route_method) ||
            c.http1_prebuilt_deadline_generation == 0 ||
            c.http1_prebuilt_deadline_generation != c.response_read_deadline_generation ||
            c.http1_prebuilt_deadline_bundle_id == 0 ||
            c.http1_prebuilt_deadline_config == nullptr ||
            c.http1_prebuilt_deadline_config != c.request_config ||
            !c.request_config->policy_bundle_id_is_valid(c.http1_prebuilt_deadline_bundle_id) ||
            c.response_header_buf.data() == nullptr || c.http1_prebuilt_total_len == 0 ||
            c.http1_prebuilt_total_len != c.response_header_buf.len() ||
            c.http1_prebuilt_header_end > c.http1_prebuilt_total_len ||
            (!header_only_representation
                 ? c.http1_prebuilt_body_len !=
                       c.http1_prebuilt_total_len - c.http1_prebuilt_header_end
                 : c.http1_prebuilt_body_len == 0 ||
                       c.http1_prebuilt_total_len != c.http1_prebuilt_header_end) ||
            c.http1_prebuilt_status != c.resp_status)
            return false;
        const auto& bundle =
            c.request_config->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1];
        const bool bodyless_get_retained_policy =
            c.http1_prebuilt_deadline_profile ==
                ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
            c.http1_prebuilt_deadline_method == static_cast<u8>(LogHttpMethod::Get) &&
            c.http1_prebuilt_deadline_route_method == kRouteMethodGet &&
            bodyless_get_complete_content_length_request_policy_is_admitted(c.request_policy_id);
        if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
            (forward_response_buffering_uses_content_length_machinery(bundle.response_buffering) &&
             (!complete_content_length_request_policy_is_admitted(c.request_policy_id) &&
                  !bodyless_get_retained_policy ||
              !complete_content_length_route_method_is_admitted(
                  c.http1_prebuilt_deadline_route_method) ||
              c.http1_prebuilt_deadline_upload.request_policy_id != c.request_policy_id ||
              (response_read_deadline_profile_is_fixed_upload(c.http1_prebuilt_deadline_profile) &&
               !complete_content_length_fixed_upload_materialization_is_stable(
                   c,
                   c.http1_prebuilt_deadline_upload,
                   c.http1_prebuilt_deadline_profile,
                   /*require_upload_complete=*/true,
                   c.http1_prebuilt_deadline_bundle_id,
                   c.http1_prebuilt_deadline_route_method,
                   bundle.response_buffering)) ||
              (c.http1_prebuilt_deadline_upload.downstream_close &&
               !complete_content_length_explicit_close_request_is_stable(
                   c,
                   c.http1_prebuilt_deadline_upload,
                   bundle.response_buffering,
                   c.http1_prebuilt_deadline_profile)))) ||
            bundle.response_policy_id != c.response_policy_id ||
            bundle.failure_policy_id != c.failure_policy_id ||
            bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
            !c.request_config->response_policy_id_is_valid(c.response_policy_id) ||
            !c.request_config->failure_policy_id_is_valid(c.failure_policy_id) ||
            !c.request_config->timeout_failure_policy_id_is_valid(c.timeout_failure_policy_id))
            return false;
        const auto& response = c.request_config->response_policies[c.response_policy_id - 1];
        const auto& failure = c.request_config->failure_policies[c.failure_policy_id - 1];
        const auto& timeout = c.request_config->failure_policies[c.timeout_failure_policy_id - 1];
        if (c.http1_prebuilt_response_layout == Http1PrebuiltResponseLayout::HeaderOnlyHead) {
            if (!response_read_deadline_profile_suppresses_head(
                    c.http1_prebuilt_deadline_profile) ||
                c.http1_prebuilt_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
                response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
                failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
                timeout.head_mode != FailurePolicyHeadMode::SuppressBody ||
                c.http1_prebuilt_header_end != c.http1_prebuilt_total_len ||
                !prebuilt_http1_header_is_complete(c))
                return false;
            if (c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::ResponseReadTimeout) {
                if (!fixed_upload_head_timeout) {
                    if (header_only_head_timeout)
                        return response_read_timeout_header_only_head_response_is_stable(
                            c,
                            c.http1_prebuilt_deadline_upload,
                            c.http1_prebuilt_deadline_config,
                            c.http1_prebuilt_deadline_bundle_id,
                            c.http1_prebuilt_deadline_generation,
                            response_phase);
                    return c.http1_prebuilt_body_len == 0;
                }
                if (!fixed_upload_head_success_proof_is_stable(
                        c,
                        c.http1_prebuilt_deadline_upload,
                        c.http1_prebuilt_deadline_config,
                        c.http1_prebuilt_deadline_bundle_id,
                        c.http1_prebuilt_deadline_profile,
                        bundle.response_buffering,
                        c.http1_prebuilt_deadline_method,
                        c.http1_prebuilt_deadline_route_method,
                        true,
                        false))
                    return false;
                HttpResponseParser parser;
                ParsedResponse parsed;
                parser.reset();
                parsed.reset();
                if (parser.parse(c.response_header_buf.data(),
                                 c.response_header_buf.len(),
                                 &parsed) != ParseStatus::Complete ||
                    parser.header_end != c.http1_prebuilt_header_end ||
                    parsed.version != HttpVersion::Http11 ||
                    parsed.status_code != timeout.status_code ||
                    parsed.reason.len != timeout.reason.len ||
                    (timeout.reason.len != 0 &&
                     __builtin_memcmp(parsed.reason.ptr, timeout.reason.ptr, timeout.reason.len) !=
                         0) ||
                    parsed.content_length_count != 1 || parsed.chunked ||
                    parsed.headers_truncated ||
                    parsed.content_length != c.http1_prebuilt_body_len ||
                    c.http1_prebuilt_body_len != timeout.body.len)
                    return false;
                auto exact_header = [&](const char* name, u32 name_len, Str expected) {
                    u32 count = 0;
                    for (u32 i = 0; i < parsed.header_count; ++i) {
                        if (!http_header_name_eq_ci(parsed.headers[i].name.ptr,
                                                    parsed.headers[i].name.len,
                                                    name,
                                                    name_len))
                            continue;
                        ++count;
                        if (parsed.headers[i].value.len != expected.len ||
                            (expected.len != 0 &&
                             __builtin_memcmp(
                                 parsed.headers[i].value.ptr, expected.ptr, expected.len) != 0))
                            return false;
                    }
                    return count == 1;
                };
                auto exact_date = [&] {
                    u32 count = 0;
                    for (u32 i = 0; i < parsed.header_count; ++i) {
                        if (!http_header_name_eq_ci(
                                parsed.headers[i].name.ptr, parsed.headers[i].name.len, "date", 4))
                            continue;
                        ++count;
                        if (parsed.headers[i].value.len != 29) return false;
                    }
                    return count == 1;
                };
                static constexpr Str kKeepAlive{"keep-alive", 10};
                return exact_header("server", 6, timeout.server) && exact_date() &&
                       exact_header("content-type", 12, timeout.content_type) &&
                       exact_header("connection", 10, kKeepAlive);
            }
            if (c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::ConfiguredForwardFailure) {
                const auto& configured = failure;
                if (!fixed_upload_head_success_proof_is_stable(
                        c,
                        c.http1_prebuilt_deadline_upload,
                        c.http1_prebuilt_deadline_config,
                        c.http1_prebuilt_deadline_bundle_id,
                        c.http1_prebuilt_deadline_profile,
                        bundle.response_buffering,
                        c.http1_prebuilt_deadline_method,
                        c.http1_prebuilt_deadline_route_method,
                        /*allow_retired_episode=*/true,
                        allow_consumed_terminal_episode))
                    return false;
                HttpResponseParser parser;
                ParsedResponse parsed;
                parser.reset();
                parsed.reset();
                if (parser.parse(c.response_header_buf.data(),
                                 c.response_header_buf.len(),
                                 &parsed) != ParseStatus::Complete ||
                    parser.header_end != c.http1_prebuilt_header_end ||
                    parsed.version != HttpVersion::Http11)
                    return false;
                if (configured.version != ForwardFailurePolicyVersion::Http11 ||
                    configured.status_code != kStatusBadGateway ||
                    configured.connection != ForwardFailurePolicyConnection::Request ||
                    configured.head_mode != FailurePolicyHeadMode::SuppressBody ||
                    parsed.status_code != configured.status_code ||
                    parsed.reason.len != configured.reason.len ||
                    (configured.reason.len != 0 &&
                     __builtin_memcmp(
                         parsed.reason.ptr, configured.reason.ptr, configured.reason.len) != 0) ||
                    parsed.content_length_count != 1 ||
                    parsed.content_length != configured.body.len || parsed.chunked ||
                    parsed.headers_truncated || c.http1_prebuilt_body_len != 0)
                    return false;
                auto exact_header = [&](const char* name, u32 name_len, Str expected) {
                    u32 count = 0;
                    for (u32 i = 0; i < parsed.header_count; ++i) {
                        if (!http_header_name_eq_ci(parsed.headers[i].name.ptr,
                                                    parsed.headers[i].name.len,
                                                    name,
                                                    name_len))
                            continue;
                        ++count;
                        if (parsed.headers[i].value.len != expected.len ||
                            (expected.len != 0 &&
                             __builtin_memcmp(
                                 parsed.headers[i].value.ptr, expected.ptr, expected.len) != 0))
                            return false;
                    }
                    return count == 1;
                };
                u32 date_count = 0;
                for (u32 i = 0; i < parsed.header_count; ++i) {
                    if (!http_header_name_eq_ci(
                            parsed.headers[i].name.ptr, parsed.headers[i].name.len, "date", 4))
                        continue;
                    ++date_count;
                    if (!response_read_deadline_http_date_is_normalized(parsed.headers[i].value))
                        return false;
                }
                static constexpr Str kKeepAlive{"keep-alive", 10};
                return date_count == 1 && exact_header("server", 6, configured.server) &&
                       exact_header("content-type", 12, configured.content_type) &&
                       exact_header("connection", 10, kKeepAlive);
            }
            if (c.http1_prebuilt_response_purpose !=
                    Http1PrebuiltResponsePurpose::StrictHeadHeaderOnly ||
                !fixed_upload_head_success_proof_is_stable(c,
                                                           c.http1_prebuilt_deadline_upload,
                                                           c.http1_prebuilt_deadline_config,
                                                           c.http1_prebuilt_deadline_bundle_id,
                                                           c.http1_prebuilt_deadline_profile,
                                                           bundle.response_buffering,
                                                           c.http1_prebuilt_deadline_method,
                                                           c.http1_prebuilt_deadline_route_method,
                                                           true,
                                                           allow_consumed_terminal_episode))
                return false;
            HttpResponseParser parser;
            ParsedResponse parsed;
            parser.reset();
            parsed.reset();
            return parser.parse(c.response_header_buf.data(),
                                c.response_header_buf.len(),
                                &parsed) == ParseStatus::Complete &&
                   parser.header_end == c.http1_prebuilt_header_end &&
                   parsed.version == HttpVersion::Http11 && parsed.status_code == 200 &&
                   parsed.content_length_count == 1 && !parsed.chunked &&
                   !parsed.headers_truncated && parsed.content_length == c.http1_prebuilt_body_len;
        }
        const bool strict_no_body_metadata =
            c.http1_prebuilt_response_layout ==
                Http1PrebuiltResponseLayout::HeaderOnlyNoBodyStatus &&
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::StrictNoBodyMetadataSuccess;
        if (!strict_no_body_metadata && c.http1_prebuilt_response_layout !=
                                            Http1PrebuiltResponseLayout::FullContentLengthNonHead)
            return false;
        const bool fixed_upload =
            response_read_deadline_profile_is_fixed_upload(c.http1_prebuilt_deadline_profile);
        const bool materialized_get =
            !fixed_upload && c.http1_prebuilt_deadline_upload.raw_total_length != 0;
        const bool request_removed = c.request_upload_complete;
        const bool exact_get =
            materialized_get && (request_removed ? c.pipeline_stash_len == 0
                                                 : c.recv_buf.len() == c.req_initial_send_len);
        const bool coalesced_get =
            materialized_get && (request_removed ? c.pipeline_stash_len != 0
                                                 : c.recv_buf.len() > c.req_initial_send_len);
        const bool materialized_get_proof =
            materialized_get && (exact_get || coalesced_get) && c.retry_req_send_len == 0 &&
            response_read_deadline_coalesced_get_phase1_proof_is_stable(
                c,
                c.http1_prebuilt_deadline_upload,
                /*allow_retired_episode=*/true,
                /*require_upload_episode=*/true,
                c.http1_prebuilt_deadline_profile,
                bundle.response_buffering,
                c.http1_prebuilt_deadline_bundle_id,
                c.http1_prebuilt_deadline_method,
                c.http1_prebuilt_deadline_route_method);
        if ((!fixed_upload && c.http1_prebuilt_deadline_profile !=
                                  ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero) ||
            (fixed_upload
                 ? !response_read_deadline_fixed_upload_method_admitted(
                       c.http1_prebuilt_deadline_method, bundle.response_buffering) ||
                       !response_read_deadline_fixed_upload_materialization_is_stable(
                           c,
                           c.http1_prebuilt_deadline_upload,
                           c.http1_prebuilt_deadline_profile,
                           /*require_upload_complete=*/true,
                           c.http1_prebuilt_deadline_bundle_id,
                           c.http1_prebuilt_deadline_route_method,
                           bundle.response_buffering,
                           /*allow_retired_episode=*/true)
                 : !response_read_deadline_non_head_method_admitted(
                       c.http1_prebuilt_deadline_method) ||
                       (materialized_get && !materialized_get_proof) ||
                       (coalesced_get && request_removed &&
                        !response_read_deadline_coalesced_get_phase1_prebuilt_stash_is_stable(
                            c,
                            c.http1_prebuilt_deadline_upload,
                            c.http1_prebuilt_deadline_profile,
                            bundle.response_buffering,
                            c.http1_prebuilt_deadline_bundle_id,
                            c.http1_prebuilt_deadline_method,
                            c.http1_prebuilt_deadline_route_method,
                            /*allow_retired_episode=*/true))) ||
            response.head_mode != ResponsePolicyHeadMode::Reject ||
            failure.head_mode != FailurePolicyHeadMode::Reject ||
            timeout.head_mode != FailurePolicyHeadMode::Reject)
            return false;
        HttpResponseParser parser;
        ParsedResponse parsed;
        parser.reset();
        parsed.reset();
        if (parser.parse(c.response_header_buf.data(), c.response_header_buf.len(), &parsed) !=
                ParseStatus::Complete ||
            parsed.version != HttpVersion::Http11 ||
            parsed.status_code != c.http1_prebuilt_status || parsed.content_length_count != 1 ||
            parsed.chunked || parsed.headers_truncated ||
            parser.header_end != c.http1_prebuilt_header_end ||
            parsed.content_length != c.http1_prebuilt_body_len)
            return false;
        auto exact_header = [&](const char* name, u32 name_len, Str expected) {
            u32 count = 0;
            for (u32 i = 0; i < parsed.header_count; ++i) {
                if (!http_header_name_eq_ci(
                        parsed.headers[i].name.ptr, parsed.headers[i].name.len, name, name_len))
                    continue;
                ++count;
                if (parsed.headers[i].value.len != expected.len ||
                    (expected.len != 0 &&
                     __builtin_memcmp(parsed.headers[i].value.ptr, expected.ptr, expected.len) !=
                         0))
                    return false;
            }
            return count == 1;
        };
        static constexpr Str kKeepAlive{"keep-alive", 10};
        static constexpr Str kClose{"close", 5};
        const Str expected_connection =
            c.http1_prebuilt_deadline_upload.downstream_close ? kClose : kKeepAlive;
        if (c.http1_prebuilt_response_layout ==
                Http1PrebuiltResponseLayout::HeaderOnlyNoBodyStatus ||
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::StrictNoBodyMetadataSuccess) {
            return strict_no_body_metadata && !fixed_upload && materialized_get_proof &&
                   c.pipeline_depth == 0 && c.http1_pipeline_request_generation == 0 &&
                   c.pipeline_stash_len == 0 && c.retry_req_send_len == 0 && !c.upstream_reused &&
                   c.upstream_attempts == 1 &&
                   c.http1_prebuilt_deadline_profile ==
                       ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                   forward_response_buffering_uses_content_length_machinery(
                       bundle.response_buffering) &&
                   c.http1_prebuilt_deadline_method == static_cast<u8>(LogHttpMethod::Get) &&
                   c.http1_prebuilt_deadline_route_method == kRouteMethodGet &&
                   (c.upstream_retirement_target_owned & static_cast<u8>(~kUpstreamOpRecv)) == 0 &&
                   (c.upstream_retirement_cancel_owned & static_cast<u8>(~kUpstreamOpRecv)) == 0 &&
                   (c.upstream_retirement_cancel_retry & static_cast<u8>(~kUpstreamOpRecv)) == 0 &&
                   parsed.status_code == 304 && c.http1_prebuilt_status == 304 &&
                   c.http1_prebuilt_body_len > 0 &&
                   c.http1_prebuilt_header_end == c.http1_prebuilt_total_len &&
                   response.head_mode == ResponsePolicyHeadMode::Reject &&
                   exact_header("server", 6, response.server) &&
                   exact_header("connection", 10, kKeepAlive);
        }
        if (c.http1_prebuilt_response_purpose ==
            Http1PrebuiltResponsePurpose::StrictNonHeadCl0Success) {
            return parsed.status_code == 200 && c.http1_prebuilt_body_len == 0 &&
                   response.head_mode == ResponsePolicyHeadMode::Reject &&
                   exact_header("server", 6, response.server) &&
                   exact_header("connection", 10, expected_connection);
        }
        if (c.http1_prebuilt_response_purpose != Http1PrebuiltResponsePurpose::ResponseReadTimeout)
            return false;
        const u8* body = c.response_header_buf.data() + c.http1_prebuilt_header_end;
        return parsed.status_code == timeout.status_code &&
               parsed.reason.len == timeout.reason.len &&
               __builtin_memcmp(parsed.reason.ptr, timeout.reason.ptr, timeout.reason.len) == 0 &&
               c.http1_prebuilt_body_len == timeout.body.len &&
               (timeout.body.len == 0 ||
                __builtin_memcmp(body, timeout.body.ptr, timeout.body.len) == 0) &&
               exact_header("server", 6, timeout.server) &&
               exact_header("content-type", 12, timeout.content_type) &&
               exact_header("connection", 10, expected_connection);
    }

    bool prebuilt_http1_layout_is_valid(const Connection& c,
                                        u8 selected_targets,
                                        Http1RequestBufferDisposition disposition,
                                        u32 request_prefix_len) const {
        const bool retiring_connect = (selected_targets & kUpstreamOpConnect) != 0;
        const bool retiring_send = (selected_targets & kUpstreamOpSend) != 0;
        const auto& send = backend.upstream_send_state[c.id];
        auto exact_send_source = [&](const u8* expected, u32 total) {
            return !retiring_send ||
                   (expected != nullptr && send.src == expected && send.offset <= total &&
                    send.remaining == total - send.offset && send.fd == c.upstream_fd &&
                    send.type == IoEventType::UpstreamSend &&
                    send.upstream_episode == c.upstream_episode);
        };

        switch (disposition) {
            case Http1RequestBufferDisposition::PrefixInRecv:
                // Before the initial upload completes, request 1 is still the
                // exact prefix of recv_buf. The only possible transport phases
                // are connect establishment or a fresh send sourced from that
                // prefix; a recv-only/owner-free handoff cannot prove this
                // layout.
                return !c.request_upload_complete && !c.upstream_request_incomplete &&
                       (retiring_connect || retiring_send) &&
                       (!retiring_connect || selected_targets == kUpstreamOpConnect) &&
                       request_prefix_len != 0 && request_prefix_len == c.req_initial_send_len &&
                       request_prefix_len <= c.recv_buf.len() && c.retry_req_send_len == 0 &&
                       c.pipeline_stash_len == 0 &&
                       exact_send_source(c.recv_buf.data(), request_prefix_len);
            case Http1RequestBufferDisposition::RetrySendBuf:
                // A retry snapshot is meaningful only while its exact replay
                // send is live and sourced from send_buf. Connect ownership is
                // not evidence that this snapshot is the active request.
                return !c.request_upload_complete && !c.upstream_request_incomplete &&
                       !retiring_connect && retiring_send && request_prefix_len != 0 &&
                       request_prefix_len == c.retry_req_send_len && c.pipeline_stash_len == 0 &&
                       request_prefix_len <= c.send_buf.len() &&
                       exact_send_source(c.send_buf.data(), request_prefix_len);
            case Http1RequestBufferDisposition::ExistingPipeline: {
                // The upload callback has already removed request 1 from
                // recv_buf. recv_buf therefore starts at the next-request
                // boundary, while any retry snapshot/pipeline stash remains in
                // send_buf until both rendezvous owners drain. A live Send has
                // not reached that callback and belongs to RetrySendBuf instead.
                const u32 stored =
                    static_cast<u32>(c.retry_req_send_len) + static_cast<u32>(c.pipeline_stash_len);
                const bool materialized_get =
                    c.http1_prebuilt_deadline_profile ==
                        ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                    c.http1_prebuilt_deadline_upload.raw_total_length != 0;
                const bool coalesced_get = materialized_get && c.pipeline_stash_len != 0;
                const bool exact_get = materialized_get && c.pipeline_stash_len == 0;
                const bool exact_get_stable =
                    exact_get && c.retry_req_send_len == 0 &&
                    response_read_deadline_coalesced_get_phase1_proof_is_stable(
                        c,
                        c.http1_prebuilt_deadline_upload,
                        /*allow_retired_episode=*/true,
                        /*require_upload_episode=*/true,
                        c.http1_prebuilt_deadline_profile,
                        c.http1_prebuilt_deadline_config != nullptr &&
                                c.http1_prebuilt_deadline_config->policy_bundle_id_is_valid(
                                    c.http1_prebuilt_deadline_bundle_id)
                            ? c.http1_prebuilt_deadline_config
                                  ->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1]
                                  .response_buffering
                            : ForwardResponseBufferingMode::None,
                        c.http1_prebuilt_deadline_bundle_id,
                        c.http1_prebuilt_deadline_method,
                        c.http1_prebuilt_deadline_route_method);
                return c.request_upload_complete && !c.upstream_request_incomplete &&
                       !retiring_connect && !retiring_send &&
                       request_prefix_len == c.retry_req_send_len && stored <= c.send_buf.len() &&
                       (!materialized_get || exact_get_stable ||
                        (coalesced_get &&
                         response_read_deadline_coalesced_get_phase1_prebuilt_stash_is_stable(
                             c,
                             c.http1_prebuilt_deadline_upload,
                             c.http1_prebuilt_deadline_profile,
                             c.http1_prebuilt_deadline_config != nullptr &&
                                     c.http1_prebuilt_deadline_config->policy_bundle_id_is_valid(
                                         c.http1_prebuilt_deadline_bundle_id)
                                 ? c.http1_prebuilt_deadline_config
                                       ->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1]
                                       .response_buffering
                                 : ForwardResponseBufferingMode::None,
                             c.http1_prebuilt_deadline_bundle_id,
                             c.http1_prebuilt_deadline_method,
                             c.http1_prebuilt_deadline_route_method,
                             /*allow_retired_episode=*/true)));
            }
            case Http1RequestBufferDisposition::None:
                return false;
        }
        return false;
    }

    void publish_prebuilt_http1_ready(Connection& c) {
        if (c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_wait != 0 || !c.http1_boundary_deferred || c.http1_boundary_ready)
            return;
        maybe_publish_http1_boundary_ready(c);
    }

    bool normalize_prebuilt_http1_request_buffer(Connection& c) {
        const u32 prefix = c.http1_prebuilt_request_prefix_len;
        switch (c.http1_prebuilt_disposition) {
            case Http1RequestBufferDisposition::PrefixInRecv: {
                if (prefix == 0 || prefix != c.req_initial_send_len || prefix > c.recv_buf.len() ||
                    c.retry_req_send_len != 0 || c.pipeline_stash_len != 0)
                    return false;
                const u32 late = c.recv_buf.len() - prefix;
                if (late != 0) __builtin_memmove(c.recv_slice, c.recv_buf.data() + prefix, late);
                c.clear_raw_request_target_witness();
                c.recv_buf.set_len(late);
                return true;
            }
            case Http1RequestBufferDisposition::RetrySendBuf:
                if (prefix == 0 || prefix != c.retry_req_send_len || c.pipeline_stash_len != 0 ||
                    prefix > c.send_buf.len())
                    return false;
                c.retry_req_send_len = 0;
                c.send_buf.reset();
                return true;
            case Http1RequestBufferDisposition::ExistingPipeline:
                return prefix == c.retry_req_send_len &&
                       static_cast<u32>(c.retry_req_send_len) +
                               static_cast<u32>(c.pipeline_stash_len) <=
                           c.send_buf.len();
            case Http1RequestBufferDisposition::None:
                return false;
        }
        return false;
    }

    [[nodiscard]] bool begin_upstream_retirement_impl(Connection& c,
                                                      u8 selected_targets,
                                                      bool detached_recv_callback,
                                                      bool transfer_live_state) {
        constexpr u8 kAllUpstreamOps = kUpstreamOpConnect | kUpstreamOpRecv | kUpstreamOpSend;
        const u32 previous_tombstone = c.upstream_retiring_episode;
        const bool replaceable_tombstone =
            previous_tombstone == 0 ||
            (valid_upstream_episode(previous_tombstone) &&
             previous_tombstone < c.upstream_episode && !c.upstream_retirement_active &&
             c.upstream_retirement_target_owned == 0 && c.upstream_retirement_cancel_owned == 0 &&
             c.upstream_retirement_cancel_retry == 0);
        if (c.id >= connection_capacity || c.upstream_episode_quarantined ||
            !valid_upstream_episode(c.upstream_episode) || !replaceable_tombstone ||
            (selected_targets & static_cast<u8>(~kAllUpstreamOps)) != 0 ||
            ((selected_targets & kUpstreamOpConnect) != 0 &&
             (selected_targets & kUpstreamOpSend) != 0) ||
            c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
            c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
            c.upstream_close_episode != 0 || c.upstream_close_target_owned != 0 ||
            c.upstream_close_cancel_owned != 0 || c.upstream_close_pause_cancel_owned ||
            c.http1_boundary_deferred || c.http1_boundary_ready || c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_request_prefix_len != 0 || c.http1_boundary_successor_episode != 0 ||
            c.upstream_fd < 0 || c.send_armed || c.yield_armed || c.yield_timeout_armed ||
            c.recv_paused_for_send || c.recv_pause_cancel_pending || c.recv_pause_target_inflight ||
            c.recv_pause_rearm_pending || c.upstream_recv_paused_for_send ||
            c.upstream_recv_pause_cancel_pending || c.upstream_recv_pause_rearm_pending ||
            c.upstream_recv_cancel_inflight || c.upstream_recv_terminal_stale)
            return false;

        const auto& downstream_send = backend.send_state[c.id];
        const auto& upstream_send = backend.upstream_send_state[c.id];
        if (downstream_send.remaining != 0) return false;

        u8 actual_targets = 0;
        if (c.upstream_connect_armed) actual_targets |= kUpstreamOpConnect;
        if (c.upstream_recv_armed) actual_targets |= kUpstreamOpRecv;
        if (c.upstream_send_armed) actual_targets |= kUpstreamOpSend;
        if (actual_targets != selected_targets) return false;
        if ((selected_targets & (kUpstreamOpConnect | kUpstreamOpSend)) != 0 &&
            c.on_upstream_send == nullptr)
            return false;
        if ((selected_targets & kUpstreamOpRecv) != 0 && !detached_recv_callback &&
            c.on_upstream_recv == nullptr)
            return false;

        if ((selected_targets & kUpstreamOpSend) != 0) {
            if (upstream_send.src == nullptr || upstream_send.fd != c.upstream_fd ||
                upstream_send.remaining == 0 || upstream_send.type != IoEventType::UpstreamSend ||
                upstream_send.upstream_episode != c.upstream_episode)
                return false;
        } else if (upstream_send.remaining != 0) {
            return false;
        }

        // Exact equality excludes every unrepresented target or cancel CQE.
        const u32 expected_pending =
            static_cast<u32>(c.recv_armed) + upstream_op_count(selected_targets);
        if (c.pending_ops != expected_pending) return false;

        // Replace a fully-drained older tombstone directly with the exact
        // current token. Never clear it through zero: from this assignment on,
        // every older episode remains default-denied by the latest-retirement
        // consumer while this exact episode owns the new recv/cancel finals.
        const u32 retiring_episode = c.upstream_episode;
        c.upstream_retiring_episode = retiring_episode;
        c.upstream_retirement_active = selected_targets != 0;
        c.upstream_retirement_target_owned = selected_targets;
        c.upstream_retirement_cancel_owned = 0;
        c.upstream_retirement_cancel_retry = 0;

        // The generic entry moves ownership atomically into the retirement
        // ledger. Leaving an old armed flag behind would let a synchronous
        // downstream close misclassify that old target as a successor op. The
        // legacy strict wrapper preserves its existing enclosing handoff: its
        // callback was already detached and abandon_strict_upstream clears the
        // recv flag synchronously before returning to the event loop.
        if (transfer_live_state) {
            if ((selected_targets & kUpstreamOpConnect) != 0) c.upstream_connect_armed = false;
            if ((selected_targets & kUpstreamOpRecv) != 0) {
                c.upstream_recv_armed = false;
                c.on_upstream_recv = nullptr;
            }
            if ((selected_targets & kUpstreamOpSend) != 0) c.upstream_send_armed = false;
            if ((selected_targets & (kUpstreamOpConnect | kUpstreamOpSend)) != 0)
                c.on_upstream_send = nullptr;
        }

        // Publish a different current token before another backend wait can
        // inspect a provided-buffer CQE. At exhaustion, use an unrepresentable
        // current token and permanently quarantine the allocator slot.
        if (!c.next_upstream_episode()) {
            c.upstream_episode = kInvalidUpstreamEventEpisode;
            c.upstream_episode_quarantined = true;
        }

        if (selected_targets == 0) {
            c.upstream_retirement_active = false;
            return true;
        }

        for (u8 op : {kUpstreamOpConnect, kUpstreamOpSend, kUpstreamOpRecv}) {
            if ((selected_targets & op) == 0) continue;
            if (backend.cancel_retiring_upstream(
                    c.id, upstream_event_for_op(op), retiring_episode)) {
                c.upstream_retirement_cancel_owned |= op;
                c.pending_ops++;
            } else {
                c.upstream_retirement_cancel_retry |= op;
                upstream_retirement_retry_count++;
            }
        }
        return true;
    }

public:
    // Queue an already-built immutable local failure response. Cleartext uses
    // the private staged helper's single flush/retry; TLS has a separate
    // one-shot path because SSL_write consumes plaintext before ciphertext
    // submission and therefore cannot safely retry after SQ exhaustion.
    [[nodiscard]] bool submit_staged_local_response(Connection& c, const u8* src, u32 len) {
        if (c.tls_active)
            return submit_staged_tls_local_response_impl(
                c, src, len, [&]() { return submit_send_impl(c, src, len); });
        return submit_staged_local_response_impl(
            c,
            src,
            len,
            [&]() {
                return !detail::injected_iouring_submit_failure(
                           detail::kTestIoUringStagedSendSubmit) &&
                       submit_send_raw(c, src, len);
            },
            [&]() { return backend.flush_pending_nonblocking(); });
    }

#ifdef RUT_TESTING
    template <typename AttemptObserver, typename FlushResult>
    [[nodiscard]] bool test_submit_staged_local_response(Connection& c,
                                                         const u8* src,
                                                         u32 len,
                                                         AttemptObserver&& observe_attempt,
                                                         FlushResult&& flush_result) {
        return submit_staged_local_response_impl(
            c,
            src,
            len,
            [&]() {
                observe_attempt();
                return submit_send_raw(c, src, len);
            },
            [&]() { return backend.test_flush_pending_nonblocking(flush_result); });
    }
#endif

    // Establish exact transport ownership for a bounded upstream episode. This
    // is foundation only: Connect/Send callers may not publish an HTTP/1
    // request boundary until #265's later epoch/header rendezvous exists.
    [[nodiscard]] bool begin_upstream_retirement(Connection& c, u8 selected_targets) {
        if (selected_targets == 0) return false;
        return begin_upstream_retirement_impl(c, selected_targets, false, true);
    }

    // Use the existing separate receive ring so a large buffered origin
    // cannot consume all buffers needed by downstream TLS requests.
    bool add_response_read_recv(Connection& c, bool direct_buffered_body = false) {
        const auto phase = c.response_read_deadline_post_commit_phase;
        const bool bounded_stream =
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
            (phase == ResponseReadDeadlinePostCommitPhase::HeaderSend ||
             phase == ResponseReadDeadlinePostCommitPhase::BodySend ||
             phase == ResponseReadDeadlinePostCommitPhase::WaitingBody);
        if (direct_buffered_body || bounded_stream) return arm_response_read_direct_body_recv(c);
        const bool complete_buffering = forward_response_buffering_uses_content_length_machinery(
            c.response_read_deadline_buffering);
        // Keep the header/first-body target on the dedicated provided ring.
        // Direct tail reads begin only after a later body recv's natural
        // terminal has been authenticated by whole-batch settlement.
        return backend.add_first_response_recv(c.upstream_fd,
                                               c.id,
                                               c.upstream_episode,
                                               complete_buffering,
                                               /*one_shot=*/complete_buffering);
    }

    // A one-shot recv of the rest of a buffered Content-Length body
    // straight into the chain's tail node, with no provided-buffer copy.
    // It is armed only after the previous one-shot provided-buffer recv has
    // naturally terminated. The capacity is capped at the response body limit
    // plus one byte, so a same-CQE Content-Length overrun remains observable
    // and fail-closed instead of being silently truncated.
    //
    // Deliberately not MSG_WAITALL: settle_response_read_deadline_batch
    // refreshes the inactivity deadline only on a positive recv CQE, so a
    // WAITALL recv filling a 256 KiB node from a steadily trickling origin
    // would expire the response although no single gap reached
    // response_read_timeout.
    [[nodiscard]] bool arm_response_read_direct_body_recv(Connection& c) {
        const auto phase = c.response_read_deadline_post_commit_phase;
        const bool buffering = phase == ResponseReadDeadlinePostCommitPhase::Buffering;
        const bool bounded_stream =
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
            (phase == ResponseReadDeadlinePostCommitPhase::HeaderSend ||
             phase == ResponseReadDeadlinePostCommitPhase::BodySend ||
             phase == ResponseReadDeadlinePostCommitPhase::WaitingBody);
        if ((!buffering && !bounded_stream) ||
            c.response_read_deadline_post_commit_terminal_pending ||
            c.response_read_deadline_post_commit_close_after_drain)
            return false;
        const u32 declared = c.response_read_deadline_post_commit_declared_body;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        const u32 raw_header_end = c.response_read_deadline_post_commit_raw_header_end;
        const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
        const u32 header = buffering || phase == ResponseReadDeadlinePostCommitPhase::HeaderSend
                               ? raw_header_end
                               : 0;
        if (received >= declared || raw_header_end == 0 || completed > received ||
            header > 0xFFFFFFFFu - (received - completed) ||
            c.buffered_response_len() != header + received - completed ||
            !response_read_deadline_identity_is_stable(c) || c.chain_direct_recv_owner.active ||
            c.upstream_recv_armed || c.upstream_recv_pause_cancel_pending ||
            c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
            c.upstream_recv_terminal_stale || c.upstream_fd < 0 ||
            !valid_upstream_episode(c.upstream_episode))
            return false;
        const u32 bulk_after =
            !c.tls_active &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    declared > SlicePool::kBulkSliceSize
                ? 0
                : c.buffered_response_bulk_after();
        if (!c.response_body_tail.reserve_tail(pool, bulk_after)) return false;
        const u32 avail = c.response_body_tail.write_avail(pool);
        const u32 body_room = ResponseBodyChain::kMaxBody - received + 1u;
        const u32 len = avail < body_room ? avail : body_room;
        if (len == 0) return false;
        u8* dst = c.response_body_tail.write_ptr(pool);
        if (!backend.add_recv_upstream_direct(c.upstream_fd, c.id, c.upstream_episode, dst, len))
            return false;
        c.chain_direct_recv_owner = {c.response_body_tail.tail, dst, len, c.upstream_episode, true};
        c.upstream_recv_direct_armed = true;
        c.upstream_recv_pause_rearm_pending = false;
        return true;
    }

    // Exact one-dispatch witness for a positive terminal upstream Recv.  The
    // owner was captured before generic CQE accounting consumed the armed flag
    // and pending count.  It is intentionally stored only in the bounded batch
    // ledger and becomes unavailable as soon as dispatch_batch returns.
    [[nodiscard]] bool current_terminal_response_recv_is_exact(const Connection& c,
                                                               const IoEvent& ev,
                                                               u32 deadline_generation,
                                                               ResponseReadDeadlineProfile profile,
                                                               u8 method,
                                                               u32 upstream_episode) const {
        if (response_read_batch_event_index >= response_read_batch_event_count ||
            ev.type != IoEventType::UpstreamRecv || ev.conn_id != c.id || ev.aux != 0 ||
            ev.result <= 0 || ev.more || ev.upstream_episode != upstream_episode ||
            ev.copy_witness != IoEventCopyWitness::Full ||
            ev.copy_deadline_generation != deadline_generation ||
            ev.copy_deadline_profile != static_cast<u8>(profile) ||
            ev.copy_deadline_method != method || ev.copy_end < ev.copy_begin ||
            ev.copy_end - ev.copy_begin != static_cast<u32>(ev.result) ||
            ev.copy_end != c.buffered_response_len() || c.upstream_episode != upstream_episode)
            return false;
        const u16 owner_index = response_read_batch_event_owner[response_read_batch_event_index];
        if (owner_index == 0 || owner_index > response_read_batch_owner_count) return false;
        const auto& owner = response_read_batch_owners[owner_index - 1u];
        return owner.valid && owner.conn_id == c.id &&
               owner.deadline_generation == deadline_generation && owner.profile == profile &&
               owner.method == method && owner.upstream_episode == upstream_episode &&
               !owner.post_commit_at_start && owner.saw_positive && owner.saw_terminal &&
               owner.positive_terminal && !owner.terminal_fault && !owner.clean_eof &&
               !owner.terminal_error && owner.last_relevant == response_read_batch_event_index &&
               owner.last_positive == response_read_batch_event_index &&
               owner.expected_copy_end == c.buffered_response_len();
    }

    // The strict no-body metadata success is evidenced only while the origin's
    // Recv remains live. A later EOF/error already present in this wait batch
    // cannot be hidden by dispatching the complete positive header first.
    [[nodiscard]] bool current_response_read_batch_keeps_origin_open(const Connection& c,
                                                                     const IoEvent& ev) const {
        if (response_read_batch_event_index >= response_read_batch_event_count ||
            ev.type != IoEventType::UpstreamRecv || ev.conn_id != c.id || ev.result <= 0 ||
            ev.aux != 0)
            return false;
        const u16 owner_index = response_read_batch_event_owner[response_read_batch_event_index];
        if (owner_index == 0 || owner_index > response_read_batch_owner_count) return false;
        const auto& owner = response_read_batch_owners[owner_index - 1u];
        return owner.valid && owner.conn_id == c.id &&
               owner.deadline_generation == c.response_read_deadline_generation &&
               owner.profile == c.response_read_deadline_profile &&
               owner.method == c.response_read_deadline_method &&
               owner.upstream_episode == c.upstream_episode && owner.saw_positive &&
               !owner.saw_terminal;
    }

    // Advance an exact, owner-free episode into the persistent tombstone. This
    // is for callbacks that observe a terminal upstream record after normal CQE
    // accounting has already cleared the final target; it never fabricates an
    // operation or pending count.
    [[nodiscard]] bool advance_upstream_retirement_tombstone(Connection& c) {
        return begin_upstream_retirement_impl(c, 0, false, true);
    }

    // The 504 TLS bridge is narrower than the general prebuilt-response path:
    // it only accepts the fully typed CompleteContentLength bodyless-GET
    // timeout frame, and only while TLS output ownership is settled.
    bool prebuilt_http11_tls_read_timeout_is_stable(const Connection& c,
                                                    bool sending = false) const {
        if (c.id >= connection_capacity || c.fd < 0 || c.request_config == nullptr ||
            c.http1_prebuilt_deadline_config != c.request_config ||
            !c.request_config->policy_bundle_id_is_valid(c.http1_prebuilt_deadline_bundle_id))
            return false;
        const auto& bundle =
            c.request_config->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1u];
        const u8 expected_wait =
            kHttp1WaitHeaderSend |
            (c.upstream_retirement_active ? kHttp1WaitUpstreamRetirement : static_cast<u8>(0));
        const bool phase_state =
            sending ? (c.state == ConnState::Sending &&
                       c.http1_prebuilt_disposition ==
                           Http1RequestBufferDisposition::ExistingPipeline &&
                       c.http1_prebuilt_wait == expected_wait && !c.http1_boundary_deferred &&
                       c.http1_prebuilt_request_prefix_len == 0 && !c.http1_boundary_ready &&
                       c.http1_boundary_successor_episode == c.upstream_episode)
                    : (c.state == ConnState::Proxying &&
                       c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None &&
                       c.http1_prebuilt_wait == 0 && c.http1_prebuilt_request_prefix_len == 0 &&
                       !c.http1_boundary_deferred && !c.http1_boundary_ready &&
                       c.http1_boundary_successor_episode == 0);
        // A coalesced request 1 keeps its pipelined successor in the stash; the
        // copied deadline proof re-proves that stash exactly as plaintext does.
        const bool stash_stable =
            c.pipeline_stash_len == 0 ||
            response_read_deadline_coalesced_get_phase1_prebuilt_stash_is_stable(
                c,
                c.http1_prebuilt_deadline_upload,
                c.http1_prebuilt_deadline_profile,
                bundle.response_buffering,
                c.http1_prebuilt_deadline_bundle_id,
                c.http1_prebuilt_deadline_method,
                c.http1_prebuilt_deadline_route_method);
        return phase_state && c.pipeline_depth == 0 && c.http1_pipeline_request_generation == 0 &&
               stash_stable &&
               forward_response_buffering_uses_content_length_machinery(
                   bundle.response_buffering) &&
               bodyless_get_complete_content_length_request_policy_is_admitted(
                   c.request_policy_id) &&
               c.http1_prebuilt_deadline_upload.request_policy_id == c.request_policy_id &&
               c.http1_prebuilt_deadline_upload.handler_generation == c.handler_gen &&
               response_read_deadline_tls_http11_engine_is_stable(c) &&
               response_read_deadline_tls_output_is_settled(c) && c.on_recv == &tls_recv<Self> &&
               c.http1_prebuilt_response_layout ==
                   Http1PrebuiltResponseLayout::FullContentLengthNonHead &&
               c.http1_prebuilt_response_purpose ==
                   Http1PrebuiltResponsePurpose::ResponseReadTimeout &&
               c.http1_prebuilt_deadline_profile ==
                   ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
               c.http1_prebuilt_deadline_method == static_cast<u8>(LogHttpMethod::Get) &&
               c.http1_prebuilt_deadline_route_method == kRouteMethodGet &&
               c.http1_prebuilt_deadline_generation == c.response_read_deadline_generation &&
               !c.http1_prebuilt_response_proof_is_neutral() &&
               prebuilt_http1_response_is_complete(c);
    }

    // Internal D2 seam. The complete header is already owned by
    // response_header_buf; this method proves transport and request-buffer
    // ownership before advancing the episode or submitting any downstream byte.
    // The staged deadline paths use this seam only after their immutable
    // response and ownership proofs have completed.
    [[nodiscard]] bool begin_prebuilt_http1_response(Connection& c,
                                                     u8 selected_targets,
                                                     Http1RequestBufferDisposition disposition,
                                                     u32 request_prefix_len,
                                                     const IoEvent* consumed_terminal = nullptr) {
        constexpr u8 kAllowed = kUpstreamOpConnect | kUpstreamOpSend | kUpstreamOpRecv;
        const bool fixed_upload =
            response_read_deadline_profile_is_fixed_upload(c.http1_prebuilt_deadline_profile);
        const bool strict_head =
            c.http1_prebuilt_response_purpose == Http1PrebuiltResponsePurpose::StrictHeadHeaderOnly;
        const bool strict_no_body_metadata =
            c.http1_prebuilt_response_layout ==
                Http1PrebuiltResponseLayout::HeaderOnlyNoBodyStatus &&
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::StrictNoBodyMetadataSuccess;
        const bool fixed_upload_head_timeout =
            c.http1_prebuilt_deadline_profile ==
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead &&
            c.http1_prebuilt_response_purpose == Http1PrebuiltResponsePurpose::ResponseReadTimeout;
        const bool configured_forward_failure =
            c.http1_prebuilt_deadline_profile ==
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead &&
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::ConfiguredForwardFailure;
        const bool exact_consumed_terminal =
            selected_targets == 0 && consumed_terminal != nullptr &&
            (strict_head || strict_no_body_metadata || configured_forward_failure) &&
            current_terminal_response_recv_is_exact(
                c,
                *consumed_terminal,
                c.http1_prebuilt_deadline_generation,
                c.http1_prebuilt_deadline_profile,
                c.http1_prebuilt_deadline_method,
                c.http1_prebuilt_deadline_upload.upload_episode);
        const bool header_only_head_timeout =
            c.http1_prebuilt_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
            c.http1_prebuilt_response_purpose ==
                Http1PrebuiltResponsePurpose::ResponseReadTimeout &&
            response_read_timeout_header_only_head_response_is_stable(
                c,
                c.http1_prebuilt_deadline_upload,
                c.http1_prebuilt_deadline_config,
                c.http1_prebuilt_deadline_bundle_id,
                c.http1_prebuilt_deadline_generation,
                ResponseReadTimeoutHeaderOnlyHeadPhase::PreBegin);
        const bool explicit_close =
            (header_only_head_timeout && c.http1_prebuilt_deadline_upload.downstream_close) ||
            (c.http1_prebuilt_deadline_config != nullptr &&
             c.http1_prebuilt_deadline_config->policy_bundle_id_is_valid(
                 c.http1_prebuilt_deadline_bundle_id) &&
             complete_content_length_explicit_close_request_is_stable(
                 c,
                 c.http1_prebuilt_deadline_upload,
                 c.http1_prebuilt_deadline_config
                     ->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1]
                     .response_buffering,
                 c.http1_prebuilt_deadline_profile));
        const bool tls_read_timeout = c.tls_active && prebuilt_http11_tls_read_timeout_is_stable(c);
        if (c.id >= connection_capacity || c.fd < 0 || c.upstream_fd < 0 ||
            c.protocol != ConnProtocol::Http11 || (c.tls_active && !tls_read_timeout) ||
            c.state != ConnState::Proxying ||
            ((!c.keep_alive || !c.req_client_keep_alive) && !explicit_close) ||
            c.req_start_us == 0 || c.epoch_held || c.resp_body_mode != BodyMode::None ||
            c.resp_body_remaining != 0 ||
            (fixed_upload ? c.req_body_mode != BodyMode::ContentLength ||
                                c.req_body_remaining != 0 || !c.request_body_fully_buffered
                          : c.req_body_mode != BodyMode::None || c.req_body_remaining != 0 ||
                                c.request_body_fully_buffered) ||
            c.req_body_streamed || c.send_armed || c.on_send != nullptr ||
            c.http1_boundary_deferred || c.http1_boundary_ready ||
            c.http1_boundary_successor_episode != 0 || c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_request_prefix_len != 0 ||
            (selected_targets & static_cast<u8>(~kAllowed)) != 0 ||
            ((selected_targets & kUpstreamOpConnect) != 0 &&
             (selected_targets & kUpstreamOpSend) != 0) ||
            ((strict_head || strict_no_body_metadata || fixed_upload_head_timeout ||
              configured_forward_failure || header_only_head_timeout) &&
             (((selected_targets != kUpstreamOpRecv || consumed_terminal != nullptr) &&
               !exact_consumed_terminal) ||
              disposition != Http1RequestBufferDisposition::ExistingPipeline ||
              request_prefix_len != 0)) ||
            !prebuilt_http1_response_is_complete(c, exact_consumed_terminal) ||
            !prebuilt_http1_layout_is_valid(c, selected_targets, disposition, request_prefix_len))
            return false;

        const bool advanced = selected_targets == 0
                                  ? advance_upstream_retirement_tombstone(c)
                                  : begin_upstream_retirement(c, selected_targets);
        if (!advanced) return false;
        if (c.upstream_episode_quarantined || !valid_upstream_episode(c.upstream_episode)) {
            close_conn(c);
            return false;
        }

        c.http1_prebuilt_wait = kHttp1WaitHeaderSend;
        if (c.upstream_retirement_active) c.http1_prebuilt_wait |= kHttp1WaitUpstreamRetirement;
        c.http1_prebuilt_disposition = disposition;
        c.http1_prebuilt_request_prefix_len = request_prefix_len;
        c.http1_boundary_successor_episode = c.upstream_episode;
        c.upstream_abandoned = true;
        c.upstream_keep_alive = false;
        c.upstream_start_us = 0;
        c.proxy_resp_started = true;
        c.on_upstream_recv = nullptr;
        c.on_upstream_send = nullptr;
        ::close(c.upstream_fd);
        c.upstream_fd = -1;
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        c.resp_body_sent = c.response_header_buf.len();
        c.transition_to_sending(&on_prebuilt_http1_header_sent<IoUringEventLoop>);
        if (!submit_send(c, c.response_header_buf.data(), c.response_header_buf.len())) {
            if (c.fd >= 0) close_conn(c);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool complete_prebuilt_http1_header_send(Connection& c) {
        const u8 expected_wait =
            kHttp1WaitHeaderSend |
            (c.upstream_retirement_active ? kHttp1WaitUpstreamRetirement : static_cast<u8>(0));
        if (c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_wait != expected_wait || c.http1_boundary_deferred ||
            c.http1_boundary_ready || c.http1_boundary_successor_episode != c.upstream_episode)
            return false;
        c.http1_prebuilt_wait &= static_cast<u8>(~kHttp1WaitHeaderSend);
        c.http1_boundary_deferred = true;
        publish_prebuilt_http1_ready(c);
        return true;
    }

    bool prebuilt_http1_header_send_completion_is_valid(const Connection& c,
                                                        const IoEvent& ev) const {
        const u8 expected_wait =
            kHttp1WaitHeaderSend |
            (c.upstream_retirement_active ? kHttp1WaitUpstreamRetirement : static_cast<u8>(0));
        if (c.id >= connection_capacity || ev.conn_id != c.id || ev.type != IoEventType::Send ||
            ev.more || ev.aux != 0 || ev.result <= 0 ||
            static_cast<u32>(ev.result) != c.response_header_buf.len() ||
            !prebuilt_http1_response_is_complete(c) ||
            c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_wait != expected_wait || c.state != ConnState::Sending ||
            c.send_armed || c.req_start_us == 0 || c.epoch_held ||
            c.on_send != &on_prebuilt_http1_header_sent<IoUringEventLoop>)
            return false;
        if (c.tls_active) {
            return prebuilt_http11_tls_read_timeout_is_stable(c, /*sending=*/true) &&
                   c.response_read_deadline_send_tombstone_generation != 0 &&
                   ev.non_upstream_generation ==
                       c.response_read_deadline_send_tombstone_generation &&
                   !c.response_read_deadline_send_owner_active &&
                   response_read_deadline_send_fields_are_neutral(c) &&
                   c.tls_raw_send_owner_is_neutral() && c.tls_single_shot_send_owner_is_neutral() &&
                   !c.tls_out_inflight && c.tls_out_buf.len() == 0;
        }
        const auto& send = backend.send_state[c.id];
        return send.src == c.response_header_buf.data() && send.fd == c.fd &&
               send.offset == c.response_header_buf.len() && send.remaining == 0 &&
               send.type == IoEventType::Send;
    }

    // Fence D2's one downstream HeaderSend target before generic Send
    // accounting. The first exact full completion continues through the normal
    // proactor accounting and dedicated callback. Once that owner is cleared,
    // every duplicate/late Send is swallowed while the two-party rendezvous is
    // still active and cannot steal the long-lived downstream recv count.
    bool consume_prebuilt_http1_header_send_event(Connection& c, const IoEvent& ev) {
        if (ev.type != IoEventType::Send ||
            c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None)
            return false;
        if ((c.http1_prebuilt_wait & kHttp1WaitHeaderSend) == 0) return true;

        const auto& send = backend.send_state[c.id];
        const bool exact_owner = c.id < connection_capacity && c.state == ConnState::Sending &&
                                 c.send_armed && c.req_start_us != 0 && !c.epoch_held &&
                                 c.on_send == &on_prebuilt_http1_header_sent<IoUringEventLoop> &&
                                 send.src == c.response_header_buf.data() && send.fd == c.fd &&
                                 send.type == IoEventType::Send;
        if (!exact_owner || ev.conn_id != c.id || ev.aux != 0 || ev.more) {
            close_conn(c);
            return true;
        }

        const bool full = ev.result > 0 &&
                          static_cast<u32>(ev.result) == c.response_header_buf.len() &&
                          send.offset == c.response_header_buf.len() && send.remaining == 0;
        if (full) return false;

        // A terminal error/invalid short record terminates exactly the owned
        // HeaderSend target. Retire that one count before close; never let the
        // generic branch consume a recv or retirement owner. F_MORE above is
        // non-terminal and remains armed for close-ledger cancellation.
        if (c.pending_ops == 0) {
            c.upstream_episode = kInvalidUpstreamEventEpisode;
            c.upstream_episode_quarantined = true;
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            running_.store(false, std::memory_order_release);
        } else {
            c.pending_ops--;
            c.send_armed = false;
            backend.send_state[c.id] = {};
        }
        close_conn(c);
        return true;
    }

    bool consume_tagged_send_close_event(Connection& c, const IoEvent& ev) {
        if (ev.type != IoEventType::Send) return false;
        const bool close_cancel = (ev.non_upstream_generation & kNonUpstreamSendCancelBit) != 0;
        const u32 event_generation = ev.non_upstream_generation & kNonUpstreamSendGenerationMask;
        if (event_generation != 0 &&
            event_generation == c.response_read_deadline_send_close_generation) {
            bool* owned = close_cancel ? &c.response_read_deadline_send_close_cancel_owned
                                       : &c.response_read_deadline_send_close_target_owned;
            if (*owned && !ev.more) {
                *owned = false;
                if (c.pending_ops == 0) {
                    backend.fatal_error.store(EPROTO, std::memory_order_release);
                    running_.store(false, std::memory_order_release);
                } else {
                    c.pending_ops--;
                }
            }
            if (!c.response_read_deadline_send_close_target_owned &&
                !c.response_read_deadline_send_close_cancel_owned)
                c.response_read_deadline_send_close_generation = 0;
            if (c.fd < 0 && c.pending_ops == 0) reclaim_slot(c.id);
            return true;
        }
        return false;
    }

    bool consume_tls_ciphertext_send_event(Connection& c, const IoEvent& ev) {
        if (ev.type != IoEventType::Send || !c.tls_active) return false;
        // Every io_uring TLS Send is a tagged ciphertext target. With no raw
        // target there is no valid application-level CQE to account; while a
        // target is live, any other token (including legacy zero) is stale.
        if (!c.tls_out_inflight) return true;
        if (c.tls_out_inflight_generation == 0) {
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            running_.store(false, std::memory_order_release);
            close_conn(c);
            return true;
        }
        if (ev.non_upstream_generation != c.tls_out_inflight_generation) return true;

        // F_MORE is not a terminal send completion. Close transfers the raw
        // token and its still-live target to the common close/cancel ledger.
        if (ev.more) {
            close_conn(c);
            return true;
        }

        if (c.id >= connection_capacity) {
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            running_.store(false, std::memory_order_release);
            close_conn(c);
            return true;
        }
        const bool has_target = c.send_armed && c.pending_ops > 0;
        const auto& send = backend.send_state[c.id];
        const bool raw_identity = tls_ciphertext_send_raw_state_matches(c) &&
                                  c.on_send == &tls_on_out_drain<Self> && ev.aux == 0;
        const bool successful = raw_identity && ev.result > 0 &&
                                static_cast<u32>(ev.result) == c.tls_out_inflight_len &&
                                send.offset == c.tls_out_inflight_len && send.remaining == 0;
        if (!has_target) {
            backend.fatal_error.store(EPROTO, std::memory_order_release);
            running_.store(false, std::memory_order_release);
            close_conn(c);
            return true;
        }

        // This authenticated, terminal raw CQE owns exactly one real kernel
        // target whether it succeeded or failed. The TLS drain must never let
        // generic dispatch decrement it a second time.
        c.pending_ops--;
        c.send_armed = false;
        // These are generic terminal Send-dispatch side effects. Apply them
        // before either the TLS continuation or fail-closed error handling.
        if (!c.throttle_paused &&
            c.response_read_deadline_state != ResponseReadDeadlineState::Armed &&
            c.response_read_deadline_state != ResponseReadDeadlineState::ExpiryPending &&
            c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending &&
            c.response_read_deadline_state != ResponseReadDeadlineState::RefreshPending)
            timer.refresh(&c,
                          c.state == ConnState::Proxying ? upstream_timeout : keepalive_timeout);
        c.clear_recv_pause_for_send();
        if (!successful) {
            backend.send_state[c.id] = {};
            Connection::visit_tls_raw_send_owner_fields(
                c, [](auto& value, const auto& reset_value) { value = reset_value; });
            close_conn(c);
            return true;
        }

        tls_on_out_drain<Self>(this, c, ev);
        return true;
    }

    [[nodiscard]] static ResponseReadDeadlineSendKind response_read_deadline_tls_send_kind(
        const Connection& c) {
        switch (c.response_read_deadline_post_commit_phase) {
            case ResponseReadDeadlinePostCommitPhase::HeaderSend:
                return ResponseReadDeadlineSendKind::Header;
            case ResponseReadDeadlinePostCommitPhase::BodySend:
                return ResponseReadDeadlineSendKind::Body;
            case ResponseReadDeadlinePostCommitPhase::CombinedSend:
                return ResponseReadDeadlineSendKind::Combined;
            case ResponseReadDeadlinePostCommitPhase::None:
            case ResponseReadDeadlinePostCommitPhase::Buffering:
            case ResponseReadDeadlinePostCommitPhase::WaitingBody:
            case ResponseReadDeadlinePostCommitPhase::OriginComplete:
                return ResponseReadDeadlineSendKind::None;
        }
        return ResponseReadDeadlineSendKind::None;
    }

    [[nodiscard]] static Connection::Callback response_read_deadline_tls_send_callback(
        ResponseReadDeadlineSendKind kind) {
        switch (kind) {
            case ResponseReadDeadlineSendKind::Header:
                return &on_response_header_sent<Self>;
            case ResponseReadDeadlineSendKind::Body:
                return &on_response_body_sent<Self>;
            case ResponseReadDeadlineSendKind::Combined:
                return &on_complete_response_sent<Self>;
            case ResponseReadDeadlineSendKind::None:
                return nullptr;
        }
        return nullptr;
    }

    [[nodiscard]] bool response_read_deadline_tls_send_frame_is_valid(
        const Connection& c,
        ResponseReadDeadlineSendKind kind,
        Connection::Callback callback,
        const u8* src,
        u32 len) const {
        if (c.id >= connection_capacity || c.fd < 0 || !c.tls_active || !c.tls_handshake_complete ||
            !c.uses_iouring_tls() || c.protocol != ConnProtocol::Http11 || c.h2 != nullptr ||
            c.state != ConnState::Sending || c.req_start_us == 0 || c.epoch_held ||
            callback == nullptr || c.on_send != callback || src == nullptr || len == 0 ||
            c.response_read_deadline_post_commit_generation == 0 ||
            c.response_read_deadline_post_commit_generation !=
                c.response_read_deadline_generation ||
            !forward_response_buffering_uses_content_length_machinery(
                c.response_read_deadline_buffering) ||
            c.response_read_deadline_send_owner_generation == 0 ||
            c.response_read_deadline_send_deadline_generation !=
                c.response_read_deadline_post_commit_generation ||
            c.response_read_deadline_send_upstream_episode !=
                c.response_read_deadline_post_commit_episode ||
            c.response_read_deadline_send_fd != c.fd || c.response_read_deadline_send_src != src ||
            c.response_read_deadline_send_len != len || c.response_read_deadline_send_kind != kind)
            return false;

        switch (kind) {
            case ResponseReadDeadlineSendKind::Header:
                return c.response_read_deadline_post_commit_phase ==
                           ResponseReadDeadlinePostCommitPhase::HeaderSend &&
                       callback == &on_response_header_sent<Self> &&
                       src == c.response_header_buf.data() && len == c.response_header_buf.len() &&
                       c.response_read_deadline_post_commit_inflight_body == 0 &&
                       c.upstream_send_len == c.response_read_deadline_post_commit_raw_header_end &&
                       c.buffered_response_len() >= c.upstream_send_len;
            case ResponseReadDeadlineSendKind::Body:
                return c.response_read_deadline_post_commit_phase ==
                           ResponseReadDeadlinePostCommitPhase::BodySend &&
                       callback == &on_response_body_sent<Self> &&
                       src == c.buffered_response_data() &&
                       len == c.response_read_deadline_post_commit_inflight_body && len != 0 &&
                       c.upstream_send_len == len && c.buffered_response_len() >= len;
            case ResponseReadDeadlineSendKind::Combined:
                return c.response_read_deadline_post_commit_phase ==
                           ResponseReadDeadlinePostCommitPhase::CombinedSend &&
                       callback == &on_complete_response_sent<Self> &&
                       src == c.response_header_buf.data() &&
                       response_read_deadline_combined_send_frame_is_stable(c) &&
                       len == c.response_read_deadline_send_len;
            case ResponseReadDeadlineSendKind::None:
                return false;
        }
        return false;
    }

    [[nodiscard]] static bool response_read_deadline_send_fields_are_neutral(const Connection& c) {
        bool neutral = true;
        const auto check = [&](const auto& value, const auto& reset_value) {
            neutral = neutral && value == reset_value;
        };
        Connection::visit_response_read_deadline_send_owner_fields(c, check);
        return neutral;
    }

    bool consume_response_read_deadline_send_event(Connection& c, const IoEvent& ev) {
        if (ev.type != IoEventType::Send) return false;
        if (!c.response_read_deadline_send_owner_active) {
            // A nonzero token is owned by this dedicated Send namespace.  Once
            // tombstoned it remains consumable across retirement/request-2;
            // generic generation-zero sends are unaffected.
            return ev.non_upstream_generation != 0;
        }
        const u32 owner = c.response_read_deadline_send_owner_generation;
        if (owner == 0 || ev.non_upstream_generation != owner) return true;

        const bool header =
            c.response_read_deadline_send_kind == ResponseReadDeadlineSendKind::Header;
        const bool body = c.response_read_deadline_send_kind == ResponseReadDeadlineSendKind::Body;
        const bool combined =
            c.response_read_deadline_send_kind == ResponseReadDeadlineSendKind::Combined;
        const auto& send = backend.send_state[c.id];
        const bool exact_shape =
            c.id < connection_capacity && c.fd >= 0 && c.send_armed && c.pending_ops > 0 &&
            !ev.more && ev.aux == 0 && ev.result > 0 &&
            static_cast<u32>(ev.result) == c.response_read_deadline_send_len &&
            c.response_read_deadline_send_deadline_generation ==
                c.response_read_deadline_post_commit_generation &&
            c.response_read_deadline_send_upstream_episode ==
                c.response_read_deadline_post_commit_episode &&
            c.response_read_deadline_send_fd == c.fd &&
            c.response_read_deadline_send_src != nullptr &&
            ((header &&
              c.response_read_deadline_post_commit_phase ==
                  ResponseReadDeadlinePostCommitPhase::HeaderSend &&
              c.on_send == &on_response_header_sent<Self> &&
              c.response_read_deadline_send_src == c.response_header_buf.data() &&
              c.response_read_deadline_send_len == c.response_header_buf.len()) ||
             (body &&
              c.response_read_deadline_post_commit_phase ==
                  ResponseReadDeadlinePostCommitPhase::BodySend &&
              c.on_send == &on_response_body_sent<Self> &&
              c.response_read_deadline_send_src == c.buffered_response_data() &&
              c.response_read_deadline_send_len ==
                  c.response_read_deadline_post_commit_inflight_body) ||
             (combined &&
              c.response_read_deadline_post_commit_phase ==
                  ResponseReadDeadlinePostCommitPhase::CombinedSend &&
              c.on_send == &on_complete_response_sent<Self> &&
              response_read_deadline_combined_send_frame_is_stable(c))) &&
            send.src == c.response_read_deadline_send_src && send.fd == c.fd &&
            send.type == IoEventType::Send && send.generation == owner &&
            send.offset == c.response_read_deadline_send_len && send.remaining == 0;
        if (exact_shape) {
            c.response_read_deadline_send_owner_active = false;
            c.response_read_deadline_send_tombstone_generation = owner;
            return false;
        }

        // F_MORE is invalid for the single-shot downstream Send, but it is not
        // terminal and therefore owns no completion count yet.  Keep the exact
        // owner live until close_conn() transfers its generation and target to
        // the close ledger; clearing it here would make the later target/cancel
        // CQEs look like unowned duplicates and leak the deferred slot.
        if (ev.more) {
            close_conn(c);
            return true;
        }

        // Only a matching terminal record may retire this Send target's one
        // pending count.  Forged generations and duplicates above consume no
        // accounting; F_MORE leaves the live target for close cancellation.
        if (c.send_armed && c.pending_ops > 0) {
            c.pending_ops--;
            c.send_armed = false;
            backend.send_state[c.id] = {};
        }
        c.response_read_deadline_send_owner_active = false;
        c.response_read_deadline_send_tombstone_generation = owner;
        c.clear_response_read_deadline_send_owner();
        close_conn(c);
        return true;
    }

    bool response_read_deadline_send_completion_is_valid(const Connection& c,
                                                         const IoEvent& ev,
                                                         ResponseReadDeadlineSendKind kind) const {
        if (c.id >= connection_capacity) return false;
        Connection::Callback expected_callback = nullptr;
        switch (kind) {
            case ResponseReadDeadlineSendKind::None:
                return false;
            case ResponseReadDeadlineSendKind::Header:
                expected_callback = &on_response_header_sent<Self>;
                break;
            case ResponseReadDeadlineSendKind::Body:
                expected_callback = &on_response_body_sent<Self>;
                break;
            case ResponseReadDeadlineSendKind::Combined:
                expected_callback = &on_complete_response_sent<Self>;
                break;
            default:
                return false;
        }
        if (c.tls_active) {
            const bool exact_tuple =
                !c.response_read_deadline_send_owner_active &&
                c.response_read_deadline_send_owner_generation != 0 &&
                c.response_read_deadline_send_tombstone_generation ==
                    c.response_read_deadline_send_owner_generation &&
                c.response_read_deadline_send_deadline_generation ==
                    c.response_read_deadline_generation &&
                c.response_read_deadline_send_deadline_generation ==
                    c.response_read_deadline_post_commit_generation &&
                c.response_read_deadline_send_upstream_episode ==
                    c.response_read_deadline_post_commit_episode &&
                c.response_read_deadline_send_fd == c.fd &&
                c.response_read_deadline_send_src != nullptr &&
                response_read_deadline_tls_send_frame_is_valid(c,
                                                               kind,
                                                               expected_callback,
                                                               c.response_read_deadline_send_src,
                                                               c.response_read_deadline_send_len);
            return exact_tuple && ev.type == IoEventType::Send && !ev.more && ev.aux == 0 &&
                   ev.conn_id == c.id &&
                   ev.non_upstream_generation == c.response_read_deadline_send_owner_generation &&
                   ev.result > 0 &&
                   static_cast<u32>(ev.result) == c.response_read_deadline_send_len &&
                   !c.send_armed && c.on_send == expected_callback &&
                   c.tls_raw_send_owner_is_neutral() && c.tls_single_shot_send_owner_is_neutral() &&
                   c.tls_out_buf.len() == 0;
        }
        const auto& send = backend.send_state[c.id];
        return !c.response_read_deadline_send_owner_active &&
               c.response_read_deadline_send_owner_generation != 0 &&
               c.response_read_deadline_send_tombstone_generation ==
                   c.response_read_deadline_send_owner_generation &&
               c.response_read_deadline_send_kind == kind && ev.type == IoEventType::Send &&
               !ev.more && ev.aux == 0 &&
               ev.non_upstream_generation == c.response_read_deadline_send_owner_generation &&
               ev.result > 0 && static_cast<u32>(ev.result) == c.response_read_deadline_send_len &&
               !c.send_armed && c.on_send == expected_callback &&
               send.src == c.response_read_deadline_send_src && send.fd == c.fd &&
               send.type == IoEventType::Send &&
               send.generation == c.response_read_deadline_send_owner_generation &&
               send.offset == c.response_read_deadline_send_len && send.remaining == 0;
    }

    // Existing production C1 caller: its callback has already been detached,
    // and the proven strict point owns at most one upstream recv target.
    [[nodiscard]] bool begin_strict_upstream_retirement(Connection& c) {
        const u8 selected = c.upstream_recv_armed ? kUpstreamOpRecv : 0;
        return begin_upstream_retirement_impl(c, selected, true, false);
    }

    // Strict clean success uses the same exact-episode recv retirement as a
    // strict rejection.  Most callers arrive with a live fd and establish the
    // retirement here.  Response-deadline and strict HEAD paths can arrive
    // after an earlier owner already closed the fd; accept only their complete,
    // internally consistent recv-only retirement (active or drained
    // tombstone), never an arbitrary closed upstream.
    [[nodiscard]] bool prepare_clean_strict_upstream_retirement(Connection& c) {
        if (c.upstream_fd >= 0) {
            if (!begin_strict_upstream_retirement(c)) return false;
            c.upstream_abandoned = true;
            return true;
        }

        const u8 recv_only = kUpstreamOpRecv;
        const u8 target = c.upstream_retirement_target_owned;
        const u8 cancel = c.upstream_retirement_cancel_owned;
        const u8 retry = c.upstream_retirement_cancel_retry;
        const bool has_owner = target != 0 || cancel != 0 || retry != 0;
        const u32 counted_owners = static_cast<u32>(target != 0) + static_cast<u32>(cancel != 0);
        const bool exact_normal_successor =
            !c.upstream_episode_quarantined &&
            c.upstream_retiring_episode < kIoUserDataMaxUpstreamEpisode &&
            c.upstream_episode == c.upstream_retiring_episode + 1u;
        const bool exact_quarantined_successor =
            c.upstream_episode_quarantined &&
            c.upstream_retiring_episode == kIoUserDataMaxUpstreamEpisode &&
            c.upstream_episode == kInvalidUpstreamEventEpisode;
        return c.upstream_abandoned && valid_upstream_episode(c.upstream_retiring_episode) &&
               (exact_normal_successor || exact_quarantined_successor) &&
               c.upstream_retirement_active == has_owner &&
               (target & static_cast<u8>(~recv_only)) == 0 &&
               (cancel & static_cast<u8>(~recv_only)) == 0 &&
               (retry & static_cast<u8>(~recv_only)) == 0 &&
               (retry & static_cast<u8>(~target)) == 0 && (cancel & retry) == 0 &&
               c.pending_ops >= counted_owners && !c.upstream_connect_armed &&
               (!c.upstream_recv_armed || (target & recv_only) != 0) && !c.upstream_send_armed &&
               c.on_upstream_recv == nullptr && c.on_upstream_send == nullptr &&
               !c.upstream_recv_paused_for_send && !c.upstream_recv_pause_cancel_pending &&
               !c.upstream_recv_pause_rearm_pending && !c.upstream_recv_cancel_inflight &&
               c.upstream_close_episode == 0 && c.upstream_close_target_owned == 0 &&
               c.upstream_close_cancel_owned == 0 && !c.upstream_close_pause_cancel_owned;
    }

    // Safe retry point: called before backend.wait submits/blocks. A full SQ
    // necessarily has work for wait() to advance; a sticky enter failure stops
    // the shard through the existing explicit fatal path.
    void retry_strict_upstream_retirement_cancels() {
        if (upstream_retirement_retry_count == 0) return;
        for (u32 id = 0; id < slots_initialized && upstream_retirement_retry_count != 0; id++) {
            Connection& c = conns[id];
            if (!c.upstream_retirement_cancel_retry) continue;
            if (!c.upstream_retirement_active ||
                (c.upstream_retirement_cancel_owned & c.upstream_retirement_cancel_retry) != 0 ||
                (c.upstream_retirement_cancel_retry &
                 static_cast<u8>(~c.upstream_retirement_target_owned)) != 0 ||
                !valid_upstream_episode(c.upstream_retiring_episode)) {
                // Corrupt retirement ownership cannot be repaired safely.
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return;
            }
            for (u8 op : {kUpstreamOpConnect, kUpstreamOpSend, kUpstreamOpRecv}) {
                if ((c.upstream_retirement_cancel_retry & op) == 0) continue;
                if (!backend.cancel_retiring_upstream(
                        c.id, upstream_event_for_op(op), c.upstream_retiring_episode))
                    continue;
                c.upstream_retirement_cancel_retry &= static_cast<u8>(~op);
                c.upstream_retirement_cancel_owned |= op;
                c.pending_ops++;
                upstream_retirement_retry_count--;
            }
        }
    }

    // Route strict-retirement CQEs before generic stale accounting. Returning
    // true means the event was consumed without entering callbacks, timer
    // refresh, armed-flag changes, send state, or current request buffers.
    bool consume_strict_upstream_retirement_event(Connection& c, const IoEvent& ev) {
        if (!io_event_is_upstream(ev.type)) return false;

        const u8 retirement_op = upstream_op_for_event(ev.type);
        const bool matching_retirement = retirement_op != 0 && c.upstream_retiring_episode != 0 &&
                                         ev.upstream_episode == c.upstream_retiring_episode;
        if (matching_retirement) {
            // Keep the token as a tombstone after completion: matching
            // duplicates remain consumed and cannot steal generic accounting.
            if (!c.upstream_retirement_active) return true;

            u8* owned = nullptr;
            if (ev.aux == 0)
                owned = &c.upstream_retirement_target_owned;
            else if (ev.aux == kUpstreamRetirementCancelAux)
                owned = &c.upstream_retirement_cancel_owned;
            if (owned == nullptr || (*owned & retirement_op) == 0 || ev.more) return true;

            // Ownership is counted when the target was armed or after the
            // cancel SQE was queued. A zero aggregate here is corrupt state;
            // fail the shard explicitly without inventing a decrement.
            if (c.pending_ops == 0) {
                c.upstream_episode = kInvalidUpstreamEventEpisode;
                c.upstream_episode_quarantined = true;
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return true;
            }
            *owned &= static_cast<u8>(~retirement_op);
            if (ev.aux == 0 && retirement_op == kUpstreamOpSend)
                backend.upstream_send_state[c.id] = {};
            c.pending_ops--;
            if (ev.aux == 0 && (c.upstream_retirement_cancel_retry & retirement_op) != 0) {
                // The target reached its terminal CQE before an initially-full
                // SQ could accept the cancel. No kernel recv remains to cancel,
                // so retire the retry obligation synchronously and keep the
                // loop-level scan count exact.
                if (upstream_retirement_retry_count == 0) {
                    c.upstream_episode = kInvalidUpstreamEventEpisode;
                    c.upstream_episode_quarantined = true;
                    backend.fatal_error.store(EPROTO, std::memory_order_release);
                    running_.store(false, std::memory_order_release);
                    return true;
                }
                c.upstream_retirement_cancel_retry &= static_cast<u8>(~retirement_op);
                upstream_retirement_retry_count--;
            }
            if (c.upstream_retirement_target_owned == 0 &&
                c.upstream_retirement_cancel_owned == 0 &&
                c.upstream_retirement_cancel_retry == 0) {
                c.upstream_retirement_active = false;
                if (c.fd < 0) {
                    // A closed slot has no successor rendezvous to publish.
                    // Clear the boundary owner at the exact final retirement
                    // transition, before any reclamation decision.
                    c.http1_boundary_deferred = false;
                    c.http1_boundary_ready = false;
                    c.http1_boundary_successor_episode = 0;
                } else if (c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None) {
                    if (!prebuilt_http1_response_is_complete(c)) {
                        close_conn(c);
                        return true;
                    }
                    if ((c.http1_prebuilt_wait & kHttp1WaitUpstreamRetirement) == 0) {
                        c.upstream_episode = kInvalidUpstreamEventEpisode;
                        c.upstream_episode_quarantined = true;
                        backend.fatal_error.store(EPROTO, std::memory_order_release);
                        running_.store(false, std::memory_order_release);
                        return true;
                    }
                    c.http1_prebuilt_wait &= static_cast<u8>(~kHttp1WaitUpstreamRetirement);
                    publish_prebuilt_http1_ready(c);
                } else if (c.http1_boundary_deferred && !c.http1_boundary_ready) {
                    maybe_publish_http1_boundary_ready(c);
                }
                if (c.fd < 0 && c.pending_ops == 0) reclaim_slot(c.id);
            }
            return true;
        }

        // A live successor can have an operation and its close-path cancel in
        // flight concurrently. Both were counted independently, so route only
        // the exact episode/type/aux owner and leave duplicates or forged
        // records unable to decrement aggregate pending_ops.
        if (c.upstream_close_episode != 0 && ev.upstream_episode == c.upstream_close_episode) {
            const u8 op = upstream_op_for_event(ev.type);

            bool owned = false;
            if (ev.aux == 0) {
                owned = (c.upstream_close_target_owned & op) != 0;
                if (owned && !ev.more) c.upstream_close_target_owned &= static_cast<u8>(~op);
            } else if (ev.aux == kUpstreamCloseCancelAux) {
                owned = (c.upstream_close_cancel_owned & op) != 0;
                if (owned && !ev.more) c.upstream_close_cancel_owned &= static_cast<u8>(~op);
            } else if (ev.aux == kPauseCancelAux && op == kUpstreamOpRecv) {
                owned = c.upstream_close_pause_cancel_owned;
                if (owned && !ev.more) c.upstream_close_pause_cancel_owned = false;
            }
            if (!owned || ev.more) return true;
            if (c.pending_ops == 0) {
                c.upstream_episode = kInvalidUpstreamEventEpisode;
                c.upstream_episode_quarantined = true;
                backend.fatal_error.store(EPROTO, std::memory_order_release);
                running_.store(false, std::memory_order_release);
                return true;
            }
            c.pending_ops--;
            if (c.fd < 0 && c.pending_ops == 0 && !strict_upstream_retirement_blocks_reclaim(c))
                reclaim_slot(c.id);
            return true;
        }

        // The strict begin precondition proves there is no other upstream
        // operation while retirement is active. Once inactive, retain the
        // latest token as a tombstone but admit documented production
        // completions carrying the exact current successor token. Retirement-
        // only, unknown, malformed, and older records own no aggregate
        // accounting and remain swallowed.
        if (c.upstream_retiring_episode == 0) return false;
        if (c.upstream_retirement_active) return true;
        return !current_successor_event_is_valid(c, ev);
    }

    // Consume every ready marker before invoking the factored continuation.
    // Called only after all CQEs returned by the current backend.wait batch.
    // Public for focused production-dispatch tests; run() is the only runtime
    // scheduler.
    // A deferred boundary resumes outside tls_process, so ciphertext the client
    // sent while the previous request owned the connection is still encrypted
    // in tls_in_buf. When the dispatched successor stopped at an incomplete
    // header, decrypt that input now: no later Recv completion will carry it.
    void resume_buffered_tls_request_input(Connection& c) {
        if (c.fd < 0 || c.state != ConnState::ReadingHeader ||
            c.tls_pending_on_recv != &on_header_received<Self>)
            return;
        (void)process_buffered_tls_input(c);
    }

    void resume_deferred_http1_boundaries() {
        if (!http1_boundary_ready_pending) return;
        http1_boundary_ready_pending = false;
        for (u32 id = 0; id < slots_initialized; id++) {
            Connection& c = conns[id];
            if (!c.http1_boundary_ready) continue;

            c.http1_boundary_ready = false;
            if (!c.http1_boundary_deferred) continue;
            if (strict_upstream_retirement_blocks_reclaim(c) ||
                idle_return_drain_blocks_boundary(c) || !c.response_read_timer_owner_is_neutral())
                continue;
            const u32 expected_episode = c.http1_boundary_successor_episode;

            if (c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None) {
                const bool has_request_callback =
                    c.on_send || c.on_upstream_recv || c.on_upstream_send ||
                    (c.uses_iouring_tls() ? c.tls_pending_on_recv != nullptr
                                          : c.on_recv != nullptr);
                const bool valid =
                    c.id == id && c.fd >= 0 && !is_draining() && !c.upstream_episode_quarantined &&
                    c.http1_prebuilt_wait == 0 && !strict_upstream_retirement_blocks_reclaim(c) &&
                    c.upstream_close_episode == 0 && c.upstream_close_target_owned == 0 &&
                    c.upstream_close_cancel_owned == 0 && !c.upstream_close_pause_cancel_owned &&
                    valid_upstream_episode(expected_episode) &&
                    c.upstream_episode == expected_episode && c.upstream_fd < 0 &&
                    !c.upstream_slot_held && c.state == ConnState::Sending && !c.send_armed &&
                    c.req_start_us == 0 && c.epoch_held && prebuilt_http1_response_is_complete(c) &&
                    !c.upstream_connect_armed && !c.upstream_send_armed && !c.upstream_recv_armed &&
                    !has_request_callback;
                const bool explicit_close =
                    (c.http1_prebuilt_deadline_profile ==
                         ResponseReadDeadlineProfile::HeaderOnlyHead &&
                     c.http1_prebuilt_response_purpose ==
                         Http1PrebuiltResponsePurpose::ResponseReadTimeout &&
                     c.http1_prebuilt_deadline_upload.downstream_close &&
                     response_read_timeout_header_only_head_response_is_stable(
                         c,
                         c.http1_prebuilt_deadline_upload,
                         c.http1_prebuilt_deadline_config,
                         c.http1_prebuilt_deadline_bundle_id,
                         c.http1_prebuilt_deadline_generation,
                         ResponseReadTimeoutHeaderOnlyHeadPhase::SendingRetired)) ||
                    (c.http1_prebuilt_deadline_config != nullptr &&
                     c.http1_prebuilt_deadline_config->policy_bundle_id_is_valid(
                         c.http1_prebuilt_deadline_bundle_id) &&
                     complete_content_length_explicit_close_request_is_stable(
                         c,
                         c.http1_prebuilt_deadline_upload,
                         c.http1_prebuilt_deadline_config
                             ->policy_bundles[c.http1_prebuilt_deadline_bundle_id - 1]
                             .response_buffering,
                         c.http1_prebuilt_deadline_profile));
                if (!valid || (!explicit_close && !normalize_prebuilt_http1_request_buffer(c))) {
                    if (c.fd >= 0) close_conn(c);
                    continue;
                }

                if (explicit_close) {
                    c.http1_boundary_deferred = false;
                    c.http1_boundary_successor_episode = 0;
                    c.http1_prebuilt_wait = 0;
                    end_stream_before_close(c);  // completed response
                    close_conn(c);
                    continue;
                }

                c.http1_boundary_deferred = false;
                c.http1_boundary_successor_episode = 0;
                c.http1_prebuilt_wait = 0;
                c.http1_prebuilt_disposition = Http1RequestBufferDisposition::None;
                c.http1_prebuilt_request_prefix_len = 0;
                c.clear_http1_prebuilt_response_proof();
                epoch_leave();
                c.epoch_held = false;
                continue_http1_request_boundary<IoUringEventLoop>(this, c);
                resume_buffered_tls_request_input(c);
                continue;
            }

            c.http1_boundary_deferred = false;
            c.http1_boundary_successor_episode = 0;

            const bool has_request_callback =
                c.on_send || c.on_upstream_recv || c.on_upstream_send ||
                (c.uses_iouring_tls() ? c.tls_pending_on_recv != nullptr : c.on_recv != nullptr);
            const bool valid =
                c.id == id && c.fd >= 0 && !is_draining() && !c.upstream_episode_quarantined &&
                !strict_upstream_retirement_blocks_reclaim(c) &&
                valid_upstream_episode(expected_episode) &&
                c.upstream_episode == expected_episode && c.state == ConnState::Sending &&
                !c.send_armed && c.req_start_us == 0 && !has_request_callback;
            if (!valid) {
                if (c.fd >= 0) close_conn(c);
                continue;
            }
            const bool explicit_close =
                c.http1_prebuilt_deadline_upload.downstream_close &&
                complete_content_length_explicit_close_request_is_stable(
                    c,
                    c.http1_prebuilt_deadline_upload,
                    ForwardResponseBufferingMode::CompleteContentLength,
                    ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero);
            // Both branches close after a completed response.
            if (c.http1_prebuilt_deadline_upload.downstream_close || explicit_close) {
                end_stream_before_close(c);
                close_conn(c);
                continue;
            }
            continue_http1_request_boundary<IoUringEventLoop>(this, c);
            resume_buffered_tls_request_input(c);
        }
    }

    // --- HTTP/1 idle upstream connection reuse (per-shard pool) ---

    // Borrow a live idle socket to (upstream_id, backend_idx) from the pool,
    // skipping the TCP connect. io_uring routes upstream completions by conn_id
    // user_data (no fd map), so installing the fd is all that's needed; the next
    // submit_send_upstream arms a send SQE tagged with this conn. Returns false
    // (no live idle socket) → caller connects fresh.
    bool reuse_idle_upstream(Connection& c, u16 upstream_id, u8 backend_idx) {
        if (!upstream) return false;
        const i32 fd = upstream->take_idle(upstream_id, backend_idx);
        if (fd < 0) return false;
        c.upstream_fd = fd;
        return true;
    }

    // Close a non-reusable upstream at proxy completion (the non-pooling half of
    // release_upstream_conn). ::close() alone does not stop an armed multishot recv:
    // io_uring holds its own file reference, so the recv stays live on the old
    // socket and completes when the origin's FIN arrives, carrying the same
    // (conn_id, UpstreamRecv, upstream_episode) user_data as the next request's
    // fresh recv on this slot. Dispatched as current, that late EOF would clear
    // upstream_recv_armed for the new recv, after which backend wait() treats the
    // new response's body CQEs as stale and drops their bytes.
    //
    // A live recv with no cancel yet is retired through the exact-episode ledger
    // (as strict clean success does): the episode advances, so wait() never copies
    // the old recv's bytes and its CQEs are consumed by the retirement consumer; the
    // cancel keeps retry ownership under SQ pressure; defer_http1_request_boundary
    // parks request 2 until the retirement drains. A recv already under a pause
    // cancel keeps that owner: its terminal is quarantined as stale (only while it
    // is still outstanding) and the drain resets the buffer before any successor
    // recv is armed. If neither ownership can be proven the downstream is closed
    // after this complete response (keep_alive = false) and close_conn's own
    // upstream teardown owns the recv; request 2 is never admitted over it.
    void close_released_upstream(Connection& c) {
        // A retirement ledger that already owns the recv has advanced the episode,
        // so that recv's CQEs are tagged stale and its cancel is owned there.
        const bool retirement_owns_recv =
            c.upstream_retirement_active ||
            (c.upstream_retirement_target_owned & kUpstreamOpRecv) != 0;
        if (c.upstream_fd >= 0 && !retirement_owns_recv) {
            const bool pause_owned =
                c.upstream_recv_cancel_inflight || c.upstream_recv_pause_cancel_pending;
            if (pause_owned) {
                if (c.upstream_recv_cancel_inflight) c.upstream_recv_terminal_stale = true;
                c.upstream_recv_close_quarantine = true;
            } else if (c.upstream_recv_armed &&
                       !begin_upstream_retirement_impl(c,
                                                       kUpstreamOpRecv,
                                                       c.on_upstream_recv == nullptr,
                                                       /*transfer_live_state=*/true)) {
                c.keep_alive = false;
                return;
            }
        }
        // From here on identical to the generic detach_upstream_close fallback.
        if (c.upstream_fd >= 0) {
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
        }
        clear_upstream_fd(c.id);
        c.upstream_recv_armed = false;
        c.upstream_send_armed = false;
    }

    // Return conn.upstream_fd to the idle pool at proxy completion. Unlike epoll's
    // synchronous detach, the multishot upstream recv (IORING_RECV_MULTISHOT) is
    // still armed here, so the fd can't be handed out until that recv stops — a new
    // borrower's recv would otherwise race the old one on the same socket. We cancel
    // the recv and DEFER the pool-return (idle_return_fd) until its terminal CQE
    // drains; try_deferred_upstream_rearm parks it then. If no recv is armed we park
    // immediately. The fd is detached from the conn (upstream_fd = -1) either way,
    // so release_upstream_conn's close is skipped; close_conn closes idle_return_fd
    // if the conn tears down before the drain.
    void return_idle_upstream(Connection& c, u16 upstream_id, u8 backend_idx) {
        if (c.upstream_fd < 0 || !upstream) return;  // caller closes
        const bool kRecvPending = c.upstream_recv_armed || c.upstream_recv_cancel_inflight ||
                                  c.upstream_recv_pause_cancel_pending;
        if (!kRecvPending) {
            const i32 fd = c.upstream_fd;
            c.upstream_fd = -1;
            c.upstream_send_armed = false;
            if (!upstream->put_idle(fd, upstream_id, backend_idx, monotonic_secs())) ::close(fd);
            return;
        }
        // The recv being drained belongs to the just-completed upstream fd, not to
        // any pipelined/follow-up request that may reuse this Connection slot. Any
        // terminal or positive CQE from it must be quarantined and dropped.
        c.upstream_recv_terminal_stale = true;
        c.upstream_recv_idle_stale_bytes = false;
        // Cancel the armed multishot recv; if the cancel SQE can't be queued, leave
        // the fd closed/detached but keep the old recv as an in-flight stale terminal
        // barrier; otherwise a later CQE can be delivered to the next request.
        if (c.upstream_recv_armed && !pause_upstream_recv_impl(c)) {
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
            c.upstream_send_armed = false;
            c.upstream_recv_cancel_inflight = true;
            return;
        }
        c.idle_return_fd = c.upstream_fd;
        c.idle_return_uid = upstream_id;
        c.idle_return_bidx = backend_idx;
        // Pin the config this fd is parked under. If a reload swaps it before the
        // recv drains, the deferred put_idle would slip a stale-config socket past
        // poll_command's pool drain — try_deferred_upstream_rearm closes on mismatch.
        c.idle_return_config = config_ptr ? *config_ptr : nullptr;
        c.upstream_fd = -1;
        c.upstream_send_armed = false;
    }

    // never pay the cost. Returns false if SlicePool is exhausted.
    bool alloc_upstream_buf(ConnectionBase& c) {
        if (c.upstream_recv_slice) return true;  // already allocated
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    bool alloc_response_header_buf(ConnectionBase& c) {
        if (c.response_header_slice) return true;
        u8* s = pool.alloc();
        if (!s) return false;
        c.response_header_slice = s;
        c.response_header_buf.bind(s, SlicePool::kSliceSize);
        return true;
    }

    // Two WebSocket terminate-mode reassembly slices (one per direction). All-or-nothing.
    bool alloc_ws_terminate_bufs(ConnectionBase& c) {
        if (c.ws_c2u_msg) return true;  // already allocated
        u8* a = pool.alloc();
        u8* b = pool.alloc();
        if (!a || !b) {
            if (a) pool.free(a);
            if (b) pool.free(b);
            return false;
        }
        c.ws_c2u_msg = a;
        c.ws_u2c_msg = b;
        return true;
    }

    // Initialize TLS termination on a freshly accepted connection: create the
    // engine, allocate the ciphertext in/out slices, and point on_recv at the
    // TLS driver. Returns false (and rolls back) if the engine or pool fails.
    bool tls_setup(Connection& c) {
        if (!tls_engine_init(c.tls_engine, tls_server)) return false;
        void* in_region = mmap(
            nullptr, kTlsInputSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (in_region == MAP_FAILED) {
            tls_engine_free(c.tls_engine);
            return false;
        }
        u8* in = static_cast<u8*>(in_region);
        // Owned ciphertext output buffer (kTlsOutBufCap, mmap like tls_in) — see
        // docs/iouring-tls-output-buffer.md. tls_out_slice holds the mmap base
        // for teardown; tls_out_buf is the Buffer view used for staging+draining.
        void* out_region = mmap(
            nullptr, kTlsOutBufCap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (out_region == MAP_FAILED) {
            munmap(in, kTlsInputSize);
            tls_engine_free(c.tls_engine);
            return false;
        }
        u8* out = static_cast<u8*>(out_region);
        c.tls_in_slice = in;
        c.tls_in_buf.bind(in, kTlsInputSize);
        c.tls_out_slice = out;
        c.tls_out_buf.bind(out, kTlsOutBufCap);
        c.tls_active = true;
        c.tls_handshake_complete = false;
        c.tls_pending_on_recv = &on_header_received<Self>;
        c.on_recv = &tls_recv<Self>;
        return true;
    }

    void free_tls_in_buf(ConnectionBase& c) {
        if (!c.tls_in_slice) return;
        munmap(c.tls_in_slice, kTlsInputSize);
        c.tls_in_slice = nullptr;
        c.tls_in_buf.bind(nullptr, 0);
    }

    void free_tls_out_buf(ConnectionBase& c) {
        if (!c.tls_out_slice) return;  // tls_out_slice is the mmap base (see tls_setup)
        munmap(c.tls_out_slice, kTlsOutBufCap);
        c.tls_out_slice = nullptr;
        c.tls_out_buf.bind(nullptr, 0);
    }

    bool response_read_batch_reuse_pinned(u32 cid) const {
        for (u32 i = 0; i < response_read_batch_pin_count; ++i) {
            if (response_read_batch_pins[i] == cid) return true;
        }
        return false;
    }

    void pin_response_read_batch_slot(u32 cid) {
        if (cid >= slots_initialized || response_read_batch_reuse_pinned(cid) ||
            response_read_batch_pin_count >= kMaxEventsPerWait)
            return;
        response_read_batch_pins[response_read_batch_pin_count++] = cid;
    }

    void release_deferred_epoch(Connection& c) {
        if (c.epoch_leave_deferred) {
            epoch_leave();
            c.epoch_leave_deferred = false;
        }
    }

    void reclaim_slot(u32 cid) {
        if (cid >= slots_initialized || response_read_batch_reuse_pinned(cid) ||
            strict_upstream_retirement_blocks_reclaim(conns[cid]) ||
            conns[cid].chain_direct_recv_owner.active || conns[cid].relay_owner.active() ||
            conns[cid].relay_owner.read_armed || conns[cid].relay_owner.write_armed ||
            conns[cid].relay_owner.read_cancel_owned || conns[cid].relay_owner.write_cancel_owned ||
            conns[cid].relay_owner.read_cancel_retry || conns[cid].relay_owner.write_cancel_retry ||
            conns[cid].relay_owner.close_pending || conns[cid].relay_owner.segment_len != 0 ||
            !conns[cid].response_read_timer_owner_is_neutral())
            return;
        bool was_pending = false;
        for (u32 i = 0; i < pending_free_count; i++) {
            if (pending_free[i] == cid) {
                pending_free[i] = pending_free[--pending_free_count];
                was_pending = true;
                break;
            }
        }
        // Every deferred slot enters pending_free in free_conn_impl. Refusing
        // an unowned reclaim makes duplicate finals idempotent.
        if (!was_pending) return;
        if (conns[cid].recv_slice) {
            pool.free(conns[cid].recv_slice);
            conns[cid].recv_slice = nullptr;
            conns[cid].recv_slice_capacity = 0;
        }
        if (conns[cid].send_slice) {
            pool.free(conns[cid].send_slice);
            conns[cid].send_slice = nullptr;
        }
        if (conns[cid].upstream_recv_slice) {
            pool.free(conns[cid].upstream_recv_slice);
            conns[cid].upstream_recv_slice = nullptr;
        }
        if (conns[cid].upstream_relay_slice) {
            pool.free(conns[cid].upstream_relay_slice);
            conns[cid].upstream_relay_slice = nullptr;
        }
        if (conns[cid].response_header_slice) {
            pool.free(conns[cid].response_header_slice);
            conns[cid].response_header_slice = nullptr;
        }
        close_response_splice_pipe(conns[cid]);
        release_deferred_epoch(conns[cid]);
        conns[cid].response_body_tail.release();
        free_tls_in_buf(conns[cid]);
        free_tls_out_buf(conns[cid]);
        if (!conns[cid].upstream_episode_quarantined) free_stack[free_top++] = cid;
    }

    void reclaim_pending() {
        u32 remaining = 0;
        for (u32 i = 0; i < pending_free_count; i++) {
            u32 cid = pending_free[i];
            if (!response_read_batch_reuse_pinned(cid) && conns[cid].pending_ops == 0 &&
                !strict_upstream_retirement_blocks_reclaim(conns[cid]) &&
                !conns[cid].chain_direct_recv_owner.active && !conns[cid].relay_owner.active() &&
                !conns[cid].relay_owner.read_armed && !conns[cid].relay_owner.write_armed &&
                !conns[cid].relay_owner.read_cancel_owned &&
                !conns[cid].relay_owner.write_cancel_owned &&
                !conns[cid].relay_owner.read_cancel_retry &&
                !conns[cid].relay_owner.write_cancel_retry &&
                !conns[cid].relay_owner.close_pending && conns[cid].relay_owner.segment_len == 0 &&
                conns[cid].response_read_timer_owner_is_neutral()) {
                if (conns[cid].recv_slice) {
                    pool.free(conns[cid].recv_slice);
                    conns[cid].recv_slice = nullptr;
                    conns[cid].recv_slice_capacity = 0;
                }
                if (conns[cid].send_slice) {
                    pool.free(conns[cid].send_slice);
                    conns[cid].send_slice = nullptr;
                }
                if (conns[cid].upstream_recv_slice) {
                    pool.free(conns[cid].upstream_recv_slice);
                    conns[cid].upstream_recv_slice = nullptr;
                }
                if (conns[cid].upstream_relay_slice) {
                    pool.free(conns[cid].upstream_relay_slice);
                    conns[cid].upstream_relay_slice = nullptr;
                }
                if (conns[cid].response_header_slice) {
                    pool.free(conns[cid].response_header_slice);
                    conns[cid].response_header_slice = nullptr;
                }
                close_response_splice_pipe(conns[cid]);
                release_deferred_epoch(conns[cid]);
                conns[cid].response_body_tail.release();
                free_tls_in_buf(conns[cid]);
                free_tls_out_buf(conns[cid]);
                if (!conns[cid].upstream_episode_quarantined) free_stack[free_top++] = cid;
            } else {
                pending_free[remaining++] = cid;
            }
        }
        pending_free_count = remaining;
    }

    // --- CRTP implementations (io_uring: async, with armed/pending_ops) ---

    // Construct and reset() every slot in [slots_initialized, n) and advance the
    // watermark. Cold path: only reached when a never-used slot is handed out.
    void initialize_slots_to(u32 n) {
        if (n > connection_capacity) n = connection_capacity;
        if (n <= slots_initialized) return;
        conns.construct_to(n);
        for (u32 i = slots_initialized; i < n; i++) {
            conns[i].reset();
            conns[i].id = i;
            conns[i].shard_id = static_cast<u8>(shard_id);
        }
        slots_initialized = n;
    }

    Connection* alloc_conn_impl() {
        if (free_top == 0) return nullptr;
        u8* rs = pool.alloc();
        u8* ss = pool.alloc();
        if (!rs || !ss) {
            if (rs) pool.free(rs);
            if (ss) pool.free(ss);
            return nullptr;
        }
        u32 id = free_stack[--free_top];
        // Fresh ids pop in ascending order, so a never-used slot is exactly
        // the next one past the watermark; initialize_slots_to also covers any
        // gap so the prefix invariant does not depend on hand-out order.
        if (id >= slots_initialized) initialize_slots_to(id + 1);
        // A free slot has drained every target and cancel completion. Failed
        // sends can leave unsent bytes in the backend proactor even after the
        // connection's close ledger drains; those bytes belong to the old fd.
        // Clear both proactors before the new connection can validate or send.
        backend.send_state[id] = {nullptr, -1, 0, 0, IoEventType::Send, 0, 0};
        backend.upstream_send_state[id] = {nullptr, -1, 0, 0, IoEventType::UpstreamSend, 0, 0};
        conns[id].reset();
        conns[id].id = id;
        conns[id].shard_id = static_cast<u8>(shard_id);
        conns[id].listener_context = this->listener_context;
        conns[id].bind_request_receive_buffer(rs, SlicePool::kSliceSize);
        conns[id].send_slice = ss;
        conns[id].send_buf.bind(ss, SlicePool::kSliceSize);
        if (capture_region_)
            conns[id].capture_buf = capture_region_ + static_cast<u64>(id) * kCaptureSliceSize;
        return &conns[id];
    }

    bool alloc_h2_impl(Connection& c) {
        if (c.h2) return true;  // already attached
        Http2Conn* h = h2_pool.alloc();
        if (!h) return false;
        c.h2 = h;
        return true;
    }

    void free_conn_impl(Connection& c) {
        u32 cid = c.id;
        timer.remove(&c);
        // A recv waiting for buffers must not re-arm on a reused slot.
        clear_deferred_recv(cid);
        // Slot reuse does not advance the upstream episode. Remove any
        // CPU-owned parked relay before reset can publish this slot again.
        clear_deferred_relay_read(cid);
        // The h2 engine is a pool object, not a kernel buffer — safe to reclaim
        // now even with ops in flight (unlike the recv/send slices below).
        if (c.h2) {
            h2_pool.free(c.h2);
            c.h2 = nullptr;
        }
        // The TlsEngine owns only the SSL object (+ its custom BIO), never the
        // io_uring-referenced slices — safe to free now even with ops in flight.
        if (c.tls_engine.ssl) tls_engine_free(c.tls_engine);
        // WebSocket terminate reassembly slices are CPU-only scratch (never handed to a
        // kernel op — the re-framed output goes in place in the recv slices), so reclaim
        // them now too, regardless of in-flight ops.
        if (c.ws_c2u_msg) {
            pool.free(c.ws_c2u_msg);
            c.ws_c2u_msg = nullptr;
        }
        if (c.ws_u2c_msg) {
            pool.free(c.ws_u2c_msg);
            c.ws_u2c_msg = nullptr;
        }
        // Reclaim immediately only after ordinary ops and the separately
        // accounted response-read timer have both drained.
        if (c.pending_ops == 0 && !c.chain_direct_recv_owner.active &&
            !response_read_batch_reuse_pinned(cid) &&
            !strict_upstream_retirement_blocks_reclaim(c) &&
            c.response_read_timer_owner_is_neutral() && !c.relay_owner.active() &&
            !c.relay_owner.read_armed && !c.relay_owner.write_armed &&
            !c.relay_owner.read_cancel_owned && !c.relay_owner.write_cancel_owned &&
            !c.relay_owner.read_cancel_retry && !c.relay_owner.write_cancel_retry &&
            !c.relay_owner.close_pending && c.relay_owner.segment_len == 0) {
            close_response_splice_pipe(c);
            if (c.recv_slice) pool.free(c.recv_slice);
            if (c.send_slice) pool.free(c.send_slice);
            if (c.upstream_recv_slice) pool.free(c.upstream_recv_slice);
            if (c.upstream_relay_slice) pool.free(c.upstream_relay_slice);
            if (c.response_header_slice) pool.free(c.response_header_slice);
            c.response_body_tail.release();
            free_tls_in_buf(c);
            free_tls_out_buf(c);
            release_deferred_epoch(c);
            c.reset();
            if (!c.upstream_episode_quarantined) free_stack[free_top++] = cid;
            return;
        }
        // Kernel ownership remains: defer until its CQEs drain.
        u8* rs = c.recv_slice;
        u8* ss = c.send_slice;
        auto response_body_tail = c.response_body_tail;
        const auto chain_direct_recv_owner = c.chain_direct_recv_owner;
        const auto relay_owner = c.relay_owner;
        const bool upstream_recv_direct_armed = c.upstream_recv_direct_armed;
        u8* us = c.upstream_recv_slice;
        u8* relay = c.upstream_relay_slice;
        u8* hs = c.response_header_slice;
        u8* tin = c.tls_in_slice;
        u8* tout = c.tls_out_slice;
        u32 ops = c.pending_ops;
        const u8 allocated_shard = c.shard_id;
        const u32 retiring_episode = c.upstream_retiring_episode;
        const bool retirement_active = c.upstream_retirement_active;
        const u8 retirement_target_owned = c.upstream_retirement_target_owned;
        const u8 retirement_cancel_owned = c.upstream_retirement_cancel_owned;
        const u8 retirement_cancel_retry = c.upstream_retirement_cancel_retry;
        const u32 close_episode = c.upstream_close_episode;
        const u8 close_target_owned = c.upstream_close_target_owned;
        const u8 close_cancel_owned = c.upstream_close_cancel_owned;
        const bool close_pause_cancel_owned = c.upstream_close_pause_cancel_owned;
        const u32 deadline_send_close_generation = c.response_read_deadline_send_close_generation;
        const bool deadline_send_close_target_owned =
            c.response_read_deadline_send_close_target_owned;
        const bool deadline_send_close_cancel_owned =
            c.response_read_deadline_send_close_cancel_owned;
        const bool epoch_leave_deferred = c.epoch_leave_deferred;
        c.reset();
        conns[cid].id = cid;
        conns[cid].shard_id = allocated_shard;
        conns[cid].recv_slice = rs;
        conns[cid].recv_slice_capacity = rs != nullptr ? SlicePool::kSliceSize : 0;
        conns[cid].send_slice = ss;
        conns[cid].response_body_tail = response_body_tail;
        conns[cid].chain_direct_recv_owner = chain_direct_recv_owner;
        conns[cid].relay_owner = relay_owner;
        conns[cid].upstream_recv_direct_armed = upstream_recv_direct_armed;
        conns[cid].upstream_recv_slice = us;
        conns[cid].upstream_relay_slice = relay;
        conns[cid].response_header_slice = hs;
        conns[cid].tls_in_slice = tin;
        conns[cid].tls_out_slice = tout;
        conns[cid].pending_ops = ops;
        conns[cid].upstream_retiring_episode = retiring_episode;
        conns[cid].upstream_retirement_active = retirement_active;
        conns[cid].upstream_retirement_target_owned = retirement_target_owned;
        conns[cid].upstream_retirement_cancel_owned = retirement_cancel_owned;
        conns[cid].upstream_retirement_cancel_retry = retirement_cancel_retry;
        conns[cid].upstream_close_episode = close_episode;
        conns[cid].upstream_close_target_owned = close_target_owned;
        conns[cid].upstream_close_cancel_owned = close_cancel_owned;
        conns[cid].upstream_close_pause_cancel_owned = close_pause_cancel_owned;
        conns[cid].response_read_deadline_send_close_generation = deadline_send_close_generation;
        conns[cid].response_read_deadline_send_close_target_owned =
            deadline_send_close_target_owned;
        conns[cid].response_read_deadline_send_close_cancel_owned =
            deadline_send_close_cancel_owned;
        conns[cid].epoch_leave_deferred = epoch_leave_deferred;
        pending_free[pending_free_count++] = cid;
    }

    void defer_recv_rearm(const Connection& c) {
        if (c.id >= connection_capacity || recv_rearm_words.data() == nullptr) return;
        u64& word = recv_rearm_words[c.id >> 6];
        const u64 bit = u64{1} << (c.id & 63u);
        if ((word & bit) != 0) return;
        word |= bit;
        recv_rearm_count++;
    }

    void clear_deferred_recv(u32 cid) {
        if (recv_rearm_count == 0 || cid >= connection_capacity) return;
        u64& word = recv_rearm_words[cid >> 6];
        const u64 bit = u64{1} << (cid & 63u);
        if ((word & bit) == 0) return;
        word &= ~bit;
        recv_rearm_count--;
    }

    // Re-arm downstream recvs that completed with the provided ring empty. Their
    // request bytes are still in the socket, so nothing was lost, but arming
    // while the ring is still short of buffers would just complete -ENOBUFS
    // again. Buffers are returned as wait() harvests, so only CQEs still queued
    // hold any: re-arm once fewer than half the ring's buffers can be pinned
    // that way. `force` (timer tick) skips that gate so a saturated CQ cannot
    // starve a connection indefinitely. At most as many recvs are armed per pass
    // as buffers can be free (a recv armed beyond that bounces straight back),
    // and the next pass resumes from recv_rearm_cursor so every parked
    // connection is reached. A recv that finds no SQE stays pending.
    void rearm_deferred_recvs(bool force) {
        if (recv_rearm_count == 0) return;
        u32 cache_free = kProvidedBufCount;
        if (backend.ws_recv_cache_enabled) {
            cache_free = ws_cache_rearm_budget;
            if (cache_free == 0) return;
        }
        const u32 pinned = backend.cq_unharvested();
        if (!force && pinned >= kProvidedBufCount / 2) return;
        u32 budget = pinned < kProvidedBufCount ? kProvidedBufCount - pinned : 0;
        if (backend.ws_recv_cache_enabled && budget > cache_free) budget = cache_free;
        if (budget == 0 && force) budget = 1;  // the backstop always makes progress
        if (slots_initialized == 0) return;
        const u32 start = recv_rearm_slot_cursor < slots_initialized ? recv_rearm_slot_cursor : 0;
        for (u32 n = 0; n < slots_initialized && recv_rearm_count != 0 && budget != 0; ++n) {
            const u32 cid = (start + n) % slots_initialized;
            const u64 bit = u64{1} << (cid & 63u);
            u64& word = recv_rearm_words[cid >> 6];
            if ((word & bit) == 0) continue;
            Connection& c = conns[cid];
            if (c.fd >= 0) {
                const bool was_armed = c.recv_armed;
                if (!submit_recv_impl(c)) {
                    recv_rearm_slot_cursor = cid;
                    return;
                }
                if (!was_armed && !c.recv_armed) continue;
                budget--;
                recv_rearm_slot_cursor = (cid + 1u) % slots_initialized;
                if (backend.ws_recv_cache_enabled) ws_cache_rearm_budget = budget;
            }
            clear_deferred_recv(cid);
        }
    }

    // Cache-mode upstream recvs must wait for a retained provided buffer to
    // return. Retrying while the cache owns every buffer only produces another
    // -ENOBUFS CQE and can spin the shard without making progress.
    void rearm_deferred_ws_cache_recvs() {
        if (!backend.ws_recv_cache_enabled) return;
        u32 budget = ws_cache_rearm_budget;
        if (budget == 0) return;
        if (slots_initialized == 0) return;
        const u32 start = ws_cache_rearm_cursor < slots_initialized ? ws_cache_rearm_cursor : 0;
        for (u32 offset = 0; offset < slots_initialized; ++offset) {
            const u32 id = (start + offset) % slots_initialized;
            Connection& c = conns[id];
            if (!ws_recv_cache_active(c) || !c.upstream_recv_pause_rearm_pending ||
                c.upstream_recv_armed)
                continue;
            const bool was_armed = c.upstream_recv_armed;
            if (!try_deferred_upstream_rearm(c)) {
                close_conn(c);
                return;
            }
            if (!was_armed && c.upstream_recv_armed) {
                ws_cache_rearm_cursor = (id + 1u) % slots_initialized;
                ws_cache_rearm_budget = --budget;
                if (budget == 0) return;
            }
        }
    }

    void rearm_deferred_cache_passes(bool force) {
        if (ws_cache_rearm_upstream_turn) {
            rearm_deferred_ws_cache_recvs();
            rearm_deferred_recvs(force);
        } else {
            rearm_deferred_recvs(force);
            rearm_deferred_ws_cache_recvs();
        }
        ws_cache_rearm_upstream_turn = !ws_cache_rearm_upstream_turn;
    }

    u32 cache_rearm_budget(u32 pinned) const {
        const u32 free = kProvidedBufCount - backend.ws_recv_cache_ordinary_count;
        return free > pinned ? free - pinned : 0;
    }

    // Tunnel callbacks consume one contiguous block while its paired send
    // owns that memory. A terminal bounded recv prevents a multishot burst
    // from filling the same buffer before dispatch can apply backpressure.
    bool use_one_shot_websocket_recv(const Connection& c) const {
        const bool cache_eligible = c.is_ws_tunnel && !c.is_ws_terminate && !c.tls_active;
        if (backend.ws_recv_cache_enabled && cache_eligible) return false;
        return (c.is_ws_tunnel || c.is_ws_terminate) && !c.tls_active &&
               c.protocol == ConnProtocol::Http11 && c.fd >= 0 && c.upstream_fd >= 0 &&
               valid_upstream_episode(c.upstream_episode);
    }

    // Terminal one-shot reads and bounded-cache multishot reads can lend this
    // connection buffer to an immediate send. Multishot writes only into
    // selected kernel buffers; wait() retains later blocks while a send owns
    // the connection buffer, so an armed cached receive cannot overwrite it.
    // A positive short write leaves the entire source buffer intact; the caller
    // submits the unsent suffix through the original send ledger and consumes
    // the full source only when that suffix completes.
    bool try_ws_sync_send(Connection& c, bool upstream, const u8* source, u32 length, i32* sent) {
        if (!study_ws_sync_send || ws_splice.enabled) return false;
        const bool kCached = ws_recv_cache_active(c) && c.protocol == ConnProtocol::Http11 &&
                             c.fd >= 0 && c.upstream_fd >= 0 &&
                             valid_upstream_episode(c.upstream_episode);
        if ((!use_one_shot_websocket_recv(c) && !kCached) || c.is_ws_terminate ||
            c.is_ws_terminate_route || c.ws_closing || c.ws_client_eof || c.ws_upstream_eof ||
            c.throttle_down_bps != 0 || c.response_policy_id != 0 ||
            (upstream ? c.upstream_send_armed : c.send_armed) || c.recv_pause_cancel_pending ||
            c.recv_pause_target_inflight || c.upstream_recv_pause_cancel_pending ||
            c.upstream_recv_cancel_inflight || length == 0)
            return false;
        auto& buffer = upstream ? c.recv_buf : c.upstream_recv_buf;
        if (source != buffer.data() || length != buffer.len() ||
            (!kCached && (upstream ? c.recv_armed : c.upstream_recv_armed)))
            return false;
        // A short direct write must be followed by an owned async suffix.
        // Reserve that completion SQE before sending any irreversible bytes.
        if (!backend.sq_has_room()) return false;
        ++study_ws_sync_attempts;
        if (kCached) ++study_ws_sync_cached;
        const bool kSampled = backend.study_io_stats && (++study_splice_calls[1] & 63u) == 0;
        const u64 kStarted = kSampled ? monotonic_ns() : 0;
        ssize_t n;
        do {
            n = ::send(
                upstream ? c.upstream_fd : c.fd, source, length, MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (n < 0 && errno == EINTR);
        const int kSavedErrno = errno;
        if (kSampled) study_record_syscall(1, monotonic_ns() - kStarted);
        errno = kSavedErrno;
        if (n < 0) {
            if (kSavedErrno == EAGAIN || kSavedErrno == EWOULDBLOCK) {
                ++study_ws_sync_blocked;
                *sent = 0;
            } else {
                ++study_ws_sync_errors;
                *sent = -kSavedErrno;
            }
        } else {
            *sent = static_cast<i32>(n);
            study_ws_sync_bytes += static_cast<u32>(n);
            if (static_cast<u32>(n) == length)
                ++study_ws_sync_full;
            else
                ++study_ws_sync_partial;
        }
        return true;
    }

    bool ws_recv_cache_active(const Connection& c) const {
        return backend.ws_recv_cache_enabled && c.is_ws_tunnel && !c.is_ws_terminate &&
               !c.tls_active;
    }
    bool ws_has_cached_input(const Connection& c) const { return backend.has_ws_recv_cache(c.id); }

    bool submit_recv_impl(Connection& c) {
        if (ws_splice.intercept_recv(*this, c)) return true;
        const bool tls_send_needs_recv =
            c.uses_iouring_tls() && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>;
        if (tls_send_needs_recv) c.recv_paused_for_send = false;
        if (c.recv_paused_for_send && !tls_send_needs_recv) {
            c.recv_pause_rearm_pending = true;
            return true;
        }
        if (c.recv_pause_cancel_pending || c.recv_pause_target_inflight) {
            c.recv_pause_rearm_pending = true;
            return true;
        }
        if (c.recv_armed) {
            if (c.recv_pause_cancel_pending) c.recv_pause_rearm_pending = true;
            return true;
        }
        bool submitted = false;
        if (use_one_shot_websocket_recv(c)) {
            const u32 kAvailable = c.recv_buf.write_avail();
            const u32 kMaximum = kProvidedBufSize;
            submitted = backend.add_recv_once(
                c.fd,
                c.id,
                kAvailable < kMaximum ? kAvailable : kMaximum,
                study_ws_poll_first && !c.is_ws_terminate && !c.is_ws_terminate_route);
            if (submitted && study_ws_poll_first && !c.is_ws_terminate && !c.is_ws_terminate_route)
                ++study_ws_poll_first_arms;
        } else {
            submitted = backend.add_recv(c.fd, c.id);
        }
        if (submitted) {
            c.pending_ops++;
            c.recv_armed = true;
            c.recv_pause_rearm_pending = false;
            return true;
        }
        return false;
    }

    // A request-boundary continuation may install the next HTTP callback after
    // an earlier TLS recv CQE was deferred behind a raw ciphertext send. The
    // CQE's bytes are already in tls_in_buf, so there may be no later socket
    // event to call tls_process. Drive that existing input only when the raw
    // send no longer owns the TLS output buffer. The caller must return
    // immediately when this reports true: tls_process can synchronously
    // dispatch a request or close/reset the connection.
    bool process_buffered_tls_input(Connection& c) {
        if (!c.uses_iouring_tls() || c.tls_in_buf.len() == 0 || c.tls_out_inflight) return false;
        tls_process<Self>(this, c);
        if (c.tls_active && (c.req_body_abandoned || c.req_body_overflow_rejected) &&
            c.tls_pending_on_recv != &tls_resume_pending_send_recv<Self>)
            tls_discard_abandoned_input<Self>(this, c);
        return true;
    }

    bool tls_ciphertext_send_raw_state_matches(const Connection& c) const {
        if (c.id >= connection_capacity || c.fd < 0 || !c.tls_active || !c.tls_out_inflight ||
            c.tls_out_inflight_len == 0 || c.tls_out_inflight_generation == 0 ||
            (c.tls_out_inflight_generation & kNonUpstreamSendCancelBit) != 0 ||
            c.tls_out_inflight_fd != c.fd || c.tls_out_inflight_src == nullptr ||
            c.tls_out_inflight_src != c.tls_out_buf.data() ||
            c.tls_out_inflight_len > c.tls_out_buf.len() || !c.send_armed || c.pending_ops == 0)
            return false;
        const auto& send = backend.send_state[c.id];
        return send.src == c.tls_out_inflight_src && send.fd == c.tls_out_inflight_fd &&
               send.type == IoEventType::Send && send.generation == c.tls_out_inflight_generation &&
               send.offset <= c.tls_out_inflight_len &&
               send.remaining <= c.tls_out_inflight_len - send.offset;
    }

    bool tls_ciphertext_send_is_current(const Connection& c) const {
        if (!tls_ciphertext_send_raw_state_matches(c)) return false;
        const auto& send = backend.send_state[c.id];
        return send.offset + send.remaining == c.tls_out_inflight_len;
    }

    // Deliver the saved continuation as a logical plaintext completion. Raw
    // ciphertext CQE accounting has already finished and is never repeated here.
    void complete_tls_logical_send(Connection& c,
                                   const TlsLogicalSendCompletionWitness& witness,
                                   Connection::Callback continuation) {
        const bool valid =
            c.id < connection_capacity && c.tls_active && c.fd == witness.fd &&
            witness.generation != 0 && (witness.generation & kNonUpstreamSendCancelBit) == 0 &&
            c.handler_gen == witness.handler_generation && witness.src != nullptr &&
            witness.len != 0 && witness.len <= static_cast<u32>(INT32_MAX) && !c.send_armed &&
            c.tls_raw_send_owner_is_neutral() && c.tls_single_shot_send_owner_is_neutral();
        if (!valid) {
            close_conn(c);
            return;
        }

        IoEvent ev = {};
        ev.conn_id = c.id;
        ev.type = IoEventType::Send;
        ev.result = static_cast<i32>(witness.len);
        const ResponseReadDeadlineSendKind strict_kind = response_read_deadline_tls_send_kind(c);
        const bool prebuilt_candidate =
            continuation == &on_prebuilt_http1_header_sent<Self> ||
            c.on_send == &on_prebuilt_http1_header_sent<Self> ||
            !c.http1_prebuilt_response_proof_is_neutral() || c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None;
        if (strict_kind != ResponseReadDeadlineSendKind::None && prebuilt_candidate) {
            close_conn(c);
            return;
        }
        if (strict_kind != ResponseReadDeadlineSendKind::None) {
            const bool owner_matches =
                continuation != nullptr && c.on_send == continuation &&
                c.response_read_deadline_send_owner_active &&
                c.response_read_deadline_send_owner_generation == witness.generation &&
                c.response_read_deadline_send_fd == witness.fd &&
                c.response_read_deadline_send_src == witness.src &&
                c.response_read_deadline_send_len == witness.len &&
                c.response_read_deadline_send_tombstone_generation < witness.generation &&
                c.response_read_deadline_send_deadline_generation ==
                    c.response_read_deadline_post_commit_generation &&
                c.response_read_deadline_send_upstream_episode ==
                    c.response_read_deadline_post_commit_episode &&
                response_read_deadline_tls_send_frame_is_valid(
                    c, strict_kind, continuation, witness.src, witness.len);
            if (!owner_matches) {
                close_conn(c);
                return;
            }
            c.response_read_deadline_send_owner_active = false;
            c.response_read_deadline_send_tombstone_generation = witness.generation;
            ev.non_upstream_generation = witness.generation;
            if (!response_read_deadline_send_completion_is_valid(c, ev, strict_kind)) {
                close_conn(c);
                return;
            }
        } else if (continuation == &on_prebuilt_http1_header_sent<Self> ||
                   c.on_send == &on_prebuilt_http1_header_sent<Self> ||
                   !c.http1_prebuilt_response_proof_is_neutral() || c.http1_prebuilt_wait != 0 ||
                   c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None) {
            const bool owner_matches =
                continuation == &on_prebuilt_http1_header_sent<Self> && c.on_send == continuation &&
                witness.src == c.response_header_buf.data() &&
                witness.len == c.http1_prebuilt_total_len &&
                response_read_deadline_send_fields_are_neutral(c) &&
                c.response_read_deadline_send_tombstone_generation < witness.generation &&
                prebuilt_http11_tls_read_timeout_is_stable(c, /*sending=*/true);
            if (!owner_matches) {
                close_conn(c);
                return;
            }
            // Publish the already-drained TLS logical send in the persistent
            // semantic tombstone.  This authenticates the synthetic event for
            // the existing prebuilt-response validator without inventing a
            // backend send-state owner.
            c.response_read_deadline_send_tombstone_generation = witness.generation;
            ev.non_upstream_generation = witness.generation;
            if (!prebuilt_http1_header_send_completion_is_valid(c, ev)) {
                close_conn(c);
                return;
            }
        } else if (!response_read_deadline_send_fields_are_neutral(c)) {
            close_conn(c);
            return;
        }
        if (continuation == nullptr) {
            if (strict_kind != ResponseReadDeadlineSendKind::None) close_conn(c);
            return;
        }
        continuation(this, c, ev);
    }

    // Submit one authenticated kernel target for the current ciphertext
    // prefix. TLS raw targets use their own identity and never inherit the
    // response-phase plaintext owner inferred by submit_send_raw().
    bool submit_tls_ciphertext_send(Connection& c, const u8* src, u32 len) {
        if (backend.failure_code() != 0 || c.id >= connection_capacity || c.fd < 0 ||
            !c.tls_active || c.tls_engine.ssl == nullptr || c.send_armed ||
            !c.tls_raw_send_owner_is_neutral() || src == nullptr || len == 0 ||
            src != c.tls_out_buf.data() || len > c.tls_out_buf.len() ||
            backend.send_state[c.id].remaining != 0)
            return false;
        u32 generation = 0;
        if (!c.next_non_upstream_send_generation(generation)) return false;
        if (!backend.add_send(
                c.fd, c.id, src, len, generation, c.tls_ciphertext_send_has_follow_up(len)))
            return false;
        c.tls_out_inflight = true;
        c.tls_out_inflight_len = len;
        c.tls_out_inflight_generation = generation;
        c.tls_out_inflight_fd = c.fd;
        c.tls_out_inflight_src = src;
        c.pending_ops++;
        c.send_armed = true;
        c.on_send = &tls_on_out_drain<Self>;
        return true;
    }

    // Raw client send — bytes go to the wire as-is (plaintext, or already-
    // encrypted ciphertext from the TLS layer).
    bool submit_send_raw(Connection& c, const u8* buf, u32 len) {
        const auto phase = c.response_read_deadline_post_commit_phase;
        const bool deadline_send = phase == ResponseReadDeadlinePostCommitPhase::HeaderSend ||
                                   phase == ResponseReadDeadlinePostCommitPhase::BodySend ||
                                   phase == ResponseReadDeadlinePostCommitPhase::CombinedSend;
        u32 generation = 0;
        if (deadline_send) {
            ResponseReadDeadlineSendKind kind = ResponseReadDeadlineSendKind::None;
            switch (phase) {
                case ResponseReadDeadlinePostCommitPhase::None:
                case ResponseReadDeadlinePostCommitPhase::Buffering:
                case ResponseReadDeadlinePostCommitPhase::WaitingBody:
                case ResponseReadDeadlinePostCommitPhase::OriginComplete:
                    return false;
                case ResponseReadDeadlinePostCommitPhase::HeaderSend:
                    kind = ResponseReadDeadlineSendKind::Header;
                    break;
                case ResponseReadDeadlinePostCommitPhase::BodySend:
                    kind = ResponseReadDeadlineSendKind::Body;
                    break;
                case ResponseReadDeadlinePostCommitPhase::CombinedSend:
                    kind = ResponseReadDeadlineSendKind::Combined;
                    break;
                default:
                    return false;
            }
            if (c.response_read_deadline_send_owner_active || buf == nullptr || len == 0 ||
                c.fd < 0 || !c.next_response_read_deadline_send_generation())
                return false;
            generation = c.response_read_deadline_send_owner_generation;
            c.response_read_deadline_send_deadline_generation = c.response_read_deadline_generation;
            c.response_read_deadline_send_upstream_episode =
                forward_response_buffering_uses_content_length_machinery(
                    c.response_read_deadline_buffering)
                    ? c.response_read_deadline_post_commit_episode
                    : c.upstream_episode;
            c.response_read_deadline_send_src = buf;
            c.response_read_deadline_send_len = len;
            c.response_read_deadline_send_fd = c.fd;
            c.response_read_deadline_send_kind = kind;
            c.response_read_deadline_send_owner_active = true;
        }
        // The completion SQE is reserved first: once written, the bytes and
        // FIN cannot be withdrawn, so the send must stay accountable.
        if (!deadline_send && final_local_response_send(c, buf, len) && backend.sq_has_room()) {
            // The last response on a closing plaintext connection: write it
            // directly and end the stream at once, as nginx does, so the FIN
            // follows the data before the client can close first.
            const ssize_t n = ::send(c.fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n > 0) {
                const u32 written = static_cast<u32>(n);
                if (written == len) (void)::shutdown(c.fd, SHUT_WR);
                if (backend.add_send_after_direct_write(
                        c.fd, c.id, buf, len, written, generation)) {
                    c.pending_ops++;
                    c.send_armed = true;
                    c.direct_write_completion_pending = true;
                    return true;
                }
                return false;
            }
        }
        BufferedSendVector* vector = nullptr;
        if (!c.tls_active &&
            c.response_read_deadline_post_commit_phase ==
                ResponseReadDeadlinePostCommitPhase::BodySend &&
            len > c.buffered_response_front_size()) {
            if (buf != c.buffered_response_data() || c.upstream_recv_buf.len() != 0 ||
                len > c.buffered_response_send_span_size() || !c.response_body_tail.head ||
                !c.response_body_tail.head->next) {
                if (deadline_send) c.clear_response_read_deadline_send_owner();
                return false;
            }
            const auto* next = c.response_body_tail.head->next;
            const u32 first = c.buffered_response_front_size();
            c.response_send_vector.bind(
                buf, first, ResponseBodyChain::payload(next) + next->offset, len - first);
            vector = &c.response_send_vector;
        }
        static const bool study_direct_body = ::getenv("RUT_STUDY_DIRECT_BODY_SEND") != nullptr;
        if (study_direct_body && c.response_read_deadline_upload.downstream_close &&
            c.req_client_connection_close_exact && !c.req_client_keep_alive && deadline_send &&
            !c.tls_active &&
            c.response_read_deadline_send_kind == ResponseReadDeadlineSendKind::Body &&
            len >= 32 * 1024 && backend.nop_inject_result && backend.sq_has_room()) {
            const u32 extra_flags = c.plaintext_send_has_follow_up(len) ? MSG_MORE : 0;
            ++study_direct_body_attempts;
            const ssize_t n =
                vector
                    ? ::sendmsg(c.fd, &vector->message, MSG_DONTWAIT | MSG_NOSIGNAL | extra_flags)
                    : ::send(c.fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL | extra_flags);
            if (n > 0) {
                ++study_direct_body_progress;
                if (static_cast<u32>(n) == len) ++study_direct_body_full;
                if (backend.add_send_after_direct_write(c.fd,
                                                        c.id,
                                                        buf,
                                                        len,
                                                        static_cast<u32>(n),
                                                        generation,
                                                        vector,
                                                        extra_flags)) {
                    c.pending_ops++;
                    c.send_armed = true;
                    return true;
                }
                return false;
            }
        }
        if (backend.add_send(
                c.fd, c.id, buf, len, generation, c.plaintext_send_has_follow_up(len), vector)) {
            c.pending_ops++;
            c.send_armed = true;
            return true;
        }
        if (deadline_send) c.clear_response_read_deadline_send_owner();
        return false;
    }

    // Plaintext local-body chunk from a sealed memfd (see add_send_file).
    // Declines — leaving the caller to send from memory — on TLS, while a
    // response-deadline send owns the connection, or without an SQE.
    SendFileOutcome submit_send_file(Connection& c, i32 file_fd, u32 file_off, u32 len) {
        if (c.tls_active || c.fd < 0 || c.send_armed || file_fd < 0 || len == 0 ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None ||
            backend.failure_code() != 0)
            return SendFileOutcome::Failed;
        // The last chunk of a closing response ends the stream as soon as it
        // is out, like final_local_response_send's direct write.
        const bool kFinal =
            !c.keep_alive && c.local_body_remaining == 0 && c.on_send == &on_response_sent<Self>;
        // A synchronous completion is only offered while none is already on
        // the stack (see in_sync_send_completion): the decision is made here,
        // once, and handed to add_send_file explicitly so the backend never
        // has to infer it (and can't disagree with this check) from
        // nop_inject_result or anything else.
        const bool kAllowSyncCompletion = !in_sync_send_completion;
        bool wrote_all = false;
        if (!backend.add_send_file(
                c.fd, c.id, file_fd, file_off, len, 0, kFinal, &wrote_all, kAllowSyncCompletion))
            return SendFileOutcome::Failed;
        if (!kFinal && wrote_all && kAllowSyncCompletion) {
            // add_send_file queued no SQE for this: the caller completes it
            // synchronously (see the comment on SendFileOutcome).
            return SendFileOutcome::CompletedSync;
        }
        c.pending_ops++;
        c.send_armed = true;
        // Bytes and FIN are on the wire: a client that read them and reset
        // must not pre-empt the completion that accounts the request.
        if (kFinal && wrote_all) c.direct_write_completion_pending = true;
        return SendFileOutcome::Armed;
    }

    [[nodiscard]] bool final_local_response_send(const Connection& c,
                                                 const u8* buf,
                                                 u32 len) const {
        return backend.nop_inject_result && !c.tls_active && !c.keep_alive && c.fd >= 0 &&
               !c.send_armed && len != 0 && len <= static_cast<u32>(INT32_MAX) &&
               c.on_send == &on_response_sent<Self> && c.send_progress == 0 &&
               c.local_body_remaining == 0 &&
               ((buf == c.send_buf.data() && len == c.send_buf.len() &&
                 c.local_body_send_len == 0) ||
                (buf == c.local_body_cursor && len == c.local_body_send_len));
    }

    static constexpr bool supports_buffered_send_vector() { return true; }

    bool submit_send_impl(Connection& c, const u8* buf, u32 len) {
        if (c.tls_active) {
            // Proxy-stream tails use the cursor fields but retain their own
            // accounting. A single-shot send owns its continuation until the
            // final ciphertext target drains, including after encryption ends.
            if (c.tls_proxy_stream || buf == nullptr || len == 0 ||
                len > static_cast<u32>(INT32_MAX) || c.fd < 0 ||
                !c.tls_single_shot_send_owner_is_neutral() || c.tls_send_src != nullptr) {
                close_conn(c);
                return false;
            }
            const ResponseReadDeadlineSendKind strict_kind =
                response_read_deadline_tls_send_kind(c);
            const Connection::Callback strict_callback =
                response_read_deadline_tls_send_callback(strict_kind);
            if (!response_read_deadline_send_fields_are_neutral(c) ||
                (strict_kind != ResponseReadDeadlineSendKind::None && strict_callback == nullptr)) {
                close_conn(c);
                return false;
            }
            u32 generation = 0;
            if (!c.next_non_upstream_send_generation(generation)) return false;
            c.tls_send_owner_generation = generation;
            c.tls_send_owner_fd = c.fd;
            c.tls_send_owner_handler_generation = c.handler_gen;
            c.tls_pending_on_send = c.on_send;
            c.tls_send_src = buf;
            c.tls_send_len = len;
            c.tls_send_off = 0;
            if (strict_kind != ResponseReadDeadlineSendKind::None) {
                c.response_read_deadline_send_owner_generation = generation;
                c.response_read_deadline_send_deadline_generation =
                    c.response_read_deadline_post_commit_generation;
                c.response_read_deadline_send_upstream_episode =
                    c.response_read_deadline_post_commit_episode;
                c.response_read_deadline_send_src = buf;
                c.response_read_deadline_send_len = len;
                c.response_read_deadline_send_fd = c.fd;
                c.response_read_deadline_send_kind = strict_kind;
                c.response_read_deadline_send_owner_active = true;
                if (c.response_read_deadline_send_tombstone_generation >= generation ||
                    !response_read_deadline_tls_send_frame_is_valid(
                        c, strict_kind, strict_callback, buf, len)) {
                    close_conn(c);
                    return false;
                }
            }
            u32 consumed = 0;
            const TlsFill kFs = tls_fill_output<Self>(this, c, buf, len, consumed);
            c.tls_send_off = consumed;
            if (!tls_send_retry_has_driver<Self>(this, c, kFs)) {
                close_conn(c);
                return false;
            }
            // Initial submission cannot complete synchronously. Done and
            // NeedRoom need a live raw target; NeedRead has an armed recv.
            return true;
        }
        return submit_send_raw(c, buf, len);
    }

    bool submit_connect_impl(Connection& c, const void* addr, u32 addr_len) {
        if (detail::injected_iouring_submit_failure(detail::kTestIoUringConnectSubmit))
            return false;
        if (backend.add_connect(c.upstream_fd, c.id, addr, addr_len, c.upstream_episode)) {
            c.pending_ops++;
            c.upstream_connect_armed = true;
            return true;
        }
        return false;
    }

    bool submit_send_upstream_impl(Connection& c, const u8* buf, u32 len) {
        if (backend.add_send_upstream(c.upstream_fd, c.id, buf, len, c.upstream_episode)) {
            c.pending_ops++;
            c.upstream_send_armed = true;
            return true;
        }
        return false;
    }

    // close() cannot end a stream that an armed io_uring recv still references:
    // the FIN would wait until the close-path cancel drains, after the client
    // has usually closed first. For a plaintext connection whose response is
    // complete, half-close the write side now. TLS keeps its own shutdown path.
    void end_stream_before_close(Connection& c) {
        // A send still in flight keeps the ordinary close ordering: half-
        // closing now would fail that send and truncate the response.
        if (c.fd >= 0 && !c.tls_active && !c.send_armed) (void)::shutdown(c.fd, SHUT_WR);
    }

    // Plaintext body relay: the one-shot body owner of an ordinary native
    // Content-Length response may send one upstream slice while the next
    // upstream recv fills a second slice. Every other owner keeps the
    // serialized recv -> send -> recv body pump.
    [[nodiscard]] bool upstream_body_relay_eligible(const Connection& c) const {
        return !c.tls_active && c.response_policy_id == 0 && c.throttle_down_bps == 0 &&
               c.resp_body_mode == BodyMode::ContentLength && c.upstream_relay_send_len == 0 &&
               c.on_upstream_recv == &on_response_body_recvd<Self> && use_one_shot_upstream_recv(c);
    }

    bool alloc_upstream_relay_slice(Connection& c) {
        if (c.upstream_relay_slice) return true;
        u8* s = pool.alloc();
        if (!s) return false;
        c.upstream_relay_slice = s;
        return true;
    }

    // A relay switches to bulk buffers only while at least this much body is
    // still to come; shorter tails finish in ordinary slices.
    static constexpr u32 kBulkRelayMinRemaining = 128 * 1024;

#ifdef RUT_TESTING
public:
    // Focused fixture seam: exercises the real pipe admission and synchronous
    // splice state machine without exposing it to production callers.
    bool test_start_response_splice(Connection& c) { return start_response_splice(c); }
#endif

    // The splice candidate starts only after the serialized prefix has drained.
    // This keeps any provided/direct recv owner out of the pipe state machine.
    [[nodiscard]] bool response_splice_eligible(const Connection& c) const {
        return c.fd >= 0 && c.upstream_fd >= 0 && !c.tls_active &&
               c.protocol == ConnProtocol::Http11 && c.response_policy_id == 0 &&
               c.resp_body_mode == BodyMode::ContentLength &&
               c.response_read_deadline_buffering == ForwardResponseBufferingMode::None &&
               c.req_method == static_cast<u8>(LogHttpMethod::Get) &&
               c.req_body_mode == BodyMode::None && c.req_body_remaining == 0 &&
               !c.request_body_fully_buffered && !c.req_body_streamed &&
               c.request_upload_complete && c.throttle_down_bps == 0 && !c.is_ws_terminate_route &&
               c.resp_body_remaining >= 64 * 1024 && c.upstream_recv_buf.len() == 0 &&
               c.upstream_recv_armed == false && c.upstream_recv_direct_armed == false &&
               c.upstream_send_armed == false && c.send_armed == false &&
               c.upstream_relay_send_len == 0 && !c.relay_owner.active() &&
               c.relay_owner.segment_len == 0 && c.relay_owner.segment_sent == 0 &&
               !c.relay_owner.read_armed && !c.relay_owner.write_armed &&
               !c.relay_owner.read_cancel_owned && !c.relay_owner.write_cancel_owned &&
               !c.relay_owner.read_cancel_retry && !c.relay_owner.write_cancel_retry &&
               !c.relay_owner.close_pending && !c.relay_owner.admit_after_prefix &&
               c.response_read_deadline_owner_is_neutral() && !c.is_ws_tunnel && !c.is_ws_terminate;
    }

    // The initial header send already includes any body bytes received with
    // the header. Once it drains, admission can use the same neutral-owner
    // checks without reading and sending a second serialized prefix first.
    bool start_response_splice_after_header(Connection& c) { return start_response_splice(c); }

    bool arm_response_splice_after_prefix(Connection& c, u32 send_len) {
        if (send_len == 0 || c.upstream_recv_buf.len() != send_len || c.fd < 0 ||
            c.upstream_fd < 0 || c.tls_active || c.protocol != ConnProtocol::Http11 ||
            c.response_policy_id != 0 || c.resp_body_mode != BodyMode::ContentLength ||
            c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
            c.req_method != static_cast<u8>(LogHttpMethod::Get) ||
            c.req_body_mode != BodyMode::None || c.req_body_remaining != 0 ||
            c.request_body_fully_buffered || c.req_body_streamed || c.throttle_down_bps != 0 ||
            !c.request_upload_complete || c.is_ws_terminate_route ||
            c.resp_body_remaining < 64 * 1024 || c.upstream_recv_armed ||
            c.upstream_recv_direct_armed || c.upstream_send_armed || c.send_armed ||
            c.upstream_relay_send_len != 0 || c.relay_owner.active() ||
            !c.response_read_deadline_owner_is_neutral())
            return false;
        c.relay_owner.admit_after_prefix = true;
        return true;
    }

    void close_response_splice_pipe(Connection& c) {
        if (c.relay_owner.pipe_read >= 0) ::close(c.relay_owner.pipe_read);
        if (c.relay_owner.pipe_write >= 0) ::close(c.relay_owner.pipe_write);
        c.relay_owner.pipe_read = c.relay_owner.pipe_write = -1;
        c.relay_owner.phase = RelayPhase::Idle;
        c.relay_owner.read_armed = c.relay_owner.write_armed = false;
        c.relay_owner.close_pending = false;
        c.relay_owner.segment_len = c.relay_owner.segment_sent = 0;
        c.relay_owner.body_bytes = 0;
        c.relay_owner.source_fd = c.relay_owner.destination_fd = -1;
        c.relay_owner.upstream_episode = 0;
        c.relay_owner.read_cancel_retry = c.relay_owner.write_cancel_retry = false;
        c.relay_owner.read_cancel_owned = c.relay_owner.write_cancel_owned = false;
        c.relay_owner.admit_after_prefix = false;
    }

    void finish_response_splice(Connection& c) {
        // The pipe is connection-owned and remains available for the next
        // eligible response.  At this point it is empty and both readiness
        // owners have retired.
        c.relay_owner.phase = RelayPhase::Idle;
        c.relay_owner.read_armed = c.relay_owner.write_armed = false;
        c.relay_owner.close_pending = false;
        c.relay_owner.segment_len = c.relay_owner.segment_sent = 0;
        c.relay_owner.body_bytes = 0;
        c.relay_owner.source_fd = c.relay_owner.destination_fd = -1;
        c.relay_owner.upstream_episode = 0;
        c.relay_owner.read_cancel_retry = c.relay_owner.write_cancel_retry = false;
        c.relay_owner.read_cancel_owned = c.relay_owner.write_cancel_owned = false;
        c.relay_owner.admit_after_prefix = false;
        c.relay_owner.initial_declined = false;
    }

    // Ready relay reads remain runnable on the shard. Queue them behind their
    // peers instead of manufacturing another readiness CQE after each segment.
    // Slot/episode authentication protects close and reuse; queue overflow uses
    // the existing kernel poll path. EAGAIN still registers a real read poll.
    void handle_response_splice_poll_failure(Connection& c) {
        if (c.relay_owner.body_bytes == 0) {
            close_response_splice_pipe(c);
            c.relay_owner.initial_declined = true;
        } else {
            close_conn(c);
        }
    }

    void defer_response_splice_read(Connection& c) {
        RelayOwner& r = c.relay_owner;
        r.phase = RelayPhase::Reading;
        for (u32 i = 0; i < deferred_relay_read_count; i++) {
            if (deferred_relay_read_ids[i] == c.id &&
                deferred_relay_read_episodes[i] == r.upstream_episode)
                return;
        }
        if (deferred_relay_read_count < kDeferredRelayReadLimit) {
            study_queue_started[c.id] = monotonic_ns();
            deferred_relay_read_ids[deferred_relay_read_count] = c.id;
            deferred_relay_read_episodes[deferred_relay_read_count] = r.upstream_episode;
            deferred_relay_read_count++;
            return;
        }
        // Queue saturation is only a fairness guard.  Preserve progress by
        // using the existing poll admission for the overflow owner.
        if (!arm_response_splice_read(c)) handle_response_splice_poll_failure(c);
    }

    bool has_ordinary_cq_work() {
        ++study_cq_probes;
        if (!backend.cq_head || !backend.cq_tail) return false;
        const u32 head = __atomic_load_n(backend.cq_head, __ATOMIC_ACQUIRE);
        const u32 tail = __atomic_load_n(backend.cq_tail, __ATOMIC_ACQUIRE);
        if (head == tail) return false;
        if (!backend.cq_entries || !backend.cq_ring_mask || tail - head > backend.cq_ring_entries)
            return true;
        // Peek only; wait() retains sole ownership of CQ consumption and all
        // cancellation/proactor accounting. Bound the scheduler hint's cost.
        const u32 count = std::min<u32>(tail - head, 32);
        for (u32 i = 0; i < count; ++i) {
            const auto& cqe = backend.cq_entries[(head + i) & *backend.cq_ring_mask];
            ++study_cq_entries;
            const u32 tag = static_cast<u32>(cqe.user_data & 0xFFu);
            const u32 type = std::min<u32>(tag, static_cast<u32>(IoEventType::Count));
            UpstreamEventToken token{};
            if (!decode_upstream_event_token(cqe.user_data, &token) ||
                (token.type != IoEventType::RelayRead && token.type != IoEventType::RelayWrite) ||
                token.aux != 0 || cqe.res < 0 || token.conn_id >= slots_initialized) {
                ++study_yield_types[type];
                return true;
            }
            const Connection& c = conns[token.conn_id];
            const RelayOwner& r = c.relay_owner;
            if (!r.active() || r.close_pending || token.episode != c.upstream_episode ||
                token.episode != r.upstream_episode ||
                (token.type == IoEventType::RelayRead ? !r.read_armed : !r.write_armed))
                return true;
        }
        // Uninspected work is conservatively serviced before the extra quantum.
        return tail - head > count;
    }

    void flush_deferred_relay_reads() {
        ++study_relay_turns;
        const u64 phase_started = monotonic_ns();
        const u32 start_calls = relay_budget_calls;
        const u32 kCount = deferred_relay_read_count;
        // CQEs have no completion timestamp. Measure only how long ordinary
        // work has been observed pending during this relay flush, not its
        // true kernel age. Reset the observation whenever the CQ is quiet.
        u64 ordinary_since_ns = has_ordinary_cq_work() ? monotonic_ns() : 0;
        for (u32 i = 0; i < kCount && deferred_relay_read_count != 0; i++) {
            // Reserve a read and write. Unprocessed entries retain FIFO order
            // into the next turn; a completed segment rejoins at the tail.
            if (relay_budget_calls < 2 || relay_budget_bytes < 2 * 64 * 1024) break;
            // Keep the first half of the turn for bounded relay progress, but
            // do not spend the larger quantum behind newly posted completions.
            // An idle CQ can still use all eight FIFO segments.
            if (relay_budget_calls <= study_relay_turn_call_limit / 2 && study_yield_enabled) {
                if (has_ordinary_cq_work()) {
                    const u64 now = monotonic_ns();
                    if (ordinary_since_ns == 0) ordinary_since_ns = now;
                    if (now - ordinary_since_ns >= ordinary_cq_wait_limit_ns) {
                        ++study_relay_yields;
                        break;
                    }
                } else {
                    ordinary_since_ns = 0;
                }
            }
            const u32 kId = deferred_relay_read_ids[0];
            const u32 kEpisode = deferred_relay_read_episodes[0];
            --deferred_relay_read_count;
            for (u32 j = 0; j < deferred_relay_read_count; ++j) {
                deferred_relay_read_ids[j] = deferred_relay_read_ids[j + 1];
                deferred_relay_read_episodes[j] = deferred_relay_read_episodes[j + 1];
            }
            if (kId >= slots_initialized) continue;
            Connection& c = conns[kId];
            RelayOwner& r = c.relay_owner;
            if (!r.active()) continue;
            // A reused slot, or a slot whose kEpisode was replaced, is an old
            // queue entry and is discarded without touching the new owner.
            if (r.upstream_episode != kEpisode || c.upstream_episode != kEpisode) continue;
            if (r.close_pending) {
                if (!r.read_armed && !r.write_armed && !r.read_cancel_owned &&
                    !r.write_cancel_owned && !r.read_cancel_retry && !r.write_cancel_retry &&
                    r.segment_len == 0)
                    close_response_splice_pipe(c);
                continue;
            }
            // Same-kEpisode state corruption must not be allowed to become a
            // second poll or a write/read owner.  The queue entry itself is
            // already consumed, so fail closed through the normal ledger.
            if (c.fd < 0 || c.upstream_fd < 0 || r.phase != RelayPhase::Reading ||
                r.source_fd != c.upstream_fd || r.destination_fd != c.fd || r.segment_len != 0 ||
                r.segment_sent != 0 || r.read_armed || r.write_armed || r.read_cancel_owned ||
                r.write_cancel_owned || r.read_cancel_retry || r.write_cancel_retry ||
                c.resp_body_remaining == 0) {
                close_conn(c);
                continue;
            }
            if (study_queue_started[c.id] != 0) {
                study_record_wait(2, monotonic_ns() - study_queue_started[c.id]);
                study_queue_started[c.id] = 0;
            }
            const IoEvent kReady{c.id, POLLIN, 0, 0, IoEventType::RelayRead, 0, 0, kEpisode};
            on_response_splice_event(c, kReady);
            if (c.relay_owner.initial_declined && c.fd >= 0 && c.upstream_fd >= 0) {
                // An initial SQE failure no longer has the synchronous caller
                // that normally resumes the copy pump. No body bytes entered
                // the pipe, so restore the existing ordinary receive path.
                c.relay_owner.initial_declined = false;
                upgrade_upstream_recv_to_bulk(c);
                c.set_slots(nullptr, nullptr, &on_response_body_recvd<IoUringEventLoop>, nullptr);
                if (!submit_recv_upstream(c)) close_conn(c);
            }
        }
        study_relay_calls += start_calls - relay_budget_calls;
        study_flush_phase_ns += monotonic_ns() - phase_started;
    }

    void clear_deferred_relay_read(u32 id) {
        for (u32 i = 0; i < deferred_relay_read_count;) {
            if (deferred_relay_read_ids[i] != id) {
                ++i;
                continue;
            }
            --deferred_relay_read_count;
            for (u32 j = i; j < deferred_relay_read_count; ++j) {
                deferred_relay_read_ids[j] = deferred_relay_read_ids[j + 1];
                deferred_relay_read_episodes[j] = deferred_relay_read_episodes[j + 1];
            }
        }
    }

    bool arm_response_splice_read(Connection& c) {
        if (!c.relay_owner.active() || c.relay_owner.read_armed || c.upstream_fd < 0 ||
            c.relay_owner.pipe_write < 0 || c.resp_body_remaining == 0)
            return false;
#ifdef RUT_TESTING
        if (test_fail_next_relay_poll) {
            test_fail_next_relay_poll = false;
            return false;
        }
#endif
        if (!backend.add_relay_poll(
                c.upstream_fd, c.id, IoEventType::RelayRead, c.relay_owner.upstream_episode))
            return false;
        study_poll_started[0][c.id] = monotonic_ns();
        c.pending_ops++;
        c.relay_owner.read_armed = true;
        c.relay_owner.phase = RelayPhase::Reading;
        return true;
    }

    void refresh_relay_progress_timer(Connection& c) {
        if (!c.throttle_paused &&
            c.response_read_deadline_state != ResponseReadDeadlineState::Armed &&
            c.response_read_deadline_state != ResponseReadDeadlineState::ExpiryPending &&
            c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending &&
            c.response_read_deadline_state != ResponseReadDeadlineState::RefreshPending)
            timer.refresh(&c,
                          c.state == ConnState::Proxying ? upstream_timeout : keepalive_timeout);
    }

    bool start_response_splice(Connection& c) {
        if (!response_splice_eligible(c)) return false;
        if (c.relay_owner.pipe_read < 0 || c.relay_owner.pipe_write < 0) {
            int fds[2] = {-1, -1};
            if (::pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return false;
            // F_SETPIPE_SZ returns the actual capacity. The pipe is still
            // private here, so a second F_GETPIPE_SZ only adds a syscall to
            // every new relay connection.
            int capacity = ::fcntl(fds[1], F_SETPIPE_SZ, study_relay_chunk_size);
            if (capacity < 64 * 1024 && study_relay_chunk_size > 64 * 1024)
                capacity = ::fcntl(fds[1], F_SETPIPE_SZ, 64 * 1024);
            if (capacity < 64 * 1024) {
                ::close(fds[0]);
                ::close(fds[1]);
                return false;
            }
            if (capacity >= 128 * 1024)
                ++study_large_pipes;
            else
                ++study_small_pipes;
            c.relay_owner.pipe_read = fds[0];
            c.relay_owner.pipe_write = fds[1];
        }
        study_poll_started[0][c.id] = study_poll_started[1][c.id] = 0;
        study_queue_started[c.id] = 0;
        c.relay_owner.phase = RelayPhase::Reading;
        c.relay_owner.upstream_episode = c.upstream_episode;
        c.relay_owner.source_fd = c.upstream_fd;
        c.relay_owner.destination_fd = c.fd;
        c.relay_owner.admit_after_prefix = false;
        // First progress is synchronous.  Only EAGAIN arms a readiness poll.
        c.relay_owner.read_armed = true;
        const IoEvent ready{c.id, POLLIN, 0, 0, IoEventType::RelayRead, 0, 0, c.upstream_episode};
        on_response_splice_event(c, ready);
        if (c.relay_owner.initial_declined) {
            c.relay_owner.initial_declined = false;
            return false;
        }
        ++relay_admissions;
        // Once the pipe has been admitted, the response is owned by the relay
        // state machine even if the first synchronous attempt completes it or
        // closes the connection.  Returning false here would make the caller
        // fall through into the ordinary body pump and double-complete it.
        return true;
    }

    bool arm_response_splice_write(Connection& c) {
        if (!c.relay_owner.active() || c.relay_owner.segment_len == 0 ||
            c.relay_owner.write_armed || c.relay_owner.pipe_read < 0 || c.fd < 0)
            return false;
#ifdef RUT_TESTING
        if (test_fail_next_relay_poll) {
            test_fail_next_relay_poll = false;
            return false;
        }
#endif
        if (!backend.add_relay_poll(
                c.fd, c.id, IoEventType::RelayWrite, c.relay_owner.upstream_episode))
            return false;
        study_poll_started[1][c.id] = monotonic_ns();
        c.pending_ops++;
        c.relay_owner.write_armed = true;
        c.relay_owner.phase = RelayPhase::Writing;
        return true;
    }

    void on_response_splice_event(Connection& c, const IoEvent& ev) {
        RelayOwner& r = c.relay_owner;
        if (!r.active() || ev.upstream_episode != r.upstream_episode ||
            ev.type == IoEventType::Count || c.upstream_fd != r.source_fd ||
            c.fd != r.destination_fd) {
            return;
        }
        if (ev.result < 0) {
            close_conn(c);
            return;
        }
        if (ev.type == IoEventType::RelayRead) {
            r.read_armed = false;
            if (relay_budget_calls < 2 || relay_budget_bytes < 2) {
                defer_response_splice_read(c);
                return;
            }
            --relay_budget_calls;
            const u32 want =
                std::min<u32>(std::min<u32>(c.resp_body_remaining, study_relay_chunk_size),
                              relay_budget_bytes / 2);
            if (study_inside_cq) ++study_cq_splice_calls;
            const bool sampled = (++study_splice_calls[0] & 63u) == 0;
            const u64 syscall_start = sampled ? monotonic_ns() : 0;
            const ssize_t n = ::splice(c.upstream_fd,
                                       nullptr,
                                       r.pipe_write,
                                       nullptr,
                                       want,
                                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            const int splice_errno = errno;
            if (sampled) study_record_syscall(0, monotonic_ns() - syscall_start);
            errno = splice_errno;
            if (n > 0 && static_cast<u32>(n) < want) ++study_splice_short[0];
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                close_conn(c);
                return;
            }
            if (n < 0) {
                ++study_splice_eagain[0];
                if (!arm_response_splice_read(c)) {
                    // Before the first byte is pulled, a readiness-SQE
                    // admission failure is a clean decline to the ordinary
                    // copy path.  Once bytes entered the pipe, losing the
                    // poll owner would strand data and must fail closed.
                    handle_response_splice_poll_failure(c);
                }
                return;
            }
            r.segment_len = static_cast<u32>(n);
            relay_budget_bytes -= static_cast<u32>(n);
            relay_pulled_bytes += static_cast<u32>(n);
            r.segment_sent = 0;
            r.body_bytes += r.segment_len;
            c.resp_body_remaining -= r.segment_len;
            refresh_relay_progress_timer(c);
            r.write_armed = true;
            const IoEvent ready{
                c.id, POLLOUT, 0, 0, IoEventType::RelayWrite, 0, 0, c.upstream_episode};
            on_response_splice_event(c, ready);
            return;
        }
        r.write_armed = false;
        if (relay_budget_calls == 0 || relay_budget_bytes == 0) {
            ++study_write_budget_polls;
            if (!arm_response_splice_write(c)) close_conn(c);
            return;
        }
        --relay_budget_calls;
        const u32 write_want = std::min<u32>(r.segment_len - r.segment_sent, relay_budget_bytes);
        if (study_inside_cq) ++study_cq_splice_calls;
        const bool sampled = (++study_splice_calls[1] & 63u) == 0;
        const u64 syscall_start = sampled ? monotonic_ns() : 0;
        const ssize_t n = ::splice(
            r.pipe_read, nullptr, c.fd, nullptr, write_want, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        const int splice_errno = errno;
        if (sampled) study_record_syscall(1, monotonic_ns() - syscall_start);
        errno = splice_errno;
        if (n > 0 && static_cast<u32>(n) < write_want) ++study_splice_short[1];
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ++study_splice_eagain[1];
            if (!arm_response_splice_write(c)) close_conn(c);
            return;
        }
        if (n <= 0 || static_cast<u32>(n) > r.segment_len - r.segment_sent) {
            close_conn(c);
            return;
        }
        r.segment_sent += static_cast<u32>(n);
        relay_budget_bytes -= static_cast<u32>(n);
        relay_written_bytes += static_cast<u32>(n);
        if (study_inside_cq) study_cq_splice_bytes += static_cast<u32>(n);
        c.resp_body_sent += static_cast<u32>(n);
        refresh_relay_progress_timer(c);
        if (r.segment_sent != r.segment_len) {
            // A partial synchronous splice is still runnable.  Spend the
            // remaining turn budget before yielding to POLLOUT; otherwise a
            // large response pays a readiness CQE for every short write.
            r.write_armed = true;
            const IoEvent ready{
                c.id, POLLOUT, 0, 0, IoEventType::RelayWrite, 0, 0, c.upstream_episode};
            on_response_splice_event(c, ready);
            return;
        }
        r.segment_len = r.segment_sent = 0;
        if (c.resp_body_remaining == 0) {
            finish_response_splice(c);
            proxy_stream_complete<IoUringEventLoop>(this, c);
            return;
        }
        if (active_count() > 1) {
            defer_response_splice_read(c);
            return;
        }
        r.read_armed = true;
        const IoEvent ready{c.id, POLLIN, 0, 0, IoEventType::RelayRead, 0, 0, c.upstream_episode};
        on_response_splice_event(c, ready);
    }

    // The buffer the next relay recv fills: the idle relay buffer, traded for
    // a bulk relay buffer while enough body remains and one is available. The
    // idle buffer is neither being sent (upstream_relay_send_len == 0 is part
    // of relay eligibility) nor a recv target, so it can be released here
    // regardless of whether a direct recv is currently armed into the
    // *other* buffer (c.upstream_recv_slice) — they're never the same one.
    u8* take_relay_recv_buffer(Connection& c) {
        u8* idle = c.upstream_relay_slice;
        if (idle == nullptr || pool.is_bulk(idle) || c.resp_body_remaining < kBulkRelayMinRemaining)
            return idle;
        u8* bulk = pool.alloc_bulk();
        if (bulk == nullptr) return idle;
        pool.free(idle);
        return bulk;
    }

    [[nodiscard]] u32 relay_buffer_capacity(const u8* buffer) const {
        return pool.capacity_of(buffer);
    }

    // Serialized body pump (response policies, non-relay owners): trade the
    // upstream recv slice for a bulk relay buffer while a large Content-Length
    // body remains, so the recv accumulates up to 256 KiB between client sends.
    // Called between sends: nothing reads the slice, so rebinding is normally
    // safe. The one exception is a *direct* recv (Part A): its destination is
    // the exact memory address captured at arm time, so the kernel could
    // still be writing into `cur` even though no callback reads it — pinning
    // (upstream_recv_direct_armed) must hold until that recv's terminal CQE
    // is consumed, so skip the upgrade this cycle rather than rebind live
    // kernel memory; the next opportunity (or release_upstream_relay_slice)
    // retries it once the recv is no longer armed direct.
    void upgrade_upstream_recv_to_bulk(Connection& c) {
        u8* cur = c.upstream_recv_slice;
        if (cur == nullptr || pool.is_bulk(cur) || c.resp_body_mode != BodyMode::ContentLength ||
            c.resp_body_remaining < kBulkRelayMinRemaining || c.upstream_recv_direct_armed)
            return;
        u8* bulk = pool.alloc_bulk();
        if (bulk == nullptr) return;
        const u32 kBuffered = c.upstream_recv_buf.len();
        if (kBuffered != 0) __builtin_memcpy(bulk, c.upstream_recv_buf.data(), kBuffered);
        c.upstream_recv_slice = bulk;
        c.upstream_recv_buf.bind(bulk, SlicePool::kBulkSliceSize);
        c.upstream_recv_buf.commit(kBuffered);
        pool.free(cur);
    }

    // Response boundary: return the relay slice unless a send still reads it,
    // and trade a bulk recv buffer back for an ordinary slice so an idle
    // keep-alive connection never pins one.
    void release_upstream_relay_slice(Connection& c) {
        if (c.upstream_relay_slice != nullptr && c.upstream_relay_send_len == 0) {
            pool.free(c.upstream_relay_slice);
            c.upstream_relay_slice = nullptr;
        }
        // A still-armed provided-buffer recv copies into whatever buffer is
        // bound when its CQE is processed, so the swap is normally safe with
        // one in flight. A *direct* recv (Part A) is different: it already
        // targets this exact memory in the kernel, so the buffer must stay
        // pinned until that recv's terminal CQE is consumed — skip the swap
        // this boundary rather than free/rebind live kernel memory; an idle
        // keep-alive connection that stays pinned this way is a correctness
        // requirement, not just an optimization (see add_recv_upstream_direct).
        u8* bulk = c.upstream_recv_slice;
        if (!pool.is_bulk(bulk) || c.upstream_recv_buf.len() != 0 || c.upstream_recv_direct_armed)
            return;
        u8* s = pool.alloc();
        if (s == nullptr) return;  // keep it; close or the next boundary returns it
        pool.free(bulk);
        c.upstream_recv_slice = s;
        c.upstream_recv_buf.bind(s, SlicePool::kSliceSize);
    }

    // A provided-buffer multishot recv can complete several 4 KiB CQEs in one
    // backend wait before the response callback gets a chance to drain them.
    // Keep mode selection structural and episode-stable: retain the existing
    // downstream-TLS owner and the ordinary, already-uploaded, bodyless HTTP/1
    // plaintext owner without a response policy. Pipeline progress is consumed
    // by pipeline_advance/recover; it does not change the recv primitive.
    [[nodiscard]] bool use_one_shot_upstream_recv(const Connection& c) const {
        const RouteConfig* cfg = c.request_config;
        const bool ordinary_response_owner = c.on_upstream_recv == &on_upstream_response<Self> ||
                                             c.on_upstream_recv == &on_response_body_recvd<Self>;
        const bool normal_state = c.state == ConnState::Proxying || c.state == ConnState::Sending;
        const bool tls_transport = c.tls_active && c.tls_handshake_complete && c.uses_iouring_tls();
        const bool plaintext_native_transport = !c.tls_active && c.response_policy_id == 0;
        return c.fd >= 0 && c.upstream_fd >= 0 && (tls_transport || plaintext_native_transport) &&
               c.protocol == ConnProtocol::Http11 && c.h2 == nullptr && normal_state &&
               cfg != nullptr && c.upstream_idx < cfg->upstream_count && c.req_start_us != 0 &&
               !c.epoch_held && ordinary_response_owner && c.on_upstream_send == nullptr &&
               !c.upstream_connect_armed && !c.upstream_send_armed &&
               valid_upstream_episode(c.upstream_episode) && !c.upstream_episode_quarantined &&
               c.upstream_attempts != 0 &&
               (c.response_policy_id == 0 || c.upstream_attempts == 1) &&
               c.request_upload_complete && !c.upstream_request_incomplete &&
               c.req_body_mode == BodyMode::None && c.req_body_remaining == 0 &&
               !c.req_client_has_content_length && !c.req_client_has_transfer_encoding &&
               !c.req_client_has_te && !c.req_client_has_expect &&
               !c.req_client_has_upgrade_header && !c.req_wants_upgrade && !c.req_malformed &&
               !c.request_policy_body_pending && !c.request_body_fully_buffered &&
               !c.req_body_streamed && !c.is_health_probe && !c.h2_proxy_recv_draining &&
               !c.h2_proxy_synth_quarantined && !c.is_ws_tunnel && !c.is_ws_terminate_route &&
               !c.is_ws_terminate && !c.ws_closing && c.response_read_deadline_owner_is_neutral() &&
               !c.upstream_abandoned && !c.upstream_recv_armed &&
               !c.upstream_recv_paused_for_send && !c.upstream_recv_pause_cancel_pending &&
               !c.upstream_recv_pause_rearm_pending && !c.upstream_recv_cancel_inflight &&
               !c.upstream_recv_terminal_stale && !strict_upstream_retirement_blocks_reclaim(c) &&
               c.idle_return_fd < 0 && c.idle_return_config == nullptr &&
               !c.close_after_idle_return && !c.upstream_recv_idle_stale_bytes &&
               !c.http1_boundary_deferred &&
               c.http1_prebuilt_disposition == Http1RequestBufferDisposition::None;
    }

    bool submit_recv_upstream_impl(Connection& c) {
        if (ws_splice.intercept_recv(*this, c)) return true;
        if (c.upstream_recv_paused_for_send) {
            c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        if (c.upstream_recv_armed) {
            // armed can be a DOOMED recv: after a pause cancel, the in-flight recv is
            // being cancelled (its -ECANCELED is pending) even though armed is still set.
            // If either the cancel or that recv terminal is still in flight, this isn't a
            // live recv we can rely on — remember the re-arm so it fires once both drain.
            if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight)
                c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        // Defer-until-drains: a prior pause's cancel SQE and/or the cancelled recv are
        // still in flight even though upstream_recv_armed is clear (proxy_stream_complete
        // clears it at the keep-alive boundary while both are still pending). Arming a new
        // multishot recv now would give it the same (conn_id, UpstreamRecv) user_data the
        // stale cancel matches, OR let the stale recv terminal clobber the fresh recv's
        // armed flag. Wait: the cancel CQE clears cancel_pending and the recv terminal
        // clears cancel_inflight; try_deferred_upstream_rearm re-arms once both are clear.
        // (epoll's pause is synchronous and never sets these, so this is io_uring-only.)
        if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight) {
            c.upstream_recv_pause_rearm_pending = true;
            return true;
        }
        const bool kPollFirst = study_ws_poll_first && use_one_shot_websocket_recv(c) &&
                                !c.is_ws_terminate && !c.is_ws_terminate_route;
        const bool kOneShot = use_one_shot_websocket_recv(c) || use_one_shot_upstream_recv(c);
        bool submitted = false;
        bool direct = false;
        if (kOneShot) {
            const u32 available = c.upstream_recv_buf.write_avail();
            if (available == 0) return false;
            const bool kDirectWs = study_ws_direct_recv_limit != 0 &&
                                   use_one_shot_websocket_recv(c) && !c.is_ws_terminate &&
                                   !c.is_ws_terminate_route && c.response_policy_id == 0 &&
                                   c.throttle_down_bps == 0 && !ws_splice.enabled;
            if (kDirectWs || pool.is_bulk(c.upstream_recv_slice)) {
                // The destination is a bulk relay buffer: recv straight into
                // it (Part A/B) instead of through a provided-buffer ring, so
                // a 256 KiB chunk costs one CQE and no ring-to-buffer copy.
                direct = true;
                submitted = backend.add_recv_upstream_direct(
                    c.upstream_fd,
                    c.id,
                    c.upstream_episode,
                    c.upstream_recv_buf.write_ptr(),
                    kDirectWs && available > study_ws_direct_recv_limit ? study_ws_direct_recv_limit
                                                                        : available,
                    kPollFirst);
                if (submitted && kDirectWs) ++study_ws_direct_recv_arms;
            } else {
                const u32 max_len = backend.upstream_once_max_len();
                const u32 recv_len = available < max_len ? available : max_len;
                submitted = backend.add_recv_upstream_once(
                    c.upstream_fd, c.id, c.upstream_episode, recv_len, kPollFirst);
            }
        } else {
            submitted = backend.add_recv_upstream(c.upstream_fd, c.id, c.upstream_episode);
        }
        if (submitted) {
            if (kPollFirst) ++study_ws_poll_first_arms;
            c.upstream_recv_direct_armed = direct;
            c.pending_ops++;
            c.upstream_recv_armed = true;
            c.upstream_recv_pause_rearm_pending = false;
            return true;
        }
        return false;
    }

    bool response_read_deadline_profile_is_stable(const Connection& c,
                                                  const RouteConfig& cfg,
                                                  u16 bundle_id) const {
        if (c.request_config != &cfg || c.response_read_deadline_bundle_id != bundle_id)
            return false;
        if (c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
            c.response_read_deadline_upload.downstream_close)
            return header_only_head_explicit_close_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                &cfg,
                bundle_id,
                ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                &on_upstream_response<Self>);
        if (header_only_head_keep_alive_precise_candidate(c))
            return header_only_head_keep_alive_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                &cfg,
                bundle_id,
                ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                &on_upstream_response<Self>);
        return response_read_deadline_owner_is_stable(
            c, &on_upstream_response<Self>, ResponseReadDeadlineOwnerPhase::ActiveAfterCopy);
    }

    [[nodiscard]] bool arm_first_response_read_deadline(Connection& c) {
        const RouteConfig* cfg = c.request_config;
        const u16 bundle_id = c.response_read_deadline_bundle_id;
        if (c.response_read_deadline_state != ResponseReadDeadlineState::Validated ||
            c.response_read_deadline_owner_generation == 0 ||
            c.response_read_deadline_owner_generation != c.response_read_deadline_generation ||
            c.response_read_deadline_profile == ResponseReadDeadlineProfile::None ||
            c.response_read_deadline_progress_generation != 0 ||
            c.response_read_deadline_progress_episode != 0 ||
            c.response_read_deadline_progress_bytes != 0 || cfg == nullptr ||
            !cfg->policy_bundle_id_is_valid(bundle_id))
            return false;
        const auto& bundle = cfg->policy_bundles[bundle_id - 1];
        if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
            bundle.response_read_timeout_seconds != c.response_read_deadline_seconds ||
            bundle.response_policy_id != c.response_policy_id ||
            bundle.failure_policy_id != c.failure_policy_id ||
            bundle.timeout_failure_policy_id != c.timeout_failure_policy_id)
            return false;
        const bool header_only_head_explicit_close_shape =
            c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
            c.response_read_deadline_upload.downstream_close;
        const bool header_only_head_keep_alive_shape =
            header_only_head_keep_alive_precise_candidate(c);
        const bool owner_stable =
            !header_only_head_explicit_close_shape && !header_only_head_keep_alive_shape &&
            response_read_deadline_owner_is_stable(
                c, &on_upstream_response<Self>, ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm);
        const bool header_only_head_explicit_close =
            header_only_head_explicit_close_shape &&
            header_only_head_explicit_close_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                cfg,
                bundle_id,
                ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm,
                &on_upstream_response<Self>);
        const bool header_only_head_keep_alive =
            header_only_head_keep_alive_shape &&
            header_only_head_keep_alive_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                cfg,
                bundle_id,
                ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm,
                &on_upstream_response<Self>);
        if (!owner_stable && !header_only_head_explicit_close && !header_only_head_keep_alive)
            return false;
        if (c.upstream_idx >= cfg->upstream_count ||
            cfg->upstreams[c.upstream_idx].addr_count != 1 ||
            cfg->upstreams[c.upstream_idx].addrs[0].sin_family != AF_INET)
            return false;
        const u32 ordinary_pending = c.recv_armed ? 1u : 0u;
        const bool tls_arm_owner =
            !c.tls_active || (response_read_deadline_tls_output_is_settled(c) &&
                              c.on_recv == &tls_recv<Self> && c.tls_pending_on_recv == nullptr);
        if (c.state != ConnState::Proxying || c.protocol != ConnProtocol::Http11 ||
            !tls_arm_owner || c.upstream_fd < 0 ||
            !response_read_deadline_upstream_reuse_is_stable(c) || c.upstream_attempts != 1 ||
            !valid_upstream_episode(c.upstream_episode) || c.upstream_episode_quarantined ||
            !c.request_upload_complete || c.upstream_request_incomplete ||
            c.buffered_response_len() != 0 || c.on_upstream_recv != &on_upstream_response<Self> ||
            c.on_upstream_send != nullptr || c.upstream_connect_armed || c.upstream_send_armed ||
            c.upstream_recv_armed || c.upstream_recv_paused_for_send ||
            c.upstream_recv_pause_cancel_pending || c.upstream_recv_pause_rearm_pending ||
            c.upstream_recv_cancel_inflight || c.upstream_retirement_active ||
            c.upstream_retirement_target_owned != 0 || c.upstream_retirement_cancel_owned != 0 ||
            c.upstream_retirement_cancel_retry != 0 || c.upstream_close_episode != 0 ||
            c.upstream_close_target_owned != 0 || c.upstream_close_cancel_owned != 0 ||
            c.upstream_close_pause_cancel_owned || c.idle_return_fd >= 0 ||
            c.idle_return_config != nullptr || c.close_after_idle_return ||
            c.h2_proxy_recv_draining || c.h2_proxy_synth_quarantined ||
            c.pending_ops != ordinary_pending)
            return false;
        if (!add_response_read_recv(c)) {
            c.clear_response_read_deadline();
            return false;
        }
        c.pending_ops++;
        c.upstream_recv_armed = true;
        c.response_read_deadline_upstream_episode = c.upstream_episode;
        c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
        if (response_read_deadline_uses_precise_timer(c)) {
            timer.remove(&c);
            const bool precise_timer_ok = backend.add_response_read_timer(
                c.id,
                c,
                static_cast<u32>(c.response_read_deadline_seconds) * 1000u,
                c.response_read_deadline_generation,
                c.upstream_episode);
            if (!precise_timer_ok) {
                c.clear_response_read_deadline();
                return false;
            }
            c.response_read_timer_last_progress_ns = monotonic_ns();
        } else {
            timer.refresh(&c, c.response_read_deadline_seconds);
        }
        return true;
    }

    [[nodiscard]] bool response_read_deadline_uses_precise_timer(
        const Connection& c, bool allow_consumed_terminal_episode = false) const {
        if (c.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
            c.protocol != ConnProtocol::Http11 ||
            (c.tls_active && !response_read_deadline_tls_http11_engine_is_stable(c)) ||
            (c.tls_active && (c.on_recv != &tls_recv<Self> || c.tls_pending_on_recv != nullptr)) ||
            c.h2 != nullptr || !response_read_deadline_upstream_reuse_is_stable(c) ||
            c.upstream_attempts != 1 || c.upstream_fd < 0 || c.response_mutations_snapshotted ||
            !valid_upstream_episode(c.upstream_episode) ||
            c.response_read_deadline_upstream_episode != c.upstream_episode)
            return false;
        const RouteConfig* cfg = c.request_config;
        if (cfg == nullptr) return false;
        if (c.response_read_deadline_profile ==
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead &&
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::None &&
            c.req_method == static_cast<u8>(LogHttpMethod::Head)) {
            if (fixed_upload_head_after_host_precise_arm_is_stable(
                    c,
                    c.response_read_deadline_upload,
                    cfg,
                    c.response_read_deadline_bundle_id,
                    ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                    &on_upstream_response<Self>,
                    allow_consumed_terminal_episode))
                return true;
            return fixed_upload_head_after_host_precise_progress_is_stable(
                c,
                c.response_read_deadline_upload,
                cfg,
                c.response_read_deadline_bundle_id,
                ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                &on_upstream_response<Self>,
                c.buffered_response_len(),
                allow_consumed_terminal_episode);
        }
        if (streaming_response_read_timer_is_stable(c)) return true;
        if (c.response_read_deadline_profile ==
                ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
            forward_response_buffering_uses_content_length_machinery(
                c.response_read_deadline_buffering) &&
            c.req_method == static_cast<u8>(LogHttpMethod::Get)) {
            if (c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None)
                return bodyless_get_complete_content_length_precise_buffering_is_stable(c);
            return bodyless_get_keep_alive_precise_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                cfg,
                c.response_read_deadline_bundle_id,
                ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                &on_upstream_response<Self>);
        }
        if (c.response_read_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
            c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
            c.req_method != static_cast<u8>(LogHttpMethod::Head) ||
            c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
            c.pipeline_depth != 0 || c.http1_pipeline_request_generation != 0)
            return false;
        if (c.response_read_deadline_upload.downstream_close)
            return header_only_head_explicit_close_arm_is_stable(
                c,
                c.response_read_deadline_upload,
                cfg,
                c.response_read_deadline_bundle_id,
                ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                &on_upstream_response<Self>);
        return header_only_head_keep_alive_arm_is_stable(
            c,
            c.response_read_deadline_upload,
            cfg,
            c.response_read_deadline_bundle_id,
            ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
            &on_upstream_response<Self>);
    }

    // Backend.wait has already appended a positive CQE before dispatch.  For
    // retained fixed-upload HEAD progress, prove that this exact record extends
    // the committed prefix before the batch ledger arbitrates it with a timer.
    [[nodiscard]] bool current_positive_response_read_uses_precise_timer(
        const Connection& c, const IoEvent& ev, bool allow_consumed_terminal_episode) const {
        const bool streaming_precise =
            c.response_read_deadline_profile ==
                ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::None;
        if (streaming_precise && response_read_deadline_uses_precise_timer(c)) {
            return ev.type == IoEventType::UpstreamRecv && ev.result > 0 && ev.aux == 0 &&
                   ev.upstream_episode == c.upstream_episode &&
                   ev.copy_witness == IoEventCopyWitness::Full && ev.copy_end >= ev.copy_begin &&
                   ev.copy_end - ev.copy_begin == static_cast<u32>(ev.result) &&
                   ev.copy_end == c.buffered_response_len() &&
                   ev.copy_deadline_generation == c.response_read_deadline_generation &&
                   ev.copy_deadline_profile == static_cast<u8>(c.response_read_deadline_profile) &&
                   ev.copy_deadline_method == c.response_read_deadline_method;
        }
        if (response_read_deadline_uses_precise_timer(c, allow_consumed_terminal_episode))
            return true;
        if (ev.type != IoEventType::UpstreamRecv || ev.result <= 0 || ev.aux != 0 ||
            ev.upstream_episode != c.upstream_episode ||
            ev.copy_witness != IoEventCopyWitness::Full || ev.copy_end < ev.copy_begin ||
            ev.copy_end - ev.copy_begin != static_cast<u32>(ev.result) ||
            ev.copy_end != c.buffered_response_len() ||
            ev.copy_deadline_generation != c.response_read_deadline_generation ||
            ev.copy_deadline_profile != static_cast<u8>(c.response_read_deadline_profile) ||
            ev.copy_deadline_method != c.response_read_deadline_method)
            return false;
        const RouteConfig* cfg = c.request_config;
        return cfg != nullptr &&
               c.response_read_deadline_profile ==
                   ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead &&
               c.response_read_deadline_buffering == ForwardResponseBufferingMode::None &&
               c.req_method == static_cast<u8>(LogHttpMethod::Head) &&
               fixed_upload_head_after_host_precise_progress_is_stable(
                   c,
                   c.response_read_deadline_upload,
                   cfg,
                   c.response_read_deadline_bundle_id,
                   ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                   &on_upstream_response<Self>,
                   ev.copy_begin,
                   allow_consumed_terminal_episode);
    }

    // Settlement runs after callbacks have appended the whole wait batch.  A
    // retained fixed-upload HEAD prefix therefore still names the pre-batch
    // copy boundary until the transactional ledger is committed below.
    [[nodiscard]] bool response_read_deadline_batch_uses_precise_timer(
        const Connection& c, const ResponseReadBatchOwner& owner) const {
        if (!owner.precise_timer_semantic || !owner.precise_timer_valid ||
            !c.response_read_timer_owner_is_valid() ||
            c.response_read_timer_phase != ResponseReadTimerPhase::Armed ||
            c.response_read_timer_owner_generation != owner.precise_timer_generation ||
            c.response_read_timer_deadline_generation != owner.deadline_generation ||
            c.response_read_timer_upstream_episode != owner.upstream_episode)
            return false;
        if (response_read_deadline_uses_precise_timer(c)) return true;
        if (!owner.saw_positive || owner.first_copy_begin == 0 || c.request_config == nullptr ||
            c.response_read_deadline_profile !=
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead ||
            c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
            c.req_method != static_cast<u8>(LogHttpMethod::Head))
            return false;
        return fixed_upload_head_after_host_precise_progress_is_stable(
            c,
            c.response_read_deadline_upload,
            c.request_config,
            c.response_read_deadline_bundle_id,
            ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
            &on_upstream_response<Self>,
            owner.first_copy_begin);
    }

    [[nodiscard]] bool rearm_precise_response_read_timer(Connection& c, u64 now_ns) {
        if (!response_read_deadline_uses_precise_timer(c) ||
            c.response_read_timer_last_progress_ns == 0)
            return false;
        const u64 timeout_ns =
            static_cast<u64>(c.response_read_deadline_seconds) * 1'000'000'000ull;
        const u32 remaining_ms = response_read_timer_remaining_ms(
            c.response_read_timer_last_progress_ns, timeout_ns, now_ns);
        if (remaining_ms == 0) return false;
        return backend.add_response_read_timer(
            c.id, c, remaining_ms, c.response_read_deadline_generation, c.upstream_episode);
    }

    // Semantic ownership is independent of timer transport custody: consuming a
    // target CQE must not make an otherwise valid stream ineligible for rearm.
    [[nodiscard]] bool streaming_response_read_timer_is_stable(const Connection& c) const {
        const bool bounded_release =
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::Buffering;
        if (c.id >= connection_capacity || c.state != ConnState::Sending || c.req_start_us == 0 ||
            c.epoch_held || !post_commit_incremental_release_active(c) ||
            (bounded_release ? !response_read_deadline_non_head_method_admitted(c.req_method)
                             : c.req_method != static_cast<u8>(LogHttpMethod::Get)) ||
            !response_read_deadline_identity_is_stable(c) ||
            !response_read_deadline_post_commit_is_stable(c))
            return false;
        const u32 submitted = c.response_read_deadline_post_commit_downstream_submitted;
        const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
        const u32 inflight = c.response_read_deadline_post_commit_inflight_body;
        const auto phase = c.response_read_deadline_post_commit_phase;
        if (phase == ResponseReadDeadlinePostCommitPhase::WaitingBody)
            return !c.send_armed && !c.response_read_deadline_send_owner_active &&
                   c.send_progress == 0 && inflight == 0 && submitted == completed &&
                   (c.on_send == &on_response_header_sent<Self> ||
                    c.on_send == &on_response_body_sent<Self>);
        const bool header = phase == ResponseReadDeadlinePostCommitPhase::HeaderSend;
        if (!header && phase != ResponseReadDeadlinePostCommitPhase::BodySend) return false;
        const u32 length = header ? c.response_header_buf.len() : inflight;
        const auto* source = header ? c.response_header_buf.data() : c.buffered_response_data();
        const auto& send = backend.send_state[c.id];
        return length != 0 && c.send_armed && c.pending_ops != 0 &&
               c.response_read_deadline_send_owner_active &&
               c.response_read_deadline_send_owner_generation != 0 &&
               c.response_read_deadline_send_deadline_generation ==
                   c.response_read_deadline_generation &&
               c.response_read_deadline_send_upstream_episode == c.upstream_episode &&
               c.response_read_deadline_send_fd == c.fd &&
               c.response_read_deadline_send_src == source &&
               c.response_read_deadline_send_len == length &&
               c.response_read_deadline_send_kind == (header
                                                          ? ResponseReadDeadlineSendKind::Header
                                                          : ResponseReadDeadlineSendKind::Body) &&
               c.on_send ==
                   (header ? &on_response_header_sent<Self> : &on_response_body_sent<Self>) &&
               (header ? submitted == 0 && completed == 0 && inflight == 0
                       : submitted >= completed && submitted - completed == inflight) &&
               send.src == source && send.fd == c.fd && send.type == IoEventType::Send &&
               send.generation == c.response_read_deadline_send_owner_generation &&
               send.offset <= length && send.remaining == length - send.offset;
    }

    [[nodiscard]] bool promote_streaming_response_read_timer(Connection& c) {
        if (!streaming_response_read_timer_is_stable(c) ||
            c.response_read_deadline_post_commit_origin_received >=
                c.response_read_deadline_post_commit_declared_body)
            return false;
        if (c.response_read_timer_phase == ResponseReadTimerPhase::Armed)
            return c.response_read_timer_owner_is_valid() &&
                   c.response_read_timer_deadline_generation ==
                       c.response_read_deadline_generation &&
                   c.response_read_timer_upstream_episode == c.upstream_episode &&
                   c.response_read_timer_last_progress_ns != 0;
        if (!c.response_read_timer_owner_is_neutral()) return false;
        timer.remove(&c);
        c.response_read_timer_last_progress_ns = monotonic_ns();
        return backend.add_response_read_timer(
            c.id,
            c,
            static_cast<u32>(c.response_read_deadline_seconds) * 1000u,
            c.response_read_deadline_generation,
            c.upstream_episode);
    }

    void disarm_response_read_deadline(Connection& c) {
        if (c.response_read_deadline_state == ResponseReadDeadlineState::None) {
            c.clear_response_read_deadline();
            return;
        }
        const bool owns_timer = c.response_read_deadline_state != ResponseReadDeadlineState::None;
        if (owns_timer) {
            if (c.response_read_timer_phase == ResponseReadTimerPhase::Armed)
                // Keep the target owner if cancel SQ submission is unavailable;
                // its natural CQE drains the immutable timespec and barrier.
                (void)backend.cancel_response_read_timer(c.id, c);
            timer.remove(&c);
        }
        c.clear_response_read_deadline();
    }

    bool response_read_deadline_identity_is_stable(const Connection& c) const {
        const RouteConfig* cfg = c.request_config;
        const u16 bundle_id = c.response_read_deadline_bundle_id;
        const bool post_commit =
            c.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None;
        const bool tls_bodyless_get_owner =
            response_read_deadline_tls_complete_get_profile_is_stable(c) &&
            c.on_recv == &tls_recv<Self> && c.tls_pending_on_recv == nullptr;
        if (c.id >= connection_capacity || c.fd < 0 || c.upstream_fd < 0 || is_draining() ||
            (c.state != ConnState::Proxying && !(post_commit && c.state == ConnState::Sending)) ||
            c.protocol != ConnProtocol::Http11 || (c.tls_active && !tls_bodyless_get_owner) ||
            c.h2 != nullptr || c.response_read_deadline_owner_generation == 0 ||
            c.response_read_deadline_owner_generation != c.response_read_deadline_generation ||
            c.response_read_deadline_profile == ResponseReadDeadlineProfile::None ||
            c.response_read_deadline_upstream_episode != c.upstream_episode ||
            !valid_upstream_episode(c.upstream_episode) || c.upstream_episode_quarantined ||
            cfg == nullptr || !cfg->policy_bundle_id_is_valid(bundle_id))
            return false;
        const auto& bundle = cfg->policy_bundles[bundle_id - 1];
        if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
            bundle.response_read_timeout_seconds != c.response_read_deadline_seconds ||
            bundle.response_policy_id != c.response_policy_id ||
            bundle.failure_policy_id != c.failure_policy_id ||
            bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
            c.upstream_idx >= cfg->upstream_count ||
            cfg->upstreams[c.upstream_idx].addr_count != 1 ||
            cfg->upstreams[c.upstream_idx].addrs[0].sin_family != AF_INET)
            return false;
        const bool no_progress = c.response_read_deadline_progress_generation == 0 &&
                                 c.response_read_deadline_progress_episode == 0 &&
                                 c.response_read_deadline_progress_bytes == 0;
        const bool exact_progress =
            c.response_read_deadline_progress_generation == c.response_read_deadline_generation &&
            c.response_read_deadline_progress_episode == c.upstream_episode &&
            c.response_read_deadline_progress_bytes != 0;
        const bool exact_post_commit_progress =
            post_commit &&
            c.response_read_deadline_progress_generation == c.response_read_deadline_generation &&
            c.response_read_deadline_progress_episode == c.upstream_episode &&
            c.response_read_deadline_progress_bytes ==
                c.response_read_deadline_post_commit_origin_received;
        const bool selecting_post_commit =
            post_commit && no_progress &&
            (c.response_read_deadline_post_commit_phase ==
                 ResponseReadDeadlinePostCommitPhase::HeaderSend ||
             c.response_read_deadline_post_commit_phase ==
                 ResponseReadDeadlinePostCommitPhase::Buffering) &&
            (c.response_read_deadline_state == ResponseReadDeadlineState::RefreshPending ||
             c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete);
        const bool header_only_head_explicit_close = header_only_head_explicit_close_arm_is_stable(
            c,
            c.response_read_deadline_upload,
            cfg,
            bundle_id,
            ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
            &on_upstream_response<Self>);
        const bool pipeline_generation_stable =
            http1_pipeline_request_generation_upload_active_is_stable(
                c,
                c.response_read_deadline_upload,
                c.response_read_deadline_profile,
                c.response_read_deadline_buffering,
                c.response_read_deadline_method,
                c.response_read_deadline_route_method);
        return (post_commit ? exact_post_commit_progress || selecting_post_commit
                            : no_progress || exact_progress) &&
               response_read_deadline_profile_is_stable(c, *cfg, bundle_id) &&
               c.upstream_attempts == 1 && response_read_deadline_upstream_reuse_is_stable(c) &&
               c.request_upload_complete && !c.upstream_request_incomplete &&
               (c.on_upstream_recv == &on_upstream_response<Self> ||
                (post_commit && c.on_upstream_recv == nullptr)) &&
               (pipeline_generation_stable || header_only_head_explicit_close) &&
               !c.target_transform_recorded && !c.req_path_overridden &&
               c.req_header_override_count == 0 && !c.req_header_override_overflow &&
               c.resp_header_mutation_count == 0 && c.resp_header_mutation_pending_count == 0 &&
               !c.resp_header_mutation_pending_overflow && !c.resp_header_mutation_overflow &&
               !c.upstream_recv_paused_for_send && !c.upstream_recv_pause_cancel_pending &&
               !c.upstream_recv_pause_rearm_pending && !c.upstream_recv_cancel_inflight &&
               !c.upstream_retirement_active && c.upstream_retirement_target_owned == 0 &&
               c.upstream_retirement_cancel_owned == 0 && c.upstream_retirement_cancel_retry == 0 &&
               c.upstream_close_episode == 0 && c.upstream_close_target_owned == 0 &&
               c.upstream_close_cancel_owned == 0 && !c.upstream_close_pause_cancel_owned &&
               c.idle_return_fd < 0 && c.idle_return_config == nullptr &&
               !c.close_after_idle_return && !c.h2_proxy_recv_draining &&
               !c.h2_proxy_synth_quarantined;
    }

    u16 find_response_read_batch_owner(u32 cid) const {
        if (!response_read_batch_owner_index_active) {
            for (u32 i = 0; i < response_read_batch_owner_count; ++i)
                if (response_read_batch_owners[i].conn_id == cid) return static_cast<u16>(i + 1);
            return 0;
        }
        u32 slot = (cid * 2654435761u) & (kResponseReadOwnerIndexSize - 1u);
        for (u32 probes = 0; probes < kResponseReadOwnerIndexSize; ++probes) {
            const u16 index = response_read_batch_owner_index[slot];
            if (index == 0) return 0;
            if (response_read_batch_owners[index - 1u].conn_id == cid) return index;
            slot = (slot + 1u) & (kResponseReadOwnerIndexSize - 1u);
        }
        return 0;
    }

    u16 publish_response_read_batch_owner() {
        const u16 index = static_cast<u16>(++response_read_batch_owner_count);
        if (response_read_batch_owner_index_active) {
            const u32 cid = response_read_batch_owners[index - 1u].conn_id;
            u32 slot = (cid * 2654435761u) & (kResponseReadOwnerIndexSize - 1u);
            while (response_read_batch_owner_index[slot] != 0)
                slot = (slot + 1u) & (kResponseReadOwnerIndexSize - 1u);
            response_read_batch_owner_index[slot] = index;
        }
        return index;
    }

    u16 find_or_add_response_read_batch_owner(u32 cid) {
        if (const u16 index = find_response_read_batch_owner(cid)) return index;
        if (cid >= slots_initialized || response_read_batch_owner_count >= kMaxEventsPerWait)
            return 0;
        const Connection& c = conns[cid];
        if (c.response_read_deadline_state != ResponseReadDeadlineState::Armed &&
            c.response_read_deadline_state != ResponseReadDeadlineState::ExpiryPending &&
            c.response_read_deadline_state != ResponseReadDeadlineState::BodyComplete)
            return 0;
        auto& owner = response_read_batch_owners[response_read_batch_owner_count];
        owner = {};
        owner.conn_id = cid;
        owner.deadline_generation = c.response_read_deadline_generation;
        owner.upstream_episode = c.upstream_episode;
        owner.profile = c.response_read_deadline_profile;
        owner.method = c.response_read_deadline_method;
        owner.post_commit_at_start =
            c.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None;
        owner.body_complete_at_start =
            c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete;
        owner.valid = response_read_deadline_identity_is_stable(c) && c.upstream_recv_armed;
        return publish_response_read_batch_owner();
    }

    u16 find_or_add_precise_timer_batch_owner(u32 cid) {
        if (const u16 index = find_response_read_batch_owner(cid)) {
            auto& owner = response_read_batch_owners[index - 1u];
            const Connection& c = conns[cid];
            if (!c.response_read_timer_owner_is_valid()) {
                owner.valid = false;
                return index;
            }
            owner.precise_timer_valid = true;
            owner.saw_precise_timer = true;
            owner.precise_timer_generation = c.response_read_timer_owner_generation;
            owner.precise_timer_semantic =
                c.response_read_deadline_state != ResponseReadDeadlineState::None &&
                c.response_read_timer_phase == ResponseReadTimerPhase::Armed;
            return index;
        }
        if (cid >= slots_initialized || response_read_batch_owner_count >= kMaxEventsPerWait)
            return 0;
        const Connection& c = conns[cid];
        if (!c.response_read_timer_owner_is_valid()) return 0;
        auto& owner = response_read_batch_owners[response_read_batch_owner_count];
        owner = {};
        owner.conn_id = cid;
        owner.deadline_generation = c.response_read_timer_deadline_generation;
        owner.upstream_episode = c.response_read_timer_upstream_episode;
        owner.profile = c.response_read_deadline_profile;
        owner.method = c.response_read_deadline_method;
        owner.post_commit_at_start =
            c.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None;
        owner.body_complete_at_start =
            c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete;
        owner.valid = true;
        owner.precise_timer_valid = true;
        owner.saw_precise_timer = true;
        owner.precise_timer_generation = c.response_read_timer_owner_generation;
        owner.precise_timer_semantic =
            c.response_read_deadline_state != ResponseReadDeadlineState::None &&
            c.response_read_timer_phase == ResponseReadTimerPhase::Armed;
        return publish_response_read_batch_owner();
    }

    u16 find_or_add_bounded_terminal_custody_owner(u32 cid) {
        if (cid >= slots_initialized) return 0;
        if (const u16 index = find_response_read_batch_owner(cid)) {
            auto& owner = response_read_batch_owners[index - 1u];
            if (!owner.bounded_terminal_custody) {
                const Connection& c = conns[cid];
                owner.bounded_terminal_custody = true;
                const u32 received = c.response_read_deadline_post_commit_origin_received;
                const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
                const u32 header = c.response_read_deadline_post_commit_phase ==
                                               ResponseReadDeadlinePostCommitPhase::HeaderSend ||
                                           c.response_read_deadline_post_commit_phase ==
                                               ResponseReadDeadlinePostCommitPhase::Buffering
                                       ? c.response_read_deadline_post_commit_raw_header_end
                                       : 0;
                owner.bounded_terminal_buffer_begin =
                    received >= completed && header <= 0xffffffffu - (received - completed)
                        ? header + received - completed
                        : 0xffffffffu;
                owner.expected_copy_end = owner.bounded_terminal_buffer_begin;
                owner.post_commit_at_start = true;
                owner.valid =
                    c.fd >= 0 && c.response_read_deadline_post_commit_terminal_pending &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    c.response_read_deadline_generation == owner.deadline_generation &&
                    c.upstream_episode == owner.upstream_episode;
            }
            return index;
        }
        if (response_read_batch_owner_count >= kMaxEventsPerWait) return 0;
        const Connection& c = conns[cid];
        auto& owner = response_read_batch_owners[response_read_batch_owner_count];
        owner = {};
        owner.conn_id = cid;
        owner.deadline_generation = c.response_read_deadline_generation;
        owner.upstream_episode = c.upstream_episode;
        owner.profile = c.response_read_deadline_profile;
        owner.method = c.response_read_deadline_method;
        owner.post_commit_at_start = true;
        owner.bounded_terminal_custody = true;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
        const u32 header = c.response_read_deadline_post_commit_phase ==
                                       ResponseReadDeadlinePostCommitPhase::HeaderSend ||
                                   c.response_read_deadline_post_commit_phase ==
                                       ResponseReadDeadlinePostCommitPhase::Buffering
                               ? c.response_read_deadline_post_commit_raw_header_end
                               : 0;
        owner.bounded_terminal_buffer_begin =
            received >= completed && header <= 0xffffffffu - (received - completed)
                ? header + received - completed
                : 0xffffffffu;
        owner.expected_copy_end = owner.bounded_terminal_buffer_begin;
        owner.valid =
            c.fd >= 0 && c.response_read_deadline_post_commit_terminal_pending &&
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None &&
            c.response_read_deadline_generation != 0 &&
            c.response_read_deadline_owner_generation == c.response_read_deadline_generation &&
            c.response_read_deadline_upstream_episode == c.upstream_episode &&
            c.response_read_deadline_post_commit_generation ==
                c.response_read_deadline_generation &&
            c.response_read_deadline_post_commit_episode == c.upstream_episode &&
            valid_upstream_episode(c.upstream_episode);
        return publish_response_read_batch_owner();
    }

    void prepare_bounded_terminal_timer_eof_pairs(const IoEvent* events, u32 count) {
        for (u32 recv_index = 0; recv_index < count; ++recv_index) {
            const IoEvent& recv = events[recv_index];
            if (recv.type != IoEventType::UpstreamRecv || recv.result != 0 || recv.more ||
                recv.aux != 0 || recv.copy_witness != IoEventCopyWitness::None ||
                recv.conn_id >= slots_initialized)
                continue;
            const Connection& c = conns[recv.conn_id];
            if (c.fd < 0 ||
                c.response_read_deadline_buffering != ForwardResponseBufferingMode::Bounded ||
                c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::None ||
                c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::Buffering ||
                c.response_read_deadline_state != ResponseReadDeadlineState::Armed ||
                recv.upstream_episode != c.upstream_episode || !c.upstream_recv_armed ||
                !c.response_read_timer_owner_is_valid() ||
                c.response_read_timer_phase != ResponseReadTimerPhase::Armed ||
                !response_read_deadline_uses_precise_timer(c) ||
                !post_commit_incremental_release_active(c) ||
                !response_read_deadline_post_commit_is_stable(c) ||
                !streaming_response_read_timer_is_stable(c))
                continue;
            const u32 received = c.response_read_deadline_post_commit_origin_received;
            const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
            const u32 header = c.response_read_deadline_post_commit_raw_header_end;
            if (completed > received || header > 0xffffffffu - (received - completed)) continue;
            const u32 buffer_begin = header + received - completed;
            if (buffer_begin != c.buffered_response_len()) continue;

            u32 timer_index = count;
            bool duplicate = false;
            for (u32 i = 0; i < count; ++i) {
                if (events[i].conn_id != recv.conn_id) continue;
                if (i != recv_index && events[i].type == IoEventType::UpstreamRecv &&
                    events[i].upstream_episode == recv.upstream_episode && events[i].result <= 0)
                    duplicate = true;
                if (events[i].type == IoEventType::ResponseReadTimer) {
                    if (timer_index != count) duplicate = true;
                    timer_index = i;
                }
            }
            if (duplicate || timer_index == count) continue;
            const IoEvent& timer_ev = events[timer_index];
            if (!valid_response_read_timer_transport_event(timer_ev) ||
                (timer_ev.non_upstream_generation & kResponseReadTimerCancelBit) != 0 ||
                (timer_ev.non_upstream_generation & kResponseReadTimerGenerationMask) !=
                    c.response_read_timer_owner_generation ||
                timer_ev.result != -ETIME || response_read_batch_owner_count >= kMaxEventsPerWait)
                continue;

            auto& owner = response_read_batch_owners[response_read_batch_owner_count];
            owner = {};
            owner.conn_id = recv.conn_id;
            owner.deadline_generation = c.response_read_deadline_generation;
            owner.upstream_episode = c.upstream_episode;
            owner.profile = c.response_read_deadline_profile;
            owner.method = c.response_read_deadline_method;
            owner.post_commit_at_start = true;
            owner.bounded_terminal_custody = true;
            owner.bounded_terminal_prospective = true;
            owner.bounded_terminal_buffer_begin = buffer_begin;
            owner.expected_copy_end = owner.bounded_terminal_buffer_begin;
            owner.bounded_terminal_recv_seen = false;
            owner.saw_precise_timer = true;
            owner.precise_timer_valid = true;
            owner.precise_timer_semantic = true;
            owner.precise_timer_generation = c.response_read_timer_owner_generation;
            owner.valid =
                c.response_read_deadline_generation != 0 &&
                c.response_read_deadline_owner_generation == c.response_read_deadline_generation &&
                c.response_read_deadline_upstream_episode == c.upstream_episode &&
                c.response_read_deadline_post_commit_generation ==
                    c.response_read_deadline_generation &&
                c.response_read_deadline_post_commit_episode == c.upstream_episode &&
                valid_upstream_episode(c.upstream_episode) &&
                owner.bounded_terminal_buffer_begin == c.buffered_response_len();
            const u16 owner_index = publish_response_read_batch_owner();
            response_read_batch_event_owner[recv_index] = owner_index;
            response_read_batch_event_owner[timer_index] = owner_index;
        }
    }

    void prepare_response_read_deadline_batch(const IoEvent* events, u32 count) {
        ws_splice.last_batch_ws_only = false;
        response_read_batch_events = events;
        response_read_batch_owner_count = 0;
        response_read_batch_owner_index_active = false;
        // These auxiliary domains belong exclusively to the opaque WebSocket
        // relay ledger, including its cancel acknowledgements. They cannot
        // contribute HTTP response-read deadline owners. Keep the common
        // post-dispatch maintenance, and always prepare mixed batches normally.
        bool ws_only = ws_splice.enabled && ws_splice.fast_batch && count != 0;
        for (u32 i = 0; ws_only && i < count; ++i) {
            const auto& ev = events[i];
            ws_only = (ev.type == IoEventType::RelayRead || ev.type == IoEventType::RelayWrite) &&
                      (ev.aux == 32 || ev.aux == 33 || ev.aux == 96 || ev.aux == 97);
        }
        if (ws_only) {
            ws_splice.last_batch_ws_only = true;
            response_read_batch_event_count = count;
            response_read_batch_event_index = 0;
            response_read_batch_pin_count = 0;
            for (u32 i = 0; i < count; ++i) response_read_batch_event_owner[i] = 0;
            ++ws_splice.deadline_batches_skipped;
            return;
        }
        __builtin_memset(
            response_read_batch_owner_index, 0, sizeof(response_read_batch_owner_index));
        response_read_batch_owner_index_active = true;
        response_read_batch_event_count = count;
        response_read_batch_event_index = 0;
        response_read_batch_pin_count = 0;
        for (u32 i = 0; i < count; ++i) response_read_batch_event_owner[i] = 0;
        prepare_bounded_terminal_timer_eof_pairs(events, count);

        // Discover only owners touched by this bounded wait batch.  A timer-only
        // owner remains on the ordinary expiry path; a response or downstream
        // terminal creates an entry without retaining a Connection pointer.
        for (u32 i = 0; i < count; ++i) {
            if (response_read_batch_event_owner[i] != 0) continue;
            const IoEvent& ev = events[i];
            if (ev.conn_id >= slots_initialized) continue;
            const Connection& c = conns[ev.conn_id];
            const bool current_upstream =
                ev.type == IoEventType::UpstreamRecv && ev.upstream_episode == c.upstream_episode;
            const bool downstream_terminal = ev.type == IoEventType::Recv && ev.result <= 0;
            const bool bounded_terminal_pending =
                c.response_read_deadline_post_commit_terminal_pending &&
                c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded;
            const bool bounded_terminal_custody =
                bounded_terminal_pending &&
                (ev.type == IoEventType::UpstreamRecv || ev.aux == kPauseCancelAux);
            if (bounded_terminal_custody) {
                response_read_batch_event_owner[i] =
                    find_or_add_bounded_terminal_custody_owner(ev.conn_id);
                continue;
            }
            if (current_upstream || downstream_terminal)
                (void)find_or_add_response_read_batch_owner(ev.conn_id);
            if (ev.type == IoEventType::ResponseReadTimer)
                (void)find_or_add_precise_timer_batch_owner(ev.conn_id);
        }

        for (u32 i = 0; i < count; ++i) {
            const IoEvent& ev = events[i];
            if (ev.conn_id >= slots_initialized) continue;
            if (response_read_batch_event_owner[i] == 0xffffu) continue;
            const u16 owner_index = find_response_read_batch_owner(ev.conn_id);
            if (owner_index == 0) continue;
            auto& owner = response_read_batch_owners[owner_index - 1];
            if (owner.bounded_terminal_prospective) continue;
            if (owner.bounded_terminal_custody && ev.type != IoEventType::ResponseReadTimer) {
                response_read_batch_event_owner[i] = owner_index;
                const Connection& c = conns[ev.conn_id];
                if (!owner.valid || !c.response_read_deadline_post_commit_terminal_pending ||
                    ev.upstream_episode != owner.upstream_episode ||
                    owner.deadline_generation != c.response_read_deadline_generation ||
                    owner.profile != c.response_read_deadline_profile ||
                    owner.method != c.response_read_deadline_method) {
                    owner.bounded_terminal_custody_invalid = true;
                    continue;
                }
                if (ev.aux == kPauseCancelAux) {
                    if (!c.response_read_deadline_post_commit_terminal_pending ||
                        !c.upstream_recv_pause_cancel_pending ||
                        owner.bounded_terminal_cancel_seen || ev.more ||
                        ev.copy_witness != IoEventCopyWitness::None ||
                        (ev.result != 0 && ev.result != -ENOENT)) {
                        owner.bounded_terminal_custody_invalid = true;
                    } else {
                        owner.bounded_terminal_cancel_seen = true;
                    }
                    continue;
                }
                if (ev.aux != 0 || ev.copy_witness == IoEventCopyWitness::Invalid) {
                    owner.bounded_terminal_custody_invalid = true;
                    continue;
                }
                if (ev.result > 0) {
                    if (!c.upstream_recv_cancel_inflight || !c.upstream_recv_terminal_stale ||
                        ev.copy_witness != IoEventCopyWitness::Full || ev.more == false ||
                        ev.copy_deadline_generation != owner.deadline_generation ||
                        ev.copy_deadline_profile != static_cast<u8>(owner.profile) ||
                        ev.copy_deadline_method != owner.method || ev.copy_end < ev.copy_begin ||
                        ev.copy_end - ev.copy_begin != static_cast<u32>(ev.result) ||
                        ev.copy_begin != owner.expected_copy_end ||
                        owner.expected_copy_end > 0xffffffffu - static_cast<u32>(ev.result)) {
                        owner.bounded_terminal_custody_invalid = true;
                    } else {
                        if (!owner.saw_positive) owner.first_copy_begin = ev.copy_begin;
                        owner.expected_copy_end = ev.copy_end;
                        owner.positive_bytes += static_cast<u32>(ev.result);
                        owner.saw_positive = true;
                    }
                    continue;
                }
                if (ev.more || ev.copy_witness != IoEventCopyWitness::None || owner.saw_terminal ||
                    (ev.result != -ECANCELED && ev.result != 0) ||
                    !c.upstream_recv_cancel_inflight || !c.upstream_recv_terminal_stale) {
                    owner.bounded_terminal_custody_invalid = true;
                } else {
                    owner.bounded_terminal_recv_seen = true;
                }
                continue;
            }
            if (ev.type == IoEventType::ResponseReadTimer) {
                const bool transport_valid = valid_response_read_timer_transport_event(ev);
                const bool identity_valid =
                    owner.precise_timer_valid &&
                    (ev.non_upstream_generation & kResponseReadTimerGenerationMask) ==
                        owner.precise_timer_generation;
                owner.saw_precise_timer = true;
                const bool cancel = (ev.non_upstream_generation & kResponseReadTimerCancelBit) != 0;
                if (cancel) {
                    if (owner.precise_timer_cancel_seen) owner.valid = false;
                    owner.precise_timer_cancel_seen = true;
                } else {
                    if (owner.precise_timer_target_seen) owner.valid = false;
                    owner.precise_timer_target_seen = true;
                }
                if (!transport_valid || !identity_valid) owner.valid = false;
                continue;
            }
            if (ev.type == IoEventType::Recv && ev.result <= 0) {
                owner.valid = false;
                continue;
            }
            if (ev.type != IoEventType::UpstreamRecv ||
                ev.upstream_episode != owner.upstream_episode)
                continue;

            response_read_batch_event_owner[i] = owner_index;
            owner.last_relevant = i;
            owner.saw_relevant = true;
            if (ev.aux != 0 || ev.result == -ENOBUFS || ev.result == -ECANCELED ||
                ev.copy_witness == IoEventCopyWitness::Invalid)
                owner.valid = false;

            if (ev.result > 0) {
                owner.last_positive = i;
                if (owner.saw_terminal && !owner.terminal_fault) owner.valid = false;
                if (ev.copy_witness != IoEventCopyWitness::Full ||
                    ev.copy_deadline_generation != owner.deadline_generation ||
                    ev.copy_deadline_profile != static_cast<u8>(owner.profile) ||
                    ev.copy_deadline_method != owner.method || ev.copy_end < ev.copy_begin ||
                    ev.copy_end - ev.copy_begin != static_cast<u32>(ev.result)) {
                    owner.valid = false;
                } else {
                    if (!owner.saw_positive) {
                        owner.first_copy_begin = ev.copy_begin;
                        owner.expected_copy_end = ev.copy_begin;
                    }
                    if (ev.copy_begin != owner.expected_copy_end) owner.valid = false;
                    owner.expected_copy_end = ev.copy_end;
                    const u32 positive = static_cast<u32>(ev.result);
                    if (owner.positive_bytes > 0xFFFFFFFFu - positive)
                        owner.valid = false;
                    else
                        owner.positive_bytes += positive;
                    owner.saw_positive = true;
                }
                if (!ev.more) {
                    if (owner.saw_terminal) owner.valid = false;
                    owner.saw_terminal = true;
                    owner.positive_terminal = true;
                }
            } else {
                if (ev.more || ev.copy_witness != IoEventCopyWitness::None) owner.valid = false;
                if (owner.saw_terminal) owner.valid = false;
                owner.terminal_fault = true;
                owner.clean_eof = ev.result == 0;
                owner.terminal_error = ev.result < 0;
                owner.saw_terminal = true;
            }
        }

        // For an initial buffered selection, a following clean EOF is a
        // terminal disposition, not the parser event. Parse the cumulative
        // bytes at the final positive CQE and retain EOF in the owner ledger
        // for settlement, independent of timeout placement.
        for (u32 oi = 0; oi < response_read_batch_owner_count; ++oi) {
            auto& owner = response_read_batch_owners[oi];
            const Connection& c = conns[owner.conn_id];
            if (owner.bounded_terminal_custody) {
                if (owner.bounded_terminal_prospective) {
                    continue;
                }
                const bool exact_copy_end =
                    owner.saw_positive
                        ? owner.first_copy_begin == owner.bounded_terminal_buffer_begin &&
                              owner.expected_copy_end == c.buffered_response_len()
                        : c.buffered_response_len() == owner.bounded_terminal_buffer_begin;
                owner.valid =
                    owner.valid && !owner.bounded_terminal_custody_invalid &&
                    c.response_read_deadline_post_commit_terminal_pending &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    c.response_read_deadline_generation == owner.deadline_generation &&
                    c.upstream_episode == owner.upstream_episode &&
                    valid_upstream_episode(owner.upstream_episode) && exact_copy_end &&
                    (owner.bounded_terminal_recv_seen || owner.bounded_terminal_cancel_seen ||
                     owner.saw_positive);
                if (owner.saw_positive &&
                    (owner.bounded_terminal_buffer_begin > 0xffffffffu - owner.positive_bytes ||
                     owner.bounded_terminal_buffer_begin + owner.positive_bytes !=
                         c.buffered_response_len()))
                    owner.valid = false;
                continue;
            }
            if (!owner.post_commit_at_start && owner.clean_eof && owner.saw_positive &&
                forward_response_buffering_uses_content_length_machinery(
                    c.response_read_deadline_buffering))
                owner.last_relevant = owner.last_positive;
        }

        // Finish every owner's read-only proof before removing a timer or
        // closing a connection.  The backend has already appended all Full
        // copies, so the exact final length proves the first range begins at
        // the pre-batch cumulative length and that no hidden copy occurred.
        for (u32 oi = 0; oi < response_read_batch_owner_count; ++oi) {
            auto& owner = response_read_batch_owners[oi];
            const Connection& c = conns[owner.conn_id];
            if (owner.bounded_terminal_custody) continue;
            if (!owner.saw_relevant && !owner.saw_precise_timer) owner.valid = false;
            const u32 pre_batch_bytes =
                owner.saw_positive ? owner.first_copy_begin : c.buffered_response_len();
            const bool no_prior_progress = c.response_read_deadline_progress_generation == 0 &&
                                           c.response_read_deadline_progress_episode == 0 &&
                                           c.response_read_deadline_progress_bytes == 0;
            const bool exact_prior_progress =
                c.response_read_deadline_progress_generation == owner.deadline_generation &&
                c.response_read_deadline_progress_episode == owner.upstream_episode &&
                c.response_read_deadline_progress_bytes == pre_batch_bytes && pre_batch_bytes != 0;
            if (owner.post_commit_at_start) {
                const u32 unsent = c.response_read_deadline_post_commit_origin_received -
                                   c.response_read_deadline_post_commit_downstream_completed;
                const u32 header_prefix =
                    c.response_read_deadline_post_commit_phase ==
                                ResponseReadDeadlinePostCommitPhase::HeaderSend ||
                            c.response_read_deadline_post_commit_phase ==
                                ResponseReadDeadlinePostCommitPhase::Buffering
                        ? c.response_read_deadline_post_commit_raw_header_end
                        : 0;
                if (header_prefix > 0xFFFFFFFFu - unsent ||
                    pre_batch_bytes != header_prefix + unsent ||
                    c.response_read_deadline_progress_generation != owner.deadline_generation ||
                    c.response_read_deadline_progress_episode != owner.upstream_episode ||
                    c.response_read_deadline_progress_bytes !=
                        c.response_read_deadline_post_commit_origin_received)
                    owner.valid = false;
            } else if ((pre_batch_bytes == 0 && !no_prior_progress) ||
                       (pre_batch_bytes != 0 && !exact_prior_progress)) {
                owner.valid = false;
            }
            if (owner.saw_positive &&
                (owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
                 owner.first_copy_begin + owner.positive_bytes != owner.expected_copy_end ||
                 owner.expected_copy_end != c.buffered_response_len()))
                owner.valid = false;
        }

        for (u32 oi = 0; oi < response_read_batch_owner_count; ++oi) {
            auto& owner = response_read_batch_owners[oi];
            pin_response_read_batch_slot(owner.conn_id);
            Connection& c = conns[owner.conn_id];
            if (owner.bounded_terminal_custody) {
                if (!owner.valid && c.fd >= 0) close_conn(c);
                continue;
            }
            // A timer can outlive the logical deadline owner after a successful
            // disarm (for example while the exact 504 Send is in flight). Its
            // CQE is custody-only: keep the slot pinned, but do not force the
            // ordinary deadline state machine to manufacture a mismatch.
            if (owner.saw_precise_timer && !owner.precise_timer_semantic) continue;
            const bool key_stable =
                c.id == owner.conn_id &&
                c.response_read_deadline_generation == owner.deadline_generation &&
                c.upstream_episode == owner.upstream_episode &&
                c.response_read_deadline_profile == owner.profile &&
                c.response_read_deadline_method == owner.method &&
                (c.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                 c.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending ||
                 c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete);
            if (!owner.valid || !key_stable) {
                owner.valid = false;
                if (c.fd >= 0) close_conn(c);
                continue;
            }
            timer.remove(&c);
            c.response_read_deadline_state = ResponseReadDeadlineState::BatchPending;
        }
    }

    [[nodiscard]] bool continue_response_read_deadline_after_incomplete(Connection& c,
                                                                        const IoEvent& ev) {
        if (c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending ||
            !response_read_deadline_identity_is_stable(c) || ev.type != IoEventType::UpstreamRecv ||
            ev.result <= 0 || ev.aux != 0 || ev.upstream_episode != c.upstream_episode)
            return false;
        if (ev.more) {
            if (!c.upstream_recv_armed) return false;
            c.response_read_deadline_state = ResponseReadDeadlineState::RefreshPending;
            return true;
        }
        if (c.upstream_recv_armed || c.upstream_recv_pause_cancel_pending ||
            c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
            !add_response_read_recv(c))
            return false;
        c.pending_ops++;
        c.upstream_recv_armed = true;
        c.response_read_deadline_state = ResponseReadDeadlineState::RefreshPending;
        return true;
    }

    // Publish cumulative response progress only after the wait-batch copy
    // ledger, the live deadline owner, the receive continuation, and the
    // cumulative parser result all agree.  Keeping this transition separate
    // from the transport timer clock lets a policy choose whether accepted
    // bytes move its deadline origin without weakening the progress proof used
    // by a later expiry.
    [[nodiscard]] bool commit_response_read_deadline_incomplete_progress(
        Connection& c, const ResponseReadBatchOwner& owner) {
        if (!owner.valid || !owner.saw_positive || owner.terminal_fault || owner.conn_id != c.id ||
            owner.deadline_generation == 0 ||
            owner.deadline_generation != c.response_read_deadline_generation ||
            owner.upstream_episode != c.upstream_episode ||
            c.response_read_deadline_state != ResponseReadDeadlineState::RefreshPending ||
            !c.upstream_recv_armed || !response_read_deadline_identity_is_stable(c))
            return false;

        const u32 total = c.buffered_response_len();
        if (total == 0 || owner.expected_copy_end != total ||
            owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
            owner.first_copy_begin + owner.positive_bytes != total)
            return false;
        const bool no_prior_progress = c.response_read_deadline_progress_generation == 0 &&
                                       c.response_read_deadline_progress_episode == 0 &&
                                       c.response_read_deadline_progress_bytes == 0;
        const bool exact_prior_progress =
            c.response_read_deadline_progress_generation == owner.deadline_generation &&
            c.response_read_deadline_progress_episode == owner.upstream_episode &&
            c.response_read_deadline_progress_bytes == owner.first_copy_begin &&
            owner.first_copy_begin != 0;
        if ((owner.first_copy_begin == 0 && !no_prior_progress) ||
            (owner.first_copy_begin != 0 && !exact_prior_progress))
            return false;

        HttpResponseParser parser;
        ParsedResponse response;
        parser.reset();
        response.reset();
        if (parser.parse(c.upstream_recv_buf.data(), c.upstream_recv_buf.len(), &response) !=
            ParseStatus::Incomplete)
            return false;

        c.response_read_deadline_progress_generation = owner.deadline_generation;
        c.response_read_deadline_progress_episode = owner.upstream_episode;
        c.response_read_deadline_progress_bytes = total;
        return true;
    }

    [[nodiscard]] bool commit_response_read_deadline_streaming_progress(
        Connection& c, const ResponseReadBatchOwner& owner) {
        bool member = false;
        for (u32 i = 0; i < response_read_batch_owner_count; ++i)
            member = member || &owner == &response_read_batch_owners[i];
        const bool bounded_clean_eof =
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
            owner.clean_eof;
        if (!member || response_read_batch_events == nullptr || !owner.valid ||
            !owner.post_commit_at_start || (!owner.saw_positive && !bounded_clean_eof) ||
            owner.conn_id != c.id ||
            owner.deadline_generation != c.response_read_deadline_generation ||
            owner.upstream_episode != c.upstream_episode ||
            (c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending &&
             c.response_read_deadline_state != ResponseReadDeadlineState::RefreshPending) ||
            !streaming_response_read_timer_is_stable(c))
            return false;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        const u32 declared = c.response_read_deadline_post_commit_declared_body;
        const u32 completed = c.response_read_deadline_post_commit_downstream_completed;
        const u32 header = c.response_read_deadline_post_commit_phase ==
                                   ResponseReadDeadlinePostCommitPhase::HeaderSend
                               ? c.response_read_deadline_post_commit_raw_header_end
                               : 0;
        if (completed > received || received > declared ||
            owner.positive_bytes > declared - received ||
            (owner.terminal_fault && !bounded_clean_eof &&
             owner.positive_bytes != declared - received) ||
            (owner.saw_positive &&
             (owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
              owner.first_copy_begin + owner.positive_bytes != owner.expected_copy_end)) ||
            (!owner.saw_positive && (owner.positive_bytes != 0 || owner.first_copy_begin != 0 ||
                                     owner.expected_copy_end != 0)) ||
            header > 0xFFFFFFFFu - (received - completed) ||
            header + received - completed > 0xFFFFFFFFu - owner.positive_bytes ||
            c.buffered_response_len() != header + received - completed + owner.positive_bytes ||
            c.response_read_deadline_progress_generation != owner.deadline_generation ||
            c.response_read_deadline_progress_episode != owner.upstream_episode ||
            c.response_read_deadline_progress_bytes != received)
            return false;
        // prepare validated the pre-batch copy range. A valid Send CQE in this
        // batch may already have consumed header/body bytes; the retained range
        // above is checked against the current completed count, not offset zero.
        c.response_read_deadline_post_commit_origin_received = received + owner.positive_bytes;
        c.response_read_deadline_progress_generation = owner.deadline_generation;
        c.response_read_deadline_progress_episode = owner.upstream_episode;
        c.response_read_deadline_progress_bytes = received + owner.positive_bytes;
        c.response_read_timer_last_progress_ns = monotonic_ns();
        return true;
    }

    [[nodiscard]] bool begin_response_read_deadline_body_stream(Connection& c,
                                                                const IoEvent& ev,
                                                                u32 raw_header_end,
                                                                u32 declared_body) {
        if (c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None ||
            !response_read_deadline_identity_is_stable(c) ||
            c.response_read_deadline_profile !=
                ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
            c.req_method != static_cast<u8>(LogHttpMethod::Get) || declared_body == 0 ||
            raw_header_end == 0 || raw_header_end > c.buffered_response_len() ||
            declared_body > c.upstream_recv_buf.capacity() - raw_header_end)
            return false;
        const u32 initial_body = c.buffered_response_len() - raw_header_end;
        if (initial_body > declared_body) return false;
        const bool fragmented_header_transition =
            c.response_read_deadline_progress_generation == c.response_read_deadline_generation &&
            c.response_read_deadline_progress_episode == c.upstream_episode &&
            c.response_read_deadline_progress_bytes != 0 &&
            c.response_read_deadline_progress_bytes < raw_header_end;

        // The pre-header ledger records cumulative raw header bytes. Once this
        // exact batch proves the final header boundary and selects a positive-
        // CL stream, that prefix is no longer response body progress. Consume
        // only this generation/episode-bound proof; settle installs the exact
        // coalesced initial-body count as the new post-commit progress identity.
        if (fragmented_header_transition) {
            c.response_read_deadline_progress_generation = 0;
            c.response_read_deadline_progress_episode = 0;
            c.response_read_deadline_progress_bytes = 0;
        }

        c.response_read_deadline_post_commit_phase =
            ResponseReadDeadlinePostCommitPhase::HeaderSend;
        c.response_read_deadline_post_commit_generation = c.response_read_deadline_generation;
        c.response_read_deadline_post_commit_episode = c.upstream_episode;
        c.response_read_deadline_post_commit_raw_header_end = raw_header_end;
        c.response_read_deadline_post_commit_declared_body = declared_body;
        c.response_read_deadline_post_commit_origin_received = initial_body;
        c.response_read_deadline_post_commit_downstream_submitted = 0;
        c.response_read_deadline_post_commit_downstream_completed = 0;
        c.response_read_deadline_post_commit_inflight_body = 0;
        c.response_read_deadline_post_commit_pump_pending = false;

        if (initial_body == declared_body) {
            c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
            return true;
        }
        if (ev.result <= 0 || ev.aux != 0 || ev.upstream_episode != c.upstream_episode)
            return false;
        if (ev.more) {
            if (!c.upstream_recv_armed) return false;
        } else {
            if (c.upstream_recv_armed || c.upstream_recv_pause_cancel_pending ||
                c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
                !add_response_read_recv(c))
                return false;
            c.pending_ops++;
            c.upstream_recv_armed = true;
        }
        c.response_read_deadline_state = ResponseReadDeadlineState::RefreshPending;
        return true;
    }

    [[nodiscard]] bool begin_complete_content_length_buffering(Connection& c,
                                                               const IoEvent& ev,
                                                               u32 raw_header_end,
                                                               u32 declared_body) {
        CompleteContentLengthResponseClassification classification{};
        if (c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None ||
            !forward_response_buffering_uses_content_length_machinery(
                c.response_read_deadline_buffering) ||
            !response_read_deadline_identity_is_stable(c) ||
            (c.response_read_deadline_profile !=
                 ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
             !complete_content_length_fixed_upload_composition_is_stable(
                 c, c.response_read_deadline_upload, /*require_upload_complete=*/true)) ||
            !response_read_deadline_non_head_method_admitted(c.req_method) ||
            !complete_content_length_route_method_is_admitted(
                c.response_read_deadline_route_method) ||
            !response_read_deadline_route_method_matches(c.req_method,
                                                         c.response_read_deadline_route_method) ||
            declared_body == 0 || raw_header_end == 0 ||
            raw_header_end > c.buffered_response_len() ||
            declared_body > ResponseBodyChain::kMaxBody ||
            c.response_header_buf.data() == nullptr || c.response_header_buf.len() == 0 ||
            c.response_header_buf.len() > c.response_header_buf.capacity() ||
            !complete_content_length_raw_origin_matches_pinned(
                c, raw_header_end, declared_body, &classification))
            return false;
        const u32 initial_body = c.buffered_response_len() - raw_header_end;
        if (initial_body > declared_body) return false;
        const bool precise_header_timer = response_read_deadline_uses_precise_timer(c);
        if (precise_header_timer && c.response_read_timer_phase != ResponseReadTimerPhase::Armed)
            return false;
        const bool fragmented_header_transition =
            c.response_read_deadline_progress_generation == c.response_read_deadline_generation &&
            c.response_read_deadline_progress_episode == c.upstream_episode &&
            c.response_read_deadline_progress_bytes != 0 &&
            c.response_read_deadline_progress_bytes < raw_header_end;
        if (fragmented_header_transition) {
            c.response_read_deadline_progress_generation = 0;
            c.response_read_deadline_progress_episode = 0;
            c.response_read_deadline_progress_bytes = 0;
        }

        c.response_read_deadline_post_commit_phase = ResponseReadDeadlinePostCommitPhase::Buffering;
        c.response_read_deadline_post_commit_generation = c.response_read_deadline_generation;
        c.response_read_deadline_post_commit_episode = c.upstream_episode;
        c.response_read_deadline_post_commit_raw_header_end = raw_header_end;
        c.response_read_deadline_post_commit_declared_body = declared_body;
        c.response_read_deadline_post_commit_response_class = classification.response_class;
        c.response_read_deadline_post_commit_range_first = classification.first;
        c.response_read_deadline_post_commit_range_last = classification.last;
        c.response_read_deadline_post_commit_range_total = classification.total;
        c.response_read_deadline_post_commit_origin_received = initial_body;
        c.response_read_deadline_post_commit_downstream_submitted = 0;
        c.response_read_deadline_post_commit_downstream_completed = 0;
        c.response_read_deadline_post_commit_inflight_body = 0;
        c.response_read_deadline_post_commit_release_target = 0;
        c.response_read_deadline_post_commit_send_body = 0;
        c.response_read_deadline_post_commit_close_after_drain = false;
        c.response_read_deadline_post_commit_pump_pending = false;
        if (precise_header_timer) timer.remove(&c);
        // Whole-batch settlement owns all later Recv records.  Keeping the
        // callback detached prevents a terminal CQE from reparsing and
        // rebuilding the already pinned strict header.
        c.on_upstream_recv = nullptr;

        if (initial_body == declared_body) {
            c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
            return true;
        }
        const ResponseReadBatchOwner* batch_owner = nullptr;
        if (response_read_batch_event_index < response_read_batch_event_count) {
            const u16 owner_index =
                response_read_batch_event_owner[response_read_batch_event_index];
            if (owner_index != 0 && owner_index <= response_read_batch_owner_count)
                batch_owner = &response_read_batch_owners[owner_index - 1u];
        }
        const bool same_batch_clean_eof =
            batch_owner != nullptr && batch_owner->valid && batch_owner->conn_id == c.id &&
            batch_owner->deadline_generation == c.response_read_deadline_generation &&
            batch_owner->upstream_episode == c.upstream_episode && batch_owner->saw_positive &&
            batch_owner->positive_bytes != 0 && batch_owner->clean_eof &&
            !batch_owner->terminal_error;
        if (same_batch_clean_eof) {
            c.response_read_deadline_state = ResponseReadDeadlineState::RefreshPending;
            return true;
        }
        if (ev.result <= 0 || ev.aux != 0 || ev.upstream_episode != c.upstream_episode)
            return false;
        if (ev.more) {
            if (!c.upstream_recv_armed) return false;
        } else {
            if (c.upstream_recv_armed || c.upstream_recv_pause_cancel_pending ||
                c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
                !add_response_read_recv(c))
                return false;
            c.pending_ops++;
            c.upstream_recv_armed = true;
        }
        c.response_read_deadline_state = ResponseReadDeadlineState::RefreshPending;
        return true;
    }

    [[nodiscard]] bool complete_content_length_clean_eof_owner_is_valid(
        const Connection& c, const ResponseReadBatchOwner& owner) const {
        bool current_batch_member = false;
        if (response_read_batch_events != nullptr && response_read_batch_event_count != 0 &&
            response_read_batch_event_count <= kMaxEventsPerWait &&
            response_read_batch_owner_count != 0 &&
            response_read_batch_owner_count <= kMaxEventsPerWait) {
            for (u32 i = 0; i < response_read_batch_owner_count; ++i)
                current_batch_member =
                    current_batch_member || &response_read_batch_owners[i] == &owner;
        }
        if (!current_batch_member || !owner.valid || owner.conn_id != c.id ||
            owner.deadline_generation == 0 ||
            owner.deadline_generation != c.response_read_deadline_generation ||
            owner.upstream_episode != c.upstream_episode ||
            owner.profile != c.response_read_deadline_profile ||
            owner.method != c.response_read_deadline_method || !owner.saw_relevant ||
            !owner.saw_terminal || !owner.terminal_fault || !owner.clean_eof ||
            owner.terminal_error)
            return false;

        const u32 header = c.response_read_deadline_post_commit_raw_header_end;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        if (header == 0 || header > 0xFFFFFFFFu - received ||
            header + received != c.buffered_response_len())
            return false;
        CompleteContentLengthResponseClassification raw_classification{};
        if (!complete_content_length_raw_origin_matches_pinned(
                c, header, c.response_read_deadline_post_commit_declared_body, &raw_classification))
            return false;
        const CompleteContentLengthResponseClassification saved{
            c.response_read_deadline_post_commit_response_class,
            c.response_read_deadline_post_commit_range_first,
            c.response_read_deadline_post_commit_range_last,
            c.response_read_deadline_post_commit_range_total};
        if (!complete_content_length_response_classification_equal(raw_classification, saved))
            return false;
        // prepare_response_read_deadline_batch authenticated any retained
        // pre-batch header prefix before begin_complete_content_length_buffering
        // consumed that progress identity. The genuine active owner therefore
        // needs to prove only one contiguous current suffix ending at the exact
        // parsed header plus selected body extent.
        if (!owner.post_commit_at_start)
            return owner.saw_positive && owner.first_copy_begin <= header &&
                   owner.first_copy_begin <= 0xFFFFFFFFu - owner.positive_bytes &&
                   owner.first_copy_begin + owner.positive_bytes == header + received &&
                   owner.expected_copy_end == header + received;

        if (c.response_read_deadline_progress_generation != owner.deadline_generation ||
            c.response_read_deadline_progress_episode != owner.upstream_episode ||
            c.response_read_deadline_progress_bytes != received)
            return false;
        if (!owner.saw_positive)
            return owner.positive_bytes == 0 && owner.first_copy_begin == 0 &&
                   owner.expected_copy_end == 0;
        return owner.positive_bytes <= received &&
               owner.first_copy_begin == header + received - owner.positive_bytes &&
               owner.expected_copy_end == header + received;
    }

    [[nodiscard]] bool complete_content_length_expiry_owner_is_valid(
        const Connection& c, const ResponseReadBatchOwner& owner) const {
        bool current_batch_member = false;
        if (response_read_batch_events != nullptr && response_read_batch_event_count != 0 &&
            response_read_batch_event_count <= kMaxEventsPerWait &&
            response_read_batch_owner_count != 0 &&
            response_read_batch_owner_count <= kMaxEventsPerWait) {
            for (u32 i = 0; i < response_read_batch_owner_count; ++i)
                current_batch_member =
                    current_batch_member || &response_read_batch_owners[i] == &owner;
        }
        if (!current_batch_member || !owner.valid || !owner.saw_precise_timer ||
            !owner.precise_timer_valid || !owner.precise_timer_semantic ||
            !owner.precise_timer_target_seen || owner.precise_timer_cancel_seen ||
            owner.conn_id != c.id || owner.deadline_generation == 0 ||
            owner.deadline_generation != c.response_read_deadline_generation ||
            owner.upstream_episode != c.upstream_episode ||
            owner.profile != c.response_read_deadline_profile ||
            owner.method != c.response_read_deadline_method || owner.clean_eof ||
            owner.terminal_error || !c.response_read_timer_owner_is_neutral() ||
            c.response_read_timer_generation != owner.precise_timer_generation ||
            !response_read_deadline_uses_precise_timer(c))
            return false;

        const u32 header = c.response_read_deadline_post_commit_raw_header_end;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        if (header == 0 || header > 0xFFFFFFFFu - received ||
            header + received != c.buffered_response_len())
            return false;
        CompleteContentLengthResponseClassification raw_classification{};
        if (!complete_content_length_raw_origin_matches_pinned(
                c, header, c.response_read_deadline_post_commit_declared_body, &raw_classification))
            return false;
        const CompleteContentLengthResponseClassification saved{
            c.response_read_deadline_post_commit_response_class,
            c.response_read_deadline_post_commit_range_first,
            c.response_read_deadline_post_commit_range_last,
            c.response_read_deadline_post_commit_range_total};
        if (!complete_content_length_response_classification_equal(raw_classification, saved))
            return false;
        if (c.response_read_deadline_progress_generation != owner.deadline_generation ||
            c.response_read_deadline_progress_episode != owner.upstream_episode ||
            c.response_read_deadline_progress_bytes != received)
            return false;
        if (owner.saw_positive &&
            (owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
             owner.first_copy_begin + owner.positive_bytes != owner.expected_copy_end ||
             owner.expected_copy_end != c.buffered_response_len()))
            return false;
        if (owner.post_commit_at_start &&
            (!owner.saw_positive && (owner.positive_bytes != 0 || owner.first_copy_begin != 0 ||
                                     owner.expected_copy_end != 0) ||
             owner.saw_positive &&
                 (owner.positive_bytes > received ||
                  owner.first_copy_begin != header + received - owner.positive_bytes ||
                  owner.expected_copy_end != header + received)))
            return false;
        if (!owner.post_commit_at_start &&
            (!owner.saw_positive || owner.first_copy_begin > header ||
             owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
             owner.first_copy_begin + owner.positive_bytes != header + received))
            return false;
        if (c.response_read_timer_last_progress_ns == 0 ||
            response_read_timer_remaining_ms(
                c.response_read_timer_last_progress_ns,
                static_cast<u64>(c.response_read_deadline_seconds) * 1'000'000'000ull,
                monotonic_ns()) != 0)
            return false;

        bool saw_due_target = false;
        for (u32 ei = 0; ei < response_read_batch_event_count; ++ei) {
            const IoEvent& timer_ev = response_read_batch_events[ei];
            if (timer_ev.type != IoEventType::ResponseReadTimer ||
                timer_ev.conn_id != owner.conn_id)
                continue;
            const u32 generation =
                timer_ev.non_upstream_generation & kResponseReadTimerGenerationMask;
            if ((timer_ev.non_upstream_generation & kResponseReadTimerCancelBit) != 0 ||
                !valid_response_read_timer_transport_event(timer_ev) ||
                generation != owner.precise_timer_generation || timer_ev.result != -ETIME)
                continue;
            if (saw_due_target) return false;
            saw_due_target = true;
        }
        return saw_due_target;
    }

    // Start the first bounded downstream commit without retiring the origin.
    // The one-shot upstream recv owner remains independent and may complete
    // while the header/body sends drain; the post-commit batch ledger accounts
    // those bytes against release_target.
    [[nodiscard]] bool start_bounded_content_length_release(Connection& c, u32 target) {
        if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::Bounded ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::Buffering ||
            c.response_read_deadline_state != ResponseReadDeadlineState::Armed || target == 0 ||
            target > c.response_read_deadline_post_commit_origin_received ||
            target > c.response_read_deadline_post_commit_declared_body ||
            !response_read_deadline_post_commit_is_stable(c) || c.send_armed ||
            c.response_read_deadline_send_owner_active || c.response_header_buf.len() == 0 ||
            c.upstream_send_len != 0)
            return false;
        c.response_read_deadline_post_commit_release_target = target;
        c.response_read_deadline_post_commit_send_body = target;
        // Buffering records cumulative bytes from the raw response prefix.
        // Once the body is selected, the post-commit owner ledger is body
        // relative, so rebase its exact progress witness here.
        c.response_read_deadline_progress_generation = c.response_read_deadline_generation;
        c.response_read_deadline_progress_episode = c.upstream_episode;
        c.response_read_deadline_progress_bytes =
            c.response_read_deadline_post_commit_origin_received;
        c.response_read_deadline_post_commit_close_after_drain = false;
        c.resp_body_mode = BodyMode::ContentLength;
        c.resp_body_remaining = c.response_read_deadline_post_commit_declared_body;
        c.resp_body_sent = c.response_header_buf.len();
        c.upstream_send_len = c.response_read_deadline_post_commit_raw_header_end;
        c.proxy_resp_started = true;
        c.response_read_deadline_post_commit_phase =
            ResponseReadDeadlinePostCommitPhase::HeaderSend;
        c.transition_to_sending(&on_response_header_sent<Self>);
        return submit_send(c, c.response_header_buf.data(), c.response_header_buf.len());
    }

    [[nodiscard]] bool start_bounded_release_if_ready(Connection& c) {
        if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::Bounded ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::Buffering)
            return true;
        const u32 target =
            bounded_response_release_target(c.response_read_deadline_post_commit_raw_header_end,
                                            c.response_read_deadline_post_commit_origin_received,
                                            c.response_read_deadline_post_commit_declared_body,
                                            /*terminal=*/false);
        return target == 0 || start_bounded_content_length_release(c, target);
    }

    // Capture eligibility BEFORE retiring the exact response episode. An armed
    // multishot recv or cancel still owns the socket, so that path closes rather
    // than publishing a live descriptor to another request/shard-local borrower.
    [[nodiscard]] bool bounded_origin_can_return_idle(const Connection& c,
                                                      u32 selected,
                                                      bool close_after_drain) const {
        return bounded_get_upstream_reuse_is_admitted(c) && !close_after_drain &&
               selected == c.response_read_deadline_post_commit_declared_body &&
               c.response_read_deadline_post_commit_origin_received == selected &&
               c.upstream_keep_alive && !c.upstream_abandoned && c.request_upload_complete &&
               !c.upstream_request_incomplete && c.upstream_fd >= 0 && !c.upstream_connect_armed &&
               !c.upstream_send_armed && !c.upstream_recv_armed && !c.upstream_recv_direct_armed &&
               !c.upstream_recv_cancel_inflight && !c.upstream_recv_pause_cancel_pending &&
               !c.upstream_recv_pause_rearm_pending && !c.upstream_retirement_active &&
               !c.upstream_episode_quarantined && c.idle_return_fd < 0 && upstream && config_ptr &&
               *config_ptr == c.request_config && !is_draining();
    }

    void release_retired_bounded_origin(Connection& c, bool reusable) {
        const i32 fd = c.upstream_fd;
        c.upstream_fd = -1;
        c.upstream_reused = false;
        // Framing is already proven. Reject any queued surplus or FIN before
        // parking; take_idle repeats this probe to handle an origin closing later.
        u8 byte;
        const i32 pending =
            reusable ? static_cast<i32>(::recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)) : 0;
        if (!reusable || pending >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
            !upstream->put_idle(fd, c.upstream_idx, c.upstream_backend_idx, monotonic_secs()))
            ::close(fd);
    }

    void mark_response_read_terminal_pending(Connection& c) {
        c.response_read_deadline_post_commit_terminal_pending = true;
        response_read_terminal_scan_needed = true;
    }

    [[nodiscard]] bool finish_bounded_content_length_release(Connection& c,
                                                             u32 target,
                                                             bool close_after_drain,
                                                             bool schedule_body_pump = true) {
        if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::Bounded ||
            c.response_read_deadline_post_commit_phase ==
                ResponseReadDeadlinePostCommitPhase::None ||
            c.response_read_deadline_post_commit_phase ==
                ResponseReadDeadlinePostCommitPhase::Buffering ||
            target < c.response_read_deadline_post_commit_downstream_submitted ||
            target > c.response_read_deadline_post_commit_origin_received ||
            target > c.response_read_deadline_post_commit_declared_body ||
            !response_read_deadline_post_commit_is_stable(c))
            return false;
        if (c.response_read_deadline_post_commit_terminal_pending) {
            if (target != c.response_read_deadline_post_commit_release_target ||
                close_after_drain != c.response_read_deadline_post_commit_close_after_drain ||
                !c.response_read_timer_owner_is_neutral())
                return false;
        } else {
            if (c.response_read_timer_phase != ResponseReadTimerPhase::None &&
                (c.response_read_timer_phase != ResponseReadTimerPhase::Armed ||
                 !streaming_response_read_timer_is_stable(c) ||
                 !backend.cancel_response_read_timer(c.id, c)))
                return false;
            timer.remove(&c);
            c.response_read_deadline_post_commit_release_target = target;
            c.response_read_deadline_post_commit_send_body = target;
            c.response_read_deadline_post_commit_close_after_drain = close_after_drain;
        }
        // A terminal read can race a downstream HeaderSend/BodySend. Freeze
        // the admitted prefix now, but let that exact send owner drain before
        // asking strict upstream retirement to take custody.
        if (c.send_armed) {
            if (c.upstream_recv_armed) {
                if (!pause_upstream_recv_impl(c)) return false;
                // Reuse the exact pause-cancel CQE ledger to discard any
                // already-harvested post-terminal positive recv records.
                c.upstream_recv_terminal_stale = true;
            }
            mark_response_read_terminal_pending(c);
            return true;
        }
        const bool reusable_origin = bounded_origin_can_return_idle(c, target, close_after_drain);
        const bool recv_owned = c.upstream_recv_armed;
        if (!begin_strict_upstream_retirement(c)) return false;
        if (recv_owned) c.upstream_recv_armed = false;
        c.on_upstream_recv = nullptr;
        c.upstream_abandoned = true;
        c.upstream_keep_alive = false;
        c.upstream_start_us = 0;
        release_retired_bounded_origin(c, reusable_origin);
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
        c.response_read_deadline_post_commit_terminal_pending = false;
        // A caller already pumping this response must not queue a second pump
        // behind the BodySend it is about to submit.
        if (schedule_body_pump && c.response_read_deadline_post_commit_phase ==
                                      ResponseReadDeadlinePostCommitPhase::WaitingBody)
            defer_response_read_deadline_body_pump(c);
        return true;
    }

    [[nodiscard]] bool start_complete_content_length_send(
        Connection& c,
        CompleteContentLengthTerminalDisposition disposition,
        const ResponseReadBatchOwner* terminal_owner = nullptr) {
        if (!forward_response_buffering_uses_content_length_machinery(
                c.response_read_deadline_buffering) ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::Buffering ||
            (c.response_read_deadline_state != ResponseReadDeadlineState::BatchPending &&
             c.response_read_deadline_state != ResponseReadDeadlineState::BodyComplete &&
             c.response_read_deadline_state != ResponseReadDeadlineState::RefreshPending &&
             c.response_read_deadline_state != ResponseReadDeadlineState::ExpiryPending) ||
            !response_read_deadline_post_commit_is_stable(c))
            return false;
        const u32 received = c.response_read_deadline_post_commit_origin_received;
        const u32 declared = c.response_read_deadline_post_commit_declared_body;
        u32 body_to_send = 0;
        bool close_after_drain = true;
        switch (disposition) {
            case CompleteContentLengthTerminalDisposition::CompleteBody:
                if (terminal_owner != nullptr || received != declared) return false;
                body_to_send = declared;
                close_after_drain = c.response_read_deadline_upload.downstream_close;
                break;
            case CompleteContentLengthTerminalDisposition::CleanUpstreamEof:
                if (terminal_owner == nullptr || received >= declared ||
                    (received == 0 &&
                     c.response_read_deadline_post_commit_response_class ==
                         CompleteContentLengthResponseClass::CoherentSingleRange206) ||
                    !complete_content_length_clean_eof_owner_is_valid(c, *terminal_owner))
                    return false;
                body_to_send =
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded
                        ? c.response_read_deadline_post_commit_release_target
                        : received;
                break;
            case CompleteContentLengthTerminalDisposition::InactivityExpiry:
                if (received >= declared) return false;
                if (c.response_read_deadline_post_commit_response_class ==
                    CompleteContentLengthResponseClass::CoherentSingleRange206) {
                    if (terminal_owner == nullptr || received == 0 ||
                        !complete_content_length_expiry_owner_is_valid(c, *terminal_owner))
                        return false;
                } else if (terminal_owner != nullptr) {
                    return false;
                }
                break;
            default:
                return false;
        }
        if (body_to_send > c.response_read_deadline_post_commit_origin_received ||
            (disposition == CompleteContentLengthTerminalDisposition::CleanUpstreamEof &&
             c.response_read_deadline_post_commit_response_class ==
                 CompleteContentLengthResponseClass::CoherentSingleRange206 &&
             !bodyless_get_complete_content_length_precise_buffering_is_stable(c)) ||
            (!close_after_drain &&
             (body_to_send != c.response_read_deadline_post_commit_declared_body ||
              body_to_send != c.response_read_deadline_post_commit_origin_received)))
            return false;

        // Complete-buffered sends may reuse the spare tail of the pinned
        // response-header slice, but only when all existing downstream
        // transport ownership is neutral. A capacity miss is an ordinary
        // fallback; stale ownership is a hard failure for either path.
        if (c.id >= connection_capacity) return false;
        const auto& send_state = backend.send_state[c.id];
        if (c.send_armed || c.send_progress != 0 || c.on_send != nullptr ||
            c.response_read_deadline_send_owner_active ||
            c.response_read_deadline_send_owner_generation != 0 ||
            c.response_read_deadline_send_deadline_generation != 0 ||
            c.response_read_deadline_send_upstream_episode != 0 ||
            c.response_read_deadline_send_src != nullptr ||
            c.response_read_deadline_send_len != 0 || c.response_read_deadline_send_fd != -1 ||
            c.response_read_deadline_send_kind != ResponseReadDeadlineSendKind::None ||
            c.response_read_deadline_send_close_generation != 0 ||
            c.response_read_deadline_send_close_target_owned ||
            c.response_read_deadline_send_close_cancel_owned || send_state.remaining != 0)
            return false;

        // This is intentionally read-only and evaluated before timer/send
        // ownership changes or origin retirement. Noneligible responses keep
        // the established header-then-body path without staging any bytes.
        enum class CombinedSendEligibility : u8 { Eligible, Fallback, Invalid };
        const auto combined_send_eligibility = [&]() {
            if (c.response_body_tail.size != 0) return CombinedSendEligibility::Fallback;
            if (disposition != CompleteContentLengthTerminalDisposition::CompleteBody ||
                terminal_owner != nullptr || received != declared || declared == 0 ||
                c.response_read_deadline_post_commit_response_class !=
                    CompleteContentLengthResponseClass::BoundedPositiveBody)
                return CombinedSendEligibility::Fallback;
            const bool precise_get_profile =
                c.response_read_deadline_profile ==
                    ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                c.response_read_deadline_method == static_cast<u8>(LogHttpMethod::Get) &&
                c.response_read_deadline_route_method == kRouteMethodGet &&
                c.req_method == static_cast<u8>(LogHttpMethod::Get) && c.pipeline_depth == 0 &&
                c.http1_pipeline_request_generation == 0 && c.pipeline_stash_len == 0 &&
                bodyless_get_complete_content_length_request_policy_is_admitted(
                    c.request_policy_id) &&
                c.response_read_deadline_upload.request_policy_id == c.request_policy_id;
            if (!precise_get_profile) return CombinedSendEligibility::Fallback;
            if (!bodyless_get_complete_content_length_precise_buffering_is_stable(c))
                return CombinedSendEligibility::Invalid;
            const u32 header_len = c.response_header_buf.len();
            const u32 raw_header_end = c.response_read_deadline_post_commit_raw_header_end;
            if (c.response_header_buf.data() == nullptr || c.upstream_recv_buf.data() == nullptr ||
                header_len == 0 || header_len > c.response_header_buf.capacity() ||
                raw_header_end == 0 || raw_header_end > c.buffered_response_len() ||
                declared != c.buffered_response_len() - raw_header_end)
                return CombinedSendEligibility::Invalid;
            if (declared > c.response_header_buf.capacity() - header_len)
                return CombinedSendEligibility::Fallback;
            return CombinedSendEligibility::Eligible;
        };
        const CombinedSendEligibility combined_send_state = combined_send_eligibility();
        if (combined_send_state == CombinedSendEligibility::Invalid) return false;
        const bool combined_send = combined_send_state == CombinedSendEligibility::Eligible;
        if (c.response_read_timer_phase != ResponseReadTimerPhase::None) {
            if (c.response_read_timer_phase != ResponseReadTimerPhase::Armed ||
                !bodyless_get_complete_content_length_precise_buffering_is_stable(c) ||
                !backend.cancel_response_read_timer(c.id, c))
                return false;
        }
        timer.remove(&c);
        const bool reusable_origin =
            bounded_origin_can_return_idle(c, body_to_send, close_after_drain);
        const bool recv_owned = c.upstream_recv_armed;
        if (!begin_strict_upstream_retirement(c)) return false;
        // No buffered response byte may become visible while its origin Recv
        // episode is live. Ownership now resides in the retirement ledger for
        // both successful and truncating dispositions.
        if (recv_owned) c.upstream_recv_armed = false;
        c.on_upstream_recv = nullptr;
        c.upstream_abandoned = true;
        c.upstream_keep_alive = false;
        c.upstream_start_us = 0;
        release_retired_bounded_origin(c, reusable_origin);
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        // BodyComplete is the settled terminal state. The typed disposition,
        // selected length, and close-after-drain bit distinguish a complete
        // body from an authenticated clean-EOF prefix during asynchronous Send.
        c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
        c.response_read_deadline_post_commit_send_body = body_to_send;
        if (c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded)
            c.response_read_deadline_post_commit_release_target = body_to_send;
        c.response_read_deadline_post_commit_close_after_drain = close_after_drain;
        c.resp_body_mode = BodyMode::ContentLength;
        c.upstream_keep_alive = false;
        c.proxy_resp_started = true;
        if (combined_send) {
            const u32 header_len = c.response_header_buf.len();
            const u32 raw_header_end = c.response_read_deadline_post_commit_raw_header_end;
            // Use the header buffer's writable tail only as I/O staging. Keep
            // its logical length equal to the pure rewritten header so all
            // pinned-header proofs and response accounting retain their
            // existing meaning.
            __builtin_memcpy(c.response_header_buf.write_ptr(),
                             c.upstream_recv_buf.data() + raw_header_end,
                             body_to_send);
            c.response_read_deadline_post_commit_phase =
                ResponseReadDeadlinePostCommitPhase::CombinedSend;
            c.response_read_deadline_post_commit_downstream_submitted = body_to_send;
            c.response_read_deadline_post_commit_downstream_completed = 0;
            c.response_read_deadline_post_commit_inflight_body = body_to_send;
            c.resp_body_remaining = 0;
            c.resp_body_sent = header_len + body_to_send;
            c.upstream_send_len = raw_header_end + body_to_send;
            c.transition_to_sending(&on_complete_response_sent<Self>);
            return submit_send(c, c.response_header_buf.data(), header_len + body_to_send);
        }

        c.response_read_deadline_post_commit_phase =
            ResponseReadDeadlinePostCommitPhase::HeaderSend;
        c.resp_body_remaining =
            c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded
                ? c.response_read_deadline_post_commit_declared_body
                : body_to_send;
        c.resp_body_sent = c.response_header_buf.len();
        c.upstream_send_len = c.response_read_deadline_post_commit_raw_header_end;
        c.transition_to_sending(&on_response_header_sent<Self>);
        return submit_send(c, c.response_header_buf.data(), c.response_header_buf.len());
    }

    void defer_response_read_deadline_body_pump(Connection& c) {
        if (c.id >= connection_capacity || conns.data() == nullptr || &conns[c.id] != &c ||
            body_pump_ready_words.data() == nullptr)
            return;
        c.response_read_deadline_post_commit_pump_pending = true;
        body_pump_ready_words[c.id >> 6] |= u64{1} << (c.id & 63u);
        response_read_deadline_body_pump_pending = true;
    }

    [[nodiscard]] bool retire_response_read_deadline_origin(Connection& c) {
        if (c.response_read_deadline_state != ResponseReadDeadlineState::BodyComplete ||
            !response_read_deadline_post_commit_is_stable(c) || c.send_armed ||
            c.response_read_deadline_post_commit_origin_received !=
                c.response_read_deadline_post_commit_declared_body ||
            c.response_read_deadline_post_commit_downstream_completed !=
                c.response_read_deadline_post_commit_declared_body ||
            c.response_read_deadline_post_commit_inflight_body != 0 ||
            c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight)
            return false;
        const bool already_retired_buffered_origin =
            forward_response_buffering_uses_content_length_machinery(
                c.response_read_deadline_buffering) &&
            c.response_read_deadline_post_commit_episode == c.upstream_retiring_episode &&
            c.upstream_fd < 0 && c.upstream_abandoned;
        if (!c.upstream_retirement_active && !already_retired_buffered_origin) {
            c.on_upstream_recv = nullptr;
            c.upstream_abandoned = true;
            c.upstream_keep_alive = false;
            if (!begin_strict_upstream_retirement(c)) return false;
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
            if (c.upstream_slot_held) {
                upstream_release(c.upstream_slot_uid);
                c.upstream_slot_held = false;
            }
        } else if (!already_retired_buffered_origin) {
            return false;
        }
        c.clear_response_read_deadline();
        return true;
    }

    [[nodiscard]] bool settle_precise_complete_content_length_buffering(
        Connection& c, const ResponseReadBatchOwner& owner) {
        if (!owner.valid || owner.conn_id != c.id || owner.deadline_generation == 0 ||
            owner.deadline_generation != c.response_read_deadline_generation ||
            owner.upstream_episode != c.upstream_episode ||
            owner.profile != ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
            owner.method != static_cast<u8>(LogHttpMethod::Get) ||
            !bodyless_get_complete_content_length_precise_buffering_is_stable(c) ||
            (owner.saw_precise_timer ? !response_read_deadline_batch_uses_precise_timer(c, owner)
                                     : !response_read_deadline_uses_precise_timer(c)))
            return false;

        bool saw_timer_target = false;
        if (owner.saw_precise_timer) {
            if (!owner.precise_timer_valid || response_read_batch_events == nullptr) return false;
            for (u32 ei = 0; ei < response_read_batch_event_count; ++ei) {
                const IoEvent& timer_ev = response_read_batch_events[ei];
                if (timer_ev.type != IoEventType::ResponseReadTimer ||
                    timer_ev.conn_id != owner.conn_id)
                    continue;
                const u32 generation =
                    timer_ev.non_upstream_generation & kResponseReadTimerGenerationMask;
                const bool cancel =
                    (timer_ev.non_upstream_generation & kResponseReadTimerCancelBit) != 0;
                if (!valid_response_read_timer_transport_event(timer_ev) || cancel ||
                    generation != owner.precise_timer_generation ||
                    !c.consume_response_read_timer_completion(timer_ev.non_upstream_generation) ||
                    timer_ev.result != -ETIME || saw_timer_target)
                    return false;
                saw_timer_target = true;
            }
            if (!saw_timer_target) return false;
            if (c.response_read_timer_owner_is_neutral()) maybe_publish_http1_boundary_ready(c);
        }

        const u32 header = c.response_read_deadline_post_commit_raw_header_end;
        const u32 declared = c.response_read_deadline_post_commit_declared_body;
        u32 received = c.response_read_deadline_post_commit_origin_received;
        if (header == 0 || header > c.buffered_response_len() || received > declared) return false;
        if (owner.saw_positive) {
            if (owner.terminal_error || owner.expected_copy_end != c.buffered_response_len() ||
                owner.first_copy_begin > 0xFFFFFFFFu - owner.positive_bytes ||
                owner.first_copy_begin + owner.positive_bytes != owner.expected_copy_end)
                return false;
            if (owner.post_commit_at_start) {
                if (owner.positive_bytes > declared - received || header > 0xFFFFFFFFu - received ||
                    owner.first_copy_begin != header + received)
                    return false;
                received += owner.positive_bytes;
                c.response_read_deadline_post_commit_origin_received = received;
            } else if (received != c.buffered_response_len() - header) {
                return false;
            }
            c.response_read_deadline_progress_generation = owner.deadline_generation;
            c.response_read_deadline_progress_episode = owner.upstream_episode;
            c.response_read_deadline_progress_bytes = received;
            c.response_read_timer_last_progress_ns = monotonic_ns();
        } else if (!owner.post_commit_at_start || owner.terminal_error) {
            return false;
        }

        if (received == declared) {
            c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
            return start_complete_content_length_send(
                c, CompleteContentLengthTerminalDisposition::CompleteBody);
        }
        if (owner.clean_eof) {
            c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
            return start_complete_content_length_send(
                c, CompleteContentLengthTerminalDisposition::CleanUpstreamEof, &owner);
        }
        if (owner.terminal_fault) return false;
        if (owner.saw_terminal && !c.upstream_recv_armed) {
            if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_pause_rearm_pending ||
                c.upstream_recv_cancel_inflight ||
                !add_response_read_recv(c, /*direct_buffered_body=*/owner.post_commit_at_start))
                return false;
            c.pending_ops++;
            c.upstream_recv_armed = true;
        }

        if (saw_timer_target) {
            const u64 now_ns = monotonic_ns();
            const u64 timeout_ns =
                static_cast<u64>(c.response_read_deadline_seconds) * 1'000'000'000ull;
            if (response_read_timer_remaining_ms(
                    c.response_read_timer_last_progress_ns, timeout_ns, now_ns) == 0) {
                c.response_read_deadline_state = ResponseReadDeadlineState::ExpiryPending;
                // Keep the authenticated active-batch owner in scope while
                // selecting the generic expiry disposition.  Deferring this
                // to the connection-only expiry scan would lose the genuine
                // -ETIME witness and allow ExpiryPending alone to authorize
                // publication.
                const bool coherent206 = c.response_read_deadline_post_commit_response_class ==
                                         CompleteContentLengthResponseClass::CoherentSingleRange206;
                return start_complete_content_length_send(
                    c,
                    CompleteContentLengthTerminalDisposition::InactivityExpiry,
                    coherent206 ? &owner : nullptr);
            }
            if (!rearm_precise_response_read_timer(c, now_ns)) return false;
        }
        c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
        if (!start_bounded_release_if_ready(c)) return false;
        return true;
    }

    void settle_response_read_deadline_batch() {
        for (u32 oi = 0; oi < response_read_batch_owner_count; ++oi) {
            auto& owner = response_read_batch_owners[oi];
            if (owner.conn_id >= slots_initialized) continue;
            Connection& c = conns[owner.conn_id];
            if (owner.bounded_terminal_prospective) {
                if (!owner.valid || c.fd < 0 || !owner.bounded_terminal_timer_seen ||
                    !owner.bounded_terminal_recv_seen || c.upstream_recv_armed ||
                    !c.response_read_timer_owner_is_neutral() ||
                    c.response_read_deadline_state != ResponseReadDeadlineState::Armed ||
                    !finish_bounded_content_length_release(
                        c,
                        c.response_read_deadline_post_commit_release_target,
                        /*close_after_drain=*/true))
                    close_conn(c);
                continue;
            }
            if (owner.bounded_terminal_custody) continue;
            const bool precise_complete_content_length =
                c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::Buffering &&
                c.response_read_deadline_profile ==
                    ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                forward_response_buffering_uses_content_length_machinery(
                    c.response_read_deadline_buffering) &&
                c.response_read_deadline_method == static_cast<u8>(LogHttpMethod::Get) &&
                (owner.saw_precise_timer ||
                 c.response_read_timer_phase == ResponseReadTimerPhase::Armed);
            if (precise_complete_content_length) {
                if (!settle_precise_complete_content_length_buffering(c, owner) && c.fd >= 0)
                    close_conn(c);
                continue;
            }
            if (owner.saw_precise_timer) {
                // Capture the complete logical+transport proof before timer
                // CQEs consume their kernel custody. For a cross-batch prefix,
                // this intentionally validates the committed pre-batch copy
                // boundary; commit below advances it transactionally.
                const bool precise_active =
                    response_read_deadline_batch_uses_precise_timer(c, owner);
                bool custody_ok = owner.valid;
                bool saw_semantic_target = false;
                bool saw_canceled_target = false;
                if (response_read_batch_events != nullptr) {
                    for (u32 ei = 0; ei < response_read_batch_event_count; ++ei) {
                        const IoEvent& timer_ev = response_read_batch_events[ei];
                        if (timer_ev.type != IoEventType::ResponseReadTimer ||
                            timer_ev.conn_id != owner.conn_id)
                            continue;
                        const u32 generation =
                            timer_ev.non_upstream_generation & kResponseReadTimerGenerationMask;
                        if (!valid_response_read_timer_transport_event(timer_ev) ||
                            generation != owner.precise_timer_generation ||
                            !c.consume_response_read_timer_completion(
                                timer_ev.non_upstream_generation)) {
                            custody_ok = false;
                            continue;
                        }
                        const bool cancel =
                            (timer_ev.non_upstream_generation & kResponseReadTimerCancelBit) != 0;
                        if (cancel) {
                            if (timer_ev.result != 0 && timer_ev.result != -ENOENT)
                                custody_ok = false;
                        } else if (timer_ev.result != -ETIME && timer_ev.result != -ECANCELED) {
                            custody_ok = false;
                        }
                        if (!cancel && owner.precise_timer_semantic) {
                            // -ECANCELED is a custody-only target result (the
                            // cancel won the race); only natural -ETIME can
                            // drive logical expiry.
                            if (timer_ev.result == -ETIME)
                                saw_semantic_target = true;
                            else if (timer_ev.result == -ECANCELED)
                                saw_canceled_target = true;
                        }
                    }
                }
                // A disarmed deadline may retain only timer transport custody
                // while an HTTP/1 boundary is parked.  Duplicate or foreign
                // CQEs can invalidate the batch proof without consuming the
                // real target/cancel records; once those real owners are
                // nevertheless neutral, release the independent boundary wait.
                // Active semantic timer batches still follow the strict
                // custody/owner validation and fail-closed paths below.
                if (!owner.precise_timer_semantic && c.response_read_timer_owner_is_neutral())
                    maybe_publish_http1_boundary_ready(c);
                if (!custody_ok) {
                    if (owner.precise_timer_semantic && c.fd >= 0) close_conn(c);
                    continue;
                }
                const bool bounded_post_commit_clean_eof =
                    owner.valid && owner.clean_eof && owner.post_commit_at_start &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    post_commit_incremental_release_active(c) &&
                    streaming_response_read_timer_is_stable(c);
                if (!owner.valid ||
                    (owner.saw_terminal && !owner.saw_positive && !bounded_post_commit_clean_eof)) {
                    if (owner.precise_timer_semantic && c.fd >= 0) close_conn(c);
                    continue;
                }
                if (c.response_read_timer_owner_is_neutral()) maybe_publish_http1_boundary_ready(c);
                // The logical deadline was already disarmed before this
                // custody-only CQE was harvested. No timer result can affect
                // the successor/504 state; only the owner barrier is drained.
                if (!owner.precise_timer_semantic) continue;
                if (saw_canceled_target && precise_active) {
                    if (streaming_response_read_timer_is_stable(c)) {
                        // An Armed streaming owner has not requested cancellation.
                        // A canceled semantic target cannot leave a timerless stream.
                        if (c.fd >= 0) close_conn(c);
                        continue;
                    }
                    // A cancelled target can arrive before its cancel CQE.
                    // Keep the logical identity until the second owner drains;
                    // only a fully neutral transport owner may be cleared here.
                    if (!c.response_read_timer_cancel_owned) c.clear_response_read_deadline();
                    continue;
                }
                if (!precise_active) {
                    // A semantic timer-only owner must not be left in
                    // BatchPending when its full HeaderOnlyHead proof was
                    // invalidated during the wait.  The small timer key was
                    // enough to consume custody, but it cannot authorize a
                    // rearm or ordinary expiry after the full proof fails.
                    // A response in this same batch disarms the logical
                    // deadline and leaves a downstream Sending owner; that
                    // path has saw_relevant set (or is no longer
                    // BatchPending) and remains custody-only here.
                    if ((saw_semantic_target || saw_canceled_target) && !owner.saw_relevant &&
                        c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending &&
                        c.fd >= 0)
                        close_conn(c);
                    continue;
                }
                const bool streaming_progress = post_commit_incremental_release_active(c);
                const bool bounded_clean_eof =
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    owner.clean_eof;
                if ((owner.saw_positive || bounded_clean_eof) &&
                    !(streaming_progress
                          ? commit_response_read_deadline_streaming_progress(c, owner)
                          : commit_response_read_deadline_incomplete_progress(c, owner))) {
                    if (c.fd >= 0) close_conn(c);
                    continue;
                }
                if (streaming_progress &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    owner.saw_positive &&
                    c.response_read_deadline_post_commit_origin_received <
                        c.response_read_deadline_post_commit_declared_body) {
                    const u32 target = bounded_response_release_target(
                        c.response_read_deadline_post_commit_raw_header_end,
                        c.response_read_deadline_post_commit_origin_received,
                        c.response_read_deadline_post_commit_declared_body,
                        /*terminal=*/false);
                    if (target > c.response_read_deadline_post_commit_release_target) {
                        c.response_read_deadline_post_commit_release_target = target;
                        c.response_read_deadline_post_commit_send_body = target;
                    }
                }
                if (streaming_progress &&
                    c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    owner.clean_eof &&
                    c.response_read_deadline_post_commit_origin_received <
                        c.response_read_deadline_post_commit_declared_body) {
                    const u32 admitted = c.response_read_deadline_post_commit_release_target;
                    if (!finish_bounded_content_length_release(c,
                                                               admitted,
                                                               /*close_after_drain=*/true)) {
                        close_conn(c);
                        continue;
                    }
                    continue;
                }
                if (streaming_progress && c.response_read_deadline_post_commit_origin_received ==
                                              c.response_read_deadline_post_commit_declared_body) {
                    if (c.response_read_deadline_buffering ==
                        ForwardResponseBufferingMode::Bounded) {
                        if (!finish_bounded_content_length_release(
                                c,
                                c.response_read_deadline_post_commit_declared_body,
                                /*close_after_drain=*/false)) {
                            close_conn(c);
                            continue;
                        }
                        continue;
                    }
                    c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
                    if (c.response_read_timer_phase == ResponseReadTimerPhase::Armed &&
                        !backend.cancel_response_read_timer(c.id, c)) {
                        close_conn(c);
                        continue;
                    }
                    timer.remove(&c);
                    if (c.response_read_deadline_post_commit_phase ==
                        ResponseReadDeadlinePostCommitPhase::WaitingBody)
                        defer_response_read_deadline_body_pump(c);
                    continue;
                }
                if (streaming_progress && owner.saw_terminal && !c.upstream_recv_armed) {
                    if ((owner.terminal_fault && !owner.clean_eof) ||
                        c.upstream_recv_pause_cancel_pending ||
                        c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
                        !add_response_read_recv(c)) {
                        close_conn(c);
                        continue;
                    }
                    c.pending_ops++;
                    c.upstream_recv_armed = true;
                }
                if (!saw_semantic_target) continue;
                const u64 now_ns = monotonic_ns();
                const u64 timeout_ns =
                    static_cast<u64>(c.response_read_deadline_seconds) * 1'000'000'000ull;
                const u64 last = c.response_read_timer_last_progress_ns;
                const bool due = response_read_timer_remaining_ms(last, timeout_ns, now_ns) == 0;
                if (due) {
                    c.response_read_deadline_state = ResponseReadDeadlineState::ExpiryPending;
                    response_read_deadline_expiry_pending = true;
                } else if (!rearm_precise_response_read_timer(c, now_ns)) {
                    if (c.fd >= 0) close_conn(c);
                } else {
                    c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                }
                if (streaming_progress && c.fd >= 0 &&
                    c.response_read_deadline_state == ResponseReadDeadlineState::Armed &&
                    c.response_read_deadline_post_commit_phase ==
                        ResponseReadDeadlinePostCommitPhase::WaitingBody) {
                    if (c.response_read_deadline_buffering ==
                        ForwardResponseBufferingMode::Bounded) {
                        const u32 target = bounded_response_release_target(
                            c.response_read_deadline_post_commit_raw_header_end,
                            c.response_read_deadline_post_commit_origin_received,
                            c.response_read_deadline_post_commit_declared_body,
                            /*terminal=*/false);
                        if (target > c.response_read_deadline_post_commit_release_target) {
                            c.response_read_deadline_post_commit_release_target = target;
                            c.response_read_deadline_post_commit_send_body = target;
                            defer_response_read_deadline_body_pump(c);
                        }
                    } else {
                        defer_response_read_deadline_body_pump(c);
                    }
                }
                continue;
            }
            if (owner.valid && c.id == owner.conn_id &&
                c.response_read_deadline_post_commit_terminal_pending &&
                c.response_read_deadline_generation == owner.deadline_generation &&
                c.upstream_episode == owner.upstream_episode)
                continue;
            if (!owner.valid) continue;
            const bool key_stable =
                c.id == owner.conn_id &&
                c.response_read_deadline_generation == owner.deadline_generation &&
                c.upstream_episode == owner.upstream_episode &&
                c.response_read_deadline_profile == owner.profile &&
                c.response_read_deadline_method == owner.method;
            if (key_stable && c.response_read_deadline_post_commit_terminal_pending) continue;
            const bool initial_buffered_clean_eof =
                c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::Buffering &&
                c.response_read_deadline_state == ResponseReadDeadlineState::RefreshPending &&
                owner.clean_eof;
            if (key_stable && !owner.post_commit_at_start &&
                (c.response_read_deadline_post_commit_phase ==
                     ResponseReadDeadlinePostCommitPhase::HeaderSend ||
                 c.response_read_deadline_post_commit_phase ==
                     ResponseReadDeadlinePostCommitPhase::Buffering) &&
                (c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete ||
                 initial_buffered_clean_eof)) {
                c.response_read_deadline_progress_generation = owner.deadline_generation;
                c.response_read_deadline_progress_episode = owner.upstream_episode;
                c.response_read_deadline_progress_bytes =
                    c.response_read_deadline_post_commit_origin_received;
                if (c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::Buffering) {
                    const u32 received = c.response_read_deadline_post_commit_origin_received;
                    const u32 declared = c.response_read_deadline_post_commit_declared_body;
                    const bool complete = received == declared;
                    if (owner.terminal_error || received > declared ||
                        (!complete && !owner.clean_eof) ||
                        !start_complete_content_length_send(
                            c,
                            complete ? CompleteContentLengthTerminalDisposition::CompleteBody
                                     : CompleteContentLengthTerminalDisposition::CleanUpstreamEof,
                            complete ? nullptr : &owner))
                        close_conn(c);
                }
            } else if (key_stable && owner.body_complete_at_start &&
                       c.response_read_deadline_post_commit_phase !=
                           ResponseReadDeadlinePostCommitPhase::None &&
                       c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending) {
                if (owner.positive_bytes != 0) {
                    close_conn(c);
                    continue;
                }
                c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
            } else if (key_stable && owner.post_commit_at_start &&
                       c.response_read_deadline_post_commit_phase ==
                           ResponseReadDeadlinePostCommitPhase::Buffering &&
                       (c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                        c.response_read_deadline_state ==
                            ResponseReadDeadlineState::RefreshPending)) {
                const u32 received = c.response_read_deadline_post_commit_origin_received;
                const u32 declared = c.response_read_deadline_post_commit_declared_body;
                if (owner.positive_bytes > declared - received) {
                    close_conn(c);
                    continue;
                }
                c.response_read_deadline_post_commit_origin_received =
                    received + owner.positive_bytes;
                c.response_read_deadline_progress_generation = owner.deadline_generation;
                c.response_read_deadline_progress_episode = owner.upstream_episode;
                c.response_read_deadline_progress_bytes =
                    c.response_read_deadline_post_commit_origin_received;
                if (owner.terminal_error) {
                    close_conn(c);
                    continue;
                }
                if (c.response_read_deadline_post_commit_origin_received == declared) {
                    c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
                    if (!start_complete_content_length_send(
                            c, CompleteContentLengthTerminalDisposition::CompleteBody))
                        close_conn(c);
                    continue;
                }
                if (owner.clean_eof) {
                    c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
                    if (!start_complete_content_length_send(
                            c, CompleteContentLengthTerminalDisposition::CleanUpstreamEof, &owner))
                        close_conn(c);
                    continue;
                }
                // The body recv is a one-shot provided-buffer receive. Once
                // its natural terminal CQE has settled with positive progress,
                // the next episode can target the chain tail directly.
                if (owner.saw_terminal && !c.upstream_recv_armed) {
                    if (c.upstream_recv_pause_cancel_pending ||
                        c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
                        owner.terminal_fault || owner.clean_eof || !owner.saw_positive ||
                        !add_response_read_recv(c, /*direct_buffered_body=*/true)) {
                        close_conn(c);
                        continue;
                    }
                    c.pending_ops++;
                    c.upstream_recv_armed = true;
                }
                const bool streaming_timer = post_commit_incremental_release_active(c);
                if (streaming_timer) {
                    if (!promote_streaming_response_read_timer(c)) {
                        close_conn(c);
                        continue;
                    }
                } else if (!response_read_deadline_uses_precise_timer(c)) {
                    timer.refresh(&c, c.response_read_deadline_seconds);
                }
                c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                if (c.fd >= 0 && !start_bounded_release_if_ready(c)) close_conn(c);
            } else if (key_stable && owner.post_commit_at_start &&
                       c.response_read_deadline_post_commit_phase !=
                           ResponseReadDeadlinePostCommitPhase::None &&
                       (c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                        c.response_read_deadline_state ==
                            ResponseReadDeadlineState::RefreshPending)) {
                const u32 received = c.response_read_deadline_post_commit_origin_received;
                const u32 declared = c.response_read_deadline_post_commit_declared_body;
                if (owner.positive_bytes > declared - received) {
                    close_conn(c);
                    continue;
                }
                c.response_read_deadline_post_commit_origin_received =
                    received + owner.positive_bytes;
                c.response_read_deadline_progress_generation = owner.deadline_generation;
                c.response_read_deadline_progress_episode = owner.upstream_episode;
                c.response_read_deadline_progress_bytes =
                    c.response_read_deadline_post_commit_origin_received;
                if (owner.positive_bytes != 0 &&
                    c.response_read_deadline_profile ==
                        ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                    (c.response_read_deadline_buffering == ForwardResponseBufferingMode::None ||
                     c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded))
                    c.response_read_timer_last_progress_ns = monotonic_ns();
                if (c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded) {
                    if (owner.terminal_error) {
                        close_conn(c);
                        continue;
                    }
                    if (c.response_read_deadline_post_commit_origin_received == declared) {
                        if (!finish_bounded_content_length_release(
                                c, declared, /*close_after_drain=*/false))
                            close_conn(c);
                        continue;
                    }
                    if (owner.clean_eof) {
                        const u32 admitted = c.response_read_deadline_post_commit_release_target;
                        if (!finish_bounded_content_length_release(
                                c, admitted, /*close_after_drain=*/true))
                            close_conn(c);
                        continue;
                    }
                    const u32 target = bounded_response_release_target(
                        c.response_read_deadline_post_commit_raw_header_end,
                        c.response_read_deadline_post_commit_origin_received,
                        declared,
                        /*terminal=*/false);
                    const bool release_ready =
                        target > c.response_read_deadline_post_commit_release_target;
                    if (release_ready) {
                        c.response_read_deadline_post_commit_release_target = target;
                        c.response_read_deadline_post_commit_send_body = target;
                    }
                    if (owner.terminal_fault) {
                        close_conn(c);
                        continue;
                    }
                    if (owner.saw_terminal && !c.upstream_recv_armed) {
                        if (c.upstream_recv_pause_cancel_pending ||
                            c.upstream_recv_pause_rearm_pending ||
                            c.upstream_recv_cancel_inflight || !add_response_read_recv(c)) {
                            close_conn(c);
                            continue;
                        }
                        c.pending_ops++;
                        c.upstream_recv_armed = true;
                    }
                    if (!response_read_deadline_uses_precise_timer(c))
                        timer.refresh(&c, c.response_read_deadline_seconds);
                    c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                    if (release_ready && c.response_read_deadline_post_commit_phase ==
                                             ResponseReadDeadlinePostCommitPhase::WaitingBody)
                        defer_response_read_deadline_body_pump(c);
                    continue;
                }
                if (c.response_read_deadline_post_commit_origin_received == declared) {
                    c.response_read_deadline_state = ResponseReadDeadlineState::BodyComplete;
                    if (c.response_read_deadline_buffering == ForwardResponseBufferingMode::None &&
                        c.response_read_timer_phase == ResponseReadTimerPhase::Armed &&
                        !backend.cancel_response_read_timer(c.id, c)) {
                        close_conn(c);
                        continue;
                    }
                } else {
                    if (owner.terminal_fault) {
                        close_conn(c);
                        continue;
                    }
                    if (owner.saw_terminal && !c.upstream_recv_armed) {
                        if (c.upstream_recv_pause_cancel_pending ||
                            c.upstream_recv_pause_rearm_pending ||
                            c.upstream_recv_cancel_inflight || !add_response_read_recv(c)) {
                            close_conn(c);
                            continue;
                        }
                        c.pending_ops++;
                        c.upstream_recv_armed = true;
                    }
                    const bool streaming_timer = post_commit_incremental_release_active(c);
                    if (streaming_timer) {
                        if (!promote_streaming_response_read_timer(c)) {
                            close_conn(c);
                            continue;
                        }
                    } else if (!response_read_deadline_uses_precise_timer(c)) {
                        timer.refresh(&c, c.response_read_deadline_seconds);
                    }
                    c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                }
                if (c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::WaitingBody)
                    defer_response_read_deadline_body_pump(c);
            } else if (key_stable &&
                       c.response_read_deadline_state ==
                           ResponseReadDeadlineState::RefreshPending &&
                       c.upstream_recv_armed && response_read_deadline_identity_is_stable(c)) {
                if (c.buffered_response_len() == 0) {
                    close_conn(c);
                    continue;
                }
                if (response_read_deadline_uses_precise_timer(c) &&
                    c.response_read_deadline_post_commit_phase ==
                        ResponseReadDeadlinePostCommitPhase::None) {
                    if (!commit_response_read_deadline_incomplete_progress(c, owner)) {
                        close_conn(c);
                        continue;
                    }
                    c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                    continue;
                }
                c.response_read_deadline_progress_generation = owner.deadline_generation;
                c.response_read_deadline_progress_episode = owner.upstream_episode;
                c.response_read_deadline_progress_bytes =
                    c.response_read_deadline_post_commit_phase ==
                            ResponseReadDeadlinePostCommitPhase::None
                        ? c.buffered_response_len()
                        : c.response_read_deadline_post_commit_origin_received;
                const bool streaming_timer = post_commit_incremental_release_active(c);
                if (streaming_timer) {
                    if (!promote_streaming_response_read_timer(c)) {
                        close_conn(c);
                        continue;
                    }
                } else if (!response_read_deadline_uses_precise_timer(c)) {
                    timer.refresh(&c, c.response_read_deadline_seconds);
                }
                c.response_read_deadline_state = ResponseReadDeadlineState::Armed;
                if (c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                    c.response_read_deadline_post_commit_phase ==
                        ResponseReadDeadlinePostCommitPhase::Buffering &&
                    !start_bounded_release_if_ready(c)) {
                    close_conn(c);
                    continue;
                }
            } else if (key_stable &&
                       (c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                        c.response_read_deadline_state ==
                            ResponseReadDeadlineState::RefreshPending)) {
                close_conn(c);
                continue;
            } else if (!key_stable && c.fd >= 0 &&
                       (c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                        c.response_read_deadline_state ==
                            ResponseReadDeadlineState::RefreshPending)) {
                // The slot is batch-pinned, so a live mismatched state cannot
                // belong to a successor allocation.  Fail closed instead of
                // leaving an owner without a timer.
                close_conn(c);
            }
        }
    }

    void resolve_response_read_deadline_expiries() {
        if (!response_read_deadline_expiry_pending) return;
        response_read_deadline_expiry_pending = false;
        const auto finalize_streaming_inactivity = [&](Connection& c) {
            if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
                c.response_read_deadline_profile !=
                    ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
                c.req_method != static_cast<u8>(LogHttpMethod::Get) ||
                c.response_read_deadline_post_commit_phase !=
                    ResponseReadDeadlinePostCommitPhase::WaitingBody ||
                c.state != ConnState::Sending || c.req_start_us == 0 || c.epoch_held ||
                !response_read_deadline_identity_is_stable(c) ||
                !response_read_deadline_post_commit_is_stable(c) ||
                c.response_read_deadline_post_commit_downstream_submitted !=
                    c.response_read_deadline_post_commit_origin_received ||
                c.response_read_deadline_post_commit_downstream_completed !=
                    c.response_read_deadline_post_commit_origin_received ||
                c.response_read_deadline_post_commit_origin_received >=
                    c.response_read_deadline_post_commit_declared_body ||
                c.response_read_deadline_post_commit_inflight_body != 0 ||
                c.buffered_response_len() != 0 || c.send_armed ||
                c.response_read_deadline_send_owner_active || c.send_progress != 0 ||
                c.resp_body_mode != BodyMode::ContentLength ||
                c.resp_body_remaining != c.response_read_deadline_post_commit_declared_body -
                                             c.response_read_deadline_post_commit_origin_received ||
                c.resp_body_sent != c.response_header_buf.len() +
                                        c.response_read_deadline_post_commit_origin_received ||
                c.on_send != &on_response_body_sent<Self>)
                return false;
            // ExpiryPending is the single timer-side entry point. Completion consumes
            // req_start_us, clears every callback slot, and leaves the epoch once;
            // close_conn then disarms the deadline and invalidates the fd. A duplicate
            // expiry therefore cannot complete the request or leave the epoch twice.
            c.clear_slots();
            if (c.upstream_slot_held) {
                upstream_release(c.upstream_slot_uid);
                c.upstream_slot_held = false;
            }
            on_request_complete<Self>(this, c, c.resp_status, c.resp_body_sent);
            epoch_leave();
            close_conn(c);
            return true;
        };
        for (u32 id = 0; id < slots_initialized; id++) {
            Connection& c = conns[id];
            if (c.response_read_deadline_state != ResponseReadDeadlineState::ExpiryPending)
                continue;
            if (c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::Buffering &&
                forward_response_buffering_uses_content_length_machinery(
                    c.response_read_deadline_buffering)) {
                if (!start_complete_content_length_send(
                        c, CompleteContentLengthTerminalDisposition::InactivityExpiry))
                    close_conn(c);
                continue;
            }
            if (c.response_read_deadline_buffering == ForwardResponseBufferingMode::Bounded &&
                c.response_read_deadline_post_commit_phase !=
                    ResponseReadDeadlinePostCommitPhase::None) {
                // A bounded terminal already froze its release target and is
                // waiting for an owned send/recv/cancel CQE. Re-running the
                // expiry selector would revalidate the now-paused origin as
                // an ordinary live stream and close it before that custody
                // drains; the terminal finalizer owns this state instead.
                if (c.response_read_deadline_post_commit_terminal_pending) continue;
                const u32 admitted = c.response_read_deadline_post_commit_release_target;
                if (!finish_bounded_content_length_release(c,
                                                           admitted,
                                                           /*close_after_drain=*/true))
                    close_conn(c);
                continue;
            }
            if (c.response_read_deadline_post_commit_phase ==
                    ResponseReadDeadlinePostCommitPhase::WaitingBody &&
                finalize_streaming_inactivity(c))
                continue;
            if (c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None) {
                close_conn(c);
                continue;
            }
            // The strict-timeout helper owns the complete non-mutating proof,
            // private-prefix consumption, and deadline disarm ordering.  No
            // caller assertion can manufacture positive-progress admission.
            if (!try_prebuilt_strict_read_timeout<Self>(this, c) && c.fd >= 0) close_conn(c);
        }
    }

private:
    template <typename Callback>
    void drain_response_read_deadline_body_pump_ready(Callback&& callback) {
        if (!response_read_deadline_body_pump_pending) return;
        response_read_deadline_body_pump_pending = false;
        for (u32 word_index = 0; word_index < body_pump_ready_words.size(); ++word_index) {
            u64 remaining_mask = ~u64{0};
            while (remaining_mask != 0) {
                const u64 ready = body_pump_ready_words[word_index] & remaining_mask;
                if (ready == 0) break;
                const u32 bit = static_cast<u32>(__builtin_ctzll(ready));
                const u32 id = word_index * 64u + bit;
                const u64 bit_mask = u64{1} << bit;
                body_pump_ready_words[word_index] &= ~bit_mask;
                remaining_mask = bit == 63u ? 0 : (~u64{0} << (bit + 1u));

                if (id >= slots_initialized) continue;
                Connection& c = conns[id];
                if (!c.response_read_deadline_post_commit_pump_pending) continue;
                c.response_read_deadline_post_commit_pump_pending = false;
                if (c.fd >= 0) callback(c);
            }
        }
    }

#ifdef RUT_TESTING
public:
    template <typename Callback>
    void test_drain_response_read_deadline_body_pump_ready(Callback&& callback) {
        drain_response_read_deadline_body_pump_ready(static_cast<Callback&&>(callback));
    }
    void test_close_listen() { close_listen(); }
    void test_rearm_deferred_ws_cache_recvs() {
        ws_cache_rearm_budget = kProvidedBufCount - backend.ws_recv_cache_ordinary_count;
        rearm_deferred_ws_cache_recvs();
    }
    void test_rearm_deferred_recvs() {
        ws_cache_rearm_budget = kProvidedBufCount - backend.ws_recv_cache_ordinary_count;
        rearm_deferred_recvs(false);
    }
    u32 test_recv_rearm_count() const { return recv_rearm_count; }
    u32 test_cache_rearm_budget(u32 pinned) const { return cache_rearm_budget(pinned); }
    void test_defer_recv_rearm(const Connection& c) { defer_recv_rearm(c); }
    void test_rearm_cache_passes_with_budget(u32 budget) {
        ws_cache_rearm_budget = budget;
        rearm_deferred_cache_passes(false);
    }
    bool test_use_one_shot_websocket_recv(const Connection& c) const {
        return use_one_shot_websocket_recv(c);
    }
#endif

public:
    void pump_response_read_deadline_bodies() {
        drain_response_read_deadline_body_pump_ready(
            [this](Connection& c) { pump_response_read_deadline_body<Self>(this, c); });
    }

    // Public deterministic seam used by the production run loop and focused
    // same-batch arbitration tests.
    void dispatch_batch(const IoEvent* events, u32 count) {
        study_turn_started_ns = monotonic_ns();
        if (ws_splice.enabled) ws_splice.begin_turn();
        study_inside_cq = true;
        if (count > kMaxEventsPerWait) count = kMaxEventsPerWait;
        prepare_response_read_deadline_batch(events, count);
        for (u32 i = 0; i < count; i++) {
            response_read_batch_event_index = i;
            const u16 owner_index = response_read_batch_event_owner[i];
            if (owner_index != 0 && owner_index <= response_read_batch_owner_count &&
                response_read_batch_owners[owner_index - 1u].bounded_terminal_prospective) {
                auto& owner = response_read_batch_owners[owner_index - 1u];
                Connection& c = conns[owner.conn_id];
                const IoEvent& ev = events[i];
                if (ev.type == IoEventType::ResponseReadTimer) {
                    if (!owner.valid || !valid_response_read_timer_transport_event(ev) ||
                        ev.result != -ETIME ||
                        !c.consume_response_read_timer_completion(ev.non_upstream_generation))
                        owner.valid = false;
                    else
                        owner.bounded_terminal_timer_seen = true;
                } else if (ev.type == IoEventType::UpstreamRecv) {
                    if (!owner.valid || ev.result != 0 || ev.more || ev.aux != 0 ||
                        ev.copy_witness != IoEventCopyWitness::None ||
                        ev.upstream_episode != owner.upstream_episode || !c.upstream_recv_armed ||
                        c.pending_ops == 0) {
                        owner.valid = false;
                    } else {
                        c.upstream_recv_armed = false;
                        c.pending_ops--;
                        c.on_upstream_recv = nullptr;
                        owner.bounded_terminal_recv_seen = true;
                    }
                } else {
                    owner.valid = false;
                }
                continue;
            }
            if (!ws_splice.dispatch(*this, events[i])) dispatch(events[i]);
        }
        ws_splice.progress(*this);
        study_inside_cq = false;
        study_cq_phase_ns += monotonic_ns() - study_turn_started_ns;
        settle_response_read_deadline_batch();
        resolve_response_read_deadline_expiries();
        if (!ws_splice.fast_scan || !ws_splice.last_batch_ws_only ||
            response_read_terminal_scan_needed) {
            bool any_pending = false;
            for (u32 id = 0; id < slots_initialized; ++id) {
                Connection& c = conns[id];
                any_pending = any_pending || c.response_read_deadline_post_commit_terminal_pending;
                if (c.response_read_deadline_post_commit_terminal_pending && !c.send_armed &&
                    c.response_read_deadline_post_commit_phase ==
                        ResponseReadDeadlinePostCommitPhase::WaitingBody &&
                    !c.upstream_recv_armed && !c.upstream_recv_pause_cancel_pending &&
                    !c.upstream_recv_cancel_inflight && !c.upstream_recv_pause_rearm_pending &&
                    !c.upstream_recv_paused_for_send && c.response_read_timer_owner_is_neutral())
                    defer_response_read_deadline_body_pump(c);
            }
            response_read_terminal_scan_needed = any_pending;
        } else {
            ++ws_splice.terminal_scans_skipped;
        }
        pump_response_read_deadline_bodies();
        // Retirement/header rendezvous owners publish only readiness during
        // dispatch. Admit parked HTTP/1 request boundaries after every CQE in
        // this wait batch, before reclamation or accept reuse.
        resume_deferred_http1_boundaries();
        flush_deferred_relay_reads();
        response_read_batch_pin_count = 0;
        response_read_batch_owner_count = 0;
        response_read_batch_owner_index_active = false;
        response_read_batch_event_count = 0;
        response_read_batch_events = nullptr;
        response_read_batch_owner_index_active = false;
        reclaim_pending();
    }

    bool pause_upstream_recv_impl(Connection& c) {
        if (!c.upstream_recv_armed) return true;  // nothing armed — no cancel, no CQE
        if (c.upstream_recv_pause_cancel_pending) {
            // A cancel is already in flight (e.g. a mid-body watermark pause). If the body
            // has SINCE completed — a parked/buffered tail finished it and re-paused here
            // with resp_fully_buffered set — upgrade the stale marker so the in-flight
            // recv's terminal/data is still treated as stale post-body data. The early
            // return must not leave terminal_stale at its mid-body value of false.
            c.upstream_recv_terminal_stale =
                c.upstream_recv_terminal_stale || c.resp_fully_buffered;
            return true;
        }
        // Cancel the multishot recv by user_data — recv-only, so a concurrent upstream
        // send (WS tunnel, overlapping body upload) is never touched. The cancel is
        // COUNTED in pending_ops and its own completion (tagged kPauseCancelAux) is what
        // re-arms the recv (see try_deferred_upstream_rearm): the recv is re-armed only
        // after the cancel drains, so the in-flight cancel can never match a freshly-
        // armed recv on the reused conn_id, and the slot can't be reclaimed until then.
        if (!backend.pause_upstream_recv(c.upstream_fd, c.id, c.upstream_episode)) return false;
        c.upstream_recv_pause_cancel_pending = true;
        // The armed recv will now produce a terminal CQE (-ECANCELED, or a normal
        // completion that beat the cancel). Track it independently of upstream_recv_armed
        // so the re-arm waits for it even after proxy_stream_complete clears armed.
        c.upstream_recv_cancel_inflight = true;
        // Capture whether the body was already complete: if so, the cancelled recv's
        // terminal is stale post-body data to suppress. Captured now because
        // proxy_stream_complete clears resp_fully_buffered before that terminal drains.
        c.upstream_recv_terminal_stale = c.upstream_recv_terminal_stale || c.resp_fully_buffered;
        c.pending_ops++;
        return true;
    }

    // Re-arm an upstream recv that a pause deferred, but ONLY once BOTH the old recv and
    // its pause cancel have drained — armed cleared by the recv's CQE, cancel_pending
    // cleared by the cancel's own CQE (kPauseCancelAux). Re-arming before the cancel
    // drains would let it match the fresh recv on the reused conn_id. The recv and
    // cancel CQEs can arrive in either order, so both terminal branches call this; it
    // fires from whichever lands second. No-op unless a re-arm was actually deferred.
    // Returns false only if the re-arm failed under SQ pressure (caller must close).
    bool try_deferred_upstream_rearm(Connection& c) {
        // Deferred idle-pool return (return_idle_upstream): the cancelled multishot
        // recv has now fully drained (both the cancel and the recv terminal cleared
        // their flags), so the fd parked in idle_return_fd is safe to hand to the
        // pool — no recv can fire on it anymore. Runs at every recv-terminal drain
        // site (all call this) so whichever CQE lands last triggers it. Closes the
        // fd if the pool is full / gone.
        const bool kUpstreamRecvDrained = !c.upstream_recv_pause_cancel_pending &&
                                          !c.upstream_recv_cancel_inflight &&
                                          !c.upstream_recv_armed;
        if (c.idle_return_fd >= 0 && kUpstreamRecvDrained) {
            const i32 fd = c.idle_return_fd;
            c.idle_return_fd = -1;
            // The pin is consumed with the fd: left set, the connection would look
            // non-neutral to every later request (successor-neutrality predicates).
            const RouteConfig* const kParkedConfig = c.idle_return_config;
            c.idle_return_config = nullptr;
            // A reload landed while the cancel drained: the pinned config no longer
            // matches the live one, so poll_command's pool drain already ran and this
            // fd's (uid, bidx) may now map to a different backend — close, don't pool.
            const bool kConfigStale = !config_ptr || *config_ptr != kParkedConfig;
            // Stale bytes the backend wrote after the framed response were copied into
            // upstream_recv_buf while the cancel drained (on_upstream_recv was cleared,
            // so they were silently consumed off the socket). take_idle's MSG_PEEK can't
            // see them anymore, so the next reuse would parse them as an early response —
            // close rather than pool a desynced socket.
            const bool kStaleBytes =
                c.buffered_response_len() != 0 || c.upstream_recv_idle_stale_bytes;
            const bool kDraining = is_draining();
            if (kStaleBytes) c.upstream_recv_buf.reset();
            c.upstream_recv_idle_stale_bytes = false;
            if (kConfigStale || kStaleBytes || kDraining || !upstream ||
                !upstream->put_idle(fd, c.idle_return_uid, c.idle_return_bidx, monotonic_secs()))
                ::close(fd);
            // A request boundary parked behind this drain (defer_http1_request_boundary)
            // is now ready: the pin is cleared, so request 2 sees a neutral connection.
            maybe_publish_http1_boundary_ready(c);
        }
        // Deferred close: close_conn_impl tore the conn down (e.g. Connection: close)
        // while the deferred pool-return was still draining, leaving the slot allocated
        // so these recv-terminal CQEs would route here. The fd is now pooled (above) and
        // the recv has fully drained, so finish the slot-free that close_conn skipped.
        // free_conn defers reclamation itself if client-side cancel CQEs are still in
        // flight (parks the conn in pending_free until pending_ops hits 0).
        if (c.upstream_recv_close_quarantine && kUpstreamRecvDrained) {
            c.upstream_recv_close_quarantine = false;
            c.upstream_recv_buf.reset();
        }
        if (c.idle_return_fd < 0 && kUpstreamRecvDrained) maybe_publish_http1_boundary_ready(c);
        if (c.close_after_idle_return && kUpstreamRecvDrained) {
            c.close_after_idle_return = false;
            this->free_conn(c);
            return true;
        }
        if (c.upstream_recv_pause_cancel_pending || c.upstream_recv_cancel_inflight ||
            c.upstream_recv_armed || !c.upstream_recv_pause_rearm_pending ||
            c.upstream_recv_paused_for_send || c.upstream_fd < 0) {
            // upstream_fd < 0 ⇒ the connection is being torn down (close_conn closed the
            // upstream) — don't re-arm a recv on a dead fd. A live deferred re-arm always
            // has upstream_fd >= 0, since rearm_pending is only set by a submit_recv_-
            // upstream call, which happens only once the upstream is connected.
            return true;
        }
        c.upstream_recv_pause_rearm_pending = false;
        return submit_recv_upstream_impl(c);
    }

    [[nodiscard]] bool pause_upstream_recv_for_send(Connection& c) {
        c.upstream_recv_paused_for_send = true;
        return pause_upstream_recv_impl(c);
    }

    [[nodiscard]] bool pause_recv(Connection& c) {
        c.recv_paused_for_send = true;
        if (c.uses_iouring_tls() && c.tls_pending_on_recv == &tls_resume_pending_send_recv<Self>)
            return true;
        if (c.recv_pause_cancel_pending || c.recv_pause_target_inflight) {
            c.recv_pause_rearm_pending = true;
            return true;
        }
        if (!c.recv_armed) return true;
        if (!backend.pause_recv(c.fd, c.id)) return false;
        c.recv_pause_cancel_pending = true;
        c.recv_pause_target_inflight = true;
        // Keep the cancel SQE as an independent lifetime owner. Its CQE may
        // arrive before or after the target recv terminal.
        c.pending_ops++;
        return true;
    }

    [[nodiscard]] bool local_body_send_holds_epoch(const Connection& c) const {
        if (c.id >= connection_capacity || !c.send_armed || c.pending_ops == 0 || c.fd < 0 ||
            c.tls_active || c.local_body_cursor == nullptr || c.local_body_send_len == 0 ||
            c.epoch_leave_deferred || (c.req_start_us == 0 && !c.epoch_held) ||
            c.send_progress >= c.local_body_send_len ||
            c.response_read_deadline_post_commit_phase !=
                ResponseReadDeadlinePostCommitPhase::None ||
            c.on_send != &on_response_sent<IoUringEventLoop>)
            return false;
        const auto& send = backend.send_state[c.id];
        const u32 remaining = c.local_body_send_len - c.send_progress;
        // A memory send reads the config-owned body bytes; a file send
        // (add_send_file) reads the config-owned sealed memfd, whose POLLOUT
        // continuation calls sendfile again from wait(). Either way the config
        // must outlive the send, or LoadedProgram::destroy could close (and
        // the kernel recycle) the memfd under a pending continuation.
        const bool memory_send = send.src == c.local_body_cursor + c.send_progress;
        const bool file_send =
            send.src == nullptr && send.file_fd >= 0 && send.file_fd == c.local_body_file_fd &&
            c.local_body_base != nullptr && c.local_body_cursor >= c.local_body_base &&
            send.file_base ==
                static_cast<u32>(c.local_body_cursor - c.local_body_base) + c.send_progress;
        return send.type == IoEventType::Send && send.fd == c.fd && send.generation == 0 &&
               (memory_send || file_send) && send.offset <= remaining &&
               send.remaining == remaining - send.offset;
    }

    void close_conn_impl(Connection& c) {
        ws_splice.close(*this, c);
        if (c.tls_out_inflight) {
            // TLS close custody belongs to the actual ciphertext SQE, not the
            // logical plaintext continuation. The common ledger survives
            // free_conn::reset until target/cancel both drain.
            c.response_read_deadline_send_close_generation = c.tls_out_inflight_generation;
            if (c.response_read_deadline_send_close_generation == 0 && c.id < connection_capacity)
                c.response_read_deadline_send_close_generation =
                    backend.send_state[c.id].generation;
            c.response_read_deadline_send_close_target_owned = c.send_armed;
            c.response_read_deadline_send_close_cancel_owned = false;
        } else if (c.tls_active && !c.tls_out_inflight &&
                   c.response_read_deadline_send_owner_active) {
            // A strict TLS logical owner with no raw ciphertext target is not a
            // kernel Send. Drop only its semantic tuple; the independent recv
            // owner below still retains its own target/cancel accounting.
            c.clear_response_read_deadline_send_owner();
        } else if (c.response_read_deadline_send_owner_active) {
            c.response_read_deadline_send_close_generation =
                c.response_read_deadline_send_owner_generation;
            c.response_read_deadline_send_close_target_owned = c.send_armed;
            c.response_read_deadline_send_close_cancel_owned = false;
            c.response_read_deadline_send_tombstone_generation =
                c.response_read_deadline_send_owner_generation;
            c.clear_response_read_deadline_send_owner();
        }
        c.tls_pending_on_send = nullptr;
        c.tls_pending_on_recv = nullptr;
        Connection::visit_tls_single_shot_send_owner_fields(
            c, [](auto& value, const auto& reset_value) { value = reset_value; });
        disarm_response_read_deadline(c);
        timer.remove(&c);
        // A close is terminal for a parked request boundary. Readiness may have
        // been published earlier in the same CQE batch; batch-end scans must see
        // cleared state and never repeat request-1 completion on a dead slot.
        c.http1_boundary_deferred = false;
        c.http1_boundary_ready = false;
        c.http1_boundary_successor_episode = 0;
        c.http1_prebuilt_wait = 0;
        c.http1_prebuilt_disposition = Http1RequestBufferDisposition::None;
        c.http1_prebuilt_request_prefix_len = 0;
        // epoch_held covers a suspended continuation pinning the config epoch
        // after its ordinary req_start_us ownership has ended (or an HTTP/2
        // async stream which never used h1 request timing).
        if (local_body_send_holds_epoch(c)) {
            c.epoch_leave_deferred = true;
        } else if (!c.epoch_leave_deferred && (c.req_start_us != 0 || c.epoch_held)) {
            epoch_leave();
        }
        c.epoch_held = false;
        // Release any held upstream concurrency slot (catch-all; held flag makes a
        // prior release at completion a no-op).
        if (c.upstream_slot_held) {
            upstream_release(c.upstream_slot_uid);
            c.upstream_slot_held = false;
        }
        const bool idle_return_recv_draining =
            c.idle_return_fd >= 0 && (c.upstream_recv_armed || c.upstream_recv_cancel_inflight ||
                                      c.upstream_recv_pause_cancel_pending);
        // Preserve exact live-successor ownership across free_conn::reset().
        // The old C1 token remains in its separate tombstone; this ledger is
        // only for operations submitted under the current successor token.
        const bool successor_close_already_owned = c.upstream_close_target_owned != 0 ||
                                                   c.upstream_close_cancel_owned != 0 ||
                                                   c.upstream_close_pause_cancel_owned;
        if (!idle_return_recv_draining && !successor_close_already_owned &&
            valid_upstream_episode(c.upstream_episode)) {
            u8 targets = 0;
            if (c.upstream_connect_armed) targets |= kUpstreamOpConnect;
            if (c.upstream_recv_armed || c.upstream_recv_cancel_inflight)
                targets |= kUpstreamOpRecv;
            if (c.upstream_send_armed) targets |= kUpstreamOpSend;
            if (targets != 0 || c.upstream_recv_pause_cancel_pending) {
                c.upstream_close_episode = c.upstream_episode;
                c.upstream_close_target_owned = targets;
                c.upstream_close_pause_cancel_owned = c.upstream_recv_pause_cancel_pending;
            }
        }
        // Relay poll targets have their own target/cancel ownership; ordinary
        // upstream cancellation must not steal either operation.
        if (c.relay_owner.active()) {
            c.relay_owner.close_pending = true;
            if (c.relay_owner.read_armed && !c.relay_owner.read_cancel_owned &&
                backend.cancel_retiring_upstream(
                    c.id, IoEventType::RelayRead, c.relay_owner.upstream_episode)) {
                c.relay_owner.read_cancel_owned = true;
                c.pending_ops++;
            } else if (c.relay_owner.read_armed && !c.relay_owner.read_cancel_owned) {
                if (!c.relay_owner.read_cancel_retry) {
                    c.relay_owner.read_cancel_retry = true;
                    ++relay_cancel_retry_count;
                }
            }
            if (c.relay_owner.write_armed && !c.relay_owner.write_cancel_owned &&
                backend.cancel_retiring_upstream(
                    c.id, IoEventType::RelayWrite, c.relay_owner.upstream_episode)) {
                c.relay_owner.write_cancel_owned = true;
                c.pending_ops++;
            } else if (c.relay_owner.write_armed && !c.relay_owner.write_cancel_owned) {
                if (!c.relay_owner.write_cancel_retry) {
                    c.relay_owner.write_cancel_retry = true;
                    ++relay_cancel_retry_count;
                }
            }
            // A synchronous relay failure can leave the logical owner active
            // after both readiness targets have already retired.  There will
            // be no later CQE to drive cleanup in that state, so release the
            // connection-owned pipe immediately once the complete relay
            // cancellation ledger is neutral.
            if (!c.relay_owner.read_armed && !c.relay_owner.write_armed &&
                !c.relay_owner.read_cancel_owned && !c.relay_owner.write_cancel_owned &&
                !c.relay_owner.read_cancel_retry && !c.relay_owner.write_cancel_retry)
                close_response_splice_pipe(c);
        }
        // Only cancel when ops are in flight.
        if (c.pending_ops > 0) {
            // If an idle upstream fd is parked waiting for its old multishot recv to
            // drain, do not submit another close-path UpstreamRecv cancel for a newer
            // upstream_fd on the same conn_id. The parked recv/cancel pair owns these
            // flags until try_deferred_upstream_rearm observes both CQEs.
            const bool cancel_upstream_recv = c.upstream_recv_armed &&
                                              !c.upstream_recv_pause_cancel_pending &&
                                              !idle_return_recv_draining;
            u8 close_cancel_mask = 0;
            bool close_send_cancel_owned = false;
            const u32 submitted = backend.cancel(c.fd,
                                                 c.id,
                                                 c.recv_armed,
                                                 c.send_armed,
                                                 c.upstream_connect_armed,
                                                 cancel_upstream_recv,
                                                 c.upstream_send_armed,
                                                 c.upstream_fd >= 0,
                                                 c.upstream_episode,
                                                 c.yield_timeout_armed,
                                                 c.yield_timer_gen,
                                                 &close_cancel_mask,
                                                 &close_send_cancel_owned);
            c.upstream_close_cancel_owned |= close_cancel_mask;
            c.response_read_deadline_send_close_cancel_owned |= close_send_cancel_owned;
            c.pending_ops += submitted;
        }
        if (c.fd >= 0) {
            ::close(c.fd);
            c.fd = -1;
        }
        if (c.upstream_fd >= 0) {
            ::close(c.upstream_fd);
            c.upstream_fd = -1;
        }
        if (metrics) {
            if (c.req_start_us != 0) {
                if (metrics->requests_active > 0) metrics->requests_active--;
            }
            metrics->on_close();
        }
        // A deferred idle-pool return (return_idle_upstream parked a still-reusable
        // upstream fd in idle_return_fd) whose cancelled multishot recv has NOT yet
        // drained. Don't discard the reusable fd or free the slot: keep the conn
        // allocated so the in-flight cancel + recv-terminal CQEs still route here by
        // conn_id. try_deferred_upstream_rearm then pools the fd AND performs this
        // deferred free once the recv drains. Quiesce the client side (timer + I/O
        // callbacks) so a stray client terminal CQE can't dispatch on the now-closed
        // connection; the upstream-recv terminal branches key off the recv flags (left
        // intact here), not these callbacks, so the drain still completes. epoch / slot
        // / metrics above have already run exactly once — the deferred free_conn does
        // none of them, so there is no double release.
        if (idle_return_recv_draining) {
            c.close_after_idle_return = true;
            timer.remove(&c);
            c.on_recv = nullptr;
            c.on_send = nullptr;
            c.on_upstream_recv = nullptr;
            c.on_upstream_send = nullptr;
            c.pending_handler_fn = nullptr;
            return;
        }
        // idle_return_fd set but already drained (no recv still racing it): the fd is
        // reusable, so pool it rather than discard. In practice the synchronous close
        // right after return_idle_upstream always leaves the cancel in flight, so this
        // pools only if the recv happened to drain before close_conn ran — either way a
        // reusable fd must not be leaked/closed.
        if (c.idle_return_fd >= 0) {
            const i32 fd = c.idle_return_fd;
            c.idle_return_fd = -1;
            const RouteConfig* const kParkedConfig = c.idle_return_config;
            c.idle_return_config = nullptr;
            // Same refusals as the deferred drain in try_deferred_upstream_rearm: a
            // config swap (poll_command drained the pool) or surplus bytes copied into
            // upstream_recv_buf both desync reuse — close rather than pool.
            const bool kConfigStale = !config_ptr || *config_ptr != kParkedConfig;
            const bool kStaleBytes =
                c.buffered_response_len() != 0 || c.upstream_recv_idle_stale_bytes;
            const bool kDraining = is_draining();
            if (kStaleBytes) c.upstream_recv_buf.reset();
            c.upstream_recv_idle_stale_bytes = false;
            if (kConfigStale || kStaleBytes || kDraining || !upstream ||
                !upstream->put_idle(fd, c.idle_return_uid, c.idle_return_bidx, monotonic_secs()))
                ::close(fd);
        }
        this->free_conn(c);
    }

    // --- Dispatch ---

    // Schedule a JIT handler yield timer via IORING_OP_TIMEOUT. ms
    // precision — kernel drives the timer, CQE arrives as IoEvent with
    // type=HandlerTimer carrying conn_id. Slots should already be
    // cleared before calling (no recv/send in flight while waiting).
    //
    // Takes the conn off the keepalive wheel while the precise timer
    // owns its wakeup — otherwise waits longer than keepalive_timeout
    // get resumed early by the wheel's 1-second tick.
    //
    // Falls back to the 1-second wheel if the SQ is full; the wheel
    // tick callback checks pending_handler_fn and resumes from there,
    // degrading precision but preserving liveness.
    //
    // On success, increments pending_ops and sets yield_armed so
    // close_conn_impl will submit a cancel SQE — keeping the slot
    // pinned until the timer's CQE is harvested, so a late stale
    // HandlerTimer can't resume a handler on a reused slot.
    //
    // Returns false if no timer could be scheduled faithfully: under
    // catastrophic SQ pressure (IORING_OP_TIMEOUT fails even after
    // flush+retry) AND the requested wait exceeds what the 1-second
    // wheel fallback can represent (~63s). Caller fails the request.
    [[nodiscard]] bool schedule_yield_timer(Connection& conn, u32 ms) {
        timer.remove(&conn);
        // Ensure a recv is in flight so peer disconnect during wait(ms)
        // produces a CQE the mid-yield dispatch branch can close on.
        // submit_recv is idempotent (checks recv_armed), so this is a
        // no-op when multishot is still running. It matters when the
        // prior multishot terminated with !ev.more before this yield
        // (e.g., buffer-ring edge case) and would otherwise leave no
        // in-flight recv to surface a silent client FIN.
        this->submit_recv(conn);
        // add_recv flushes and retries on a full SQ, so a miss here means the
        // flush itself failed (the backend is then stopping). If recv still isn't armed, we'd sleep
        // without a disconnect detector — fail the request instead of leaking the slot until the
        // yield deadline expires.
        if (!conn.recv_armed) return false;
        // NOTE: we deliberately do NOT cancel the multishot recv here.
        // A cancel SQE would make the canceled target's -ECANCELED CQE
        // arrive after the handler resumes and re-sets on_recv, where
        // it would be interpreted as a peer close and kill the
        // connection (or break keep-alive). The dispatch-level
        // pending_handler_fn branch closes on any mid-yield recv CQE,
        // so an adversarial peer can't exhaust buffers or silently
        // inject data.
        if (backend.add_yield_timeout(conn.id, conn, ms)) {
            conn.yield_armed = true;
            conn.yield_timeout_armed = true;
            conn.pending_ops++;
            return true;
        }
        // Catastrophic SQ pressure — add_yield_timeout already did one
        // flush+retry. Fall back to the 1-second wheel, but only if
        // the wait actually fits: 64 slots × 1s, so seconds in
        // [1, 63] land faithfully; seconds 64+ would wrap mod-64 and
        // fire far too early. Fail the request rather than shorten.
        u32 secs = timer_seconds_from_ms(ms);
        if (secs >= TimerWheel::kSlots) return false;
        // Minimum 1 second: wait(0) on the wheel would land in the
        // current slot, which the ongoing tick has already drained —
        // the entry would then sit idle until the wheel wraps (~64s).
        // analyze rejects wait(0) upstream, so this is defence-in-depth.
        if (secs == 0) secs = 1;
        conn.yield_armed = true;
        conn.yield_timeout_armed = false;
        timer.add(&conn, secs);
        return true;
    }

    void disarm_yield_timer(Connection& conn) {
        if (!conn.yield_armed) return;
        const u32 old_gen = conn.yield_timer_gen;
        const bool timeout_armed = conn.yield_timeout_armed;
        conn.yield_armed = false;
        conn.yield_timeout_armed = false;
        conn.yield_timer_gen++;
        timer.remove(&conn);
        if (timeout_armed) (void)backend.cancel_yield_timeout(conn.id, old_gen);
    }

    // Park a @throttle-paused proxy connection for `delay_ns` via an io_uring
    // TIMEOUT SQE (ms granularity — fine for byte pacing; throttle_resume
    // re-checks the budget so rounding/early wake is safe). Reuses the JIT yield
    // timeout machinery; the HandlerTimer CQE routes back to throttle_resume when
    // the connection is throttle_paused. Returns false on SQ pressure → caller
    // falls back to the keepalive wheel.
    [[nodiscard]] bool arm_throttle_timer(Connection& conn, u64 delay_ns) {
        timer.remove(&conn);
        u32 ms = static_cast<u32>((delay_ns + 999'999ull) / 1'000'000ull);
        if (ms == 0) ms = 1;
        if (backend.add_yield_timeout(conn.id, conn, ms)) {
            conn.yield_armed = true;
            conn.yield_timeout_armed = true;
            conn.pending_ops++;
            return true;
        }
        return false;
    }

    // --- Idle keep-alive buffer trim ---
    //
    // Every live connection keeps its request-receive and send slices bound for its
    // whole life, so pages dirtied while serving a request stay resident however
    // long the connection then sits idle (8-20 KiB per connection). Once a
    // connection has been idle for a few seconds this hands those pages back with
    // MADV_DONTNEED — bindings, pointers and capacities are untouched, the next
    // request just re-faults zero pages.
    //
    // Driven from the timer wheel, not from a scan of the connection slots. A
    // connection waiting in keep-alive sits in the wheel list that pops at
    // (arm tick + keepalive_timeout), and the timer is re-armed by every request
    // and response event, so "list whose expiry is `S - age` ticks away" is
    // exactly "connections whose last activity was `age` ticks ago" for a
    // connection armed with keepalive_timeout. Each tick visits the lists aged
    // [kIdleTrimMinIdleTicks, +kIdleTrimAgeWindow), oldest first, and examines only
    // the nodes it finds there: cost follows the connections that newly aged, not
    // the slot capacity or the live population, and no slot is ever indexed by
    // number — the wheel holds only live, allocated connections.
    //
    // The age is inferred from the list, not recorded: a node armed with a
    // shorter timeout (an upstream/deadline/wait timer re-arm) that lands in a
    // visited list can be examined earlier than the nominal 5 s. That is a policy
    // imprecision only; safety never depends on age, because idle_trim_eligible()
    // re-evaluates the connection's whole state at examination time.
    //
    // Examined nodes are rotated to the tail of their list and marked
    // (Connection::idle_trim_examined); a walk stops at the first marked node, so
    // a list longer than the per-tick budget is finished on the following ticks
    // (the same list is visited again one age later) and handled nodes are never
    // walked again. TimerWheel::add clears the mark on every arm and re-arm, so a
    // re-armed node is always unexamined in its new list — with whatever timeout
    // and expiry tick it picked, including one that lands back in the very list it
    // was examined in. Reordering within a list is invisible to TimerWheel::tick(),
    // which drains the whole list. A connection that was busy when examined is not
    // retried under the same arming: whatever kept it busy ends with a dispatched
    // completion, which re-arms its timer and so earns a fresh examination.
    //
    // Releasing is batched. madvise(MADV_DONTNEED) per slice sends TLB-shootdown
    // IPIs to every CPU running another shard of this process, once per call. The
    // examination therefore only validates (SlicePool::bound_slice_valid) and queues
    // {ptr, 16 KiB} ranges; at the end of the tick's sweep — still on the shard
    // thread, before dispatch resumes, so nothing can touch a queued slice in
    // between — the queue is handed to process_madvise(pidfd-of-self,
    // MADV_DONTNEED) in chunks of at most 1024 ranges (the kernel's iovec limit),
    // which flushes TLBs about once per busy CPU per call instead of per range. The
    // kernel stops at the first range it cannot advise and reports the bytes done;
    // the un-advised remainder of that chunk is released with per-slice madvise, and
    // a connection counts as trimmed only if one of its slices really was advised.
    //
    // Platform: needs process_madvise on the calling process (syscall: Linux 5.10;
    // MADV_DONTNEED on self: observed working unprivileged on 7.2.7, minimum
    // version not established). probe_idle_trim() proves it once at init; if pidfd_open or
    // process_madvise is refused (ENOSYS, EPERM under seccomp/containers, EINVAL on
    // an older kernel) the feature is OFF entirely and the sweep is a no-op —
    // there is no per-slice mode, the shootdown cost would outweigh the memory.
    //
    // Nothing is added to any request path. Work per tick is bounded: the walk stops
    // after kIdleTrimMaxExamined nodes, kIdleTrimMaxTrims queued connections
    // (<= kIdleTrimMaxRanges = 1536 ranges, two flush calls), or when the wall clock
    // plus the projected flush (queued ranges * kIdleTrimFlushNsPerRange) reaches
    // kIdleTrimBudgetNs. Measured on Linux 7.2.7 (shared 32-CPU host, other load
    // present): examining 512 connections 0.03-0.13 ms; flush 0.25-0.9 us per range
    // (every page of every slice dirty, 0-7 busy threads: 0.35-0.55 us); a real
    // 10000-connection burst (1 shard, two slices each) took 0.4-1.5 ms per tick in
    // total, one tick in 20 took 3.0 ms (flush 2.5 ms, host interference); idle
    // ticks cost ~2.4 us. So the added stall is ~1 ms typical per tick. The 1.5 ms
    // budget is a target: the flush runs after the walk and cannot be interrupted, so
    // the hard bound is the caps (2048 examinations plus up to 1536 ranges in two
    // syscalls), realistically ~1.8 ms; host-interference outliers of ~3 ms were
    // observed. A batch that fails hard (an errno other than EINTR/EAGAIN) finishes
    // that tick per slice and then turns the feature off for the loop's life. The
    // sweep is skipped while the shard is draining. Trim
    // throughput is therefore at most 512 connections per tick; since a list is revisited on each
    // of kIdleTrimAgeWindow (40) consecutive ticks, a burst that goes idle within one
    // second is trimmed completely when it is no larger than ~40 * 512 = 20480
    // connections (10000 connections took ~20 ticks). Whatever remains when the
    // window closes is not trimmed for that idle period; its next request starts a
    // new one. The window (ages 5..44) closes 15 ticks before the default 60 s
    // keep-alive expiry; it is clipped for smaller timeouts (see sweep_idle_trim).
    //
    // Remaining proxied residual: a proxied connection's upstream receive slice is
    // never trimmed, because idle_trim_upstream_slice_quiet vetoes on
    // upstream_send_len, which stays stale after every proxied response (its recv
    // and send slices do trim; measured plateau ~9.8 KB per proxied connection).
    //
    // Cost that remains: the release itself still has a residual cost. Measured (20000 idle
    // connections trimmed during a 12 s window, 2 shards, one load generator of 64 connections,
    // throughput-limited by the client): -1.0% to -1.6% requests/s (18 alternating
    // rounds, se ~0.5-0.6), mechanism not identified. With the load generators
    // saturating the shards (2 and 4 shards, 20000 idle connections) no cost is
    // measurable: 4 shards -0.13% (6 rounds, se 0.2), 2 shards -0.45% (2 clean
    // rounds only). TLB shootdowns on the shard CPUs during the trim window fell
    // from ~20-35k (2 shards) and ~100-113k (4 shards) with per-slice madvise to
    // ~40 and ~125 with the batch (~25 without trimming), i.e. >99% removed.
    static constexpr u32 kIdleTrimMinIdleTicks = 5;
    static constexpr u32 kIdleTrimAgeWindow = 40;
    static constexpr u32 kIdleTrimMaxExamined = 2048;
    static constexpr u32 kIdleTrimMaxTrims = 512;     // connections queued per tick
    static constexpr u32 kIdleTrimSlicesPerConn = 3;  // recv, send, upstream recv
    static constexpr u32 kIdleTrimMaxRanges = kIdleTrimMaxTrims * kIdleTrimSlicesPerConn;
    static constexpr u32 kIdleTrimIovChunk = 1024;        // kernel UIO_MAXIOV per call
    static constexpr u64 kIdleTrimBudgetNs = 1500000;     // examination + projected flush
    static constexpr u64 kIdleTrimFlushNsPerRange = 900;  // upper end of the measured 0.25-0.9 us
    static_assert(kIdleTrimMaxRanges <= 0xffffu, "idle_trim_first holds u16 range indices");
    u64 idle_trim_budget_ns = kIdleTrimBudgetNs;  // per-tick budget (tests)

    // Feature state: the pidfd of this process when process_madvise(MADV_DONTNEED)
    // on it was proven to work at init (probe_idle_trim), -1 when the feature is
    // off. The sweep is a no-op while it is -1.
    i32 idle_trim_pidfd = -1;
    // Ranges queued by this tick's examination, flushed at the end of the sweep.
    // idle_trim_first[k] is the index of the first range of the k-th queued
    // connection (idle_trim_first[idle_trim_queued] == idle_trim_nranges).
    struct iovec idle_trim_iov[kIdleTrimMaxRanges];
    u16 idle_trim_first[kIdleTrimMaxTrims + 1];
    u32 idle_trim_nranges = 0;
    u32 idle_trim_queued = 0;
    // Observability / test counters; touched only by the sweep.
    u64 idle_trim_examined = 0;  // wheel nodes examined
    u64 idle_trim_conns = 0;     // connections with at least one slice released
    u64 idle_trim_madvise = 0;   // slices released (batched or per slice)
    u64 idle_trim_batches = 0;   // process_madvise calls issued
    u64 idle_trim_fallback = 0;  // slices released by the per-slice fallback

    // One-time capability probe (init): is process_madvise(MADV_DONTNEED) on this
    // process usable? Holds a pidfd of self (pidfd_open(getpid()); PIDFD_SELF
    // would save the fd but needs a 6.15+ kernel, pidfd_open works from 5.3 on)
    // for the loop's lifetime and proves the call on one scratch page, including
    // that the page reads back zero. Any failure (ENOSYS, EPERM from seccomp or a
    // container profile, EINVAL on a kernel without DONTNEED-on-self) leaves the
    // feature off. There is deliberately no per-slice mode as a feature: without
    // the batched flush the per-range cross-CPU TLB shootdowns cost more than the
    // memory is worth.
    bool probe_idle_trim() {
        if (idle_trim_pidfd >= 0) {
            ::close(idle_trim_pidfd);
            idle_trim_pidfd = -1;
        }
        // Each queued range describes one SlicePool slice.  MADV_DONTNEED
        // rounds ranges to host pages, so a host page larger than a slice
        // could discard neighbouring slices that are still in use.
        const long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0 || static_cast<u64>(page_size) > SlicePool::kSliceSize) return false;
#if defined(SYS_pidfd_open) && defined(SYS_process_madvise)
        if (detail::idle_trim_inject(detail::IdleTrimPidfdOpen, 0) >= 0) return false;
        const long fd = syscall(SYS_pidfd_open, getpid(), 0u);
        if (fd < 0) return false;
        void* page = mmap(nullptr,
                          SlicePool::kSliceSize,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1,
                          0);
        if (page == MAP_FAILED) {
            ::close(static_cast<i32>(fd));
            return false;
        }
        *static_cast<volatile u8*>(page) = 1;
        struct iovec iov = {page, SlicePool::kSliceSize};
        const long r = detail::idle_trim_inject(detail::IdleTrimProbeAdvise, 0) >= 0
                           ? -1
                           : syscall(SYS_process_madvise, fd, &iov, 1ul, MADV_DONTNEED, 0u);
        const bool ok =
            r == static_cast<long>(SlicePool::kSliceSize) && *static_cast<volatile u8*>(page) == 0;
        munmap(page, SlicePool::kSliceSize);
        if (!ok) {
            ::close(static_cast<i32>(fd));
            return false;
        }
        idle_trim_pidfd = static_cast<i32>(fd);
        return true;
#else
        return false;
#endif
    }

    // True only for plain HTTP/1.1 keep-alive at rest between requests: nothing
    // can still read or write the receive/send slice contents. The downstream
    // multishot recv is the one op allowed outstanding — it lands in backend-owned
    // provided buffers and IoUringBackend::wait() copies into recv_buf on this
    // thread, so the kernel never references the connection's slice.
    [[nodiscard]] bool idle_trim_eligible(const Connection& c) const {
        if (c.fd < 0 || c.state != ConnState::ReadingHeader) return false;
        if (c.on_recv != &on_header_received<IoUringEventLoop> || c.on_send != nullptr ||
            c.on_upstream_recv != nullptr || c.on_upstream_send != nullptr)
            return false;
        // Protocol / transport: HTTP/1.1 plaintext only.
        if (c.protocol != ConnProtocol::Http11 || c.tls_active || c.tls_engine.ssl != nullptr ||
            c.tls_in_slice != nullptr || c.tls_out_slice != nullptr || c.h2 != nullptr ||
            c.is_ws_tunnel || c.is_ws_terminate)
            return false;
        // Buffers: bound as allocated, nothing received, no live View, no stash or
        // retry snapshot. (send_buf's own length is checked per slice at trim time.)
        // is_released() first: Buffer::data() traps while a View is alive.
        if (c.recv_buf.is_released() || c.send_buf.is_released()) return false;
        if (c.recv_slice == nullptr || c.send_slice == nullptr ||
            c.recv_buf.data() != c.recv_slice || c.send_buf.data() != c.send_slice ||
            c.recv_buf.len() != 0 || c.pipeline_stash_len != 0 || c.retry_req_send_len != 0 ||
            c.pipeline_depth != 0 || c.send_progress != 0)
            return false;
        // Sends: none in flight (an IORING_OP_SEND reads its slice asynchronously),
        // no local body mid-stream.
        if (c.send_armed || c.direct_write_completion_pending || c.local_body_remaining != 0 ||
            c.local_body_send_len != 0 || c.local_body_cursor != nullptr)
            return false;
        if (c.id >= connection_capacity) return false;
        const auto& send = backend.send_state[c.id];
        if (send.remaining != 0 || send.file_fd >= 0) return false;
        // Neutrality checks shared with submit_staged_local_response_impl:
        // detach_upstream_close / return_idle_upstream clear upstream_send_armed
        // without waiting for the CQE, so an upstream IORING_OP_SEND that reads
        // recv_buf/send_buf can outlive the flag; these ledgers still record it.
        // (upstream_send_len is deliberately not here: it only describes a client
        // send sourced from upstream_recv_buf and is left stale after every
        // proxied response, so vetoing on it would exempt all proxied connections;
        // idle_trim_upstream_slice_quiet applies it to that one slice.)
        if (backend.upstream_send_state[c.id].remaining != 0 || c.upstream_request_incomplete ||
            c.response_mutations_snapshotted || !c.response_read_deadline_owner_is_neutral() ||
            backend.failure_code() != 0)
            return false;
        // The downstream recv must be the armed multishot and not mid pause/rearm.
        if (!c.recv_armed || c.recv_paused_for_send || c.recv_pause_cancel_pending ||
            c.recv_pause_rearm_pending)
            return false;
        // Backstop for any in-flight op the flags above failed to record: an idle
        // plaintext connection has exactly that multishot recv outstanding
        // (observed: pending_ops == 1 on idle keep-alive connections, both direct
        // and after proxied exchanges).
        if (c.pending_ops != 1u) return false;
        // No request in flight, no pending handler / yield / throttle / deadline.
        if (c.req_start_us != 0 || c.epoch_held || c.pending_handler_fn != nullptr ||
            c.yield_armed || c.yield_timeout_armed || c.throttle_paused ||
            c.request_policy_body_pending ||
            c.response_read_deadline_state != ResponseReadDeadlineState::None ||
            c.http1_boundary_deferred || c.http1_boundary_ready || c.http1_prebuilt_wait != 0 ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None)
            return false;
        // No upstream episode of any kind: no upstream socket or pending pool return,
        // no upstream op or cancel outstanding, no retirement/close ledger open.
        if (c.upstream_fd >= 0 || c.idle_return_fd >= 0 || c.close_after_idle_return ||
            c.upstream_connect_armed || c.upstream_recv_armed || c.upstream_send_armed ||
            c.upstream_recv_direct_armed || c.upstream_recv_cancel_inflight ||
            c.upstream_recv_pause_cancel_pending || c.upstream_recv_pause_rearm_pending ||
            c.upstream_recv_paused_for_send || c.upstream_recv_terminal_stale ||
            c.upstream_recv_idle_stale_bytes || c.upstream_recv_close_quarantine ||
            c.upstream_retirement_active || c.upstream_close_target_owned != 0 ||
            c.upstream_close_cancel_owned != 0 || c.upstream_close_pause_cancel_owned ||
            c.response_header_slice != nullptr || c.response_body_tail.size != 0 ||
            c.throttle_pending_len != 0 || c.resp_fully_buffered)
            return false;
        return true;
    }

    // A proxied connection's upstream receive slice may be trimmed as well once the
    // upstream side is quiescent (idle_trim_eligible already proved no upstream op
    // or cancel is outstanding, so no recv — including the direct-into-slice kind —
    // can still write it) and it holds no bytes. A bulk buffer swapped in for a
    // large relay is refused by SlicePool::bound_slice_valid; the relay slice is never
    // touched and its presence (possible in-flight source) skips this slice too.
    [[nodiscard]] static bool idle_trim_upstream_slice_quiet(const Connection& c) {
        if (c.upstream_recv_slice == nullptr || c.upstream_relay_slice != nullptr ||
            c.upstream_relay_send_len != 0 || c.upstream_send_len != 0 ||
            c.upstream_recv_buf.is_released())
            return false;
        return c.upstream_recv_buf.data() == c.upstream_recv_slice &&
               c.upstream_recv_buf.len() == 0;
    }

    // Queue one examined connection's releasable slices; true if at least one was
    // queued. Nothing is advised here: the ranges are released together by
    // idle_trim_flush() at the end of the sweep.
    bool idle_trim_connection(Connection& c) {
        if (!idle_trim_eligible(c)) return false;
        const u32 first = idle_trim_nranges;
        u32 n = first;
        if (pool.bound_slice_valid(c.recv_slice)) queue_trim_range(n++, c.recv_slice);
        // A proxied request on a reused upstream socket leaves its retry-snapshot
        // bytes in send_buf after completion (length kept, nothing will replay
        // them); a non-empty send_buf is never touched, so that slice stays as is.
        if (c.send_buf.len() == 0 && pool.bound_slice_valid(c.send_slice))
            queue_trim_range(n++, c.send_slice);
        if (idle_trim_upstream_slice_quiet(c) && pool.bound_slice_valid(c.upstream_recv_slice))
            queue_trim_range(n++, c.upstream_recv_slice);
        if (n == first) return false;
        idle_trim_first[idle_trim_queued++] = static_cast<u16>(first);
        idle_trim_nranges = n;
        return true;
    }

    void queue_trim_range(u32 index, u8* slice) {
        idle_trim_iov[index].iov_base = slice;
        idle_trim_iov[index].iov_len = SlicePool::kSliceSize;
    }

    // One process_madvise(MADV_DONTNEED) call over `n` queued ranges; returns the
    // bytes advised (the kernel stops at the first bad range and reports what it
    // did so far), or -1.
    long idle_trim_advise_batch(const struct iovec* iov, u32 n) {
        ++idle_trim_batches;  // attempted calls, whether injected or real
        const i64 inject = detail::idle_trim_inject(detail::IdleTrimBatchAdvise, n);
        if (inject == 0 || inject == -2) {
            errno = inject == 0 ? EPERM : EAGAIN;
            return -1;
        }
        if (inject > 0 && static_cast<u64>(inject) < n) n = static_cast<u32>(inject);
        return syscall(SYS_process_madvise, idle_trim_pidfd, iov, n, MADV_DONTNEED, 0u);
    }

    bool idle_trim_advise_slice(const struct iovec& r) {
        if (detail::idle_trim_inject(detail::IdleTrimSliceAdvise,
                                     reinterpret_cast<u64>(r.iov_base)) >= 0)
            return false;
        return madvise(r.iov_base, r.iov_len, MADV_DONTNEED) == 0;
    }

    // Release everything queued this tick, synchronously on the shard thread and
    // before dispatch resumes (nothing can touch a queued slice in between). One
    // process_madvise call per chunk of at most kIdleTrimIovChunk ranges; a short
    // or failed return leaves the un-advised remainder of that chunk to per-slice
    // madvise. A connection counts as trimmed only if one of its slices was
    // actually advised.
    void idle_trim_flush() {
        const u32 total = idle_trim_nranges;
        u32 queued = idle_trim_queued;
        idle_trim_nranges = 0;
        idle_trim_queued = 0;
        if (total == 0) return;
        idle_trim_first[queued] = static_cast<u16>(total);
        u32 conn = 0;       // connection owning range `i`
        u32 counted = ~0u;  // last connection added to idle_trim_conns
        bool hard_failure = false;
        for (u32 base = 0; base < total; base += kIdleTrimIovChunk) {
            const u32 chunk = total - base < kIdleTrimIovChunk ? total - base : kIdleTrimIovChunk;
            long r = -1;
            if (!hard_failure) {
                r = idle_trim_advise_batch(&idle_trim_iov[base], chunk);
                // EINTR / EAGAIN are transient: this tick falls back, the next tries
                // the batch again. Anything else means the batch is refused for good.
                if (r < 0 && errno != EINTR && errno != EAGAIN) hard_failure = true;
            }
            // Whole ranges the kernel reports done; a partly advised range is redone.
            const u32 advised =
                r > 0 ? static_cast<u32>(static_cast<u64>(r) / SlicePool::kSliceSize) : 0;
            for (u32 i = base; i < base + chunk; i++) {
                while (idle_trim_first[conn + 1] <= i) ++conn;
                bool ok = i - base < advised;
                if (!ok) {
                    ok = idle_trim_advise_slice(idle_trim_iov[i]);
                    if (ok) ++idle_trim_fallback;
                }
                if (!ok) continue;
                ++idle_trim_madvise;
                if (conn != counted) {
                    counted = conn;
                    ++idle_trim_conns;
                }
            }
        }
        // The per-slice fallback for this tick is done (nothing queued is left
        // un-advised). A batch that fails hard would otherwise be retried, and its
        // remainder released per slice, every tick forever: that per-slice mode is
        // exactly what the feature does not offer. Switch the feature off for the
        // life of the loop.
        if (hard_failure) {
            ::close(idle_trim_pidfd);
            idle_trim_pidfd = -1;
        }
    }

    // Walk the wheel list that pops at `expiry`, examining nodes not yet examined
    // since they were armed. Returns false once a per-tick budget is exhausted.
    bool idle_trim_walk_list(u32 expiry, u64 deadline_ns, u32& examined, u32& queued) {
        ListNode* head = &timer.slots[expiry & (TimerWheel::kSlots - 1)];
        ListNode* const last = head->prev;  // rotated nodes land after this one
        if (last == head) return true;
        const u64 node_offset = TimerWheel::timer_node_offset();
        ListNode* node = head->next;
        for (;;) {
            if (examined == kIdleTrimMaxExamined || queued == kIdleTrimMaxTrims) return false;
            auto* c = reinterpret_cast<Connection*>(reinterpret_cast<char*>(node) - node_offset);
            if (c->idle_trim_examined) return true;  // reached the examined region
            ListNode* const next = node->next;
            const bool at_end = node == last;
            c->idle_trim_examined = true;
            node->remove();
            head->prev->insert_after(node);
            examined++;
            idle_trim_examined++;
            if (idle_trim_connection(*c)) queued++;
            // The time budget is checked after the node, so every tick makes progress.
            if (monotonic_ns() + idle_trim_nranges * kIdleTrimFlushNsPerRange >= deadline_ns)
                return false;
            if (at_end) return true;
            node = next;
        }
    }

    // Once per timer tick, after TimerWheel::tick() has advanced the cursor. The
    // keep-alive timer was armed `age` ticks ago iff its list pops at
    // cursor + keepalive_timeout - age (add() files a node under cursor + timeout,
    // tick() pops slot `cursor` and then increments it). Idle connections are
    // armed with keepalive_timeout by accept and by every request/response event
    // (a proxied exchange finishing while state is still Proxying re-arms with
    // keepalive_timeout too: measured, they are found here). A timeout too small
    // for the age range or too large for the wheel (it would wrap) contributes only
    // the ages that fit, or nothing. A stalled loop that ticked several times at
    // once ages every node by that much; the window is wider than any realistic
    // stall, and a longer one only skips nodes that are about to expire anyway.
    void sweep_idle_trim() {
        if (idle_trim_pidfd < 0) return;
        const u32 timeout = keepalive_timeout;
        if (timeout >= TimerWheel::kSlots || timeout <= kIdleTrimMinIdleTicks) return;
        const u64 deadline_ns = monotonic_ns() + idle_trim_budget_ns;
        u32 examined = 0;
        u32 queued = 0;
        for (u32 back = kIdleTrimAgeWindow; back-- != 0;) {
            const u32 age = kIdleTrimMinIdleTicks + back;
            if (age >= timeout) continue;
            if (!idle_trim_walk_list(timer.cursor + (timeout - age), deadline_ns, examined, queued))
                break;
        }
        idle_trim_flush();
    }

    void dispatch(const IoEvent& ev) {
        switch (ev.type) {
            case IoEventType::Accept:
                on_accept(ev);
                break;
            case IoEventType::HandlerTimer:
                // JIT handler yield timer fired (or was cancelled — same
                // resume path; any error bubbles through the handler).
                //
                // Decrement pending_ops unconditionally: IORING_OP_TIMEOUT
                // never sets CQE_F_MORE, and the cancel SQE submitted in
                // close_conn_impl shares this user_data — both CQEs route
                // here and must each decrement. yield_armed can't gate this
                // because free_conn_impl::reset() clears the flag when a
                // close lands while the timer is in flight.
                if (ev.conn_id < slots_initialized) {
                    auto& c = conns[ev.conn_id];
                    if (c.pending_ops > 0) c.pending_ops--;
                    const bool matching_generation =
                        ev.result == static_cast<i32>(c.yield_timer_gen);
                    const bool was_yield_armed = c.yield_armed;
                    if (matching_generation) {
                        c.yield_armed = false;
                        c.yield_timeout_armed = false;
                    }
                    if (c.throttle_paused && matching_generation) {
                        // @throttle pacing timer fired — resume the parked proxy
                        // pump (re-checks the byte budget; may re-park).
                        throttle_resume<IoUringEventLoop>(this, c);
                    } else if (c.pending_handler_fn && matching_generation &&
                               (c.pending_yield_kind == jit::YieldKind::Timer ||
                                (was_yield_armed &&
                                 yield_kind_matches_event(c.pending_yield_kind,
                                                          IoEventType::HandlerTimer)))) {
                        c.resume_event_kind = jit::YieldKind::Timer;
                        c.resume_event_result = 0;
                        resume_jit_handler<IoUringEventLoop>(this, c);
                    } else if (c.pending_ops == 0 && !c.pending_handler_fn && c.fd < 0) {
                        // Stale CQE for an already-closed slot; safe to
                        // reclaim now that the last in-flight op has drained.
                        reclaim_slot(ev.conn_id);
                    }
                }
                break;
            case IoEventType::Timeout: {
                if (accept_rearm_pending) rearm_accept();
                // Last resort for a recv the batch-end gate kept waiting.
                rearm_deferred_recvs(/*force=*/true);
                i32 ticks = ev.result > 0 ? ev.result : 1;
                const i32 max_ticks = static_cast<i32>(TimerWheel::kSlots);
                if (ticks > max_ticks) ticks = max_ticks;
                for (i32 t = 0; t < ticks; t++) {
                    timer.tick([this](Connection* c) {
                        // See epoll_event_loop.h: timer fires for keepalive,
                        // wait(ms), or wait-any timeout completion.
                        if (c->response_read_deadline_state == ResponseReadDeadlineState::Armed) {
                            c->response_read_deadline_state =
                                ResponseReadDeadlineState::ExpiryPending;
                            response_read_deadline_expiry_pending = true;
                        } else if (c->pending_handler_fn &&
                                   (c->pending_yield_kind == jit::YieldKind::Timer ||
                                    (c->yield_armed &&
                                     yield_kind_matches_event(c->pending_yield_kind,
                                                              IoEventType::Timeout)))) {
                            c->yield_armed = false;
                            c->yield_timeout_armed = false;
                            c->resume_event_kind = jit::YieldKind::Timer;
                            c->resume_event_result = 0;
                            resume_jit_handler<IoUringEventLoop>(this, *c);
                        } else if (c->state == ConnState::Proxying && !c->proxy_resp_started) {
                            // Upstream stalled before responding → 504. A genuine
                            // in-flight h2 proxy stream reframes as h2 (raw h1 504
                            // bytes would corrupt the stream); anything else uses
                            // the HTTP/1 path.
                            if (c->protocol == ConnProtocol::Http2 && c->h2 != nullptr &&
                                c->h2->async_stream != 0)
                                h2_proxy_fail<IoUringEventLoop>(this, *c, 504);
                            else
                                respond_upstream_timeout<IoUringEventLoop>(this, *c);
                        } else if (c->throttle_paused) {
                            throttle_resume<IoUringEventLoop>(this, *c);
#if RUT_ENABLE_WEBSOCKET
                        } else if (c->is_ws_tunnel || c->is_ws_terminate) {
                            // WebSocket tunnel/terminate: long-lived sessions
                            // have no idle keepalive timeout — a quiet-but-
                            // healthy WebSocket must not be reaped at the HTTP
                            // keep-alive deadline (RFC 6455 liveness is
                            // ping/pong, not idle close).
#endif
                        } else {
                            this->close_conn(*c);
                        }
                    });
                }
                this->fire_due_timers();
                // io_uring: sweep re-arms health-probe deadlines but issues no
                // probes (kSupportsHealthProbe == false). EPOLL-only this slice.
                this->sweep_health_probes();
                // Evict idle pooled upstream sockets past the keepalive deadline
                // (1s-granular) — bounds dead-socket accumulation for endpoints that
                // never get another request to trigger take_idle's probe.
                if (upstream)
                    upstream->sweep(static_cast<u32>(monotonic_secs()), keepalive_timeout);
                if (draining_.load(std::memory_order_acquire)) {
                    u64 start = drain_start_.load(std::memory_order_relaxed);
                    u32 period = drain_period_.load(std::memory_order_relaxed);
                    u64 now = monotonic_secs();
                    for (u32 i = 0; i < slots_initialized; i++) {
                        if (conns[i].fd >= 0 && conns[i].state == ConnState::ReadingHeader &&
                            should_drain_close(i, start, now, period)) {
                            this->close_conn(conns[i]);
                        }
                    }
                } else {
                    sweep_idle_trim();
                    pool.study_trim_bulk_idle_cache();
                }
                break;
            }
            case IoEventType::Recv:
            case IoEventType::Send:
            case IoEventType::UpstreamConnect:
            case IoEventType::UpstreamRecv:
            case IoEventType::UpstreamSend:
                if (ev.conn_id < slots_initialized) {
                    auto& conn = conns[ev.conn_id];
                    if (ev.type == IoEventType::Send && consume_tagged_send_close_event(conn, ev))
                        break;
                    if (ev.type == IoEventType::Send && consume_tls_ciphertext_send_event(conn, ev))
                        break;
                    if (consume_strict_upstream_retirement_event(conn, ev)) break;
                    if (consume_response_read_deadline_send_event(conn, ev)) break;
                    if (consume_prebuilt_http1_header_send_event(conn, ev)) break;
                    const bool stale_tagged_upstream =
                        io_event_is_tagged_stale(ev, conn.upstream_episode);
                    if (stale_tagged_upstream) {
                        // The backend has already returned any provided buffer.
                        // Retire only this completion's lifetime accounting; do
                        // not touch current callbacks, armed flags, timers, or
                        // handler state.
                        if (!ev.more && conn.pending_ops > 0) conn.pending_ops--;
                        if (conn.fd < 0 && conn.pending_ops == 0) reclaim_slot(conn.id);
                        break;
                    }
                    // A close-path downstream recv target and the cancel SQE
                    // submitted for it own separate pending-op counts.  The
                    // cancel's tagged completion carries no bytes and must not
                    // clear/rearm the target's recv_armed state.
                    if (ev.type == IoEventType::Recv && ev.aux == kDownstreamCloseCancelAux) {
                        if (ev.more || conn.pending_ops == 0) {
                            backend.fatal_error.store(EPROTO, std::memory_order_release);
                            running_.store(false, std::memory_order_release);
                            break;
                        }
                        conn.pending_ops--;
                        if (conn.fd < 0 && conn.pending_ops == 0) reclaim_slot(conn.id);
                        break;
                    }
                    // The provided ring ran empty, so the kernel ended the multishot
                    // recv before consuming any socket bytes: the request is still
                    // in the socket and the peer did nothing wrong. Never close;
                    // account the terminal and re-arm once buffers are back (see
                    // rearm_deferred_recvs). Paused/boundary connections are
                    // covered: submit_recv_impl parks the re-arm behind a pause.
                    if (ev.type == IoEventType::Recv && ev.aux == kPauseCancelAux) {
                        // This CQE owns only the cancel SQE. The recv target has
                        // an independent owner and may drain before or after it.
                        if (conn.pending_ops == 0) {
                            backend.fatal_error.store(EPROTO, std::memory_order_release);
                            running_.store(false, std::memory_order_release);
                            break;
                        }
                        conn.pending_ops--;
                        conn.recv_pause_cancel_pending = false;
                        if (conn.recv_pause_target_inflight) conn.recv_pause_rearm_pending = true;
                        if (conn.fd < 0) {
                            if (conn.pending_ops == 0) reclaim_slot(conn.id);
                            break;
                        }
                        if (conn.recv_pause_rearm_pending && !conn.recv_pause_target_inflight &&
                            !conn.recv_paused_for_send) {
                            conn.recv_pause_rearm_pending = false;
                            if (!submit_recv_impl(conn)) {
                                close_conn(conn);
                                break;
                            }
                        }
                        break;
                    }
                    if (ev.type == IoEventType::Recv && ev.provided_ring_empty &&
                        ev.result == -ENOBUFS) {
                        // F_MORE means the multishot recv is still live.
                        if (ev.more) break;
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        conn.recv_armed = false;
                        if (conn.recv_pause_target_inflight) {
                            conn.recv_pause_target_inflight = false;
                            if (conn.recv_pause_cancel_pending)
                                conn.recv_pause_rearm_pending = true;
                        }
                        if (conn.fd < 0) {
                            if (conn.pending_ops == 0) reclaim_slot(conn.id);
                            break;
                        }
                        defer_recv_rearm(conn);
                        break;
                    }
                    // A strict-retirement boundary may coexist with the
                    // long-lived downstream multishot recv. wait() has already
                    // copied positive provided-buffer bytes into recv_buf; keep
                    // them byte-exact but do not parse, route, refresh timers,
                    // invoke callbacks, or alter request state until batch-end
                    // retirement handoff. Terminal-positive rearms only this
                    // buffering recv target. EOF/error/cancel fails closed and
                    // cancels the marker without repeating request completion.
                    if (ev.type == IoEventType::Recv &&
                        (conn.http1_boundary_deferred ||
                         conn.http1_prebuilt_disposition != Http1RequestBufferDisposition::None)) {
                        if (!ev.more) {
                            if (conn.pending_ops > 0) conn.pending_ops--;
                            conn.recv_armed = false;
                            if (conn.recv_pause_target_inflight)
                                conn.recv_pause_target_inflight = false;
                        }
                        if (ev.result <= 0) {
                            // EOF/error terminates the parked boundary. Clear the
                            // rendezvous before teardown and again after deferred
                            // free bookkeeping so no late retirement CQE can publish it.
                            conn.http1_boundary_deferred = false;
                            conn.http1_boundary_ready = false;
                            conn.http1_boundary_successor_episode = 0;
                            this->close_conn(conn);
                            conn.http1_boundary_deferred = false;
                            conn.http1_boundary_ready = false;
                            conn.http1_boundary_successor_episode = 0;
                            break;
                        }
                        if (!ev.more) {
                            if (conn.recv_pause_cancel_pending) {
                                conn.recv_pause_rearm_pending = true;
                            } else if (!this->submit_recv_impl(conn)) {
                                this->close_conn(conn);
                            }
                        }
                        break;
                    }
                    // Send-wait recv pause: pause_recv() cancels the multishot
                    // recv before a non-empty wait(downstream.send()). Only the
                    // terminal -ECANCELED CQE is special-cased here (flag reset
                    // + optional rearm). A *positive* recv CQE that was already
                    // harvested into recv_buf before the cancel took effect is
                    // deliberately NOT suppressed: those bytes are always past
                    // the current request's framing (needs_req_body buffers the
                    // full Content-Length body before the handler can yield, and
                    // chunked bodies are rejected with 400), so they are the
                    // next pipelined request. Every request accessor re-parses
                    // req_data and bounds its output to the first request
                    // (rut_helper_req_body caps at content_length, path/method/
                    // header to the first request's line/block), so the larger
                    // req_len is inert — no route value can observe the raced
                    // bytes. Dropping them would instead corrupt HTTP/1.1
                    // pipelining, and would diverge from the timer/upstream wait
                    // contract that intentionally keeps such bytes (see the
                    // mid-yield stray-CQE handling below). The pause is thus
                    // best-effort liveness/buffer-pressure defence, not a hard
                    // data barrier the residual in-flight CQE could breach.
                    if (ev.type == IoEventType::Recv && ev.result == -ECANCELED &&
                        (conn.recv_pause_cancel_pending || conn.recv_pause_target_inflight ||
                         conn.recv_pause_rearm_pending)) {
                        // Both the target recv and its pause cancel own a
                        // pending operation. Either CQE may arrive first; the
                        // last owner is the only one allowed to re-arm.
                        if (conn.recv_pause_target_inflight) {
                            conn.recv_pause_target_inflight = false;
                            if (conn.pending_ops > 0) conn.pending_ops--;
                        }
                        conn.recv_pause_rearm_pending = true;
                        conn.recv_armed = false;
                        if (!conn.recv_pause_cancel_pending && !conn.recv_pause_target_inflight &&
                            !conn.recv_paused_for_send && conn.fd >= 0) {
                            conn.recv_pause_rearm_pending = false;
                            if (!this->submit_recv_impl(conn)) {
                                this->close_conn(conn);
                                break;
                            }
                        } else {
                            conn.recv_pause_rearm_pending = true;
                        }
                        break;
                    }
                    // The pause cancel's OWN completion (real conn_id + kPauseCancelAux,
                    // counted in pending_ops). The cancel has fully drained, so a freshly-
                    // armed recv on this conn_id can no longer be matched by it — re-arm
                    // now if the recv side has also drained. Carries no data.
                    if (ev.type == IoEventType::UpstreamRecv && ev.aux == kPauseCancelAux) {
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        conn.upstream_recv_pause_cancel_pending = false;
                        if (conn.fd < 0) {
                            // Connection already closed — this is a stale/close-path cancel
                            // completion. The early break below skips the generic
                            // pending_ops==0 reclaim, so reclaim here if it was the last op,
                            // or the slot leaks and proxy churn exhausts the table. A deferred
                            // close (close_after_idle_return) routes through the rearm helper
                            // instead: it pools idle_return_fd once the recv fully drains and
                            // then performs the slot-free close_conn postponed.
                            if (conn.close_after_idle_return)
                                this->try_deferred_upstream_rearm(conn);
                            else if (conn.pending_ops == 0)
                                this->reclaim_slot(conn.id);
                            break;
                        }
                        if (conn.response_read_deadline_post_commit_terminal_pending &&
                            conn.response_read_deadline_buffering ==
                                ForwardResponseBufferingMode::Bounded) {
                            if (!conn.upstream_recv_armed &&
                                !conn.upstream_recv_pause_cancel_pending &&
                                !conn.upstream_recv_cancel_inflight && !conn.send_armed &&
                                conn.response_read_timer_owner_is_neutral() &&
                                conn.response_read_deadline_post_commit_phase ==
                                    ResponseReadDeadlinePostCommitPhase::WaitingBody)
                                defer_response_read_deadline_body_pump(conn);
                            break;
                        }
                        if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                        if (conn.fd >= 0 &&
                            conn.response_read_deadline_post_commit_terminal_pending &&
                            !conn.upstream_recv_armed && !conn.upstream_recv_pause_cancel_pending &&
                            !conn.upstream_recv_cancel_inflight && !conn.send_armed &&
                            conn.response_read_deadline_post_commit_phase ==
                                ResponseReadDeadlinePostCommitPhase::WaitingBody)
                            defer_response_read_deadline_body_pump(conn);
                        break;
                    }
                    if (ev.type == IoEventType::UpstreamRecv && ev.result == -ECANCELED) {
                        // The recv was cancelled (cancel won the race). Don't clear
                        // cancel_pending or re-arm here — the cancel's own CQE owns that,
                        // and may not have drained yet. Account the recv and mark its
                        // terminal drained; re-arm fires from whichever of {recv, cancel}
                        // CQE lands second.
                        conn.upstream_recv_armed = false;
                        conn.upstream_recv_cancel_inflight = false;
                        conn.upstream_recv_terminal_stale = false;
                        // A torn-down h2-proxy episode's recv terminal has now drained,
                        // so the next episode may safely arm its own recv — but first
                        // discard any stale positive bytes wait() copied into the buffer
                        // before this terminal, or the next stream would parse them as its
                        // own response. Gated on the flag so the normal recv path (which
                        // delivers the real bytes below) is untouched.
                        if (conn.h2_proxy_recv_draining) {
                            conn.h2_proxy_recv_draining = false;
                            conn.upstream_recv_buf.reset();
                        }
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (!conn.response_read_deadline_post_commit_terminal_pending &&
                            (conn.response_read_deadline_state ==
                                 ResponseReadDeadlineState::Armed ||
                             conn.response_read_deadline_state ==
                                 ResponseReadDeadlineState::ExpiryPending)) {
                            disarm_response_read_deadline(conn);
                            if (conn.fd >= 0) this->close_conn(conn);
                            break;
                        }
                        if (conn.fd < 0) {
                            // Closed conn (e.g. the close-path cancel of an armed upstream
                            // recv): reclaim the slot if this drained the last op, since the
                            // break skips the generic reclaim below. A deferred close pools
                            // idle_return_fd + performs its postponed slot-free via the rearm
                            // helper once the recv has fully drained.
                            if (conn.close_after_idle_return)
                                this->try_deferred_upstream_rearm(conn);
                            else if (conn.pending_ops == 0)
                                this->reclaim_slot(conn.id);
                            break;
                        }
                        if (conn.response_read_deadline_post_commit_terminal_pending &&
                            conn.response_read_deadline_buffering ==
                                ForwardResponseBufferingMode::Bounded) {
                            if (!conn.upstream_recv_armed &&
                                !conn.upstream_recv_pause_cancel_pending &&
                                !conn.upstream_recv_cancel_inflight && !conn.send_armed &&
                                conn.response_read_timer_owner_is_neutral() &&
                                conn.response_read_deadline_post_commit_phase ==
                                    ResponseReadDeadlinePostCommitPhase::WaitingBody)
                                defer_response_read_deadline_body_pump(conn);
                            break;
                        }
                        if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                        if (conn.fd >= 0 &&
                            conn.response_read_deadline_post_commit_terminal_pending &&
                            !conn.upstream_recv_armed && !conn.upstream_recv_pause_cancel_pending &&
                            !conn.upstream_recv_cancel_inflight && !conn.send_armed &&
                            conn.response_read_deadline_post_commit_phase ==
                                ResponseReadDeadlinePostCommitPhase::WaitingBody)
                            defer_response_read_deadline_body_pump(conn);
                        break;
                    }
                    // Stale post-body recv data/terminal. A body-done pause cancelled this
                    // recv (cancel_inflight) at the keep-alive boundary, but its already-
                    // harvested multishot CQEs — both F_MORE data and the final terminal —
                    // still arrive, and wait() has already appended their bytes to
                    // upstream_recv_buf. Roll those bytes back and NEVER deliver: once
                    // proxy_stream_complete repoints the slot to the next pipelined request,
                    // delivering or leaving stale bytes would corrupt/close it. (The next
                    // request's recv can't have produced data yet — it re-arms only after
                    // THIS recv drains.) Only the final CQE accounts/drains the recv.
                    if (ev.type == IoEventType::UpstreamRecv &&
                        conn.upstream_recv_cancel_inflight && conn.upstream_recv_terminal_stale) {
                        const u16 custody_owner_index =
                            response_read_batch_event_index < response_read_batch_event_count
                                ? response_read_batch_event_owner[response_read_batch_event_index]
                                : 0;
                        const bool valid_bounded_terminal_custody =
                            custody_owner_index != 0 &&
                            custody_owner_index <= response_read_batch_owner_count &&
                            response_read_batch_owners[custody_owner_index - 1u]
                                .bounded_terminal_custody &&
                            response_read_batch_owners[custody_owner_index - 1u].valid &&
                            ev.result > 0 && ev.copy_witness == IoEventCopyWitness::Full;
                        const bool deadline_surplus =
                            ev.result > 0 &&
                            conn.response_read_deadline_state ==
                                ResponseReadDeadlineState::BodyComplete &&
                            conn.response_read_deadline_post_commit_phase !=
                                ResponseReadDeadlinePostCommitPhase::None &&
                            !valid_bounded_terminal_custody;
                        if (ev.result > 0) {
                            if (conn.idle_return_fd >= 0)
                                conn.upstream_recv_idle_stale_bytes = true;
                            const u32 stale = static_cast<u32>(ev.result);
                            if (conn.upstream_recv_buf.len() >= stale)
                                conn.upstream_recv_buf.set_len(conn.upstream_recv_buf.len() -
                                                               stale);
                        }
                        if (deadline_surplus) {
                            if (!ev.more) {
                                conn.upstream_recv_armed = false;
                                conn.upstream_recv_cancel_inflight = false;
                                conn.upstream_recv_terminal_stale = false;
                                if (conn.pending_ops > 0) conn.pending_ops--;
                            }
                            this->close_conn(conn);
                            break;
                        }
                        if (!ev.more) {
                            conn.upstream_recv_armed = false;
                            conn.upstream_recv_cancel_inflight = false;
                            conn.upstream_recv_terminal_stale = false;
                            if (conn.pending_ops > 0) conn.pending_ops--;
                            if (conn.fd < 0) {
                                // A deferred close pools idle_return_fd + performs its
                                // postponed slot-free via the rearm helper once the recv has
                                // fully drained; otherwise reclaim if this was the last op.
                                if (conn.close_after_idle_return)
                                    this->try_deferred_upstream_rearm(conn);
                                else if (conn.pending_ops == 0)
                                    this->reclaim_slot(conn.id);
                                break;
                            }
                            if (conn.response_read_deadline_post_commit_terminal_pending &&
                                conn.response_read_deadline_buffering ==
                                    ForwardResponseBufferingMode::Bounded) {
                                if (!conn.upstream_recv_armed &&
                                    !conn.upstream_recv_pause_cancel_pending &&
                                    !conn.upstream_recv_cancel_inflight && !conn.send_armed &&
                                    conn.response_read_timer_owner_is_neutral() &&
                                    conn.response_read_deadline_post_commit_phase ==
                                        ResponseReadDeadlinePostCommitPhase::WaitingBody)
                                    defer_response_read_deadline_body_pump(conn);
                                break;
                            }
                            if (!this->try_deferred_upstream_rearm(conn)) this->close_conn(conn);
                            if (conn.fd >= 0 &&
                                conn.response_read_deadline_post_commit_terminal_pending &&
                                !conn.upstream_recv_pause_cancel_pending && !conn.send_armed &&
                                conn.response_read_deadline_post_commit_phase ==
                                    ResponseReadDeadlinePostCommitPhase::WaitingBody)
                                defer_response_read_deadline_body_pump(conn);
                        }
                        break;
                    }
                    // Async CQE accounting: decrement pending_ops on final CQE.
                    if (!ev.more) {
                        if (conn.pending_ops > 0) conn.pending_ops--;
                        if (ev.type == IoEventType::Recv) {
                            conn.recv_armed = false;
                            if (conn.recv_pause_target_inflight) {
                                conn.recv_pause_target_inflight = false;
                                if (conn.recv_pause_cancel_pending)
                                    conn.recv_pause_rearm_pending = true;
                            }
                            if (conn.recv_pause_rearm_pending && !conn.recv_pause_cancel_pending &&
                                !conn.recv_pause_target_inflight && !conn.recv_paused_for_send &&
                                conn.fd >= 0) {
                                conn.recv_pause_rearm_pending = false;
                                if (!submit_recv_impl(conn)) {
                                    close_conn(conn);
                                    break;
                                }
                            }
                        }
                        if (ev.type == IoEventType::Send) {
                            conn.send_armed = false;
                            conn.direct_write_completion_pending = false;
                        }
                        if (ev.type == IoEventType::UpstreamConnect)
                            conn.upstream_connect_armed = false;
                        if (ev.type == IoEventType::UpstreamSend) {
                            conn.upstream_send_armed = false;
                            // A torn-down h2-proxy episode's request send has now drained, so
                            // pending_synth is free again — lift the reuse quarantine.
                            conn.h2_proxy_synth_quarantined = false;
                        }
                        if (ev.type == IoEventType::UpstreamRecv) {
                            // Recv ended normally and is NOT stale (the stale case is handled
                            // and dropped above). If a pause cancel lost the race its own CQE
                            // still clears cancel_pending and owns the re-arm; here just
                            // account, mark the recv terminal drained, and re-arm if both
                            // sides drained, then fall through to deliver the real bytes.
                            conn.upstream_recv_armed = false;
                            conn.upstream_recv_cancel_inflight = false;
                            conn.upstream_recv_terminal_stale = false;
                            // A bounded one-shot recv that found its provided ring
                            // empty consumed no socket bytes, and its owner is still
                            // waiting for them: select another buffer rather than
                            // deliver a terminal the response pumps treat as fatal
                            // (header) or as already re-armed (body). This batch's
                            // buffers were returned before dispatch.
                            const bool kOneShotRingEmpty =
                                ev.provided_ring_empty && ev.result == -ENOBUFS &&
                                (use_one_shot_websocket_recv(conn) ||
                                 use_one_shot_upstream_recv(conn) || ws_recv_cache_active(conn));
                            // A torn-down h2-proxy episode's recv terminal has now drained;
                            // discard any stale positive bytes it left so the next stream
                            // can't parse them as its response. Gated on the flag so the
                            // normal recv (delivered via dispatch_event below) is untouched
                            // — for the draining case on_upstream_recv is null, so the
                            // fall-through delivery is suppressed by the abandoned guard.
                            if (conn.h2_proxy_recv_draining) {
                                conn.h2_proxy_recv_draining = false;
                                conn.upstream_recv_buf.reset();
                            }
                            if (conn.fd < 0) {
                                // Closed conn: reclaim if this was the last op (the break
                                // below skips the generic pending_ops==0 reclaim). A deferred
                                // close pools idle_return_fd + performs its postponed slot-free
                                // via the rearm helper once the recv has fully drained.
                                if (conn.close_after_idle_return)
                                    this->try_deferred_upstream_rearm(conn);
                                else if (conn.pending_ops == 0)
                                    this->reclaim_slot(conn.id);
                                break;
                            }
                            if (!this->try_deferred_upstream_rearm(conn)) {
                                this->close_conn(conn);
                                break;
                            }
                            if (kOneShotRingEmpty) {
                                if (ws_recv_cache_active(conn)) {
                                    conn.upstream_recv_pause_rearm_pending = true;
                                    break;
                                }
                                if (!this->submit_recv_upstream(conn)) this->close_conn(conn);
                                break;
                            }
                        }
                    }
                    if (ev.type == IoEventType::UpstreamRecv &&
                        response_read_batch_event_index < response_read_batch_event_count) {
                        const u16 owner_index =
                            response_read_batch_event_owner[response_read_batch_event_index];
                        if (owner_index != 0 && owner_index <= response_read_batch_owner_count) {
                            const auto& owner = response_read_batch_owners[owner_index - 1];
                            if (owner.bounded_terminal_custody) break;
                            if (!owner.valid) break;
                            const bool retained_initial_clean_eof =
                                owner.clean_eof && !owner.post_commit_at_start &&
                                response_read_batch_event_index != owner.last_relevant &&
                                conn.id == owner.conn_id &&
                                conn.response_read_deadline_generation ==
                                    owner.deadline_generation &&
                                conn.upstream_episode == owner.upstream_episode &&
                                conn.response_read_deadline_post_commit_phase ==
                                    ResponseReadDeadlinePostCommitPhase::Buffering &&
                                (conn.response_read_deadline_state ==
                                     ResponseReadDeadlineState::RefreshPending ||
                                 conn.response_read_deadline_state ==
                                     ResponseReadDeadlineState::BodyComplete);
                            if (retained_initial_clean_eof) break;
                            const bool key_stable =
                                conn.id == owner.conn_id &&
                                conn.response_read_deadline_generation ==
                                    owner.deadline_generation &&
                                conn.upstream_episode == owner.upstream_episode &&
                                conn.response_read_deadline_state ==
                                    ResponseReadDeadlineState::BatchPending;
                            if (!key_stable || !response_read_deadline_identity_is_stable(conn)) {
                                if (conn.fd >= 0) close_conn(conn);
                                break;
                            }
                            // Backend.wait already copied every fragment.  Earlier
                            // related CQEs own accounting only; parsing the cumulative
                            // buffer exactly once at the last relevant index prevents
                            // interleaved owners and F_MORE fragments from observing a
                            // partial or future range.
                            if (response_read_batch_event_index != owner.last_relevant) break;
                        }
                    }
                    if (ev.type == IoEventType::UpstreamRecv &&
                        (conn.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                         conn.response_read_deadline_state ==
                             ResponseReadDeadlineState::ExpiryPending)) {
                        const bool matching_owner =
                            conn.response_read_deadline_owner_generation != 0 &&
                            conn.response_read_deadline_owner_generation ==
                                conn.response_read_deadline_generation &&
                            conn.response_read_deadline_upstream_episode == conn.upstream_episode &&
                            ev.upstream_episode == conn.upstream_episode && ev.aux == 0;
                        if (!matching_owner) {
                            this->close_conn(conn);
                            break;
                        }
                        const ResponseReadDeadlineProfile first_profile =
                            conn.response_read_deadline_profile;
                        const u8 first_method = conn.response_read_deadline_method;
                        const u8 first_route_method = conn.response_read_deadline_route_method;
                        const u32 first_generation = conn.response_read_deadline_generation;
                        const u16 first_bundle = conn.response_read_deadline_bundle_id;
                        const ForwardResponseBufferingMode first_buffering =
                            conn.response_read_deadline_buffering;
                        const ResponseReadDeadlineUploadProof first_upload =
                            conn.response_read_deadline_upload;
                        const bool consumed_terminal =
                            ev.result > 0 && !ev.more &&
                            current_terminal_response_recv_is_exact(conn,
                                                                    ev,
                                                                    first_generation,
                                                                    first_profile,
                                                                    first_method,
                                                                    first_upload.upload_episode);
                        const bool precise_positive =
                            response_read_deadline_uses_precise_timer(conn, consumed_terminal) &&
                            ev.result > 0 && ev.copy_witness == IoEventCopyWitness::Full;
                        if (!precise_positive) disarm_response_read_deadline(conn);
                        conn.response_read_deadline_first_batch = true;
                        conn.response_read_deadline_first_batch_profile = first_profile;
                        conn.response_read_deadline_first_batch_method = first_method;
                        conn.response_read_deadline_first_batch_route_method = first_route_method;
                        conn.response_read_deadline_first_batch_generation = first_generation;
                        conn.response_read_deadline_first_batch_bundle_id = first_bundle;
                        conn.response_read_deadline_first_batch_buffering = first_buffering;
                        conn.response_read_deadline_first_batch_upload = first_upload;
                    }
                    const bool has_recv_slot =
                        conn.on_recv && (!conn.uses_iouring_tls() || conn.tls_pending_on_recv);
                    if (has_recv_slot || conn.on_send || conn.on_upstream_recv ||
                        conn.on_upstream_send) {
                        // See EpollEventLoop: don't let stray events bump a
                        // @throttle-paused connection's byte-rate-window timer back
                        // to the keepalive timeout.
                        if (!conn.throttle_paused &&
                            conn.response_read_deadline_state != ResponseReadDeadlineState::Armed &&
                            conn.response_read_deadline_state !=
                                ResponseReadDeadlineState::ExpiryPending &&
                            conn.response_read_deadline_state !=
                                ResponseReadDeadlineState::BatchPending &&
                            conn.response_read_deadline_state !=
                                ResponseReadDeadlineState::RefreshPending)
                            timer.refresh(&conn,
                                          conn.state == ConnState::Proxying ? upstream_timeout
                                                                            : keepalive_timeout);
                        if (ev.type == IoEventType::Send) conn.clear_recv_pause_for_send();
                        this->dispatch_event(conn, ev);
                    } else if (conn.pending_handler_fn) {
                        if (yield_kind_matches_event(conn.pending_yield_kind, ev.type)) {
                            if (conn.uses_iouring_tls() && ev.type == IoEventType::Recv) {
                                conn.tls_pending_on_recv =
                                    &tls_resume_pending_handler_recv<IoUringEventLoop>;
                                tls_recv<IoUringEventLoop>(this, conn, ev);
                                if (conn.tls_active && conn.pending_handler_fn)
                                    conn.tls_pending_on_recv = nullptr;
                                break;
                            }
                            if (ev.type == IoEventType::Send) conn.clear_recv_pause_for_send();
                            disarm_yield_timer(conn);
                            conn.resume_event_kind = yield_kind_from_event(ev.type);
                            conn.resume_event_result = ev.result;
                            resume_jit_handler<IoUringEventLoop>(this, conn);
                            break;
                        }
                        // Stray CQE for a conn that's mid-yield (all slots null
                        // while the timer owns the wakeup). Provided-buffer
                        // lifetime is already handled inside
                        // IoUringBackend::wait(); this branch only decides
                        // whether the stray completion should terminate the
                        // connection.
                        //
                        // Rules:
                        //   - ev.result > 0                 → keep alive. Bytes
                        //     the peer sends during wait(ms) — segmented body,
                        //     pipelined next request — are contractually noise
                        //     for slice 0 (analyze rejects the patterns where
                        //     they'd be meaningful). Killing here would punish
                        //     legitimate clients.
                        //   - ev.result == 0 && !ev.more    → peer FIN. Close.
                        //   - ev.result < 0 (non-CANCEL)    → recv error,
                        //     including -ENOBUFS when recv_buf fills. On older
                        //     kernels -ENOBUFS can arrive with ev.more still set,
                        //     so relying on !ev.more here would let the loop
                        //     hot-spin on repeated error CQEs until the yield
                        //     deadline fires. Close unconditionally.
                        const bool kRecvError = (ev.type == IoEventType::Recv && ev.result < 0 &&
                                                 ev.result != -ECANCELED);
                        const bool kPeerClose =
                            (ev.type == IoEventType::Recv && !ev.more && ev.result == 0);
                        if (kRecvError || kPeerClose) {
                            this->close_conn(conn);
                        } else if (ev.type == IoEventType::Recv && !ev.more && ev.result > 0) {
                            // Positive-data terminal CQE: multishot ended (the
                            // generic accounting above cleared recv_armed).
                            // Re-arm so a subsequent peer disconnect during the
                            // remaining wait(ms) still produces a CQE and
                            // reaches the close_conn branch — otherwise the
                            // slot would sit occupied until the yield deadline.
                            this->submit_recv(conn);
                        }
                    } else if (conn.pending_ops == 0) {
                        // Stale CQE for a genuinely closed connection.
                        reclaim_slot(ev.conn_id);
                    }
                }
                break;
            case IoEventType::RelayRead:
            case IoEventType::RelayWrite:
                if (ev.conn_id < slots_initialized) {
                    auto& conn = conns[ev.conn_id];
                    RelayOwner& relay = conn.relay_owner;
                    const bool cancel = ev.aux == kUpstreamRetirementCancelAux;
                    if (ev.aux != 0 && !cancel) break;
                    const bool owned =
                        (ev.type == IoEventType::RelayRead && relay.phase == RelayPhase::Reading &&
                         (cancel ? relay.read_cancel_owned : relay.read_armed)) ||
                        (ev.type == IoEventType::RelayWrite && relay.phase == RelayPhase::Writing &&
                         (cancel ? relay.write_cancel_owned : relay.write_armed));
                    if (!owned || ev.upstream_episode != relay.upstream_episode)
                        break;  // stale/duplicate: no ownership mutation
                    if (conn.pending_ops == 0) {
                        conn.upstream_episode = kInvalidUpstreamEventEpisode;
                        conn.upstream_episode_quarantined = true;
                        backend.fatal_error.store(EPROTO, std::memory_order_release);
                        running_.store(false, std::memory_order_release);
                        break;
                    }
                    const u32 wait_kind = ev.type == IoEventType::RelayRead ? 0 : 1;
                    const u64 started = study_poll_started[wait_kind][conn.id];
                    study_poll_started[wait_kind][conn.id] = 0;
                    if (!cancel && started != 0)
                        study_record_wait(wait_kind, monotonic_ns() - started);
                    --conn.pending_ops;
                    if (ev.type == IoEventType::RelayRead) {
                        if (cancel)
                            relay.read_cancel_owned = false;
                        else {
                            relay.read_armed = false;
                            if (relay.read_cancel_retry) {
                                relay.read_cancel_retry = false;
                                if (relay_cancel_retry_count == 0) {
                                    conn.upstream_episode = kInvalidUpstreamEventEpisode;
                                    conn.upstream_episode_quarantined = true;
                                    backend.fatal_error.store(EPROTO, std::memory_order_release);
                                    running_.store(false, std::memory_order_release);
                                    break;
                                }
                                --relay_cancel_retry_count;
                            }
                        }
                    } else {
                        if (cancel)
                            relay.write_cancel_owned = false;
                        else {
                            relay.write_armed = false;
                            if (relay.write_cancel_retry) {
                                relay.write_cancel_retry = false;
                                if (relay_cancel_retry_count == 0) {
                                    conn.upstream_episode = kInvalidUpstreamEventEpisode;
                                    conn.upstream_episode_quarantined = true;
                                    backend.fatal_error.store(EPROTO, std::memory_order_release);
                                    running_.store(false, std::memory_order_release);
                                    break;
                                }
                                --relay_cancel_retry_count;
                            }
                        }
                    }
                    const bool canonical_common = !ev.more && ev.has_buf == 0 && ev.buf_id == 0 &&
                                                  ev.copy_witness == IoEventCopyWitness::None;
                    const bool canonical = canonical_common && (cancel || ev.aux == 0);
                    const bool endpoint_ok =
                        relay.close_pending ||
                        (conn.upstream_fd == relay.source_fd && conn.fd == relay.destination_fd);
                    if (!canonical || (!relay.close_pending && !endpoint_ok)) {
                        close_conn(conn);
                        break;
                    }
                    if (cancel) {
                        if (relay.close_pending && !relay.read_armed && !relay.write_armed &&
                            !relay.read_cancel_owned && !relay.write_cancel_owned &&
                            !relay.read_cancel_retry && !relay.write_cancel_retry)
                            close_response_splice_pipe(conn);
                        break;
                    }
                    if (relay.close_pending) {
                        if (!relay.read_armed && !relay.write_armed && !relay.read_cancel_owned &&
                            !relay.write_cancel_owned && !relay.read_cancel_retry &&
                            !relay.write_cancel_retry)
                            close_response_splice_pipe(conn);
                        break;
                    }
                    on_response_splice_event(conn, ev);
                }
                break;
            case IoEventType::ResponseReadTimer:
                if (ev.conn_id < slots_initialized &&
                    valid_response_read_timer_transport_event(ev)) {
                    auto& c = conns[ev.conn_id];
                    // Timer CQEs are settled after the complete wait batch so
                    // a same-batch positive Full-copy response wins regardless
                    // of CQE order. Direct dispatch callers retain the simple
                    // consume-only behavior.
                    if (response_read_batch_event_count == 0) {
                        if (c.consume_response_read_timer_completion(ev.non_upstream_generation) &&
                            c.response_read_timer_owner_is_neutral()) {
                            maybe_publish_http1_boundary_ready(c);
                            reclaim_pending();
                        }
                    }
                }
                break;
            case IoEventType::Count:
                break;
        }
    }

    // Forced drain-deadline shutdown: close every live client, then close any
    // upstream fd still parked for a deferred idle-pool return. Public so the
    // deferred-fd close path is unit-testable. Called only from run().
    void force_close_all() {
        close_live_clients();
        close_deferred_idle_return_fds();
    }

private:
    using Self = IoUringEventLoop;

    void close_live_clients() {
        for (u32 i = 0; i < slots_initialized; i++) {
            if (conns[i].fd >= 0) {
                // A LIVE keep-alive client can also hold a parked idle_return_fd while
                // its upstream recv cancel drains. close_conn takes the deferred path
                // here (keeps the conn allocated, leaves idle_return_fd for a future
                // CQE) — so the fd survives below and is closed there.
                this->close_conn(conns[i]);
            }
        }
    }

    void close_deferred_idle_return_fds() {
        for (u32 i = 0; i < slots_initialized; i++) {
            // A reusable upstream fd is parked in idle_return_fd awaiting a recv-cancel
            // drain that this forced shutdown will never deliver — close it directly so
            // it can't leak. Covers both a slot whose client fd was already closed
            // (deferred-close) and a live client just torn down above whose close_conn
            // took the deferred path. close_conn's synchronous path already pooled/closed
            // and set idle_return_fd = -1, so the guard prevents a double-close.
            if (conns[i].idle_return_fd >= 0) {
                ::close(conns[i].idle_return_fd);
                conns[i].idle_return_fd = -1;
                conns[i].idle_return_config = nullptr;
            }
        }
    }

    // Arm multishot accept; a failed arm (no SQE) retries on the next tick.
    // Never arms once the listener is closed.
    void rearm_accept() {
        if (listen_fd < 0) {
            accept_rearm_pending = false;
            return;
        }
        accept_rearm_pending = !backend.add_accept();
    }

    // A multishot accept ends with a CQE lacking F_MORE (EMFILE/ENFILE/ENOMEM/
    // ENOBUFS, ECONNABORTED, CQ overflow, cancel). Without a re-arm this shard
    // never accepts again while the kernel keeps steering SO_REUSEPORT
    // connections to it.
    void on_accept_terminated(i32 result) {
        if (listen_fd < 0) return;  // intentional close_listen(): stay down
        if (result >= 0) {
            rearm_accept();
            return;
        }
        switch (-result) {
            // Immediate: the failing connection was consumed from the backlog,
            // so the next accept makes progress.
            case ECONNABORTED:
            case EINTR:
            case EAGAIN:
            case EPROTO:
            case ENOPROTOOPT:
            case ENETDOWN:
            case ENONET:
            case EHOSTDOWN:
            case EHOSTUNREACH:
            case ENETUNREACH:
                rearm_accept();
                return;
            // Permanent: the listener itself is unusable.
            case EBADF:
            case ENOTSOCK:
            case EINVAL:
            case EOPNOTSUPP:
                return;
            // Deferred to the next tick: the backlog entry was not consumed
            // (EMFILE/ENFILE/ENOBUFS/ENOMEM, LSM EPERM/EACCES), so an immediate
            // re-arm would spin; or the cause is unknown. ECANCELED lands here
            // too: our own close_listen() was filtered out above, so it is a
            // kernel-side cancel (failed CQE post, io-wq cancel), not ours.
            default:
                accept_rearm_pending = true;
                return;
        }
    }

    void on_accept(const IoEvent& ev) {
        if (ev.result >= 0) on_accepted_fd(ev);
        if (!ev.more) on_accept_terminated(ev.result);
    }

    void on_accepted_fd(const IoEvent& ev) {
        Connection* c = this->alloc_conn();
        if (!c) {
            // Try reclaiming slots from stale CQEs.
            reclaim_pending();
            c = this->alloc_conn();
            if (!c) {
                // Defer the accept fd and retry after the batch finishes.
                if (deferred_accept_count < kMaxDeferredAccepts) {
                    deferred_accepts[deferred_accept_count++] = ev.result;
                } else {
                    ::close(ev.result);
                }
                return;
            }
        }
        c->fd = ev.result;
        struct sockaddr_in peer = {};
        socklen_t peer_len = sizeof(peer);
        if (::getpeername(c->fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
            peer.sin_family == AF_INET) {
            c->peer_addr = peer.sin_addr.s_addr;
            c->peer_port = ntohs(peer.sin_port);
        }
        c->state = ConnState::ReadingHeader;
        c->keep_alive = !draining_.load(std::memory_order_relaxed);
        if (tls_server) {
            if (!tls_setup(*c)) {
                ::close(c->fd);
                c->fd = -1;
                this->free_conn(*c);
                return;
            }
        } else {
            c->on_recv = &on_header_received<Self>;
        }
        timer.add(c, keepalive_timeout);
        if (metrics) metrics->on_accept();
        this->submit_recv(*c);
    }

    void retry_deferred_accepts() {
        for (u32 i = 0; i < deferred_accept_count; i++) {
            i32 fd = deferred_accepts[i];
            Connection* c = this->alloc_conn();
            if (!c) {
                ::close(fd);
                continue;
            }
            c->fd = fd;
            struct sockaddr_in peer = {};
            socklen_t peer_len = sizeof(peer);
            if (::getpeername(c->fd, reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0 &&
                peer.sin_family == AF_INET) {
                c->peer_addr = peer.sin_addr.s_addr;
                c->peer_port = ntohs(peer.sin_port);
            }
            c->state = ConnState::ReadingHeader;
            c->keep_alive = !draining_.load(std::memory_order_relaxed);
            if (tls_server) {
                if (!tls_setup(*c)) {
                    ::close(c->fd);
                    c->fd = -1;
                    this->free_conn(*c);
                    continue;
                }
            } else {
                c->on_recv = &on_header_received<Self>;
            }
            timer.add(c, keepalive_timeout);
            if (metrics) metrics->on_accept();
            this->submit_recv(*c);
        }
        deferred_accept_count = 0;
    }

    void close_listen() {
        if (listen_fd >= 0) {
            backend.cancel_accept();
            ::close(listen_fd);
            listen_fd = -1;
            // Keep the backend from ever re-arming on a closed/recycled fd.
            backend.listen_fd = -1;
            accept_rearm_pending = false;
        }
    }
};

}  // namespace rut
