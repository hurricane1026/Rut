#pragma once
#include "rut/runtime/connection.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/mapped_array.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rut {
// Experimental opaque plaintext tunnel. One pinned owner and two independent
// pipe/readiness ledgers; no application framing or response-size prediction.
struct WsSpliceExperiment {
    struct Direction {
        i32 read_fd = -1, write_fd = -1;
        u32 buffered = 0;
        bool eof = false, armed = false, writing = false, cancel_owned = false;
        // A cancel CQE can precede its target poll CQE. Keep the target's
        // cancellation state until that poll retires, so it is never canceled twice.
        bool cancel_acknowledged = false;
        bool copying = false, probe_copy = true;
        bool splice_inflight = false;
        bool pair_active = false;
        u8 pair_pending = 0, pair_cancel_owned = 0, pair_cancel_acknowledged = 0;
        i32 pair_read_result = 0, pair_write_result = 0;
    };
    struct Owner {
        Direction direction[2];
        i32 retiring_client = -1, retiring_upstream = -1;
        u32 episode = 0;
        u8 next_direction = 0;
        // Diagnostic storage is unconditional to keep Owner layout identical
        // across rut_runtime and RUT_TESTING translation units.
        u64 eof_read_calls[2]{}, eof_forwarded_bytes[2]{};
        u32 eof_opposite_buffered_at_snapshot = 0;
        bool eof_snapshot_taken = false, eof_reverse_write_cancel_attempted = false,
             eof_cancel_retry_deferred = false;
        bool requested = false, active = false, closing = false, eof_closing = false,
             queued = false, failed = false, budget_deferred = false, reclaim_pending = false;
    };
    MappedArray<Owner> owners;
    MappedArray<u32> queued;
    u32 queued_count = 0, queued_head = 0, turn_budget_remaining = 0;
    u32 budget_deferred_runnable_count = 0;
    bool turn_budget_active = false;
    bool budget_deferred_runnable = false;
    u32 admission_budget_remaining = 0;
    bool asynchronous = false, linked = false, poll_next_read = false;
    bool async_queue_budget = false;
    u32 turn_call_limit = 8;
    u64 ordinary_since_ns = 0;
    u64 queue_budget_yields = 0;
    bool queue_budget_yielded = false;
    bool enabled = false, copy_first = false, check_available = false, fast_batch = false;
    bool fast_scan = false, last_batch_ws_only = false;
    u64 deadline_batches_skipped = 0, terminal_scans_skipped = 0;
    bool no_delay = true;
    u64 nodelay_changes = 0, nodelay_failures = 0;
    u64 admissions = 0, transferred[2]{}, calls = 0, read_calls[2]{};
    u32 chunk_size = 65536, call_budget = 8;
    u32 copy_limit = 4096;
    u64 polls = 0, eagain[2]{}, pipe_grow_failures = 0;
    u32 minimum_pipe_capacity = 0xffffffffu;
    bool enable(u32 capacity) {
        if (!owners.init(capacity) || !queued.init(capacity)) return false;
        enabled = true;
        queued_head = queued_count = 0;
        budget_deferred_runnable_count = 0;
        budget_deferred_runnable = false;
        return true;
    }
    template <class Loop>
    void begin_turn(Loop& loop) {
        turn_call_limit = async_queue_budget && asynchronous && loop.backend.splice_supported
                              ? loop.backend.sq_ring_entries
                              : call_budget;
        turn_budget_remaining = turn_call_limit;
        admission_budget_remaining = 1;
        turn_budget_active = true;
        ordinary_since_ns = async_queue_budget && asynchronous && loop.backend.splice_supported &&
                                    loop.has_ordinary_cq_work()
                                ? monotonic_ns()
                                : 0;
        queue_budget_yielded = false;
    }

    template <class Loop>
    bool yield_for_ordinary_cq(Loop& loop, u32 id) {
        if (!async_queue_budget || !asynchronous || !loop.backend.splice_supported) return false;
        if (queue_budget_yielded) {
            set_budget_deferred(id, true);
            enqueue(id);
            return true;
        }
        if (!loop.has_ordinary_cq_work()) {
            ordinary_since_ns = 0;
            return false;
        }
        const u64 now = monotonic_ns();
        if (ordinary_since_ns == 0) ordinary_since_ns = now;
        if (now - ordinary_since_ns < loop.ordinary_cq_wait_limit_ns) return false;
        queue_budget_yielded = true;
        ++queue_budget_yields;
        turn_budget_remaining = 0;
        set_budget_deferred(id, true);
        enqueue(id);
        return true;
    }
    void enqueue(u32 id) {
        if (!owners[id].queued) {
            owners[id].queued = true;
            queued[(queued_head + queued_count) % queued.size()] = id;
            ++queued_count;
            if (owners[id].budget_deferred) ++budget_deferred_runnable_count;
            budget_deferred_runnable = budget_deferred_runnable_count != 0;
        }
    }
    void set_budget_deferred(u32 id, bool deferred) {
        auto& owner = owners[id];
        if (owner.budget_deferred == deferred) return;
        if (owner.queued) {
            if (deferred)
                ++budget_deferred_runnable_count;
            else if (budget_deferred_runnable_count != 0)
                --budget_deferred_runnable_count;
        }
        owner.budget_deferred = deferred;
        budget_deferred_runnable = budget_deferred_runnable_count != 0;
    }
    u32 dequeue() {
        const u32 id = queued[queued_head];
        queued_head = (queued_head + 1) % queued.size();
        --queued_count;
        owners[id].queued = false;
        if (owners[id].budget_deferred && budget_deferred_runnable_count != 0)
            --budget_deferred_runnable_count;
        budget_deferred_runnable = budget_deferred_runnable_count != 0;
        return id;
    }
    static void close_pipes(Owner& owner) {
        if (owner.retiring_client >= 0) ::close(owner.retiring_client);
        if (owner.retiring_upstream >= 0) ::close(owner.retiring_upstream);
        owner.retiring_client = owner.retiring_upstream = -1;
        for (auto& d : owner.direction) {
            if (d.read_fd >= 0) ::close(d.read_fd);
            if (d.write_fd >= 0) ::close(d.write_fd);
            d.read_fd = d.write_fd = -1;
            d.buffered = 0;
        }
    }
    void shutdown() {
        if (enabled)
            for (u32 i = 0; i < owners.size(); ++i) close_pipes(owners[i]);
        owners.destroy();
        queued.destroy();
        enabled = false;
        queued_head = queued_count = 0;
        budget_deferred_runnable_count = 0;
        budget_deferred_runnable = false;
        turn_budget_active = false;
    }
    template <class Loop>
    bool intercept_recv(Loop& loop, Connection& c) {
        if (!enabled || !c.is_ws_tunnel || c.is_ws_terminate || c.is_ws_terminate_route ||
            c.tls_active || c.protocol != ConnProtocol::Http11 || c.throttle_down_bps != 0 ||
            c.response_policy_id != 0 || c.fd < 0 || c.upstream_fd < 0)
            return false;
        auto& o = owners[c.id];
        if (o.failed) return false;
        if (!o.requested && !o.active && !o.closing) {
            o = {};
            o.requested = true;
            o.episode = c.upstream_episode;
            ++c.pending_ops;  // owner pin survives handoff and cancel submission retries
            enqueue(c.id);
        }
        if (o.active || o.closing) return true;
        if (c.recv_armed && !c.recv_pause_cancel_pending && !c.recv_pause_target_inflight)
            if (!loop.pause_recv(c)) {
                loop.close_conn(c);
                return true;
            }
        if (c.upstream_recv_armed && !c.upstream_recv_pause_cancel_pending &&
            !c.upstream_recv_cancel_inflight)
            if (!loop.pause_upstream_recv(c)) {
                loop.close_conn(c);
                return true;
            }
        return true;
    }
    template <class Loop>
    bool arm(Loop& loop, Connection& c, u32 index, bool writing) {
        auto& o = owners[c.id];
        auto& d = o.direction[index];
        const i32 kSource = index == 0 ? c.fd : c.upstream_fd;
        const i32 kDestination = index == 0 ? c.upstream_fd : c.fd;
        const auto kType = writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
        if (!loop.backend.add_relay_poll(writing ? kDestination : kSource,
                                         c.id,
                                         kType,
                                         o.episode,
                                         static_cast<u8>(32 + index)))
            return false;
        ++polls;
        d.armed = true;
        d.writing = writing;
        ++c.pending_ops;
        return true;
    }
    template <class Loop>
    void finish_eof_close(Loop& loop, Connection& c) {
        auto& o = owners[c.id];
        if (!o.eof_closing) return;
        for (u32 index = 0; index < 2; ++index) {
            auto& d = o.direction[index];
            if (!d.eof || d.buffered != 0) return;
            if (d.armed || d.cancel_owned || d.cancel_acknowledged) {
                if (d.armed && !d.cancel_owned && !d.cancel_acknowledged) {
                    const auto kType = d.writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
                    const u64 kTarget = encode_upstream_event_token(
                        {c.id, kType, o.episode, static_cast<u8>(32 + index)});
#ifdef RUT_TESTING
                    const bool kCancelSubmitted =
                        loop.test_consume_ws_splice_cancel_failure()
                            ? false
                            : loop.backend.cancel_ws_splice_poll(
                                  kTarget, c.id, kType, static_cast<u8>(96 + index), o.episode);
#else
                    const bool kCancelSubmitted = loop.backend.cancel_ws_splice_poll(
                        kTarget, c.id, kType, static_cast<u8>(96 + index), o.episode);
#endif
                    if (kCancelSubmitted) {
                        d.cancel_owned = true;
                        ++c.pending_ops;
                    } else {
                        set_budget_deferred(c.id, true);
                        enqueue(c.id);
                    }
                }
                return;
            }
        }
        // Hand the owner pin to the normal close/cancel ledger. Keeping this
        // EOF marker set would make progress call close_conn again after the
        // last poll CQE retires.
        o.eof_closing = false;
        loop.close_conn(c);
    }
    // One outstanding splice, linked pair, or readiness poll per direction. A pipe is kept
    // alive until both its target CQE and any cancel CQE have retired.
    template <class Loop>
    void pump_async(Loop& loop, Connection& c, u32 index) {
        auto& o = owners[c.id];
        auto& d = o.direction[index];
        if (!o.active || o.closing || d.armed || d.cancel_owned || d.cancel_acknowledged ||
            d.pair_active)
            return;
        if (d.eof && d.buffered == 0) {
            if (o.direction[index ^ 1u].eof && o.direction[index ^ 1u].buffered == 0)
                loop.close_conn(c);
            return;
        }
        if (yield_for_ordinary_cq(loop, c.id)) return;
        if (turn_budget_remaining == 0) {
            set_budget_deferred(c.id, true);
            enqueue(c.id);
            return;
        }
        const bool writing = d.buffered != 0;
        const i32 source = index == 0 ? c.fd : c.upstream_fd;
        const i32 destination = index == 0 ? c.upstream_fd : c.fd;
        if (linked && !writing && turn_budget_remaining >= 2) {
            // A hard link preserves the write after a short read. Each direction
            // owns an empty private pipe, so the write cannot consume more than
            // this read actually produced. Account only after both CQEs arrive.
            if (!loop.backend.add_relay_splice_pair(source,
                                                    d.write_fd,
                                                    d.read_fd,
                                                    destination,
                                                    c.id,
                                                    o.episode,
                                                    chunk_size,
                                                    false,
                                                    true,
                                                    static_cast<u8>(32 + index))) {
                loop.close_conn(c);
                return;
            }
            turn_budget_remaining -= 2;
            calls += 2;
            ++read_calls[index];
            d.pair_active = true;
            d.pair_pending = 3;
            d.pair_read_result = d.pair_write_result = 0;
            c.pending_ops += 2;
            if (turn_budget_remaining == 0) {
                set_budget_deferred(c.id, true);
                enqueue(c.id);
            }
            return;
        }
        if (!loop.backend.add_relay_splice(
                writing ? d.read_fd : source,
                writing ? destination : d.write_fd,
                c.id,
                writing ? IoEventType::RelayWrite : IoEventType::RelayRead,
                o.episode,
                writing ? d.buffered : chunk_size,
                false,
                static_cast<u8>(32 + index))) {
            loop.close_conn(c);
            return;
        }
        --turn_budget_remaining;
        ++calls;
        if (!writing) ++read_calls[index];
        d.writing = writing;
        d.splice_inflight = d.armed = true;
        ++c.pending_ops;
        if (turn_budget_remaining == 0) {
            set_budget_deferred(c.id, true);
            enqueue(c.id);
        }
    }
    template <class Loop>
    void pump(Loop& loop, Connection& c, u32 index) {
        if (asynchronous && loop.backend.splice_supported) {
            pump_async(loop, c, index);
            return;
        }
        auto& o = owners[c.id];
        auto& d = o.direction[index];
        if (!o.active || o.closing || d.armed || d.cancel_owned || d.cancel_acknowledged) return;
        if (d.eof && d.buffered == 0) {
            finish_eof_close(loop, c);
            return;
        }
        const i32 kSource = index == 0 ? c.fd : c.upstream_fd;
        const i32 kDestination = index == 0 ? c.upstream_fd : c.fd;
        // A full copied prefix can leave immediately available bytes behind it.
        // Permit one additional read/write pair before yielding, bounded to
        // two extra syscalls per turn; never extend from a guessed frame size.
        u32 turn_limit = call_budget;
        bool extended = false;
        for (u32 budget = 0; budget < turn_limit && turn_budget_remaining != 0; ++budget) {
            const bool kWriting = d.buffered != 0;
            auto& buffer = index == 0 ? c.recv_buf : c.upstream_recv_buf;
            bool copy = kWriting ? d.copying : (copy_first && d.probe_copy);
            const u32 kCopyLength =
                buffer.write_avail() < copy_limit ? buffer.write_avail() : copy_limit;
            if (!kWriting && copy && check_available) {
                int available = 0;
                if (::ioctl(kSource, FIONREAD, &available) == 0 &&
                    available > static_cast<int>(kCopyLength)) {
                    copy = false;
                    d.probe_copy = false;
                }
            }
            if (!kWriting && copy && kCopyLength == 0) {
                loop.close_conn(c);
                return;
            }
            const u32 kKind = kWriting ? 1u : 0u;
            const bool kSampled =
                loop.backend.study_io_stats && (++loop.study_splice_calls[kKind] & 63u) == 0;
            const u64 kStarted = kSampled ? monotonic_ns() : 0;
            ssize_t n;
            do {
                ++calls;
                --turn_budget_remaining;
                if (!kWriting) ++read_calls[index];
#ifdef RUT_TESTING
                if (loop.test_eintr_next_ws_splice_call) {
                    loop.test_eintr_next_ws_splice_call = false;
                    n = -1;
                    errno = EINTR;
                } else
#endif
                {
                    if (copy) {
                        n = kWriting
                                ? ::send(kDestination,
                                         buffer.data(),
                                         d.buffered,
                                         MSG_DONTWAIT | MSG_NOSIGNAL)
                                : ::recv(kSource, buffer.write_ptr(), kCopyLength, MSG_DONTWAIT);
                    } else
                        n = kWriting ? ::splice(d.read_fd,
                                                nullptr,
                                                kDestination,
                                                nullptr,
                                                d.buffered,
                                                SPLICE_F_NONBLOCK | SPLICE_F_MOVE)
                                     : ::splice(kSource,
                                                nullptr,
                                                d.write_fd,
                                                nullptr,
                                                chunk_size,
                                                SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
                }
            } while (n < 0 && errno == EINTR && turn_budget_remaining != 0);
            if (kSampled) {
                const int kSavedErrno = errno;
                loop.study_record_syscall(kKind, monotonic_ns() - kStarted);
                errno = kSavedErrno;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                ++eagain[kWriting ? 1 : 0];
                if (!kWriting) d.probe_copy = true;
                if (!arm(loop, c, index, kWriting)) loop.close_conn(c);
                const auto& other = o.direction[index ^ 1u];
                // If this was the last call, the opposite direction still needs
                // one probe before both directions can sleep on readiness.
                if (turn_budget_remaining == 0 && !other.armed && !other.cancel_owned &&
                    !other.cancel_acknowledged && (!other.eof || other.buffered != 0))
                    set_budget_deferred(c.id, true);
                o.next_direction = static_cast<u8>(index ^ 1u);
                enqueue(c.id);
                return;
            }
            if (n < 0 && errno == EINTR && turn_budget_remaining == 0) {
                o.next_direction = static_cast<u8>(index);
                set_budget_deferred(c.id, true);
                enqueue(c.id);
                return;
            }
            if (n < 0 || (kWriting && n == 0)) {
                loop.close_conn(c);
                return;
            }
            if (!kWriting && n == 0) {
                d.eof = true;
                (void)::shutdown(kDestination, SHUT_WR);
                o.eof_closing = true;
#ifdef RUT_TESTING
                if (!o.eof_snapshot_taken) {
                    o.eof_snapshot_taken = true;
                    for (u32 direction = 0; direction < 2; ++direction) {
                        o.eof_read_calls[direction] = read_calls[direction];
                        o.eof_forwarded_bytes[direction] =
                            transferred[direction] + o.direction[direction].buffered;
                    }
                }
#endif
                // Keep the owner queued: a failed cancellation submission must
                // be retried by the next progress turn until its cancel CQE.
                o.requested = true;
                const u32 kOther = index ^ 1u;
                auto& other = o.direction[kOther];
                other.eof = true;
#ifdef RUT_TESTING
                o.eof_opposite_buffered_at_snapshot = other.buffered;
                o.eof_reverse_write_cancel_attempted = other.armed && other.writing &&
                                                       !other.cancel_owned &&
                                                       !other.cancel_acknowledged;
#endif
                // A buffered reverse write is part of the EOF snapshot and
                // must drain before either endpoint is closed. Only an armed
                // read can be canceled to stop new bytes entering the pipe.
                if (other.armed && !other.writing && !other.cancel_owned &&
                    !other.cancel_acknowledged) {
                    const auto kType =
                        other.writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
                    const u64 kTarget = encode_upstream_event_token(
                        {c.id, kType, o.episode, static_cast<u8>(32 + kOther)});
                    const bool kCancelSubmitted =
#ifdef RUT_TESTING
                        loop.test_consume_ws_splice_cancel_failure()
                            ? false
                            : loop.backend.cancel_ws_splice_poll(
                                  kTarget, c.id, kType, static_cast<u8>(96 + kOther), o.episode);
#else
                        loop.backend.cancel_ws_splice_poll(
                            kTarget, c.id, kType, static_cast<u8>(96 + kOther), o.episode);
#endif
                    if (kCancelSubmitted) {
                        other.cancel_owned = true;
                        ++c.pending_ops;
                    } else {
                        // The owner may have been dequeued before this EOF
                        // arrived. Keep it runnable so cancellation is retried
                        // without waiting for unrelated readiness.
                        set_budget_deferred(c.id, true);
                        enqueue(c.id);
#ifdef RUT_TESTING
                        o.eof_cancel_retry_deferred = true;
#endif
                    }
                }
                pump(loop, c, kOther);
                finish_eof_close(loop, c);
                return;
            }
            if (kWriting) {
                d.buffered -= static_cast<u32>(n);
                if (copy) buffer.consume(static_cast<u32>(n));
                transferred[index] += static_cast<u32>(n);
                if (d.eof && d.buffered == 0) {
                    finish_eof_close(loop, c);
                    return;
                }
            } else {
                d.copying = copy;
                d.buffered = static_cast<u32>(n);
                if (copy) {
                    buffer.commit(static_cast<u32>(n));
                    if (static_cast<u32>(n) == kCopyLength) {
                        d.probe_copy = false;
                        if (!extended) {
                            turn_limit += 2;
                            extended = true;
                        }
                    }
                }
            }
        }
        if (turn_budget_remaining == 0) {
            o.next_direction = static_cast<u8>(d.buffered != 0 ? index : (index ^ 1u));
            set_budget_deferred(c.id, true);
            enqueue(c.id);
            return;
        }
        if (!arm(loop, c, index, d.buffered != 0)) loop.close_conn(c);
        finish_eof_close(loop, c);
    }
    template <class Loop>
    void close(Loop& loop, Connection& c) {
        if (!enabled) return;
        auto& o = owners[c.id];
        if (o.failed) {
            o = {};
            return;
        }
        if (!o.requested && !o.active && !o.closing) return;
        // An external close can race a queued EOF completion. From this point
        // the ordinary close ledger owns the polls and the owner pin.
        o.eof_closing = false;
        o.closing = true;
        o.requested = false;
        o.active = false;
        if (asynchronous && (o.direction[0].armed || o.direction[1].armed ||
                             o.direction[0].pair_active || o.direction[1].pair_active)) {
            o.retiring_client = c.fd;
            o.retiring_upstream = c.upstream_fd;
        }
        if (!asynchronous) close_pipes(o);
        enqueue(c.id);
        retire(loop, c);
    }
    template <class Loop>
    void retire(Loop& loop, Connection& c) {
        auto& o = owners[c.id];
        if (!o.closing) return;
        bool pending = false;
        for (u32 index = 0; index < 2; ++index) {
            auto& d = o.direction[index];
            if (d.pair_active) {
                for (u8 side = 0; side < 2; ++side) {
                    const u8 bit = static_cast<u8>(1u << side);
                    if (!(d.pair_pending & bit) || (d.pair_cancel_owned & bit) ||
                        (d.pair_cancel_acknowledged & bit))
                        continue;
                    const auto type = side == 0 ? IoEventType::RelayRead : IoEventType::RelayWrite;
                    const u64 target = encode_upstream_event_token(
                        {c.id, type, o.episode, static_cast<u8>(32 + index)});
                    bool submitted = false;
#ifdef RUT_TESTING
                    if (!loop.test_consume_ws_splice_cancel_failure())
#endif
                        submitted = loop.backend.cancel_ws_splice_poll(
                            target, c.id, type, static_cast<u8>(96 + index), o.episode);
                    if (submitted) {
                        d.pair_cancel_owned |= bit;
                        ++c.pending_ops;
                    } else {
                        set_budget_deferred(c.id, true);
                        enqueue(c.id);
                    }
                }
                const bool pair_pending =
                    d.pair_pending || d.pair_cancel_owned || d.pair_cancel_acknowledged;
                pending = pending || pair_pending;
                if (!pair_pending) d.pair_active = false;
            }
            if (d.armed && !d.cancel_owned && !d.cancel_acknowledged) {
                const auto kType = d.writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
                const u64 kTarget = encode_upstream_event_token(
                    {c.id, kType, o.episode, static_cast<u8>(32 + index)});
                bool submitted = false;
#ifdef RUT_TESTING
                if (!loop.test_consume_ws_splice_cancel_failure())
#endif
                    submitted = loop.backend.cancel_ws_splice_poll(
                        kTarget, c.id, kType, static_cast<u8>(96 + index), o.episode);
                if (submitted) {
                    d.cancel_owned = true;
                    ++c.pending_ops;
                } else {
                    set_budget_deferred(c.id, true);
                    enqueue(c.id);
                }
            }
            pending = pending || d.armed || d.cancel_owned || d.cancel_acknowledged;
        }
        if (!pending) {
            close_pipes(o);
            o.closing = false;
            if (c.pending_ops == 0)
                loop.backend.fatal_error.store(EPROTO);
            else {
                --c.pending_ops;
                if (c.fd < 0 && c.pending_ops == 0) {
                    if (o.queued)
                        o.reclaim_pending = true;
                    else
                        loop.reclaim_slot(c.id);
                }
            }
        }
    }
    template <class Loop>
    void dispatch_pair(Loop& loop, Connection& c, const IoEvent& ev, u32 index, bool cancel) {
        auto& o = owners[c.id];
        auto& d = o.direction[index];
        const u8 bit = ev.type == IoEventType::RelayRead ? 1 : 2;
        if (!((cancel ? d.pair_cancel_owned : d.pair_pending) & bit)) return;
        if (c.pending_ops == 0 || ev.more || ev.has_buf) {
            loop.backend.fatal_error.store(EPROTO);
            return;
        }
        --c.pending_ops;
        if (cancel) {
            d.pair_cancel_owned &= static_cast<u8>(~bit);
            if (d.pair_pending & bit) d.pair_cancel_acknowledged |= bit;
        } else {
            d.pair_pending &= static_cast<u8>(~bit);
            d.pair_cancel_acknowledged &= static_cast<u8>(~bit);
            if (bit == 1)
                d.pair_read_result = ev.result;
            else
                d.pair_write_result = ev.result;
        }
        if (o.closing) {
            retire(loop, c);
            return;
        }
        if (d.pair_pending || d.pair_cancel_owned || d.pair_cancel_acknowledged) return;
        d.pair_active = false;
        const i32 read = d.pair_read_result, written = d.pair_write_result;
        const bool write_empty = written == -EAGAIN || written == -EWOULDBLOCK || written == 0;
        if (read == -EAGAIN || read == -EWOULDBLOCK) ++eagain[0];
        if (written == -EAGAIN || written == -EWOULDBLOCK) ++eagain[1];
        if (read < 0) {
            if ((read == -EAGAIN || read == -EWOULDBLOCK || read == -EINTR) && write_empty) {
                if (!arm(loop, c, index, false)) loop.close_conn(c);
            } else
                loop.close_conn(c);
            return;
        }
        if (read == 0) {
            if (!write_empty) {
                loop.close_conn(c);
                return;
            }
            d.eof = true;
            (void)::shutdown(index == 0 ? c.upstream_fd : c.fd, SHUT_WR);
            pump(loop, c, index);
            return;
        }
        if (static_cast<u32>(read) > chunk_size || written > read || written == 0 ||
            (written < 0 && written != -EAGAIN && written != -EWOULDBLOCK && written != -EINTR)) {
            loop.close_conn(c);
            return;
        }
        const u32 sent = written > 0 ? static_cast<u32>(written) : 0;
        d.buffered = static_cast<u32>(read) - sent;
        transferred[index] += sent;
        if (written == -EAGAIN || written == -EWOULDBLOCK) {
            if (!arm(loop, c, index, true)) loop.close_conn(c);
        } else if (poll_next_read && d.buffered == 0) {
            if (!arm(loop, c, index, false)) loop.close_conn(c);
        } else
            pump(loop, c, index);
    }
    template <class Loop>
    bool dispatch(Loop& loop, const IoEvent& ev) {
        if ((ev.type != IoEventType::RelayRead && ev.type != IoEventType::RelayWrite) ||
            (ev.aux != 32 && ev.aux != 33 && ev.aux != 96 && ev.aux != 97))
            return false;
        if (!enabled || ev.conn_id >= loop.slots_initialized) return true;
        auto& c = loop.conns[ev.conn_id];
        auto& o = owners[c.id];
        const bool kCancel = ev.aux >= 96;
        const u32 kIndex = ev.aux - (kCancel ? 96 : 32);
        auto& d = o.direction[kIndex];
        if (ev.upstream_episode != o.episode) return true;
        if (d.pair_active) {
            dispatch_pair(loop, c, ev, kIndex, kCancel);
            return true;
        }
        if (ev.upstream_episode != o.episode || (ev.type == IoEventType::RelayWrite) != d.writing ||
            !(kCancel ? d.cancel_owned : d.armed))
            return true;
        if (c.pending_ops == 0 || ev.more || ev.has_buf) {
            loop.backend.fatal_error.store(EPROTO);
            return true;
        }
        const bool completed_splice = !kCancel && d.splice_inflight;
        if (!kCancel) d.splice_inflight = false;
        --c.pending_ops;
        if (kCancel) {
            d.cancel_owned = false;
            d.cancel_acknowledged = d.armed;
        } else {
            d.armed = false;
            d.cancel_acknowledged = false;
        }
        if (o.closing) {
            retire(loop, c);
            return true;
        }
        if (kCancel) {
            if (o.eof_closing) {
                pump(loop, c, kIndex);
                finish_eof_close(loop, c);
            }
            return true;
        }
        if (c.fd < 0) return true;
        if (completed_splice) {
            if (ev.result == -EAGAIN || ev.result == -EWOULDBLOCK) {
                ++eagain[d.writing ? 1 : 0];
                if (!arm(loop, c, kIndex, d.writing)) loop.close_conn(c);
                return true;
            }
            if (ev.result == -EINTR) {
                pump(loop, c, kIndex);
                return true;
            }
            if (ev.result < 0 || (d.writing && ev.result == 0)) {
                loop.close_conn(c);
                return true;
            }
            if (d.writing) {
                if (static_cast<u32>(ev.result) > d.buffered) {
                    loop.backend.fatal_error.store(EPROTO);
                    loop.close_conn(c);
                    return true;
                }
                d.buffered -= static_cast<u32>(ev.result);
                transferred[kIndex] += static_cast<u32>(ev.result);
            } else if (ev.result == 0) {
                d.eof = true;
                (void)::shutdown(kIndex == 0 ? c.upstream_fd : c.fd, SHUT_WR);
            } else {
                d.buffered = static_cast<u32>(ev.result);
            }
        } else if (ev.result < 0) {
            loop.close_conn(c);
            return true;
        }
        if (completed_splice && d.writing && d.buffered == 0 && !d.eof && poll_next_read) {
            if (!arm(loop, c, kIndex, false)) loop.close_conn(c);
        } else
            pump(loop, c, kIndex);
        return true;
    }
    template <class Loop>
    void progress(Loop& loop) {
        budget_deferred_runnable = false;
        if (!turn_budget_active) begin_turn(loop);
        const u32 kOwnersToVisit = queued_count < turn_call_limit ? queued_count : turn_call_limit;
        for (u32 i = 0; i < kOwnersToVisit; ++i) {
            const u32 kId = dequeue();
            auto& c = loop.conns[kId];
            auto& o = owners[kId];
            set_budget_deferred(kId, false);
            if (o.reclaim_pending) {
                o.reclaim_pending = false;
                loop.reclaim_slot(kId);
                continue;
            }
            if (o.closing) retire(loop, c);
            if (o.eof_closing) {
                finish_eof_close(loop, c);
                for (u32 offset = 0; offset < 2 && o.eof_closing && turn_budget_remaining != 0;
                     ++offset) {
                    const u32 direction = (o.next_direction + offset) & 1u;
                    if (o.direction[direction].buffered != 0 && !o.direction[direction].armed &&
                        !o.direction[direction].cancel_owned &&
                        !o.direction[direction].cancel_acknowledged)
                        pump(loop, c, direction);
                }
                o.next_direction ^= 1u;
                finish_eof_close(loop, c);
                if (o.eof_closing || o.closing) enqueue(kId);
                continue;
            }
            if (o.active) {
                if (yield_for_ordinary_cq(loop, kId)) continue;
                if (turn_budget_remaining == 0) {
                    set_budget_deferred(kId, true);
                    enqueue(kId);
                    break;
                }
                const u32 first = o.next_direction;
                pump(loop, c, first);
                o.next_direction = static_cast<u8>(first ^ 1u);
                if (turn_budget_remaining != 0 && c.fd >= 0) {
                    pump(loop, c, o.next_direction);
                    o.next_direction ^= 1u;
                }
                continue;
            }
            if (o.requested && c.fd >= 0 && !c.recv_armed && !c.upstream_recv_armed &&
                !c.recv_pause_cancel_pending && !c.recv_pause_target_inflight &&
                !c.upstream_recv_pause_cancel_pending && !c.upstream_recv_cancel_inflight &&
                !c.send_armed && !c.upstream_send_armed && !c.ws_client_send_pending &&
                !c.ws_upstream_send_pending && c.recv_buf.len() == 0 &&
                c.upstream_recv_buf.len() == 0 && !loop.backend.has_ws_recv_cache(c.id)) {
                if (admission_budget_remaining == 0) {
                    set_budget_deferred(kId, true);
                    enqueue(kId);
                    break;
                }
                --admission_budget_remaining;
                bool ok = true;
                for (auto& d : o.direction) {
                    if (d.read_fd >= 0) continue;
                    int fds[2];
                    if (::pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
                        ok = false;
                        break;
                    }
                    d.read_fd = fds[0];
                    d.write_fd = fds[1];
                    if (::fcntl(d.write_fd, F_SETPIPE_SZ, chunk_size) <
                        static_cast<int>(chunk_size))
                        ++pipe_grow_failures;
                    const int kCapacity = ::fcntl(d.write_fd, F_GETPIPE_SZ);
                    if (kCapacity > 0 && static_cast<u32>(kCapacity) < minimum_pipe_capacity)
                        minimum_pipe_capacity = static_cast<u32>(kCapacity);
                }
                if (!ok) {
                    close_pipes(o);
                    o.requested = false;
                    o.failed = true;
                    --c.pending_ops;
                    c.recv_paused_for_send = c.upstream_recv_paused_for_send = false;
                    if (!loop.submit_recv(c) || !loop.submit_recv_upstream(c)) loop.close_conn(c);
                } else if (o.direction[0].read_fd < 0 || o.direction[1].read_fd < 0) {
                    // Keep a partially prepared owner queued; the next shard turn
                    // finishes setup before any tunnel bytes are consumed.
                    enqueue(kId);
                } else {
                    if (!no_delay) {
                        const int kSavedErrno = errno;
                        const int kDisabled = 0;
                        const i32 kFds[2] = {c.fd, c.upstream_fd};
                        for (const i32 kFd : kFds) {
                            if (::setsockopt(
                                    kFd, IPPROTO_TCP, TCP_NODELAY, &kDisabled, sizeof(kDisabled)) ==
                                0)
                                ++nodelay_changes;
                            else
                                ++nodelay_failures;
                        }
                        errno = kSavedErrno;
                    }
                    o.requested = false;
                    o.active = true;
                    ++admissions;
                    pump(loop, c, o.next_direction);
                    o.next_direction ^= 1u;
                    if (turn_budget_remaining != 0 && c.fd >= 0) {
                        pump(loop, c, o.next_direction);
                        o.next_direction ^= 1u;
                    }
                }
            }
            if (o.requested || o.closing || o.eof_closing) enqueue(kId);
        }
        budget_deferred_runnable = budget_deferred_runnable_count != 0;
        turn_budget_active = false;
    }
};
}  // namespace rut
