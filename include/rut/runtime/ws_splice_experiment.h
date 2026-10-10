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
        bool copying = false, probe_copy = true;
    };
    struct Owner {
        Direction direction[2];
        u32 episode = 0;
        bool requested = false, active = false, closing = false, eof_closing = false,
             queued = false, failed = false;
    };
    MappedArray<Owner> owners;
    MappedArray<u32> queued;
    u32 queued_count = 0;
    bool enabled = false, copy_first = false, check_available = false, fast_batch = false;
    bool fast_scan = false, last_batch_ws_only = false;
    u64 deadline_batches_skipped = 0, terminal_scans_skipped = 0;
    bool no_delay = true;
    u64 nodelay_changes = 0, nodelay_failures = 0;
    u64 admissions = 0, transferred[2]{}, calls = 0;
    u32 chunk_size = 65536, call_budget = 8;
    u32 copy_limit = 4096;
    u64 polls = 0, eagain[2]{}, pipe_grow_failures = 0;
    u32 minimum_pipe_capacity = 0xffffffffu;
    bool enable(u32 capacity) {
        if (!owners.init(capacity) || !queued.init(capacity)) return false;
        enabled = true;
        return true;
    }
    void enqueue(u32 id) {
        if (!owners[id].queued) {
            owners[id].queued = true;
            queued[queued_count++] = id;
        }
    }
    static void close_pipes(Owner& owner) {
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
        queued_count = 0;
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
        for (auto& d : o.direction)
            if (!d.eof || d.buffered != 0 || d.armed || d.cancel_owned) return;
        loop.close_conn(c);
    }
    template <class Loop>
    void pump(Loop& loop, Connection& c, u32 index) {
        auto& o = owners[c.id];
        auto& d = o.direction[index];
        if (!o.active || o.closing || d.armed) return;
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
        for (u32 budget = 0; budget < turn_limit; ++budget) {
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
                if (copy) {
                    n = kWriting ? ::send(kDestination,
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
            } while (n < 0 && errno == EINTR);
            if (kSampled) {
                const int kSavedErrno = errno;
                loop.study_record_syscall(kKind, monotonic_ns() - kStarted);
                errno = kSavedErrno;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                ++eagain[kWriting ? 1 : 0];
                if (!kWriting) d.probe_copy = true;
                if (!arm(loop, c, index, kWriting)) loop.close_conn(c);
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
                const u32 kOther = index ^ 1u;
                auto& other = o.direction[kOther];
                other.eof = true;
                if (other.armed && !other.cancel_owned) {
                    const auto kType =
                        other.writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
                    const u64 kTarget = encode_upstream_event_token(
                        {c.id, kType, o.episode, static_cast<u8>(32 + kOther)});
                    if (loop.backend.cancel_ws_splice_poll(
                            kTarget, c.id, kType, static_cast<u8>(96 + kOther), o.episode)) {
                        other.cancel_owned = true;
                        ++c.pending_ops;
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
        o.closing = true;
        o.requested = false;
        o.active = false;
        close_pipes(o);
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
            if (d.armed && !d.cancel_owned) {
                const auto kType = d.writing ? IoEventType::RelayWrite : IoEventType::RelayRead;
                const u64 kTarget = encode_upstream_event_token(
                    {c.id, kType, o.episode, static_cast<u8>(32 + index)});
                if (loop.backend.cancel_ws_splice_poll(
                        kTarget, c.id, kType, static_cast<u8>(96 + index), o.episode)) {
                    d.cancel_owned = true;
                    ++c.pending_ops;
                }
            }
            pending = pending || d.armed || d.cancel_owned;
        }
        if (!pending) {
            o.closing = false;
            if (c.pending_ops == 0)
                loop.backend.fatal_error.store(EPROTO);
            else
                --c.pending_ops;
        }
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
        if (ev.upstream_episode != o.episode || (ev.type == IoEventType::RelayWrite) != d.writing ||
            !(kCancel ? d.cancel_owned : d.armed))
            return true;
        if (c.pending_ops == 0 || ev.more || ev.has_buf) {
            loop.backend.fatal_error.store(EPROTO);
            return true;
        }
        --c.pending_ops;
        if (kCancel)
            d.cancel_owned = false;
        else
            d.armed = false;
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
        if (ev.result < 0) {
            loop.close_conn(c);
            return true;
        }
        pump(loop, c, kIndex);
        return true;
    }
    template <class Loop>
    void progress(Loop& loop) {
        u32 retained = 0;
        const u32 kCount = queued_count;
        for (u32 i = 0; i < kCount; ++i) {
            const u32 kId = queued[i];
            auto& c = loop.conns[kId];
            auto& o = owners[kId];
            if (o.closing) retire(loop, c);
            if (o.requested && c.fd >= 0 && !c.recv_armed && !c.upstream_recv_armed &&
                !c.recv_pause_cancel_pending && !c.recv_pause_target_inflight &&
                !c.upstream_recv_pause_cancel_pending && !c.upstream_recv_cancel_inflight &&
                !c.send_armed && !c.upstream_send_armed && !c.ws_client_send_pending &&
                !c.ws_upstream_send_pending && c.recv_buf.len() == 0 &&
                c.upstream_recv_buf.len() == 0 && !loop.backend.has_ws_recv_cache(c.id)) {
                bool ok = true;
                for (auto& d : o.direction) {
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
                    pump(loop, c, 0);
                    if (c.fd >= 0) pump(loop, c, 1);
                }
            }
            if (o.requested || o.closing)
                queued[retained++] = kId;
            else
                o.queued = false;
        }
        queued_count = retained;
    }
};
}  // namespace rut
