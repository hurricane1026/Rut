#include "rut/runtime/kqueue_backend.h"

#include "rut/platform/socket.h"
#include "rut/runtime/tls.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace rut {
namespace {
constexpr uintptr_t kTickTimer = 1;
constexpr uintptr_t kYieldTimer = 2;
constexpr uintptr_t kWake = 3;
constexpr u32 kListener = 0xFFFFFF;
constexpr u32 kTimer = 0xFFFFFE;
constexpr i32 kWouldBlock = INT_MIN;

u64 token(u32 id, IoEventType type, u32 episode = 0) {
    return io_event_is_upstream(type) ? encode_upstream_event_token({id, type, episode, 0})
                                      : encode_non_upstream_user_data({id, type, 0});
}

int change(int queue,
           uintptr_t ident,
           i16 filter,
           u16 flags,
           u32 fflags = 0,
           intptr_t data = 0,
           u64 user_data = 0) {
    struct kevent64_s event;
    EV_SET64(&event, ident, filter, flags, fflags, data, user_data, 0, 0);
    int result;
    do {
        result = kevent64(queue, &event, 1, nullptr, 0, 0, nullptr);
    } while (result < 0 && errno == EINTR);
    return result;
}

bool remove_filter(int queue, int fd, i16 filter) {
    return change(queue, fd, filter, EV_DELETE) == 0 || errno == ENOENT;
}

bool detach(int queue, int fd) {
    const bool read = remove_filter(queue, fd, EVFILT_READ);
    const int error = errno;
    const bool write = remove_filter(queue, fd, EVFILT_WRITE);
    if (!read) errno = error;
    return read && write;
}

IoEvent completion(u32 id, IoEventType type, i32 result, u32 episode = 0, u8 aux = 0) {
    IoEvent event{};
    event.conn_id = id;
    event.type = type;
    event.result = result;
    event.upstream_episode = episode;
    event.aux = aux;
    return event;
}

int tls_error(SSL* ssl, int result) {
    const int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (error == SSL_ERROR_SYSCALL) return errno ? -errno : -ECONNRESET;
    return -EPROTO;
}
}  // namespace

void KqueueBackend::fail(i32 error) {
    i32 expected = 0;
    failure_.compare_exchange_strong(expected, error ? error : EIO, std::memory_order_release);
}

core::Expected<void, Error> KqueueBackend::init(u32 /*shard_id*/, i32 listener) {
    listen_fd = listener;
    pending_count = pending_streak_ = 0;
    tls_read_hint_ = kMaxFdMap;
    failure_.store(0, std::memory_order_relaxed);
    for (u32 i = 0; i < kMaxFdMap; i++) {
        downstream_fd_map[i] = upstream_fd_map[i] = -1;
        active_upstream_episode[i] = 0;
        downstream_read_[i] = upstream_read_[i] = ReadMode::Disabled;
        downstream_tls_[i] = nullptr;
        tls_recv_filter_[i] = EVFILT_READ;
        clear_send_state(i);
    }
    kqueue_fd = kqueue();
    if (kqueue_fd < 0) return core::make_unexpected(Error::from_errno(Error::Source::Kqueue));
    if (fcntl(kqueue_fd, F_SETFD, FD_CLOEXEC) < 0 ||
        change(kqueue_fd,
               kTickTimer,
               EVFILT_TIMER,
               EV_ADD | EV_ENABLE,
               NOTE_SECONDS,
               1,
               token(kTimer, IoEventType::Timeout)) < 0 ||
        change(kqueue_fd,
               kWake,
               EVFILT_USER,
               EV_ADD | EV_CLEAR,
               0,
               0,
               token(kTimer, IoEventType::Timeout)) < 0) {
        const int error = errno;
        shutdown();
        return core::make_unexpected(Error::make(error, Error::Source::Kqueue));
    }
    return {};
}

void KqueueBackend::shutdown() {
    if (kqueue_fd >= 0) close(kqueue_fd);
    kqueue_fd = -1;
    pending_count = pending_streak_ = 0;
}

void KqueueBackend::wake() {
    if (kqueue_fd >= 0 && change(kqueue_fd, kWake, EVFILT_USER, 0, NOTE_TRIGGER) < 0) fail(errno);
}

void KqueueBackend::arm_yield_timer(u64 deadline_ns) {
    if (deadline_ns == 0) {
        if (change(kqueue_fd, kYieldTimer, EVFILT_TIMER, EV_DELETE) < 0 && errno != ENOENT)
            fail(errno);
        return;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const u64 ns = static_cast<u64>(now.tv_sec) * 1'000'000'000ull + now.tv_nsec;
    const u64 delay = deadline_ns > ns ? deadline_ns - ns : 1;
    if (change(kqueue_fd,
               kYieldTimer,
               EVFILT_TIMER,
               EV_ADD | EV_ONESHOT,
               NOTE_NSECONDS,
               static_cast<intptr_t>(delay),
               token(kTimer, IoEventType::HandlerTimer)) < 0)
        fail(errno);
}

void KqueueBackend::add_accept() {
    if (listen_fd >= 0 && change(kqueue_fd,
                                 listen_fd,
                                 EVFILT_READ,
                                 EV_ADD | EV_ENABLE,
                                 0,
                                 0,
                                 token(kListener, IoEventType::Accept)) < 0)
        fail(errno);
}

void KqueueBackend::cancel_accept() {
    if (listen_fd >= 0 && !remove_filter(kqueue_fd, listen_fd, EVFILT_READ)) fail(errno);
}

bool KqueueBackend::valid_owner(u32 id, u32 episode) const {
    return id < kMaxFdMap && valid_upstream_episode(episode) &&
           active_upstream_episode[id] == episode;
}

bool KqueueBackend::register_read(u32 id, bool upstream) {
    const int fd = upstream ? upstream_fd_map[id] : downstream_fd_map[id];
    if (fd < 0) return true;
    const ReadMode mode = upstream ? upstream_read_[id] : downstream_read_[id];
    const auto& send = upstream ? upstream_send_state[id] : send_state[id];
    // SSL_read and SSL_write can each need the opposite direction. Preserve
    // the other operation's filter when updating one side of a full-duplex TLS
    // connection; send retries own READ only while SSL_write wants input.
    const bool send_reads = send.remaining && send.tls && send.tls_wait_filter == EVFILT_READ;
    const bool recv_writes =
        !upstream && mode == ReadMode::Active && tls_recv_filter_[id] == EVFILT_WRITE;
    if (send_reads) {
        if (change(kqueue_fd,
                   fd,
                   EVFILT_READ,
                   EV_ADD | EV_ENABLE,
                   NOTE_LOWAT,
                   1,
                   token(id, send.type, send.upstream_episode)) < 0)
            return false;
    } else if (mode == ReadMode::Disabled || recv_writes) {
        if (!remove_filter(kqueue_fd, fd, EVFILT_READ)) return false;
    } else if (change(kqueue_fd,
                      fd,
                      EVFILT_READ,
                      EV_ADD | EV_ENABLE,
                      NOTE_LOWAT,
                      mode == ReadMode::EofOnly ? INT_MAX : 1,
                      token(id,
                            upstream ? IoEventType::UpstreamRecv : IoEventType::Recv,
                            upstream ? active_upstream_episode[id] : 0)) < 0) {
        return false;
    }
    if (recv_writes && (!send.remaining || send_reads))
        return change(kqueue_fd,
                      fd,
                      EVFILT_WRITE,
                      EV_ADD | EV_ENABLE,
                      0,
                      0,
                      token(id, IoEventType::Recv)) == 0;
    return true;
}

bool KqueueBackend::add_recv(i32 fd, u32 id) {
    if (id >= kMaxFdMap || fd < 0) return false;
    downstream_fd_map[id] = fd;
    downstream_read_[id] = ReadMode::Active;
    if (downstream_tls_[id] && SSL_pending(downstream_tls_[id])) tls_read_hint_ = id;
    return register_read(id, false);
}

bool KqueueBackend::add_recv_upstream(i32 fd, u32 id, u32 episode) {
    if (!valid_owner(id, episode) || fd < 0) return false;
    const int previous = upstream_fd_map[id];
    upstream_fd_map[id] = fd;
    upstream_read_[id] = ReadMode::Active;
    if (register_read(id, true)) return true;
    upstream_fd_map[id] = previous;
    return false;
}

void KqueueBackend::pause_recv(u32 id, bool preserve_send_interest) {
    if (id >= kMaxFdMap) return;
    downstream_read_[id] = ReadMode::EofOnly;
    if (!register_read(id, false)) fail(errno);
    if (!preserve_send_interest && downstream_fd_map[id] >= 0 &&
        !remove_filter(kqueue_fd, downstream_fd_map[id], EVFILT_WRITE))
        fail(errno);
}

void KqueueBackend::pause_upstream_recv(u32 id, u32 episode, bool preserve_send_interest) {
    if (!valid_owner(id, episode)) return;
    upstream_read_[id] = ReadMode::Disabled;
    if (!register_read(id, true)) fail(errno);
    if (!preserve_send_interest && upstream_fd_map[id] >= 0 &&
        !remove_filter(kqueue_fd, upstream_fd_map[id], EVFILT_WRITE))
        fail(errno);
}

void KqueueBackend::quiesce_recv(u32 id, bool upstream, u32 episode) {
    if (id >= kMaxFdMap || (upstream && !valid_owner(id, episode))) return;
    (upstream ? upstream_read_[id] : downstream_read_[id]) = ReadMode::Disabled;
    if (!register_read(id, upstream)) fail(errno);
}

void KqueueBackend::clear_send_state(u32 id) {
    if (id >= kMaxFdMap) return;
    send_state[id] = {};
    upstream_send_state[id] = {};
    upstream_send_state[id].type = IoEventType::UpstreamSend;
}

bool KqueueBackend::queue(u32 id, IoEventType type, i32 result, u32 episode, u8 aux) {
    if (pending_count == kPendingCap) return false;
    pending_[pending_count++] = completion(id, type, result, episode, aux);
    return true;
}

u32 KqueueBackend::pop_pending(IoEvent* event, Connection* conns, u32 max_conns) {
    while (pending_count) {
        const IoEvent candidate = pending_[--pending_count];
        if (io_event_is_upstream(candidate.type) &&
            (!valid_owner(candidate.conn_id, candidate.upstream_episode) || !conns ||
             candidate.conn_id >= max_conns ||
             conns[candidate.conn_id].upstream_episode != candidate.upstream_episode))
            continue;
        *event = candidate;
        pending_streak_++;
        return 1;
    }
    return 0;
}

bool KqueueBackend::arm_send(u32 id, SendState& state) {
    const i16 filter = state.tls ? state.tls_wait_filter : static_cast<i16>(EVFILT_WRITE);
    if (change(kqueue_fd,
               state.fd,
               filter,
               EV_ADD | EV_ENABLE,
               filter == EVFILT_READ ? NOTE_LOWAT : 0,
               filter == EVFILT_READ ? 1 : 0,
               token(id, state.type, state.upstream_episode)) < 0)
        return false;
    if (filter == EVFILT_READ && !remove_filter(kqueue_fd, state.fd, EVFILT_WRITE)) return false;
    return register_read(id, state.type == IoEventType::UpstreamSend);
}

// Complete synchronously or retain exactly the buffer/offset required by the
// native write filter. EV_EOF is not a substitute for recv/send: unread data
// may coexist with EOF, and a half-closed peer may still receive our response.
i32 KqueueBackend::flush_send(SendState& state, SSL* ssl) {
    while (state.remaining) {
        ssize_t written;
        errno = 0;
        if (state.tls) {
            if (!ssl) return -EINVAL;
            written = SSL_write(ssl, state.src + state.offset, static_cast<int>(state.remaining));
            if (written <= 0) {
                const int error = SSL_get_error(ssl, static_cast<int>(written));
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                    state.tls_wait_filter =
                        error == SSL_ERROR_WANT_READ ? EVFILT_READ : EVFILT_WRITE;
                    return kWouldBlock;
                }
                return tls_error(ssl, static_cast<int>(written));
            }
        } else {
            written =
                send(state.fd, state.src + state.offset, state.remaining, platform::kSendFlags);
            if (written < 0 && errno == EINTR) continue;
            if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return kWouldBlock;
            if (written <= 0) return written == 0 ? -EPIPE : -errno;
        }
        state.offset += static_cast<u32>(written);
        state.remaining -= static_cast<u32>(written);
    }
    return static_cast<i32>(state.offset);
}

bool KqueueBackend::finish_send(u32 id, SendState& state, SSL* ssl, IoEvent& event) {
    const int result = flush_send(state, ssl);
    if (result == kWouldBlock) {
        if (arm_send(id, state)) return false;
        event = completion(id,
                           state.type,
                           -errno,
                           state.upstream_episode,
                           state.upstream_episode ? kLocalSubmitFailureAux : 0);
    } else {
        event = completion(id, state.type, result, state.upstream_episode);
    }
    const bool upstream = state.type == IoEventType::UpstreamSend;
    const int fd = state.fd;
    state = {};
    state.type = upstream ? IoEventType::UpstreamSend : IoEventType::Send;
    if (!remove_filter(kqueue_fd, fd, EVFILT_WRITE) || !register_read(id, upstream)) fail(errno);
    if (!upstream && ssl && SSL_pending(ssl)) tls_read_hint_ = id;
    return true;
}

bool KqueueBackend::start_send(i32 fd, u32 id, const u8* buf, u32 len, bool upstream, u32 episode) {
    if (id >= kMaxFdMap || pending_count == kPendingCap || (upstream && !valid_owner(id, episode)))
        return false;
    auto& state = upstream ? upstream_send_state[id] : send_state[id];
    if (state.remaining) return false;
    (upstream ? upstream_fd_map[id] : downstream_fd_map[id]) = fd;
    const IoEventType type = upstream ? IoEventType::UpstreamSend : IoEventType::Send;
    state = {buf, fd, 0, len, type, false, EVFILT_WRITE, episode};
    IoEvent event{};
    if (finish_send(id, state, nullptr, event)) pending_[pending_count++] = event;
    return true;
}

bool KqueueBackend::add_send(i32 fd, u32 id, const u8* buf, u32 len) {
    return start_send(fd, id, buf, len, false, 0);
}

bool KqueueBackend::add_send_upstream(i32 fd, u32 id, const u8* buf, u32 len, u32 episode) {
    return start_send(fd, id, buf, len, true, episode);
}

bool KqueueBackend::add_send_tls(Connection& conn, const u8* buf, u32 len) {
    const u32 id = conn.id;
    if (id >= kMaxFdMap || pending_count == kPendingCap || send_state[id].remaining) return false;
    downstream_fd_map[id] = conn.fd;
    downstream_tls_[id] = conn.tls;
    send_state[id] = {buf, conn.fd, 0, len, IoEventType::Send, true, EVFILT_WRITE, 0};
    IoEvent event{};
    if (finish_send(id, send_state[id], conn.tls, event)) pending_[pending_count++] = event;
    return true;
}

bool KqueueBackend::add_connect(i32 fd, u32 id, const void* addr, u32 len, u32 episode) {
    if (!valid_owner(id, episode) || pending_count == kPendingCap) return false;
    upstream_fd_map[id] = fd;
    upstream_read_[id] = ReadMode::Disabled;
    const int result = connect(fd, static_cast<const sockaddr*>(addr), len);
    if (result == 0) return queue(id, IoEventType::UpstreamConnect, 0, episode);
    if (errno != EINPROGRESS) return queue(id, IoEventType::UpstreamConnect, -errno, episode);
    if (change(kqueue_fd,
               fd,
               EVFILT_WRITE,
               EV_ADD | EV_ONESHOT,
               0,
               0,
               token(id, IoEventType::UpstreamConnect, episode)) < 0)
        return queue(id, IoEventType::UpstreamConnect, -errno, episode, kLocalSubmitFailureAux);
    return true;
}

bool KqueueBackend::receive(Connection& conn, bool upstream, IoEvent& event) {
    const u32 id = conn.id;
    const int fd = upstream ? upstream_fd_map[id] : downstream_fd_map[id];
    auto& buf = upstream ? conn.upstream_recv_buf : conn.recv_buf;
    const auto type = upstream ? IoEventType::UpstreamRecv : IoEventType::Recv;
    const u32 episode = upstream ? conn.upstream_episode : 0;
    int result = -ENOBUFS;
    if (!upstream && downstream_read_[id] == ReadMode::EofOnly) {
        // A NOTE_LOWAT EOF-only filter must not consume pipelined request bytes
        // into a yielded handler's buffer. Report peer shutdown to its owner.
        event = completion(id, type, 0);
        return true;
    }
    // While a response send owns the receive buffer, more readiness is not a
    // failed recv. Disable that filter until the send callback consumes the
    // bytes and submits the next read. In particular, do not emit ENOBUFS into
    // an empty callback slot and abort a backpressured streaming response.
    if (buf.write_avail() == 0 && conn.on_send &&
        (upstream ? conn.on_upstream_recv == nullptr : conn.on_recv == nullptr)) {
        (upstream ? upstream_read_[id] : downstream_read_[id]) = ReadMode::Disabled;
        if (!register_read(id, upstream)) fail(errno);
        return false;
    }
    if (!upstream && conn.tls_active) {
        SSL* ssl = conn.tls;
        downstream_tls_[id] = ssl;
        if (!ssl) {
            event = completion(id, type, -EINVAL);
            return true;
        }
        auto retry = [&](int rc) {
            const int error = SSL_get_error(ssl, rc);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return false;
            tls_recv_filter_[id] = error == SSL_ERROR_WANT_READ ? EVFILT_READ : EVFILT_WRITE;
            if (tls_recv_filter_[id] == EVFILT_READ && !send_state[id].remaining &&
                !remove_filter(kqueue_fd, fd, EVFILT_WRITE))
                fail(errno);
            if (!register_read(id, false)) fail(errno);
            return true;
        };
        if (!conn.tls_handshake_complete) {
            errno = 0;
            const int rc = SSL_accept(ssl);
            if (rc != 1) {
                if (retry(rc)) return false;
                event = completion(id, type, tls_error(ssl, rc));
                return true;
            }
            conn.tls_handshake_complete = true;
            if (tls_negotiated_protocol(ssl) == AlpnProtocol::H2)
                conn.protocol = ConnProtocol::Http2;
        }
        if (buf.write_avail()) {
            errno = 0;
            result = SSL_read(ssl, buf.write_ptr(), static_cast<int>(buf.write_avail()));
            if (result <= 0) {
                if (retry(result)) return false;
                result = tls_error(ssl, result);
            } else {
                buf.commit(static_cast<u32>(result));
                tls_recv_filter_[id] = EVFILT_READ;
                if (!send_state[id].remaining && !remove_filter(kqueue_fd, fd, EVFILT_WRITE))
                    fail(errno);
                if (!register_read(id, false)) fail(errno);
                if (SSL_pending(ssl)) tls_read_hint_ = id;
            }
        }
    } else if (buf.write_avail()) {
        do {
            result = static_cast<int>(recv(fd, buf.write_ptr(), buf.write_avail(), 0));
        } while (result < 0 && errno == EINTR);
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
        if (result > 0)
            buf.commit(static_cast<u32>(result));
        else if (result < 0)
            result = -errno;
    }
    event = completion(id, type, result, episode);
    return true;
}

u32 KqueueBackend::wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns) {
    if (max_events == 0 || failure_code()) return 0;
    if (pending_count && pending_streak_ < kPendingBurstQuota)
        return pop_pending(events, conns, max_conns);
    if (tls_read_hint_ < kMaxFdMap && tls_read_hint_ < max_conns && conns) {
        const u32 id = tls_read_hint_;
        tls_read_hint_ = kMaxFdMap;
        if (downstream_read_[id] == ReadMode::Active && conns[id].fd == downstream_fd_map[id] &&
            conns[id].tls && conns[id].tls == downstream_tls_[id] && SSL_pending(conns[id].tls) &&
            conns[id].recv_buf.write_avail() && receive(conns[id], false, *events))
            return 1;
    }
    // Fetch one native event at a time: callbacks can close/reuse descriptors
    // and connection slots before the next wait, so never cache a stale batch.
    struct kevent64_s ready;
    const struct timespec zero{};
    int n;
    do {
        n = kevent64(kqueue_fd, nullptr, 0, &ready, 1, 0, pending_count ? &zero : nullptr);
    } while (n < 0 && errno == EINTR);
    pending_streak_ = 0;
    if (n < 0) {
        fail(errno);
        return 0;
    }
    if (n == 0) return pop_pending(events, conns, max_conns);
    if (ready.flags & EV_ERROR) {
        fail(static_cast<int>(ready.data));
        return 0;
    }
    if (ready.filter == EVFILT_USER) return 0;  // control wake, not an elapsed timer tick
    if (ready.filter == EVFILT_TIMER) {
        // Darwin counts elapsed intervals even for a relative EV_ONESHOT
        // timer. Normalize handler expiration to one; periodic ticks retain
        // their count so the timer wheel can catch up after a delayed wait.
        const bool handler = ready.ident == kYieldTimer;
        const i32 ticks = ready.data > INT_MAX ? INT_MAX : static_cast<i32>(ready.data);
        *events = completion(
            0, handler ? IoEventType::HandlerTimer : IoEventType::Timeout, handler ? 1 : ticks);
        return 1;
    }
    const u64 data = ready.udata;
    const IoEventType type = static_cast<IoEventType>(data & 0xFFu);
    u32 id, episode = 0;
    if (io_event_is_upstream(type)) {
        UpstreamEventToken value;
        if (!decode_upstream_event_token(data, &value)) return 0;
        id = value.conn_id;
        episode = value.episode;
        if (!valid_owner(id, episode) || !conns || id >= max_conns ||
            conns[id].upstream_episode != episode ||
            upstream_fd_map[id] != static_cast<int>(ready.ident))
            return 0;
    } else {
        NonUpstreamUserData value;
        if (!decode_non_upstream_user_data(data, &value)) return 0;
        id = value.conn_id;
    }
    if (id == kListener) {
        const int fd = platform::accept_nonblocking(listen_fd);
        if (fd < 0) return 0;
        *events = completion(0, IoEventType::Accept, fd);
        return 1;
    }
    if (id >= kMaxFdMap) return 0;
    if (!io_event_is_upstream(type) && downstream_fd_map[id] != static_cast<int>(ready.ident))
        return 0;
    if (type == IoEventType::UpstreamConnect) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(upstream_fd_map[id], SOL_SOCKET, SO_ERROR, &error, &length) < 0)
            error = errno;
        *events = completion(id, type, -error, episode);
        return 1;
    }
    if (type == IoEventType::Send || type == IoEventType::UpstreamSend) {
        auto& state = type == IoEventType::Send ? send_state[id] : upstream_send_state[id];
        if (!state.remaining || state.fd != static_cast<int>(ready.ident)) {
            if (!remove_filter(kqueue_fd, static_cast<int>(ready.ident), ready.filter)) fail(errno);
            if (ready.filter == EVFILT_READ &&
                !register_read(id, type == IoEventType::UpstreamSend))
                fail(errno);
            return 0;
        }
        return finish_send(id, state, conns && id < max_conns ? conns[id].tls : nullptr, *events)
                   ? 1
                   : 0;
    }
    if (!conns || id >= max_conns) return 0;
    return receive(conns[id], type == IoEventType::UpstreamRecv, *events) ? 1 : 0;
}

u32 KqueueBackend::cancel(i32 fd, u32 id, bool, bool, bool, bool, bool) {
    if (fd >= 0 && !detach(kqueue_fd, fd)) fail(errno);
    if (id >= kMaxFdMap) return 0;
    if (downstream_fd_map[id] == fd) {
        downstream_fd_map[id] = -1;
        downstream_tls_[id] = nullptr;
        tls_recv_filter_[id] = EVFILT_READ;
        downstream_read_[id] = ReadMode::Disabled;
        if (tls_read_hint_ == id) tls_read_hint_ = kMaxFdMap;
    }
    if (upstream_fd_map[id] == fd) {
        upstream_fd_map[id] = -1;
        upstream_read_[id] = ReadMode::Disabled;
    }
    u32 keep = 0;
    for (u32 i = 0; i < pending_count; i++)
        if (pending_[i].conn_id != id) pending_[keep++] = pending_[i];
    pending_count = keep;
    return 0;
}

bool KqueueBackend::begin_upstream_episode(u32 id, u32 episode) {
    if (id >= kMaxFdMap || !valid_upstream_episode(episode) || active_upstream_episode[id] ||
        upstream_fd_map[id] >= 0 || upstream_send_state[id].remaining ||
        upstream_send_state[id].src || upstream_send_state[id].fd >= 0)
        return false;
    active_upstream_episode[id] = episode;
    return true;
}

bool KqueueBackend::retire_upstream_episode_after_detach(Connection& conn, u32 episode) {
    const u32 id = conn.id;
    if (!valid_owner(id, episode) || conn.upstream_episode != episode || upstream_fd_map[id] >= 0 ||
        upstream_send_state[id].remaining || upstream_send_state[id].src ||
        upstream_send_state[id].fd >= 0)
        return false;
    if (!conn.next_upstream_episode()) {
        active_upstream_episode[id] = kUpstreamEpisodeExhausted;
        return false;
    }
    active_upstream_episode[id] = 0;
    return true;
}

bool KqueueBackend::detach_upstream(Connection& conn, i32* detached_fd) {
    if (detached_fd) *detached_fd = -1;
    const int fd = conn.upstream_fd;
    const bool detached = fd < 0 || detach(kqueue_fd, fd);
    if (conn.id < kMaxFdMap) {
        upstream_fd_map[conn.id] = -1;
        upstream_read_[conn.id] = ReadMode::Disabled;
        upstream_send_state[conn.id] = {};
        upstream_send_state[conn.id].type = IoEventType::UpstreamSend;
    }
    conn.upstream_fd = -1;
    conn.upstream_recv_armed = conn.upstream_send_armed = false;
    // A failed filter deletion may leave kernel events live. Close before
    // retiring ownership; never retry an indeterminate close or let a later
    // fd-less detach release the quarantined slot.
    bool fd_closed = false;
    bool close_failed = false;
    if (!detached && fd >= 0) {
        fd_closed = true;
        close_failed = close(fd) < 0;
    }
    if (close_failed && conn.id < kMaxFdMap)
        active_upstream_episode[conn.id] = kUpstreamEpisodeExhausted;
    const bool retired =
        !close_failed && retire_upstream_episode_after_detach(conn, conn.upstream_episode);
    if (detached && retired && detached_fd)
        *detached_fd = fd;
    else if (fd >= 0 && !fd_closed)
        close(fd);
    return detached && retired;
}

void KqueueBackend::quarantine_upstream_episode_on_slot_release(u32 id) {
    if (id < kMaxFdMap && active_upstream_episode[id])
        active_upstream_episode[id] = kUpstreamEpisodeExhausted;
}

}  // namespace rut
