#include "rut/runtime/epoll_backend.h"

#include "core/expected.h"
#include "epoll_tls_hooks.h"
#include "rut/runtime/error.h"

#include <errno.h>
#include <openssl/ssl.h>
#include <string.h>  // memset
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

namespace rut {

static constexpr u32 kListenConnId = 0xFFFFFF;
static constexpr u32 kTimerConnId = 0xFFFFFE;

const EpollTlsHooks* get_epoll_tls_hooks_for_test() __attribute__((weak));

namespace {

i32 default_ssl_accept(SSL* ssl) {
    return SSL_accept(ssl);
}
i32 default_ssl_read(SSL* ssl, void* buf, i32 len) {
    return SSL_read(ssl, buf, len);
}
i32 default_ssl_write(SSL* ssl, const void* buf, i32 len) {
    return SSL_write(ssl, buf, len);
}
i32 default_ssl_get_error(SSL* ssl, i32 rc) {
    return SSL_get_error(ssl, rc);
}
AlpnProtocol default_alpn_negotiated(SSL* ssl) {
    return tls_negotiated_protocol(ssl);
}

EpollTlsHooks default_tls_hooks = {default_ssl_accept,
                                   default_ssl_read,
                                   default_ssl_write,
                                   default_ssl_get_error,
                                   default_alpn_negotiated};

const EpollTlsHooks* get_tls_hooks() {
    if (const EpollTlsHooks* hooks =
            get_epoll_tls_hooks_for_test ? get_epoll_tls_hooks_for_test() : nullptr)
        return hooks;
    return &default_tls_hooks;
}

}  // namespace

static i32 map_tls_error(SSL* ssl, i32 rc) {
    i32 err = get_tls_hooks()->ssl_get_error(ssl, rc);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_SYSCALL) {
        if (errno != 0) return -errno;
        return -ECONNRESET;
    }
    return -EPROTO;
}

static u32 tls_interest_for_error(i32 ssl_err) {
    if (ssl_err == SSL_ERROR_WANT_WRITE) return EPOLLOUT;
    return EPOLLIN;
}

static u32 tls_send_interest_for_error(i32 ssl_err) {
    return EPOLLIN | tls_interest_for_error(ssl_err);
}

static u32 tls_send_interest_for_state(const EpollBackend::SendState& ss) {
    return EPOLLIN | (ss.tls_wait_events ? ss.tls_wait_events : EPOLLIN);
}

static void queue_pending_completion(IoEvent* pending_completions,
                                     u32& pending_count,
                                     u32 conn_id,
                                     IoEventType type,
                                     i32 result,
                                     bool force_slot = false) {
    if (pending_count >= 64) {
        if (!force_slot) return;
        pending_count = 63;
    }

    pending_completions[pending_count].conn_id = conn_id;
    pending_completions[pending_count].type = type;
    pending_completions[pending_count].result = result;
    pending_completions[pending_count].buf_id = 0;
    pending_completions[pending_count].has_buf = 0;
    pending_completions[pending_count].more = 0;
    pending_count++;
}

static i32 set_fd_interest(i32 epoll_fd, i32 fd, u32 conn_id, IoEventType type, u32 events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.u64 = (static_cast<u64>(conn_id) << 8) | static_cast<u64>(type);
    i32 rc = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    if (rc < 0 && errno == ENOENT) {
        rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }
    if (rc < 0) return -errno;
    return 0;
}

static void rearm_recv_interest(i32 epoll_fd,
                                u32 conn_id,
                                IoEventType type,
                                const i32* downstream_fd_map,
                                const i32* upstream_fd_map) {
    if (conn_id >= EpollBackend::kMaxFdMap) return;

    if (type == IoEventType::UpstreamRecv || type == IoEventType::UpstreamSend) {
        i32 fd = upstream_fd_map[conn_id];
        if (fd >= 0)
            (void)set_fd_interest(epoll_fd, fd, conn_id, IoEventType::UpstreamRecv, EPOLLIN);
        return;
    }

    i32 fd = downstream_fd_map[conn_id];
    if (fd >= 0) (void)set_fd_interest(epoll_fd, fd, conn_id, IoEventType::Recv, EPOLLIN);
}

u64 EpollBackend::encode_data(u32 conn_id, IoEventType type) {
    return (static_cast<u64>(conn_id) << 8) | static_cast<u64>(type);
}

void EpollBackend::decode_data(u64 data, u32& conn_id, IoEventType& type) {
    type = static_cast<IoEventType>(data & 0xFF);
    conn_id = static_cast<u32>(data >> 8);
}

core::Expected<void, Error> EpollBackend::init(u32 /*shard_id*/, i32 lfd) {
    listen_fd = lfd;
    epoll_fd = -1;
    timer_fd = -1;
    yield_timer_fd = -1;
    pending_count = 0;
    for (u32 i = 0; i < kMaxFdMap; i++) {
        downstream_fd_map[i] = -1;
        upstream_fd_map[i] = -1;
        send_state[i] = {nullptr, -1, 0, 0, IoEventType::Send, false, 0};
        upstream_send_state[i] = {nullptr, -1, 0, 0, IoEventType::UpstreamSend, false, 0};
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return core::make_unexpected(Error::from_errno(Error::Source::Epoll));

    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        i32 err = errno;
        close(epoll_fd);
        epoll_fd = -1;
        return core::make_unexpected(Error::make(err, Error::Source::Timerfd));
    }

    struct itimerspec ts;
    memset(&ts, 0, sizeof(ts));
    ts.it_interval.tv_sec = 1;
    ts.it_value.tv_sec = 1;
    timerfd_settime(timer_fd, 0, &ts, nullptr);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = encode_data(kTimerConnId, IoEventType::Timeout);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) < 0) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Epoll));
    }

    // yield_timer_fd — one-shot, armed on demand when the JIT-yield heap's
    // top deadline changes. Disarmed at init (it_value = 0). Carries the
    // HandlerTimer event type so wait()/dispatch can route it through the
    // per-conn resume path.
    yield_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (yield_timer_fd < 0) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Timerfd));
    }
    struct epoll_event yev;
    yev.events = EPOLLIN;
    yev.data.u64 = encode_data(kTimerConnId, IoEventType::HandlerTimer);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, yield_timer_fd, &yev) < 0) {
        i32 err = errno;
        shutdown();
        return core::make_unexpected(Error::make(err, Error::Source::Epoll));
    }

    return {};
}

void EpollBackend::arm_yield_timerfd(u64 deadline_ns) {
    if (yield_timer_fd < 0) return;
    struct itimerspec ts;
    __builtin_memset(&ts, 0, sizeof(ts));
    if (deadline_ns > 0) {
        ts.it_value.tv_sec = static_cast<time_t>(deadline_ns / 1'000'000'000ull);
        ts.it_value.tv_nsec = static_cast<long>(deadline_ns % 1'000'000'000ull);
    }
    // TFD_TIMER_ABSTIME — deadline_ns is absolute CLOCK_MONOTONIC. A zero
    // value disarms the timer. it_interval stays zero → one-shot.
    timerfd_settime(yield_timer_fd, TFD_TIMER_ABSTIME, &ts, nullptr);
}

void EpollBackend::add_accept() {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = encode_data(kListenConnId, IoEventType::Accept);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
}

bool EpollBackend::add_recv(i32 fd, u32 conn_id) {
    if (conn_id < kMaxFdMap) downstream_fd_map[conn_id] = fd;
    set_fd_interest(epoll_fd, fd, conn_id, IoEventType::Recv, EPOLLIN);
    return true;
}

void EpollBackend::pause_recv(u32 conn_id, bool preserve_send_interest) {
    if (conn_id >= kMaxFdMap) return;
    i32 fd = downstream_fd_map[conn_id];
    if (fd < 0) return;
    // Mask EPOLLIN so client data bytes during wait(ms) don't wake us on
    // a level-triggered ready socket with no handler to consume them
    // (busy-loop risk on a full recv_buf). KEEP EPOLLRDHUP so a clean
    // peer FIN still surfaces — the kernel only sets EPOLLHUP when BOTH
    // directions are closed, and without RDHUP interest a half-close
    // would go undetected and the slot would sit until the yield
    // deadline. EPOLLERR is always delivered regardless of mask.
    IoEventType type = IoEventType::Recv;
    u32 events = EPOLLRDHUP;
    if (preserve_send_interest) {
        const auto& ss = send_state[conn_id];
        if (ss.remaining > 0 && ss.fd == fd) {
            type = ss.type;
            if (ss.tls) {
                events = (ss.tls_wait_events == EPOLLIN) ? (EPOLLIN | EPOLLRDHUP)
                                                         : (EPOLLOUT | EPOLLRDHUP);
            } else {
                events = EPOLLOUT | EPOLLRDHUP;
            }
        }
    }
    set_fd_interest(epoll_fd, fd, conn_id, type, events);
}

void EpollBackend::pause_upstream_recv(u32 conn_id, bool preserve_send_interest) {
    if (conn_id >= kMaxFdMap) return;
    i32 fd = upstream_fd_map[conn_id];
    if (fd < 0) return;
    // Mask all readability (events=0) so neither buffered upstream data nor a
    // half-close (EPOLLRDHUP, which dispatch folds into has_read) can fire
    // UpstreamRecv and drive the pipeline past the parked @throttle pump.
    // EPOLLHUP/EPOLLERR are still delivered by the kernel regardless, but those
    // are genuine terminal conditions. submit_recv_upstream re-arms EPOLLIN on
    // resume, at which point any buffered upstream bytes surface immediately.
    IoEventType type = IoEventType::UpstreamRecv;
    u32 events = 0;
    if (preserve_send_interest) {
        const auto& ss = upstream_send_state[conn_id];
        if (ss.remaining > 0 && ss.fd == fd) {
            events = EPOLLOUT;
        }
    }
    set_fd_interest(epoll_fd, fd, conn_id, type, events);
}

bool EpollBackend::add_send_upstream(i32 fd, u32 conn_id, const u8* buf, u32 len) {
    ssize_t nw = send(fd, buf, len, MSG_NOSIGNAL);

    if (nw == static_cast<ssize_t>(len)) {
        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = conn_id;
            pending_completions[pending_count].type = IoEventType::UpstreamSend;
            pending_completions[pending_count].result = static_cast<i32>(nw);
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    if (nw < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = conn_id;
            pending_completions[pending_count].type = IoEventType::UpstreamSend;
            pending_completions[pending_count].result = -errno;
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    u32 sent = (nw > 0) ? static_cast<u32>(nw) : 0;
    if (conn_id < kMaxFdMap) {
        upstream_send_state[conn_id] = {
            buf, fd, sent, len - sent, IoEventType::UpstreamSend, false, 0};
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.u64 = encode_data(conn_id, IoEventType::UpstreamRecv);
    i32 rc = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    if (rc < 0 && errno == ENOENT) {
        rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }
    if (rc < 0) {
        i32 err = errno;
        if (conn_id < kMaxFdMap) {
            upstream_send_state[conn_id] = {nullptr, -1, 0, 0, IoEventType::UpstreamSend, false, 0};
        }
        if (pending_count >= 64) pending_count = 63;
        pending_completions[pending_count].conn_id = conn_id;
        pending_completions[pending_count].type = IoEventType::UpstreamSend;
        pending_completions[pending_count].result = -err;
        pending_completions[pending_count].buf_id = 0;
        pending_completions[pending_count].has_buf = 0;
        pending_completions[pending_count].more = 0;
        pending_count++;
    }
    return true;
}

bool EpollBackend::add_recv_upstream(i32 fd, u32 conn_id) {
    if (conn_id < kMaxFdMap) upstream_fd_map[conn_id] = fd;
    set_fd_interest(epoll_fd, fd, conn_id, IoEventType::UpstreamRecv, EPOLLIN);
    return true;
}

bool EpollBackend::add_send(i32 fd, u32 conn_id, const u8* buf, u32 len) {
    ssize_t nw = send(fd, buf, len, MSG_NOSIGNAL);

    if (nw == static_cast<ssize_t>(len)) {
        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = conn_id;
            pending_completions[pending_count].type = IoEventType::Send;
            pending_completions[pending_count].result = static_cast<i32>(nw);
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    if (nw < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = conn_id;
            pending_completions[pending_count].type = IoEventType::Send;
            pending_completions[pending_count].result = -errno;
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    u32 sent = (nw > 0) ? static_cast<u32>(nw) : 0;
    if (conn_id < kMaxFdMap) {
        send_state[conn_id] = {buf, fd, sent, len - sent, IoEventType::Send, false, 0};
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.u64 = encode_data(conn_id, IoEventType::Send);
    i32 rc = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    if (rc < 0 && errno == ENOENT) {
        rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }
    if (rc < 0) {
        i32 err = errno;
        if (conn_id < kMaxFdMap) {
            send_state[conn_id] = {nullptr, -1, 0, 0, IoEventType::Send, false, 0};
        }
        if (pending_count >= 64) pending_count = 63;
        pending_completions[pending_count].conn_id = conn_id;
        pending_completions[pending_count].type = IoEventType::Send;
        pending_completions[pending_count].result = -err;
        pending_completions[pending_count].buf_id = 0;
        pending_completions[pending_count].has_buf = 0;
        pending_completions[pending_count].more = 0;
        pending_count++;
    }
    return true;
}

bool EpollBackend::add_send_tls(Connection& c, const u8* buf, u32 len) {
    if (!c.tls_active || !c.tls) return add_send(c.fd, c.id, buf, len);

    SSL* ssl = c.tls;
    const EpollTlsHooks* tls_hooks = get_tls_hooks();
    u32 sent = 0;
    while (sent < len) {
        errno = 0;
        i32 nw = tls_hooks->ssl_write(ssl, buf + sent, static_cast<i32>(len - sent));
        if (nw > 0) {
            sent += static_cast<u32>(nw);
            continue;
        }

        i32 ssl_err = tls_hooks->ssl_get_error(ssl, nw);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            if (c.id >= kMaxFdMap) {
                queue_pending_completion(
                    pending_completions, pending_count, c.id, IoEventType::Send, -EINVAL, true);
                return true;
            }
            send_state[c.id] = {buf,
                                c.fd,
                                sent,
                                len - sent,
                                IoEventType::Send,
                                true,
                                tls_interest_for_error(ssl_err)};
            i32 rc = set_fd_interest(
                epoll_fd, c.fd, c.id, IoEventType::Send, tls_send_interest_for_error(ssl_err));
            if (rc < 0) {
                send_state[c.id] = {nullptr, -1, 0, 0, IoEventType::Send, false, 0};
                queue_pending_completion(
                    pending_completions, pending_count, c.id, IoEventType::Send, rc, true);
            }
            return true;
        }

        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = c.id;
            pending_completions[pending_count].type = IoEventType::Send;
            pending_completions[pending_count].result = map_tls_error(ssl, nw);
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    if (pending_count < 64) {
        pending_completions[pending_count].conn_id = c.id;
        pending_completions[pending_count].type = IoEventType::Send;
        pending_completions[pending_count].result = static_cast<i32>(len);
        pending_completions[pending_count].buf_id = 0;
        pending_completions[pending_count].has_buf = 0;
        pending_completions[pending_count].more = 0;
        pending_count++;
    }
    return true;
}

bool EpollBackend::add_connect(i32 fd, u32 conn_id, const void* addr, u32 addr_len) {
    if (conn_id < kMaxFdMap) upstream_fd_map[conn_id] = fd;
    i32 rc = connect(fd, static_cast<const struct sockaddr*>(addr), addr_len);
    if (rc == 0) {
        struct epoll_event reg_ev;
        reg_ev.events = EPOLLIN;
        reg_ev.data.u64 = encode_data(conn_id, IoEventType::UpstreamRecv);
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &reg_ev);
        if (pending_count < 64) {
            pending_completions[pending_count].conn_id = conn_id;
            pending_completions[pending_count].type = IoEventType::UpstreamConnect;
            pending_completions[pending_count].result = 0;
            pending_completions[pending_count].buf_id = 0;
            pending_completions[pending_count].has_buf = 0;
            pending_completions[pending_count].more = 0;
            pending_count++;
        }
        return true;
    }

    if (errno == EINPROGRESS) {
        struct epoll_event ev;
        ev.events = EPOLLOUT;
        ev.data.u64 = encode_data(conn_id, IoEventType::UpstreamConnect);
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        return true;
    }

    if (pending_count < 64) {
        pending_completions[pending_count].conn_id = conn_id;
        pending_completions[pending_count].type = IoEventType::UpstreamConnect;
        pending_completions[pending_count].result = -errno;
        pending_completions[pending_count].buf_id = 0;
        pending_completions[pending_count].has_buf = 0;
        pending_completions[pending_count].more = 0;
        pending_count++;
    }
    return true;
}

u32 EpollBackend::cancel(i32 fd,
                         u32 /*conn_id*/,
                         bool /*recv_armed*/,
                         bool /*send_armed*/,
                         bool /*upstream_recv_armed*/,
                         bool /*upstream_send_armed*/,
                         bool /*has_upstream*/) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    return 0;
}

void EpollBackend::cancel_accept() {
    if (listen_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listen_fd, nullptr);
    }
}

u32 EpollBackend::wait(IoEvent* events, u32 max_events, Connection* conns, u32 max_conns) {
    u32 out = 0;

    while (pending_count > 0 && out < max_events) {
        events[out] = pending_completions[--pending_count];
        out++;
    }

    i32 timeout_ms = (out > 0) ? 0 : -1;

    struct epoll_event ep_events[kMaxEventsPerWait];
    u32 max_ep = max_events - out;
    if (max_ep > kMaxEventsPerWait) max_ep = kMaxEventsPerWait;

    i32 n;
    for (;;) {
        n = epoll_wait(epoll_fd, ep_events, static_cast<i32>(max_ep), timeout_ms);
        if (n >= 0) break;
        if (errno == EINTR) continue;
        return out;
    }

    for (i32 i = 0; i < n && out < max_events; i++) {
        u32 conn_id;
        IoEventType type;
        decode_data(ep_events[i].data.u64, conn_id, type);
        // EPOLLHUP/EPOLLERR always fire regardless of the interest mask
        // (per epoll_ctl(2)), so pause_recv(events=0) can't prevent them.
        // Fold them into has_read so peer-close / hard-error routes
        // through handle_epollin → recv() returns 0 or -errno → emits a
        // terminal Recv event the dispatcher can close on. Without this,
        // a HUP during yield would silently drop every iteration and
        // the kernel would re-deliver it forever (busy loop + slot leak).
        bool has_read = (ep_events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0;
        bool has_write = (ep_events[i].events & EPOLLOUT) != 0;

        if (conn_id == kListenConnId) {
            for (;;) {
                i32 fd = accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0) break;
                if (out >= max_events) {
                    close(fd);
                    break;
                }
                events[out].conn_id = 0;
                events[out].type = IoEventType::Accept;
                events[out].result = fd;
                events[out].buf_id = 0;
                events[out].has_buf = 0;
                events[out].more = 0;
                out++;
            }
        } else if (conn_id == kTimerConnId) {
            // Two timerfds share kTimerConnId; the decoded type disambiguates.
            // HandlerTimer → yield_timer_fd (one-shot, ms precision, per-heap-top).
            // Timeout      → timer_fd      (1 Hz interval, drives keepalive wheel).
            i32 fd = (type == IoEventType::HandlerTimer) ? yield_timer_fd : timer_fd;
            u64 ticks = 0;
            ssize_t rr = read(fd, &ticks, sizeof(ticks));
            if (rr != static_cast<ssize_t>(sizeof(ticks))) continue;
            if (out < max_events) {
                events[out].conn_id = 0;
                events[out].type = type;
                events[out].result = (ticks > 0x7FFFFFFF) ? 0x7FFFFFFF : static_cast<i32>(ticks);
                events[out].buf_id = 0;
                events[out].has_buf = 0;
                events[out].more = 0;
                out++;
            }
        } else if (type == IoEventType::UpstreamConnect && has_write) {
            i32 err = 0;
            socklen_t errlen = sizeof(err);
            i32 cfd = (conn_id < kMaxFdMap) ? upstream_fd_map[conn_id] : -1;
            if (cfd >= 0) getsockopt(cfd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            events[out].conn_id = conn_id;
            events[out].type = IoEventType::UpstreamConnect;
            events[out].result = err ? -err : 0;
            events[out].buf_id = 0;
            events[out].has_buf = 0;
            events[out].more = 0;
            out++;
            continue;
        } else if (type == IoEventType::Recv && conn_id < max_conns && conns[conn_id].tls_active &&
                   (has_read || has_write)) {
            goto handle_epollin;
        } else if (type == IoEventType::Send && conn_id < kMaxFdMap && send_state[conn_id].tls &&
                   send_state[conn_id].remaining > 0) {
            auto& ss = send_state[conn_id];
            if (has_write || (has_read && ss.tls_wait_events == EPOLLIN)) {
                goto handle_epollout;
            }
            if (has_read) goto handle_epollin;
        } else if (has_read) {
        handle_epollin:
            IoEventType recv_type = type;
            if (type == IoEventType::Send) recv_type = IoEventType::Recv;
            i32 fd = -1;
            if (conn_id < kMaxFdMap) {
                fd = (recv_type == IoEventType::UpstreamRecv) ? upstream_fd_map[conn_id]
                                                              : downstream_fd_map[conn_id];
            }
            if (fd < 0 || conn_id >= max_conns) continue;

            auto& conn = conns[conn_id];
            auto& buf =
                (recv_type == IoEventType::UpstreamRecv) ? conn.upstream_recv_buf : conn.recv_buf;
            i32 result = -EINVAL;

            if (conn.tls_active && recv_type == IoEventType::Recv) {
                SSL* ssl = conn.tls;
                if (!ssl) {
                    result = -EINVAL;
                } else {
                    if (!conn.tls_handshake_complete) {
                        errno = 0;
                        i32 rc = get_tls_hooks()->ssl_accept(ssl);
                        if (rc == 1) {
                            conn.tls_handshake_complete = true;
                            // Fix the wire protocol from the ALPN result. Hook
                            // may be null in older test tables → keep Http11.
                            auto alpn_fn = get_tls_hooks()->alpn_negotiated;
                            if (alpn_fn && alpn_fn(ssl) == AlpnProtocol::H2)
                                conn.protocol = ConnProtocol::Http2;
                            set_fd_interest(epoll_fd, fd, conn_id, type, EPOLLIN);
                        } else {
                            i32 ssl_err = get_tls_hooks()->ssl_get_error(ssl, rc);
                            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                                set_fd_interest(
                                    epoll_fd, fd, conn_id, type, tls_interest_for_error(ssl_err));
                                continue;
                            }
                            result = map_tls_error(ssl, rc);
                            events[out].conn_id = conn_id;
                            events[out].type = recv_type;
                            events[out].result = result;
                            events[out].buf_id = 0;
                            events[out].has_buf = 0;
                            events[out].more = 0;
                            out++;
                            continue;
                        }
                    }

                    u32 avail = buf.write_avail();
                    if (avail == 0) {
                        result = -ENOBUFS;
                    } else {
                        errno = 0;
                        i32 nr = get_tls_hooks()->ssl_read(
                            ssl, buf.write_ptr(), static_cast<i32>(avail));
                        if (nr > 0) {
                            buf.commit(static_cast<u32>(nr));
                            result = nr;
                            if (type == IoEventType::Send && conn_id < kMaxFdMap &&
                                send_state[conn_id].remaining > 0) {
                                set_fd_interest(epoll_fd,
                                                fd,
                                                conn_id,
                                                type,
                                                tls_send_interest_for_state(send_state[conn_id]));
                            } else {
                                set_fd_interest(epoll_fd, fd, conn_id, type, EPOLLIN);
                            }
                        } else {
                            i32 ssl_err = get_tls_hooks()->ssl_get_error(ssl, nr);
                            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                                if (type == IoEventType::Send && conn_id < kMaxFdMap &&
                                    send_state[conn_id].remaining > 0) {
                                    set_fd_interest(
                                        epoll_fd,
                                        fd,
                                        conn_id,
                                        type,
                                        tls_send_interest_for_state(send_state[conn_id]));
                                } else {
                                    set_fd_interest(epoll_fd,
                                                    fd,
                                                    conn_id,
                                                    type,
                                                    tls_interest_for_error(ssl_err));
                                }
                                continue;
                            }
                            result = map_tls_error(ssl, nr);
                        }
                    }
                }
            } else {
                u32 avail = buf.write_avail();
                if (avail > 0) {
                    ssize_t nr;
                    do {
                        nr = recv(fd, buf.write_ptr(), avail, 0);
                    } while (nr < 0 && errno == EINTR);
                    if (nr > 0) {
                        buf.commit(static_cast<u32>(nr));
                        result = static_cast<i32>(nr);
                    } else if (nr == 0) {
                        result = 0;
                    } else {
                        result = -errno;
                    }
                } else {
                    result = -ENOBUFS;
                }
            }

            events[out].conn_id = conn_id;
            events[out].type = recv_type;
            events[out].result = result;
            events[out].buf_id = 0;
            events[out].has_buf = 0;
            events[out].more = 0;
            out++;

            if (has_write && conn_id < kMaxFdMap && out < max_events) {
                if ((type == IoEventType::Send && send_state[conn_id].remaining > 0) ||
                    (type != IoEventType::Send && upstream_send_state[conn_id].remaining > 0)) {
                goto handle_epollout;
                }
            }
        } else if (has_write) {
        handle_epollout:
            if (conn_id >= kMaxFdMap) continue;
            auto& ss = (type == IoEventType::Send) ? send_state[conn_id] : upstream_send_state[conn_id];
            if (ss.tls && conn_id >= max_conns) continue;
            if (ss.remaining == 0 || !ss.src || ss.fd < 0) {
                // No outstanding send associated with this connection.
                // Drop EPOLLOUT so a stale level-triggered wakeup cannot spin.
                rearm_recv_interest(epoll_fd, conn_id, type, downstream_fd_map, upstream_fd_map);
                continue;
            }

            i32 result = 0;
            bool pending_retry = false;

            if (ss.tls) {
                auto& conn = conns[conn_id];
                SSL* ssl = conn.tls;
                if (!ssl) {
                    result = -EINVAL;
                } else {
                    while (ss.remaining > 0) {
                        errno = 0;
                        i32 nw = get_tls_hooks()->ssl_write(
                            ssl, ss.src + ss.offset, static_cast<i32>(ss.remaining));
                        if (nw > 0) {
                            ss.offset += static_cast<u32>(nw);
                            ss.remaining -= static_cast<u32>(nw);
                            continue;
                        }
                        i32 ssl_err = get_tls_hooks()->ssl_get_error(ssl, nw);
                        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                            ss.tls_wait_events = tls_interest_for_error(ssl_err);
                            set_fd_interest(epoll_fd,
                                            ss.fd,
                                            conn_id,
                                            ss.type,
                                            tls_send_interest_for_error(ssl_err));
                            pending_retry = true;
                            break;
                        }
                        result = map_tls_error(ssl, nw);
                        ss.remaining = 0;
                        break;
                    }
                    if (!pending_retry && result == 0) result = static_cast<i32>(ss.offset);
                }
            } else {
                while (ss.remaining > 0) {
                    ssize_t nw;
                    do {
                        nw = send(ss.fd, ss.src + ss.offset, ss.remaining, MSG_NOSIGNAL);
                    } while (nw < 0 && errno == EINTR);
                    if (nw > 0) {
                        ss.offset += static_cast<u32>(nw);
                        ss.remaining -= static_cast<u32>(nw);
                    } else if (nw < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        pending_retry = true;
                        break;
                    } else {
                        result = (nw < 0) ? -errno : -EPIPE;
                        ss.remaining = 0;
                        break;
                    }
                }
                if (!pending_retry && result == 0) result = static_cast<i32>(ss.offset);
            }

            if (pending_retry) continue;

            i32 send_fd = ss.fd;
            IoEventType next_type = (ss.type == IoEventType::UpstreamSend)
                                        ? IoEventType::UpstreamRecv
                                        : IoEventType::Recv;
            IoEventType emit_type = ss.type;
            if (type == IoEventType::Send) {
                ss = {nullptr, -1, 0, 0, IoEventType::Send, false, 0};
            } else {
                ss = {nullptr, -1, 0, 0, IoEventType::UpstreamSend, false, 0};
            }
            if (send_fd >= 0) set_fd_interest(epoll_fd, send_fd, conn_id, next_type, EPOLLIN);

            events[out].conn_id = conn_id;
            events[out].type = emit_type;
            events[out].result = result;
            events[out].buf_id = 0;
            events[out].has_buf = 0;
            events[out].more = 0;
            out++;
        }
    }

    return out;
}

void EpollBackend::shutdown() {
    if (timer_fd >= 0) {
        close(timer_fd);
        timer_fd = -1;
    }
    if (yield_timer_fd >= 0) {
        close(yield_timer_fd);
        yield_timer_fd = -1;
    }
    if (epoll_fd >= 0) {
        close(epoll_fd);
        epoll_fd = -1;
    }
}

}  // namespace rut
