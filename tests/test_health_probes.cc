#include "route_config_fixture.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "test.h"
#include <new>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

namespace {
bool fail_connect_submit = false;

struct Socket {
    i32 fd = -1;
    ~Socket() {
        if (fd >= 0) ::close(fd);
    }
};

template <typename Loop>
struct ProbeRig {
    rut::test::RouteConfigFixture owner;
    const RouteConfig* active = nullptr;
    Loop* loop = nullptr;
    Socket listener;
    u16 port = 0;
    bool initialized = false;
    ShardMetrics metrics{};

    bool init() {
        if (!owner.config) return false;
        listener.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (listener.fd < 0 ||
            bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
            listen(listener.fd, 16))
            return false;
        socklen_t kLength = sizeof(address);
        if (getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &kLength)) return false;
        port = ntohs(address.sin_port);
        void* storage =
            mmap(nullptr, sizeof(Loop), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (storage == MAP_FAILED) return false;
        loop = new (storage) Loop();
        if (!loop->init(0, -1, 0, 128)) return false;
        initialized = true;
        active = owner.config;
        loop->config_ptr = &active;
        loop->metrics = &metrics;
        loop->upstream_timeout = 2;
        if (!owner.config->add_upstream("api", 0x7f000001u, port)) return false;
        if (!owner.config->set_upstream_health_check(0, "/healthz", 8, 1000, 200)) return false;
        loop->arm_health_on_config_change();
        return true;
    }

    u32 initialized_slots() const {
        if constexpr (requires { loop->slots_initialized; })
            return loop->slots_initialized;
        else
            return loop->connection_capacity;
    }

    void pump() {
        if constexpr (requires { loop->retry_strict_upstream_retirement_cancels(); })
            loop->retry_strict_upstream_retirement_cancels();
        IoEvent events[32]{};
        const u32 kCount = loop->backend.wait(events, 32, loop->conns, initialized_slots(), 0);
        u32 kept = 0;
        for (u32 i = 0; i < kCount; ++i) {
            if (events[i].type != IoEventType::Timeout) events[kept++] = events[i];
        }
        loop->dispatch_batch(events, kept);
        if constexpr (requires { loop->reclaim_pending(); }) loop->reclaim_pending();
    }

    template <typename Predicate>
    bool until(Predicate predicate) {
        for (u32 i = 0; i < 3000; ++i) {
            if (predicate()) return true;
            pump();
            usleep(1000);
        }
        return predicate();
    }

    Connection* probe() {
        for (u32 i = 0; i < initialized_slots(); ++i) {
            auto& c = loop->conns[i];
            if (c.is_health_probe && c.upstream_fd >= 0) return &c;
        }
        return nullptr;
    }

    bool receive_request(Socket& peer, char* request, u32 capacity) {
        u32 used = 0;
        return until([&] {
            if (peer.fd < 0)
                peer.fd = accept4(listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (peer.fd >= 0 && used + 1 < capacity) {
                const ssize_t kRead =
                    recv(peer.fd, request + used, capacity - used - 1, MSG_DONTWAIT);
                if (kRead > 0) used += static_cast<u32>(kRead);
                request[used] = '\0';
            }
            return strstr(request, "\r\n\r\n") != nullptr;
        });
    }

    bool respond(Socket& peer, const char* response) {
        const u32 kLength = static_cast<u32>(strlen(response));
        if (send(peer.fd, response, kLength, MSG_NOSIGNAL) != static_cast<ssize_t>(kLength))
            return false;
        return until([&] { return !probe_in_flight(0, 0); });
    }

    ~ProbeRig() {
        fail_connect_submit = false;
        if (loop) {
            if (initialized) {
                loop->force_close_all();
                (void)until([&] { return loop->active_count() == 0; });
                loop->shutdown();
            }
            loop->~Loop();
            munmap(loop, sizeof(Loop));
        }
        reset_backend_health();
    }
};

template <typename Loop>
void health_and_recovery(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    const u32 kFreeSlots = rig.loop->free_conn_slots();
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    REQUIRE(rig.probe());
    CHECK(rig.probe()->fd < 0);
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    CHECK(strstr(request, "GET /healthz HTTP/1.1\r\n") != nullptr);
    CHECK(strstr(request, "Host: 127.0.0.1:") != nullptr);
    REQUIRE(rig.respond(peer, "HTTP/1.1 500 Failed\r\nContent-Length: 0\r\n\r\n"));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket recovery;
    request[0] = '\0';
    REQUIRE(rig.receive_request(recovery, request, sizeof(request)));
    REQUIRE(rig.respond(recovery, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK_FALSE(backend_ejected(0, 0, 0));
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_EQ(rig.metrics.connections_total, 0u);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
    CHECK_EQ(rig.metrics.requests_total, 0u);
    CHECK_EQ(rig.metrics.requests_active, 0u);
}

template <typename Loop>
void health_thresholds(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    REQUIRE(rig.owner.config->set_upstream_health_check(0, "/healthz", 8, 1000, 200, {2, 3}));
    const auto respond = [&](bool success) {
        Socket peer;
        char request[512]{};
        return start_health_probe(rig.loop, 0, 0) &&
               rig.receive_request(peer, request, sizeof(request)) &&
               rig.respond(peer,
                           success ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                                   : "HTTP/1.1 500 Failed\r\nContent-Length: 0\r\n\r\n");
    };
    struct Outcome {
        bool success;
        bool ejected;
    };
    const Outcome outcomes[] = {{false, false},
                                {true, false},
                                {false, false},
                                {false, true},
                                {true, true},
                                {true, true},
                                {false, true},
                                {true, true},
                                {true, true},
                                {true, false}};
    for (const auto& outcome : outcomes) {
        REQUIRE(respond(outcome.success));
        record_backend_result(0, 0, true, 0);
        CHECK_EQ(backend_ejected(0, 0, ~u64{0}), outcome.ejected);
    }

    // The previous configuration's partial streak cannot eject a replacement.
    REQUIRE(respond(false));
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket stalled;
    char request[512]{};
    REQUIRE(rig.receive_request(stalled, request, sizeof(request)));
    for (u32 i = 0; i < 3; ++i) rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_FALSE(backend_ejected(0, 0, ~u64{0}));
    REQUIRE(respond(false));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    CHECK_EQ(rig.loop->active_count(), 0u);
}

template <typename Loop>
void timeout_and_reclaim(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    Connection* probe = rig.probe();
    REQUIRE(probe);
    for (u32 i = 0; i < 3; ++i) rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK(backend_ejected(0, 0, ~u64{0}));
    if constexpr (requires { rig.loop->pending_free_count; }) {
        CHECK(probe_in_flight(0, 0));
        CHECK(probe->pending_ops > 0);
        CHECK(probe->upstream_recv_slice != nullptr);
        CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    }
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->active_count(), 0u);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
}

template <typename Loop>
void connect_timeout_wheel_ownership(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    Connection* c = rig.loop->alloc_conn();
    REQUIRE(c);
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->on_upstream_send = &on_upstream_connected<Loop>;
    const u32 episode = c->upstream_episode;
    auto& target = rig.owner.config->upstreams[0];
    arm_connect_timeout(rig.loop, *c, target);  // Omission leaves the timer alone.
    CHECK_EQ(c->connect_timeout_episode, 0u);
    target.connect_timeout_seconds = 2;
    c->is_health_probe = true;
    arm_connect_timeout(rig.loop, *c, target);
    CHECK_EQ(c->connect_timeout_episode, 0u);
    c->is_health_probe = false;
    c->tls_active = true;
    arm_connect_timeout(rig.loop, *c, target);
    CHECK_EQ(c->connect_timeout_episode, 0u);
    c->tls_active = false;
    target.http2 = true;
    arm_connect_timeout(rig.loop, *c, target);
    CHECK_EQ(c->connect_timeout_episode, 0u);
    target.http2 = false;
    c->on_upstream_send = nullptr;
    arm_connect_timeout(rig.loop, *c, target);
    CHECK_EQ(c->connect_timeout_episode, 0u);
    c->on_upstream_send = &on_upstream_connected<Loop>;
    arm_connect_timeout(rig.loop, *c, target);
    CHECK_EQ(c->connect_timeout_episode, episode);
    u32 expired = 0;
    for (u32 i = 0; i < 2; ++i) rig.loop->timer.tick([&](Connection*) { ++expired; });
    CHECK_EQ(expired, 0u);
    rig.loop->timer.tick([&](Connection* value) {
        CHECK(value == c);
        ++expired;
    });
    CHECK_EQ(expired, 1u);
    c->connect_timeout_episode = 0;
    rig.loop->free_conn(*c);
}

TEST(health_probe, epoll_connect_timeout_wheel_ownership) {
    connect_timeout_wheel_ownership<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_connect_timeout_wheel_ownership) {
    connect_timeout_wheel_ownership<IoUringEventLoop>(_tc);
}

template <typename Loop>
void connect_timeout_closes_and_drains_pending_connect(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.loop->upstream_timeout = 10;
    auto& target = rig.owner.config->upstreams[0];
    target.connect_timeout_seconds = 1;
    reset_backend_health();
    target.passive_health.enabled = true;
    target.passive_health.timeouts = 2;
    target.passive_health.successes = 1;
    target.passive_health.healthy_statuses[0] = 1;
    // A full listen queue leaves a real second loopback TCP connect pending.
    REQUIRE_EQ(listen(rig.listener.fd, 0), 0);
    Socket filler;
    filler.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(filler.fd >= 0);
    REQUIRE_EQ(connect(filler.fd,
                       reinterpret_cast<const sockaddr*>(&target.addrs[0]),
                       sizeof(target.addrs[0])),
               0);
    Socket peer;
    int downstream[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, downstream), 0);
    peer.fd = downstream[1];
    Connection* c = rig.loop->alloc_conn();
    REQUIRE(c);
    const u32 id = c->id;
    c->fd = downstream[0];
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->request_config = rig.active;
    c->upstream_idx = 0;
    c->upstream_backend_idx = 0;
    c->upstream_attempts = 1;
    c->req_start_us = monotonic_us();
    rig.loop->epoch_enter();
    constexpr char request[] = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    REQUIRE(c->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1));
    c->req_initial_send_len = sizeof(request) - 1;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->upstream_fd = UpstreamPool::create_socket();
    REQUIRE(c->upstream_fd >= 0);
    c->set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
    REQUIRE(rig.loop->submit_connect(*c, &target.addrs[0], sizeof(target.addrs[0])));
    const u32 episode = c->upstream_episode;
    arm_connect_timeout(rig.loop, *c, target);
    rig.pump();  // Submit any queued io_uring SQE and detect unexpected completion.
    REQUIRE_EQ(c->connect_timeout_episode, episode);
    pollfd pending{c->upstream_fd, POLLOUT, 0};
    REQUIRE_EQ(poll(&pending, 1, 0), 0);
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(c->connect_timeout_episode, episode);
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    char byte = 0;
    CHECK_EQ(recv(peer.fd, &byte, 1, 0), 0);
    BackendHealth* health = backend_health(0, 0);
    REQUIRE(health);
    CHECK_EQ(health->passive_timeouts, 1u);
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(health->passive_timeouts, 1u);
    if constexpr (requires { rig.loop->backend.sq_head; }) {
        CHECK_EQ(c->upstream_close_episode, episode);
        CHECK((c->upstream_close_target_owned & kUpstreamOpConnect) != 0);
    }
    REQUIRE(rig.until([&] { return rig.loop->active_count() == 0; }));
    CHECK_EQ(rig.loop->conns[id].pending_ops, 0u);
    reset_backend_health();
}

template <typename Loop>
void connect_timeout_retries_pending_socket(rut::test::TestCase* _tc,
                                            bool disconnect = false,
                                            bool reload = false) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& target = rig.owner.config->upstreams[0];
    target.connect_timeout_seconds = 1;
    target.passive_health.enabled = true;
    target.passive_health.timeouts = 2;
    target.passive_health.successes = 1;
    target.passive_health.healthy_statuses[0] = 1;
    reset_backend_health();
    target.connect_attempts = 2;
    target.addr_count = 2;
    Socket alternate;
    alternate.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(alternate.fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE_EQ(bind(alternate.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    REQUIRE_EQ(listen(alternate.fd, 16), 0);
    socklen_t len = sizeof(address);
    REQUIRE_EQ(getsockname(alternate.fd, reinterpret_cast<sockaddr*>(&address), &len), 0);
    target.addrs[1] = address;
    REQUIRE_EQ(listen(rig.listener.fd, 0), 0);
    Socket filler;
    filler.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(filler.fd >= 0);
    REQUIRE_EQ(connect(filler.fd,
                       reinterpret_cast<const sockaddr*>(&target.addrs[0]),
                       sizeof(target.addrs[0])),
               0);
    int downstream[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, downstream), 0);
    Socket peer;
    peer.fd = downstream[1];
    Connection* c = rig.loop->alloc_conn();
    REQUIRE(c);
    c->fd = downstream[0];
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->request_config = rig.active;
    c->upstream_idx = 0;
    c->upstream_backend_idx = 0;
    c->upstream_attempts = 1;
    c->upstream_attempted_backends = 1;
    c->req_start_us = monotonic_us();
    rig.loop->epoch_enter();
    constexpr char request[] = "GET /retry HTTP/1.1\r\nHost: test\r\n\r\n";
    constexpr char successor[] = "GET /next HTTP/1.1\r\nHost: test\r\n\r\n";
    REQUIRE(c->recv_buf.write(reinterpret_cast<const u8*>(request), sizeof(request) - 1));
    if (!disconnect)
        REQUIRE(c->recv_buf.write(reinterpret_cast<const u8*>(successor), sizeof(successor) - 1));
    c->req_initial_send_len = sizeof(request) - 1;
    c->req_header_end = sizeof(request) - 1;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->upstream_fd = UpstreamPool::create_socket();
    REQUIRE(c->upstream_fd >= 0);
    c->set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
    REQUIRE(rig.loop->submit_connect(*c, &target.addrs[0], sizeof(target.addrs[0])));
    REQUIRE(rig.loop->submit_recv(*c));
    arm_connect_timeout(rig.loop, *c, target);
    rig.pump();
    pollfd pending{c->upstream_fd, POLLOUT, 0};
    REQUIRE_EQ(poll(&pending, 1, 0), 0);
    IoEvent tick{0, 2, 0, 0, IoEventType::Timeout, 0};
    if (reload) {
        // A configuration change after retirement starts invalidates the lease
        // before any successor connect is submitted at the batch boundary.
        expire_connect_attempt(rig.loop, *c);
        rig.active = nullptr;
        rig.loop->dispatch_batch(nullptr, 0);
        REQUIRE(rig.until([&] { return rig.loop->active_count() == 0; }));
        CHECK_EQ(accept4(alternate.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC), -1);
        return;
    }
    if (disconnect) {
        REQUIRE_EQ(shutdown(peer.fd, SHUT_WR), 0);
        IoEvent events[32]{};
        IoEvent terminal{};
        bool found = false;
        for (u32 tries = 0; tries < 3000 && !found; ++tries) {
            const u32 count =
                rig.loop->backend.wait(events, 32, rig.loop->conns, rig.initialized_slots(), 0);
            for (u32 i = 0; i < count; ++i) {
                if (events[i].type == IoEventType::Recv && events[i].conn_id == c->id &&
                    events[i].result <= 0) {
                    terminal = events[i];
                    found = true;
                } else if (events[i].type != IoEventType::Timeout) {
                    rig.loop->dispatch(events[i]);
                }
            }
            if (!found) usleep(1000);
        }
        REQUIRE(found);
        const IoEvent batch[] = {tick, terminal};
        rig.loop->dispatch_batch(batch, 2);
        REQUIRE(rig.until([&] { return rig.loop->active_count() == 0; }));
        CHECK_EQ(accept4(alternate.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC), -1);
        BackendHealth* health = backend_health(0, 0);
        REQUIRE(health);
        CHECK_EQ(health->passive_timeouts, 1u);
        return;
    }
    if constexpr (requires { rig.loop->begin_upstream_retirement(*c, kUpstreamOpConnect); }) {
        rig.loop->dispatch_batch(&tick, 1);
    } else {
        // A success already returned by epoll in the timer's batch belongs to
        // the detached episode and must not send the request to the old peer.
        const IoEvent late_success{
            c->id, 0, 0, 0, IoEventType::UpstreamConnect, 0, 0, c->upstream_episode};
        const IoEvent batch[] = {tick, late_success};
        rig.loop->dispatch_batch(batch, 2);
    }
    Socket origin;
    char wire[256]{};
    u32 used = 0;
    const bool received = rig.until([&] {
        if (origin.fd < 0)
            origin.fd = accept4(alternate.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (origin.fd >= 0) {
            const auto n = recv(origin.fd, wire + used, sizeof(wire) - used, 0);
            if (n > 0) used += static_cast<u32>(n);
        }
        return used >= sizeof(request) - 1;
    });
    REQUIRE(received);
    CHECK_EQ(used, sizeof(request) - 1);
    CHECK_EQ(memcmp(wire, request, sizeof(request) - 1), 0);
    CHECK_EQ(c->upstream_attempts, 2u);
    CHECK_EQ(c->upstream_backend_idx, 1u);
    REQUIRE(rig.until([&] { return c->pipeline_stash_len == sizeof(successor) - 1; }));
    CHECK_EQ(memcmp(c->send_buf.data() + c->retry_req_send_len, successor, sizeof(successor) - 1),
             0);
    BackendHealth* health = backend_health(0, 0);
    REQUIRE(health);
    CHECK_EQ(health->passive_timeouts, 1u);
    rig.loop->close_conn(*c);
    REQUIRE(rig.until([&] { return rig.loop->active_count() == 0; }));
}

TEST(health_probe, epoll_connect_timeout_retries_pending_socket) {
    connect_timeout_retries_pending_socket<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_connect_timeout_retries_pending_socket) {
    connect_timeout_retries_pending_socket<IoUringEventLoop>(_tc);
}

TEST(health_probe, epoll_connect_timeout_same_batch_disconnect) {
    connect_timeout_retries_pending_socket<EpollEventLoop>(_tc, true);
}
TEST(health_probe, iouring_connect_timeout_same_batch_disconnect) {
    connect_timeout_retries_pending_socket<IoUringEventLoop>(_tc, true);
}

TEST(health_probe, epoll_connect_timeout_reload_before_resume) {
    connect_timeout_retries_pending_socket<EpollEventLoop>(_tc, false, true);
}
TEST(health_probe, iouring_connect_timeout_reload_before_resume) {
    connect_timeout_retries_pending_socket<IoUringEventLoop>(_tc, false, true);
}

TEST(health_probe, epoll_connect_timeout_dispatch) {
    connect_timeout_closes_and_drains_pending_connect<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_connect_timeout_dispatch) {
    connect_timeout_closes_and_drains_pending_connect<IoUringEventLoop>(_tc);
}

template <typename Loop>
void zero_weight_and_slot_reserve(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.owner.config->upstreams[0].weights[0] = 0;
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    CHECK_FALSE(probe_in_flight(0, 0));
    CHECK_EQ(rig.loop->active_count(), 0u);
    rig.owner.config->upstreams[0].weights[0] = 1;
    Connection* held[64]{};
    for (Connection*& c : held) {
        c = rig.loop->alloc_conn();
        REQUIRE(c);
    }
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    CHECK_FALSE(probe_in_flight(0, 0));
    CHECK_FALSE(backend_ejected(0, 0, 0));
    for (Connection* c : held) rig.loop->free_conn(*c);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
}

template <typename Loop>
void same_address_reload(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& target = rig.owner.config->upstreams[0];
    target.hc_require_initial_success = 1;
    record_active_probe_result(0, 0, true, 0);
    REQUIRE(backend_initially_ready(target, 0, 0));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    CHECK_FALSE(backend_initially_ready(target, 0, 0));
    record_active_probe_result(0, 0, false, 0);
    REQUIRE(rig.respond(peer, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    CHECK_FALSE(backend_initially_ready(target, 0, 0));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket next;
    request[0] = '\0';
    REQUIRE(rig.receive_request(next, request, sizeof(request)));
    REQUIRE(rig.respond(next, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK_FALSE(backend_ejected(0, 0, 0));
    CHECK(backend_initially_ready(target, 0, 0));
}
template <typename Loop>
void sweep_respects_disabled_interval_and_drain(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.owner.config->upstreams[0].hc_interval_ms = 10000;
    rig.owner.config->upstreams[0].weights[0] = 0;
    rig.loop->health_probe_deadline_ns[0] = 0;
    rig.loop->sweep_health_probes();
    CHECK(rig.loop->health_probe_deadline_ns[0] > monotonic_ns());
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_FALSE(probe_in_flight(0, 0));
    rig.owner.config->upstreams[0].weights[0] = 1;
    rig.loop->drain(1);
    rig.loop->health_probe_deadline_ns[0] = 0;
    rig.loop->sweep_health_probes();
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_FALSE(probe_in_flight(0, 0));
}

template <typename Loop>
void tcp_health_and_recovery(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    REQUIRE(rig.owner.config->set_upstream_health_check(
        0, nullptr, 0, 1000, 0, {2, 2}, ActiveHealthType::Tcp, 1000, {}, {}, true));
    const u32 kFreeSlots = rig.loop->free_conn_slots();
    ::close(rig.listener.fd);
    rig.listener.fd = -1;
    for (u32 i = 0; i < 2; ++i) {
        REQUIRE(start_health_probe(rig.loop, 0, 0));
        REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
        CHECK_EQ(backend_ejected(0, 0, ~u64{0}), i == 1);
        CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    }
    rig.listener.fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(rig.listener.fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(rig.port);
    REQUIRE_EQ(bind(rig.listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    REQUIRE_EQ(listen(rig.listener.fd, 16), 0);
    // TCP probes deliberately do not instantiate upstream TLS or HTTP/2 state.
    rig.owner.config->upstreams[0].tls.enabled = true;
    for (u32 i = 0; i < 2; ++i) {
        rig.owner.config->upstreams[0].http2 = i == 1;
        REQUIRE(start_health_probe(rig.loop, 0, 0));
        Connection* probe = rig.probe();
        REQUIRE(probe);
        CHECK(probe->health_probe_tcp);
        CHECK_EQ(probe->recv_buf.len(), 0u);
        CHECK_EQ(probe->upstream_recv_slice, nullptr);
        CHECK_FALSE(probe->h1_tls_transport);
        CHECK_EQ(probe->h2, nullptr);
        Socket peer;
        REQUIRE(rig.until([&] {
            if (peer.fd < 0)
                peer.fd = accept4(rig.listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            return peer.fd >= 0 && !probe_in_flight(0, 0);
        }));
        char data[64]{};
        CHECK_EQ(recv(peer.fd, data, sizeof(data), MSG_DONTWAIT), 0);  // EOF, no application bytes
        CHECK_EQ(backend_ejected(0, 0, 0), i == 0);
        CHECK_EQ(backend_initially_ready(rig.owner.config->upstreams[0], 0, 0), i == 1);
        CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    }
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_EQ(rig.metrics.connections_total, 0u);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
    CHECK_EQ(rig.metrics.requests_total, 0u);
}

template <typename Loop>
void tcp_pending_timeout_and_reload(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.loop->upstream_timeout = 30;
    REQUIRE(rig.owner.config->set_upstream_health_check(
        0, nullptr, 0, 1000, 0, {}, ActiveHealthType::Tcp, 1000));
    const u32 kFreeSlots = rig.loop->free_conn_slots();
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    REQUIRE(rig.probe());
    // Expire before polling the queued Connect: late successful completion must
    // drain rather than restore health or release the guard twice.
    for (u32 i = 0; i < 2; ++i) rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK(backend_ejected(0, 0, ~u64{0}));
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    record_active_probe_result(0, 0, false, 0);
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK(backend_ejected(0, 0, ~u64{0}));  // old success ignored at same config address
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
}

template <typename Loop>
void explicit_http_probe_timeout(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.loop->upstream_timeout = 30;
    REQUIRE(rig.owner.config->set_upstream_health_check(
        0, "/healthz", 8, 1000, 200, {}, ActiveHealthType::Http, 1000));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    for (u32 i = 0; i < 2; ++i) rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK(backend_ejected(0, 0, ~u64{0}));
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->active_count(), 0u);
}

template <typename Loop>
void tcp_mode_survives_destroyed_configuration(rut::test::TestCase* _tc) {
    rut::test::RouteConfigFixture next;
    REQUIRE(next.config);
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    REQUIRE(rig.owner.config->set_upstream_health_check(
        0, nullptr, 0, 1000, 0, {}, ActiveHealthType::Tcp, 1000));
    REQUIRE(next.config->add_upstream("api", 0x7f000001u, rig.port));
    REQUIRE(next.config->set_upstream_health_check(0, "/next", 5, 1000, 200));
    const u32 kFreeSlots = rig.loop->free_conn_slots();
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    REQUIRE(rig.probe());
    CHECK(rig.probe()->health_probe_tcp);
    rig.active = next.config;
    rig.owner.config->~RouteConfig();
    rig.owner.config = nullptr;
    rig.owner.arena.destroy();
    REQUIRE(rig.loop->arm_health_on_config_change());
    record_active_probe_result(0, 0, false, 0);
    Socket peer;
    REQUIRE(rig.until([&] {
        if (peer.fd < 0)
            peer.fd = accept4(rig.listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        return peer.fd >= 0 && !probe_in_flight(0, 0);
    }));
    char data[16]{};
    CHECK_EQ(recv(peer.fd, data, sizeof(data), MSG_DONTWAIT), 0);
    CHECK(backend_ejected(0, 0, ~u64{0}));  // never apply old TCP success to the HTTP replacement
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
}

}  // namespace

namespace rut::detail {
bool test_fail_iouring_submit(u8 operation) noexcept {
    return fail_connect_submit && operation == kTestIoUringConnectSubmit;
}
}  // namespace rut::detail

TEST(health_probe, epoll_health_and_recovery) {
    health_and_recovery<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_health_and_recovery) {
    health_and_recovery<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_health_thresholds) {
    health_thresholds<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_health_thresholds) {
    health_thresholds<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_timeout_and_reclaim) {
    timeout_and_reclaim<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_timeout_and_reclaim) {
    timeout_and_reclaim<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_zero_weight_and_slot_reserve) {
    zero_weight_and_slot_reserve<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_zero_weight_and_slot_reserve) {
    zero_weight_and_slot_reserve<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_same_address_reload) {
    same_address_reload<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_same_address_reload) {
    same_address_reload<IoUringEventLoop>(_tc);
}

TEST(health_probe, iouring_submit_failure_and_queue_budget) {
    ProbeRig<IoUringEventLoop> rig;
    REQUIRE(rig.init());
    const u32 kFreeSlots = rig.loop->free_conn_slots();
    auto& target = rig.owner.config->upstreams[0];
    target.hc_unhealthy_interval_ms = 1000;
    rig.loop->health_probe_last_issue_ns[0][0] = 0;
    fail_connect_submit = true;
    rig.loop->sweep_health_probes();
    CHECK_EQ(rig.loop->health_probe_last_issue_ns[0][0], 0u);
    CHECK_FALSE(rig.loop->health_probe_issued[0][0]);
    fail_connect_submit = false;
    CHECK_FALSE(probe_in_flight(0, 0));
    CHECK_FALSE(backend_ejected(0, 0, 0));
    CHECK_EQ(rig.loop->free_conn_slots(), kFreeSlots);
    auto& backend = rig.loop->backend;
    const u32 kTail = *backend.sq_tail;
    *backend.sq_tail = *backend.sq_head + backend.sq_ring_entries - 8;
    const u32 kBudget = rig.loop->health_probe_issue_budget();
    *backend.sq_tail = kTail;
    CHECK_EQ(kBudget, 0u);
    CHECK_EQ(rig.loop->active_count(), 0u);
}

TEST(health_probe, iouring_cancel_retries_after_sq_pressure) {
    ProbeRig<IoUringEventLoop> rig;
    REQUIRE(rig.init());
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    REQUIRE(rig.until([&] { return rig.probe() && rig.probe()->upstream_recv_armed; }));
    rig.pump();  // Submit the pending recv before injecting queue pressure.
    Connection* probe = rig.probe();
    REQUIRE(probe);
    auto& backend = rig.loop->backend;
    REQUIRE(backend.pending == 0);
    const u32 kOriginalTail = *backend.sq_tail;
    *backend.sq_tail = *backend.sq_head + backend.sq_ring_entries;
    backend.disable_full_sq_flush = true;
    rig.loop->free_health_probe(*probe);
    backend.disable_full_sq_flush = false;
    *backend.sq_tail = kOriginalTail;
    CHECK(probe_in_flight(0, 0));
    CHECK(probe->upstream_recv_slice != nullptr);
    CHECK_EQ(probe->upstream_retirement_cancel_retry, kUpstreamOpRecv);
    CHECK_EQ(rig.loop->upstream_retirement_retry_count, 1u);
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->upstream_retirement_retry_count, 0u);
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_EQ(backend.failure_code(), 0);
    CHECK_FALSE(backend_ejected(0, 0, 0));
}

TEST(health_probe, iouring_connect_address_survives_retired_config) {
    rut::test::RouteConfigFixture next_owner;
    REQUIRE(next_owner.config);
    ProbeRig<IoUringEventLoop> rig;
    REQUIRE(rig.init());
    REQUIRE(next_owner.config->add_upstream("api", 0x7f000001u, rig.port));
    REQUIRE(next_owner.config->set_upstream_health_check(0, "/next", 5, 1000, 200));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    const Connection* probe = rig.probe();
    REQUIRE(probe);
    const auto* address = reinterpret_cast<const sockaddr_in*>(probe->send_buf.data());
    CHECK_EQ(ntohs(address->sin_port), rig.port);
    rig.active = next_owner.config;
    rig.owner.config->~RouteConfig();
    rig.owner.config = nullptr;
    rig.owner.arena.destroy();
    REQUIRE(rig.loop->arm_health_on_config_change());
    record_active_probe_result(0, 0, false, 0);
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    CHECK(strstr(request, "GET /healthz HTTP/1.1") != nullptr);
    REQUIRE(rig.respond(peer, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    CHECK_EQ(rig.loop->active_count(), 0u);
}

TEST(health_probe, epoll_sweep_respects_disabled_interval_and_drain) {
    sweep_respects_disabled_interval_and_drain<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_sweep_respects_disabled_interval_and_drain) {
    sweep_respects_disabled_interval_and_drain<IoUringEventLoop>(_tc);
}

TEST(health_probe, epoll_tcp_health_and_recovery) {
    tcp_health_and_recovery<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_tcp_health_and_recovery) {
    tcp_health_and_recovery<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_tcp_pending_timeout_and_reload) {
    tcp_pending_timeout_and_reload<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_tcp_pending_timeout_and_reload) {
    tcp_pending_timeout_and_reload<IoUringEventLoop>(_tc);
}
TEST(health_probe, epoll_explicit_http_probe_timeout) {
    explicit_http_probe_timeout<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_explicit_http_probe_timeout) {
    explicit_http_probe_timeout<IoUringEventLoop>(_tc);
}

TEST(health_probe, public_health_api_rejects_ambiguous_or_invalid_modes) {
    rut::test::RouteConfigFixture owner;
    REQUIRE(owner.config);
    auto& cfg = *owner.config;
    REQUIRE(cfg.add_upstream("api", 0x7f000001, 9001));
    CHECK_FALSE(cfg.set_upstream_health_check(0, "/", 1, 1000, 0, {}, ActiveHealthType::Tcp));
    CHECK_FALSE(cfg.set_upstream_health_check(0, nullptr, 0, 1000, 200, {}, ActiveHealthType::Tcp));
    CHECK_FALSE(cfg.set_upstream_health_check(
        0, nullptr, 0, 1000, 0, {}, static_cast<ActiveHealthType>(255)));
    CHECK_FALSE(
        cfg.set_upstream_health_check(0, "/", 1, 1000, 200, {}, ActiveHealthType::Http, 1500));
    CHECK_FALSE(
        cfg.set_upstream_health_check(0, "/", 1, 1000, 200, {}, ActiveHealthType::Http, 61000));
    CHECK_FALSE(cfg.set_upstream_health_check(
        0, "/", 1, 1000, 200, {}, ActiveHealthType::Http, 0xffffffffu));
    CHECK_FALSE(cfg.set_upstream_health_check(
        0, nullptr, 0, 1000, 0, {}, ActiveHealthType::Tcp, 0, {"tenant", 6}));
    CHECK_FALSE(cfg.set_upstream_health_check(
        0, "/", 1, 1000, 200, {}, ActiveHealthType::Http, 0, {"bad,host", 8}));
    CHECK_FALSE(cfg.upstreams[0].hc_enabled);
    cfg.upstreams[0].http2 = true;
    CHECK_FALSE(cfg.set_upstream_health_check(0, "/", 1, 1000, 200));
    CHECK(cfg.set_upstream_health_check(0, nullptr, 0, 1000, 0, {}, ActiveHealthType::Tcp, 60000));
    CHECK_EQ(cfg.upstreams[0].hc_type, ActiveHealthType::Tcp);
    CHECK_EQ(cfg.upstreams[0].hc_timeout_ms, 60000u);
}

TEST(health_probe, epoll_tcp_mode_survives_destroyed_configuration) {
    tcp_mode_survives_destroyed_configuration<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_tcp_mode_survives_destroyed_configuration) {
    tcp_mode_survives_destroyed_configuration<IoUringEventLoop>(_tc);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(health_probe, iouring_tls_guard_survives_transport_reclaim) {
    ProbeRig<IoUringEventLoop> rig;
    REQUIRE(rig.init());
    Connection owner{};
    owner.is_health_probe = true;
    owner.upstream_idx = 0;
    owner.upstream_backend_idx = 0;
    set_probe_in_flight(0, 0, true);
    Connection* transport = rig.loop->alloc_conn();
    REQUIRE(transport != nullptr);
    const u32 id = transport->id;
    h1_tls_transfer_probe_guard(owner, *transport);
    release_health_probe_guard(owner);
    CHECK(probe_in_flight(0, 0));
    // Model an outstanding transport CQE: free_conn must retain the guard in
    // its deferred slot until that CQE is accounted and the slot is reclaimed.
    transport->pending_ops = 1;
    rig.loop->free_conn(*transport);
    CHECK(probe_in_flight(0, 0));
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    rig.loop->conns[id].pending_ops = 0;
    rig.loop->reclaim_pending();
    CHECK_FALSE(probe_in_flight(0, 0));
}

TEST(health_probe, tls_transport_close_transfers_guard_before_owner_callback) {
    ProbeRig<EpollEventLoop> rig;
    REQUIRE(rig.init());
    Connection owner{};
    Connection transport{};
    owner.is_health_probe = true;
    owner.upstream_idx = 0;
    owner.upstream_backend_idx = 0;
    owner.on_upstream_send = [](void*, Connection& c, IoEvent) { release_health_probe_guard(c); };
    set_probe_in_flight(0, 0, true);
    auto* state = reinterpret_cast<H1TlsUpstream*>(rig.loop->pool.alloc());
    REQUIRE(state != nullptr);
    *state = {};
    state->owner = &owner;
    state->transport = &transport;
    owner.h1_tls_upstream = state;
    transport.h1_tls_transport = state;
    h1_tls_closed<EpollEventLoop>(rig.loop, transport);
    CHECK(probe_in_flight(0, 0));
    CHECK(transport.health_probe_guard_inherited);
    release_health_probe_guard(transport);
    CHECK_FALSE(probe_in_flight(0, 0));
}

TEST(health_probe, iouring_tls_detach_keeps_guard_until_recv_cancel_drains) {
    ProbeRig<IoUringEventLoop> rig;
    REQUIRE(rig.init());
    auto& up = rig.owner.config->upstreams[0];
    up.hc_concurrency = 1;
    up.addr_count = 2;
    up.addrs[1] = up.addrs[0];
    up.weights[1] = 1;
    rig.loop->health_probe_last_issue_ns[0][1] = 0;
    i32 sockets[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets), 0);
    Socket peer;
    peer.fd = sockets[1];
    Connection owner{};
    owner.is_health_probe = true;
    owner.upstream_idx = 0;
    owner.upstream_backend_idx = 0;
    Connection* transport = rig.loop->alloc_conn();
    REQUIRE(transport != nullptr);
    transport->fd = sockets[0];
    auto* state = reinterpret_cast<H1TlsUpstream*>(rig.loop->pool.alloc());
    REQUIRE(state != nullptr);
    *state = {};
    state->owner = &owner;
    state->transport = transport;
    owner.h1_tls_upstream = state;
    transport->h1_tls_transport = state;
    transport->on_close = &h1_tls_closed<IoUringEventLoop>;
    set_probe_in_flight(0, 0, true);
    REQUIRE(rig.loop->submit_recv(*transport));
    rig.pump();  // Submit the receive before detach requests its cancellation.
    REQUIRE(transport->pending_ops > 0);
    h1_tls_detach(rig.loop, owner);
    release_health_probe_guard(owner);
    CHECK(probe_in_flight(0, 0));
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    rig.loop->sweep_health_probes();
    CHECK_FALSE(probe_in_flight(0, 1));
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->active_count(), 0u);
    rig.loop->sweep_health_probes();
    CHECK(probe_in_flight(0, 1));
}

template <typename Loop>
void tls_reload_during_handshake(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& tls = rig.owner.config->upstreams[0].tls;
    tls.enabled = true;
    static constexpr char kCa[] = RUT_TLS_FIXTURES "/localhost_cert.pem";
    static constexpr char kName[] = "localhost";
    for (u32 i = 0; i < sizeof(kCa); ++i) tls.ca[i] = kCa[i];
    for (u32 i = 0; i < sizeof(kName); ++i) tls.server_name[i] = kName[i];
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    REQUIRE(rig.until([&] {
        peer.fd = accept4(rig.listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        return peer.fd >= 0;
    }));
    REQUIRE(rig.until([&] { return rig.probe() && rig.probe()->h1_tls_upstream; }));
    // The child is stalled in TLS negotiation. Replace the identity at the
    // same address before disconnecting it, so its failure cannot eject the
    // new target even if the numeric upstream/backend pair is reused.
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    ::close(peer.fd);
    peer.fd = -1;
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_FALSE(backend_ejected(0, 0, ~u64{0}));
    CHECK_EQ(rig.loop->active_count(), 0u);

    REQUIRE(start_health_probe(rig.loop, 0, 0));
    REQUIRE(rig.until([&] {
        peer.fd = accept4(rig.listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        return peer.fd >= 0;
    }));
    REQUIRE(rig.until([&] { return rig.probe() && rig.probe()->h1_tls_upstream; }));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    CHECK_EQ(rig.loop->active_count(), 0u);
    CHECK_EQ(rig.metrics.connections_closed, 0u);
}

TEST(health_probe, epoll_tls_reload_during_handshake) {
    tls_reload_during_handshake<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_tls_reload_during_handshake) {
    tls_reload_during_handshake<IoUringEventLoop>(_tc);
}

template <typename Loop>
void tls_probe_slot_reserve(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& tls = rig.owner.config->upstreams[0].tls;
    tls.enabled = true;
    static constexpr char kCa[] = RUT_TLS_FIXTURES "/localhost_cert.pem";
    static constexpr char kName[] = "localhost";
    for (u32 i = 0; i < sizeof(kCa); ++i) tls.ca[i] = kCa[i];
    for (u32 i = 0; i < sizeof(kName); ++i) tls.server_name[i] = kName[i];
    Connection* held[63]{};
    for (Connection*& c : held) {
        c = rig.loop->alloc_conn();
        REQUIRE(c);
    }
    CHECK_EQ(rig.loop->free_conn_slots(), 65u);
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
    CHECK_FALSE(probe_in_flight(0, 0));
    rig.loop->free_conn(*held[0]);
    held[0] = nullptr;
    CHECK_EQ(rig.loop->free_conn_slots(), 66u);
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0); }));
    for (Connection* c : held)
        if (c) rig.loop->free_conn(*c);
}

TEST(health_probe, epoll_tls_probe_slot_reserve) {
    tls_probe_slot_reserve<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_tls_probe_slot_reserve) {
    tls_probe_slot_reserve<IoUringEventLoop>(_tc);
}

TEST(health_probes, active_status_sets_validate_canonical_bits) {
    ActiveHealthStatuses statuses{};
    statuses.words[(200 - 200) / 64] |= u64{1} << ((200 - 200) % 64);
    statuses.words[(302 - 200) / 64] |= u64{1} << ((302 - 200) % 64);
    CHECK(valid_active_health_check(ActiveHealthType::Http, "/", 1, 1000, 0, {}, 0, statuses));
    CHECK_FALSE(
        valid_active_health_check(ActiveHealthType::Http, "/", 1, 1000, 200, {}, 0, statuses));
    CHECK_FALSE(
        valid_active_health_check(ActiveHealthType::Tcp, nullptr, 0, 1000, 0, {}, 0, statuses));
    statuses.words[6] |= u64{1} << 16;
    CHECK_FALSE(
        valid_active_health_check(ActiveHealthType::Http, "/", 1, 1000, 0, {}, 0, statuses));
    CHECK_FALSE(valid_active_health_check(ActiveHealthType::Http, "/", 1, 1000, 0, {}, 0));
}

template <typename Loop>
void unhealthy_cadence(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& up = rig.owner.config->upstreams[0];
    up.hc_interval_ms = 10000;
    up.hc_unhealthy_interval_ms = 1000;
    up.addr_count = 2;
    up.addrs[1] = up.addrs[0];
    up.weights[1] = 1;
    record_active_probe_result(0, 1, false, 0);
    BackendHealth* healthy = backend_health(0, 0);
    REQUIRE(healthy);
    healthy->eject_until_us = UINT64_MAX;
    CHECK_FALSE(probe_backend_latched_down(0, 0));
    healthy->passive_down = true;
    CHECK(probe_backend_latched_down(0, 0));
    healthy->passive_down = false;
    const u64 old = monotonic_ns() - 2'000'000'000ull;
    rig.loop->health_probe_last_issue_ns[0][0] = old;
    rig.loop->health_probe_last_issue_ns[0][1] = old;
    // Even a latched-down target's first issue uses the ordinary interval.
    rig.loop->sweep_health_probes();
    CHECK_FALSE(probe_in_flight(0, 0));
    CHECK_FALSE(probe_in_flight(0, 1));
    rig.loop->health_probe_issued[0][0] = true;
    rig.loop->health_probe_issued[0][1] = true;
    rig.loop->sweep_health_probes();
    CHECK_FALSE(probe_in_flight(0, 0));
    CHECK(probe_in_flight(0, 1));
    CHECK_EQ(rig.loop->health_probe_last_issue_ns[0][0], old);
    CHECK(rig.loop->health_probe_last_issue_ns[0][1] > old);
    const u64 issued = rig.loop->health_probe_last_issue_ns[0][1];
    rig.loop->sweep_health_probes();
    CHECK_EQ(rig.loop->health_probe_last_issue_ns[0][1], issued);
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    CHECK_FALSE(rig.loop->health_probe_issued[0][1]);
    CHECK(rig.loop->health_probe_last_issue_ns[0][1] >= issued);
}
TEST(health_probe, epoll_unhealthy_cadence) {
    unhealthy_cadence<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_unhealthy_cadence) {
    unhealthy_cadence<IoUringEventLoop>(_tc);
}

TEST(health_probe, epoll_unhealthy_cadence_rotates_under_small_budget) {
    ProbeRig<EpollEventLoop> rig;
    REQUIRE(rig.init());
    auto& up = rig.owner.config->upstreams[0];
    up.hc_unhealthy_interval_ms = 1000;
    up.addr_count = 3;
    for (u32 b = 0; b < up.addr_count; ++b) {
        up.addrs[b] = up.addrs[0];
        up.weights[b] = 1;
        rig.loop->health_probe_issued[0][b] = true;
        rig.loop->health_probe_last_issue_ns[0][b] = 0;
    }
    for (u32 expected = 0; expected < up.addr_count; ++expected) {
        rig.loop->backend.pending_count = rig.loop->backend.kPendingCap - 17;
        rig.loop->sweep_health_probes();
        CHECK(probe_in_flight(0, expected));
        Connection* c = rig.probe();
        REQUIRE(c);
        CHECK_EQ(c->upstream_backend_idx, expected);
        free_probe_conn(rig.loop, *c);
        rig.loop->backend.pending_count = 0;
        // A short interval can make an earlier target due again before the next sweep.
        rig.loop->health_probe_last_issue_ns[0][expected] = 0;
    }
}

static bool body_idle_loopback_pair(i32 pair[2]) {
    Socket listener;
    listener.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener.fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ||
        listen(listener.fd, 1))
        return false;
    socklen_t len = sizeof(addr);
    if (getsockname(listener.fd, reinterpret_cast<sockaddr*>(&addr), &len)) return false;
    pair[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (pair[0] < 0 || connect(pair[0], reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
        return false;
    pair[1] = accept4(listener.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (pair[1] < 0) return false;
    const int flags = fcntl(pair[0], F_GETFL, 0);
    return flags >= 0 && fcntl(pair[0], F_SETFL, flags | O_NONBLOCK) == 0;
}

template <typename Loop>
void body_idle_same_batch_progress(rut::test::TestCase* _tc, bool timeout_first) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.owner.config->upstreams[0].response_body_idle_timeout_seconds = 1;
    i32 upstream[2]{-1, -1};
    i32 downstream[2]{-1, -1};
    REQUIRE(body_idle_loopback_pair(upstream));
    REQUIRE(body_idle_loopback_pair(downstream));
    Socket origin;
    origin.fd = upstream[1];
    Socket client;
    client.fd = downstream[1];
    Connection* c = rig.loop->alloc_conn();
    REQUIRE(c);
    c->fd = downstream[0];
    c->upstream_fd = upstream[0];
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->request_config = rig.active;
    c->upstream_idx = 0;
    c->upstream_attempts = 1;
    c->req_start_us = monotonic_us();
    c->request_upload_complete = true;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->resp_body_mode = BodyMode::ContentLength;
    c->resp_body_remaining = 2;
    c->proxy_resp_started = true;
    c->upstream_recv_slice = rig.loop->pool.alloc();
    REQUIRE(c->upstream_recv_slice);
    c->upstream_recv_buf.bind(c->upstream_recv_slice, SlicePool::kSliceSize);
    c->set_slots(nullptr, nullptr, &on_response_body_recvd<Loop>, nullptr);
    rig.loop->epoch_enter();
    if constexpr (requires { rig.loop->backend.active_upstream_episode[c->id]; })
        rig.loop->backend.active_upstream_episode[c->id] = c->upstream_episode;
    REQUIRE(rig.loop->submit_recv_upstream(*c));
    REQUIRE(c->response_body_idle_armed);
    REQUIRE_EQ(send(origin.fd, "x", 1, MSG_NOSIGNAL), 1);
    IoEvent events[32]{};
    IoEvent progress{};
    bool found = false;
    for (u32 tries = 0; tries < 3000 && !found; ++tries) {
        const u32 count =
            rig.loop->backend.wait(events, 32, rig.loop->conns, rig.initialized_slots(), 0);
        for (u32 i = 0; i < count; ++i) {
            if (events[i].type == IoEventType::UpstreamRecv && events[i].conn_id == c->id &&
                events[i].result > 0) {
                progress = events[i];
                found = true;
            } else if (events[i].type != IoEventType::Timeout) {
                rig.loop->dispatch(events[i]);
            }
        }
        if (!found) usleep(1000);
    }
    REQUIRE(found);
    rig.loop->timer.remove(c);
    rig.loop->timer.add(c, 0);
    const IoEvent tick{0, 1, 0, 0, IoEventType::Timeout, 0};
    const IoEvent batch[] = {timeout_first ? tick : progress, timeout_first ? progress : tick};
    rig.loop->dispatch_batch(batch, 2);
    CHECK(c->fd >= 0);
    CHECK_FALSE(c->response_body_idle_expiry_pending);
    char byte = 0;
    REQUIRE(rig.until([&] { return recv(client.fd, &byte, 1, MSG_DONTWAIT) == 1; }));
    CHECK_EQ(byte, 'x');
}

TEST(body_idle, epoll_same_batch_progress) {
    body_idle_same_batch_progress<EpollEventLoop>(_tc, true);
    body_idle_same_batch_progress<EpollEventLoop>(_tc, false);
}
TEST(body_idle, iouring_same_batch_progress) {
    body_idle_same_batch_progress<IoUringEventLoop>(_tc, true);
    body_idle_same_batch_progress<IoUringEventLoop>(_tc, false);
}

TEST(health_probe, epoll_unhealthy_cadence_rotates_upstreams_under_small_budget) {
    ProbeRig<EpollEventLoop> rig;
    REQUIRE(rig.init());
    REQUIRE(rig.owner.config->add_upstream("second", 0x7f000001u, rig.port));
    REQUIRE(rig.owner.config->set_upstream_health_check(1, "/healthz", 8, 1000, 200));
    for (u32 u = 0; u < 2; ++u) {
        rig.owner.config->upstreams[u].hc_unhealthy_interval_ms = 1000;
        rig.loop->health_probe_issued[u][0] = true;
        rig.loop->health_probe_last_issue_ns[u][0] = 0;
    }
    for (u32 expected = 0; expected < 2; ++expected) {
        rig.loop->backend.pending_count = rig.loop->backend.kPendingCap - 17;
        rig.loop->sweep_health_probes();
        CHECK(probe_in_flight(static_cast<u16>(expected), 0));
        Connection* c = rig.probe();
        REQUIRE(c);
        CHECK_EQ(c->upstream_idx, expected);
        free_probe_conn(rig.loop, *c);
        rig.loop->backend.pending_count = 0;
        rig.loop->health_probe_last_issue_ns[expected][0] = 0;
    }
}

template <typename Loop>
void concurrency_limit(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& up = rig.owner.config->upstreams[0];
    up.hc_concurrency = 1;
    up.addr_count = 2;
    up.addrs[1] = up.addrs[0];
    up.weights[1] = 1;
    REQUIRE(rig.owner.config->add_upstream("second", 0x7f000001u, rig.port));
    REQUIRE(rig.owner.config->set_upstream_health_check(1, "/healthz", 8, 1000, 200));
    rig.loop->health_probe_last_issue_ns[0][0] = 0;
    rig.loop->health_probe_last_issue_ns[0][1] = 0;
    rig.loop->health_probe_deadline_ns[1] = 0;
    rig.loop->sweep_health_probes();
    CHECK(probe_in_flight(0, 0));
    CHECK_FALSE(probe_in_flight(0, 1));
    CHECK(probe_in_flight(1, 0));
    rig.loop->sweep_health_probes();
    CHECK_FALSE(probe_in_flight(0, 1));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 0) && !probe_in_flight(1, 0); }));
    rig.loop->sweep_health_probes();
    CHECK(probe_in_flight(0, 1));
}
TEST(health_probe, epoll_concurrency_limit) {
    concurrency_limit<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_concurrency_limit) {
    concurrency_limit<IoUringEventLoop>(_tc);
}

template <typename Loop>
void concurrency_old_guard(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    auto& up = rig.owner.config->upstreams[0];
    up.hc_concurrency = 1;
    up.addr_count = 2;
    up.addrs[1] = up.addrs[0];
    up.weights[1] = 1;
    REQUIRE(start_health_probe(rig.loop, 0, 1));
    up.addr_count = 1;
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    rig.loop->health_probe_last_issue_ns[0][0] = 0;
    rig.loop->sweep_health_probes();
    CHECK_FALSE(probe_in_flight(0, 0));
    rig.loop->force_close_all();
    REQUIRE(rig.until([&] { return !probe_in_flight(0, 1); }));
    rig.loop->sweep_health_probes();
    CHECK(probe_in_flight(0, 0));
}
TEST(health_probe, epoll_concurrency_old_guard) {
    concurrency_old_guard<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_concurrency_old_guard) {
    concurrency_old_guard<IoUringEventLoop>(_tc);
}
