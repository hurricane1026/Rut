#include "route_config_fixture.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "test.h"
#include <new>

#include <arpa/inet.h>
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
        for (u32 i = 0; i < kCount; ++i) {
            if (events[i].type != IoEventType::Timeout) loop->dispatch(events[i]);
        }
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
    rig.loop->upstream_timeout = 10;
    REQUIRE(rig.owner.config->set_upstream_health_check(0, "/healthz", 8, 1000, 200, {}, 2));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    Connection* probe = rig.probe();
    REQUIRE(probe);
    for (u32 i = 0; i < 2; ++i) {
        rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
        CHECK(probe_in_flight(0, 0));
    }
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
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
    const u32 episode = c->upstream_episode;
    auto& target = rig.owner.config->upstreams[0];
    target.connect_timeout_seconds = 2;
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
void connect_timeout_dispatches_and_fences_late_completion(rut::test::TestCase* _tc) {
    ProbeRig<Loop> rig;
    REQUIRE(rig.init());
    rig.loop->upstream_timeout = 10;
    auto& target = rig.owner.config->upstreams[0];
    target.connect_timeout_seconds = 1;
    Socket peer;
    int downstream[2];
    REQUIRE_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, downstream), 0);
    peer.fd = downstream[1];
    Connection* c = rig.loop->alloc_conn();
    REQUIRE(c);
    c->fd = downstream[0];
    c->protocol = ConnProtocol::Http11;
    c->state = ConnState::Proxying;
    c->request_config = rig.active;
    c->upstream_idx = 0;
    c->upstream_backend_idx = 0;
    c->req_method = static_cast<u8>(LogHttpMethod::Get);
    c->upstream_fd = UpstreamPool::create_socket();
    REQUIRE(c->upstream_fd >= 0);
    c->set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<Loop>);
    REQUIRE(rig.loop->submit_connect(*c, &target.addrs[0], sizeof(target.addrs[0])));
    const u32 episode = c->upstream_episode;
    arm_connect_timeout(rig.loop, *c, target);
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(c->connect_timeout_episode, episode);
    rig.loop->dispatch({0, 1, 0, 0, IoEventType::Timeout, 0});
    CHECK_EQ(c->connect_timeout_episode, 0u);
    CHECK_EQ(c->resp_status, 504u);
    CHECK_EQ(c->upstream_fd, -1);
    CHECK(c->upstream_abandoned);
    const auto status = c->resp_status;
    const auto state = c->state;
    const auto callback = c->on_send;
    // A late old-episode event must not replace the 504 response owner.
    rig.loop->dispatch({c->id, 0, 0, 0, IoEventType::UpstreamConnect, 1, 0, episode});
    CHECK_EQ(c->resp_status, status);
    CHECK_EQ(c->state, state);
    CHECK_EQ(c->on_send, callback);
    REQUIRE(rig.until([&] { return rig.loop->active_count() == 0; }));
}

TEST(health_probe, epoll_connect_timeout_dispatch) {
    connect_timeout_dispatches_and_fences_late_completion<EpollEventLoop>(_tc);
}
TEST(health_probe, iouring_connect_timeout_dispatch) {
    connect_timeout_dispatches_and_fences_late_completion<IoUringEventLoop>(_tc);
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
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket peer;
    char request[512]{};
    REQUIRE(rig.receive_request(peer, request, sizeof(request)));
    rig.owner.config->http_cache_identity = http_cache_config_identity();
    REQUIRE(rig.loop->arm_health_on_config_change());
    record_active_probe_result(0, 0, false, 0);
    REQUIRE(rig.respond(peer, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK(backend_ejected(0, 0, ~u64{0}));
    REQUIRE(start_health_probe(rig.loop, 0, 0));
    Socket next;
    request[0] = '\0';
    REQUIRE(rig.receive_request(next, request, sizeof(request)));
    REQUIRE(rig.respond(next, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    CHECK_FALSE(backend_ejected(0, 0, 0));
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
    fail_connect_submit = true;
    CHECK_FALSE(start_health_probe(rig.loop, 0, 0));
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
