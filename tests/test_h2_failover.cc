#include "mock_backend.h"
#include "route_config_fixture.h"
#include "rut/common/load_balance.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/consistent_hash.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/http2_frame.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/upstream_concurrency.h"
#include "rut/runtime/upstream_pool.h"
#include "test.h"
#include "test_helpers.h"
#include <atomic>

#include <errno.h>
#include <string.h>

namespace {
struct RetryRig {
    rut::test::RouteConfigFixture owner;
    SmallLoop loop;
    Http2Conn h2{};
    Connection* conn = nullptr;
    const RouteConfig* active = nullptr;

    bool init(u32 count = 2) {
        if (!owner.config) return false;
        loop.setup();
        conn = loop.alloc_conn();
        if (!conn) return false;
        auto& cfg = *owner.config;
        if (!cfg.add_upstream("api", 0x7f000001, 9000)) return false;
        for (u32 i = 1; i < count; ++i)
            if (!cfg.add_upstream_backend(0, 0x7f000001, static_cast<u16>(9000 + i))) return false;
        for (u32 i = 0; i < count; ++i) *backend_health(0, i) = {};
        active = &cfg;
        loop.config_ptr = &active;
        h2.init();
        h2.nstreams = 1;
        h2.streams[0] = {};
        h2.streams[0].id = 1;
        h2.streams[0].state = Http2StreamState::Open;
        h2.streams[0].send_window = static_cast<i32>(kDefaultInitialWindowSize);
        h2.streams[0].recv_window = static_cast<i32>(kDefaultInitialWindowSize);
        h2.streams[0].got_headers = true;
        h2.async_stream = 1;
        h2.async_kind = H2AsyncKind::Proxy;
        h2.async_cfg = &cfg;
        h2.async_load_balance = {};
        h2.async_load_balance.site = 1;
        h2.async_load_balance.policy = LoadBalancePolicy::RoundRobin;
        static constexpr char kRequest[] = "POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        memcpy(h2.pending_synth, kRequest, sizeof(kRequest) - 1);
        h2.async_synth_len = sizeof(kRequest) - 1;
        conn->h2 = &h2;
        conn->epoch_held = true;
        conn->upstream_idx = 0;
        conn->upstream_backend_idx = 0;
        conn->upstream_attempts = 1;
        conn->upstream_attempted_backends = 1;
        conn->upstream_fd = UpstreamPool::create_socket();
        conn->set_slots(nullptr, nullptr, nullptr, &h2_on_upstream_connected<SmallLoop>);
        hold_backend_active(*conn, &cfg);
        return conn->upstream_fd >= 0;
    }
    void fail(i32 result = -ECONNREFUSED, u32 aux = 0) {
        auto ev = make_ev(conn->id, IoEventType::UpstreamConnect, result);
        ev.aux = aux;
        h2_on_upstream_connected<SmallLoop>(&loop, *conn, ev);
    }
    ~RetryRig() {
        if (conn) {
            (void)detach_upstream_close(&loop, *conn);
            conn->h2 = nullptr;
        }
        for (u32 i = 0; i < 4; ++i) *backend_health(0, i) = {};
    }
};
}  // namespace

TEST(h2_failover, preserves_request_policy_and_backend_accounting) {
    RetryRig rig;
    REQUIRE(rig.init());
    rig.h2.async_load_balance.policy = LoadBalancePolicy::LeastRequests;
    const u32 kLength = rig.h2.async_synth_len;
    rig.fail();
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 1u);
    CHECK_EQ(rig.conn->upstream_attempts, 2u);
    CHECK_EQ(rig.conn->upstream_backend_idx, 1u);
    CHECK_EQ(rig.conn->upstream_attempted_backends, 3u);
    CHECK(rig.conn->on_upstream_send == &h2_on_upstream_connected<SmallLoop>);
    CHECK(rig.conn->request_config == nullptr);
    CHECK(rig.conn->epoch_held);
    CHECK_EQ(rig.h2.async_stream, 1u);
    CHECK_EQ(rig.h2.async_synth_len, kLength);
    CHECK_EQ(rig.h2.async_synth_sent, 0u);
    CHECK_EQ(memcmp(rig.h2.pending_synth + kLength - 4, "body", 4), 0);
    CHECK_EQ(rig.owner.config->backend_selection[0].active[0][0], 0u);
    CHECK_EQ(rig.owner.config->backend_selection[0].active[0][1], 1u);
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Send), 0u);
    h2_on_upstream_connected<SmallLoop>(
        &rig.loop, *rig.conn, make_ev(rig.conn->id, IoEventType::UpstreamConnect, 0));
    CHECK(rig.conn->on_upstream_send == &h2_on_upstream_request_sent<SmallLoop>);
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Send), 1u);
}

TEST(h2_failover, distinct_targets_and_three_attempt_limit) {
    RetryRig rig;
    REQUIRE(rig.init(4));
    rig.fail();
    rig.fail();
    CHECK_EQ(rig.conn->upstream_attempts, 3u);
    CHECK_EQ(rig.conn->upstream_attempted_backends, 7u);
    rig.fail();
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 2u);
    CHECK_EQ(rig.conn->upstream_fd, -1);
    CHECK_EQ(rig.h2.async_stream, 0u);
    CHECK_FALSE(rig.conn->epoch_held);
    CHECK_GT(rig.conn->send_buf.len(), 0u);
    for (u32 i = 0; i < 4; ++i) CHECK_EQ(rig.owner.config->backend_selection[0].active[0][i], 0u);
}

TEST(h2_failover, configured_budget_releases_each_backend) {
    constexpr u32 kBudgets[] = {1u, 2u, 4u};
    for (u32 budget : kBudgets) {
        RetryRig rig;
        REQUIRE(rig.init(4));
        rig.owner.config->upstreams[0].connect_attempts = static_cast<u8>(budget);
        for (u32 attempt = 0; attempt < budget; ++attempt) rig.fail();
        CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), budget - 1);
        CHECK_EQ(rig.conn->upstream_fd, -1);
        CHECK_EQ(rig.h2.async_stream, 0u);
        CHECK_FALSE(rig.conn->epoch_held);
        for (u32 i = 0; i < 4; ++i)
            CHECK_EQ(rig.owner.config->backend_selection[0].active[0][i], 0u);
    }
}

TEST(h2_failover, exhausted_or_disabled_targets_do_not_reconnect) {
    for (u32 count = 1; count <= 2; ++count) {
        RetryRig rig;
        REQUIRE(rig.init(count));
        if (count == 2) rig.owner.config->upstreams[0].weights[1] = 0;
        rig.fail();
        CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 0u);
        CHECK_EQ(rig.conn->upstream_fd, -1);
        CHECK_GT(rig.conn->send_buf.len(), 0u);
    }
}

TEST(h2_failover, rejects_retired_config_cancel_local_error_and_started_request) {
    for (u32 scenario = 0; scenario < 7; ++scenario) {
        RetryRig rig;
        REQUIRE(rig.init());
        switch (scenario) {
            case 0:
                rig.active = nullptr;
                break;
            case 1:
                rig.h2.async_synth_sent = 1;
                break;
            case 2:
                rig.h2.async_proxy_response_seen = true;
                break;
            case 3:
                rig.conn->on_upstream_send = &h2_on_upstream_request_sent<SmallLoop>;
                break;
            case 4:
                rig.h2.async_kind = H2AsyncKind::None;
                break;
            default:
                break;
        }
        rig.fail(scenario == 5 ? -ECANCELED : -ECONNREFUSED,
                 scenario == 6 ? kLocalSubmitFailureAux : 0);
        CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 0u);
        CHECK_EQ(rig.conn->upstream_fd, -1);
    }
}

TEST(h2_failover, submission_failure_releases_new_backend) {
    RetryRig rig;
    REQUIRE(rig.init());
    rig.loop.backend.fail_connect = true;
    rig.fail();
    CHECK_EQ(rig.conn->upstream_fd, -1);
    CHECK_EQ(rig.h2.async_stream, 0u);
    CHECK_EQ(rig.owner.config->backend_selection[0].active[0][1], 0u);
    CHECK_GT(rig.conn->send_buf.len(), 0u);
}

TEST(h2_failover, consistent_hash_keeps_owned_digest_and_excludes_attempted_endpoint) {
    RetryRig rig;
    REQUIRE(rig.init(3));
    auto& spec = rig.h2.async_load_balance;
    spec.policy = LoadBalancePolicy::ConsistentHash;
    spec.hash_status = 1;
    REQUIRE(consistent_hash_digest(
        lit_str("tenant"), 1, lit_str("0123456789abcdef0123456789abcdef"), spec.hash_digest));
    const ForwardLoadBalance kSaved = spec;
    const u32 kExpected =
        select_forward_backend(rig.owner.config, 0, spec, 0, 3, monotonic_us(), 1);
    rig.fail();
    CHECK_EQ(rig.conn->upstream_backend_idx, kExpected);
    CHECK_EQ(memcmp(spec.hash_digest, kSaved.hash_digest, sizeof(spec.hash_digest)), 0);
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 1u);
}

TEST(h2_failover, healthy_capacity_floor_prevents_fail_open_retry) {
    RetryRig rig;
    REQUIRE(rig.init());
    rig.owner.config->upstreams[0].minimum_healthy_weight_percent = 100;
    backend_health(0, 1)->active_down = true;
    rig.fail();
    CHECK_EQ(rig.loop.backend.count_ops(MockOp::Connect), 0u);
    CHECK_EQ(rig.conn->upstream_fd, -1);
    CHECK_GT(rig.conn->send_buf.len(), 0u);
}

TEST(h2_failover, retains_one_admission_slot_until_final_failure) {
    RetryRig rig;
    REQUIRE(rig.init());
    UpstreamConcurrency concurrency{};
    concurrency.reset();
    rig.loop.upstream_cc = &concurrency;
    REQUIRE(concurrency.try_acquire(0, 1));
    rig.conn->upstream_slot_held = true;
    rig.conn->upstream_slot_uid = 0;
    rig.fail();
    CHECK(rig.conn->upstream_slot_held);
    CHECK_EQ(concurrency.inflight[0].load(std::memory_order_relaxed), 1u);
    CHECK_FALSE(concurrency.try_acquire(0, 1));
    rig.fail();
    CHECK_FALSE(rig.conn->upstream_slot_held);
    CHECK_EQ(concurrency.inflight[0].load(std::memory_order_relaxed), 0u);
    rig.loop.upstream_cc = nullptr;
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
