// Per-shard metrics tests: counters, histograms, aggregation, callback integration.
#include "rut/runtime/control_plane_snapshot.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/prometheus.h"
#include "test.h"
#include "test_helpers.h"

#include <string.h>

using namespace rut;

namespace {
bool prom_contains(const char* hay, u32 hlen, const char* needle) {
    const u32 nlen = static_cast<u32>(strlen(needle));
    if (nlen > hlen) return false;
    for (u32 i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return true;
    return false;
}
}  // namespace

// === LatencyHistogram: bucket selection ===

TEST(histogram, bucket_0_under_100us) {
    CHECK_EQ(LatencyHistogram::find_bucket(0), 0u);
    CHECK_EQ(LatencyHistogram::find_bucket(50), 0u);
    CHECK_EQ(LatencyHistogram::find_bucket(99), 0u);
}

TEST(histogram, bucket_1_100_to_500us) {
    CHECK_EQ(LatencyHistogram::find_bucket(100), 1u);
    CHECK_EQ(LatencyHistogram::find_bucket(499), 1u);
}

TEST(histogram, bucket_2_500_to_1ms) {
    CHECK_EQ(LatencyHistogram::find_bucket(500), 2u);
    CHECK_EQ(LatencyHistogram::find_bucket(999), 2u);
}

TEST(histogram, bucket_3_1ms_to_5ms) {
    CHECK_EQ(LatencyHistogram::find_bucket(1000), 3u);
    CHECK_EQ(LatencyHistogram::find_bucket(4999), 3u);
}

TEST(histogram, bucket_4_5ms_to_10ms) {
    CHECK_EQ(LatencyHistogram::find_bucket(5000), 4u);
    CHECK_EQ(LatencyHistogram::find_bucket(9999), 4u);
}

TEST(histogram, bucket_5_to_9_high_latency) {
    CHECK_EQ(LatencyHistogram::find_bucket(10000), 5u);
    CHECK_EQ(LatencyHistogram::find_bucket(50000), 6u);
    CHECK_EQ(LatencyHistogram::find_bucket(100000), 7u);
    CHECK_EQ(LatencyHistogram::find_bucket(500000), 8u);
    CHECK_EQ(LatencyHistogram::find_bucket(1000000), 9u);
}

TEST(histogram, bucket_10_overflow) {
    CHECK_EQ(LatencyHistogram::find_bucket(5000000), 10u);
    CHECK_EQ(LatencyHistogram::find_bucket(0xFFFFFFFF), 10u);
}

// === LatencyHistogram: recording ===

TEST(histogram, record_single) {
    LatencyHistogram h;
    h.init();
    h.record(150);  // bucket 1 (100-500μs)
    CHECK_EQ(h.buckets[1], 1u);
    CHECK_EQ(h.sum_us, 150u);
    CHECK_EQ(h.count, 1u);
}

TEST(histogram, record_multiple_buckets) {
    LatencyHistogram h;
    h.init();
    h.record(50);     // bucket 0
    h.record(200);    // bucket 1
    h.record(1500);   // bucket 3
    h.record(50000);  // bucket 6

    CHECK_EQ(h.buckets[0], 1u);
    CHECK_EQ(h.buckets[1], 1u);
    CHECK_EQ(h.buckets[3], 1u);
    CHECK_EQ(h.buckets[6], 1u);
    CHECK_EQ(h.count, 4u);
    CHECK_EQ(h.sum_us, static_cast<u64>(50 + 200 + 1500 + 50000));
}

TEST(histogram, record_same_bucket_accumulates) {
    LatencyHistogram h;
    h.init();
    for (u32 i = 0; i < 100; i++) h.record(50);
    CHECK_EQ(h.buckets[0], 100u);
    CHECK_EQ(h.count, 100u);
    CHECK_EQ(h.sum_us, 5000u);
}

// === ShardMetrics: basic operations ===

TEST(shard_metrics, init_zeros) {
    ShardMetrics m;
    m.init();
    CHECK_EQ(m.requests_total, 0u);
    CHECK_EQ(m.requests_active, 0u);
    CHECK_EQ(m.connections_total, 0u);
    CHECK_EQ(m.connections_active, 0u);
    CHECK_EQ(m.connections_closed, 0u);
}

TEST(shard_metrics, on_accept) {
    ShardMetrics m;
    m.init();
    m.on_accept();
    CHECK_EQ(m.connections_total, 1u);
    CHECK_EQ(m.connections_active, 1u);
    m.on_accept();
    CHECK_EQ(m.connections_total, 2u);
    CHECK_EQ(m.connections_active, 2u);
}

TEST(shard_metrics, on_close) {
    ShardMetrics m;
    m.init();
    m.on_accept();
    m.on_accept();
    m.on_close();
    CHECK_EQ(m.connections_active, 1u);
    CHECK_EQ(m.connections_closed, 1u);
}

TEST(shard_metrics, on_close_floor_at_zero) {
    ShardMetrics m;
    m.init();
    m.on_close();  // should not underflow
    CHECK_EQ(m.connections_active, 0u);
    CHECK_EQ(m.connections_closed, 1u);
}

TEST(shard_metrics, request_lifecycle) {
    ShardMetrics m;
    m.init();
    m.on_request_start();
    CHECK_EQ(m.requests_active, 1u);
    m.on_request_complete(250);
    CHECK_EQ(m.requests_active, 0u);
    CHECK_EQ(m.requests_total, 1u);
    CHECK_EQ(m.request_latency.count, 1u);
    CHECK_EQ(m.request_latency.sum_us, 250u);
    CHECK_EQ(m.request_latency.buckets[1], 1u);  // 250μs → bucket 1 (100-499μs)
}

// === Aggregation ===

TEST(aggregate, two_shards) {
    ShardMetrics s1, s2;
    s1.init();
    s2.init();

    s1.on_accept();
    s1.on_accept();
    s1.on_request_start();
    s1.on_request_complete(100);  // bucket 1

    s2.on_accept();
    s2.on_request_start();
    s2.on_request_complete(2000);  // bucket 3

    ShardMetrics* ptrs[] = {&s1, &s2};
    auto agg = aggregate_metrics(ptrs, 2);

    CHECK_EQ(agg.connections_total, 3u);
    CHECK_EQ(agg.connections_active, 3u);
    CHECK_EQ(agg.requests_total, 2u);
    CHECK_EQ(agg.request_latency.count, 2u);
    CHECK_EQ(agg.request_latency.sum_us, 2100u);
    CHECK_EQ(agg.request_latency.buckets[1], 1u);
    CHECK_EQ(agg.request_latency.buckets[3], 1u);
}

TEST(aggregate, empty) {
    auto agg = aggregate_metrics(nullptr, 0);
    CHECK_EQ(agg.requests_total, 0u);
    CHECK_EQ(agg.connections_total, 0u);
}

TEST(aggregate, handler_snapshot_is_value_only_and_latched) {
    ShardMetrics local;
    ShardMetrics other;
    local.init();
    other.init();
    local.requests_total = 10;
    local.requests_active = 1;
    other.requests_total = 20;
    ShardMetrics* registry[] = {&local, &other};
    struct Loop {
        u32 shard_id = 3;
        ShardMetrics* metrics = nullptr;
        ShardMetrics* const* all_shard_metrics = nullptr;
        u32 shard_metrics_count = 0;
    } loop{3, &local, registry, 2};
    jit::HandlerCtx ctx{};

    latch_control_plane_snapshot(&loop, &ctx);
    REQUIRE(ctx.control_plane.valid);
    CHECK_EQ(ctx.control_plane.shard_id, 3u);
    CHECK_EQ(ctx.control_plane.shard_count, 2u);
    CHECK_EQ(ctx.control_plane.stats.requests_total, 10u);
    CHECK_EQ(ctx.control_plane.metrics.requests_total, 30u);

    local.requests_total = 100;
    other.requests_total = 200;
    CHECK_EQ(ctx.control_plane.stats.requests_total, 10u);
    CHECK_EQ(ctx.control_plane.metrics.requests_total, 30u);
}

// === Callback + proxy integration ===

// Fixture: SmallLoop with ShardMetrics wired. Provides helpers for
// proxy setup at various stages.
struct MetricsLoopF {
    SmallLoop loop;
    ShardMetrics m;
    Connection* c = nullptr;
    u32 cid = 0;

    void SetUp() {
        loop.setup();
        m.init();
        loop.metrics = &m;
    }
    void TearDown() {}

    // Accept fd=42, recv header → connection ready for response or proxy.
    bool accept_and_recv() {
        loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
        c = loop.find_fd(42);
        if (!c) return false;
        cid = c->id;
        loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 100));
        return true;
    }

    // accept_and_recv + wire proxy + upstream connect.
    bool wire_proxy() {
        if (!accept_and_recv()) return false;
        c->upstream_fd = 99;
        c->on_upstream_send = &on_upstream_connected<SmallLoop>;
        return true;
    }

    // wire_proxy + upstream connect success + forward request → ready for upstream response.
    bool advance_to_upstream_response() {
        if (!wire_proxy()) return false;
        loop.inject_and_dispatch(make_ev(cid, IoEventType::UpstreamConnect, 0));
        u32 req_len = c->recv_buf.len();
        loop.inject_and_dispatch(
            make_ev(cid, IoEventType::UpstreamSend, static_cast<i32>(req_len)));
        return true;
    }

    // Complete a direct (non-proxy) request cycle: accept → recv → send.
    bool complete_direct_request() {
        if (!accept_and_recv()) return false;
        u32 send_len = c->send_buf.len();
        loop.inject_and_dispatch(make_ev(cid, IoEventType::Send, static_cast<i32>(send_len)));
        return true;
    }
};

TEST_F(MetricsLoopF, records_on_response) {
    REQUIRE(self.complete_direct_request());
    CHECK_EQ(self.m.requests_total, 1u);
    CHECK_EQ(self.m.request_latency.count, 1u);
    CHECK(self.m.request_latency.sum_us < 1000000u);
}

TEST(callback_metrics, no_crash_without_metrics) {
    SmallLoop loop;
    loop.setup();
    // metrics = nullptr (default)

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* c = loop.find_fd(42);
    REQUIRE(c != nullptr);
    loop.inject_and_dispatch(make_ev(c->id, IoEventType::Recv, 100));
    u32 send_len = c->send_buf.len();
    loop.inject_and_dispatch(make_ev(c->id, IoEventType::Send, static_cast<i32>(send_len)));
    CHECK(true);  // no crash
}

TEST_F(MetricsLoopF, requests_active_decremented_on_send_error) {
    REQUIRE(self.accept_and_recv());
    CHECK_EQ(self.m.requests_active, 1u);
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, -1));
    CHECK_EQ(self.m.requests_active, 0u);
}

TEST_F(MetricsLoopF, requests_active_decremented_after_partial_send_completes) {
    REQUIRE(self.accept_and_recv());
    CHECK_EQ(self.m.requests_active, 1u);
    const u32 send_len = self.c->send_buf.len();
    REQUIRE(send_len > 1u);
    const u32 partial_len = 1u;
    self.loop.inject_and_dispatch(
        make_ev(self.cid, IoEventType::Send, static_cast<i32>(partial_len)));
    CHECK_EQ(self.m.requests_active, 1u);
    self.loop.inject_and_dispatch(
        make_ev(self.cid, IoEventType::Send, static_cast<i32>(send_len - partial_len)));
    CHECK_EQ(self.m.requests_active, 0u);
}

TEST_F(MetricsLoopF, requests_active_unchanged_on_wrong_event) {
    REQUIRE(self.accept_and_recv());
    CHECK_EQ(self.m.requests_active, 1u);
    // UpstreamConnect → on_upstream_send (null) → ignored, conn stays alive.
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    CHECK_EQ(self.m.requests_active, 1u);
}

// === Proxy callback tests ===

TEST_F(MetricsLoopF, upstream_connect_success) {
    REQUIRE(self.wire_proxy());
    u32 sends_before = self.loop.backend.count_ops(MockOp::Send);
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    CHECK_EQ(self.c->state, ConnState::Proxying);
    CHECK(self.loop.backend.count_ops(MockOp::Send) > sends_before);
}

TEST_F(MetricsLoopF, upstream_connect_fail_502) {
    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, -1));
    CHECK_EQ(self.c->resp_status, static_cast<u16>(502));
    CHECK(!self.c->keep_alive);
}

TEST_F(MetricsLoopF, upstream_connect_wrong_event_ignored) {
    REQUIRE(self.wire_proxy());
    // Recv EOF → handle_unhandled_recv → tolerate
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Recv, 0));
    CHECK(self.loop.conns[self.cid].fd >= 0);
}

TEST_F(MetricsLoopF, upstream_request_sent_success) {
    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    u32 recvs_before = self.loop.backend.count_ops(MockOp::Recv);
    u32 req_len = self.c->recv_buf.len();
    self.loop.inject_and_dispatch(
        make_ev(self.cid, IoEventType::UpstreamSend, static_cast<i32>(req_len)));
    CHECK(self.loop.backend.count_ops(MockOp::Recv) > recvs_before);
}

TEST_F(MetricsLoopF, upstream_request_sent_error) {
    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamSend, -1));
    CHECK_EQ(self.loop.conns[self.cid].fd, -1);
}

TEST_F(MetricsLoopF, upstream_request_sent_any_positive_succeeds) {
    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamSend, 1));
    CHECK(self.loop.conns[self.cid].fd >= 0);
}

TEST_F(MetricsLoopF, upstream_request_sent_wrong_event) {
    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, 0));
    // Recv → on_recv (null) → handle_unhandled_recv → tolerate
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Recv, 1));
    CHECK(self.loop.conns[self.cid].fd >= 0);
}

TEST_F(MetricsLoopF, upstream_response_success) {
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    CHECK_EQ(self.c->state, ConnState::Sending);
}

TEST_F(MetricsLoopF, upstream_response_error) {
    REQUIRE(self.advance_to_upstream_response());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamRecv, -1));
    CHECK_EQ(self.loop.conns[self.cid].fd, -1);
}

TEST_F(MetricsLoopF, upstream_response_wrong_event) {
    REQUIRE(self.advance_to_upstream_response());
    // Send → on_send (null) → ignored
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, 1));
    CHECK(self.loop.conns[self.cid].fd >= 0);
}

TEST_F(MetricsLoopF, proxy_response_sent_success) {
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    u32 resp_len = self.c->upstream_recv_buf.len();
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, static_cast<i32>(resp_len)));
    CHECK_EQ(self.m.requests_total, 1u);
    CHECK_EQ(self.c->state, ConnState::ReadingHeader);
}

TEST_F(MetricsLoopF, proxy_response_sent_error) {
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, -1));
    CHECK_EQ(self.loop.conns[self.cid].fd, -1);
}

TEST_F(MetricsLoopF, proxy_response_sent_any_positive_succeeds) {
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, 1));
    CHECK_EQ(self.loop.conns[self.cid].state, ConnState::ReadingHeader);
}

TEST_F(MetricsLoopF, proxy_response_sent_wrong_event) {
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    // Recv → on_recv (null) → handle_unhandled_recv → tolerate
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Recv, 1));
    CHECK(self.loop.conns[self.cid].fd >= 0);
}

TEST_F(MetricsLoopF, proxy_response_sent_draining_closes) {
    self.loop.draining = true;
    REQUIRE(self.advance_to_upstream_response());
    inject_upstream_response(self.loop, *self.c);
    // During drain, on_upstream_response rebuilds response in send_buf with
    // "Connection: close" injected.
    u32 resp_len = self.c->send_buf.len();
    CHECK_GT(resp_len, 0u);
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, static_cast<i32>(resp_len)));
    CHECK_EQ(self.loop.conns[self.cid].fd, -1);
    CHECK_EQ(self.m.requests_total, 1u);
}

TEST_F(MetricsLoopF, 502_response_records_correct_status) {
    AccessLogRing ring;
    ring.init();
    self.loop.access_log = &ring;

    REQUIRE(self.wire_proxy());
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::UpstreamConnect, -1));
    u32 send_len = self.c->send_buf.len();
    self.loop.inject_and_dispatch(make_ev(self.cid, IoEventType::Send, static_cast<i32>(send_len)));

    CHECK_EQ(self.m.requests_total, 1u);
    AccessLogEntry entry{};
    CHECK(ring.pop(entry));
    CHECK_EQ(entry.status, static_cast<u16>(502));
}

// === Prometheus text-format serializer ===

TEST(prometheus, counters_and_histogram) {
    ShardMetrics m;
    m.init();
    m.requests_total = 5;
    m.connections_active = 3;
    m.request_latency.record(50);    // bucket 0 (<100us)
    m.request_latency.record(50);    // bucket 0
    m.request_latency.record(2000);  // bucket 3 (<5ms) — 2000us
    // sum_us = 2100, count = 3

    char buf[4096];
    const u32 n = format_prometheus(m, buf, sizeof(buf));
    REQUIRE(n > 0);
    CHECK(prom_contains(buf, n, "# TYPE rut_requests_total counter\n"));
    CHECK(prom_contains(buf, n, "rut_requests_total 5\n"));
    CHECK(prom_contains(buf, n, "# TYPE rut_connections_active gauge\n"));
    CHECK(prom_contains(buf, n, "rut_connections_active 3\n"));
    CHECK(prom_contains(buf, n, "# TYPE rut_request_duration_seconds histogram\n"));
    // Cumulative buckets: two 50us samples in le=0.0001; the 2000us sample lands
    // by le=0.005, so that bucket holds all 3.
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"0.0001\"} 2\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"0.005\"} 3\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_count 3\n"));
    // 2100us == 0.002100s
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_sum 0.002100\n"));
}

TEST(prometheus, cumulative_buckets_monotonic) {
    ShardMetrics m;
    m.init();
    m.request_latency.record(50);       // le 0.0001
    m.request_latency.record(300);      // le 0.0005
    m.request_latency.record(7000000);  // >= 5s → only the +Inf bucket
    char buf[4096];
    const u32 n = format_prometheus(m, buf, sizeof(buf));
    REQUIRE(n > 0);
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"0.0001\"} 1\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"0.0005\"} 2\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"5\"} 2\n"));
    CHECK(prom_contains(buf, n, "rut_request_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
}

TEST(prometheus, buffer_too_small_returns_zero) {
    ShardMetrics m;
    m.init();
    char buf[16];  // far too small for the full exposition
    CHECK_EQ(format_prometheus(m, buf, sizeof(buf)), 0u);
}

TEST(prometheus, serializes_aggregated_metrics) {
    ShardMetrics a;
    a.init();
    a.requests_total = 10;
    ShardMetrics b;
    b.init();
    b.requests_total = 7;
    ShardMetrics* shards[] = {&a, &b};
    ShardMetrics agg = aggregate_metrics(shards, 2);
    char buf[4096];
    const u32 n = format_prometheus(agg, buf, sizeof(buf));
    REQUIRE(n > 0);
    CHECK(prom_contains(buf, n, "rut_requests_total 17\n"));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
