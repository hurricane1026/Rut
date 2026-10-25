#pragma once

#include "rut/common/types.h"
#include "rut/runtime/rate_limit.h"

namespace rut {

// Latency histogram — log-scale buckets for request/upstream duration.
//
// Buckets: [<100μs, <500μs, <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, <1s, <5s, ≥5s]
// Recording: ~3ns (one clz + one array increment).
//
// Per-shard, no atomics needed (single-writer). Aggregated on read by metrics endpoint.

struct LatencyHistogram {
    static constexpr u32 kBucketCount = 11;

    // Bucket upper bounds in microseconds. Last bucket (index 10) is ≥5s.
    static constexpr u32 kBounds[kBucketCount] = {
        100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, 0xFFFFFFFF};

    u64 buckets[kBucketCount];
    u64 sum_us;  // total duration across all recorded samples
    u64 count;   // total number of samples

    void init() {
        for (u32 i = 0; i < kBucketCount; i++) buckets[i] = 0;
        sum_us = 0;
        count = 0;
    }

    // Record a duration in microseconds. O(1) — uses clz for fast bucket lookup.
    void record(u64 duration_us) {
        u32 bucket = find_bucket(duration_us);
        buckets[bucket]++;
        sum_us += duration_us;
        count++;
    }

    // Find bucket index for a given duration.
    // Uses binary-search-like approach with clz for the common fast path.
    static u32 find_bucket(u64 duration_us) {
        // Fast path: most requests are <10ms (buckets 0-4).
        // Use the bit width to narrow down, then linear check.
        if (duration_us < 100) return 0;
        if (duration_us < 500) return 1;
        if (duration_us < 1000) return 2;
        if (duration_us < 5000) return 3;
        if (duration_us < 10000) return 4;
        if (duration_us < 50000) return 5;
        if (duration_us < 100000) return 6;
        if (duration_us < 500000) return 7;
        if (duration_us < 1000000) return 8;
        if (duration_us < 5000000) return 9;
        return 10;
    }
};

// Per-shard metrics — all counters are u64, written by shard thread only.
// Read by the metrics/Prometheus endpoint (cross-thread, but reads of u64
// on x86-64 are atomic at aligned addresses).

struct ShardMetrics {
    static constexpr u32 kRateLimitReasonCount = 5;
    // --- Request metrics ---
    u64 requests_total;   // completed requests
    u64 requests_active;  // currently processing (inc on recv, dec on response sent)

    // Rate-limit admission is recorded once per request. Reason slots are fixed
    // (budget, shard collision, state overflow, missing global, missing ID) so
    // exposition remains bounded and label cardinality cannot follow user keys.
    u64 rate_limit_attempts_total;
    u64 rate_limit_rejected_total;
    u64 rate_limit_rejected_by_reason[kRateLimitReasonCount];

    // Native gRPC RPC lifecycle, independent of connection-level HTTP accounting.
    u64 grpc_started;
    u64 grpc_active;
    u64 grpc_completed[17];  // canonical grpc-status 0..16
    LatencyHistogram grpc_latency;

    // --- Connection metrics ---
    u64 connections_total;   // total accepted
    u64 connections_active;  // currently open
    u64 connections_closed;  // total closed

    // --- Latency ---
    LatencyHistogram request_latency;

    // --- Memory metrics (snapshot, updated periodically) ---
    u64 memory_arena_used;
    u64 memory_slices_used;
    u64 memory_slices_free;
    u64 memory_connections_used;

    void init() {
        requests_total = 0;
        requests_active = 0;
        rate_limit_attempts_total = 0;
        rate_limit_rejected_total = 0;
        for (auto& count : rate_limit_rejected_by_reason) count = 0;
        grpc_started = grpc_active = 0;
        for (auto& count : grpc_completed) count = 0;
        grpc_latency.init();
        connections_total = 0;
        connections_active = 0;
        connections_closed = 0;
        request_latency.init();
        memory_arena_used = 0;
        memory_slices_used = 0;
        memory_slices_free = 0;
        memory_connections_used = 0;
    }

    // --- Recording helpers (called from shard thread) ---

    void on_accept() {
        connections_total++;
        connections_active++;
    }

    void on_close() {
        if (connections_active > 0) connections_active--;
        connections_closed++;
    }

    void on_grpc_start() {
        grpc_started++;
        grpc_active++;
    }

    void on_grpc_complete(u8 status, u64 duration_us) {
        if (grpc_active > 0) grpc_active--;
        grpc_completed[status <= 16 ? status : 2]++;
        grpc_latency.record(duration_us);
    }

    void on_request_start() { requests_active++; }

    void on_rate_limit(const RateLimitDecision& decision) {
        rate_limit_attempts_total++;
        if (decision.allowed) return;
        rate_limit_rejected_total++;
        u32 reason = 0;
        switch (decision.reject_reason) {
            case RateLimitRejectReason::Budget:
                reason = 0;
                break;
            case RateLimitRejectReason::ShardCollision:
                reason = 1;
                break;
            case RateLimitRejectReason::StateOverflow:
                reason = 2;
                break;
            case RateLimitRejectReason::MissingGlobal:
                reason = 3;
                break;
            case RateLimitRejectReason::MissingSemanticId:
                reason = 4;
                break;
            case RateLimitRejectReason::None:
                reason = 0;
                break;
        }
        rate_limit_rejected_by_reason[reason]++;
    }

    void on_request_complete(u32 duration_us) {
        requests_total++;
        if (requests_active > 0) requests_active--;
        request_latency.record(duration_us);
    }
};

// Aggregate metrics across all shards (for Prometheus endpoint).
// Caller provides array of ShardMetrics pointers and count.
// Result is a single ShardMetrics with summed counters and merged histograms.
inline ShardMetrics aggregate_metrics(ShardMetrics* const* shards, u32 count) {
    ShardMetrics agg;
    agg.init();

    for (u32 i = 0; i < count; i++) {
        const auto& s = *shards[i];
        agg.requests_total += s.requests_total;
        agg.requests_active += s.requests_active;
        agg.rate_limit_attempts_total += s.rate_limit_attempts_total;
        agg.rate_limit_rejected_total += s.rate_limit_rejected_total;
        for (u32 reason = 0; reason < ShardMetrics::kRateLimitReasonCount; reason++)
            agg.rate_limit_rejected_by_reason[reason] += s.rate_limit_rejected_by_reason[reason];
        agg.grpc_started += s.grpc_started;
        agg.grpc_active += s.grpc_active;
        for (u32 code = 0; code < 17; code++) agg.grpc_completed[code] += s.grpc_completed[code];
        for (u32 b = 0; b < LatencyHistogram::kBucketCount; b++)
            agg.grpc_latency.buckets[b] += s.grpc_latency.buckets[b];
        agg.grpc_latency.sum_us += s.grpc_latency.sum_us;
        agg.grpc_latency.count += s.grpc_latency.count;
        agg.connections_total += s.connections_total;
        agg.connections_active += s.connections_active;
        agg.connections_closed += s.connections_closed;
        agg.memory_arena_used += s.memory_arena_used;
        agg.memory_slices_used += s.memory_slices_used;
        agg.memory_slices_free += s.memory_slices_free;
        agg.memory_connections_used += s.memory_connections_used;

        for (u32 b = 0; b < LatencyHistogram::kBucketCount; b++) {
            agg.request_latency.buckets[b] += s.request_latency.buckets[b];
        }
        agg.request_latency.sum_us += s.request_latency.sum_us;
        agg.request_latency.count += s.request_latency.count;
    }
    return agg;
}

}  // namespace rut
