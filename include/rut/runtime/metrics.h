#pragma once

#include "rut/common/types.h"
#include <atomic>

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
    void record(u32 duration_us) {
        u32 bucket = find_bucket(duration_us);
        buckets[bucket]++;
        sum_us += duration_us;
        count++;
    }

    // Find bucket index for a given duration.
    // Uses binary-search-like approach with clz for the common fast path.
    static u32 find_bucket(u32 duration_us) {
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

// Per-shard metrics. Writers run on the owning shard thread; cross-shard
// readers take the small lock so every snapshot is race-free and internally
// consistent (including the latency histogram).

struct ShardMetrics {
    mutable std::atomic_flag snapshot_lock = ATOMIC_FLAG_INIT;

    // --- Request metrics ---
    u64 requests_total;   // completed requests
    u64 requests_active;  // currently processing (inc on recv, dec on response sent)

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
        connections_total = 0;
        connections_active = 0;
        connections_closed = 0;
        request_latency.init();
        memory_arena_used = 0;
        memory_slices_used = 0;
        memory_slices_free = 0;
        memory_connections_used = 0;
    }

    ShardMetrics() = default;

    ShardMetrics(const ShardMetrics& other) { copy_from(other); }

    ShardMetrics& operator=(const ShardMetrics& other) {
        if (this != &other) copy_from(other);
        return *this;
    }

    void lock_snapshot() const {
        while (snapshot_lock.test_and_set(std::memory_order_acquire)) {
        }
    }

    void unlock_snapshot() const { snapshot_lock.clear(std::memory_order_release); }

    // --- Recording helpers (called from shard thread) ---

    void on_accept() {
        lock_snapshot();
        connections_total++;
        connections_active++;
        unlock_snapshot();
    }

    void on_close() {
        lock_snapshot();
        if (connections_active > 0) connections_active--;
        connections_closed++;
        unlock_snapshot();
    }

    void on_request_start() {
        lock_snapshot();
        requests_active++;
        unlock_snapshot();
    }

    void on_request_complete(u32 duration_us) {
        lock_snapshot();
        requests_total++;
        if (requests_active > 0) requests_active--;
        request_latency.record(duration_us);
        unlock_snapshot();
    }

    void on_request_cancel() {
        lock_snapshot();
        if (requests_active > 0) requests_active--;
        unlock_snapshot();
    }

    void update_memory(u64 arena_used, u64 slices_used, u64 slices_free, u64 connections_used) {
        lock_snapshot();
        memory_arena_used = arena_used;
        memory_slices_used = slices_used;
        memory_slices_free = slices_free;
        memory_connections_used = connections_used;
        unlock_snapshot();
    }

private:
    void copy_from(const ShardMetrics& other) {
        other.lock_snapshot();
        requests_total = other.requests_total;
        requests_active = other.requests_active;
        connections_total = other.connections_total;
        connections_active = other.connections_active;
        connections_closed = other.connections_closed;
        request_latency = other.request_latency;
        memory_arena_used = other.memory_arena_used;
        memory_slices_used = other.memory_slices_used;
        memory_slices_free = other.memory_slices_free;
        memory_connections_used = other.memory_connections_used;
        other.unlock_snapshot();
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
        s.lock_snapshot();
        agg.requests_total += s.requests_total;
        agg.requests_active += s.requests_active;
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
        s.unlock_snapshot();
    }
    return agg;
}

}  // namespace rut
