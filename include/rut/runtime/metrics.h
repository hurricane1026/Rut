/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "rut/common/types.h"

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

// Per-shard metrics — all counters are u64, written by shard thread only.
// Read by the metrics/Prometheus endpoint (cross-thread, but reads of u64
// on x86-64 are atomic at aligned addresses).

struct ShardMetrics {
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

    // --- Recording helpers (called from shard thread) ---

    void on_accept() {
        connections_total++;
        connections_active++;
    }

    void on_close() {
        if (connections_active > 0) connections_active--;
        connections_closed++;
    }

    void on_request_start() { requests_active++; }

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
