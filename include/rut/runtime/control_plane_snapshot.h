#pragma once

#include "rut/jit/handler_abi.h"
#include "rut/runtime/metrics.h"

namespace rut {

inline jit::ControlPlaneMetricValues copy_control_plane_metrics(const ShardMetrics& source) {
    jit::ControlPlaneMetricValues out{};
    source.lock_snapshot();
    out.requests_total = source.requests_total;
    out.requests_active = source.requests_active;
    out.connections_total = source.connections_total;
    out.connections_active = source.connections_active;
    out.connections_closed = source.connections_closed;
    static_assert(LatencyHistogram::kBucketCount == jit::kControlPlaneLatencyBucketCount);
    for (u32 i = 0; i < LatencyHistogram::kBucketCount; i++)
        out.request_latency_buckets[i] = source.request_latency.buckets[i];
    out.request_latency_sum_us = source.request_latency.sum_us;
    out.request_latency_count = source.request_latency.count;
    out.memory_arena_used = source.memory_arena_used;
    out.memory_slices_used = source.memory_slices_used;
    out.memory_slices_free = source.memory_slices_free;
    out.memory_connections_used = source.memory_connections_used;
    source.unlock_snapshot();
    return out;
}

template <typename Loop>
inline void refresh_control_plane_memory_metrics(Loop* loop) {
    if (loop == nullptr || loop->metrics == nullptr) return;
    u64 arena_used = 0;
    u64 slices_used = 0;
    u64 slices_free = 0;
    u64 connections_used = 0;
    if constexpr (requires { loop->metrics_arena; }) {
        if (loop->metrics_arena != nullptr) arena_used = loop->metrics_arena->space_used();
    }
    if constexpr (requires {
                      loop->pool.in_use();
                      loop->pool.available();
                  }) {
        slices_used = loop->pool.in_use();
        slices_free = loop->pool.available();
    }
    if constexpr (requires { loop->active_count(); }) connections_used = loop->active_count();
    loop->metrics->update_memory(arena_used, slices_used, slices_free, connections_used);
}

// Latch the only control-plane data visible to one handler invocation. The
// requires-expressions preserve compatibility with small test loops while
// production loops provide both a local metric set and the aggregate registry.
template <typename Loop>
inline void latch_control_plane_snapshot(Loop* loop, jit::HandlerCtx* ctx) {
    if (loop == nullptr || ctx == nullptr) return;
    auto& snapshot = ctx->control_plane;
    snapshot = {};
    if constexpr (requires { loop->metrics; }) {
        if (loop->metrics == nullptr) return;
        refresh_control_plane_memory_metrics(loop);
        snapshot.stats = copy_control_plane_metrics(*loop->metrics);
        snapshot.metrics = snapshot.stats;
        snapshot.shard_count = 1;
        if constexpr (requires { loop->shard_id; }) snapshot.shard_id = loop->shard_id;
        if constexpr (requires {
                          loop->all_shard_metrics;
                          loop->shard_metrics_count;
                      }) {
            if (loop->all_shard_metrics != nullptr && loop->shard_metrics_count != 0) {
                snapshot.metrics = copy_control_plane_metrics(
                    aggregate_metrics(loop->all_shard_metrics, loop->shard_metrics_count));
                snapshot.shard_count = loop->shard_metrics_count;
            }
        }
        snapshot.valid = true;
    }
}

}  // namespace rut
