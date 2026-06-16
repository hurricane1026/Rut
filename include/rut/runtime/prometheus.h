#pragma once

#include "rut/common/types.h"
#include "rut/runtime/metrics.h"

// Prometheus text-format (v0.0.4) serializer for aggregated ShardMetrics.
// Pure and allocation-free: the caller provides the output buffer. No stdlib —
// integers and the histogram sum are formatted by hand. Returns the number of
// bytes written, or 0 if the output would not fit in `cap` (nothing partial is
// relied upon by callers; they treat 0 as "buffer too small").
namespace rut {

namespace prom_detail {

// Append helper that tracks overflow. Once the buffer is exceeded it stops
// writing but keeps the `ok` flag false so the caller can reject the result.
struct Writer {
    char* buf;
    u32 cap;
    u32 len = 0;
    bool ok = true;

    void ch(char c) {
        if (len < cap)
            buf[len] = c;
        else
            ok = false;
        len++;
    }
    void str(const char* s) {
        while (*s != '\0') ch(*s++);
    }
    void u64v(u64 v) {
        char tmp[20];
        u32 n = 0;
        if (v == 0) {
            ch('0');
            return;
        }
        while (v > 0) {
            tmp[n++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (n > 0) ch(tmp[--n]);
    }
    // Append microseconds as a fixed-point seconds value: <int>.<6-digit frac>.
    void seconds_from_us(u64 us) {
        u64v(us / 1'000'000ull);
        ch('.');
        u32 frac = static_cast<u32>(us % 1'000'000ull);
        // Zero-pad to 6 digits.
        char d[6];
        for (i32 i = 5; i >= 0; i--) {
            d[i] = static_cast<char>('0' + frac % 10);
            frac /= 10;
        }
        for (u32 i = 0; i < 6; i++) ch(d[i]);
    }
};

// Emit one "# HELP/# TYPE/name value" counter or gauge block.
inline void emit_scalar(
    Writer& w, const char* name, const char* help, const char* type, u64 value) {
    w.str("# HELP ");
    w.str(name);
    w.ch(' ');
    w.str(help);
    w.ch('\n');
    w.str("# TYPE ");
    w.str(name);
    w.ch(' ');
    w.str(type);
    w.ch('\n');
    w.str(name);
    w.ch(' ');
    w.u64v(value);
    w.ch('\n');
}

}  // namespace prom_detail

// Cumulative `le` upper bounds (seconds) for LatencyHistogram::kBounds, plus the
// implicit +Inf. Indices align with kBounds[0..kBucketCount-1]; the last bound
// (≥5s) maps to +Inf.
inline const char* const kPromLatencyLe[LatencyHistogram::kBucketCount] = {
    "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "+Inf"};

inline u32 format_prometheus(const ShardMetrics& m, char* buf, u32 cap) {
    prom_detail::Writer w{buf, cap};
    using prom_detail::emit_scalar;

    emit_scalar(w, "rut_requests_total", "Total completed requests.", "counter", m.requests_total);
    emit_scalar(w,
                "rut_requests_active",
                "Requests currently being processed.",
                "gauge",
                m.requests_active);
    emit_scalar(
        w, "rut_connections_total", "Total accepted connections.", "counter", m.connections_total);
    emit_scalar(
        w, "rut_connections_active", "Currently open connections.", "gauge", m.connections_active);
    emit_scalar(
        w, "rut_connections_closed", "Total closed connections.", "counter", m.connections_closed);

    // Request latency histogram (cumulative buckets, then _sum/_count).
    w.str("# HELP rut_request_duration_seconds Request duration in seconds.\n");
    w.str("# TYPE rut_request_duration_seconds histogram\n");
    u64 cumulative = 0;
    for (u32 i = 0; i < LatencyHistogram::kBucketCount; i++) {
        cumulative += m.request_latency.buckets[i];
        w.str("rut_request_duration_seconds_bucket{le=\"");
        w.str(kPromLatencyLe[i]);
        w.str("\"} ");
        w.u64v(cumulative);
        w.ch('\n');
    }
    w.str("rut_request_duration_seconds_sum ");
    w.seconds_from_us(m.request_latency.sum_us);
    w.ch('\n');
    w.str("rut_request_duration_seconds_count ");
    w.u64v(m.request_latency.count);
    w.ch('\n');

    emit_scalar(
        w, "rut_memory_arena_used_bytes", "Arena bytes in use.", "gauge", m.memory_arena_used);
    emit_scalar(w,
                "rut_memory_slices_used",
                "Network buffer slices in use.",
                "gauge",
                m.memory_slices_used);
    emit_scalar(
        w, "rut_memory_slices_free", "Free network buffer slices.", "gauge", m.memory_slices_free);
    emit_scalar(w,
                "rut_memory_connections_used",
                "Connection slots in use.",
                "gauge",
                m.memory_connections_used);

    return w.ok ? w.len : 0;
}

}  // namespace rut
