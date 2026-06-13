#pragma once

#include "rut/common/types.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/traffic_capture.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

namespace rut {

// Result of simulating one captured request through a real Shard.
struct SimResult {
    // Identity
    u8 method;          // LogHttpMethod enum from capture
    char path[64];      // from capture entry raw headers
    char upstream[32];  // expected upstream (from capture)

    // Expected (from capture file)
    u16 expected_status;

    // Actual (from simulation)
    u16 actual_status;
    bool status_match;

    // Performance
    u32 latency_us;  // round-trip: send headers → recv response

    // Flags
    bool success;  // false if connection/send/recv failed
};

// Summary of a simulation session.
struct SimSummary {
    u32 total;
    u32 succeeded;
    u32 matched;
    u32 mismatched;
    u32 failed;  // connection/IO errors

    // Latency (microseconds)
    u32 latency_min;
    u32 latency_max;
    u64 latency_sum;

    // Resource snapshot (from ShardMetrics at end)
    u64 connections_total;
    u64 requests_total;

    u32 latency_avg() const {
        return succeeded > 0 ? static_cast<u32>(latency_sum / succeeded) : 0;
    }
};

// Extract method and path from raw HTTP headers for display.
// Writes into result.method and result.path.
inline void sim_extract_request_info(const CaptureEntry& entry, SimResult& result) {
    result.method = entry.method;

    // Copy upstream from capture (ensure null termination)
    constexpr u32 kUpCopy = sizeof(result.upstream) < sizeof(entry.upstream_name)
                                ? sizeof(result.upstream)
                                : sizeof(entry.upstream_name);
    u32 up_len = 0;
    for (u32 i = 0; i < kUpCopy; i++) {
        if (entry.upstream_name[i] == '\0') break;
        result.upstream[i] = entry.upstream_name[i];
        up_len = i + 1;
    }
    if (up_len < sizeof(result.upstream))
        result.upstream[up_len] = '\0';
    else
        result.upstream[sizeof(result.upstream) - 1] = '\0';

    // Extract path from raw headers: skip "METHOD " → read until ' ' or '\r'
    const u8* h = entry.raw_headers;
    u32 len = entry.raw_header_len;
    u32 pos = 0;

    // Skip method
    while (pos < len && h[pos] != ' ') pos++;
    if (pos < len) pos++;  // skip space

    // Read path
    u32 path_start = pos;
    while (pos < len && h[pos] != ' ' && h[pos] != '\r' && h[pos] != '?') pos++;
    u32 path_len = pos - path_start;
    if (path_len >= sizeof(result.path)) path_len = sizeof(result.path) - 1;
    for (u32 i = 0; i < path_len; i++) result.path[i] = static_cast<char>(h[path_start + i]);
    result.path[path_len] = '\0';
}

// Elapsed microseconds between two CLOCK_MONOTONIC timespecs.
inline u32 elapsed_us(const struct timespec& t0, const struct timespec& t1) {
    i64 sec_diff = static_cast<i64>(t1.tv_sec) - static_cast<i64>(t0.tv_sec);
    i64 nsec_diff = static_cast<i64>(t1.tv_nsec) - static_cast<i64>(t0.tv_nsec);
    if (nsec_diff < 0) {
        sec_diff -= 1;
        nsec_diff += 1000000000LL;
    }
    if (sec_diff < 0) return 0;
    u64 total_us = static_cast<u64>(sec_diff) * 1000000ULL + static_cast<u64>(nsec_diff) / 1000ULL;
    return static_cast<u32>(total_us);
}

// Synthetic resume values used when replaying JIT waits in the simulator.
// Keep these aligned with runtime semantics for downstream send waits.
inline i32 sim_synthetic_resume_result(jit::YieldKind kind) {
    switch (kind) {
        case jit::YieldKind::Timer:
        case jit::YieldKind::UpstreamConnect:
            return 0;
        case jit::YieldKind::Recv:
        case jit::YieldKind::UpstreamRecv:
        case jit::YieldKind::UpstreamSend:
        case jit::YieldKind::HttpGet:
        case jit::YieldKind::HttpPost:
        case jit::YieldKind::Forward:
        case jit::YieldKind::Any:
            return 1;
        case jit::YieldKind::Send:
            return 0;
    }
    return 1;
}

// Simulate one captured request via loopback TCP.
// server_port: port where the real Shard is listening.
// Returns SimResult with status comparison + latency.
inline SimResult sim_one(u16 server_port, const CaptureEntry& entry) {
    SimResult result{};
    result.expected_status = entry.resp_status;
    result.success = false;
    sim_extract_request_info(entry, result);

    // Connect to server
    i32 fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return result;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = __builtin_bswap16(server_port);
    addr.sin_addr.s_addr = __builtin_bswap32(0x7F000001);

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return result;
    }

    // Measure latency: start
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    // Send raw headers (retry on EINTR)
    const u8* p = entry.raw_headers;
    u32 remaining = entry.raw_header_len;
    while (remaining > 0) {
        ssize_t n = send(fd, p, remaining, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return result;
        }
        if (n == 0) {
            close(fd);
            return result;
        }
        p += n;
        remaining -= static_cast<u32>(n);
    }

    // Recv response (retry on EINTR)
    char resp[4096];
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t resp_len;
    do {
        resp_len = recv(fd, resp, sizeof(resp), 0);
    } while (resp_len < 0 && errno == EINTR);

    // Measure latency: end
    clock_gettime(CLOCK_MONOTONIC, &t1);
    result.latency_us = elapsed_us(t0, t1);

    close(fd);

    if (resp_len < 12) return result;  // too short for "HTTP/1.1 NNN"

    // Parse status code from "HTTP/1.1 NNN ..."
    if (resp[0] != 'H' || resp[8] != ' ') return result;
    // Validate digits
    if (resp[9] < '0' || resp[9] > '9' || resp[10] < '0' || resp[10] > '9' || resp[11] < '0' ||
        resp[11] > '9')
        return result;
    u16 code = static_cast<u16>((resp[9] - '0') * 100 + (resp[10] - '0') * 10 + (resp[11] - '0'));

    result.actual_status = code;
    result.status_match = (code == entry.resp_status);
    result.success = true;
    return result;
}

// Format one SimResult as a text line.
// Format: "MATCH  GET  /path          200 → 200  0.12ms"
//    or:  "MISS   POST /api/users     200 → 404  0.15ms  upstream: api-v1"
inline u32 sim_format_result(const SimResult& r, char* buf, u32 buf_size) {
    u32 pos = 0;
    auto put = [&](const char* s) {
        while (*s && pos < buf_size - 1) buf[pos++] = *s++;
    };
    auto put_u16 = [&](u16 v) {
        char tmp[6];
        u32 n = 0;
        if (v == 0) {
            tmp[n++] = '0';
        } else {
            u16 d = 10000;
            bool started = false;
            while (d > 0) {
                char c = static_cast<char>('0' + (v / d) % 10);
                if (c != '0' || started) {
                    tmp[n++] = c;
                    started = true;
                }
                d /= 10;
            }
        }
        for (u32 i = 0; i < n && pos < buf_size - 1; i++) buf[pos++] = tmp[i];
    };
    auto put_u32 = [&](u32 v) {
        char tmp[11];
        u32 n = 0;
        if (v == 0) {
            tmp[n++] = '0';
        } else {
            u32 d = 1000000000;
            bool started = false;
            while (d > 0) {
                char c = static_cast<char>('0' + (v / d) % 10);
                if (c != '0' || started) {
                    tmp[n++] = c;
                    started = true;
                }
                d /= 10;
            }
        }
        for (u32 i = 0; i < n && pos < buf_size - 1; i++) buf[pos++] = tmp[i];
    };

    // Verdict
    if (!r.success)
        put("FAIL   ");
    else if (r.status_match)
        put("MATCH  ");
    else
        put("MISS   ");

    // Method
    static const char* kMethods[] = {"GET    ",
                                     "POST   ",
                                     "PUT    ",
                                     "DELETE ",
                                     "PATCH  ",
                                     "HEAD   ",
                                     "OPTIONS",
                                     "CONNECT",
                                     "TRACE  ",
                                     "OTHER  "};
    u8 m = r.method < 10 ? r.method : 9;
    put(kMethods[m]);
    put(" ");

    // Path (padded to 20 chars for alignment)
    put(r.path);
    u32 plen = 0;
    while (r.path[plen]) plen++;
    for (u32 i = plen; i < 20 && pos < buf_size - 1; i++) buf[pos++] = ' ';

    // Status: expected → actual
    put_u16(r.expected_status);
    put(" -> ");
    put_u16(r.actual_status);

    // Latency
    put("  ");
    put_u32(r.latency_us);
    put("us");

    // Upstream (if set)
    if (r.upstream[0]) {
        put("  upstream: ");
        put(r.upstream);
    }

    buf[pos++] = '\n';
    if (pos < buf_size) buf[pos] = '\0';
    return pos;
}

// Format a SimSummary as a text block.
inline u32 sim_format_summary(const SimSummary& s, char* buf, u32 buf_size) {
    u32 pos = 0;
    auto put = [&](const char* str) {
        while (*str && pos < buf_size - 1) buf[pos++] = *str++;
    };
    auto put_u32 = [&](u32 v) {
        char tmp[11];
        u32 n = 0;
        if (v == 0) {
            tmp[n++] = '0';
        } else {
            u32 d = 1000000000;
            bool started = false;
            while (d > 0) {
                char c = static_cast<char>('0' + (v / d) % 10);
                if (c != '0' || started) {
                    tmp[n++] = c;
                    started = true;
                }
                d /= 10;
            }
        }
        for (u32 i = 0; i < n && pos < buf_size - 1; i++) buf[pos++] = tmp[i];
    };
    auto put_u64 = [&](u64 v) {
        char tmp[21];
        u32 n = 0;
        if (v == 0) {
            tmp[n++] = '0';
        } else {
            u64 d = 10000000000000000000ULL;
            bool started = false;
            while (d > 0) {
                char c = static_cast<char>('0' + (v / d) % 10);
                if (c != '0' || started) {
                    tmp[n++] = c;
                    started = true;
                }
                d /= 10;
            }
        }
        for (u32 i = 0; i < n && pos < buf_size - 1; i++) buf[pos++] = tmp[i];
    };

    put("--- Simulation Summary ---\n");
    put("Total:      ");
    put_u32(s.total);
    put("\n");
    put("Succeeded:  ");
    put_u32(s.succeeded);
    put("\n");
    put("Matched:    ");
    put_u32(s.matched);
    put("\n");
    put("Mismatched: ");
    put_u32(s.mismatched);
    put("\n");
    put("Failed:     ");
    put_u32(s.failed);
    put("\n");
    put("Latency avg: ");
    put_u32(s.latency_avg());
    put("us\n");
    put("Latency min: ");
    put_u32(s.latency_min);
    put("us\n");
    put("Latency max: ");
    put_u32(s.latency_max);
    put("us\n");
    put("Connections: ");
    put_u64(s.connections_total);
    put("\n");
    put("Requests:   ");
    put_u64(s.requests_total);
    put("\n");

    if (pos < buf_size) buf[pos] = '\0';
    return pos;
}

}  // namespace rut
