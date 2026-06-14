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

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include <atomic>

#include <pthread.h>
#include <time.h>
#include <unistd.h>

namespace rut {

// HTTP methods (compact enum for log entries).
enum class LogHttpMethod : u8 {
    Get = 0,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Other,
};

// Access log entry — fixed-size, written by shard thread on request completion.
// 128 bytes: fits two per cache line pair, ~64KB for 512 entries.
struct AccessLogEntry {
    u64 timestamp_us;  // microseconds since epoch (clock_realtime)
    u32 duration_us;   // request processing time
    u32 req_size;      // request size (full message until parser available)
    u32 resp_size;     // response size (full message until parser available)
    u32 upstream_us;   // upstream latency (0 if no proxy)
    u32 addr;          // client IPv4 (network byte order)
    u16 status;        // HTTP status code
    u8 method;         // LogHttpMethod enum
    u8 shard_id;
    char path[64];      // truncated if longer, null-terminated
    char upstream[24];  // upstream name, null-terminated
    u8 _pad[8];         // pad to 128 bytes
};

static_assert(sizeof(AccessLogEntry) == 128, "AccessLogEntry must be 128 bytes");

// Microsecond wall-clock timestamp (for access log timestamp field).
// Returns 0 if CLOCK_REALTIME cannot be read.
u64 realtime_us();

// Monotonic microsecond clock (for elapsed duration measurement).
// Immune to NTP adjustments and wall-clock jumps.
// Returns a per-thread nonzero monotonic fallback if CLOCK_MONOTONIC fails; successful reads are
// clamped to never move backward.
u64 monotonic_us();

// SPSC (single-producer, single-consumer) ring buffer for access log entries.
//
// Producer: shard thread (writes on request completion)
// Consumer: background flusher thread (reads + writes raw binary to fd)
//
// Lock-free via acquire/release atomics on positions.
// Overflow policy: drop newest (push returns false when full).
// Flusher catches up and future entries succeed.
//
// Capacity must be power of 2 for fast modulo.

struct AccessLogRing {
    static constexpr u32 kCapacity = 512;  // 512 * 128 = 64KB
    static constexpr u32 kMask = kCapacity - 1;

    // Cache-line aligned to prevent false sharing between producer and consumer.
    alignas(64) std::atomic<u32> write_pos;  // written by shard thread only
    alignas(64) std::atomic<u32> read_pos;   // written by flusher thread only
    AccessLogEntry entries[kCapacity];

    void init();

    // Producer: write an entry. Returns false if full (entry dropped).
    // Called from shard thread only — no contention on write_pos.
    //
    // The producer never touches read_pos. When the ring is full, the entry
    // is silently dropped. This avoids a race where the producer advances
    // read_pos while the consumer is mid-read of the slot being overwritten.
    // Dropping newest under backpressure is acceptable for access logs —
    // the flusher will catch up and future entries will succeed.
    bool push(const AccessLogEntry& entry);

    // Consumer: read one entry. Returns false if empty.
    // Called from flusher thread only — no contention on read_pos.
    bool pop(AccessLogEntry& out);

    // Number of entries available to read.
    u32 available() const;
};

// Format an access log entry as a text line into buf.
// Returns bytes written. Format: "ts method path status duration_us req_size resp_size addr
// shard\n" Caller provides buf of at least 512 bytes.
u32 format_access_log_text(const AccessLogEntry& entry, char* buf, u32 buf_size);

// Background flusher — reads from all shard rings, writes text entries to fd.
// Optionally compresses output with zstd streaming compression.
//
// Modes:
//   compress=false: writes plain text lines (greppable, ~350 bytes/entry)
//   compress=true:  writes zstd-compressed text (~25-35 bytes/entry)
//
// Enable via: --access-log-compress flag or RUE_ACCESS_LOG_COMPRESS=1 env var.
//
// Lifecycle: init() → start() → [running] → stop()
// The flusher thread wakes every flush_interval_ms to drain all rings.

struct AccessLogFlusher {
    static constexpr u32 kMaxRings = 64;

    AccessLogRing* rings[kMaxRings];
    u32 ring_count;
    i32 output_fd;          // fd to write to
    u32 flush_interval_ms;  // how often to flush (default 100ms)
    bool compress;          // zstd compression enabled
    i32 compress_level;     // zstd level: 1-4 (fast/doubleFast only)

    pthread_t thread;
    std::atomic<bool> running;  // cross-thread: accessed via std::atomic

    // Opaque zstd state (ZSTD_CStream*), managed in access_log.cc.
    void* zstd_ctx;

    // Max supported level — higher levels require strategies we excluded at build time.
    static constexpr i32 kMinLevel = 1;
    static constexpr i32 kMaxLevel = 4;
    static constexpr i32 kDefaultLevel = 3;

    void init(i32 fd,
              bool compress_enabled = false,
              i32 level = kDefaultLevel,
              u32 interval_ms = 100);

    void add_ring(AccessLogRing* ring);

    core::Expected<void, Error> start();
    void stop();

    // Flush all rings once. Returns total entries flushed.
    u32 flush_once();

    // Write a batch of formatted text, optionally compressing with zstd.
    bool flush_batch(const u8* data, u32 len);

private:
    static void* thread_entry(void* arg);
};

}  // namespace rut
