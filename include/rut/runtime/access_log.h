#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include <atomic>
#include <cstddef>
#include <type_traits>

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

// Explicit entries preserve complete checked request targets only through 128 bytes. Longer
// observed strict-H1 targets are represented by an over-limit marker, never by a prefix.
inline constexpr u32 kAccessLogCompleteTargetMax = 128;
inline constexpr u32 kAccessLogLegacyTargetWidth = 64;
inline constexpr u32 kAccessLogObservedStrictH1TargetMax = 16367;
inline constexpr u32 kAccessLogTextLineCapacity = 512;
static_assert(kAccessLogObservedStrictH1TargetMax <= static_cast<u32>(~u16{0}));

enum class AccessLogTargetState : u8 {
    LegacyNullTerminated = 0,
    Complete = 1,
    OverLimit = 2,
    Unavailable = 3,
    Invalid = 4,
};

static_assert(std::is_same_v<std::underlying_type_t<AccessLogTargetState>, u8>);
static_assert(static_cast<u8>(AccessLogTargetState::LegacyNullTerminated) == 0);
static_assert(static_cast<u8>(AccessLogTargetState::Complete) == 1);
static_assert(static_cast<u8>(AccessLogTargetState::OverLimit) == 2);
static_assert(static_cast<u8>(AccessLogTargetState::Unavailable) == 3);
static_assert(static_cast<u8>(AccessLogTargetState::Invalid) == 4);

// Per-request owned copy captured while the checked strict-H1 target still
// refers to the live receive slice.  The episode makes a stale snapshot fail
// closed after keep-alive/pipeline successor capture or Connection reuse.
struct AccessLogTargetSnapshot {
    char path[kAccessLogCompleteTargetMax];
    u32 episode;
    u16 target_length;
    AccessLogTargetState target_state;
    u8 _pad;
};

static_assert(sizeof(AccessLogTargetSnapshot) == 136);
static_assert(alignof(AccessLogTargetSnapshot) == 4);

// Access log entry — fixed-size, written by shard thread on request completion.
// State zero remains available only for legacy/manual callers. Access-enabled production
// completions publish an explicit nonzero target state.
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
    char path[kAccessLogCompleteTargetMax];
    char upstream[24];  // upstream name, null-terminated
    u16 target_length;
    AccessLogTargetState target_state;
    u8 _pad[5];
};

static_assert(offsetof(AccessLogEntry, timestamp_us) == 0);
static_assert(offsetof(AccessLogEntry, duration_us) == 8);
static_assert(offsetof(AccessLogEntry, req_size) == 12);
static_assert(offsetof(AccessLogEntry, resp_size) == 16);
static_assert(offsetof(AccessLogEntry, upstream_us) == 20);
static_assert(offsetof(AccessLogEntry, addr) == 24);
static_assert(offsetof(AccessLogEntry, status) == 28);
static_assert(offsetof(AccessLogEntry, method) == 30);
static_assert(offsetof(AccessLogEntry, shard_id) == 31);
static_assert(offsetof(AccessLogEntry, path) == 32);
static_assert(offsetof(AccessLogEntry, upstream) == 160);
static_assert(offsetof(AccessLogEntry, target_length) == 184);
static_assert(offsetof(AccessLogEntry, target_state) == 186);
static_assert(sizeof(AccessLogEntry) == 192, "AccessLogEntry must be 192 bytes");
static_assert(alignof(AccessLogEntry) == 8, "AccessLogEntry must retain scalar-prefix alignment");

// Microsecond wall-clock timestamp (for access log timestamp field).
// Returns 0 if CLOCK_REALTIME cannot be read.
u64 realtime_us();

// Monotonic microsecond clock (for elapsed duration measurement).
// Immune to NTP adjustments and wall-clock jumps.
// Returns a per-thread nonzero monotonic fallback if CLOCK_MONOTONIC fails; successful reads are
// clamped to never move backward.
u64 monotonic_us();

// Monotonic nanoseconds (CLOCK_MONOTONIC, raw — not clamped). Used for the
// @throttle token bucket's sub-millisecond pacing.
u64 monotonic_ns();

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
    static constexpr u32 kCapacity = 512;
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

static_assert(sizeof(AccessLogRing) == 98432, "AccessLogRing layout must remain explicitly pinned");

// Format an access log entry as a text line into buf.
// Returns bytes written. Format: "ts method path status duration_us req_size resp_size addr
// shard\n". Formatting is transactional: a null or undersized output returns zero without
// modifying caller storage. kAccessLogTextLineCapacity bounds every valid entry line.
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
