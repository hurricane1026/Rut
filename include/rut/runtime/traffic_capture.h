#pragma once

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"  // realtime_us()
#include <atomic>

namespace rut {

// Traffic capture entry — fixed-size, written by shard thread on request completion.
//
// Captures raw request headers (up to 8KB) plus response metadata for traffic
// replay testing. Body content is NOT captured — JIT routing decisions depend
// only on request headers, method, and path.
//
// Layout: 64 bytes metadata + 8192 bytes raw headers = 8256 bytes per entry.

struct CaptureEntry {
    static constexpr u32 kMaxHeaderLen = 8192;

    // --- Metadata (64 bytes) ---
    u64 timestamp_us;         // 8  — realtime_us() at capture
    u32 req_content_length;   // 4  — request body size (not captured)
    u32 resp_content_length;  // 4  — response body size
    u16 resp_status;          // 2  — HTTP response status code
    u16 raw_header_len;       // 2  — actual bytes in raw_headers[]
    u8 method;                // 1  — LogHttpMethod enum
    u8 shard_id;              // 1  — which shard captured this
    u8 flags;                 // 1  — reserved (truncated, etc.)
    u8 _pad;                  // 1  — alignment
    char upstream_name[32];    // 32 — upstream target name (null-terminated)
    u16 peer_port;            // 2  — peer source port (host order)
    u8 _reserved[6];          // 6  — future use
    // Total metadata: 64 bytes

    // --- Raw request headers (method line + headers + \r\n\r\n) ---
    u8 raw_headers[kMaxHeaderLen];
};

static_assert(sizeof(CaptureEntry) == 8256, "CaptureEntry must be 8256 bytes");

// Flags for CaptureEntry::flags
static constexpr u8 kCaptureFlagTruncated = 0x01;  // headers exceeded 8KB, truncated

// Binary file header for capture files.
// Written once at the start of the file, entry_count updated on close.
struct CaptureFileHeader {
    char magic[8];     // "RUTCAP01"
    u32 version;       // 1
    u32 flags;         // reserved
    u64 entry_count;   // total entries written (updated on close)
    u32 entry_size;    // sizeof(CaptureEntry), for forward compat
    u8 _reserved[36];  // pad to 64 bytes
};

static_assert(sizeof(CaptureFileHeader) == 64, "CaptureFileHeader must be 64 bytes");

void capture_file_header_init(CaptureFileHeader* hdr);
bool capture_file_header_valid(const CaptureFileHeader* hdr);

// SPSC ring buffer for traffic capture entries.
//
// Same lock-free pattern as AccessLogRing: producer (shard thread) writes,
// consumer (background flusher) reads. Overflow drops newest entry.
//
// 256 entries × 8256 bytes = ~2MB — modest for mmap.
// Power-of-2 capacity for fast modulo.

struct CaptureRing {
    static constexpr u32 kCapacity = 256;
    static constexpr u32 kMask = kCapacity - 1;

    alignas(64) std::atomic<u32> write_pos;
    alignas(64) std::atomic<u32> read_pos;
    CaptureEntry entries[kCapacity];

    void init() {
        write_pos = 0;
        read_pos = 0;
    }

    // Producer: write an entry. Returns false if full (entry dropped).
    bool push(const CaptureEntry& entry) {
        u32 wp = write_pos.load(std::memory_order_relaxed);
        u32 rp = read_pos.load(std::memory_order_acquire);

        if (wp - rp >= kCapacity) {
            return false;  // full — drop
        }

        entries[wp & kMask] = entry;
        write_pos.store(wp + 1, std::memory_order_release);
        return true;
    }

    // Consumer: read one entry. Returns false if empty.
    bool pop(CaptureEntry& out) {
        u32 rp = read_pos.load(std::memory_order_relaxed);
        u32 wp = write_pos.load(std::memory_order_acquire);

        if (rp == wp) return false;

        out = entries[rp & kMask];
        read_pos.store(rp + 1, std::memory_order_release);
        return true;
    }

    u32 available() const {
        u32 wp = write_pos.load(std::memory_order_acquire);
        u32 rp = read_pos.load(std::memory_order_relaxed);
        return wp - rp;
    }
};

// Write one captured entry to a file descriptor opened in append mode.
// Returns 0 on success, -1 on write error. The caller updates header
// entry_count separately.
//
// Usage pattern (background flusher):
//   CaptureEntry entry;
//   while (ring->pop(entry)) {
//       capture_write_entry(fd, entry);
//       count++;
//   }
i32 capture_write_entry(i32 fd, const CaptureEntry& entry);

// Read one capture entry from fd at current position.
// Returns 0 on success, -1 on error/EOF.
i32 capture_read_entry(i32 fd, CaptureEntry& entry);

}  // namespace rut
