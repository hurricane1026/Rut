#pragma once

#include "rut/common/types.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/io_event.h"
#include "rut/runtime/traffic_capture.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

namespace rut {

// Result of replaying one captured request against a live event loop.
struct ReplayResult {
    u16 expected_status;  // from capture file
    u16 actual_status;    // from replay
    bool status_match;    // expected == actual
    bool replayed;        // true if a static response was replayed; false
                          // means either skipped or replay/injection failed
    bool skipped;         // meaningful when replayed == false: true if
                          // intentionally unsupported, false if failed
};

// Summary of a full replay session.
struct ReplaySummary {
    u32 total;       // entries in capture file
    u32 replayed;    // successfully injected
    u32 matched;     // status matched
    u32 mismatched;  // status didn't match
    u32 skipped;     // intentionally unsupported entries
    u32 failed;      // injection failures
};

// Read a capture file sequentially. Manages fd and header validation.
//
// Usage:
//   ReplayReader reader;
//   if (reader.open("/path/to/capture.bin") < 0) { error }
//   CaptureEntry entry;
//   while (reader.next(entry) == 0) { ... }
//   reader.close();
struct ReplayReader {
    i32 fd = -1;
    CaptureFileHeader header{};
    u64 entries_read = 0;
    u32 capture_file_version = 1;

    // Open a capture file. Returns 0 on success, -1 on error.
    // Closes any previously open fd to prevent leaks on re-open.
    i32 open(const char* path) {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
        fd = ::open(path, O_RDONLY);
        if (fd < 0) return -1;

        u8* p = reinterpret_cast<u8*>(&header);
        u32 remaining = sizeof(header);
        while (remaining > 0) {
            ssize_t n = ::read(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR) continue;
                ::close(fd);
                fd = -1;
                return -1;
            }
            if (n == 0) {
                ::close(fd);
                fd = -1;
                return -1;
            }
            p += n;
            remaining -= static_cast<u32>(n);
        }

        if (!capture_file_header_valid(&header)) {
            ::close(fd);
            fd = -1;
            return -1;
        }
        capture_file_version = header.version;
        entries_read = 0;
        return 0;
    }

    // Read the next entry. Returns 0 on success, -1 on EOF/error/past entry_count.
    i32 next(CaptureEntry& entry) {
        if (fd < 0) return -1;
        if (entries_read >= header.entry_count) return -1;
        i32 rc = capture_read_entry(fd, entry);
        if (rc == 0) {
            if (capture_file_version == 1) entry.peer_port = 0;
            entries_read++;
        }
        return rc;
    }

    // Total entries declared in the file header.
    u64 entry_count() const { return header.entry_count; }

    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

// Replay one captured entry through a mock/injectable event loop.
//
// Designed for SmallLoop and other test loops that expose:
//   - loop.backend.inject(ev): inject synthetic I/O events
//   - loop.backend.wait(events, max): drain pending events
//   - loop.conns[]: indexable connection array with fd, recv_buf, resp_status
//   - loop.dispatch(ev): route events to callback slots
//
// NOT suitable for production event loops (EpollEventLoop, IoUringEventLoop)
// which drive I/O from real kernel events. Use sim_one() for production-path
// replay via loopback TCP.
//
// Steps:
//   1. Inject Accept → allocate connection
//   2. Write raw_headers into recv_buf
//   3. Dispatch Recv → triggers on_header_received → route decision → response
//   4. Dispatch Send → triggers on_request_complete (skipped for proxy routes)
//   5. Read resp_status from connection
//   6. Close connection (inject EOF)
//
// Returns ReplayResult with comparison.
template <typename Loop>
ReplayResult replay_one(Loop& loop, const CaptureEntry& entry, i32 fake_fd) {
    ReplayResult result{};
    result.expected_status = entry.resp_status;
    result.replayed = false;

    // Step 1: Accept
    IoEvent accept_ev = {0, fake_fd, 0, 0, IoEventType::Accept, 0};
    loop.backend.inject(accept_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    Connection* conn = nullptr;
    for (u32 i = 0; i < Loop::kMaxConns; i++) {
        if (loop.conns[i].fd == fake_fd) {
            conn = &loop.conns[i];
            break;
        }
    }
    if (!conn) return result;

    conn->peer_port = entry.peer_port;

    // Step 2: Write raw headers into recv_buf
    conn->recv_buf.reset();
    u32 hdr_len = entry.raw_header_len;
    if (hdr_len > conn->recv_buf.write_avail()) hdr_len = conn->recv_buf.write_avail();
    conn->recv_buf.write(entry.raw_headers, hdr_len);

    // Step 3: Dispatch Recv (don't use inject_and_dispatch — it overwrites recv_buf)
    IoEvent recv_ev = {conn->id, static_cast<i32>(hdr_len), 0, 0, IoEventType::Recv, 0};
    loop.backend.inject(recv_ev);
    n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // Step 4: Proxy/forward routes are not replayable here. The replay
    // harness validates static response decisions only; proxy routes
    // either submit an upstream connect or synthesize a local 502 if
    // socket creation fails. In both cases upstream_name has been
    // populated before the route leaves on_header_received.
    if (conn->upstream_name[0] != '\0' || conn->state == ConnState::Proxying) {
        const i32 saved_upstream_fd = conn->upstream_fd;
        if (saved_upstream_fd >= 0) conn->upstream_fd = -1;
        loop.close_conn(*conn);
        if (saved_upstream_fd >= 0) ::close(saved_upstream_fd);
        result.skipped = true;
        return result;
    }

    // Step 5: Complete send (non-static routes that didn't generate a response are not replayable)
    u32 send_len = conn->send_buf.len();
    if (send_len == 0) {
        const i32 saved_upstream_fd = conn->upstream_fd;
        if (saved_upstream_fd >= 0) conn->upstream_fd = -1;
        loop.close_conn(*conn);
        if (saved_upstream_fd >= 0) ::close(saved_upstream_fd);
        result.skipped = true;
        return result;
    }
    const u32 conn_id = conn->id;
    const u16 actual_status = conn->resp_status;
    const bool is_keep_alive = conn->keep_alive;
    IoEvent send_ev = {conn_id, static_cast<i32>(send_len), 0, 0, IoEventType::Send, 0};
    loop.inject_and_dispatch(send_ev);

    result.actual_status = actual_status;
    result.status_match = (result.expected_status == result.actual_status);
    result.replayed = true;

    // Step 6: Close keep-alive connections; non-keep-alive paths close in on_response_sent.
    if (is_keep_alive) {
        IoEvent eof_ev = {conn_id, 0, 0, 0, IoEventType::Recv, 0};
        loop.inject_and_dispatch(eof_ev);
    }

    return result;
}

// Replay an entire capture file through a loop.
// Returns summary with match/mismatch counts.
template <typename Loop>
ReplaySummary replay_file(Loop& loop, ReplayReader& reader) {
    ReplaySummary summary{};
    CaptureEntry entry{};
    i32 fake_fd = 10000;  // start with high fd to avoid collisions

    while (reader.next(entry) == 0) {
        summary.total++;
        ReplayResult result = replay_one(loop, entry, fake_fd++);
        if (result.replayed) {
            summary.replayed++;
            if (result.status_match)
                summary.matched++;
            else
                summary.mismatched++;
        } else {
            if (result.skipped)
                summary.skipped++;
            else
                summary.failed++;
        }
    }
    return summary;
}

}  // namespace rut
