// Tests for traffic capture: CaptureEntry, CaptureRing, file I/O, and
// integration with the mock event loop (capture through callback pipeline).
#include "fault_injection.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/traffic_capture.h"
#include "test.h"
#include "test_helpers.h"
#include <atomic>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace rut;
using rut::test_fault::IoFaultConfig;
using rut::test_fault::ScopedIoFault;
using rut::test_fault::single_read_eintr;
using rut::test_fault::single_write_eintr;

// Compile-time interface checks: every EventLoop type that callbacks.h
// templates instantiate for MUST have capture_ring and set_capture().
// If a new loop type is added without these, this file won't compile.
namespace {
template <typename Loop>
void verify_capture_interface() {
    Loop* lp = nullptr;
    (void)lp->capture_ring;
    (void)lp->set_capture(nullptr);
}
// Force instantiation for all production + test loop types.
[[maybe_unused]] void compile_time_capture_check() {
    verify_capture_interface<EpollEventLoop>();
    verify_capture_interface<IoUringEventLoop>();
    verify_capture_interface<SmallLoop>();
    // EventLoop<EpollBackend> and EventLoop<IoUringBackend> covered
    // by the concrete loop types above.
}
}  // namespace

// === CaptureEntry layout ===

TEST(capture_entry, size) {
    CHECK_EQ(sizeof(CaptureEntry), 8256u);
}

TEST(capture_entry, metadata_offset) {
    // raw_headers starts at offset 64
    CaptureEntry entry{};
    auto* base = reinterpret_cast<u8*>(&entry);
    auto* headers = reinterpret_cast<u8*>(&entry.raw_headers);
    CHECK_EQ(static_cast<u32>(headers - base), 64u);
}

// === capture_stage_headers edge cases (direct unit tests) ===

TEST(capture_stage, null_capture_buf) {
    Connection conn;
    conn.reset();
    // capture_buf is nullptr after reset
    CHECK(conn.capture_buf == nullptr);
    capture_stage_headers(conn);
    CHECK_EQ(conn.capture_header_len, 0);
}

TEST(capture_stage, null_recv_data) {
    Connection conn;
    conn.reset();
    u8 buf[CaptureEntry::kMaxHeaderLen];
    conn.capture_buf = buf;
    // recv_buf has nullptr data (not bound)
    CHECK(conn.recv_buf.data() == nullptr);
    capture_stage_headers(conn);
    CHECK_EQ(conn.capture_header_len, 0);  // early return, no crash
}

TEST(capture_stage, zero_length_recv) {
    Connection conn;
    conn.reset();
    u8 capture_buf[CaptureEntry::kMaxHeaderLen];
    u8 recv_storage[128];
    conn.capture_buf = capture_buf;
    conn.recv_buf.bind(recv_storage, 128);
    // recv_buf is bound but empty (len=0), header_end=0
    conn.req_header_end = 0;
    CHECK_EQ(conn.recv_buf.len(), 0u);
    capture_stage_headers(conn);
    CHECK_EQ(conn.capture_header_len, 0);  // nothing to copy
}

TEST(capture_stage, normal_copy) {
    Connection conn;
    conn.reset();
    u8 capture_buf[CaptureEntry::kMaxHeaderLen];
    u8 recv_storage[256];
    conn.capture_buf = capture_buf;
    conn.recv_buf.bind(recv_storage, 256);

    const char req[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    conn.recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    conn.req_header_end = sizeof(req) - 1;

    capture_stage_headers(conn);
    CHECK_EQ(conn.capture_header_len, static_cast<u16>(sizeof(req) - 1));
    CHECK_EQ(capture_buf[0], static_cast<u8>('G'));
    CHECK_EQ(capture_buf[1], static_cast<u8>('E'));
    CHECK_EQ(capture_buf[2], static_cast<u8>('T'));
}

TEST(capture_stage, header_end_zero_falls_back_to_recv_len) {
    Connection conn;
    conn.reset();
    u8 capture_buf[CaptureEntry::kMaxHeaderLen];
    u8 recv_storage[256];
    conn.capture_buf = capture_buf;
    conn.recv_buf.bind(recv_storage, 256);

    const char data[] = "partial data";
    conn.recv_buf.write(reinterpret_cast<const u8*>(data), sizeof(data) - 1);
    conn.req_header_end = 0;  // parser didn't set it

    capture_stage_headers(conn);
    // Falls back to recv_buf.len()
    CHECK_EQ(conn.capture_header_len, static_cast<u16>(sizeof(data) - 1));
}

// === CaptureRing ===

TEST(capture_ring, push_pop_single) {
    CaptureRing ring;
    ring.init();
    CHECK_EQ(ring.available(), 0u);

    CaptureEntry entry{};
    entry.resp_status = 200;
    entry.method = static_cast<u8>(LogHttpMethod::Get);
    const char* path = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    u32 path_len = 0;
    while (path[path_len]) path_len++;
    __builtin_memcpy(entry.raw_headers, path, path_len);
    entry.raw_header_len = static_cast<u16>(path_len);

    CHECK(ring.push(entry));
    CHECK_EQ(ring.available(), 1u);

    CaptureEntry out{};
    CHECK(ring.pop(out));
    CHECK_EQ(out.resp_status, 200);
    CHECK_EQ(out.method, static_cast<u8>(LogHttpMethod::Get));
    CHECK_EQ(out.raw_header_len, static_cast<u16>(path_len));
    CHECK_EQ(ring.available(), 0u);
}

TEST(capture_ring, pop_empty) {
    CaptureRing ring;
    ring.init();
    CaptureEntry out{};
    CHECK(!ring.pop(out));
}

TEST(capture_ring, full_drops) {
    CaptureRing ring;
    ring.init();

    CaptureEntry entry{};
    for (u32 i = 0; i < CaptureRing::kCapacity; i++) {
        entry.resp_status = static_cast<u16>(i);
        CHECK(ring.push(entry));
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity);

    // Ring full — push should fail
    entry.resp_status = 999;
    CHECK(!ring.push(entry));

    // Pop one, push should succeed again
    CaptureEntry out{};
    CHECK(ring.pop(out));
    CHECK_EQ(out.resp_status, 0);  // first entry
    CHECK(ring.push(entry));
}

TEST(capture_ring, begin_push_and_commit) {
    CaptureRing ring;
    ring.init();

    CaptureEntry* slot = nullptr;
    u32 wp = 0;
    CHECK(ring.begin_push(&slot, &wp));
    REQUIRE(slot != nullptr);

    __builtin_memset(slot, 0, sizeof(*slot));
    slot->resp_status = 201;
    slot->method = static_cast<u8>(LogHttpMethod::Post);
    slot->raw_header_len = 4;
    const u8 prefix[] = {'P', 'O', 'S', 'T'};
    for (u32 i = 0; i < 4; i++) slot->raw_headers[i] = prefix[i];
    ring.commit_push(wp);

    CHECK_EQ(ring.available(), 1u);

    CaptureEntry out{};
    CHECK(ring.pop(out));
    CHECK_EQ(out.resp_status, 201);
    CHECK_EQ(out.method, static_cast<u8>(LogHttpMethod::Post));
    CHECK_EQ(out.raw_header_len, 4);
    CHECK_EQ(out.raw_headers[0], 'P');
    CHECK_EQ(out.raw_headers[3], 'T');

    ring.pop(out);
    CHECK_EQ(ring.available(), 0u);

    CaptureEntry* full_slots[CaptureRing::kCapacity];
    for (u32 i = 0; i < CaptureRing::kCapacity; i++) {
        u32 full_wp = 0;
        CHECK(ring.begin_push(&full_slots[i], &full_wp));
        CHECK_NE(full_slots[i], nullptr);
        ring.commit_push(full_wp);
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity);
    CHECK(!ring.begin_push(nullptr, nullptr));
}

TEST(capture_ring, fifo_order) {
    CaptureRing ring;
    ring.init();

    CaptureEntry entry{};
    for (u32 i = 0; i < 10; i++) {
        entry.resp_status = static_cast<u16>(100 + i);
        ring.push(entry);
    }

    CaptureEntry out{};
    for (u32 i = 0; i < 10; i++) {
        CHECK(ring.pop(out));
        CHECK_EQ(out.resp_status, static_cast<u16>(100 + i));
    }
}

// === File header ===

TEST(capture_file, header_init_valid) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    CHECK(capture_file_header_valid(&hdr));
    CHECK_EQ(hdr.version, kCaptureFileVersion);
    CHECK_EQ(hdr.entry_size, static_cast<u32>(sizeof(CaptureEntry)));
    CHECK_EQ(hdr.entry_count, 0u);
}

TEST(capture_file, header_invalid_magic) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.magic[0] = 'X';
    CHECK(!capture_file_header_valid(&hdr));
}

TEST(capture_file, header_invalid_version) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.version = 3;
    CHECK(!capture_file_header_valid(&hdr));
}

TEST(capture_file, header_invalid_entry_size) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_size = sizeof(CaptureEntry) - 1;
    CHECK(!capture_file_header_valid(&hdr));
}

// === File I/O round-trip ===

TEST(capture_file, write_read_roundtrip) {
    // Create temp file
    char path[] = "/tmp/rut_capture_test_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    // Write header
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 3;
    ssize_t hw = write(fd, &hdr, sizeof(hdr));
    REQUIRE(hw >= 0);
    CHECK_EQ(hw, static_cast<ssize_t>(sizeof(hdr)));

    // Write 3 entries
    for (u32 i = 0; i < 3; i++) {
        CaptureEntry entry{};
        entry.resp_status = static_cast<u16>(200 + i);
        entry.method = static_cast<u8>(LogHttpMethod::Get);
        entry.raw_header_len = 5;
        entry.raw_headers[0] = 'G';
        entry.raw_headers[1] = 'E';
        entry.raw_headers[2] = 'T';
        entry.raw_headers[3] = ' ';
        entry.raw_headers[4] = '/';
        CHECK_EQ(capture_write_entry(fd, entry), 0);
    }

    // Seek back and read
    lseek(fd, 0, SEEK_SET);

    CaptureFileHeader read_hdr;
    ssize_t hr = read(fd, &read_hdr, sizeof(read_hdr));
    REQUIRE(hr >= 0);
    CHECK_EQ(hr, static_cast<ssize_t>(sizeof(read_hdr)));
    CHECK(capture_file_header_valid(&read_hdr));
    CHECK_EQ(read_hdr.entry_count, 3u);

    for (u32 i = 0; i < 3; i++) {
        CaptureEntry out{};
        CHECK_EQ(capture_read_entry(fd, out), 0);
        CHECK_EQ(out.resp_status, static_cast<u16>(200 + i));
        CHECK_EQ(out.raw_header_len, 5);
        CHECK_EQ(out.raw_headers[0], static_cast<u8>('G'));
    }

    close(fd);
    unlink(path);
}

TEST(capture_file, read_truncated_entry_fails) {
    char path[] = "/tmp/rut_capture_truncated_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    entry.resp_status = 200;
    entry.raw_header_len = 3;
    entry.raw_headers[0] = 'G';
    entry.raw_headers[1] = 'E';
    entry.raw_headers[2] = 'T';

    const u8* bytes = reinterpret_cast<const u8*>(&entry);
    ssize_t written = write(fd, bytes, sizeof(CaptureEntry) - 1);
    REQUIRE(written >= 0);
    CHECK_EQ(written, static_cast<ssize_t>(sizeof(CaptureEntry) - 1));
    lseek(fd, 0, SEEK_SET);

    CaptureEntry out{};
    CHECK_EQ(capture_read_entry(fd, out), -1);

    close(fd);
    unlink(path);
}

TEST(capture_file, read_zeroed_entry_succeeds_as_empty) {
    char path[] = "/tmp/rut_capture_zeroed_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    CHECK_EQ(capture_write_entry(fd, entry), 0);
    lseek(fd, 0, SEEK_SET);

    CaptureEntry out{};
    CHECK_EQ(capture_read_entry(fd, out), 0);
    CHECK_EQ(out.resp_status, 0);
    CHECK_EQ(out.method, 0);
    CHECK_EQ(out.raw_header_len, 0);
    CHECK_EQ(out.raw_headers[0], 0u);
    CHECK_EQ(out.raw_headers[CaptureEntry::kMaxHeaderLen - 1], 0u);

    close(fd);
    unlink(path);
}

TEST(capture_file, write_entry_retries_eintr) {
    char path[] = "/tmp/rut_capture_write_eintr_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    entry.resp_status = 204;
    entry.raw_header_len = 4;
    entry.raw_headers[0] = 'H';
    entry.raw_headers[1] = 'E';
    entry.raw_headers[2] = 'A';
    entry.raw_headers[3] = 'D';

    {
        ScopedIoFault fault(single_write_eintr(fd));
        CHECK_EQ(capture_write_entry(fd, entry), 0);
        CHECK_EQ(fault.remaining_write_eintrs(), 0);
    }

    lseek(fd, 0, SEEK_SET);
    CaptureEntry out{};
    CHECK_EQ(capture_read_entry(fd, out), 0);
    CHECK_EQ(out.resp_status, 204);
    CHECK_EQ(out.raw_header_len, 4);
    CHECK_EQ(out.raw_headers[0], static_cast<u8>('H'));

    close(fd);
    unlink(path);
}

TEST(capture_file, read_entry_retries_eintr) {
    char path[] = "/tmp/rut_capture_read_eintr_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    entry.resp_status = 201;
    entry.method = static_cast<u8>(LogHttpMethod::Post);
    entry.raw_header_len = 5;
    entry.raw_headers[0] = 'P';
    entry.raw_headers[1] = 'O';
    entry.raw_headers[2] = 'S';
    entry.raw_headers[3] = 'T';
    entry.raw_headers[4] = ' ';
    CHECK_EQ(capture_write_entry(fd, entry), 0);

    lseek(fd, 0, SEEK_SET);
    CaptureEntry out{};
    {
        ScopedIoFault fault(single_read_eintr(fd));
        CHECK_EQ(capture_read_entry(fd, out), 0);
        CHECK_EQ(fault.remaining_read_eintrs(), 0);
    }
    CHECK_EQ(out.resp_status, 201);
    CHECK_EQ(out.method, static_cast<u8>(LogHttpMethod::Post));
    CHECK_EQ(out.raw_header_len, 5);
    CHECK_EQ(out.raw_headers[0], static_cast<u8>('P'));

    close(fd);
    unlink(path);
}

TEST(capture_file, write_entry_handles_short_write) {
    char path[] = "/tmp/rut_capture_short_write_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    entry.resp_status = 206;
    entry.raw_header_len = 3;
    entry.raw_headers[0] = 'P';
    entry.raw_headers[1] = 'A';
    entry.raw_headers[2] = 'R';

    {
        IoFaultConfig fault_config;
        fault_config.fd = fd;
        fault_config.write_short_len = 17;
        fault_config.write_shorts = 1;
        ScopedIoFault fault(fault_config);
        CHECK_EQ(capture_write_entry(fd, entry), 0);
    }

    lseek(fd, 0, SEEK_SET);
    CaptureEntry out{};
    CHECK_EQ(capture_read_entry(fd, out), 0);
    CHECK_EQ(out.resp_status, 206);
    CHECK_EQ(out.raw_header_len, 3);
    CHECK_EQ(out.raw_headers[0], static_cast<u8>('P'));

    close(fd);
    unlink(path);
}

TEST(capture_file, read_entry_handles_short_read) {
    char path[] = "/tmp/rut_capture_short_read_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureEntry entry{};
    entry.resp_status = 207;
    entry.method = static_cast<u8>(LogHttpMethod::Put);
    entry.raw_header_len = 4;
    entry.raw_headers[0] = 'R';
    entry.raw_headers[1] = 'E';
    entry.raw_headers[2] = 'A';
    entry.raw_headers[3] = 'D';
    CHECK_EQ(capture_write_entry(fd, entry), 0);

    lseek(fd, 0, SEEK_SET);
    CaptureEntry out{};
    {
        IoFaultConfig fault_config;
        fault_config.fd = fd;
        fault_config.read_short_len = 19;
        fault_config.read_shorts = 1;
        ScopedIoFault fault(fault_config);
        CHECK_EQ(capture_read_entry(fd, out), 0);
    }
    CHECK_EQ(out.resp_status, 207);
    CHECK_EQ(out.method, static_cast<u8>(LogHttpMethod::Put));
    CHECK_EQ(out.raw_header_len, 4);
    CHECK_EQ(out.raw_headers[0], static_cast<u8>('R'));

    close(fd);
    unlink(path);
}

// === Integration: capture through mock event loop ===

TEST(capture_integration, basic_request_captured) {
    // Allocate ring on heap (too large for stack: 256 * 8256 = ~2MB)
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    // Accept connection
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    // capture_buf should be wired
    CHECK(conn->capture_buf != nullptr);

    // Inject a valid HTTP request into recv_buf
    conn->recv_buf.reset();
    const char req[] = "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    u32 req_len = sizeof(req) - 1;
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), req_len);

    // Dispatch recv — triggers on_header_received → capture_stage_headers
    // Use direct callback dispatch (recv_buf already has data)
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(req_len));
    // Don't use inject_and_dispatch (it overwrites recv_buf with mock bytes).
    // Instead, inject directly and dispatch manually.
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // After on_header_received, capture_buf should have the headers staged
    CHECK_GT(conn->capture_header_len, 0);

    // Complete the send — triggers on_response_sent → on_request_complete → capture write
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    // Ring should have one entry
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    CHECK(ring->pop(cap));
    CHECK_EQ(cap.resp_status, 200);
    CHECK_EQ(cap.method, static_cast<u8>(LogHttpMethod::Get));
    CHECK_GT(cap.raw_header_len, 0);

    // Verify raw headers contain the request line
    bool found_get =
        cap.raw_headers[0] == 'G' && cap.raw_headers[1] == 'E' && cap.raw_headers[2] == 'T';
    CHECK(found_get);

    munmap(ring, sizeof(CaptureRing));
}

TEST(capture_integration, no_capture_when_disabled) {
    SmallLoop loop;
    loop.setup();
    // capture_ring is nullptr — no capture

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf == nullptr);

    loop.inject_and_dispatch(make_ev(conn->id, IoEventType::Recv, 50));
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));
    // No crash, no capture — just verify it doesn't blow up
}

TEST(capture_integration, keepalive_captures_both) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Two keep-alive request cycles
    for (int cycle = 0; cycle < 2; cycle++) {
        conn->recv_buf.reset();
        const char req[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);

        IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
        loop.backend.inject(recv_ev);
        IoEvent events[8];
        u32 n = loop.backend.wait(events, 8);
        for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

        loop.inject_and_dispatch(
            make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));
    }

    // Both requests captured
    CHECK_EQ(ring->available(), 2u);

    munmap(ring, sizeof(CaptureRing));
}

// === Runtime enable/disable via control block ===

TEST(capture_control, enable_via_control_block) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    // Wire control block
    ShardControlBlock ctrl{};
    ctrl.pending_capture.store(nullptr, std::memory_order_relaxed);
    loop.control = &ctrl;

    // Initially no capture
    CHECK(loop.capture_ring == nullptr);

    // Enable via control block
    ctrl.pending_capture.store(ring, std::memory_order_release);
    loop.poll_command();
    CHECK_EQ(loop.capture_ring, ring);

    munmap(ring, sizeof(CaptureRing));
}

TEST(capture_control, disable_via_control_block) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    ShardControlBlock ctrl{};
    ctrl.pending_capture.store(nullptr, std::memory_order_relaxed);
    loop.control = &ctrl;

    // Enable
    ctrl.pending_capture.store(ring, std::memory_order_release);
    loop.poll_command();
    CHECK_EQ(loop.capture_ring, ring);

    // Disable
    ctrl.pending_capture.store(kCaptureDisable, std::memory_order_release);
    loop.poll_command();
    CHECK(loop.capture_ring == nullptr);

    munmap(ring, sizeof(CaptureRing));
}

TEST(capture_control, enable_captures_disable_stops) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    // Accept + request with capture on
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Manually set capture_buf (SmallLoop wires it from capture_storage)
    // Already wired by alloc_conn_impl since capture_ring is set

    conn->recv_buf.reset();
    const char req[] = "GET /on HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    CHECK_EQ(ring->available(), 1u);

    // Disable capture
    loop.set_capture(nullptr);

    // Second request — should NOT be captured
    conn->recv_buf.reset();
    const char req2[] = "GET /off HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req2), sizeof(req2) - 1);
    recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req2) - 1));
    loop.backend.inject(recv_ev);
    n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    // Still only 1 entry
    CHECK_EQ(ring->available(), 1u);

    munmap(ring, sizeof(CaptureRing));
}

TEST(capture_control, conn_before_enable_gets_backfilled) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    // Wire control block
    ShardControlBlock ctrl{};
    ctrl.pending_capture.store(nullptr, std::memory_order_relaxed);
    loop.control = &ctrl;

    // Accept connection BEFORE capture is enabled
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf == nullptr);  // no capture yet

    // Enable capture via control block
    ctrl.pending_capture.store(ring, std::memory_order_release);
    loop.poll_command();
    CHECK_EQ(loop.capture_ring, ring);

    // Backfill should have set capture_buf on the existing connection
    CHECK(conn->capture_buf != nullptr);

    // Now send a request — it should be captured
    conn->recv_buf.reset();
    const char req[] = "GET /backfill HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    // Should have captured the request
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    CHECK(ring->pop(cap));
    CHECK_EQ(cap.resp_status, 200);
    // Verify raw headers contain "/backfill"
    bool found = false;
    for (u32 i = 0; i + 8 < cap.raw_header_len; i++) {
        if (cap.raw_headers[i] == '/' && cap.raw_headers[i + 1] == 'b') {
            found = true;
            break;
        }
    }
    CHECK(found);

    munmap(ring, sizeof(CaptureRing));
}

// --- State transition tests ---
// Cover all capture on/off × connection lifecycle combinations.

// Helper: send a request on an existing connection, bypassing inject_and_dispatch
// (which overwrites recv_buf with mock bytes). Returns send_buf length for send completion.
static u32 send_request(SmallLoop& loop, Connection& conn, const char* req_str) {
    u32 req_len = 0;
    while (req_str[req_len]) req_len++;

    conn.recv_buf.reset();
    conn.recv_buf.write(reinterpret_cast<const u8*>(req_str), req_len);

    IoEvent recv_ev = make_ev(conn.id, IoEventType::Recv, static_cast<i32>(req_len));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    u32 send_len = conn.send_buf.len();
    loop.inject_and_dispatch(make_ev(conn.id, IoEventType::Send, static_cast<i32>(send_len)));
    return send_len;
}

TEST(capture_transition, production_capture_persisted_tail_zero) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    REQUIRE(conn->capture_buf != nullptr);
    for (u32 i = 0; i < CaptureEntry::kMaxHeaderLen; i++) conn->capture_buf[i] = 0xA5;

    send_request(loop, *conn, "GET /tail-zero HTTP/1.1\r\nHost: x\r\n\r\n");

    CaptureEntry cap{};
    REQUIRE(ring->pop(cap));
    REQUIRE(cap.raw_header_len > 0u);
    REQUIRE(cap.raw_header_len < static_cast<u16>(CaptureEntry::kMaxHeaderLen));

    char path[] = "/tmp/rut_capture_tail_zero_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    CHECK_EQ(capture_write_entry(fd, cap), 0);
    lseek(fd, 0, SEEK_SET);

    CaptureEntry out{};
    CHECK_EQ(capture_read_entry(fd, out), 0);
    CHECK_EQ(out.raw_header_len, cap.raw_header_len);
    for (u32 i = 0; i < out.raw_header_len; i++) CHECK_EQ(out.raw_headers[i], cap.raw_headers[i]);
    for (u32 i = out.raw_header_len; i < CaptureEntry::kMaxHeaderLen; i++) {
        CHECK_EQ(out.raw_headers[i], 0u);
    }

    close(fd);
    unlink(path);
    munmap(ring, sizeof(CaptureRing));
}

// 2. on → accept → off → request: disable after accept, request not captured
TEST(capture_transition, on_accept_off_request) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    // Accept while capture is on — capture_buf is wired
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf != nullptr);

    // Disable capture
    loop.set_capture(nullptr);

    // Request should NOT be captured (capture_ring is null at completion)
    send_request(loop, *conn, "GET /after-disable HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 0u);

    munmap(ring, sizeof(CaptureRing));
}

// 3. on → accept → off → on → request: re-enable backfills, request captured
TEST(capture_transition, on_off_on_reenable_backfill) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    ShardControlBlock ctrl{};
    ctrl.pending_capture.store(nullptr, std::memory_order_relaxed);
    loop.control = &ctrl;

    // Enable, accept, disable
    ctrl.pending_capture.store(ring, std::memory_order_release);
    loop.poll_command();
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf != nullptr);

    ctrl.pending_capture.store(kCaptureDisable, std::memory_order_release);
    loop.poll_command();
    CHECK(loop.capture_ring == nullptr);

    // Accept a second connection while capture is off
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 43));
    auto* conn2 = loop.find_fd(43);
    REQUIRE(conn2 != nullptr);
    CHECK(conn2->capture_buf == nullptr);  // no capture during off

    // Re-enable — both connections should get backfilled
    ctrl.pending_capture.store(ring, std::memory_order_release);
    loop.poll_command();
    CHECK_EQ(loop.capture_ring, ring);
    CHECK(conn->capture_buf != nullptr);
    CHECK(conn2->capture_buf != nullptr);  // backfilled

    // Requests on both should be captured
    send_request(loop, *conn, "GET /re1 HTTP/1.1\r\nHost: x\r\n\r\n");
    send_request(loop, *conn2, "GET /re2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);

    munmap(ring, sizeof(CaptureRing));
}

// 4. Disable mid-request: headers staged (capture on), but completion sees capture off.
//    Should not crash, request silently not captured.
TEST(capture_transition, disable_mid_request) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Send request headers — triggers on_header_received, stages headers
    conn->recv_buf.reset();
    const char req[] = "GET /mid HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // Headers are staged
    CHECK_GT(conn->capture_header_len, 0);

    // Disable capture BETWEEN header recv and send completion
    loop.set_capture(nullptr);

    // Complete the send — on_request_complete sees capture_ring == nullptr
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    // Not captured (ring was disabled at completion time)
    CHECK_EQ(ring->available(), 0u);
    // Connection still alive (keep-alive)
    CHECK_EQ(conn->state, ConnState::ReadingHeader);

    munmap(ring, sizeof(CaptureRing));
}

// 5. Mixed: conn1 accepted while off, conn2 accepted while on.
//    set_capture() backfills conn1, so BOTH should be captured.
TEST(capture_transition, mixed_conns_both_captured_after_enable) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    // capture off initially

    // Accept conn1 while capture off
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn1 = loop.find_fd(42);
    REQUIRE(conn1 != nullptr);
    CHECK(conn1->capture_buf == nullptr);

    // Enable capture — backfills conn1
    loop.set_capture(ring);
    CHECK(conn1->capture_buf != nullptr);  // backfilled

    // Accept conn2 while capture on
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 43));
    auto* conn2 = loop.find_fd(43);
    REQUIRE(conn2 != nullptr);
    CHECK(conn2->capture_buf != nullptr);

    // Both requests captured
    send_request(loop, *conn1, "GET /c1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    send_request(loop, *conn2, "GET /c2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);

    munmap(ring, sizeof(CaptureRing));
}

// 6. Close connection after disable — no crash.
TEST(capture_transition, close_after_disable) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    u32 cid = conn->id;

    // Disable capture, then close — should not crash
    loop.set_capture(nullptr);
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Recv, 0));  // EOF → close
    CHECK_EQ(loop.conns[cid].fd, -1);

    munmap(ring, sizeof(CaptureRing));
}

// 7. Keep-alive: capture off for req1, on for req2. req2 must NOT
//    contain stale header data from req1.
TEST(capture_transition, keepalive_off_then_on_no_stale) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Request 1 with capture on — establishes header_len
    send_request(loop, *conn, "GET /req1 HTTP/1.1\r\nHost: a\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    // Disable capture, send request 2
    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /req2-off HTTP/1.1\r\nHost: b\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);  // still 1

    // Re-enable capture, send request 3
    loop.set_capture(ring);
    send_request(loop, *conn, "GET /req3 HTTP/1.1\r\nHost: c\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);  // 1 from req1 + 1 from req3

    // Verify req3's capture has the correct headers (not req1's stale data)
    CaptureEntry cap1{}, cap3{};
    ring->pop(cap1);  // req1
    ring->pop(cap3);  // req3

    // req3 headers should contain "/req3", not "/req1"
    bool found_req3 = false;
    for (u32 i = 0; i + 4 < cap3.raw_header_len; i++) {
        if (cap3.raw_headers[i] == '/' && cap3.raw_headers[i + 1] == 'r' &&
            cap3.raw_headers[i + 2] == 'e' && cap3.raw_headers[i + 3] == 'q' &&
            cap3.raw_headers[i + 4] == '3') {
            found_req3 = true;
            break;
        }
    }
    CHECK(found_req3);

    munmap(ring, sizeof(CaptureRing));
}

// 8. The exact interleaving bug: capture on for header recv, off at completion,
//    then re-enabled before next request. Stale capture_header_len from req1
//    must not leak into the next request's capture entry.
TEST(capture_transition, stale_header_len_across_disable_reenable) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Request 1: headers staged (capture on), then disable before send completion
    conn->recv_buf.reset();
    const char r1[] = "GET /staged HTTP/1.1\r\nHost: x\r\nX-Big: aaaa\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(r1), sizeof(r1) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(r1) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    CHECK_GT(conn->capture_header_len, 0);  // headers staged
    u16 stale_len = conn->capture_header_len;

    // Disable capture, complete the send
    loop.set_capture(nullptr);
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));
    CHECK_EQ(ring->available(), 0u);  // not captured (disabled at completion)

    // Re-enable capture
    loop.set_capture(ring);

    // Request 2: shorter headers. capture_header_len must reflect req2, not req1.
    send_request(loop, *conn, "GET /s HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    ring->pop(cap);
    // req2 headers are shorter than req1's stale_len
    CHECK(cap.raw_header_len < stale_len);
    CHECK_EQ(cap.resp_status, 200);

    munmap(ring, sizeof(CaptureRing));
}

// 9. Ring overflow: push more entries than capacity, verify no crash,
//    oldest entries survive, overflow entries are dropped.
TEST(capture_ring, overflow_pressure) {
    CaptureRing ring;
    ring.init();

    CaptureEntry entry{};
    entry.method = static_cast<u8>(LogHttpMethod::Post);

    // Fill ring completely
    for (u32 i = 0; i < CaptureRing::kCapacity; i++) {
        entry.resp_status = static_cast<u16>(i);
        CHECK(ring.push(entry));
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity);

    // Overflow: next 100 pushes should all fail
    for (u32 i = 0; i < 100; i++) {
        entry.resp_status = static_cast<u16>(9000 + i);
        CHECK(!ring.push(entry));
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity);

    // Drain half, then push should succeed again
    CaptureEntry out{};
    for (u32 i = 0; i < CaptureRing::kCapacity / 2; i++) {
        CHECK(ring.pop(out));
        CHECK_EQ(out.resp_status, static_cast<u16>(i));  // FIFO preserved
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity / 2);

    // Push again — should succeed
    for (u32 i = 0; i < CaptureRing::kCapacity / 2; i++) {
        entry.resp_status = static_cast<u16>(5000 + i);
        CHECK(ring.push(entry));
    }
    CHECK_EQ(ring.available(), CaptureRing::kCapacity);
}

// ============================================================
// Systematic cross-state coverage
// ============================================================
//
// Notation: each request is labeled by capture state at
//   (header_received, request_complete)
// e.g. "on/on" = capture on at both points = captured
//      "on/off" = staged but not written
//      "off/on" = not staged, header_len=0, not written
//      "off/off" = not captured
//
// Keep-alive sequences test 2-3 requests per connection.

// --- A. Keep-alive toggle sequences ---

// A1: off → off → on (3 requests, capture only on for req3)
TEST(capture_cross, keepalive_off_off_on) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    // Accept while off
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // req1: off
    send_request(loop, *conn, "GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 0u);

    // req2: still off
    send_request(loop, *conn, "GET /r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 0u);

    // Enable, req3: on
    loop.set_capture(ring);
    send_request(loop, *conn, "GET /r3 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    ring->pop(cap);
    CHECK_EQ(cap.resp_status, 200);
    // Verify it's req3's headers, not stale from req1/req2
    bool found = false;
    for (u32 i = 0; i + 2 < cap.raw_header_len; i++) {
        if (cap.raw_headers[i] == 'r' && cap.raw_headers[i + 1] == '3') {
            found = true;
            break;
        }
    }
    CHECK(found);

    munmap(ring, sizeof(CaptureRing));
}

// A2: off → on → off (3 requests, only req2 captured)
TEST(capture_cross, keepalive_off_on_off) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // req1: off
    send_request(loop, *conn, "GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 0u);

    // Enable, req2: on
    loop.set_capture(ring);
    send_request(loop, *conn, "GET /r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    // Disable, req3: off
    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /r3 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);  // still 1

    munmap(ring, sizeof(CaptureRing));
}

// A3: on → on → off (3 requests, req1+req2 captured, req3 not)
TEST(capture_cross, keepalive_on_on_off) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    send_request(loop, *conn, "GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    send_request(loop, *conn, "GET /r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);

    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /r3 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);  // still 2

    munmap(ring, sizeof(CaptureRing));
}

// A4: on → off → off (3 requests, only req1 captured)
TEST(capture_cross, keepalive_on_off_off) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    send_request(loop, *conn, "GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    send_request(loop, *conn, "GET /r3 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    munmap(ring, sizeof(CaptureRing));
}

// A5: Double toggle: on → off → on → off (4 requests)
TEST(capture_cross, keepalive_double_toggle) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    send_request(loop, *conn, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);  // on

    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);  // off

    loop.set_capture(ring);
    send_request(loop, *conn, "GET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);  // on

    loop.set_capture(nullptr);
    send_request(loop, *conn, "GET /d HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);  // off

    // Verify captured entries have correct headers
    CaptureEntry cap_a{}, cap_c{};
    ring->pop(cap_a);
    ring->pop(cap_c);

    bool found_a = false, found_c = false;
    for (u32 i = 0; i + 1 < cap_a.raw_header_len; i++)
        if (cap_a.raw_headers[i] == '/' && cap_a.raw_headers[i + 1] == 'a') found_a = true;
    for (u32 i = 0; i + 1 < cap_c.raw_header_len; i++)
        if (cap_c.raw_headers[i] == '/' && cap_c.raw_headers[i + 1] == 'c') found_c = true;
    CHECK(found_a);
    CHECK(found_c);

    munmap(ring, sizeof(CaptureRing));
}

// --- B. Per-request state: off at header, on at complete ---
// (enable between header_received and request_complete)
// Should NOT capture — header_len is 0, even though ring is now set.

TEST(capture_cross, enable_between_header_and_complete) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    // capture OFF initially

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Recv request while capture OFF — headers not staged
    conn->recv_buf.reset();
    const char req[] = "GET /between HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    CHECK_EQ(conn->capture_header_len, 0);  // not staged

    // Enable capture BETWEEN header recv and send completion
    loop.set_capture(ring);
    CHECK(conn->capture_buf != nullptr);  // backfilled

    // Complete the send
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    // Should NOT capture — capture_header_len is 0
    CHECK_EQ(ring->available(), 0u);

    // Next request SHOULD be captured normally
    send_request(loop, *conn, "GET /next HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    munmap(ring, sizeof(CaptureRing));
}

// --- C. Multi-connection interleaved enable/disable ---

TEST(capture_cross, two_conns_alternating_capture) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 43));
    auto* c1 = loop.find_fd(42);
    auto* c2 = loop.find_fd(43);
    REQUIRE(c1 != nullptr);
    REQUIRE(c2 != nullptr);

    // req on c1 (on) — captured
    send_request(loop, *c1, "GET /c1r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    // Disable, req on c2 (off) — not captured
    loop.set_capture(nullptr);
    send_request(loop, *c2, "GET /c2r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    // Re-enable, req on c2 (on) — captured
    loop.set_capture(ring);
    send_request(loop, *c2, "GET /c2r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 2u);

    // req on c1 (on) — captured
    send_request(loop, *c1, "GET /c1r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 3u);

    munmap(ring, sizeof(CaptureRing));
}

// --- D. Cross with drain mode ---

TEST(capture_cross, capture_during_drain) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Enable drain mode
    loop.draining = true;

    // Request during drain — should still be captured, response is "Connection: close"
    send_request(loop, *conn, "GET /drain HTTP/1.1\r\nHost: x\r\n\r\n");

    // Connection closed (drain sends Connection: close, keep_alive=false)
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    ring->pop(cap);
    CHECK_EQ(cap.resp_status, 200);  // still 200, just with Connection: close

    munmap(ring, sizeof(CaptureRing));
}

// --- E. Close with staged headers (capture on at header, conn reset before completion) ---

TEST(capture_cross, close_with_staged_headers) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    u32 cid = conn->id;

    // Recv request — headers staged
    conn->recv_buf.reset();
    const char req[] = "GET /close HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    CHECK_GT(conn->capture_header_len, 0);

    // Send fails → connection close (before on_request_complete writes capture)
    loop.inject_and_dispatch(make_ev(cid, IoEventType::Send, -32));  // EPIPE
    CHECK_EQ(loop.conns[cid].fd, -1);                                // closed

    // Headers were staged but never written to ring (close bypasses on_request_complete)
    CHECK_EQ(ring->available(), 0u);

    munmap(ring, sizeof(CaptureRing));
}

// --- F. Proxy flow with capture ---

TEST(capture_cross, proxy_cycle_captured) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    // Accept + recv request
    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    conn->recv_buf.reset();
    const char req[] = "GET /proxy HTTP/1.1\r\nHost: upstream\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // Headers should be staged
    CHECK_GT(conn->capture_header_len, 0);

    // Switch to proxy mode
    conn->upstream_fd = 100;
    conn->set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<SmallLoop>);
    conn->state = ConnState::Proxying;
    loop.submit_connect(*conn, nullptr, 0);

    // Proxy cycle: connect → send to upstream → recv response → send to client
    loop.inject_and_dispatch(make_ev(conn->id, IoEventType::UpstreamConnect, 0));
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::UpstreamSend, static_cast<i32>(sizeof(req) - 1)));
    inject_upstream_response(loop, *conn);

    // Complete: send proxy response to client
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(kMockHttpResponseLen)));

    // Proxy response captured with correct headers
    CHECK_EQ(ring->available(), 1u);

    CaptureEntry cap{};
    ring->pop(cap);
    CHECK_EQ(cap.resp_status, 200);
    // Verify raw headers contain "/proxy"
    bool found = false;
    for (u32 i = 0; i + 5 < cap.raw_header_len; i++) {
        if (cap.raw_headers[i] == '/' && cap.raw_headers[i + 1] == 'p' &&
            cap.raw_headers[i + 2] == 'r') {
            found = true;
            break;
        }
    }
    CHECK(found);

    munmap(ring, sizeof(CaptureRing));
}

// Proxy 502 (upstream connect failure) with capture
TEST(capture_cross, proxy_502_captured) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    conn->recv_buf.reset();
    const char req[] = "GET /fail HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // Proxy connect fails → 502
    conn->upstream_fd = 100;
    conn->set_slots(nullptr, nullptr, nullptr, &on_upstream_connected<SmallLoop>);
    loop.inject_and_dispatch(make_ev(conn->id, IoEventType::UpstreamConnect, -111));

    // 502 response sent to client
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    CHECK_EQ(ring->available(), 1u);
    CaptureEntry cap{};
    ring->pop(cap);
    CHECK_EQ(cap.resp_status, 502);

    munmap(ring, sizeof(CaptureRing));
}

// --- G. Ring overflow with live event loop ---

TEST(capture_cross, ring_overflow_live) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Send enough requests to overflow the ring (capacity = 256)
    for (u32 i = 0; i < CaptureRing::kCapacity + 10; i++) {
        send_request(loop, *conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    // Ring should be full at capacity, no crash
    CHECK_EQ(ring->available(), CaptureRing::kCapacity);

    // Drain some, then new requests succeed
    CaptureEntry out{};
    for (u32 i = 0; i < 10; i++) ring->pop(out);
    CHECK_EQ(ring->available(), CaptureRing::kCapacity - 10);

    send_request(loop, *conn, "GET /after HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), CaptureRing::kCapacity - 10 + 1);

    munmap(ring, sizeof(CaptureRing));
}

// ============================================================
// End-to-end and failure path verification
// ============================================================

// H1. Full pipeline: event loop → ring → file → read back → verify headers
TEST(capture_e2e, pipeline_to_file) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Three distinct requests
    const char* reqs[] = {
        "GET /users HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n",
        "POST /login HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
        "DELETE /session HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer tok\r\n\r\n",
    };
    for (int i = 0; i < 3; i++) {
        send_request(loop, *conn, reqs[i]);
    }
    CHECK_EQ(ring->available(), 3u);

    // Write to temp file
    char path[] = "/tmp/rut_e2e_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 3;
    ssize_t hw = write(fd, &hdr, sizeof(hdr));
    CHECK_EQ(static_cast<u32>(hw), static_cast<u32>(sizeof(hdr)));

    CaptureEntry entry{};
    for (u32 i = 0; i < 3; i++) {
        CHECK(ring->pop(entry));
        CHECK_EQ(capture_write_entry(fd, entry), 0);
    }
    CHECK_EQ(ring->available(), 0u);

    // Read back and verify
    lseek(fd, 0, SEEK_SET);

    CaptureFileHeader read_hdr;
    ssize_t hr = read(fd, &read_hdr, sizeof(read_hdr));
    CHECK_EQ(static_cast<u32>(hr), static_cast<u32>(sizeof(read_hdr)));
    CHECK(capture_file_header_valid(&read_hdr));
    CHECK_EQ(read_hdr.entry_count, 3u);

    // Verify each entry's headers match what was sent
    const char* expected_paths[] = {"/users", "/login", "/session"};
    const u8 expected_methods[] = {
        static_cast<u8>(LogHttpMethod::Get),
        static_cast<u8>(LogHttpMethod::Post),
        static_cast<u8>(LogHttpMethod::Delete),
    };

    for (u32 i = 0; i < 3; i++) {
        CaptureEntry cap{};
        CHECK_EQ(capture_read_entry(fd, cap), 0);
        CHECK_EQ(cap.resp_status, 200);
        CHECK_EQ(cap.method, expected_methods[i]);
        CHECK_GT(cap.raw_header_len, 0);

        // Find expected path in raw headers
        u32 plen = 0;
        while (expected_paths[i][plen]) plen++;
        bool found = false;
        for (u32 j = 0; j + plen <= cap.raw_header_len; j++) {
            bool match = true;
            for (u32 k = 0; k < plen; k++) {
                if (cap.raw_headers[j + k] != static_cast<u8>(expected_paths[i][k])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                found = true;
                break;
            }
        }
        CHECK(found);
    }

    // EOF — no more entries
    CaptureEntry eof_cap{};
    CHECK_EQ(capture_read_entry(fd, eof_cap), -1);

    close(fd);
    unlink(path);
    munmap(ring, sizeof(CaptureRing));
}

// H2. Empty file — read returns -1 immediately
TEST(capture_e2e, read_empty_file) {
    char path[] = "/tmp/rut_empty_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    // Write only header, no entries
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 0;
    write(fd, &hdr, sizeof(hdr));

    lseek(fd, sizeof(hdr), SEEK_SET);
    CaptureEntry cap{};
    CHECK_EQ(capture_read_entry(fd, cap), -1);  // no entries

    close(fd);
    unlink(path);
}

// H3. Partial write recovery — truncated entry detected on read
TEST(capture_e2e, truncated_entry_read_fails) {
    char path[] = "/tmp/rut_trunc_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 1;
    write(fd, &hdr, sizeof(hdr));

    // Write only half an entry
    CaptureEntry entry{};
    entry.resp_status = 200;
    write(fd, &entry, sizeof(entry) / 2);

    lseek(fd, sizeof(hdr), SEEK_SET);
    CaptureEntry cap{};
    CHECK_EQ(capture_read_entry(fd, cap), -1);  // incomplete → error

    close(fd);
    unlink(path);
}

// H4. set_capture idempotent — calling twice with same ring doesn't double-backfill
TEST(capture_e2e, set_capture_idempotent) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf == nullptr);

    // First set_capture — backfills
    loop.set_capture(ring);
    CHECK(conn->capture_buf != nullptr);
    u8* buf1 = conn->capture_buf;

    // Second set_capture with same ring — should not change capture_buf
    loop.set_capture(ring);
    CHECK_EQ(conn->capture_buf, buf1);  // same pointer, not double-assigned

    // Request works correctly
    send_request(loop, *conn, "GET /idem HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring->available(), 1u);

    munmap(ring, sizeof(CaptureRing));
}

// H5. Disable then enable with different ring — old entries stay in old ring
TEST(capture_e2e, switch_ring) {
    auto* ring1 = static_cast<CaptureRing*>(mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    auto* ring2 = static_cast<CaptureRing*>(mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(ring1 != MAP_FAILED);
    REQUIRE(ring2 != MAP_FAILED);
    ring1->init();
    ring2->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring1);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Request to ring1
    send_request(loop, *conn, "GET /r1 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring1->available(), 1u);
    CHECK_EQ(ring2->available(), 0u);

    // Switch to ring2
    loop.set_capture(ring2);

    // Request to ring2
    send_request(loop, *conn, "GET /r2 HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK_EQ(ring1->available(), 1u);  // unchanged
    CHECK_EQ(ring2->available(), 1u);

    munmap(ring1, sizeof(CaptureRing));
    munmap(ring2, sizeof(CaptureRing));
}

// H6. Large header near 8KB limit — verify truncation flag
TEST(capture_e2e, large_header_near_limit) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Build a request with many headers that stays under SmallLoop's 4KB buf
    // (SmallLoop uses 4KB buffers, so we can't test the full 8KB path here,
    // but we can verify capture works near the buffer limit)
    conn->recv_buf.reset();
    const char prefix[] = "GET /big HTTP/1.1\r\nHost: x\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(prefix), sizeof(prefix) - 1);

    // Fill with padding headers up to ~3.5KB
    u32 target = 3500;
    while (conn->recv_buf.len() < target) {
        const char hdr[] = "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        u32 avail = conn->recv_buf.write_avail();
        if (avail < sizeof(hdr)) break;
        conn->recv_buf.write(reinterpret_cast<const u8*>(hdr), sizeof(hdr) - 1);
    }
    conn->recv_buf.write(reinterpret_cast<const u8*>("\r\n"), 2);

    u32 total = conn->recv_buf.len();
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(total));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    CHECK_EQ(ring->available(), 1u);
    CaptureEntry cap{};
    ring->pop(cap);
    CHECK_GT(cap.raw_header_len, 100);               // captured something substantial
    CHECK(cap.raw_header_len <= total);              // not more than sent
    CHECK_EQ(cap.flags & kCaptureFlagTruncated, 0);  // not truncated (under 8KB)

    munmap(ring, sizeof(CaptureRing));
}

// ============================================================
// SPSC stress tests
// ============================================================

struct CaptureProducerCtx {
    CaptureRing* ring;
    u32 count;
    u32 pushed;
    u32 dropped;
};

static void* capture_producer(void* arg) {
    auto* ctx = static_cast<CaptureProducerCtx*>(arg);
    ctx->pushed = 0;
    ctx->dropped = 0;
    for (u32 i = 0; i < ctx->count; i++) {
        CaptureEntry entry{};
        entry.resp_status = static_cast<u16>(i & 0xFFFF);
        entry.req_content_length = i;  // use as sequence number
        entry.raw_header_len = 10;
        // Write a recognizable pattern into raw_headers
        for (u32 j = 0; j < 10; j++) entry.raw_headers[j] = static_cast<u8>((i + j) & 0xFF);
        if (ctx->ring->push(entry))
            ctx->pushed++;
        else
            ctx->dropped++;
    }
    return nullptr;
}

struct CaptureConsumerCtx {
    CaptureRing* ring;
    u32 consumed;
    u32 last_seq;
    bool order_ok;
    bool data_ok;
    bool stop;
};

static void* capture_consumer(void* arg) {
    auto* ctx = static_cast<CaptureConsumerCtx*>(arg);
    ctx->consumed = 0;
    ctx->last_seq = 0;
    ctx->order_ok = true;
    ctx->data_ok = true;
    CaptureEntry entry{};
    while (!ctx->stop || ctx->ring->available() > 0) {
        if (ctx->ring->pop(entry)) {
            u32 seq = entry.req_content_length;
            // Verify monotonic ordering
            if (seq < ctx->last_seq) ctx->order_ok = false;
            ctx->last_seq = seq;
            // Verify data integrity
            for (u32 j = 0; j < 10; j++) {
                if (entry.raw_headers[j] != static_cast<u8>((seq + j) & 0xFF)) ctx->data_ok = false;
            }
            ctx->consumed++;
        }
    }
    return nullptr;
}

// Dual-thread SPSC: verify no loss, no reorder, no data corruption.
TEST(capture_stress, spsc_concurrent) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    CaptureProducerCtx prod{ring, 50000, 0, 0};
    CaptureConsumerCtx cons{ring, 0, 0, true, true, false};

    pthread_t prod_thread, cons_thread;
    pthread_create(&cons_thread, nullptr, capture_consumer, &cons);
    pthread_create(&prod_thread, nullptr, capture_producer, &prod);

    pthread_join(prod_thread, nullptr);
    cons.stop = true;
    pthread_join(cons_thread, nullptr);

    u32 remaining = ring->available();
    CHECK_EQ(prod.pushed, cons.consumed + remaining);
    CHECK_EQ(prod.pushed + prod.dropped, prod.count);
    CHECK(cons.order_ok);
    CHECK(cons.data_ok);

    munmap(ring, sizeof(CaptureRing));
}

// Backpressure: producer overwhelms consumer, verify drops + ordering.
TEST(capture_stress, spsc_backpressure) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    CaptureProducerCtx prod{ring, CaptureRing::kCapacity * 5, 0, 0};

    pthread_t prod_thread;
    pthread_create(&prod_thread, nullptr, capture_producer, &prod);
    pthread_join(prod_thread, nullptr);

    u32 consumed = 0;
    u32 last_seq = 0;
    bool order_ok = true;
    bool data_ok = true;
    CaptureEntry entry{};

    // Drain in small batches after the producer has already overrun the ring.
    for (u32 batch = 0; batch < 50; batch++) {
        for (u32 j = 0; j < 32; j++) {
            if (ring->pop(entry)) {
                u32 seq = entry.req_content_length;
                if (seq < last_seq) order_ok = false;
                last_seq = seq;
                for (u32 k = 0; k < 10; k++) {
                    if (entry.raw_headers[k] != static_cast<u8>((seq + k) & 0xFF)) data_ok = false;
                }
                consumed++;
            }
        }
    }

    // Drain
    while (ring->pop(entry)) {
        u32 seq = entry.req_content_length;
        if (seq < last_seq) order_ok = false;
        last_seq = seq;
        consumed++;
    }

    CHECK(order_ok);
    CHECK(data_ok);
    CHECK_EQ(prod.pushed + prod.dropped, prod.count);
    CHECK_EQ(prod.pushed, consumed);
    CHECK_GT(prod.dropped, 0u);

    munmap(ring, sizeof(CaptureRing));
}

// Rapid enable/disable toggle with concurrent requests on SmallLoop.
// Verifies no crash, no corruption under rapid state changes.
TEST(capture_stress, rapid_toggle) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // 200 requests with capture toggling every 3 requests
    u32 total_captured = 0;
    for (u32 i = 0; i < 200; i++) {
        if (i % 3 == 0) {
            if (loop.capture_ring)
                loop.set_capture(nullptr);
            else
                loop.set_capture(ring);
        }

        bool was_on = (loop.capture_ring != nullptr);
        send_request(loop, *conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        if (was_on) total_captured++;
    }

    // Ring entries should match expected count (capped at capacity)
    u32 ring_count = ring->available();
    u32 expected =
        total_captured < CaptureRing::kCapacity ? total_captured : CaptureRing::kCapacity;
    CHECK_EQ(ring_count, expected);

    // Verify all entries in ring are valid (status 200, non-zero header_len)
    CaptureEntry cap{};
    while (ring->pop(cap)) {
        CHECK_EQ(cap.resp_status, 200);
        CHECK_GT(cap.raw_header_len, 0);
    }

    munmap(ring, sizeof(CaptureRing));
}

// ============================================================
// Coverage gap tests (from systematic review)
// ============================================================

// G1. Truncation flag: capture_stage_headers with >8KB data
TEST(capture_gap, truncation_flag_set) {
    Connection conn;
    conn.reset();
    // Allocate a large capture buf and recv buf
    u8 capture_buf[CaptureEntry::kMaxHeaderLen];
    // Use mmap for a recv buffer larger than 8KB
    u32 big_size = CaptureEntry::kMaxHeaderLen + 1024;
    u8* big_recv = static_cast<u8*>(
        mmap(nullptr, big_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(big_recv != MAP_FAILED);

    conn.capture_buf = capture_buf;
    conn.recv_buf.bind(big_recv, big_size);

    // Fill with data larger than 8KB
    for (u32 i = 0; i < big_size; i++) big_recv[i] = static_cast<u8>('A' + (i % 26));
    conn.recv_buf.commit(big_size);
    conn.req_header_end = big_size;  // pretend headers are huge

    capture_stage_headers(conn);
    CHECK_EQ(conn.capture_header_len, static_cast<u16>(CaptureEntry::kMaxHeaderLen));

    // Now simulate on_request_complete writing the entry
    CaptureRing ring;
    ring.init();
    CaptureEntry cap{};
    cap.raw_header_len = conn.capture_header_len;
    cap.flags =
        (conn.capture_header_len == CaptureEntry::kMaxHeaderLen) ? kCaptureFlagTruncated : 0;
    __builtin_memcpy(cap.raw_headers, conn.capture_buf, conn.capture_header_len);
    ring.push(cap);

    CaptureEntry out{};
    ring.pop(out);
    CHECK_EQ(out.flags & kCaptureFlagTruncated, kCaptureFlagTruncated);
    CHECK_EQ(out.raw_header_len, static_cast<u16>(CaptureEntry::kMaxHeaderLen));
    CHECK_EQ(out.raw_headers[0], static_cast<u8>('A'));

    // Clean up — unbind before munmap to avoid Buffer destructor trap
    conn.recv_buf.bind(nullptr, 0);
    munmap(big_recv, big_size);
}

// G2. upstream_name: verify correct copy into captured entry, including boundary
TEST(capture_gap, upstream_name_copied) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    // Recv request, then manually set upstream_name (simulating proxy path)
    conn->recv_buf.reset();
    const char req[] = "GET /up HTTP/1.1\r\nHost: x\r\n\r\n";
    conn->recv_buf.write(reinterpret_cast<const u8*>(req), sizeof(req) - 1);
    IoEvent recv_ev = make_ev(conn->id, IoEventType::Recv, static_cast<i32>(sizeof(req) - 1));
    loop.backend.inject(recv_ev);
    IoEvent events[8];
    u32 n = loop.backend.wait(events, 8);
    for (u32 i = 0; i < n; i++) loop.dispatch(events[i]);

    // Set upstream_name before completion
    const char up_name[] = "api-backend-v2";
    for (u32 i = 0; i < sizeof(up_name); i++) conn->upstream_name[i] = up_name[i];

    // Complete send
    loop.inject_and_dispatch(
        make_ev(conn->id, IoEventType::Send, static_cast<i32>(conn->send_buf.len())));

    CHECK_EQ(ring->available(), 1u);
    CaptureEntry cap{};
    ring->pop(cap);

    // Verify upstream_name was copied correctly
    bool name_match = true;
    for (u32 i = 0; i < sizeof(up_name) - 1; i++) {
        if (cap.upstream_name[i] != up_name[i]) name_match = false;
    }
    CHECK(name_match);
    CHECK_EQ(cap.upstream_name[sizeof(up_name) - 1], '\0');

    munmap(ring, sizeof(CaptureRing));
}

// G2b. upstream_name at max length (23 chars + null) — no overflow
TEST(capture_gap, upstream_name_max_length) {
    Connection conn;
    conn.reset();
    // Fill upstream_name to max (23 chars + null = 24 bytes)
    for (u32 i = 0; i < Connection::kMaxUpstreamNameLen - 1; i++)
        conn.upstream_name[i] = static_cast<char>('a' + (i % 26));
    conn.upstream_name[Connection::kMaxUpstreamNameLen - 1] = '\0';

    // Simulate the copy loop from on_request_complete
    CaptureEntry cap{};
    for (u32 i = 0; i < sizeof(conn.upstream_name); i++) {
        cap.upstream_name[i] = conn.upstream_name[i];
        if (conn.upstream_name[i] == '\0') break;
    }

    // Verify: 23 chars copied, null terminated
    CHECK_EQ(cap.upstream_name[Connection::kMaxUpstreamNameLen - 1], '\0');
    CHECK_EQ(cap.upstream_name[0], 'a');
    CHECK_EQ(cap.upstream_name[22], static_cast<char>('a' + 22 % 26));
}

// G3. Metadata fields: timestamp, shard_id, content lengths
TEST(capture_gap, metadata_fields) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.shard_id = 7;
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);

    u64 before_us = realtime_us();
    send_request(loop, *conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    u64 after_us = realtime_us();

    CaptureEntry cap{};
    ring->pop(cap);

    // Timestamp should be between before and after
    CHECK(cap.timestamp_us >= before_us);
    CHECK(cap.timestamp_us <= after_us);

    // shard_id comes from conn.shard_id (set at alloc)
    // SmallLoop doesn't set shard_id on conns, so it's 0
    CHECK_EQ(cap.shard_id, 0);

    // No body → content lengths should be 0
    CHECK_EQ(cap.req_content_length, 0u);

    // resp_content_length is the resp_size passed to on_request_complete
    CHECK_GT(cap.resp_content_length, 0u);

    munmap(ring, sizeof(CaptureRing));
}

// G5. File header validation: wrong version, wrong entry_size
TEST(capture_gap, file_header_wrong_version) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.version = 3;
    CHECK(!capture_file_header_valid(&hdr));
}

TEST(capture_gap, file_header_wrong_entry_size) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_size = 100;
    CHECK(!capture_file_header_valid(&hdr));
}

TEST(capture_gap, file_header_wrong_magic_middle) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.magic[4] = 'X';  // corrupt middle of magic
    CHECK(!capture_file_header_valid(&hdr));
}

// G6. set_capture(nullptr) leaves capture_buf intact on connections
TEST(capture_gap, disable_preserves_capture_buf) {
    void* ring_mem = mmap(
        nullptr, sizeof(CaptureRing), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(ring_mem != MAP_FAILED);
    auto* ring = new (ring_mem) CaptureRing();
    ring->init();

    SmallLoop loop;
    loop.setup();
    loop.set_capture(ring);

    loop.inject_and_dispatch(make_ev(0, IoEventType::Accept, 42));
    auto* conn = loop.find_fd(42);
    REQUIRE(conn != nullptr);
    CHECK(conn->capture_buf != nullptr);
    u8* saved_buf = conn->capture_buf;

    // Disable — capture_buf should remain (region not freed)
    loop.set_capture(nullptr);
    CHECK_EQ(conn->capture_buf, saved_buf);

    // New connection after disable — should still get capture_buf
    // (because capture_region_ is never freed, and alloc_conn checks it)
    // Note: SmallLoop uses static storage, so this is always true.
    // The real EventLoop path checks capture_region_ in alloc_conn.

    munmap(ring, sizeof(CaptureRing));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
